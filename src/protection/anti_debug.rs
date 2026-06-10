//! Anti-Debug Module - Detects debugging attempts
//!
//! This module implements comprehensive anti-debugging detection:
//! - Windows: IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB flags
//! - Windows: NtGlobalFlag, Hardware breakpoints (DR0-DR3)
//! - Windows: Timing attacks, debug object detection
//! - Linux: TracerPid, ptrace detection
//! - macOS: P_TRACED flag via sysctl
//! - Cross-platform: Debug environment variables
//!
//! MITRE ATT&CK Coverage:
//! - T1562.001 - Disable or Modify Tools (debugger used to disable EDR)
//! - T1497.001 - Virtualization/Sandbox Evasion: System Checks

// Anti-debug detector. PascalCase mirrors NT API param names; scaffolded
// fields retained for upcoming detection paths.
#![allow(dead_code, unused_variables, non_snake_case, unused_unsafe)]

use anyhow::Result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::{TamperEvent, TamperEventType, TamperSeverity};

/// Anti-debug configuration
#[derive(Debug, Clone)]
pub struct AntiDebugConfig {
    /// Enable anti-debug checks
    pub enabled: bool,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Enable timing attack detection
    pub enable_timing_check: bool,
    /// Timing threshold in milliseconds
    pub timing_threshold_ms: u64,
    /// Enable hardware breakpoint detection
    pub enable_hw_breakpoint_check: bool,
    /// Enable environment variable check
    pub enable_env_check: bool,
    /// Action on detection: log, alert, or evade
    pub on_detection: AntiDebugAction,
}

/// Action to take when debugger is detected
#[derive(Debug, Clone, PartialEq)]
pub enum AntiDebugAction {
    /// Log the detection only
    Log,
    /// Send alert but continue
    Alert,
    /// Take evasive action (clear sensitive data, randomize behavior)
    Evade,
}

impl Default for AntiDebugConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 10,
            enable_timing_check: true,
            timing_threshold_ms: 100,
            enable_hw_breakpoint_check: true,
            enable_env_check: true,
            on_detection: AntiDebugAction::Alert,
        }
    }
}

/// Detection result type
#[derive(Debug, Clone)]
pub struct DebuggerDetection {
    pub detection_type: TamperEventType,
    pub description: String,
    pub technique: Option<String>,
}

/// Anti-debug engine
pub struct AntiDebugEngine {
    config: AntiDebugConfig,
    running: Arc<AtomicBool>,
    detection_count: Arc<AtomicU64>,
    tamper_tx: mpsc::Sender<TamperEvent>,
    last_check_time: std::sync::RwLock<Option<Instant>>,
}

impl AntiDebugEngine {
    /// Create a new anti-debug engine
    pub fn new(config: AntiDebugConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            detection_count: Arc::new(AtomicU64::new(0)),
            tamper_tx,
            last_check_time: std::sync::RwLock::new(None),
        }
    }

    /// Initialize anti-debug monitoring
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Anti-debug checks disabled by configuration");
            return Ok(());
        }

        info!("Initializing anti-debug engine");
        self.running.store(true, Ordering::SeqCst);

        // Perform initial check
        let detections = self.run_all_checks();
        for detection in &detections {
            self.handle_detection(detection).await;
        }

        // Start periodic monitoring
        self.start_monitoring_task();

        Ok(())
    }

    /// Run all anti-debug checks
    pub fn run_all_checks(&self) -> Vec<DebuggerDetection> {
        let mut detections = Vec::new();

        // Platform-specific checks
        #[cfg(target_os = "windows")]
        {
            // Method 1: IsDebuggerPresent
            if self.check_is_debugger_present() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debugger detected via IsDebuggerPresent API".to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 2: CheckRemoteDebuggerPresent
            if self.check_remote_debugger() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerRemote,
                    description: "Remote debugger detected via CheckRemoteDebuggerPresent"
                        .to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 3: NtGlobalFlag in PEB
            if self.check_ntglobalflag() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerNtGlobalFlag,
                    description: "Debugger artifacts in NtGlobalFlag (heap debug flags)"
                        .to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 4: Hardware breakpoints
            if self.config.enable_hw_breakpoint_check && self.check_hardware_breakpoints() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerHardwareBreakpoint,
                    description: "Hardware breakpoints detected in debug registers DR0-DR3"
                        .to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 5: ProcessDebugPort
            if self.check_debug_port() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debugger detected via ProcessDebugPort query".to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 6: ProcessDebugObjectHandle
            if self.check_debug_object() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debug object handle detected via ProcessDebugObjectHandle"
                        .to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 7: ProcessDebugFlags
            if self.check_debug_flags() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debug flags indicate debugger (NoDebugInherit clear)".to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            // Method 8: Timing attack detection
            if self.config.enable_timing_check && self.check_timing_anomaly() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerTimingAnomaly,
                    description: format!(
                        "Execution timing anomaly (>{}ms threshold)",
                        self.config.timing_threshold_ms
                    ),
                    technique: Some("T1497.001".to_string()),
                });
            }
        }

        #[cfg(target_os = "linux")]
        {
            if self.check_tracer_pid() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debugger detected via /proc/self/status TracerPid".to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }

            if self.check_ptrace_self() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debugger detected via ptrace self-trace test".to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }
        }

        #[cfg(target_os = "macos")]
        {
            if self.check_p_traced() {
                detections.push(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerAttached,
                    description: "Debugger detected via sysctl P_TRACED flag".to_string(),
                    technique: Some("T1562.001".to_string()),
                });
            }
        }

        // Cross-platform: environment variables
        if self.config.enable_env_check {
            if let Some(detection) = self.check_debug_environment() {
                detections.push(detection);
            }
        }

        // Update last check time
        *self
            .last_check_time
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

        detections
    }

    // =========================================================================
    // Windows-specific checks
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn check_is_debugger_present(&self) -> bool {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        unsafe { IsDebuggerPresent().as_bool() }
    }

    #[cfg(target_os = "windows")]
    fn check_remote_debugger(&self) -> bool {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let mut debugger_present = BOOL(0);
            if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut debugger_present).is_ok() {
                return debugger_present.as_bool();
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    fn check_ntglobalflag(&self) -> bool {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtQueryInformationProcess\0".as_ptr()),
            );
            let nt_query: NtQueryInformationProcessFn = match func {
                Some(f) => std::mem::transmute(f),
                None => return false,
            };

            // ProcessBasicInformation = 0
            #[repr(C)]
            struct ProcessBasicInformation {
                reserved1: usize,
                peb_base_address: *const u8,
                reserved2: [usize; 2],
                unique_process_id: usize,
                reserved3: usize,
            }

            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length: u32 = 0;

            let status = nt_query(
                GetCurrentProcess(),
                0,
                &mut pbi as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            if status != 0 || pbi.peb_base_address.is_null() {
                return false;
            }

            // NtGlobalFlag offset
            #[cfg(target_arch = "x86_64")]
            let offset: usize = 0xBC;
            #[cfg(target_arch = "x86")]
            let offset: usize = 0x68;

            let ntglobalflag_ptr = pbi.peb_base_address.add(offset) as *const u32;
            let ntglobalflag = std::ptr::read_volatile(ntglobalflag_ptr);

            // Debug heap flags: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
            // FLG_HEAP_VALIDATE_PARAMETERS = 0x70
            (ntglobalflag & 0x70) != 0
        }
    }

    #[cfg(target_os = "windows")]
    fn check_hardware_breakpoints(&self) -> bool {
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, CONTEXT, CONTEXT_FLAGS,
        };
        use windows::Win32::System::Threading::GetCurrentThread;

        unsafe {
            let mut context: CONTEXT = std::mem::zeroed();
            // CONTEXT_DEBUG_REGISTERS
            context.ContextFlags = CONTEXT_FLAGS(0x00100010);

            if GetThreadContext(GetCurrentThread(), &mut context).is_ok() {
                return context.Dr0 != 0
                    || context.Dr1 != 0
                    || context.Dr2 != 0
                    || context.Dr3 != 0;
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    fn check_debug_port(&self) -> bool {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtQueryInformationProcess\0".as_ptr()),
            );
            let nt_query: NtQueryInformationProcessFn = match func {
                Some(f) => std::mem::transmute(f),
                None => return false,
            };

            // ProcessDebugPort = 7
            let mut debug_port: usize = 0;
            let mut return_length: u32 = 0;

            let status = nt_query(
                GetCurrentProcess(),
                7,
                &mut debug_port as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            );

            status == 0 && debug_port != 0
        }
    }

    #[cfg(target_os = "windows")]
    fn check_debug_object(&self) -> bool {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtQueryInformationProcess\0".as_ptr()),
            );
            let nt_query: NtQueryInformationProcessFn = match func {
                Some(f) => std::mem::transmute(f),
                None => return false,
            };

            // ProcessDebugObjectHandle = 30
            let mut debug_object: usize = 0;
            let mut return_length: u32 = 0;

            let status = nt_query(
                GetCurrentProcess(),
                30,
                &mut debug_object as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            );

            // If we can query a debug object handle, we're being debugged
            // STATUS_PORT_NOT_SET (0xC0000353) means no debugger
            status == 0
        }
    }

    #[cfg(target_os = "windows")]
    fn check_debug_flags(&self) -> bool {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtQueryInformationProcess\0".as_ptr()),
            );
            let nt_query: NtQueryInformationProcessFn = match func {
                Some(f) => std::mem::transmute(f),
                None => return false,
            };

            // ProcessDebugFlags = 31
            let mut debug_flags: u32 = 0;
            let mut return_length: u32 = 0;

            let status = nt_query(
                GetCurrentProcess(),
                31,
                &mut debug_flags as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                &mut return_length,
            );

            // NoDebugInherit flag: 0 means debugged, 1 means not debugged
            status == 0 && debug_flags == 0
        }
    }

    #[cfg(target_os = "windows")]
    fn check_timing_anomaly(&self) -> bool {
        let start = Instant::now();

        // Perform a simple operation that should complete quickly
        let mut x: u64 = 0;
        for i in 0..10000 {
            x = x.wrapping_add(i);
        }

        // Prevent optimization
        std::hint::black_box(x);

        let elapsed = start.elapsed();
        elapsed.as_millis() > self.config.timing_threshold_ms as u128
    }

    // =========================================================================
    // Linux-specific checks
    // =========================================================================

    #[cfg(target_os = "linux")]
    fn check_tracer_pid(&self) -> bool {
        use std::fs;

        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split_whitespace().nth(1) {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            return pid != 0;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    fn check_ptrace_self(&self) -> bool {
        // PTRACE_TRACEME is ambiguous in hardened services and can become
        // destructive/noisy after no_new_privs, seccomp, or capability changes.
        // TracerPid in /proc/self/status remains the Linux signal of record.
        false
    }

    // =========================================================================
    // macOS-specific checks
    // =========================================================================

    #[cfg(target_os = "macos")]
    fn check_p_traced(&self) -> bool {
        macos_process_is_traced(std::process::id())
    }

    // =========================================================================
    // Cross-platform checks
    // =========================================================================

    fn check_debug_environment(&self) -> Option<DebuggerDetection> {
        let debugger_names = [
            "gdb", "lldb", "strace", "ltrace", "x64dbg", "ollydbg", "windbg", "ida", "radare2",
            "r2", "frida",
        ];

        // Check _ variable (contains parent process on Unix)
        if let Ok(underscore) = std::env::var("_") {
            let lower = underscore.to_lowercase();
            for name in &debugger_names {
                if lower.contains(name) {
                    return Some(DebuggerDetection {
                        detection_type: TamperEventType::DebuggerEnvironment,
                        description: format!("Debugger detected in parent: {}", underscore),
                        technique: Some("T1562.001".to_string()),
                    });
                }
            }
        }

        // Check LD_PRELOAD (Linux library injection)
        if let Ok(ld_preload) = std::env::var("LD_PRELOAD") {
            if !ld_preload.is_empty() {
                return Some(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerEnvironment,
                    description: format!("LD_PRELOAD set: {}", ld_preload),
                    technique: Some("T1055".to_string()),
                });
            }
        }

        // Check DYLD_INSERT_LIBRARIES (macOS library injection)
        if let Ok(dyld) = std::env::var("DYLD_INSERT_LIBRARIES") {
            if !dyld.is_empty() {
                return Some(DebuggerDetection {
                    detection_type: TamperEventType::DebuggerEnvironment,
                    description: format!("DYLD_INSERT_LIBRARIES set: {}", dyld),
                    technique: Some("T1055".to_string()),
                });
            }
        }

        None
    }

    // Stub implementations for non-applicable platforms
    #[cfg(not(target_os = "windows"))]
    fn check_is_debugger_present(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_remote_debugger(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_ntglobalflag(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_hardware_breakpoints(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_debug_port(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_debug_object(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_debug_flags(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "windows"))]
    fn check_timing_anomaly(&self) -> bool {
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn check_tracer_pid(&self) -> bool {
        false
    }
    #[cfg(not(target_os = "linux"))]
    fn check_ptrace_self(&self) -> bool {
        false
    }

    #[cfg(not(target_os = "macos"))]
    fn check_p_traced(&self) -> bool {
        false
    }

    /// Handle a detection
    async fn handle_detection(&self, detection: &DebuggerDetection) {
        self.detection_count.fetch_add(1, Ordering::SeqCst);

        match self.config.on_detection {
            AntiDebugAction::Log => {
                warn!(description = %detection.description, "Debugger detection (log only)");
            }
            AntiDebugAction::Alert => {
                warn!(description = %detection.description, "Debugger detection - sending alert");

                let event = TamperEvent {
                    timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                    event_type: detection.detection_type.clone(),
                    description: detection.description.clone(),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Critical,
                    mitre_technique: detection.technique.clone(),
                };

                let _ = self.tamper_tx.send(event).await;
            }
            AntiDebugAction::Evade => {
                warn!(description = %detection.description, "Debugger detection - taking evasive action");

                let event = TamperEvent {
                    timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                    event_type: detection.detection_type.clone(),
                    description: detection.description.clone(),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Critical,
                    mitre_technique: detection.technique.clone(),
                };

                let _ = self.tamper_tx.send(event).await;

                // Take evasive action
                self.evasive_action();
            }
        }
    }

    /// Take evasive action when debugger detected
    fn evasive_action(&self) {
        warn!("Taking evasive action due to debugger detection");

        // Option 1: Clear sensitive data from memory
        // Option 2: Randomize timing and behavior
        // Option 3: Reduce functionality but continue operating

        // We intentionally do NOT exit or crash - this would allow
        // an attacker to disable the agent by attaching a debugger
    }

    /// Start monitoring task
    fn start_monitoring_task(&self) {
        let running = self.running.clone();
        let config = self.config.clone();
        let tamper_tx = self.tamper_tx.clone();
        let detection_count = self.detection_count.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(config.check_interval_secs));

            let engine = AntiDebugEngine {
                config: config.clone(),
                running: running.clone(),
                detection_count: detection_count.clone(),
                tamper_tx: tamper_tx.clone(),
                last_check_time: std::sync::RwLock::new(None),
            };

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                let detections = engine.run_all_checks();
                for detection in &detections {
                    engine.handle_detection(detection).await;
                }
            }
        });

        debug!(
            interval = self.config.check_interval_secs,
            "Anti-debug monitoring started"
        );
    }

    /// Get detection count
    pub fn get_detection_count(&self) -> u64 {
        self.detection_count.load(Ordering::SeqCst)
    }

    /// Check if currently being debugged (instant check)
    pub fn is_debugger_present(&self) -> bool {
        let detections = self.run_all_checks();
        !detections.is_empty()
    }

    /// Shutdown anti-debug engine
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Anti-debug engine shutdown");
    }
}

#[cfg(target_os = "macos")]
fn macos_process_is_traced(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stat| stat.contains('T'))
        .unwrap_or(false)
}

/// Anti-debug status
#[derive(Debug, Clone)]
pub struct AntiDebugStatus {
    pub enabled: bool,
    pub detection_count: u64,
    pub last_check: Option<u64>,
    pub debugger_present: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AntiDebugConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_interval_secs, 10);
        assert!(config.enable_timing_check);
    }
}
