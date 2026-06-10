//! Process Guard Module - Prevents agent process termination
//!
//! This module implements multiple layers of process protection:
//! - Windows Protected Process Light (PPL) registration
//! - Critical process flag via NtSetInformationProcess
//! - Kernel driver callbacks for handle stripping
//! - Process termination monitoring and alerting
//!
//! MITRE ATT&CK Coverage:
//! - T1562.001 - Disable or Modify Tools
//! - T1489 - Service Stop

// Process guard. PascalCase mirrors NT API param names; scaffolded fields
// retained for upcoming PPL / kernel callback paths.
#![allow(dead_code, unused_variables, non_snake_case, unused_unsafe)]

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{TamperEvent, TamperEventType, TamperSeverity};

/// Critical processes that should NEVER be killed by the EDR
/// These are Windows system processes that would cause system instability
pub const CRITICAL_PROCESSES: &[&str] = &[
    "csrss.exe",          // Client/Server Runtime Subsystem
    "smss.exe",           // Session Manager Subsystem
    "wininit.exe",        // Windows Initialization Process
    "services.exe",       // Service Control Manager
    "lsass.exe",          // Local Security Authority
    "winlogon.exe",       // Windows Logon Process
    "dwm.exe",            // Desktop Window Manager
    "System",             // NT Kernel & System
    "Registry",           // Registry Process
    "Memory Compression", // Memory Compression Process
    "svchost.exe",        // Service Host (with critical flags)
    "tamandua-agent.exe", // This agent itself
    "TamanduaAgent.exe",  // Alternative agent name
];

/// Process protection configuration
#[derive(Debug, Clone)]
pub struct ProcessGuardConfig {
    /// Enable critical process flag (causes BSOD on termination)
    pub enable_critical_process: bool,
    /// Enable driver-based protection
    pub enable_driver_protection: bool,
    /// Enable PPL registration (requires signed binary)
    pub enable_ppl: bool,
    /// Monitor for termination attempts
    pub monitor_termination_attempts: bool,
    /// Check interval for termination monitoring (seconds)
    pub monitor_interval_secs: u64,
}

impl Default for ProcessGuardConfig {
    fn default() -> Self {
        Self {
            enable_critical_process: false,
            enable_driver_protection: true,
            enable_ppl: true,
            monitor_termination_attempts: true,
            monitor_interval_secs: 5,
        }
    }
}

/// Process guard state
pub struct ProcessGuard {
    config: ProcessGuardConfig,
    running: Arc<AtomicBool>,
    critical_process_set: AtomicBool,
    driver_protection_active: AtomicBool,
    ppl_active: AtomicBool,
    termination_attempts: Arc<AtomicU64>,
    tamper_tx: mpsc::Sender<TamperEvent>,
}

impl ProcessGuard {
    /// Create a new process guard
    pub fn new(config: ProcessGuardConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            critical_process_set: AtomicBool::new(false),
            driver_protection_active: AtomicBool::new(false),
            ppl_active: AtomicBool::new(false),
            termination_attempts: Arc::new(AtomicU64::new(0)),
            tamper_tx,
        }
    }

    /// Initialize process protection
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing process guard");
        self.running.store(true, Ordering::SeqCst);

        // Set critical process flag (highest priority protection)
        if self.config.enable_critical_process {
            match self.set_critical_process() {
                Ok(()) => {
                    self.critical_process_set.store(true, Ordering::SeqCst);
                    info!("Process marked as critical - termination will cause BSOD");
                }
                Err(e) => {
                    warn!(
                        "Failed to set critical process flag: {} (requires elevation)",
                        e
                    );
                }
            }
        }

        // Register with kernel driver for protection
        if self.config.enable_driver_protection {
            match self.register_driver_protection().await {
                Ok(()) => {
                    self.driver_protection_active.store(true, Ordering::SeqCst);
                    info!("Registered with kernel driver for process protection");
                }
                Err(e) => {
                    warn!(
                        "Failed to register driver protection: {} (driver may not be loaded)",
                        e
                    );
                }
            }
        }

        // Register for PPL (Protected Process Light)
        if self.config.enable_ppl {
            match self.register_ppl() {
                Ok(()) => {
                    self.ppl_active.store(true, Ordering::SeqCst);
                    info!("Registered as Protected Process Light");
                }
                Err(e) => {
                    warn!("Failed to register PPL: {} (requires signed binary)", e);
                }
            }
        }

        // Start termination monitoring
        if self.config.monitor_termination_attempts {
            self.start_termination_monitor();
        }

        Ok(())
    }

    /// Set process as critical via RtlSetProcessIsCritical
    /// When a critical process is terminated, the system will BSOD
    #[cfg(target_os = "windows")]
    fn set_critical_process(&self) -> Result<()> {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        unsafe {
            let ntdll = GetModuleHandleW(w!("ntdll.dll"))
                .map_err(|e| anyhow!("Failed to get ntdll handle: {:?}", e))?;

            type RtlSetProcessIsCriticalFn =
                unsafe extern "system" fn(NewValue: u32, OldValue: *mut u32, CheckFlag: u32) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"RtlSetProcessIsCritical\0".as_ptr()),
            );

            if let Some(f) = func {
                let rtl_set_critical: RtlSetProcessIsCriticalFn = std::mem::transmute(f);
                let mut old_value: u32 = 0;

                // First, enable SE_DEBUG_NAME privilege (required)
                self.enable_debug_privilege()?;

                let status = rtl_set_critical(1, &mut old_value, 0);

                if status != 0 {
                    return Err(anyhow!(
                        "RtlSetProcessIsCritical failed: NTSTATUS 0x{:08X}",
                        status
                    ));
                }
            } else {
                return Err(anyhow!("RtlSetProcessIsCritical not found in ntdll"));
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn set_critical_process(&self) -> Result<()> {
        // On Linux/macOS, we rely on other protection mechanisms
        Ok(())
    }

    /// Enable SE_DEBUG_NAME privilege required for critical process setting
    #[cfg(target_os = "windows")]
    fn enable_debug_privilege(&self) -> Result<()> {
        use windows::core::w;
        use windows::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)
                .map_err(|e| anyhow!("OpenProcessToken failed: {:?}", e))?;

            let mut luid = windows::Win32::Foundation::LUID::default();
            LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid)
                .map_err(|e| anyhow!("LookupPrivilegeValueW failed: {:?}", e))?;

            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)
                .map_err(|e| anyhow!("AdjustTokenPrivileges failed: {:?}", e))?;

            let _ = windows::Win32::Foundation::CloseHandle(token);
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn enable_debug_privilege(&self) -> Result<()> {
        Ok(())
    }

    /// Register with kernel driver for process protection
    #[cfg(target_os = "windows")]
    async fn register_driver_protection(&self) -> Result<()> {
        use crate::driver::{self, protect_flags};

        if !driver::is_driver_loaded() {
            warn!("Kernel driver not loaded - process protection unavailable");
            return Ok(());
        }

        let mut conn = driver::DriverConnection::new();
        conn.connect()?;

        let agent_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Register agent with full protection
        conn.register_agent(
            &agent_path,
            None,
            true, // auto_restart
            true, // protected
        )?;

        // Protect our process with all flags:
        // - NO_TERMINATE: Block termination
        // - NO_INJECT: Block DLL injection
        // - NO_MEMORY_ACCESS: Block memory read/write
        // - NO_HANDLE_DUP: Block handle duplication
        conn.protect_process(std::process::id(), protect_flags::FULL)?;

        // Register PID with anti-tamper watchdog
        conn.register_agent_pid()?;

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn register_driver_protection(&self) -> Result<()> {
        // On Linux, we use other protection mechanisms (see linux_process_protection)
        self.linux_process_protection()
    }

    /// Linux-specific process protection
    #[cfg(target_os = "linux")]
    fn linux_process_protection(&self) -> Result<()> {
        use std::fs;

        // Make the process undumpable (ptrace protection)
        unsafe {
            // PR_SET_DUMPABLE = 4, 0 = not dumpable
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }

        // Try to set no_new_privs (prevents privilege escalation)
        unsafe {
            // PR_SET_NO_NEW_PRIVS = 38
            libc::prctl(38, 1, 0, 0, 0);
        }

        // OOM killer protection - set score to minimum
        if let Ok(_) = fs::write("/proc/self/oom_score_adj", "-1000") {
            debug!("Set OOM score to minimum");
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn linux_process_protection(&self) -> Result<()> {
        Ok(())
    }

    /// Register as Protected Process Light (PPL)
    #[cfg(target_os = "windows")]
    fn register_ppl(&self) -> Result<()> {
        // PPL registration requires:
        // 1. A signed binary with specific EKU
        // 2. Calling NtSetInformationProcess with ProcessProtectionInformation
        //
        // For now, this is done via the kernel driver which can set PPL flags
        // from kernel mode using PsSetProtectedProcess or similar APIs

        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = GetModuleHandleW(w!("ntdll.dll"))
                .map_err(|e| anyhow!("Failed to get ntdll handle: {:?}", e))?;

            type NtSetInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *const std::ffi::c_void,
                ProcessInformationLength: u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtSetInformationProcess\0".as_ptr()),
            );

            if let Some(f) = func {
                let nt_set: NtSetInformationProcessFn = std::mem::transmute(f);

                // ProcessProtectionInformation = 61
                // PS_PROTECTION structure: Type (3=PPL), Audit (0), Signer (6=Antimalware)
                #[repr(C)]
                struct PsProtection {
                    type_audit_signer: u8,
                }

                let protection = PsProtection {
                    // Type=3 (Protected Light), Audit=0, Signer=6 (Antimalware)
                    // Packed as: (Signer << 4) | (Audit << 3) | Type
                    type_audit_signer: (6 << 4) | 3,
                };

                let status = nt_set(
                    GetCurrentProcess(),
                    61, // ProcessProtectionInformation
                    &protection as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<PsProtection>() as u32,
                );

                if status != 0 {
                    // This commonly fails unless the binary is signed with the correct EKU
                    return Err(anyhow!(
                        "NtSetInformationProcess(ProcessProtectionInformation) failed: 0x{:08X} (binary must be signed)",
                        status
                    ));
                }
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn register_ppl(&self) -> Result<()> {
        Ok(())
    }

    /// Start monitoring for termination attempts
    fn start_termination_monitor(&self) {
        let running = self.running.clone();
        let tamper_tx = self.tamper_tx.clone();
        let termination_attempts = self.termination_attempts.clone();
        let interval_secs = self.config.monitor_interval_secs;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            // Track our process handle count
            let mut last_handle_count = Self::get_open_handle_count();

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                // Check for suspicious handle activity
                let current_handles = Self::get_open_handle_count();

                // Sudden spike in handles could indicate enumeration attack
                if current_handles > last_handle_count + 100 {
                    warn!(
                        "Suspicious handle activity: {} -> {} handles",
                        last_handle_count, current_handles
                    );

                    termination_attempts.fetch_add(1, Ordering::SeqCst);

                    let event = TamperEvent {
                        timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                        event_type: TamperEventType::HandleDuplication,
                        description: format!(
                            "Suspicious handle activity detected: {} handles opened to agent process",
                            current_handles - last_handle_count
                        ),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::High,
                        mitre_technique: Some("T1562.001".to_string()),
                    };

                    let _ = tamper_tx.send(event).await;
                }

                last_handle_count = current_handles;
            }
        });
    }

    /// Get count of handles opened to our process
    #[cfg(target_os = "windows")]
    fn get_open_handle_count() -> usize {
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

        unsafe {
            let mut count: u32 = 0;
            if GetProcessHandleCount(GetCurrentProcess(), &mut count).is_ok() {
                return count as usize;
            }
        }
        0
    }

    #[cfg(not(target_os = "windows"))]
    fn get_open_handle_count() -> usize {
        // On Linux, count entries in /proc/self/fd
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            return entries.count();
        }
        0
    }

    /// Check if a process name is critical and should not be terminated
    pub fn is_critical_process(process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        CRITICAL_PROCESSES
            .iter()
            .any(|critical| name_lower == critical.to_lowercase())
    }

    /// Check if a process ID belongs to a critical process
    #[cfg(target_os = "windows")]
    pub fn is_critical_pid(pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameA;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buffer = [0u8; 260];
                let len = K32GetProcessImageFileNameA(handle, &mut buffer);
                let _ = CloseHandle(handle);

                if len > 0 {
                    let path = String::from_utf8_lossy(&buffer[..len as usize]);
                    if let Some(name) = path.rsplit('\\').next() {
                        return Self::is_critical_process(name);
                    }
                }
            }

            // System process (PID 4) is always critical
            pid == 4
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn is_critical_pid(pid: u32) -> bool {
        // On Linux, check /proc/{pid}/comm
        if let Ok(name) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
            return Self::is_critical_process(name.trim());
        }

        // Init (PID 1) is always critical
        pid == 1
    }

    /// Get protection status
    pub fn status(&self) -> ProcessGuardStatus {
        ProcessGuardStatus {
            critical_process_set: self.critical_process_set.load(Ordering::SeqCst),
            driver_protection_active: self.driver_protection_active.load(Ordering::SeqCst),
            ppl_active: self.ppl_active.load(Ordering::SeqCst),
            termination_attempts: self.termination_attempts.load(Ordering::SeqCst),
        }
    }

    /// Shutdown protection
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);

        // Optionally clear critical process flag before shutdown
        // This prevents BSOD during planned shutdown
        #[cfg(target_os = "windows")]
        if self.critical_process_set.load(Ordering::SeqCst) {
            if let Err(e) = self.clear_critical_process() {
                warn!("Failed to clear critical process flag: {}", e);
            }
        }
    }

    /// Clear critical process flag (for clean shutdown)
    #[cfg(target_os = "windows")]
    fn clear_critical_process(&self) -> Result<()> {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        unsafe {
            let ntdll = GetModuleHandleW(w!("ntdll.dll"))?;

            type RtlSetProcessIsCriticalFn =
                unsafe extern "system" fn(NewValue: u32, OldValue: *mut u32, CheckFlag: u32) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"RtlSetProcessIsCritical\0".as_ptr()),
            );

            if let Some(f) = func {
                let rtl_set_critical: RtlSetProcessIsCriticalFn = std::mem::transmute(f);
                let mut old_value: u32 = 0;
                rtl_set_critical(0, &mut old_value, 0);
            }
        }

        self.critical_process_set.store(false, Ordering::SeqCst);
        info!("Critical process flag cleared for clean shutdown");
        Ok(())
    }
}

/// Process guard status
#[derive(Debug, Clone)]
pub struct ProcessGuardStatus {
    pub critical_process_set: bool,
    pub driver_protection_active: bool,
    pub ppl_active: bool,
    pub termination_attempts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_critical_process() {
        assert!(ProcessGuard::is_critical_process("csrss.exe"));
        assert!(ProcessGuard::is_critical_process("CSRSS.EXE"));
        assert!(ProcessGuard::is_critical_process("lsass.exe"));
        assert!(ProcessGuard::is_critical_process("System"));
        assert!(!ProcessGuard::is_critical_process("notepad.exe"));
        assert!(!ProcessGuard::is_critical_process("malware.exe"));
    }
}
