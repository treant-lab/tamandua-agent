//! Intel CET (Control-flow Enforcement Technology) and Shadow Stack Detection
//!
//! This module provides comprehensive detection and enforcement of Intel CET features:
//!
//! ## Features Detected
//!
//! - **Shadow Stack (CET_SS)** - Hardware-based return address protection
//! - **Indirect Branch Tracking (IBT)** - Validates indirect call/jump targets
//! - **Kernel CET** - OS kernel-level CET enforcement
//! - **Process CET** - Per-process CET policy status
//!
//! ## Windows Requirements
//!
//! - Windows 11+ or Windows 10 with specific updates for full CET support
//! - Intel 11th Gen+ (Tiger Lake) or AMD Zen 3+ CPUs
//! - VBS (Virtualization Based Security) may be required for kernel CET
//!
//! ## CPUID Detection
//!
//! - Leaf 7, ECX bit 7 (CET_SS): Shadow Stack support
//! - Leaf 7, ECX bit 20 (CET_IBT): Indirect Branch Tracking support
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1574 - Hijack Execution Flow (CET prevents ROP/JOP attacks)
//! - T1055 - Process Injection (Shadow stack detects return address manipulation)
//! - T1203 - Exploitation for Client Execution (CET mitigates control-flow attacks)
//!
//! ## Security Considerations
//!
//! CET is one of the most effective mitigations against return-oriented programming (ROP)
//! and jump-oriented programming (JOP) attacks. Attackers may attempt to:
//! - Disable CET via SetProcessMitigationPolicy (monitored by this module)
//! - Load CET-incompatible code to force CET relaxation
//! - Manipulate shadow stack directly (hardware protected)

#![cfg(target_os = "windows")]
// Intel CET / shadow-stack detector. Some inner unsafe blocks nest within
// outer unsafe for clarity at call sites.
#![allow(dead_code, unused_unsafe, non_snake_case)]

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessMitigationPolicy, OpenProcess, SetProcessMitigationPolicy,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use super::{TamperEvent, TamperEventType, TamperSeverity};

// ============================================================================
// Constants
// ============================================================================

/// CPUID leaf 7, subleaf 0 for extended features
const CPUID_EXTENDED_FEATURES_LEAF: u32 = 7;
const CPUID_EXTENDED_FEATURES_SUBLEAF: u32 = 0;

/// Bit positions in ECX for CET features
const CET_SS_BIT: u32 = 7; // Shadow Stack support
const CET_IBT_BIT: u32 = 20; // Indirect Branch Tracking support

/// Windows build numbers for CET support
const WINDOWS_11_BUILD: u32 = 22000; // Windows 11 initial release
const WINDOWS_10_CET_BUILD: u32 = 20000; // Windows 10 with CET preview support

/// Process mitigation policy type for User Shadow Stack (not in windows-rs yet)
const PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_TYPE: i32 = 13;

// ============================================================================
// Data Structures
// ============================================================================

/// CET support status for CPU and OS
#[derive(Debug, Clone, Default)]
pub struct CetSupport {
    /// CPU supports Shadow Stack (CPUID.7.0:ECX bit 7)
    pub cpu_supports_shadow_stack: bool,
    /// CPU supports Indirect Branch Tracking (CPUID.7.0:ECX bit 20)
    pub cpu_supports_ibt: bool,
    /// OS supports CET (Windows 11+ or Win10 with updates)
    pub os_supports_cet: bool,
    /// Current process has CET enabled
    pub process_cet_enabled: bool,
    /// Kernel CET is enabled (VBS required)
    pub kernel_cet_enabled: bool,
    /// Windows build number
    pub windows_build: u32,
    /// CPU vendor string
    pub cpu_vendor: String,
    /// CET enforcement mode
    pub enforcement_mode: CetEnforcementMode,
}

/// CET enforcement modes
#[derive(Debug, Clone, Default, PartialEq)]
pub enum CetEnforcementMode {
    /// CET not available
    #[default]
    Unavailable,
    /// CET available but not enforced (compatibility mode)
    CompatibilityMode,
    /// CET enforced with audit logging
    AuditMode,
    /// CET fully enforced (strict mode)
    Strict,
}

/// Per-process CET status
#[derive(Debug, Clone, Default)]
pub struct ProcessCetStatus {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// User Shadow Stack enabled
    pub shadow_stack_enabled: bool,
    /// IBT enabled
    pub ibt_enabled: bool,
    /// CET strict mode
    pub strict_mode: bool,
    /// Audit mode only
    pub audit_mode: bool,
    /// CET can be disabled by process
    pub can_disable: bool,
    /// Error if status couldn't be retrieved
    pub error: Option<String>,
}

/// CET bypass attempt types
#[derive(Debug, Clone, PartialEq)]
pub enum CetBypassAttempt {
    /// Process attempted to disable CET
    DisableCet { pid: u32, process_name: String },
    /// Shadow stack tampering detected
    ShadowStackTamper {
        pid: u32,
        process_name: String,
        details: String,
    },
    /// CET-incompatible DLL loaded
    IncompatibleDllLoad { pid: u32, dll_path: String },
    /// Return address mismatch detected
    ReturnAddressMismatch {
        pid: u32,
        expected: u64,
        actual: u64,
    },
    /// IBT violation (indirect branch to non-ENDBR)
    IbtViolation { pid: u32, target_address: u64 },
}

/// User Shadow Stack Policy flags (matching Windows SDK)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserShadowStackPolicyFlags {
    pub flags: u32,
}

impl UserShadowStackPolicyFlags {
    /// Enable user-mode shadow stack
    pub const ENABLE_USER_SHADOW_STACK: u32 = 0x00000001;
    /// Enable strict mode (no relaxation)
    pub const ENABLE_USER_SHADOW_STACK_STRICT_MODE: u32 = 0x00000002;
    /// Audit mode only (don't enforce, just log)
    pub const AUDIT_USER_SHADOW_STACK: u32 = 0x00000004;
    /// Block non-CET binaries
    pub const BLOCK_NON_CET_BINARIES: u32 = 0x00000008;
    /// Block non-CET binaries in non-EHCONT binaries
    pub const BLOCK_NON_CET_BINARIES_NON_EHCONT: u32 = 0x00000010;

    pub fn is_enabled(&self) -> bool {
        (self.flags & Self::ENABLE_USER_SHADOW_STACK) != 0
    }

    pub fn is_strict(&self) -> bool {
        (self.flags & Self::ENABLE_USER_SHADOW_STACK_STRICT_MODE) != 0
    }

    pub fn is_audit_only(&self) -> bool {
        (self.flags & Self::AUDIT_USER_SHADOW_STACK) != 0
            && (self.flags & Self::ENABLE_USER_SHADOW_STACK) == 0
    }

    pub fn blocks_non_cet_binaries(&self) -> bool {
        (self.flags & Self::BLOCK_NON_CET_BINARIES) != 0
    }
}

/// CET monitoring configuration
#[derive(Debug, Clone)]
pub struct CetMonitorConfig {
    /// Enable CET monitoring
    pub enabled: bool,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Enable process CET status monitoring
    pub monitor_process_cet: bool,
    /// Enable CET bypass detection
    pub detect_bypass_attempts: bool,
    /// Enable CET enforcement for agent process
    pub enforce_agent_cet: bool,
    /// Alert on CET-incompatible DLL loads
    pub alert_incompatible_dlls: bool,
}

impl Default for CetMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 30,
            monitor_process_cet: true,
            detect_bypass_attempts: true,
            enforce_agent_cet: true,
            alert_incompatible_dlls: true,
        }
    }
}

/// CET monitoring engine status
#[derive(Debug, Clone, Default)]
pub struct CetMonitorStatus {
    /// Current CET support status
    pub cet_support: CetSupport,
    /// Agent process CET status
    pub agent_cet_status: ProcessCetStatus,
    /// Number of bypass attempts detected
    pub bypass_attempts_detected: u64,
    /// Number of processes monitored
    pub processes_monitored: u64,
    /// Number of CET-incompatible processes found
    pub incompatible_processes: u64,
    /// Last check timestamp
    pub last_check_timestamp: Option<u64>,
}

// ============================================================================
// CPUID Detection Functions
// ============================================================================

/// Check CPUID for CET support (Shadow Stack and IBT)
///
/// Returns (shadow_stack_supported, ibt_supported)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_cpuid_cet() -> (bool, bool) {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid_count;

        unsafe {
            // First check if leaf 7 is supported
            let leaf0 = std::arch::x86_64::__cpuid(0);
            if leaf0.eax < CPUID_EXTENDED_FEATURES_LEAF {
                return (false, false);
            }

            // Query leaf 7, subleaf 0 for extended features
            let result = __cpuid_count(
                CPUID_EXTENDED_FEATURES_LEAF,
                CPUID_EXTENDED_FEATURES_SUBLEAF,
            );

            // ECX bit 7 = CET_SS (Shadow Stack)
            // ECX bit 20 = CET_IBT (Indirect Branch Tracking)
            let shadow_stack = (result.ecx & (1 << CET_SS_BIT)) != 0;
            let ibt = (result.ecx & (1 << CET_IBT_BIT)) != 0;

            (shadow_stack, ibt)
        }
    }

    #[cfg(target_arch = "x86")]
    {
        use std::arch::x86::__cpuid_count;

        unsafe {
            let leaf0 = std::arch::x86::__cpuid(0);
            if leaf0.eax < CPUID_EXTENDED_FEATURES_LEAF {
                return (false, false);
            }

            let result = __cpuid_count(
                CPUID_EXTENDED_FEATURES_LEAF,
                CPUID_EXTENDED_FEATURES_SUBLEAF,
            );

            let shadow_stack = (result.ecx & (1 << CET_SS_BIT)) != 0;
            let ibt = (result.ecx & (1 << CET_IBT_BIT)) != 0;

            (shadow_stack, ibt)
        }
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_cpuid_cet() -> (bool, bool) {
    // CET is x86-specific
    (false, false)
}

/// Get CPU vendor string from CPUID
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_cpu_vendor() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;

        unsafe {
            let result = __cpuid(0);

            // Vendor string is in EBX, EDX, ECX (in that order)
            let mut vendor = [0u8; 12];
            vendor[0..4].copy_from_slice(&result.ebx.to_le_bytes());
            vendor[4..8].copy_from_slice(&result.edx.to_le_bytes());
            vendor[8..12].copy_from_slice(&result.ecx.to_le_bytes());

            String::from_utf8_lossy(&vendor).to_string()
        }
    }

    #[cfg(target_arch = "x86")]
    {
        use std::arch::x86::__cpuid;

        unsafe {
            let result = __cpuid(0);

            let mut vendor = [0u8; 12];
            vendor[0..4].copy_from_slice(&result.ebx.to_le_bytes());
            vendor[4..8].copy_from_slice(&result.edx.to_le_bytes());
            vendor[8..12].copy_from_slice(&result.ecx.to_le_bytes());

            String::from_utf8_lossy(&vendor).to_string()
        }
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn get_cpu_vendor() -> String {
    "Unknown".to_string()
}

// ============================================================================
// Windows Version Detection
// ============================================================================

/// Get Windows build number
fn get_windows_build() -> u32 {
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

    unsafe {
        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };

        #[allow(deprecated)]
        if GetVersionExW(&mut version_info).is_ok() {
            version_info.dwBuildNumber
        } else {
            0
        }
    }
}

/// Check if Windows version supports CET
fn is_windows_cet_supported() -> bool {
    let build = get_windows_build();
    build >= WINDOWS_10_CET_BUILD
}

/// Check if this is Windows 11 (full CET support)
fn is_windows_11() -> bool {
    get_windows_build() >= WINDOWS_11_BUILD
}

// ============================================================================
// CET Support Detection
// ============================================================================

/// Detect comprehensive CET support status
pub fn is_cet_supported() -> CetSupport {
    let (cpu_ss, cpu_ibt) = check_cpuid_cet();
    let windows_build = get_windows_build();
    let os_supports = is_windows_cet_supported();

    let mut support = CetSupport {
        cpu_supports_shadow_stack: cpu_ss,
        cpu_supports_ibt: cpu_ibt,
        os_supports_cet: os_supports,
        windows_build,
        cpu_vendor: get_cpu_vendor(),
        ..Default::default()
    };

    // Check process CET status
    if os_supports && cpu_ss {
        if let Ok(status) = get_current_process_cet_status() {
            support.process_cet_enabled = status.shadow_stack_enabled;
            support.enforcement_mode = if status.strict_mode {
                CetEnforcementMode::Strict
            } else if status.audit_mode {
                CetEnforcementMode::AuditMode
            } else if status.shadow_stack_enabled {
                CetEnforcementMode::CompatibilityMode
            } else {
                CetEnforcementMode::Unavailable
            };
        }
    }

    // Check kernel CET (requires checking system information)
    support.kernel_cet_enabled = check_kernel_cet_enabled();

    debug!(
        cpu_ss = support.cpu_supports_shadow_stack,
        cpu_ibt = support.cpu_supports_ibt,
        os_cet = support.os_supports_cet,
        process_cet = support.process_cet_enabled,
        kernel_cet = support.kernel_cet_enabled,
        build = support.windows_build,
        vendor = %support.cpu_vendor,
        "CET support detection complete"
    );

    support
}

/// Check if kernel CET is enabled (VBS-dependent)
fn check_kernel_cet_enabled() -> bool {
    // Kernel CET requires VBS (Virtualization Based Security)
    // We check via registry
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Check Device Guard settings
    if let Ok(key) = hklm.open_subkey(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks",
    ) {
        if let Ok(enabled) = key.get_value::<u32, _>("Enabled") {
            return enabled == 1;
        }
    }

    false
}

// ============================================================================
// Process CET Status Functions
// ============================================================================

/// Get CET status for the current process
fn get_current_process_cet_status() -> Result<ProcessCetStatus> {
    let handle = unsafe { GetCurrentProcess() };
    get_process_cet_status_from_handle(handle, std::process::id(), "current_process".to_string())
}

/// Get CET status for a specific process by PID
pub fn get_process_cet_status(pid: u32) -> Result<ProcessCetStatus> {
    let process_name = get_process_name(pid).unwrap_or_else(|_| format!("pid_{}", pid));

    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .context(format!("Failed to open process {}", pid))?
    };

    let result = get_process_cet_status_from_handle(handle, pid, process_name);

    unsafe {
        let _ = CloseHandle(handle);
    }

    result
}

/// Get CET status from a process handle
fn get_process_cet_status_from_handle(
    handle: HANDLE,
    pid: u32,
    process_name: String,
) -> Result<ProcessCetStatus> {
    let mut status = ProcessCetStatus {
        pid,
        process_name,
        ..Default::default()
    };

    // Use GetProcessMitigationPolicy to query shadow stack policy
    // Note: ProcessUserShadowStackPolicy is type 13
    let mut policy = UserShadowStackPolicyFlags::default();
    let policy_size = mem::size_of::<UserShadowStackPolicyFlags>();

    let success = unsafe {
        GetProcessMitigationPolicy(
            handle,
            windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY(
                PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_TYPE,
            ),
            &mut policy as *mut _ as *mut c_void,
            policy_size,
        )
    };

    if success.is_ok() {
        status.shadow_stack_enabled = policy.is_enabled();
        status.strict_mode = policy.is_strict();
        status.audit_mode = policy.is_audit_only();
        status.can_disable = !policy.is_strict(); // Strict mode prevents disabling
        status.ibt_enabled = policy.is_enabled(); // IBT usually enabled with shadow stack
    } else {
        // Policy query failed - might not be supported on this OS version
        let err = std::io::Error::last_os_error();
        status.error = Some(format!("GetProcessMitigationPolicy failed: {}", err));
        debug!(pid, error = %err, "Failed to query CET status for process");
    }

    Ok(status)
}

/// Get process name from PID
fn get_process_name(pid: u32) -> Result<String> {
    use windows::Win32::Foundation::MAX_PATH;
    use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };

    let mut name_buffer = [0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleBaseNameW(handle, None, &mut name_buffer) };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if len > 0 {
        Ok(String::from_utf16_lossy(&name_buffer[..len as usize]))
    } else {
        Ok(format!("pid_{}", pid))
    }
}

// ============================================================================
// CET Enforcement Functions
// ============================================================================

/// Enable Shadow Stack for the current process
///
/// # Requirements
/// - Windows 11+ or Windows 10 with CET updates
/// - CPU with CET support (Intel 11th Gen+, AMD Zen 3+)
///
/// # Note
/// Once enabled in strict mode, cannot be disabled
pub fn enable_shadow_stack() -> Result<()> {
    let support = is_cet_supported();

    if !support.cpu_supports_shadow_stack {
        return Err(anyhow::anyhow!(
            "CPU does not support Shadow Stack (CET_SS). Vendor: {}",
            support.cpu_vendor
        ));
    }

    if !support.os_supports_cet {
        return Err(anyhow::anyhow!(
            "Windows version does not support CET. Build: {} (requires {}+)",
            support.windows_build,
            WINDOWS_10_CET_BUILD
        ));
    }

    // Already enabled?
    if support.process_cet_enabled {
        info!("Shadow Stack already enabled for this process");
        return Ok(());
    }

    // Enable shadow stack via SetProcessMitigationPolicy
    let policy = UserShadowStackPolicyFlags {
        flags: UserShadowStackPolicyFlags::ENABLE_USER_SHADOW_STACK
            | UserShadowStackPolicyFlags::ENABLE_USER_SHADOW_STACK_STRICT_MODE,
    };

    let result = unsafe {
        SetProcessMitigationPolicy(
            windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY(
                PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_TYPE,
            ),
            &policy as *const _ as *const c_void,
            mem::size_of::<UserShadowStackPolicyFlags>(),
        )
    };

    if result.is_ok() {
        info!("Shadow Stack enabled successfully for agent process");
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(anyhow::anyhow!(
            "Failed to enable Shadow Stack: {}. \
             This may require running as administrator or specific Windows updates.",
            err
        ))
    }
}

/// Enable Shadow Stack with audit mode (log violations but don't enforce)
pub fn enable_shadow_stack_audit() -> Result<()> {
    let support = is_cet_supported();

    if !support.cpu_supports_shadow_stack || !support.os_supports_cet {
        return Err(anyhow::anyhow!("CET not supported on this system"));
    }

    let policy = UserShadowStackPolicyFlags {
        flags: UserShadowStackPolicyFlags::AUDIT_USER_SHADOW_STACK,
    };

    let result = unsafe {
        SetProcessMitigationPolicy(
            windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY(
                PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_TYPE,
            ),
            &policy as *const _ as *const c_void,
            mem::size_of::<UserShadowStackPolicyFlags>(),
        )
    };

    if result.is_ok() {
        info!("Shadow Stack audit mode enabled");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to enable Shadow Stack audit mode: {}",
            std::io::Error::last_os_error()
        ))
    }
}

// ============================================================================
// CET Monitoring Engine
// ============================================================================

/// CET monitoring engine for detecting bypass attempts and policy violations
pub struct CetMonitor {
    config: CetMonitorConfig,
    running: Arc<AtomicBool>,
    tamper_tx: mpsc::Sender<TamperEvent>,
    /// Cached process CET statuses
    process_cache: Arc<tokio::sync::RwLock<HashMap<u32, ProcessCetStatus>>>,
    /// Bypass attempt counter
    bypass_count: Arc<std::sync::atomic::AtomicU64>,
}

impl CetMonitor {
    /// Create a new CET monitor
    pub fn new(config: CetMonitorConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            tamper_tx,
            process_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            bypass_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Initialize CET monitoring
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("CET monitoring disabled by configuration");
            return Ok(());
        }

        info!("Initializing CET monitoring engine");

        // Check CET support
        let support = is_cet_supported();

        info!(
            cpu_ss = support.cpu_supports_shadow_stack,
            cpu_ibt = support.cpu_supports_ibt,
            os_cet = support.os_supports_cet,
            build = support.windows_build,
            "CET support status"
        );

        // Enable CET for agent process if configured and supported
        if self.config.enforce_agent_cet
            && support.cpu_supports_shadow_stack
            && support.os_supports_cet
        {
            match enable_shadow_stack() {
                Ok(()) => info!("CET enabled for agent process"),
                Err(e) => warn!(error = %e, "Could not enable CET for agent process"),
            }
        }

        self.running.store(true, Ordering::SeqCst);

        // Start monitoring task
        self.start_monitoring_task();

        Ok(())
    }

    /// Start the background monitoring task
    fn start_monitoring_task(&self) {
        let running = self.running.clone();
        let config = self.config.clone();
        let tamper_tx = self.tamper_tx.clone();
        let process_cache = self.process_cache.clone();
        let bypass_count = self.bypass_count.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(config.check_interval_secs));

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                // Check for CET status changes and bypass attempts
                if config.detect_bypass_attempts {
                    Self::check_for_bypass_attempts(&tamper_tx, &process_cache, &bypass_count)
                        .await;
                }

                // Monitor process CET statuses
                if config.monitor_process_cet {
                    Self::update_process_cet_cache(&process_cache).await;
                }
            }

            debug!("CET monitoring task stopped");
        });
    }

    /// Check for CET bypass attempts
    async fn check_for_bypass_attempts(
        tamper_tx: &mpsc::Sender<TamperEvent>,
        process_cache: &Arc<tokio::sync::RwLock<HashMap<u32, ProcessCetStatus>>>,
        bypass_count: &Arc<std::sync::atomic::AtomicU64>,
    ) {
        let cache = process_cache.read().await;

        for (pid, old_status) in cache.iter() {
            // Re-check current status
            if let Ok(new_status) = get_process_cet_status(*pid) {
                // Detect if CET was disabled
                if old_status.shadow_stack_enabled && !new_status.shadow_stack_enabled {
                    warn!(
                        pid = *pid,
                        process = %old_status.process_name,
                        "CET disabled for process - potential bypass attempt"
                    );

                    bypass_count.fetch_add(1, Ordering::SeqCst);

                    let event = TamperEvent {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        event_type: TamperEventType::CriticalProcessViolation,
                        description: format!(
                            "CET Shadow Stack disabled for process {} (PID {})",
                            old_status.process_name, pid
                        ),
                        source_pid: Some(*pid),
                        source_process: Some(old_status.process_name.clone()),
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1562.001".to_string()), // Impair Defenses
                    };

                    if let Err(e) = tamper_tx.send(event).await {
                        error!(error = %e, "Failed to send CET bypass event");
                    }
                }

                // Detect strict mode downgrade
                if old_status.strict_mode && !new_status.strict_mode {
                    warn!(
                        pid = *pid,
                        process = %old_status.process_name,
                        "CET strict mode downgraded - potential evasion"
                    );

                    bypass_count.fetch_add(1, Ordering::SeqCst);

                    let event = TamperEvent {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        event_type: TamperEventType::CriticalProcessViolation,
                        description: format!(
                            "CET strict mode downgraded for process {} (PID {})",
                            old_status.process_name, pid
                        ),
                        source_pid: Some(*pid),
                        source_process: Some(old_status.process_name.clone()),
                        severity: TamperSeverity::High,
                        mitre_technique: Some("T1562.001".to_string()),
                    };

                    if let Err(e) = tamper_tx.send(event).await {
                        error!(error = %e, "Failed to send CET downgrade event");
                    }
                }
            }
        }
    }

    /// Update the process CET status cache
    async fn update_process_cet_cache(
        process_cache: &Arc<tokio::sync::RwLock<HashMap<u32, ProcessCetStatus>>>,
    ) {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let snapshot = unsafe {
            match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(e) => {
                    debug!(error = %e, "Failed to create process snapshot");
                    return;
                }
            }
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut cache = process_cache.write().await;

        unsafe {
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;

                    // Skip system processes
                    if pid > 4 {
                        if let Ok(status) = get_process_cet_status(pid) {
                            cache.insert(pid, status);
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

    /// Get current monitoring status
    pub async fn get_status(&self) -> CetMonitorStatus {
        let cache = self.process_cache.read().await;
        let support = is_cet_supported();

        let incompatible_count = cache
            .values()
            .filter(|s| !s.shadow_stack_enabled && s.error.is_none())
            .count() as u64;

        CetMonitorStatus {
            cet_support: support.clone(),
            agent_cet_status: get_current_process_cet_status().unwrap_or_default(),
            bypass_attempts_detected: self.bypass_count.load(Ordering::SeqCst),
            processes_monitored: cache.len() as u64,
            incompatible_processes: incompatible_count,
            last_check_timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ),
        }
    }

    /// Stop the monitoring engine
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("CET monitoring stopped");
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if a specific DLL is CET-compatible
///
/// CET-compatible binaries have EHCONT (exception handling continuation) metadata
/// in their PE header
pub fn is_dll_cet_compatible(dll_path: &str) -> Result<bool> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(dll_path)?;
    let mut header = [0u8; 1024]; // Read first KB for PE headers
    let bytes_read = file.read(&mut header)?;

    // A valid PE must have at least the DOS header (64 bytes) plus the e_lfanew
    // pointer to the PE header. Anything shorter is not a CET-compatible DLL.
    if bytes_read < 64 {
        return Ok(false);
    }

    // Check DOS signature
    if &header[0..2] != b"MZ" {
        return Ok(false);
    }

    // Get PE header offset from DOS header at offset 0x3C
    let pe_offset =
        u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as usize;

    if pe_offset + 4 > header.len() {
        return Ok(false);
    }

    // Check PE signature
    if &header[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Ok(false);
    }

    // Parse COFF header to find optional header
    let optional_header_offset = pe_offset + 24;

    // Check for PE32+ (64-bit)
    let magic = u16::from_le_bytes([
        header[optional_header_offset],
        header[optional_header_offset + 1],
    ]);
    let is_pe32plus = magic == 0x20b;

    // DllCharacteristics field contains CET compatibility flags
    // For PE32+, it's at offset 70 from optional header start
    // For PE32, it's at offset 62
    let dll_characteristics_offset = if is_pe32plus {
        optional_header_offset + 70
    } else {
        optional_header_offset + 62
    };

    if dll_characteristics_offset + 2 > header.len() {
        return Ok(false);
    }

    let dll_characteristics = u16::from_le_bytes([
        header[dll_characteristics_offset],
        header[dll_characteristics_offset + 1],
    ]);

    // IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000 (has CFG)
    // IMAGE_DLLCHARACTERISTICS_CET_COMPAT = 0x0004 (in extended characteristics)
    // For CET compatibility, typically check extended DLL characteristics
    // in the Load Config Directory

    // Simplified check: If CFG is enabled, it's more likely to be CET-compatible
    let has_cfg = (dll_characteristics & 0x4000) != 0;

    Ok(has_cfg)
}

/// Get a summary of system CET status for logging/reporting
pub fn get_cet_summary() -> String {
    let support = is_cet_supported();

    format!(
        "CET Status: CPU Shadow Stack={}, CPU IBT={}, OS Support={} (Build {}), \
         Process CET={}, Kernel CET={}, Mode={:?}",
        support.cpu_supports_shadow_stack,
        support.cpu_supports_ibt,
        support.os_supports_cet,
        support.windows_build,
        support.process_cet_enabled,
        support.kernel_cet_enabled,
        support.enforcement_mode,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_cet_detection() {
        let (ss, ibt) = check_cpuid_cet();
        println!("Shadow Stack supported: {}", ss);
        println!("IBT supported: {}", ibt);
        // Test passes regardless of actual support - just verifies detection works
    }

    #[test]
    fn test_cpu_vendor_detection() {
        let vendor = get_cpu_vendor();
        println!("CPU Vendor: {}", vendor);
        assert!(!vendor.is_empty());
    }

    #[test]
    fn test_cet_support_detection() {
        let support = is_cet_supported();
        println!("CET Support: {:?}", support);
        // Verify struct is properly populated
        assert!(support.windows_build > 0 || !cfg!(windows));
    }

    #[test]
    fn test_windows_version_detection() {
        let build = get_windows_build();
        println!("Windows Build: {}", build);
        // Should be non-zero on Windows
        if cfg!(windows) {
            assert!(build > 0);
        }
    }

    #[test]
    fn test_kernel_cet_check() {
        let enabled = check_kernel_cet_enabled();
        println!("Kernel CET enabled: {}", enabled);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_cet_summary() {
        let summary = get_cet_summary();
        println!("CET Summary: {}", summary);
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_user_shadow_stack_policy_flags() {
        let flags = UserShadowStackPolicyFlags { flags: 0x03 };
        assert!(flags.is_enabled());
        assert!(flags.is_strict());
        assert!(!flags.is_audit_only());

        let audit_flags = UserShadowStackPolicyFlags { flags: 0x04 };
        assert!(!audit_flags.is_enabled());
        assert!(audit_flags.is_audit_only());
    }

    #[test]
    fn test_process_cet_status() {
        // Test getting current process CET status
        if let Ok(status) = get_process_cet_status(std::process::id()) {
            println!("Current process CET status: {:?}", status);
        } else {
            println!("Could not get current process CET status (may require elevation)");
        }
    }
}
