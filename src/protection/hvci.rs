//! HVCI (Hypervisor-protected Code Integrity) Detection and Monitoring
//!
//! Detects and monitors the status of Windows Virtualization Based Security (VBS) features:
//! - HVCI (Hypervisor-protected Code Integrity)
//! - Credential Guard
//! - System Guard
//! - Secure Boot
//! - UEFI Lock
//!
//! HVCI provides kernel code integrity protection by using hardware virtualization
//! to isolate the code integrity service from the Windows kernel. This significantly
//! improves resistance to kernel-mode malware and rootkits.
//!
//! ## Detection Methods
//!
//! 1. **Registry** - DeviceGuard configuration keys
//! 2. **WMI** - Win32_DeviceGuard class queries
//! 3. **NtQuerySystemInformation** - SystemCodeIntegrityInformation
//!
//! ## Security Value
//!
//! - HVCI blocks unsigned drivers and many kernel-mode exploits
//! - Credential Guard protects LSASS credentials from theft
//! - System Guard validates system integrity at boot
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1014 - Rootkit (HVCI blocks many kernel rootkit techniques)
//! - T1068 - Exploitation for Privilege Escalation (HVCI mitigates kernel exploits)
//! - T1003 - OS Credential Dumping (Credential Guard protects credentials)

#![cfg(target_os = "windows")]
// This module mirrors the Win32_DeviceGuard / DeviceGuard registry surface
// (HVCI, Credential Guard, System Guard, Secure Boot states and codes). Many
// constants are documented values kept exhaustive for monitoring/reporting even
// when not currently dispatched.
#![allow(dead_code, non_snake_case, unused_unsafe)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{TamperEvent, TamperEventType, TamperSeverity};

// ============================================================================
// HVCI STATUS STRUCTURE
// ============================================================================

/// Comprehensive HVCI and VBS status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HvciStatus {
    /// Virtualization Based Security is enabled
    pub vbs_enabled: bool,
    /// HVCI (Hypervisor-protected Code Integrity) is running
    pub hvci_enabled: bool,
    /// HVCI is in enforcement mode (not just audit mode)
    pub hvci_enforced: bool,
    /// Secure Boot is enabled
    pub secure_boot_enabled: bool,
    /// HVCI configuration is locked in UEFI
    pub uefi_lock: bool,
    /// Credential Guard is enabled
    pub credential_guard: bool,
    /// System Guard (Secure Launch) is enabled
    pub system_guard: bool,
    /// VBS running status from WMI (0=not running, 1=not configurable, 2=running)
    pub vbs_running_status: u32,
    /// HVCI policy enforcement status from WMI (0=off, 1=audit, 2=enforce)
    pub hvci_policy_status: u32,
    /// Required security properties from registry
    pub required_security_properties: u32,
    /// Available security properties from registry
    pub available_security_properties: u32,
    /// Code integrity options from NtQuerySystemInformation
    pub code_integrity_options: u32,
    /// Whether hardware supports HVCI
    pub hardware_supported: bool,
    /// Reason if HVCI is not available
    pub unavailable_reason: Option<String>,
    /// Last check timestamp (Unix milliseconds)
    pub last_check: u64,
}

impl HvciStatus {
    /// Create a new status with current timestamp
    fn new() -> Self {
        Self {
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        }
    }

    /// Check if system has adequate protection level
    pub fn is_well_protected(&self) -> bool {
        self.hvci_enforced && self.secure_boot_enabled
    }

    /// Calculate a security posture score (0-100)
    pub fn security_score(&self) -> u32 {
        let mut score = 0u32;

        // Core protections (60 points max)
        if self.vbs_enabled {
            score += 15;
        }
        if self.hvci_enabled {
            score += 15;
        }
        if self.hvci_enforced {
            score += 10;
        }
        if self.secure_boot_enabled {
            score += 10;
        }
        if self.uefi_lock {
            score += 10;
        }

        // Additional protections (40 points max)
        if self.credential_guard {
            score += 20;
        }
        if self.system_guard {
            score += 15;
        }
        if self.hardware_supported {
            score += 5;
        }

        score.min(100)
    }

    /// Get human-readable status description
    pub fn description(&self) -> String {
        let mut parts = Vec::new();

        if self.hvci_enforced {
            parts.push("HVCI Enforced");
        } else if self.hvci_enabled {
            parts.push("HVCI Audit Mode");
        } else {
            parts.push("HVCI Disabled");
        }

        if self.vbs_enabled {
            parts.push("VBS Enabled");
        }

        if self.credential_guard {
            parts.push("Credential Guard");
        }

        if self.secure_boot_enabled {
            parts.push("Secure Boot");
        }

        if self.uefi_lock {
            parts.push("UEFI Locked");
        }

        parts.join(", ")
    }
}

// ============================================================================
// HVCI CONFIGURATION
// ============================================================================

/// Configuration for HVCI monitoring
#[derive(Debug, Clone)]
pub struct HvciConfig {
    /// Enable HVCI status monitoring
    pub enabled: bool,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Alert if HVCI is not enabled on supported hardware
    pub alert_if_disabled: bool,
    /// Alert if HVCI is disabled after being enabled
    pub alert_on_disable: bool,
    /// Alert if running in audit mode instead of enforcement
    pub alert_audit_mode: bool,
    /// Minimum security score to avoid alert (0-100)
    pub minimum_security_score: u32,
}

impl Default for HvciConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 300, // 5 minutes
            alert_if_disabled: true,
            alert_on_disable: true,
            alert_audit_mode: true,
            minimum_security_score: 50,
        }
    }
}

// ============================================================================
// REGISTRY KEYS AND VALUES
// ============================================================================

/// DeviceGuard registry path
const DEVICE_GUARD_KEY: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard";

/// DeviceGuard Scenarios registry path
const DEVICE_GUARD_SCENARIOS_KEY: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios";

/// HVCI Scenario key
const HVCI_SCENARIO_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";

/// Credential Guard Scenario key
const CREDENTIAL_GUARD_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard";

/// System Guard Launch key
const SYSTEM_GUARD_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard";

/// LSA protection registry key
const LSA_PROTECTION_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";

/// Secure Boot registry key
const SECURE_BOOT_KEY: &str = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State";

// ============================================================================
// CODE INTEGRITY FLAGS (from NtQuerySystemInformation)
// ============================================================================

/// Code integrity is enabled
const CODEINTEGRITY_OPTION_ENABLED: u32 = 0x01;

/// Test signing is enabled (debug/development mode)
const CODEINTEGRITY_OPTION_TESTSIGN: u32 = 0x02;

/// UMCI (User Mode Code Integrity) is enabled
const CODEINTEGRITY_OPTION_UMCI_ENABLED: u32 = 0x04;

/// UMCI audit mode (not enforcing)
const CODEINTEGRITY_OPTION_UMCI_AUDITMODE: u32 = 0x08;

/// HVCI is enabled
const CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED: u32 = 0x10;

/// HVCI audit mode
const CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE: u32 = 0x20;

/// HVCI strict mode
const CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED: u32 = 0x40;

/// HVCI IUM (Isolated User Mode) enabled
const CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED: u32 = 0x80;

// ============================================================================
// VBS STATUS VALUES (from WMI)
// ============================================================================

/// VBS not configured
const VBS_NOT_CONFIGURED: u32 = 0;

/// VBS reboot required
const VBS_REBOOT_REQUIRED: u32 = 1;

/// VBS running
const VBS_RUNNING: u32 = 2;

// ============================================================================
// HVCI MONITOR ENGINE
// ============================================================================

/// HVCI monitoring engine
pub struct HvciMonitor {
    config: HvciConfig,
    running: Arc<AtomicBool>,
    last_status: Arc<tokio::sync::RwLock<Option<HvciStatus>>>,
    tamper_tx: mpsc::Sender<TamperEvent>,
}

impl HvciMonitor {
    /// Create a new HVCI monitor
    pub fn new(config: HvciConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            last_status: Arc::new(tokio::sync::RwLock::new(None)),
            tamper_tx,
        }
    }

    /// Initialize HVCI monitoring
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("HVCI monitoring disabled by configuration");
            return Ok(());
        }

        info!("Initializing HVCI monitor");
        self.running.store(true, Ordering::SeqCst);

        // Perform initial status check
        let initial_status = get_hvci_status()?;
        self.evaluate_and_alert(&initial_status, None).await;

        // Store initial status
        {
            let mut last = self.last_status.write().await;
            *last = Some(initial_status);
        }

        // Start periodic monitoring
        self.start_monitoring_task();

        Ok(())
    }

    /// Start the background monitoring task
    fn start_monitoring_task(&self) {
        let running = self.running.clone();
        let last_status = self.last_status.clone();
        let tamper_tx = self.tamper_tx.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.check_interval_secs));

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                match get_hvci_status() {
                    Ok(current_status) => {
                        // Get previous status for comparison
                        let previous = {
                            let guard = last_status.read().await;
                            guard.clone()
                        };

                        // Evaluate changes and alert if necessary
                        Self::evaluate_and_alert_static(
                            &current_status,
                            previous.as_ref(),
                            &config,
                            &tamper_tx,
                        )
                        .await;

                        // Update stored status
                        {
                            let mut guard = last_status.write().await;
                            *guard = Some(current_status);
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to query HVCI status");
                    }
                }
            }

            debug!("HVCI monitor task stopped");
        });
    }

    /// Evaluate status and send alerts if needed
    async fn evaluate_and_alert(&self, current: &HvciStatus, previous: Option<&HvciStatus>) {
        Self::evaluate_and_alert_static(current, previous, &self.config, &self.tamper_tx).await;
    }

    /// Static version for use in spawned task
    async fn evaluate_and_alert_static(
        current: &HvciStatus,
        previous: Option<&HvciStatus>,
        config: &HvciConfig,
        tamper_tx: &mpsc::Sender<TamperEvent>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Alert if HVCI disabled on supported hardware
        if config.alert_if_disabled && current.hardware_supported && !current.hvci_enabled {
            let event = TamperEvent {
                timestamp: now,
                event_type: TamperEventType::ConfigTamper,
                description: format!(
                    "HVCI is not enabled on supported hardware. Security score: {}%. \
                     Recommendation: Enable HVCI in Windows Security settings for \
                     improved kernel protection against rootkits and exploits.",
                    current.security_score()
                ),
                source_pid: None,
                source_process: None,
                severity: TamperSeverity::Medium,
                mitre_technique: Some("T1014".to_string()),
            };

            if let Err(e) = tamper_tx.send(event).await {
                error!(error = %e, "Failed to send HVCI disabled alert");
            }
        }

        // Alert if HVCI was disabled after being enabled
        if config.alert_on_disable {
            if let Some(prev) = previous {
                if prev.hvci_enabled && !current.hvci_enabled {
                    let event = TamperEvent {
                        timestamp: now,
                        event_type: TamperEventType::ConfigTamper,
                        description: "HVCI has been disabled! This significantly reduces \
                             kernel protection and may indicate tampering or attack preparation."
                            .to_string(),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1562.001".to_string()),
                    };

                    if let Err(e) = tamper_tx.send(event).await {
                        error!(error = %e, "Failed to send HVCI disable alert");
                    }
                }

                // Alert if VBS was disabled
                if prev.vbs_enabled && !current.vbs_enabled {
                    let event = TamperEvent {
                        timestamp: now,
                        event_type: TamperEventType::ConfigTamper,
                        description: "Virtualization Based Security (VBS) has been disabled! \
                             This affects HVCI, Credential Guard, and other security features."
                            .to_string(),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1562.001".to_string()),
                    };

                    if let Err(e) = tamper_tx.send(event).await {
                        error!(error = %e, "Failed to send VBS disable alert");
                    }
                }

                // Alert if Credential Guard was disabled
                if prev.credential_guard && !current.credential_guard {
                    let event = TamperEvent {
                        timestamp: now,
                        event_type: TamperEventType::ConfigTamper,
                        description: "Credential Guard has been disabled! LSASS credentials \
                             are no longer protected by virtualization isolation."
                            .to_string(),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::High,
                        mitre_technique: Some("T1003".to_string()),
                    };

                    if let Err(e) = tamper_tx.send(event).await {
                        error!(error = %e, "Failed to send Credential Guard disable alert");
                    }
                }
            }
        }

        // Alert if running in audit mode
        if config.alert_audit_mode && current.hvci_enabled && !current.hvci_enforced {
            // Only alert once, check if previous was also audit mode
            let should_alert =
                previous.map_or(true, |prev| !(prev.hvci_enabled && !prev.hvci_enforced));

            if should_alert {
                let event = TamperEvent {
                    timestamp: now,
                    event_type: TamperEventType::ConfigTamper,
                    description: "HVCI is running in audit mode, not enforcement mode. \
                         Unsigned drivers are being logged but not blocked."
                        .to_string(),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Low,
                    mitre_technique: Some("T1014".to_string()),
                };

                if let Err(e) = tamper_tx.send(event).await {
                    error!(error = %e, "Failed to send HVCI audit mode alert");
                }
            }
        }

        // Alert if security score is below minimum
        let score = current.security_score();
        if score < config.minimum_security_score {
            // Only alert if score decreased or this is the first check
            let should_alert = previous.map_or(true, |prev| {
                prev.security_score() >= config.minimum_security_score
            });

            if should_alert {
                let event = TamperEvent {
                    timestamp: now,
                    event_type: TamperEventType::ConfigTamper,
                    description: format!(
                        "Security posture score ({}) is below minimum threshold ({}). \
                         Current status: {}. Consider enabling additional protections.",
                        score,
                        config.minimum_security_score,
                        current.description()
                    ),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Medium,
                    mitre_technique: None,
                };

                if let Err(e) = tamper_tx.send(event).await {
                    error!(error = %e, "Failed to send security score alert");
                }
            }
        }
    }

    /// Stop the monitor
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("HVCI monitor stopped");
    }

    /// Get current HVCI status
    pub async fn get_status(&self) -> Result<HvciStatus> {
        let guard = self.last_status.read().await;
        guard
            .clone()
            .ok_or_else(|| anyhow!("HVCI status not yet available"))
    }
}

// ============================================================================
// HVCI STATUS DETECTION FUNCTIONS
// ============================================================================

/// Get comprehensive HVCI and VBS status
///
/// Combines information from:
/// 1. Registry (DeviceGuard configuration)
/// 2. WMI (Win32_DeviceGuard class)
/// 3. NtQuerySystemInformation (SystemCodeIntegrityInformation)
pub fn get_hvci_status() -> Result<HvciStatus> {
    let mut status = HvciStatus::new();

    // Query registry for DeviceGuard configuration
    if let Err(e) = query_registry_status(&mut status) {
        debug!(error = %e, "Registry query for HVCI status failed");
    }

    // Query WMI for runtime status
    if let Err(e) = query_wmi_device_guard(&mut status) {
        debug!(error = %e, "WMI query for HVCI status failed");
    }

    // Query NtQuerySystemInformation for code integrity flags
    if let Err(e) = query_code_integrity_info(&mut status) {
        debug!(error = %e, "NtQuerySystemInformation for code integrity failed");
    }

    // Check Secure Boot status
    if let Err(e) = query_secure_boot_status(&mut status) {
        debug!(error = %e, "Secure Boot status query failed");
    }

    // Determine hardware support
    status.hardware_supported = check_hardware_support();

    // Determine unavailability reason if HVCI is not enabled
    if !status.hvci_enabled {
        status.unavailable_reason = determine_unavailability_reason(&status);
    }

    info!(
        vbs = status.vbs_enabled,
        hvci = status.hvci_enabled,
        enforced = status.hvci_enforced,
        credential_guard = status.credential_guard,
        secure_boot = status.secure_boot_enabled,
        score = status.security_score(),
        "HVCI status queried"
    );

    Ok(status)
}

/// Query registry for DeviceGuard configuration
fn query_registry_status(status: &mut HvciStatus) -> Result<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Query main DeviceGuard key
    if let Ok(key) = hklm.open_subkey_with_flags(DEVICE_GUARD_KEY, KEY_READ) {
        // EnableVirtualizationBasedSecurity
        if let Ok(value) = key.get_value::<u32, _>("EnableVirtualizationBasedSecurity") {
            status.vbs_enabled = value == 1;
        }

        // RequirePlatformSecurityFeatures
        if let Ok(value) = key.get_value::<u32, _>("RequirePlatformSecurityFeatures") {
            status.required_security_properties = value;
        }

        // HypervisorEnforcedCodeIntegrity (legacy location)
        if let Ok(value) = key.get_value::<u32, _>("HypervisorEnforcedCodeIntegrity") {
            if value == 1 {
                status.hvci_enabled = true;
            }
        }

        // Locked
        if let Ok(value) = key.get_value::<u32, _>("Locked") {
            status.uefi_lock = value == 1;
        }
    }

    // Query HVCI scenario
    if let Ok(key) = hklm.open_subkey_with_flags(HVCI_SCENARIO_KEY, KEY_READ) {
        if let Ok(value) = key.get_value::<u32, _>("Enabled") {
            status.hvci_enabled = value == 1;
        }

        if let Ok(value) = key.get_value::<u32, _>("Locked") {
            status.uefi_lock = value == 1;
        }
    }

    // Query Credential Guard scenario
    if let Ok(key) = hklm.open_subkey_with_flags(CREDENTIAL_GUARD_KEY, KEY_READ) {
        if let Ok(value) = key.get_value::<u32, _>("Enabled") {
            status.credential_guard = value == 1;
        }
    }

    // Query System Guard scenario
    if let Ok(key) = hklm.open_subkey_with_flags(SYSTEM_GUARD_KEY, KEY_READ) {
        if let Ok(value) = key.get_value::<u32, _>("Enabled") {
            status.system_guard = value == 1;
        }
    }

    Ok(())
}

/// Query WMI Win32_DeviceGuard class for runtime status
///
/// TODO: Implement WMI query using proper windows-rs API
/// The WMI IWbemClassObject::Get API signature changed in recent windows-rs versions.
/// For now, we rely on registry and NtQuerySystemInformation for HVCI detection.
fn query_wmi_device_guard(_status: &mut HvciStatus) -> Result<()> {
    // WMI query disabled - using registry and NtQuerySystemInformation instead
    // The full WMI implementation requires careful handling of VARIANT types
    // which has API changes between windows-rs versions.
    debug!("WMI DeviceGuard query skipped - using alternative detection methods");
    Ok(())
}

/// Query NtQuerySystemInformation for code integrity flags
fn query_code_integrity_info(status: &mut HvciStatus) -> Result<()> {
    use windows::core::{w, PCSTR};

    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    // SystemCodeIntegrityInformation = 103
    const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;

    #[repr(C)]
    struct SystemCodeIntegrityInformation {
        length: u32,
        code_integrity_options: u32,
    }

    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll"))?;

        type NtQuerySystemInformationFn = unsafe extern "system" fn(
            SystemInformationClass: u32,
            SystemInformation: *mut std::ffi::c_void,
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        let func = GetProcAddress(
            ntdll,
            PCSTR::from_raw(b"NtQuerySystemInformation\0".as_ptr()),
        );
        let nt_query: NtQuerySystemInformationFn = match func {
            Some(f) => std::mem::transmute(f),
            None => return Err(anyhow!("Failed to get NtQuerySystemInformation")),
        };

        let mut info = SystemCodeIntegrityInformation {
            length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            code_integrity_options: 0,
        };

        let mut return_length = 0u32;
        let ntstatus = nt_query(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            &mut return_length,
        );

        if ntstatus != 0 {
            return Err(anyhow!(
                "NtQuerySystemInformation failed: 0x{:08X}",
                ntstatus
            ));
        }

        status.code_integrity_options = info.code_integrity_options;

        // Parse the flags
        if info.code_integrity_options & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED != 0 {
            status.hvci_enabled = true;

            // Check if it's in strict/enforcement mode (not audit)
            if info.code_integrity_options & CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE == 0 {
                status.hvci_enforced = true;
            }
        }

        debug!(
            code_integrity_options = format!("0x{:08X}", info.code_integrity_options),
            "Code integrity options"
        );
    }

    Ok(())
}

/// Query Secure Boot status
fn query_secure_boot_status(status: &mut HvciStatus) -> Result<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    if let Ok(key) = hklm.open_subkey_with_flags(SECURE_BOOT_KEY, KEY_READ) {
        if let Ok(value) = key.get_value::<u32, _>("UEFISecureBootEnabled") {
            status.secure_boot_enabled = value == 1;
        }
    }

    // Alternative: Use GetFirmwareEnvironmentVariable to check UEFI variables
    // This requires SeSystemEnvironmentPrivilege

    Ok(())
}

/// Check if hardware supports HVCI
///
/// Uses CPUID to detect virtualization extensions (VT-x/AMD-V) and
/// Extended Page Tables (EPT/NPT) which are required for VBS/HVCI.
fn check_hardware_support() -> bool {
    // Check CPUID for virtualization and SLAT support
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;

        unsafe {
            // Check CPUID leaf 1 for virtualization support
            let cpuid1 = __cpuid(1);

            // ECX bit 5 = VMX (Intel VT-x)
            let vmx_supported = (cpuid1.ecx & (1 << 5)) != 0;

            // For AMD, check leaf 0x80000001, ECX bit 2 = SVM (AMD-V)
            let max_extended = __cpuid(0x80000000).eax;
            let svm_supported = if max_extended >= 0x80000001 {
                let cpuid_ext1 = __cpuid(0x80000001);
                (cpuid_ext1.ecx & (1 << 2)) != 0
            } else {
                false
            };

            let virt_supported = vmx_supported || svm_supported;

            // Check for SLAT (Second Level Address Translation)
            // Intel: EPT via CPUID or MSR (we can't read MSR from usermode)
            // AMD: NPT via CPUID leaf 0x8000000A, EDX bit 0
            //
            // Since we can't reliably detect SLAT from usermode without reading MSRs,
            // we'll check the registry for Device Guard's capability assessment
            let slat_supported = check_slat_via_registry();

            virt_supported && slat_supported
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // ARM64 has different virtualization requirements
        // Check registry for capability assessment
        check_slat_via_registry()
    }
}

/// Check SLAT support via registry (Device Guard capability info)
fn check_slat_via_registry() -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Check Device Guard available security properties
    // Bit 1 = SLAT available
    if let Ok(key) = hklm.open_subkey_with_flags(DEVICE_GUARD_KEY, KEY_READ) {
        if let Ok(props) = key.get_value::<u32, _>("AvailableSecurityProperties") {
            // Bit 1 indicates SLAT is available
            return (props & 0x02) != 0;
        }
    }

    // Alternative: Check via WMI results if registry doesn't have the value
    // If we can't determine, assume supported (let the OS decide)
    true
}

/// Determine why HVCI is not available
fn determine_unavailability_reason(status: &HvciStatus) -> Option<String> {
    if !status.hardware_supported {
        return Some("Hardware does not support virtualization or SLAT".to_string());
    }

    if !status.vbs_enabled {
        return Some("Virtualization Based Security (VBS) is not enabled".to_string());
    }

    if !status.secure_boot_enabled {
        return Some("Secure Boot is disabled".to_string());
    }

    // Check if test signing is enabled
    if status.code_integrity_options & CODEINTEGRITY_OPTION_TESTSIGN != 0 {
        return Some("Test signing mode is enabled".to_string());
    }

    None
}

// ============================================================================
// HVCI HEALTH METRICS
// ============================================================================

/// HVCI health metrics for inclusion in agent health reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HvciHealthMetrics {
    /// Whether HVCI status collection succeeded
    pub collection_success: bool,
    /// Current HVCI status
    pub status: HvciStatus,
    /// Security posture score (0-100)
    pub security_score: u32,
    /// Whether system meets minimum protection requirements
    pub meets_minimum_requirements: bool,
    /// Human-readable protection level
    pub protection_level: String,
}

impl HvciHealthMetrics {
    /// Collect HVCI health metrics
    pub fn collect() -> Self {
        match get_hvci_status() {
            Ok(status) => {
                let score = status.security_score();
                let level = if score >= 90 {
                    "Excellent"
                } else if score >= 70 {
                    "Good"
                } else if score >= 50 {
                    "Moderate"
                } else if score >= 25 {
                    "Limited"
                } else {
                    "Minimal"
                };

                Self {
                    collection_success: true,
                    security_score: score,
                    meets_minimum_requirements: status.is_well_protected(),
                    protection_level: level.to_string(),
                    status,
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to collect HVCI health metrics");
                Self {
                    collection_success: false,
                    status: HvciStatus::default(),
                    security_score: 0,
                    meets_minimum_requirements: false,
                    protection_level: "Unknown".to_string(),
                }
            }
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hvci_status_defaults() {
        let status = HvciStatus::new();
        assert!(!status.vbs_enabled);
        assert!(!status.hvci_enabled);
        assert!(!status.hvci_enforced);
        assert_eq!(status.security_score(), 0);
    }

    #[test]
    fn test_security_score_calculation() {
        let mut status = HvciStatus::new();

        // No protection
        assert_eq!(status.security_score(), 0);

        // VBS only
        status.vbs_enabled = true;
        assert_eq!(status.security_score(), 15);

        // VBS + HVCI
        status.hvci_enabled = true;
        assert_eq!(status.security_score(), 30);

        // VBS + HVCI enforced
        status.hvci_enforced = true;
        assert_eq!(status.security_score(), 40);

        // + Secure Boot
        status.secure_boot_enabled = true;
        assert_eq!(status.security_score(), 50);

        // + UEFI Lock
        status.uefi_lock = true;
        assert_eq!(status.security_score(), 60);

        // + Credential Guard
        status.credential_guard = true;
        assert_eq!(status.security_score(), 80);

        // + System Guard
        status.system_guard = true;
        assert_eq!(status.security_score(), 95);

        // + Hardware support
        status.hardware_supported = true;
        assert_eq!(status.security_score(), 100);
    }

    #[test]
    fn test_is_well_protected() {
        let mut status = HvciStatus::new();
        assert!(!status.is_well_protected());

        status.hvci_enforced = true;
        assert!(!status.is_well_protected());

        status.secure_boot_enabled = true;
        assert!(status.is_well_protected());
    }

    #[test]
    fn test_status_description() {
        let mut status = HvciStatus::new();
        let desc = status.description();
        assert!(desc.contains("HVCI Disabled"));

        status.hvci_enabled = true;
        let desc = status.description();
        assert!(desc.contains("HVCI Audit Mode"));

        status.hvci_enforced = true;
        let desc = status.description();
        assert!(desc.contains("HVCI Enforced"));
    }

    #[test]
    fn test_config_defaults() {
        let config = HvciConfig::default();
        assert!(config.enabled);
        assert!(config.alert_if_disabled);
        assert!(config.alert_on_disable);
        assert_eq!(config.minimum_security_score, 50);
    }

    #[test]
    fn test_get_hvci_status() {
        // This test may have different results depending on the system
        let result = get_hvci_status();
        assert!(result.is_ok());

        let status = result.unwrap();
        // Basic sanity checks
        assert!(status.last_check > 0);
    }

    #[test]
    fn test_hvci_health_metrics() {
        let metrics = HvciHealthMetrics::collect();
        // Should always succeed, even if data is empty
        assert!(metrics.collection_success);
        assert!(!metrics.protection_level.is_empty());
    }
}
