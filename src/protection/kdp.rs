//! # Kernel Data Protection (KDP) Status Detection and Monitoring
//!
//! This module provides comprehensive KDP (Kernel Data Protection) status detection
//! for Windows 10 20H1 (build 19041) and later systems. KDP is a security feature
//! that leverages Virtualization-Based Security (VBS) to protect kernel data from
//! modification by making certain regions of kernel memory read-only.
//!
//! ## What is KDP?
//!
//! Kernel Data Protection (KDP) is a Windows security feature introduced in Windows 10
//! version 2004 (20H1). It uses VBS and Hypervisor-protected Code Integrity (HVCI) to
//! mark certain kernel memory regions as read-only at the hypervisor level.
//!
//! Key benefits:
//! - Protects critical kernel data structures from rootkit modifications
//! - Prevents certain classes of kernel exploits
//! - Part of the Defense-in-Depth strategy with VBS, HVCI, and Credential Guard
//!
//! ## Requirements
//!
//! KDP requires:
//! - Windows 10 version 2004 (build 19041) or later
//! - VBS (Virtualization-Based Security) enabled
//! - HVCI (Hypervisor-protected Code Integrity) enabled
//! - Compatible hardware (SLAT, TPM 2.0 recommended)
//!
//! ## MITRE ATT&CK Coverage
//!
//! - **T1014** - Rootkit (KDP protects against kernel data manipulation)
//! - **T1562.001** - Disable or Modify Tools (detects missing security features)
//! - **T1211** - Exploitation for Defense Evasion (KDP bypass detection)
//!
//! ## Module Components
//!
//! 1. **Status Detection** - Queries current KDP state via registry and system calls
//! 2. **VBS Integration** - Checks VBS requirements for KDP
//! 3. **Health Reporting** - Provides security posture assessment
//! 4. **Alerting** - Generates alerts when KDP is disabled or bypassed
//! 5. **Driver Integration** - Communicates with kernel driver for region enumeration

// This module enumerates KDP region/protection type codes and registry-backed
// VBS prerequisites. Many constants are documented Windows reference values
// kept exhaustive for posture assessment even when not currently dispatched.
#![allow(dead_code, non_snake_case, unused_unsafe)]

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// =============================================================================
// KDP Status Structures
// =============================================================================

/// KDP protection type for protected regions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KdpProtectionType {
    /// Static read-only data protection
    StaticReadOnly = 0,
    /// Dynamic data protection (runtime allocated)
    DynamicReadOnly = 1,
    /// Code integrity protected region
    CodeIntegrity = 2,
    /// Secure kernel data
    SecureKernel = 3,
    /// Unknown protection type
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for KdpProtectionType {
    fn from(value: u32) -> Self {
        match value {
            0 => KdpProtectionType::StaticReadOnly,
            1 => KdpProtectionType::DynamicReadOnly,
            2 => KdpProtectionType::CodeIntegrity,
            3 => KdpProtectionType::SecureKernel,
            _ => KdpProtectionType::Unknown,
        }
    }
}

impl std::fmt::Display for KdpProtectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdpProtectionType::StaticReadOnly => write!(f, "StaticReadOnly"),
            KdpProtectionType::DynamicReadOnly => write!(f, "DynamicReadOnly"),
            KdpProtectionType::CodeIntegrity => write!(f, "CodeIntegrity"),
            KdpProtectionType::SecureKernel => write!(f, "SecureKernel"),
            KdpProtectionType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// KDP status information
#[derive(Debug, Clone, Default)]
pub struct KdpStatus {
    /// Whether the OS version supports KDP (Windows 10 20H1+ / build 19041+)
    pub os_supports_kdp: bool,
    /// Whether KDP is currently enabled and active
    pub kdp_enabled: bool,
    /// Whether VBS is required (and enabled) for KDP
    pub vbs_required: bool,
    /// VBS is currently running
    pub vbs_running: bool,
    /// HVCI (Hypervisor Code Integrity) is enabled
    pub hvci_enabled: bool,
    /// Number of protected data regions (if available via driver)
    pub protected_data_regions: u32,
    /// KDP is locked (cannot be disabled without reboot)
    pub kdp_locked: bool,
    /// Windows build number
    pub build_number: u32,
    /// Additional status flags from NtQuerySystemInformation
    pub raw_flags: u64,
    /// Last status check timestamp
    pub last_check_timestamp: u64,
}

/// A protected kernel data region (enumerated via driver)
#[derive(Debug, Clone)]
pub struct KdpRegion {
    /// Base virtual address of the region
    pub base: u64,
    /// Size of the region in bytes
    pub size: usize,
    /// Type of protection applied
    pub protection_type: KdpProtectionType,
    /// Owner module/driver name (if identifiable)
    pub owner: String,
    /// Additional flags
    pub flags: u32,
}

/// KDP health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdpHealthLevel {
    /// KDP is fully operational
    Healthy,
    /// KDP is supported but not enabled
    Degraded,
    /// KDP is not supported on this system
    Unsupported,
    /// Potential KDP bypass or tampering detected
    Compromised,
    /// Unable to determine KDP status
    Unknown,
}

impl std::fmt::Display for KdpHealthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdpHealthLevel::Healthy => write!(f, "Healthy"),
            KdpHealthLevel::Degraded => write!(f, "Degraded"),
            KdpHealthLevel::Unsupported => write!(f, "Unsupported"),
            KdpHealthLevel::Compromised => write!(f, "Compromised"),
            KdpHealthLevel::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Comprehensive KDP health report
#[derive(Debug, Clone)]
pub struct KdpHealth {
    /// Overall health level
    pub level: KdpHealthLevel,
    /// Current KDP status
    pub status: KdpStatus,
    /// Human-readable description
    pub description: String,
    /// Security recommendations
    pub recommendations: Vec<String>,
    /// MITRE ATT&CK technique if relevant
    pub mitre_technique: Option<String>,
}

// =============================================================================
// IOCTL Definitions for Driver Communication
// =============================================================================

/// Device type for Tamandua driver IOCTLs
const FILE_DEVICE_TAMANDUA: u32 = 0x8022;

/// IOCTL method: METHOD_BUFFERED = 0
const METHOD_BUFFERED: u32 = 0;

/// IOCTL access
const FILE_READ_ACCESS: u32 = 1;

/// Macro to construct IOCTL codes
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)
}

/// Base function code for KDP IOCTLs
const KDP_IOCTL_BASE: u32 = 0xA00;

/// Query KDP status from kernel driver.
///
/// Input: None
/// Output: `KdpStatusResponse` with detailed KDP state
///
/// The driver queries the kernel's internal KDP state and returns
/// comprehensive status information including protection flags and region counts.
pub const IOCTL_QUERY_KDP_STATUS: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    KDP_IOCTL_BASE,
    METHOD_BUFFERED,
    FILE_READ_ACCESS,
);

/// Enumerate KDP protected regions.
///
/// Input: `KdpRegionQuery` with offset and count
/// Output: Array of `KdpRegionInfo` structures
///
/// Returns information about protected kernel data regions. This requires
/// kernel-mode access and can only be performed via the driver.
pub const IOCTL_ENUMERATE_KDP_REGIONS: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    KDP_IOCTL_BASE + 1,
    METHOD_BUFFERED,
    FILE_READ_ACCESS,
);

/// Query VBS/HVCI status for KDP prerequisites.
///
/// Input: None
/// Output: `VbsStatusResponse` with VBS/HVCI state
///
/// Returns the status of Virtualization-Based Security features that
/// KDP depends on.
pub const IOCTL_QUERY_VBS_STATUS: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    KDP_IOCTL_BASE + 2,
    METHOD_BUFFERED,
    FILE_READ_ACCESS,
);

// =============================================================================
// Request/Response Structures for Driver Communication
// =============================================================================

/// KDP status response from driver
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KdpStatusResponse {
    /// NTSTATUS from the operation
    pub status: i32,
    /// KDP enabled flag
    pub kdp_enabled: u32,
    /// VBS running flag
    pub vbs_running: u32,
    /// HVCI enabled flag
    pub hvci_enabled: u32,
    /// Number of protected regions
    pub protected_region_count: u32,
    /// Raw KDP flags from kernel
    pub raw_flags: u64,
    /// Reserved
    pub reserved: [u32; 4],
}

/// KDP region query request
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KdpRegionQuery {
    /// Starting offset in region list
    pub offset: u32,
    /// Maximum number of regions to return
    pub count: u32,
    /// Reserved
    pub reserved: [u32; 2],
}

/// KDP region information from driver
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct KdpRegionInfo {
    /// Base virtual address
    pub base_address: u64,
    /// Region size in bytes
    pub size: u64,
    /// Protection type
    pub protection_type: u32,
    /// Additional flags
    pub flags: u32,
    /// Owner name (null-terminated, max 64 chars)
    pub owner_name: [u16; 64],
}

impl Default for KdpRegionInfo {
    fn default() -> Self {
        Self {
            base_address: 0,
            size: 0,
            protection_type: 0,
            flags: 0,
            owner_name: [0; 64],
        }
    }
}

// =============================================================================
// Windows Version Constants
// =============================================================================

/// Minimum Windows 10 build for KDP support (20H1 / version 2004)
const MIN_KDP_BUILD: u32 = 19041;

/// Windows 11 minimum build number
const WIN11_MIN_BUILD: u32 = 22000;

// =============================================================================
// NtQuerySystemInformation Constants and Structures
// =============================================================================

#[cfg(target_os = "windows")]
mod ntapi {
    /// SystemKernelVaShadowInformation class for NtQuerySystemInformation
    /// This returns Spectre/Meltdown mitigation status including VBS state
    pub const SYSTEM_KERNEL_VA_SHADOW_INFORMATION: u32 = 196;

    /// SystemSecureKernelProfileInformation for secure kernel info
    pub const SYSTEM_SECURE_KERNEL_PROFILE_INFORMATION: u32 = 210;

    /// SystemCodeIntegrityInformation
    pub const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;

    /// SystemDeviceGuardInformation (VBS/Device Guard status)
    pub const SYSTEM_DEVICE_GUARD_INFORMATION: u32 = 203;

    /// Code integrity flags
    pub const CODEINTEGRITY_OPTION_ENABLED: u32 = 0x01;
    pub const CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED: u32 = 0x400;
    pub const CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED: u32 = 0x2000;

    /// VBS flags
    pub const DEVICE_GUARD_VBS_RUNNING: u32 = 0x01;
    pub const DEVICE_GUARD_HVCI_CONFIGURED: u32 = 0x02;
    pub const DEVICE_GUARD_HVCI_ENFORCED: u32 = 0x04;
    pub const DEVICE_GUARD_KDP_ENABLED: u32 = 0x1000;
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Get the current KDP status.
///
/// Queries system information to determine whether KDP is supported and enabled.
/// This function works without requiring a kernel driver by querying registry
/// and system information directly.
///
/// # Returns
///
/// * `Ok(KdpStatus)` - Current KDP status information
/// * `Err` - If status cannot be determined
///
/// # Example
///
/// ```ignore
/// use protection::kdp::get_kdp_status;
///
/// let status = get_kdp_status()?;
/// if status.kdp_enabled {
///     println!("KDP is active with {} protected regions", status.protected_data_regions);
/// }
/// ```
#[cfg(target_os = "windows")]
pub fn get_kdp_status() -> Result<KdpStatus> {
    let mut status = KdpStatus::default();
    status.last_check_timestamp = current_timestamp();

    // Get Windows build number
    status.build_number = get_windows_build_number()?;
    status.os_supports_kdp = status.build_number >= MIN_KDP_BUILD;

    if !status.os_supports_kdp {
        debug!(
            build = status.build_number,
            min_required = MIN_KDP_BUILD,
            "Windows build does not support KDP"
        );
        return Ok(status);
    }

    // Check VBS/HVCI status via NtQuerySystemInformation
    let vbs_status = query_vbs_status()?;
    status.vbs_running = vbs_status.0;
    status.hvci_enabled = vbs_status.1;
    status.raw_flags = vbs_status.2;

    // VBS is required for KDP
    status.vbs_required = true;

    // Check registry for KDP configuration
    let (kdp_enabled, kdp_locked) = check_kdp_registry()?;
    status.kdp_enabled = kdp_enabled && status.vbs_running;
    status.kdp_locked = kdp_locked;

    // If we have driver access, query protected region count
    // For now, this returns 0 unless driver is available
    status.protected_data_regions = 0;

    debug!(
        build = status.build_number,
        kdp_enabled = status.kdp_enabled,
        vbs_running = status.vbs_running,
        hvci_enabled = status.hvci_enabled,
        "KDP status queried"
    );

    Ok(status)
}

#[cfg(not(target_os = "windows"))]
pub fn get_kdp_status() -> Result<KdpStatus> {
    Ok(KdpStatus {
        os_supports_kdp: false,
        kdp_enabled: false,
        vbs_required: false,
        vbs_running: false,
        hvci_enabled: false,
        protected_data_regions: 0,
        kdp_locked: false,
        build_number: 0,
        raw_flags: 0,
        last_check_timestamp: current_timestamp(),
    })
}

/// Enumerate KDP protected regions via kernel driver.
///
/// This function requires the Tamandua kernel driver to be loaded and
/// communicates via IOCTL to enumerate protected memory regions.
///
/// # Returns
///
/// * `Ok(Vec<KdpRegion>)` - List of protected regions
/// * `Err` - If driver is not available or enumeration fails
///
/// # Example
///
/// ```ignore
/// use protection::kdp::enumerate_kdp_regions;
///
/// let regions = enumerate_kdp_regions()?;
/// for region in regions {
///     println!("Protected region: 0x{:016X} - {} bytes ({})",
///         region.base, region.size, region.protection_type);
/// }
/// ```
#[cfg(target_os = "windows")]
pub fn enumerate_kdp_regions() -> Result<Vec<KdpRegion>> {
    // Check if driver is available
    if !is_driver_available() {
        return Err(anyhow!(
            "KDP region enumeration requires the Tamandua kernel driver. \
             Install and load the driver to enable this feature."
        ));
    }

    // STUB — DESIGN-DORMANT, not production. Even when is_driver_available() passes,
    // this returns an empty Vec (an Ok success) rather than performing the driver
    // IOCTL. Callers cannot distinguish "no protected regions" from "not implemented".
    // Missing: the IOCTL_QUERY_KDP_REGIONS round-trip with the kernel driver.
    debug!("KDP region enumeration via driver IOCTL is not yet implemented");

    Ok(Vec::new())
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_kdp_regions() -> Result<Vec<KdpRegion>> {
    Err(anyhow!("KDP is a Windows-only feature"))
}

/// Get comprehensive KDP health status.
///
/// Analyzes the current KDP state and returns a health assessment with
/// recommendations for improving security posture.
///
/// # Returns
///
/// `KdpHealth` containing:
/// - Overall health level (Healthy, Degraded, Unsupported, Compromised, Unknown)
/// - Current KDP status
/// - Human-readable description
/// - Security recommendations
///
/// # Example
///
/// ```ignore
/// use protection::kdp::get_kdp_health;
///
/// let health = get_kdp_health();
/// if health.level != KdpHealthLevel::Healthy {
///     println!("KDP Health: {} - {}", health.level, health.description);
///     for rec in &health.recommendations {
///         println!("  Recommendation: {}", rec);
///     }
/// }
/// ```
pub fn get_kdp_health() -> KdpHealth {
    match get_kdp_status() {
        Ok(status) => analyze_kdp_health(status),
        Err(e) => KdpHealth {
            level: KdpHealthLevel::Unknown,
            status: KdpStatus::default(),
            description: format!("Unable to determine KDP status: {}", e),
            recommendations: vec![
                "Ensure the agent is running with administrative privileges".to_string(),
                "Check if Windows security services are running".to_string(),
            ],
            mitre_technique: None,
        },
    }
}

/// Check if KDP should be enabled but is not.
///
/// Useful for alerting when a supported system has KDP disabled.
///
/// # Returns
///
/// * `true` - KDP is supported but not enabled (security risk)
/// * `false` - KDP is enabled, not supported, or status unknown
pub fn is_kdp_misconfigured() -> bool {
    if let Ok(status) = get_kdp_status() {
        status.os_supports_kdp && !status.kdp_enabled
    } else {
        false
    }
}

/// Check for potential KDP bypass indicators.
///
/// Looks for signs that KDP protection may have been bypassed or disabled.
///
/// # Returns
///
/// * `Some((description, mitre_technique))` - If bypass indicators found
/// * `None` - No bypass indicators detected
#[cfg(target_os = "windows")]
pub fn detect_kdp_bypass() -> Option<(String, String)> {
    // Check 1: KDP was enabled but VBS is now not running
    if let Ok(status) = get_kdp_status() {
        if status.os_supports_kdp {
            // VBS should be running if KDP was configured
            let (kdp_configured, _) = check_kdp_registry().unwrap_or((false, false));

            if kdp_configured && !status.vbs_running {
                return Some((
                    "KDP is configured but VBS is not running - possible bypass or tampering"
                        .to_string(),
                    "T1562.001".to_string(), // Disable or Modify Tools
                ));
            }

            // HVCI should be enabled for full KDP protection
            if kdp_configured && status.vbs_running && !status.hvci_enabled {
                return Some((
                    "KDP is enabled but HVCI is disabled - reduced protection".to_string(),
                    "T1211".to_string(), // Exploitation for Defense Evasion
                ));
            }
        }
    }

    // Check 2: Look for known KDP bypass techniques via registry
    if let Ok(bypass_detected) = check_kdp_bypass_registry() {
        if bypass_detected {
            return Some((
                "KDP bypass configuration detected in registry".to_string(),
                "T1562.001".to_string(),
            ));
        }
    }

    None
}

#[cfg(not(target_os = "windows"))]
pub fn detect_kdp_bypass() -> Option<(String, String)> {
    None
}

// =============================================================================
// KDP Monitor for Continuous Monitoring
// =============================================================================

/// KDP monitor for continuous status monitoring
pub struct KdpMonitor {
    /// Running flag
    running: Arc<AtomicBool>,
    /// Last known status
    last_status: Arc<std::sync::RwLock<KdpStatus>>,
    /// Alert callback sender
    alert_tx: Option<tokio::sync::mpsc::Sender<KdpAlert>>,
    /// Check interval in seconds
    check_interval_secs: u64,
    /// Alert on misconfiguration
    alert_on_misconfiguration: bool,
}

/// KDP alert event
#[derive(Debug, Clone)]
pub struct KdpAlert {
    /// Timestamp
    pub timestamp: u64,
    /// Alert type
    pub alert_type: KdpAlertType,
    /// Description
    pub description: String,
    /// MITRE technique
    pub mitre_technique: Option<String>,
    /// Current KDP status
    pub status: KdpStatus,
}

/// Types of KDP alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdpAlertType {
    /// KDP is not enabled on a supported system
    KdpNotEnabled,
    /// KDP was disabled after being enabled
    KdpDisabled,
    /// Potential KDP bypass detected
    BypassDetected,
    /// VBS is not running
    VbsNotRunning,
    /// HVCI is not enabled
    HvciNotEnabled,
    /// Status check failed
    StatusCheckFailed,
}

impl std::fmt::Display for KdpAlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdpAlertType::KdpNotEnabled => write!(f, "KDP_NOT_ENABLED"),
            KdpAlertType::KdpDisabled => write!(f, "KDP_DISABLED"),
            KdpAlertType::BypassDetected => write!(f, "KDP_BYPASS_DETECTED"),
            KdpAlertType::VbsNotRunning => write!(f, "VBS_NOT_RUNNING"),
            KdpAlertType::HvciNotEnabled => write!(f, "HVCI_NOT_ENABLED"),
            KdpAlertType::StatusCheckFailed => write!(f, "STATUS_CHECK_FAILED"),
        }
    }
}

impl KdpMonitor {
    /// Create a new KDP monitor
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            last_status: Arc::new(std::sync::RwLock::new(KdpStatus::default())),
            alert_tx: None,
            check_interval_secs: 60,
            alert_on_misconfiguration: true,
        }
    }

    /// Create a new KDP monitor with alert channel
    pub fn with_alerts(
        alert_tx: tokio::sync::mpsc::Sender<KdpAlert>,
        check_interval_secs: u64,
    ) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            last_status: Arc::new(std::sync::RwLock::new(KdpStatus::default())),
            alert_tx: Some(alert_tx),
            check_interval_secs,
            alert_on_misconfiguration: true,
        }
    }

    /// Start continuous monitoring
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("KDP monitor is already running"));
        }

        info!(interval = self.check_interval_secs, "Starting KDP monitor");
        self.running.store(true, Ordering::SeqCst);

        // Initial status check
        if let Ok(status) = get_kdp_status() {
            *self.last_status.write().unwrap_or_else(|e| e.into_inner()) = status.clone();

            // Check for initial misconfiguration
            if self.alert_on_misconfiguration && status.os_supports_kdp && !status.kdp_enabled {
                self.send_alert(KdpAlert {
                    timestamp: current_timestamp(),
                    alert_type: KdpAlertType::KdpNotEnabled,
                    description: "KDP is not enabled on this system but is supported".to_string(),
                    mitre_technique: Some("T1562.001".to_string()),
                    status,
                })
                .await;
            }
        }

        // Start monitoring task
        let running = self.running.clone();
        let last_status = self.last_status.clone();
        let alert_tx = self.alert_tx.clone();
        let interval_secs = self.check_interval_secs;
        let alert_on_misconfig = self.alert_on_misconfiguration;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                match get_kdp_status() {
                    Ok(current_status) => {
                        let prev_status = match last_status.read() {
                            Ok(s) => s.clone(),
                            Err(e) => {
                                error!(error = %e, "KDP last_status lock poisoned; stopping monitor");
                                break;
                            }
                        };

                        // Check for status changes
                        if prev_status.kdp_enabled && !current_status.kdp_enabled {
                            // KDP was disabled
                            warn!("KDP has been disabled");
                            if let Some(ref tx) = alert_tx {
                                let _ = tx
                                    .send(KdpAlert {
                                        timestamp: current_timestamp(),
                                        alert_type: KdpAlertType::KdpDisabled,
                                        description: "KDP was disabled after being enabled"
                                            .to_string(),
                                        mitre_technique: Some("T1562.001".to_string()),
                                        status: current_status.clone(),
                                    })
                                    .await;
                            }
                        }

                        if prev_status.vbs_running && !current_status.vbs_running {
                            // VBS stopped running
                            warn!("VBS is no longer running");
                            if let Some(ref tx) = alert_tx {
                                let _ = tx
                                    .send(KdpAlert {
                                        timestamp: current_timestamp(),
                                        alert_type: KdpAlertType::VbsNotRunning,
                                        description: "VBS has stopped running".to_string(),
                                        mitre_technique: Some("T1562.001".to_string()),
                                        status: current_status.clone(),
                                    })
                                    .await;
                            }
                        }

                        // Check for bypass
                        if let Some((desc, mitre)) = detect_kdp_bypass() {
                            error!(description = %desc, "Potential KDP bypass detected");
                            if let Some(ref tx) = alert_tx {
                                let _ = tx
                                    .send(KdpAlert {
                                        timestamp: current_timestamp(),
                                        alert_type: KdpAlertType::BypassDetected,
                                        description: desc,
                                        mitre_technique: Some(mitre),
                                        status: current_status.clone(),
                                    })
                                    .await;
                            }
                        }

                        match last_status.write() {
                            Ok(mut s) => *s = current_status,
                            Err(e) => {
                                error!(error = %e, "KDP last_status lock poisoned; stopping monitor");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to check KDP status");
                        if let Some(ref tx) = alert_tx {
                            let status_clone = match last_status.read() {
                                Ok(s) => s.clone(),
                                Err(e) => {
                                    error!(error = %e, "KDP last_status lock poisoned; stopping monitor");
                                    break;
                                }
                            };
                            let _ = tx
                                .send(KdpAlert {
                                    timestamp: current_timestamp(),
                                    alert_type: KdpAlertType::StatusCheckFailed,
                                    description: format!("KDP status check failed: {}", e),
                                    mitre_technique: None,
                                    status: status_clone,
                                })
                                .await;
                        }
                    }
                }
            }

            debug!("KDP monitor stopped");
        });

        Ok(())
    }

    /// Stop continuous monitoring
    pub fn stop(&self) {
        info!("Stopping KDP monitor");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get last known KDP status
    pub fn get_last_status(&self) -> KdpStatus {
        self.last_status
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    async fn send_alert(&self, alert: KdpAlert) {
        if let Some(ref tx) = self.alert_tx {
            if let Err(e) = tx.send(alert).await {
                error!(error = %e, "Failed to send KDP alert");
            }
        }
    }
}

impl Default for KdpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get Windows build number
#[cfg(target_os = "windows")]
fn get_windows_build_number() -> Result<u32> {
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

    unsafe {
        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };

        #[allow(deprecated)]
        if GetVersionExW(&mut version_info).is_ok() {
            Ok(version_info.dwBuildNumber)
        } else {
            // Fallback: Try to read from registry
            get_build_from_registry()
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_windows_build_number() -> Result<u32> {
    Ok(0)
}

/// Get build number from registry (fallback)
#[cfg(target_os = "windows")]
fn get_build_from_registry() -> Result<u32> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;

    // Try CurrentBuildNumber first (string), then CurrentBuild
    if let Ok(build_str) = key.get_value::<String, _>("CurrentBuildNumber") {
        if let Ok(build) = build_str.parse::<u32>() {
            return Ok(build);
        }
    }

    if let Ok(build_str) = key.get_value::<String, _>("CurrentBuild") {
        if let Ok(build) = build_str.parse::<u32>() {
            return Ok(build);
        }
    }

    Err(anyhow!("Could not determine Windows build number"))
}

/// Query VBS/HVCI status via NtQuerySystemInformation
#[cfg(target_os = "windows")]
fn query_vbs_status() -> Result<(bool, bool, u64)> {
    use ntapi::*;
    use windows::core::{w, PCSTR};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    // Structure for SYSTEM_CODEINTEGRITY_INFORMATION
    #[repr(C)]
    struct SystemCodeIntegrityInformation {
        length: u32,
        options: u32,
    }

    let mut vbs_running = false;
    let mut hvci_enabled = false;
    let mut raw_flags = 0u64;

    // Query Code Integrity information via dynamically loaded NtQuerySystemInformation
    unsafe {
        // Get ntdll handle
        let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
            Ok(h) => h,
            Err(e) => {
                debug!(error = %e, "Failed to get ntdll.dll handle");
                // Fall back to registry-only check
                if let Ok((vbs, kdp_flag)) = query_device_guard_status() {
                    return Ok((
                        vbs,
                        false,
                        if kdp_flag {
                            DEVICE_GUARD_KDP_ENABLED as u64
                        } else {
                            0
                        },
                    ));
                }
                return Ok((false, false, 0));
            }
        };

        // Define NtQuerySystemInformation function type
        type NtQuerySystemInformationFn = unsafe extern "system" fn(
            SystemInformationClass: u32,
            SystemInformation: *mut std::ffi::c_void,
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        // Get NtQuerySystemInformation address
        let func = GetProcAddress(
            ntdll,
            PCSTR::from_raw(b"NtQuerySystemInformation\0".as_ptr()),
        );
        let nt_query: NtQuerySystemInformationFn = match func {
            Some(f) => std::mem::transmute(f),
            None => {
                debug!("Failed to get NtQuerySystemInformation address");
                // Fall back to registry-only check
                if let Ok((vbs, kdp_flag)) = query_device_guard_status() {
                    return Ok((
                        vbs,
                        false,
                        if kdp_flag {
                            DEVICE_GUARD_KDP_ENABLED as u64
                        } else {
                            0
                        },
                    ));
                }
                return Ok((false, false, 0));
            }
        };

        let mut ci_info = SystemCodeIntegrityInformation {
            length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            options: 0,
        };
        let mut return_length = 0u32;

        let ntstatus = nt_query(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut ci_info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            &mut return_length,
        );

        if ntstatus == 0 {
            raw_flags = ci_info.options as u64;

            // Check for HVCI flags
            if ci_info.options & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED != 0 {
                hvci_enabled = true;
                vbs_running = true; // HVCI requires VBS
            }

            if ci_info.options & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED != 0 {
                hvci_enabled = true;
                vbs_running = true;
            }

            debug!(
                options = ci_info.options,
                hvci = hvci_enabled,
                "Code Integrity status queried"
            );
        } else {
            debug!(
                ntstatus = format!("0x{:08X}", ntstatus),
                "NtQuerySystemInformation for Code Integrity failed"
            );
        }
    }

    // Additional check: Query Device Guard status
    // This provides more accurate VBS status
    if let Ok((vbs, kdp_flag)) = query_device_guard_status() {
        vbs_running = vbs_running || vbs;
        if kdp_flag {
            raw_flags |= DEVICE_GUARD_KDP_ENABLED as u64;
        }
    }

    Ok((vbs_running, hvci_enabled, raw_flags))
}

#[cfg(not(target_os = "windows"))]
fn query_vbs_status() -> Result<(bool, bool, u64)> {
    Ok((false, false, 0))
}

/// Query Device Guard / VBS status
#[cfg(target_os = "windows")]
fn query_device_guard_status() -> Result<(bool, bool)> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Check VBS configuration
    let vbs_running =
        if let Ok(key) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\DeviceGuard") {
            // Check if VBS is enabled
            let enabled: u32 = key
                .get_value("EnableVirtualizationBasedSecurity")
                .unwrap_or(0);
            enabled == 1
        } else {
            false
        };

    // Check for KDP specific flag
    let kdp_enabled = if let Ok(key) = hklm
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDataProtection")
    {
        let enabled: u32 = key.get_value("Enabled").unwrap_or(0);
        enabled == 1
    } else {
        false
    };

    Ok((vbs_running, kdp_enabled))
}

/// Check KDP configuration in registry
#[cfg(target_os = "windows")]
fn check_kdp_registry() -> Result<(bool, bool)> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Primary KDP configuration location
    let kdp_path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDataProtection";

    match hklm.open_subkey(kdp_path) {
        Ok(key) => {
            let enabled: u32 = key.get_value("Enabled").unwrap_or(0);
            let locked: u32 = key.get_value("Locked").unwrap_or(0);

            debug!(
                enabled = enabled,
                locked = locked,
                "KDP registry configuration"
            );

            Ok((enabled == 1, locked == 1))
        }
        Err(_) => {
            // Key doesn't exist - KDP not configured
            debug!("KDP registry key not found - not configured");
            Ok((false, false))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn check_kdp_registry() -> Result<(bool, bool)> {
    Ok((false, false))
}

/// Check for KDP bypass indicators in registry
#[cfg(target_os = "windows")]
fn check_kdp_bypass_registry() -> Result<bool> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Check for test signing mode (potential bypass indicator)
    if let Ok(key) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\CI") {
        let test_signing: u32 = key.get_value("TestSigning").unwrap_or(0);
        if test_signing == 1 {
            warn!("Test signing mode is enabled - potential security risk");
            return Ok(true);
        }
    }

    // Check for disabled integrity checks
    if let Ok(key) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\DeviceGuard") {
        // Check if VBS was deliberately disabled
        let locked: u32 = key.get_value("Locked").unwrap_or(0);
        let enabled: u32 = key
            .get_value("EnableVirtualizationBasedSecurity")
            .unwrap_or(1);

        if locked == 1 && enabled == 0 {
            warn!("VBS is locked in disabled state");
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(target_os = "windows"))]
fn check_kdp_bypass_registry() -> Result<bool> {
    Ok(false)
}

/// Check if the Tamandua driver is available
#[cfg(target_os = "windows")]
fn is_driver_available() -> bool {
    // Check if driver device exists
    let driver_path = r"\\.\TamanduaDriver";

    // Simple existence check - actual implementation would try to open the device
    // For now, always return false since driver enumeration requires actual driver
    false
}

#[cfg(not(target_os = "windows"))]
fn is_driver_available() -> bool {
    false
}

/// Analyze KDP status and generate health report
fn analyze_kdp_health(status: KdpStatus) -> KdpHealth {
    let mut recommendations = Vec::new();
    let level: KdpHealthLevel;
    let description: String;
    let mut mitre_technique = None;

    if !status.os_supports_kdp {
        // Unsupported OS version
        level = KdpHealthLevel::Unsupported;
        description = format!(
            "Windows build {} does not support KDP (requires build {} or later)",
            status.build_number, MIN_KDP_BUILD
        );
        recommendations
            .push("Upgrade to Windows 10 version 2004 or later to enable KDP".to_string());
    } else if status.kdp_enabled && status.vbs_running && status.hvci_enabled {
        // Fully healthy
        level = KdpHealthLevel::Healthy;
        description = format!(
            "KDP is fully operational with {} protected regions",
            status.protected_data_regions
        );
    } else if status.kdp_enabled && status.vbs_running && !status.hvci_enabled {
        // Degraded - KDP enabled but HVCI not
        level = KdpHealthLevel::Degraded;
        description = "KDP is enabled but HVCI is not - reduced protection".to_string();
        mitre_technique = Some("T1211".to_string());
        recommendations
            .push("Enable HVCI (Memory Integrity) in Windows Security settings".to_string());
    } else if status.kdp_enabled && !status.vbs_running {
        // Compromised - KDP enabled but VBS not running
        level = KdpHealthLevel::Compromised;
        description = "KDP is configured but VBS is not running - protection inactive".to_string();
        mitre_technique = Some("T1562.001".to_string());
        recommendations
            .push("Investigate why VBS is not running (may indicate tampering)".to_string());
        recommendations.push("Check hardware compatibility for VBS".to_string());
    } else if !status.kdp_enabled && status.vbs_running {
        // Degraded - VBS running but KDP not configured
        level = KdpHealthLevel::Degraded;
        description = "VBS is running but KDP is not enabled".to_string();
        recommendations
            .push("Enable KDP via Group Policy or registry for additional protection".to_string());
    } else {
        // Degraded - Nothing enabled
        level = KdpHealthLevel::Degraded;
        description = "KDP and VBS are not enabled on this supported system".to_string();
        mitre_technique = Some("T1562.001".to_string());
        recommendations.push("Enable VBS (Virtualization Based Security) in BIOS/UEFI".to_string());
        recommendations.push("Enable Memory Integrity (HVCI) in Windows Security".to_string());
        recommendations.push("Enable KDP for kernel data protection".to_string());
    }

    // Add hardware recommendations if VBS is not running
    if status.os_supports_kdp && !status.vbs_running {
        recommendations
            .push("Ensure CPU supports virtualization extensions (VT-x/AMD-V)".to_string());
        recommendations
            .push("Ensure SLAT (Second Level Address Translation) is supported".to_string());
        recommendations.push("Enable TPM 2.0 for secure boot".to_string());
    }

    KdpHealth {
        level,
        status,
        description,
        recommendations,
        mitre_technique,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdp_protection_type_from_u32() {
        assert_eq!(
            KdpProtectionType::from(0),
            KdpProtectionType::StaticReadOnly
        );
        assert_eq!(
            KdpProtectionType::from(1),
            KdpProtectionType::DynamicReadOnly
        );
        assert_eq!(KdpProtectionType::from(2), KdpProtectionType::CodeIntegrity);
        assert_eq!(KdpProtectionType::from(3), KdpProtectionType::SecureKernel);
        assert_eq!(KdpProtectionType::from(999), KdpProtectionType::Unknown);
    }

    #[test]
    fn test_kdp_status_default() {
        let status = KdpStatus::default();
        assert!(!status.os_supports_kdp);
        assert!(!status.kdp_enabled);
        assert!(!status.vbs_running);
        assert_eq!(status.protected_data_regions, 0);
    }

    #[test]
    fn test_kdp_health_level_display() {
        assert_eq!(format!("{}", KdpHealthLevel::Healthy), "Healthy");
        assert_eq!(format!("{}", KdpHealthLevel::Degraded), "Degraded");
        assert_eq!(format!("{}", KdpHealthLevel::Unsupported), "Unsupported");
        assert_eq!(format!("{}", KdpHealthLevel::Compromised), "Compromised");
        assert_eq!(format!("{}", KdpHealthLevel::Unknown), "Unknown");
    }

    #[test]
    fn test_kdp_alert_type_display() {
        assert_eq!(
            format!("{}", KdpAlertType::KdpNotEnabled),
            "KDP_NOT_ENABLED"
        );
        assert_eq!(format!("{}", KdpAlertType::KdpDisabled), "KDP_DISABLED");
        assert_eq!(
            format!("{}", KdpAlertType::BypassDetected),
            "KDP_BYPASS_DETECTED"
        );
    }

    #[test]
    fn test_analyze_unsupported_health() {
        let status = KdpStatus {
            os_supports_kdp: false,
            kdp_enabled: false,
            vbs_required: false,
            vbs_running: false,
            hvci_enabled: false,
            protected_data_regions: 0,
            kdp_locked: false,
            build_number: 17763, // Windows 10 1809
            raw_flags: 0,
            last_check_timestamp: 0,
        };

        let health = analyze_kdp_health(status);
        assert_eq!(health.level, KdpHealthLevel::Unsupported);
        assert!(!health.recommendations.is_empty());
    }

    #[test]
    fn test_analyze_healthy_health() {
        let status = KdpStatus {
            os_supports_kdp: true,
            kdp_enabled: true,
            vbs_required: true,
            vbs_running: true,
            hvci_enabled: true,
            protected_data_regions: 42,
            kdp_locked: true,
            build_number: 22621, // Windows 11 22H2
            raw_flags: 0,
            last_check_timestamp: 0,
        };

        let health = analyze_kdp_health(status);
        assert_eq!(health.level, KdpHealthLevel::Healthy);
    }

    #[test]
    fn test_analyze_compromised_health() {
        let status = KdpStatus {
            os_supports_kdp: true,
            kdp_enabled: true,
            vbs_required: true,
            vbs_running: false, // VBS stopped!
            hvci_enabled: false,
            protected_data_regions: 0,
            kdp_locked: true,
            build_number: 22621,
            raw_flags: 0,
            last_check_timestamp: 0,
        };

        let health = analyze_kdp_health(status);
        assert_eq!(health.level, KdpHealthLevel::Compromised);
        assert!(health.mitre_technique.is_some());
    }

    #[test]
    fn test_kdp_monitor_default() {
        let monitor = KdpMonitor::default();
        assert!(!monitor.is_running());
    }

    #[test]
    fn test_ioctl_codes() {
        // Ensure IOCTL codes are unique
        assert_ne!(IOCTL_QUERY_KDP_STATUS, IOCTL_ENUMERATE_KDP_REGIONS);
        assert_ne!(IOCTL_ENUMERATE_KDP_REGIONS, IOCTL_QUERY_VBS_STATUS);
        assert_ne!(IOCTL_QUERY_KDP_STATUS, IOCTL_QUERY_VBS_STATUS);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_kdp_status() {
        // This test will run on Windows
        let result = get_kdp_status();
        assert!(result.is_ok());

        let status = result.unwrap();
        // Build number should be non-zero on Windows
        assert!(status.build_number > 0);
        println!("Windows build: {}", status.build_number);
        println!("KDP supported: {}", status.os_supports_kdp);
        println!("KDP enabled: {}", status.kdp_enabled);
        println!("VBS running: {}", status.vbs_running);
        println!("HVCI enabled: {}", status.hvci_enabled);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_kdp_health() {
        let health = get_kdp_health();
        println!("KDP Health: {}", health.level);
        println!("Description: {}", health.description);
        for rec in &health.recommendations {
            println!("  - {}", rec);
        }
    }
}
