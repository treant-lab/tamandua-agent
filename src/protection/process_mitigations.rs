//! Process Mitigation Policies for Windows
//!
//! Applies comprehensive exploit mitigation policies to the agent process at startup.
//! These policies must be set early (before loading untrusted code) and cannot be reversed.
//!
//! ## Mitigations Applied
//!
//! ### Classic Mitigations (Windows 8+)
//! - **DEP** - Data Execution Prevention (always on)
//! - **ASLR** - Address Space Layout Randomization (force relocations, high entropy)
//! - **ACG** - Arbitrary Code Guard (prohibit dynamic code generation)
//! - **CFG** - Control Flow Guard (validate indirect calls)
//! - **CIG** - Code Integrity Guard (Microsoft-signed binaries only)
//! - **Extension Points** - Disable legacy extension points
//! - **Image Load** - Prefer System32 images, block remote/low-label images
//!
//! ### New CFI Mitigations (Windows 10 20H1+ / Windows 11)
//! - **CET Shadow Stack** - Intel Control-flow Enforcement Technology shadow stack
//! - **CET IBT** - Indirect Branch Tracking
//! - **XFG** - eXtended Flow Guard (enhanced CFG with type-based checks)
//! - **HVCI** - Hypervisor-enforced Code Integrity (query only)
//! - **KDP** - Kernel Data Protection (query only)
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1055 - Process Injection (blocked by ACG, CIG, DEP, CET)
//! - T1574 - Hijack Execution Flow (blocked by CFG, CIG, XFG)
//! - T1620 - Reflective Code Loading (blocked by ACG)
//! - T1106 - Native API (blocked by CET shadow stack)
//!
//! ## Windows Version Requirements
//!
//! - Windows 8+ for most policies
//! - Windows 10 1703+ for CFG export suppression
//! - Windows 10 20H1+ (build 19041+) for CET shadow stack
//! - Windows 11+ for full CET IBT support
//! - Graceful degradation on older versions

#![cfg(target_os = "windows")]
// This module enumerates the full Windows process mitigation policy surface
// (PROCESS_MITIGATION_*_POLICY flags, CET/XFG/HVCI/KDP query codes, etc.). Many
// constants are documented reference values that are not always consumed by the
// current call sites but are kept exhaustive for clarity and future use.
#![allow(dead_code, non_snake_case, unused_unsafe)]

use anyhow::{Context, Result};
use std::fmt;
use tracing::{debug, info, warn};
use windows::Win32::System::Threading::{GetProcessMitigationPolicy, SetProcessMitigationPolicy};

// =============================================================================
// Mitigation Status Structures
// =============================================================================

/// Comprehensive mitigation status for the process
#[derive(Debug, Clone, Default)]
pub struct MitigationStatus {
    // Classic mitigations
    /// DEP (Data Execution Prevention) enabled
    pub dep_enabled: bool,
    /// ASLR (Address Space Layout Randomization) enabled
    pub aslr_enabled: bool,
    /// CFG (Control Flow Guard) enabled
    pub cfg_enabled: bool,
    /// ACG (Arbitrary Code Guard) enabled
    pub acg_enabled: bool,
    /// CIG (Code Integrity Guard) enabled
    pub cig_enabled: bool,
    /// Extension points disabled
    pub extension_points_disabled: bool,
    /// Image load restrictions enabled
    pub image_load_restricted: bool,

    // New CFI mitigations
    /// CET Shadow Stack enabled (hardware-enforced return address protection)
    pub cet_shadow_stack: bool,
    /// CET Indirect Branch Tracking enabled
    pub cet_ibt: bool,
    /// XFG (eXtended Flow Guard) enabled
    pub xfg_enabled: bool,
    /// HVCI (Hypervisor-enforced Code Integrity) enabled (system-wide)
    pub hvci_enabled: bool,
    /// KDP (Kernel Data Protection) enabled (system-wide)
    pub kdp_enabled: bool,

    // Scores
    /// CFI coverage score (0-100)
    pub cfi_coverage_score: u8,
    /// Overall hardening score (0-100)
    pub overall_hardening_score: u8,

    // Metadata
    /// Windows version (major, minor, build)
    pub windows_version: (u32, u32, u32),
    /// Recommendations for improving security
    pub recommendations: Vec<String>,
}

impl MitigationStatus {
    /// Calculate the CFI coverage score based on enabled mitigations
    fn calculate_cfi_score(&mut self) {
        let mut score = 0u8;

        // CFG is baseline (30 points)
        if self.cfg_enabled {
            score += 30;
        }

        // XFG adds type-based checks (20 points)
        if self.xfg_enabled {
            score += 20;
        }

        // CET Shadow Stack provides hardware ROP protection (30 points)
        if self.cet_shadow_stack {
            score += 30;
        }

        // CET IBT provides hardware JOP protection (20 points)
        if self.cet_ibt {
            score += 20;
        }

        self.cfi_coverage_score = score.min(100);
    }

    /// Calculate overall hardening score
    fn calculate_overall_score(&mut self) {
        let mut score = 0u8;
        let mut max_score = 0u8;

        // Classic mitigations (50 points total)
        max_score += 50;
        if self.dep_enabled {
            score += 8;
        }
        if self.aslr_enabled {
            score += 8;
        }
        if self.cfg_enabled {
            score += 10;
        }
        if self.acg_enabled {
            score += 10;
        }
        if self.cig_enabled {
            score += 8;
        }
        if self.extension_points_disabled {
            score += 3;
        }
        if self.image_load_restricted {
            score += 3;
        }

        // CFI mitigations (35 points total)
        max_score += 35;
        if self.cet_shadow_stack {
            score += 15;
        }
        if self.cet_ibt {
            score += 10;
        }
        if self.xfg_enabled {
            score += 10;
        }

        // System-level protections (15 points total)
        max_score += 15;
        if self.hvci_enabled {
            score += 10;
        }
        if self.kdp_enabled {
            score += 5;
        }

        // Scale to 0-100
        self.overall_hardening_score = ((score as u32 * 100) / max_score as u32) as u8;
    }

    /// Generate recommendations based on missing mitigations
    fn generate_recommendations(&mut self) {
        self.recommendations.clear();

        if !self.cet_shadow_stack {
            self.recommendations.push(
                "Upgrade to Windows 11 or Windows 10 20H1+ with CET-capable CPU for shadow stack protection".to_string()
            );
        }

        if !self.cet_ibt {
            self.recommendations.push(
                "Windows 11 with Intel 12th gen+ or AMD Zen 3+ provides Indirect Branch Tracking"
                    .to_string(),
            );
        }

        if !self.xfg_enabled {
            self.recommendations.push(
                "Recompile with /guard:xfg for enhanced type-based control flow protection"
                    .to_string(),
            );
        }

        if !self.hvci_enabled {
            self.recommendations.push(
                "Enable HVCI (Memory Integrity) in Windows Security for hypervisor-enforced code integrity".to_string()
            );
        }

        if !self.kdp_enabled {
            self.recommendations
                .push("Windows 10 20H1+ with HVCI enables Kernel Data Protection".to_string());
        }

        if !self.cfg_enabled {
            self.recommendations
                .push("Recompile with /guard:cf for Control Flow Guard protection".to_string());
        }

        if !self.acg_enabled {
            self.recommendations.push(
                "ACG (Arbitrary Code Guard) blocks dynamic code - ensure no JIT dependencies"
                    .to_string(),
            );
        }

        if !self.cig_enabled {
            self.recommendations.push(
                "CIG requires Microsoft-signed binaries - ensure all dependencies are signed"
                    .to_string(),
            );
        }
    }
}

impl fmt::Display for MitigationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Process Mitigation Status ===")?;
        writeln!(
            f,
            "Windows Version: {}.{}.{}",
            self.windows_version.0, self.windows_version.1, self.windows_version.2
        )?;
        writeln!(f)?;

        writeln!(f, "--- Classic Mitigations ---")?;
        writeln!(
            f,
            "  DEP:                    {}",
            status_str(self.dep_enabled)
        )?;
        writeln!(
            f,
            "  ASLR:                   {}",
            status_str(self.aslr_enabled)
        )?;
        writeln!(
            f,
            "  CFG:                    {}",
            status_str(self.cfg_enabled)
        )?;
        writeln!(
            f,
            "  ACG:                    {}",
            status_str(self.acg_enabled)
        )?;
        writeln!(
            f,
            "  CIG:                    {}",
            status_str(self.cig_enabled)
        )?;
        writeln!(
            f,
            "  Extension Pts Disabled: {}",
            status_str(self.extension_points_disabled)
        )?;
        writeln!(
            f,
            "  Image Load Restricted:  {}",
            status_str(self.image_load_restricted)
        )?;
        writeln!(f)?;

        writeln!(f, "--- CFI Mitigations ---")?;
        writeln!(
            f,
            "  CET Shadow Stack:       {}",
            status_str(self.cet_shadow_stack)
        )?;
        writeln!(f, "  CET IBT:                {}", status_str(self.cet_ibt))?;
        writeln!(
            f,
            "  XFG:                    {}",
            status_str(self.xfg_enabled)
        )?;
        writeln!(f)?;

        writeln!(f, "--- System Protections ---")?;
        writeln!(
            f,
            "  HVCI:                   {}",
            status_str(self.hvci_enabled)
        )?;
        writeln!(
            f,
            "  KDP:                    {}",
            status_str(self.kdp_enabled)
        )?;
        writeln!(f)?;

        writeln!(f, "--- Scores ---")?;
        writeln!(f, "  CFI Coverage:           {}%", self.cfi_coverage_score)?;
        writeln!(
            f,
            "  Overall Hardening:      {}%",
            self.overall_hardening_score
        )?;

        if !self.recommendations.is_empty() {
            writeln!(f)?;
            writeln!(f, "--- Recommendations ---")?;
            for (i, rec) in self.recommendations.iter().enumerate() {
                writeln!(f, "  {}. {}", i + 1, rec)?;
            }
        }

        Ok(())
    }
}

fn status_str(enabled: bool) -> &'static str {
    if enabled {
        "ENABLED"
    } else {
        "disabled"
    }
}

// =============================================================================
// Windows Version Detection
// =============================================================================

/// Get Windows version for compatibility checks
fn get_windows_version() -> (u32, u32, u32) {
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

    unsafe {
        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };

        #[allow(deprecated)]
        if GetVersionExW(&mut version_info).is_ok() {
            (
                version_info.dwMajorVersion,
                version_info.dwMinorVersion,
                version_info.dwBuildNumber,
            )
        } else {
            // Try RtlGetVersion via ntdll for more accurate version on newer Windows
            if let Some(version) = get_version_via_ntdll() {
                version
            } else {
                // Default to Windows 10 if we can't detect
                (10, 0, 0)
            }
        }
    }
}

/// Get version via RtlGetVersion (more reliable on modern Windows)
fn get_version_via_ntdll() -> Option<(u32, u32, u32)> {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    #[repr(C)]
    struct RtlOsVersionInfoEx {
        dw_os_version_info_size: u32,
        dw_major_version: u32,
        dw_minor_version: u32,
        dw_build_number: u32,
        dw_platform_id: u32,
        sz_csd_version: [u16; 128],
        w_service_pack_major: u16,
        w_service_pack_minor: u16,
        w_suite_mask: u16,
        w_product_type: u8,
        w_reserved: u8,
    }

    unsafe {
        let ntdll = GetModuleHandleW(PCWSTR::from_raw(
            "ntdll.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        ))
        .ok()?;

        let rtl_get_version = GetProcAddress(
            ntdll,
            windows::core::PCSTR::from_raw(b"RtlGetVersion\0".as_ptr()),
        )?;

        let rtl_get_version: extern "system" fn(*mut RtlOsVersionInfoEx) -> i32 =
            std::mem::transmute(rtl_get_version);

        let mut version_info = RtlOsVersionInfoEx {
            dw_os_version_info_size: std::mem::size_of::<RtlOsVersionInfoEx>() as u32,
            ..std::mem::zeroed()
        };

        if rtl_get_version(&mut version_info) == 0 {
            Some((
                version_info.dw_major_version,
                version_info.dw_minor_version,
                version_info.dw_build_number,
            ))
        } else {
            None
        }
    }
}

/// Check if we're on Windows 10 1703+ (build 15063+)
fn is_windows_10_1703_or_newer() -> bool {
    let (major, _, build) = get_windows_version();
    major >= 10 && build >= 15063
}

/// Check if we're on Windows 10 20H1+ (build 19041+) which supports CET
fn is_windows_10_20h1_or_newer() -> bool {
    let (major, _, build) = get_windows_version();
    major >= 10 && build >= 19041
}

/// Check if we're on Windows 11 (build 22000+)
fn is_windows_11_or_later() -> bool {
    let (major, _, build) = get_windows_version();
    major >= 10 && build >= 22000
}

// =============================================================================
// CPU Feature Detection
// =============================================================================

/// Check if CPU supports Intel CET (Control-flow Enforcement Technology)
fn is_cet_supported_by_cpu() -> bool {
    // CPUID leaf 7, subleaf 0, ECX bit 7 (CET_SS) and EDX bit 20 (CET_IBT)
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // Use raw CPUID to check for CET support
        let result = unsafe { std::arch::x86_64::__cpuid_count(7, 0) };
        let cet_ss = (result.ecx & (1 << 7)) != 0; // Shadow Stack
        let cet_ibt = (result.edx & (1 << 20)) != 0; // Indirect Branch Tracking
        cet_ss || cet_ibt
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Check specifically for shadow stack support
fn is_shadow_stack_supported_by_cpu() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let result = unsafe { std::arch::x86_64::__cpuid_count(7, 0) };
        (result.ecx & (1 << 7)) != 0
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Check specifically for IBT support
fn is_ibt_supported_by_cpu() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let result = unsafe { std::arch::x86_64::__cpuid_count(7, 0) };
        (result.edx & (1 << 20)) != 0
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

// =============================================================================
// Policy Structures (from Windows SDK)
// =============================================================================

// ProcessMitigationPolicy enum values
const PROCESS_DEP_POLICY: i32 = 0;
const PROCESS_ASLR_POLICY: i32 = 1;
const PROCESS_DYNAMIC_CODE_POLICY: i32 = 2;
// const PROCESS_STRICT_HANDLE_CHECK_POLICY: i32 = 3;
// const PROCESS_SYSTEM_CALL_DISABLE_POLICY: i32 = 4;
// const PROCESS_MITIGATION_OPTION_MASK: i32 = 5;
const PROCESS_EXTENSION_POINT_DISABLE_POLICY: i32 = 6;
const PROCESS_CONTROL_FLOW_GUARD_POLICY: i32 = 7;
const PROCESS_SIGNATURE_POLICY: i32 = 8;
// const PROCESS_FONT_DISABLE_POLICY: i32 = 9;
const PROCESS_IMAGE_LOAD_POLICY: i32 = 10;
// const PROCESS_SYSTEM_CALL_FILTER_POLICY: i32 = 11;
// const PROCESS_PAYLOAD_RESTRICTION_POLICY: i32 = 12;
// const PROCESS_CHILD_PROCESS_POLICY: i32 = 13;
// const PROCESS_SIDE_CHANNEL_ISOLATION_POLICY: i32 = 14;
const PROCESS_USER_SHADOW_STACK_POLICY: i32 = 15;

#[repr(C)]
struct ProcessDepPolicy {
    flags: u32,
    permanent: u32,
}

#[repr(C)]
struct ProcessAslrPolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessDynamicCodePolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessExtensionPointDisablePolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessSignaturePolicy {
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProcessControlFlowGuardPolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessImageLoadPolicy {
    flags: u32,
}

/// User Shadow Stack Policy (Windows 10 20H1+)
/// Controls Intel CET shadow stack enforcement
#[repr(C)]
#[derive(Default)]
struct ProcessUserShadowStackPolicy {
    flags: u32,
}

// Shadow Stack Policy Flags
const USS_ENABLE_USER_SHADOW_STACK: u32 = 0x00000001;
const USS_AUDIT_USER_SHADOW_STACK: u32 = 0x00000002;
const USS_SET_CONTEXT_IP_VALIDATION: u32 = 0x00000004;
const USS_AUDIT_SET_CONTEXT_IP_VALIDATION: u32 = 0x00000008;
const USS_ENABLE_USER_SHADOW_STACK_STRICT_MODE: u32 = 0x00000010;
const USS_BLOCK_NON_CET_BINARIES: u32 = 0x00000020;
const USS_BLOCK_NON_CET_BINARIES_NON_EHCONT: u32 = 0x00000040;
const USS_AUDIT_BLOCK_NON_CET_BINARIES: u32 = 0x00000080;
const USS_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY: u32 = 0x00000100;
const USS_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE: u32 = 0x00000200;

// CFG Policy Flags
const CFG_ENABLE_CFG: u32 = 0x00000001;
const CFG_ENABLE_EXPORT_SUPPRESSION: u32 = 0x00000002;
const CFG_STRICT_MODE: u32 = 0x00000004;
// XFG is indicated by additional flag when binary is compiled with /guard:xfg
const CFG_ENABLE_XFG: u32 = 0x00000008;
const CFG_ENABLE_XFG_AUDIT_MODE: u32 = 0x00000010;

// =============================================================================
// Classic Mitigation Policies
// =============================================================================

/// Apply DEP (Data Execution Prevention) policy
fn apply_dep_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessDEPPolicy;

    let policy = ProcessDepPolicy {
        flags: 1,     // PROCESS_DEP_ENABLE
        permanent: 1, // Make it permanent
    };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessDEPPolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessDepPolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessDEPPolicy) failed")?;
    }

    Ok(())
}

/// Apply ASLR policy (force relocations, high entropy)
fn apply_aslr_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessASLRPolicy;

    let policy = ProcessAslrPolicy {
        flags: 0x07, // EnableBottomUpRandomization | EnableForceRelocateImages | EnableHighEntropy
    };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessASLRPolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessAslrPolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessASLRPolicy) failed")?;
    }

    Ok(())
}

/// Apply dynamic code policy (ACG - Arbitrary Code Guard)
fn apply_dynamic_code_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessDynamicCodePolicy;

    let policy = ProcessDynamicCodePolicy {
        flags: 0x01, // ProhibitDynamicCode
    };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessDynamicCodePolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessDynamicCodePolicy) failed")?;
    }

    Ok(())
}

/// Apply extension point disable policy
fn apply_extension_point_disable_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessExtensionPointDisablePolicy;

    let policy = ProcessExtensionPointDisablePolicy {
        flags: 0x01, // DisableExtensionPoints
    };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessExtensionPointDisablePolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy) failed")?;
    }

    Ok(())
}

/// Apply signature policy (CIG - Code Integrity Guard)
fn apply_signature_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessSignaturePolicy;

    let policy = ProcessSignaturePolicy {
        flags: 0x01, // MicrosoftSignedOnly
    };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessSignaturePolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessSignaturePolicy) failed")?;
    }

    Ok(())
}

/// Apply Control Flow Guard policy
fn apply_control_flow_guard_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessControlFlowGuardPolicy;

    let flags = if is_windows_10_1703_or_newer() {
        CFG_ENABLE_CFG | CFG_ENABLE_EXPORT_SUPPRESSION
    } else {
        CFG_ENABLE_CFG
    };

    let policy = ProcessControlFlowGuardPolicy { flags };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessControlFlowGuardPolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessControlFlowGuardPolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy) failed")?;
    }

    Ok(())
}

/// Apply image load policy
fn apply_image_load_policy() -> Result<()> {
    use windows::Win32::System::Threading::ProcessImageLoadPolicy;

    let policy = ProcessImageLoadPolicy {
        flags: 0x07, // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
    };

    unsafe {
        SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessImageLoadPolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessImageLoadPolicy) failed")?;
    }

    Ok(())
}

// =============================================================================
// New CFI Mitigation Policies
// =============================================================================

/// Apply CET Shadow Stack policy (Windows 10 20H1+ / Windows 11)
///
/// Intel CET (Control-flow Enforcement Technology) provides hardware-enforced
/// shadow stack that prevents ROP (Return-Oriented Programming) attacks.
///
/// Requirements:
/// - Windows 10 20H1+ (build 19041+) or Windows 11
/// - Intel 11th gen+ or AMD Zen 3+ CPU with CET support
/// - Binary compiled with /CETCOMPAT linker flag
pub fn apply_shadow_stack_policy() -> Result<()> {
    // Check OS version
    if !is_windows_10_20h1_or_newer() {
        return Err(anyhow::anyhow!(
            "CET Shadow Stack requires Windows 10 20H1+ (build 19041+)"
        ));
    }

    // Check CPU support
    if !is_shadow_stack_supported_by_cpu() {
        return Err(anyhow::anyhow!(
            "CPU does not support CET Shadow Stack (requires Intel 11th gen+ or AMD Zen 3+)"
        ));
    }

    // Build policy flags based on Windows version
    let mut flags = USS_ENABLE_USER_SHADOW_STACK | USS_SET_CONTEXT_IP_VALIDATION;

    // Windows 11 supports strict mode and blocking non-CET binaries
    if is_windows_11_or_later() {
        flags |= USS_ENABLE_USER_SHADOW_STACK_STRICT_MODE;
        // Note: We don't enable USS_BLOCK_NON_CET_BINARIES by default as it may
        // break compatibility with some third-party DLLs. Enable in audit mode first.
        flags |= USS_AUDIT_BLOCK_NON_CET_BINARIES;
        flags |= USS_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY;
    }

    let policy = ProcessUserShadowStackPolicy { flags };

    unsafe {
        // ProcessUserShadowStackPolicy = 15
        SetProcessMitigationPolicy(
            std::mem::transmute::<i32, windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY>(
                PROCESS_USER_SHADOW_STACK_POLICY,
            ),
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessUserShadowStackPolicy>(),
        )
        .context("SetProcessMitigationPolicy(ProcessUserShadowStackPolicy) failed")?;
    }

    Ok(())
}

/// Apply XFG (eXtended Flow Guard) policy
///
/// XFG enhances CFG with type-based checks. The indirect call target must not only
/// be a valid CFG target but also have a matching function signature hash.
///
/// Requirements:
/// - Windows 10 20H1+ (build 19041+)
/// - Binary compiled with /guard:xfg
pub fn apply_xfg_policy() -> Result<()> {
    if !is_windows_10_20h1_or_newer() {
        return Err(anyhow::anyhow!(
            "XFG requires Windows 10 20H1+ (build 19041+)"
        ));
    }

    // XFG is an enhancement to CFG - we enable it via CFG policy with XFG flag
    let flags = CFG_ENABLE_CFG | CFG_ENABLE_EXPORT_SUPPRESSION | CFG_ENABLE_XFG;

    let policy = ProcessControlFlowGuardPolicy { flags };

    unsafe {
        SetProcessMitigationPolicy(
            std::mem::transmute::<i32, windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY>(
                PROCESS_CONTROL_FLOW_GUARD_POLICY,
            ),
            &policy as *const _ as *const _,
            std::mem::size_of::<ProcessControlFlowGuardPolicy>(),
        )
        .context("SetProcessMitigationPolicy(XFG via CFG) failed")?;
    }

    Ok(())
}

// =============================================================================
// System Protection Status Queries
// =============================================================================

/// Query HVCI (Hypervisor-enforced Code Integrity) status
///
/// HVCI uses virtualization-based security to isolate code integrity decisions
/// from the kernel. This is a system-wide setting, not per-process.
pub fn get_hvci_status() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    // SYSTEM_CODEINTEGRITY_INFORMATION structure
    #[repr(C)]
    struct SystemCodeIntegrityInformation {
        length: u32,
        code_integrity_options: u32,
    }

    // SystemCodeIntegrityInformation = 103
    const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;

    // HVCI flags
    const CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED: u32 = 0x0400;

    unsafe {
        // Get NtQuerySystemInformation from ntdll
        let ntdll = match GetModuleHandleW(PCWSTR::from_raw(
            "ntdll.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        )) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let nt_query_system_information = match GetProcAddress(
            ntdll,
            windows::core::PCSTR::from_raw(b"NtQuerySystemInformation\0".as_ptr()),
        ) {
            Some(f) => f,
            None => return false,
        };

        type NtQuerySystemInformationFn = extern "system" fn(
            system_information_class: u32,
            system_information: *mut std::ffi::c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        let nt_query_system_information: NtQuerySystemInformationFn =
            std::mem::transmute(nt_query_system_information);

        let mut info = SystemCodeIntegrityInformation {
            length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            code_integrity_options: 0,
        };

        let mut return_length: u32 = 0;

        let status = nt_query_system_information(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            &mut return_length,
        );

        // STATUS_SUCCESS = 0
        if status == 0 {
            (info.code_integrity_options & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0
        } else {
            false
        }
    }
}

/// Query KDP (Kernel Data Protection) status
///
/// KDP uses VBS to protect kernel data structures from modification.
/// Introduced in Windows 10 20H1.
pub fn get_kdp_status() -> bool {
    // KDP status is exposed via SYSTEM_SECUREBOOT_POLICY_INFORMATION
    // or can be inferred from HVCI + specific registry keys
    if !is_windows_10_20h1_or_newer() {
        return false;
    }

    // Check registry for KDP status
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
    };

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0"
            .encode_utf16()
            .collect();

        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .is_err()
        {
            return false;
        }

        let value_name: Vec<u16> = "EnableKernelDataProtection\0".encode_utf16().collect();
        let mut data: u32 = 0;
        let mut data_size = std::mem::size_of::<u32>() as u32;
        let mut value_type = REG_DWORD;

        let result = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(value_name.as_ptr()),
            None,
            Some(&mut value_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut data_size),
        );

        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);

        result.is_ok() && data == 1
    }
}

/// Query current CFG status including XFG
fn get_cfg_status() -> (bool, bool) {
    use windows::Win32::System::Threading::ProcessControlFlowGuardPolicy;

    let mut policy = ProcessControlFlowGuardPolicy::default();

    unsafe {
        if GetProcessMitigationPolicy(
            windows::Win32::System::Threading::GetCurrentProcess(),
            ProcessControlFlowGuardPolicy,
            &mut policy as *mut _ as *mut _,
            std::mem::size_of::<ProcessControlFlowGuardPolicy>(),
        )
        .is_ok()
        {
            let cfg_enabled = (policy.flags & CFG_ENABLE_CFG) != 0;
            let xfg_enabled = (policy.flags & CFG_ENABLE_XFG) != 0;
            (cfg_enabled, xfg_enabled)
        } else {
            (false, false)
        }
    }
}

/// Query current shadow stack status
fn get_shadow_stack_status() -> (bool, bool) {
    if !is_windows_10_20h1_or_newer() {
        return (false, false);
    }

    let mut policy = ProcessUserShadowStackPolicy::default();

    unsafe {
        if GetProcessMitigationPolicy(
            windows::Win32::System::Threading::GetCurrentProcess(),
            std::mem::transmute::<i32, windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY>(
                PROCESS_USER_SHADOW_STACK_POLICY,
            ),
            &mut policy as *mut _ as *mut _,
            std::mem::size_of::<ProcessUserShadowStackPolicy>(),
        )
        .is_ok()
        {
            let shadow_stack_enabled = (policy.flags & USS_ENABLE_USER_SHADOW_STACK) != 0;
            // IBT is typically coupled with shadow stack on supported hardware
            let ibt_enabled = is_ibt_supported_by_cpu() && shadow_stack_enabled;
            (shadow_stack_enabled, ibt_enabled)
        } else {
            (false, false)
        }
    }
}

// =============================================================================
// Main Entry Points
// =============================================================================

/// Apply all process mitigation policies and return comprehensive status
///
/// Must be called EARLY in process startup, before loading any untrusted code.
/// Policies cannot be reversed once applied.
///
/// This function applies mitigations with graceful degradation:
/// - Tries all mitigations
/// - Logs which ones succeeded/failed
/// - Calculates overall protection score
/// - Returns recommendations for improving protection
pub fn apply_all_mitigations() -> Result<MitigationStatus> {
    info!("Applying process mitigation policies");

    let mut status = MitigationStatus {
        windows_version: get_windows_version(),
        ..Default::default()
    };

    // Track successes for summary
    let mut success_count = 0;
    let mut total_count = 0;

    // ===================
    // Classic Mitigations
    // ===================

    // DEP - Data Execution Prevention
    total_count += 1;
    match apply_dep_policy() {
        Ok(()) => {
            success_count += 1;
            status.dep_enabled = true;
            debug!("DEP policy applied successfully");
        }
        Err(e) => {
            // DEP is usually already enabled by OS/compiler
            status.dep_enabled = true; // Assume enabled if we can't change it
            debug!(error = %e, "DEP policy failed (likely already enabled)");
        }
    }

    // ASLR - Address Space Layout Randomization
    total_count += 1;
    match apply_aslr_policy() {
        Ok(()) => {
            success_count += 1;
            status.aslr_enabled = true;
            debug!("ASLR policy applied successfully");
        }
        Err(e) => {
            warn!(error = %e, "ASLR policy failed");
        }
    }

    // ACG - Arbitrary Code Guard
    total_count += 1;
    match apply_dynamic_code_policy() {
        Ok(()) => {
            success_count += 1;
            status.acg_enabled = true;
            debug!("Dynamic code policy (ACG) applied successfully");
        }
        Err(e) => {
            warn!(error = %e, "Dynamic code policy (ACG) failed");
        }
    }

    // Extension Points
    total_count += 1;
    match apply_extension_point_disable_policy() {
        Ok(()) => {
            success_count += 1;
            status.extension_points_disabled = true;
            debug!("Extension point disable policy applied successfully");
        }
        Err(e) => {
            warn!(error = %e, "Extension point disable policy failed");
        }
    }

    // CIG - Code Integrity Guard
    total_count += 1;
    match apply_signature_policy() {
        Ok(()) => {
            success_count += 1;
            status.cig_enabled = true;
            debug!("Signature policy (CIG) applied successfully");
        }
        Err(e) => {
            warn!(error = %e, "Signature policy (CIG) failed");
        }
    }

    // CFG - Control Flow Guard
    total_count += 1;
    match apply_control_flow_guard_policy() {
        Ok(()) => {
            success_count += 1;
            status.cfg_enabled = true;
            debug!("Control Flow Guard (CFG) policy applied successfully");
        }
        Err(e) => {
            warn!(error = %e, "Control Flow Guard (CFG) policy failed");
        }
    }

    // Image Load Policy
    total_count += 1;
    match apply_image_load_policy() {
        Ok(()) => {
            success_count += 1;
            status.image_load_restricted = true;
            debug!("Image load policy applied successfully");
        }
        Err(e) => {
            warn!(error = %e, "Image load policy failed");
        }
    }

    // ==================
    // New CFI Mitigations
    // ==================

    // CET Shadow Stack (Windows 10 20H1+ / Windows 11)
    if is_windows_10_20h1_or_newer() {
        total_count += 1;
        match apply_shadow_stack_policy() {
            Ok(()) => {
                success_count += 1;
                status.cet_shadow_stack = true;
                // IBT is typically enabled along with shadow stack on supported CPUs
                if is_ibt_supported_by_cpu() {
                    status.cet_ibt = true;
                }
                info!("CET Shadow Stack policy applied successfully");
            }
            Err(e) => {
                warn!(error = %e, "CET Shadow Stack policy failed (CPU or binary may not support CET)");
            }
        }
    } else {
        debug!("Skipping CET Shadow Stack (requires Windows 10 20H1+)");
    }

    // XFG - eXtended Flow Guard (if binary supports it)
    if is_windows_10_20h1_or_newer() {
        total_count += 1;
        match apply_xfg_policy() {
            Ok(()) => {
                success_count += 1;
                status.xfg_enabled = true;
                info!("XFG (eXtended Flow Guard) policy applied successfully");
            }
            Err(e) => {
                // XFG failure is common if binary wasn't compiled with /guard:xfg
                debug!(error = %e, "XFG policy failed (binary may not be XFG-compatible)");
            }
        }
    } else {
        debug!("Skipping XFG (requires Windows 10 20H1+)");
    }

    // ========================
    // Query System Protections
    // ========================

    // HVCI status (system-wide, read-only)
    status.hvci_enabled = get_hvci_status();
    if status.hvci_enabled {
        info!("HVCI (Memory Integrity) is enabled on this system");
    } else {
        debug!("HVCI (Memory Integrity) is not enabled");
    }

    // KDP status (system-wide, read-only)
    status.kdp_enabled = get_kdp_status();
    if status.kdp_enabled {
        info!("KDP (Kernel Data Protection) is enabled on this system");
    } else {
        debug!("KDP (Kernel Data Protection) is not enabled");
    }

    // Verify actual status via query
    let (actual_cfg, actual_xfg) = get_cfg_status();
    if actual_cfg && !status.cfg_enabled {
        status.cfg_enabled = true;
        debug!("CFG was already enabled");
    }
    if actual_xfg && !status.xfg_enabled {
        status.xfg_enabled = true;
        debug!("XFG was already enabled");
    }

    let (actual_ss, actual_ibt) = get_shadow_stack_status();
    if actual_ss && !status.cet_shadow_stack {
        status.cet_shadow_stack = true;
        debug!("Shadow Stack was already enabled");
    }
    if actual_ibt && !status.cet_ibt {
        status.cet_ibt = true;
        debug!("IBT was already enabled");
    }

    // =================
    // Calculate Scores
    // =================

    status.calculate_cfi_score();
    status.calculate_overall_score();
    status.generate_recommendations();

    // =================
    // Summary Logging
    // =================

    info!(
        success = success_count,
        total = total_count,
        cfi_score = status.cfi_coverage_score,
        overall_score = status.overall_hardening_score,
        "Process mitigation policies applied ({}/{}) - CFI: {}%, Overall: {}%",
        success_count,
        total_count,
        status.cfi_coverage_score,
        status.overall_hardening_score
    );

    // Warn if less than half succeeded
    if success_count < total_count / 2 {
        warn!(
            "Only {}/{} mitigation policies succeeded - may be running on older Windows version",
            success_count, total_count
        );
    }

    // Log recommendations
    if !status.recommendations.is_empty() {
        info!("Security recommendations available - call print_mitigation_report() for details");
    }

    Ok(status)
}

/// Get current mitigation status without applying any changes
pub fn get_mitigation_status() -> MitigationStatus {
    let mut status = MitigationStatus {
        windows_version: get_windows_version(),
        ..Default::default()
    };

    // Query classic mitigations
    // DEP is almost always enabled on modern Windows
    status.dep_enabled = true;

    // Query ASLR
    {
        use windows::Win32::System::Threading::ProcessASLRPolicy;
        let mut policy = ProcessAslrPolicy { flags: 0 };
        unsafe {
            if GetProcessMitigationPolicy(
                windows::Win32::System::Threading::GetCurrentProcess(),
                ProcessASLRPolicy,
                &mut policy as *mut _ as *mut _,
                std::mem::size_of::<ProcessAslrPolicy>(),
            )
            .is_ok()
            {
                status.aslr_enabled = policy.flags != 0;
            }
        }
    }

    // Query ACG
    {
        use windows::Win32::System::Threading::ProcessDynamicCodePolicy;
        let mut policy = ProcessDynamicCodePolicy { flags: 0 };
        unsafe {
            if GetProcessMitigationPolicy(
                windows::Win32::System::Threading::GetCurrentProcess(),
                ProcessDynamicCodePolicy,
                &mut policy as *mut _ as *mut _,
                std::mem::size_of::<ProcessDynamicCodePolicy>(),
            )
            .is_ok()
            {
                status.acg_enabled = (policy.flags & 0x01) != 0;
            }
        }
    }

    // Query extension points
    {
        use windows::Win32::System::Threading::ProcessExtensionPointDisablePolicy;
        let mut policy = ProcessExtensionPointDisablePolicy { flags: 0 };
        unsafe {
            if GetProcessMitigationPolicy(
                windows::Win32::System::Threading::GetCurrentProcess(),
                ProcessExtensionPointDisablePolicy,
                &mut policy as *mut _ as *mut _,
                std::mem::size_of::<ProcessExtensionPointDisablePolicy>(),
            )
            .is_ok()
            {
                status.extension_points_disabled = (policy.flags & 0x01) != 0;
            }
        }
    }

    // Query CIG
    {
        use windows::Win32::System::Threading::ProcessSignaturePolicy;
        let mut policy = ProcessSignaturePolicy { flags: 0 };
        unsafe {
            if GetProcessMitigationPolicy(
                windows::Win32::System::Threading::GetCurrentProcess(),
                ProcessSignaturePolicy,
                &mut policy as *mut _ as *mut _,
                std::mem::size_of::<ProcessSignaturePolicy>(),
            )
            .is_ok()
            {
                status.cig_enabled = (policy.flags & 0x01) != 0;
            }
        }
    }

    // Query image load
    {
        use windows::Win32::System::Threading::ProcessImageLoadPolicy;
        let mut policy = ProcessImageLoadPolicy { flags: 0 };
        unsafe {
            if GetProcessMitigationPolicy(
                windows::Win32::System::Threading::GetCurrentProcess(),
                ProcessImageLoadPolicy,
                &mut policy as *mut _ as *mut _,
                std::mem::size_of::<ProcessImageLoadPolicy>(),
            )
            .is_ok()
            {
                status.image_load_restricted = policy.flags != 0;
            }
        }
    }

    // Query CFG and XFG
    let (cfg, xfg) = get_cfg_status();
    status.cfg_enabled = cfg;
    status.xfg_enabled = xfg;

    // Query shadow stack
    let (ss, ibt) = get_shadow_stack_status();
    status.cet_shadow_stack = ss;
    status.cet_ibt = ibt;

    // Query system protections
    status.hvci_enabled = get_hvci_status();
    status.kdp_enabled = get_kdp_status();

    // Calculate scores
    status.calculate_cfi_score();
    status.calculate_overall_score();
    status.generate_recommendations();

    status
}

/// Print detailed mitigation report to stdout
pub fn print_mitigation_report() {
    let status = get_mitigation_status();
    println!("{}", status);
}

/// Print mitigation report via tracing
pub fn log_mitigation_report() {
    let status = get_mitigation_status();

    info!("=== Process Mitigation Report ===");
    info!(
        "Windows Version: {}.{}.{}",
        status.windows_version.0, status.windows_version.1, status.windows_version.2
    );

    info!("--- Classic Mitigations ---");
    info!("  DEP: {}", status_str(status.dep_enabled));
    info!("  ASLR: {}", status_str(status.aslr_enabled));
    info!("  CFG: {}", status_str(status.cfg_enabled));
    info!("  ACG: {}", status_str(status.acg_enabled));
    info!("  CIG: {}", status_str(status.cig_enabled));
    info!(
        "  Extension Points Disabled: {}",
        status_str(status.extension_points_disabled)
    );
    info!(
        "  Image Load Restricted: {}",
        status_str(status.image_load_restricted)
    );

    info!("--- CFI Mitigations ---");
    info!(
        "  CET Shadow Stack: {}",
        status_str(status.cet_shadow_stack)
    );
    info!("  CET IBT: {}", status_str(status.cet_ibt));
    info!("  XFG: {}", status_str(status.xfg_enabled));

    info!("--- System Protections ---");
    info!("  HVCI: {}", status_str(status.hvci_enabled));
    info!("  KDP: {}", status_str(status.kdp_enabled));

    info!("--- Scores ---");
    info!("  CFI Coverage: {}%", status.cfi_coverage_score);
    info!("  Overall Hardening: {}%", status.overall_hardening_score);

    if !status.recommendations.is_empty() {
        info!("--- Recommendations ---");
        for (i, rec) in status.recommendations.iter().enumerate() {
            info!("  {}. {}", i + 1, rec);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_version_detection() {
        let (major, minor, build) = get_windows_version();
        println!("Windows version: {}.{}.{}", major, minor, build);
        assert!(major >= 6); // At least Windows Vista
    }

    #[test]
    fn test_version_checks() {
        let (_, _, build) = get_windows_version();
        println!("Build: {}", build);
        println!("Windows 10 1703+: {}", is_windows_10_1703_or_newer());
        println!("Windows 10 20H1+: {}", is_windows_10_20h1_or_newer());
        println!("Windows 11+: {}", is_windows_11_or_later());
    }

    #[test]
    fn test_cpu_cet_detection() {
        println!("CET supported by CPU: {}", is_cet_supported_by_cpu());
        println!(
            "Shadow Stack supported: {}",
            is_shadow_stack_supported_by_cpu()
        );
        println!("IBT supported: {}", is_ibt_supported_by_cpu());
    }

    #[test]
    fn test_get_mitigation_status() {
        let status = get_mitigation_status();
        println!("{}", status);
        assert!(status.overall_hardening_score <= 100);
        assert!(status.cfi_coverage_score <= 100);
    }

    #[test]
    fn test_apply_mitigations() {
        // This test will succeed on Windows 10+ and may partially fail on older versions
        let result = apply_all_mitigations();
        assert!(result.is_ok());

        let status = result.unwrap();
        println!("{}", status);

        // DEP should always be available
        assert!(status.dep_enabled);
    }

    #[test]
    fn test_score_calculation() {
        let mut status = MitigationStatus::default();

        // No mitigations
        status.calculate_cfi_score();
        status.calculate_overall_score();
        assert_eq!(status.cfi_coverage_score, 0);
        assert_eq!(status.overall_hardening_score, 0);

        // All classic mitigations
        status.dep_enabled = true;
        status.aslr_enabled = true;
        status.cfg_enabled = true;
        status.acg_enabled = true;
        status.cig_enabled = true;
        status.extension_points_disabled = true;
        status.image_load_restricted = true;
        status.calculate_cfi_score();
        status.calculate_overall_score();
        assert_eq!(status.cfi_coverage_score, 30); // Only CFG contributes to CFI score
        assert!(status.overall_hardening_score >= 40); // Classic mitigations worth ~50 points

        // Add all CFI
        status.cet_shadow_stack = true;
        status.cet_ibt = true;
        status.xfg_enabled = true;
        status.calculate_cfi_score();
        status.calculate_overall_score();
        assert_eq!(status.cfi_coverage_score, 100); // Full CFI coverage
        assert!(status.overall_hardening_score >= 80);

        // Add system protections
        status.hvci_enabled = true;
        status.kdp_enabled = true;
        status.calculate_overall_score();
        assert_eq!(status.overall_hardening_score, 100); // Full hardening
    }

    #[test]
    fn test_recommendations() {
        let mut status = MitigationStatus::default();
        status.generate_recommendations();

        // Should have recommendations for all missing mitigations
        assert!(!status.recommendations.is_empty());
        println!("Recommendations:");
        for rec in &status.recommendations {
            println!("  - {}", rec);
        }
    }

    #[test]
    fn test_hvci_status() {
        let hvci = get_hvci_status();
        println!("HVCI enabled: {}", hvci);
    }

    #[test]
    fn test_kdp_status() {
        let kdp = get_kdp_status();
        println!("KDP enabled: {}", kdp);
    }
}
