//! eXtended Flow Guard (XFG) Detection and Status Monitoring
//!
//! XFG is Microsoft's enhancement to Control Flow Guard (CFG) that adds:
//! - Type-based control flow integrity using function signature hashes
//! - Protection against more sophisticated CFI bypass attacks
//! - Stronger indirect call validation than CFG alone
//!
//! ## Requirements
//!
//! - Windows 10 20H1 (build 19041) or later
//! - MSVC compiler with `/guard:xfg` flag
//! - Windows SDK 10.0.19041.0 or later
//!
//! ## Build Configuration
//!
//! To build Tamandua with XFG:
//!
//! 1. Use MSVC compiler with /guard:xfg flag
//! 2. Link with /guard:xfg
//! 3. Requires Windows SDK 10.0.19041.0+
//!
//! In Cargo.toml / .cargo/config.toml:
//! ```toml
//! [target.x86_64-pc-windows-msvc]
//! rustflags = ["-C", "link-args=/guard:xfg"]
//! ```
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1574 - Hijack Execution Flow
//! - T1055 - Process Injection
//! - T1620 - Reflective Code Loading
//!
//! ## XFG vs CFG
//!
//! CFG validates that indirect calls target valid function entry points.
//! XFG additionally validates that the function signature matches the expected type.
//! This prevents attacks where an attacker redirects a function pointer to
//! a different valid function with an incompatible signature.

#![cfg(target_os = "windows")]
// This module enumerates PE Load Config Directory layout constants and XFG /
// CFG GuardFlags. Many values are documented PE structure offsets kept
// exhaustive for clarity and future PE-walking utilities.
#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ============================================================================
// PE Load Config Directory Constants
// ============================================================================

/// IMAGE_GUARD_CF_INSTRUMENTED - Module performs control flow integrity checks
const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x00000100;

/// IMAGE_GUARD_CFW_INSTRUMENTED - Module performs control flow and write integrity checks
const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x00000200;

/// IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT - Module contains valid CFG function table
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x00000400;

/// IMAGE_GUARD_SECURITY_COOKIE_UNUSED - Security cookie check has been disabled
const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x00000800;

/// IMAGE_GUARD_PROTECT_DELAYLOAD_IAT - Module supports delay load import protection
const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: u32 = 0x00001000;

/// IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION - Delay load import table in its own section
const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x00002000;

/// IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT - Export suppression info present
const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x00004000;

/// IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION - Export suppression enabled
const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x00008000;

/// IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT - Longjump target table present
const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x00010000;

/// IMAGE_GUARD_XFG_ENABLED - XFG metadata present (Windows 10 20H1+)
const IMAGE_GUARD_XFG_ENABLED: u32 = 0x00800000;

/// IMAGE_GUARD_RETPOLINE_PRESENT - Module was built with retpoline
const IMAGE_GUARD_RETPOLINE_PRESENT: u32 = 0x00100000;

/// Stride bits mask in GuardFlags
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF0000000;

/// Stride bits shift
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;

// ============================================================================
// XFG Status Types
// ============================================================================

/// XFG status for a process or the OS
#[derive(Debug, Clone, Default)]
pub struct XfgStatus {
    /// Whether the OS supports XFG (Windows 10 20H1+)
    pub os_supports_xfg: bool,
    /// Whether XFG is enabled for the process
    pub process_xfg_enabled: bool,
    /// Whether XFG is in audit mode (vs enforce mode)
    pub xfg_audit_mode: bool,
    /// Whether CFG is enabled (XFG requires CFG)
    pub cfg_enabled: bool,
    /// Whether CFG export suppression is enabled
    pub cfg_export_suppression: bool,
    /// Windows build number
    pub windows_build: u32,
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
}

/// XFG information from PE file analysis
#[derive(Debug, Clone, Default)]
pub struct PeXfgInfo {
    /// Whether XFG metadata is present in the PE
    pub has_xfg_metadata: bool,
    /// Number of XFG-protected functions
    pub xfg_function_count: u32,
    /// Raw GuardFlags from IMAGE_LOAD_CONFIG_DIRECTORY
    pub guard_flags: u32,
    /// CFG function table present
    pub has_cfg_function_table: bool,
    /// Export suppression enabled
    pub export_suppression_enabled: bool,
    /// Longjump table present
    pub longjump_table_present: bool,
    /// Module built with retpoline
    pub retpoline_present: bool,
    /// XFG check function pointer present
    pub has_xfg_check_function: bool,
    /// XFG dispatch function pointer present
    pub has_xfg_dispatch_function: bool,
    /// XFG table dispatch function pointer present
    pub has_xfg_table_dispatch_function: bool,
    /// File path analyzed
    pub file_path: PathBuf,
    /// Is 64-bit PE
    pub is_64bit: bool,
}

/// XFG status for a loaded module
#[derive(Debug, Clone, Default)]
pub struct ModuleXfgStatus {
    /// Module name (e.g., "kernel32.dll")
    pub module_name: String,
    /// Full module path
    pub module_path: PathBuf,
    /// Module base address in process
    pub base_address: u64,
    /// Module size
    pub size: u64,
    /// XFG enabled for this module
    pub xfg_enabled: bool,
    /// CFG enabled for this module
    pub cfg_enabled: bool,
    /// Export suppression enabled
    pub export_suppression: bool,
    /// Raw guard flags
    pub guard_flags: u32,
    /// Whether this is a system module
    pub is_system_module: bool,
}

/// XFG alert types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XfgAlertType {
    /// XFG-incompatible module loaded into protected process
    IncompatibleModuleLoaded,
    /// CFG/XFG disabled in process
    CfgXfgDisabled,
    /// Low XFG coverage in critical process
    LowXfgCoverage,
    /// XFG violation detected (if ETW enabled)
    XfgViolation,
    /// Process mitigation policy tampering
    MitigationTampering,
}

/// XFG alert for reporting
#[derive(Debug, Clone)]
pub struct XfgAlert {
    /// Alert type
    pub alert_type: XfgAlertType,
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Alert description
    pub description: String,
    /// Module involved (if applicable)
    pub module_name: Option<String>,
    /// Module path (if applicable)
    pub module_path: Option<PathBuf>,
    /// XFG coverage percentage (if applicable)
    pub coverage_percent: Option<f32>,
    /// MITRE ATT&CK technique
    pub mitre_technique: String,
    /// Timestamp
    pub timestamp: u64,
}

// ============================================================================
// OS and Process XFG Status Detection
// ============================================================================

/// Get XFG status for the current process
pub fn get_xfg_status() -> Result<XfgStatus> {
    get_process_xfg_status(std::process::id())
}

/// Get XFG status for a specific process
pub fn get_process_xfg_status(pid: u32) -> Result<XfgStatus> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetProcessMitigationPolicy, OpenProcess, ProcessControlFlowGuardPolicy,
        PROCESS_QUERY_INFORMATION,
    };

    let mut status = XfgStatus {
        pid,
        ..Default::default()
    };

    // Check OS support (Windows 10 20H1 = build 19041)
    let build = get_windows_build();
    status.windows_build = build;
    status.os_supports_xfg = build >= 19041;

    if !status.os_supports_xfg {
        debug!(
            build = build,
            "Windows build does not support XFG (requires 19041+)"
        );
        return Ok(status);
    }

    // Get process name
    status.process_name = get_process_name(pid).unwrap_or_default();

    // Query process mitigation policy
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
            .context("Failed to open process for XFG query")?;

        let _guard = scopeguard::guard(handle, |h| {
            let _ = CloseHandle(h);
        });

        // Query CFG policy
        #[repr(C)]
        #[derive(Default)]
        struct ProcessControlFlowGuardPolicyStruct {
            flags: u32,
        }

        let mut cfg_policy: ProcessControlFlowGuardPolicyStruct = Default::default();
        let result = GetProcessMitigationPolicy(
            handle,
            ProcessControlFlowGuardPolicy,
            &mut cfg_policy as *mut _ as *mut _,
            std::mem::size_of::<ProcessControlFlowGuardPolicyStruct>(),
        );

        if result.is_ok() {
            // Bit 0: EnableControlFlowGuard
            status.cfg_enabled = (cfg_policy.flags & 0x01) != 0;
            // Bit 1: EnableExportSuppression
            status.cfg_export_suppression = (cfg_policy.flags & 0x02) != 0;
            // Bit 2: StrictMode (XFG-related on newer builds)
            // Note: XFG enablement is actually determined by PE headers,
            // but we can infer it from strict mode being enabled
            status.process_xfg_enabled = status.cfg_enabled && (cfg_policy.flags & 0x04) != 0;
        } else {
            warn!(pid = pid, "Failed to query CFG policy");
        }

        // Query user shadow stack policy for additional XFG context
        // ProcessUserShadowStackPolicy = 48
        #[repr(C)]
        #[derive(Default)]
        struct ProcessUserShadowStackPolicyStruct {
            flags: u32,
        }

        let mut shadow_policy: ProcessUserShadowStackPolicyStruct = Default::default();
        // This may fail on older Windows versions, which is fine
        let _ = GetProcessMitigationPolicy(
            handle,
            windows::Win32::System::Threading::ProcessUserShadowStackPolicy,
            &mut shadow_policy as *mut _ as *mut _,
            std::mem::size_of::<ProcessUserShadowStackPolicyStruct>(),
        );
    }

    debug!(
        pid = pid,
        process = %status.process_name,
        cfg_enabled = status.cfg_enabled,
        xfg_enabled = status.process_xfg_enabled,
        "XFG status queried"
    );

    Ok(status)
}

/// Check if the current process's main executable has XFG enabled
pub fn check_current_exe_xfg() -> Result<PeXfgInfo> {
    let exe_path = std::env::current_exe()?;
    check_pe_xfg_support(&exe_path)
}

// ============================================================================
// PE Header Analysis for XFG
// ============================================================================

/// Analyze PE file for XFG support
///
/// Checks IMAGE_LOAD_CONFIG_DIRECTORY for XFG metadata:
/// - GuardXFGCheckFunctionPointer
/// - GuardXFGDispatchFunctionPointer
/// - GuardXFGTableDispatchFunctionPointer
pub fn check_pe_xfg_support(path: &Path) -> Result<PeXfgInfo> {
    let data = std::fs::read(path).context("Failed to read PE file")?;

    parse_pe_xfg_info(&data, path)
}

/// Parse PE data for XFG information
fn parse_pe_xfg_info(data: &[u8], path: &Path) -> Result<PeXfgInfo> {
    let mut info = PeXfgInfo {
        file_path: path.to_path_buf(),
        ..Default::default()
    };

    // Check DOS signature
    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return Err(anyhow!("Invalid DOS signature"));
    }

    // Get PE offset
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    if pe_offset + 4 > data.len() {
        return Err(anyhow!("Invalid PE offset"));
    }

    // Check PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(anyhow!("Invalid PE signature"));
    }

    // Parse COFF header
    let coff_offset = pe_offset + 4;
    if coff_offset + 20 > data.len() {
        return Err(anyhow!("PE too small for COFF header"));
    }

    let _machine = u16::from_le_bytes([data[coff_offset], data[coff_offset + 1]]);
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    // Parse Optional header
    let optional_offset = coff_offset + 20;
    if optional_offset + 2 > data.len() {
        return Err(anyhow!("PE too small for optional header"));
    }

    let magic = u16::from_le_bytes([data[optional_offset], data[optional_offset + 1]]);
    info.is_64bit = magic == 0x20B; // PE32+ (64-bit)

    if magic != 0x10B && magic != 0x20B {
        return Err(anyhow!("Unknown PE magic: 0x{:04X}", magic));
    }

    // Get Load Config Directory RVA and size
    // For PE32: offset 176, for PE32+: offset 192
    let load_config_dir_offset = if info.is_64bit {
        optional_offset + 112 + 80 // Data directory 10 (Load Config)
    } else {
        optional_offset + 96 + 80 // Data directory 10 (Load Config)
    };

    if load_config_dir_offset + 8 > data.len() {
        debug!(path = %path.display(), "No Load Config directory");
        return Ok(info);
    }

    let load_config_rva = u32::from_le_bytes([
        data[load_config_dir_offset],
        data[load_config_dir_offset + 1],
        data[load_config_dir_offset + 2],
        data[load_config_dir_offset + 3],
    ]);
    let load_config_size = u32::from_le_bytes([
        data[load_config_dir_offset + 4],
        data[load_config_dir_offset + 5],
        data[load_config_dir_offset + 6],
        data[load_config_dir_offset + 7],
    ]);

    if load_config_rva == 0 || load_config_size == 0 {
        debug!(path = %path.display(), "Load Config directory not present");
        return Ok(info);
    }

    // Convert RVA to file offset
    let sections_offset = optional_offset + optional_header_size;
    let load_config_file_offset =
        rva_to_file_offset(data, load_config_rva, sections_offset, num_sections)?;

    // Parse IMAGE_LOAD_CONFIG_DIRECTORY
    parse_load_config_directory(data, load_config_file_offset as usize, &mut info)?;

    debug!(
        path = %path.display(),
        has_xfg = info.has_xfg_metadata,
        xfg_functions = info.xfg_function_count,
        guard_flags = format!("0x{:08X}", info.guard_flags),
        "PE XFG analysis complete"
    );

    Ok(info)
}

/// Parse IMAGE_LOAD_CONFIG_DIRECTORY for XFG metadata
fn parse_load_config_directory(data: &[u8], offset: usize, info: &mut PeXfgInfo) -> Result<()> {
    // Minimum size check
    if offset + 4 > data.len() {
        return Err(anyhow!("Load config too small"));
    }

    let size = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;

    // Guard flags offset depends on PE32 vs PE32+
    // For PE32+: GuardFlags at offset 136
    // For PE32: GuardFlags at offset 88
    let guard_flags_offset = if info.is_64bit {
        offset + 136
    } else {
        offset + 88
    };

    if guard_flags_offset + 4 <= offset + size && guard_flags_offset + 4 <= data.len() {
        info.guard_flags = u32::from_le_bytes([
            data[guard_flags_offset],
            data[guard_flags_offset + 1],
            data[guard_flags_offset + 2],
            data[guard_flags_offset + 3],
        ]);

        // Parse guard flags
        info.has_cfg_function_table =
            (info.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0;
        info.export_suppression_enabled =
            (info.guard_flags & IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION) != 0;
        info.longjump_table_present =
            (info.guard_flags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT) != 0;
        info.retpoline_present = (info.guard_flags & IMAGE_GUARD_RETPOLINE_PRESENT) != 0;
        info.has_xfg_metadata = (info.guard_flags & IMAGE_GUARD_XFG_ENABLED) != 0;
    }

    // XFG function pointers (PE32+)
    // GuardXFGCheckFunctionPointer at offset 216
    // GuardXFGDispatchFunctionPointer at offset 224
    // GuardXFGTableDispatchFunctionPointer at offset 232
    if info.is_64bit {
        let xfg_check_offset = offset + 216;
        let xfg_dispatch_offset = offset + 224;
        let xfg_table_dispatch_offset = offset + 232;

        if xfg_check_offset + 8 <= offset + size && xfg_check_offset + 8 <= data.len() {
            let ptr = u64::from_le_bytes([
                data[xfg_check_offset],
                data[xfg_check_offset + 1],
                data[xfg_check_offset + 2],
                data[xfg_check_offset + 3],
                data[xfg_check_offset + 4],
                data[xfg_check_offset + 5],
                data[xfg_check_offset + 6],
                data[xfg_check_offset + 7],
            ]);
            info.has_xfg_check_function = ptr != 0;
        }

        if xfg_dispatch_offset + 8 <= offset + size && xfg_dispatch_offset + 8 <= data.len() {
            let ptr = u64::from_le_bytes([
                data[xfg_dispatch_offset],
                data[xfg_dispatch_offset + 1],
                data[xfg_dispatch_offset + 2],
                data[xfg_dispatch_offset + 3],
                data[xfg_dispatch_offset + 4],
                data[xfg_dispatch_offset + 5],
                data[xfg_dispatch_offset + 6],
                data[xfg_dispatch_offset + 7],
            ]);
            info.has_xfg_dispatch_function = ptr != 0;
        }

        if xfg_table_dispatch_offset + 8 <= offset + size
            && xfg_table_dispatch_offset + 8 <= data.len()
        {
            let ptr = u64::from_le_bytes([
                data[xfg_table_dispatch_offset],
                data[xfg_table_dispatch_offset + 1],
                data[xfg_table_dispatch_offset + 2],
                data[xfg_table_dispatch_offset + 3],
                data[xfg_table_dispatch_offset + 4],
                data[xfg_table_dispatch_offset + 5],
                data[xfg_table_dispatch_offset + 6],
                data[xfg_table_dispatch_offset + 7],
            ]);
            info.has_xfg_table_dispatch_function = ptr != 0;
        }
    }

    // Count XFG functions from CFG function table
    // GuardCFFunctionCount at offset 96 (PE32+) or 64 (PE32)
    let func_count_offset = if info.is_64bit {
        offset + 96
    } else {
        offset + 64
    };

    if func_count_offset + 8 <= offset + size && func_count_offset + 8 <= data.len() {
        info.xfg_function_count = u64::from_le_bytes([
            data[func_count_offset],
            data[func_count_offset + 1],
            data[func_count_offset + 2],
            data[func_count_offset + 3],
            data[func_count_offset + 4],
            data[func_count_offset + 5],
            data[func_count_offset + 6],
            data[func_count_offset + 7],
        ]) as u32;
    }

    Ok(())
}

/// Convert RVA to file offset using section headers
fn rva_to_file_offset(
    data: &[u8],
    rva: u32,
    sections_offset: usize,
    num_sections: usize,
) -> Result<u32> {
    const SECTION_HEADER_SIZE: usize = 40;

    for i in 0..num_sections {
        let section_offset = sections_offset + i * SECTION_HEADER_SIZE;
        if section_offset + 40 > data.len() {
            break;
        }

        let virtual_size = u32::from_le_bytes([
            data[section_offset + 8],
            data[section_offset + 9],
            data[section_offset + 10],
            data[section_offset + 11],
        ]);
        let virtual_address = u32::from_le_bytes([
            data[section_offset + 12],
            data[section_offset + 13],
            data[section_offset + 14],
            data[section_offset + 15],
        ]);
        let raw_data_ptr = u32::from_le_bytes([
            data[section_offset + 20],
            data[section_offset + 21],
            data[section_offset + 22],
            data[section_offset + 23],
        ]);

        if rva >= virtual_address && rva < virtual_address + virtual_size {
            return Ok(raw_data_ptr + (rva - virtual_address));
        }
    }

    Err(anyhow!("RVA 0x{:08X} not found in any section", rva))
}

// ============================================================================
// Module Scanning
// ============================================================================

/// Scan loaded modules for XFG compatibility
pub fn scan_modules_xfg_status(pid: u32) -> Vec<ModuleXfgStatus> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, K32GetModuleInformation, MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut modules = Vec::new();

    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        else {
            warn!(pid = pid, "Failed to open process for module enumeration");
            return modules;
        };

        let _guard = scopeguard::guard(handle, |h| {
            let _ = CloseHandle(h);
        });

        let mut module_handles: Vec<windows::Win32::Foundation::HMODULE> =
            vec![windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut cb_needed = 0u32;

        if EnumProcessModules(
            handle,
            module_handles.as_mut_ptr(),
            (module_handles.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>())
                as u32,
            &mut cb_needed,
        )
        .is_ok()
        {
            let count =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

            for i in 0..count.min(module_handles.len()) {
                if module_handles[i].is_invalid() {
                    continue;
                }

                let mut info: MODULEINFO = std::mem::zeroed();
                if !K32GetModuleInformation(
                    handle,
                    module_handles[i],
                    &mut info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .as_bool()
                {
                    continue;
                }

                let mut name_buf = vec![0u16; 512];
                let len = GetModuleFileNameExW(handle, module_handles[i], &mut name_buf);
                if len == 0 {
                    continue;
                }

                let module_path_str = String::from_utf16_lossy(&name_buf[..len as usize]);
                let module_path = PathBuf::from(&module_path_str);
                let module_name = module_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                let is_system = is_system_module(&module_path);

                let mut status = ModuleXfgStatus {
                    module_name: module_name.clone(),
                    module_path: module_path.clone(),
                    base_address: info.lpBaseOfDll as u64,
                    size: info.SizeOfImage as u64,
                    is_system_module: is_system,
                    ..Default::default()
                };

                // Read PE headers from memory to get guard flags
                let base_addr = info.lpBaseOfDll as u64;
                let mut dos_header = vec![0u8; 64];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    handle,
                    base_addr as *const _,
                    dos_header.as_mut_ptr() as *mut _,
                    dos_header.len(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    modules.push(status);
                    continue;
                }

                // Parse DOS header
                if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
                    modules.push(status);
                    continue;
                }

                let pe_offset = u32::from_le_bytes([
                    dos_header[0x3C],
                    dos_header[0x3D],
                    dos_header[0x3E],
                    dos_header[0x3F],
                ]) as u64;

                // Read PE headers (enough for Load Config Directory)
                let mut pe_headers = vec![0u8; 0x400];
                if ReadProcessMemory(
                    handle,
                    (base_addr + pe_offset) as *const _,
                    pe_headers.as_mut_ptr() as *mut _,
                    pe_headers.len(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    modules.push(status);
                    continue;
                }

                if &pe_headers[0..4] != b"PE\0\0" {
                    modules.push(status);
                    continue;
                }

                // Check if 64-bit
                let optional_header_offset = 24;
                let magic = u16::from_le_bytes([
                    pe_headers[optional_header_offset],
                    pe_headers[optional_header_offset + 1],
                ]);

                let is_64bit = magic == 0x20B;

                // Get Load Config Directory RVA
                let load_config_dir_offset = if is_64bit {
                    optional_header_offset + 112 + 80
                } else {
                    optional_header_offset + 96 + 80
                };

                if load_config_dir_offset + 8 <= pe_headers.len() {
                    let load_config_rva = u32::from_le_bytes([
                        pe_headers[load_config_dir_offset],
                        pe_headers[load_config_dir_offset + 1],
                        pe_headers[load_config_dir_offset + 2],
                        pe_headers[load_config_dir_offset + 3],
                    ]);

                    if load_config_rva != 0 {
                        // Read Load Config from memory
                        let mut load_config = vec![0u8; 0x100];
                        if ReadProcessMemory(
                            handle,
                            (base_addr + load_config_rva as u64) as *const _,
                            load_config.as_mut_ptr() as *mut _,
                            load_config.len(),
                            Some(&mut bytes_read),
                        )
                        .is_ok()
                        {
                            let guard_flags_offset = if is_64bit { 136 } else { 88 };
                            if guard_flags_offset + 4 <= load_config.len() {
                                status.guard_flags = u32::from_le_bytes([
                                    load_config[guard_flags_offset],
                                    load_config[guard_flags_offset + 1],
                                    load_config[guard_flags_offset + 2],
                                    load_config[guard_flags_offset + 3],
                                ]);

                                status.cfg_enabled =
                                    (status.guard_flags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
                                status.xfg_enabled =
                                    (status.guard_flags & IMAGE_GUARD_XFG_ENABLED) != 0;
                                status.export_suppression = (status.guard_flags
                                    & IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION)
                                    != 0;
                            }
                        }
                    }
                }

                modules.push(status);
            }
        }
    }

    info!(
        pid = pid,
        module_count = modules.len(),
        "Module XFG scan complete"
    );

    modules
}

/// Calculate XFG coverage percentage for a process
pub fn calculate_xfg_coverage(modules: &[ModuleXfgStatus]) -> f32 {
    if modules.is_empty() {
        return 0.0;
    }

    let xfg_enabled_count = modules.iter().filter(|m| m.xfg_enabled).count();
    (xfg_enabled_count as f32 / modules.len() as f32) * 100.0
}

/// Calculate CFG coverage percentage for a process
pub fn calculate_cfg_coverage(modules: &[ModuleXfgStatus]) -> f32 {
    if modules.is_empty() {
        return 0.0;
    }

    let cfg_enabled_count = modules.iter().filter(|m| m.cfg_enabled).count();
    (cfg_enabled_count as f32 / modules.len() as f32) * 100.0
}

/// Get modules without CFG/XFG protection
pub fn get_unprotected_modules(modules: &[ModuleXfgStatus]) -> Vec<&ModuleXfgStatus> {
    modules.iter().filter(|m| !m.cfg_enabled).collect()
}

/// Get non-system modules without XFG (potential security risk)
pub fn get_xfg_incompatible_nonsystem_modules(
    modules: &[ModuleXfgStatus],
) -> Vec<&ModuleXfgStatus> {
    modules
        .iter()
        .filter(|m| !m.is_system_module && !m.xfg_enabled && !m.cfg_enabled)
        .collect()
}

// ============================================================================
// Alerting
// ============================================================================

/// Check for XFG-related security issues and generate alerts
pub fn check_xfg_alerts(pid: u32, process_name: &str) -> Vec<XfgAlert> {
    let mut alerts = Vec::new();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Get XFG status
    let status = match get_process_xfg_status(pid) {
        Ok(s) => s,
        Err(e) => {
            warn!(pid = pid, error = %e, "Failed to get XFG status");
            return alerts;
        }
    };

    // Alert if CFG/XFG is disabled on a process that should have it
    if !status.cfg_enabled {
        alerts.push(XfgAlert {
            alert_type: XfgAlertType::CfgXfgDisabled,
            pid,
            process_name: process_name.to_string(),
            description: format!(
                "Control Flow Guard is disabled for process {} (PID {})",
                process_name, pid
            ),
            module_name: None,
            module_path: None,
            coverage_percent: None,
            mitre_technique: "T1574".to_string(),
            timestamp,
        });
    }

    // Scan modules
    let modules = scan_modules_xfg_status(pid);
    let cfg_coverage = calculate_cfg_coverage(&modules);
    let xfg_coverage = calculate_xfg_coverage(&modules);

    // Alert on low CFG coverage
    if cfg_coverage < 80.0 {
        alerts.push(XfgAlert {
            alert_type: XfgAlertType::LowXfgCoverage,
            pid,
            process_name: process_name.to_string(),
            description: format!(
                "Low CFG coverage ({:.1}%) for process {} (PID {})",
                cfg_coverage, process_name, pid
            ),
            module_name: None,
            module_path: None,
            coverage_percent: Some(cfg_coverage),
            mitre_technique: "T1574".to_string(),
            timestamp,
        });
    }

    // Alert on incompatible modules
    for module in get_xfg_incompatible_nonsystem_modules(&modules) {
        alerts.push(XfgAlert {
            alert_type: XfgAlertType::IncompatibleModuleLoaded,
            pid,
            process_name: process_name.to_string(),
            description: format!(
                "XFG/CFG-incompatible module '{}' loaded into process {} (PID {})",
                module.module_name, process_name, pid
            ),
            module_name: Some(module.module_name.clone()),
            module_path: Some(module.module_path.clone()),
            coverage_percent: None,
            mitre_technique: "T1055".to_string(),
            timestamp,
        });
    }

    debug!(
        pid = pid,
        alert_count = alerts.len(),
        cfg_coverage = cfg_coverage,
        xfg_coverage = xfg_coverage,
        "XFG alert check complete"
    );

    alerts
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get Windows build number
fn get_windows_build() -> u32 {
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

    unsafe {
        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
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

/// Get process name from PID
fn get_process_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

        let _guard = scopeguard::guard(handle, |h| {
            let _ = CloseHandle(h);
        });

        let mut name_buf = vec![0u16; 512];
        let len = GetModuleBaseNameW(handle, None, &mut name_buf);
        if len > 0 {
            Some(String::from_utf16_lossy(&name_buf[..len as usize]))
        } else {
            None
        }
    }
}

/// Check if a module path is a system module
fn is_system_module(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    // Windows system directories
    path_str.contains("\\windows\\system32\\")
        || path_str.contains("\\windows\\syswow64\\")
        || path_str.contains("\\windows\\winsxs\\")
        || path_str.contains("\\program files\\windows")
        || path_str.contains("\\windows\\")
            && (path_str.ends_with(".dll") || path_str.ends_with(".exe"))
}

// ============================================================================
// XFG Status Monitoring (for continuous monitoring)
// ============================================================================

/// XFG monitoring configuration
#[derive(Debug, Clone)]
pub struct XfgMonitorConfig {
    /// Minimum CFG coverage percentage to not alert
    pub min_cfg_coverage: f32,
    /// Minimum XFG coverage percentage to not alert
    pub min_xfg_coverage: f32,
    /// Alert on any non-system module without CFG
    pub alert_on_unprotected_nonsystem: bool,
    /// Processes to monitor (empty = all)
    pub monitored_processes: Vec<String>,
    /// Check interval in seconds
    pub check_interval_secs: u64,
}

impl Default for XfgMonitorConfig {
    fn default() -> Self {
        Self {
            min_cfg_coverage: 80.0,
            min_xfg_coverage: 50.0,
            alert_on_unprotected_nonsystem: true,
            monitored_processes: vec![],
            check_interval_secs: 60,
        }
    }
}

/// XFG monitor for continuous protection status tracking
pub struct XfgMonitor {
    config: XfgMonitorConfig,
    /// Cache of module statuses per process
    module_cache: HashMap<u32, Vec<ModuleXfgStatus>>,
    /// Processes we've already alerted on (pid, alert_type)
    alerted: std::collections::HashSet<(u32, String)>,
}

impl XfgMonitor {
    /// Create a new XFG monitor
    pub fn new(config: XfgMonitorConfig) -> Self {
        Self {
            config,
            module_cache: HashMap::new(),
            alerted: std::collections::HashSet::new(),
        }
    }

    /// Check a process for XFG status and return new alerts
    pub fn check_process(&mut self, pid: u32, process_name: &str) -> Vec<XfgAlert> {
        // Filter by monitored processes if configured
        if !self.config.monitored_processes.is_empty()
            && !self
                .config
                .monitored_processes
                .iter()
                .any(|p| p.eq_ignore_ascii_case(process_name))
        {
            return vec![];
        }

        let alerts = check_xfg_alerts(pid, process_name);

        // Update cache
        let modules = scan_modules_xfg_status(pid);
        self.module_cache.insert(pid, modules);

        // Filter out already-alerted issues
        alerts
            .into_iter()
            .filter(|a| {
                let key = (pid, format!("{:?}", a.alert_type));
                if self.alerted.contains(&key) {
                    false
                } else {
                    self.alerted.insert(key);
                    true
                }
            })
            .collect()
    }

    /// Clear alerts for a process (e.g., when it exits)
    pub fn clear_process(&mut self, pid: u32) {
        self.module_cache.remove(&pid);
        self.alerted.retain(|(p, _)| *p != pid);
    }

    /// Get cached module status for a process
    pub fn get_cached_modules(&self, pid: u32) -> Option<&Vec<ModuleXfgStatus>> {
        self.module_cache.get(&pid)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_windows_build() {
        let build = get_windows_build();
        println!("Windows build: {}", build);
        assert!(build > 0);
    }

    #[test]
    fn test_get_xfg_status_current_process() {
        let status = get_xfg_status();
        assert!(status.is_ok());
        let status = status.unwrap();
        println!("XFG Status: {:?}", status);
        assert!(status.windows_build > 0);
    }

    #[test]
    fn test_check_current_exe_xfg() {
        let info = check_current_exe_xfg();
        println!("Current EXE XFG info: {:?}", info);
        // May or may not have XFG depending on build configuration
    }

    #[test]
    fn test_scan_modules_current_process() {
        let pid = std::process::id();
        let modules = scan_modules_xfg_status(pid);
        println!("Loaded modules: {}", modules.len());
        for module in &modules {
            println!(
                "  {} - CFG: {}, XFG: {}",
                module.module_name, module.cfg_enabled, module.xfg_enabled
            );
        }
        assert!(!modules.is_empty());
    }

    #[test]
    fn test_calculate_coverage() {
        let modules = vec![
            ModuleXfgStatus {
                module_name: "test1.dll".to_string(),
                cfg_enabled: true,
                xfg_enabled: true,
                ..Default::default()
            },
            ModuleXfgStatus {
                module_name: "test2.dll".to_string(),
                cfg_enabled: true,
                xfg_enabled: false,
                ..Default::default()
            },
            ModuleXfgStatus {
                module_name: "test3.dll".to_string(),
                cfg_enabled: false,
                xfg_enabled: false,
                ..Default::default()
            },
        ];

        let cfg_coverage = calculate_cfg_coverage(&modules);
        let xfg_coverage = calculate_xfg_coverage(&modules);

        assert!((cfg_coverage - 66.67).abs() < 1.0);
        assert!((xfg_coverage - 33.33).abs() < 1.0);
    }

    #[test]
    fn test_is_system_module() {
        assert!(is_system_module(Path::new(
            "C:\\Windows\\System32\\kernel32.dll"
        )));
        assert!(is_system_module(Path::new(
            "C:\\Windows\\SysWOW64\\ntdll.dll"
        )));
        assert!(!is_system_module(Path::new("C:\\Users\\test\\malware.dll")));
        assert!(!is_system_module(Path::new(
            "C:\\Program Files\\App\\app.dll"
        )));
    }

    #[test]
    fn test_pe_xfg_support_ntdll() {
        // Test with a known system DLL
        let ntdll_path = Path::new("C:\\Windows\\System32\\ntdll.dll");
        if ntdll_path.exists() {
            let info = check_pe_xfg_support(ntdll_path);
            println!("ntdll.dll XFG info: {:?}", info);
            // ntdll should have CFG on modern Windows
        }
    }

    #[test]
    fn test_xfg_monitor() {
        let mut monitor = XfgMonitor::new(XfgMonitorConfig::default());
        let pid = std::process::id();
        let alerts = monitor.check_process(pid, "test_process");
        println!("Alerts: {:?}", alerts);

        // Second check should not return same alerts
        let alerts2 = monitor.check_process(pid, "test_process");
        assert!(alerts2.len() <= alerts.len());

        monitor.clear_process(pid);
        assert!(monitor.get_cached_modules(pid).is_none());
    }
}
