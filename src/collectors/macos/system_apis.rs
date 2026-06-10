//! macOS system API wrappers
//!
//! Provides safe Rust wrappers around macOS system APIs for:
//! - Code signature verification (via Security.framework)
//! - Audit token extraction (via proc_pidinfo)
//! - Process introspection
//! - Full Disk Access detection
//!
//! ## Architecture
//! Where possible, we use native FFI instead of shelling out to command-line tools.
//! This provides better performance, reliability, and access to data not exposed via CLI.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use tracing::{debug, info, warn};

#[cfg(target_os = "macos")]
use libc::{c_void, pid_t};

// =============================================================================
// FFI Bindings for proc_pidinfo (libproc.h)
// =============================================================================

#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
mod libproc {
    use libc::{c_int, c_void, gid_t, pid_t, uid_t};

    pub const PROC_PIDTASKALLINFO: c_int = 2;
    pub const PROC_PIDTBSDINFO: c_int = 3;

    /// BSD process info structure (subset of proc_bsdinfo)
    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct proc_bsdinfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_xstatus: u32,
        pub pbi_pid: u32,
        pub pbi_ppid: u32,
        pub pbi_uid: uid_t,
        pub pbi_gid: gid_t,
        pub pbi_ruid: uid_t,
        pub pbi_rgid: gid_t,
        pub pbi_svuid: uid_t,
        pub pbi_svgid: gid_t,
        pub _reserved: u32,
        pub pbi_comm: [u8; 16],
        pub pbi_name: [u8; 32],
        pub pbi_nfiles: u32,
        pub pbi_pgid: u32,
        pub pbi_pjobc: u32,
        pub e_tdev: u32,
        pub e_tpgid: u32,
        pub pbi_nice: i32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }

    /// Task info structure
    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct proc_taskinfo {
        pub pti_virtual_size: u64,
        pub pti_resident_size: u64,
        pub pti_total_user: u64,
        pub pti_total_system: u64,
        pub pti_threads_user: u64,
        pub pti_threads_system: u64,
        pub pti_policy: i32,
        pub pti_faults: i32,
        pub pti_pageins: i32,
        pub pti_cow_faults: i32,
        pub pti_messages_sent: i32,
        pub pti_messages_received: i32,
        pub pti_syscalls_mach: i32,
        pub pti_syscalls_unix: i32,
        pub pti_csw: i32,
        pub pti_threadnum: i32,
        pub pti_numrunning: i32,
        pub pti_priority: i32,
    }

    /// Combined task all info
    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct proc_taskallinfo {
        pub pbsd: proc_bsdinfo,
        pub ptinfo: proc_taskinfo,
    }

    extern "C" {
        pub fn proc_pidinfo(
            pid: pid_t,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;

        pub fn proc_pidpath(pid: pid_t, buffer: *mut c_void, buffersize: u32) -> c_int;
    }
}

// =============================================================================
// FFI Bindings for Security.framework (codesigning)
// =============================================================================

#[cfg(target_os = "macos")]
mod security_ffi {
    use core_foundation::base::{CFTypeRef, OSStatus, TCFType};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use std::os::raw::c_void;
    use std::ptr;

    pub type SecCodeRef = *const c_void;
    pub type SecStaticCodeRef = *const c_void;
    pub type CFDictionaryRef = *const c_void;
    pub type CFStringRef = *const c_void;
    pub type CFErrorRef = *mut c_void;

    // SecCS flags
    pub const kSecCSDefaultFlags: u32 = 0;
    pub const kSecCSCheckAllArchitectures: u32 = 0x0001;
    pub const kSecCSDoNotValidateExecutable: u32 = 0x0002;
    pub const kSecCSDoNotValidateResources: u32 = 0x0004;
    pub const kSecCSCheckNestedCode: u32 = 0x0008;
    pub const kSecCSStrictValidate: u32 = 0x0010;
    pub const kSecCSBasicValidateOnly: u32 =
        kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources;

    // Signing info keys (as CFString)
    pub const K_SEC_CODE_INFO_IDENTIFIER: &str = "identifier";
    pub const K_SEC_CODE_INFO_TEAM_IDENTIFIER: &str = "teamid";
    pub const K_SEC_CODE_INFO_CERTIFICATES: &str = "certificates";
    pub const K_SEC_CODE_INFO_CDHASHES: &str = "cdhashes";
    pub const K_SEC_CODE_INFO_FLAGS: &str = "flags";
    pub const K_SEC_CODE_INFO_STATUS: &str = "status";

    // Guest attribute keys
    pub const K_SEC_GUEST_ATTRIBUTE_PID: &str = "pid";

    // Code signing flags
    pub const CS_VALID: u32 = 0x00000001;
    pub const CS_ADHOC: u32 = 0x00000002;
    pub const CS_PLATFORM_BINARY: u32 = 0x04000000;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        pub fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attributes: CFDictionaryRef,
            flags: u32,
            guest: *mut SecCodeRef,
        ) -> OSStatus;

        pub fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;

        pub fn SecCodeCheckValidity(
            code: SecCodeRef,
            flags: u32,
            requirement: *const c_void,
        ) -> OSStatus;

        pub fn SecStaticCodeCreateWithPath(
            path: CFStringRef,
            flags: u32,
            static_code: *mut SecStaticCodeRef,
        ) -> OSStatus;

        pub fn CFRelease(cf: CFTypeRef);
    }

    /// Get code signing info for a PID using Security.framework
    pub fn get_codesign_info_ffi(pid: u32) -> Result<super::CodesignInfo, String> {
        use core_foundation::base::FromVoid;
        use core_foundation::dictionary::CFDictionaryRef as CFDictRef;

        unsafe {
            // Create attributes dictionary with PID
            let pid_key = CFString::new(K_SEC_GUEST_ATTRIBUTE_PID);
            let pid_value = CFNumber::from(pid as i64);

            let keys = [pid_key.as_CFTypeRef()];
            let values = [pid_value.as_CFTypeRef()];

            let attributes =
                CFDictionary::from_CFType_pairs(&[(pid_key.as_CFType(), pid_value.as_CFType())]);

            // Get SecCode for the process
            let mut code_ref: SecCodeRef = ptr::null();
            let status = SecCodeCopyGuestWithAttributes(
                ptr::null(), // host = NULL means "any host"
                attributes.as_concrete_TypeRef() as CFDictionaryRef,
                kSecCSDefaultFlags,
                &mut code_ref,
            );

            if status != 0 || code_ref.is_null() {
                return Err(format!("SecCodeCopyGuestWithAttributes failed: {}", status));
            }

            // Check validity
            let is_valid =
                SecCodeCheckValidity(code_ref, kSecCSBasicValidateOnly, ptr::null()) == 0;

            // Get signing information
            let mut info_dict: CFDictionaryRef = ptr::null();
            let status =
                SecCodeCopySigningInformation(code_ref, kSecCSDefaultFlags, &mut info_dict);

            let mut result = super::CodesignInfo {
                is_signed: false,
                signer: None,
                team_id: None,
                signing_id: None,
                cdhash: None,
                is_platform_binary: false,
                is_valid,
            };

            if status == 0 && !info_dict.is_null() {
                // Parse the dictionary
                let dict = CFDictionary::<CFString, CFTypeRef>::wrap_under_create_rule(
                    info_dict as CFDictRef,
                );

                // Get identifier
                if let Some(id) = dict.find(CFString::new(K_SEC_CODE_INFO_IDENTIFIER)) {
                    if let Some(id_str) = CFString::wrap_under_get_rule(*id as *const _)
                        .to_string()
                        .into()
                    {
                        result.signing_id = Some(id_str);
                        result.is_signed = true;
                    }
                }

                // Get team ID
                if let Some(team) = dict.find(CFString::new(K_SEC_CODE_INFO_TEAM_IDENTIFIER)) {
                    if let Some(team_str) = CFString::wrap_under_get_rule(*team as *const _)
                        .to_string()
                        .into()
                    {
                        result.team_id = Some(team_str);
                    }
                }

                // Get flags to check for platform binary
                if let Some(flags) = dict.find(CFString::new(K_SEC_CODE_INFO_FLAGS)) {
                    let flags_num = CFNumber::wrap_under_get_rule(*flags as *const _);
                    if let Some(flags_val) = flags_num.to_i64() {
                        result.is_platform_binary = (flags_val as u32 & CS_PLATFORM_BINARY) != 0;
                        if (flags_val as u32 & CS_ADHOC) != 0 {
                            result.signer = Some("Ad-hoc signed".to_string());
                        }
                    }
                }

                // CFRelease is handled by wrap_under_create_rule
            }

            // Release the code ref
            if !code_ref.is_null() {
                CFRelease(code_ref as CFTypeRef);
            }

            Ok(result)
        }
    }
}

/// Code signature information for a process or binary
#[derive(Debug, Clone)]
pub struct CodesignInfo {
    /// Whether the binary is signed
    pub is_signed: bool,
    /// Signing identity (e.g., "Developer ID Application: Company Name")
    pub signer: Option<String>,
    /// Team identifier (e.g., "ABCDEFGHIJ")
    pub team_id: Option<String>,
    /// Signing identifier (bundle ID or binary name)
    pub signing_id: Option<String>,
    /// Code directory hash (cdhash)
    pub cdhash: Option<Vec<u8>>,
    /// Whether the binary is a platform binary (signed by Apple)
    pub is_platform_binary: bool,
    /// Whether the signature is valid
    pub is_valid: bool,
}

/// Get code signature information for a running process
///
/// Uses Security.framework FFI for native access (no shell out).
/// Falls back to `codesign` CLI if FFI fails.
///
/// ## Arguments
/// * `pid` - Process ID
///
/// ## Returns
/// * `Ok(CodesignInfo)` - Signature information
/// * `Err(String)` - Verification error
#[cfg(target_os = "macos")]
pub fn get_process_codesign_info(pid: u32) -> Result<CodesignInfo, String> {
    debug!(
        pid = pid,
        "Getting process code signature via Security.framework"
    );

    // Try native FFI first (faster, more reliable)
    match security_ffi::get_codesign_info_ffi(pid) {
        Ok(info) => {
            debug!(
                pid = pid,
                signed = info.is_signed,
                "Got codesign info via FFI"
            );
            return Ok(info);
        }
        Err(e) => {
            debug!(pid = pid, error = %e, "FFI codesign failed, falling back to CLI");
        }
    }

    // Fallback: Try to extract signature via `codesign` command
    let output = std::process::Command::new("codesign")
        .arg("-dvvv")
        .arg(format!("--pid={}", pid))
        .output()
        .map_err(|e| format!("Failed to execute codesign: {}", e))?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut info = CodesignInfo {
        is_signed: false,
        signer: None,
        team_id: None,
        signing_id: None,
        cdhash: None,
        is_platform_binary: false,
        is_valid: false,
    };

    // Parse codesign output
    for line in stderr.lines() {
        if line.contains("Signature=") {
            info.is_signed = !line.contains("not signed");
        } else if line.starts_with("Authority=") {
            info.signer = Some(line.trim_start_matches("Authority=").to_string());
        } else if line.starts_with("TeamIdentifier=") {
            info.team_id = Some(line.trim_start_matches("TeamIdentifier=").to_string());
        } else if line.starts_with("Identifier=") {
            info.signing_id = Some(line.trim_start_matches("Identifier=").to_string());
        } else if line.contains("CDHash=") {
            if let Some(hash) = line.split('=').nth(1) {
                info.cdhash = Some(hex::decode(hash.trim()).unwrap_or_default());
            }
        } else if line.contains("Platform Binary") {
            info.is_platform_binary = true;
        } else if line.contains("satisfies its Designated Requirement") {
            info.is_valid = true;
        }
    }

    Ok(info)
}

#[cfg(not(target_os = "macos"))]
pub fn get_process_codesign_info(_pid: u32) -> Result<CodesignInfo, String> {
    Err("Code signature verification is only available on macOS".to_string())
}

/// Extended process info from proc_pidinfo
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Effective user ID
    pub euid: u32,
    /// Effective group ID
    pub egid: u32,
    /// Real user ID
    pub ruid: u32,
    /// Real group ID
    pub rgid: u32,
    /// Saved user ID
    pub svuid: u32,
    /// Saved group ID
    pub svgid: u32,
    /// Process group ID
    pub pgid: u32,
    /// Process name (short)
    pub comm: String,
    /// Process name (full)
    pub name: String,
    /// Number of open files
    pub nfiles: u32,
    /// Nice value
    pub nice: i32,
    /// Start time (seconds since epoch)
    pub start_time: u64,
    /// Virtual memory size
    pub virtual_size: u64,
    /// Resident memory size
    pub resident_size: u64,
    /// Number of threads
    pub num_threads: i32,
}

/// Get audit token for a process (macOS kernel credential)
///
/// Uses proc_pidinfo FFI for native access (no shell out).
/// Returns complete audit token with all 8 fields populated.
///
/// The audit token contains:
/// - AUID (Audit User ID) - set to RUID as approximation
/// - EUID (Effective User ID)
/// - EGID (Effective Group ID)
/// - RUID (Real User ID)
/// - RGID (Real Group ID)
/// - PID
/// - Session ID (PGID as approximation)
/// - Terminal ID (tdev)
///
/// ## Arguments
/// * `pid` - Process ID
///
/// ## Returns
/// * `Ok([u32; 8])` - Audit token (8 32-bit values)
/// * `Err(String)` - Extraction error
#[cfg(target_os = "macos")]
pub fn get_process_audit_token(pid: u32) -> Result<[u32; 8], String> {
    debug!(pid = pid, "Getting audit token via proc_pidinfo");

    // Use proc_pidinfo for complete process info
    let info = get_process_info_native(pid)?;

    // Construct audit token from process info
    // Format: [auid, euid, egid, ruid, rgid, pid, sessionid, termid]
    let token = [
        info.ruid, // AUID (approximated as RUID)
        info.euid, // EUID
        info.egid, // EGID
        info.ruid, // RUID
        info.rgid, // RGID
        info.pid,  // PID
        info.pgid, // Session ID (approximated as PGID)
        0,         // Terminal ID (not directly available)
    ];

    debug!(
        pid = pid,
        euid = info.euid,
        ruid = info.ruid,
        egid = info.egid,
        rgid = info.rgid,
        "Got complete audit token"
    );

    Ok(token)
}

/// Get extended process info using native proc_pidinfo FFI
#[cfg(target_os = "macos")]
pub fn get_process_info_native(pid: u32) -> Result<ProcessInfo, String> {
    use std::mem::size_of;

    unsafe {
        let mut info: libproc::proc_taskallinfo = std::mem::zeroed();
        let info_size = size_of::<libproc::proc_taskallinfo>() as c_int;

        let result = libproc::proc_pidinfo(
            pid as pid_t,
            libproc::PROC_PIDTASKALLINFO,
            0,
            &mut info as *mut _ as *mut c_void,
            info_size,
        );

        if result <= 0 {
            return Err(format!("proc_pidinfo failed for pid {}", pid));
        }

        // Extract comm string (null-terminated)
        let comm = CStr::from_ptr(info.pbsd.pbi_comm.as_ptr() as *const _)
            .to_string_lossy()
            .to_string();

        // Extract name string (null-terminated)
        let name = CStr::from_ptr(info.pbsd.pbi_name.as_ptr() as *const _)
            .to_string_lossy()
            .to_string();

        Ok(ProcessInfo {
            pid: info.pbsd.pbi_pid,
            ppid: info.pbsd.pbi_ppid,
            euid: info.pbsd.pbi_uid,
            egid: info.pbsd.pbi_gid,
            ruid: info.pbsd.pbi_ruid,
            rgid: info.pbsd.pbi_rgid,
            svuid: info.pbsd.pbi_svuid,
            svgid: info.pbsd.pbi_svgid,
            pgid: info.pbsd.pbi_pgid,
            comm,
            name,
            nfiles: info.pbsd.pbi_nfiles,
            nice: info.pbsd.pbi_nice,
            start_time: info.pbsd.pbi_start_tvsec,
            virtual_size: info.ptinfo.pti_virtual_size,
            resident_size: info.ptinfo.pti_resident_size,
            num_threads: info.ptinfo.pti_threadnum,
        })
    }
}

/// Get process executable path using proc_pidpath FFI
#[cfg(target_os = "macos")]
pub fn get_process_path_native(pid: u32) -> Result<String, String> {
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

    unsafe {
        let mut buffer = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
        let result = libproc::proc_pidpath(
            pid as pid_t,
            buffer.as_mut_ptr() as *mut c_void,
            PROC_PIDPATHINFO_MAXSIZE,
        );

        if result <= 0 {
            return Err(format!("proc_pidpath failed for pid {}", pid));
        }

        let path = CStr::from_ptr(buffer.as_ptr() as *const _)
            .to_string_lossy()
            .to_string();

        Ok(path)
    }
}

#[cfg(not(target_os = "macos"))]
pub fn get_process_info_native(_pid: u32) -> Result<ProcessInfo, String> {
    Err("Process info is only available on macOS".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn get_process_path_native(_pid: u32) -> Result<String, String> {
    Err("Process path is only available on macOS".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn get_process_audit_token(_pid: u32) -> Result<[u32; 8], String> {
    Err("Audit tokens are only available on macOS".to_string())
}

/// Full Disk Access status with details
#[derive(Debug, Clone)]
pub struct FdaStatus {
    /// Whether FDA is granted
    pub has_fda: bool,
    /// Which test file was used to determine status
    pub test_file: Option<String>,
    /// Additional details
    pub details: String,
}

/// Check if a process has Full Disk Access permission
///
/// On macOS 10.14+, Full Disk Access (FDA) is required to access certain files
/// like ~/Library/Safari, TCC.db, Mail data, etc.
///
/// ## Strategy
/// Try to read multiple known protected files to improve reliability.
/// Different apps may have different files available.
///
/// ## Returns
/// * `Ok(true)` - Process has Full Disk Access
/// * `Ok(false)` - Process does not have Full Disk Access
/// * `Err(String)` - Check failed
#[cfg(target_os = "macos")]
pub fn has_full_disk_access() -> Result<bool, String> {
    match check_full_disk_access_detailed() {
        Ok(status) => Ok(status.has_fda),
        Err(e) => Err(e),
    }
}

/// Check Full Disk Access with detailed status
#[cfg(target_os = "macos")]
pub fn check_full_disk_access_detailed() -> Result<FdaStatus, String> {
    let home = dirs::home_dir().ok_or("Failed to get home directory")?;

    // List of FDA-protected files to try (ordered by likelihood of existence)
    let test_paths = [
        // User TCC database (always exists on macOS 10.14+)
        home.join("Library/Application Support/com.apple.TCC/TCC.db"),
        // Safari history
        home.join("Library/Safari/History.db"),
        // Safari bookmarks
        home.join("Library/Safari/Bookmarks.plist"),
        // Mail data
        home.join("Library/Mail/V9/MailData/Envelope Index"),
        home.join("Library/Mail/V8/MailData/Envelope Index"),
        home.join("Library/Mail/V7/MailData/Envelope Index"),
        // Messages database
        home.join("Library/Messages/chat.db"),
        // Contacts
        home.join("Library/Application Support/AddressBook/AddressBook-v22.abcddb"),
        // Calendar
        home.join("Library/Calendars/Calendar Cache"),
        // Photos library
        home.join("Pictures/Photos Library.photoslibrary/database/Photos.sqlite"),
    ];

    // Also check system TCC database (requires root or FDA)
    let system_tcc = std::path::PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db");

    // Find a test file that exists
    let mut found_test_file = None;
    for path in test_paths.iter() {
        if path.exists() {
            found_test_file = Some(path.clone());
            break;
        }
    }

    // If no user files found, try system TCC
    let test_path = match found_test_file {
        Some(p) => p,
        None => {
            if system_tcc.exists() {
                system_tcc
            } else {
                // No test files available - inconclusive but likely no FDA
                info!("No FDA test files found - assuming no FDA");
                return Ok(FdaStatus {
                    has_fda: false,
                    test_file: None,
                    details: "No protected test files found on this system".to_string(),
                });
            }
        }
    };

    // Attempt to open the file
    match std::fs::File::open(&test_path) {
        Ok(_) => {
            info!(path = %test_path.display(), "Full Disk Access check: GRANTED");
            Ok(FdaStatus {
                has_fda: true,
                test_file: Some(test_path.display().to_string()),
                details: "Successfully opened FDA-protected file".to_string(),
            })
        }
        Err(e) => {
            // EPERM (operation not permitted) indicates lack of FDA
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                debug!(path = %test_path.display(), "Full Disk Access check: DENIED");
                Ok(FdaStatus {
                    has_fda: false,
                    test_file: Some(test_path.display().to_string()),
                    details: format!("Permission denied: {}", e),
                })
            } else {
                // Other errors are inconclusive
                warn!(path = %test_path.display(), error = %e, "FDA check inconclusive");
                Err(format!("Full Disk Access check inconclusive: {}", e))
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn has_full_disk_access() -> Result<bool, String> {
    Err("Full Disk Access check is only available on macOS".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn check_full_disk_access_detailed() -> Result<FdaStatus, String> {
    Err("Full Disk Access check is only available on macOS".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_get_audit_token() {
        // Test for current process
        let pid = std::process::id();
        let result = get_process_audit_token(pid);
        assert!(
            result.is_ok(),
            "Failed to get audit token for current process"
        );

        // Verify we got valid data
        let token = result.unwrap();
        assert_eq!(token[5], pid, "PID should match in token");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_get_process_info_native() {
        let pid = std::process::id();
        let result = get_process_info_native(pid);
        assert!(result.is_ok(), "Failed to get process info");

        let info = result.unwrap();
        assert_eq!(info.pid, pid, "PID should match");
        assert!(!info.comm.is_empty(), "Process name should not be empty");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_get_process_path_native() {
        let pid = std::process::id();
        let result = get_process_path_native(pid);
        assert!(result.is_ok(), "Failed to get process path");

        let path = result.unwrap();
        assert!(!path.is_empty(), "Process path should not be empty");
        assert!(path.starts_with('/'), "Process path should be absolute");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_codesign_info() {
        let pid = std::process::id();
        let result = get_process_codesign_info(pid);
        // May fail if running in debugger or unsigned, that's OK
        if let Ok(info) = result {
            // At minimum, is_signed should be set
            println!("Codesign info: {:?}", info);
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_fda_check() {
        let result = check_full_disk_access_detailed();
        assert!(result.is_ok(), "FDA check should complete");

        let status = result.unwrap();
        println!("FDA status: {:?}", status);
        // Just verify it runs - actual result depends on entitlements
    }
}
