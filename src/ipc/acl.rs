//! Windows ACL implementation for IPC security
//!
//! This module provides functions to apply restrictive ACLs to:
//! - IPC token file (SYSTEM + Administrators only)
//! - Named pipe (SYSTEM + Administrators full control, Authenticated Users read/write)
//!
//! # Security Model
//!
//! ## Token File ACL
//! The IPC token file stores a shared secret used for challenge-response authentication
//! between the agent service and GUI/CLI clients. Access is restricted to:
//! - **SYSTEM**: The agent service runs as SYSTEM and needs full control
//! - **Administrators**: GUI/CLI need elevation to read the token for authentication
//! - **No others**: Unprivileged users cannot read the token, preventing unauthorized IPC
//!
//! This model ensures that only elevated processes can authenticate to the agent,
//! providing defense-in-depth alongside the challenge-response protocol.
//!
//! ## Named Pipe ACL
//! The named pipe endpoint allows IPC communication. Access is:
//! - **SYSTEM**: Full control for the agent service
//! - **Administrators**: Full control for elevated management tools
//! - **Authenticated Users**: Read/Write to allow GUI connections
//!
//! Non-elevated users can connect to the pipe but must still pass challenge-response
//! authentication, which requires reading the token file (which they cannot access).
//! This provides a layered security model where pipe access alone is insufficient.

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use std::path::Path;
use tracing::{debug, info, warn};

#[cfg(windows)]
use windows::Win32::Security::{
    Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    },
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};

#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};

#[cfg(windows)]
use windows::core::PCWSTR;

/// Security Descriptor Definition Language (SDDL) for token file:
/// - Owner: SYSTEM (SY)
/// - DACL:
///   - SYSTEM: Full control (FA)
///   - Administrators: Full control (FA)
///   - No access for anyone else
#[cfg(windows)]
const TOKEN_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// SDDL for named pipe:
/// - Owner: SYSTEM (SY)
/// - DACL:
///   - SYSTEM: Full control (FA)
///   - Administrators: Full control (FA)
///   - Authenticated Users: Read/Write (GRGW)
///
/// The GUI runs as an authenticated user (admin or standard), so we allow
/// authenticated users to connect. The challenge-response auth provides
/// the actual authorization control.
#[cfg(windows)]
const NAMED_PIPE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGW;;;AU)";

/// Apply restrictive ACL to the IPC token file.
///
/// On Windows, this sets a DACL that grants:
/// - SYSTEM: Full control
/// - Administrators: Full control
/// - Everyone else: No access
///
/// This prevents unprivileged users from reading the token file.
///
/// # Implementation Notes
///
/// The SDDL string is first converted to a security descriptor, then we
/// extract the DACL pointer from it using `GetSecurityDescriptorDacl`.
/// This extracted DACL is what we pass to `SetNamedSecurityInfoW`.
///
/// The security descriptor must be freed with `LocalFree` after use,
/// but only after `SetNamedSecurityInfoW` has completed (it copies the DACL).
#[cfg(windows)]
pub fn set_token_file_acl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::BOOL;

    info!("Setting restrictive ACL on token file: {}", path.display());

    // Convert path to wide string
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Convert SDDL to security descriptor
    let sddl_wide: Vec<u16> = TOKEN_FILE_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut sd_size: u32 = 0;

    unsafe {
        // Parse SDDL string into a security descriptor
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl_wide.as_ptr()),
            1, // SDDL_REVISION_1
            &mut sd,
            Some(&mut sd_size),
        )
        .map_err(|e| {
            warn!("Failed to parse SDDL for token file: {}", e);
            anyhow::anyhow!("Failed to parse SDDL for token file: {}", e)
        })?;

        // Ensure we free the security descriptor on all exit paths
        let _sd_guard = scopeguard::guard(sd, |sd| {
            if !sd.0.is_null() {
                let _ = LocalFree(HLOCAL(sd.0));
            }
        });

        // Extract DACL from the security descriptor
        // The DACL is embedded within the security descriptor, not the descriptor itself
        let mut dacl_present: BOOL = BOOL::default();
        let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted: BOOL = BOOL::default();

        GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted)
            .map_err(|e| {
                warn!("Failed to extract DACL from security descriptor: {}", e);
                anyhow::anyhow!("Failed to extract DACL from security descriptor: {}", e)
            })?;

        if !dacl_present.as_bool() {
            warn!("Security descriptor does not contain a DACL");
            return Err(anyhow::anyhow!(
                "Security descriptor does not contain a DACL"
            ));
        }

        if dacl_ptr.is_null() {
            // NULL DACL means full access to everyone - not what we want
            warn!("DACL is NULL (grants everyone full access)");
            return Err(anyhow::anyhow!("DACL is NULL, cannot apply security"));
        }

        // Apply the extracted DACL to the file
        // SetNamedSecurityInfoW copies the DACL, so we can free sd after this
        SetNamedSecurityInfoW(
            PCWSTR::from_raw(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,           // owner - don't change
            None,           // group - don't change
            Some(dacl_ptr), // dacl - the extracted DACL pointer
            None,           // sacl - don't change
        )
        .map_err(|e| {
            warn!("Failed to set ACL on token file: {}", e);
            anyhow::anyhow!("Failed to set ACL on token file: {}", e)
        })?;
    }

    debug!(
        "Successfully applied restrictive ACL to token file: {}",
        path.display()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_admin_group(path: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let group_name = CString::new("admin").context("Invalid macOS admin group name")?;
    let group = unsafe { libc::getgrnam(group_name.as_ptr()) };
    if group.is_null() {
        return Err(anyhow::anyhow!("macOS admin group was not found"));
    }

    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("Invalid IPC path: {}", path.display()))?;
    let gid = unsafe { (*group).gr_gid };
    let result = unsafe { libc::chown(c_path.as_ptr(), 0, gid) };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to set root:admin ownership on {}", path.display()))
    }
}

/// Unix implementation - uses standard file permissions.
#[cfg(unix)]
pub fn set_token_file_acl(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    info!(
        "Setting restrictive permissions on token file: {}",
        path.display()
    );

    #[cfg(target_os = "macos")]
    set_admin_group(path)?;

    let mut perms = std::fs::metadata(path)
        .context("Failed to get file metadata")?
        .permissions();

    #[cfg(target_os = "macos")]
    perms.set_mode(0o640); // Root writes; admin-group GUI clients can read the IPC secret.

    #[cfg(not(target_os = "macos"))]
    perms.set_mode(0o600); // Read/write for owner only

    std::fs::set_permissions(path, perms).context("Failed to set permissions")?;

    #[cfg(target_os = "macos")]
    let mode = "0640";

    #[cfg(not(target_os = "macos"))]
    let mode = "0600";

    debug!(
        "Successfully set {} permissions on token file: {}",
        mode,
        path.display()
    );
    Ok(())
}

/// Apply restrictive permissions to the Unix IPC socket.
#[cfg(unix)]
pub fn set_socket_file_acl(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "macos")]
    set_admin_group(path)?;

    let mut perms = std::fs::metadata(path)
        .context("Failed to get IPC socket metadata")?
        .permissions();

    #[cfg(target_os = "macos")]
    perms.set_mode(0o660); // Root/admin read-write.

    #[cfg(not(target_os = "macos"))]
    perms.set_mode(0o600); // Owner read-write only.

    std::fs::set_permissions(path, perms).context("Failed to set IPC socket permissions")?;

    Ok(())
}

/// Create security attributes for the named pipe.
///
/// Returns a SECURITY_ATTRIBUTES structure with a DACL that grants:
/// - SYSTEM: Full control
/// - Administrators: Full control
/// - Authenticated Users: Read/Write (connect and communicate)
///
/// # Implementation Notes
///
/// Unlike `set_token_file_acl` which uses `SetNamedSecurityInfoW` (requires a DACL),
/// pipe creation via `CreateNamedPipeW` accepts a full security descriptor in the
/// `SECURITY_ATTRIBUTES.lpSecurityDescriptor` field. This is correct API usage.
///
/// # Safety
///
/// The returned `PipeSecurityContext` owns the security descriptor memory.
/// It must be kept alive for the duration of the pipe's lifetime, as the
/// security attributes contain a raw pointer to the security descriptor.
#[cfg(windows)]
pub struct PipeSecurityContext {
    pub security_attributes: SECURITY_ATTRIBUTES,
    _security_descriptor: PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl std::fmt::Debug for PipeSecurityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeSecurityContext")
            .field("nLength", &self.security_attributes.nLength)
            .field(
                "bInheritHandle",
                &self.security_attributes.bInheritHandle.as_bool(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl PipeSecurityContext {
    /// Create a new security context for named pipe creation.
    ///
    /// The security descriptor grants SYSTEM and Administrators full control,
    /// while Authenticated Users get read/write access for IPC communication.
    pub fn new() -> Result<Self> {
        // Convert SDDL to security descriptor
        let sddl_wide: Vec<u16> = NAMED_PIPE_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        let mut sd_size: u32 = 0;

        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR::from_raw(sddl_wide.as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd,
                Some(&mut sd_size),
            )
            .map_err(|e| {
                warn!("Failed to parse SDDL for named pipe: {}", e);
                anyhow::anyhow!("Failed to parse SDDL for named pipe: {}", e)
            })?;

            // For CreateNamedPipeW, we pass the full security descriptor
            // (not just the DACL) via SECURITY_ATTRIBUTES.lpSecurityDescriptor
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };

            debug!(
                "Created pipe security context with {} byte security descriptor",
                sd_size
            );

            Ok(Self {
                security_attributes: sa,
                _security_descriptor: sd,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for PipeSecurityContext {
    fn drop(&mut self) {
        unsafe {
            if !self._security_descriptor.0.is_null() {
                let _ = LocalFree(HLOCAL(self._security_descriptor.0));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_token_file_acl() {
        let temp_dir = tempfile::tempdir().unwrap();
        let token_path = temp_dir.path().join("test_token.json");

        // Create a test file
        std::fs::write(&token_path, "test").unwrap();

        // Apply ACL
        let result = set_token_file_acl(&token_path);
        assert!(result.is_ok(), "Failed to set token file ACL: {:?}", result);
    }

    #[test]
    #[cfg(windows)]
    fn test_pipe_security_context() {
        let result = PipeSecurityContext::new();
        assert!(
            result.is_ok(),
            "Failed to create pipe security context: {:?}",
            result
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_token_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let token_path = temp_dir.path().join("test_token.json");

        // Create a test file
        std::fs::write(&token_path, "test").unwrap();

        // Apply permissions
        let result = set_token_file_acl(&token_path);
        assert!(result.is_ok());

        // Verify permissions
        let metadata = std::fs::metadata(&token_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
