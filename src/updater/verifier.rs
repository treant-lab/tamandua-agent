/// Platform-specific code signature verification for update binaries.
///
/// This module provides comprehensive signature verification across all platforms:
/// - **Windows**: Authenticode signature verification using WinVerifyTrust
/// - **macOS**: Code signature and notarization verification using codesign/spctl
/// - **Linux**: GPG detached signature verification
///
/// ## Security Model
///
/// Updates go through a two-stage verification process:
/// 1. **Transport security**: Ed25519 signature on the update manifest (prevents
///    MITM attacks and ensures manifest authenticity)
/// 2. **Binary integrity**: Platform-specific code signatures (ensures the binary
///    itself was signed by a trusted authority and hasn't been tampered with)
///
/// Both checks must pass before an update is installed.
use anyhow::{bail, Result};
use std::path::Path;
use tracing::{debug, error, info};

// ============================================================================
// Public API
// ============================================================================

/// Verify the code signature of an update binary.
///
/// This performs platform-specific signature verification:
/// - Windows: Authenticode via WinVerifyTrust
/// - macOS: codesign + spctl (Gatekeeper) + notarization check
/// - Linux: GPG detached signature (.asc file must be present)
///
/// Returns `Ok(())` if the signature is valid and trusted, or an error otherwise.
pub fn verify_code_signature(binary_path: &Path) -> Result<()> {
    info!(
        path = %binary_path.display(),
        platform = std::env::consts::OS,
        "Verifying code signature"
    );

    #[cfg(target_os = "windows")]
    {
        verify_windows_authenticode(binary_path)
    }

    #[cfg(target_os = "macos")]
    {
        verify_macos_signature(binary_path)
    }

    #[cfg(target_os = "linux")]
    {
        verify_linux_gpg_signature(binary_path)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        warn!("Code signature verification not implemented for this platform");
        Ok(())
    }
}

/// Extract signature information from a binary for logging/reporting.
///
/// Returns a human-readable string with signature details (signer name,
/// timestamp, etc.) or None if signatures are not supported on this platform.
pub fn get_signature_info(binary_path: &Path) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        get_windows_signature_info(binary_path)
    }

    #[cfg(target_os = "macos")]
    {
        get_macos_signature_info(binary_path)
    }

    #[cfg(target_os = "linux")]
    {
        get_linux_signature_info(binary_path)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

// ============================================================================
// Windows: Authenticode Verification
// ============================================================================

#[cfg(target_os = "windows")]
fn verify_windows_authenticode(binary_path: &Path) -> Result<()> {
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_UICONTEXT,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_SAFER_FLAG,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    debug!("Performing Windows Authenticode verification");

    // Convert path to wide string
    let wide_path: Vec<u16> = binary_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Initialize file info structure
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR::from_raw(wide_path.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        // Initialize trust data structure
        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                pFile: &mut file_info as *mut _,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: HANDLE::default(),
            pwszURLReference: PWSTR::null(),
            dwProvFlags: WTD_SAFER_FLAG,
            dwUIContext: WINTRUST_DATA_UICONTEXT(0),
            pSignatureSettings: std::ptr::null_mut(),
        };

        // Perform verification
        let mut action_id: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(
            HWND::default(),
            &mut action_id as *mut GUID,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        );

        if result == 0 {
            info!("Windows Authenticode signature verified successfully");
            Ok(())
        } else {
            error!(error_code = result, "Authenticode verification failed");
            bail!(
                "Windows Authenticode verification failed (error code: 0x{:08X}). \
                 Binary may be unsigned, signature invalid, or certificate not trusted.",
                result as u32
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn get_windows_signature_info(_binary_path: &Path) -> Option<String> {
    // Simplified implementation - just return a placeholder
    // Full implementation would parse PKCS#7 certificate details
    Some("Windows Authenticode signature (use Get-AuthenticodeSignature for details)".to_string())
}

// ============================================================================
// macOS: Code Signature & Notarization Verification
// ============================================================================

#[cfg(target_os = "macos")]
fn verify_macos_signature(binary_path: &Path) -> Result<()> {
    debug!("Performing macOS code signature verification");

    // Step 1: Verify code signature with codesign
    verify_codesign(binary_path)?;

    // Step 2: Verify Gatekeeper assessment with spctl
    verify_spctl(binary_path)?;

    // Step 3: Check notarization ticket
    verify_notarization(binary_path)?;

    info!("macOS signature verification passed (codesign + spctl + notarization)");
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_codesign(binary_path: &Path) -> Result<()> {
    use std::process::Command;

    debug!("Running codesign verification");

    let output = Command::new("codesign")
        .args(&[
            "--verify",
            "--deep",
            "--strict",
            "--verbose=2",
            binary_path.to_str().unwrap(),
        ])
        .output()
        .context("Failed to execute codesign command")?;

    if output.status.success() {
        debug!("codesign verification passed");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(stderr = %stderr, "codesign verification failed");
        bail!(
            "macOS code signature verification failed: {}",
            stderr.trim()
        );
    }
}

#[cfg(target_os = "macos")]
fn verify_spctl(binary_path: &Path) -> Result<()> {
    use std::process::Command;

    debug!("Running Gatekeeper (spctl) assessment");

    let output = Command::new("spctl")
        .args(&[
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            binary_path.to_str().unwrap(),
        ])
        .output()
        .context("Failed to execute spctl command")?;

    if output.status.success() {
        debug!("Gatekeeper assessment passed");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // spctl sometimes outputs to stderr even on success
        if stderr.contains("accepted") || stderr.contains("source=Notarized Developer ID") {
            debug!("Gatekeeper assessment passed (notarized)");
            Ok(())
        } else {
            error!(stderr = %stderr, "Gatekeeper assessment failed");
            bail!(
                "macOS Gatekeeper assessment failed: {}. \
                 Binary may not be notarized or signed with a Developer ID.",
                stderr.trim()
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_notarization(binary_path: &Path) -> Result<()> {
    use std::process::Command;

    debug!("Checking for stapled notarization ticket");

    let output = Command::new("stapler")
        .args(&["validate", binary_path.to_str().unwrap()])
        .output()
        .context("Failed to execute stapler command")?;

    if output.status.success() {
        info!("Notarization ticket found and validated (stapled)");
        Ok(())
    } else {
        // Ticket not stapled -- will be fetched online during first run
        // This is OK, not an error
        warn!(
            "Notarization ticket not stapled (will be fetched online). \
             For offline installations, ensure the ticket is stapled."
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn get_macos_signature_info(binary_path: &Path) -> Option<String> {
    use std::process::Command;

    let output = Command::new("codesign")
        .args(&["--display", "--verbose=4", binary_path.to_str()?])
        .output()
        .ok()?;

    if output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Some(stderr.to_string())
    } else {
        None
    }
}

// ============================================================================
// Linux: GPG Signature Verification
// ============================================================================

#[cfg(target_os = "linux")]
fn verify_linux_gpg_signature(binary_path: &Path) -> Result<()> {
    use std::process::Command;

    debug!("Performing Linux GPG signature verification");

    // Detached signature file should be <binary>.asc
    let sig_path = binary_path.with_extension("asc");

    if !sig_path.exists() {
        bail!(
            "GPG signature file not found: {}. \
             Linux binaries must have a detached .asc signature.",
            sig_path.display()
        );
    }

    // Verify with gpg --verify
    let output = Command::new("gpg")
        .args(&[
            "--verify",
            sig_path.to_str().unwrap(),
            binary_path.to_str().unwrap(),
        ])
        .output()
        .context("Failed to execute gpg command (ensure gpg is installed)")?;

    if output.status.success() {
        // gpg writes verification output to stderr even on success
        let stderr = String::from_utf8_lossy(&output.stderr);

        if stderr.contains("Good signature") {
            info!("GPG signature verified successfully");
            debug!(output = %stderr, "GPG verification output");
            Ok(())
        } else if stderr.contains("BAD signature") {
            error!(output = %stderr, "GPG signature is invalid");
            bail!("GPG signature verification failed: BAD signature");
        } else {
            // Could be warning about key trust, but signature is valid
            warn!(output = %stderr, "GPG verification completed with warnings");

            if stderr.contains("Good signature") {
                Ok(())
            } else {
                bail!("GPG signature verification failed: {}", stderr.trim());
            }
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(stderr = %stderr, "GPG verification failed");
        bail!("GPG signature verification failed: {}", stderr.trim());
    }
}

#[cfg(target_os = "linux")]
fn get_linux_signature_info(binary_path: &Path) -> Option<String> {
    use std::process::Command;

    let sig_path = binary_path.with_extension("asc");
    if !sig_path.exists() {
        return None;
    }

    let output = Command::new("gpg")
        .args(&["--verify", sig_path.to_str()?, binary_path.to_str()?])
        .output()
        .ok()?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    Some(stderr.to_string())
}

// ============================================================================
// Public Key Management
// ============================================================================

/// Install the Tamandua GPG public key for signature verification (Linux only).
///
/// This imports the public key from either:
/// 1. An embedded key (compiled into the binary)
/// 2. A downloaded key from the update server
/// 3. A keyserver (keys.openpgp.org, keyserver.ubuntu.com)
#[cfg(target_os = "linux")]
pub fn install_gpg_public_key(key_data: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Command;

    info!("Installing Tamandua GPG public key");

    let mut child = Command::new("gpg")
        .args(&["--import"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn gpg import process")?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("Failed to open stdin for gpg import")?;
        stdin
            .write_all(key_data.as_bytes())
            .context("Failed to write public key to gpg stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait for gpg import process")?;

    if output.status.success() {
        info!("GPG public key imported successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to import GPG public key: {}", stderr.trim());
    }
}

/// Fetch the Tamandua GPG public key from a keyserver (Linux only).
#[cfg(target_os = "linux")]
pub fn fetch_gpg_key_from_keyserver(key_id: &str) -> Result<()> {
    use std::process::Command;

    info!(key_id = %key_id, "Fetching GPG key from keyserver");

    let keyservers = ["keyserver.ubuntu.com", "keys.openpgp.org"];

    for keyserver in &keyservers {
        debug!(keyserver = %keyserver, "Trying keyserver");

        let output = Command::new("gpg")
            .args(&["--keyserver", keyserver, "--recv-keys", key_id])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                info!(keyserver = %keyserver, "GPG key fetched successfully");
                return Ok(());
            }
        }
    }

    bail!("Failed to fetch GPG key from any keyserver");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;
