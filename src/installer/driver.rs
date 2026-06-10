//! Driver extraction, service registration, and minifilter loading.
//!
//! Handles extracting the embedded kernel driver to disk, creating the
//! Windows kernel driver service, setting up minifilter registry keys,
//! and loading the driver.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// Include the generated driver bytes from build.rs
include!(concat!(env!("OUT_DIR"), "/driver_embedded.rs"));

/// Default driver file name
const DRIVER_FILENAME: &str = "tamandua.sys";

/// Default driver service name
#[allow(dead_code)]
const DRIVER_SERVICE_NAME: &str = "tamandua";

/// Minifilter altitude (FSFilter Activity Monitor range: 360000-389999)
const MINIFILTER_ALTITUDE: &str = "385200";

/// Minifilter instance name
const MINIFILTER_INSTANCE_NAME: &str = "Tamandua Instance";

/// Extract the embedded driver to the specified path and verify integrity.
pub fn extract_to(dest: &Path) -> Result<()> {
    if !DRIVER_EMBEDDED {
        bail!("No driver binary was embedded at build time. Build with the driver present to enable installation.");
    }

    if DRIVER_BYTES.is_empty() {
        bail!("Embedded driver is empty");
    }

    // Verify SHA-256 integrity
    let mut hasher = Sha256::new();
    hasher.update(DRIVER_BYTES);
    let computed_hash = hex::encode(hasher.finalize());

    if computed_hash != DRIVER_SHA256 {
        bail!(
            "Driver integrity check failed: expected {}, got {}",
            DRIVER_SHA256,
            computed_hash
        );
    }

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Write driver to disk
    std::fs::write(dest, DRIVER_BYTES)
        .with_context(|| format!("Failed to write driver to: {}", dest.display()))?;

    info!(
        path = %dest.display(),
        size = DRIVER_BYTES.len(),
        sha256 = %DRIVER_SHA256,
        "Driver extracted successfully"
    );

    Ok(())
}

/// Default path for the driver installation.
pub fn default_driver_path() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\drivers").join(DRIVER_FILENAME)
}

/// Check if the embedded driver is available.
pub fn has_embedded_driver() -> bool {
    DRIVER_EMBEDDED && !DRIVER_BYTES.is_empty()
}

/// Get the size of the embedded driver in bytes.
pub fn embedded_driver_size() -> usize {
    DRIVER_BYTES.len()
}

/// Create the kernel driver service via Windows SCM.
#[cfg(target_os = "windows")]
pub fn create_driver_service(service_name: &str, sys_path: &Path) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::*;

    let sys_path_str = sys_path.to_string_lossy();

    // Convert strings to wide (UTF-16)
    let service_name_w: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let display_name = format!("Tamandua EDR Driver");
    let display_name_w: Vec<u16> = display_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let binary_path_w: Vec<u16> = sys_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let load_group = "FSFilter Anti-Virus";
    let load_group_w: Vec<u16> = load_group
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Open SCM
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
            .context("Failed to open Service Control Manager")?;

        let _scm_guard = scopeguard::guard(scm, |h| {
            let _ = CloseServiceHandle(h);
        });

        // Create the driver service. Re-running the GUI installer should be
        // idempotent, so an existing driver service is treated as success.
        let service = match CreateServiceW(
            scm,
            PCWSTR(service_name_w.as_ptr()),
            PCWSTR(display_name_w.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER, // type = kernel driver
            // The kernel driver is still a guarded/lab capability. Keep it
            // demand-start by default to avoid boot-loop risk until release
            // signing, HLK coverage, and recovery telemetry are complete.
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(binary_path_w.as_ptr()),
            PCWSTR(load_group_w.as_ptr()), // load order group
            None,                          // tag id
            PCWSTR::null(),                // dependencies
            PCWSTR::null(),                // service start name
            PCWSTR::null(),                // password
        ) {
            Ok(service) => {
                info!(
                    service = service_name,
                    path = %sys_path.display(),
                    "Driver service created"
                );
                service
            }
            Err(error) if error.code().0 == 0x80070431u32 as i32 => {
                warn!(
                    service = service_name,
                    error = %error,
                    "Driver service already exists; reusing existing service"
                );

                OpenServiceW(scm, PCWSTR(service_name_w.as_ptr()), SERVICE_ALL_ACCESS)
                    .context("Failed to open existing driver service")?
            }
            Err(error) => {
                return Err(error).context("Failed to create driver service");
            }
        };

        let _svc_guard = scopeguard::guard(service, |h| {
            let _ = CloseServiceHandle(h);
        });
    }

    // Register minifilter instance in the registry
    register_minifilter_instance(service_name)?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn create_driver_service(_service_name: &str, _sys_path: &Path) -> Result<()> {
    bail!("Driver service creation is only supported on Windows");
}

/// Register minifilter instance and altitude in the Windows registry.
#[cfg(target_os = "windows")]
fn register_minifilter_instance(service_name: &str) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Create the Instances subkey under the driver's service key
    let instances_path = format!(
        r"SYSTEM\CurrentControlSet\Services\{}\Instances",
        service_name
    );
    let (instances_key, _) = hklm
        .create_subkey(&instances_path)
        .context("Failed to create minifilter Instances key")?;

    // Set the default instance
    instances_key
        .set_value("DefaultInstance", &MINIFILTER_INSTANCE_NAME)
        .context("Failed to set DefaultInstance")?;

    // Create the instance subkey
    let instance_path = format!(r"{}\{}", instances_path, MINIFILTER_INSTANCE_NAME);
    let (instance_key, _) = hklm
        .create_subkey(&instance_path)
        .context("Failed to create minifilter instance key")?;

    // Set altitude and flags
    instance_key
        .set_value("Altitude", &MINIFILTER_ALTITUDE)
        .context("Failed to set minifilter Altitude")?;

    instance_key
        .set_value("Flags", &0x0u32)
        .context("Failed to set minifilter Flags")?;

    info!(
        altitude = MINIFILTER_ALTITUDE,
        instance = MINIFILTER_INSTANCE_NAME,
        "Minifilter instance registered"
    );

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn register_minifilter_instance(_service_name: &str) -> Result<()> {
    Ok(())
}

/// Load the minifilter driver using fltmc.
#[cfg(target_os = "windows")]
pub fn load_driver(service_name: &str) -> Result<()> {
    // Try FilterLoad API first via fltlib
    // Fall back to fltmc command-line tool
    let output = std::process::Command::new("fltmc")
        .args(["load", service_name])
        .output()
        .context("Failed to execute fltmc")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Error 0x801F0010 = already loaded, which is OK
        if stderr.contains("0x801F0010") || stdout.contains("0x801F0010") {
            info!(service = service_name, "Driver already loaded");
            return Ok(());
        }

        bail!(
            "fltmc load failed (exit {}): {} {}",
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        );
    }

    info!(service = service_name, "Minifilter driver loaded");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn load_driver(_service_name: &str) -> Result<()> {
    bail!("Driver loading is only supported on Windows");
}

/// Unload the minifilter driver.
#[cfg(target_os = "windows")]
pub fn unload_driver(service_name: &str) -> Result<()> {
    let output = std::process::Command::new("fltmc")
        .args(["unload", service_name])
        .output()
        .context("Failed to execute fltmc")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Not loaded = OK for uninstall
        if stderr.contains("0x801F0013") || stdout.contains("0x801F0013") {
            info!(service = service_name, "Driver was not loaded");
            return Ok(());
        }

        warn!(
            service = service_name,
            stderr = %stderr.trim(),
            "fltmc unload returned an error (continuing)"
        );
    } else {
        info!(service = service_name, "Minifilter driver unloaded");
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn unload_driver(_service_name: &str) -> Result<()> {
    Ok(())
}

/// Delete the driver service from SCM.
#[cfg(target_os = "windows")]
pub fn delete_driver_service(service_name: &str) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::*;

    let service_name_w: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
            .context("Failed to open SCM")?;

        let _scm_guard = scopeguard::guard(scm, |h| {
            let _ = CloseServiceHandle(h);
        });

        let service = match OpenServiceW(scm, PCWSTR(service_name_w.as_ptr()), SERVICE_ALL_ACCESS) {
            Ok(s) => s,
            Err(e) => {
                // Service doesn't exist - that's fine for uninstall
                warn!(service = service_name, error = %e, "Driver service not found (may already be removed)");
                return Ok(());
            }
        };

        let _svc_guard = scopeguard::guard(service, |h| {
            let _ = CloseServiceHandle(h);
        });

        DeleteService(service).context("Failed to delete driver service")?;

        info!(service = service_name, "Driver service deleted");
    }

    // Clean up minifilter registry keys
    clean_minifilter_registry(service_name);

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn delete_driver_service(_service_name: &str) -> Result<()> {
    Ok(())
}

/// Remove minifilter registry keys during uninstall.
#[cfg(target_os = "windows")]
fn clean_minifilter_registry(service_name: &str) {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let instances_path = format!(
        r"SYSTEM\CurrentControlSet\Services\{}\Instances",
        service_name
    );

    if let Err(e) = hklm.delete_subkey_all(&instances_path) {
        // Not critical - the service deletion will clean up anyway
        warn!(path = %instances_path, error = %e, "Failed to clean minifilter registry keys");
    }
}

#[cfg(not(target_os = "windows"))]
fn clean_minifilter_registry(_service_name: &str) {}
