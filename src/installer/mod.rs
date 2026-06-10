//! Self-contained installer for the Tamandua EDR agent.
//!
//! Orchestrates the complete installation and uninstallation flow:
//! - Token validation and exchange with backend
//! - Directory structure creation
//! - Agent binary deployment
//! - Kernel driver extraction and service registration
//! - Scheduled task for backup persistence
//! - WMI event subscription for backup persistence
//! - Configuration file generation
//! - Service registration and startup
//! - Service recovery actions configuration
//! - Uninstall protection via hashed token

pub mod driver;
pub mod scheduled_task;
pub mod service_recovery;
pub mod token;
pub mod wmi_persistence;

// Re-export for convenience
pub use scheduled_task::{
    check_scheduled_task, install_scheduled_task, remove_scheduled_task, TASK_NAME,
};
pub use service_recovery::{configure_service_recovery, RecoveryDelays};
pub use wmi_persistence::{
    check_wmi_persistence, install_wmi_persistence, remove_wmi_persistence, verify_wmi_persistence,
    WMI_PERSISTENCE_NAME,
};

use crate::pki::CertPaths;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::time::Duration;
use tracing::{info, warn};

/// Default service name for persistence checks.
pub const DEFAULT_SERVICE_NAME: &str = "TamanduaAgent";

/// Status of all persistence mechanisms.
#[derive(Debug, Clone, Default)]
pub struct PersistenceStatus {
    /// Windows service is installed and configured
    pub service_installed: bool,
    /// Service recovery actions are configured
    pub service_recovery_configured: bool,
    /// WMI event subscription is installed
    pub wmi_persistence_installed: bool,
    /// Scheduled task is installed
    pub scheduled_task_installed: bool,
    /// External watchdog process is running
    pub watchdog_running: bool,
    /// Kernel driver protection is active
    pub driver_protection_active: bool,
}

impl PersistenceStatus {
    /// Check if all persistence mechanisms are active.
    pub fn is_fully_protected(&self) -> bool {
        self.service_installed
            && self.service_recovery_configured
            && self.wmi_persistence_installed
            && self.scheduled_task_installed
    }

    /// Get a summary of missing persistence mechanisms.
    pub fn missing_mechanisms(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.service_installed {
            missing.push("Windows Service");
        }
        if !self.service_recovery_configured {
            missing.push("Service Recovery Actions");
        }
        if !self.wmi_persistence_installed {
            missing.push("WMI Event Subscription");
        }
        if !self.scheduled_task_installed {
            missing.push("Scheduled Task");
        }
        missing
    }

    /// Print status to console.
    pub fn print_status(&self) {
        println!("Persistence Status:");
        println!("=========================================");
        println!(
            "  Windows Service:         {}",
            if self.service_installed {
                "INSTALLED"
            } else {
                "NOT INSTALLED"
            }
        );
        println!(
            "  Service Recovery:        {}",
            if self.service_recovery_configured {
                "CONFIGURED"
            } else {
                "NOT CONFIGURED"
            }
        );
        println!(
            "  WMI Persistence:         {}",
            if self.wmi_persistence_installed {
                "INSTALLED"
            } else {
                "NOT INSTALLED"
            }
        );
        println!(
            "  Scheduled Task:          {}",
            if self.scheduled_task_installed {
                "INSTALLED"
            } else {
                "NOT INSTALLED"
            }
        );
        println!(
            "  Watchdog Process:        {}",
            if self.watchdog_running {
                "RUNNING"
            } else {
                "NOT RUNNING"
            }
        );
        println!(
            "  Driver Protection:       {}",
            if self.driver_protection_active {
                "ACTIVE"
            } else {
                "NOT ACTIVE"
            }
        );
        println!("=========================================");

        let missing = self.missing_mechanisms();
        if missing.is_empty() {
            println!("All persistence mechanisms are active.");
        } else {
            println!("Missing mechanisms: {}", missing.join(", "));
        }
    }
}

/// Installation configuration.
pub struct InstallConfig {
    /// Service name (default: "TamanduaAgent")
    pub name: String,
    /// Installation token for backend validation
    pub token: String,
    /// Backend server URL (WebSocket)
    pub server: String,
    /// Enrollment API base URL (HTTPS). Defaults to the server URL host.
    pub enrollment_url: Option<String>,
    /// Organization ID (optional, auto-detected from token)
    pub org_id: Option<String>,
    /// Skip driver installation
    pub no_driver: bool,
}

/// Uninstall configuration.
pub struct UninstallConfig {
    /// Service name
    pub name: String,
    /// Installation token for verification
    pub token: String,
}

#[derive(Debug, Clone)]
struct ExistingEnrollment {
    agent_id: String,
}

/// Default installation directory.
#[cfg(target_os = "windows")]
fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"\Program Files"))
        .join("Tamandua")
}

#[cfg(not(target_os = "windows"))]
fn install_dir() -> PathBuf {
    PathBuf::from("/opt/tamandua")
}

/// Default data directory.
#[cfg(target_os = "windows")]
fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"\ProgramData"))
        .join("Tamandua")
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/tamandua")
}

#[cfg(target_os = "macos")]
fn data_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/Tamandua")
}

/// Run the full installation flow.
pub async fn install(config: InstallConfig) -> Result<()> {
    println!(
        "Tamandua EDR Agent Installer v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("=========================================");

    // Step 0: Verify platform-specific elevated privileges.
    println!(
        "[1/10] Checking {} privileges...",
        elevated_privilege_label()
    );
    check_admin()?;

    // Step 1: Validate token against backend
    println!("[2/10] Validating installation token...");
    let enrollment_base = config.enrollment_url.as_deref().unwrap_or(&config.server);
    let mut validation_fallback_reason: Option<String> = None;
    let validation = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        token::validate_token(enrollment_base, &config.token),
    )
    .await
    {
        Err(_) => {
            warn!("Token validation timed out; continuing with offline service install");
            validation_fallback_reason = Some("Token validation timed out".to_string());
            println!("       WARNING: Token validation timed out.");
            println!(
                "       Continuing to CSR enrollment; the CSR endpoint will validate the token."
            );
            None
        }
        Ok(result) => match result {
            Ok(validation) => {
                println!("       Token is valid.");
                Some(validation)
            }
            Err(error) => {
                if is_fatal_token_validation_error(&error) {
                    bail!("Token validation failed: {}", error);
                }

                warn!(error = %error, "Token validation failed; continuing with offline service install");
                validation_fallback_reason = Some(error.to_string());
                println!("       WARNING: Token validation failed: {}", error);
                println!("       Continuing to CSR enrollment; the CSR endpoint will validate the token.");
                None
            }
        },
    };

    // Step 2: Create directory structure before CSR enrollment writes key material.
    println!("[3/10] Creating directory structure...");
    let install_path = install_dir();
    let data_path = data_dir();
    create_directories(&install_path, &data_path)?;
    let existing_enrollment = detect_existing_enrollment(&data_path);
    if let Some(existing) = &existing_enrollment {
        println!(
            "       Existing enrolled agent detected: {}",
            existing.agent_id
        );
    }

    // Step 3: Enroll using CSR so the private key never leaves the endpoint.
    println!("[4/10] Enrolling with CSR for mTLS credentials...");
    let cert_paths = CertPaths::default_paths();
    let mut enrollment_fallback_reason: Option<String> = None;
    let enrollment = {
        if validation.is_none() && existing_enrollment.is_some() {
            let reason = validation_fallback_reason
                .as_deref()
                .unwrap_or("token validation did not complete");
            warn!(
                reason = %reason,
                "Preserving existing enrollment instead of attempting CSR with an unvalidated token"
            );
            enrollment_fallback_reason = Some(format!(
                "Preserved existing enrollment because token validation failed: {}",
                reason
            ));
            println!("       Existing enrollment preserved; skipping CSR retry with invalid/unvalidated token.");
            None
        } else {
            if let Some(reason) = validation_fallback_reason.as_deref() {
                warn!(reason = %reason, "Attempting CSR enrollment despite token pre-validation failure");
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(180),
                token::enroll_with_csr(enrollment_base, &config.token, None),
            )
            .await
            {
                Err(_) => {
                    warn!("CSR enrollment timed out; continuing with offline service install");
                    enrollment_fallback_reason = Some(
                        "CSR enrollment timed out before mTLS credentials were issued".to_string(),
                    );
                    println!("       WARNING: CSR enrollment timed out.");
                    println!(
                        "       Continuing with offline service install. The agent will run locally"
                    );
                    println!(
                        "       and can be enrolled after the backend enrollment endpoint recovers."
                    );
                    None
                }
                Ok(result) => match result {
                    Ok(enrollment) => {
                        println!("       Agent ID: {}", enrollment.agent_id);
                        println!("       Org ID:   {}", enrollment.org_id);
                        println!("       Cert:     {}", cert_paths.cert_path.display());
                        Some(enrollment)
                    }
                    Err(error) => {
                        warn!(error = %error, "CSR enrollment failed; continuing with offline service install");
                        enrollment_fallback_reason = Some(error.to_string());
                        println!("       WARNING: CSR enrollment failed: {}", error);
                        println!("       Continuing with offline service install. The agent will run locally");
                        println!("       and can be enrolled after the backend enrollment endpoint recovers.");
                        None
                    }
                },
            }
        }
    };

    // Step 4: Copy agent binary
    println!("[5/10] Deploying agent binary...");
    let mut agent_dest = install_path.join(agent_binary_name());
    #[cfg(target_os = "windows")]
    prepare_existing_agent_for_upgrade(&config.name, &agent_dest);
    if let Err(error) = deploy_agent_binary(&agent_dest, &config.name) {
        #[cfg(target_os = "windows")]
        {
            warn!(
                error = %error,
                dest = %agent_dest.display(),
                "Primary agent binary deployment failed; falling back to ProgramData bin path"
            );
            println!(
                "       WARNING: Failed to deploy to {}: {}",
                agent_dest.display(),
                error
            );
            println!("       Falling back to ProgramData service binary.");

            let fallback_dir = data_path.join("bin");
            std::fs::create_dir_all(&fallback_dir).with_context(|| {
                format!(
                    "Failed to create fallback agent binary directory {}",
                    fallback_dir.display()
                )
            })?;
            let fallback_dest = fallback_dir.join(agent_binary_name());
            deploy_agent_binary(&fallback_dest, &config.name).with_context(|| {
                format!(
                    "Failed to deploy agent binary to primary path {} or fallback path {}",
                    agent_dest.display(),
                    fallback_dest.display()
                )
            })?;
            agent_dest = fallback_dest;
        }

        #[cfg(not(target_os = "windows"))]
        {
            return Err(error);
        }
    }

    // Step 5: Extract and install driver (Windows only)
    if !config.no_driver && cfg!(target_os = "windows") {
        if driver::has_embedded_driver() {
            println!("[6/10] Extracting kernel driver...");
            let driver_path = driver::default_driver_path();
            driver::extract_to(&driver_path)?;
            println!(
                "       Driver: {} ({} bytes)",
                driver_path.display(),
                driver::embedded_driver_size()
            );

            println!("[7/10] Registering driver service...");
            driver::create_driver_service("tamandua", &driver_path)?;
        } else {
            println!("[6/10] Skipping driver extraction (no driver embedded)");
            println!("[7/10] Skipping driver service registration");
        }
    } else {
        println!("[6/10] Skipping driver installation (--no-driver or non-Windows)");
        println!("[7/10] Skipping driver service registration");
    }

    // Step 6: Write config file
    println!("[8/10] Writing configuration...");
    if let Some(enrollment) = &enrollment {
        write_config(&data_path, &config.server, enrollment, &cert_paths)?;
    } else if let Some(existing) = &existing_enrollment {
        println!(
            "       Keeping existing enrolled configuration for agent {}.",
            existing.agent_id
        );
    } else {
        write_pending_config(
            &data_path,
            &config.server,
            config
                .org_id
                .as_deref()
                .or(validation
                    .as_ref()
                    .and_then(|value| value.org_id.as_deref()))
                .unwrap_or("pending"),
        )?;
    }

    // Step 7: Register agent service
    println!("[9/10] Registering agent service...");
    register_agent_service(&config.name, &agent_dest, &data_path)?;

    // Step 7b: Configure service recovery actions (Windows only)
    #[cfg(target_os = "windows")]
    {
        println!("       Configuring service recovery actions...");
        if let Err(e) = service_recovery::configure_service_recovery(&config.name, None) {
            warn!(error = %e, "Failed to configure service recovery (non-fatal)");
            println!("       WARNING: Recovery configuration failed: {}", e);
        } else {
            println!("       Recovery: restart after 5s/10s/30s, reset after 1 day");
        }
    }

    // Step 7c: Install scheduled task for backup persistence (Windows only)
    #[cfg(target_os = "windows")]
    {
        println!("       Installing backup scheduled task...");
        if let Err(e) = scheduled_task::install_scheduled_task(&agent_dest) {
            warn!(error = %e, "Failed to install scheduled task (non-fatal)");
            println!("       WARNING: Scheduled task installation failed: {}", e);
        } else {
            println!(
                "       Task: {} (every 5 min + boot trigger)",
                scheduled_task::TASK_NAME
            );
        }
    }

    // Step 7d: Install WMI event subscription for backup persistence (Windows only)
    #[cfg(target_os = "windows")]
    {
        println!("       Installing WMI event subscription...");
        if let Err(e) = wmi_persistence::install_wmi_persistence(&agent_dest) {
            warn!(error = %e, "Failed to install WMI persistence (non-fatal)");
            println!("       WARNING: WMI persistence installation failed: {}", e);
        } else {
            println!(
                "       WMI: {} event subscription installed",
                wmi_persistence::WMI_PERSISTENCE_NAME
            );
        }
    }

    // Step 8: Load driver and start services
    if !config.no_driver && cfg!(target_os = "windows") && driver::has_embedded_driver() {
        println!("       Loading minifilter driver...");
        if let Err(e) = driver::load_driver("tamandua") {
            warn!(error = %e, "Failed to load driver (agent will run without kernel driver)");
            let message = e.to_string();
            if message.contains("0x80070241") || message.contains("digital signature") {
                println!(
                    "       WARNING: Kernel driver was installed but not loaded because Windows rejected the driver signature. The agent will run in user-mode until a signed driver is installed."
                );
            } else {
                println!("       WARNING: Driver load failed: {}", e);
            }
        }
    }

    println!("       Starting agent service...");
    start_agent_service(&config.name)?;

    // Step 9: Store hashed token for uninstall protection
    println!("[10/10] Securing installation...");
    let token_hash = token::hash_token(&config.token)?;
    token::store_token_hash(&token_hash)?;
    if enrollment.is_some() || validation.is_some() {
        token::store_recovery_token(&config.token)?;
    } else {
        warn!("Skipping recovery token storage because enrollment token was not validated");
    }

    println!();
    println!("=========================================");
    println!("Installation complete!");
    println!();
    println!(
        "  Agent ID:    {}",
        enrollment
            .as_ref()
            .map(|value| value.agent_id.as_str())
            .or_else(|| existing_enrollment
                .as_ref()
                .map(|value| value.agent_id.as_str()))
            .unwrap_or("pending-local")
    );
    println!("  Service:     {}", config.name);
    println!("  Install dir: {}", install_path.display());
    println!("  Data dir:    {}", data_path.display());
    println!("  Server:      {}", config.server);
    println!();
    if enrollment.is_some() || existing_enrollment.is_some() {
        println!("The agent is now running and connected to the backend.");
    } else {
        println!("The agent service is installed and started in offline enrollment-pending mode.");
        if let Some(reason) = enrollment_fallback_reason.as_deref() {
            println!("Enrollment pending reason: {}", reason);
        }
    }
    #[cfg(target_os = "windows")]
    println!("Use 'sc query {}' to check service status.", config.name);
    #[cfg(target_os = "macos")]
    println!(
        "Use 'launchctl print system/com.tamandua.{}' to check service status.",
        config.name.to_lowercase()
    );
    #[cfg(all(unix, not(target_os = "macos")))]
    println!(
        "Use 'systemctl status {}' to check service status.",
        config.name
    );
    #[cfg(target_os = "windows")]
    println!(
        "Use 'sc qfailure {}' to verify recovery actions.",
        config.name
    );

    Ok(())
}

/// Run the full uninstallation flow.
pub async fn uninstall(config: UninstallConfig) -> Result<()> {
    println!("Tamandua EDR Agent Uninstaller");
    println!("=========================================");

    // Step 0: Verify platform-specific elevated privileges.
    println!(
        "[1/7] Checking {} privileges...",
        elevated_privilege_label()
    );
    check_admin()?;

    // Step 1: Verify uninstall token
    println!("[2/7] Verifying uninstall token...");
    let stored_hash = token::get_stored_token_hash()
        .context("Cannot verify token - installation metadata not found")?;

    if !token::verify_token_hash(&config.token, &stored_hash)? {
        bail!("Invalid uninstall token. The token must match the one used during installation.");
    }
    println!("       Token verified.");

    // Step 2: Stop agent service
    println!("[3/7] Stopping agent service...");
    stop_agent_service(&config.name);

    // Step 3: Unload driver
    println!("[4/7] Unloading kernel driver...");
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = driver::unload_driver("tamandua") {
            warn!(error = %e, "Driver unload failed (continuing)");
        }
    }

    // Step 4: Delete driver service
    println!("[5/7] Removing driver service...");
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = driver::delete_driver_service("tamandua") {
            warn!(error = %e, "Driver service deletion failed (continuing)");
        }
    }

    // Delete agent service
    println!("       Removing agent service...");
    delete_agent_service(&config.name);

    // Step 4b: Remove scheduled task (Windows only)
    #[cfg(target_os = "windows")]
    {
        println!("       Removing scheduled task...");
        if let Err(e) = scheduled_task::remove_scheduled_task() {
            warn!(error = %e, "Failed to remove scheduled task (continuing)");
        }
    }

    // Step 4c: Remove WMI event subscription (Windows only)
    #[cfg(target_os = "windows")]
    {
        println!("       Removing WMI event subscription...");
        if let Err(e) = wmi_persistence::remove_wmi_persistence() {
            warn!(error = %e, "Failed to remove WMI persistence (continuing)");
        }
    }

    // Step 5: Remove files and directories
    println!("[6/7] Removing files...");
    remove_files();

    // Step 6: Clean registry
    println!("[7/7] Cleaning up...");
    token::remove_recovery_token()?;
    token::remove_token_hash()?;

    println!();
    println!("=========================================");
    println!("Uninstallation complete.");
    println!("All Tamandua EDR components have been removed.");

    Ok(())
}

// ===========================================================================
// Helper functions
// ===========================================================================

/// Check that the current process is running with platform-specific elevated privileges.
#[cfg(target_os = "windows")]
fn check_admin() -> Result<()> {
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("Failed to open process token")?;

        let _guard = scopeguard::guard(token, |h| {
            let _ = windows::Win32::Foundation::CloseHandle(h);
        });

        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .context("Failed to get token elevation")?;

        if elevation.TokenIsElevated == 0 {
            bail!("This command requires administrator privileges. Please run as Administrator.");
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn check_admin() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("This command requires root privileges. Please run with sudo.");
    }
    Ok(())
}

fn elevated_privilege_label() -> &'static str {
    if cfg!(target_os = "windows") {
        "administrator"
    } else if cfg!(target_os = "macos") {
        "root/sudo"
    } else {
        "root"
    }
}

/// Create the installation directory structure.
fn create_directories(install_dir: &Path, data_dir: &Path) -> Result<()> {
    let dirs = [
        install_dir.to_path_buf(),
        data_dir.to_path_buf(),
        data_dir.join("config"),
        data_dir.join("logs"),
        data_dir.join("journal"),
        data_dir.join("journal").join("backups"),
        data_dir.join("quarantine"),
        data_dir.join("rules"),
        data_dir.join("rules").join("yara"),
        data_dir.join("rules").join("sigma"),
    ];

    for dir in &dirs {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
    }

    info!(
        install = %install_dir.display(),
        data = %data_dir.display(),
        "Directory structure created"
    );

    Ok(())
}

/// Get the platform-appropriate binary name.
fn agent_binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "tamandua-agent.exe"
    } else {
        "tamandua-agent"
    }
}

fn is_fatal_token_validation_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();

    message.contains("HTTP 401")
        || message.contains("Invalid token")
        || message.contains("Token has expired")
        || message.contains("maximum number of uses")
        || message.contains("Token has been revoked")
}

/// Copy the current running binary to the installation directory.
fn deploy_agent_binary(dest: &Path, service_name: &str) -> Result<()> {
    let current_exe =
        std::env::current_exe().context("Failed to determine current executable path")?;

    // Don't copy over ourselves
    if let (Ok(src), Ok(dst)) = (current_exe.canonicalize(), dest.canonicalize()) {
        if src == dst {
            info!("Agent binary already in place, skipping copy");
            return Ok(());
        }
    }

    if let Err(first_error) = std::fs::copy(&current_exe, dest) {
        #[cfg(target_os = "windows")]
        {
            warn!(
                error = %first_error,
                dest = %dest.display(),
                "Agent binary copy failed; retrying after terminating stale installed processes"
            );
            disable_service_autostart(service_name)?;
            terminate_service_process(service_name)?;
            terminate_installed_agent_processes(dest)?;
            terminate_agent_processes_by_name()?;
            std::thread::sleep(Duration::from_millis(750));
        }

        std::fs::copy(&current_exe, dest)
            .with_context(|| format!("Failed to copy agent to {}", dest.display()))?;
    }

    info!(
        src = %current_exe.display(),
        dest = %dest.display(),
        "Agent binary deployed"
    );

    Ok(())
}

#[cfg(target_os = "windows")]
fn prepare_existing_agent_for_upgrade(service_name: &str, agent_dest: &Path) {
    if let Err(error) = wmi_persistence::remove_wmi_persistence() {
        warn!(
            error = %error,
            "Failed to remove existing WMI persistence before upgrade"
        );
    }

    if let Err(error) = scheduled_task::remove_scheduled_task() {
        warn!(
            error = %error,
            "Failed to remove existing scheduled task before upgrade"
        );
    }

    if let Err(error) = disable_service_autostart(service_name) {
        warn!(
            error = %error,
            service = service_name,
            "Failed to temporarily disable service autostart before upgrade"
        );
    }

    stop_agent_service(service_name);
    std::thread::sleep(Duration::from_millis(1500));

    if let Err(error) = terminate_service_process(service_name) {
        warn!(
            error = %error,
            service = service_name,
            "Failed to terminate stale Windows service process before upgrade"
        );
    }

    if let Err(error) = terminate_installed_agent_processes(agent_dest) {
        warn!(
            error = %error,
            dest = %agent_dest.display(),
            "Failed to terminate stale installed agent processes before upgrade"
        );
    }

    if let Err(error) = terminate_agent_processes_by_name() {
        warn!(
            error = %error,
            "Failed to terminate stale agent processes by image name before upgrade"
        );
    }
}

#[cfg(target_os = "windows")]
fn disable_service_autostart(service_name: &str) -> Result<()> {
    let output = std::process::Command::new("sc.exe")
        .args(["config", service_name, "start=", "disabled"])
        .output()
        .with_context(|| format!("Failed to configure service {service_name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Failed to disable service autostart for {}: {}{}",
            service_name,
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn enable_service_autostart(service_name: &str) -> Result<()> {
    let output = std::process::Command::new("sc.exe")
        .args(["config", service_name, "start=", "auto"])
        .output()
        .with_context(|| format!("Failed to configure service {service_name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Failed to enable service autostart for {}: {}{}",
            service_name,
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn terminate_service_process(service_name: &str) -> Result<()> {
    let output = std::process::Command::new("sc.exe")
        .args(["queryex", service_name])
        .output()
        .with_context(|| format!("Failed to query service {service_name}"))?;

    if !output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(pid) = parse_sc_query_pid(&stdout) else {
        return Ok(());
    };

    if pid == 0 || pid == std::process::id() {
        return Ok(());
    }

    let kill_output = std::process::Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/F"])
        .output()
        .with_context(|| format!("Failed to terminate service process {pid}"))?;

    if !kill_output.status.success() {
        bail!(
            "taskkill failed for service process {}: {}",
            pid,
            String::from_utf8_lossy(&kill_output.stderr).trim()
        );
    }

    std::thread::sleep(Duration::from_millis(750));
    Ok(())
}

#[cfg(target_os = "windows")]
fn parse_sc_query_pid(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("PID") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

#[cfg(target_os = "windows")]
fn terminate_installed_agent_processes(agent_dest: &Path) -> Result<()> {
    let current_pid = std::process::id();
    let target_path = agent_dest
        .canonicalize()
        .unwrap_or_else(|_| agent_dest.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let quoted_target = powershell_single_quote(&target_path);
    let script = format!(
        "$target = {quoted_target}; \
         $currentPid = {current_pid}; \
         Get-CimInstance Win32_Process -Filter \"Name='tamandua-agent.exe'\" | \
         Where-Object {{ $_.ExecutablePath -eq $target -and $_.ProcessId -ne $currentPid }} | \
         ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
    );

    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .context("Failed to launch PowerShell to terminate stale agent processes")?;

    if !output.status.success() {
        bail!(
            "PowerShell failed while terminating stale agent processes: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn terminate_agent_processes_by_name() -> Result<()> {
    let current_pid = std::process::id();
    let script = format!(
        "$currentPid = {current_pid}; \
         Get-CimInstance Win32_Process -Filter \"Name='tamandua-agent.exe'\" | \
         Where-Object {{ $_.ProcessId -ne $currentPid }} | \
         ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
    );

    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .context("Failed to launch PowerShell to terminate agent processes by image name")?;

    if !output.status.success() {
        bail!(
            "PowerShell failed while terminating agent processes by image name: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn detect_existing_enrollment(data_dir: &Path) -> Option<ExistingEnrollment> {
    let config_path = data_dir.join("config").join("agent.toml");
    let content = std::fs::read_to_string(&config_path).ok()?;
    let agent_id = extract_toml_string(&content, "agent_id")?;

    if agent_id.starts_with("pending-") {
        return None;
    }

    if !content.contains("[tls]") || !content.contains("enabled = true") {
        return None;
    }

    Some(ExistingEnrollment { agent_id })
}

fn extract_toml_string(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{} =", key);

    content.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with(&prefix) {
            return None;
        }

        let value = trimmed.split_once('=')?.1.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))?;

        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

/// Write the agent configuration file from enrollment data.
fn write_config(
    data_dir: &Path,
    server_url: &str,
    enrollment: &token::CsrEnrollmentResponse,
    cert_paths: &CertPaths,
) -> Result<()> {
    let config_path = data_dir.join("config").join("agent.toml");

    let config_content = format!(
        r#"# Tamandua EDR Agent Configuration
# Auto-generated during installation - do not edit manually

agent_id = "{agent_id}"
server_url = "{server_url}"
organization_id = "{org_id}"
auth_token = "{jwt}"
performance_profile = "balanced"
max_cpu_percent = 15.0
sub_loop_interval_multiplier = 3.0
full_scan_features = false

[auth]
jwt = "{jwt}"

[tls]
enabled = true
cert_path = '{cert_path}'
key_path = '{key_path}'
ca_path = '{ca_path}'
skip_verify = false

[transport]
reconnect_interval_ms = 5000
max_reconnect_attempts = 0
heartbeat_interval_ms = 30000

[collectors]
process_enabled = true
file_enabled = true
network_enabled = true
dns_enabled = true
usb_enabled = true
ransomware_canary_enabled = true
health_enabled = true
persistence_enabled = true
registry_enabled = true
etw_enabled = true
fim_enabled = true
injection_enabled = false
memory_enabled = false
network_dpi_enabled = false
network_anomaly_enabled = false
exploit_mitigation_enabled = false
defense_evasion_enabled = false
syscall_evasion_enabled = false
credential_theft_enabled = false
lateral_movement_enabled = false
process_hollowing_enabled = false
scheduled_tasks_enabled = false
named_pipes_enabled = false
driver_blocklist_enabled = false
script_inspector_enabled = false
firmware_enabled = false
browser_protection_enabled = false
clipboard_enabled = false
input_capture_enabled = false
office_email_enabled = false
cloud_enabled = false
container_enabled = false
dlp_enabled = false
clipboard_dlp_enabled = false
ai_discovery_enabled = false
software_inventory_enabled = false
wmi_enabled = false
clr_enabled = false
amsi_enabled = false
lsass_enabled = false
ad_monitor_enabled = false
identity_enabled = false

[collector_tuning]
process_scan_interval_secs = 5
memory_scan_interval_secs = 120
dns_poll_interval_ms = 2000
network_poll_interval_ms = 3000
registry_poll_interval_secs = 10
cpu_throttle_threshold = 15.0
adaptive_throttling_enabled = true
skip_expensive_analysis = true

[detection]
local_analysis_enabled = true
yara_enabled = true
behavioral_enabled = true

[file_journal]
enabled = true
max_db_size_mb = 500
max_backup_size_mb = 100
retention_hours = 72
vss_enabled = true
vss_interval_hours = 4

[updater]
enabled = true
check_interval_hours = 1
"#,
        agent_id = enrollment.agent_id,
        server_url = server_url,
        org_id = enrollment.org_id,
        jwt = enrollment.jwt,
        cert_path = cert_paths.cert_path.display(),
        key_path = cert_paths.key_path.display(),
        ca_path = cert_paths.ca_bundle_path.display(),
    );

    std::fs::write(&config_path, config_content)
        .with_context(|| format!("Failed to write config to {}", config_path.display()))?;

    info!(path = %config_path.display(), "Configuration written");
    Ok(())
}

/// Write a runnable local configuration when server-side CSR enrollment is
/// temporarily unavailable. This keeps the Windows service installable and
/// lets the GUI/IPC recovery flow come online instead of failing before
/// `CreateServiceW`.
fn write_pending_config(data_dir: &Path, server_url: &str, org_id: &str) -> Result<()> {
    let config_path = data_dir.join("config").join("agent.toml");
    let agent_id = format!("pending-{}", uuid::Uuid::new_v4());

    let config_content = format!(
        r#"# Tamandua EDR Agent Configuration
# Auto-generated during installation - do not edit manually
# Enrollment status: pending. Re-run enrollment when the backend CSR endpoint is available.

agent_id = "{agent_id}"
server_url = "{server_url}"
organization_id = "{org_id}"
enrollment_pending = true
performance_profile = "balanced"
max_cpu_percent = 15.0
sub_loop_interval_multiplier = 3.0
full_scan_features = false

[tls]
enabled = false
skip_verify = false

[transport]
reconnect_interval_ms = 5000
max_reconnect_attempts = 0
heartbeat_interval_ms = 30000

[collectors]
process_enabled = true
file_enabled = true
network_enabled = true
dns_enabled = true
usb_enabled = true
ransomware_canary_enabled = true
health_enabled = true
persistence_enabled = true
registry_enabled = true
etw_enabled = true
fim_enabled = true
injection_enabled = false
memory_enabled = false
network_dpi_enabled = false
network_anomaly_enabled = false
exploit_mitigation_enabled = false
defense_evasion_enabled = false
syscall_evasion_enabled = false
credential_theft_enabled = false
lateral_movement_enabled = false
process_hollowing_enabled = false
scheduled_tasks_enabled = false
named_pipes_enabled = false
driver_blocklist_enabled = false
script_inspector_enabled = false
firmware_enabled = false
browser_protection_enabled = false
clipboard_enabled = false
input_capture_enabled = false
office_email_enabled = false
cloud_enabled = false
container_enabled = false
dlp_enabled = false
clipboard_dlp_enabled = false
ai_discovery_enabled = false
software_inventory_enabled = false
wmi_enabled = false
clr_enabled = false
amsi_enabled = false
lsass_enabled = false
ad_monitor_enabled = false
identity_enabled = false

[collector_tuning]
process_scan_interval_secs = 5
memory_scan_interval_secs = 120
dns_poll_interval_ms = 2000
network_poll_interval_ms = 3000
registry_poll_interval_secs = 10
cpu_throttle_threshold = 15.0
adaptive_throttling_enabled = true
skip_expensive_analysis = true

[detection]
local_analysis_enabled = true
yara_enabled = true
behavioral_enabled = true

[file_journal]
enabled = true
max_db_size_mb = 500
max_backup_size_mb = 100
retention_hours = 72
vss_enabled = true
vss_interval_hours = 4

[updater]
enabled = true
check_interval_hours = 1
"#,
        agent_id = agent_id,
        server_url = server_url,
        org_id = org_id,
    );

    std::fs::write(&config_path, config_content).with_context(|| {
        format!(
            "Failed to write pending config to {}",
            config_path.display()
        )
    })?;

    warn!(path = %config_path.display(), "Pending enrollment configuration written");
    Ok(())
}

/// Register the agent as a Windows service.
#[cfg(target_os = "windows")]
fn register_agent_service(name: &str, exe_path: &Path, data_dir: &Path) -> Result<()> {
    use crate::service::{ServiceConfig, StartType};

    let config_path = data_dir.join("config").join("agent.toml");

    let svc_config = ServiceConfig {
        name: name.to_string(),
        display_name: "Tamandua EDR Agent".to_string(),
        description:
            "Tamandua Endpoint Detection and Response Agent - Protects your system from threats"
                .to_string(),
        executable_path: exe_path.to_path_buf(),
        arguments: vec![
            "--config".to_string(),
            config_path.to_string_lossy().into_owned(),
            "service".to_string(),
        ],
        start_type: StartType::Auto,
        ..Default::default()
    };

    let manager = crate::service::get_service_manager();
    manager.install(&svc_config)?;

    #[cfg(target_os = "windows")]
    enable_service_autostart(name)?;

    info!(name = name, "Agent service registered");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn register_agent_service(name: &str, exe_path: &Path, data_dir: &Path) -> Result<()> {
    use crate::service::{ServiceConfig, StartType};

    let config_path = data_dir.join("config").join("agent.toml");

    let svc_config = ServiceConfig {
        name: name.to_string(),
        display_name: "Tamandua EDR Agent".to_string(),
        description: "Tamandua Endpoint Detection and Response Agent".to_string(),
        executable_path: exe_path.to_path_buf(),
        arguments: vec![
            "--foreground".to_string(),
            "--config".to_string(),
            config_path.to_string_lossy().into_owned(),
        ],
        start_type: StartType::Auto,
        ..Default::default()
    };

    let manager = crate::service::get_service_manager();
    manager.install(&svc_config)?;

    info!(name = name, "Agent service registered");
    Ok(())
}

/// Start the agent service.
fn start_agent_service(name: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    enable_service_autostart(name)?;

    let manager = crate::service::get_service_manager();
    manager.start(name)?;
    info!(name = name, "Agent service started");
    Ok(())
}

/// Stop the agent service (best-effort, doesn't fail on errors).
fn stop_agent_service(name: &str) {
    let manager = crate::service::get_service_manager();
    match manager.stop(name) {
        Ok(_) => info!(name = name, "Agent service stopped"),
        Err(e) => {
            warn!(name = name, error = %e, "Failed to stop agent service (may not be running)")
        }
    }
}

/// Delete the agent service (best-effort).
fn delete_agent_service(name: &str) {
    let manager = crate::service::get_service_manager();
    match manager.uninstall(name) {
        Ok(_) => info!(name = name, "Agent service removed"),
        Err(e) => warn!(name = name, error = %e, "Failed to remove agent service"),
    }
}

/// Remove installation files and directories.
fn remove_files() {
    let install_path = install_dir();
    let data_path = data_dir();

    // Remove driver file
    #[cfg(target_os = "windows")]
    {
        let driver_path = driver::default_driver_path();
        if driver_path.exists() {
            match std::fs::remove_file(&driver_path) {
                Ok(_) => info!(path = %driver_path.display(), "Driver file removed"),
                Err(e) => {
                    warn!(path = %driver_path.display(), error = %e, "Failed to remove driver file")
                }
            }
        }
    }

    // Remove installation directory
    if install_path.exists() {
        match std::fs::remove_dir_all(&install_path) {
            Ok(_) => info!(path = %install_path.display(), "Installation directory removed"),
            Err(e) => {
                warn!(path = %install_path.display(), error = %e, "Failed to remove installation directory")
            }
        }
    }

    // Remove data directory
    if data_path.exists() {
        match std::fs::remove_dir_all(&data_path) {
            Ok(_) => info!(path = %data_path.display(), "Data directory removed"),
            Err(e) => {
                warn!(path = %data_path.display(), error = %e, "Failed to remove data directory")
            }
        }
    }
}

// ===========================================================================
// Persistence Management Functions
// ===========================================================================

/// Check the status of all persistence mechanisms.
///
/// Returns a `PersistenceStatus` struct with the status of each mechanism.
/// Logs warnings for any missing mechanisms.
#[cfg(target_os = "windows")]
pub fn check_persistence(service_name: &str) -> Result<PersistenceStatus> {
    info!("Checking persistence status");

    let mut status = PersistenceStatus::default();

    // Check Windows service
    let manager = crate::service::get_service_manager();
    status.service_installed = manager.is_installed(service_name).unwrap_or(false);

    // Check service recovery configuration
    status.service_recovery_configured = check_service_recovery_configured(service_name);

    // Check WMI persistence
    status.wmi_persistence_installed = wmi_persistence::check_wmi_persistence().unwrap_or(false);

    // Check scheduled task
    status.scheduled_task_installed = scheduled_task::check_scheduled_task().unwrap_or(false);

    // Check watchdog process
    status.watchdog_running = is_watchdog_running();

    // Check driver protection
    status.driver_protection_active = is_driver_protection_active();

    // Log warnings for missing mechanisms
    let missing = status.missing_mechanisms();
    if !missing.is_empty() {
        warn!(
            missing = ?missing,
            "Some persistence mechanisms are not active"
        );
    }

    Ok(status)
}

#[cfg(not(target_os = "windows"))]
pub fn check_persistence(_service_name: &str) -> Result<PersistenceStatus> {
    // On non-Windows, only service-based persistence is applicable
    let mut status = PersistenceStatus::default();

    // Check systemd service
    let manager = crate::service::get_service_manager();
    status.service_installed = manager.is_installed(DEFAULT_SERVICE_NAME).unwrap_or(false);

    // Other mechanisms are Windows-specific
    status.service_recovery_configured = true; // systemd handles this automatically
    status.wmi_persistence_installed = true; // N/A on Linux
    status.scheduled_task_installed = true; // N/A on Linux

    Ok(status)
}

/// Check if service recovery actions are configured.
#[cfg(target_os = "windows")]
fn check_service_recovery_configured(service_name: &str) -> bool {
    use std::process::Command;

    // Use sc.exe to query failure actions
    let output = Command::new("sc").args(["qfailure", service_name]).output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Check if restart actions are configured
            stdout.contains("RESTART")
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn check_service_recovery_configured(_service_name: &str) -> bool {
    // systemd handles recovery via Restart= directive
    true
}

/// Check if the watchdog process is running.
#[cfg(target_os = "windows")]
fn is_watchdog_running() -> bool {
    use std::process::Command;

    let output = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq tamandua-watchdog.exe", "/NH"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.contains("tamandua-watchdog.exe")
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn is_watchdog_running() -> bool {
    use std::process::Command;

    let output = Command::new("pgrep").arg("tamandua-watchdog").output();

    matches!(output, Ok(out) if out.status.success())
}

/// Check if driver protection is active.
#[cfg(target_os = "windows")]
fn is_driver_protection_active() -> bool {
    use std::process::Command;

    // Check if the tamandua minifilter driver is loaded
    let output = Command::new("fltmc").output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.to_lowercase().contains("tamandua")
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn is_driver_protection_active() -> bool {
    // Check for eBPF-based protection on Linux
    use std::process::Command;

    let output = Command::new("bpftool").args(["prog", "list"]).output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.to_lowercase().contains("tamandua")
        }
        Err(_) => false,
    }
}

/// Install all persistence mechanisms.
///
/// This is a standalone function that can be called separately from the main
/// install flow to add persistence to an existing installation.
#[cfg(target_os = "windows")]
pub fn install_all_persistence(service_name: &str) -> Result<()> {
    println!("Installing all persistence mechanisms...");
    println!("=========================================");

    check_admin()?;

    let install_path = install_dir();
    let agent_path = install_path.join(agent_binary_name());

    if !agent_path.exists() {
        bail!(
            "Agent not found at {}. Run 'install' first.",
            agent_path.display()
        );
    }

    let mut errors = Vec::new();

    // 1. Configure service recovery
    println!("[1/4] Configuring service recovery actions...");
    match service_recovery::configure_service_recovery(service_name, None) {
        Ok(_) => println!("       Service recovery configured."),
        Err(e) => {
            println!("       FAILED: {}", e);
            errors.push(format!("Service recovery: {}", e));
        }
    }

    // 2. Install scheduled task
    println!("[2/4] Installing scheduled task...");
    match scheduled_task::install_scheduled_task(&agent_path) {
        Ok(_) => println!("       Scheduled task installed."),
        Err(e) => {
            println!("       FAILED: {}", e);
            errors.push(format!("Scheduled task: {}", e));
        }
    }

    // 3. Install WMI persistence
    println!("[3/4] Installing WMI event subscription...");
    match wmi_persistence::install_wmi_persistence(&agent_path) {
        Ok(_) => println!("       WMI event subscription installed."),
        Err(e) => {
            println!("       FAILED: {}", e);
            errors.push(format!("WMI persistence: {}", e));
        }
    }

    // 4. Start watchdog (if binary exists)
    println!("[4/4] Starting watchdog process...");
    let watchdog_path = install_path.join("tamandua-watchdog.exe");
    if watchdog_path.exists() {
        match start_watchdog(&watchdog_path) {
            Ok(_) => println!("       Watchdog started."),
            Err(e) => {
                println!("       FAILED: {}", e);
                errors.push(format!("Watchdog: {}", e));
            }
        }
    } else {
        println!("       Skipped (watchdog binary not found).");
    }

    println!("=========================================");

    if errors.is_empty() {
        println!("All persistence mechanisms installed successfully.");
        Ok(())
    } else {
        println!("Some persistence mechanisms failed to install:");
        for err in &errors {
            println!("  - {}", err);
        }
        bail!("{} persistence mechanism(s) failed", errors.len());
    }
}

#[cfg(not(target_os = "windows"))]
pub fn install_all_persistence(_service_name: &str) -> Result<()> {
    println!("Persistence mechanisms on Linux are managed by systemd.");
    println!("The service unit file already includes:");
    println!("  - Restart=always");
    println!("  - RestartSec=5");
    println!("  - WatchdogSec=30");
    Ok(())
}

/// Remove all persistence mechanisms.
#[cfg(target_os = "windows")]
pub fn remove_all_persistence(service_name: &str) -> Result<()> {
    println!("Removing all persistence mechanisms...");
    println!("=========================================");

    check_admin()?;

    // 1. Stop watchdog
    println!("[1/3] Stopping watchdog process...");
    stop_watchdog();
    println!("       Watchdog stopped.");

    // 2. Remove scheduled task
    println!("[2/3] Removing scheduled task...");
    if let Err(e) = scheduled_task::remove_scheduled_task() {
        warn!(error = %e, "Failed to remove scheduled task");
        println!("       WARNING: {}", e);
    } else {
        println!("       Scheduled task removed.");
    }

    // 3. Remove WMI persistence
    println!("[3/3] Removing WMI event subscription...");
    if let Err(e) = wmi_persistence::remove_wmi_persistence() {
        warn!(error = %e, "Failed to remove WMI persistence");
        println!("       WARNING: {}", e);
    } else {
        println!("       WMI event subscription removed.");
    }

    println!("=========================================");
    println!("Persistence mechanisms removed.");
    println!();
    println!(
        "Note: The Windows service '{}' was NOT removed.",
        service_name
    );
    println!("Use 'uninstall' to completely remove the agent.");

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn remove_all_persistence(_service_name: &str) -> Result<()> {
    println!("Persistence mechanisms on Linux are managed by systemd.");
    println!("Use 'uninstall' to remove the systemd service.");
    Ok(())
}

/// Repair any broken persistence mechanisms.
///
/// Checks each mechanism and reinstalls any that are missing.
#[cfg(target_os = "windows")]
pub fn repair_persistence(service_name: &str) -> Result<()> {
    println!("Repairing persistence mechanisms...");
    println!("=========================================");

    check_admin()?;

    let status = check_persistence(service_name)?;
    let install_path = install_dir();
    let agent_path = install_path.join(agent_binary_name());

    if !agent_path.exists() {
        bail!(
            "Agent not found at {}. Run 'install' first.",
            agent_path.display()
        );
    }

    let mut repaired = 0;
    let mut failed = 0;

    // Repair service recovery if missing
    if !status.service_recovery_configured {
        println!("  Repairing service recovery actions...");
        match service_recovery::configure_service_recovery(service_name, None) {
            Ok(_) => {
                println!("    REPAIRED");
                repaired += 1;
            }
            Err(e) => {
                println!("    FAILED: {}", e);
                failed += 1;
            }
        }
    }

    // Repair scheduled task if missing
    if !status.scheduled_task_installed {
        println!("  Repairing scheduled task...");
        match scheduled_task::install_scheduled_task(&agent_path) {
            Ok(_) => {
                println!("    REPAIRED");
                repaired += 1;
            }
            Err(e) => {
                println!("    FAILED: {}", e);
                failed += 1;
            }
        }
    }

    // Repair WMI persistence if missing
    if !status.wmi_persistence_installed {
        println!("  Repairing WMI event subscription...");
        match wmi_persistence::install_wmi_persistence(&agent_path) {
            Ok(_) => {
                println!("    REPAIRED");
                repaired += 1;
            }
            Err(e) => {
                println!("    FAILED: {}", e);
                failed += 1;
            }
        }
    }

    // Start watchdog if not running
    if !status.watchdog_running {
        let watchdog_path = install_path.join("tamandua-watchdog.exe");
        if watchdog_path.exists() {
            println!("  Starting watchdog process...");
            match start_watchdog(&watchdog_path) {
                Ok(_) => {
                    println!("    STARTED");
                    repaired += 1;
                }
                Err(e) => {
                    println!("    FAILED: {}", e);
                    failed += 1;
                }
            }
        }
    }

    println!("=========================================");

    if repaired == 0 && failed == 0 {
        println!("All persistence mechanisms are already active.");
    } else if failed == 0 {
        println!("Repaired {} mechanism(s).", repaired);
    } else {
        println!("Repaired {} mechanism(s), {} failed.", repaired, failed);
    }

    if failed > 0 {
        bail!("{} repair(s) failed", failed);
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn repair_persistence(service_name: &str) -> Result<()> {
    println!("Checking systemd service...");
    let manager = crate::service::get_service_manager();

    if !manager.is_installed(service_name)? {
        println!("Service '{}' is not installed.", service_name);
        println!("Run 'install' to install the agent.");
        return Ok(());
    }

    // Reload systemd configuration
    let output = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output()
        .context("Failed to reload systemd")?;

    if output.status.success() {
        println!("Systemd configuration reloaded.");
    }

    // Ensure service is enabled
    let output = std::process::Command::new("systemctl")
        .args(["enable", service_name])
        .output()
        .context("Failed to enable service")?;

    if output.status.success() {
        println!("Service enabled for auto-start.");
    }

    Ok(())
}

/// Start the watchdog process.
#[cfg(target_os = "windows")]
fn start_watchdog(watchdog_path: &Path) -> Result<()> {
    use std::process::Command;

    // Check if already running
    if is_watchdog_running() {
        info!("Watchdog is already running");
        return Ok(());
    }

    // Start watchdog as a detached process
    Command::new(watchdog_path)
        .args(["--daemon"])
        .spawn()
        .context("Failed to start watchdog process")?;

    info!("Watchdog process started");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn start_watchdog(_watchdog_path: &Path) -> Result<()> {
    // On Linux, watchdog is typically managed by systemd
    Ok(())
}

/// Stop the watchdog process.
#[cfg(target_os = "windows")]
fn stop_watchdog() {
    use std::process::Command;

    // Kill watchdog process if running
    let _ = Command::new("taskkill")
        .args(["/IM", "tamandua-watchdog.exe", "/F"])
        .output();
}

#[cfg(not(target_os = "windows"))]
fn stop_watchdog() {
    use std::process::Command;

    let _ = Command::new("pkill").arg("tamandua-watchdog").output();
}
