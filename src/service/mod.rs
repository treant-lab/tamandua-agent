//! Service management for EDR-grade persistence
//!
//! Handles installation, removal, and management of the agent as a system service.
//! - Windows: Uses Service Control Manager (SCM)
//! - Linux: Uses systemd
//! - macOS: Uses launchd

use anyhow::Result;
use tracing::{info, warn};

pub mod runner;

#[cfg(target_os = "linux")]
pub mod systemd;

/// Service installation configuration
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name
    pub name: String,
    /// Display name (Windows)
    pub display_name: String,
    /// Service description
    pub description: String,
    /// Path to the executable
    pub executable_path: std::path::PathBuf,
    /// Command line arguments
    pub arguments: Vec<String>,
    /// Working directory
    pub working_dir: Option<std::path::PathBuf>,
    /// Start type (auto, manual, delayed)
    pub start_type: StartType,
    /// Recovery options
    pub recovery: RecoveryConfig,
}

/// Service start type
#[derive(Debug, Clone, Default)]
pub enum StartType {
    /// Start automatically on boot
    #[default]
    Auto,
    /// Start automatically with delay
    AutoDelayed,
    /// Start manually
    Manual,
}

/// Service recovery configuration
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Action on first failure
    pub first_failure: RecoveryAction,
    /// Action on second failure
    pub second_failure: RecoveryAction,
    /// Action on subsequent failures
    pub subsequent_failures: RecoveryAction,
    /// Reset failure count after this many seconds
    pub reset_period_seconds: u32,
    /// Delay before first restart in milliseconds
    pub first_restart_delay_ms: u32,
    /// Delay before second restart in milliseconds
    pub second_restart_delay_ms: u32,
    /// Delay before subsequent restarts in milliseconds
    pub subsequent_restart_delay_ms: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            first_failure: RecoveryAction::Restart,
            second_failure: RecoveryAction::Restart,
            subsequent_failures: RecoveryAction::Restart,
            reset_period_seconds: 86400,         // 24 hours
            first_restart_delay_ms: 5_000,       // 5 seconds
            second_restart_delay_ms: 10_000,     // 10 seconds
            subsequent_restart_delay_ms: 30_000, // 30 seconds
        }
    }
}

/// Recovery action on failure
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    None,
    Restart,
    RebootComputer,
    RunProgram { command: String },
}

impl Default for ServiceConfig {
    fn default() -> Self {
        let exe_path = std::env::current_exe().unwrap_or_default();

        Self {
            name: "TamanduaAgent".to_string(),
            display_name: "Tamandua EDR Agent".to_string(),
            description:
                "Tamandua Endpoint Detection and Response Agent - Protects your system from threats"
                    .to_string(),
            executable_path: exe_path,
            arguments: vec!["--foreground".to_string()],
            working_dir: None,
            start_type: StartType::Auto,
            recovery: RecoveryConfig::default(),
        }
    }
}

/// Service manager trait for cross-platform support
pub trait ServiceManager {
    /// Install the service
    fn install(&self, config: &ServiceConfig) -> Result<()>;

    /// Uninstall the service
    fn uninstall(&self, service_name: &str) -> Result<()>;

    /// Start the service
    fn start(&self, service_name: &str) -> Result<()>;

    /// Stop the service
    fn stop(&self, service_name: &str) -> Result<()>;

    /// Check if the service is installed
    fn is_installed(&self, service_name: &str) -> Result<bool>;

    /// Check if the service is running
    fn is_running(&self, service_name: &str) -> Result<bool>;

    /// Get service status
    fn status(&self, service_name: &str) -> Result<ServiceStatus>;
}

/// Service status
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Starting,
    Stopping,
    Unknown,
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
pub mod win_service {
    use super::*;
    use ::windows::core::PCWSTR;
    use ::windows::Win32::System::Services::*;

    use ::windows::Win32::Security::SC_HANDLE;

    pub struct WindowsServiceManager;

    impl WindowsServiceManager {
        pub fn new() -> Self {
            Self
        }

        fn open_sc_manager(&self, access: u32) -> Result<SC_HANDLE> {
            unsafe {
                let handle = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access)?;
                Ok(handle)
            }
        }

        fn to_wide(s: &str) -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            std::ffi::OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        fn quote_command_arg(value: &str) -> String {
            if value.is_empty() || value.contains(char::is_whitespace) || value.contains('"') {
                format!("\"{}\"", value.replace('"', "\\\""))
            } else {
                value.to_string()
            }
        }
    }

    impl ServiceManager for WindowsServiceManager {
        fn install(&self, config: &ServiceConfig) -> Result<()> {
            info!(name = %config.name, "Installing Windows service");

            // Build command line
            let mut cmd = Self::quote_command_arg(&config.executable_path.to_string_lossy());
            if !config.arguments.is_empty() {
                cmd.push(' ');
                cmd.push_str(
                    &config
                        .arguments
                        .iter()
                        .map(|arg| Self::quote_command_arg(arg))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }

            let name_wide = Self::to_wide(&config.name);
            let display_wide = Self::to_wide(&config.display_name);
            let cmd_wide = Self::to_wide(&cmd);

            unsafe {
                let sc_manager = self.open_sc_manager(SC_MANAGER_ALL_ACCESS)?;

                let start_type = match config.start_type {
                    StartType::Auto => SERVICE_AUTO_START,
                    StartType::AutoDelayed => SERVICE_AUTO_START, // Will set delayed flag separately
                    StartType::Manual => SERVICE_DEMAND_START,
                };

                let service = match CreateServiceW(
                    sc_manager,
                    PCWSTR(name_wide.as_ptr()),
                    PCWSTR(display_wide.as_ptr()),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    start_type,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(cmd_wide.as_ptr()),
                    PCWSTR::null(), // No load ordering group
                    None,           // No tag
                    PCWSTR::null(), // No dependencies
                    PCWSTR::null(), // LocalSystem account
                    PCWSTR::null(), // No password
                ) {
                    Ok(service) => service,
                    Err(error) if error.code().0 == 0x80070431u32 as i32 => {
                        warn!(
                            name = %config.name,
                            error = %error,
                            "Windows service already exists; reusing existing service"
                        );

                        let service = OpenServiceW(
                            sc_manager,
                            PCWSTR(name_wide.as_ptr()),
                            SERVICE_ALL_ACCESS,
                        )?;

                        ChangeServiceConfigW(
                            service,
                            SERVICE_WIN32_OWN_PROCESS,
                            start_type,
                            SERVICE_ERROR_NORMAL,
                            PCWSTR(cmd_wide.as_ptr()),
                            PCWSTR::null(),
                            None,
                            PCWSTR::null(),
                            PCWSTR::null(),
                            PCWSTR::null(),
                            PCWSTR(display_wide.as_ptr()),
                        )?;

                        service
                    }
                    Err(error) => return Err(error.into()),
                };

                // Set description
                let desc_wide = Self::to_wide(&config.description);
                let mut desc = SERVICE_DESCRIPTIONW {
                    lpDescription: ::windows::core::PWSTR(desc_wide.as_ptr() as *mut _),
                };
                let _ = ChangeServiceConfig2W(
                    service,
                    SERVICE_CONFIG_DESCRIPTION,
                    Some(&mut desc as *mut _ as *mut _),
                );

                // Configure recovery options with different delays for each failure
                let actions = [
                    SC_ACTION {
                        Type: match config.recovery.first_failure {
                            RecoveryAction::Restart => SC_ACTION_RESTART,
                            RecoveryAction::RebootComputer => SC_ACTION_REBOOT,
                            RecoveryAction::RunProgram { .. } => SC_ACTION_RUN_COMMAND,
                            RecoveryAction::None => SC_ACTION_NONE,
                        },
                        Delay: config.recovery.first_restart_delay_ms,
                    },
                    SC_ACTION {
                        Type: match config.recovery.second_failure {
                            RecoveryAction::Restart => SC_ACTION_RESTART,
                            RecoveryAction::RebootComputer => SC_ACTION_REBOOT,
                            RecoveryAction::RunProgram { .. } => SC_ACTION_RUN_COMMAND,
                            RecoveryAction::None => SC_ACTION_NONE,
                        },
                        Delay: config.recovery.second_restart_delay_ms,
                    },
                    SC_ACTION {
                        Type: match config.recovery.subsequent_failures {
                            RecoveryAction::Restart => SC_ACTION_RESTART,
                            RecoveryAction::RebootComputer => SC_ACTION_REBOOT,
                            RecoveryAction::RunProgram { .. } => SC_ACTION_RUN_COMMAND,
                            RecoveryAction::None => SC_ACTION_NONE,
                        },
                        Delay: config.recovery.subsequent_restart_delay_ms,
                    },
                ];

                let mut failure_actions = SERVICE_FAILURE_ACTIONSW {
                    dwResetPeriod: config.recovery.reset_period_seconds,
                    lpRebootMsg: ::windows::core::PWSTR::null(),
                    lpCommand: ::windows::core::PWSTR::null(),
                    cActions: actions.len() as u32,
                    lpsaActions: actions.as_ptr() as *mut _,
                };

                let _ = ChangeServiceConfig2W(
                    service,
                    SERVICE_CONFIG_FAILURE_ACTIONS,
                    Some(&mut failure_actions as *mut _ as *mut _),
                );

                // Set delayed auto-start if requested
                if matches!(config.start_type, StartType::AutoDelayed) {
                    let mut delayed = SERVICE_DELAYED_AUTO_START_INFO {
                        fDelayedAutostart: true.into(),
                    };
                    let _ = ChangeServiceConfig2W(
                        service,
                        SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                        Some(&mut delayed as *mut _ as *mut _),
                    );
                }

                //
                // ============================================================
                // Anti-tamper: Service hardening
                // ============================================================
                //

                // 1. Set Service SID type to UNRESTRICTED.
                //    RESTRICTED is only safe after ProgramData/driver/log
                //    ACLs are explicitly granted to the service SID. Without
                //    those ACLs the service can start and then exit during IPC
                //    token or named-pipe initialization.
                //    SERVICE_SID_TYPE_UNRESTRICTED = 1
                {
                    #[repr(C)]
                    struct ServiceSidInfo {
                        dw_service_sid_type: u32,
                    }

                    let mut sid_info = ServiceSidInfo {
                        dw_service_sid_type: 1, // SERVICE_SID_TYPE_UNRESTRICTED
                    };

                    let result = ChangeServiceConfig2W(
                        service,
                        SERVICE_CONFIG_SERVICE_SID_INFO,
                        Some(&mut sid_info as *mut _ as *mut _),
                    );

                    if result.is_ok() {
                        info!(name = %config.name, "Service SID type set to UNRESTRICTED");
                    } else {
                        warn!(name = %config.name, "Failed to set service SID type (non-fatal)");
                    }
                }

                // 2. Set failure actions flag to apply recovery even on
                //    non-zero exit codes. This ensures that if an attacker
                //    forces the agent to crash with a specific exit code,
                //    SCM still restarts it.
                //    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
                {
                    #[repr(C)]
                    struct ServiceFailureActionsFlag {
                        f_failure_actions_on_non_crash_failures: i32,
                    }

                    let mut flag = ServiceFailureActionsFlag {
                        f_failure_actions_on_non_crash_failures: 1, // TRUE
                    };

                    let _ = ChangeServiceConfig2W(
                        service,
                        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                        Some(&mut flag as *mut _ as *mut _),
                    );
                }

                // 4. Set pre-shutdown timeout to give agent time for graceful cleanup
                //    SERVICE_CONFIG_PRESHUTDOWN_INFO = 7
                {
                    #[repr(C)]
                    struct ServicePreshutdownInfo {
                        dw_preshutdown_timeout: u32,
                    }

                    let mut preshutdown = ServicePreshutdownInfo {
                        dw_preshutdown_timeout: 30000, // 30 seconds
                    };

                    let _ = ChangeServiceConfig2W(
                        service,
                        SERVICE_CONFIG_PRESHUTDOWN_INFO,
                        Some(&mut preshutdown as *mut _ as *mut _),
                    );
                }

                CloseServiceHandle(service)?;
                CloseServiceHandle(sc_manager)?;
            }

            info!(name = %config.name, "Service installed successfully with anti-tamper hardening");
            Ok(())
        }

        fn uninstall(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Uninstalling Windows service");

            // First stop the service if running
            let _ = self.stop(service_name);

            let name_wide = Self::to_wide(service_name);

            unsafe {
                let sc_manager = self.open_sc_manager(SC_MANAGER_ALL_ACCESS)?;
                let service =
                    OpenServiceW(sc_manager, PCWSTR(name_wide.as_ptr()), SERVICE_ALL_ACCESS)?;

                DeleteService(service)?;

                CloseServiceHandle(service)?;
                CloseServiceHandle(sc_manager)?;
            }

            info!(name = %service_name, "Service uninstalled successfully");
            Ok(())
        }

        fn start(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Starting Windows service");

            let name_wide = Self::to_wide(service_name);

            unsafe {
                let sc_manager = self.open_sc_manager(SC_MANAGER_CONNECT)?;
                let service = OpenServiceW(sc_manager, PCWSTR(name_wide.as_ptr()), SERVICE_START)?;

                if let Err(error) = StartServiceW(service, None) {
                    // ERROR_SERVICE_ALREADY_RUNNING. Treat this as success so
                    // install/enroll remains idempotent when recovery mechanisms
                    // or SCM are already bringing the agent up.
                    if error.code().0 != 0x80070420u32 as i32 {
                        return Err(error.into());
                    }
                    info!(name = %service_name, "Service already running");
                }

                CloseServiceHandle(service)?;
                CloseServiceHandle(sc_manager)?;
            }

            info!(name = %service_name, "Service started");
            Ok(())
        }

        fn stop(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Stopping Windows service");

            let name_wide = Self::to_wide(service_name);

            unsafe {
                let sc_manager = self.open_sc_manager(SC_MANAGER_CONNECT)?;
                let service = OpenServiceW(sc_manager, PCWSTR(name_wide.as_ptr()), SERVICE_STOP)?;

                let mut status = SERVICE_STATUS::default();
                ControlService(service, SERVICE_CONTROL_STOP, &mut status)?;

                CloseServiceHandle(service)?;
                CloseServiceHandle(sc_manager)?;
            }

            info!(name = %service_name, "Service stopped");
            Ok(())
        }

        fn is_installed(&self, service_name: &str) -> Result<bool> {
            let name_wide = Self::to_wide(service_name);

            unsafe {
                let sc_manager = self.open_sc_manager(SC_MANAGER_CONNECT)?;
                let result =
                    OpenServiceW(sc_manager, PCWSTR(name_wide.as_ptr()), SERVICE_QUERY_STATUS);

                CloseServiceHandle(sc_manager)?;

                match result {
                    Ok(service) => {
                        CloseServiceHandle(service)?;
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
        }

        fn is_running(&self, service_name: &str) -> Result<bool> {
            Ok(self.status(service_name)? == ServiceStatus::Running)
        }

        fn status(&self, service_name: &str) -> Result<ServiceStatus> {
            let name_wide = Self::to_wide(service_name);

            unsafe {
                let sc_manager = self.open_sc_manager(SC_MANAGER_CONNECT)?;
                let service =
                    OpenServiceW(sc_manager, PCWSTR(name_wide.as_ptr()), SERVICE_QUERY_STATUS)?;

                let mut status = SERVICE_STATUS::default();
                QueryServiceStatus(service, &mut status)?;

                CloseServiceHandle(service)?;
                CloseServiceHandle(sc_manager)?;

                Ok(match status.dwCurrentState {
                    SERVICE_RUNNING => ServiceStatus::Running,
                    SERVICE_STOPPED => ServiceStatus::Stopped,
                    SERVICE_START_PENDING => ServiceStatus::Starting,
                    SERVICE_STOP_PENDING => ServiceStatus::Stopping,
                    _ => ServiceStatus::Unknown,
                })
            }
        }
    }
}

// ============================================================================
// Linux Implementation (systemd)
// ============================================================================

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    pub struct SystemdServiceManager;

    impl SystemdServiceManager {
        pub fn new() -> Self {
            Self
        }

        fn unit_file_path(service_name: &str) -> std::path::PathBuf {
            std::path::PathBuf::from(format!("/etc/systemd/system/{}.service", service_name))
        }

        fn generate_unit_file(config: &ServiceConfig) -> String {
            let start_type = match config.start_type {
                StartType::Auto | StartType::AutoDelayed => "multi-user.target",
                StartType::Manual => "",
            };

            let restart_policy = match &config.recovery.first_failure {
                RecoveryAction::Restart => "always",
                _ => "no",
            };

            // systemd uses a single RestartSec value; use the first failure delay
            let restart_sec = config.recovery.first_restart_delay_ms / 1000;

            let working_dir = config
                .working_dir
                .as_ref()
                .map(|p| format!("WorkingDirectory={}", p.display()))
                .unwrap_or_default();

            format!(
                r#"[Unit]
Description={description}
After=network.target
StartLimitIntervalSec={reset_period}
StartLimitBurst=5

[Service]
Type=simple
ExecStart={exec_path} {args}
{working_dir}
Restart={restart_policy}
RestartSec={restart_sec}
StandardOutput=journal
StandardError=journal
SyslogIdentifier={name}
# Security hardening
NoNewPrivileges=no
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy={wanted_by}
"#,
                description = config.description,
                exec_path = config.executable_path.display(),
                args = config.arguments.join(" "),
                working_dir = working_dir,
                restart_policy = restart_policy,
                restart_sec = restart_sec,
                reset_period = config.recovery.reset_period_seconds,
                name = config.name,
                wanted_by = start_type,
            )
        }

        fn run_systemctl(&self, args: &[&str]) -> Result<()> {
            let output = Command::new("systemctl").args(args).output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("systemctl failed: {}", stderr));
            }

            Ok(())
        }
    }

    impl ServiceManager for SystemdServiceManager {
        fn install(&self, config: &ServiceConfig) -> Result<()> {
            info!(name = %config.name, "Installing systemd service");

            let unit_path = Self::unit_file_path(&config.name);
            let unit_content = Self::generate_unit_file(config);

            // Write unit file
            fs::write(&unit_path, &unit_content)?;

            // Set permissions (644)
            let mut perms = fs::metadata(&unit_path)?.permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&unit_path, perms)?;

            // Reload systemd
            self.run_systemctl(&["daemon-reload"])?;

            // Enable service (auto-start)
            if matches!(config.start_type, StartType::Auto | StartType::AutoDelayed) {
                self.run_systemctl(&["enable", &config.name])?;
            }

            info!(name = %config.name, path = %unit_path.display(), "Service installed successfully");
            Ok(())
        }

        fn uninstall(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Uninstalling systemd service");

            // Stop service first
            let _ = self.stop(service_name);

            // Disable service
            let _ = self.run_systemctl(&["disable", service_name]);

            // Remove unit file
            let unit_path = Self::unit_file_path(service_name);
            if unit_path.exists() {
                fs::remove_file(&unit_path)?;
            }

            // Reload systemd
            self.run_systemctl(&["daemon-reload"])?;

            info!(name = %service_name, "Service uninstalled successfully");
            Ok(())
        }

        fn start(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Starting systemd service");
            self.run_systemctl(&["start", service_name])?;
            info!(name = %service_name, "Service started");
            Ok(())
        }

        fn stop(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Stopping systemd service");
            self.run_systemctl(&["stop", service_name])?;
            info!(name = %service_name, "Service stopped");
            Ok(())
        }

        fn is_installed(&self, service_name: &str) -> Result<bool> {
            Ok(Self::unit_file_path(service_name).exists())
        }

        fn is_running(&self, service_name: &str) -> Result<bool> {
            let output = Command::new("systemctl")
                .args(["is-active", service_name])
                .output()?;

            Ok(output.status.success())
        }

        fn status(&self, service_name: &str) -> Result<ServiceStatus> {
            let output = Command::new("systemctl")
                .args(["is-active", service_name])
                .output()?;

            let status_str = String::from_utf8_lossy(&output.stdout);

            Ok(match status_str.trim() {
                "active" => ServiceStatus::Running,
                "inactive" => ServiceStatus::Stopped,
                "activating" => ServiceStatus::Starting,
                "deactivating" => ServiceStatus::Stopping,
                _ => ServiceStatus::Unknown,
            })
        }
    }
}

// ============================================================================
// macOS Implementation (launchd)
// ============================================================================

#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    use std::fs;
    use std::process::Command;

    pub struct LaunchdServiceManager;

    impl LaunchdServiceManager {
        pub fn new() -> Self {
            Self
        }

        fn plist_path(service_name: &str) -> std::path::PathBuf {
            std::path::PathBuf::from(format!(
                "/Library/LaunchDaemons/com.tamandua.{}.plist",
                service_name.to_lowercase()
            ))
        }

        fn plist_label(service_name: &str) -> String {
            format!("com.tamandua.{}", service_name.to_lowercase())
        }

        fn escape_plist_string(value: &str) -> String {
            value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&apos;")
        }

        fn generate_plist(config: &ServiceConfig) -> String {
            let label = Self::plist_label(&config.name);
            let mut args = vec![config.executable_path.to_string_lossy().to_string()];
            args.extend(config.arguments.clone());
            let working_dir = config
                .working_dir
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/opt/tamandua"));

            let args_xml: String = args
                .iter()
                .map(|a| format!("        <string>{}</string>", Self::escape_plist_string(a)))
                .collect::<Vec<_>>()
                .join("\n");

            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>

    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>{throttle}</integer>

    <key>WorkingDirectory</key>
    <string>{working_dir}</string>

    <key>StandardOutPath</key>
    <string>/var/log/tamandua/tamandua-agent.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/tamandua/tamandua-agent.log</string>

    <key>UserName</key>
    <string>root</string>

    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
                label = Self::escape_plist_string(&label),
                args_xml = args_xml,
                working_dir = Self::escape_plist_string(&working_dir.to_string_lossy()),
                // launchd uses ThrottleInterval for restart delay; use first failure delay
                throttle = config.recovery.first_restart_delay_ms / 1000,
            )
        }
    }

    impl ServiceManager for LaunchdServiceManager {
        fn install(&self, config: &ServiceConfig) -> Result<()> {
            info!(name = %config.name, "Installing launchd service");

            let plist_path = Self::plist_path(&config.name);
            let plist_content = Self::generate_plist(config);

            // Create log directory
            let _ = fs::create_dir_all("/var/log/tamandua");
            if let Some(parent) = plist_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let working_dir = config
                .working_dir
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/opt/tamandua"));
            let _ = fs::create_dir_all(&working_dir);

            // Write plist file
            fs::write(&plist_path, &plist_content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644))?;
            }

            // Load the service
            let label = Self::plist_label(&config.name);
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("system/{label}")])
                .output();
            Command::new("launchctl")
                .args(["bootstrap", "system", &plist_path.to_string_lossy()])
                .output()?;
            let _ = Command::new("launchctl")
                .args(["enable", &format!("system/{label}")])
                .output();
            let _ = Command::new("launchctl")
                .args(["kickstart", "-k", &format!("system/{label}")])
                .output();

            info!(name = %config.name, path = %plist_path.display(), "Service installed successfully");
            Ok(())
        }

        fn uninstall(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Uninstalling launchd service");

            let plist_path = Self::plist_path(service_name);

            // Unload the service
            let label = Self::plist_label(service_name);
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("system/{label}")])
                .output();

            // Remove plist file
            if plist_path.exists() {
                fs::remove_file(&plist_path)?;
            }

            info!(name = %service_name, "Service uninstalled successfully");
            Ok(())
        }

        fn start(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Starting launchd service");
            let label = Self::plist_label(service_name);
            Command::new("launchctl")
                .args(["kickstart", "-k", &format!("system/{label}")])
                .output()?;
            info!(name = %service_name, "Service started");
            Ok(())
        }

        fn stop(&self, service_name: &str) -> Result<()> {
            info!(name = %service_name, "Stopping launchd service");
            let label = Self::plist_label(service_name);
            Command::new("launchctl")
                .args(["kill", "TERM", &format!("system/{label}")])
                .output()?;
            info!(name = %service_name, "Service stopped");
            Ok(())
        }

        fn is_installed(&self, service_name: &str) -> Result<bool> {
            Ok(Self::plist_path(service_name).exists())
        }

        fn is_running(&self, service_name: &str) -> Result<bool> {
            let label = Self::plist_label(service_name);
            let output = Command::new("launchctl")
                .args(["print", &format!("system/{label}")])
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(output.status.success()
                && (stdout.contains("state = running") || stdout.contains("state = active")))
        }

        fn status(&self, service_name: &str) -> Result<ServiceStatus> {
            if self.is_running(service_name)? {
                Ok(ServiceStatus::Running)
            } else if self.is_installed(service_name)? {
                Ok(ServiceStatus::Stopped)
            } else {
                Ok(ServiceStatus::Unknown)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        #[test]
        fn generated_plist_escapes_arguments_and_matches_launchdaemon_shape() {
            let config = ServiceConfig {
                name: "TamanduaAgent".to_string(),
                executable_path: PathBuf::from("/opt/tamandua/tamandua-agent"),
                arguments: vec![
                    "--foreground".to_string(),
                    "--config".to_string(),
                    "/opt/tamandua/config/agent & qa.toml".to_string(),
                    "--server".to_string(),
                    "wss://example.test/socket?a=1&b=2".to_string(),
                ],
                working_dir: Some(PathBuf::from("/opt/tamandua")),
                ..Default::default()
            };

            let plist = LaunchdServiceManager::generate_plist(&config);

            assert!(plist.contains("<string>com.tamandua.tamanduaagent</string>"));
            assert!(plist.contains("<key>UserName</key>"));
            assert!(plist.contains("<string>root</string>"));
            assert!(plist.contains("<key>WorkingDirectory</key>"));
            assert!(plist.contains("<string>/opt/tamandua</string>"));
            assert!(plist.contains("/opt/tamandua/config/agent &amp; qa.toml"));
            assert!(plist.contains("wss://example.test/socket?a=1&amp;b=2"));
            assert!(!plist.contains("agent & qa.toml"));
            assert!(!plist.contains("a=1&b=2"));
        }
    }
}

// ============================================================================
// Cross-platform helper functions
// ============================================================================

/// Get the platform-specific service manager
pub fn get_service_manager() -> Box<dyn ServiceManager> {
    #[cfg(target_os = "windows")]
    {
        Box::new(win_service::WindowsServiceManager::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux::SystemdServiceManager::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(macos::LaunchdServiceManager::new())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        compile_error!("Unsupported platform for service management")
    }
}

/// Install the agent as a system service
pub fn install_service(config: Option<ServiceConfig>) -> Result<()> {
    let config = config.unwrap_or_default();
    let manager = get_service_manager();

    if manager.is_installed(&config.name)? {
        warn!(name = %config.name, "Service is already installed");
        return Ok(());
    }

    manager.install(&config)?;
    info!(name = %config.name, "Agent installed as system service");
    Ok(())
}

/// Uninstall the agent service
pub fn uninstall_service(service_name: Option<&str>) -> Result<()> {
    let name = service_name.unwrap_or("TamanduaAgent");
    let manager = get_service_manager();

    if !manager.is_installed(name)? {
        warn!(name = %name, "Service is not installed");
        return Ok(());
    }

    manager.uninstall(name)?;
    info!(name = %name, "Agent service uninstalled");
    Ok(())
}

/// Check if agent is installed as a service
pub fn is_service_installed(service_name: Option<&str>) -> Result<bool> {
    let name = service_name.unwrap_or("TamanduaAgent");
    let manager = get_service_manager();
    manager.is_installed(name)
}

/// Get agent service status
pub fn get_service_status(service_name: Option<&str>) -> Result<ServiceStatus> {
    let name = service_name.unwrap_or("TamanduaAgent");
    let manager = get_service_manager();
    manager.status(name)
}
