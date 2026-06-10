//! Scheduled Task backup persistence mechanism.
//!
//! Creates a Windows Task Scheduler task that:
//! - Runs every 5 minutes to check if the agent is running
//! - Starts the agent if it's not running
//! - Runs at system boot as a backup to the service
//! - Runs as SYSTEM with highest privileges
//!
//! This provides defense-in-depth persistence to ensure the agent
//! remains active even if the main service is stopped.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Task name for the health check scheduled task.
pub const TASK_NAME: &str = "TamanduaAgentHealthCheck";

/// Task folder path (root of Task Scheduler).
const TASK_FOLDER: &str = "\\";

/// Install the scheduled task for agent health monitoring.
///
/// Creates a task that:
/// 1. Runs every 5 minutes checking if the agent process is running
/// 2. Starts the agent if it's not running
/// 3. Also runs at system boot as a backup persistence mechanism
///
/// # Arguments
/// * `agent_path` - Path to the agent executable
///
/// # Returns
/// * `Ok(())` if the task was created successfully
/// * `Err` if task creation failed
#[cfg(target_os = "windows")]
pub fn install_scheduled_task(agent_path: &Path) -> Result<()> {
    use windows::core::{ComInterface, BSTR};
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::TaskScheduler::*;
    use windows::Win32::System::Variant::VARIANT;

    // Helper to convert bool to VARIANT_BOOL
    fn vb(b: bool) -> VARIANT_BOOL {
        VARIANT_BOOL(if b { -1 } else { 0 })
    }

    info!(
        task = TASK_NAME,
        path = %agent_path.display(),
        "Installing scheduled task for agent health monitoring"
    );

    // Validate agent path exists
    if !agent_path.exists() {
        bail!(
            "Agent executable not found at: {}. Install the agent first.",
            agent_path.display()
        );
    }

    let agent_path_str = agent_path.to_string_lossy().to_string();
    let agent_dir = agent_path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    unsafe {
        // Initialize COM
        CoInitializeEx(None, COINIT_MULTITHREADED).ok();
        let _com_guard = scopeguard::guard((), |_| {
            CoUninitialize();
        });

        // Create TaskService instance
        let task_service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                .context("Failed to create TaskScheduler COM instance")?;

        // Connect to local task service
        task_service
            .Connect(
                VARIANT::default(),
                VARIANT::default(),
                VARIANT::default(),
                VARIANT::default(),
            )
            .context("Failed to connect to Task Scheduler service")?;

        debug!("Connected to Task Scheduler service");

        // Get root folder
        let root_folder = task_service
            .GetFolder(&BSTR::from(TASK_FOLDER))
            .context("Failed to get root task folder")?;

        // Delete existing task if present (for reinstall/update)
        let _ = root_folder.DeleteTask(&BSTR::from(TASK_NAME), 0);

        // Create new task definition
        let task_def = task_service
            .NewTask(0)
            .context("Failed to create new task definition")?;

        // Configure registration info
        let reg_info = task_def
            .RegistrationInfo()
            .context("Failed to get registration info")?;

        reg_info
            .SetDescription(&BSTR::from(
                "Tamandua EDR Agent health check - ensures the agent is always running",
            ))
            .context("Failed to set task description")?;

        reg_info
            .SetAuthor(&BSTR::from("Tamandua EDR"))
            .context("Failed to set task author")?;

        // Configure principal (run as SYSTEM with highest privileges)
        let principal = task_def
            .Principal()
            .context("Failed to get task principal")?;

        principal
            .SetUserId(&BSTR::from("SYSTEM"))
            .context("Failed to set user to SYSTEM")?;

        principal
            .SetLogonType(TASK_LOGON_SERVICE_ACCOUNT)
            .context("Failed to set logon type")?;

        principal
            .SetRunLevel(TASK_RUNLEVEL_HIGHEST)
            .context("Failed to set run level to highest")?;

        debug!("Configured task to run as SYSTEM with highest privileges");

        // Configure settings
        let settings = task_def.Settings().context("Failed to get task settings")?;

        // Don't stop if running longer than expected
        settings
            .SetStopIfGoingOnBatteries(vb(false))
            .context("Failed to disable stop on battery")?;

        settings
            .SetDisallowStartIfOnBatteries(vb(false))
            .context("Failed to allow start on battery")?;

        // Allow running on demand
        settings
            .SetAllowDemandStart(vb(true))
            .context("Failed to allow demand start")?;

        // Run task as soon as possible after a scheduled start is missed
        settings
            .SetStartWhenAvailable(vb(true))
            .context("Failed to set start when available")?;

        // Don't delete the task if it's not scheduled to run again
        settings
            .SetDeleteExpiredTaskAfter(&BSTR::new())
            .context("Failed to clear expired task deletion")?;

        // Multiple instances policy - do not start new if already running
        settings
            .SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)
            .context("Failed to set multiple instances policy")?;

        // Execution time limit - 1 hour max
        settings
            .SetExecutionTimeLimit(&BSTR::from("PT1H"))
            .context("Failed to set execution time limit")?;

        // Allow task to be run on demand
        settings
            .SetEnabled(vb(true))
            .context("Failed to enable task")?;

        // Wake computer to run this task (important for always-on protection)
        settings
            .SetWakeToRun(vb(true))
            .context("Failed to enable wake to run")?;

        debug!("Configured task settings");

        // Add triggers
        let triggers = task_def
            .Triggers()
            .context("Failed to get triggers collection")?;

        // Trigger 1: Time-based trigger (every 5 minutes)
        let time_trigger: ITimeTrigger = triggers
            .Create(TASK_TRIGGER_TIME)
            .context("Failed to create time trigger")?
            .cast()
            .context("Failed to cast to ITimeTrigger")?;

        // Start immediately (use current time)
        let now = chrono::Utc::now();
        let start_time = now.format("%Y-%m-%dT%H:%M:%S").to_string();
        time_trigger
            .SetStartBoundary(&BSTR::from(start_time))
            .context("Failed to set start boundary")?;

        // Repeat every 5 minutes indefinitely
        let repetition = time_trigger
            .Repetition()
            .context("Failed to get repetition pattern")?;

        repetition
            .SetInterval(&BSTR::from("PT5M")) // 5 minutes
            .context("Failed to set repetition interval")?;

        repetition
            .SetDuration(&BSTR::new()) // Indefinite duration
            .context("Failed to set repetition duration")?;

        repetition
            .SetStopAtDurationEnd(vb(false))
            .context("Failed to disable stop at duration end")?;

        time_trigger
            .SetEnabled(vb(true))
            .context("Failed to enable time trigger")?;

        debug!("Created time trigger (every 5 minutes)");

        // Trigger 2: Boot trigger (runs at system startup)
        let boot_trigger: IBootTrigger = triggers
            .Create(TASK_TRIGGER_BOOT)
            .context("Failed to create boot trigger")?
            .cast()
            .context("Failed to cast to IBootTrigger")?;

        // Delay 30 seconds after boot to let services start first
        boot_trigger
            .SetDelay(&BSTR::from("PT30S"))
            .context("Failed to set boot delay")?;

        boot_trigger
            .SetEnabled(vb(true))
            .context("Failed to enable boot trigger")?;

        debug!("Created boot trigger (30 seconds after startup)");

        // Add action - run PowerShell script to check and start agent
        let actions = task_def
            .Actions()
            .context("Failed to get actions collection")?;

        let exec_action: IExecAction = actions
            .Create(TASK_ACTION_EXEC)
            .context("Failed to create exec action")?
            .cast()
            .context("Failed to cast to IExecAction")?;

        // PowerShell script to check if agent is running and start it if not
        let ps_script = format!(
            r#"$proc = Get-Process -Name "tamandua-agent" -ErrorAction SilentlyContinue; if (-not $proc) {{ Start-Process -FilePath '{}' -ArgumentList 'service' -WindowStyle Hidden -Verb RunAs }}"#,
            agent_path_str.replace('\\', "\\\\").replace('\'', "''")
        );

        exec_action
            .SetPath(&BSTR::from("powershell.exe"))
            .context("Failed to set PowerShell path")?;

        exec_action
            .SetArguments(&BSTR::from(format!(
                "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"{}\"",
                ps_script
            )))
            .context("Failed to set PowerShell arguments")?;

        exec_action
            .SetWorkingDirectory(&BSTR::from(agent_dir))
            .context("Failed to set working directory")?;

        debug!("Created exec action (PowerShell health check)");

        // Register the task
        let _registered_task = root_folder
            .RegisterTaskDefinition(
                &BSTR::from(TASK_NAME),
                &task_def,
                TASK_CREATE_OR_UPDATE.0,
                VARIANT::default(), // No user (uses principal settings)
                VARIANT::default(), // No password
                TASK_LOGON_SERVICE_ACCOUNT,
                VARIANT::default(), // No sddl
            )
            .context("Failed to register task definition")?;

        info!(task = TASK_NAME, "Scheduled task installed successfully");
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn install_scheduled_task(_agent_path: &Path) -> Result<()> {
    bail!("Scheduled task installation is only supported on Windows");
}

/// Remove the scheduled task.
///
/// # Returns
/// * `Ok(())` if the task was removed or didn't exist
/// * `Err` if removal failed
#[cfg(target_os = "windows")]
pub fn remove_scheduled_task() -> Result<()> {
    use windows::core::BSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::TaskScheduler::*;
    use windows::Win32::System::Variant::VARIANT;

    info!(task = TASK_NAME, "Removing scheduled task");

    unsafe {
        // Initialize COM
        CoInitializeEx(None, COINIT_MULTITHREADED).ok();
        let _com_guard = scopeguard::guard((), |_| {
            CoUninitialize();
        });

        // Create TaskService instance
        let task_service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                .context("Failed to create TaskScheduler COM instance")?;

        // Connect to local task service
        task_service
            .Connect(
                VARIANT::default(),
                VARIANT::default(),
                VARIANT::default(),
                VARIANT::default(),
            )
            .context("Failed to connect to Task Scheduler service")?;

        // Get root folder
        let root_folder = task_service
            .GetFolder(&BSTR::from(TASK_FOLDER))
            .context("Failed to get root task folder")?;

        // Delete the task (0 = no special flags)
        match root_folder.DeleteTask(&BSTR::from(TASK_NAME), 0) {
            Ok(_) => {
                info!(task = TASK_NAME, "Scheduled task removed");
            }
            Err(e) => {
                // Check if task doesn't exist (0x80070002 = file not found)
                let hr = e.code().0 as u32;
                if hr == 0x80070002 {
                    debug!(task = TASK_NAME, "Task doesn't exist, nothing to remove");
                } else {
                    warn!(
                        task = TASK_NAME,
                        error = %e,
                        "Failed to delete task (may not exist)"
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn remove_scheduled_task() -> Result<()> {
    bail!("Scheduled task removal is only supported on Windows");
}

/// Check if the scheduled task exists and is enabled.
///
/// # Returns
/// * `Ok(true)` if the task exists and is enabled
/// * `Ok(false)` if the task doesn't exist or is disabled
/// * `Err` if the check failed
#[cfg(target_os = "windows")]
pub fn check_scheduled_task() -> Result<bool> {
    use windows::core::BSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::TaskScheduler::*;
    use windows::Win32::System::Variant::VARIANT;

    unsafe {
        // Initialize COM
        CoInitializeEx(None, COINIT_MULTITHREADED).ok();
        let _com_guard = scopeguard::guard((), |_| {
            CoUninitialize();
        });

        // Create TaskService instance
        let task_service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                .context("Failed to create TaskScheduler COM instance")?;

        // Connect to local task service
        task_service
            .Connect(
                VARIANT::default(),
                VARIANT::default(),
                VARIANT::default(),
                VARIANT::default(),
            )
            .context("Failed to connect to Task Scheduler service")?;

        // Get root folder
        let root_folder = task_service
            .GetFolder(&BSTR::from(TASK_FOLDER))
            .context("Failed to get root task folder")?;

        // Try to get the task
        match root_folder.GetTask(&BSTR::from(TASK_NAME)) {
            Ok(task) => {
                // Check if enabled
                let enabled = task.Enabled().unwrap_or_default();
                debug!(task = TASK_NAME, enabled = enabled.as_bool(), "Task found");
                Ok(enabled.as_bool())
            }
            Err(e) => {
                // Task doesn't exist
                let hr = e.code().0 as u32;
                if hr == 0x80070002 {
                    debug!(task = TASK_NAME, "Task not found");
                    Ok(false)
                } else {
                    Err(e).context("Failed to get task")
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_scheduled_task() -> Result<bool> {
    bail!("Scheduled task check is only supported on Windows");
}

/// Get default agent path for scheduled task.
pub fn default_agent_path() -> std::path::PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"\Program Files"))
        .join("Tamandua")
        .join("tamandua-agent.exe")
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Note: These tests require admin privileges and affect system state.
    // Run with caution in isolated test environments.

    #[test]
    #[ignore = "requires admin privileges and modifies system state"]
    fn test_install_and_remove_scheduled_task() {
        // Use a test path (doesn't need to exist for registration, only for running)
        let test_path = PathBuf::from(r"C:\Windows\System32\cmd.exe");

        // Install
        install_scheduled_task(&test_path).expect("Failed to install task");

        // Check exists
        assert!(check_scheduled_task().expect("Failed to check task"));

        // Remove
        remove_scheduled_task().expect("Failed to remove task");

        // Check removed
        assert!(!check_scheduled_task().expect("Failed to check task after removal"));
    }

    #[test]
    fn test_check_nonexistent_task() {
        // This should work without admin if just checking
        // But task service connection may still need elevation
    }
}
