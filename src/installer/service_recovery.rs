//! Windows Service Recovery Actions Configuration
//!
//! Configures automatic restart behavior when the service fails:
//! - First failure: Restart after 5 seconds
//! - Second failure: Restart after 10 seconds
//! - Subsequent failures: Restart after 30 seconds
//! - Reset failure count after 1 day (86400 seconds)
//!
//! This module provides `configure_service_recovery()` which can be called:
//! - After `CreateServiceW` during installation
//! - Standalone via `tamandua-agent.exe configure-recovery` to reconfigure existing service

use anyhow::{Context, Result};
use tracing::{info, warn};

/// Recovery action delays in milliseconds
pub struct RecoveryDelays {
    /// Delay before first restart (default: 5000ms = 5 seconds)
    pub first_failure_ms: u32,
    /// Delay before second restart (default: 10000ms = 10 seconds)
    pub second_failure_ms: u32,
    /// Delay before subsequent restarts (default: 30000ms = 30 seconds)
    pub subsequent_failures_ms: u32,
    /// Reset failure count after this many seconds (default: 86400 = 1 day)
    pub reset_period_seconds: u32,
}

impl Default for RecoveryDelays {
    fn default() -> Self {
        Self {
            first_failure_ms: 5_000,        // 5 seconds
            second_failure_ms: 10_000,      // 10 seconds
            subsequent_failures_ms: 30_000, // 30 seconds
            reset_period_seconds: 86_400,   // 1 day
        }
    }
}

/// Configure service recovery actions for an existing Windows service.
///
/// This function opens the service by name and configures failure recovery
/// using `ChangeServiceConfig2W` with `SERVICE_CONFIG_FAILURE_ACTIONS`.
///
/// # Arguments
/// * `service_name` - The name of the Windows service (e.g., "TamanduaAgent")
/// * `delays` - Optional custom delay configuration; uses defaults if None
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if the service cannot be opened or configured
#[cfg(target_os = "windows")]
pub fn configure_service_recovery(
    service_name: &str,
    delays: Option<RecoveryDelays>,
) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_ACTION,
        SC_ACTION_RESTART, SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG,
        SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        SERVICE_FAILURE_ACTIONSW,
    };

    let delays = delays.unwrap_or_default();

    info!(
        service = service_name,
        first_delay_ms = delays.first_failure_ms,
        second_delay_ms = delays.second_failure_ms,
        subsequent_delay_ms = delays.subsequent_failures_ms,
        reset_period_s = delays.reset_period_seconds,
        "Configuring service recovery actions"
    );

    // Convert service name to wide string
    let name_wide: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Open Service Control Manager
        let sc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .context("Failed to open Service Control Manager")?;

        let _sc_guard = scopeguard::guard(sc_manager, |h| {
            let _ = CloseServiceHandle(h);
        });

        // Open the service with CHANGE_CONFIG access
        let service = OpenServiceW(
            sc_manager,
            PCWSTR(name_wide.as_ptr()),
            SERVICE_CHANGE_CONFIG,
        )
        .with_context(|| {
            format!(
                "Failed to open service '{}' for configuration",
                service_name
            )
        })?;

        let _svc_guard = scopeguard::guard(service, |h| {
            let _ = CloseServiceHandle(h);
        });

        // Configure the failure actions with different delays for each attempt
        //
        // SC_ACTION array:
        //   [0] = First failure action
        //   [1] = Second failure action
        //   [2] = Subsequent failures action
        let actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: delays.first_failure_ms,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: delays.second_failure_ms,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: delays.subsequent_failures_ms,
            },
        ];

        let mut failure_actions = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: delays.reset_period_seconds,
            lpRebootMsg: windows::core::PWSTR::null(),
            lpCommand: windows::core::PWSTR::null(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_ptr() as *mut _,
        };

        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            Some(&mut failure_actions as *mut _ as *mut _),
        )
        .context("Failed to set SERVICE_CONFIG_FAILURE_ACTIONS")?;

        // Also set the failure actions flag to trigger recovery on non-crash failures
        // This ensures the service restarts even if it exits with a non-zero exit code
        // (e.g., application error vs. crash)
        //
        // SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
        #[repr(C)]
        struct ServiceFailureActionsFlag {
            f_failure_actions_on_non_crash_failures: i32,
        }

        let mut flag = ServiceFailureActionsFlag {
            f_failure_actions_on_non_crash_failures: 1, // TRUE
        };

        let flag_result = ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            Some(&mut flag as *mut _ as *mut _),
        );

        if flag_result.is_err() {
            warn!("Failed to set failure actions flag (service will still restart on crashes)");
        }

        info!(
            service = service_name,
            "Service recovery actions configured successfully"
        );

        Ok(())
    }
}

/// Configure service recovery actions (stub for non-Windows platforms).
#[cfg(not(target_os = "windows"))]
pub fn configure_service_recovery(
    service_name: &str,
    _delays: Option<RecoveryDelays>,
) -> Result<()> {
    info!(
        service = service_name,
        "Service recovery configuration is only applicable on Windows"
    );
    Ok(())
}

/// Configure service recovery for an existing service using an open service handle.
///
/// This is called from the installer after `CreateServiceW` to configure
/// recovery actions on the newly created service.
///
/// # Safety
/// The caller must ensure `service_handle` is a valid open service handle
/// with `SERVICE_CHANGE_CONFIG` access.
#[cfg(target_os = "windows")]
pub fn configure_service_recovery_with_handle(
    service_handle: windows::Win32::Security::SC_HANDLE,
    delays: Option<RecoveryDelays>,
) -> Result<()> {
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, SC_ACTION, SC_ACTION_RESTART, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
    };

    let delays = delays.unwrap_or_default();

    info!(
        first_delay_ms = delays.first_failure_ms,
        second_delay_ms = delays.second_failure_ms,
        subsequent_delay_ms = delays.subsequent_failures_ms,
        reset_period_s = delays.reset_period_seconds,
        "Configuring service recovery actions via handle"
    );

    unsafe {
        // Configure the failure actions with different delays for each attempt
        let actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: delays.first_failure_ms,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: delays.second_failure_ms,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: delays.subsequent_failures_ms,
            },
        ];

        let mut failure_actions = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: delays.reset_period_seconds,
            lpRebootMsg: windows::core::PWSTR::null(),
            lpCommand: windows::core::PWSTR::null(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_ptr() as *mut _,
        };

        ChangeServiceConfig2W(
            service_handle,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            Some(&mut failure_actions as *mut _ as *mut _),
        )
        .context("Failed to set SERVICE_CONFIG_FAILURE_ACTIONS")?;

        // Set the failure actions flag for non-crash failures
        #[repr(C)]
        struct ServiceFailureActionsFlag {
            f_failure_actions_on_non_crash_failures: i32,
        }

        let mut flag = ServiceFailureActionsFlag {
            f_failure_actions_on_non_crash_failures: 1,
        };

        let _ = ChangeServiceConfig2W(
            service_handle,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            Some(&mut flag as *mut _ as *mut _),
        );

        info!("Service recovery actions configured successfully via handle");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_delays() {
        let delays = RecoveryDelays::default();
        assert_eq!(delays.first_failure_ms, 5_000);
        assert_eq!(delays.second_failure_ms, 10_000);
        assert_eq!(delays.subsequent_failures_ms, 30_000);
        assert_eq!(delays.reset_period_seconds, 86_400);
    }

    #[test]
    fn test_custom_delays() {
        let delays = RecoveryDelays {
            first_failure_ms: 1_000,
            second_failure_ms: 2_000,
            subsequent_failures_ms: 5_000,
            reset_period_seconds: 3600,
        };
        assert_eq!(delays.first_failure_ms, 1_000);
        assert_eq!(delays.second_failure_ms, 2_000);
        assert_eq!(delays.subsequent_failures_ms, 5_000);
        assert_eq!(delays.reset_period_seconds, 3600);
    }
}
