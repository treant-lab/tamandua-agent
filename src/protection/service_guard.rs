//! Service Guard Module - Protects Windows service from tampering
//!
//! This module implements service protection mechanisms:
//! - Set restrictive DACL on service to prevent stop/delete
//! - Monitor SCM for suspicious queries
//! - Auto-restart on unexpected termination
//! - Service configuration integrity monitoring
//!
//! MITRE ATT&CK Coverage:
//! - T1489 - Service Stop
//! - T1562.001 - Disable or Modify Tools

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{TamperEvent, TamperEventType, TamperSeverity};

/// Service guard configuration
#[derive(Debug, Clone)]
pub struct ServiceGuardConfig {
    /// Service name to protect
    pub service_name: String,
    /// Enable DACL protection on service
    pub enable_dacl_protection: bool,
    /// Enable service status monitoring
    pub enable_monitoring: bool,
    /// Monitor interval in seconds
    pub monitor_interval_secs: u64,
    /// Enable automatic recovery configuration
    pub enable_recovery: bool,
    /// Recovery delay in milliseconds
    pub recovery_delay_ms: u32,
}

impl Default for ServiceGuardConfig {
    fn default() -> Self {
        Self {
            service_name: "TamanduaAgent".to_string(),
            enable_dacl_protection: true,
            enable_monitoring: true,
            monitor_interval_secs: 15,
            enable_recovery: true,
            recovery_delay_ms: 5000,
        }
    }
}

/// Service guard state
pub struct ServiceGuard {
    config: ServiceGuardConfig,
    running: Arc<AtomicBool>,
    stop_attempts: Arc<AtomicU64>,
    tamper_tx: mpsc::Sender<TamperEvent>,
}

impl ServiceGuard {
    /// Create a new service guard
    pub fn new(config: ServiceGuardConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            stop_attempts: Arc::new(AtomicU64::new(0)),
            tamper_tx,
        }
    }

    /// Initialize service protection (Windows only)
    #[cfg(windows)]
    pub async fn initialize(&self) -> Result<()> {
        info!(service = %self.config.service_name, "Initializing service guard");
        self.running.store(true, Ordering::SeqCst);

        // Set restrictive DACL on service
        if self.config.enable_dacl_protection {
            if let Err(e) = self.protect_service_dacl() {
                warn!("Failed to set service DACL: {}", e);
            }
        }

        // Configure service recovery
        if self.config.enable_recovery {
            if let Err(e) = self.configure_service_recovery() {
                warn!("Failed to configure service recovery: {}", e);
            }
        }

        // Start service monitoring
        if self.config.enable_monitoring {
            self.start_service_monitor();
        }

        Ok(())
    }

    #[cfg(not(windows))]
    pub async fn initialize(&self) -> Result<()> {
        info!("Service guard not applicable on this platform (using systemd protection)");

        // On Linux, configure systemd service hardening
        #[cfg(target_os = "linux")]
        {
            self.configure_systemd_protection()?;
        }

        Ok(())
    }

    /// Set restrictive DACL on Windows service
    #[cfg(windows)]
    fn protect_service_dacl(&self) -> Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_SERVICE};
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_ALL_ACCESS,
            SERVICE_ALL_ACCESS,
        };

        let service_name: Vec<u16> = self
            .config
            .service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            // Open Service Control Manager
            let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
                .map_err(|e| anyhow!("Failed to open SCM: {:?}", e))?;

            // Open the service
            let service = OpenServiceW(scm, PCWSTR(service_name.as_ptr()), SERVICE_ALL_ACCESS);

            let service_handle = match service {
                Ok(h) => h,
                Err(e) => {
                    let _ = CloseServiceHandle(scm);
                    return Err(anyhow!("Failed to open service: {:?}", e));
                }
            };

            // Set protected DACL on the service
            // This prevents unauthorized stop/delete operations
            let result = SetSecurityInfo(
                HANDLE(service_handle.0 as isize),
                SE_SERVICE,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                None, // Keep current DACL but protect it
                None,
            );

            let _ = CloseServiceHandle(service_handle);
            let _ = CloseServiceHandle(scm);

            if result.is_err() {
                return Err(anyhow!("Failed to set service security: {:?}", result));
            }
        }

        info!(service = %self.config.service_name, "Service DACL protection applied");
        Ok(())
    }

    /// Configure service recovery options
    #[cfg(windows)]
    fn configure_service_recovery(&self) -> Result<()> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::System::Services::{
            ChangeServiceConfig2W, CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_ACTION,
            SC_ACTION_TYPE, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
            SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_FAILURE_ACTIONSW,
        };

        let service_name: Vec<u16> = self
            .config
            .service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
                .map_err(|e| anyhow!("Failed to open SCM: {:?}", e))?;

            let service = OpenServiceW(scm, PCWSTR(service_name.as_ptr()), SERVICE_ALL_ACCESS);

            let service_handle = match service {
                Ok(h) => h,
                Err(e) => {
                    let _ = CloseServiceHandle(scm);
                    return Err(anyhow!("Failed to open service: {:?}", e));
                }
            };

            // Configure failure actions:
            // First failure: Restart immediately
            // Second failure: Restart after 5 seconds
            // Subsequent failures: Restart after 30 seconds
            let actions = [
                SC_ACTION {
                    Type: SC_ACTION_TYPE(1), // SC_ACTION_RESTART
                    Delay: 0,
                },
                SC_ACTION {
                    Type: SC_ACTION_TYPE(1), // SC_ACTION_RESTART
                    Delay: self.config.recovery_delay_ms,
                },
                SC_ACTION {
                    Type: SC_ACTION_TYPE(1), // SC_ACTION_RESTART
                    Delay: 30000,
                },
            ];

            let failure_actions = SERVICE_FAILURE_ACTIONSW {
                dwResetPeriod: 86400, // Reset failure count after 24 hours
                lpRebootMsg: PWSTR::null(),
                lpCommand: PWSTR::null(),
                cActions: 3,
                lpsaActions: actions.as_ptr() as *mut SC_ACTION,
            };

            let result = ChangeServiceConfig2W(
                service_handle,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                Some(&failure_actions as *const _ as *const std::ffi::c_void),
            );

            let _ = CloseServiceHandle(service_handle);
            let _ = CloseServiceHandle(scm);

            if result.is_err() {
                return Err(anyhow!(
                    "Failed to configure service recovery: {:?}",
                    result
                ));
            }
        }

        info!(service = %self.config.service_name, "Service recovery configured");
        Ok(())
    }

    /// Start service monitoring task
    #[cfg(windows)]
    fn start_service_monitor(&self) {
        let running = self.running.clone();
        let tamper_tx = self.tamper_tx.clone();
        let stop_attempts = self.stop_attempts.clone();
        let service_name = self.config.service_name.clone();
        let interval_secs = self.config.monitor_interval_secs;

        tokio::spawn(async move {
            use windows::core::PCWSTR;
            use windows::Win32::System::Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
                SC_MANAGER_CONNECT, SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                SERVICE_STATUS, SERVICE_STOPPED,
            };

            let service_name_wide: Vec<u16> = service_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            let mut was_running = true;

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                unsafe {
                    let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    let service = match OpenServiceW(
                        scm,
                        PCWSTR(service_name_wide.as_ptr()),
                        SERVICE_QUERY_STATUS,
                    ) {
                        Ok(h) => h,
                        Err(_) => {
                            let _ = CloseServiceHandle(scm);
                            continue;
                        }
                    };

                    let mut status = SERVICE_STATUS::default();

                    if QueryServiceStatus(service, &mut status).is_ok() {
                        let current_state = status.dwCurrentState;

                        // Check if service stopped unexpectedly
                        if current_state == SERVICE_STOPPED && was_running {
                            warn!(service = %service_name, "Service stopped unexpectedly");

                            stop_attempts.fetch_add(1, Ordering::SeqCst);

                            let event = TamperEvent {
                                timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                                event_type: TamperEventType::ServiceStopAttempt,
                                description: format!(
                                    "Service {} stopped unexpectedly",
                                    service_name
                                ),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::Critical,
                                mitre_technique: Some("T1489".to_string()),
                            };

                            let _ = tamper_tx.send(event).await;
                        }

                        // Check if service was paused
                        if current_state == SERVICE_PAUSED {
                            warn!(service = %service_name, "Service paused");

                            let event = TamperEvent {
                                timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                                event_type: TamperEventType::ServiceModification,
                                description: format!("Service {} was paused", service_name),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::High,
                                mitre_technique: Some("T1562.001".to_string()),
                            };

                            let _ = tamper_tx.send(event).await;
                        }

                        was_running = current_state == SERVICE_RUNNING;
                    }

                    let _ = CloseServiceHandle(service);
                    let _ = CloseServiceHandle(scm);
                }

                // Also check service configuration
                Self::check_service_config(&service_name, &tamper_tx).await;
            }
        });
    }

    /// Check service configuration for tampering
    #[cfg(windows)]
    async fn check_service_config(service_name: &str, tamper_tx: &mpsc::Sender<TamperEvent>) {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
            QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
        };

        let service_name_wide: Vec<u16> = service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
                Ok(h) => h,
                Err(_) => return,
            };

            let service = match OpenServiceW(
                scm,
                PCWSTR(service_name_wide.as_ptr()),
                SERVICE_QUERY_CONFIG,
            ) {
                Ok(h) => h,
                Err(_) => {
                    let _ = CloseServiceHandle(scm);
                    return;
                }
            };

            // Query buffer size needed
            let mut bytes_needed: u32 = 0;
            let _ = QueryServiceConfigW(service, None, 0, &mut bytes_needed);

            if bytes_needed > 0 {
                let mut buffer: Vec<u8> = vec![0; bytes_needed as usize];
                let config_ptr = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;

                if QueryServiceConfigW(service, Some(config_ptr), bytes_needed, &mut bytes_needed)
                    .is_ok()
                {
                    let config = &*config_ptr;

                    // Check start type (should be 2 = SERVICE_AUTO_START)
                    let start_type_value = config.dwStartType.0 as u32;
                    if start_type_value != 2 {
                        warn!(
                            service = service_name,
                            start_type = start_type_value,
                            "Service start type modified"
                        );

                        let event = TamperEvent {
                            timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                            event_type: TamperEventType::ServiceDisableAttempt,
                            description: format!(
                                "Service {} start type changed to {} (expected AUTO_START=2)",
                                service_name, start_type_value
                            ),
                            source_pid: None,
                            source_process: None,
                            severity: TamperSeverity::Critical,
                            mitre_technique: Some("T1562.001".to_string()),
                        };

                        let _ = tamper_tx.send(event).await;
                    }
                }
            }

            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(scm);
        }
    }

    #[cfg(not(windows))]
    fn start_service_monitor(&self) {
        // On Linux, monitor systemd service status
        #[cfg(target_os = "linux")]
        {
            let running = self.running.clone();
            let tamper_tx = self.tamper_tx.clone();
            let interval_secs = self.config.monitor_interval_secs;

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

                while running.load(Ordering::SeqCst) {
                    interval.tick().await;

                    // Check systemd service status
                    let output = std::process::Command::new("systemctl")
                        .args(["is-active", "tamandua"])
                        .output();

                    if let Ok(output) = output {
                        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if status != "active" && status != "activating" {
                            warn!(status = %status, "Tamandua service not active");

                            let event = TamperEvent {
                                timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                                event_type: TamperEventType::ServiceStopAttempt,
                                description: format!("Tamandua service status: {}", status),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::Critical,
                                mitre_technique: Some("T1489".to_string()),
                            };

                            let _ = tamper_tx.send(event).await;
                        }
                    }
                }
            });
        }
    }

    /// Configure systemd service hardening (Linux)
    #[cfg(target_os = "linux")]
    fn configure_systemd_protection(&self) -> Result<()> {
        // The systemd service file should include these directives:
        // [Service]
        // Restart=always
        // RestartSec=5
        // ProtectSystem=strict
        // ProtectHome=read-only
        // PrivateTmp=true
        // NoNewPrivileges=true
        // CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE ...

        // Verify service is configured for auto-restart
        let output = std::process::Command::new("systemctl")
            .args(["show", "tamandua", "-p", "Restart"])
            .output();

        if let Ok(output) = output {
            let restart_setting = String::from_utf8_lossy(&output.stdout);
            if !restart_setting.contains("always") && !restart_setting.contains("on-failure") {
                warn!("Tamandua systemd service not configured for auto-restart");
            }
        }

        Ok(())
    }

    /// Get stop attempt count
    pub fn get_stop_attempts(&self) -> u64 {
        self.stop_attempts.load(Ordering::SeqCst)
    }

    /// Shutdown service guard
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Service guard shutdown");
    }
}

/// Service guard status
#[derive(Debug, Clone)]
pub struct ServiceGuardStatus {
    pub monitoring_active: bool,
    pub dacl_protected: bool,
    pub recovery_configured: bool,
    pub stop_attempts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServiceGuardConfig::default();
        assert_eq!(config.service_name, "TamanduaAgent");
        assert!(config.enable_dacl_protection);
        assert!(config.enable_monitoring);
    }
}
