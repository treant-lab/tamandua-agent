//! Service runner implementation
//!
//! Runs the privileged agent service with full telemetry and response capabilities.

use anyhow::{Context, Result};
#[cfg(target_os = "windows")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::AgentConfig;
use crate::ipc::{IpcAuthenticator, IpcServer};
use crate::updater::Updater;

#[cfg(target_os = "windows")]
static SERVICE_CONFIG: OnceLock<AgentConfig> = OnceLock::new();

/// Service runner state
pub struct ServiceRunner {
    config: Arc<RwLock<AgentConfig>>,
    ipc_server: Arc<IpcServer>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl ServiceRunner {
    /// Create a new service runner
    pub async fn new(config: AgentConfig) -> Result<Self> {
        info!("Initializing service runner");

        // Create IPC authenticator
        let auth = IpcAuthenticator::new();

        // Save token for GUI to use
        let token_path = IpcAuthenticator::default_token_path();
        auth.save_to_file(&token_path)
            .await
            .context("Failed to save IPC token")?;

        // Create IPC server
        let config = Arc::new(RwLock::new(config));
        let ipc_server = Arc::new(IpcServer::with_config(auth, Arc::clone(&config)));

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        Ok(Self {
            config,
            ipc_server,
            shutdown_tx,
        })
    }

    /// Run the service
    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("Starting Tamandua Agent service");

        // Start IPC server
        let _ipc_handle = self
            .ipc_server
            .clone()
            .start()
            .await
            .context("Failed to start IPC server")?;

        let updater_handle = self.start_updater().await;

        // Start telemetry collection and transport
        // NOTE: Full collector initialization is in main.rs run_agent()
        // For service mode, we need to:
        // 1. Initialize collectors based on config (process, file, network, dns, etc.)
        // 2. Start the event pipeline (analyzers, alerting, MITRE mapping)
        // 3. Connect to backend via WebSocket transport
        // 4. Start response executor for receiving commands
        //
        // For now, the IPC server provides status info to the GUI.
        // Full telemetry requires extracting the collector loop from main.rs
        // into a shared TelemetryEngine that both foreground and service modes use.

        info!("Service running - IPC server active, awaiting full telemetry integration");
        info!("Use foreground mode (--foreground) for full collector functionality");

        // Wait for shutdown signal
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        #[cfg(target_os = "windows")]
        {
            let _ = shutdown_rx.recv().await;
            info!("Shutdown signal received");
        }

        #[cfg(not(target_os = "windows"))]
        {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                }
                result = tokio::signal::ctrl_c() => {
                    if let Err(e) = result {
                        error!("Error waiting for Ctrl+C: {}", e);
                    }
                    info!("Ctrl+C received");
                }
            }
        }

        // Graceful shutdown
        self.shutdown().await?;
        if let Some(handle) = updater_handle {
            handle.abort();
        }

        Ok(())
    }

    /// Shutdown the service
    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down service");

        // Shutdown IPC server
        self.ipc_server.shutdown().await?;

        // When telemetry engine is integrated, shutdown order:
        // 1. Stop accepting new commands (response executor)
        // 2. Flush pending events to backend (transport)
        // 3. Stop collectors
        // 4. Close backend connection

        info!("Service shutdown complete");
        Ok(())
    }

    /// Signal shutdown
    pub fn signal_shutdown(&self) -> Result<()> {
        self.shutdown_tx.send(())?;
        Ok(())
    }

    async fn start_updater(&self) -> Option<tokio::task::JoinHandle<()>> {
        let mut config = self.config.read().await.clone();

        if !config.updater.enabled {
            info!("Service updater disabled by configuration");
            return None;
        }

        // Service mode should not self-exit underneath the SCM. Stage the
        // updated binary and require a restart to activate it.
        config.updater.auto_restart = false;

        match Updater::new(&config.updater, &config.agent_id, &config.server_url) {
            Ok(updater) => {
                info!(
                    interval_hours = config.updater.check_interval_hours,
                    "Service updater background loop enabled"
                );
                Some(updater.spawn_background_loop())
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize service updater");
                None
            }
        }
    }
}

/// Run as Windows service
#[cfg(target_os = "windows")]
pub async fn run_windows_service(config: AgentConfig) -> Result<()> {
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    let _ = SERVICE_CONFIG.set(config);

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(arguments: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service(arguments) {
            error!("Service error: {}", e);
        }
    }

    fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<()> {
        // Create runtime
        let runtime = tokio::runtime::Runtime::new()?;

        // Prefer the CLI-provided service config. Falling back to the legacy
        // default path keeps SCM launches resilient if the dispatcher is
        // invoked without a preloaded config.
        let config = SERVICE_CONFIG
            .get()
            .cloned()
            .unwrap_or(AgentConfig::load_or_default()?);

        let runner_slot: Arc<Mutex<Option<Arc<ServiceRunner>>>> = Arc::new(Mutex::new(None));
        let runner_slot_for_handler = Arc::clone(&runner_slot);

        // Define service control handler
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("Service stop requested");
                    let runner = runner_slot_for_handler
                        .lock()
                        .ok()
                        .and_then(|guard| guard.as_ref().cloned());

                    if let Some(runner) = runner {
                        if let Err(e) = runner.signal_shutdown() {
                            error!("Failed to signal shutdown: {}", e);
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        // Register service control handler
        let status_handle = service_control_handler::register("TamanduaAgent", event_handler)?;

        // Tell Windows we're starting
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(60),
            process_id: None,
        })?;

        // Report RUNNING before initializing IPC/updater/collectors. Windows
        // SCM treats any long work between service_main and RUNNING as a
        // start failure, even when the process is alive as LocalSystem.
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        let runner = match runtime.block_on(async { ServiceRunner::new(config).await }) {
            Ok(runner) => Arc::new(runner),
            Err(error) => {
                error!("Failed to initialize service runner: {}", error);
                status_handle.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(1),
                    checkpoint: 0,
                    wait_hint: std::time::Duration::default(),
                    process_id: None,
                })?;
                return Err(error);
            }
        };

        if let Ok(mut slot) = runner_slot.lock() {
            *slot = Some(Arc::clone(&runner));
        }

        // Apply process mitigations after the SCM has accepted the service as
        // running. Some endpoints are slow here, and doing this before status
        // registration can trigger ERROR_SERVICE_REQUEST_TIMEOUT (1053).
        #[cfg(target_os = "windows")]
        {
            use crate::protection::process_mitigations;
            if let Err(e) = process_mitigations::apply_all_mitigations() {
                eprintln!("Warning: Failed to apply process mitigations: {}", e);
            }
        }

        // Run service
        let run_result = runtime.block_on(async { runner.run().await });

        // Report final status
        let final_state = if run_result.is_ok() {
            ServiceState::Stopped
        } else {
            ServiceState::Stopped
        };

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: final_state,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        run_result
    }

    // Dispatch service
    service_dispatcher::start("TamanduaAgent", ffi_service_main)?;

    Ok(())
}

/// Run as foreground service (for debugging)
pub async fn run_foreground(config: AgentConfig) -> Result<()> {
    info!("Running agent in foreground mode");

    let runner = Arc::new(ServiceRunner::new(config).await?);
    runner.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_runner_creation() {
        let config = AgentConfig::default();
        let runner = ServiceRunner::new(config).await;
        assert!(runner.is_ok());
    }
}
