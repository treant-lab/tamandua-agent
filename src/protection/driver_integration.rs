//! Driver Integration Module - Communicates with kernel driver for protection
//!
//! This module provides communication with the Tamandua kernel driver located at
//! `apps/tamandua_driver/` for enhanced protection capabilities:
//!
//! - Process protection via ObRegisterCallbacks (strips dangerous access rights)
//! - Registry protection via CmRegisterCallbackEx (blocks tampering)
//! - Driver integrity verification (CRC32 checksums)
//! - Anti-tamper watchdog (auto-restart on termination)
//! - Self-protection statistics retrieval
//!
//! MITRE ATT&CK Coverage:
//! - T1562.001 - Disable or Modify Tools
//! - T1489 - Service Stop
//! - T1112 - Modify Registry

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::TamperEvent;

#[cfg(target_os = "windows")]
use crate::driver::{self, protect_flags, DriverConnection};

/// Driver integration configuration
#[derive(Debug, Clone)]
pub struct DriverIntegrationConfig {
    /// Enable driver connection
    pub enable_driver: bool,
    /// Enable process protection via driver
    pub enable_process_protection: bool,
    /// Enable file protection via driver
    pub enable_file_protection: bool,
    /// Enable network isolation capabilities
    pub enable_network_control: bool,
    /// Enable anti-tamper watchdog
    pub enable_watchdog: bool,
    /// Enable restart protection (auto-restart on unexpected termination)
    pub enable_restart_protection: bool,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Stats polling interval in seconds
    pub stats_interval_secs: u64,
    /// Service name for restart protection (used for SCM restart)
    pub service_name: String,
}

impl Default for DriverIntegrationConfig {
    fn default() -> Self {
        Self {
            enable_driver: true,
            enable_process_protection: true,
            enable_file_protection: true,
            enable_network_control: true,
            enable_watchdog: true,
            enable_restart_protection: true,
            heartbeat_interval_secs: 30,
            stats_interval_secs: 60,
            service_name: "TamanduaAgent".to_string(),
        }
    }
}

/// Self-protection statistics from kernel driver
#[derive(Debug, Clone, Default)]
pub struct DriverSelfProtStats {
    /// Number of times process access was stripped
    pub process_access_stripped: u64,
    /// Number of times thread access was stripped
    pub thread_access_stripped: u64,
    /// Number of blocked registry deletes
    pub registry_blocked_deletes: u64,
    /// Number of blocked registry set operations
    pub registry_blocked_set_values: u64,
    /// Number of integrity checks performed
    pub integrity_checks_performed: u64,
    /// Number of integrity failures
    pub integrity_failures: u64,
    /// Number of debugger detections
    pub debugger_detections: u64,
    /// Object protection active
    pub object_protection_active: bool,
    /// Registry protection active
    pub registry_protection_active: bool,
    /// Driver integrity valid
    pub integrity_valid: bool,
    /// Debugger detected
    pub debugger_present: bool,
    /// Protected agent PID
    pub agent_process_id: u32,
    /// Restart protection registered
    pub restart_protection_registered: bool,
    /// Restart protection enabled
    pub restart_protection_enabled: bool,
    /// Number of driver-initiated restarts
    pub restart_count: u32,
}

/// Driver integration manager
pub struct DriverIntegration {
    config: DriverIntegrationConfig,
    running: Arc<AtomicBool>,
    #[cfg(target_os = "windows")]
    connection: Arc<std::sync::Mutex<DriverConnection>>,
    connected: AtomicBool,
    last_stats: std::sync::RwLock<DriverSelfProtStats>,
    tamper_tx: mpsc::Sender<TamperEvent>,
    start_time: std::time::Instant,
    events_processed: Arc<AtomicU64>,
}

impl DriverIntegration {
    /// Create a new driver integration manager
    pub fn new(config: DriverIntegrationConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "windows")]
            connection: Arc::new(std::sync::Mutex::new(DriverConnection::new())),
            connected: AtomicBool::new(false),
            last_stats: std::sync::RwLock::new(DriverSelfProtStats::default()),
            tamper_tx,
            start_time: std::time::Instant::now(),
            events_processed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Initialize driver integration
    #[cfg(target_os = "windows")]
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enable_driver {
            info!("Driver integration disabled by configuration");
            return Ok(());
        }

        info!("Initializing driver integration");
        self.running.store(true, Ordering::SeqCst);

        // Check if driver is loaded
        if !driver::is_driver_loaded() {
            warn!("Tamandua kernel driver is not loaded - running in usermode-only mode");
            return Ok(());
        }

        // Connect to driver
        {
            let mut conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());
            match conn.connect() {
                Ok(()) => {
                    self.connected.store(true, Ordering::SeqCst);
                    info!("Connected to Tamandua kernel driver");
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to driver: {} - running in usermode-only mode",
                        e
                    );
                    return Ok(());
                }
            }
        }

        // Register agent with driver
        self.register_agent().await?;

        // Enable process protection
        if self.config.enable_process_protection {
            self.enable_process_protection().await?;
        }

        // Register PID with watchdog
        if self.config.enable_watchdog {
            self.register_watchdog().await?;
        }

        // Register for restart protection
        if self.config.enable_restart_protection {
            self.register_restart_protection().await?;
        }

        // Start heartbeat task
        self.start_heartbeat_task();

        // Start stats polling task
        self.start_stats_polling_task();

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn initialize(&self) -> Result<()> {
        info!("Driver integration not available on this platform");
        Ok(())
    }

    /// Register agent with the driver
    #[cfg(target_os = "windows")]
    async fn register_agent(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let agent_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cmd_line = std::env::args().collect::<Vec<_>>().join(" ");

        conn.register_agent(
            &agent_path,
            Some(&cmd_line),
            true, // auto_restart
            true, // protected
        )?;

        info!("Agent registered with kernel driver");
        Ok(())
    }

    /// Enable process protection via driver
    #[cfg(target_os = "windows")]
    async fn enable_process_protection(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        // Protect our process with all flags:
        // NO_TERMINATE | NO_INJECT | NO_MEMORY_ACCESS | NO_HANDLE_DUP
        conn.protect_process(std::process::id(), protect_flags::FULL)?;

        info!(
            pid = std::process::id(),
            "Process protected via kernel driver"
        );
        Ok(())
    }

    /// Register with anti-tamper watchdog
    #[cfg(target_os = "windows")]
    async fn register_watchdog(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        conn.register_agent_pid()?;
        info!("Registered with kernel anti-tamper watchdog");
        Ok(())
    }

    /// Register for restart protection with the kernel driver.
    ///
    /// When enabled, the kernel driver monitors the agent process using
    /// PsSetCreateProcessNotifyRoutineEx. If the agent terminates unexpectedly
    /// (without calling signal_clean_shutdown), the driver will restart it.
    ///
    /// Restart methods (in order of preference):
    /// 1. SCM service restart (preferred, most reliable)
    /// 2. Recovery helper process signal
    /// 3. Direct process creation via ZwCreateUserProcess (fallback)
    #[cfg(target_os = "windows")]
    async fn register_restart_protection(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let agent_path = std::env::current_exe()?;
        let service_name = &self.config.service_name;

        conn.register_restart_protection(
            &agent_path,
            service_name,
            driver::restart_flags::DEFAULT,
        )?;

        info!(
            service = service_name,
            path = %agent_path.display(),
            "Restart protection registered with kernel driver"
        );
        Ok(())
    }

    /// Start heartbeat task
    #[cfg(target_os = "windows")]
    fn start_heartbeat_task(&self) {
        let running = self.running.clone();
        let connection = self.connection.clone();
        let interval_secs = self.config.heartbeat_interval_secs;
        let start_time = self.start_time;
        let events_processed = self.events_processed.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                let uptime = start_time.elapsed().as_secs() as u32;
                let events = events_processed.load(Ordering::SeqCst) as u32;

                if let Ok(conn) = connection.lock() {
                    if let Err(e) = conn.heartbeat(uptime, events) {
                        debug!("Driver heartbeat failed: {}", e);
                    }
                }
            }
        });

        debug!(interval = interval_secs, "Driver heartbeat task started");
    }

    #[cfg(not(target_os = "windows"))]
    fn start_heartbeat_task(&self) {
        // No-op on non-Windows
    }

    /// Start statistics polling task
    #[cfg(target_os = "windows")]
    fn start_stats_polling_task(&self) {
        let running = self.running.clone();
        let tamper_tx = self.tamper_tx.clone();
        let last_stats = self
            .last_stats
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let interval_secs = self.config.stats_interval_secs;

        // Note: The actual IOCTL for getting stats would need to be implemented
        // in the driver module. This is a placeholder for the stats retrieval logic.

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            let prev_integrity_failures = 0u64;
            let prev_debugger_detections = 0u64;

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                // In a real implementation, this would call the driver to get stats
                // For now, we'll check for events that indicate driver-detected issues

                // If integrity failures increased, report tampering
                // If debugger detections increased, report debugging

                // This is a placeholder - actual implementation requires IOCTL
            }
        });

        debug!(
            interval = interval_secs,
            "Driver stats polling task started"
        );
    }

    #[cfg(not(target_os = "windows"))]
    fn start_stats_polling_task(&self) {
        // No-op on non-Windows
    }

    /// Signal clean shutdown to driver.
    ///
    /// IMPORTANT: Call this before a planned agent exit (update, administrative
    /// shutdown, etc.) to prevent the kernel driver from restarting the agent.
    #[cfg(target_os = "windows")]
    pub async fn signal_clean_shutdown(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Ok(()); // Non-fatal if not connected
        }

        conn.signal_clean_shutdown()?;
        info!("Clean shutdown signaled to driver watchdog");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn signal_clean_shutdown(&self) -> Result<()> {
        Ok(())
    }

    // ========================================================================
    // Public Restart Protection API
    //
    // These methods allow the agent to manage its restart protection state.
    // The primary workflow is:
    // 1. register_for_restart_protection() is called during initialization
    // 2. signal_clean_shutdown() is called before planned exits
    // 3. On unexpected termination, the driver restarts the agent
    // ========================================================================

    /// Register the agent for restart protection.
    ///
    /// This is the primary public API for enabling restart protection.
    /// Call this during agent startup to ensure the agent will be restarted
    /// if it is terminated unexpectedly.
    ///
    /// # Arguments
    /// * `agent_path` - Path to the agent executable (for direct restart)
    ///
    /// # Example
    /// ```ignore
    /// let agent_path = std::env::current_exe()?;
    /// driver_integration.register_for_restart_protection(&agent_path).await?;
    /// ```
    #[cfg(target_os = "windows")]
    pub async fn register_for_restart_protection(
        &self,
        agent_path: &std::path::Path,
    ) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        conn.register_restart_protection(
            agent_path,
            &self.config.service_name,
            driver::restart_flags::DEFAULT,
        )?;

        info!(
            path = %agent_path.display(),
            service = %self.config.service_name,
            "Registered for restart protection"
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn register_for_restart_protection(
        &self,
        _agent_path: &std::path::Path,
    ) -> Result<()> {
        // Restart protection is Windows-only (requires kernel driver)
        info!("Restart protection not available on this platform");
        Ok(())
    }

    /// Unregister from restart protection.
    ///
    /// Call this when uninstalling the agent or when restart protection
    /// is no longer desired.
    #[cfg(target_os = "windows")]
    pub async fn unregister_restart_protection(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Ok(()); // Non-fatal
        }

        conn.unregister_restart_protection()?;
        info!("Unregistered from restart protection");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn unregister_restart_protection(&self) -> Result<()> {
        Ok(())
    }

    /// Temporarily disable restart protection.
    ///
    /// Use this during updates or maintenance when you don't want
    /// the agent to be automatically restarted.
    #[cfg(target_os = "windows")]
    pub async fn disable_restart_protection(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Ok(());
        }

        conn.set_restart_enabled(false)?;
        info!("Restart protection temporarily disabled");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn disable_restart_protection(&self) -> Result<()> {
        Ok(())
    }

    /// Re-enable restart protection after it was temporarily disabled.
    #[cfg(target_os = "windows")]
    pub async fn enable_restart_protection(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        conn.set_restart_enabled(true)?;
        info!("Restart protection re-enabled");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn enable_restart_protection(&self) -> Result<()> {
        Ok(())
    }

    /// Get the current restart protection status.
    #[cfg(target_os = "windows")]
    pub fn get_restart_protection_status(&self) -> Result<driver::RestartProtectionStatus> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());
        conn.get_restart_status()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_restart_protection_status(&self) -> Result<RestartProtectionStatusFallback> {
        Ok(RestartProtectionStatusFallback::default())
    }

    /// Protect a file via driver
    #[cfg(target_os = "windows")]
    pub fn protect_file(&self, path: &str) -> Result<()> {
        // This would call the driver's file protection IOCTL
        // The driver uses minifilter to protect files from modification/deletion
        debug!(path = path, "File protection requested (via driver)");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn protect_file(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    /// Enable network isolation via driver (WFP)
    #[cfg(target_os = "windows")]
    pub async fn enable_network_isolation(&self, allowed_ips: &[u32]) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        conn.isolate_network(true, allowed_ips)?;
        info!(
            allowed_count = allowed_ips.len(),
            "Network isolation enabled via driver"
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn enable_network_isolation(&self, _allowed_ips: &[u32]) -> Result<()> {
        Err(anyhow!("Network isolation not available on this platform"))
    }

    /// Disable network isolation via driver
    #[cfg(target_os = "windows")]
    pub async fn disable_network_isolation(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        conn.restore_network()?;
        info!("Network isolation disabled via driver");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn disable_network_isolation(&self) -> Result<()> {
        Ok(())
    }

    /// Kill a process via driver (kernel-level termination)
    #[cfg(target_os = "windows")]
    pub fn kill_process(&self, pid: u32) -> Result<()> {
        let conn = self.connection.lock().unwrap_or_else(|e| e.into_inner());

        if !conn.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        conn.kill_process(pid)?;
        info!(pid = pid, "Process killed via kernel driver");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn kill_process(&self, _pid: u32) -> Result<()> {
        Err(anyhow!(
            "Kernel process kill not available on this platform"
        ))
    }

    /// Get driver connection status
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Get driver safety state (usermode fallback status)
    #[cfg(target_os = "windows")]
    pub fn get_safety_state(&self) -> driver::DriverSafetyState {
        if let Ok(conn) = self.connection.lock() {
            conn.get_safety_state()
        } else {
            driver::DriverSafetyState::default()
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_safety_state(&self) -> DriverSafetyFallback {
        DriverSafetyFallback::default()
    }

    /// Get last retrieved stats
    pub fn get_last_stats(&self) -> DriverSelfProtStats {
        self.last_stats
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Increment events processed counter
    pub fn record_event_processed(&self) {
        self.events_processed.fetch_add(1, Ordering::SeqCst);
    }

    /// Shutdown driver integration
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);

        // Signal clean shutdown to driver
        if let Err(e) = self.signal_clean_shutdown().await {
            warn!("Failed to signal clean shutdown: {}", e);
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(mut conn) = self.connection.lock() {
                conn.disconnect();
            }
        }

        self.connected.store(false, Ordering::SeqCst);
        info!("Driver integration shutdown");
    }
}

/// Fallback safety state for non-Windows platforms
#[derive(Debug, Clone, Default)]
pub struct DriverSafetyFallback {
    pub usermode_fallback: bool,
}

/// Restart protection status fallback for non-Windows platforms
#[derive(Debug, Clone, Default)]
pub struct RestartProtectionStatusFallback {
    pub registered: bool,
    pub enabled: bool,
    pub restart_count: u32,
    pub last_restart_time: u64,
    pub clean_shutdown_signaled: bool,
}

/// Driver integration status
#[derive(Debug, Clone)]
pub struct DriverIntegrationStatus {
    pub connected: bool,
    pub process_protected: bool,
    pub watchdog_registered: bool,
    pub restart_protection_registered: bool,
    pub usermode_fallback: bool,
    pub stats: DriverSelfProtStats,
}

// =============================================================================
// Standalone Public API Functions
//
// These functions provide a simple interface for restart protection that can
// be called without needing a DriverIntegration instance. They use a global
// driver connection under the hood.
// =============================================================================

/// Register the current agent process for restart protection.
///
/// This is a convenience function that registers the agent for automatic
/// restart when it is terminated unexpectedly. The kernel driver will monitor
/// the agent process and restart it if it dies without calling
/// `signal_clean_shutdown()`.
///
/// # Arguments
/// * `agent_path` - Path to the agent executable
///
/// # Returns
/// * `Ok(())` if registration succeeded or driver is not available
/// * `Err` if registration failed
///
/// # Example
/// ```ignore
/// use std::path::Path;
/// use protection::driver_integration::register_for_restart_protection;
///
/// let agent_path = std::env::current_exe()?;
/// register_for_restart_protection(&agent_path)?;
/// ```
#[cfg(target_os = "windows")]
pub fn register_for_restart_protection(agent_path: &std::path::Path) -> Result<()> {
    use crate::driver::{self, restart_flags, DriverConnection};

    // Check if driver is available
    if !driver::is_driver_loaded() {
        info!("Kernel driver not loaded - restart protection not available");
        return Ok(());
    }

    // Create a temporary connection to register
    let mut conn = DriverConnection::new();
    if conn.connect().is_err() {
        info!("Could not connect to driver - restart protection not available");
        return Ok(());
    }

    conn.register_restart_protection(agent_path, "TamanduaAgent", restart_flags::DEFAULT)?;

    info!(path = %agent_path.display(), "Registered for restart protection");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn register_for_restart_protection(_agent_path: &std::path::Path) -> Result<()> {
    // Restart protection is Windows-only
    Ok(())
}

/// Signal that the agent is performing a clean shutdown.
///
/// Call this before the agent exits normally (e.g., for updates or
/// administrative shutdown). This tells the kernel driver NOT to restart
/// the agent when it terminates.
///
/// # Returns
/// * `Ok(())` if signal was sent or driver is not available
/// * `Err` if communication failed
///
/// # Example
/// ```ignore
/// use protection::driver_integration::signal_clean_shutdown;
///
/// // Before exiting normally
/// signal_clean_shutdown()?;
/// std::process::exit(0);
/// ```
#[cfg(target_os = "windows")]
pub fn signal_clean_shutdown() -> Result<()> {
    use crate::driver::{self, DriverConnection};

    if !driver::is_driver_loaded() {
        return Ok(());
    }

    let mut conn = DriverConnection::new();
    if conn.connect().is_err() {
        return Ok(());
    }

    conn.signal_clean_shutdown()?;
    info!("Clean shutdown signaled - driver will not restart agent");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn signal_clean_shutdown() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DriverIntegrationConfig::default();
        assert!(config.enable_driver);
        assert!(config.enable_process_protection);
        assert!(config.enable_watchdog);
        assert!(config.enable_restart_protection);
        assert_eq!(config.service_name, "TamanduaAgent");
    }

    #[test]
    fn test_restart_status_fallback_default() {
        let status = RestartProtectionStatusFallback::default();
        assert!(!status.registered);
        assert!(!status.enabled);
        assert_eq!(status.restart_count, 0);
    }
}
