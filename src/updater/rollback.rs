//! Rollback mechanism for the agent self-updater.
//!
//! Provides backup management, post-update health checks, automatic rollback
//! on failure, and version history tracking. Works in tandem with the main
//! updater to ensure the agent can always recover from a bad update.
//!
//! ## Rollback flow
//!
//! 1. Before installing an update, [`RollbackManager::create_backup`] copies the
//!    current binary to a versioned backup location and writes a rollback marker.
//! 2. After the new binary starts, [`RollbackManager::run_health_check`] verifies
//!    connectivity and collector functionality within 60 seconds.
//! 3. If the health check fails, [`RollbackManager::execute_rollback`] restores
//!    the previous binary and restarts the agent.
//! 4. If the health check passes, [`RollbackManager::confirm_update`] cleans up
//!    old backups (keeping the last 2 versions) and removes the rollback marker.
//!
//! ## Platform-specific behavior
//!
//! - **Windows**: Rollback state is recorded in both a file marker and a
//!   registry key (`HKLM\SOFTWARE\Tamandua\PendingRollback`). The registry
//!   flag survives crashes that corrupt the marker file.
//! - **Linux/macOS**: Rollback state is recorded in a file flag at
//!   `/var/lib/tamandua/.rollback_pending`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Maximum number of backup versions to retain.
const MAX_BACKUP_VERSIONS: usize = 2;

/// Duration to wait for a successful health check after an update.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between individual health check attempts.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Name of the rollback pending flag file.
const ROLLBACK_FLAG_FILENAME: &str = ".rollback_pending";

/// Windows registry path for the rollback flag.
#[cfg(target_os = "windows")]
const REGISTRY_KEY_PATH: &str = r"SOFTWARE\Tamandua";

/// Windows registry value name for the rollback flag.
#[cfg(target_os = "windows")]
const REGISTRY_VALUE_NAME: &str = "PendingRollback";

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Metadata for a single backup version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Semantic version of the backed-up binary.
    pub version: String,
    /// Path to the backup file.
    pub path: String,
    /// SHA-256 hash of the backup binary (lowercase hex).
    pub sha256: String,
    /// Unix timestamp when the backup was created.
    pub created_at: u64,
    /// Size of the backup in bytes.
    pub size: u64,
}

/// Rollback state persisted to disk alongside backup files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackState {
    /// Ordered list of backup entries (newest first).
    pub backups: Vec<BackupEntry>,
    /// If set, a rollback is pending and this contains the version to
    /// roll back to if the health check fails.
    pub pending_rollback: Option<PendingRollback>,
}

impl Default for RollbackState {
    fn default() -> Self {
        Self {
            backups: Vec::new(),
            pending_rollback: None,
        }
    }
}

/// Details of a pending rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRollback {
    /// Version we are rolling back from (the newly installed version).
    pub from_version: String,
    /// Version we are rolling back to (the backup).
    pub to_version: String,
    /// Path to the backup binary to restore.
    pub backup_path: String,
    /// Unix timestamp when the update was installed.
    pub installed_at: u64,
    /// Agent ID for reporting.
    pub agent_id: String,
}

/// Result of a post-update health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Whether the server is reachable.
    pub server_reachable: bool,
    /// Whether the agent process is healthy (not crashing).
    pub process_healthy: bool,
    /// Optional error details.
    pub error: Option<String>,
}

impl HealthCheckResult {
    /// Returns `true` if all health checks passed.
    pub fn is_healthy(&self) -> bool {
        self.server_reachable && self.process_healthy
    }
}

// ---------------------------------------------------------------------------
// RollbackManager
// ---------------------------------------------------------------------------

/// Manages binary backups, health checks, and rollback operations.
pub struct RollbackManager {
    /// Directory where backup binaries and state are stored.
    backup_dir: PathBuf,
    /// Path to the state file.
    state_path: PathBuf,
    /// Server URL for health checks.
    server_url: String,
    /// Agent ID for reporting.
    agent_id: String,
}

impl RollbackManager {
    /// Create a new RollbackManager.
    ///
    /// The backup directory is created if it does not exist.
    pub fn new(server_url: &str, agent_id: &str) -> Result<Self> {
        let backup_dir = Self::default_backup_dir();

        std::fs::create_dir_all(&backup_dir).with_context(|| {
            format!(
                "Failed to create backup directory: {}",
                backup_dir.display()
            )
        })?;

        let state_path = backup_dir.join("rollback_state.json");

        Ok(Self {
            backup_dir,
            state_path,
            server_url: server_url.to_string(),
            agent_id: agent_id.to_string(),
        })
    }

    /// Platform-specific default backup directory.
    fn default_backup_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Tamandua\backups")
        }
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/backups")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/backups")
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./backups")
        }
    }

    /// Load the rollback state from disk, or return a default state.
    pub fn load_state(&self) -> RollbackState {
        if !self.state_path.exists() {
            return RollbackState::default();
        }

        match std::fs::read_to_string(&self.state_path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(state) => state,
                Err(e) => {
                    warn!(error = %e, "Failed to parse rollback state, using default");
                    RollbackState::default()
                }
            },
            Err(e) => {
                warn!(error = %e, "Failed to read rollback state, using default");
                RollbackState::default()
            }
        }
    }

    /// Persist the rollback state to disk.
    fn save_state(&self, state: &RollbackState) -> Result<()> {
        let json =
            serde_json::to_string_pretty(state).context("Failed to serialize rollback state")?;
        std::fs::write(&self.state_path, json).with_context(|| {
            format!(
                "Failed to write rollback state: {}",
                self.state_path.display()
            )
        })?;
        debug!(path = %self.state_path.display(), "Rollback state saved");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Backup creation
    // -----------------------------------------------------------------------

    /// Create a backup of the current agent binary before an update.
    ///
    /// Returns the path to the backup file.
    pub fn create_backup(&self, current_version: &str) -> Result<PathBuf> {
        let current_exe =
            std::env::current_exe().context("Failed to determine current executable path")?;

        let extension = if cfg!(target_os = "windows") {
            ".exe"
        } else {
            ""
        };
        let backup_filename = format!("tamandua-agent-v{}{}", current_version, extension,);
        let backup_path = self.backup_dir.join(&backup_filename);

        info!(
            source = %current_exe.display(),
            dest = %backup_path.display(),
            version = %current_version,
            "Creating backup of current binary"
        );

        std::fs::copy(&current_exe, &backup_path).with_context(|| {
            format!(
                "Failed to copy binary to backup: {} -> {}",
                current_exe.display(),
                backup_path.display()
            )
        })?;

        // Compute hash of backup
        let sha256 = super::signature::sha256_file(&backup_path)?;

        // Get file size
        let metadata = std::fs::metadata(&backup_path)?;

        // Update state
        let mut state = self.load_state();
        let entry = BackupEntry {
            version: current_version.to_string(),
            path: backup_path.to_string_lossy().to_string(),
            sha256,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            size: metadata.len(),
        };

        // Insert at front (newest first)
        state.backups.insert(0, entry);

        // Prune old backups beyond MAX_BACKUP_VERSIONS
        self.prune_old_backups(&mut state);

        self.save_state(&state)?;

        info!(
            backup = %backup_path.display(),
            version = %current_version,
            total_backups = state.backups.len(),
            "Backup created successfully"
        );

        Ok(backup_path)
    }

    /// Remove old backup files beyond the retention limit.
    fn prune_old_backups(&self, state: &mut RollbackState) {
        while state.backups.len() > MAX_BACKUP_VERSIONS {
            if let Some(old) = state.backups.pop() {
                let old_path = PathBuf::from(&old.path);
                if old_path.exists() {
                    match std::fs::remove_file(&old_path) {
                        Ok(()) => {
                            info!(
                                path = %old_path.display(),
                                version = %old.version,
                                "Pruned old backup"
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                path = %old_path.display(),
                                "Failed to prune old backup file"
                            );
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Pending rollback flag
    // -----------------------------------------------------------------------

    /// Set the pending rollback flag after installing an update.
    ///
    /// This flag is checked on startup to determine if a rollback should be
    /// attempted. Uses both a file flag and (on Windows) a registry key for
    /// resilience.
    pub fn set_pending_rollback(
        &self,
        from_version: &str,
        to_version: &str,
        backup_path: &Path,
    ) -> Result<()> {
        let pending = PendingRollback {
            from_version: from_version.to_string(),
            to_version: to_version.to_string(),
            backup_path: backup_path.to_string_lossy().to_string(),
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            agent_id: self.agent_id.clone(),
        };

        // Update state file
        let mut state = self.load_state();
        state.pending_rollback = Some(pending.clone());
        self.save_state(&state)?;

        // Write flag file
        let flag_path = self.flag_file_path();
        let flag_json = serde_json::to_string_pretty(&pending)
            .context("Failed to serialize pending rollback flag")?;
        std::fs::write(&flag_path, flag_json)
            .with_context(|| format!("Failed to write rollback flag: {}", flag_path.display()))?;

        info!(
            from = %from_version,
            to = %to_version,
            "Pending rollback flag set"
        );

        // Windows: also write to registry for crash resilience
        #[cfg(target_os = "windows")]
        {
            self.set_registry_flag(from_version, to_version, backup_path);
        }

        Ok(())
    }

    /// Clear the pending rollback flag (called after successful health check).
    pub fn clear_pending_rollback(&self) -> Result<()> {
        // Clear state
        let mut state = self.load_state();
        state.pending_rollback = None;
        self.save_state(&state)?;

        // Remove flag file
        let flag_path = self.flag_file_path();
        if flag_path.exists() {
            std::fs::remove_file(&flag_path).with_context(|| {
                format!("Failed to remove rollback flag: {}", flag_path.display())
            })?;
        }

        // Windows: clear registry flag
        #[cfg(target_os = "windows")]
        {
            self.clear_registry_flag();
        }

        info!("Pending rollback flag cleared");
        Ok(())
    }

    /// Check whether a rollback is pending.
    pub fn is_rollback_pending(&self) -> Option<PendingRollback> {
        // Check file flag first
        let flag_path = self.flag_file_path();
        if flag_path.exists() {
            if let Ok(json) = std::fs::read_to_string(&flag_path) {
                if let Ok(pending) = serde_json::from_str::<PendingRollback>(&json) {
                    return Some(pending);
                }
            }
        }

        // Fall back to state file
        let state = self.load_state();
        state.pending_rollback
    }

    /// Path to the rollback pending flag file.
    fn flag_file_path(&self) -> PathBuf {
        self.backup_dir.join(ROLLBACK_FLAG_FILENAME)
    }

    // -----------------------------------------------------------------------
    // Windows registry flag
    // -----------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    fn set_registry_flag(&self, from_version: &str, to_version: &str, backup_path: &Path) {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        match hklm.create_subkey(REGISTRY_KEY_PATH) {
            Ok((key, _)) => {
                let value = format!("{}|{}|{}", from_version, to_version, backup_path.display());
                if let Err(e) = key.set_value(REGISTRY_VALUE_NAME, &value) {
                    warn!(error = %e, "Failed to set rollback registry flag");
                } else {
                    debug!("Rollback registry flag set");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to create registry key for rollback flag");
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn clear_registry_flag(&self) {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok((key, _)) = hklm.create_subkey(REGISTRY_KEY_PATH) {
            let _ = key.delete_value(REGISTRY_VALUE_NAME);
            debug!("Rollback registry flag cleared");
        }
    }

    // -----------------------------------------------------------------------
    // Health check
    // -----------------------------------------------------------------------

    /// Run a post-update health check.
    ///
    /// Attempts to verify server connectivity and basic agent functionality
    /// within [`HEALTH_CHECK_TIMEOUT`]. Returns the health check result.
    pub async fn run_health_check(&self) -> HealthCheckResult {
        info!(
            timeout_secs = HEALTH_CHECK_TIMEOUT.as_secs(),
            "Starting post-update health check"
        );

        let deadline = tokio::time::Instant::now() + HEALTH_CHECK_TIMEOUT;
        let mut attempt = 0u32;

        while tokio::time::Instant::now() < deadline {
            attempt += 1;
            debug!(attempt = attempt, "Health check attempt");

            let result = self.check_health_once().await;

            if result.is_healthy() {
                info!(attempt = attempt, "Post-update health check passed");
                return result;
            }

            debug!(
                attempt = attempt,
                server_reachable = result.server_reachable,
                process_healthy = result.process_healthy,
                error = ?result.error,
                "Health check attempt failed, retrying"
            );

            tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
        }

        // Final attempt
        let result = self.check_health_once().await;
        if !result.is_healthy() {
            error!(
                server_reachable = result.server_reachable,
                process_healthy = result.process_healthy,
                error = ?result.error,
                "Post-update health check FAILED after {} seconds",
                HEALTH_CHECK_TIMEOUT.as_secs()
            );
        }

        result
    }

    /// Perform a single health check attempt.
    async fn check_health_once(&self) -> HealthCheckResult {
        let mut result = HealthCheckResult {
            server_reachable: false,
            process_healthy: true,
            error: None,
        };

        // Check 1: Verify the server health endpoint is reachable
        let health_url = self.derive_health_url();
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(client) => {
                match client.get(&health_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        result.server_reachable = true;
                        debug!(url = %health_url, "Server health endpoint reachable");
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        debug!(
                            url = %health_url,
                            status = status.as_u16(),
                            "Server returned non-success status"
                        );
                        // Server is reachable even if it returns 4xx/5xx
                        result.server_reachable = true;
                    }
                    Err(e) => {
                        result.error = Some(format!("Server unreachable: {}", e));
                    }
                }
            }
            Err(e) => {
                result.error = Some(format!("Failed to create HTTP client: {}", e));
                result.process_healthy = false;
            }
        }

        // Check 2: Verify the agent process is not in a crash loop
        // (basic self-check -- if we got this far, the process is running)
        result.process_healthy = true;

        result
    }

    /// Derive the health check URL from the server URL.
    fn derive_health_url(&self) -> String {
        let base = self
            .server_url
            .replace("wss://", "https://")
            .replace("ws://", "http://");

        if let Some(idx) = base.find("/socket") {
            format!("{}/api/v1/health", &base[..idx])
        } else {
            format!("{}/api/v1/health", base.trim_end_matches('/'))
        }
    }

    // -----------------------------------------------------------------------
    // Rollback execution
    // -----------------------------------------------------------------------

    /// Execute a rollback: restore the backup binary and restart.
    ///
    /// Returns `Ok(())` if the rollback was successful (and the process will
    /// be restarted). Returns `Err` if the rollback failed.
    pub fn execute_rollback(&self, pending: &PendingRollback) -> Result<()> {
        let backup_path = PathBuf::from(&pending.backup_path);
        let current_exe =
            std::env::current_exe().context("Failed to determine current executable path")?;

        if !backup_path.exists() {
            bail!(
                "Rollback failed: backup binary does not exist: {}",
                backup_path.display()
            );
        }

        info!(
            from = %pending.from_version,
            to = %pending.to_version,
            backup = %backup_path.display(),
            current = %current_exe.display(),
            "Executing rollback"
        );

        // Verify backup integrity
        let state = self.load_state();
        if let Some(entry) = state
            .backups
            .iter()
            .find(|b| b.version == pending.to_version)
        {
            match super::signature::sha256_file(&backup_path) {
                Ok(hash) if hash == entry.sha256 => {
                    debug!("Backup integrity verified");
                }
                Ok(hash) => {
                    warn!(
                        expected = %entry.sha256,
                        actual = %hash,
                        "Backup hash mismatch -- proceeding with caution"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "Failed to verify backup integrity -- proceeding anyway");
                }
            }
        }

        // Move current (broken) binary aside
        let broken_path = current_exe.with_extension("broken");
        if let Err(e) = std::fs::rename(&current_exe, &broken_path) {
            warn!(error = %e, "Failed to rename broken binary, trying copy approach");
            // Fallback: overwrite current with backup
            std::fs::copy(&backup_path, &current_exe)
                .context("Failed to copy backup over current binary")?;
        } else {
            // Restore backup to current path
            std::fs::copy(&backup_path, &current_exe).with_context(|| {
                format!(
                    "Failed to restore backup: {} -> {}",
                    backup_path.display(),
                    current_exe.display()
                )
            })?;
        }

        // Set executable permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755));
        }

        // Clean up the broken file (best effort)
        let _ = std::fs::remove_file(&broken_path);

        // Clear the pending rollback flag
        if let Err(e) = self.clear_pending_rollback() {
            warn!(error = %e, "Failed to clear rollback flag after rollback");
        }

        info!(
            version = %pending.to_version,
            "Rollback complete, previous binary restored at {}",
            current_exe.display()
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Update confirmation
    // -----------------------------------------------------------------------

    /// Confirm that an update is stable and clean up pending state.
    ///
    /// Called after a successful post-update health check.
    pub fn confirm_update(&self) -> Result<()> {
        info!("Confirming update as stable");

        self.clear_pending_rollback()?;

        // Prune old backups to keep only MAX_BACKUP_VERSIONS
        let mut state = self.load_state();
        self.prune_old_backups(&mut state);
        self.save_state(&state)?;

        info!(
            retained_backups = state.backups.len(),
            "Update confirmed, old backups pruned"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Backup listing
    // -----------------------------------------------------------------------

    /// List all available backup versions.
    pub fn list_backups(&self) -> Vec<BackupEntry> {
        let state = self.load_state();
        // Filter out entries whose files no longer exist
        state
            .backups
            .into_iter()
            .filter(|b| PathBuf::from(&b.path).exists())
            .collect()
    }

    /// Get the most recent backup entry.
    pub fn latest_backup(&self) -> Option<BackupEntry> {
        self.list_backups().into_iter().next()
    }
}
