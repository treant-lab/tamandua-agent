//! Agent self-update mechanism.
//!
//! Provides automatic update checking, downloading, verification, and
//! atomic installation with rollback support. Updates are checked on a
//! configurable interval (default: every 6 hours) or can be triggered
//! immediately by a server-pushed command.
//!
//! ## Update flow
//!
//! 1. `check_for_update()` calls `GET /api/v1/updates/check` with platform,
//!    version, and agent ID.
//! 2. If the server returns an [`UpdateManifest`] (newer version available for
//!    this agent based on rollout percentage), the manifest signature is
//!    verified with Ed25519.
//! 3. `download_update()` downloads the binary to a temporary location with
//!    progress tracking.
//! 4. `verify_update()` checks the SHA-256 hash of the downloaded file
//!    against the manifest.
//! 5. `install_update()` performs an atomic rename dance:
//!    - current binary -> current binary + `.bak`
//!    - downloaded binary -> current binary path
//!    - Write an update marker file (`.tamandua_update_marker`)
//!    - Spawn the new binary as a child process and exit the current process.
//! 6. On startup, the agent checks for the marker file. If the marker exists
//!    and the binary is less than 60 seconds old, it assumes the new version
//!    crashed and triggers a `rollback()`.

pub mod canary;
pub mod model_updater;
pub mod rollback;
pub mod signature;
pub mod verifier;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Build-time version from Cargo.toml.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of the marker file written after an update is installed.
/// Presence of this file on startup indicates a recent update.
const UPDATE_MARKER_FILENAME: &str = ".tamandua_update_marker";

/// If the binary is younger than this after an update, assume it crashed
/// and rollback immediately.
const CRASH_DETECTION_WINDOW: Duration = Duration::from_secs(60);

/// Extended probation period after an update. If the agent crashes within
/// this window (but after CRASH_DETECTION_WINDOW), the marker file is
/// still present and rollback triggers on the next restart. Only after
/// this period does the agent consider the update stable and clean up
/// the marker + backup files.
const UPDATE_PROBATION_PERIOD: Duration = Duration::from_secs(600); // 10 minutes

/// Maximum number of HTTP retry attempts for downloads.
const MAX_DOWNLOAD_RETRIES: u32 = 3;

/// Base delay for exponential backoff on download retries.
const DOWNLOAD_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Update manifest returned by the server's update check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Semantic version of the new release (e.g. "0.2.0").
    pub version: String,
    /// Target platform identifier (e.g. "windows-x86_64", "linux-x86_64").
    pub platform: String,
    /// SHA-256 hash of the update binary (lowercase hex).
    pub sha256: String,
    /// Ed25519 signature of the canonical manifest JSON (base64).
    pub signature: String,
    /// URL to download the update binary from.
    pub download_url: String,
    /// Size of the update binary in bytes.
    pub size: u64,
    /// Human-readable release notes.
    pub release_notes: String,
    /// Rollout percentage (0.0 - 100.0). The server already decides
    /// whether this agent should update; this is informational.
    pub rollout_percentage: f32,
}

/// Updater configuration, typically loaded from the `[updater]` section
/// of the agent config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateConfig {
    /// Master switch for the auto-updater.
    pub enabled: bool,
    /// Interval in hours between automatic binary update checks.
    pub check_interval_hours: u64,
    /// Interval in hours between automatic model/rule update checks.
    /// Defaults to 1 hour (models and rules change more frequently than
    /// the agent binary).
    pub model_update_interval_hours: u64,
    /// Whether model/rule updates are enabled.
    pub model_updates_enabled: bool,
    /// Base URL for the update API (e.g. "https://updates.treantlab.org/api/v1/updates").
    pub update_url: String,
    /// Whether to automatically restart after installing an update.
    pub auto_restart: bool,
    /// Ed25519 public key for update manifest verification (base64).
    /// If empty, the compiled-in default key is used.
    pub signing_public_key: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_hours: 6,
            model_update_interval_hours: 1,
            model_updates_enabled: true,
            update_url: String::new(), // Derived from server_url at runtime
            auto_restart: true,
            signing_public_key: String::new(),
        }
    }
}

/// Update status reported back to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateReport {
    pub agent_id: String,
    pub from_version: String,
    pub to_version: String,
    pub success: bool,
    pub error_message: Option<String>,
    pub platform: String,
}

/// Content of the update marker file written after installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateMarker {
    /// Version that was installed.
    version: String,
    /// Version we updated from (for rollback reporting).
    previous_version: String,
    /// Unix timestamp when the update was installed.
    installed_at: u64,
    /// Path to the backup (.bak) binary.
    backup_path: String,
    /// Original arguments used to launch the agent.
    original_args: Vec<String>,
}

// ---------------------------------------------------------------------------
// Updater
// ---------------------------------------------------------------------------

/// The self-update manager. Runs as a background task inside the agent.
pub struct Updater {
    config: UpdateConfig,
    current_version: String,
    agent_id: String,
    http_client: reqwest::Client,
    update_check_interval: Duration,
    server_url: String,
}

impl Updater {
    /// Create a new Updater from agent configuration.
    pub fn new(update_config: &UpdateConfig, agent_id: &str, server_url: &str) -> Result<Self> {
        // Emit a one-time diagnostic about the signing key
        let configured_key = if update_config.signing_public_key.is_empty() {
            None
        } else {
            Some(update_config.signing_public_key.as_str())
        };
        signature::warn_if_placeholder_key(configured_key);

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300)) // 5 min for large downloads
            .connect_timeout(Duration::from_secs(30))
            .user_agent(format!("tamandua-agent/{}", CURRENT_VERSION))
            .build()
            .context("Failed to build HTTP client for updater")?;

        let interval = Duration::from_secs(update_config.check_interval_hours * 3600);

        Ok(Self {
            config: update_config.clone(),
            current_version: CURRENT_VERSION.to_string(),
            agent_id: agent_id.to_string(),
            http_client,
            update_check_interval: interval,
            server_url: server_url.to_string(),
        })
    }

    /// Resolve the update API base URL.
    ///
    /// If `update_url` is explicitly configured, use that. Otherwise,
    /// derive it from the WebSocket server URL by switching to HTTPS
    /// and appending `/api/v1/updates`.
    fn update_base_url(&self) -> String {
        if !self.config.update_url.is_empty() {
            return self.config.update_url.trim_end_matches('/').to_string();
        }

        // Derive from server_url: ws://host:port/socket/agent -> https://host:port/api/v1/updates
        let base = self
            .server_url
            .replace("wss://", "https://")
            .replace("ws://", "http://");

        // Strip the WebSocket path segments
        if let Some(idx) = base.find("/socket") {
            format!("{}/api/v1/updates", &base[..idx])
        } else {
            format!("{}/api/v1/updates", base.trim_end_matches('/'))
        }
    }

    /// Get the current platform identifier.
    pub(crate) fn platform() -> &'static str {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            "windows-x86_64"
        }
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            "windows-aarch64"
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            "linux-x86_64"
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            "linux-aarch64"
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            "macos-x86_64"
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            "macos-aarch64"
        }
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "windows", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
        )))]
        {
            "unknown"
        }
    }

    // -----------------------------------------------------------------------
    // Core update flow
    // -----------------------------------------------------------------------

    /// Check the server for a newer version of the agent binary.
    ///
    /// Returns `Some(manifest)` if an update is available and the manifest
    /// signature is valid, or `None` if the agent is up to date.
    pub async fn check_for_update(&self) -> Result<Option<UpdateManifest>> {
        let base_url = self.update_base_url();
        let url = format!(
            "{}/check?platform={}&version={}&agent_id={}",
            base_url,
            Self::platform(),
            self.current_version,
            self.agent_id,
        );

        info!(
            url = %url,
            current_version = %self.current_version,
            "Checking for agent updates"
        );

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to send update check request")?;

        let status = response.status();

        if status == reqwest::StatusCode::NO_CONTENT || status == reqwest::StatusCode::NOT_FOUND {
            info!("Agent is up to date (no update available)");
            return Ok(None);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!(
                "Update check failed with HTTP {}: {}",
                status.as_u16(),
                body
            );
        }

        let manifest: UpdateManifest = response
            .json()
            .await
            .context("Failed to parse update manifest JSON")?;

        info!(
            new_version = %manifest.version,
            current_version = %self.current_version,
            rollout = manifest.rollout_percentage,
            size = manifest.size,
            "Update available"
        );

        // Verify manifest signature before proceeding
        self.verify_manifest(&manifest)?;

        // Check if this agent should update based on canary rollout
        if !canary::should_update(
            &self.agent_id,
            &manifest.version,
            manifest.rollout_percentage,
        ) {
            info!(
                version = %manifest.version,
                rollout = manifest.rollout_percentage,
                "Update available but agent not in rollout bucket"
            );
            return Ok(None);
        }

        Ok(Some(manifest))
    }

    /// Verify the Ed25519 signature on an update manifest.
    ///
    /// The signed message is the manifest JSON without the `signature` field.
    fn verify_manifest(&self, manifest: &UpdateManifest) -> Result<()> {
        // Reconstruct canonical JSON without the signature field
        let canonical = serde_json::json!({
            "version": manifest.version,
            "platform": manifest.platform,
            "sha256": manifest.sha256,
            "download_url": manifest.download_url,
            "size": manifest.size,
            "release_notes": manifest.release_notes,
            "rollout_percentage": manifest.rollout_percentage,
        });
        let canonical_json =
            serde_json::to_string(&canonical).context("Failed to serialize canonical manifest")?;

        let public_key = if self.config.signing_public_key.is_empty() {
            None
        } else {
            Some(self.config.signing_public_key.as_str())
        };

        signature::verify_manifest_signature(&canonical_json, &manifest.signature, public_key)
    }

    /// Download the update binary to a temporary file.
    ///
    /// Retries up to [`MAX_DOWNLOAD_RETRIES`] times with exponential backoff
    /// on transient failures. Returns the path to the downloaded temp file.
    pub async fn download_update(&self, manifest: &UpdateManifest) -> Result<PathBuf> {
        self.download_update_with_progress(manifest, |_downloaded, _total, _percent| {})
            .await
    }

    /// Download the update binary to a temporary file and report progress.
    pub async fn download_update_with_progress<F>(
        &self,
        manifest: &UpdateManifest,
        mut on_progress: F,
    ) -> Result<PathBuf>
    where
        F: FnMut(u64, u64, f32) + Send,
    {
        let temp_dir = std::env::temp_dir();
        let temp_filename = format!(
            "tamandua-update-{}{}",
            manifest.version,
            Self::binary_extension()
        );
        let temp_path = temp_dir.join(&temp_filename);

        info!(
            url = %manifest.download_url,
            size = manifest.size,
            dest = %temp_path.display(),
            "Downloading update binary"
        );

        let mut last_error = None;

        for attempt in 0..MAX_DOWNLOAD_RETRIES {
            if attempt > 0 {
                let delay = DOWNLOAD_RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
                warn!(
                    attempt = attempt + 1,
                    max_attempts = MAX_DOWNLOAD_RETRIES,
                    delay_secs = delay.as_secs(),
                    "Retrying update download"
                );
                tokio::time::sleep(delay).await;
            }

            match self
                .download_once_with_progress(&manifest.download_url, &temp_path, &mut on_progress)
                .await
            {
                Ok(()) => {
                    // Verify downloaded size
                    let metadata = std::fs::metadata(&temp_path)
                        .context("Failed to read downloaded file metadata")?;
                    if metadata.len() != manifest.size {
                        let err = anyhow::anyhow!(
                            "Downloaded file size mismatch: expected {} bytes, got {}",
                            manifest.size,
                            metadata.len()
                        );
                        last_error = Some(err);
                        continue;
                    }

                    info!(
                        path = %temp_path.display(),
                        size = metadata.len(),
                        "Update binary downloaded successfully"
                    );
                    return Ok(temp_path);
                }
                Err(e) => {
                    warn!(error = %e, attempt = attempt + 1, "Download attempt failed");
                    last_error = Some(e);
                }
            }
        }

        bail!(
            "Failed to download update after {} attempts: {}",
            MAX_DOWNLOAD_RETRIES,
            last_error.map(|e| e.to_string()).unwrap_or_default()
        );
    }

    /// Perform a single download attempt, streaming to disk.
    #[allow(dead_code)]
    async fn download_once(&self, url: &str, dest: &Path) -> Result<()> {
        self.download_once_with_progress(url, dest, &mut |_downloaded, _total, _percent| {})
            .await
    }

    async fn download_once_with_progress<F>(
        &self,
        url: &str,
        dest: &Path,
        on_progress: &mut F,
    ) -> Result<()>
    where
        F: FnMut(u64, u64, f32) + Send,
    {
        use tokio::io::AsyncWriteExt;

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .context("HTTP request failed")?;

        if !response.status().is_success() {
            bail!("Download failed with HTTP {}", response.status().as_u16());
        }

        let total_size = response.content_length().unwrap_or(0);
        let mut stream = response.bytes_stream();

        let mut file = tokio::fs::File::create(dest)
            .await
            .with_context(|| format!("Failed to create temp file: {}", dest.display()))?;

        let mut downloaded: u64 = 0;
        let mut last_progress: u64 = 0;

        use futures_util::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.context("Error reading download stream")?;
            file.write_all(&chunk)
                .await
                .context("Error writing to temp file")?;
            downloaded += chunk.len() as u64;
            let percent = if total_size > 0 {
                ((downloaded as f64 / total_size as f64) * 100.0) as f32
            } else {
                0.0
            };
            on_progress(downloaded, total_size, percent);

            // Log progress every 10%
            if total_size > 0 {
                let progress = (downloaded * 100) / total_size;
                if progress >= last_progress + 10 {
                    debug!(
                        downloaded_bytes = downloaded,
                        total_bytes = total_size,
                        progress_pct = progress,
                        "Download progress"
                    );
                    last_progress = progress;
                }
            }
        }

        file.flush()
            .await
            .context("Failed to flush downloaded file")?;
        Ok(())
    }

    /// Verify a downloaded update binary against the manifest.
    ///
    /// Performs two-stage verification:
    /// 1. SHA-256 hash check (ensures download integrity)
    /// 2. Platform-specific code signature verification (ensures binary authenticity)
    pub fn verify_update(&self, path: &Path, manifest: &UpdateManifest) -> Result<()> {
        info!(
            path = %path.display(),
            expected_sha256 = %manifest.sha256,
            "Verifying update binary integrity"
        );

        // Stage 1: Verify SHA-256 hash
        signature::verify_file_hash(path, &manifest.sha256)
            .context("Update binary hash check failed")?;

        info!("Update binary hash verified");

        // Stage 2: Verify code signature
        verifier::verify_code_signature(path)
            .context("Update binary code signature verification failed")?;

        // Log signature details
        if let Some(sig_info) = verifier::get_signature_info(path) {
            debug!(signature_info = %sig_info, "Code signature details");
        }

        info!("Update binary fully verified (hash + code signature)");
        Ok(())
    }

    /// Install the update by performing an atomic rename dance.
    ///
    /// 1. Rename current binary to `current.bak`
    /// 2. Move the new binary to the current binary path
    /// 3. Set executable permissions (Unix)
    /// 4. Write the update marker file
    /// 5. Spawn the new binary and exit (if `auto_restart` is enabled)
    ///
    /// Returns the path to the installed binary.
    pub async fn install_update(
        &self,
        downloaded_path: &Path,
        manifest: &UpdateManifest,
    ) -> Result<PathBuf> {
        let current_exe =
            std::env::current_exe().context("Failed to determine current executable path")?;

        let backup_path = current_exe.with_extension("bak");

        info!(
            current = %current_exe.display(),
            backup = %backup_path.display(),
            new = %downloaded_path.display(),
            version = %manifest.version,
            "Installing update"
        );

        // Step 1: Remove any old backup
        if backup_path.exists() {
            std::fs::remove_file(&backup_path).with_context(|| {
                format!("Failed to remove old backup: {}", backup_path.display())
            })?;
            debug!("Removed old backup file");
        }

        // Step 2: Rename current binary to .bak
        // On Windows, the running binary is locked. We use a platform-specific
        // approach: rename (MoveFileEx) with MOVEFILE_REPLACE_EXISTING.
        #[cfg(target_os = "windows")]
        {
            // On Windows, we cannot rename a running .exe directly. Instead
            // we rename it to .bak first (Windows allows renaming a running
            // file, just not deleting it).
            std::fs::rename(&current_exe, &backup_path).with_context(|| {
                format!(
                    "Failed to rename running binary to backup: {} -> {}",
                    current_exe.display(),
                    backup_path.display()
                )
            })?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            std::fs::rename(&current_exe, &backup_path).with_context(|| {
                format!(
                    "Failed to rename current binary to backup: {} -> {}",
                    current_exe.display(),
                    backup_path.display()
                )
            })?;
        }

        info!("Current binary backed up to {}", backup_path.display());

        // Step 3: Copy new binary to current path
        // We copy instead of rename in case they are on different filesystems.
        std::fs::copy(downloaded_path, &current_exe).with_context(|| {
            format!(
                "Failed to copy new binary to target: {} -> {}",
                downloaded_path.display(),
                current_exe.display()
            )
        })?;

        info!("New binary installed at {}", current_exe.display());

        // Step 4: Set executable permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&current_exe, permissions)
                .context("Failed to set executable permissions")?;
            debug!("Set executable permissions on new binary");
        }

        // Step 5: Write update marker
        let marker = UpdateMarker {
            version: manifest.version.clone(),
            previous_version: self.current_version.clone(),
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            backup_path: backup_path.to_string_lossy().to_string(),
            original_args: std::env::args().collect(),
        };

        let marker_path = Self::marker_file_path(&current_exe);
        let marker_json =
            serde_json::to_string_pretty(&marker).context("Failed to serialize update marker")?;
        std::fs::write(&marker_path, marker_json)
            .with_context(|| format!("Failed to write update marker: {}", marker_path.display()))?;

        info!(
            marker = %marker_path.display(),
            "Update marker written"
        );

        // Step 6: Clean up temp download
        let _ = std::fs::remove_file(downloaded_path);

        // Step 7: Report success to server
        self.report_update(manifest, true, None).await;

        // Step 8: Restart if configured
        if self.config.auto_restart {
            info!(
                exe = %current_exe.display(),
                version = %manifest.version,
                "Restarting agent with new binary"
            );

            // Spawn the new binary with the original arguments (skip argv[0])
            let args: Vec<String> = std::env::args().skip(1).collect();
            match std::process::Command::new(&current_exe).args(&args).spawn() {
                Ok(child) => {
                    info!(
                        pid = child.id(),
                        "New agent process spawned, exiting current process"
                    );
                    // Give the new process a moment to start
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    std::process::exit(0);
                }
                Err(e) => {
                    error!(error = %e, "Failed to spawn new agent process - initiating rollback");
                    if let Err(rb_err) = Self::do_rollback(&marker) {
                        error!(error = %rb_err, "Rollback after spawn failure also failed!");
                    }
                    bail!("Failed to restart agent after update: {}", e);
                }
            }
        }

        Ok(current_exe)
    }

    /// Perform the full update pipeline: check -> download -> verify -> install.
    ///
    /// This is the main entry point called by the background update loop
    /// and by immediate-update command handlers. Integrates with the
    /// [`rollback::RollbackManager`] to create versioned backups and
    /// set a pending rollback flag so the agent can recover if the new
    /// binary is broken.
    ///
    /// Returns `true` if an update was installed (and a restart initiated).
    pub async fn perform_update(&self) -> Result<bool> {
        let manifest = match self.check_for_update().await? {
            Some(m) => m,
            None => return Ok(false),
        };

        info!(
            from_version = %self.current_version,
            to_version = %manifest.version,
            "Starting update installation"
        );

        // Create a versioned backup via the RollbackManager before we
        // download and install the new binary.
        let rollback_mgr = rollback::RollbackManager::new(&self.server_url, &self.agent_id);

        if let Ok(mgr) = rollback_mgr.as_ref() {
            match mgr.create_backup(&self.current_version) {
                Ok(backup_path) => {
                    info!(
                        backup = %backup_path.display(),
                        "Versioned backup created via RollbackManager"
                    );

                    // Set pending rollback flag so we can recover if the
                    // new binary crashes before passing the health check.
                    if let Err(e) = mgr.set_pending_rollback(
                        &manifest.version,
                        &self.current_version,
                        &backup_path,
                    ) {
                        warn!(error = %e, "Failed to set rollback flag (continuing with update)");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to create versioned backup (continuing with update)");
                }
            }
        } else if let Err(ref e) = rollback_mgr {
            warn!(error = %e, "Failed to initialize RollbackManager (continuing with update)");
        }

        let downloaded_path = self.download_update(&manifest).await?;
        self.verify_update(&downloaded_path, &manifest)?;
        self.install_update(&downloaded_path, &manifest).await?;

        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Rollback
    // -----------------------------------------------------------------------

    /// Check for a recent update and rollback if the binary appears to have
    /// crashed shortly after the update.
    ///
    /// Called at startup, before the main agent loop begins.
    ///
    /// This first consults the [`rollback::RollbackManager`] for a pending
    /// rollback flag (set during `perform_update`). If found and the binary
    /// is within the crash detection window, it executes a rollback through
    /// the manager. Otherwise it falls through to the legacy marker-file
    /// based rollback check for backward compatibility.
    ///
    /// Returns `true` if a rollback was performed.
    pub fn check_and_rollback_if_needed() -> Result<bool> {
        let current_exe =
            std::env::current_exe().context("Failed to determine current executable path")?;

        // --- RollbackManager-based check (preferred) ---
        // We cannot know the server_url or agent_id at this point (config
        // hasn't been loaded yet), so we pass placeholders -- the manager
        // only needs the backup directory to check the flag file.
        if let Ok(mgr) = rollback::RollbackManager::new("", "") {
            if let Some(pending) = mgr.is_rollback_pending() {
                let binary_age = std::fs::metadata(&current_exe)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.elapsed().ok())
                    .unwrap_or(Duration::from_secs(u64::MAX));

                if binary_age < CRASH_DETECTION_WINDOW {
                    warn!(
                        binary_age_secs = binary_age.as_secs(),
                        from_version = %pending.from_version,
                        to_version = %pending.to_version,
                        "Post-update crash detected (RollbackManager) - initiating rollback"
                    );

                    mgr.execute_rollback(&pending)?;
                    return Ok(true);
                }

                if binary_age >= UPDATE_PROBATION_PERIOD {
                    // Update survived probation -- confirm it.
                    info!(
                        binary_age_secs = binary_age.as_secs(),
                        version = %pending.from_version,
                        "Update stable past probation (RollbackManager), confirming"
                    );
                    if let Err(e) = mgr.confirm_update() {
                        warn!(error = %e, "Failed to confirm update via RollbackManager");
                    }
                } else {
                    info!(
                        binary_age_secs = binary_age.as_secs(),
                        probation_secs = UPDATE_PROBATION_PERIOD.as_secs(),
                        "Update in probation (RollbackManager), keeping rollback flag"
                    );
                }
            }
        }

        // --- Legacy marker-file based check ---
        let marker_path = Self::marker_file_path(&current_exe);
        if !marker_path.exists() {
            return Ok(false);
        }

        // Read the marker
        let marker_json =
            std::fs::read_to_string(&marker_path).context("Failed to read update marker")?;
        let marker: UpdateMarker =
            serde_json::from_str(&marker_json).context("Failed to parse update marker")?;

        // Check if the binary is young enough to be a crash recovery
        let binary_metadata =
            std::fs::metadata(&current_exe).context("Failed to read binary metadata")?;

        let binary_age = binary_metadata
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .unwrap_or(Duration::from_secs(u64::MAX));

        if binary_age < CRASH_DETECTION_WINDOW {
            // Binary is very new -- this is likely a crash recovery restart.
            // The system (watchdog/service manager) restarted us quickly.
            warn!(
                binary_age_secs = binary_age.as_secs(),
                version = %marker.version,
                previous_version = %marker.previous_version,
                "Recently updated binary restarted within crash window - initiating rollback"
            );

            Self::do_rollback(&marker)?;

            // Clean up marker
            let _ = std::fs::remove_file(&marker_path);

            return Ok(true);
        }

        if binary_age < UPDATE_PROBATION_PERIOD {
            // Binary survived the immediate crash window but is still in
            // probation. Keep the marker and backup so that if the agent
            // crashes again (e.g. due to a subtle bug that manifests after
            // a few minutes), the next restart will see the marker and
            // trigger the rollback above.
            info!(
                binary_age_secs = binary_age.as_secs(),
                probation_secs = UPDATE_PROBATION_PERIOD.as_secs(),
                version = %marker.version,
                "Update in probation period -- keeping marker and backup for rollback safety"
            );
            return Ok(false);
        }

        // Binary has been running past the full probation period -- the
        // update is stable. Clean up marker and backup.
        info!(
            version = %marker.version,
            binary_age_secs = binary_age.as_secs(),
            "Update appears stable (past probation), cleaning up marker and backup"
        );

        let _ = std::fs::remove_file(&marker_path);
        let backup_path = PathBuf::from(&marker.backup_path);
        if backup_path.exists() {
            let _ = std::fs::remove_file(&backup_path);
            debug!("Cleaned up backup file: {}", backup_path.display());
        }

        Ok(false)
    }

    /// Perform the actual rollback: restore the backup binary and restart.
    fn do_rollback(marker: &UpdateMarker) -> Result<()> {
        let current_exe =
            std::env::current_exe().context("Failed to determine current executable path")?;
        let backup_path = PathBuf::from(&marker.backup_path);

        if !backup_path.exists() {
            bail!(
                "Rollback failed: backup file does not exist: {}",
                backup_path.display()
            );
        }

        info!(
            backup = %backup_path.display(),
            current = %current_exe.display(),
            "Rolling back to previous version {}", marker.previous_version
        );

        // On Windows: rename current (new, broken) -> .broken, then backup -> current
        let broken_path = current_exe.with_extension("broken");

        // Move current broken binary out of the way
        if let Err(e) = std::fs::rename(&current_exe, &broken_path) {
            warn!(error = %e, "Failed to rename broken binary (may be in use), trying copy approach");
            // Fallback: copy backup over current
            std::fs::copy(&backup_path, &current_exe)
                .context("Failed to copy backup over current binary")?;
        } else {
            // Restore backup
            std::fs::rename(&backup_path, &current_exe).with_context(|| {
                format!(
                    "Failed to restore backup: {} -> {}",
                    backup_path.display(),
                    current_exe.display()
                )
            })?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755));
        }

        info!(
            version = %marker.previous_version,
            "Rollback complete, previous binary restored"
        );

        // Clean up broken file (best effort)
        let _ = std::fs::remove_file(&broken_path);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Server reporting
    // -----------------------------------------------------------------------

    /// Report the outcome of an update attempt to the server.
    async fn report_update(&self, manifest: &UpdateManifest, success: bool, error: Option<String>) {
        let report = UpdateReport {
            agent_id: self.agent_id.clone(),
            from_version: self.current_version.clone(),
            to_version: manifest.version.clone(),
            success,
            error_message: error,
            platform: Self::platform().to_string(),
        };

        let base_url = self.update_base_url();
        let url = format!("{}/report", base_url);

        match self.http_client.post(&url).json(&report).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Update report sent to server");
            }
            Ok(resp) => {
                warn!(
                    status = resp.status().as_u16(),
                    "Server rejected update report"
                );
            }
            Err(e) => {
                warn!(error = %e, "Failed to send update report (non-fatal)");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Background task
    // -----------------------------------------------------------------------

    /// Spawn the periodic update check loop as a background tokio task.
    ///
    /// This task runs `check_for_update()` every `check_interval_hours` hours.
    /// If an update is found, it runs the full pipeline. Errors are logged
    /// but never crash the agent.
    pub fn spawn_background_loop(self) -> tokio::task::JoinHandle<()> {
        let interval = self.update_check_interval;

        tokio::spawn(async move {
            info!(
                interval_hours = interval.as_secs() / 3600,
                "Updater background loop started"
            );

            // Wait a short period before the first check to let the agent stabilize
            tokio::time::sleep(Duration::from_secs(60)).await;

            let mut timer = tokio::time::interval(interval);
            // Consume the first tick (already waited above)
            timer.tick().await;

            loop {
                timer.tick().await;

                debug!("Running scheduled update check");

                match self.perform_update().await {
                    Ok(true) => {
                        // Update was installed and restart initiated.
                        // This branch is theoretically unreachable because
                        // `install_update` calls `process::exit`, but we
                        // handle it gracefully just in case.
                        info!("Update installed, restart should be in progress");
                        break;
                    }
                    Ok(false) => {
                        debug!("No update available");
                    }
                    Err(e) => {
                        warn!(error = %e, "Update check failed (will retry next interval)");
                    }
                }
            }
        })
    }

    /// Trigger an immediate update check (called from command handlers).
    /// Returns `true` if an update was installed.
    pub async fn trigger_immediate_update(&self) -> Result<bool> {
        info!("Immediate update check triggered by server command");
        self.perform_update().await
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Get the path to the update marker file, located next to the binary.
    fn marker_file_path(exe_path: &Path) -> PathBuf {
        exe_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(UPDATE_MARKER_FILENAME)
    }

    /// Platform-specific binary extension.
    fn binary_extension() -> &'static str {
        #[cfg(target_os = "windows")]
        {
            ".exe"
        }
        #[cfg(not(target_os = "windows"))]
        {
            ""
        }
    }
}
