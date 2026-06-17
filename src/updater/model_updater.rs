//! ML model and rule hot-reload via the server update API.
//!
//! This module handles downloading and atomically installing new versions of:
//!
//! - **ONNX models** (Malware-SMELL, ByteTransformer, Ensemble) used by the
//!   local ML inference engine for offline malware detection.
//! - **YARA rules** pushed from the server or a threat intel feed.
//! - **Sigma rules** for behavioral detection.
//! - **IOC lists** (hashes, IPs, domains).
//!
//! ## Update protocol
//!
//! The agent polls `GET /api/v1/updates/models` with its current model version
//! hashes. The server responds with a manifest listing newer assets. Each asset
//! is downloaded to a temp file, hash-verified, then atomically renamed into
//! position. After installation the agent signals the ONNX inference engine
//! (and YARA/Sigma loaders) to reload.
//!
//! ## Atomic file replacement
//!
//! To avoid serving a half-written model or rule file, downloads always go to
//! a `.tmp` sibling file. Once the download is complete and the hash verified,
//! the tmp file is renamed over the target path. On most operating systems
//! `rename` within the same filesystem is atomic.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Maximum retry attempts for asset downloads.
const MAX_DOWNLOAD_RETRIES: u32 = 3;

/// Base delay for exponential backoff on download retries.
const DOWNLOAD_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Types of assets that can be updated via the model updater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    /// Malware-SMELL VGG-19 ONNX model.
    OnnxSmell,
    /// ByteTransformer ONNX model.
    OnnxTransformer,
    /// Combined ensemble ONNX model.
    OnnxEnsemble,
    /// Feature-based local ML model.
    OnnxFeatures,
    /// YARA rule bundle (tar.gz of .yar files).
    YaraRules,
    /// Sigma rule bundle (tar.gz of .yml files).
    SigmaRules,
    /// IOC list (JSON file).
    IocList,
}

impl AssetType {
    /// Human-readable name for logging.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::OnnxSmell => "ONNX SMELL model",
            Self::OnnxTransformer => "ONNX ByteTransformer model",
            Self::OnnxEnsemble => "ONNX Ensemble model",
            Self::OnnxFeatures => "ONNX Features model",
            Self::YaraRules => "YARA rules",
            Self::SigmaRules => "Sigma rules",
            Self::IocList => "IOC list",
        }
    }
}

/// A single asset listed in the model update manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetManifestEntry {
    /// Type of asset.
    pub asset_type: AssetType,
    /// Version identifier (e.g. "2.1.0" or a date-based tag).
    pub version: String,
    /// SHA-256 hash of the asset file (lowercase hex).
    pub sha256: String,
    /// URL to download the asset from.
    pub download_url: String,
    /// Size of the asset in bytes.
    pub size: u64,
}

/// Response from the model update check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelUpdateManifest {
    /// List of assets that have newer versions available.
    pub assets: Vec<AssetManifestEntry>,
    /// Ed25519 signature of the canonical manifest JSON (base64).
    pub signature: String,
}

/// Current versions of all tracked assets, sent to the server so it can
/// determine which assets need updating.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentAssetVersions {
    /// SHA-256 hash of the currently installed SMELL model (or empty).
    pub smell_sha256: String,
    /// SHA-256 hash of the currently installed ByteTransformer model (or empty).
    pub transformer_sha256: String,
    /// SHA-256 hash of the currently installed ensemble model (or empty).
    pub ensemble_sha256: String,
    /// SHA-256 hash of the currently installed features model (or empty).
    pub features_sha256: String,
    /// SHA-256 hash of the current YARA rules bundle (or empty).
    pub yara_sha256: String,
    /// SHA-256 hash of the current Sigma rules bundle (or empty).
    pub sigma_sha256: String,
    /// SHA-256 hash of the current IOC list (or empty).
    pub ioc_sha256: String,
}

/// Callback invoked after a model asset has been successfully installed.
/// The updater calls this so the inference engine can reload the model
/// without restarting.
pub type ReloadCallback = Box<dyn Fn(AssetType, &Path) -> Result<()> + Send + Sync>;

// ---------------------------------------------------------------------------
// ModelUpdater
// ---------------------------------------------------------------------------

/// Manages checking, downloading, and installing ML model and rule updates.
pub struct ModelUpdater {
    /// HTTP client for downloads.
    http_client: reqwest::Client,
    /// Base URL for the model update API.
    update_base_url: String,
    /// Agent ID for the update check request.
    agent_id: String,
    /// Platform identifier.
    platform: String,
    /// Interval between automatic model update checks.
    check_interval: Duration,
    /// Ed25519 public key for manifest verification (base64, or empty for default).
    signing_public_key: String,
    /// Optional callback to invoke after a model is installed.
    reload_callback: Option<ReloadCallback>,
}

impl ModelUpdater {
    /// Create a new ModelUpdater.
    ///
    /// `server_url` is the WebSocket server URL (used to derive the REST API
    /// base). `check_interval_hours` controls how often the background loop
    /// polls for new model versions.
    pub fn new(
        server_url: &str,
        agent_id: &str,
        check_interval_hours: u64,
        signing_public_key: &str,
    ) -> Result<Self> {
        let configured_key = if signing_public_key.trim().is_empty() {
            None
        } else {
            Some(signing_public_key)
        };
        super::signature::ensure_non_placeholder_key(configured_key)?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(600)) // 10 min for large models
            .connect_timeout(Duration::from_secs(30))
            .user_agent(format!("tamandua-agent/{}", super::CURRENT_VERSION))
            .build()
            .context("Failed to build HTTP client for model updater")?;

        let update_base_url = Self::derive_base_url(server_url);
        let platform = super::Updater::platform().to_string();

        Ok(Self {
            http_client,
            update_base_url,
            agent_id: agent_id.to_string(),
            platform,
            check_interval: Duration::from_secs(check_interval_hours * 3600),
            signing_public_key: signing_public_key.to_string(),
            reload_callback: None,
        })
    }

    /// Set the callback invoked after a model asset is successfully installed.
    pub fn set_reload_callback(&mut self, cb: ReloadCallback) {
        self.reload_callback = Some(cb);
    }

    /// Derive the model update API base URL from the server URL.
    fn derive_base_url(server_url: &str) -> String {
        let base = server_url
            .replace("wss://", "https://")
            .replace("ws://", "http://");

        if let Some(idx) = base.find("/socket") {
            format!("{}/api/v1/updates/models", &base[..idx])
        } else {
            format!("{}/api/v1/updates/models", base.trim_end_matches('/'))
        }
    }

    // -----------------------------------------------------------------------
    // Current asset hashing
    // -----------------------------------------------------------------------

    /// Compute the current versions (SHA-256 hashes) of all tracked assets.
    pub fn current_versions(&self) -> CurrentAssetVersions {
        CurrentAssetVersions {
            smell_sha256: self.hash_if_exists(&Self::model_path(AssetType::OnnxSmell)),
            transformer_sha256: self.hash_if_exists(&Self::model_path(AssetType::OnnxTransformer)),
            ensemble_sha256: self.hash_if_exists(&Self::model_path(AssetType::OnnxEnsemble)),
            features_sha256: self.hash_if_exists(&Self::model_path(AssetType::OnnxFeatures)),
            yara_sha256: self.hash_if_exists(&Self::rules_path(AssetType::YaraRules)),
            sigma_sha256: self.hash_if_exists(&Self::rules_path(AssetType::SigmaRules)),
            ioc_sha256: self.hash_if_exists(&Self::rules_path(AssetType::IocList)),
        }
    }

    /// Compute SHA-256 of a file if it exists, or return an empty string.
    fn hash_if_exists(&self, path: &Path) -> String {
        if path.exists() {
            super::signature::sha256_file(path).unwrap_or_default()
        } else {
            String::new()
        }
    }

    /// Get the default installation path for a given asset type.
    pub fn model_path(asset_type: AssetType) -> PathBuf {
        let base = Self::asset_base_dir();
        match asset_type {
            AssetType::OnnxSmell => base.join("models").join("malware_smell.onnx"),
            AssetType::OnnxTransformer => base.join("models").join("byte_transformer.onnx"),
            AssetType::OnnxEnsemble => base.join("models").join("ensemble.onnx"),
            AssetType::OnnxFeatures => base.join("models").join("malware_features.onnx"),
            _ => base.join("unknown"),
        }
    }

    /// Get the default installation path for rule assets.
    pub fn rules_path(asset_type: AssetType) -> PathBuf {
        let base = Self::asset_base_dir();
        match asset_type {
            AssetType::YaraRules => base.join("rules").join("yara_bundle.tar.gz"),
            AssetType::SigmaRules => base.join("rules").join("sigma_bundle.tar.gz"),
            AssetType::IocList => base.join("iocs.json"),
            _ => base.join("unknown"),
        }
    }

    /// Get the target installation path for any asset type.
    fn target_path(asset_type: AssetType) -> PathBuf {
        match asset_type {
            AssetType::OnnxSmell
            | AssetType::OnnxTransformer
            | AssetType::OnnxEnsemble
            | AssetType::OnnxFeatures => Self::model_path(asset_type),
            AssetType::YaraRules | AssetType::SigmaRules | AssetType::IocList => {
                Self::rules_path(asset_type)
            }
        }
    }

    /// Platform-specific base directory for assets.
    fn asset_base_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Tamandua")
        }
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua")
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from(".")
        }
    }

    // -----------------------------------------------------------------------
    // Check for updates
    // -----------------------------------------------------------------------

    /// Check the server for newer model/rule versions.
    ///
    /// Returns a manifest listing assets that need updating, or `None` if
    /// everything is up to date.
    pub async fn check_for_updates(&self) -> Result<Option<ModelUpdateManifest>> {
        let versions = self.current_versions();

        let url = format!(
            "{}/check?platform={}&agent_id={}",
            self.update_base_url, self.platform, self.agent_id,
        );

        info!(url = %url, "Checking for model/rule updates");

        let response = self
            .http_client
            .post(&url)
            .json(&versions)
            .send()
            .await
            .context("Failed to send model update check request")?;

        let status = response.status();

        if status == reqwest::StatusCode::NO_CONTENT || status == reqwest::StatusCode::NOT_FOUND {
            info!("All models and rules are up to date");
            return Ok(None);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!(
                "Model update check failed with HTTP {}: {}",
                status.as_u16(),
                body
            );
        }

        let manifest: ModelUpdateManifest = response
            .json()
            .await
            .context("Failed to parse model update manifest")?;

        if manifest.assets.is_empty() {
            info!("No model or rule updates available");
            return Ok(None);
        }

        info!(
            asset_count = manifest.assets.len(),
            "Model/rule updates available"
        );

        // Verify manifest signature
        self.verify_manifest(&manifest)?;

        Ok(Some(manifest))
    }

    /// Verify the Ed25519 signature on a model update manifest.
    fn verify_manifest(&self, manifest: &ModelUpdateManifest) -> Result<()> {
        let canonical = serde_json::json!({
            "assets": manifest.assets,
        });
        let canonical_json = serde_json::to_string(&canonical)
            .context("Failed to serialize canonical model manifest")?;

        let public_key = if self.signing_public_key.is_empty() {
            None
        } else {
            Some(self.signing_public_key.as_str())
        };

        super::signature::verify_manifest_signature(
            &canonical_json,
            &manifest.signature,
            public_key,
        )
    }

    // -----------------------------------------------------------------------
    // Download and install assets
    // -----------------------------------------------------------------------

    /// Download and install all assets in a manifest.
    ///
    /// Each asset is downloaded, hash-verified, and atomically moved into
    /// position. After each model asset is installed, the reload callback
    /// is invoked so the inference engine picks up the new model without
    /// restarting.
    ///
    /// Returns the number of successfully installed assets.
    pub async fn install_updates(&self, manifest: &ModelUpdateManifest) -> Result<usize> {
        let mut installed = 0usize;

        for entry in &manifest.assets {
            match self.install_single_asset(entry).await {
                Ok(()) => {
                    installed += 1;
                    info!(
                        asset = entry.asset_type.display_name(),
                        version = %entry.version,
                        "Asset updated successfully"
                    );
                }
                Err(e) => {
                    error!(
                        asset = entry.asset_type.display_name(),
                        version = %entry.version,
                        error = %e,
                        "Failed to install asset (skipping)"
                    );
                }
            }
        }

        info!(
            installed = installed,
            total = manifest.assets.len(),
            "Model/rule update batch complete"
        );

        Ok(installed)
    }

    /// Download, verify, and atomically install a single asset.
    async fn install_single_asset(&self, entry: &AssetManifestEntry) -> Result<()> {
        let target = Self::target_path(entry.asset_type);

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        // Download to temp file
        let tmp_path = target.with_extension("tmp");

        info!(
            asset = entry.asset_type.display_name(),
            url = %entry.download_url,
            size = entry.size,
            dest = %target.display(),
            "Downloading asset"
        );

        self.download_with_retry(&entry.download_url, &tmp_path, entry.size)
            .await?;

        // Verify hash
        let actual_hash = super::signature::sha256_file(&tmp_path)?;
        if actual_hash != entry.sha256.to_lowercase() {
            let _ = std::fs::remove_file(&tmp_path);
            bail!(
                "Asset hash mismatch for {}: expected {}, got {}",
                entry.asset_type.display_name(),
                entry.sha256,
                actual_hash
            );
        }

        debug!(
            asset = entry.asset_type.display_name(),
            hash = %actual_hash,
            "Asset hash verified"
        );

        // Atomic rename: tmp -> target
        // On the same filesystem, rename is atomic on most OSes.
        std::fs::rename(&tmp_path, &target).with_context(|| {
            format!(
                "Failed to rename temp file to target: {} -> {}",
                tmp_path.display(),
                target.display()
            )
        })?;

        info!(
            asset = entry.asset_type.display_name(),
            path = %target.display(),
            version = %entry.version,
            "Asset installed"
        );

        // Signal the inference engine / rule loader to reload
        if let Some(ref cb) = self.reload_callback {
            match cb(entry.asset_type, &target) {
                Ok(()) => {
                    info!(
                        asset = entry.asset_type.display_name(),
                        "Reload callback executed successfully"
                    );
                }
                Err(e) => {
                    warn!(
                        asset = entry.asset_type.display_name(),
                        error = %e,
                        "Reload callback failed (asset is installed but not yet active)"
                    );
                }
            }
        }

        Ok(())
    }

    /// Download a file with retry and progress logging.
    async fn download_with_retry(&self, url: &str, dest: &Path, expected_size: u64) -> Result<()> {
        let mut last_error = None;

        for attempt in 0..MAX_DOWNLOAD_RETRIES {
            if attempt > 0 {
                let delay = DOWNLOAD_RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
                warn!(
                    attempt = attempt + 1,
                    max = MAX_DOWNLOAD_RETRIES,
                    "Retrying asset download"
                );
                tokio::time::sleep(delay).await;
            }

            match self.download_once(url, dest).await {
                Ok(()) => {
                    // Verify size
                    let actual_size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);

                    if expected_size > 0 && actual_size != expected_size {
                        last_error = Some(anyhow::anyhow!(
                            "Size mismatch: expected {} bytes, got {}",
                            expected_size,
                            actual_size
                        ));
                        continue;
                    }

                    return Ok(());
                }
                Err(e) => {
                    warn!(error = %e, attempt = attempt + 1, "Download attempt failed");
                    last_error = Some(e);
                }
            }
        }

        bail!(
            "Failed to download asset after {} attempts: {}",
            MAX_DOWNLOAD_RETRIES,
            last_error.map(|e| e.to_string()).unwrap_or_default()
        );
    }

    /// Perform a single streaming download.
    async fn download_once(&self, url: &str, dest: &Path) -> Result<()> {
        use futures_util::StreamExt;
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

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.context("Error reading download stream")?;
            file.write_all(&chunk)
                .await
                .context("Error writing to temp file")?;
            downloaded += chunk.len() as u64;

            // Log progress every 25%
            if total_size > 0 {
                let progress = (downloaded * 100) / total_size;
                if progress >= last_progress + 25 {
                    debug!(
                        downloaded = downloaded,
                        total = total_size,
                        pct = progress,
                        "Asset download progress"
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

    // -----------------------------------------------------------------------
    // Full update pipeline
    // -----------------------------------------------------------------------

    /// Run the full model update pipeline: check -> download -> verify -> install.
    ///
    /// Returns the number of assets updated (0 if everything is current).
    pub async fn perform_update(&self) -> Result<usize> {
        let manifest = match self.check_for_updates().await? {
            Some(m) => m,
            None => return Ok(0),
        };

        self.install_updates(&manifest).await
    }

    // -----------------------------------------------------------------------
    // Background loop
    // -----------------------------------------------------------------------

    /// Spawn a background task that periodically checks for model/rule updates.
    ///
    /// Errors are logged but never crash the agent.
    pub fn spawn_background_loop(self) -> tokio::task::JoinHandle<()> {
        let interval = self.check_interval;

        tokio::spawn(async move {
            info!(
                interval_hours = interval.as_secs() / 3600,
                "Model updater background loop started"
            );

            // Wait before the first check to let the agent stabilize
            tokio::time::sleep(Duration::from_secs(120)).await;

            let mut timer = tokio::time::interval(interval);
            // Consume first tick
            timer.tick().await;

            loop {
                timer.tick().await;

                debug!("Running scheduled model update check");

                match self.perform_update().await {
                    Ok(0) => {
                        debug!("All models and rules are current");
                    }
                    Ok(n) => {
                        info!(updated = n, "Model/rule update cycle complete");
                    }
                    Err(e) => {
                        warn!(error = %e, "Model update check failed (will retry next interval)");
                    }
                }
            }
        })
    }

    /// Trigger an immediate model update check.
    pub async fn trigger_immediate_update(&self) -> Result<usize> {
        info!("Immediate model update check triggered");
        self.perform_update().await
    }
}
