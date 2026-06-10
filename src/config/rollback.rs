//! Configuration backup and rollback system.
//!
//! Features:
//! - Automatic backup before applying config updates
//! - Stores last 10 config versions with timestamps
//! - SHA256 checksums for integrity verification
//! - Automatic rollback on health check failure
//! - Manual rollback to specific versions
//! - Diff between config versions

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

/// Maximum number of config backups to retain
const MAX_BACKUPS: usize = 10;

/// Backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Version number (incrementing)
    pub version: u64,
    /// Timestamp when backup was created
    pub timestamp: DateTime<Utc>,
    /// SHA256 checksum of the config file
    pub checksum: String,
    /// Optional description (e.g., "pre-update", "manual backup")
    pub description: Option<String>,
    /// Source of the config change (e.g., "server-push", "manual-edit", "rollback")
    pub source: String,
    /// User or system that triggered the change
    pub triggered_by: Option<String>,
}

/// Configuration backup manager
pub struct ConfigRollback {
    /// Directory where backups are stored.
    ///
    /// This is `pub` so integration tests can redirect backups to a tempdir.
    /// In production this is always initialized via [`ConfigRollback::new`] to
    /// the platform-specific protected location.
    pub backup_dir: PathBuf,
    /// Path to the active config file.
    pub config_path: PathBuf,
    /// Path to metadata index.
    ///
    /// `pub` for the same testing reason as `backup_dir`.
    pub metadata_path: PathBuf,
}

impl ConfigRollback {
    /// Returns a reference to the backup directory path.
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Returns a reference to the metadata index path.
    pub fn metadata_path(&self) -> &Path {
        &self.metadata_path
    }

    /// Returns a reference to the active config file path.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

impl ConfigRollback {
    /// Create a new ConfigRollback manager
    pub fn new(config_path: &Path) -> Result<Self> {
        let backup_dir = Self::get_backup_dir()?;

        // Create backup directory if it doesn't exist
        if !backup_dir.exists() {
            fs::create_dir_all(&backup_dir).with_context(|| {
                format!(
                    "Failed to create backup directory: {}",
                    backup_dir.display()
                )
            })?;
            info!(path = %backup_dir.display(), "Created config backup directory");
        }

        let metadata_path = backup_dir.join("metadata.json");

        Ok(Self {
            backup_dir,
            config_path: config_path.to_path_buf(),
            metadata_path,
        })
    }

    /// Get platform-specific backup directory
    fn get_backup_dir() -> Result<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            let dir = PathBuf::from(r"C:\ProgramData\Tamandua\config\backups");
            Ok(dir)
        }

        #[cfg(target_os = "linux")]
        {
            let dir = PathBuf::from("/var/lib/tamandua/config/backups");
            Ok(dir)
        }

        #[cfg(target_os = "macos")]
        {
            let dir = PathBuf::from("/Library/Application Support/Tamandua/config/backups");
            Ok(dir)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            // Fallback for other platforms
            let home = dirs::home_dir().context("Failed to get home directory")?;
            Ok(home.join(".tamandua/config/backups"))
        }
    }

    /// Calculate SHA256 checksum of a file
    fn calculate_checksum(path: &Path) -> Result<String> {
        let content = fs::read(path)
            .with_context(|| format!("Failed to read file for checksum: {}", path.display()))?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();

        Ok(hex::encode(hash))
    }

    /// Load metadata index
    fn load_metadata(&self) -> Result<Vec<BackupMetadata>> {
        if !self.metadata_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&self.metadata_path).with_context(|| {
            format!("Failed to read metadata: {}", self.metadata_path.display())
        })?;

        let metadata: Vec<BackupMetadata> =
            serde_json::from_str(&content).context("Failed to parse metadata JSON")?;

        Ok(metadata)
    }

    /// Save metadata index
    fn save_metadata(&self, metadata: &[BackupMetadata]) -> Result<()> {
        let content =
            serde_json::to_string_pretty(metadata).context("Failed to serialize metadata")?;

        fs::write(&self.metadata_path, content).with_context(|| {
            format!("Failed to write metadata: {}", self.metadata_path.display())
        })?;

        Ok(())
    }

    /// Create a backup of the current config
    pub fn create_backup(
        &self,
        description: Option<String>,
        source: &str,
        triggered_by: Option<String>,
    ) -> Result<u64> {
        if !self.config_path.exists() {
            bail!("Config file does not exist: {}", self.config_path.display());
        }

        // Load existing metadata
        let mut metadata_list = self.load_metadata()?;

        // Calculate new version number
        let version = metadata_list.iter().map(|m| m.version).max().unwrap_or(0) + 1;

        // Calculate checksum
        let checksum = Self::calculate_checksum(&self.config_path)?;

        // Check if this is identical to the last backup
        if let Some(last) = metadata_list.last() {
            if last.checksum == checksum {
                debug!(version = last.version, "Config unchanged, skipping backup");
                return Ok(last.version);
            }
        }

        // Create backup file
        let backup_filename = format!("config_v{:04}.toml", version);
        let backup_path = self.backup_dir.join(&backup_filename);

        fs::copy(&self.config_path, &backup_path).with_context(|| {
            format!("Failed to copy config to backup: {}", backup_path.display())
        })?;

        // Create metadata entry
        let metadata = BackupMetadata {
            version,
            timestamp: Utc::now(),
            checksum: checksum.clone(),
            description,
            source: source.to_string(),
            triggered_by,
        };

        metadata_list.push(metadata);

        // Trim old backups if we exceed MAX_BACKUPS
        if metadata_list.len() > MAX_BACKUPS {
            let to_remove = metadata_list.len() - MAX_BACKUPS;
            for meta in metadata_list.drain(0..to_remove) {
                let old_backup = self
                    .backup_dir
                    .join(format!("config_v{:04}.toml", meta.version));
                if old_backup.exists() {
                    if let Err(e) = fs::remove_file(&old_backup) {
                        warn!(path = %old_backup.display(), error = %e, "Failed to remove old backup");
                    } else {
                        debug!(version = meta.version, "Removed old backup");
                    }
                }
            }
        }

        // Save updated metadata
        self.save_metadata(&metadata_list)?;

        info!(
            version = version,
            source = %source,
            checksum = %&checksum[..16],
            "Config backup created"
        );

        Ok(version)
    }

    /// List all available backups
    pub fn list_backups(&self) -> Result<Vec<BackupMetadata>> {
        self.load_metadata()
    }

    /// Get a specific backup by version
    pub fn get_backup(&self, version: u64) -> Result<BackupMetadata> {
        let metadata_list = self.load_metadata()?;

        metadata_list
            .into_iter()
            .find(|m| m.version == version)
            .with_context(|| format!("Backup version {} not found", version))
    }

    /// Restore config from a specific backup version
    pub fn restore_version(&self, version: u64) -> Result<()> {
        // Find the backup metadata
        let metadata = self.get_backup(version)?;

        // Construct backup file path
        let backup_path = self.backup_dir.join(format!("config_v{:04}.toml", version));

        if !backup_path.exists() {
            bail!("Backup file not found: {}", backup_path.display());
        }

        // Verify checksum
        let current_checksum = Self::calculate_checksum(&backup_path)?;
        if current_checksum != metadata.checksum {
            error!(
                version = version,
                expected = %metadata.checksum,
                actual = %current_checksum,
                "Backup checksum mismatch - possible corruption"
            );
            bail!("Backup integrity check failed for version {}", version);
        }

        // Before restoring, create a backup of the current config
        // (in case we need to rollback the rollback)
        if self.config_path.exists() {
            let _ = self.create_backup(
                Some(format!("pre-rollback to v{}", version)),
                "auto-backup",
                None,
            );
        }

        // Copy backup to active config location
        fs::copy(&backup_path, &self.config_path).with_context(|| {
            format!(
                "Failed to restore config from backup: {}",
                backup_path.display()
            )
        })?;

        info!(
            version = version,
            timestamp = %metadata.timestamp,
            "Config restored from backup"
        );

        Ok(())
    }

    /// Restore the most recent backup
    pub fn restore_latest(&self) -> Result<()> {
        let metadata_list = self.load_metadata()?;

        let latest = metadata_list.last().context("No backups available")?;

        self.restore_version(latest.version)
    }

    /// Get diff between two versions (or between a version and current config)
    pub fn diff_versions(&self, version1: u64, version2: Option<u64>) -> Result<String> {
        let path1 = self
            .backup_dir
            .join(format!("config_v{:04}.toml", version1));

        if !path1.exists() {
            bail!("Version {} not found", version1);
        }

        let content1 = fs::read_to_string(&path1)?;

        let content2 = if let Some(v2) = version2 {
            let path2 = self.backup_dir.join(format!("config_v{:04}.toml", v2));
            if !path2.exists() {
                bail!("Version {} not found", v2);
            }
            fs::read_to_string(&path2)?
        } else {
            // Compare with current config
            if !self.config_path.exists() {
                bail!("Current config file not found");
            }
            fs::read_to_string(&self.config_path)?
        };

        // Simple line-by-line diff
        let diff = self.simple_diff(&content1, &content2);

        Ok(diff)
    }

    /// Simple diff implementation (could be enhanced with external diff crate)
    fn simple_diff(&self, content1: &str, content2: &str) -> String {
        let lines1: Vec<&str> = content1.lines().collect();
        let lines2: Vec<&str> = content2.lines().collect();

        let mut diff = String::new();
        let max_len = lines1.len().max(lines2.len());

        for i in 0..max_len {
            let line1 = lines1.get(i).copied();
            let line2 = lines2.get(i).copied();

            match (line1, line2) {
                (Some(l1), Some(l2)) => {
                    if l1 != l2 {
                        diff.push_str(&format!("- {}\n", l1));
                        diff.push_str(&format!("+ {}\n", l2));
                    }
                }
                (Some(l1), None) => {
                    diff.push_str(&format!("- {}\n", l1));
                }
                (None, Some(l2)) => {
                    diff.push_str(&format!("+ {}\n", l2));
                }
                (None, None) => {}
            }
        }

        if diff.is_empty() {
            diff.push_str("No differences found\n");
        }

        diff
    }

    /// Verify integrity of all backups
    pub fn verify_backups(&self) -> Result<Vec<(u64, bool)>> {
        let metadata_list = self.load_metadata()?;
        let mut results = Vec::new();

        for meta in metadata_list {
            let backup_path = self
                .backup_dir
                .join(format!("config_v{:04}.toml", meta.version));

            if !backup_path.exists() {
                warn!(version = meta.version, "Backup file missing");
                results.push((meta.version, false));
                continue;
            }

            match Self::calculate_checksum(&backup_path) {
                Ok(checksum) => {
                    let valid = checksum == meta.checksum;
                    if !valid {
                        warn!(
                            version = meta.version,
                            expected = %meta.checksum,
                            actual = %checksum,
                            "Backup checksum mismatch"
                        );
                    }
                    results.push((meta.version, valid));
                }
                Err(e) => {
                    warn!(version = meta.version, error = %e, "Failed to verify backup");
                    results.push((meta.version, false));
                }
            }
        }

        Ok(results)
    }

    /// Clean up all backups (for testing or manual cleanup)
    #[cfg(test)]
    pub fn cleanup_all(&self) -> Result<()> {
        let metadata_list = self.load_metadata()?;

        for meta in metadata_list {
            let backup_path = self
                .backup_dir
                .join(format!("config_v{:04}.toml", meta.version));
            if backup_path.exists() {
                fs::remove_file(&backup_path)?;
            }
        }

        if self.metadata_path.exists() {
            fs::remove_file(&self.metadata_path)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config(dir: &Path) -> PathBuf {
        let config_path = dir.join("agent.toml");
        fs::write(
            &config_path,
            "agent_id = \"test\"\nserver_url = \"wss://localhost:4000\"\n",
        )
        .unwrap();
        config_path
    }

    #[test]
    fn test_create_backup() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let mut rollback = ConfigRollback::new(&config_path).unwrap();
        rollback.backup_dir = temp_dir.path().join("backups");
        rollback.metadata_path = rollback.backup_dir.join("metadata.json");
        fs::create_dir_all(&rollback.backup_dir).unwrap();

        let version = rollback
            .create_backup(
                Some("test backup".to_string()),
                "test",
                Some("admin".to_string()),
            )
            .unwrap();

        assert_eq!(version, 1);

        // Verify backup file exists
        let backup_path = rollback.backup_dir.join("config_v0001.toml");
        assert!(backup_path.exists());

        // Verify metadata
        let metadata_list = rollback.list_backups().unwrap();
        assert_eq!(metadata_list.len(), 1);
        assert_eq!(metadata_list[0].version, 1);
        assert_eq!(
            metadata_list[0].description,
            Some("test backup".to_string())
        );
    }

    #[test]
    fn test_restore_backup() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let mut rollback = ConfigRollback::new(&config_path).unwrap();
        rollback.backup_dir = temp_dir.path().join("backups");
        rollback.metadata_path = rollback.backup_dir.join("metadata.json");
        fs::create_dir_all(&rollback.backup_dir).unwrap();

        // Create initial backup
        let v1 = rollback.create_backup(None, "test", None).unwrap();

        // Modify config
        fs::write(
            &config_path,
            "agent_id = \"modified\"\nserver_url = \"wss://modified:4000\"\n",
        )
        .unwrap();

        // Create second backup
        let v2 = rollback.create_backup(None, "test", None).unwrap();
        assert_eq!(v2, 2);

        // Restore first version
        rollback.restore_version(v1).unwrap();

        // Verify content
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("test"));
        assert!(!content.contains("modified"));
    }

    #[test]
    fn test_max_backups() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let mut rollback = ConfigRollback::new(&config_path).unwrap();
        rollback.backup_dir = temp_dir.path().join("backups");
        rollback.metadata_path = rollback.backup_dir.join("metadata.json");
        fs::create_dir_all(&rollback.backup_dir).unwrap();

        // Create more than MAX_BACKUPS
        for i in 1..=15 {
            fs::write(&config_path, format!("version = {}\n", i)).unwrap();
            rollback.create_backup(None, "test", None).unwrap();
        }

        let metadata_list = rollback.list_backups().unwrap();
        assert!(metadata_list.len() <= MAX_BACKUPS);

        // Verify oldest backups were removed
        assert!(metadata_list.iter().all(|m| m.version > 5));
    }

    #[test]
    fn test_checksum_verification() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let mut rollback = ConfigRollback::new(&config_path).unwrap();
        rollback.backup_dir = temp_dir.path().join("backups");
        rollback.metadata_path = rollback.backup_dir.join("metadata.json");
        fs::create_dir_all(&rollback.backup_dir).unwrap();

        let version = rollback.create_backup(None, "test", None).unwrap();

        // Corrupt the backup file
        let backup_path = rollback
            .backup_dir
            .join(format!("config_v{:04}.toml", version));
        fs::write(&backup_path, "corrupted content").unwrap();

        // Verify should fail
        let results = rollback.verify_backups().unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].1); // Should be invalid
    }

    #[test]
    fn test_no_backup_on_identical_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let mut rollback = ConfigRollback::new(&config_path).unwrap();
        rollback.backup_dir = temp_dir.path().join("backups");
        rollback.metadata_path = rollback.backup_dir.join("metadata.json");
        fs::create_dir_all(&rollback.backup_dir).unwrap();

        let v1 = rollback.create_backup(None, "test", None).unwrap();
        let v2 = rollback.create_backup(None, "test", None).unwrap();

        assert_eq!(v1, v2); // Should return same version
        assert_eq!(rollback.list_backups().unwrap().len(), 1);
    }
}
