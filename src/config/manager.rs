//! Unified configuration manager with rollback, validation, and health checks.
//!
//! This module provides a high-level interface for:
//! - Safe config updates with automatic backup
//! - Validation before applying changes
//! - Health monitoring after config changes
//! - Automatic rollback on failure
//! - Manual rollback to previous versions

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use super::{
    health_check::{HealthCheckConfig, HealthChecker, HealthStatus},
    rollback::{BackupMetadata, ConfigRollback},
    validator::{ConfigValidator, ValidationResult},
    AgentConfig,
};

/// Configuration manager with rollback and validation
pub struct ConfigManager {
    /// Path to active config file
    config_path: PathBuf,
    /// Current loaded config
    current_config: Arc<RwLock<AgentConfig>>,
    /// Rollback manager
    rollback: ConfigRollback,
    /// Health checker
    health_checker: HealthChecker,
    /// Whether to automatically rollback on health check failure
    auto_rollback_enabled: bool,
}

/// Result of a config update operation
#[derive(Debug)]
pub struct UpdateResult {
    /// Whether the update was successful
    pub success: bool,
    /// Version number of the backup created (if any)
    pub backup_version: Option<u64>,
    /// Validation result
    pub validation: ValidationResult,
    /// Whether a rollback occurred
    pub rolled_back: bool,
    /// Health check status
    pub health_status: HealthStatus,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();

        // Load initial config
        let config = AgentConfig::from_file(&config_path).with_context(|| {
            format!(
                "Failed to load initial config from {}",
                config_path.display()
            )
        })?;

        let rollback = ConfigRollback::new(&config_path)?;

        let health_checker = HealthChecker::new(HealthCheckConfig::default());

        Ok(Self {
            config_path,
            current_config: Arc::new(RwLock::new(config)),
            rollback,
            health_checker,
            auto_rollback_enabled: true,
        })
    }

    /// Create with custom health check configuration
    pub fn with_health_config(
        config_path: impl AsRef<Path>,
        health_config: HealthCheckConfig,
    ) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();

        let config = AgentConfig::from_file(&config_path).with_context(|| {
            format!(
                "Failed to load initial config from {}",
                config_path.display()
            )
        })?;

        let rollback = ConfigRollback::new(&config_path)?;
        let health_checker = HealthChecker::new(health_config);

        Ok(Self {
            config_path,
            current_config: Arc::new(RwLock::new(config)),
            rollback,
            health_checker,
            auto_rollback_enabled: true,
        })
    }

    /// Get current config (read-only clone)
    pub async fn get_config(&self) -> AgentConfig {
        let config = self.current_config.read().await;
        config.clone()
    }

    /// Get health checker for external monitoring
    pub fn health_checker(&self) -> &HealthChecker {
        &self.health_checker
    }

    /// Enable or disable automatic rollback
    pub fn set_auto_rollback(&mut self, enabled: bool) {
        self.auto_rollback_enabled = enabled;
        info!(enabled = enabled, "Automatic rollback set");
    }

    /// Validate a config file without applying it
    pub fn validate_file(&self, path: &Path) -> Result<ValidationResult> {
        // Parse TOML
        let config = ConfigValidator::validate_toml_file(path)?;

        // Validate config structure and values
        let mut result = ConfigValidator::validate_config(&config);

        // Optionally validate YARA rules if enabled
        if config.yara_enabled {
            let yara_dir = Self::get_yara_rules_dir();
            if yara_dir.exists() {
                match ConfigValidator::validate_yara_rules(&yara_dir) {
                    Ok(yara_result) => result.merge(yara_result),
                    Err(e) => {
                        result.warning("yara", format!("YARA validation error: {}", e));
                    }
                }
            }
        }

        // Validate Sigma rules if local analysis is enabled
        if config.local_analysis_enabled {
            let sigma_dir = Self::get_sigma_rules_dir();
            if sigma_dir.exists() {
                match ConfigValidator::validate_sigma_rules(&sigma_dir) {
                    Ok(sigma_result) => result.merge(sigma_result),
                    Err(e) => {
                        result.warning("sigma", format!("Sigma validation error: {}", e));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Validate TOML string
    pub fn validate_string(&self, toml_content: &str) -> Result<ValidationResult> {
        // Parse TOML
        let config = ConfigValidator::validate_toml_string(toml_content)?;

        // Validate config structure and values
        Ok(ConfigValidator::validate_config(&config))
    }

    /// Apply a new configuration from a file
    ///
    /// Steps:
    /// 1. Validate new config
    /// 2. Create backup of current config
    /// 3. Apply new config
    /// 4. Run health check
    /// 5. Rollback if health check fails (if auto_rollback is enabled)
    pub async fn apply_config_file(
        &mut self,
        new_config_path: &Path,
        source: &str,
        triggered_by: Option<String>,
    ) -> Result<UpdateResult> {
        info!(
            path = %new_config_path.display(),
            source = %source,
            "Applying new configuration"
        );

        // Step 1: Validate new config
        let validation = self.validate_file(new_config_path)?;

        if !validation.is_valid() {
            error!(
                errors = validation.errors.len(),
                "Configuration validation failed"
            );
            for err in &validation.errors {
                error!(field = %err.field, message = %err.message, "Validation error");
            }

            return Ok(UpdateResult {
                success: false,
                backup_version: None,
                validation,
                rolled_back: false,
                health_status: HealthStatus::Pending,
            });
        }

        // Log warnings
        for warn in &validation.warnings {
            warn!(field = %warn.field, message = %warn.message, "Validation warning");
        }

        // Step 2: Create backup
        let backup_version = self.rollback.create_backup(
            Some(format!("pre-update from {}", source)),
            source,
            triggered_by,
        )?;

        info!(version = backup_version, "Config backup created");

        // Step 3: Apply new config
        std::fs::copy(new_config_path, &self.config_path).with_context(|| {
            format!(
                "Failed to copy new config to {}",
                self.config_path.display()
            )
        })?;

        // Reload config into memory
        match AgentConfig::from_file(&self.config_path) {
            Ok(new_config) => {
                let mut current = self.current_config.write().await;
                *current = new_config;
                drop(current);
                info!("New configuration loaded into memory");
            }
            Err(e) => {
                error!(error = %e, "Failed to load new config, rolling back");
                self.rollback.restore_version(backup_version)?;
                return Ok(UpdateResult {
                    success: false,
                    backup_version: Some(backup_version),
                    validation,
                    rolled_back: true,
                    health_status: HealthStatus::Unhealthy,
                });
            }
        }

        // Step 4: Reset and run health check
        self.health_checker.reset().await;

        let health_check_handle = {
            let checker = self.health_checker.clone();
            tokio::spawn(async move { checker.run_health_check().await })
        };

        let health_passed = match health_check_handle.await {
            Ok(Ok(passed)) => passed,
            Ok(Err(e)) => {
                error!(error = %e, "Health check error");
                false
            }
            Err(e) => {
                error!(error = %e, "Health check task panicked");
                false
            }
        };

        let health_status = self.health_checker.get_status().await;

        // Step 5: Rollback if health check failed
        if !health_passed && self.auto_rollback_enabled {
            error!("Health check failed, rolling back to previous config");

            if let Some(reason) = self.health_checker.get_failure_reason().await {
                error!(reason = %reason, "Health check failure reason");
            }

            // Restore previous version
            self.rollback.restore_version(backup_version)?;

            // Reload old config
            let old_config = AgentConfig::from_file(&self.config_path)?;
            let mut current = self.current_config.write().await;
            *current = old_config;

            error!(version = backup_version, "Config rolled back");

            return Ok(UpdateResult {
                success: false,
                backup_version: Some(backup_version),
                validation,
                rolled_back: true,
                health_status,
            });
        }

        info!("Configuration successfully applied");

        Ok(UpdateResult {
            success: true,
            backup_version: Some(backup_version),
            validation,
            rolled_back: false,
            health_status,
        })
    }

    /// Apply config from TOML string
    pub async fn apply_config_string(
        &mut self,
        toml_content: &str,
        source: &str,
        triggered_by: Option<String>,
    ) -> Result<UpdateResult> {
        // Write to a temporary file first
        let temp_path = self.config_path.with_extension("tmp");

        std::fs::write(&temp_path, toml_content)
            .context("Failed to write temporary config file")?;

        // Apply using the file-based method
        let result = self
            .apply_config_file(&temp_path, source, triggered_by)
            .await;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path);

        result
    }

    /// List all available backup versions
    pub fn list_backups(&self) -> Result<Vec<BackupMetadata>> {
        self.rollback.list_backups()
    }

    /// Manually restore a specific backup version
    pub async fn restore_backup(&mut self, version: u64) -> Result<()> {
        info!(version = version, "Manually restoring config backup");

        // Create a backup of current state first
        let _ = self.rollback.create_backup(
            Some(format!("pre-manual-restore to v{}", version)),
            "manual-restore",
            None,
        )?;

        // Restore the requested version
        self.rollback.restore_version(version)?;

        // Reload config
        let config = AgentConfig::from_file(&self.config_path)?;
        let mut current = self.current_config.write().await;
        *current = config;

        info!(version = version, "Config backup restored");

        Ok(())
    }

    /// Get diff between two backup versions
    pub fn diff_backups(&self, version1: u64, version2: Option<u64>) -> Result<String> {
        self.rollback.diff_versions(version1, version2)
    }

    /// Verify integrity of all backups
    pub fn verify_backups(&self) -> Result<Vec<(u64, bool)>> {
        self.rollback.verify_backups()
    }

    /// Get platform-specific YARA rules directory
    fn get_yara_rules_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Tamandua\rules\yara")
        }

        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/rules/yara")
        }

        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/rules/yara")
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./rules/yara")
        }
    }

    /// Get platform-specific Sigma rules directory
    fn get_sigma_rules_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Tamandua\rules\sigma")
        }

        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/rules/sigma")
        }

        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/rules/sigma")
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./rules/sigma")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config(dir: &Path) -> PathBuf {
        let config_path = dir.join("agent.toml");
        let config = AgentConfig::default();
        config.save(&config_path).unwrap();
        config_path
    }

    #[tokio::test]
    async fn test_config_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let manager = ConfigManager::new(&config_path);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_validate_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let manager = ConfigManager::new(&config_path).unwrap();
        let result = manager.validate_file(&config_path).unwrap();

        assert!(result.is_valid());
    }

    #[tokio::test]
    async fn test_get_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let manager = ConfigManager::new(&config_path).unwrap();
        let config = manager.get_config().await;

        assert!(!config.agent_id.is_empty());
    }

    #[tokio::test]
    async fn test_list_backups() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(temp_dir.path());

        let manager = ConfigManager::new(&config_path).unwrap();
        let backups = manager.list_backups().unwrap();

        // Initially no backups
        assert_eq!(backups.len(), 0);
    }
}
