//! Integration tests for config rollback system

use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tamandua_agent::config::{
    health_check::{HealthCheckConfig, HealthChecker},
    rollback::ConfigRollback,
    validator::ConfigValidator,
    AgentConfig,
};
use tempfile::TempDir;

/// Helper to create a test config file
fn create_test_config(dir: &std::path::Path, server_url: &str) -> PathBuf {
    let config_path = dir.join("agent.toml");
    let mut config = AgentConfig::default();
    config.server_url = server_url.to_string();
    config.heartbeat_interval_seconds = 30;
    config.save(&config_path).unwrap();
    config_path
}

#[test]
fn test_backup_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://test1:4000");

    let mut rollback = ConfigRollback::new(&config_path)?;
    // Override backup dir for testing
    rollback.backup_dir = temp_dir.path().join("backups");
    rollback.metadata_path = rollback.backup_dir.join("metadata.json");
    fs::create_dir_all(&rollback.backup_dir)?;

    // Create first backup
    let v1 = rollback.create_backup(
        Some("test backup 1".to_string()),
        "test",
        Some("admin".to_string()),
    )?;

    assert_eq!(v1, 1);

    // Verify backup file exists
    let backup_path = rollback.backup_dir.join("config_v0001.toml");
    assert!(backup_path.exists());

    // Modify config
    fs::write(&config_path, "server_url = \"wss://test2:4000\"\n")?;

    // Create second backup
    let v2 = rollback.create_backup(Some("test backup 2".to_string()), "test", None)?;

    assert_eq!(v2, 2);

    // List backups
    let backups = rollback.list_backups()?;
    assert_eq!(backups.len(), 2);

    Ok(())
}

#[test]
fn test_backup_restoration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://original:4000");

    let mut rollback = ConfigRollback::new(&config_path)?;
    rollback.backup_dir = temp_dir.path().join("backups");
    rollback.metadata_path = rollback.backup_dir.join("metadata.json");
    fs::create_dir_all(&rollback.backup_dir)?;

    // Create backup
    let v1 = rollback.create_backup(None, "test", None)?;

    // Modify config
    fs::write(&config_path, "server_url = \"wss://modified:4000\"\n")?;

    // Verify config changed
    let content = fs::read_to_string(&config_path)?;
    assert!(content.contains("modified"));

    // Restore original
    rollback.restore_version(v1)?;

    // Verify restored
    let content = fs::read_to_string(&config_path)?;
    assert!(content.contains("original"));

    Ok(())
}

#[test]
fn test_max_backups_limit() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://test:4000");

    let mut rollback = ConfigRollback::new(&config_path)?;
    rollback.backup_dir = temp_dir.path().join("backups");
    rollback.metadata_path = rollback.backup_dir.join("metadata.json");
    fs::create_dir_all(&rollback.backup_dir)?;

    // Create 15 backups (more than MAX_BACKUPS=10)
    for i in 1..=15 {
        fs::write(&config_path, format!("version = {}\n", i))?;
        rollback.create_backup(None, "test", None)?;
    }

    let backups = rollback.list_backups()?;
    assert!(backups.len() <= 10);

    // Verify oldest backups were removed
    assert!(backups.iter().all(|b| b.version > 5));

    Ok(())
}

#[test]
fn test_validation_valid_config() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://localhost:4000");

    let result = ConfigValidator::validate_toml_file(&config_path)?;
    let validation = ConfigValidator::validate_config(&result);

    assert!(validation.is_valid());
    assert_eq!(validation.errors.len(), 0);

    Ok(())
}

#[test]
fn test_validation_invalid_server_url() {
    let mut config = AgentConfig::default();
    config.server_url = "http://invalid".to_string(); // Should be ws:// or wss://

    let validation = ConfigValidator::validate_config(&config);

    assert!(!validation.is_valid());
    assert!(validation.errors.iter().any(|e| e.field == "server_url"));
}

#[test]
fn test_validation_invalid_intervals() {
    let mut config = AgentConfig::default();
    config.heartbeat_interval_seconds = 0; // Invalid

    let validation = ConfigValidator::validate_config(&config);

    assert!(!validation.is_valid());
    assert!(validation
        .errors
        .iter()
        .any(|e| e.field == "heartbeat_interval_seconds"));
}

#[test]
fn test_validation_invalid_toml() {
    let invalid_toml = "this is not valid toml [[[";

    let result = ConfigValidator::validate_toml_string(invalid_toml);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_health_check_success() -> Result<()> {
    // Disable resource thresholds so a busy test runner (high CPU / memory)
    // cannot spuriously fail this test; we are exercising the connection
    // state machine, not real resource monitoring.
    let config = HealthCheckConfig {
        delay: Duration::from_millis(100),
        timeout: Duration::from_secs(2),
        memory_threshold_mb: u64::MAX,
        cpu_threshold_percent: f32::INFINITY,
        ..Default::default()
    };

    let checker = HealthChecker::new(config);

    // Mark the connection healthy BEFORE spawning the check. The check's
    // own configured delay (100 ms) provides the scheduling window the
    // test used to depend on, removing the spawn-vs-mark race that caused
    // the previous flake under parallel `cargo test` load.
    checker.mark_connection_healthy().await;

    let checker_clone = checker.clone();
    let check_handle = tokio::spawn(async move { checker_clone.run_health_check().await });

    // Health check should pass
    let result = check_handle.await??;
    assert!(result);

    Ok(())
}

#[tokio::test]
async fn test_health_check_timeout() -> Result<()> {
    let config = HealthCheckConfig {
        delay: Duration::from_millis(50),
        timeout: Duration::from_millis(300),
        ..Default::default()
    };

    let checker = HealthChecker::new(config);

    // Run without marking connection healthy
    let result = checker.run_health_check().await?;

    // Should timeout
    assert!(!result);

    Ok(())
}

#[tokio::test]
async fn test_health_check_collector_panic() -> Result<()> {
    let checker = HealthChecker::new(HealthCheckConfig::default());

    checker
        .report_collector_panic("test_collector".to_string())
        .await;

    let binding = checker.state();
    let state = binding.read().await;
    assert!(!state.collectors_healthy);

    Ok(())
}

#[test]
fn test_checksum_verification() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://test:4000");

    let mut rollback = ConfigRollback::new(&config_path)?;
    rollback.backup_dir = temp_dir.path().join("backups");
    rollback.metadata_path = rollback.backup_dir.join("metadata.json");
    fs::create_dir_all(&rollback.backup_dir)?;

    let version = rollback.create_backup(None, "test", None)?;

    // All backups should be valid initially
    let results = rollback.verify_backups()?;
    assert_eq!(results.len(), 1);
    assert!(results[0].1);

    // Corrupt the backup file
    let backup_path = rollback
        .backup_dir
        .join(format!("config_v{:04}.toml", version));
    fs::write(&backup_path, "corrupted content")?;

    // Verification should fail
    let results = rollback.verify_backups()?;
    assert_eq!(results.len(), 1);
    assert!(!results[0].1);

    Ok(())
}

#[test]
fn test_identical_config_no_backup() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://test:4000");

    let mut rollback = ConfigRollback::new(&config_path)?;
    rollback.backup_dir = temp_dir.path().join("backups");
    rollback.metadata_path = rollback.backup_dir.join("metadata.json");
    fs::create_dir_all(&rollback.backup_dir)?;

    let v1 = rollback.create_backup(None, "test", None)?;
    let v2 = rollback.create_backup(None, "test", None)?;

    // Should return same version if content unchanged
    assert_eq!(v1, v2);

    let backups = rollback.list_backups()?;
    assert_eq!(backups.len(), 1);

    Ok(())
}

#[test]
fn test_diff_versions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), "wss://version1:4000");

    let mut rollback = ConfigRollback::new(&config_path)?;
    rollback.backup_dir = temp_dir.path().join("backups");
    rollback.metadata_path = rollback.backup_dir.join("metadata.json");
    fs::create_dir_all(&rollback.backup_dir)?;

    let v1 = rollback.create_backup(None, "test", None)?;

    // Modify config
    fs::write(&config_path, "server_url = \"wss://version2:4000\"\n")?;

    let v2 = rollback.create_backup(None, "test", None)?;

    // Get diff
    let diff = rollback.diff_versions(v1, Some(v2))?;

    assert!(diff.contains("version1"));
    assert!(diff.contains("version2"));

    Ok(())
}
