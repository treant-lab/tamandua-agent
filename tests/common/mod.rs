//! Common test utilities and helpers
//!
//! This module provides shared test infrastructure including:
//! - Mock WebSocket server for integration testing
//! - Test data generators
//! - Helper functions for setting up test environments
//! - Platform-specific test utilities

pub mod mock_server;
pub mod test_data;
pub mod helpers;

pub use mock_server::*;
pub use test_data::*;
pub use helpers::*;

use std::path::PathBuf;
use tempfile::TempDir;

/// Test environment for isolated testing
pub struct TestEnvironment {
    /// Temporary directory for test files
    pub temp_dir: TempDir,
    /// Test config directory
    pub config_dir: PathBuf,
    /// Test data directory
    pub data_dir: PathBuf,
}

impl TestEnvironment {
    /// Create a new test environment
    pub fn new() -> std::io::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let config_dir = temp_dir.path().join("config");
        let data_dir = temp_dir.path().join("data");

        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(&data_dir)?;

        Ok(Self {
            temp_dir,
            config_dir,
            data_dir,
        })
    }

    /// Get path to temp directory
    pub fn temp_path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }

    /// Create a test file with content
    pub fn create_file(&self, name: &str, content: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.data_dir.join(name);
        std::fs::write(&path, content)?;
        Ok(path)
    }

    /// Create a test executable
    #[cfg(target_os = "windows")]
    pub fn create_executable(&self, name: &str) -> std::io::Result<PathBuf> {
        let path = self.data_dir.join(format!("{}.exe", name));
        // Create minimal PE executable for testing
        let pe_header = include_bytes!("../../test_data/minimal.exe");
        std::fs::write(&path, pe_header)?;
        Ok(path)
    }

    #[cfg(unix)]
    pub fn create_executable(&self, name: &str) -> std::io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let path = self.data_dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\necho test\n")?;

        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)?;

        Ok(path)
    }
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self::new().expect("Failed to create test environment")
    }
}

/// Wait for a condition with timeout
pub async fn wait_for<F>(mut condition: F, timeout: std::time::Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    false
}

/// Create a test process event
pub fn create_test_process_event(pid: u32, name: &str) -> tamandua_agent::collectors::TelemetryEvent {
    tamandua_agent::collectors::TelemetryEvent::new(
        tamandua_agent::collectors::EventType::ProcessCreate,
        tamandua_agent::collectors::Severity::Info,
        tamandua_agent::collectors::EventPayload::Process(
            tamandua_agent::collectors::ProcessEvent {
                pid,
                ppid: 1,
                name: name.to_string(),
                path: format!("/usr/bin/{}", name),
                cmdline: name.to_string(),
                user: "test".to_string(),
                sha256: vec![0u8; 32],
                entropy: 5.5,
                is_elevated: false,
                parent_name: Some("init".to_string()),
                parent_path: Some("/sbin/init".to_string()),
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            },
        ),
    )
}

/// Create a test file event
pub fn create_test_file_event(path: &str) -> tamandua_agent::collectors::TelemetryEvent {
    tamandua_agent::collectors::TelemetryEvent::new(
        tamandua_agent::collectors::EventType::FileCreate,
        tamandua_agent::collectors::Severity::Info,
        tamandua_agent::collectors::EventPayload::File(
            tamandua_agent::collectors::FileEvent {
                path: path.to_string(),
                old_path: None,
                operation: "create".to_string(),
                pid: 1234,
                process_name: "test".to_string(),
                sha256: vec![0u8; 32],
                size: 1024,
                entropy: 5.0,
                file_type: "text/plain".to_string(),
            },
        ),
    )
}

/// Create a test network event
pub fn create_test_network_event() -> tamandua_agent::collectors::TelemetryEvent {
    tamandua_agent::collectors::TelemetryEvent::new(
        tamandua_agent::collectors::EventType::NetworkConnect,
        tamandua_agent::collectors::Severity::Info,
        tamandua_agent::collectors::EventPayload::Network(
            tamandua_agent::collectors::NetworkEvent {
                pid: 1234,
                process_name: "test".to_string(),
                local_ip: "192.168.1.100".to_string(),
                local_port: 50000,
                remote_ip: "8.8.8.8".to_string(),
                remote_port: 443,
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                state: Some("ESTABLISHED".to_string()),
                bytes_sent: 0,
                bytes_received: 0,
                ..Default::default()
            },
        ),
    )
}
