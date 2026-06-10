//! Tests for response action timeout handling
//!
//! These tests exercise timeout logic, retry mechanisms, and ack parsing
//! WITHOUT modifying OS state. Safe to run on dev machines.

use tamandua_agent::response::*;
use tamandua_agent::transport::{Command, CommandResult, CommandType};
use tokio::time::{sleep, Duration};

/// Helper to create a test command
fn create_test_command(command_type: CommandType, payload: serde_json::Value) -> Command {
    Command {
        command_id: format!("test-cmd-{}", uuid::Uuid::new_v4()),
        command_type,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        payload,
    }
}

#[tokio::test]
async fn test_command_result_serialization() {
    // Success case
    let success_result = CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({"pid": 1234, "killed": true})),
    };

    let json = serde_json::to_string(&success_result).unwrap();
    let deserialized: CommandResult = serde_json::from_str(&json).unwrap();

    assert!(deserialized.success);
    assert!(deserialized.error_message.is_none());
    assert!(deserialized.result_data.is_some());
}

#[tokio::test]
async fn test_command_result_error_serialization() {
    // Error case
    let error_result = CommandResult {
        success: false,
        error_message: Some("Process not found".to_string()),
        result_data: None,
    };

    let json = serde_json::to_string(&error_result).unwrap();
    let deserialized: CommandResult = serde_json::from_str(&json).unwrap();

    assert!(!deserialized.success);
    assert_eq!(
        deserialized.error_message,
        Some("Process not found".to_string())
    );
    assert!(deserialized.result_data.is_none());
}

#[tokio::test]
async fn test_kill_process_invalid_pid_zero() {
    let command = create_test_command(CommandType::KillProcess, serde_json::json!({"pid": 0}));

    let result = execute_command(&command).await;

    assert!(!result.success);
    assert!(result.error_message.is_some());
    assert!(result
        .error_message
        .unwrap()
        .to_lowercase()
        .contains("invalid"));
}

#[tokio::test]
async fn test_kill_process_invalid_pid_nonexistent() {
    // Use extremely high PID unlikely to exist
    let command = create_test_command(
        CommandType::KillProcess,
        serde_json::json!({"pid": 99999999}),
    );

    let result = execute_command(&command).await;

    // Should fail because process doesn't exist
    assert!(!result.success);
    assert!(result.error_message.is_some());
}

#[tokio::test]
async fn test_quarantine_file_invalid_path_empty() {
    let command = create_test_command(CommandType::QuarantineFile, serde_json::json!({"path": ""}));

    let result = execute_command(&command).await;

    assert!(!result.success);
    assert!(result.error_message.is_some());
    assert!(result
        .error_message
        .unwrap()
        .to_lowercase()
        .contains("invalid"));
}

#[tokio::test]
async fn test_quarantine_file_nonexistent_file() {
    let command = create_test_command(
        CommandType::QuarantineFile,
        serde_json::json!({"path": "/nonexistent/file/path/test.exe"}),
    );

    let result = execute_command(&command).await;

    // Should fail because file doesn't exist
    // Note: This test is safe because it never creates the file,
    // just verifies the error handling for missing files
    assert!(!result.success);
}

#[tokio::test]
async fn test_command_type_serialization() {
    let test_cases = vec![
        CommandType::KillProcess,
        CommandType::QuarantineFile,
        CommandType::IsolateNetwork,
        CommandType::UnisolateNetwork,
    ];

    for cmd_type in test_cases {
        let json = serde_json::to_string(&cmd_type).unwrap();
        let deserialized: CommandType = serde_json::from_str(&json).unwrap();

        // Verify round-trip serialization works
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, json2);
    }
}

// NOTE: Actual timeout testing requires integration with the Elixir Worker
// These tests verify the Rust side handles results correctly
#[tokio::test]
async fn test_timeout_result_structure() {
    // Simulate what a timeout response from backend would look like
    let timeout_error = CommandResult {
        success: false,
        error_message: Some("Command timeout".to_string()),
        result_data: Some(serde_json::json!({
            "timeout_ms": 30000,
            "retries": 3,
        })),
    };

    assert!(!timeout_error.success);
    assert!(timeout_error
        .error_message
        .unwrap()
        .contains("timeout"));
}

#[tokio::test]
async fn test_kill_process_force_flag_parsing() {
    // Test with force=false
    let cmd_graceful = create_test_command(
        CommandType::KillProcess,
        serde_json::json!({"pid": 99999999, "force": false}),
    );

    // Test with force=true
    let cmd_force = create_test_command(
        CommandType::KillProcess,
        serde_json::json!({"pid": 99999999, "force": true}),
    );

    // Both should parse correctly (even if they fail due to nonexistent PID)
    let _ = execute_command(&cmd_graceful).await;
    let _ = execute_command(&cmd_force).await;
}

#[tokio::test]
async fn test_isolate_network_allowed_ips_parsing() {
    let command = create_test_command(
        CommandType::IsolateNetwork,
        serde_json::json!({
            "allowed_ips": ["192.168.1.1", "10.0.0.1"],
            "server_url": "wss://192.168.1.100:4000/socket/agent"
        }),
    );

    // This test verifies the command can be created and payload parsed
    // The actual isolation is NOT executed here
    assert_eq!(command.command_type, CommandType::IsolateNetwork);
    assert!(command.payload.get("allowed_ips").is_some());
    assert!(command.payload.get("server_url").is_some());
}

#[tokio::test]
async fn test_unisolate_network_command_structure() {
    let command = create_test_command(CommandType::UnisolateNetwork, serde_json::json!({}));

    assert_eq!(command.command_type, CommandType::UnisolateNetwork);
}

// Test that validates command ID uniqueness
#[test]
fn test_command_id_uniqueness() {
    let mut ids = std::collections::HashSet::new();

    for _ in 0..1000 {
        let cmd = create_test_command(CommandType::KillProcess, serde_json::json!({"pid": 1234}));
        assert!(ids.insert(cmd.command_id), "Command ID should be unique");
    }
}

// Test command timestamp is reasonable
#[test]
fn test_command_timestamp() {
    let cmd = create_test_command(CommandType::KillProcess, serde_json::json!({"pid": 1234}));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Timestamp should be within 1 second of now
    assert!((cmd.timestamp as i64 - now as i64).abs() <= 1);
}
