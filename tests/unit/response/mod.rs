//! Unit tests for response actions
//!
//! Tests all response capabilities:
//! - Process termination
//! - File quarantine
//! - Network isolation
//! - Live response actions
//! - VSS rollback
//! - Forensic collection

mod kill_process;
mod quarantine;
mod network_isolation;
mod live_response;
mod vss_rollback;

// New validation tests (safe to run on dev machines)
mod response_timeout_test;
mod quarantine_rollback_test;
mod isolation_state_machine_test;

use tamandua_agent::response::*;
use tamandua_agent::transport::{Command, CommandType, CommandResult};

/// Helper to create a test command
fn create_test_command(command_type: CommandType, payload: serde_json::Value) -> Command {
    Command {
        command_id: uuid::Uuid::new_v4().to_string(),
        command_type,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        payload,
    }
}

#[tokio::test]
async fn test_execute_invalid_command() {
    let command = create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": 0 }),
    );

    let result = execute_command(&command).await;
    assert!(!result.success);
    assert!(result.error_message.is_some());
}

#[tokio::test]
async fn test_command_result_serialization() {
    let result = CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({ "pid": 1234 })),
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("true"));
    assert!(json.contains("1234"));
}
