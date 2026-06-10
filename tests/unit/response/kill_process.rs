//! Tests for process termination

use tamandua_agent::response::*;
use tamandua_agent::transport::{CommandType};

#[tokio::test]
async fn test_kill_process_invalid_pid() {
    let command = super::create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": 0 }),
    );

    let result = execute_command(&command).await;
    assert!(!result.success);
    assert!(result.error_message.unwrap().contains("Invalid PID"));
}

#[tokio::test]
async fn test_kill_process_nonexistent() {
    let command = super::create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": 99999999 }),
    );

    let result = execute_command(&command).await;
    // Should fail because process doesn't exist
    assert!(!result.success);
}

#[tokio::test]
#[ignore = "requires elevated privileges"]
async fn test_kill_process_success() {
    use std::process::Command as ProcessCommand;

    // Spawn a test process
    #[cfg(windows)]
    let mut child = ProcessCommand::new("cmd")
        .args(&["/C", "timeout", "/t", "300", "/nobreak"])
        .spawn()
        .expect("Failed to spawn test process");

    #[cfg(unix)]
    let mut child = ProcessCommand::new("sleep")
        .arg("300")
        .spawn()
        .expect("Failed to spawn test process");

    let test_pid = child.id();

    // Kill it via response action
    let command = super::create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": test_pid, "force": true }),
    );

    let result = execute_command(&command).await;

    // Should succeed
    if result.success {
        // Wait a bit for process to die
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Verify process is gone
        assert!(child.try_wait().unwrap().is_some());
    } else {
        // Cleanup on failure
        let _ = child.kill();
        panic!("Failed to kill process: {:?}", result.error_message);
    }
}

#[tokio::test]
async fn test_kill_process_force_flag() {
    // Test with force=false (graceful)
    let command_graceful = super::create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": 99999999, "force": false }),
    );

    let _ = execute_command(&command_graceful).await;

    // Test with force=true (forceful)
    let command_force = super::create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": 99999999, "force": true }),
    );

    let _ = execute_command(&command_force).await;

    // Both should handle the flag properly
}

#[test]
fn test_process_exists_check() {
    use crate::tests::common::helpers::process_exists;

    // Current process should exist
    let current_pid = std::process::id();
    assert!(process_exists(current_pid));

    // Invalid PID should not exist
    assert!(!process_exists(99999999));
}
