//! Integration tests for response actions
//!
//! ⚠️  WARNING: These tests modify OS state and MUST run on disposable VMs ⚠️
//!
//! All tests in this file are #[ignore]d by default and gated behind the
//! `integration_vm` feature flag to prevent accidental execution on dev machines.
//!
//! These tests:
//! - Spawn and kill real processes
//! - Quarantine and restore real files
//! - Install and remove firewall rules
//! - Require elevated privileges (admin/root)
//!
//! To run these tests:
//! ```bash
//! # On a disposable Windows VM (as Administrator)
//! cargo test --test response_actions --features integration_vm -- --ignored
//!
//! # On a disposable Linux VM (as root)
//! sudo cargo test --test response_actions --features integration_vm -- --ignored
//!
//! # On a disposable macOS VM (as root)
//! sudo cargo test --test response_actions --features integration_vm -- --ignored
//! ```
//!
//! DO NOT RUN THESE TESTS ON PRODUCTION SYSTEMS OR DEV MACHINES.

use tamandua_agent::response::*;
use tamandua_agent::transport::{Command, CommandType, CommandResult};

/// Helper to create a test command
fn create_test_command(command_type: CommandType, payload: serde_json::Value) -> Command {
    Command {
        command_id: format!("vm-test-cmd-{}", uuid::Uuid::new_v4()),
        command_type,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        payload,
    }
}

// ============================================================================
// Kill Process Tests
// ============================================================================

#[cfg(feature = "integration_vm")]
#[tokio::test]
#[ignore = "Requires VM: spawns and kills real process"]
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
    println!("Spawned test process with PID: {}", test_pid);

    // Kill it via response action
    let command = create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": test_pid, "force": true }),
    );

    let result = execute_command(&command).await;

    // Should succeed
    assert!(
        result.success,
        "Failed to kill process: {:?}",
        result.error_message
    );

    // Wait for process to die
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify process is gone
    assert!(
        child.try_wait().unwrap().is_some(),
        "Process should be terminated"
    );

    println!("✓ Kill process test passed");
}

#[cfg(feature = "integration_vm")]
#[tokio::test]
#[ignore = "Requires VM: attempts to kill protected process"]
async fn test_kill_process_permission_denied() {
    // Try to kill a protected process (should fail)
    #[cfg(windows)]
    let protected_pid = 4; // System process on Windows

    #[cfg(unix)]
    let protected_pid = 1; // init/systemd on Linux/macOS

    let command = create_test_command(
        CommandType::KillProcess,
        serde_json::json!({ "pid": protected_pid, "force": true }),
    );

    let result = execute_command(&command).await;

    // Should fail with permission denied
    assert!(!result.success, "Should not be able to kill protected process");
    assert!(result.error_message.is_some());

    let error = result.error_message.unwrap().to_lowercase();
    assert!(
        error.contains("access") || error.contains("denied") || error.contains("permission"),
        "Error should mention access/permission denied, got: {}",
        error
    );

    println!("✓ Kill process permission denied test passed");
}

// ============================================================================
// Quarantine File Tests
// ============================================================================

#[cfg(all(feature = "integration_vm", target_os = "windows"))]
#[tokio::test]
#[ignore = "Requires VM: quarantines and deletes real file"]
async fn test_quarantine_file_success() {
    use std::fs;
    use std::io::Write;

    // Create a test file
    let test_file_path = "C:\\ProgramData\\tamandua_test_file.txt";
    let mut file = fs::File::create(test_file_path).expect("Failed to create test file");
    file.write_all(b"This is a test file for quarantine")
        .expect("Failed to write test file");
    drop(file);

    println!("Created test file: {}", test_file_path);

    // Quarantine it
    let command = create_test_command(
        CommandType::QuarantineFile,
        serde_json::json!({ "path": test_file_path }),
    );

    let result = execute_command(&command).await;

    // Should succeed
    assert!(
        result.success,
        "Failed to quarantine file: {:?}",
        result.error_message
    );

    // Verify original file is gone
    assert!(
        !std::path::Path::new(test_file_path).exists(),
        "Original file should be deleted after quarantine"
    );

    println!("✓ Quarantine file test passed");

    // Cleanup: Try to find and delete the quarantined file
    // (In production, this would be done via restore API)
}

#[cfg(all(feature = "integration_vm", target_os = "windows"))]
#[tokio::test]
#[ignore = "Requires VM: attempts to quarantine protected system file"]
async fn test_quarantine_file_permission_denied() {
    // Try to quarantine a protected system file (should fail)
    let protected_file = "C:\\Windows\\System32\\kernel32.dll";

    let command = create_test_command(
        CommandType::QuarantineFile,
        serde_json::json!({ "path": protected_file }),
    );

    let result = execute_command(&command).await;

    // Should fail with permission denied
    assert!(
        !result.success,
        "Should not be able to quarantine protected system file"
    );
    assert!(result.error_message.is_some());

    println!("✓ Quarantine permission denied test passed");
}

// ============================================================================
// Network Isolation Tests (Windows)
// ============================================================================

#[cfg(all(feature = "integration_vm", target_os = "windows"))]
#[tokio::test]
#[ignore = "Requires VM: installs WFP firewall rules"]
async fn test_network_isolation_success_windows() {
    // Isolate network (allow only server)
    let command = create_test_command(
        CommandType::IsolateNetwork,
        serde_json::json!({
            "allowed_ips": ["127.0.0.1"],
            "server_url": "wss://127.0.0.1:4000/socket/agent"
        }),
    );

    let result = execute_command(&command).await;

    // Should succeed
    assert!(
        result.success,
        "Failed to isolate network: {:?}",
        result.error_message
    );

    println!("✓ Network isolation (Windows WFP) test passed");

    // Cleanup: Unisolate
    let unisolate_cmd = create_test_command(CommandType::UnisolateNetwork, serde_json::json!({}));

    let unisolate_result = execute_command(&unisolate_cmd).await;
    assert!(
        unisolate_result.success,
        "Failed to unisolate: {:?}",
        unisolate_result.error_message
    );

    println!("✓ Network unisolation (Windows WFP) test passed");
}

// ============================================================================
// Network Isolation Tests (Linux)
// ============================================================================

#[cfg(all(feature = "integration_vm", target_os = "linux"))]
#[tokio::test]
#[ignore = "Requires VM: installs iptables/nftables rules"]
async fn test_network_isolation_success_linux() {
    // Isolate network (allow only server)
    let command = create_test_command(
        CommandType::IsolateNetwork,
        serde_json::json!({
            "allowed_ips": ["127.0.0.1"],
            "server_url": "wss://127.0.0.1:4000/socket/agent"
        }),
    );

    let result = execute_command(&command).await;

    // Should succeed
    assert!(
        result.success,
        "Failed to isolate network: {:?}",
        result.error_message
    );

    println!("✓ Network isolation (Linux) test passed");

    // Cleanup: Unisolate
    let unisolate_cmd = create_test_command(CommandType::UnisolateNetwork, serde_json::json!({}));

    let unisolate_result = execute_command(&unisolate_cmd).await;
    assert!(
        unisolate_result.success,
        "Failed to unisolate: {:?}",
        unisolate_result.error_message
    );

    println!("✓ Network unisolation (Linux) test passed");
}

// ============================================================================
// Network Isolation Tests (macOS)
// ============================================================================

#[cfg(all(feature = "integration_vm", target_os = "macos"))]
#[tokio::test]
#[ignore = "Requires VM: installs pfctl rules"]
async fn test_network_isolation_success_macos() {
    // Isolate network (allow only server)
    let command = create_test_command(
        CommandType::IsolateNetwork,
        serde_json::json!({
            "allowed_ips": ["127.0.0.1"],
            "server_url": "wss://127.0.0.1:4000/socket/agent"
        }),
    );

    let result = execute_command(&command).await;

    // Should succeed
    assert!(
        result.success,
        "Failed to isolate network: {:?}",
        result.error_message
    );

    println!("✓ Network isolation (macOS pfctl) test passed");

    // Cleanup: Unisolate
    let unisolate_cmd = create_test_command(CommandType::UnisolateNetwork, serde_json::json!({}));

    let unisolate_result = execute_command(&unisolate_cmd).await;
    assert!(
        unisolate_result.success,
        "Failed to unisolate: {:?}",
        unisolate_result.error_message
    );

    println!("✓ Network unisolation (macOS pfctl) test passed");
}

// ============================================================================
// Auto-Rollback Tests
// ============================================================================

#[cfg(feature = "integration_vm")]
#[tokio::test]
#[ignore = "Requires VM: tests auto-rollback on server unreachable"]
async fn test_network_isolation_auto_rollback() {
    // Isolate with invalid server IP (should trigger auto-rollback)
    let command = create_test_command(
        CommandType::IsolateNetwork,
        serde_json::json!({
            "allowed_ips": [],
            "server_url": "wss://192.0.2.1:4000/socket/agent" // TEST-NET-1 (unreachable)
        }),
    );

    let result = execute_command(&command).await;

    // Should fail with auto-rollback message
    assert!(
        !result.success || result.error_message.is_some(),
        "Should fail or warn when server unreachable"
    );

    if let Some(error) = result.error_message {
        assert!(
            error.contains("Auto-rollback") || error.contains("unreachable"),
            "Error should mention auto-rollback or unreachable, got: {}",
            error
        );
    }

    println!("✓ Network isolation auto-rollback test passed");
}

// ============================================================================
// Stubs for non-VM builds
// ============================================================================

#[cfg(not(feature = "integration_vm"))]
#[test]
fn integration_vm_tests_disabled() {
    println!("Integration VM tests are disabled. Enable with --features integration_vm");
}
