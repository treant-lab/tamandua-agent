//! Integration tests for Linux Application Control
//!
//! These tests verify AppArmor and SELinux integration.
//! Some tests require root privileges and will be skipped if not run as root.

#![cfg(target_os = "linux")]

use tamandua_agent::response::app_control::app_control_linux::{
    EnforcementMode, LinuxAppControl, LsmBackend,
};

/// Check if running as root
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_lsm_detection() {
    let control = LinuxAppControl::new();
    assert!(control.is_ok(), "Should be able to detect LSM");

    let control = control.unwrap();
    let backend = control.backend();

    println!("Detected LSM backend: {:?}", backend);

    // Should detect at least one backend or None
    assert!(
        backend == LsmBackend::AppArmor
            || backend == LsmBackend::SELinux
            || backend == LsmBackend::None
    );
}

#[test]
fn test_mode_setting() {
    let mut control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping mode test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping mode test - requires root");
        return;
    }

    // Should be able to set mode
    let result = control.set_mode(EnforcementMode::Audit);
    assert!(result.is_ok(), "Should be able to set audit mode");

    assert_eq!(control.mode(), EnforcementMode::Audit);
}

#[test]
fn test_allow_application() {
    let mut control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping allow test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping allow test - requires root");
        return;
    }

    // Try to allow a system binary
    let test_binary = "/bin/ls";
    let result = control.allow_application(test_binary, None);

    assert!(result.is_ok(), "Should be able to allow application");

    let rule_id = result.unwrap();
    println!("Created allow rule: {}", rule_id);

    // Verify rule exists
    let rules = control.list_rules();
    assert!(rules.iter().any(|r| r.id == rule_id));

    // Clean up
    let _ = control.remove_rule(&rule_id);
}

#[test]
fn test_block_application() {
    let mut control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping block test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping block test - requires root");
        return;
    }

    // Use a non-critical binary for testing
    let test_binary = "/bin/date";
    let result = control.block_application(test_binary, None);

    assert!(result.is_ok(), "Should be able to block application");

    let rule_id = result.unwrap();
    println!("Created block rule: {}", rule_id);

    // Verify rule exists
    let rules = control.list_rules();
    assert!(rules.iter().any(|r| r.id == rule_id && !r.allow));

    // Clean up
    let _ = control.remove_rule(&rule_id);
}

#[test]
fn test_enable_disable_rule() {
    let mut control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping enable/disable test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping enable/disable test - requires root");
        return;
    }

    // Create a test rule
    let test_binary = "/bin/echo";
    let rule_id = control
        .allow_application(test_binary, None)
        .expect("Failed to create test rule");

    // Disable the rule
    let result = control.disable_rule(&rule_id);
    assert!(result.is_ok(), "Should be able to disable rule");

    // Verify it's disabled
    let rules = control.list_rules();
    let rule = rules.iter().find(|r| r.id == rule_id).unwrap();
    assert!(!rule.enabled, "Rule should be disabled");

    // Re-enable the rule
    let result = control.enable_rule(&rule_id);
    assert!(result.is_ok(), "Should be able to enable rule");

    // Verify it's enabled
    let rules = control.list_rules();
    let rule = rules.iter().find(|r| r.id == rule_id).unwrap();
    assert!(rule.enabled, "Rule should be enabled");

    // Clean up
    let _ = control.remove_rule(&rule_id);
}

#[test]
fn test_remove_rule() {
    let mut control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping remove test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping remove test - requires root");
        return;
    }

    // Create a test rule
    let test_binary = "/bin/cat";
    let rule_id = control
        .allow_application(test_binary, None)
        .expect("Failed to create test rule");

    // Verify rule exists
    let rules = control.list_rules();
    assert!(rules.iter().any(|r| r.id == rule_id));

    // Remove the rule
    let result = control.remove_rule(&rule_id);
    assert!(result.is_ok(), "Should be able to remove rule");
    assert!(result.unwrap(), "Rule should have been removed");

    // Verify rule is gone
    let rules = control.list_rules();
    assert!(!rules.iter().any(|r| r.id == rule_id));
}

#[test]
fn test_get_status() {
    let control = LinuxAppControl::new().expect("Failed to create control");

    let status = control.get_status();
    println!("Status: {}", serde_json::to_string_pretty(&status).unwrap());

    // Verify expected fields
    assert!(status.get("backend").is_some());
    assert!(status.get("mode").is_some());
    assert!(status.get("total_rules").is_some());
    assert!(status.get("enabled_rules").is_some());
}

#[test]
fn test_get_stats() {
    let control = LinuxAppControl::new().expect("Failed to create control");

    let stats = control.get_stats();
    println!("Stats: {:?}", stats);

    // Should have valid stats
    assert_eq!(stats.total_rules, 0); // Initially empty
}

#[test]
#[ignore] // This test reads actual logs and may require specific setup
fn test_query_audit_log() {
    let control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping audit log test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping audit log test - requires root");
        return;
    }

    // Query recent audit events
    let result = control.query_audit_log(None);

    if let Ok(events) = result {
        println!("Found {} audit events", events.len());

        for event in events.iter().take(5) {
            println!("Event: {}", serde_json::to_string_pretty(event).unwrap());
        }
    } else {
        println!("Audit log query failed (may not be available)");
    }
}

#[test]
fn test_multiple_rules() {
    let mut control = LinuxAppControl::new().expect("Failed to create control");

    if control.backend() == LsmBackend::None {
        println!("Skipping multiple rules test - no LSM backend available");
        return;
    }

    if !is_root() {
        println!("Skipping multiple rules test - requires root");
        return;
    }

    // Create multiple rules
    let binaries = vec!["/bin/true", "/bin/false", "/bin/yes"];
    let mut rule_ids = Vec::new();

    for binary in &binaries {
        if let Ok(rule_id) = control.allow_application(binary, None) {
            rule_ids.push(rule_id);
        }
    }

    // Verify all rules exist
    let rules = control.list_rules();
    assert_eq!(rules.len(), rule_ids.len());

    // Clean up
    for rule_id in rule_ids {
        let _ = control.remove_rule(&rule_id);
    }

    // Verify cleanup
    let rules = control.list_rules();
    assert_eq!(rules.len(), 0);
}
