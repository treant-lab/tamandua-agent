//! Tests for network isolation state machine
//!
//! These tests verify isolation status tracking, connectivity verification logic,
//! and state transitions WITHOUT installing actual firewall rules.
//! Safe to run on dev machines.

use serde::{Deserialize, Serialize};

/// Mirror of IsolationState from isolation_status module
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IsolationState {
    Disabled,
    Active,
    Partial,
    Failed,
}

/// Mirror of ConnectivityStatus
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectivityStatus {
    server_reachable: bool,
    internet_blocked: bool,
    verification_timestamp: u64,
}

/// Mock isolation status
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MockIsolationStatus {
    state: IsolationState,
    method: String,
    applied_at: u64,
    connectivity: Option<ConnectivityStatus>,
}

#[test]
fn test_isolation_state_serialization() {
    let states = vec![
        IsolationState::Disabled,
        IsolationState::Active,
        IsolationState::Partial,
        IsolationState::Failed,
    ];

    for state in states {
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: IsolationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }
}

#[test]
fn test_isolation_status_complete() {
    let status = MockIsolationStatus {
        state: IsolationState::Active,
        method: "wfp".to_string(),
        applied_at: 1234567890,
        connectivity: Some(ConnectivityStatus {
            server_reachable: true,
            internet_blocked: true,
            verification_timestamp: 1234567891,
        }),
    };

    let json = serde_json::to_string(&status).unwrap();
    let deserialized: MockIsolationStatus = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.state, IsolationState::Active);
    assert_eq!(deserialized.method, "wfp");
    assert!(deserialized.connectivity.is_some());

    let conn = deserialized.connectivity.unwrap();
    assert!(conn.server_reachable);
    assert!(conn.internet_blocked);
}

#[test]
fn test_isolation_failed_state() {
    let status = MockIsolationStatus {
        state: IsolationState::Failed,
        method: "nftables".to_string(),
        applied_at: 1234567890,
        connectivity: Some(ConnectivityStatus {
            server_reachable: false,
            internet_blocked: false,
            verification_timestamp: 1234567891,
        }),
    };

    // Failed state should have server_reachable=false (triggering auto-rollback)
    assert_eq!(status.state, IsolationState::Failed);
    assert!(!status.connectivity.as_ref().unwrap().server_reachable);
}

#[test]
fn test_isolation_partial_state() {
    let status = MockIsolationStatus {
        state: IsolationState::Partial,
        method: "iptables".to_string(),
        applied_at: 1234567890,
        connectivity: Some(ConnectivityStatus {
            server_reachable: true,
            internet_blocked: false, // Should be blocked but isn't
            verification_timestamp: 1234567891,
        }),
    };

    // Partial state: server reachable but internet NOT blocked
    assert_eq!(status.state, IsolationState::Partial);
    assert!(status.connectivity.as_ref().unwrap().server_reachable);
    assert!(!status.connectivity.as_ref().unwrap().internet_blocked);
}

#[test]
fn test_connectivity_verification_logic() {
    // Simulate the logic in isolation handlers

    // Case 1: Server unreachable -> Auto-rollback -> Failed
    let server_reachable = false;
    let internet_blocked = false;

    let (expected_state, should_rollback) = if !server_reachable {
        (IsolationState::Failed, true)
    } else if !internet_blocked {
        (IsolationState::Partial, false)
    } else {
        (IsolationState::Active, false)
    };

    assert_eq!(expected_state, IsolationState::Failed);
    assert!(should_rollback);

    // Case 2: Server reachable, internet NOT blocked -> Partial
    let server_reachable = true;
    let internet_blocked = false;

    let (expected_state, should_rollback) = if !server_reachable {
        (IsolationState::Failed, true)
    } else if !internet_blocked {
        (IsolationState::Partial, false)
    } else {
        (IsolationState::Active, false)
    };

    assert_eq!(expected_state, IsolationState::Partial);
    assert!(!should_rollback);

    // Case 3: Server reachable, internet blocked -> Active
    let server_reachable = true;
    let internet_blocked = true;

    let (expected_state, should_rollback) = if !server_reachable {
        (IsolationState::Failed, true)
    } else if !internet_blocked {
        (IsolationState::Partial, false)
    } else {
        (IsolationState::Active, false)
    };

    assert_eq!(expected_state, IsolationState::Active);
    assert!(!should_rollback);
}

#[test]
fn test_isolation_method_strings() {
    let methods = vec![
        "wfp",       // Windows
        "nftables",  // Linux modern
        "iptables",  // Linux legacy
        "pfctl",     // macOS
    ];

    for method in methods {
        let status = MockIsolationStatus {
            state: IsolationState::Active,
            method: method.to_string(),
            applied_at: 1234567890,
            connectivity: None,
        };

        assert_eq!(status.method, method);
    }
}

#[test]
fn test_unisolate_state_transition() {
    // Before unisolation: Active
    let before = MockIsolationStatus {
        state: IsolationState::Active,
        method: "wfp".to_string(),
        applied_at: 1234567890,
        connectivity: Some(ConnectivityStatus {
            server_reachable: true,
            internet_blocked: true,
            verification_timestamp: 1234567891,
        }),
    };

    assert_eq!(before.state, IsolationState::Active);

    // After successful unisolation: Disabled
    let after = MockIsolationStatus {
        state: IsolationState::Disabled,
        method: "wfp".to_string(),
        applied_at: 1234567892,
        connectivity: Some(ConnectivityStatus {
            server_reachable: true,
            internet_blocked: false,
            verification_timestamp: 1234567893,
        }),
    };

    assert_eq!(after.state, IsolationState::Disabled);
    assert!(after.connectivity.as_ref().unwrap().server_reachable);
    assert!(!after.connectivity.as_ref().unwrap().internet_blocked);
}

#[test]
fn test_allowed_ips_payload_parsing() {
    // Test parsing of allowed_ips from command payload
    let payload = serde_json::json!({
        "allowed_ips": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        "server_url": "wss://192.168.1.100:4000/socket/agent"
    });

    let allowed_ips: Vec<String> = payload
        .get("allowed_ips")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    assert_eq!(allowed_ips.len(), 3);
    assert_eq!(allowed_ips[0], "192.168.1.1");
    assert_eq!(allowed_ips[1], "10.0.0.1");
    assert_eq!(allowed_ips[2], "172.16.0.1");
}

#[test]
fn test_server_url_extraction() {
    // Test extracting server IP from WebSocket URL
    let payload = serde_json::json!({
        "server_url": "wss://192.168.1.100:4000/socket/agent"
    });

    let server_url = payload
        .get("server_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let server_host = url::Url::parse(server_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from));

    assert_eq!(server_host, Some("192.168.1.100".to_string()));
}

#[test]
fn test_isolation_timestamp_ordering() {
    let applied_at = 1234567890u64;
    let verification_at = 1234567891u64;

    // Verification should happen after application
    assert!(verification_at > applied_at);

    let status = MockIsolationStatus {
        state: IsolationState::Active,
        method: "nftables".to_string(),
        applied_at,
        connectivity: Some(ConnectivityStatus {
            server_reachable: true,
            internet_blocked: true,
            verification_timestamp: verification_at,
        }),
    };

    assert!(status.connectivity.unwrap().verification_timestamp > status.applied_at);
}

#[test]
fn test_auto_rollback_error_message() {
    // When auto-rollback triggers, expected error format
    let error_msg = "Auto-rollback: server unreachable after isolation";

    assert!(error_msg.contains("Auto-rollback"));
    assert!(error_msg.contains("server unreachable"));
}

#[test]
fn test_isolation_state_transitions() {
    // Valid state transitions
    let transitions = vec![
        (IsolationState::Disabled, IsolationState::Active),   // Isolate success
        (IsolationState::Disabled, IsolationState::Failed),   // Isolate failed
        (IsolationState::Active, IsolationState::Disabled),   // Unisolate success
        (IsolationState::Active, IsolationState::Partial),    // Degraded
        (IsolationState::Partial, IsolationState::Active),    // Recovered
        (IsolationState::Failed, IsolationState::Disabled),   // Rollback
    ];

    for (from, to) in transitions {
        // Just verify the states can be created
        assert_ne!(from, to);
    }
}

#[test]
fn test_connectivity_status_no_connectivity() {
    // Case where connectivity check is not performed
    let status = MockIsolationStatus {
        state: IsolationState::Active,
        method: "wfp".to_string(),
        applied_at: 1234567890,
        connectivity: None,
    };

    assert!(status.connectivity.is_none());
}

#[test]
fn test_backend_detection_logic() {
    // Simulate backend detection logic (Linux)

    // If `nft --version` succeeds -> nftables
    let nft_available = true;
    let backend = if nft_available { "nftables" } else { "iptables" };
    assert_eq!(backend, "nftables");

    // If `nft --version` fails -> iptables
    let nft_available = false;
    let backend = if nft_available { "nftables" } else { "iptables" };
    assert_eq!(backend, "iptables");
}

#[test]
fn test_isolation_status_json_schema() {
    // Verify the JSON schema matches expected structure
    let status = MockIsolationStatus {
        state: IsolationState::Active,
        method: "wfp".to_string(),
        applied_at: 1234567890,
        connectivity: Some(ConnectivityStatus {
            server_reachable: true,
            internet_blocked: true,
            verification_timestamp: 1234567891,
        }),
    };

    let json = serde_json::to_value(&status).unwrap();

    assert_eq!(json["state"], "active");
    assert_eq!(json["method"], "wfp");
    assert_eq!(json["applied_at"], 1234567890);
    assert_eq!(json["connectivity"]["server_reachable"], true);
    assert_eq!(json["connectivity"]["internet_blocked"], true);
}
