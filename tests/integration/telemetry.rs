//! Telemetry collection and transmission integration tests
//!
//! Tests:
//! - Event creation from collectors
//! - Batch assembly and transmission
//! - Event acknowledgment handling
//! - Offline event queueing

use std::time::Duration;
use chrono::Utc;

use super::util::{test_agent_id, test_server_url, should_run_server_tests};

/// Create a test process event
fn create_test_process_event() -> tamandua_agent::collectors::TelemetryEvent {
    use tamandua_agent::collectors::{EventPayload, EventType, ProcessInfo, TelemetryEvent};

    TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::ProcessCreate,
        payload: EventPayload::Process(ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "notepad.exe".to_string(),
            path: "C:\\Windows\\System32\\notepad.exe".to_string(),
            cmdline: "notepad.exe test.txt".to_string(),
            user: "user".to_string(),
            is_elevated: false,
            is_signed: true,
            signer: Some("Microsoft Corporation".to_string()),
            sha256: None,
            start_time: Utc::now(),
        }),
        detections: vec![],
    }
}

/// Create a test file event
fn create_test_file_event() -> tamandua_agent::collectors::TelemetryEvent {
    use tamandua_agent::collectors::{EventPayload, EventType, FileInfo, TelemetryEvent};

    TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::FileCreate,
        payload: EventPayload::File(FileInfo {
            path: "C:\\Users\\test\\Downloads\\document.pdf".to_string(),
            sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
            size: 1024,
            entropy: Some(5.5),
            is_executable: false,
            is_signed: false,
            signer: None,
        }),
        detections: vec![],
    }
}

/// Create a test network event
fn create_test_network_event() -> tamandua_agent::collectors::TelemetryEvent {
    use tamandua_agent::collectors::{EventPayload, EventType, NetworkInfo, TelemetryEvent};

    TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::NetworkConnect,
        payload: EventPayload::Network(NetworkInfo {
            pid: 5678,
            process_name: "chrome.exe".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_port: 54321,
            remote_ip: "172.217.14.100".to_string(),
            remote_port: 443,
            protocol: "tcp".to_string(),
            direction: "outbound".to_string(),
        }),
        detections: vec![],
    }
}

/// Create a test DNS event
fn create_test_dns_event() -> tamandua_agent::collectors::TelemetryEvent {
    use tamandua_agent::collectors::{DnsInfo, EventPayload, EventType, TelemetryEvent};

    TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::DnsQuery,
        payload: EventPayload::Dns(DnsInfo {
            pid: Some(5678),
            process_name: Some("chrome.exe".to_string()),
            query: "www.google.com".to_string(),
            query_type: "A".to_string(),
            response_ips: vec!["172.217.14.100".to_string()],
            response_code: 0,
        }),
        detections: vec![],
    }
}

#[tokio::test]
async fn test_event_serialization() {
    let event = create_test_process_event();

    // Should serialize to JSON without error
    let json = serde_json::to_string(&event).expect("Event should serialize");
    assert!(json.contains("process_create") || json.contains("ProcessCreate"));
    assert!(json.contains("notepad.exe"));
}

#[tokio::test]
async fn test_batch_creation() {
    let events = vec![
        create_test_process_event(),
        create_test_file_event(),
        create_test_network_event(),
        create_test_dns_event(),
    ];

    // Batch should contain all events
    let json = serde_json::to_string(&events).expect("Batch should serialize");

    assert!(json.contains("notepad.exe"));
    assert!(json.contains("document.pdf"));
    assert!(json.contains("chrome.exe"));
    assert!(json.contains("www.google.com"));
}

#[tokio::test]
#[ignore = "requires running server"]
async fn test_telemetry_sent_and_acked() {
    if !should_run_server_tests() {
        return;
    }

    let config = tamandua_agent::config::AgentConfig {
        agent_id: test_agent_id(),
        server_url: test_server_url(),
        auth_token: Some("dev-token-test".to_string()),
        heartbeat_interval_seconds: 30,
        batch_size: 100,
        batch_timeout_seconds: 5,
        reconnect_delay_seconds: 5,
        max_reconnect_attempts: 3,
        local_queue_size: Some(1000),
        yara_enabled: false,
        entropy_check_enabled: true,
        entropy_threshold: 7.5,
        honeyfiles_enabled: false,
        local_analysis_enabled: false,
        health_interval_seconds: 60,
        excluded_paths: vec![],
        excluded_processes: vec![],
        tls: tamandua_agent::config::TlsConfig::default(),
        collectors: tamandua_agent::config::CollectorsConfig::default(),
    };

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {:?}", e);
            return;
        }
    };

    if client.connect().await.is_err() {
        eprintln!("Connection failed");
        return;
    }

    // Wait for connection to stabilize
    tokio::time::sleep(Duration::from_secs(1)).await;

    if !client.is_connected().await {
        eprintln!("Not connected after wait");
        return;
    }

    // Send test events
    let events = vec![
        create_test_process_event(),
        create_test_file_event(),
    ];

    match client.send_telemetry(&events).await {
        Ok(()) => {
            println!("Telemetry sent successfully");
        }
        Err(e) => {
            eprintln!("Failed to send telemetry: {:?}", e);
        }
    }

    // Give server time to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Queue should be empty (events sent)
    let queue_size = client.get_queue_size().await;
    assert_eq!(queue_size, 0);
}

#[tokio::test]
async fn test_offline_event_queueing() {
    let config = tamandua_agent::config::AgentConfig {
        agent_id: test_agent_id(),
        server_url: "ws://nonexistent:4000/socket/agent".to_string(),
        auth_token: Some("dev-token-test".to_string()),
        heartbeat_interval_seconds: 30,
        batch_size: 100,
        batch_timeout_seconds: 5,
        reconnect_delay_seconds: 5,
        max_reconnect_attempts: 1,
        local_queue_size: Some(100),
        yara_enabled: false,
        entropy_check_enabled: true,
        entropy_threshold: 7.5,
        honeyfiles_enabled: false,
        local_analysis_enabled: false,
        health_interval_seconds: 60,
        excluded_paths: vec![],
        excluded_processes: vec![],
        tls: tamandua_agent::config::TlsConfig::default(),
        collectors: tamandua_agent::config::CollectorsConfig::default(),
    };

    let client = tamandua_agent::transport::BackendClient::new(&config)
        .await
        .expect("Client creation should succeed");

    // Don't connect - simulate offline

    // Queue events
    let events: Vec<_> = (0..10).map(|_| create_test_process_event()).collect();
    client.send_telemetry(&events).await.unwrap();

    // Verify queue size
    assert_eq!(client.get_queue_size().await, 10);
}

#[tokio::test]
async fn test_queue_size_limit() {
    let config = tamandua_agent::config::AgentConfig {
        agent_id: test_agent_id(),
        server_url: "ws://nonexistent:4000/socket/agent".to_string(),
        auth_token: Some("dev-token-test".to_string()),
        heartbeat_interval_seconds: 30,
        batch_size: 100,
        batch_timeout_seconds: 5,
        reconnect_delay_seconds: 5,
        max_reconnect_attempts: 1,
        local_queue_size: Some(5), // Small queue for testing
        yara_enabled: false,
        entropy_check_enabled: true,
        entropy_threshold: 7.5,
        honeyfiles_enabled: false,
        local_analysis_enabled: false,
        health_interval_seconds: 60,
        excluded_paths: vec![],
        excluded_processes: vec![],
        tls: tamandua_agent::config::TlsConfig::default(),
        collectors: tamandua_agent::config::CollectorsConfig::default(),
    };

    let client = tamandua_agent::transport::BackendClient::new(&config)
        .await
        .expect("Client creation should succeed");

    // Queue more events than limit
    let events: Vec<_> = (0..10).map(|_| create_test_process_event()).collect();
    client.send_telemetry(&events).await.unwrap();

    // Queue should be at limit (oldest dropped)
    assert!(client.get_queue_size().await <= 5);
}

#[tokio::test]
async fn test_event_detection_attachment() {
    use tamandua_agent::collectors::{Detection, EventPayload, EventType, ProcessInfo, TelemetryEvent};

    let event = TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::ProcessCreate,
        payload: EventPayload::Process(ProcessInfo {
            pid: 9999,
            ppid: 1,
            name: "mimikatz.exe".to_string(),
            path: "C:\\Temp\\mimikatz.exe".to_string(),
            cmdline: "mimikatz.exe sekurlsa::logonpasswords".to_string(),
            user: "admin".to_string(),
            is_elevated: true,
            is_signed: false,
            signer: None,
            sha256: Some("abc123".to_string()),
            start_time: Utc::now(),
        }),
        detections: vec![Detection {
            rule_name: "Mimikatz Credential Theft".to_string(),
            rule_type: "yara".to_string(),
            confidence: 0.95,
            description: "Known credential theft tool detected".to_string(),
            mitre_tactics: vec!["credential-access".to_string()],
            mitre_techniques: vec!["T1003.001".to_string()],
        }],
    };

    // Verify detection is attached
    assert_eq!(event.detections.len(), 1);
    assert_eq!(event.detections[0].rule_name, "Mimikatz Credential Theft");
    assert_eq!(event.detections[0].confidence, 0.95);

    // Should serialize correctly
    let json = serde_json::to_string(&event).expect("Should serialize");
    assert!(json.contains("Mimikatz"));
    assert!(json.contains("T1003.001"));
}

#[tokio::test]
async fn test_large_batch_handling() {
    // Create a large batch of events
    let events: Vec<_> = (0..1000)
        .map(|i| {
            use tamandua_agent::collectors::{EventPayload, EventType, ProcessInfo, TelemetryEvent};

            TelemetryEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: EventType::ProcessCreate,
                payload: EventPayload::Process(ProcessInfo {
                    pid: 1000 + i,
                    ppid: 1,
                    name: format!("process{}.exe", i),
                    path: format!("C:\\Windows\\process{}.exe", i),
                    cmdline: "test".to_string(),
                    user: "SYSTEM".to_string(),
                    is_elevated: false,
                    is_signed: true,
                    signer: Some("Test".to_string()),
                    sha256: None,
                    start_time: Utc::now(),
                }),
                detections: vec![],
            }
        })
        .collect();

    // Should serialize without issues
    let json = serde_json::to_string(&events).expect("Large batch should serialize");
    assert!(json.len() > 100_000); // Verify it's actually large
}
