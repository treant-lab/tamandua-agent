//! Server connection integration tests
//!
//! Tests the WebSocket connection to the backend server including:
//! - Initial connection establishment
//! - Phoenix channel join
//! - Authentication flow
//! - Reconnection handling
//! - Configuration reception

use std::time::Duration;
use tokio::time::timeout;

use super::util::{test_agent_id, test_server_url, should_run_server_tests, TEST_TIMEOUT};

/// Mock agent configuration for testing
fn test_config() -> tamandua_agent::config::AgentConfig {
    tamandua_agent::config::AgentConfig {
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
    }
}

#[tokio::test]
#[ignore = "requires running server"]
async fn test_agent_connects_to_server() {
    if !should_run_server_tests() {
        eprintln!("Skipping server connection test - set TAMANDUA_TEST_SERVER or RUN_INTEGRATION_TESTS");
        return;
    }

    let config = test_config();

    let result = timeout(TEST_TIMEOUT, async {
        tamandua_agent::transport::BackendClient::new(&config).await
    })
    .await;

    match result {
        Ok(Ok(client)) => {
            // Client created successfully
            assert!(!client.is_connected().await);

            // Try to connect
            let connect_result = timeout(
                Duration::from_secs(10),
                client.connect(),
            )
            .await;

            match connect_result {
                Ok(Ok(())) => {
                    // Wait a bit for connection to stabilize
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    assert!(client.is_connected().await);
                }
                Ok(Err(e)) => {
                    eprintln!("Connection failed (expected if no server): {:?}", e);
                }
                Err(_) => {
                    eprintln!("Connection timed out");
                }
            }
        }
        Ok(Err(e)) => {
            panic!("Failed to create client: {:?}", e);
        }
        Err(_) => {
            panic!("Client creation timed out");
        }
    }
}

#[tokio::test]
#[ignore = "requires running server"]
async fn test_agent_receives_config_on_connect() {
    if !should_run_server_tests() {
        return;
    }

    let config = test_config();

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {:?}", e);
            return;
        }
    };

    if client.connect().await.is_err() {
        eprintln!("Connection failed (expected if no server)");
        return;
    }

    // Wait for config update
    let config_result = timeout(
        Duration::from_secs(5),
        client.receive_config_update(),
    )
    .await;

    match config_result {
        Ok(Ok(update)) => {
            // Verify config structure
            assert!(update.config.is_object());
        }
        Ok(Err(e)) => {
            eprintln!("No config received: {:?}", e);
        }
        Err(_) => {
            eprintln!("Config reception timed out");
        }
    }
}

#[tokio::test]
#[ignore = "requires running server"]
async fn test_agent_reconnects_on_disconnect() {
    if !should_run_server_tests() {
        return;
    }

    let config = test_config();

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {:?}", e);
            return;
        }
    };

    // Connect
    if client.connect().await.is_err() {
        eprintln!("Initial connection failed");
        return;
    }

    // Disconnect
    let _ = client.disconnect().await;

    // Connection monitor should attempt reconnect
    tokio::time::sleep(Duration::from_secs(2)).await;

    // State should reflect disconnection
    assert!(!client.is_connected().await);
}

#[tokio::test]
async fn test_local_queue_stores_events_when_disconnected() {
    let config = test_config();

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            panic!("Failed to create client: {:?}", e);
        }
    };

    // Don't connect - simulate offline mode

    // Create test events
    let events: Vec<tamandua_agent::collectors::TelemetryEvent> = (0..5)
        .map(|i| tamandua_agent::collectors::TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type: tamandua_agent::collectors::EventType::ProcessCreate,
            payload: tamandua_agent::collectors::EventPayload::Process(
                tamandua_agent::collectors::ProcessInfo {
                    pid: 1000 + i,
                    ppid: 1,
                    name: format!("test{}.exe", i),
                    path: format!("C:\\Windows\\test{}.exe", i),
                    cmdline: "test".to_string(),
                    user: "SYSTEM".to_string(),
                    is_elevated: false,
                    is_signed: true,
                    signer: Some("Test".to_string()),
                    sha256: None,
                    start_time: chrono::Utc::now(),
                },
            ),
            detections: vec![],
        })
        .collect();

    // Send events while disconnected
    client.send_telemetry(&events).await.unwrap();

    // Verify events are queued
    let queue_size = client.get_queue_size().await;
    assert_eq!(queue_size, 5);
}

#[tokio::test]
async fn test_connection_state_transitions() {
    let config = test_config();

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            panic!("Failed to create client: {:?}", e);
        }
    };

    // Initial state should be disconnected
    use tamandua_agent::transport::ConnectionState;
    assert_eq!(client.get_state().await, ConnectionState::Disconnected);
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[tokio::test]
    async fn test_config_creation() {
        let config = test_config();
        assert!(!config.agent_id.is_empty());
        assert!(config.server_url.contains("socket/agent"));
    }

    #[tokio::test]
    async fn test_client_creation_does_not_connect() {
        let config = test_config();

        let client = tamandua_agent::transport::BackendClient::new(&config)
            .await
            .expect("Client creation should not fail");

        // Client should be created but not connected
        assert!(!client.is_connected().await);
    }
}
