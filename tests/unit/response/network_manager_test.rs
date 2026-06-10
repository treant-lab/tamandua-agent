//! Network Manager Tests

use tamandua_agent::response::network_manager::*;

#[tokio::test]
async fn test_enumerate_connections() {
    // Test basic connection enumeration
    let result = enumerate_connections().await;
    assert!(result.is_ok());

    let connections = result.unwrap();
    println!("Found {} connections", connections.len());

    // Verify each connection has required fields
    for conn in &connections {
        assert!(conn.pid > 0 || conn.pid == 0); // System can be 0
        assert!(!conn.process_name.is_empty());
        assert!(!conn.local_ip.is_empty());
        assert!(!conn.remote_ip.is_empty());
        assert!(!conn.protocol.is_empty());
        assert!(!conn.state.is_empty());
    }
}

#[tokio::test]
async fn test_connection_tracker() {
    let mut tracker = ConnectionTracker::new();

    // Simulate first snapshot
    let result = enumerate_connections().await;
    if let Ok(connections) = result {
        tracker.update(connections.clone());

        let active = tracker.get_active();
        assert!(!active.is_empty());

        // Simulate second snapshot (should preserve first_seen)
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracker.update(connections);

        let active_2 = tracker.get_active();
        assert_eq!(active.len(), active_2.len());

        // Verify first_seen is preserved
        if let (Some(first), Some(second)) = (active.first(), active_2.first()) {
            assert_eq!(first.first_seen, second.first_seen);
        }
    }
}

#[tokio::test]
async fn test_connection_stats() {
    let result = enumerate_connections().await;
    if let Ok(connections) = result {
        let stats = get_connection_stats(&connections).await;

        let total = stats.get("total_connections").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(total as usize, connections.len());

        let tcp = stats.get("tcp_connections").and_then(|v| v.as_u64()).unwrap_or(0);
        let udp = stats.get("udp_connections").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!((tcp + udp) as usize, connections.len());

        println!("Connection statistics: {}", serde_json::to_string_pretty(&stats).unwrap());
    }
}

#[test]
fn test_connection_tracker_history() {
    let mut tracker = ConnectionTracker::new();

    // Create mock connections
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mock_conn = NetworkConnection {
        pid: 1234,
        process_name: "test".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 8080,
        remote_ip: "192.168.1.1".to_string(),
        remote_port: 443,
        protocol: "tcp".to_string(),
        state: "ESTABLISHED".to_string(),
        direction: "outbound".to_string(),
        bytes_sent: 1024,
        bytes_received: 2048,
        first_seen: now,
        last_seen: now,
        process_path: Some("/bin/test".to_string()),
        is_elevated: false,
    };

    // Add connection
    tracker.update(vec![mock_conn.clone()]);
    assert_eq!(tracker.get_active().len(), 1);

    // Remove connection (simulate it closing)
    tracker.update(vec![]);
    assert_eq!(tracker.get_active().len(), 0);
    assert_eq!(tracker.get_history(0).len(), 1);

    // Cleanup old history
    tracker.cleanup_history(now + 3600);
    assert_eq!(tracker.get_history(0).len(), 0);
}
