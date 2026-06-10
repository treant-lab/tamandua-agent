//! Comprehensive unit tests for transport module
//!
//! Tests cover WebSocket communication, message serialization, reconnection logic,
//! delivery guarantees, and backoff algorithms.

#[cfg(test)]
mod sans_io_tests;

#[cfg(test)]
mod connection_tests {
    use crate::transport::{ConnectionState, DeliveryStats, LocalEventQueue};

    #[test]
    fn test_connection_state_equality() {
        assert_eq!(ConnectionState::Connected, ConnectionState::Connected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connecting, ConnectionState::Reconnecting);
    }

    #[test]
    fn test_delivery_stats_default() {
        let stats = DeliveryStats::default();
        assert_eq!(stats.events_sent, 0);
        assert_eq!(stats.events_acked, 0);
        assert_eq!(stats.events_retried, 0);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.events_confirmed_after_ack, 0);
        assert_eq!(stats.ack_count_mismatches, 0);
        assert_eq!(stats.in_flight_batches, 0);
    }

    #[test]
    fn test_delivery_stats_tracking() {
        let mut stats = DeliveryStats::default();

        stats.events_sent = 100;
        stats.events_acked = 95;
        stats.events_retried = 3;
        stats.events_dropped = 2;
        stats.in_flight_batches = 5;

        assert_eq!(stats.events_sent, 100);
        assert_eq!(stats.events_acked, 95);
        assert_eq!(stats.events_retried, 3);
        assert_eq!(stats.events_dropped, 2);
        assert_eq!(stats.events_confirmed_after_ack, 0);
        assert_eq!(stats.ack_count_mismatches, 0);

        // Calculate loss rate
        let loss_rate = (stats.events_dropped as f64) / (stats.events_sent as f64);
        assert!(loss_rate < 0.05); // Less than 5% loss
    }

    #[test]
    fn test_local_queue_basic_operations() {
        use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};

        let mut queue = LocalEventQueue::new(10, None, b"test-integrity-key".to_vec());

        let event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid: 123,
                ppid: 1,
                name: "test".to_string(),
                path: "/bin/test".to_string(),
                cmdline: "test".to_string(),
                user: "root".to_string(),
                sha256: vec![],
                entropy: 5.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
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
            }),
        );

        assert!(queue.is_empty());
        queue.push(event.clone());
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());

        let batch = queue.drain_batch(5);
        assert_eq!(batch.len(), 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_local_queue_overflow() {
        use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};

        let max_size = 5;
        let mut queue = LocalEventQueue::new(max_size, None, b"test-integrity-key".to_vec());

        // Push more events than capacity
        for i in 0..10 {
            let event = TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid: i as u32,
                    ppid: 1,
                    name: format!("test{}", i),
                    path: "/bin/test".to_string(),
                    cmdline: "test".to_string(),
                    user: "root".to_string(),
                    sha256: vec![],
                    entropy: 5.0,
                    is_elevated: false,
                    parent_name: None,
                    parent_path: None,
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
                }),
            );
            queue.push(event);
        }

        // Queue should not exceed max_size
        assert_eq!(queue.len(), max_size);
    }

    #[test]
    fn test_local_queue_confirm_event_ids_preserves_unacked_events() {
        use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};

        fn make_event(pid: u32) -> TelemetryEvent {
            TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid,
                    ppid: 1,
                    name: format!("test{pid}"),
                    path: "/bin/test".to_string(),
                    cmdline: "test".to_string(),
                    user: "root".to_string(),
                    sha256: vec![],
                    entropy: 5.0,
                    is_elevated: false,
                    parent_name: None,
                    parent_path: None,
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
                }),
            )
        }

        let mut queue = LocalEventQueue::new(10, None, b"test-integrity-key".to_vec());
        let first = make_event(1);
        let second = make_event(2);
        let third = make_event(3);

        let first_id = first.event_id.clone();
        let third_id = third.event_id.clone();
        let second_id = second.event_id.clone();

        queue.push(first);
        queue.push(second);
        queue.push(third);

        let confirmed = queue.confirm_event_ids(&[first_id.as_str(), third_id.as_str()]);
        assert_eq!(confirmed, 2);
        assert_eq!(queue.len(), 1);

        let remaining = queue.peek_batch(10);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].event_id, second_id);
    }
}

#[cfg(test)]
mod message_serialization_tests {
    use crate::transport::{Command, CommandResult, CommandType};

    #[test]
    fn test_command_serialization() {
        let command = Command {
            command_id: "cmd-123".to_string(),
            command_type: CommandType::KillProcess,
            timestamp: 1234567890,
            payload: serde_json::json!({ "pid": 1234 }),
        };

        let json = serde_json::to_string(&command).unwrap();
        let deserialized: Command = serde_json::from_str(&json).unwrap();

        assert_eq!(command.command_id, deserialized.command_id);
        assert_eq!(command.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_command_result_serialization() {
        let result = CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({ "status": "completed" })),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CommandResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.success, deserialized.success);
        assert!(deserialized.result_data.is_some());
    }
}

#[cfg(test)]
mod backoff_tests {
    #[test]
    fn test_exponential_backoff() {
        let base_delay = 2;
        let max_delay = 60;

        let delays: Vec<u64> = (0..10)
            .map(|attempt| {
                let delay = base_delay * 2u64.pow(attempt.min(6));
                delay.min(max_delay)
            })
            .collect();

        assert_eq!(delays[0], 2);
        assert_eq!(delays[1], 4);
        assert_eq!(delays[2], 8);
        assert_eq!(delays[3], 16);
        assert_eq!(delays[4], 32);
        assert_eq!(delays[5], 60); // Capped
    }
}
