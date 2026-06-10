//! Sans-IO Protocol Tests
//!
//! This module contains comprehensive tests for the sans-IO protocol implementation.
//! Tests use controlled time and simulated network conditions for deterministic behavior.

use crate::collectors::{EventPayload, EventType, Severity, TelemetryEvent};
use crate::transport::codec::{MessageCodec, ProtocolMessage};
use crate::transport::sans_io::*;
use crate::transport::state_machine::*;
use std::time::{Duration, Instant};

/// Test helper for controlled time
struct TimeController {
    current: Instant,
}

impl TimeController {
    fn new() -> Self {
        Self {
            current: Instant::now(),
        }
    }

    fn now(&self) -> Instant {
        self.current
    }

    fn advance(&mut self, duration: Duration) {
        self.current += duration;
    }
}

/// Test helper for simulating network conditions
struct NetworkSimulator {
    /// Packet loss rate (0.0 - 1.0)
    packet_loss: f64,

    /// Latency
    latency: Duration,

    /// Bandwidth limit (bytes per second, 0 = unlimited)
    bandwidth_limit: u64,

    /// Random seed for deterministic tests
    seed: u64,
}

impl NetworkSimulator {
    fn new() -> Self {
        Self {
            packet_loss: 0.0,
            latency: Duration::ZERO,
            bandwidth_limit: 0,
            seed: 12345,
        }
    }

    fn with_packet_loss(mut self, rate: f64) -> Self {
        self.packet_loss = rate.clamp(0.0, 1.0);
        self
    }

    fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    fn with_bandwidth_limit(mut self, bytes_per_sec: u64) -> Self {
        self.bandwidth_limit = bytes_per_sec;
        self
    }

    /// Check if a packet should be dropped
    fn should_drop_packet(&mut self) -> bool {
        // Simple LCG for deterministic randomness
        self.seed = self.seed.wrapping_mul(1103515245).wrapping_add(12345);
        let random = (self.seed / 65536) % 100;
        (random as f64 / 100.0) < self.packet_loss
    }

    /// Calculate transmission time for given data size
    fn transmission_time(&self, bytes: usize) -> Duration {
        let mut time = self.latency;

        if self.bandwidth_limit > 0 {
            let seconds = bytes as f64 / self.bandwidth_limit as f64;
            time += Duration::from_secs_f64(seconds);
        }

        time
    }
}

// ============================================================================
// Connection Lifecycle Tests
// ============================================================================

#[test]
fn test_connection_establishment() {
    let config = ProtocolConfig::default();
    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();

    // Initially disconnected
    assert!(matches!(protocol.state(), &ProtocolState::Disconnected));

    // Connect
    protocol.handle_connected(time.now());

    // Should be connected
    assert!(matches!(protocol.state(), &ProtocolState::Connected));

    // Should emit Connected event
    match protocol.poll_event() {
        Some(ProtocolEvent::Connected) => {}
        other => panic!("Expected Connected event, got {:?}", other),
    }

    // No more events
    assert!(protocol.poll_event().is_none());
}

#[test]
fn test_clean_disconnection() {
    let config = ProtocolConfig::default();
    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();

    // Connect first
    protocol.handle_connected(time.now());
    let _ = protocol.poll_event(); // Consume Connected event

    // Disconnect cleanly
    protocol.handle_disconnected(DisconnectReason::Clean, time.now());

    // Should be disconnected
    assert!(matches!(protocol.state(), &ProtocolState::Disconnected));

    // Should emit Disconnected event
    match protocol.poll_event() {
        Some(ProtocolEvent::Disconnected { reason }) => {
            assert_eq!(reason, DisconnectReason::Clean);
        }
        other => panic!("Expected Disconnected event, got {:?}", other),
    }
}

#[test]
fn test_reconnection_after_timeout() {
    let mut config = ProtocolConfig::default();
    config.heartbeat_timeout = Duration::from_secs(10);

    let mut protocol = AgentProtocol::new(config);
    let mut time = TimeController::new();

    // Connect
    protocol.handle_connected(time.now());
    let _ = protocol.poll_event(); // Consume Connected

    // Advance time past heartbeat timeout
    time.advance(Duration::from_secs(15));
    protocol.handle_timeout(time.now());

    // Should transition to disconnected
    assert!(matches!(protocol.state(), &ProtocolState::Disconnected));

    // Should emit Disconnected event with HeartbeatTimeout reason
    match protocol.poll_event() {
        Some(ProtocolEvent::Disconnected { reason }) => {
            assert_eq!(reason, DisconnectReason::HeartbeatTimeout);
        }
        other => panic!("Expected Disconnected event, got {:?}", other),
    }

    // Should emit ReconnectRequired event
    match protocol.poll_event() {
        Some(ProtocolEvent::ReconnectRequired { delay }) => {
            assert!(delay > Duration::ZERO);
        }
        other => panic!("Expected ReconnectRequired event, got {:?}", other),
    }
}

// ============================================================================
// State Transition Tests
// ============================================================================

#[test]
fn test_state_machine_valid_transitions() {
    let mut sm = StateMachine::new(ProtocolState::Disconnected, Instant::now());

    // Disconnected -> Connecting
    assert!(sm
        .transition(StateTransition::Connect, Instant::now())
        .is_ok());
    assert_eq!(sm.current(), ProtocolState::Connecting);

    // Connecting -> Connected
    assert!(sm
        .transition(StateTransition::Connected, Instant::now())
        .is_ok());
    assert_eq!(sm.current(), ProtocolState::Connected);

    // Connected -> Disconnected (via error)
    assert!(sm
        .transition(StateTransition::Error("test".to_string()), Instant::now())
        .is_ok());
    assert_eq!(sm.current(), ProtocolState::Reconnecting);
}

#[test]
fn test_state_machine_invalid_transitions() {
    let mut sm = StateMachine::new(ProtocolState::Disconnected, Instant::now());

    // Cannot go directly from Disconnected to Connected
    let result = sm.transition(StateTransition::Connected, Instant::now());
    assert!(result.is_err());
}

#[test]
fn test_state_machine_history() {
    let mut sm = StateMachine::new(ProtocolState::Disconnected, Instant::now());

    let _ = sm.transition(StateTransition::Connect, Instant::now());
    let _ = sm.transition(StateTransition::Connected, Instant::now());

    assert_eq!(sm.total_transitions(), 2);
    assert_eq!(sm.history().len(), 2);

    let first = &sm.history()[0];
    assert_eq!(first.from, ProtocolState::Disconnected);
    assert_eq!(first.to, ProtocolState::Connecting);
}

#[test]
fn test_rapid_cycling_detection() {
    let mut sm = StateMachine::new(ProtocolState::Disconnected, Instant::now());
    let mut time = TimeController::new();

    // Simulate rapid state changes
    for _ in 0..20 {
        time.advance(Duration::from_millis(50));
        let _ = sm.transition(StateTransition::Connect, time.now());
        time.advance(Duration::from_millis(50));
        let _ = sm.transition(StateTransition::Connected, time.now());
        time.advance(Duration::from_millis(50));
        let _ = sm.transition(StateTransition::Disconnected, time.now());
    }

    // Should detect rapid cycling in 5 second window
    assert!(sm.is_rapid_cycling(20, Duration::from_secs(5), time.now()));
}

// ============================================================================
// Telemetry Batching Tests
// ============================================================================

#[test]
fn test_telemetry_batching() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 10;

    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();

    // Connect
    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Send 5 events (below batch size)
    for i in 0..5 {
        let event = create_test_event(i);
        protocol.send_telemetry(event, time.now()).unwrap();
    }

    // No transmit yet (batch not full)
    assert!(protocol.poll_transmit().is_none());

    // Send 5 more events (reaches batch size)
    for i in 5..10 {
        let event = create_test_event(i);
        protocol.send_telemetry(event, time.now()).unwrap();
    }

    // Should have a transmit now
    let transmit = protocol.poll_transmit().expect("Expected transmit");
    assert_eq!(transmit.destination, TransmitDestination::Server);
    assert!(transmit.sequence.is_some());
}

#[test]
fn test_batch_timeout() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 100; // Large batch size
    config.batch_timeout = Duration::from_secs(5);

    let mut protocol = AgentProtocol::new(config);
    let mut time = TimeController::new();

    // Connect
    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Send 1 event
    let event = create_test_event(0);
    protocol.send_telemetry(event, time.now()).unwrap();

    // No transmit yet
    assert!(protocol.poll_transmit().is_none());

    // Advance time past batch timeout
    time.advance(Duration::from_secs(6));
    protocol.handle_timeout(time.now());

    // Should flush batch now
    let transmit = protocol.poll_transmit().expect("Expected transmit");
    assert!(transmit.sequence.is_some());
}

// ============================================================================
// ACK and Retry Tests
// ============================================================================

#[test]
fn test_telemetry_acknowledgment() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 5;

    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();

    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Send batch
    for i in 0..5 {
        protocol
            .send_telemetry(create_test_event(i), time.now())
            .unwrap();
    }

    let transmit = protocol.poll_transmit().expect("Expected transmit");
    let sequence = transmit.sequence.expect("Expected sequence");

    // Simulate ACK from server
    let ack_message = ProtocolMessage::TelemetryAck { sequence, count: 5 };

    let codec = MessageCodec::new();
    let ack_data = codec.encode(&ack_message).unwrap();

    protocol.handle_input(&ack_data, time.now()).unwrap();

    // Should emit TelemetryAcknowledged event
    loop {
        match protocol.poll_event() {
            Some(ProtocolEvent::TelemetryAcknowledged {
                sequence: ack_seq,
                count,
            }) => {
                assert_eq!(ack_seq, sequence);
                assert_eq!(count, 5);
                break;
            }
            Some(_) => continue,
            None => panic!("Expected TelemetryAcknowledged event"),
        }
    }

    // Stats should reflect acknowledgment
    assert_eq!(protocol.stats().events_sent, 5);
    assert_eq!(protocol.stats().events_acked, 5);
}

#[test]
fn test_ack_timeout_and_retry() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 5;
    config.ack_timeout = Duration::from_secs(10);

    let mut protocol = AgentProtocol::new(config);
    let mut time = TimeController::new();

    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Send batch
    for i in 0..5 {
        protocol
            .send_telemetry(create_test_event(i), time.now())
            .unwrap();
    }

    let transmit = protocol.poll_transmit().expect("Expected transmit");
    let sequence = transmit.sequence.expect("Expected sequence");

    // Don't send ACK, advance time past timeout
    time.advance(Duration::from_secs(11));
    protocol.handle_timeout(time.now());

    // Should retry
    let retry_transmit = protocol.poll_transmit();
    assert!(retry_transmit.is_some());
    assert_eq!(retry_transmit.unwrap().sequence, Some(sequence));

    // Stats should show retry
    assert!(protocol.stats().events_retried > 0);
}

#[test]
fn test_max_retries_exceeded() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 5;
    config.ack_timeout = Duration::from_secs(5);
    config.max_retries = 2;
    let max_retries = config.max_retries;

    let mut protocol = AgentProtocol::new(config);
    let mut time = TimeController::new();

    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Send batch
    for i in 0..5 {
        protocol
            .send_telemetry(create_test_event(i), time.now())
            .unwrap();
    }

    let _ = protocol.poll_transmit(); // Original send

    // Simulate max retries. Each retry uses exponential backoff
    // (ack_timeout * 2^retry_count): with ack_timeout = 5s the deadlines fall at
    // ~5s, ~30s and ~60s. Advance 20s per iteration so every ACK deadline fires,
    // while keeping the cumulative time under the 120s heartbeat timeout (which
    // would otherwise disconnect the protocol before the ACK checks run).
    for _ in 0..=max_retries {
        time.advance(Duration::from_secs(20));
        protocol.handle_timeout(time.now());
        let _ = protocol.poll_transmit(); // Retry
    }

    // After max retries, batch should be dropped
    assert_eq!(protocol.stats().events_dropped, 5);
}

// ============================================================================
// Backpressure Tests
// ============================================================================

#[test]
fn test_backpressure_applied() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 1;
    config.ack_timeout = Duration::from_secs(100); // Long timeout

    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();

    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Fill in-flight queue
    for i in 0..100 {
        protocol
            .send_telemetry(create_test_event(i), time.now())
            .unwrap();
        let _ = protocol.poll_transmit();
    }

    // Should emit BackpressureApplied event
    let mut found_backpressure = false;
    while let Some(event) = protocol.poll_event() {
        if matches!(event, ProtocolEvent::BackpressureApplied { .. }) {
            found_backpressure = true;
            break;
        }
    }

    assert!(found_backpressure, "Expected BackpressureApplied event");
}

#[test]
fn test_backpressure_released() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 1;

    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();

    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Create backpressure
    for i in 0..100 {
        protocol
            .send_telemetry(create_test_event(i), time.now())
            .unwrap();
        let _ = protocol.poll_transmit();
    }

    // Clear backpressure events
    while let Some(_) = protocol.poll_event() {}

    // ACK half the batches
    let codec = MessageCodec::new();
    for seq in 1..=50 {
        let ack = ProtocolMessage::TelemetryAck {
            sequence: seq,
            count: 1,
        };
        let data = codec.encode(&ack).unwrap();
        protocol.handle_input(&data, time.now()).unwrap();
    }

    // Should emit BackpressureReleased
    let mut found_release = false;
    while let Some(event) = protocol.poll_event() {
        if matches!(event, ProtocolEvent::BackpressureReleased) {
            found_release = true;
            break;
        }
    }

    assert!(found_release, "Expected BackpressureReleased event");
}

// ============================================================================
// Codec Tests
// ============================================================================

#[test]
fn test_codec_encode_decode() {
    let codec = MessageCodec::new();

    let message = ProtocolMessage::HeartbeatAck;

    let encoded = codec.encode(&message).unwrap();
    let (decoded, consumed) = codec.decode(&encoded).unwrap().unwrap();

    assert_eq!(consumed, encoded.len());
    assert!(matches!(decoded, ProtocolMessage::HeartbeatAck));
}

#[test]
fn test_codec_incomplete_frame() {
    let codec = MessageCodec::new();

    let message = ProtocolMessage::HeartbeatAck;
    let mut encoded = codec.encode(&message).unwrap();

    // Truncate
    encoded.truncate(encoded.len() - 5);

    let result = codec.decode(&encoded).unwrap();
    assert!(result.is_none()); // Need more data
}

#[test]
fn test_codec_multiple_frames() {
    let codec = MessageCodec::new();

    let msg1 = ProtocolMessage::HeartbeatAck;
    let msg2 = ProtocolMessage::Error {
        message: "test".to_string(),
    };

    let mut buffer = Vec::new();
    buffer.extend_from_slice(&codec.encode(&msg1).unwrap());
    buffer.extend_from_slice(&codec.encode(&msg2).unwrap());

    // Decode first
    let (decoded1, consumed1) = codec.decode(&buffer).unwrap().unwrap();
    assert!(matches!(decoded1, ProtocolMessage::HeartbeatAck));

    // Decode second
    let remaining = &buffer[consumed1..];
    let (decoded2, _consumed2) = codec.decode(remaining).unwrap().unwrap();

    if let ProtocolMessage::Error { message } = decoded2 {
        assert_eq!(message, "test");
    } else {
        panic!("Expected Error message");
    }
}

// ============================================================================
// Network Simulation Tests
// ============================================================================

#[test]
fn test_packet_loss_simulation() {
    let mut net = NetworkSimulator::new().with_packet_loss(0.3);

    let mut dropped = 0;
    let mut delivered = 0;

    for _ in 0..100 {
        if net.should_drop_packet() {
            dropped += 1;
        } else {
            delivered += 1;
        }
    }

    // Should be roughly 30% loss (allow some variance)
    let loss_rate = dropped as f64 / 100.0;
    assert!(
        loss_rate > 0.2 && loss_rate < 0.4,
        "Loss rate {} outside expected range",
        loss_rate
    );
}

#[test]
fn test_latency_simulation() {
    let net = NetworkSimulator::new().with_latency(Duration::from_millis(100));

    let tx_time = net.transmission_time(1000);
    assert_eq!(tx_time, Duration::from_millis(100));
}

#[test]
fn test_bandwidth_limit_simulation() {
    let net = NetworkSimulator::new().with_bandwidth_limit(1000); // 1 KB/s

    // 500 bytes should take 0.5 seconds
    let tx_time = net.transmission_time(500);
    assert!(tx_time >= Duration::from_millis(500));
}

// ============================================================================
// Heartbeat Tests
// ============================================================================

#[test]
fn test_heartbeat_generation() {
    let mut config = ProtocolConfig::default();
    config.heartbeat_interval = Duration::from_secs(30);

    let mut protocol = AgentProtocol::new(config);
    let mut time = TimeController::new();

    protocol.handle_connected(time.now());
    let _ = protocol.poll_event();

    // Advance time past heartbeat interval
    time.advance(Duration::from_secs(31));
    protocol.handle_timeout(time.now());

    // Should emit HeartbeatRequired event
    let mut found_heartbeat = false;
    while let Some(event) = protocol.poll_event() {
        if matches!(event, ProtocolEvent::HeartbeatRequired) {
            found_heartbeat = true;
            break;
        }
    }

    assert!(found_heartbeat, "Expected HeartbeatRequired event");
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_event(id: u64) -> TelemetryEvent {
    TelemetryEvent {
        event_id: format!("test-{}", id),
        event_type: EventType::ProcessCreate,
        timestamp: id,
        severity: Severity::Info,
        payload: EventPayload::Process(crate::collectors::ProcessEvent {
            pid: id as u32,
            ppid: 1,
            name: format!("test-{}", id),
            path: format!("/bin/test-{}", id),
            cmdline: format!("test-{}", id),
            user: "testuser".to_string(),
            sha256: vec![0; 32],
            entropy: 0.0,
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
        detections: vec![],
        metadata: Default::default(),
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_lifecycle_with_telemetry() {
    let mut config = ProtocolConfig::default();
    config.batch_size = 10;

    let mut protocol = AgentProtocol::new(config);
    let time = TimeController::new();
    let codec = MessageCodec::new();

    // Connect
    protocol.handle_connected(time.now());
    assert!(matches!(
        protocol.poll_event(),
        Some(ProtocolEvent::Connected)
    ));

    // Send telemetry
    for i in 0..10 {
        protocol
            .send_telemetry(create_test_event(i), time.now())
            .unwrap();
    }

    // Should have transmit
    let transmit = protocol.poll_transmit().expect("Expected transmit");
    let sequence = transmit.sequence.expect("Expected sequence");

    // Simulate ACK
    let ack = ProtocolMessage::TelemetryAck {
        sequence,
        count: 10,
    };
    let ack_data = codec.encode(&ack).unwrap();
    protocol.handle_input(&ack_data, time.now()).unwrap();

    // Check stats
    assert_eq!(protocol.stats().events_sent, 10);
    assert_eq!(protocol.stats().events_acked, 10);

    // Disconnect
    protocol.handle_disconnected(DisconnectReason::Clean, time.now());
    assert!(matches!(protocol.state(), &ProtocolState::Disconnected));
}
