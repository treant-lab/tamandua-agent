//! Sans-IO WebSocket Protocol Implementation
//!
//! This module implements a pure sans-IO protocol state machine for the Tamandua Agent
//! WebSocket transport layer, following the design pattern from Firezone's blog post
//! (https://www.firezone.dev/blog/sans-io).
//!
//! # Sans-IO Architecture Benefits
//!
//! The sans-IO pattern separates protocol logic from I/O operations, providing:
//!
//! - **Deterministic Testing**: Protocol logic can be tested without real I/O,
//!   using controlled time and simulated network conditions
//! - **Portability**: Same protocol logic works on Tokio, async-std, or even
//!   synchronous code with minimal changes
//! - **Debuggability**: Protocol state transitions are pure functions that can
//!   be inspected and replayed
//! - **Performance**: Zero-copy operations where possible, no async overhead in
//!   protocol logic
//! - **Correctness**: Easier to verify protocol invariants and state machine
//!   correctness
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                  Application Layer                       │
//! │         (Collectors, Response Handlers)                  │
//! └──────────────┬──────────────────────────┬────────────────┘
//!                │                          │
//!                v                          v
//!    ┌───────────────────┐      ┌──────────────────┐
//!    │  Protocol Events  │      │  Send Telemetry  │
//!    │   (poll_event)    │      │  Send Response   │
//!    └───────────────────┘      └──────────────────┘
//!                │                          │
//!                v                          v
//!        ┌─────────────────────────────────────────┐
//!        │       AgentProtocol (Sans-IO Core)      │
//!        │                                          │
//!        │  • State machine (pure)                 │
//!        │  • Message encoding/decoding            │
//!        │  • Timeout tracking                     │
//!        │  • Queue management                     │
//!        └─────────────────────────────────────────┘
//!                │                          │
//!                v                          v
//!    ┌───────────────────┐      ┌──────────────────┐
//!    │  Transmit Queue   │      │   Input Buffer   │
//!    │  (poll_transmit)  │      │ (handle_input)   │
//!    └───────────────────┘      └──────────────────┘
//!                │                          │
//!                v                          v
//!        ┌─────────────────────────────────────────┐
//!        │         Event Loop (I/O Layer)          │
//!        │                                          │
//!        │  • Tokio runtime                        │
//!        │  • WebSocket I/O                        │
//!        │  • Timer management                     │
//!        └─────────────────────────────────────────┘
//! ```
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use tamandua_agent::transport::sans_io::{AgentProtocol, ProtocolConfig, ProtocolEvent};
//! use std::time::Instant;
//!
//! let config = ProtocolConfig::default();
//! let mut protocol = AgentProtocol::new(config);
//! let now = Instant::now();
//!
//! // Connection established
//! protocol.handle_connected(now);
//!
//! // Poll for events
//! while let Some(event) = protocol.poll_event() {
//!     match event {
//!         ProtocolEvent::Connected => {
//!             println!("Connected to server");
//!         }
//!         ProtocolEvent::CommandReceived(cmd) => {
//!             println!("Command: {:?}", cmd);
//!         }
//!         _ => {}
//!     }
//! }
//!
//! // Poll for data to transmit
//! while let Some(transmit) = protocol.poll_transmit() {
//!     // Send transmit.payload to transmit.destination
//! }
//!
//! // Handle timeout
//! if let Some(deadline) = protocol.poll_timeout() {
//!     if Instant::now() >= deadline {
//!         protocol.handle_timeout(Instant::now());
//!     }
//! }
//! ```

// Sans-IO transport state machine. Scaffolded protocol fields retained
// for future replay/debug surface.
#![allow(dead_code)]

use crate::collectors::TelemetryEvent;
use crate::config::AgentConfig;
use crate::transport::codec::current_timestamp_millis;
use crate::transport::{Command, CommandResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

/// Maximum number of in-flight batches before backpressure
const MAX_IN_FLIGHT: usize = 100;

/// Maximum size of outgoing queue before dropping events
const MAX_QUEUE_SIZE: usize = 10000;

/// Maximum message size (10 MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Transmit request - what needs to be sent
#[derive(Debug, Clone)]
pub struct Transmit {
    /// Where to send this data
    pub destination: TransmitDestination,
    /// The payload to send
    pub payload: Vec<u8>,
    /// When this transmit was created
    pub created_at: Instant,
    /// Sequence number for ACK tracking (if applicable)
    pub sequence: Option<u64>,
}

/// Destination for transmit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitDestination {
    /// Send to backend server
    Server,
    /// Send to kernel driver (Windows/Linux)
    Driver,
    /// Send to local process (IPC)
    LocalProcess(u32),
}

/// Protocol events to be handled by the application
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    /// Connection established
    Connected,

    /// Connection lost
    Disconnected { reason: DisconnectReason },

    /// Command received from server
    CommandReceived(Command),

    /// Configuration update received
    ConfigUpdated(AgentConfig),

    /// Rules update received
    RulesUpdated(RulesUpdate),

    /// Heartbeat should be sent
    HeartbeatRequired,

    /// Reconnection required
    ReconnectRequired { delay: Duration },

    /// Telemetry batch acknowledged by server
    TelemetryAcknowledged { sequence: u64, count: usize },

    /// ML scan result received
    MlScanResult(MlScanResult),

    /// Backpressure applied - slow down event generation
    BackpressureApplied { queue_size: usize },

    /// Backpressure released - resume normal operation
    BackpressureReleased,
}

/// Reason for disconnection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Clean shutdown initiated by agent
    Clean,

    /// Server closed connection
    ServerClosed,

    /// Network error
    NetworkError(String),

    /// Protocol error (invalid message, etc)
    ProtocolError(String),

    /// Heartbeat timeout
    HeartbeatTimeout,

    /// Authentication failed
    AuthenticationFailed,

    /// Invalid state transition
    InvalidStateTransition,
}

/// Rules update from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesUpdate {
    /// YARA rules
    pub yara_rules: Option<Vec<serde_json::Value>>,

    /// Sigma rules
    pub sigma_rules: Option<Vec<serde_json::Value>>,

    /// IOCs (Indicators of Compromise)
    pub iocs: Option<Vec<serde_json::Value>>,
}

/// ML scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlScanResult {
    /// SHA256 hash
    pub sha256: String,

    /// Original file path
    pub file_path: String,

    /// Whether malicious
    pub is_malicious: bool,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,

    /// Classification
    pub classification: Option<String>,

    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,

    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
}

/// Protocol configuration
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Agent ID
    pub agent_id: String,

    /// Heartbeat interval
    pub heartbeat_interval: Duration,

    /// Heartbeat timeout (no server message)
    pub heartbeat_timeout: Duration,

    /// Batch size for telemetry
    pub batch_size: usize,

    /// Batch timeout
    pub batch_timeout: Duration,

    /// ACK timeout
    pub ack_timeout: Duration,

    /// Max retries for unacknowledged batches
    pub max_retries: u32,

    /// Reconnect delay base
    pub reconnect_delay_base: Duration,

    /// Max reconnect delay
    pub reconnect_delay_max: Duration,

    /// Max reconnect attempts (0 = infinite)
    pub max_reconnect_attempts: u32,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            agent_id: uuid::Uuid::new_v4().to_string(),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(120),
            batch_size: 100,
            batch_timeout: Duration::from_secs(5),
            ack_timeout: Duration::from_secs(10),
            max_retries: 3,
            reconnect_delay_base: Duration::from_secs(1),
            reconnect_delay_max: Duration::from_secs(60),
            max_reconnect_attempts: 0, // Infinite
        }
    }
}

/// Protocol statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    /// Total events sent
    pub events_sent: u64,

    /// Total events acknowledged
    pub events_acked: u64,

    /// Total events retried
    pub events_retried: u64,

    /// Total events dropped
    pub events_dropped: u64,

    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Total reconnections
    pub reconnections: u64,

    /// Current in-flight batches
    pub in_flight_batches: usize,

    /// Current queue size
    pub queue_size: usize,
}

/// Protocol error
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Message too large: {size} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { size: usize },

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Queue full: {size} events")]
    QueueFull { size: usize },

    #[error("Too many in-flight batches: {count}")]
    TooManyInFlight { count: usize },
}

/// In-flight batch awaiting acknowledgment
#[derive(Debug, Clone)]
struct InFlightBatch {
    /// Sequence number
    sequence: u64,

    /// Events in batch
    events: Vec<TelemetryEvent>,

    /// When sent
    sent_at: Instant,

    /// Retry count
    retry_count: u32,

    /// Deadline for ACK
    deadline: Instant,
}

/// Pending telemetry batch
#[derive(Debug, Clone)]
struct PendingBatch {
    /// Events in batch
    events: Vec<TelemetryEvent>,

    /// When batch was started
    started_at: Instant,
}

use super::codec::{MessageCodec, ProtocolMessage};
use super::state_machine::ProtocolState;

/// The main sans-IO protocol state machine
pub struct AgentProtocol {
    /// Current protocol state
    state: ProtocolState,

    /// Configuration
    config: ProtocolConfig,

    /// Statistics
    stats: ProtocolStats,

    /// Outgoing transmit queue
    outgoing: VecDeque<Transmit>,

    /// Event queue for application
    events: VecDeque<ProtocolEvent>,

    /// Message codec for encoding/decoding
    codec: MessageCodec,

    /// Sequence number for batches
    next_sequence: u64,

    /// In-flight batches awaiting ACK
    in_flight: HashMap<u64, InFlightBatch>,

    /// Current pending batch
    pending_batch: Option<PendingBatch>,

    /// Last heartbeat sent
    last_heartbeat_sent: Option<Instant>,

    /// Last message received from server
    last_server_message: Option<Instant>,

    /// Reconnection attempts
    reconnect_attempts: u32,

    /// Next timeout deadline
    next_timeout: Option<Instant>,

    /// Backpressure state
    backpressure_active: bool,

    /// Incomplete incoming message buffer
    incoming_buffer: Vec<u8>,
}

impl AgentProtocol {
    /// Create a new protocol instance
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            state: ProtocolState::Disconnected,
            config,
            stats: ProtocolStats::default(),
            outgoing: VecDeque::new(),
            events: VecDeque::new(),
            codec: MessageCodec::new(),
            next_sequence: 1,
            in_flight: HashMap::new(),
            pending_batch: None,
            last_heartbeat_sent: None,
            last_server_message: None,
            reconnect_attempts: 0,
            next_timeout: None,
            backpressure_active: false,
            incoming_buffer: Vec::new(),
        }
    }

    /// Poll for data that needs to be transmitted
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.outgoing.pop_front()
    }

    /// Poll for events that need to be handled
    pub fn poll_event(&mut self) -> Option<ProtocolEvent> {
        self.events.pop_front()
    }

    /// Get the next timeout deadline
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.next_timeout
    }

    /// Get current protocol state
    pub fn state(&self) -> &ProtocolState {
        &self.state
    }

    /// Get protocol statistics
    pub fn stats(&self) -> &ProtocolStats {
        &self.stats
    }

    /// Handle incoming data from server
    pub fn handle_input(&mut self, data: &[u8], now: Instant) -> Result<(), ProtocolError> {
        trace!(bytes = data.len(), "Received data from server");

        self.stats.bytes_received += data.len() as u64;
        self.last_server_message = Some(now);

        // Append to buffer
        self.incoming_buffer.extend_from_slice(data);

        // Try to decode messages
        while !self.incoming_buffer.is_empty() {
            match self.codec.decode(&self.incoming_buffer) {
                Ok(Some((message, consumed))) => {
                    // Remove consumed bytes
                    self.incoming_buffer.drain(..consumed);

                    // Handle message
                    self.handle_message(message, now)?;
                }
                Ok(None) => {
                    // Need more data
                    break;
                }
                Err(e) => {
                    error!("Failed to decode message: {}", e);

                    // Clear buffer and disconnect
                    self.incoming_buffer.clear();
                    self.transition_to_disconnected(
                        DisconnectReason::ProtocolError(e.to_string()),
                        now,
                    );

                    return Err(ProtocolError::DecodingError(e.to_string()));
                }
            }
        }

        // Update timeouts
        self.update_timeouts(now);

        Ok(())
    }

    /// Handle timeout expiration
    pub fn handle_timeout(&mut self, now: Instant) {
        trace!("Handling timeout");

        // Check heartbeat timeout (no server messages)
        if let Some(last_msg) = self.last_server_message {
            let elapsed = now.duration_since(last_msg);
            if elapsed >= self.config.heartbeat_timeout {
                warn!("Heartbeat timeout - no server message in {:?}", elapsed);
                self.transition_to_disconnected(DisconnectReason::HeartbeatTimeout, now);
                return;
            }
        }

        // Check if heartbeat needed
        if let Some(last_hb) = self.last_heartbeat_sent {
            let elapsed = now.duration_since(last_hb);
            if elapsed >= self.config.heartbeat_interval {
                self.queue_event(ProtocolEvent::HeartbeatRequired);
                self.last_heartbeat_sent = Some(now);
            }
        } else if matches!(self.state, ProtocolState::Connected) {
            // First heartbeat
            self.queue_event(ProtocolEvent::HeartbeatRequired);
            self.last_heartbeat_sent = Some(now);
        }

        // Check batch timeout
        if let Some(ref batch) = self.pending_batch {
            let elapsed = now.duration_since(batch.started_at);
            if elapsed >= self.config.batch_timeout {
                // Flush batch
                self.flush_pending_batch(now);
            }
        }

        // Check ACK timeouts
        self.check_ack_timeouts(now);

        // Update timeouts
        self.update_timeouts(now);
    }

    /// Handle connection established
    pub fn handle_connected(&mut self, now: Instant) {
        info!("Connection established");

        self.state = ProtocolState::Connected;
        self.reconnect_attempts = 0;
        self.last_server_message = Some(now);
        self.last_heartbeat_sent = None;

        self.queue_event(ProtocolEvent::Connected);

        // Schedule first heartbeat
        self.last_heartbeat_sent = Some(now);

        self.update_timeouts(now);
    }

    /// Handle connection lost
    pub fn handle_disconnected(&mut self, reason: DisconnectReason, now: Instant) {
        info!("Connection lost: {:?}", reason);

        self.transition_to_disconnected(reason, now);
    }

    /// Queue a telemetry event to be sent
    pub fn send_telemetry(
        &mut self,
        event: TelemetryEvent,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        trace!(event_type = ?event.event_type, "Queueing telemetry event");

        // Check state
        if !matches!(self.state, ProtocolState::Connected) {
            return Err(ProtocolError::InvalidStateTransition(format!(
                "Cannot send telemetry in state {:?}",
                self.state
            )));
        }

        // Check queue size
        if self.stats.queue_size >= MAX_QUEUE_SIZE {
            self.stats.events_dropped += 1;
            return Err(ProtocolError::QueueFull {
                size: self.stats.queue_size,
            });
        }

        // Add to pending batch
        if let Some(ref mut batch) = self.pending_batch {
            batch.events.push(event);
        } else {
            self.pending_batch = Some(PendingBatch {
                events: vec![event],
                started_at: now,
            });
        }

        self.stats.queue_size += 1;

        // Check if batch is full
        if let Some(ref batch) = self.pending_batch {
            if batch.events.len() >= self.config.batch_size {
                self.flush_pending_batch(now);
            }
        }

        // Check backpressure
        self.check_backpressure();

        Ok(())
    }

    /// Queue a command response
    pub fn send_command_response(
        &mut self,
        command_id: String,
        result: CommandResult,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        debug!(command_id = %command_id, success = result.success, "Sending command response");

        // Encode message
        let message = ProtocolMessage::CommandResponse {
            command_id,
            success: result.success,
            error_message: result.error_message,
            result_data: result.result_data,
            executed_at: current_timestamp_millis(),
        };

        let payload = self
            .codec
            .encode(&message)
            .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: payload.len(),
            });
        }

        self.queue_transmit(TransmitDestination::Server, payload, None, now);

        Ok(())
    }

    /// Send heartbeat
    pub fn send_heartbeat(&mut self, now: Instant) -> Result<(), ProtocolError> {
        trace!("Sending heartbeat");

        let message = ProtocolMessage::Heartbeat {
            timestamp: current_timestamp_millis(),
            stats: self.stats.clone(),
        };

        let payload = self
            .codec
            .encode(&message)
            .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

        self.queue_transmit(TransmitDestination::Server, payload, None, now);
        self.last_heartbeat_sent = Some(now);

        Ok(())
    }

    // Private methods

    fn handle_message(
        &mut self,
        message: ProtocolMessage,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match message {
            ProtocolMessage::Command(command) => {
                debug!(command_id = %command.command_id, "Received command");
                self.queue_event(ProtocolEvent::CommandReceived(command));
            }

            ProtocolMessage::ConfigUpdate(config) => {
                info!("Received config update");
                self.queue_event(ProtocolEvent::ConfigUpdated(config));
            }

            ProtocolMessage::RulesUpdate(rules) => {
                info!("Received rules update");
                self.queue_event(ProtocolEvent::RulesUpdated(rules));
            }

            ProtocolMessage::TelemetryAck { sequence, count } => {
                debug!(sequence = sequence, count = count, "Received telemetry ACK");
                self.handle_telemetry_ack(sequence, count, now);
            }

            ProtocolMessage::MlScanResult(result) => {
                info!(sha256 = %result.sha256, is_malicious = result.is_malicious, "Received ML scan result");
                self.queue_event(ProtocolEvent::MlScanResult(result));
            }

            ProtocolMessage::HeartbeatAck => {
                trace!("Received heartbeat ACK");
                // Nothing to do - just updates last_server_message
            }

            ProtocolMessage::Error { message } => {
                error!("Server error: {}", message);
                // Continue operation
            }

            _ => {
                warn!("Unhandled message type: {:?}", message);
            }
        }

        Ok(())
    }

    fn flush_pending_batch(&mut self, now: Instant) {
        if let Some(batch) = self.pending_batch.take() {
            if batch.events.is_empty() {
                return;
            }

            let sequence = self.next_sequence;
            self.next_sequence += 1;

            let count = batch.events.len();

            // Encode batch
            let message = ProtocolMessage::TelemetryBatch {
                sequence,
                events: batch.events.clone(),
                timestamp: current_timestamp_millis(),
            };

            let payload = match self.codec.encode(&message) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to encode batch: {}", e);
                    self.stats.events_dropped += count as u64;
                    self.stats.queue_size = self.stats.queue_size.saturating_sub(count);
                    return;
                }
            };

            if payload.len() > MAX_MESSAGE_SIZE {
                error!(
                    "Batch too large: {} bytes, dropping {} events",
                    payload.len(),
                    count
                );
                self.stats.events_dropped += count as u64;
                self.stats.queue_size = self.stats.queue_size.saturating_sub(count);
                return;
            }

            // Queue transmit
            self.queue_transmit(TransmitDestination::Server, payload, Some(sequence), now);

            // Track in-flight
            let deadline = now + self.config.ack_timeout;
            self.in_flight.insert(
                sequence,
                InFlightBatch {
                    sequence,
                    events: batch.events,
                    sent_at: now,
                    retry_count: 0,
                    deadline,
                },
            );

            self.stats.events_sent += count as u64;
            self.stats.in_flight_batches = self.in_flight.len();
            self.stats.queue_size = self.stats.queue_size.saturating_sub(count);
        }
    }

    fn handle_telemetry_ack(&mut self, sequence: u64, count: usize, _now: Instant) {
        if let Some(batch) = self.in_flight.remove(&sequence) {
            self.stats.events_acked += count as u64;
            self.stats.in_flight_batches = self.in_flight.len();

            debug!(
                sequence = sequence,
                count = count,
                retry_count = batch.retry_count,
                "Telemetry batch acknowledged"
            );

            self.queue_event(ProtocolEvent::TelemetryAcknowledged { sequence, count });

            // Check backpressure release
            self.check_backpressure();
        }
    }

    fn check_ack_timeouts(&mut self, now: Instant) {
        let mut timed_out = Vec::new();

        for (seq, batch) in &self.in_flight {
            if now >= batch.deadline {
                timed_out.push(*seq);
            }
        }

        for seq in timed_out {
            if let Some(mut batch) = self.in_flight.remove(&seq) {
                if batch.retry_count >= self.config.max_retries {
                    // Drop batch
                    let count = batch.events.len();
                    error!(
                        sequence = seq,
                        count = count,
                        retries = batch.retry_count,
                        "Dropping batch after max retries"
                    );
                    self.stats.events_dropped += count as u64;
                    self.stats.in_flight_batches = self.in_flight.len();
                } else {
                    // Retry batch
                    batch.retry_count += 1;
                    warn!(
                        sequence = seq,
                        count = batch.events.len(),
                        retry = batch.retry_count,
                        max_retries = self.config.max_retries,
                        "Retrying batch"
                    );

                    // Re-encode and send
                    let message = ProtocolMessage::TelemetryBatch {
                        sequence: seq,
                        events: batch.events.clone(),
                        timestamp: current_timestamp_millis(),
                    };

                    if let Ok(payload) = self.codec.encode(&message) {
                        self.queue_transmit(TransmitDestination::Server, payload, Some(seq), now);
                    }

                    // Update deadline with exponential backoff
                    let backoff = self.config.ack_timeout * 2u32.pow(batch.retry_count);
                    batch.sent_at = now;
                    batch.deadline = now + backoff;

                    // Re-insert
                    self.in_flight.insert(seq, batch);

                    self.stats.events_retried += 1;
                }
            }
        }

        self.stats.in_flight_batches = self.in_flight.len();
    }

    fn check_backpressure(&mut self) {
        let threshold = MAX_IN_FLIGHT / 2;

        if !self.backpressure_active && self.in_flight.len() >= MAX_IN_FLIGHT {
            self.backpressure_active = true;
            warn!(in_flight = self.in_flight.len(), "Backpressure applied");
            self.queue_event(ProtocolEvent::BackpressureApplied {
                queue_size: self.stats.queue_size,
            });
        } else if self.backpressure_active && self.in_flight.len() <= threshold {
            self.backpressure_active = false;
            info!("Backpressure released");
            self.queue_event(ProtocolEvent::BackpressureReleased);
        }
    }

    fn queue_transmit(
        &mut self,
        destination: TransmitDestination,
        payload: Vec<u8>,
        sequence: Option<u64>,
        now: Instant,
    ) {
        self.stats.bytes_sent += payload.len() as u64;

        self.outgoing.push_back(Transmit {
            destination,
            payload,
            created_at: now,
            sequence,
        });
    }

    fn queue_event(&mut self, event: ProtocolEvent) {
        self.events.push_back(event);
    }

    fn transition_to_disconnected(&mut self, reason: DisconnectReason, now: Instant) {
        if matches!(self.state, ProtocolState::Disconnected) {
            return;
        }

        self.state = ProtocolState::Disconnected;
        self.queue_event(ProtocolEvent::Disconnected {
            reason: reason.clone(),
        });

        // Calculate reconnect delay
        let delay = self.calculate_reconnect_delay();
        self.reconnect_attempts += 1;

        if self.config.max_reconnect_attempts > 0
            && self.reconnect_attempts >= self.config.max_reconnect_attempts
        {
            error!(
                attempts = self.reconnect_attempts,
                "Max reconnect attempts reached, giving up"
            );
            return;
        }

        info!(
            delay_secs = delay.as_secs(),
            attempt = self.reconnect_attempts,
            "Scheduling reconnection"
        );

        self.queue_event(ProtocolEvent::ReconnectRequired { delay });
        self.stats.reconnections += 1;

        self.update_timeouts(now);
    }

    fn calculate_reconnect_delay(&self) -> Duration {
        let backoff = self.config.reconnect_delay_base * 2u32.pow(self.reconnect_attempts.min(6));
        backoff.min(self.config.reconnect_delay_max)
    }

    fn update_timeouts(&mut self, _now: Instant) {
        let mut next_timeout: Option<Instant> = None;

        // Heartbeat timeout
        if matches!(self.state, ProtocolState::Connected) {
            if let Some(last_msg) = self.last_server_message {
                let deadline = last_msg + self.config.heartbeat_timeout;
                next_timeout = Some(deadline);
            }

            // Heartbeat send
            if let Some(last_hb) = self.last_heartbeat_sent {
                let deadline = last_hb + self.config.heartbeat_interval;
                next_timeout = Some(match next_timeout {
                    Some(t) => t.min(deadline),
                    None => deadline,
                });
            }
        }

        // Batch timeout
        if let Some(ref batch) = self.pending_batch {
            let deadline = batch.started_at + self.config.batch_timeout;
            next_timeout = Some(match next_timeout {
                Some(t) => t.min(deadline),
                None => deadline,
            });
        }

        // ACK timeouts
        for batch in self.in_flight.values() {
            next_timeout = Some(match next_timeout {
                Some(t) => t.min(batch.deadline),
                None => batch.deadline,
            });
        }

        self.next_timeout = next_timeout;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::{EventPayload, EventType, Severity};

    #[test]
    fn test_protocol_creation() {
        let config = ProtocolConfig::default();
        let protocol = AgentProtocol::new(config);

        assert!(matches!(protocol.state(), &ProtocolState::Disconnected));
        assert_eq!(protocol.stats().events_sent, 0);
    }

    #[test]
    fn test_connection_lifecycle() {
        let config = ProtocolConfig::default();
        let mut protocol = AgentProtocol::new(config);
        let now = Instant::now();

        // Connect
        protocol.handle_connected(now);
        assert!(matches!(protocol.state(), &ProtocolState::Connected));

        // Should emit Connected event
        if let Some(ProtocolEvent::Connected) = protocol.poll_event() {
            // OK
        } else {
            panic!("Expected Connected event");
        }

        // Disconnect
        protocol.handle_disconnected(DisconnectReason::Clean, now);
        assert!(matches!(protocol.state(), &ProtocolState::Disconnected));
    }

    #[test]
    fn reconnect_backoff_is_capped_and_resets_after_successful_connect() {
        let config = ProtocolConfig {
            reconnect_delay_base: Duration::from_secs(1),
            reconnect_delay_max: Duration::from_secs(8),
            max_reconnect_attempts: 0,
            ..ProtocolConfig::default()
        };
        let mut protocol = AgentProtocol::new(config);
        let now = Instant::now();

        for (attempt, seconds) in [1, 2, 4, 8, 8].into_iter().enumerate() {
            protocol.reconnect_attempts = attempt as u32;
            assert_eq!(
                protocol.calculate_reconnect_delay(),
                Duration::from_secs(seconds)
            );
        }

        protocol.reconnect_attempts = 5;
        protocol.handle_connected(now);

        assert_eq!(protocol.reconnect_attempts, 0);
        assert!(matches!(
            protocol.poll_event(),
            Some(ProtocolEvent::Connected)
        ));
    }

    #[test]
    fn heartbeat_timeout_disconnects_and_schedules_reconnect() {
        let config = ProtocolConfig {
            heartbeat_timeout: Duration::from_secs(5),
            reconnect_delay_base: Duration::from_secs(1),
            ..ProtocolConfig::default()
        };
        let mut protocol = AgentProtocol::new(config);
        let now = Instant::now();

        protocol.handle_connected(now);
        assert!(matches!(
            protocol.poll_event(),
            Some(ProtocolEvent::Connected)
        ));

        protocol.handle_timeout(now + Duration::from_secs(6));

        assert!(matches!(protocol.state(), &ProtocolState::Disconnected));
        assert!(matches!(
            protocol.poll_event(),
            Some(ProtocolEvent::Disconnected {
                reason: DisconnectReason::HeartbeatTimeout
            })
        ));
        assert!(matches!(
            protocol.poll_event(),
            Some(ProtocolEvent::ReconnectRequired { .. })
        ));
    }

    #[test]
    fn telemetry_ack_timeout_retries_then_drops_after_max_retries() {
        let config = ProtocolConfig {
            batch_size: 1,
            ack_timeout: Duration::from_millis(10),
            max_retries: 1,
            ..ProtocolConfig::default()
        };
        let mut protocol = AgentProtocol::new(config);
        let now = Instant::now();

        protocol.handle_connected(now);
        let _ = protocol.poll_event();

        protocol
            .send_telemetry(test_event("network_connect"), now)
            .expect("telemetry should queue");
        assert_eq!(protocol.stats().events_sent, 1);
        assert_eq!(protocol.stats().in_flight_batches, 1);
        assert!(protocol.poll_transmit().is_some());

        protocol.handle_timeout(now + Duration::from_millis(11));
        assert_eq!(protocol.stats().events_retried, 1);
        assert_eq!(protocol.stats().events_dropped, 0);
        assert_eq!(protocol.stats().in_flight_batches, 1);
        assert!(protocol.poll_transmit().is_some());

        protocol.handle_timeout(now + Duration::from_millis(40));
        assert_eq!(protocol.stats().events_dropped, 1);
        assert_eq!(protocol.stats().in_flight_batches, 0);
    }

    fn test_event(kind: &str) -> TelemetryEvent {
        TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::NetworkConnect,
            timestamp: current_timestamp_millis(),
            severity: Severity::Info,
            payload: EventPayload::Generic(serde_json::json!({ "kind": kind })),
            detections: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }
}
