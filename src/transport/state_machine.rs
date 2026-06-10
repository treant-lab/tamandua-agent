//! Protocol State Machine
//!
//! This module defines the protocol state machine for the Tamandua Agent transport.
//! States are pure and transitions are explicit, making the protocol behavior
//! deterministic and testable.
//!
//! # State Diagram
//!
//! ```text
//!     ┌──────────────┐
//!     │              │
//!     │ Disconnected │ ◄───────────┐
//!     │              │             │
//!     └──────┬───────┘             │
//!            │                     │
//!            │ connect()           │
//!            │                     │
//!            v                     │
//!     ┌──────────────┐             │
//!     │              │             │
//!     │  Connecting  │             │
//!     │              │             │
//!     └──────┬───────┘             │
//!            │                     │
//!            │ connected()         │
//!            │                     │
//!            v                     │
//!     ┌──────────────┐             │
//!     │              │  error()    │
//!     │  Connected   ├─────────────┤
//!     │              │  timeout()  │
//!     └──────┬───────┘  close()    │
//!            │                     │
//!            │ disconnect()        │
//!            │                     │
//!            v                     │
//!     ┌──────────────┐             │
//!     │              │             │
//!     │ Reconnecting ├─────────────┘
//!     │              │
//!     └──────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

/// Protocol states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolState {
    /// Not connected
    Disconnected,

    /// Attempting initial connection
    Connecting,

    /// Connected and operational
    Connected,

    /// Reconnecting after disconnect
    Reconnecting,

    /// Shutting down gracefully
    ShuttingDown,

    /// Terminal error state
    Failed,
}

impl fmt::Display for ProtocolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolState::Disconnected => write!(f, "Disconnected"),
            ProtocolState::Connecting => write!(f, "Connecting"),
            ProtocolState::Connected => write!(f, "Connected"),
            ProtocolState::Reconnecting => write!(f, "Reconnecting"),
            ProtocolState::ShuttingDown => write!(f, "ShuttingDown"),
            ProtocolState::Failed => write!(f, "Failed"),
        }
    }
}

/// State transition event
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTransition {
    /// Initiate connection
    Connect,

    /// Connection established
    Connected,

    /// Connection lost
    Disconnected,

    /// Error occurred
    Error(String),

    /// Timeout expired
    Timeout,

    /// Shutdown requested
    Shutdown,

    /// Retry connection
    Retry,
}

impl ProtocolState {
    /// Check if a transition is valid from this state
    pub fn can_transition_to(&self, next: ProtocolState) -> bool {
        use ProtocolState::*;

        match (*self, next) {
            // Disconnected can transition to Connecting or Failed
            (Disconnected, Connecting) => true,
            (Disconnected, Failed) => true,

            // Connecting can transition to Connected, Reconnecting, or Disconnected
            (Connecting, Connected) => true,
            (Connecting, Reconnecting) => true,
            (Connecting, Disconnected) => true,

            // Connected can transition to Disconnected, Reconnecting, or ShuttingDown
            (Connected, Disconnected) => true,
            (Connected, Reconnecting) => true,
            (Connected, ShuttingDown) => true,

            // Reconnecting can transition to Connecting, Disconnected, or Failed
            (Reconnecting, Connecting) => true,
            (Reconnecting, Disconnected) => true,
            (Reconnecting, Failed) => true,

            // ShuttingDown can only transition to Disconnected
            (ShuttingDown, Disconnected) => true,

            // Failed is terminal
            (Failed, _) => false,

            // Any state can stay in itself
            (a, b) if a == b => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    /// Apply a state transition event
    pub fn apply_transition(
        &self,
        event: StateTransition,
    ) -> Result<ProtocolState, StateTransitionError> {
        use ProtocolState as PS;
        use StateTransition as ST;

        let next_state = match (self, event.clone()) {
            // Connect event from Disconnected
            (PS::Disconnected, ST::Connect) => PS::Connecting,

            // Connected event from Connecting
            (PS::Connecting, ST::Connected) => PS::Connected,

            // Disconnected event from any active state
            (PS::Connecting, ST::Disconnected) | (PS::Connected, ST::Disconnected) => {
                PS::Reconnecting
            }
            (PS::Reconnecting, ST::Disconnected) => PS::Disconnected,

            // Retry from Reconnecting
            (PS::Reconnecting, ST::Retry) => PS::Connecting,

            // Error events
            (PS::Connecting, ST::Error(_)) => PS::Reconnecting,
            (PS::Connected, ST::Error(_)) => PS::Reconnecting,
            (PS::Reconnecting, ST::Error(_)) => PS::Disconnected,

            // Timeout events
            (PS::Connecting, ST::Timeout) => PS::Reconnecting,
            (PS::Connected, ST::Timeout) => PS::Reconnecting,

            // Shutdown events
            (PS::Connected, ST::Shutdown) | (PS::Connecting, ST::Shutdown) => PS::ShuttingDown,
            (PS::ShuttingDown, ST::Disconnected) => PS::Disconnected,

            // Already in target state (no-op)
            (state, _) if *state == PS::Disconnected && matches!(event, ST::Disconnected) => {
                PS::Disconnected
            }

            // Invalid transitions
            (state, event) => {
                return Err(StateTransitionError::InvalidTransition {
                    from: *state,
                    event,
                });
            }
        };

        // Verify transition is valid
        if self.can_transition_to(next_state) {
            Ok(next_state)
        } else {
            Err(StateTransitionError::InvalidTransition {
                from: *self,
                event: StateTransition::Connect, // Placeholder
            })
        }
    }

    /// Check if this state allows sending telemetry
    pub fn can_send_telemetry(&self) -> bool {
        matches!(self, ProtocolState::Connected)
    }

    /// Check if this state allows receiving commands
    pub fn can_receive_commands(&self) -> bool {
        matches!(self, ProtocolState::Connected)
    }

    /// Check if this state is in an error/failed condition
    pub fn is_error_state(&self) -> bool {
        matches!(self, ProtocolState::Failed)
    }

    /// Check if currently connected
    pub fn is_connected(&self) -> bool {
        matches!(self, ProtocolState::Connected)
    }

    /// Check if disconnected
    pub fn is_disconnected(&self) -> bool {
        matches!(self, ProtocolState::Disconnected)
    }
}

/// State transition error
#[derive(Debug, Clone, thiserror::Error)]
pub enum StateTransitionError {
    #[error("Invalid state transition from {from} on event {event:?}")]
    InvalidTransition {
        from: ProtocolState,
        event: StateTransition,
    },

    #[error("Operation not allowed in state {state}")]
    OperationNotAllowed { state: ProtocolState },
}

/// State machine with history and timing
#[derive(Debug, Clone)]
pub struct StateMachine {
    /// Current state
    current: ProtocolState,

    /// Previous state
    previous: Option<ProtocolState>,

    /// State entered at
    entered_at: Instant,

    /// Duration in current state
    #[allow(dead_code)]
    state_duration: Duration,

    /// Total state transitions
    total_transitions: u64,

    /// History of recent transitions (last N)
    history: Vec<StateHistoryEntry>,

    /// Max history entries
    max_history: usize,
}

/// State history entry
#[derive(Debug, Clone)]
pub struct StateHistoryEntry {
    /// From state
    pub from: ProtocolState,

    /// To state
    pub to: ProtocolState,

    /// Transition event
    pub event: StateTransition,

    /// When transition occurred
    pub timestamp: Instant,

    /// Duration in previous state
    pub duration: Duration,
}

impl StateMachine {
    /// Create a new state machine
    pub fn new(initial: ProtocolState, now: Instant) -> Self {
        Self {
            current: initial,
            previous: None,
            entered_at: now,
            state_duration: Duration::ZERO,
            total_transitions: 0,
            history: Vec::new(),
            max_history: 100,
        }
    }

    /// Get current state
    pub fn current(&self) -> ProtocolState {
        self.current
    }

    /// Get previous state
    pub fn previous(&self) -> Option<ProtocolState> {
        self.previous
    }

    /// Get duration in current state
    pub fn state_duration(&self, now: Instant) -> Duration {
        now.duration_since(self.entered_at)
    }

    /// Transition to a new state
    pub fn transition(
        &mut self,
        event: StateTransition,
        now: Instant,
    ) -> Result<ProtocolState, StateTransitionError> {
        let next_state = self.current.apply_transition(event.clone())?;

        if next_state != self.current {
            let duration = now.duration_since(self.entered_at);

            // Record history
            let entry = StateHistoryEntry {
                from: self.current,
                to: next_state,
                event,
                timestamp: now,
                duration,
            };

            self.history.push(entry);
            if self.history.len() > self.max_history {
                self.history.remove(0);
            }

            // Update state
            self.previous = Some(self.current);
            self.current = next_state;
            self.entered_at = now;
            self.total_transitions += 1;
        }

        Ok(next_state)
    }

    /// Get state history
    pub fn history(&self) -> &[StateHistoryEntry] {
        &self.history
    }

    /// Get total transitions
    pub fn total_transitions(&self) -> u64 {
        self.total_transitions
    }

    /// Count transitions in a time window
    pub fn count_transitions_in_window(&self, window: Duration, now: Instant) -> usize {
        let cutoff = now.checked_sub(window).unwrap_or(now);

        self.history
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .count()
    }

    /// Check for rapid cycling (too many transitions in short time)
    pub fn is_rapid_cycling(&self, threshold: usize, window: Duration, now: Instant) -> bool {
        self.count_transitions_in_window(window, now) >= threshold
    }
}

/// Timeout configuration per state
#[derive(Debug, Clone)]
pub struct StateTimeouts {
    /// Timeout in Connecting state
    pub connecting_timeout: Duration,

    /// Timeout in Connected state (heartbeat)
    pub connected_timeout: Duration,

    /// Timeout in Reconnecting state
    pub reconnecting_timeout: Duration,

    /// Timeout in ShuttingDown state
    pub shutdown_timeout: Duration,
}

impl Default for StateTimeouts {
    fn default() -> Self {
        Self {
            connecting_timeout: Duration::from_secs(30),
            connected_timeout: Duration::from_secs(120),
            reconnecting_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}

impl StateTimeouts {
    /// Get timeout for a given state
    pub fn timeout_for_state(&self, state: ProtocolState) -> Option<Duration> {
        match state {
            ProtocolState::Connecting => Some(self.connecting_timeout),
            ProtocolState::Connected => Some(self.connected_timeout),
            ProtocolState::Reconnecting => Some(self.reconnecting_timeout),
            ProtocolState::ShuttingDown => Some(self.shutdown_timeout),
            ProtocolState::Disconnected | ProtocolState::Failed => None,
        }
    }

    /// Check if state has timed out
    pub fn is_timed_out(&self, state: ProtocolState, duration: Duration) -> bool {
        if let Some(timeout) = self.timeout_for_state(state) {
            duration >= timeout
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        let state = ProtocolState::Disconnected;
        assert!(state.can_transition_to(ProtocolState::Connecting));

        let state = ProtocolState::Connecting;
        assert!(state.can_transition_to(ProtocolState::Connected));

        let state = ProtocolState::Connected;
        assert!(state.can_transition_to(ProtocolState::Disconnected));
    }

    #[test]
    fn test_invalid_transitions() {
        let state = ProtocolState::Disconnected;
        assert!(!state.can_transition_to(ProtocolState::Connected));

        let state = ProtocolState::Failed;
        assert!(!state.can_transition_to(ProtocolState::Connected));
    }

    #[test]
    fn test_state_machine_transitions() {
        let now = Instant::now();
        let mut sm = StateMachine::new(ProtocolState::Disconnected, now);

        assert_eq!(sm.current(), ProtocolState::Disconnected);

        // Connect
        let result = sm.transition(StateTransition::Connect, now);
        assert!(result.is_ok());
        assert_eq!(sm.current(), ProtocolState::Connecting);

        // Connected
        let result = sm.transition(StateTransition::Connected, now);
        assert!(result.is_ok());
        assert_eq!(sm.current(), ProtocolState::Connected);

        assert_eq!(sm.total_transitions(), 2);
    }

    #[test]
    fn test_state_capabilities() {
        let state = ProtocolState::Connected;
        assert!(state.can_send_telemetry());
        assert!(state.can_receive_commands());

        let state = ProtocolState::Disconnected;
        assert!(!state.can_send_telemetry());
        assert!(!state.can_receive_commands());
    }

    #[test]
    fn test_rapid_cycling_detection() {
        let now = Instant::now();
        let mut sm = StateMachine::new(ProtocolState::Disconnected, now);

        // Simulate rapid state changes
        for i in 0..10 {
            let t = now + Duration::from_millis(i * 100);
            let _ = sm.transition(StateTransition::Connect, t);
            let _ = sm.transition(StateTransition::Connected, t);
            let _ = sm.transition(StateTransition::Disconnected, t);
        }

        let window = Duration::from_secs(5);
        assert!(sm.is_rapid_cycling(10, window, now + Duration::from_secs(1)));
    }

    #[test]
    fn test_state_timeouts() {
        let timeouts = StateTimeouts::default();

        assert!(timeouts
            .timeout_for_state(ProtocolState::Connecting)
            .is_some());
        assert!(timeouts
            .timeout_for_state(ProtocolState::Disconnected)
            .is_none());

        let duration = Duration::from_secs(31);
        assert!(timeouts.is_timed_out(ProtocolState::Connecting, duration));
    }
}
