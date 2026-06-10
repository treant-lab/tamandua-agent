//! Throttling and backpressure enforcement for collectors.

use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Throttle Actions
// ---------------------------------------------------------------------------

/// Action to take when a collector exceeds its budget.
#[derive(Debug, Clone, PartialEq)]
pub enum ThrottleAction {
    /// No action, collector is within budget.
    None,

    /// Apply throttling: introduce a delay before next operation.
    Throttle {
        /// How long to delay
        delay: Duration,
    },

    /// Pause the collector for a duration.
    /// The collector should stop processing until resumed.
    Pause {
        /// How long to pause
        duration: Duration,
    },
}

// ---------------------------------------------------------------------------
// Throttler State
// ---------------------------------------------------------------------------

/// Internal state of the throttler.
#[derive(Debug)]
struct ThrottlerState {
    /// Current throttle delay (if any)
    current_delay: Option<Duration>,
    /// Whether the collector is paused
    is_paused: bool,
    /// When the pause will end (if paused)
    pause_until: Option<Instant>,
    /// Total number of throttle events
    throttle_count: u64,
    /// Total number of pause events
    pause_count: u64,
    /// Last action applied
    last_action: ThrottleAction,
}

impl Default for ThrottlerState {
    fn default() -> Self {
        Self {
            current_delay: None,
            is_paused: false,
            pause_until: None,
            throttle_count: 0,
            pause_count: 0,
            last_action: ThrottleAction::None,
        }
    }
}

// ---------------------------------------------------------------------------
// Throttler
// ---------------------------------------------------------------------------

/// Throttler for a single collector.
///
/// Collectors use this to check if they should delay or pause their work.
pub struct CollectorThrottler {
    /// Collector name (for logging)
    name: String,
    /// Current throttle state
    state: Arc<RwLock<ThrottlerState>>,
    /// Notify handle for resume signaling
    resume_notify: Arc<Notify>,
}

impl CollectorThrottler {
    /// Create a new throttler.
    pub fn new(name: String) -> Self {
        Self {
            name,
            state: Arc::new(RwLock::new(ThrottlerState::default())),
            resume_notify: Arc::new(Notify::new()),
        }
    }

    /// Apply a throttle action.
    ///
    /// Called by the ResourceManager when budget checks indicate throttling
    /// or pausing is needed.
    pub fn apply_action(&self, action: ThrottleAction) {
        let mut state = self.state.write();

        // Ignore redundant actions
        if action == state.last_action {
            return;
        }

        match action {
            ThrottleAction::None => {
                // Clear any active throttling/pausing
                if state.current_delay.is_some() || state.is_paused {
                    debug!(
                        collector = %self.name,
                        "Resource usage back within budget - clearing throttle"
                    );
                    state.current_delay = None;
                    state.is_paused = false;
                    state.pause_until = None;
                    self.resume_notify.notify_waiters();
                }
            }

            ThrottleAction::Throttle { delay } => {
                state.current_delay = Some(delay);
                state.throttle_count += 1;

                // If we were paused, unpause (throttle is lighter than pause)
                if state.is_paused {
                    state.is_paused = false;
                    state.pause_until = None;
                    self.resume_notify.notify_waiters();
                }

                if state.throttle_count % 10 == 0 {
                    // Log every 10th throttle to reduce spam
                    debug!(
                        collector = %self.name,
                        delay_ms = delay.as_millis(),
                        count = state.throttle_count,
                        "Collector throttled due to budget overrun"
                    );
                }
            }

            ThrottleAction::Pause { duration } => {
                state.is_paused = true;
                state.pause_until = Some(Instant::now() + duration);
                state.current_delay = None; // Clear throttle when pausing
                state.pause_count += 1;

                warn!(
                    collector = %self.name,
                    duration_ms = duration.as_millis(),
                    count = state.pause_count,
                    "Collector PAUSED due to critical budget overrun"
                );
            }
        }

        state.last_action = action;
    }

    /// Check if the collector should throttle (delay before next operation).
    ///
    /// Returns:
    /// - `Some(Duration)`: Delay for this duration before proceeding.
    /// - `None`: No throttling needed.
    ///
    /// Example:
    /// ```rust,ignore
    /// if let Some(delay) = throttler.should_throttle() {
    ///     tokio::time::sleep(delay).await;
    /// }
    /// ```
    pub fn should_throttle(&self) -> Option<Duration> {
        let state = self.state.read();
        state.current_delay
    }

    /// Check if the collector is paused.
    pub fn is_paused(&self) -> bool {
        let mut state = self.state.write();

        // Check if pause has expired
        if let Some(until) = state.pause_until {
            if Instant::now() >= until {
                // Pause expired, resume
                debug!(
                    collector = %self.name,
                    "Pause duration expired - resuming collector"
                );
                state.is_paused = false;
                state.pause_until = None;
                self.resume_notify.notify_waiters();
                return false;
            }
        }

        state.is_paused
    }

    /// Wait for the collector to be resumed (if paused).
    ///
    /// This is an async function that blocks until the throttler is unpaused.
    ///
    /// Example:
    /// ```rust,ignore
    /// if throttler.is_paused() {
    ///     throttler.wait_for_resume().await;
    /// }
    /// ```
    pub async fn wait_for_resume(&self) {
        // Check if we're actually paused
        if !self.is_paused() {
            return;
        }

        // Calculate how long to wait
        let wait_duration = {
            let state = self.state.read();
            if let Some(until) = state.pause_until {
                let now = Instant::now();
                if until > now {
                    until - now
                } else {
                    return; // Already expired
                }
            } else {
                return; // Not paused
            }
        };

        // Wait with timeout (in case pause_until changes)
        tokio::select! {
            _ = tokio::time::sleep(wait_duration) => {
                // Timeout expired, clear pause
                let mut state = self.state.write();
                state.is_paused = false;
                state.pause_until = None;
            }
            _ = self.resume_notify.notified() => {
                // Explicitly resumed by manager
            }
        }
    }

    /// Get throttling statistics.
    pub fn stats(&self) -> ThrottlerStats {
        let state = self.state.read();
        ThrottlerStats {
            throttle_count: state.throttle_count,
            pause_count: state.pause_count,
            is_throttled: state.current_delay.is_some(),
            is_paused: state.is_paused,
            current_delay_ms: state.current_delay.map(|d| d.as_millis() as u64),
        }
    }

    /// Reset all throttling (for testing).
    #[cfg(test)]
    pub fn reset(&self) {
        let mut state = self.state.write();
        *state = ThrottlerState::default();
        self.resume_notify.notify_waiters();
    }
}

/// Throttling statistics for a collector.
#[derive(Debug, Clone)]
pub struct ThrottlerStats {
    /// Total number of throttle events
    pub throttle_count: u64,
    /// Total number of pause events
    pub pause_count: u64,
    /// Whether currently throttled
    pub is_throttled: bool,
    /// Whether currently paused
    pub is_paused: bool,
    /// Current throttle delay in milliseconds (if throttled)
    pub current_delay_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_throttler_none() {
        let throttler = CollectorThrottler::new("test".to_string());
        assert!(!throttler.is_paused());
        assert!(throttler.should_throttle().is_none());
    }

    #[test]
    fn test_throttler_throttle() {
        let throttler = CollectorThrottler::new("test".to_string());
        throttler.apply_action(ThrottleAction::Throttle {
            delay: Duration::from_millis(100),
        });

        assert!(!throttler.is_paused());
        assert_eq!(
            throttler.should_throttle(),
            Some(Duration::from_millis(100))
        );

        let stats = throttler.stats();
        assert_eq!(stats.throttle_count, 1);
        assert!(stats.is_throttled);
    }

    #[test]
    fn test_throttler_pause() {
        let throttler = CollectorThrottler::new("test".to_string());
        throttler.apply_action(ThrottleAction::Pause {
            duration: Duration::from_millis(100),
        });

        assert!(throttler.is_paused());
        let stats = throttler.stats();
        assert_eq!(stats.pause_count, 1);
        assert!(stats.is_paused);
    }

    #[test]
    fn test_throttler_pause_expiry() {
        let throttler = CollectorThrottler::new("test".to_string());
        throttler.apply_action(ThrottleAction::Pause {
            duration: Duration::from_millis(50),
        });

        assert!(throttler.is_paused());

        // Wait for pause to expire
        std::thread::sleep(Duration::from_millis(100));

        // Check should clear the pause
        assert!(!throttler.is_paused());
    }

    #[test]
    fn test_throttler_resume() {
        let throttler = CollectorThrottler::new("test".to_string());
        throttler.apply_action(ThrottleAction::Pause {
            duration: Duration::from_secs(10),
        });

        assert!(throttler.is_paused());

        // Resume by clearing throttle
        throttler.apply_action(ThrottleAction::None);
        assert!(!throttler.is_paused());
    }

    #[tokio::test]
    async fn test_wait_for_resume() {
        let throttler = Arc::new(CollectorThrottler::new("test".to_string()));
        throttler.apply_action(ThrottleAction::Pause {
            duration: Duration::from_millis(100),
        });

        let throttler_clone = Arc::clone(&throttler);
        let start = Instant::now();

        // Wait in background
        let wait_task = tokio::spawn(async move {
            throttler_clone.wait_for_resume().await;
        });

        // Wait should complete after ~100ms
        wait_task.await.unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(80)); // Allow for timing variance
        assert!(elapsed < Duration::from_millis(200));
    }
}
