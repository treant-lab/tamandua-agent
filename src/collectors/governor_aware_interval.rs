//! Governor-aware interval wrapper
//!
//! Provides a drop-in replacement for `tokio::time::interval` that automatically
//! adjusts sleep duration based on resource pressure from the ResourceGovernor.
//!
//! # Usage
//!
//! Instead of:
//! ```ignore
//! let mut interval = tokio::time::interval(Duration::from_millis(5000));
//! interval.tick().await;
//! ```
//!
//! Use:
//! ```ignore
//! let mut interval = GovernorAwareInterval::new(
//!     Duration::from_millis(5000),
//!     governor_handle.clone(),
//! );
//! interval.tick().await;
//! ```
//!
//! When resource pressure increases, the interval automatically becomes longer:
//! - No pressure: 5000ms (1x)
//! - Light: 10000ms (2x)
//! - Moderate: 20000ms (4x)
//! - Heavy: 40000ms (8x)
//! - Critical: 80000ms (16x)

use crate::resource_governor::GovernorHandle;
use std::time::Duration;
use tokio::time::Interval;
use tracing::debug;

/// Wrapper around tokio::time::Interval that applies pressure-based multipliers
pub struct GovernorAwareInterval {
    /// Base interval duration (when no pressure)
    base_duration_ms: u64,
    /// Underlying tokio interval (created once at init)
    interval: Interval,
    /// Handle to read current pressure level
    governor_handle: Option<GovernorHandle>,
    /// Last used multiplier (for logging)
    last_multiplier: f32,
}

impl GovernorAwareInterval {
    /// Create a new governor-aware interval
    ///
    /// The actual sleep time will be `base_duration * pressure.multiplier()`
    pub fn new(base_duration: Duration, governor_handle: Option<GovernorHandle>) -> Self {
        let base_duration_ms = base_duration.as_millis() as u64;

        // Create interval with base duration (will be adjusted by pressure later)
        let interval = tokio::time::interval(base_duration);

        Self {
            base_duration_ms,
            interval,
            governor_handle,
            last_multiplier: 1.0,
        }
    }

    /// Wait for the next tick, respecting resource pressure
    ///
    /// Returns immediately if this is the first call (initializes the interval).
    /// Subsequent calls sleep for `base_duration * pressure.multiplier()`.
    pub async fn tick(&mut self) {
        // First tick of a tokio::Interval returns immediately
        self.interval.tick().await;

        // If we have a governor handle, check pressure and sleep accordingly
        if let Some(ref gov) = self.governor_handle {
            let multiplier = gov.interval_multiplier();

            // If multiplier changed, recalculate actual sleep time
            if multiplier != self.last_multiplier {
                let actual_duration_ms = (self.base_duration_ms as f32 * multiplier) as u64;

                // Schedule the next tick
                self.interval = tokio::time::interval(Duration::from_millis(actual_duration_ms));
                self.last_multiplier = multiplier;

                debug!(
                    base_ms = self.base_duration_ms,
                    multiplier = format!("{:.1}x", multiplier),
                    actual_ms = actual_duration_ms,
                    "Governor pressure adjusted collector interval"
                );
            }
        }
    }

    /// Get the effective interval duration in milliseconds
    pub fn effective_duration_ms(&self) -> u64 {
        if let Some(ref gov) = self.governor_handle {
            let multiplier = gov.interval_multiplier();
            (self.base_duration_ms as f32 * multiplier) as u64
        } else {
            self.base_duration_ms
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_governor_aware_interval_no_governor() {
        let interval = GovernorAwareInterval::new(Duration::from_millis(100), None);
        assert_eq!(interval.effective_duration_ms(), 100);
    }

    #[tokio::test]
    async fn test_effective_duration_calculation() {
        // Without governor, should return base duration
        let mut interval = GovernorAwareInterval::new(Duration::from_millis(5000), None);
        assert_eq!(interval.effective_duration_ms(), 5000);

        // First tick returns immediately
        interval.tick().await;

        // Effective duration should still be 5000 (no pressure)
        assert_eq!(interval.effective_duration_ms(), 5000);
    }
}
