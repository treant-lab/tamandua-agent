//! Canary rollout implementation for staged agent updates.
//!
//! Updates progress through stages: Canary (5%) -> Early (25%) -> General (100%)
//! Each agent deterministically belongs to a rollout bucket based on agent_id hash.

use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{debug, info};

/// Canary rollout stages with their target percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryStage {
    /// Initial canary: 5% of agents
    Canary,
    /// Early adopters: 25% of agents
    Early,
    /// General availability: 100% of agents
    General,
    /// Rollout paused due to issues
    Paused,
    /// Rolled back to previous version
    RolledBack,
}

impl CanaryStage {
    /// Get the rollout percentage for this stage.
    pub fn percentage(&self) -> f32 {
        match self {
            Self::Canary => 5.0,
            Self::Early => 25.0,
            Self::General => 100.0,
            Self::Paused | Self::RolledBack => 0.0,
        }
    }

    /// Minimum soak time before advancing to next stage.
    pub fn min_soak_duration(&self) -> Duration {
        match self {
            Self::Canary => Duration::from_secs(3600), // 1 hour
            Self::Early => Duration::from_secs(7200),  // 2 hours
            Self::General => Duration::from_secs(0),   // No soak needed
            Self::Paused | Self::RolledBack => Duration::from_secs(u64::MAX),
        }
    }

    /// Next stage in progression.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Canary => Some(Self::Early),
            Self::Early => Some(Self::General),
            Self::General | Self::Paused | Self::RolledBack => None,
        }
    }

    /// Get stage name as string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Canary => "canary",
            Self::Early => "early",
            Self::General => "general",
            Self::Paused => "paused",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// Canary rollout configuration.
#[derive(Debug, Clone)]
pub struct CanaryConfig {
    /// Maximum failure rate (0.0-1.0) before triggering rollback.
    pub max_failure_rate: f32,
    /// Minimum successful reports before advancing stage.
    pub min_success_count: u32,
    /// Window for failure rate calculation.
    pub failure_window: Duration,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            max_failure_rate: 0.05,                    // 5% failure rate triggers rollback
            min_success_count: 10,                     // Need 10 successes before advancing
            failure_window: Duration::from_secs(1800), // 30 minute window
        }
    }
}

/// Determine if this agent should update based on rollout percentage.
///
/// Uses deterministic hashing of agent_id + version to ensure consistent
/// bucket assignment across restarts.
pub fn should_update(agent_id: &str, version: &str, rollout_percentage: f32) -> bool {
    if rollout_percentage >= 100.0 {
        return true;
    }
    if rollout_percentage <= 0.0 {
        return false;
    }

    // Hash agent_id + version for deterministic bucket
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(b":");
    hasher.update(version.as_bytes());
    let hash = hasher.finalize();

    // Use first 4 bytes as u32, mod 10000 for 0.01% precision
    let bucket = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 10000;
    let threshold = (rollout_percentage * 100.0) as u32;

    let should = bucket < threshold;
    debug!(
        agent_id = %agent_id,
        version = %version,
        bucket = bucket,
        threshold = threshold,
        rollout_percentage = rollout_percentage,
        should_update = should,
        "Canary rollout decision"
    );

    should
}

/// Agent-side rollout state tracking.
#[derive(Debug, Clone)]
pub struct AgentRolloutState {
    pub current_version: String,
    pub target_version: Option<String>,
    pub update_attempted_at: Option<std::time::Instant>,
    pub update_success: Option<bool>,
    pub consecutive_failures: u32,
}

impl AgentRolloutState {
    pub fn new(current_version: &str) -> Self {
        Self {
            current_version: current_version.to_string(),
            target_version: None,
            update_attempted_at: None,
            update_success: None,
            consecutive_failures: 0,
        }
    }

    /// Record update attempt.
    pub fn record_attempt(&mut self, target_version: &str) {
        self.target_version = Some(target_version.to_string());
        self.update_attempted_at = Some(std::time::Instant::now());
        info!(
            current_version = %self.current_version,
            target_version = %target_version,
            "Recording update attempt"
        );
    }

    /// Record update outcome.
    pub fn record_outcome(&mut self, success: bool) {
        self.update_success = Some(success);
        if success {
            self.consecutive_failures = 0;
            info!(
                target_version = ?self.target_version,
                "Update completed successfully"
            );
        } else {
            self.consecutive_failures += 1;
            info!(
                target_version = ?self.target_version,
                consecutive_failures = self.consecutive_failures,
                "Update failed"
            );
        }
    }

    /// Should we skip updates due to repeated failures?
    pub fn should_skip_updates(&self) -> bool {
        self.consecutive_failures >= 3
    }

    /// Get time since last update attempt.
    pub fn time_since_attempt(&self) -> Option<Duration> {
        self.update_attempted_at.map(|t| t.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_update_100_percent() {
        assert!(should_update("agent-1", "1.0.0", 100.0));
        assert!(should_update("agent-2", "1.0.0", 100.0));
        assert!(should_update("any-agent", "any-version", 100.0));
    }

    #[test]
    fn test_should_update_0_percent() {
        assert!(!should_update("agent-1", "1.0.0", 0.0));
        assert!(!should_update("agent-2", "1.0.0", 0.0));
        assert!(!should_update("any-agent", "any-version", 0.0));
    }

    #[test]
    fn test_should_update_deterministic() {
        // Same agent_id + version should always return same result
        let result1 = should_update("test-agent", "2.0.0", 50.0);
        let result2 = should_update("test-agent", "2.0.0", 50.0);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_should_update_distribution() {
        // With 50% rollout, roughly half should update
        let mut update_count = 0;
        for i in 0..1000 {
            if should_update(&format!("agent-{}", i), "1.0.0", 50.0) {
                update_count += 1;
            }
        }
        // Allow 10% tolerance (400-600 out of 1000)
        assert!(
            update_count >= 400 && update_count <= 600,
            "Expected ~500 agents to update, got {}",
            update_count
        );
    }

    #[test]
    fn test_canary_stage_progression() {
        assert_eq!(CanaryStage::Canary.next(), Some(CanaryStage::Early));
        assert_eq!(CanaryStage::Early.next(), Some(CanaryStage::General));
        assert_eq!(CanaryStage::General.next(), None);
        assert_eq!(CanaryStage::Paused.next(), None);
        assert_eq!(CanaryStage::RolledBack.next(), None);
    }

    #[test]
    fn test_canary_stage_percentages() {
        assert!((CanaryStage::Canary.percentage() - 5.0).abs() < f32::EPSILON);
        assert!((CanaryStage::Early.percentage() - 25.0).abs() < f32::EPSILON);
        assert!((CanaryStage::General.percentage() - 100.0).abs() < f32::EPSILON);
        assert!((CanaryStage::Paused.percentage() - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_agent_rollout_state() {
        let mut state = AgentRolloutState::new("1.0.0");
        assert!(!state.should_skip_updates());

        state.record_attempt("2.0.0");
        assert!(state.target_version.is_some());

        // Record 3 failures
        state.record_outcome(false);
        state.record_outcome(false);
        assert!(!state.should_skip_updates());
        state.record_outcome(false);
        assert!(state.should_skip_updates());

        // Success resets counter
        state.record_outcome(true);
        assert!(!state.should_skip_updates());
    }
}
