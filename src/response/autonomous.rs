//! Autonomous Response Engine
//!
//! Enables the agent to take immediate response actions at machine speed
//! without waiting for server commands. Detections flowing through the
//! analysis pipeline are evaluated against a set of local response rules,
//! and matching actions (kill, quarantine, isolate, block, forensics) are
//! executed immediately on-agent.
//!
//! ## Design
//!
//! - Rules are evaluated in priority order (lowest number = highest priority).
//! - All conditions within a rule use AND logic: every specified field must match.
//! - Rate limiting (max actions per hour) and cooldown (per-rule per-process) prevent
//!   runaway response loops.
//! - Four hardcoded default rules cover the most critical attack scenarios:
//!     1. Ransomware auto-kill + quarantine + isolate
//!     2. Critical process injection kill
//!     3. Credential theft (LSASS) kill + forensics
//!     4. C2 network block
//! - The server can push updated rules via `load_rules()`, which replaces
//!   custom rules while preserving the built-in defaults.
//! - All executed actions are logged to a bounded ring buffer for server sync.

// Autonomous response engine. Scaffolded rule fields and helpers retained
// for upcoming server-pushed rule expansions.
#![allow(dead_code, unused_variables)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;

// ---------------------------------------------------------------------------
// Rule configuration types
// ---------------------------------------------------------------------------

/// A local response rule evaluated entirely on-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousResponseRule {
    /// Unique rule identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Whether this rule is currently active.
    pub enabled: bool,
    /// Evaluation priority (lower = evaluated first).
    pub priority: u32,

    /// Conditions that must ALL match for the rule to fire.
    pub conditions: RuleConditions,

    /// Actions to execute when the rule fires.
    pub actions: Vec<ResponseAction>,

    /// Maximum number of actions this rule may fire per rolling hour.
    pub max_actions_per_hour: u32,
    /// Cooldown in seconds: suppress re-triggering the same rule for the
    /// same process (by PID) within this window.
    pub cooldown_seconds: u64,
}

/// Conditions for an autonomous response rule (AND logic: all specified
/// fields must match).  `None` fields are treated as "don't care".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConditions {
    /// Minimum severity: "critical", "high", "medium", "low".
    /// The detection severity must be >= this level.
    pub min_severity: Option<String>,
    /// Minimum threat score (0.0 - 1.0).
    pub min_threat_score: Option<f64>,
    /// Match if ANY of these MITRE ATT&CK technique IDs appear.
    /// Supports prefix matching: "T1055" matches "T1055.001", "T1055.012", etc.
    pub mitre_techniques: Option<Vec<String>>,
    /// Match if ANY of these MITRE ATT&CK tactics appear (case-insensitive).
    pub mitre_tactics: Option<Vec<String>>,
    /// Match if the event type string equals any of these.
    pub event_types: Option<Vec<String>>,
    /// Match if the process name equals any of these (case-insensitive).
    pub process_names: Option<Vec<String>>,
    /// Match if any of these detection types produced the detection.
    /// Values: "sigma", "yara", "ml", "behavioral", "ioc", etc.
    pub detection_types: Option<Vec<String>>,
}

/// An action the autonomous engine can execute.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Terminate the offending process.
    KillProcess,
    /// Move the offending file to quarantine.
    QuarantineFile,
    /// Apply full network isolation (WFP/nftables), keeping only
    /// the management channel alive.
    IsolateNetwork,
    /// Block a specific IP address at the host firewall.
    BlockIP { ip: String },
    /// Block DNS resolution for a specific domain.
    BlockDomain { domain: String },
    /// Collect forensic artifacts (memory dump + disk artifacts).
    CollectForensics,
    /// Snapshot affected registry keys for later analysis.
    SnapshotRegistry,
}

impl std::fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseAction::KillProcess => write!(f, "kill_process"),
            ResponseAction::QuarantineFile => write!(f, "quarantine_file"),
            ResponseAction::IsolateNetwork => write!(f, "isolate_network"),
            ResponseAction::BlockIP { ip } => write!(f, "block_ip({})", ip),
            ResponseAction::BlockDomain { domain } => write!(f, "block_domain({})", domain),
            ResponseAction::CollectForensics => write!(f, "collect_forensics"),
            ResponseAction::SnapshotRegistry => write!(f, "snapshot_registry"),
        }
    }
}

// ---------------------------------------------------------------------------
// Detection result (input from the analysis pipeline)
// ---------------------------------------------------------------------------

/// Summarized detection information passed from the analysis pipeline to
/// the autonomous response engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Unique event identifier from the telemetry event.
    pub event_id: String,
    /// Event type (e.g., "process_create", "file_execute").
    pub event_type: String,
    /// Severity string: "critical", "high", "medium", "low", "info".
    pub severity: String,
    /// Aggregate threat score (0.0 - 1.0).
    pub threat_score: f64,
    /// MITRE ATT&CK tactics observed.
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK technique IDs observed.
    pub mitre_techniques: Vec<String>,
    /// Detection engines that fired (e.g., "sigma", "yara", "ml").
    pub detection_types: Vec<String>,
    /// Name of the offending process (if applicable).
    pub process_name: Option<String>,
    /// PID of the offending process (if applicable).
    pub process_pid: Option<u32>,
    /// Path to the offending file (if applicable).
    pub file_path: Option<String>,
    /// Source IP address (network events).
    pub source_ip: Option<String>,
    /// Destination IP address (network events).
    pub dest_ip: Option<String>,
    /// Destination domain (DNS / network events).
    pub domain: Option<String>,
}

// ---------------------------------------------------------------------------
// Pending action (output from evaluation)
// ---------------------------------------------------------------------------

/// An action approved by the engine, ready for execution.
#[derive(Debug, Clone)]
pub struct PendingAction {
    /// The rule that triggered this action.
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// The detection that matched.
    pub detection_event_id: String,
    /// The action to execute.
    pub action: ResponseAction,
    /// PID to target (if relevant).
    pub target_pid: Option<u32>,
    /// File path to target (if relevant).
    pub target_file: Option<String>,
    /// IP to target (if relevant).
    pub target_ip: Option<String>,
    /// Domain to target (if relevant).
    pub target_domain: Option<String>,
}

// ---------------------------------------------------------------------------
// Action log entry (for server sync)
// ---------------------------------------------------------------------------

/// Record of an action executed by the autonomous engine, queued for
/// synchronization with the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogEntry {
    /// When the action was executed.
    pub timestamp: DateTime<Utc>,
    /// The rule that triggered the action.
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// The detection event that triggered the action.
    pub detection_event_id: String,
    /// The action that was executed.
    pub action: ResponseAction,
    /// Whether the action succeeded.
    pub success: bool,
    /// Error message (if the action failed).
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Cooldown key
// ---------------------------------------------------------------------------

/// Composite key for cooldown tracking: (rule_id, process_pid).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CooldownKey {
    rule_id: String,
    process_pid: u32,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of entries retained in the action log ring buffer.
const MAX_ACTION_LOG_SIZE: usize = 1000;

/// One hour in seconds, used for rate-limit window resets.
const RATE_LIMIT_WINDOW_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

/// Map a severity string to a numeric rank for comparison.
/// Higher rank = more severe.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" => 0,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Autonomous Response Engine
// ---------------------------------------------------------------------------

/// The main autonomous response engine.
///
/// Holds the rule set, rate-limit counters, cooldown timers, and an
/// action log ring buffer.  All state is in-memory; rule configuration
/// can be pushed from the server.
pub struct AutonomousResponseEngine {
    /// Active rules, sorted by priority (ascending).
    rules: Vec<AutonomousResponseRule>,
    /// Bounded ring buffer of recently executed actions.
    action_log: VecDeque<ActionLogEntry>,
    /// Per-rule rate-limit counters: rule_id -> (count, window_start).
    action_counts: HashMap<String, (u32, Instant)>,
    /// Per-(rule, pid) cooldown tracking: key -> last_fired_at.
    cooldowns: HashMap<CooldownKey, Instant>,
    /// Master enable switch.
    enabled: bool,
}

impl AutonomousResponseEngine {
    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Create a new engine seeded with default rules and optional config
    /// overrides.
    pub fn new(config: &AgentConfig) -> Self {
        let mut rules = Self::default_rules();

        // The engine is enabled by default.  A future `AgentConfig` field
        // (e.g. `autonomous_response_enabled`) could disable it.
        let enabled = true;

        // Sort rules by priority (lowest number first).
        rules.sort_by_key(|r| r.priority);

        info!(
            rule_count = rules.len(),
            enabled = enabled,
            "Autonomous response engine initialized"
        );

        Self {
            rules,
            action_log: VecDeque::with_capacity(MAX_ACTION_LOG_SIZE),
            action_counts: HashMap::new(),
            cooldowns: HashMap::new(),
            enabled,
        }
    }

    // -----------------------------------------------------------------
    // Rule management
    // -----------------------------------------------------------------

    /// Replace custom rules with a new set pushed from the server.
    /// Built-in default rules (prefixed with `builtin_`) are always
    /// preserved; the caller cannot remove them, only disable them.
    pub fn load_rules(&mut self, mut rules: Vec<AutonomousResponseRule>) {
        // Retain built-in rules from the current set.
        let mut merged: Vec<AutonomousResponseRule> = self
            .rules
            .iter()
            .filter(|r| r.id.starts_with("builtin_"))
            .cloned()
            .collect();

        // Check if any incoming rule overrides a built-in rule's enabled state.
        for incoming in &rules {
            if incoming.id.starts_with("builtin_") {
                if let Some(existing) = merged.iter_mut().find(|r| r.id == incoming.id) {
                    existing.enabled = incoming.enabled;
                    // Also allow overriding rate limits and cooldown.
                    existing.max_actions_per_hour = incoming.max_actions_per_hour;
                    existing.cooldown_seconds = incoming.cooldown_seconds;
                }
            }
        }

        // Append non-builtin incoming rules.
        for rule in rules.drain(..) {
            if !rule.id.starts_with("builtin_") {
                merged.push(rule);
            }
        }

        merged.sort_by_key(|r| r.priority);

        info!(
            rule_count = merged.len(),
            builtin = merged
                .iter()
                .filter(|r| r.id.starts_with("builtin_"))
                .count(),
            custom = merged
                .iter()
                .filter(|r| !r.id.starts_with("builtin_"))
                .count(),
            "Autonomous response rules updated"
        );

        self.rules = merged;
    }

    /// Return a snapshot of the current rule set (for diagnostics / API).
    pub fn rules(&self) -> &[AutonomousResponseRule] {
        &self.rules
    }

    // -----------------------------------------------------------------
    // Detection evaluation
    // -----------------------------------------------------------------

    /// Evaluate a detection against all enabled rules and return the list
    /// of actions to execute.
    ///
    /// Rules are evaluated in priority order.  Rate limits and cooldowns
    /// are checked before an action is approved.
    pub fn evaluate_detection(&mut self, detection: &DetectionResult) -> Vec<PendingAction> {
        if !self.enabled {
            return Vec::new();
        }

        let mut pending: Vec<PendingAction> = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // ---- Condition matching (AND logic) ----
            if !Self::matches_conditions(&rule.conditions, detection) {
                continue;
            }

            // ---- Rate limiting ----
            if self.is_rate_limited(&rule.id, rule.max_actions_per_hour) {
                debug!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "Rate limit reached, skipping rule"
                );
                continue;
            }

            // ---- Cooldown (per rule + per PID) ----
            if let Some(pid) = detection.process_pid {
                if self.is_on_cooldown(&rule.id, pid, rule.cooldown_seconds) {
                    debug!(
                        rule_id = %rule.id,
                        rule_name = %rule.name,
                        pid = pid,
                        cooldown_secs = rule.cooldown_seconds,
                        "Cooldown active, skipping rule for this process"
                    );
                    continue;
                }
            }

            // ---- Build pending actions ----
            info!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                event_id = %detection.event_id,
                severity = %detection.severity,
                threat_score = detection.threat_score,
                "Autonomous rule matched"
            );

            for action in &rule.actions {
                // For BlockIP / BlockDomain, substitute the detection's values.
                let resolved_action = self.resolve_action(action, detection);

                pending.push(PendingAction {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    detection_event_id: detection.event_id.clone(),
                    action: resolved_action,
                    target_pid: detection.process_pid,
                    target_file: detection.file_path.clone(),
                    target_ip: detection.dest_ip.clone(),
                    target_domain: detection.domain.clone(),
                });
            }
        }

        if !pending.is_empty() {
            info!(
                action_count = pending.len(),
                event_id = %detection.event_id,
                "Autonomous response actions queued"
            );
        }

        pending
    }

    // -----------------------------------------------------------------
    // Action recording
    // -----------------------------------------------------------------

    /// Record that an action was executed (or failed).  Updates the rate
    /// limiter, cooldown timers, and action log.
    pub fn record_action(
        &mut self,
        rule_id: &str,
        action: &ResponseAction,
        success: bool,
        detection_event_id: &str,
        target_pid: Option<u32>,
        error_msg: Option<String>,
    ) {
        let now = Instant::now();

        // Update rate-limit counter.
        let entry = self
            .action_counts
            .entry(rule_id.to_string())
            .or_insert((0, now));

        // Reset window if expired.
        if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            *entry = (0, now);
        }
        entry.0 += 1;

        // Update cooldown.
        if let Some(pid) = target_pid {
            let key = CooldownKey {
                rule_id: rule_id.to_string(),
                process_pid: pid,
            };
            self.cooldowns.insert(key, now);
        }

        // Find rule name from the rule set.
        let rule_name = self
            .rules
            .iter()
            .find(|r| r.id == rule_id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| rule_id.to_string());

        let log_entry = ActionLogEntry {
            timestamp: Utc::now(),
            rule_id: rule_id.to_string(),
            rule_name,
            detection_event_id: detection_event_id.to_string(),
            action: action.clone(),
            success,
            error: error_msg,
        };

        if success {
            info!(
                rule_id = %log_entry.rule_id,
                action = %log_entry.action,
                event_id = %log_entry.detection_event_id,
                "Autonomous action executed successfully"
            );
        } else {
            warn!(
                rule_id = %log_entry.rule_id,
                action = %log_entry.action,
                event_id = %log_entry.detection_event_id,
                error = ?log_entry.error,
                "Autonomous action failed"
            );
        }

        // Append to bounded ring buffer.
        if self.action_log.len() >= MAX_ACTION_LOG_SIZE {
            self.action_log.pop_front();
        }
        self.action_log.push_back(log_entry);
    }

    // -----------------------------------------------------------------
    // Action log retrieval (for server sync)
    // -----------------------------------------------------------------

    /// Return a copy of the recent action log.
    pub fn get_action_log(&self) -> Vec<ActionLogEntry> {
        self.action_log.iter().cloned().collect()
    }

    /// Drain (take and remove) action log entries accumulated since the
    /// last sync.  Useful for batch-uploading to the server.
    pub fn drain_action_log(&mut self) -> Vec<ActionLogEntry> {
        self.action_log.drain(..).collect()
    }

    // -----------------------------------------------------------------
    // Enable / disable
    // -----------------------------------------------------------------

    /// Whether the engine is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the engine at runtime.
    pub fn set_enabled(&mut self, enabled: bool) {
        if self.enabled != enabled {
            info!(enabled = enabled, "Autonomous response engine toggled");
        }
        self.enabled = enabled;
    }

    // -----------------------------------------------------------------
    // Internal: condition matching
    // -----------------------------------------------------------------

    /// Check whether a detection satisfies ALL conditions of a rule.
    fn matches_conditions(conditions: &RuleConditions, detection: &DetectionResult) -> bool {
        // -- min_severity --
        if let Some(ref min_sev) = conditions.min_severity {
            if severity_rank(&detection.severity) < severity_rank(min_sev) {
                return false;
            }
        }

        // -- min_threat_score --
        if let Some(min_score) = conditions.min_threat_score {
            if detection.threat_score < min_score {
                return false;
            }
        }

        // -- mitre_techniques (ANY match, with prefix support) --
        if let Some(ref techniques) = conditions.mitre_techniques {
            if !techniques.is_empty() {
                let matched = detection.mitre_techniques.iter().any(|det_tech| {
                    techniques.iter().any(|rule_tech| {
                        // Exact match or prefix match (e.g., "T1055" matches "T1055.001")
                        det_tech == rule_tech || det_tech.starts_with(&format!("{}.", rule_tech))
                    })
                });
                if !matched {
                    return false;
                }
            }
        }

        // -- mitre_tactics (ANY match, case-insensitive) --
        if let Some(ref tactics) = conditions.mitre_tactics {
            if !tactics.is_empty() {
                let matched = detection.mitre_tactics.iter().any(|det_tac| {
                    tactics
                        .iter()
                        .any(|rule_tac| det_tac.eq_ignore_ascii_case(rule_tac))
                });
                if !matched {
                    return false;
                }
            }
        }

        // -- event_types (ANY match) --
        if let Some(ref event_types) = conditions.event_types {
            if !event_types.is_empty()
                && !event_types
                    .iter()
                    .any(|et| et.eq_ignore_ascii_case(&detection.event_type))
            {
                return false;
            }
        }

        // -- process_names (ANY match, case-insensitive) --
        if let Some(ref process_names) = conditions.process_names {
            if !process_names.is_empty() {
                match &detection.process_name {
                    Some(pname) => {
                        if !process_names
                            .iter()
                            .any(|rn| pname.eq_ignore_ascii_case(rn))
                        {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
        }

        // -- detection_types (ANY match, case-insensitive) --
        if let Some(ref detection_types) = conditions.detection_types {
            if !detection_types.is_empty() {
                let matched = detection.detection_types.iter().any(|dt| {
                    detection_types
                        .iter()
                        .any(|rdt| dt.eq_ignore_ascii_case(rdt))
                });
                if !matched {
                    return false;
                }
            }
        }

        true
    }

    // -----------------------------------------------------------------
    // Internal: rate limiting
    // -----------------------------------------------------------------

    /// Returns `true` if the rule has exceeded its max_actions_per_hour.
    fn is_rate_limited(&self, rule_id: &str, max_per_hour: u32) -> bool {
        if max_per_hour == 0 {
            // 0 means unlimited.
            return false;
        }

        if let Some((count, window_start)) = self.action_counts.get(rule_id) {
            let elapsed = Instant::now().duration_since(*window_start).as_secs();
            if elapsed < RATE_LIMIT_WINDOW_SECS {
                return *count >= max_per_hour;
            }
            // Window expired -- not rate limited.
        }

        false
    }

    // -----------------------------------------------------------------
    // Internal: cooldown
    // -----------------------------------------------------------------

    /// Returns `true` if the (rule, pid) pair is still within the cooldown window.
    fn is_on_cooldown(&self, rule_id: &str, pid: u32, cooldown_secs: u64) -> bool {
        if cooldown_secs == 0 {
            return false;
        }

        let key = CooldownKey {
            rule_id: rule_id.to_string(),
            process_pid: pid,
        };

        if let Some(last_fired) = self.cooldowns.get(&key) {
            return Instant::now().duration_since(*last_fired).as_secs() < cooldown_secs;
        }

        false
    }

    // -----------------------------------------------------------------
    // Internal: action resolution
    // -----------------------------------------------------------------

    /// Resolve template actions (BlockIP / BlockDomain) by substituting
    /// values from the detection result.
    fn resolve_action(
        &self,
        action: &ResponseAction,
        detection: &DetectionResult,
    ) -> ResponseAction {
        match action {
            ResponseAction::BlockIP { ip } if ip.is_empty() || ip == "$dest_ip" => {
                // Substitute detection's dest_ip.
                ResponseAction::BlockIP {
                    ip: detection
                        .dest_ip
                        .clone()
                        .unwrap_or_else(|| "0.0.0.0".to_string()),
                }
            }
            ResponseAction::BlockDomain { domain } if domain.is_empty() || domain == "$domain" => {
                // Substitute detection's domain.
                ResponseAction::BlockDomain {
                    domain: detection
                        .domain
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                }
            }
            other => other.clone(),
        }
    }

    // -----------------------------------------------------------------
    // Default (built-in) rules
    // -----------------------------------------------------------------

    /// Hardcoded default rules that cover the highest-impact attack scenarios.
    fn default_rules() -> Vec<AutonomousResponseRule> {
        vec![
            // ---- 1. Ransomware Auto-Kill ----
            // T1486 = Data Encrypted for Impact.
            // Threat score >= 0.8 required to reduce false positives.
            AutonomousResponseRule {
                id: "builtin_ransomware_autokill".to_string(),
                name: "Ransomware Auto-Kill".to_string(),
                enabled: true,
                priority: 10,
                conditions: RuleConditions {
                    min_severity: None,
                    min_threat_score: Some(0.8),
                    mitre_techniques: Some(vec!["T1486".to_string()]),
                    mitre_tactics: None,
                    event_types: None,
                    process_names: None,
                    detection_types: None,
                },
                actions: vec![
                    ResponseAction::KillProcess,
                    ResponseAction::QuarantineFile,
                    ResponseAction::IsolateNetwork,
                ],
                max_actions_per_hour: 50,
                cooldown_seconds: 30,
            },
            // ---- 2. Critical Injection Kill ----
            // T1055.* = Process Injection (all sub-techniques).
            // Only fires at critical severity.
            AutonomousResponseRule {
                id: "builtin_critical_injection_kill".to_string(),
                name: "Critical Injection Kill".to_string(),
                enabled: true,
                priority: 20,
                conditions: RuleConditions {
                    min_severity: Some("critical".to_string()),
                    min_threat_score: None,
                    mitre_techniques: Some(vec!["T1055".to_string()]),
                    mitre_tactics: None,
                    event_types: None,
                    process_names: None,
                    detection_types: None,
                },
                actions: vec![ResponseAction::KillProcess],
                max_actions_per_hour: 100,
                cooldown_seconds: 15,
            },
            // ---- 3. Credential Theft Block (LSASS protection) ----
            // T1003.* = OS Credential Dumping.
            // Only fires when the target process is LSASS.
            AutonomousResponseRule {
                id: "builtin_credential_theft_block".to_string(),
                name: "Credential Theft Block".to_string(),
                enabled: true,
                priority: 15,
                conditions: RuleConditions {
                    min_severity: None,
                    min_threat_score: None,
                    mitre_techniques: Some(vec!["T1003".to_string()]),
                    mitre_tactics: None,
                    event_types: None,
                    process_names: Some(vec!["lsass.exe".to_string(), "lsass".to_string()]),
                    detection_types: None,
                },
                actions: vec![
                    ResponseAction::KillProcess,
                    ResponseAction::CollectForensics,
                ],
                max_actions_per_hour: 30,
                cooldown_seconds: 60,
            },
            // ---- 4. C2 Network Block ----
            // T1071.* = Application Layer Protocol (C2 comms).
            // Requires very high threat score to avoid blocking legitimate traffic.
            AutonomousResponseRule {
                id: "builtin_c2_network_block".to_string(),
                name: "C2 Network Block".to_string(),
                enabled: true,
                priority: 25,
                conditions: RuleConditions {
                    min_severity: None,
                    min_threat_score: Some(0.9),
                    mitre_techniques: Some(vec!["T1071".to_string()]),
                    mitre_tactics: None,
                    event_types: None,
                    process_names: None,
                    detection_types: None,
                },
                actions: vec![
                    ResponseAction::BlockIP {
                        ip: "$dest_ip".to_string(),
                    },
                    ResponseAction::BlockDomain {
                        domain: "$domain".to_string(),
                    },
                ],
                max_actions_per_hour: 200,
                cooldown_seconds: 10,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal AgentConfig for test construction.
    fn test_config() -> AgentConfig {
        AgentConfig::default()
    }

    /// Helper: create a basic DetectionResult.
    fn base_detection() -> DetectionResult {
        DetectionResult {
            event_id: "evt-001".to_string(),
            event_type: "process_create".to_string(),
            severity: "medium".to_string(),
            threat_score: 0.5,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            detection_types: vec!["sigma".to_string()],
            process_name: Some("malware.exe".to_string()),
            process_pid: Some(1234),
            file_path: Some("C:\\temp\\malware.exe".to_string()),
            source_ip: None,
            dest_ip: None,
            domain: None,
        }
    }

    // -------------------------------------------------------------------
    // Construction and defaults
    // -------------------------------------------------------------------

    #[test]
    fn test_engine_has_default_rules() {
        let engine = AutonomousResponseEngine::new(&test_config());
        assert!(engine.is_enabled());
        assert_eq!(engine.rules().len(), 4);

        // Verify all default rule IDs.
        let ids: Vec<&str> = engine.rules().iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"builtin_ransomware_autokill"));
        assert!(ids.contains(&"builtin_critical_injection_kill"));
        assert!(ids.contains(&"builtin_credential_theft_block"));
        assert!(ids.contains(&"builtin_c2_network_block"));
    }

    #[test]
    fn test_rules_sorted_by_priority() {
        let engine = AutonomousResponseEngine::new(&test_config());
        let priorities: Vec<u32> = engine.rules().iter().map(|r| r.priority).collect();
        let mut sorted = priorities.clone();
        sorted.sort();
        assert_eq!(priorities, sorted);
    }

    // -------------------------------------------------------------------
    // Severity ranking
    // -------------------------------------------------------------------

    #[test]
    fn test_severity_rank() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("info"));
        assert_eq!(severity_rank("unknown"), 0);
    }

    // -------------------------------------------------------------------
    // Condition matching
    // -------------------------------------------------------------------

    #[test]
    fn test_no_conditions_always_matches() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: None,
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: None,
        };
        let det = base_detection();
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_severity_condition() {
        let conditions = RuleConditions {
            min_severity: Some("high".to_string()),
            min_threat_score: None,
            mitre_techniques: None,
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: None,
        };

        // Medium < High => should NOT match.
        let mut det = base_detection();
        det.severity = "medium".to_string();
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // High == High => should match.
        det.severity = "high".to_string();
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // Critical > High => should match.
        det.severity = "critical".to_string();
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_threat_score_condition() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: Some(0.8),
            mitre_techniques: None,
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: None,
        };

        let mut det = base_detection();
        det.threat_score = 0.7;
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.threat_score = 0.8;
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.threat_score = 0.95;
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_mitre_technique_exact_match() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: Some(vec!["T1486".to_string()]),
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: None,
        };

        let mut det = base_detection();
        det.mitre_techniques = vec!["T1486".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.mitre_techniques = vec!["T1059".to_string()];
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_mitre_technique_prefix_match() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: Some(vec!["T1055".to_string()]),
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: None,
        };

        let mut det = base_detection();

        // T1055.001 should match T1055 prefix.
        det.mitre_techniques = vec!["T1055.001".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // T1055.012 should also match.
        det.mitre_techniques = vec!["T1055.012".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // T10550 should NOT match (no dot separator).
        det.mitre_techniques = vec!["T10550".to_string()];
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_mitre_tactic_match_case_insensitive() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: None,
            mitre_tactics: Some(vec!["Impact".to_string()]),
            event_types: None,
            process_names: None,
            detection_types: None,
        };

        let mut det = base_detection();
        det.mitre_tactics = vec!["impact".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.mitre_tactics = vec!["IMPACT".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.mitre_tactics = vec!["Execution".to_string()];
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_process_name_match_case_insensitive() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: None,
            mitre_tactics: None,
            event_types: None,
            process_names: Some(vec!["lsass.exe".to_string()]),
            detection_types: None,
        };

        let mut det = base_detection();
        det.process_name = Some("LSASS.EXE".to_string());
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.process_name = Some("lsass.exe".to_string());
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.process_name = Some("svchost.exe".to_string());
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // No process name at all => should NOT match.
        det.process_name = None;
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_event_type_match() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: None,
            mitre_tactics: None,
            event_types: Some(vec![
                "process_create".to_string(),
                "file_execute".to_string(),
            ]),
            process_names: None,
            detection_types: None,
        };

        let mut det = base_detection();
        det.event_type = "process_create".to_string();
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.event_type = "file_execute".to_string();
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.event_type = "network_connect".to_string();
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_detection_type_match() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: None,
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: Some(vec!["yara".to_string(), "ml".to_string()]),
        };

        let mut det = base_detection();
        det.detection_types = vec!["sigma".to_string()];
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.detection_types = vec!["yara".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        det.detection_types = vec!["sigma".to_string(), "ml".to_string()];
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    #[test]
    fn test_combined_conditions_and_logic() {
        // This rule requires BOTH T1486 AND threat_score >= 0.8.
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: Some(0.8),
            mitre_techniques: Some(vec!["T1486".to_string()]),
            mitre_tactics: None,
            event_types: None,
            process_names: None,
            detection_types: None,
        };

        let mut det = base_detection();

        // Technique matches but score too low => no match.
        det.mitre_techniques = vec!["T1486".to_string()];
        det.threat_score = 0.5;
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // Score OK but wrong technique => no match.
        det.mitre_techniques = vec!["T1059".to_string()];
        det.threat_score = 0.9;
        assert!(!AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));

        // Both match => match.
        det.mitre_techniques = vec!["T1486".to_string()];
        det.threat_score = 0.85;
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }

    // -------------------------------------------------------------------
    // Rule evaluation (full engine)
    // -------------------------------------------------------------------

    #[test]
    fn test_ransomware_rule_fires() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        let det = DetectionResult {
            event_id: "evt-ransom-001".to_string(),
            event_type: "file_modify".to_string(),
            severity: "critical".to_string(),
            threat_score: 0.95,
            mitre_tactics: vec!["Impact".to_string()],
            mitre_techniques: vec!["T1486".to_string()],
            detection_types: vec!["behavioral".to_string()],
            process_name: Some("ransomware.exe".to_string()),
            process_pid: Some(5678),
            file_path: Some("C:\\Users\\victim\\Documents\\important.docx".to_string()),
            source_ip: None,
            dest_ip: None,
            domain: None,
        };

        let actions = engine.evaluate_detection(&det);
        assert_eq!(actions.len(), 3);

        let action_types: Vec<&ResponseAction> = actions.iter().map(|a| &a.action).collect();
        assert!(action_types.contains(&&ResponseAction::KillProcess));
        assert!(action_types.contains(&&ResponseAction::QuarantineFile));
        assert!(action_types.contains(&&ResponseAction::IsolateNetwork));

        // All actions should reference the ransomware rule.
        for a in &actions {
            assert_eq!(a.rule_id, "builtin_ransomware_autokill");
        }
    }

    #[test]
    fn test_injection_rule_requires_critical() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // High severity + T1055.001 => should NOT fire (requires critical).
        let mut det = base_detection();
        det.mitre_techniques = vec!["T1055.001".to_string()];
        det.severity = "high".to_string();

        let actions = engine.evaluate_detection(&det);
        assert!(actions.is_empty());

        // Critical severity + T1055.001 => should fire.
        det.severity = "critical".to_string();
        let actions = engine.evaluate_detection(&det);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, ResponseAction::KillProcess);
        assert_eq!(actions[0].rule_id, "builtin_critical_injection_kill");
    }

    #[test]
    fn test_credential_theft_rule_requires_lsass() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // T1003.001 but process is NOT lsass => should NOT fire.
        let mut det = base_detection();
        det.mitre_techniques = vec!["T1003.001".to_string()];
        det.process_name = Some("svchost.exe".to_string());

        let actions = engine.evaluate_detection(&det);
        assert!(actions.is_empty());

        // T1003.001 and process IS lsass => should fire.
        det.process_name = Some("lsass.exe".to_string());
        let actions = engine.evaluate_detection(&det);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].rule_id, "builtin_credential_theft_block");
    }

    #[test]
    fn test_c2_rule_resolves_ip_and_domain() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        let det = DetectionResult {
            event_id: "evt-c2-001".to_string(),
            event_type: "network_connect".to_string(),
            severity: "high".to_string(),
            threat_score: 0.95,
            mitre_tactics: vec!["Command and Control".to_string()],
            mitre_techniques: vec!["T1071.001".to_string()],
            detection_types: vec!["sigma".to_string()],
            process_name: Some("beacon.exe".to_string()),
            process_pid: Some(9999),
            file_path: None,
            source_ip: Some("192.168.1.100".to_string()),
            dest_ip: Some("45.33.32.156".to_string()),
            domain: Some("evil-c2.example.com".to_string()),
        };

        let actions = engine.evaluate_detection(&det);
        assert_eq!(actions.len(), 2);

        // Verify IP was resolved.
        assert_eq!(
            actions[0].action,
            ResponseAction::BlockIP {
                ip: "45.33.32.156".to_string()
            }
        );
        // Verify domain was resolved.
        assert_eq!(
            actions[1].action,
            ResponseAction::BlockDomain {
                domain: "evil-c2.example.com".to_string()
            }
        );
    }

    #[test]
    fn test_no_match_for_benign_detection() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // Low severity, low score, no matching techniques.
        let det = DetectionResult {
            event_id: "evt-benign-001".to_string(),
            event_type: "process_create".to_string(),
            severity: "low".to_string(),
            threat_score: 0.1,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            detection_types: vec!["sigma".to_string()],
            process_name: Some("notepad.exe".to_string()),
            process_pid: Some(100),
            file_path: Some("C:\\Windows\\notepad.exe".to_string()),
            source_ip: None,
            dest_ip: None,
            domain: None,
        };

        let actions = engine.evaluate_detection(&det);
        assert!(actions.is_empty());
    }

    // -------------------------------------------------------------------
    // Rate limiting
    // -------------------------------------------------------------------

    #[test]
    fn test_rate_limiting() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // The credential theft rule has max_actions_per_hour = 30.
        let det = DetectionResult {
            event_id: "evt-cred".to_string(),
            event_type: "credential_access".to_string(),
            severity: "high".to_string(),
            threat_score: 0.85,
            mitre_tactics: vec!["Credential Access".to_string()],
            mitre_techniques: vec!["T1003.001".to_string()],
            detection_types: vec!["behavioral".to_string()],
            process_name: Some("lsass.exe".to_string()),
            process_pid: None, // No PID so cooldown won't block us.
            file_path: None,
            source_ip: None,
            dest_ip: None,
            domain: None,
        };

        // Record 30 actions against the credential theft rule.
        for i in 0..30 {
            engine.record_action(
                "builtin_credential_theft_block",
                &ResponseAction::KillProcess,
                true,
                &format!("evt-{}", i),
                None,
                None,
            );
        }

        // The 31st attempt should be rate-limited.
        let actions = engine.evaluate_detection(&det);
        assert!(
            actions.is_empty(),
            "Should be rate-limited after 30 actions"
        );
    }

    // -------------------------------------------------------------------
    // Cooldown
    // -------------------------------------------------------------------

    #[test]
    fn test_cooldown_blocks_same_pid() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        let det = DetectionResult {
            event_id: "evt-inject-001".to_string(),
            event_type: "process_inject".to_string(),
            severity: "critical".to_string(),
            threat_score: 0.9,
            mitre_tactics: vec!["Defense Evasion".to_string()],
            mitre_techniques: vec!["T1055.001".to_string()],
            detection_types: vec!["behavioral".to_string()],
            process_name: Some("injector.exe".to_string()),
            process_pid: Some(4444),
            file_path: None,
            source_ip: None,
            dest_ip: None,
            domain: None,
        };

        // First evaluation should fire.
        let actions = engine.evaluate_detection(&det);
        assert!(!actions.is_empty());

        // Record the action for PID 4444.
        engine.record_action(
            "builtin_critical_injection_kill",
            &ResponseAction::KillProcess,
            true,
            "evt-inject-001",
            Some(4444),
            None,
        );

        // Second evaluation with same PID should be on cooldown.
        let actions = engine.evaluate_detection(&det);
        assert!(actions.is_empty(), "Same PID should be on cooldown");

        // Different PID should NOT be on cooldown.
        let mut det2 = det.clone();
        det2.event_id = "evt-inject-002".to_string();
        det2.process_pid = Some(5555);
        let actions = engine.evaluate_detection(&det2);
        assert!(
            !actions.is_empty(),
            "Different PID should not be on cooldown"
        );
    }

    // -------------------------------------------------------------------
    // Rule loading
    // -------------------------------------------------------------------

    #[test]
    fn test_load_rules_preserves_builtins() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        let custom_rule = AutonomousResponseRule {
            id: "custom_lateral_movement_block".to_string(),
            name: "Lateral Movement Block".to_string(),
            enabled: true,
            priority: 30,
            conditions: RuleConditions {
                min_severity: Some("high".to_string()),
                min_threat_score: None,
                mitre_techniques: Some(vec!["T1021".to_string()]),
                mitre_tactics: None,
                event_types: None,
                process_names: None,
                detection_types: None,
            },
            actions: vec![ResponseAction::KillProcess, ResponseAction::IsolateNetwork],
            max_actions_per_hour: 20,
            cooldown_seconds: 120,
        };

        engine.load_rules(vec![custom_rule]);

        // Should have 4 built-in + 1 custom = 5.
        assert_eq!(engine.rules().len(), 5);

        let ids: Vec<&str> = engine.rules().iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"builtin_ransomware_autokill"));
        assert!(ids.contains(&"custom_lateral_movement_block"));
    }

    #[test]
    fn test_load_rules_can_disable_builtin() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // Verify ransomware rule starts enabled.
        assert!(
            engine
                .rules()
                .iter()
                .find(|r| r.id == "builtin_ransomware_autokill")
                .unwrap()
                .enabled
        );

        // Push an override that disables it.
        let override_rule = AutonomousResponseRule {
            id: "builtin_ransomware_autokill".to_string(),
            name: "Ransomware Auto-Kill".to_string(),
            enabled: false,
            priority: 10,
            conditions: RuleConditions {
                min_severity: None,
                min_threat_score: None,
                mitre_techniques: None,
                mitre_tactics: None,
                event_types: None,
                process_names: None,
                detection_types: None,
            },
            actions: vec![],
            max_actions_per_hour: 50,
            cooldown_seconds: 30,
        };

        engine.load_rules(vec![override_rule]);

        // Should still have 4 rules.
        assert_eq!(engine.rules().len(), 4);

        // But the ransomware rule should now be disabled.
        assert!(
            !engine
                .rules()
                .iter()
                .find(|r| r.id == "builtin_ransomware_autokill")
                .unwrap()
                .enabled
        );
    }

    // -------------------------------------------------------------------
    // Action log
    // -------------------------------------------------------------------

    #[test]
    fn test_action_log_bounded() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // Insert more than MAX_ACTION_LOG_SIZE entries.
        for i in 0..(MAX_ACTION_LOG_SIZE + 50) {
            engine.record_action(
                "test_rule",
                &ResponseAction::KillProcess,
                true,
                &format!("evt-{}", i),
                Some(i as u32),
                None,
            );
        }

        let log = engine.get_action_log();
        assert_eq!(log.len(), MAX_ACTION_LOG_SIZE);

        // Oldest entries should have been evicted; the first remaining
        // entry should be evt-50.
        assert_eq!(log[0].detection_event_id, "evt-50");
    }

    #[test]
    fn test_drain_action_log() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        engine.record_action(
            "test_rule",
            &ResponseAction::KillProcess,
            true,
            "evt-1",
            None,
            None,
        );
        engine.record_action(
            "test_rule",
            &ResponseAction::QuarantineFile,
            false,
            "evt-2",
            None,
            Some("access denied".to_string()),
        );

        let drained = engine.drain_action_log();
        assert_eq!(drained.len(), 2);
        assert!(drained[0].success);
        assert!(!drained[1].success);
        assert_eq!(drained[1].error, Some("access denied".to_string()));

        // Log should be empty after drain.
        assert!(engine.get_action_log().is_empty());
    }

    // -------------------------------------------------------------------
    // Enable / disable
    // -------------------------------------------------------------------

    #[test]
    fn test_disabled_engine_returns_no_actions() {
        let mut engine = AutonomousResponseEngine::new(&test_config());
        engine.set_enabled(false);

        let det = DetectionResult {
            event_id: "evt-001".to_string(),
            event_type: "file_modify".to_string(),
            severity: "critical".to_string(),
            threat_score: 0.99,
            mitre_tactics: vec!["Impact".to_string()],
            mitre_techniques: vec!["T1486".to_string()],
            detection_types: vec!["yara".to_string()],
            process_name: Some("evil.exe".to_string()),
            process_pid: Some(1000),
            file_path: Some("C:\\temp\\evil.exe".to_string()),
            source_ip: None,
            dest_ip: None,
            domain: None,
        };

        let actions = engine.evaluate_detection(&det);
        assert!(actions.is_empty());
    }

    // -------------------------------------------------------------------
    // Multiple rules can fire on the same detection
    // -------------------------------------------------------------------

    #[test]
    fn test_multiple_rules_fire() {
        let mut engine = AutonomousResponseEngine::new(&test_config());

        // A detection that matches BOTH ransomware AND injection rules:
        // T1486 + T1055.001 at critical severity with score >= 0.8.
        let det = DetectionResult {
            event_id: "evt-multi-001".to_string(),
            event_type: "process_inject".to_string(),
            severity: "critical".to_string(),
            threat_score: 0.92,
            mitre_tactics: vec!["Impact".to_string(), "Defense Evasion".to_string()],
            mitre_techniques: vec!["T1486".to_string(), "T1055.001".to_string()],
            detection_types: vec!["behavioral".to_string(), "yara".to_string()],
            process_name: Some("multi_threat.exe".to_string()),
            process_pid: Some(7777),
            file_path: Some("C:\\temp\\multi_threat.exe".to_string()),
            source_ip: None,
            dest_ip: None,
            domain: None,
        };

        let actions = engine.evaluate_detection(&det);

        // Ransomware (3 actions) + Injection (1 action) = 4 total.
        assert_eq!(actions.len(), 4);

        let rule_ids: Vec<&str> = actions.iter().map(|a| a.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"builtin_ransomware_autokill"));
        assert!(rule_ids.contains(&"builtin_critical_injection_kill"));
    }

    // -------------------------------------------------------------------
    // Action resolution (template substitution)
    // -------------------------------------------------------------------

    #[test]
    fn test_block_ip_resolution_from_detection() {
        let engine = AutonomousResponseEngine::new(&test_config());

        let det = DetectionResult {
            event_id: "evt-001".to_string(),
            event_type: "network_connect".to_string(),
            severity: "high".to_string(),
            threat_score: 0.9,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            detection_types: vec![],
            process_name: None,
            process_pid: None,
            file_path: None,
            source_ip: None,
            dest_ip: Some("10.0.0.99".to_string()),
            domain: Some("malicious.example.com".to_string()),
        };

        let template_ip = ResponseAction::BlockIP {
            ip: "$dest_ip".to_string(),
        };
        let resolved = engine.resolve_action(&template_ip, &det);
        assert_eq!(
            resolved,
            ResponseAction::BlockIP {
                ip: "10.0.0.99".to_string()
            }
        );

        let template_domain = ResponseAction::BlockDomain {
            domain: "$domain".to_string(),
        };
        let resolved = engine.resolve_action(&template_domain, &det);
        assert_eq!(
            resolved,
            ResponseAction::BlockDomain {
                domain: "malicious.example.com".to_string()
            }
        );

        // Explicit IP should NOT be resolved.
        let explicit_ip = ResponseAction::BlockIP {
            ip: "1.2.3.4".to_string(),
        };
        let resolved = engine.resolve_action(&explicit_ip, &det);
        assert_eq!(
            resolved,
            ResponseAction::BlockIP {
                ip: "1.2.3.4".to_string()
            }
        );
    }

    // -------------------------------------------------------------------
    // Empty conditions edge case
    // -------------------------------------------------------------------

    #[test]
    fn test_empty_vec_conditions_treated_as_no_filter() {
        let conditions = RuleConditions {
            min_severity: None,
            min_threat_score: None,
            mitre_techniques: Some(vec![]),
            mitre_tactics: Some(vec![]),
            event_types: Some(vec![]),
            process_names: Some(vec![]),
            detection_types: Some(vec![]),
        };
        let det = base_detection();
        // Empty vectors should be treated as "no constraint".
        assert!(AutonomousResponseEngine::matches_conditions(
            &conditions,
            &det
        ));
    }
}
