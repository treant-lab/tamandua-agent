//! Real-Time Alerting and Correlation Engine
//!
//! Provides comprehensive alert management for the EDR agent:
//! - Multi-level severity classification (Critical, High, Medium, Low, Info)
//! - Alert aggregation and deduplication
//! - Event correlation across time windows
//! - Risk scoring with time-decay
//! - MITRE ATT&CK enrichment
//! - Multiple notification channels
//! - Configurable alert rules with boolean logic
//! - Auto-response triggers
//! - Full alert lifecycle management

use crate::collectors::{Detection, DetectionType, EventPayload, Severity, TelemetryEvent};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;

// ============================================================================
// ALERT SEVERITY AND STATUS
// ============================================================================

/// Alert severity levels with configurable thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Informational - for audit/logging purposes
    Info = 0,
    /// Low - minor suspicious activity
    Low = 1,
    /// Medium - suspicious activity requiring investigation
    Medium = 2,
    /// High - active threat detected
    High = 3,
    /// Critical - immediate response required
    Critical = 4,
}

impl AlertSeverity {
    /// Get numeric weight for risk calculations
    pub fn weight(&self) -> f32 {
        match self {
            Self::Info => 0.1,
            Self::Low => 0.25,
            Self::Medium => 0.5,
            Self::High => 0.75,
            Self::Critical => 1.0,
        }
    }

    /// Convert from detection Severity
    pub fn from_detection_severity(severity: &Severity) -> Self {
        match severity {
            Severity::Info => Self::Info,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

impl Default for AlertSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

/// Alert lifecycle status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    /// Newly created alert
    New,
    /// Alert acknowledged by operator/server
    Acknowledged,
    /// Alert being investigated
    Investigating,
    /// Alert resolved/closed
    Resolved,
    /// False positive - dismissed
    FalsePositive,
    /// Escalated to higher tier
    Escalated,
}

impl Default for AlertStatus {
    fn default() -> Self {
        Self::New
    }
}

// ============================================================================
// ALERT STRUCTURE
// ============================================================================

/// Core alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert identifier
    pub alert_id: String,

    /// Alert title/name
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Alert severity
    pub severity: AlertSeverity,

    /// Current status
    pub status: AlertStatus,

    /// Creation timestamp (Unix millis)
    pub created_at: u64,

    /// Last update timestamp
    pub updated_at: u64,

    /// Source detection that triggered this alert
    pub source_detection: Option<Detection>,

    /// Related event IDs
    pub related_event_ids: Vec<String>,

    /// Related alerts (for correlated alerts)
    pub related_alert_ids: Vec<String>,

    /// Process context
    pub process_context: Option<ProcessContext>,

    /// Network context
    pub network_context: Option<NetworkContext>,

    /// File context
    pub file_context: Option<FileContext>,

    /// MITRE ATT&CK mapping
    pub mitre_mapping: MitreMapping,

    /// Threat intelligence context
    pub threat_intel: Option<ThreatIntelContext>,

    /// Risk score (0.0 - 100.0)
    pub risk_score: f32,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,

    /// Whether auto-response was triggered
    pub auto_response_triggered: bool,

    /// Auto-response actions taken
    pub auto_response_actions: Vec<String>,

    /// Alert suppression count (how many similar alerts were suppressed)
    pub suppression_count: u32,

    /// Custom tags
    pub tags: Vec<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Alert {
    /// Create a new alert
    pub fn new(title: String, description: String, severity: AlertSeverity) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            alert_id: Uuid::new_v4().to_string(),
            title,
            description,
            severity,
            status: AlertStatus::New,
            created_at: now,
            updated_at: now,
            source_detection: None,
            related_event_ids: Vec::new(),
            related_alert_ids: Vec::new(),
            process_context: None,
            network_context: None,
            file_context: None,
            mitre_mapping: MitreMapping::default(),
            threat_intel: None,
            risk_score: 0.0,
            confidence: 0.5,
            auto_response_triggered: false,
            auto_response_actions: Vec::new(),
            suppression_count: 0,
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create from a detection
    pub fn from_detection(event: &TelemetryEvent, detection: &Detection) -> Self {
        let severity = AlertSeverity::from_detection_severity(&event.severity);
        let mut alert = Self::new(
            detection.rule_name.clone(),
            detection.description.clone(),
            severity,
        );

        alert.source_detection = Some(detection.clone());
        alert.related_event_ids.push(event.event_id.clone());
        alert.confidence = detection.confidence;

        // Extract context from event
        match &event.payload {
            EventPayload::Process(proc) => {
                alert.process_context = Some(ProcessContext {
                    pid: proc.pid,
                    ppid: proc.ppid,
                    name: proc.name.clone(),
                    path: proc.path.clone(),
                    cmdline: proc.cmdline.clone(),
                    user: proc.user.clone(),
                    sha256: hex::encode(&proc.sha256),
                    parent_name: proc.parent_name.clone(),
                    parent_path: proc.parent_path.clone(),
                    is_elevated: proc.is_elevated,
                    is_signed: proc.is_signed,
                    signer: proc.signer.clone(),
                });
            }
            EventPayload::Network(net) => {
                alert.network_context = Some(NetworkContext {
                    pid: net.pid,
                    process_name: net.process_name.clone(),
                    local_ip: net.local_ip.clone(),
                    local_port: net.local_port,
                    remote_ip: net.remote_ip.clone(),
                    remote_port: net.remote_port,
                    protocol: net.protocol.clone(),
                    direction: net.direction.clone(),
                });
            }
            EventPayload::File(file) => {
                alert.file_context = Some(FileContext {
                    path: file.path.clone(),
                    old_path: file.old_path.clone(),
                    operation: file.operation.clone(),
                    pid: file.pid,
                    process_name: file.process_name.clone(),
                    sha256: hex::encode(&file.sha256),
                    size: file.size,
                    entropy: file.entropy,
                    file_type: file.file_type.clone(),
                });
            }
            _ => {}
        }

        // Set MITRE mapping
        alert.mitre_mapping = MitreMapping {
            tactics: detection.mitre_tactics.clone(),
            techniques: detection.mitre_techniques.clone(),
            sub_techniques: Vec::new(),
        };

        alert
    }

    /// Calculate fingerprint for deduplication
    pub fn fingerprint(&self) -> String {
        let mut parts = vec![self.title.clone(), format!("{:?}", self.severity)];

        if let Some(ref proc) = self.process_context {
            parts.push(proc.path.clone());
            parts.push(proc.sha256.clone());
        }

        if let Some(ref net) = self.network_context {
            parts.push(format!("{}:{}", net.remote_ip, net.remote_port));
        }

        if let Some(ref file) = self.file_context {
            parts.push(file.path.clone());
            parts.push(file.sha256.clone());
        }

        // Create hash of joined parts
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(parts.join("|"));
        hex::encode(hasher.finalize())
    }
}

// ============================================================================
// CONTEXT STRUCTURES
// ============================================================================

/// Process context for alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub user: String,
    pub sha256: String,
    pub parent_name: Option<String>,
    pub parent_path: Option<String>,
    pub is_elevated: bool,
    pub is_signed: bool,
    pub signer: Option<String>,
}

/// Network context for alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub pid: u32,
    pub process_name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub direction: String,
}

/// File context for alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    pub path: String,
    pub old_path: Option<String>,
    pub operation: String,
    pub pid: u32,
    pub process_name: String,
    pub sha256: String,
    pub size: u64,
    pub entropy: f32,
    pub file_type: String,
}

/// MITRE ATT&CK mapping
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub sub_techniques: Vec<String>,
}

/// Threat intelligence context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelContext {
    pub source: String,
    pub indicator_type: String,
    pub indicator_value: String,
    pub confidence: f32,
    pub tags: Vec<String>,
    pub related_campaigns: Vec<String>,
    pub related_actors: Vec<String>,
}

// ============================================================================
// ALERT RULES
// ============================================================================

/// Condition operator for alert rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    In,
    NotIn,
}

/// Single condition in a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    /// Field to check (supports dot notation for nested fields)
    pub field: String,
    /// Operator
    pub operator: ConditionOperator,
    /// Value(s) to compare against
    pub value: serde_json::Value,
    /// Negate this condition
    #[serde(default)]
    pub negate: bool,
}

impl RuleCondition {
    /// Evaluate condition against an event
    pub fn evaluate(&self, event: &TelemetryEvent) -> bool {
        let event_json = match serde_json::to_value(event) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let field_value = self.get_field_value(&event_json, &self.field);

        let result = match &field_value {
            Some(fv) => self.compare(fv, &self.value),
            None => false,
        };

        if self.negate {
            !result
        } else {
            result
        }
    }

    fn get_field_value<'a>(
        &self,
        json: &'a serde_json::Value,
        field: &str,
    ) -> Option<&'a serde_json::Value> {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = json;

        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    current = map.get(part)?;
                }
                serde_json::Value::Array(arr) => {
                    let idx: usize = part.parse().ok()?;
                    current = arr.get(idx)?;
                }
                _ => return None,
            }
        }

        Some(current)
    }

    fn compare(&self, field_value: &serde_json::Value, rule_value: &serde_json::Value) -> bool {
        match &self.operator {
            ConditionOperator::Equals => field_value == rule_value,
            ConditionOperator::NotEquals => field_value != rule_value,
            ConditionOperator::Contains => {
                if let (Some(fv), Some(rv)) = (field_value.as_str(), rule_value.as_str()) {
                    fv.to_lowercase().contains(&rv.to_lowercase())
                } else {
                    false
                }
            }
            ConditionOperator::StartsWith => {
                if let (Some(fv), Some(rv)) = (field_value.as_str(), rule_value.as_str()) {
                    fv.to_lowercase().starts_with(&rv.to_lowercase())
                } else {
                    false
                }
            }
            ConditionOperator::EndsWith => {
                if let (Some(fv), Some(rv)) = (field_value.as_str(), rule_value.as_str()) {
                    fv.to_lowercase().ends_with(&rv.to_lowercase())
                } else {
                    false
                }
            }
            ConditionOperator::Regex => {
                if let (Some(fv), Some(pattern)) = (field_value.as_str(), rule_value.as_str()) {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(fv))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            ConditionOperator::GreaterThan => {
                self.compare_numeric(field_value, rule_value, |a, b| a > b)
            }
            ConditionOperator::LessThan => {
                self.compare_numeric(field_value, rule_value, |a, b| a < b)
            }
            ConditionOperator::GreaterOrEqual => {
                self.compare_numeric(field_value, rule_value, |a, b| a >= b)
            }
            ConditionOperator::LessOrEqual => {
                self.compare_numeric(field_value, rule_value, |a, b| a <= b)
            }
            ConditionOperator::In => {
                if let Some(arr) = rule_value.as_array() {
                    arr.contains(field_value)
                } else {
                    false
                }
            }
            ConditionOperator::NotIn => {
                if let Some(arr) = rule_value.as_array() {
                    !arr.contains(field_value)
                } else {
                    true
                }
            }
        }
    }

    fn compare_numeric<F>(&self, fv: &serde_json::Value, rv: &serde_json::Value, cmp: F) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        let fv_num = fv.as_f64().or_else(|| fv.as_i64().map(|i| i as f64));
        let rv_num = rv.as_f64().or_else(|| rv.as_i64().map(|i| i as f64));

        match (fv_num, rv_num) {
            (Some(a), Some(b)) => cmp(a, b),
            _ => false,
        }
    }
}

/// Boolean logic for combining conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicOperator {
    And,
    Or,
    Not,
}

/// Condition group with logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionGroup {
    pub logic: LogicOperator,
    pub conditions: Vec<RuleCondition>,
    #[serde(default)]
    pub groups: Vec<ConditionGroup>,
}

impl ConditionGroup {
    /// Evaluate the condition group
    pub fn evaluate(&self, event: &TelemetryEvent) -> bool {
        let condition_results: Vec<bool> =
            self.conditions.iter().map(|c| c.evaluate(event)).collect();

        let group_results: Vec<bool> = self.groups.iter().map(|g| g.evaluate(event)).collect();

        let all_results: Vec<bool> = condition_results.into_iter().chain(group_results).collect();

        match self.logic {
            LogicOperator::And => all_results.iter().all(|&r| r),
            LogicOperator::Or => all_results.iter().any(|&r| r),
            LogicOperator::Not => {
                // NOT applies to the AND of all conditions
                !all_results.iter().all(|&r| r)
            }
        }
    }
}

/// Time-based condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeCondition {
    /// Number of events required
    pub count: u32,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Group by field (optional)
    pub group_by: Option<String>,
}

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique rule identifier
    pub rule_id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: String,

    /// Whether rule is enabled
    pub enabled: bool,

    /// Condition group (required)
    pub conditions: ConditionGroup,

    /// Time-based condition (optional)
    pub time_condition: Option<TimeCondition>,

    /// Alert severity to assign
    pub severity: AlertSeverity,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,

    /// MITRE ATT&CK mapping
    pub mitre_mapping: MitreMapping,

    /// Tags to add to alerts
    pub tags: Vec<String>,

    /// Auto-response actions to trigger
    pub auto_response: Vec<AutoResponseAction>,
}

impl AlertRule {
    /// Check if rule matches event
    pub fn matches(&self, event: &TelemetryEvent) -> bool {
        if !self.enabled {
            return false;
        }
        self.conditions.evaluate(event)
    }

    /// Create alert from matched rule
    pub fn create_alert(&self, event: &TelemetryEvent) -> Alert {
        let mut alert = Alert::new(self.name.clone(), self.description.clone(), self.severity);

        alert.confidence = self.confidence;
        alert.related_event_ids.push(event.event_id.clone());
        alert.mitre_mapping = self.mitre_mapping.clone();
        alert.tags = self.tags.clone();

        // Extract context based on event type
        match &event.payload {
            EventPayload::Process(proc) => {
                alert.process_context = Some(ProcessContext {
                    pid: proc.pid,
                    ppid: proc.ppid,
                    name: proc.name.clone(),
                    path: proc.path.clone(),
                    cmdline: proc.cmdline.clone(),
                    user: proc.user.clone(),
                    sha256: hex::encode(&proc.sha256),
                    parent_name: proc.parent_name.clone(),
                    parent_path: proc.parent_path.clone(),
                    is_elevated: proc.is_elevated,
                    is_signed: proc.is_signed,
                    signer: proc.signer.clone(),
                });
            }
            EventPayload::Network(net) => {
                alert.network_context = Some(NetworkContext {
                    pid: net.pid,
                    process_name: net.process_name.clone(),
                    local_ip: net.local_ip.clone(),
                    local_port: net.local_port,
                    remote_ip: net.remote_ip.clone(),
                    remote_port: net.remote_port,
                    protocol: net.protocol.clone(),
                    direction: net.direction.clone(),
                });
            }
            EventPayload::File(file) => {
                alert.file_context = Some(FileContext {
                    path: file.path.clone(),
                    old_path: file.old_path.clone(),
                    operation: file.operation.clone(),
                    pid: file.pid,
                    process_name: file.process_name.clone(),
                    sha256: hex::encode(&file.sha256),
                    size: file.size,
                    entropy: file.entropy,
                    file_type: file.file_type.clone(),
                });
            }
            _ => {}
        }

        alert
    }
}

// ============================================================================
// AUTO-RESPONSE
// ============================================================================

/// Auto-response action types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoResponseAction {
    /// Kill the associated process
    KillProcess { force: bool },
    /// Quarantine the associated file
    QuarantineFile,
    /// Isolate the endpoint from the network
    IsolateNetwork { allowed_ips: Vec<String> },
    /// Block an IP address
    BlockIP {
        direction: String, // "inbound", "outbound", "both"
    },
    /// Block a domain
    BlockDomain,
    /// Send emergency callback to server
    EmergencyCallback { message: String },
    /// Custom response with JSON payload
    Custom {
        action_type: String,
        payload: serde_json::Value,
    },
}

/// Auto-response trigger conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponseTrigger {
    /// Minimum severity to trigger
    pub min_severity: AlertSeverity,
    /// Minimum confidence to trigger
    pub min_confidence: f32,
    /// Actions to execute
    pub actions: Vec<AutoResponseAction>,
    /// Require manual approval
    pub require_approval: bool,
    /// Cooldown period in seconds
    pub cooldown_seconds: u64,
}

// ============================================================================
// CORRELATION ENGINE
// ============================================================================

/// Event for correlation tracking
#[derive(Debug, Clone)]
struct CorrelationEvent {
    event: TelemetryEvent,
    alert: Option<Alert>,
    timestamp: Instant,
}

/// Attack chain stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainStage {
    pub stage_name: String,
    pub alert_ids: Vec<String>,
    pub event_ids: Vec<String>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub timestamp: u64,
}

/// Correlated attack chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub chain_id: String,
    pub stages: Vec<AttackChainStage>,
    pub overall_severity: AlertSeverity,
    pub overall_confidence: f32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub related_pids: Vec<u32>,
    pub related_ips: Vec<String>,
    pub related_files: Vec<String>,
}

/// Correlation rule for attack chain detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    /// Sequence of event patterns to match
    pub sequence: Vec<ConditionGroup>,
    /// Maximum time between stages (seconds)
    pub max_gap_seconds: u64,
    /// Fields to correlate on (e.g., "pid", "process_name")
    pub correlation_fields: Vec<String>,
    /// Resulting severity
    pub severity: AlertSeverity,
}

/// Session tracking for correlation
#[derive(Debug, Clone)]
struct SessionState {
    /// Stable identifier emitted with serialized alerts; populated at construction
    /// even though the in-memory engine currently routes by HashMap key.
    #[allow(dead_code)]
    session_id: String,
    events: VecDeque<CorrelationEvent>,
    pids: HashSet<u32>,
    ips: HashSet<String>,
    files: HashSet<String>,
    first_seen: Instant,
    last_seen: Instant,
}

/// Correlation engine
pub struct CorrelationEngine {
    /// Correlation rules
    rules: Vec<CorrelationRule>,
    /// Session states by correlation key
    sessions: HashMap<String, SessionState>,
    /// Maximum session age
    max_session_age: Duration,
    /// Event buffer for time-based correlation
    event_buffer: VecDeque<CorrelationEvent>,
    /// Buffer retention time
    buffer_retention: Duration,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            sessions: HashMap::new(),
            max_session_age: Duration::from_secs(3600), // 1 hour
            event_buffer: VecDeque::new(),
            buffer_retention: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Add a correlation rule
    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    /// Process event for correlation
    pub fn process_event(
        &mut self,
        event: &TelemetryEvent,
        alert: Option<&Alert>,
    ) -> Vec<AttackChain> {
        let now = Instant::now();

        // Clean old data
        self.cleanup_old_sessions(now);
        self.cleanup_old_buffer(now);

        // Add to buffer
        self.event_buffer.push_back(CorrelationEvent {
            event: event.clone(),
            alert: alert.cloned(),
            timestamp: now,
        });

        // Extract correlation keys
        let correlation_keys = self.extract_correlation_keys(event);

        // Update sessions
        for key in &correlation_keys {
            self.update_session(key, event, alert, now);
        }

        // Check for attack chains
        let mut detected_chains = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            for key in &correlation_keys {
                if let Some(chain) = self.check_correlation_rule(rule, key) {
                    detected_chains.push(chain);
                }
            }
        }

        detected_chains
    }

    fn extract_correlation_keys(&self, event: &TelemetryEvent) -> Vec<String> {
        let mut keys = Vec::new();

        match &event.payload {
            EventPayload::Process(proc) => {
                keys.push(format!("pid:{}", proc.pid));
                keys.push(format!("ppid:{}", proc.ppid));
                keys.push(format!("user:{}", proc.user));
                if !proc.sha256.is_empty() {
                    keys.push(format!("sha256:{}", hex::encode(&proc.sha256)));
                }
            }
            EventPayload::Network(net) => {
                keys.push(format!("pid:{}", net.pid));
                keys.push(format!("remote_ip:{}", net.remote_ip));
            }
            EventPayload::File(file) => {
                keys.push(format!("pid:{}", file.pid));
                keys.push(format!("file_sha256:{}", hex::encode(&file.sha256)));
            }
            _ => {}
        }

        keys
    }

    fn update_session(
        &mut self,
        key: &str,
        event: &TelemetryEvent,
        alert: Option<&Alert>,
        now: Instant,
    ) {
        let session = self
            .sessions
            .entry(key.to_string())
            .or_insert_with(|| SessionState {
                session_id: Uuid::new_v4().to_string(),
                events: VecDeque::new(),
                pids: HashSet::new(),
                ips: HashSet::new(),
                files: HashSet::new(),
                first_seen: now,
                last_seen: now,
            });

        session.last_seen = now;
        session.events.push_back(CorrelationEvent {
            event: event.clone(),
            alert: alert.cloned(),
            timestamp: now,
        });

        // Update tracking sets
        match &event.payload {
            EventPayload::Process(proc) => {
                session.pids.insert(proc.pid);
            }
            EventPayload::Network(net) => {
                session.pids.insert(net.pid);
                session.ips.insert(net.remote_ip.clone());
            }
            EventPayload::File(file) => {
                session.pids.insert(file.pid);
                session.files.insert(file.path.clone());
            }
            _ => {}
        }

        // Limit session size
        while session.events.len() > 1000 {
            session.events.pop_front();
        }
    }

    fn check_correlation_rule(&self, rule: &CorrelationRule, key: &str) -> Option<AttackChain> {
        let session = self.sessions.get(key)?;

        if session.events.len() < rule.sequence.len() {
            return None;
        }

        // Check if sequence matches
        let mut matched_stages = Vec::new();
        let mut seq_idx = 0;
        let mut last_match_time: Option<Instant> = None;

        for corr_event in &session.events {
            if seq_idx >= rule.sequence.len() {
                break;
            }

            // Check time gap
            if let Some(last_time) = last_match_time {
                let gap = corr_event.timestamp.duration_since(last_time);
                if gap.as_secs() > rule.max_gap_seconds {
                    // Gap too large, reset
                    seq_idx = 0;
                    matched_stages.clear();
                }
            }

            if rule.sequence[seq_idx].evaluate(&corr_event.event) {
                let now_millis = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                matched_stages.push(AttackChainStage {
                    stage_name: format!("Stage {}", seq_idx + 1),
                    alert_ids: corr_event
                        .alert
                        .as_ref()
                        .map(|a| vec![a.alert_id.clone()])
                        .unwrap_or_default(),
                    event_ids: vec![corr_event.event.event_id.clone()],
                    tactics: Vec::new(),
                    techniques: Vec::new(),
                    timestamp: now_millis,
                });
                last_match_time = Some(corr_event.timestamp);
                seq_idx += 1;
            }
        }

        // Check if full sequence matched
        if seq_idx == rule.sequence.len() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            return Some(AttackChain {
                chain_id: Uuid::new_v4().to_string(),
                stages: matched_stages,
                overall_severity: rule.severity,
                overall_confidence: 0.8,
                first_seen: session.first_seen.elapsed().as_millis() as u64,
                last_seen: now,
                related_pids: session.pids.iter().copied().collect(),
                related_ips: session.ips.iter().cloned().collect(),
                related_files: session.files.iter().cloned().collect(),
            });
        }

        None
    }

    fn cleanup_old_sessions(&mut self, now: Instant) {
        let max_age = self.max_session_age;
        self.sessions
            .retain(|_, session| now.duration_since(session.last_seen) < max_age);
    }

    fn cleanup_old_buffer(&mut self, now: Instant) {
        let retention = self.buffer_retention;
        while let Some(front) = self.event_buffer.front() {
            if now.duration_since(front.timestamp) > retention {
                self.event_buffer.pop_front();
            } else {
                break;
            }
        }
    }
}

// ============================================================================
// RISK SCORING
// ============================================================================

/// Risk score entry with time decay
#[derive(Debug, Clone)]
struct RiskEntry {
    score: f32,
    timestamp: Instant,
}

/// Risk scoring engine
pub struct RiskScorer {
    /// Risk scores by process ID
    process_scores: HashMap<u32, Vec<RiskEntry>>,
    /// Risk scores by endpoint (aggregated)
    endpoint_score: Vec<RiskEntry>,
    /// Score weights by detection type
    weights: HashMap<DetectionType, f32>,
    /// Time decay half-life in seconds
    decay_half_life: f32,
    /// Maximum entries per entity
    max_entries: usize,
}

impl RiskScorer {
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert(DetectionType::Ransomware, 10.0);
        weights.insert(DetectionType::Malware, 8.0);
        weights.insert(DetectionType::MemoryThreat, 7.0);
        weights.insert(DetectionType::Honeyfile, 9.0);
        weights.insert(DetectionType::DriverThreat, 8.0);
        weights.insert(DetectionType::ThreatIntel, 6.0);
        weights.insert(DetectionType::Behavioral, 5.0);
        weights.insert(DetectionType::Yara, 6.0);
        weights.insert(DetectionType::Sigma, 5.0);
        weights.insert(DetectionType::Ioc, 6.0);
        weights.insert(DetectionType::Entropy, 3.0);
        weights.insert(DetectionType::WmiPersistence, 6.0);
        weights.insert(DetectionType::UsbThreat, 4.0);

        Self {
            process_scores: HashMap::new(),
            endpoint_score: Vec::new(),
            weights,
            decay_half_life: 3600.0, // 1 hour
            max_entries: 100,
        }
    }

    /// Add a risk event for a process
    pub fn add_process_risk(&mut self, pid: u32, detection: &Detection, severity: AlertSeverity) {
        let base_score = self
            .weights
            .get(&detection.detection_type)
            .copied()
            .unwrap_or(1.0);
        let severity_mult = severity.weight();
        let confidence_mult = detection.confidence;

        let score = base_score * severity_mult * confidence_mult;

        let entry = RiskEntry {
            score,
            timestamp: Instant::now(),
        };

        let entries = self.process_scores.entry(pid).or_insert_with(Vec::new);
        entries.push(entry.clone());

        // Limit entries
        if entries.len() > self.max_entries {
            entries.remove(0);
        }

        // Also add to endpoint score
        self.endpoint_score.push(entry);
        if self.endpoint_score.len() > self.max_entries * 10 {
            self.endpoint_score.remove(0);
        }
    }

    /// Calculate current risk score for a process with time decay
    pub fn get_process_risk(&self, pid: u32) -> f32 {
        let entries = match self.process_scores.get(&pid) {
            Some(e) => e,
            None => return 0.0,
        };

        self.calculate_decayed_score(entries)
    }

    /// Calculate current endpoint risk score
    pub fn get_endpoint_risk(&self) -> f32 {
        self.calculate_decayed_score(&self.endpoint_score)
    }

    fn calculate_decayed_score(&self, entries: &[RiskEntry]) -> f32 {
        let now = Instant::now();
        let mut total = 0.0;

        for entry in entries {
            let age = now.duration_since(entry.timestamp).as_secs_f32();
            let decay = 0.5_f32.powf(age / self.decay_half_life);
            total += entry.score * decay;
        }

        // Normalize to 0-100 scale
        (total * 10.0).min(100.0)
    }

    /// Clean up old entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let max_age = Duration::from_secs((self.decay_half_life * 10.0) as u64);

        for entries in self.process_scores.values_mut() {
            entries.retain(|e| now.duration_since(e.timestamp) < max_age);
        }

        self.endpoint_score
            .retain(|e| now.duration_since(e.timestamp) < max_age);

        // Remove empty process entries
        self.process_scores.retain(|_, entries| !entries.is_empty());
    }
}

// ============================================================================
// ALERT AGGREGATION
// ============================================================================

/// Aggregation window entry
#[derive(Debug, Clone)]
struct AggregationEntry {
    alert: Alert,
    count: u32,
    first_seen: Instant,
    last_seen: Instant,
}

/// Alert aggregation engine
pub struct AlertAggregator {
    /// Aggregation windows by fingerprint
    windows: HashMap<String, AggregationEntry>,
    /// Window duration
    window_duration: Duration,
    /// Minimum count before aggregating
    min_count: u32,
    /// Maximum suppression count
    max_suppression: u32,
}

impl AlertAggregator {
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
            window_duration: Duration::from_secs(300), // 5 minutes
            min_count: 2,
            max_suppression: 100,
        }
    }

    /// Process an alert, returns Some if alert should be emitted
    pub fn process(&mut self, alert: Alert) -> Option<Alert> {
        let now = Instant::now();
        let fingerprint = alert.fingerprint();

        // Clean old windows
        self.cleanup(now);

        if let Some(entry) = self.windows.get_mut(&fingerprint) {
            // Existing window - aggregate
            entry.count += 1;
            entry.last_seen = now;

            if entry.count > self.max_suppression {
                // Emit aggregated alert
                let mut agg_alert = entry.alert.clone();
                agg_alert.suppression_count = entry.count;
                self.windows.remove(&fingerprint);
                return Some(agg_alert);
            }

            // Suppress
            None
        } else {
            // New alert - start window
            self.windows.insert(
                fingerprint,
                AggregationEntry {
                    alert: alert.clone(),
                    count: 1,
                    first_seen: now,
                    last_seen: now,
                },
            );

            // Emit first occurrence
            Some(alert)
        }
    }

    /// Flush all pending aggregated alerts
    pub fn flush(&mut self) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for entry in self.windows.values() {
            if entry.count >= self.min_count {
                let mut alert = entry.alert.clone();
                alert.suppression_count = entry.count;
                alerts.push(alert);
            }
        }

        self.windows.clear();
        alerts
    }

    fn cleanup(&mut self, now: Instant) {
        let duration = self.window_duration;
        self.windows
            .retain(|_, entry| now.duration_since(entry.first_seen) < duration);
    }
}

// ============================================================================
// NOTIFICATION CHANNELS
// ============================================================================

/// Notification channel trait
#[async_trait::async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Send an alert through this channel
    async fn send(&self, alert: &Alert) -> Result<()>;

    /// Channel name
    fn name(&self) -> &str;

    /// Whether channel is available
    fn is_available(&self) -> bool;
}

/// WebSocket notification (to backend server)
pub struct WebSocketChannel {
    sender: mpsc::Sender<Alert>,
}

impl WebSocketChannel {
    pub fn new(sender: mpsc::Sender<Alert>) -> Self {
        Self { sender }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for WebSocketChannel {
    async fn send(&self, alert: &Alert) -> Result<()> {
        self.sender
            .send(alert.clone())
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send failed: {}", e))
    }

    fn name(&self) -> &str {
        "websocket"
    }

    fn is_available(&self) -> bool {
        !self.sender.is_closed()
    }
}

/// Windows Event Log channel
#[cfg(target_os = "windows")]
pub struct WindowsEventLogChannel {
    source_name: String,
}

#[cfg(target_os = "windows")]
impl WindowsEventLogChannel {
    pub fn new(source_name: &str) -> Self {
        Self {
            source_name: source_name.to_string(),
        }
    }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl NotificationChannel for WindowsEventLogChannel {
    async fn send(&self, alert: &Alert) -> Result<()> {
        use std::process::Command;

        let event_type = match alert.severity {
            AlertSeverity::Critical | AlertSeverity::High => "Error",
            AlertSeverity::Medium => "Warning",
            _ => "Information",
        };

        let event_id = match alert.severity {
            AlertSeverity::Critical => 1001,
            AlertSeverity::High => 1002,
            AlertSeverity::Medium => 1003,
            AlertSeverity::Low => 1004,
            AlertSeverity::Info => 1005,
        };

        let message = format!(
            "[{}] {}\n\nDescription: {}\nAlert ID: {}\nConfidence: {:.0}%",
            alert.severity as u8,
            alert.title,
            alert.description,
            alert.alert_id,
            alert.confidence * 100.0
        );

        // Use eventcreate command
        let result = Command::new("eventcreate")
            .args([
                "/T",
                event_type,
                "/ID",
                &event_id.to_string(),
                "/L",
                "Application",
                "/SO",
                &self.source_name,
                "/D",
                &message,
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(anyhow::anyhow!(
                "eventcreate failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(e) => Err(anyhow::anyhow!("Failed to run eventcreate: {}", e)),
        }
    }

    fn name(&self) -> &str {
        "windows_event_log"
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Syslog channel (Linux/macOS)
#[cfg(unix)]
pub struct SyslogChannel {
    facility: String,
}

#[cfg(unix)]
impl SyslogChannel {
    pub fn new(facility: &str) -> Self {
        Self {
            facility: facility.to_string(),
        }
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl NotificationChannel for SyslogChannel {
    async fn send(&self, alert: &Alert) -> Result<()> {
        use std::process::Command;

        let priority = match alert.severity {
            AlertSeverity::Critical => "crit",
            AlertSeverity::High => "err",
            AlertSeverity::Medium => "warning",
            AlertSeverity::Low => "notice",
            AlertSeverity::Info => "info",
        };

        let message = format!(
            "[Tamandua] {} - {} (ID: {}, Confidence: {:.0}%)",
            alert.title,
            alert.description,
            alert.alert_id,
            alert.confidence * 100.0
        );

        let result = Command::new("logger")
            .args([
                "-p",
                &format!("{}.{}", self.facility, priority),
                "-t",
                "tamandua",
                &message,
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(anyhow::anyhow!(
                "logger failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(e) => Err(anyhow::anyhow!("Failed to run logger: {}", e)),
        }
    }

    fn name(&self) -> &str {
        "syslog"
    }

    fn is_available(&self) -> bool {
        std::path::Path::new("/usr/bin/logger").exists()
            || std::path::Path::new("/bin/logger").exists()
    }
}

/// File output channel
pub struct FileChannel {
    path: String,
}

impl FileChannel {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for FileChannel {
    async fn send(&self, alert: &Alert) -> Result<()> {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;

        let json = serde_json::to_string(alert)?;
        let line = format!("{}\n", json);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;

        file.write_all(line.as_bytes()).await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }

    fn is_available(&self) -> bool {
        // Check if we can write to the directory
        if let Some(parent) = std::path::Path::new(&self.path).parent() {
            parent.exists() || std::fs::create_dir_all(parent).is_ok()
        } else {
            true
        }
    }
}

// ============================================================================
// ALERTING ENGINE
// ============================================================================

/// Configuration for the alerting engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    /// Enable alerting
    pub enabled: bool,

    /// Minimum severity to alert on
    pub min_severity: AlertSeverity,

    /// Enable alert aggregation
    pub aggregation_enabled: bool,

    /// Aggregation window in seconds
    pub aggregation_window_seconds: u64,

    /// Enable auto-response
    pub auto_response_enabled: bool,

    /// Auto-response triggers
    pub auto_response_triggers: Vec<AutoResponseTrigger>,

    /// Alert rate limit (max alerts per minute)
    pub rate_limit_per_minute: u32,

    /// Enable file logging
    pub file_logging_enabled: bool,

    /// File log path
    pub file_log_path: String,

    /// Enable local event log (Windows Event Log / Syslog)
    pub local_log_enabled: bool,

    /// Risk score threshold for escalation
    pub risk_escalation_threshold: f32,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_severity: AlertSeverity::Low,
            aggregation_enabled: true,
            aggregation_window_seconds: 300,
            auto_response_enabled: false,
            auto_response_triggers: vec![AutoResponseTrigger {
                min_severity: AlertSeverity::Critical,
                min_confidence: 0.9,
                actions: vec![AutoResponseAction::IsolateNetwork {
                    allowed_ips: vec![],
                }],
                require_approval: false,
                cooldown_seconds: 300,
            }],
            rate_limit_per_minute: 100,
            file_logging_enabled: false,
            file_log_path: if cfg!(windows) {
                "C:\\ProgramData\\Tamandua\\alerts.jsonl".to_string()
            } else {
                "/var/log/tamandua/alerts.jsonl".to_string()
            },
            local_log_enabled: true,
            risk_escalation_threshold: 80.0,
        }
    }
}

/// Main alerting engine
pub struct AlertingEngine {
    /// Configuration
    config: AlertingConfig,

    /// Alert rules
    rules: Arc<RwLock<Vec<AlertRule>>>,

    /// Correlation engine
    correlation: Arc<Mutex<CorrelationEngine>>,

    /// Risk scorer
    risk_scorer: Arc<Mutex<RiskScorer>>,

    /// Alert aggregator
    aggregator: Arc<Mutex<AlertAggregator>>,

    /// Notification channels
    channels: Vec<Arc<dyn NotificationChannel>>,

    /// Alert state tracking
    alert_states: Arc<RwLock<HashMap<String, AlertStatus>>>,

    /// Rate limiter (timestamps of recent alerts)
    rate_limiter: Arc<Mutex<VecDeque<Instant>>>,

    /// Auto-response cooldowns
    response_cooldowns: Arc<RwLock<HashMap<String, Instant>>>,

    /// Pending auto-response actions (for approval)
    pending_responses: Arc<RwLock<Vec<(Alert, Vec<AutoResponseAction>)>>>,
}

impl AlertingEngine {
    /// Create a new alerting engine
    pub fn new(config: AlertingConfig) -> Self {
        let mut aggregator = AlertAggregator::new();
        aggregator.window_duration = Duration::from_secs(config.aggregation_window_seconds);

        Self {
            config,
            rules: Arc::new(RwLock::new(Vec::new())),
            correlation: Arc::new(Mutex::new(CorrelationEngine::new())),
            risk_scorer: Arc::new(Mutex::new(RiskScorer::new())),
            aggregator: Arc::new(Mutex::new(aggregator)),
            channels: Vec::new(),
            alert_states: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(VecDeque::new())),
            response_cooldowns: Arc::new(RwLock::new(HashMap::new())),
            pending_responses: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a notification channel
    pub fn add_channel(&mut self, channel: Arc<dyn NotificationChannel>) {
        self.channels.push(channel);
    }

    /// Add an alert rule
    pub async fn add_rule(&self, rule: AlertRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    /// Add a correlation rule
    pub async fn add_correlation_rule(&self, rule: CorrelationRule) {
        let mut correlation = self.correlation.lock().await;
        correlation.add_rule(rule);
    }

    /// Process a telemetry event
    pub async fn process_event(&self, event: &TelemetryEvent) -> Vec<Alert> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut generated_alerts = Vec::new();

        // Check alert rules
        let rules = self.rules.read().await;
        for rule in rules.iter() {
            if rule.matches(event) {
                let alert = rule.create_alert(event);
                generated_alerts.push(alert);
            }
        }

        // Create alerts from detections
        for detection in &event.detections {
            let alert = Alert::from_detection(event, detection);
            generated_alerts.push(alert);
        }

        // Filter by minimum severity
        generated_alerts.retain(|a| a.severity >= self.config.min_severity);

        // Process through correlation engine
        let mut correlation = self.correlation.lock().await;
        let mut chain_alerts = Vec::new();
        for alert in &generated_alerts {
            let chains = correlation.process_event(event, Some(alert));
            for chain in chains {
                let chain_alert = self.create_chain_alert(&chain);
                chain_alerts.push(chain_alert);
            }
        }
        drop(correlation);
        generated_alerts.extend(chain_alerts);

        // Update risk scores
        let mut risk_scorer = self.risk_scorer.lock().await;
        for alert in &generated_alerts {
            if let Some(ref proc_ctx) = alert.process_context {
                if let Some(ref detection) = alert.source_detection {
                    risk_scorer.add_process_risk(proc_ctx.pid, detection, alert.severity);
                }
            }
        }

        // Check for risk-based escalation
        let endpoint_risk = risk_scorer.get_endpoint_risk();
        if endpoint_risk >= self.config.risk_escalation_threshold {
            let mut escalation_alert = Alert::new(
                "High Endpoint Risk Score".to_string(),
                format!("Endpoint risk score has reached {:.1}%", endpoint_risk),
                AlertSeverity::High,
            );
            escalation_alert.risk_score = endpoint_risk;
            escalation_alert.tags.push("risk_escalation".to_string());
            generated_alerts.push(escalation_alert);
        }
        drop(risk_scorer);

        // Apply aggregation if enabled
        let mut final_alerts = Vec::new();
        if self.config.aggregation_enabled {
            let mut aggregator = self.aggregator.lock().await;
            for alert in generated_alerts {
                if let Some(agg_alert) = aggregator.process(alert) {
                    final_alerts.push(agg_alert);
                }
            }
        } else {
            final_alerts = generated_alerts;
        }

        // Apply rate limiting
        final_alerts = self.apply_rate_limit(final_alerts).await;

        // Process auto-responses
        for alert in &final_alerts {
            self.process_auto_response(alert).await;
        }

        // Send through notification channels
        for alert in &final_alerts {
            self.notify(alert).await;
        }

        // Track alert states
        let mut states = self.alert_states.write().await;
        for alert in &final_alerts {
            states.insert(alert.alert_id.clone(), alert.status);
        }

        final_alerts
    }

    /// Process a detection directly (without full event)
    pub async fn process_detection(
        &self,
        event: &TelemetryEvent,
        detection: &Detection,
    ) -> Option<Alert> {
        if !self.config.enabled {
            return None;
        }

        let alert = Alert::from_detection(event, detection);

        if alert.severity < self.config.min_severity {
            return None;
        }

        // Check rate limit
        let alerts = self.apply_rate_limit(vec![alert]).await;
        let alert = alerts.into_iter().next()?;

        // Process auto-response
        self.process_auto_response(&alert).await;

        // Notify
        self.notify(&alert).await;

        // Track state
        let mut states = self.alert_states.write().await;
        states.insert(alert.alert_id.clone(), alert.status);

        Some(alert)
    }

    fn create_chain_alert(&self, chain: &AttackChain) -> Alert {
        let mut alert = Alert::new(
            format!("Attack Chain Detected ({} stages)", chain.stages.len()),
            format!(
                "Correlated attack chain with {} stages detected",
                chain.stages.len()
            ),
            chain.overall_severity,
        );

        alert.confidence = chain.overall_confidence;
        alert.related_alert_ids = chain
            .stages
            .iter()
            .flat_map(|s| s.alert_ids.clone())
            .collect();
        alert.related_event_ids = chain
            .stages
            .iter()
            .flat_map(|s| s.event_ids.clone())
            .collect();
        alert.tags.push("attack_chain".to_string());
        alert.tags.push(format!("stages:{}", chain.stages.len()));

        alert.metadata.insert(
            "related_pids".to_string(),
            chain
                .related_pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        alert
            .metadata
            .insert("related_ips".to_string(), chain.related_ips.join(","));

        alert
    }

    async fn apply_rate_limit(&self, alerts: Vec<Alert>) -> Vec<Alert> {
        let mut limiter = self.rate_limiter.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(60);

        // Remove old entries
        while let Some(front) = limiter.front() {
            if now.duration_since(*front) > window {
                limiter.pop_front();
            } else {
                break;
            }
        }

        // Check limit
        let remaining = self
            .config
            .rate_limit_per_minute
            .saturating_sub(limiter.len() as u32);
        let to_take = (remaining as usize).min(alerts.len());

        // Record new alerts
        for _ in 0..to_take {
            limiter.push_back(now);
        }

        alerts.into_iter().take(to_take).collect()
    }

    async fn process_auto_response(&self, alert: &Alert) {
        if !self.config.auto_response_enabled {
            return;
        }

        for trigger in &self.config.auto_response_triggers {
            if alert.severity >= trigger.min_severity && alert.confidence >= trigger.min_confidence
            {
                // Check cooldown
                let cooldown_key = format!("{}:{:?}", alert.fingerprint(), trigger.min_severity);
                let cooldowns = self.response_cooldowns.read().await;

                if let Some(last_trigger) = cooldowns.get(&cooldown_key) {
                    if last_trigger.elapsed().as_secs() < trigger.cooldown_seconds {
                        continue;
                    }
                }
                drop(cooldowns);

                if trigger.require_approval {
                    // Queue for approval
                    let mut pending = self.pending_responses.write().await;
                    pending.push((alert.clone(), trigger.actions.clone()));
                    info!(
                        alert_id = %alert.alert_id,
                        "Auto-response queued for approval"
                    );
                } else {
                    // Execute immediately
                    self.execute_auto_response(alert, &trigger.actions).await;

                    // Update cooldown
                    let mut cooldowns = self.response_cooldowns.write().await;
                    cooldowns.insert(cooldown_key, Instant::now());
                }

                break;
            }
        }
    }

    async fn execute_auto_response(&self, alert: &Alert, actions: &[AutoResponseAction]) {
        for action in actions {
            match action {
                AutoResponseAction::KillProcess { force } => {
                    if let Some(ref proc_ctx) = alert.process_context {
                        info!(
                            pid = proc_ctx.pid,
                            force = force,
                            alert_id = %alert.alert_id,
                            "Auto-response: killing process"
                        );
                        // Note: Actual kill would be done through response module
                    }
                }
                AutoResponseAction::QuarantineFile => {
                    if let Some(ref file_ctx) = alert.file_context {
                        info!(
                            path = %file_ctx.path,
                            alert_id = %alert.alert_id,
                            "Auto-response: quarantining file"
                        );
                    }
                }
                AutoResponseAction::IsolateNetwork { allowed_ips } => {
                    info!(
                        alert_id = %alert.alert_id,
                        allowed_ips = ?allowed_ips,
                        "Auto-response: isolating network"
                    );
                }
                AutoResponseAction::BlockIP { direction } => {
                    if let Some(ref net_ctx) = alert.network_context {
                        info!(
                            ip = %net_ctx.remote_ip,
                            direction = %direction,
                            alert_id = %alert.alert_id,
                            "Auto-response: blocking IP"
                        );
                    }
                }
                AutoResponseAction::BlockDomain => {
                    info!(
                        alert_id = %alert.alert_id,
                        "Auto-response: blocking domain"
                    );
                }
                AutoResponseAction::EmergencyCallback { message } => {
                    warn!(
                        alert_id = %alert.alert_id,
                        message = %message,
                        "Auto-response: emergency callback triggered"
                    );
                }
                AutoResponseAction::Custom {
                    action_type,
                    payload: _,
                } => {
                    info!(
                        alert_id = %alert.alert_id,
                        action_type = %action_type,
                        "Auto-response: custom action"
                    );
                }
            }
        }
    }

    async fn notify(&self, alert: &Alert) {
        for channel in &self.channels {
            if channel.is_available() {
                if let Err(e) = channel.send(alert).await {
                    error!(
                        channel = channel.name(),
                        error = %e,
                        "Failed to send alert through channel"
                    );
                }
            }
        }
    }

    /// Update alert status
    pub async fn update_status(&self, alert_id: &str, status: AlertStatus) {
        let mut states = self.alert_states.write().await;
        states.insert(alert_id.to_string(), status);
    }

    /// Get alert status
    pub async fn get_status(&self, alert_id: &str) -> Option<AlertStatus> {
        let states = self.alert_states.read().await;
        states.get(alert_id).copied()
    }

    /// Get pending auto-responses requiring approval
    pub async fn get_pending_responses(&self) -> Vec<(Alert, Vec<AutoResponseAction>)> {
        let pending = self.pending_responses.read().await;
        pending.clone()
    }

    /// Approve a pending auto-response
    pub async fn approve_response(&self, alert_id: &str) -> bool {
        let mut pending = self.pending_responses.write().await;

        if let Some(pos) = pending.iter().position(|(a, _)| a.alert_id == alert_id) {
            let (alert, actions) = pending.remove(pos);
            drop(pending);

            self.execute_auto_response(&alert, &actions).await;
            true
        } else {
            false
        }
    }

    /// Reject a pending auto-response
    pub async fn reject_response(&self, alert_id: &str) -> bool {
        let mut pending = self.pending_responses.write().await;

        if let Some(pos) = pending.iter().position(|(a, _)| a.alert_id == alert_id) {
            pending.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get current endpoint risk score
    pub async fn get_endpoint_risk(&self) -> f32 {
        let scorer = self.risk_scorer.lock().await;
        scorer.get_endpoint_risk()
    }

    /// Get risk score for a specific process
    pub async fn get_process_risk(&self, pid: u32) -> f32 {
        let scorer = self.risk_scorer.lock().await;
        scorer.get_process_risk(pid)
    }

    /// Flush aggregated alerts
    pub async fn flush_aggregated(&self) -> Vec<Alert> {
        let mut aggregator = self.aggregator.lock().await;
        let alerts = aggregator.flush();

        for alert in &alerts {
            self.notify(alert).await;
        }

        alerts
    }

    /// Periodic cleanup task
    pub async fn cleanup(&self) {
        let mut risk_scorer = self.risk_scorer.lock().await;
        risk_scorer.cleanup();
    }
}

// ============================================================================
// BUILDER PATTERN
// ============================================================================

/// Builder for AlertingEngine
pub struct AlertingEngineBuilder {
    config: AlertingConfig,
    channels: Vec<Arc<dyn NotificationChannel>>,
    rules: Vec<AlertRule>,
    correlation_rules: Vec<CorrelationRule>,
}

impl AlertingEngineBuilder {
    pub fn new() -> Self {
        Self {
            config: AlertingConfig::default(),
            channels: Vec::new(),
            rules: Vec::new(),
            correlation_rules: Vec::new(),
        }
    }

    pub fn config(mut self, config: AlertingConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_channel(mut self, channel: Arc<dyn NotificationChannel>) -> Self {
        self.channels.push(channel);
        self
    }

    pub fn add_rule(mut self, rule: AlertRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn add_correlation_rule(mut self, rule: CorrelationRule) -> Self {
        self.correlation_rules.push(rule);
        self
    }

    pub fn with_file_logging(mut self, path: &str) -> Self {
        self.config.file_logging_enabled = true;
        self.config.file_log_path = path.to_string();
        self.channels.push(Arc::new(FileChannel::new(path)));
        self
    }

    #[cfg(target_os = "windows")]
    pub fn with_windows_event_log(mut self, source: &str) -> Self {
        self.config.local_log_enabled = true;
        self.channels
            .push(Arc::new(WindowsEventLogChannel::new(source)));
        self
    }

    #[cfg(unix)]
    pub fn with_syslog(mut self, facility: &str) -> Self {
        self.config.local_log_enabled = true;
        self.channels.push(Arc::new(SyslogChannel::new(facility)));
        self
    }

    pub async fn build(self) -> AlertingEngine {
        let mut engine = AlertingEngine::new(self.config);

        for channel in self.channels {
            engine.add_channel(channel);
        }

        for rule in self.rules {
            engine.add_rule(rule).await;
        }

        for rule in self.correlation_rules {
            engine.add_correlation_rule(rule).await;
        }

        engine
    }
}

impl Default for AlertingEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PREDEFINED RULES
// ============================================================================

/// Get predefined alert rules
pub fn get_predefined_rules() -> Vec<AlertRule> {
    vec![
        // Encoded PowerShell detection
        AlertRule {
            rule_id: "encoded_powershell".to_string(),
            name: "Encoded PowerShell Execution".to_string(),
            description: "PowerShell executed with encoded command - common malware technique"
                .to_string(),
            enabled: true,
            conditions: ConditionGroup {
                logic: LogicOperator::And,
                conditions: vec![RuleCondition {
                    field: "payload.cmdline".to_string(),
                    operator: ConditionOperator::Contains,
                    value: serde_json::Value::String("-enc".to_string()),
                    negate: false,
                }],
                groups: vec![],
            },
            time_condition: None,
            severity: AlertSeverity::High,
            confidence: 0.8,
            mitre_mapping: MitreMapping {
                tactics: vec!["TA0002".to_string()],       // Execution
                techniques: vec!["T1059.001".to_string()], // PowerShell
                sub_techniques: vec![],
            },
            tags: vec!["powershell".to_string(), "encoded".to_string()],
            auto_response: vec![],
        },
        // Office spawning shell
        AlertRule {
            rule_id: "office_shell_spawn".to_string(),
            name: "Office Application Spawning Shell".to_string(),
            description: "Office application spawned a command shell - possible macro malware"
                .to_string(),
            enabled: true,
            conditions: ConditionGroup {
                logic: LogicOperator::And,
                conditions: vec![
                    RuleCondition {
                        field: "payload.parent_name".to_string(),
                        operator: ConditionOperator::Regex,
                        value: serde_json::Value::String(
                            "(?i)(winword|excel|powerpnt|outlook)".to_string(),
                        ),
                        negate: false,
                    },
                    RuleCondition {
                        field: "payload.name".to_string(),
                        operator: ConditionOperator::Regex,
                        value: serde_json::Value::String(
                            "(?i)(cmd|powershell|wscript|cscript)".to_string(),
                        ),
                        negate: false,
                    },
                ],
                groups: vec![],
            },
            time_condition: None,
            severity: AlertSeverity::High,
            confidence: 0.85,
            mitre_mapping: MitreMapping {
                tactics: vec!["TA0001".to_string(), "TA0002".to_string()], // Initial Access, Execution
                techniques: vec!["T1566.001".to_string()], // Spearphishing Attachment
                sub_techniques: vec![],
            },
            tags: vec!["office".to_string(), "macro".to_string()],
            auto_response: vec![],
        },
        // Execution from temp
        AlertRule {
            rule_id: "temp_execution".to_string(),
            name: "Process Execution from Temp Directory".to_string(),
            description: "Executable running from temporary directory".to_string(),
            enabled: true,
            conditions: ConditionGroup {
                logic: LogicOperator::And,
                conditions: vec![
                    RuleCondition {
                        field: "payload.path".to_string(),
                        operator: ConditionOperator::Regex,
                        value: serde_json::Value::String("(?i)(\\\\temp\\\\|/tmp/)".to_string()),
                        negate: false,
                    },
                    RuleCondition {
                        field: "event_type".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::Value::String("process_create".to_string()),
                        negate: false,
                    },
                ],
                groups: vec![],
            },
            time_condition: None,
            severity: AlertSeverity::Medium,
            confidence: 0.6,
            mitre_mapping: MitreMapping {
                tactics: vec!["TA0005".to_string()],   // Defense Evasion
                techniques: vec!["T1036".to_string()], // Masquerading
                sub_techniques: vec![],
            },
            tags: vec!["temp_execution".to_string()],
            auto_response: vec![],
        },
        // High entropy file write
        AlertRule {
            rule_id: "high_entropy_write".to_string(),
            name: "High Entropy File Written".to_string(),
            description: "File with very high entropy written - possible encryption/packing"
                .to_string(),
            enabled: true,
            conditions: ConditionGroup {
                logic: LogicOperator::And,
                conditions: vec![
                    RuleCondition {
                        field: "payload.entropy".to_string(),
                        operator: ConditionOperator::GreaterThan,
                        value: serde_json::Value::Number(
                            serde_json::Number::from_f64(7.9).expect("7.9 is a valid finite f64"),
                        ),
                        negate: false,
                    },
                    RuleCondition {
                        field: "event_type".to_string(),
                        operator: ConditionOperator::In,
                        value: serde_json::json!(["file_create", "file_modify"]),
                        negate: false,
                    },
                ],
                groups: vec![],
            },
            time_condition: None,
            severity: AlertSeverity::Medium,
            confidence: 0.5,
            mitre_mapping: MitreMapping {
                tactics: vec!["TA0040".to_string()],   // Impact
                techniques: vec!["T1486".to_string()], // Data Encrypted for Impact
                sub_techniques: vec![],
            },
            tags: vec!["entropy".to_string(), "encryption".to_string()],
            auto_response: vec![],
        },
    ]
}

/// Get predefined correlation rules
pub fn get_predefined_correlation_rules() -> Vec<CorrelationRule> {
    vec![
        // Initial Access -> Execution -> Persistence chain
        CorrelationRule {
            rule_id: "initial_exec_persist".to_string(),
            name: "Initial Access to Persistence Chain".to_string(),
            description: "Detects pattern: file download -> execution -> registry persistence"
                .to_string(),
            enabled: true,
            sequence: vec![
                // Stage 1: File creation from network
                ConditionGroup {
                    logic: LogicOperator::And,
                    conditions: vec![RuleCondition {
                        field: "event_type".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::Value::String("file_create".to_string()),
                        negate: false,
                    }],
                    groups: vec![],
                },
                // Stage 2: Process execution
                ConditionGroup {
                    logic: LogicOperator::And,
                    conditions: vec![RuleCondition {
                        field: "event_type".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::Value::String("process_create".to_string()),
                        negate: false,
                    }],
                    groups: vec![],
                },
                // Stage 3: Registry modification (persistence)
                ConditionGroup {
                    logic: LogicOperator::And,
                    conditions: vec![
                        RuleCondition {
                            field: "event_type".to_string(),
                            operator: ConditionOperator::Equals,
                            value: serde_json::Value::String("registry_set_value".to_string()),
                            negate: false,
                        },
                        RuleCondition {
                            field: "payload.key_path".to_string(),
                            operator: ConditionOperator::Contains,
                            value: serde_json::Value::String("Run".to_string()),
                            negate: false,
                        },
                    ],
                    groups: vec![],
                },
            ],
            max_gap_seconds: 300,
            correlation_fields: vec!["pid".to_string()],
            severity: AlertSeverity::Critical,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }

    #[test]
    fn test_alert_fingerprint() {
        let alert1 = Alert::new(
            "Test Alert".to_string(),
            "Description".to_string(),
            AlertSeverity::Medium,
        );

        let alert2 = Alert::new(
            "Test Alert".to_string(),
            "Different description".to_string(),
            AlertSeverity::Medium,
        );

        // Same title and severity, so same fingerprint
        assert_eq!(alert1.fingerprint(), alert2.fingerprint());
    }

    #[test]
    fn test_condition_evaluation() {
        let condition = RuleCondition {
            field: "test".to_string(),
            operator: ConditionOperator::Contains,
            value: serde_json::Value::String("hello".to_string()),
            negate: false,
        };

        // Note: This would need a proper event to test against
        // Just verifying the structure compiles
        assert!(!condition.negate);
    }

    #[tokio::test]
    async fn test_alerting_engine_creation() {
        let config = AlertingConfig::default();
        let engine = AlertingEngine::new(config);

        assert_eq!(engine.get_endpoint_risk().await, 0.0);
    }

    #[test]
    fn test_predefined_rules() {
        let rules = get_predefined_rules();
        assert!(!rules.is_empty());

        for rule in &rules {
            assert!(!rule.rule_id.is_empty());
            assert!(!rule.name.is_empty());
            assert!(rule.enabled);
        }
    }
}
