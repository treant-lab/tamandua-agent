//! External Detection Rule Engine
//!
//! Provides a configurable rule-based detection system that externalizes
//! hardcoded detection logic into YAML/JSON rule files.
//!
//! Features:
//! - Load rules from YAML/JSON files
//! - Hot-reload rules without restart
//! - Compile rules to efficient matchers
//! - Validate rule syntax
//! - Support for multiple rule categories (process, file, network, registry, behavioral)

pub mod loader;
pub mod compiler;
pub mod schema;
pub mod validator;
pub mod engine;
pub mod hot_reload;

pub use engine::RuleEngine;
pub use loader::RuleLoader;
pub use schema::*;
pub use validator::RuleValidator;
pub use hot_reload::HotReloadWatcher;

use crate::collectors::{TelemetryEvent, EventPayload, Detection, DetectionType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

/// Rule match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Rule ID that matched
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Match confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Description of the match
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Recommended response actions
    pub response_actions: Vec<ResponseAction>,
    /// Additional metadata from the rule
    pub metadata: HashMap<String, serde_json::Value>,
    /// Matched field values for context
    pub matched_fields: HashMap<String, String>,
}

impl RuleMatch {
    /// Convert to Detection event
    pub fn to_detection(&self) -> Detection {
        Detection {
            detection_type: match self.severity {
                Severity::Critical | Severity::High => DetectionType::Behavioral,
                Severity::Medium => DetectionType::Heuristic,
                Severity::Low | Severity::Info => DetectionType::Behavioral,
            },
            rule_name: format!("rule_{}", self.rule_id),
            confidence: self.confidence,
            description: self.description.clone(),
            mitre_tactics: self.mitre_tactics.clone(),
            mitre_techniques: self.mitre_techniques.clone(),
        }
    }
}

/// Rule severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn to_risk_score(&self) -> f32 {
        match self {
            Severity::Critical => 95.0,
            Severity::High => 80.0,
            Severity::Medium => 60.0,
            Severity::Low => 40.0,
            Severity::Info => 20.0,
        }
    }
}

/// Response actions that can be triggered by rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    Alert,
    KillProcess,
    QuarantineFile,
    IsolateHost,
    BlockNetwork,
    CollectEvidence,
    SubmitSample,
    NotifySOC,
    LogOnly,
}

/// Rule categories for organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RuleCategory {
    Process,
    File,
    Network,
    Registry,
    Dns,
    Behavioral,
    Memory,
    Authentication,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleCategory::Process => write!(f, "process"),
            RuleCategory::File => write!(f, "file"),
            RuleCategory::Network => write!(f, "network"),
            RuleCategory::Registry => write!(f, "registry"),
            RuleCategory::Dns => write!(f, "dns"),
            RuleCategory::Behavioral => write!(f, "behavioral"),
            RuleCategory::Memory => write!(f, "memory"),
            RuleCategory::Authentication => write!(f, "authentication"),
        }
    }
}

/// Statistics about loaded rules
#[derive(Debug, Clone, Default)]
pub struct RuleStats {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub rules_by_category: HashMap<RuleCategory, usize>,
    pub rules_by_severity: HashMap<String, usize>,
    pub last_reload: Option<std::time::Instant>,
    pub load_errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_risk_score() {
        assert_eq!(Severity::Critical.to_risk_score(), 95.0);
        assert_eq!(Severity::High.to_risk_score(), 80.0);
        assert_eq!(Severity::Medium.to_risk_score(), 60.0);
        assert_eq!(Severity::Low.to_risk_score(), 40.0);
        assert_eq!(Severity::Info.to_risk_score(), 20.0);
    }

    #[test]
    fn test_rule_category_display() {
        assert_eq!(format!("{}", RuleCategory::Process), "process");
        assert_eq!(format!("{}", RuleCategory::Network), "network");
    }
}
