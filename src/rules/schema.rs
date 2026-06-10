//! Rule Schema Definitions
//!
//! Defines the YAML/JSON schema for detection rules.

use super::{RuleCategory, Severity, ResponseAction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root structure for a rule file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    /// File version for compatibility
    #[serde(default = "default_version")]
    pub version: String,
    /// Optional metadata about the rule file
    #[serde(default)]
    pub metadata: RuleFileMetadata,
    /// List of rules in this file
    pub rules: Vec<DetectionRule>,
}

fn default_version() -> String {
    "1.0".to_string()
}

/// Metadata about a rule file
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleFileMetadata {
    /// Author of the rules
    #[serde(default)]
    pub author: String,
    /// Description of the rule pack
    #[serde(default)]
    pub description: String,
    /// When rules were last updated
    #[serde(default)]
    pub last_updated: Option<String>,
    /// License information
    #[serde(default)]
    pub license: String,
    /// References or sources
    #[serde(default)]
    pub references: Vec<String>,
}

/// A single detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// Unique rule identifier (e.g., "CRED-001")
    pub id: String,
    /// Human-readable rule name
    pub name: String,
    /// Detailed description
    #[serde(default)]
    pub description: String,
    /// Rule category
    pub category: RuleCategory,
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
    /// Whether rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// MITRE ATT&CK mapping
    #[serde(default)]
    pub mitre: MitreMapping,
    /// Detection conditions
    pub conditions: RuleConditions,
    /// Response actions to take
    #[serde(default)]
    pub response: Vec<ResponseAction>,
    /// Tags for filtering/grouping
    #[serde(default)]
    pub tags: Vec<String>,
    /// Custom metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    /// False positive notes
    #[serde(default)]
    pub false_positives: Vec<String>,
    /// References
    #[serde(default)]
    pub references: Vec<String>,
    /// Risk score override (if not derived from severity)
    #[serde(default)]
    pub risk_score: Option<f32>,
    /// Confidence score for matches (0.0 - 1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f32,
}

fn default_true() -> bool {
    true
}

fn default_confidence() -> f32 {
    0.8
}

/// MITRE ATT&CK mapping
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitreMapping {
    /// Tactics (e.g., "credential-access", "execution")
    #[serde(default)]
    pub tactics: Vec<String>,
    /// Techniques (e.g., "T1003", "T1003.001")
    #[serde(default)]
    pub techniques: Vec<String>,
    /// Sub-techniques
    #[serde(default)]
    pub subtechniques: Vec<String>,
}

/// Detection conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConditions {
    /// Match ANY of these conditions (OR)
    #[serde(default)]
    pub any: Vec<FieldCondition>,
    /// Match ALL of these conditions (AND)
    #[serde(default)]
    pub all: Vec<FieldCondition>,
    /// Match NONE of these (exclusion)
    #[serde(default)]
    pub none: Vec<FieldCondition>,
    /// Complex condition expression (optional, overrides any/all/none)
    #[serde(default)]
    pub expression: Option<String>,
    /// Timeframe for aggregation rules
    #[serde(default)]
    pub timeframe: Option<Timeframe>,
    /// Count threshold for aggregation rules
    #[serde(default)]
    pub count: Option<CountCondition>,
}

/// A single field condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldCondition {
    /// Simple field match: field_name -> matcher
    Simple(HashMap<String, FieldMatcher>),
    /// Nested condition group
    Nested(NestedCondition),
}

/// Nested condition for complex logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedCondition {
    #[serde(default)]
    pub any: Vec<FieldCondition>,
    #[serde(default)]
    pub all: Vec<FieldCondition>,
    #[serde(default)]
    pub none: Vec<FieldCondition>,
}

/// Field matcher types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldMatcher {
    /// Exact value match
    Exact(String),
    /// Match any value in list
    List(Vec<String>),
    /// Complex matcher with operators
    Complex(ComplexMatcher),
}

/// Complex field matcher with operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexMatcher {
    /// Equals (exact match)
    #[serde(default)]
    pub eq: Option<String>,
    /// Not equals
    #[serde(default)]
    pub ne: Option<String>,
    /// Contains substring
    #[serde(default)]
    pub contains: Option<StringOrList>,
    /// Starts with
    #[serde(default)]
    pub starts_with: Option<StringOrList>,
    /// Ends with
    #[serde(default)]
    pub ends_with: Option<StringOrList>,
    /// Regex pattern
    #[serde(default)]
    pub regex: Option<String>,
    /// Matches glob pattern
    #[serde(default)]
    pub matches: Option<String>,
    /// In list
    #[serde(rename = "in")]
    #[serde(default)]
    pub in_list: Option<Vec<String>>,
    /// Not in list
    #[serde(default)]
    pub not_in: Option<Vec<String>>,
    /// Greater than (numeric)
    #[serde(default)]
    pub gt: Option<f64>,
    /// Greater than or equal (numeric)
    #[serde(default)]
    pub gte: Option<f64>,
    /// Less than (numeric)
    #[serde(default)]
    pub lt: Option<f64>,
    /// Less than or equal (numeric)
    #[serde(default)]
    pub lte: Option<f64>,
    /// Between range (numeric)
    #[serde(default)]
    pub between: Option<(f64, f64)>,
    /// Is null/empty
    #[serde(default)]
    pub is_null: Option<bool>,
    /// Case-insensitive matching
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
    /// Base64 encoded value to match
    #[serde(default)]
    pub base64: Option<String>,
    /// CIDR network match for IPs
    #[serde(default)]
    pub cidr: Option<String>,
}

/// String or list of strings helper
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrList {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            StringOrList::Single(s) => vec![s.clone()],
            StringOrList::Multiple(v) => v.clone(),
        }
    }
}

/// Timeframe specification for aggregation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeframe {
    /// Duration in seconds
    #[serde(default)]
    pub seconds: Option<u64>,
    /// Duration in minutes
    #[serde(default)]
    pub minutes: Option<u64>,
    /// Duration in hours
    #[serde(default)]
    pub hours: Option<u64>,
}

impl Timeframe {
    pub fn to_millis(&self) -> u64 {
        let secs = self.seconds.unwrap_or(0);
        let mins = self.minutes.unwrap_or(0);
        let hours = self.hours.unwrap_or(0);
        (hours * 3600 + mins * 60 + secs) * 1000
    }
}

/// Count condition for aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountCondition {
    /// Field to count by
    #[serde(default)]
    pub field: Option<String>,
    /// Minimum count threshold
    #[serde(default)]
    pub min: Option<u64>,
    /// Maximum count threshold
    #[serde(default)]
    pub max: Option<u64>,
    /// Exact count match
    #[serde(default)]
    pub exact: Option<u64>,
}

// ============================================================================
// Convenience constructors
// ============================================================================

impl DetectionRule {
    /// Create a new rule with minimal required fields
    pub fn new(id: &str, name: &str, category: RuleCategory) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            category,
            severity: Severity::Medium,
            enabled: true,
            mitre: MitreMapping::default(),
            conditions: RuleConditions {
                any: Vec::new(),
                all: Vec::new(),
                none: Vec::new(),
                expression: None,
                timeframe: None,
                count: None,
            },
            response: vec![ResponseAction::Alert],
            tags: Vec::new(),
            metadata: HashMap::new(),
            false_positives: Vec::new(),
            references: Vec::new(),
            risk_score: None,
            confidence: 0.8,
        }
    }

    /// Get the effective risk score
    pub fn effective_risk_score(&self) -> f32 {
        self.risk_score.unwrap_or_else(|| self.severity.to_risk_score())
    }
}

impl RuleConditions {
    /// Check if conditions are empty
    pub fn is_empty(&self) -> bool {
        self.any.is_empty() && self.all.is_empty() && self.none.is_empty() && self.expression.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
rules:
  - id: TEST-001
    name: Test Rule
    category: process
    severity: high
    mitre:
      tactics: [execution]
      techniques: [T1059.001]
    conditions:
      any:
        - process.name:
            contains: mimikatz
    response:
      - alert
      - kill_process
"#;
        let rule_file: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule_file.rules.len(), 1);
        assert_eq!(rule_file.rules[0].id, "TEST-001");
        assert_eq!(rule_file.rules[0].severity, Severity::High);
    }

    #[test]
    fn test_parse_complex_matcher() {
        let yaml = r#"
rules:
  - id: TEST-002
    name: Complex Test
    category: file
    conditions:
      all:
        - file.path:
            ends_with: [".exe", ".dll"]
            case_insensitive: true
        - file.entropy:
            gt: 7.5
"#;
        let rule_file: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(!rule_file.rules[0].conditions.all.is_empty());
    }

    #[test]
    fn test_timeframe_to_millis() {
        let tf = Timeframe {
            seconds: Some(30),
            minutes: Some(5),
            hours: Some(1),
        };
        assert_eq!(tf.to_millis(), (1 * 3600 + 5 * 60 + 30) * 1000);
    }
}
