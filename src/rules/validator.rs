//! Rule Validator
//!
//! Validates detection rules for syntax errors, semantic issues,
//! and best practices.

use super::schema::{
    ComplexMatcher, DetectionRule, FieldCondition, FieldMatcher, RuleConditions, RuleFile,
};
use super::RuleCategory;
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use tracing::{debug, warn};

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Rule ID (if applicable)
    pub rule_id: Option<String>,
    /// Error severity
    pub severity: ValidationSeverity,
    /// Field that caused the error (if applicable)
    pub field: Option<String>,
    /// Error message
    pub message: String,
    /// Error code for programmatic handling
    pub code: ValidationErrorCode,
}

/// Validation severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

/// Validation error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorCode {
    // Syntax errors
    InvalidRegex,
    InvalidCidr,
    InvalidFieldName,
    EmptyConditions,
    InvalidTimeframe,

    // Semantic errors
    DuplicateRuleId,
    MissingRequiredField,
    InvalidSeverity,
    InvalidCategory,
    ConflictingConditions,

    // Best practice warnings
    NoMitreMapping,
    NoDescription,
    NoFalsePositives,
    VeryBroadCondition,
    HighFalsePositiveRisk,
    NoResponseActions,
}

/// Rule validator
pub struct RuleValidator {
    /// Known field names by category
    known_fields: std::collections::HashMap<RuleCategory, HashSet<String>>,
    /// Seen rule IDs for duplicate detection
    seen_ids: HashSet<String>,
}

impl RuleValidator {
    /// Create a new validator
    pub fn new() -> Self {
        let mut known_fields = std::collections::HashMap::new();

        // Process fields
        known_fields.insert(
            RuleCategory::Process,
            [
                "process.name",
                "process.path",
                "process.cmdline",
                "process.command_line",
                "process.pid",
                "process.ppid",
                "process.parent_name",
                "process.parent_path",
                "process.user",
                "process.sha256",
                "process.entropy",
                "process.is_elevated",
                "process.is_signed",
                "process.signer",
                "process.company_name",
                "process.file_version",
                "process.product_name",
                "process.start_time",
                "process.cpu_usage",
                "process.memory_bytes",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // File fields
        known_fields.insert(
            RuleCategory::File,
            [
                "file.path",
                "file.name",
                "file.extension",
                "file.operation",
                "file.entropy",
                "file.sha256",
                "file.size",
                "file.process_name",
                "file.process_pid",
                "file.is_encrypted",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // Network fields
        known_fields.insert(
            RuleCategory::Network,
            [
                "network.remote_ip",
                "network.remote_port",
                "network.local_ip",
                "network.local_port",
                "network.protocol",
                "network.direction",
                "network.bytes_sent",
                "network.bytes_received",
                "network.process_name",
                "network.process_pid",
                "network.state",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // Registry fields
        known_fields.insert(
            RuleCategory::Registry,
            [
                "registry.key_path",
                "registry.value_name",
                "registry.value_data",
                "registry.operation",
                "registry.process_name",
                "registry.process_pid",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // DNS fields
        known_fields.insert(
            RuleCategory::Dns,
            [
                "dns.query",
                "dns.query_type",
                "dns.response",
                "dns.resolved_ips",
                "dns.process_name",
                "dns.process_pid",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // Behavioral fields (aggregate/computed)
        known_fields.insert(
            RuleCategory::Behavioral,
            [
                "behavior.event_count",
                "behavior.event_rate",
                "behavior.unique_destinations",
                "behavior.unique_files",
                "behavior.risk_score",
                "behavior.parent_child_anomaly",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        Self {
            known_fields,
            seen_ids: HashSet::new(),
        }
    }

    /// Validate a rule file
    pub fn validate_file(&mut self, rule_file: &RuleFile) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for rule in &rule_file.rules {
            errors.extend(self.validate_rule(rule));
        }

        errors
    }

    /// Validate a single rule
    pub fn validate_rule(&mut self, rule: &DetectionRule) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Check for duplicate ID
        if self.seen_ids.contains(&rule.id) {
            errors.push(ValidationError {
                rule_id: Some(rule.id.clone()),
                severity: ValidationSeverity::Error,
                field: Some("id".to_string()),
                message: format!("Duplicate rule ID: {}", rule.id),
                code: ValidationErrorCode::DuplicateRuleId,
            });
        } else {
            self.seen_ids.insert(rule.id.clone());
        }

        // Check for empty conditions
        if rule.conditions.is_empty() {
            errors.push(ValidationError {
                rule_id: Some(rule.id.clone()),
                severity: ValidationSeverity::Error,
                field: Some("conditions".to_string()),
                message: "Rule has no conditions defined".to_string(),
                code: ValidationErrorCode::EmptyConditions,
            });
        }

        // Validate conditions
        errors.extend(self.validate_conditions(&rule.id, &rule.conditions, rule.category));

        // Best practice warnings
        if rule.mitre.tactics.is_empty() && rule.mitre.techniques.is_empty() {
            errors.push(ValidationError {
                rule_id: Some(rule.id.clone()),
                severity: ValidationSeverity::Warning,
                field: Some("mitre".to_string()),
                message: "Rule has no MITRE ATT&CK mapping".to_string(),
                code: ValidationErrorCode::NoMitreMapping,
            });
        }

        if rule.description.is_empty() {
            errors.push(ValidationError {
                rule_id: Some(rule.id.clone()),
                severity: ValidationSeverity::Warning,
                field: Some("description".to_string()),
                message: "Rule has no description".to_string(),
                code: ValidationErrorCode::NoDescription,
            });
        }

        if rule.false_positives.is_empty() {
            errors.push(ValidationError {
                rule_id: Some(rule.id.clone()),
                severity: ValidationSeverity::Info,
                field: Some("false_positives".to_string()),
                message: "Rule has no documented false positives".to_string(),
                code: ValidationErrorCode::NoFalsePositives,
            });
        }

        if rule.response.is_empty() {
            errors.push(ValidationError {
                rule_id: Some(rule.id.clone()),
                severity: ValidationSeverity::Warning,
                field: Some("response".to_string()),
                message: "Rule has no response actions defined".to_string(),
                code: ValidationErrorCode::NoResponseActions,
            });
        }

        errors
    }

    /// Validate conditions
    fn validate_conditions(
        &self,
        rule_id: &str,
        conditions: &RuleConditions,
        category: RuleCategory,
    ) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for condition in &conditions.any {
            errors.extend(self.validate_field_condition(rule_id, condition, category));
        }

        for condition in &conditions.all {
            errors.extend(self.validate_field_condition(rule_id, condition, category));
        }

        for condition in &conditions.none {
            errors.extend(self.validate_field_condition(rule_id, condition, category));
        }

        // Validate timeframe if present
        if let Some(ref timeframe) = conditions.timeframe {
            if timeframe.to_millis() == 0 {
                errors.push(ValidationError {
                    rule_id: Some(rule_id.to_string()),
                    severity: ValidationSeverity::Error,
                    field: Some("timeframe".to_string()),
                    message: "Timeframe results in 0 milliseconds".to_string(),
                    code: ValidationErrorCode::InvalidTimeframe,
                });
            }
        }

        errors
    }

    /// Validate a field condition
    fn validate_field_condition(
        &self,
        rule_id: &str,
        condition: &FieldCondition,
        category: RuleCategory,
    ) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        match condition {
            FieldCondition::Simple(map) => {
                for (field, matcher) in map {
                    // Check if field is known
                    if let Some(known) = self.known_fields.get(&category) {
                        if !known.contains(field) && !field.starts_with("_") {
                            errors.push(ValidationError {
                                rule_id: Some(rule_id.to_string()),
                                severity: ValidationSeverity::Warning,
                                field: Some(field.clone()),
                                message: format!(
                                    "Unknown field '{}' for category {:?}",
                                    field, category
                                ),
                                code: ValidationErrorCode::InvalidFieldName,
                            });
                        }
                    }

                    errors.extend(self.validate_field_matcher(rule_id, field, matcher));
                }
            }
            FieldCondition::Nested(nested) => {
                for condition in &nested.any {
                    errors.extend(self.validate_field_condition(rule_id, condition, category));
                }
                for condition in &nested.all {
                    errors.extend(self.validate_field_condition(rule_id, condition, category));
                }
                for condition in &nested.none {
                    errors.extend(self.validate_field_condition(rule_id, condition, category));
                }
            }
        }

        errors
    }

    /// Validate a field matcher
    fn validate_field_matcher(
        &self,
        rule_id: &str,
        field: &str,
        matcher: &FieldMatcher,
    ) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if let FieldMatcher::Complex(complex) = matcher {
            // Validate regex
            if let Some(ref pattern) = complex.regex {
                if Regex::new(pattern).is_err() {
                    errors.push(ValidationError {
                        rule_id: Some(rule_id.to_string()),
                        severity: ValidationSeverity::Error,
                        field: Some(field.to_string()),
                        message: format!("Invalid regex pattern: {}", pattern),
                        code: ValidationErrorCode::InvalidRegex,
                    });
                }
            }

            // Validate CIDR
            if let Some(ref cidr) = complex.cidr {
                if !self.is_valid_cidr(cidr) {
                    errors.push(ValidationError {
                        rule_id: Some(rule_id.to_string()),
                        severity: ValidationSeverity::Error,
                        field: Some(field.to_string()),
                        message: format!("Invalid CIDR notation: {}", cidr),
                        code: ValidationErrorCode::InvalidCidr,
                    });
                }
            }

            // Check for very broad conditions that might cause false positives
            if complex.contains.is_some() {
                if let Some(ref strings) = complex.contains {
                    let patterns = strings.to_vec();
                    for pattern in patterns {
                        if pattern.len() <= 2 {
                            errors.push(ValidationError {
                                rule_id: Some(rule_id.to_string()),
                                severity: ValidationSeverity::Warning,
                                field: Some(field.to_string()),
                                message: format!(
                                    "Very short 'contains' pattern '{}' may cause false positives",
                                    pattern
                                ),
                                code: ValidationErrorCode::VeryBroadCondition,
                            });
                        }
                    }
                }
            }
        }

        errors
    }

    /// Check if a CIDR notation is valid
    fn is_valid_cidr(&self, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        // Check IP
        if parts[0].parse::<std::net::Ipv4Addr>().is_err() {
            return false;
        }

        // Check prefix
        if let Ok(prefix) = parts[1].parse::<u32>() {
            prefix <= 32
        } else {
            false
        }
    }

    /// Reset the validator state (clear seen IDs)
    pub fn reset(&mut self) {
        self.seen_ids.clear();
    }
}

impl Default for RuleValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate rules and return only errors (filter out warnings)
pub fn validate_rules_strict(rules: &[DetectionRule]) -> Result<()> {
    let mut validator = RuleValidator::new();
    let mut all_errors = Vec::new();

    for rule in rules {
        let errors = validator.validate_rule(rule);
        let fatal_errors: Vec<_> = errors
            .into_iter()
            .filter(|e| e.severity == ValidationSeverity::Error)
            .collect();
        all_errors.extend(fatal_errors);
    }

    if all_errors.is_empty() {
        Ok(())
    } else {
        let messages: Vec<String> = all_errors
            .iter()
            .map(|e| {
                format!(
                    "[{}] {}: {}",
                    e.rule_id.as_deref().unwrap_or("unknown"),
                    e.field.as_deref().unwrap_or(""),
                    e.message
                )
            })
            .collect();
        anyhow::bail!("Rule validation failed:\n{}", messages.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_conditions() {
        let mut validator = RuleValidator::new();
        let rule = DetectionRule::new("TEST-001", "Test", RuleCategory::Process);

        let errors = validator.validate_rule(&rule);
        assert!(errors.iter().any(|e| e.code == ValidationErrorCode::EmptyConditions));
    }

    #[test]
    fn test_validate_duplicate_id() {
        let mut validator = RuleValidator::new();

        let rule1 = DetectionRule::new("DUP-001", "Test 1", RuleCategory::Process);
        let rule2 = DetectionRule::new("DUP-001", "Test 2", RuleCategory::Process);

        let _ = validator.validate_rule(&rule1);
        let errors = validator.validate_rule(&rule2);

        assert!(errors.iter().any(|e| e.code == ValidationErrorCode::DuplicateRuleId));
    }

    #[test]
    fn test_validate_invalid_regex() {
        let yaml = r#"
rules:
  - id: TEST-001
    name: Test
    category: process
    conditions:
      any:
        - process.name:
            regex: "[invalid(regex"
"#;
        let rule_file: super::super::schema::RuleFile = serde_yaml::from_str(yaml).unwrap();
        let mut validator = RuleValidator::new();
        let errors = validator.validate_file(&rule_file);

        assert!(errors.iter().any(|e| e.code == ValidationErrorCode::InvalidRegex));
    }

    #[test]
    fn test_validate_invalid_cidr() {
        let yaml = r#"
rules:
  - id: TEST-001
    name: Test
    category: network
    conditions:
      any:
        - network.remote_ip:
            cidr: "invalid.cidr/99"
"#;
        let rule_file: super::super::schema::RuleFile = serde_yaml::from_str(yaml).unwrap();
        let mut validator = RuleValidator::new();
        let errors = validator.validate_file(&rule_file);

        assert!(errors.iter().any(|e| e.code == ValidationErrorCode::InvalidCidr));
    }

    #[test]
    fn test_validate_missing_mitre() {
        let mut validator = RuleValidator::new();
        let rule = DetectionRule::new("TEST-001", "Test", RuleCategory::Process);

        let errors = validator.validate_rule(&rule);
        assert!(errors.iter().any(|e| e.code == ValidationErrorCode::NoMitreMapping));
    }
}
