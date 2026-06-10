//! Rule Compiler
//!
//! Compiles detection rules into efficient matchers for runtime evaluation.

use super::schema::{
    ComplexMatcher, DetectionRule, FieldCondition, FieldMatcher, NestedCondition,
    RuleConditions, StringOrList,
};
use super::RuleCategory;
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, warn};

/// Compiled rule ready for efficient matching
#[derive(Clone)]
pub struct CompiledRule {
    /// Original rule ID
    pub id: String,
    /// Original rule reference
    pub rule: Arc<DetectionRule>,
    /// Compiled condition matchers
    pub matcher: CompiledMatcher,
}

/// Compiled matcher for conditions
#[derive(Clone)]
pub struct CompiledMatcher {
    /// ANY conditions (OR logic)
    pub any: Vec<CompiledFieldCondition>,
    /// ALL conditions (AND logic)
    pub all: Vec<CompiledFieldCondition>,
    /// NONE conditions (exclusion)
    pub none: Vec<CompiledFieldCondition>,
}

/// Compiled field condition
#[derive(Clone)]
pub struct CompiledFieldCondition {
    /// Field name to match
    pub field: String,
    /// Compiled matcher
    pub matcher: CompiledFieldMatcher,
}

/// Compiled field matcher variants
#[derive(Clone)]
pub enum CompiledFieldMatcher {
    /// Exact string match (case-insensitive stored lowercase)
    Exact(String, bool), // value, case_insensitive
    /// Match any in list
    InList(Vec<String>, bool),
    /// Not in list
    NotInList(Vec<String>, bool),
    /// Contains substring(s)
    Contains(Vec<String>, bool),
    /// Starts with
    StartsWith(Vec<String>, bool),
    /// Ends with
    EndsWith(Vec<String>, bool),
    /// Regex pattern
    Regex(Regex),
    /// Glob pattern (converted to regex)
    Glob(Regex),
    /// Numeric greater than
    GreaterThan(f64),
    /// Numeric greater than or equal
    GreaterThanOrEqual(f64),
    /// Numeric less than
    LessThan(f64),
    /// Numeric less than or equal
    LessThanOrEqual(f64),
    /// Between range
    Between(f64, f64),
    /// Not equal
    NotEqual(String, bool),
    /// Is null/empty
    IsNull(bool),
    /// CIDR network match
    Cidr(CidrMatcher),
    /// Nested condition group (any/all/none)
    Nested(Box<CompiledMatcher>),
}

/// CIDR matcher for IP addresses
#[derive(Clone)]
pub struct CidrMatcher {
    network: u32,
    mask: u32,
}

impl CidrMatcher {
    pub fn new(cidr: &str) -> Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid CIDR format: {}", cidr);
        }

        let ip: std::net::Ipv4Addr = parts[0].parse()
            .with_context(|| format!("Invalid IP in CIDR: {}", parts[0]))?;
        let prefix: u32 = parts[1].parse()
            .with_context(|| format!("Invalid prefix in CIDR: {}", parts[1]))?;

        if prefix > 32 {
            anyhow::bail!("Invalid CIDR prefix: {}", prefix);
        }

        let network = u32::from(ip);
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };

        Ok(Self {
            network: network & mask,
            mask,
        })
    }

    pub fn matches(&self, ip_str: &str) -> bool {
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            let ip_num = u32::from(ip);
            (ip_num & self.mask) == self.network
        } else {
            false
        }
    }
}

/// Rule compiler
pub struct RuleCompiler {
    /// Cache of compiled regex patterns
    regex_cache: HashMap<String, Regex>,
}

impl RuleCompiler {
    /// Create a new rule compiler
    pub fn new() -> Self {
        Self {
            regex_cache: HashMap::new(),
        }
    }

    /// Compile a single rule
    pub fn compile(&mut self, rule: &DetectionRule) -> Result<CompiledRule> {
        let matcher = self.compile_conditions(&rule.conditions)?;

        Ok(CompiledRule {
            id: rule.id.clone(),
            rule: Arc::new(rule.clone()),
            matcher,
        })
    }

    /// Compile rule conditions
    fn compile_conditions(&mut self, conditions: &RuleConditions) -> Result<CompiledMatcher> {
        let any = conditions
            .any
            .iter()
            .filter_map(|c| self.compile_field_condition(c).ok())
            .flatten()
            .collect();

        let all = conditions
            .all
            .iter()
            .filter_map(|c| self.compile_field_condition(c).ok())
            .flatten()
            .collect();

        let none = conditions
            .none
            .iter()
            .filter_map(|c| self.compile_field_condition(c).ok())
            .flatten()
            .collect();

        Ok(CompiledMatcher { any, all, none })
    }

    /// Compile a field condition
    fn compile_field_condition(
        &mut self,
        condition: &FieldCondition,
    ) -> Result<Vec<CompiledFieldCondition>> {
        match condition {
            FieldCondition::Simple(map) => {
                let mut compiled = Vec::new();
                for (field, matcher) in map {
                    compiled.push(CompiledFieldCondition {
                        field: field.clone(),
                        matcher: self.compile_field_matcher(matcher)?,
                    });
                }
                Ok(compiled)
            }
            FieldCondition::Nested(nested) => {
                let inner_matcher = self.compile_nested_condition(nested)?;
                Ok(vec![CompiledFieldCondition {
                    field: "_nested".to_string(),
                    matcher: CompiledFieldMatcher::Nested(Box::new(inner_matcher)),
                }])
            }
        }
    }

    /// Compile a nested condition
    fn compile_nested_condition(&mut self, nested: &NestedCondition) -> Result<CompiledMatcher> {
        let any = nested
            .any
            .iter()
            .filter_map(|c| self.compile_field_condition(c).ok())
            .flatten()
            .collect();

        let all = nested
            .all
            .iter()
            .filter_map(|c| self.compile_field_condition(c).ok())
            .flatten()
            .collect();

        let none = nested
            .none
            .iter()
            .filter_map(|c| self.compile_field_condition(c).ok())
            .flatten()
            .collect();

        Ok(CompiledMatcher { any, all, none })
    }

    /// Compile a field matcher
    fn compile_field_matcher(&mut self, matcher: &FieldMatcher) -> Result<CompiledFieldMatcher> {
        match matcher {
            FieldMatcher::Exact(value) => {
                Ok(CompiledFieldMatcher::Exact(value.to_lowercase(), true))
            }
            FieldMatcher::List(values) => Ok(CompiledFieldMatcher::InList(
                values.iter().map(|v| v.to_lowercase()).collect(),
                true,
            )),
            FieldMatcher::Complex(complex) => self.compile_complex_matcher(complex),
        }
    }

    /// Compile a complex matcher
    fn compile_complex_matcher(&mut self, complex: &ComplexMatcher) -> Result<CompiledFieldMatcher> {
        let case_insensitive = complex.case_insensitive;

        // Process in order of precedence
        if let Some(ref pattern) = complex.regex {
            let regex = self.get_or_compile_regex(pattern, case_insensitive)?;
            return Ok(CompiledFieldMatcher::Regex(regex));
        }

        if let Some(ref pattern) = complex.matches {
            let regex = self.compile_glob_to_regex(pattern, case_insensitive)?;
            return Ok(CompiledFieldMatcher::Glob(regex));
        }

        if let Some(ref cidr) = complex.cidr {
            let matcher = CidrMatcher::new(cidr)?;
            return Ok(CompiledFieldMatcher::Cidr(matcher));
        }

        if let Some(ref list) = complex.in_list {
            let values = if case_insensitive {
                list.iter().map(|v| v.to_lowercase()).collect()
            } else {
                list.clone()
            };
            return Ok(CompiledFieldMatcher::InList(values, case_insensitive));
        }

        if let Some(ref list) = complex.not_in {
            let values = if case_insensitive {
                list.iter().map(|v| v.to_lowercase()).collect()
            } else {
                list.clone()
            };
            return Ok(CompiledFieldMatcher::NotInList(values, case_insensitive));
        }

        if let Some(ref strings) = complex.contains {
            let values = strings.to_vec();
            let values = if case_insensitive {
                values.iter().map(|v| v.to_lowercase()).collect()
            } else {
                values
            };
            return Ok(CompiledFieldMatcher::Contains(values, case_insensitive));
        }

        if let Some(ref strings) = complex.starts_with {
            let values = strings.to_vec();
            let values = if case_insensitive {
                values.iter().map(|v| v.to_lowercase()).collect()
            } else {
                values
            };
            return Ok(CompiledFieldMatcher::StartsWith(values, case_insensitive));
        }

        if let Some(ref strings) = complex.ends_with {
            let values = strings.to_vec();
            let values = if case_insensitive {
                values.iter().map(|v| v.to_lowercase()).collect()
            } else {
                values
            };
            return Ok(CompiledFieldMatcher::EndsWith(values, case_insensitive));
        }

        if let Some(value) = complex.gt {
            return Ok(CompiledFieldMatcher::GreaterThan(value));
        }

        if let Some(value) = complex.gte {
            return Ok(CompiledFieldMatcher::GreaterThanOrEqual(value));
        }

        if let Some(value) = complex.lt {
            return Ok(CompiledFieldMatcher::LessThan(value));
        }

        if let Some(value) = complex.lte {
            return Ok(CompiledFieldMatcher::LessThanOrEqual(value));
        }

        if let Some((min, max)) = complex.between {
            return Ok(CompiledFieldMatcher::Between(min, max));
        }

        if let Some(ref value) = complex.eq {
            let value = if case_insensitive {
                value.to_lowercase()
            } else {
                value.clone()
            };
            return Ok(CompiledFieldMatcher::Exact(value, case_insensitive));
        }

        if let Some(ref value) = complex.ne {
            let value = if case_insensitive {
                value.to_lowercase()
            } else {
                value.clone()
            };
            return Ok(CompiledFieldMatcher::NotEqual(value, case_insensitive));
        }

        if let Some(is_null) = complex.is_null {
            return Ok(CompiledFieldMatcher::IsNull(is_null));
        }

        // Default: empty match (always true)
        warn!("Complex matcher has no conditions, defaulting to exact empty match");
        Ok(CompiledFieldMatcher::Exact(String::new(), true))
    }

    /// Get or compile a regex pattern
    fn get_or_compile_regex(&mut self, pattern: &str, case_insensitive: bool) -> Result<Regex> {
        let cache_key = format!("{}:{}", case_insensitive, pattern);

        if let Some(regex) = self.regex_cache.get(&cache_key) {
            return Ok(regex.clone());
        }

        let regex = if case_insensitive {
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
        } else {
            Regex::new(pattern)
        }
        .with_context(|| format!("Invalid regex pattern: {}", pattern))?;

        self.regex_cache.insert(cache_key, regex.clone());
        Ok(regex)
    }

    /// Compile a glob pattern to regex
    fn compile_glob_to_regex(&mut self, glob: &str, case_insensitive: bool) -> Result<Regex> {
        // Convert glob to regex pattern
        let mut regex_pattern = String::from("^");

        for c in glob.chars() {
            match c {
                '*' => regex_pattern.push_str(".*"),
                '?' => regex_pattern.push('.'),
                '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                    regex_pattern.push('\\');
                    regex_pattern.push(c);
                }
                _ => regex_pattern.push(c),
            }
        }

        regex_pattern.push('$');
        self.get_or_compile_regex(&regex_pattern, case_insensitive)
    }
}

impl Default for RuleCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl CompiledFieldMatcher {
    /// Check if the matcher matches a string value
    pub fn matches_str(&self, value: &str) -> bool {
        match self {
            CompiledFieldMatcher::Exact(target, ci) => {
                if *ci {
                    value.to_lowercase() == *target
                } else {
                    value == target
                }
            }
            CompiledFieldMatcher::InList(list, ci) => {
                let test = if *ci { value.to_lowercase() } else { value.to_string() };
                list.contains(&test)
            }
            CompiledFieldMatcher::NotInList(list, ci) => {
                let test = if *ci { value.to_lowercase() } else { value.to_string() };
                !list.contains(&test)
            }
            CompiledFieldMatcher::Contains(patterns, ci) => {
                let test = if *ci { value.to_lowercase() } else { value.to_string() };
                patterns.iter().any(|p| test.contains(p))
            }
            CompiledFieldMatcher::StartsWith(patterns, ci) => {
                let test = if *ci { value.to_lowercase() } else { value.to_string() };
                patterns.iter().any(|p| test.starts_with(p))
            }
            CompiledFieldMatcher::EndsWith(patterns, ci) => {
                let test = if *ci { value.to_lowercase() } else { value.to_string() };
                patterns.iter().any(|p| test.ends_with(p))
            }
            CompiledFieldMatcher::Regex(regex) => regex.is_match(value),
            CompiledFieldMatcher::Glob(regex) => regex.is_match(value),
            CompiledFieldMatcher::NotEqual(target, ci) => {
                if *ci {
                    value.to_lowercase() != *target
                } else {
                    value != target
                }
            }
            CompiledFieldMatcher::IsNull(expect_null) => {
                let is_empty = value.is_empty();
                *expect_null == is_empty
            }
            CompiledFieldMatcher::Cidr(cidr) => cidr.matches(value),
            _ => false, // Numeric matchers don't apply to strings
        }
    }

    /// Check if the matcher matches a numeric value
    pub fn matches_num(&self, value: f64) -> bool {
        match self {
            CompiledFieldMatcher::GreaterThan(threshold) => value > *threshold,
            CompiledFieldMatcher::GreaterThanOrEqual(threshold) => value >= *threshold,
            CompiledFieldMatcher::LessThan(threshold) => value < *threshold,
            CompiledFieldMatcher::LessThanOrEqual(threshold) => value <= *threshold,
            CompiledFieldMatcher::Between(min, max) => value >= *min && value <= *max,
            _ => false, // String matchers don't apply to numbers
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = CompiledFieldMatcher::Exact("test".to_string(), true);
        assert!(matcher.matches_str("TEST"));
        assert!(matcher.matches_str("test"));
        assert!(!matcher.matches_str("testing"));
    }

    #[test]
    fn test_contains_match() {
        let matcher = CompiledFieldMatcher::Contains(vec!["mimikatz".to_string()], true);
        assert!(matcher.matches_str("C:\\temp\\mimikatz.exe"));
        assert!(matcher.matches_str("MIMIKATZ"));
        assert!(!matcher.matches_str("notepad"));
    }

    #[test]
    fn test_ends_with_match() {
        let matcher = CompiledFieldMatcher::EndsWith(vec![".exe".to_string(), ".dll".to_string()], true);
        assert!(matcher.matches_str("notepad.exe"));
        assert!(matcher.matches_str("kernel32.DLL"));
        assert!(!matcher.matches_str("file.txt"));
    }

    #[test]
    fn test_regex_match() {
        let regex = Regex::new(r"(?i)sekurlsa").unwrap();
        let matcher = CompiledFieldMatcher::Regex(regex);
        assert!(matcher.matches_str("sekurlsa::logonpasswords"));
        assert!(matcher.matches_str("SEKURLSA::minidump"));
        assert!(!matcher.matches_str("other command"));
    }

    #[test]
    fn test_numeric_matchers() {
        let gt = CompiledFieldMatcher::GreaterThan(7.0);
        assert!(gt.matches_num(7.5));
        assert!(!gt.matches_num(7.0));
        assert!(!gt.matches_num(6.0));

        let between = CompiledFieldMatcher::Between(5.0, 10.0);
        assert!(between.matches_num(7.5));
        assert!(between.matches_num(5.0));
        assert!(between.matches_num(10.0));
        assert!(!between.matches_num(4.9));
    }

    #[test]
    fn test_cidr_match() {
        let matcher = CidrMatcher::new("192.168.1.0/24").unwrap();
        assert!(matcher.matches("192.168.1.100"));
        assert!(matcher.matches("192.168.1.1"));
        assert!(!matcher.matches("192.168.2.1"));
        assert!(!matcher.matches("10.0.0.1"));
    }

    #[test]
    fn test_compile_rule() {
        use super::super::schema::*;

        let rule = DetectionRule {
            id: "TEST-001".to_string(),
            name: "Test Rule".to_string(),
            description: "Test description".to_string(),
            category: RuleCategory::Process,
            severity: super::super::Severity::High,
            enabled: true,
            mitre: MitreMapping::default(),
            conditions: RuleConditions {
                any: vec![FieldCondition::Simple({
                    let mut map = HashMap::new();
                    map.insert(
                        "process.name".to_string(),
                        FieldMatcher::Complex(ComplexMatcher {
                            contains: Some(StringOrList::Single("mimikatz".to_string())),
                            case_insensitive: true,
                            ..Default::default()
                        }),
                    );
                    map
                })],
                all: vec![],
                none: vec![],
                expression: None,
                timeframe: None,
                count: None,
            },
            response: vec![super::super::ResponseAction::Alert],
            tags: vec![],
            metadata: HashMap::new(),
            false_positives: vec![],
            references: vec![],
            risk_score: None,
            confidence: 0.9,
        };

        let mut compiler = RuleCompiler::new();
        let compiled = compiler.compile(&rule).unwrap();

        assert_eq!(compiled.id, "TEST-001");
        assert!(!compiled.matcher.any.is_empty());
    }
}

impl Default for ComplexMatcher {
    fn default() -> Self {
        Self {
            eq: None,
            ne: None,
            contains: None,
            starts_with: None,
            ends_with: None,
            regex: None,
            matches: None,
            in_list: None,
            not_in: None,
            gt: None,
            gte: None,
            lt: None,
            lte: None,
            between: None,
            is_null: None,
            case_insensitive: true,
            base64: None,
            cidr: None,
        }
    }
}
