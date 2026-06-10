//! Rule Loader
//!
//! Loads detection rules from YAML/JSON files on disk.

use super::schema::{DetectionRule, RuleFile};
use super::{RuleCategory, RuleStats};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn, error};

/// Rule loader for loading rules from disk
pub struct RuleLoader {
    /// Base directory for rules
    rules_dir: PathBuf,
    /// Loaded rules indexed by ID
    rules: HashMap<String, DetectionRule>,
    /// Rules indexed by category
    rules_by_category: HashMap<RuleCategory, Vec<String>>,
    /// Load statistics
    stats: RuleStats,
}

impl RuleLoader {
    /// Create a new rule loader
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Self {
        Self {
            rules_dir: rules_dir.as_ref().to_path_buf(),
            rules: HashMap::new(),
            rules_by_category: HashMap::new(),
            stats: RuleStats::default(),
        }
    }

    /// Load all rules from the rules directory
    pub fn load_all(&mut self) -> Result<&RuleStats> {
        self.rules.clear();
        self.rules_by_category.clear();
        self.stats = RuleStats::default();

        if !self.rules_dir.exists() {
            warn!(path = %self.rules_dir.display(), "Rules directory does not exist");
            return Ok(&self.stats);
        }

        // Load from main rules directory and subdirectories
        self.load_directory(&self.rules_dir.clone())?;

        // Load from packs subdirectory if exists
        let packs_dir = self.rules_dir.join("packs");
        if packs_dir.exists() {
            self.load_directory(&packs_dir)?;
        }

        self.stats.last_reload = Some(std::time::Instant::now());
        self.update_stats();

        info!(
            total = self.stats.total_rules,
            enabled = self.stats.enabled_rules,
            errors = self.stats.load_errors,
            "Rules loaded"
        );

        Ok(&self.stats)
    }

    /// Load rules from a single directory
    fn load_directory(&mut self, dir: &Path) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recursively load subdirectories
                self.load_directory(&path)?;
            } else if Self::is_rule_file(&path) {
                if let Err(e) = self.load_file(&path) {
                    error!(path = %path.display(), error = %e, "Failed to load rule file");
                    self.stats.load_errors += 1;
                }
            }
        }
        Ok(())
    }

    /// Check if a file is a rule file (YAML or JSON)
    fn is_rule_file(path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(ext.to_lowercase().as_str(), "yml" | "yaml" | "json")
    }

    /// Load rules from a single file
    pub fn load_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read rule file: {}", path.display()))?;

        let rule_file: RuleFile = if path.extension().map(|e| e == "json").unwrap_or(false) {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse JSON rule file: {}", path.display()))?
        } else {
            serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse YAML rule file: {}", path.display()))?
        };

        let count = rule_file.rules.len();

        for rule in rule_file.rules {
            self.add_rule(rule);
        }

        debug!(path = %path.display(), count, "Loaded rule file");
        Ok(count)
    }

    /// Add a single rule
    fn add_rule(&mut self, rule: DetectionRule) {
        let id = rule.id.clone();
        let category = rule.category;

        // Add to main index
        self.rules.insert(id.clone(), rule);

        // Add to category index
        self.rules_by_category
            .entry(category)
            .or_insert_with(Vec::new)
            .push(id);
    }

    /// Load rules from a YAML string (for testing or dynamic loading)
    pub fn load_from_string(&mut self, yaml: &str) -> Result<usize> {
        let rule_file: RuleFile = serde_yaml::from_str(yaml)
            .context("Failed to parse YAML rules")?;

        let count = rule_file.rules.len();
        for rule in rule_file.rules {
            self.add_rule(rule);
        }

        self.update_stats();
        Ok(count)
    }

    /// Get a rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&DetectionRule> {
        self.rules.get(id)
    }

    /// Get all rules
    pub fn get_all_rules(&self) -> impl Iterator<Item = &DetectionRule> {
        self.rules.values()
    }

    /// Get rules by category
    pub fn get_rules_by_category(&self, category: RuleCategory) -> Vec<&DetectionRule> {
        self.rules_by_category
            .get(&category)
            .map(|ids| ids.iter().filter_map(|id| self.rules.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get enabled rules by category
    pub fn get_enabled_rules_by_category(&self, category: RuleCategory) -> Vec<&DetectionRule> {
        self.get_rules_by_category(category)
            .into_iter()
            .filter(|r| r.enabled)
            .collect()
    }

    /// Get all enabled rules
    pub fn get_enabled_rules(&self) -> impl Iterator<Item = &DetectionRule> {
        self.rules.values().filter(|r| r.enabled)
    }

    /// Get loading statistics
    pub fn get_stats(&self) -> &RuleStats {
        &self.stats
    }

    /// Update internal statistics
    fn update_stats(&mut self) {
        self.stats.total_rules = self.rules.len();
        self.stats.enabled_rules = self.rules.values().filter(|r| r.enabled).count();

        self.stats.rules_by_category.clear();
        for (category, ids) in &self.rules_by_category {
            self.stats.rules_by_category.insert(*category, ids.len());
        }

        self.stats.rules_by_severity.clear();
        for rule in self.rules.values() {
            let severity = format!("{:?}", rule.severity);
            *self.stats.rules_by_severity.entry(severity).or_insert(0) += 1;
        }
    }

    /// Clear all loaded rules
    pub fn clear(&mut self) {
        self.rules.clear();
        self.rules_by_category.clear();
        self.stats = RuleStats::default();
    }

    /// Enable or disable a rule by ID
    pub fn set_rule_enabled(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.get_mut(id) {
            rule.enabled = enabled;
            self.update_stats();
            true
        } else {
            false
        }
    }

    /// Get the rules directory path
    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }
}

impl Default for RuleLoader {
    fn default() -> Self {
        let rules_dir = if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\Tamandua\\rules")
        } else {
            PathBuf::from("/etc/tamandua/rules")
        };
        Self::new(rules_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_from_string() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-001
    name: Test Rule
    category: process
    severity: critical
    conditions:
      any:
        - process.name: mimikatz.exe
    response:
      - alert
"#;
        let mut loader = RuleLoader::new("/tmp/test_rules");
        let count = loader.load_from_string(yaml).unwrap();

        assert_eq!(count, 1);
        assert_eq!(loader.get_stats().total_rules, 1);

        let rule = loader.get_rule("TEST-001").unwrap();
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.category, RuleCategory::Process);
    }

    #[test]
    fn test_rules_by_category() {
        let yaml = r#"
rules:
  - id: PROC-001
    name: Process Rule
    category: process
    conditions:
      any:
        - process.name: test
  - id: NET-001
    name: Network Rule
    category: network
    conditions:
      any:
        - network.port: 4444
"#;
        let mut loader = RuleLoader::new("/tmp/test_rules");
        loader.load_from_string(yaml).unwrap();

        let process_rules = loader.get_rules_by_category(RuleCategory::Process);
        assert_eq!(process_rules.len(), 1);
        assert_eq!(process_rules[0].id, "PROC-001");

        let network_rules = loader.get_rules_by_category(RuleCategory::Network);
        assert_eq!(network_rules.len(), 1);
        assert_eq!(network_rules[0].id, "NET-001");
    }

    #[test]
    fn test_enable_disable_rule() {
        let yaml = r#"
rules:
  - id: TEST-001
    name: Test
    category: process
    conditions:
      any: []
"#;
        let mut loader = RuleLoader::new("/tmp/test_rules");
        loader.load_from_string(yaml).unwrap();

        assert!(loader.get_rule("TEST-001").unwrap().enabled);
        loader.set_rule_enabled("TEST-001", false);
        assert!(!loader.get_rule("TEST-001").unwrap().enabled);
        assert_eq!(loader.get_stats().enabled_rules, 0);
    }
}
