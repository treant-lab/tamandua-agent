//! YARA rule scanning module
//!
//! Provides local YARA rule scanning capabilities for the agent.
//! Rules are received from the backend and compiled locally.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// YARA match result
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Name of the matching rule
    pub rule_name: String,
    /// Rule namespace (if any)
    pub namespace: Option<String>,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata (author, description, etc.)
    pub metadata: HashMap<String, String>,
    /// Matched strings with their offsets
    pub strings: Vec<MatchedString>,
}

/// A matched string from a YARA rule
#[derive(Debug, Clone)]
pub struct MatchedString {
    /// String identifier (e.g., "$s1")
    pub identifier: String,
    /// Offset where the string was found
    pub offset: usize,
    /// The matched data
    pub data: Vec<u8>,
}

/// YARA scanner with compiled rules
pub struct YaraScanner {
    /// Compiled rules
    rules: Arc<RwLock<Option<yara::Rules>>>,
    /// Rule source for recompilation
    rule_sources: Arc<RwLock<Vec<RuleSource>>>,
    /// Statistics
    scan_count: Arc<RwLock<u64>>,
    match_count: Arc<RwLock<u64>>,
}

/// Source of a YARA rule
#[derive(Clone)]
struct RuleSource {
    name: String,
    content: String,
}

impl YaraScanner {
    /// Create a new YARA scanner
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(None)),
            rule_sources: Arc::new(RwLock::new(Vec::new())),
            scan_count: Arc::new(RwLock::new(0)),
            match_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Load rules from string sources
    pub async fn load_rules(&self, rules: Vec<(String, String)>) -> Result<usize> {
        let mut sources = self.rule_sources.write().await;
        sources.clear();

        for (name, content) in &rules {
            sources.push(RuleSource {
                name: name.clone(),
                content: content.clone(),
            });
        }

        let rule_count = sources.len();
        drop(sources);

        // Compile rules
        self.compile_rules().await?;

        info!("Loaded {} YARA rules", rule_count);
        Ok(rule_count)
    }

    /// Add a single rule
    pub async fn add_rule(&self, name: String, content: String) -> Result<()> {
        {
            let mut sources = self.rule_sources.write().await;
            // Remove existing rule with same name
            sources.retain(|r| r.name != name);
            sources.push(RuleSource { name, content });
        }

        // Recompile all rules
        self.compile_rules().await?;
        Ok(())
    }

    /// Compile all loaded rule sources
    async fn compile_rules(&self) -> Result<()> {
        let sources = self.rule_sources.read().await;

        if sources.is_empty() {
            let mut rules = self.rules.write().await;
            *rules = None;
            return Ok(());
        }

        // Build compiler
        let mut compiler = yara::Compiler::new()?;

        for source in sources.iter() {
            match compiler.add_rules_str(&source.content) {
                Ok(_) => debug!("Compiled rule: {}", source.name),
                Err(e) => {
                    warn!("Failed to compile rule {}: {}", source.name, e);
                    // Continue with other rules
                }
            }
        }

        // Compile to rules
        let compiled = compiler
            .compile_rules()
            .context("Failed to compile YARA rules")?;

        let mut rules = self.rules.write().await;
        *rules = Some(compiled);

        Ok(())
    }

    /// Scan a file path
    pub async fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<YaraMatch>> {
        let path = path.as_ref().to_path_buf();
        let rules = self.rules.clone();
        let scan_count = self.scan_count.clone();
        let match_count = self.match_count.clone();

        tokio::task::spawn_blocking(move || {
            let rules_guard = futures::executor::block_on(rules.read());

            let compiled = match rules_guard.as_ref() {
                Some(r) => r,
                None => {
                    debug!("No YARA rules loaded, skipping scan");
                    return Ok(Vec::new());
                }
            };

            // Increment scan count
            {
                let mut count = futures::executor::block_on(scan_count.write());
                *count += 1;
            }

            // Perform scan
            let scan_result = compiled.scan_file(&path, 60)?;

            let matches: Vec<YaraMatch> = scan_result
                .iter()
                .map(|rule| {
                    let metadata: HashMap<String, String> = rule
                        .metadatas
                        .iter()
                        .filter_map(|m| {
                            let value = match &m.value {
                                yara::MetadataValue::Integer(i) => i.to_string(),
                                yara::MetadataValue::String(s) => s.to_string(),
                                yara::MetadataValue::Boolean(b) => b.to_string(),
                            };
                            Some((m.identifier.to_string(), value))
                        })
                        .collect();

                    let strings: Vec<MatchedString> = rule
                        .strings
                        .iter()
                        .map(|s| MatchedString {
                            identifier: s.identifier.to_string(),
                            offset: s.matches.first().map(|m| m.offset).unwrap_or(0),
                            data: s
                                .matches
                                .first()
                                .map(|m| m.data.clone())
                                .unwrap_or_default(),
                        })
                        .collect();

                    YaraMatch {
                        rule_name: rule.identifier.to_string(),
                        namespace: rule.namespace.map(|s| s.to_string()),
                        tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                        metadata,
                        strings,
                    }
                })
                .collect();

            // Update match count
            if !matches.is_empty() {
                let mut count = futures::executor::block_on(match_count.write());
                *count += matches.len() as u64;
            }

            Ok(matches)
        })
        .await?
    }

    /// Scan byte data
    pub async fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let data = data.to_vec();
        let rules = self.rules.clone();
        let scan_count = self.scan_count.clone();
        let match_count = self.match_count.clone();

        tokio::task::spawn_blocking(move || {
            let rules_guard = futures::executor::block_on(rules.read());

            let compiled = match rules_guard.as_ref() {
                Some(r) => r,
                None => {
                    debug!("No YARA rules loaded, skipping scan");
                    return Ok(Vec::new());
                }
            };

            // Increment scan count
            {
                let mut count = futures::executor::block_on(scan_count.write());
                *count += 1;
            }

            // Perform scan
            let scan_result = compiled.scan_mem(&data, 60)?;

            let matches: Vec<YaraMatch> = scan_result
                .iter()
                .map(|rule| {
                    let metadata: HashMap<String, String> = rule
                        .metadatas
                        .iter()
                        .filter_map(|m| {
                            let value = match &m.value {
                                yara::MetadataValue::Integer(i) => i.to_string(),
                                yara::MetadataValue::String(s) => s.to_string(),
                                yara::MetadataValue::Boolean(b) => b.to_string(),
                            };
                            Some((m.identifier.to_string(), value))
                        })
                        .collect();

                    let strings: Vec<MatchedString> = rule
                        .strings
                        .iter()
                        .map(|s| MatchedString {
                            identifier: s.identifier.to_string(),
                            offset: s.matches.first().map(|m| m.offset).unwrap_or(0),
                            data: s
                                .matches
                                .first()
                                .map(|m| m.data.clone())
                                .unwrap_or_default(),
                        })
                        .collect();

                    YaraMatch {
                        rule_name: rule.identifier.to_string(),
                        namespace: rule.namespace.map(|s| s.to_string()),
                        tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                        metadata,
                        strings,
                    }
                })
                .collect();

            // Update match count
            if !matches.is_empty() {
                let mut count = futures::executor::block_on(match_count.write());
                *count += matches.len() as u64;
            }

            Ok(matches)
        })
        .await?
    }

    /// Get scanner statistics
    pub async fn get_stats(&self) -> (u64, u64, usize) {
        let scan_count = *self.scan_count.read().await;
        let match_count = *self.match_count.read().await;
        let rule_count = self.rule_sources.read().await.len();
        (scan_count, match_count, rule_count)
    }

    /// Check if rules are loaded
    pub async fn has_rules(&self) -> bool {
        self.rules.read().await.is_some()
    }

    /// Clear all rules
    pub async fn clear_rules(&self) {
        let mut sources = self.rule_sources.write().await;
        sources.clear();

        let mut rules = self.rules.write().await;
        *rules = None;

        info!("Cleared all YARA rules");
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
        rule test_rule {
            meta:
                description = "Test rule"
                author = "Test"
            strings:
                $test = "test_string"
            condition:
                $test
        }
    "#;

    #[tokio::test]
    async fn test_load_rules() {
        let scanner = YaraScanner::new();
        let result = scanner
            .load_rules(vec![("test".to_string(), TEST_RULE.to_string())])
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        assert!(scanner.has_rules().await);
    }

    #[tokio::test]
    async fn test_scan_bytes() {
        let scanner = YaraScanner::new();
        scanner
            .load_rules(vec![("test".to_string(), TEST_RULE.to_string())])
            .await
            .unwrap();

        let matches = scanner
            .scan_bytes(b"this is a test_string for matching")
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "test_rule");
    }

    #[tokio::test]
    async fn test_no_match() {
        let scanner = YaraScanner::new();
        scanner
            .load_rules(vec![("test".to_string(), TEST_RULE.to_string())])
            .await
            .unwrap();

        let matches = scanner
            .scan_bytes(b"no matching content here")
            .await
            .unwrap();
        assert!(matches.is_empty());
    }
}
