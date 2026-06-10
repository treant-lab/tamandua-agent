//! Local rule engine for offline detection.
//!
//! Evaluates YARA and Sigma rules locally without backend connectivity.
//! Rules are loaded from disk and cached in memory.

// Local rule engine. Stub function parameters are intentional placeholders
// for upcoming YARA/Sigma offline integrations.
#![allow(dead_code, unused_variables)]

use crate::collectors::{Detection, DetectionType};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

#[cfg(feature = "yara")]
use crate::analyzers::yara::YaraScanner;

/// Local rule engine for offline detection.
pub struct LocalRuleEngine {
    #[cfg(feature = "yara")]
    yara_scanner: Option<Arc<YaraScanner>>,

    #[cfg(not(feature = "yara"))]
    _yara_placeholder: (),

    /// Loaded Sigma rules (simple pattern matching)
    sigma_patterns: Vec<SigmaPattern>,

    /// Statistics
    files_scanned: AtomicU64,
    detections_found: AtomicU64,
}

/// Simplified Sigma pattern for offline matching.
#[derive(Debug, Clone)]
pub struct SigmaPattern {
    pub name: String,
    pub logsource: String,
    pub patterns: Vec<String>,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
}

impl LocalRuleEngine {
    /// Create a new local rule engine.
    pub async fn new(yara_rules_dir: &str, sigma_rules_dir: &str) -> Self {
        info!(
            yara_dir = %yara_rules_dir,
            sigma_dir = %sigma_rules_dir,
            "Initializing local rule engine"
        );

        // Load YARA rules
        #[cfg(feature = "yara")]
        let yara_scanner = {
            let scanner = Arc::new(YaraScanner::new());
            let rules_path = Path::new(yara_rules_dir);
            if rules_path.is_dir() {
                let mut rule_files = Vec::new();
                if let Ok(entries) = std::fs::read_dir(rules_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let ext = path
                            .extension()
                            .map(|e| e.to_string_lossy().to_lowercase())
                            .unwrap_or_default();
                        if ext == "yar" || ext == "yara" {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                let name = path
                                    .file_stem()
                                    .map(|s| s.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                rule_files.push((name, content));
                            }
                        }
                    }
                }
                if !rule_files.is_empty() {
                    match scanner.load_rules(rule_files).await {
                        Ok(n) => info!(count = n, "Loaded local YARA rules"),
                        Err(e) => warn!(error = %e, "Failed to load local YARA rules"),
                    }
                } else {
                    info!(dir = %yara_rules_dir, "No YARA rule files found in directory");
                }
            } else {
                info!(dir = %yara_rules_dir, "YARA rules directory does not exist");
            }
            Some(scanner)
        };

        // Load Sigma rules (simplified pattern extraction)
        let sigma_patterns = Self::load_sigma_patterns(sigma_rules_dir);

        Self {
            #[cfg(feature = "yara")]
            yara_scanner,
            #[cfg(not(feature = "yara"))]
            _yara_placeholder: (),
            sigma_patterns,
            files_scanned: AtomicU64::new(0),
            detections_found: AtomicU64::new(0),
        }
    }

    /// Load Sigma rules and extract patterns for simple matching.
    fn load_sigma_patterns(rules_dir: &str) -> Vec<SigmaPattern> {
        let mut patterns = Vec::new();
        let rules_path = Path::new(rules_dir);

        if !rules_path.is_dir() {
            info!(path = %rules_dir, "Sigma rules directory not found");
            return patterns;
        }

        if let Ok(entries) = std::fs::read_dir(rules_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default();

                if ext == "yml" || ext == "yaml" {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Some(pattern) = Self::parse_sigma_rule(&content) {
                            patterns.push(pattern);
                        }
                    }
                }
            }
        }

        info!(count = patterns.len(), "Loaded local Sigma patterns");
        patterns
    }

    /// Parse a Sigma rule YAML and extract searchable patterns.
    fn parse_sigma_rule(content: &str) -> Option<SigmaPattern> {
        // Simplified YAML parsing for offline matching
        // In production, use full Sigma parser
        let mut name = String::new();
        let mut logsource = String::new();
        let mut patterns = Vec::new();
        let mut severity = "medium".to_string();
        let mut mitre = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("title:") {
                name = line
                    .strip_prefix("title:")?
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .to_string();
            } else if line.starts_with("level:") {
                severity = line.strip_prefix("level:")?.trim().to_string();
            } else if line.starts_with("product:") || line.starts_with("service:") {
                logsource = line.split(':').nth(1)?.trim().to_string();
            } else if line.starts_with("- attack.t") || line.starts_with("- attack.T") {
                let technique = line.strip_prefix("- attack.")?.trim().to_uppercase();
                mitre.push(technique);
            } else if line.contains('|') && line.contains(':') {
                // Detection condition like "CommandLine|contains:"
                if let Some(value) = line.split(':').nth(1) {
                    let cleaned = value.trim().trim_matches('\'').trim_matches('"');
                    if !cleaned.is_empty() {
                        patterns.push(cleaned.to_string());
                    }
                }
            } else if line.starts_with("- '") || line.starts_with("- \"") {
                // Pattern list item
                let value = line
                    .strip_prefix("- ")?
                    .trim_matches('\'')
                    .trim_matches('"');
                if !value.is_empty() {
                    patterns.push(value.to_string());
                }
            }
        }

        if name.is_empty() || patterns.is_empty() {
            return None;
        }

        Some(SigmaPattern {
            name,
            logsource,
            patterns,
            severity,
            mitre_techniques: mitre,
        })
    }

    /// Analyze a file using local rules.
    pub async fn analyze_file(&self, path: &Path) -> Vec<Detection> {
        self.files_scanned.fetch_add(1, Ordering::Relaxed);
        let detections = Vec::new();

        // YARA scan
        #[cfg(feature = "yara")]
        if let Some(ref scanner) = self.yara_scanner {
            match scanner.scan_file(path).await {
                Ok(matches) => {
                    for m in matches {
                        detections.push(Detection {
                            detection_type: DetectionType::Yara,
                            rule_name: format!("LOCAL_YARA_{}", m.rule_name),
                            confidence: 0.85,
                            description: format!(
                                "Local YARA rule '{}' matched on {}",
                                m.rule_name,
                                path.display()
                            ),
                            mitre_tactics: vec!["Execution".to_string()],
                            mitre_techniques: vec![],
                        });
                    }
                }
                Err(e) => {
                    debug!(error = %e, path = %path.display(), "YARA scan failed");
                }
            }
        }

        if !detections.is_empty() {
            self.detections_found
                .fetch_add(detections.len() as u64, Ordering::Relaxed);
        }

        detections
    }

    /// Analyze raw bytes using local rules.
    pub async fn analyze_bytes(&self, data: &[u8], label: &str) -> Vec<Detection> {
        self.files_scanned.fetch_add(1, Ordering::Relaxed);
        let detections = Vec::new();

        // YARA scan
        #[cfg(feature = "yara")]
        if let Some(ref scanner) = self.yara_scanner {
            match scanner.scan_bytes(data).await {
                Ok(matches) => {
                    for m in matches {
                        detections.push(Detection {
                            detection_type: DetectionType::Yara,
                            rule_name: format!("LOCAL_YARA_{}", m.rule_name),
                            confidence: 0.85,
                            description: format!(
                                "Local YARA rule '{}' matched on {}",
                                m.rule_name, label
                            ),
                            mitre_tactics: vec!["Execution".to_string()],
                            mitre_techniques: vec![],
                        });
                    }
                }
                Err(e) => {
                    debug!(error = %e, label = %label, "YARA scan failed");
                }
            }
        }

        if !detections.is_empty() {
            self.detections_found
                .fetch_add(detections.len() as u64, Ordering::Relaxed);
        }

        detections
    }

    /// Check if a command line matches any Sigma patterns.
    pub fn check_command_line(&self, cmd: &str) -> Vec<Detection> {
        let mut detections = Vec::new();
        let cmd_lower = cmd.to_lowercase();

        for pattern in &self.sigma_patterns {
            for p in &pattern.patterns {
                if cmd_lower.contains(&p.to_lowercase()) {
                    detections.push(Detection {
                        detection_type: DetectionType::Sigma,
                        rule_name: format!("LOCAL_SIGMA_{}", pattern.name.replace(' ', "_")),
                        confidence: 0.75,
                        description: format!(
                            "Local Sigma rule '{}' matched pattern '{}' in command: {}",
                            pattern.name,
                            p,
                            cmd.chars().take(100).collect::<String>()
                        ),
                        mitre_tactics: vec!["Execution".to_string()],
                        mitre_techniques: pattern.mitre_techniques.clone(),
                    });
                    break;
                }
            }
        }

        if !detections.is_empty() {
            self.detections_found
                .fetch_add(detections.len() as u64, Ordering::Relaxed);
        }

        detections
    }

    /// Check if an event matches any Sigma patterns.
    pub fn check_event(
        &self,
        event_data: &std::collections::HashMap<String, String>,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Combine all event field values for pattern matching
        let combined: String = event_data
            .values()
            .map(|v| v.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        for pattern in &self.sigma_patterns {
            for p in &pattern.patterns {
                if combined.contains(&p.to_lowercase()) {
                    detections.push(Detection {
                        detection_type: DetectionType::Sigma,
                        rule_name: format!("LOCAL_SIGMA_{}", pattern.name.replace(' ', "_")),
                        confidence: 0.70,
                        description: format!(
                            "Local Sigma rule '{}' matched pattern '{}' in event",
                            pattern.name, p,
                        ),
                        mitre_tactics: vec!["Execution".to_string()],
                        mitre_techniques: pattern.mitre_techniques.clone(),
                    });
                    break;
                }
            }
        }

        if !detections.is_empty() {
            self.detections_found
                .fetch_add(detections.len() as u64, Ordering::Relaxed);
        }

        detections
    }

    /// Get statistics.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.files_scanned.load(Ordering::Relaxed),
            self.detections_found.load(Ordering::Relaxed),
        )
    }

    /// Get loaded rule counts.
    pub fn rule_counts(&self) -> (usize, usize) {
        let yara_count = {
            #[cfg(feature = "yara")]
            {
                if self.yara_scanner.is_some() {
                    1
                } else {
                    0
                } // Simplified count
            }
            #[cfg(not(feature = "yara"))]
            {
                0
            }
        };
        (yara_count, self.sigma_patterns.len())
    }

    /// Get list of loaded Sigma pattern names.
    pub fn sigma_pattern_names(&self) -> Vec<&str> {
        self.sigma_patterns
            .iter()
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Add a Sigma pattern at runtime.
    pub fn add_sigma_pattern(&mut self, pattern: SigmaPattern) {
        info!(name = %pattern.name, "Added Sigma pattern to local rule engine");
        self.sigma_patterns.push(pattern);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigma_pattern_extraction() {
        let yaml = r#"
title: Suspicious PowerShell Download
status: test
level: high
logsource:
    product: windows
    service: powershell
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"#;
        let pattern = LocalRuleEngine::parse_sigma_rule(yaml);
        assert!(pattern.is_some());
        let p = pattern.unwrap();
        assert_eq!(p.name, "Suspicious PowerShell Download");
        assert_eq!(p.severity, "high");
        assert!(p.patterns.contains(&"Invoke-WebRequest".to_string()));
    }

    #[test]
    fn test_sigma_pattern_extraction_with_list() {
        let yaml = r#"
title: Mimikatz Detection
level: critical
detection:
    keywords:
        - 'sekurlsa'
        - 'kerberos::list'
        - 'privilege::debug'
tags:
    - attack.t1003
"#;
        let pattern = LocalRuleEngine::parse_sigma_rule(yaml);
        assert!(pattern.is_some());
        let p = pattern.unwrap();
        assert_eq!(p.name, "Mimikatz Detection");
        assert_eq!(p.severity, "critical");
        assert!(p.patterns.contains(&"sekurlsa".to_string()));
        assert!(p.mitre_techniques.contains(&"T1003".to_string()));
    }

    #[tokio::test]
    async fn test_command_line_matching() {
        let engine = LocalRuleEngine::new("/nonexistent", "/nonexistent").await;

        // Engine should work even with no rules loaded
        let detections = engine.check_command_line("powershell.exe -encodedcommand");
        // No Sigma rules loaded, so no detections
        assert!(detections.is_empty());
    }

    #[tokio::test]
    async fn test_stats() {
        let engine = LocalRuleEngine::new("/nonexistent", "/nonexistent").await;

        let (files, detections) = engine.stats();
        assert_eq!(files, 0);
        assert_eq!(detections, 0);

        let (yara_count, sigma_count) = engine.rule_counts();
        #[cfg(feature = "yara")]
        assert!(yara_count <= 1);
        #[cfg(not(feature = "yara"))]
        assert_eq!(yara_count, 0);
        assert_eq!(sigma_count, 0);
    }

    #[tokio::test]
    async fn test_add_sigma_pattern() {
        let mut engine = LocalRuleEngine::new("/nonexistent", "/nonexistent").await;

        let pattern = SigmaPattern {
            name: "Test Pattern".to_string(),
            logsource: "windows".to_string(),
            patterns: vec!["test-indicator".to_string()],
            severity: "high".to_string(),
            mitre_techniques: vec!["T1059".to_string()],
        };

        engine.add_sigma_pattern(pattern);
        assert_eq!(engine.sigma_patterns.len(), 1);

        // Now the pattern should match
        let detections = engine.check_command_line("cmd /c test-indicator");
        assert_eq!(detections.len(), 1);
        assert!(detections[0].rule_name.contains("Test_Pattern"));
    }

    #[tokio::test]
    async fn test_check_event() {
        let mut engine = LocalRuleEngine::new("/nonexistent", "/nonexistent").await;

        let pattern = SigmaPattern {
            name: "Suspicious Process".to_string(),
            logsource: "windows".to_string(),
            patterns: vec!["mimikatz".to_string()],
            severity: "critical".to_string(),
            mitre_techniques: vec!["T1003".to_string()],
        };
        engine.add_sigma_pattern(pattern);

        let mut event = std::collections::HashMap::new();
        event.insert("ProcessName".to_string(), "mimikatz.exe".to_string());
        event.insert("CommandLine".to_string(), "-p dump".to_string());

        let detections = engine.check_event(&event);
        assert_eq!(detections.len(), 1);
    }
}
