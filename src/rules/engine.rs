//! Rule Engine
//!
//! Runtime evaluation of detection rules against telemetry events.

use super::compiler::{CompiledFieldMatcher, CompiledMatcher, CompiledRule, RuleCompiler};
use super::loader::RuleLoader;
use super::schema::DetectionRule;
use super::{RuleCategory, RuleMatch, RuleStats};
use crate::collectors::{
    DnsEvent, EventPayload, FileEvent, NetworkEvent, ProcessEvent, RegistryEvent, TelemetryEvent,
};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Rule engine for evaluating detection rules
pub struct RuleEngine {
    /// Rule loader
    loader: Arc<RwLock<RuleLoader>>,
    /// Compiled rules by category
    compiled_rules: Arc<RwLock<HashMap<RuleCategory, Vec<CompiledRule>>>>,
    /// Rule compiler
    compiler: Arc<RwLock<RuleCompiler>>,
    /// Statistics
    stats: Arc<RwLock<EngineStats>>,
}

/// Engine statistics
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    pub events_processed: u64,
    pub rules_evaluated: u64,
    pub matches_found: u64,
    pub processing_time_ms: u64,
}

impl RuleEngine {
    /// Create a new rule engine with the specified rules directory
    pub async fn new<P: AsRef<Path>>(rules_dir: P) -> Result<Self> {
        let loader = Arc::new(RwLock::new(RuleLoader::new(rules_dir)));
        let compiled_rules = Arc::new(RwLock::new(HashMap::new()));
        let compiler = Arc::new(RwLock::new(RuleCompiler::new()));

        let engine = Self {
            loader,
            compiled_rules,
            compiler,
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        // Load and compile rules
        engine.reload_rules().await?;

        Ok(engine)
    }

    /// Reload all rules from disk
    pub async fn reload_rules(&self) -> Result<RuleStats> {
        info!("Reloading rules from disk");

        let mut loader = self.loader.write().await;
        let stats = loader.load_all()?;

        // Compile all rules
        let mut compiler = self.compiler.write().await;
        let mut compiled = HashMap::new();

        for rule in loader.get_enabled_rules() {
            match compiler.compile(rule) {
                Ok(compiled_rule) => {
                    compiled
                        .entry(rule.category)
                        .or_insert_with(Vec::new)
                        .push(compiled_rule);
                }
                Err(e) => {
                    warn!(rule_id = %rule.id, error = %e, "Failed to compile rule");
                }
            }
        }

        // Update compiled rules
        let mut rules = self.compiled_rules.write().await;
        *rules = compiled;

        info!(
            total = stats.total_rules,
            enabled = stats.enabled_rules,
            "Rules reloaded and compiled"
        );

        Ok(stats.clone())
    }

    /// Load rules from a YAML string (for testing or dynamic rules)
    pub async fn load_from_string(&self, yaml: &str) -> Result<usize> {
        let mut loader = self.loader.write().await;
        let count = loader.load_from_string(yaml)?;

        // Recompile all rules
        let mut compiler = self.compiler.write().await;
        let mut compiled = HashMap::new();

        for rule in loader.get_enabled_rules() {
            match compiler.compile(rule) {
                Ok(compiled_rule) => {
                    compiled
                        .entry(rule.category)
                        .or_insert_with(Vec::new)
                        .push(compiled_rule);
                }
                Err(e) => {
                    warn!(rule_id = %rule.id, error = %e, "Failed to compile rule");
                }
            }
        }

        let mut rules = self.compiled_rules.write().await;
        *rules = compiled;

        Ok(count)
    }

    /// Evaluate an event against all applicable rules
    pub async fn evaluate(&self, event: &TelemetryEvent) -> Vec<RuleMatch> {
        let start = std::time::Instant::now();
        let mut matches = Vec::new();

        // Determine applicable category from event payload
        let category = match &event.payload {
            EventPayload::Process(_) => RuleCategory::Process,
            EventPayload::File(_) => RuleCategory::File,
            EventPayload::Network(_) => RuleCategory::Network,
            EventPayload::Registry(_) => RuleCategory::Registry,
            EventPayload::Dns(_) => RuleCategory::Dns,
            _ => return matches, // No rules for other event types yet
        };

        let rules = self.compiled_rules.read().await;

        if let Some(category_rules) = rules.get(&category) {
            for compiled in category_rules {
                if let Some(rule_match) = self.evaluate_rule(compiled, event).await {
                    matches.push(rule_match);
                }
            }
        }

        // Also check behavioral rules (they can apply to any event type)
        if let Some(behavioral_rules) = rules.get(&RuleCategory::Behavioral) {
            for compiled in behavioral_rules {
                if let Some(rule_match) = self.evaluate_rule(compiled, event).await {
                    matches.push(rule_match);
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.events_processed += 1;
            stats.rules_evaluated += rules.values().map(|v| v.len() as u64).sum::<u64>();
            stats.matches_found += matches.len() as u64;
            stats.processing_time_ms += start.elapsed().as_millis() as u64;
        }

        matches
    }

    /// Evaluate a single compiled rule against an event
    async fn evaluate_rule(
        &self,
        compiled: &CompiledRule,
        event: &TelemetryEvent,
    ) -> Option<RuleMatch> {
        let fields = self.extract_fields(event);
        let rule = &compiled.rule;

        // Evaluate conditions
        let any_matched = compiled.matcher.any.is_empty()
            || compiled.matcher.any.iter().any(|c| self.matches_field(&fields, c));

        let all_matched = compiled.matcher.all.is_empty()
            || compiled.matcher.all.iter().all(|c| self.matches_field(&fields, c));

        let none_matched = compiled.matcher.none.is_empty()
            || !compiled.matcher.none.iter().any(|c| self.matches_field(&fields, c));

        // For a rule to match:
        // - If ANY conditions exist, at least one must match
        // - If ALL conditions exist, all must match
        // - No NONE conditions can match
        let matches = any_matched && all_matched && none_matched;

        if matches {
            // Collect matched field values for context
            let mut matched_fields = HashMap::new();
            for cond in compiled.matcher.any.iter().chain(compiled.matcher.all.iter()) {
                if let Some(value) = fields.get(&cond.field) {
                    matched_fields.insert(cond.field.clone(), value.clone());
                }
            }

            Some(RuleMatch {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                confidence: rule.confidence,
                description: rule.description.clone(),
                severity: rule.severity,
                mitre_tactics: rule.mitre.tactics.clone(),
                mitre_techniques: rule.mitre.techniques.clone(),
                response_actions: rule.response.clone(),
                metadata: rule.metadata.clone(),
                matched_fields,
            })
        } else {
            None
        }
    }

    /// Check if a field condition matches
    fn matches_field(
        &self,
        fields: &HashMap<String, String>,
        condition: &super::compiler::CompiledFieldCondition,
    ) -> bool {
        // Handle nested conditions
        if condition.field == "_nested" {
            if let CompiledFieldMatcher::Nested(nested) = &condition.matcher {
                return self.matches_nested(fields, nested);
            }
            return false;
        }

        // Get field value
        let value = match fields.get(&condition.field) {
            Some(v) => v,
            None => return false,
        };

        // Try numeric match first if applicable
        if let Ok(num) = value.parse::<f64>() {
            if condition.matcher.matches_num(num) {
                return true;
            }
        }

        // String match
        condition.matcher.matches_str(value)
    }

    /// Match nested conditions
    fn matches_nested(
        &self,
        fields: &HashMap<String, String>,
        nested: &CompiledMatcher,
    ) -> bool {
        let any_matched = nested.any.is_empty()
            || nested.any.iter().any(|c| self.matches_field(fields, c));

        let all_matched = nested.all.is_empty()
            || nested.all.iter().all(|c| self.matches_field(fields, c));

        let none_matched = nested.none.is_empty()
            || !nested.none.iter().any(|c| self.matches_field(fields, c));

        any_matched && all_matched && none_matched
    }

    /// Extract fields from an event into a flat map
    fn extract_fields(&self, event: &TelemetryEvent) -> HashMap<String, String> {
        let mut fields = HashMap::new();

        // Add common fields
        fields.insert("agent_id".to_string(), event.agent_id.clone());
        fields.insert("timestamp".to_string(), event.timestamp.to_string());

        // Extract payload-specific fields
        match &event.payload {
            EventPayload::Process(p) => {
                self.extract_process_fields(p, &mut fields);
            }
            EventPayload::File(f) => {
                self.extract_file_fields(f, &mut fields);
            }
            EventPayload::Network(n) => {
                self.extract_network_fields(n, &mut fields);
            }
            EventPayload::Registry(r) => {
                self.extract_registry_fields(r, &mut fields);
            }
            EventPayload::Dns(d) => {
                self.extract_dns_fields(d, &mut fields);
            }
            _ => {}
        }

        fields
    }

    fn extract_process_fields(&self, p: &ProcessEvent, fields: &mut HashMap<String, String>) {
        fields.insert("process.name".to_string(), p.name.clone());
        fields.insert("process.path".to_string(), p.path.clone());
        fields.insert("process.cmdline".to_string(), p.cmdline.clone());
        fields.insert("process.command_line".to_string(), p.cmdline.clone());
        fields.insert("process.pid".to_string(), p.pid.to_string());
        fields.insert("process.ppid".to_string(), p.ppid.to_string());
        fields.insert("process.user".to_string(), p.user.clone());
        fields.insert("process.entropy".to_string(), p.entropy.to_string());
        fields.insert("process.is_elevated".to_string(), p.is_elevated.to_string());
        fields.insert("process.is_signed".to_string(), p.is_signed.to_string());

        if let Some(ref parent_name) = p.parent_name {
            fields.insert("process.parent_name".to_string(), parent_name.clone());
        }
        if let Some(ref parent_path) = p.parent_path {
            fields.insert("process.parent_path".to_string(), parent_path.clone());
        }
        if let Some(ref signer) = p.signer {
            fields.insert("process.signer".to_string(), signer.clone());
        }
        if let Some(ref company) = p.company_name {
            fields.insert("process.company_name".to_string(), company.clone());
        }
        if let Some(ref version) = p.file_version {
            fields.insert("process.file_version".to_string(), version.clone());
        }
        if let Some(ref product) = p.product_name {
            fields.insert("process.product_name".to_string(), product.clone());
        }

        // SHA256 as hex
        if !p.sha256.is_empty() {
            fields.insert(
                "process.sha256".to_string(),
                hex::encode(&p.sha256),
            );
        }
    }

    fn extract_file_fields(&self, f: &FileEvent, fields: &mut HashMap<String, String>) {
        fields.insert("file.path".to_string(), f.path.clone());
        fields.insert("file.operation".to_string(), f.operation.clone());
        fields.insert("file.process_name".to_string(), f.process_name.clone());
        fields.insert("file.process_pid".to_string(), f.pid.to_string());
        fields.insert("file.entropy".to_string(), f.entropy.to_string());

        // Extract filename and extension
        if let Some(name) = std::path::Path::new(&f.path).file_name() {
            fields.insert("file.name".to_string(), name.to_string_lossy().to_string());
        }
        if let Some(ext) = std::path::Path::new(&f.path).extension() {
            fields.insert("file.extension".to_string(), ext.to_string_lossy().to_string());
        }

        if !f.sha256.is_empty() {
            fields.insert("file.sha256".to_string(), hex::encode(&f.sha256));
        }
    }

    fn extract_network_fields(&self, n: &NetworkEvent, fields: &mut HashMap<String, String>) {
        fields.insert("network.remote_ip".to_string(), n.remote_ip.clone());
        fields.insert("network.remote_port".to_string(), n.remote_port.to_string());
        fields.insert("network.local_ip".to_string(), n.local_ip.clone());
        fields.insert("network.local_port".to_string(), n.local_port.to_string());
        fields.insert("network.protocol".to_string(), n.protocol.clone());
        fields.insert("network.direction".to_string(), n.direction.clone());
        fields.insert("network.process_name".to_string(), n.process_name.clone());
        fields.insert("network.process_pid".to_string(), n.pid.to_string());
        fields.insert("network.bytes_sent".to_string(), n.bytes_sent.to_string());
        fields.insert("network.bytes_received".to_string(), n.bytes_received.to_string());
    }

    fn extract_registry_fields(&self, r: &RegistryEvent, fields: &mut HashMap<String, String>) {
        fields.insert("registry.key_path".to_string(), r.key_path.clone());
        fields.insert("registry.value_name".to_string(), r.value_name.clone());
        fields.insert("registry.value_data".to_string(), r.value_data.clone());
        fields.insert("registry.operation".to_string(), r.operation.clone());
        fields.insert("registry.process_name".to_string(), r.process_name.clone());
        fields.insert("registry.process_pid".to_string(), r.pid.to_string());
    }

    fn extract_dns_fields(&self, d: &DnsEvent, fields: &mut HashMap<String, String>) {
        fields.insert("dns.query".to_string(), d.query.clone());
        fields.insert("dns.query_type".to_string(), d.query_type.clone());
        fields.insert("dns.process_name".to_string(), d.process_name.clone());
        fields.insert("dns.process_pid".to_string(), d.pid.to_string());

        if !d.resolved_ips.is_empty() {
            fields.insert("dns.resolved_ips".to_string(), d.resolved_ips.join(","));
        }
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> EngineStats {
        self.stats.read().await.clone()
    }

    /// Get rule loading statistics
    pub async fn get_rule_stats(&self) -> RuleStats {
        self.loader.read().await.get_stats().clone()
    }

    /// Enable or disable a rule
    pub async fn set_rule_enabled(&self, rule_id: &str, enabled: bool) -> bool {
        let result = self.loader.write().await.set_rule_enabled(rule_id, enabled);
        if result {
            // Recompile rules
            let _ = self.reload_rules().await;
        }
        result
    }

    /// Get a specific rule by ID
    pub async fn get_rule(&self, id: &str) -> Option<DetectionRule> {
        self.loader.read().await.get_rule(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled_rules_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules")
    }

    fn network_event(process_name: &str, remote_port: u16) -> TelemetryEvent {
        TelemetryEvent {
            agent_id: "test-agent".to_string(),
            timestamp: 1000,
            event_type: "network_connect".to_string(),
            payload: EventPayload::Network(NetworkEvent {
                pid: 1234,
                process_name: process_name.to_string(),
                local_ip: "192.168.1.100".to_string(),
                local_port: 50000,
                remote_ip: "203.0.113.10".to_string(),
                remote_port,
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                state: "established".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
            }),
        }
    }

    fn process_event(name: &str, path: &str) -> TelemetryEvent {
        TelemetryEvent {
            agent_id: "test-agent".to_string(),
            timestamp: 1000,
            event_type: "process_create".to_string(),
            payload: EventPayload::Process(ProcessEvent {
                pid: 1234,
                ppid: 1000,
                name: name.to_string(),
                path: path.to_string(),
                cmdline: path.to_string(),
                user: "SYSTEM".to_string(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: true,
                parent_name: Some("wininit.exe".to_string()),
                parent_path: Some("D:\\Windows\\System32\\wininit.exe".to_string()),
                is_signed: true,
                signer: Some("Microsoft Windows".to_string()),
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: Some("Microsoft Corporation".to_string()),
                file_description: None,
                product_name: Some("Microsoft Windows Operating System".to_string()),
                file_version: None,
                environment: None,
            }),
        }
    }

    fn has_rule(matches: &[RuleMatch], rule_id: &str) -> bool {
        matches.iter().any(|rule_match| rule_match.rule_id == rule_id)
    }

    #[tokio::test]
    async fn test_evaluate_process_rule() {
        let engine = RuleEngine::new("/tmp/nonexistent").await.unwrap();

        // Load a test rule
        let yaml = r#"
rules:
  - id: TEST-001
    name: Mimikatz Detection
    category: process
    severity: critical
    mitre:
      tactics: [credential-access]
      techniques: [T1003.001]
    conditions:
      any:
        - process.name:
            contains: mimikatz
    response:
      - alert
      - kill_process
"#;
        engine.load_from_string(yaml).await.unwrap();

        // Create a test event
        let event = TelemetryEvent {
            agent_id: "test-agent".to_string(),
            timestamp: 1000,
            event_type: "process_create".to_string(),
            payload: EventPayload::Process(ProcessEvent {
                pid: 1234,
                ppid: 1000,
                name: "mimikatz.exe".to_string(),
                path: "C:\\temp\\mimikatz.exe".to_string(),
                cmdline: "mimikatz.exe sekurlsa::logonpasswords".to_string(),
                user: "admin".to_string(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: true,
                parent_name: Some("cmd.exe".to_string()),
                parent_path: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        };

        let matches = engine.evaluate(&event).await;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "TEST-001");
        assert_eq!(matches[0].severity, super::super::Severity::Critical);
    }

    #[tokio::test]
    async fn test_evaluate_network_rule() {
        let engine = RuleEngine::new("/tmp/nonexistent").await.unwrap();

        let yaml = r#"
rules:
  - id: NET-001
    name: Suspicious Port
    category: network
    severity: high
    conditions:
      any:
        - network.remote_port:
            in: ["4444", "5555", "6666"]
    response:
      - alert
"#;
        engine.load_from_string(yaml).await.unwrap();

        let event = TelemetryEvent {
            agent_id: "test-agent".to_string(),
            timestamp: 1000,
            event_type: "network_connect".to_string(),
            payload: EventPayload::Network(NetworkEvent {
                pid: 1234,
                process_name: "beacon.exe".to_string(),
                local_ip: "192.168.1.100".to_string(),
                local_port: 50000,
                remote_ip: "10.0.0.1".to_string(),
                remote_port: 4444,
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                state: "established".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
            }),
        };

        let matches = engine.evaluate(&event).await;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "NET-001");
    }

    #[tokio::test]
    async fn test_all_conditions() {
        let engine = RuleEngine::new("/tmp/nonexistent").await.unwrap();

        let yaml = r#"
rules:
  - id: TEST-002
    name: All Conditions Test
    category: process
    conditions:
      all:
        - process.name:
            ends_with: .exe
        - process.is_elevated: "true"
    response:
      - alert
"#;
        engine.load_from_string(yaml).await.unwrap();

        // Should match - both conditions true
        let event = TelemetryEvent {
            agent_id: "test".to_string(),
            timestamp: 1000,
            event_type: "process_create".to_string(),
            payload: EventPayload::Process(ProcessEvent {
                pid: 1234,
                ppid: 1000,
                name: "test.exe".to_string(),
                path: "C:\\test.exe".to_string(),
                cmdline: "test.exe".to_string(),
                user: "admin".to_string(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: true,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        };

        let matches = engine.evaluate(&event).await;
        assert_eq!(matches.len(), 1);

        // Should not match - not elevated
        let event2 = TelemetryEvent {
            agent_id: "test".to_string(),
            timestamp: 1000,
            event_type: "process_create".to_string(),
            payload: EventPayload::Process(ProcessEvent {
                pid: 1234,
                ppid: 1000,
                name: "test.exe".to_string(),
                path: "C:\\test.exe".to_string(),
                cmdline: "test.exe".to_string(),
                user: "user".to_string(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        };

        let matches2 = engine.evaluate(&event2).await;
        assert!(matches2.is_empty());
    }

    #[tokio::test]
    async fn test_c2_net_006_only_matches_cobalt_strike_default_port() {
        let engine = RuleEngine::new(bundled_rules_dir()).await.unwrap();

        for port in [443, 8080] {
            let matches = engine.evaluate(&network_event("curl.exe", port)).await;
            assert!(
                !has_rule(&matches, "C2-NET-006"),
                "C2-NET-006 should not match curl traffic to port {port}; matches: {matches:?}"
            );
        }

        let matches = engine.evaluate(&network_event("beacon.exe", 50050)).await;
        assert!(
            has_rule(&matches, "C2-NET-006"),
            "C2-NET-006 should match port 50050; matches: {matches:?}"
        );
    }

    #[tokio::test]
    async fn test_evasion_002_allows_system32_lsass_and_flags_public_lsass() {
        let engine = RuleEngine::new(bundled_rules_dir()).await.unwrap();

        let system32_matches = engine
            .evaluate(&process_event("lsass.exe", "D:\\Windows\\System32\\lsass.exe"))
            .await;
        assert!(
            !has_rule(&system32_matches, "EVASION-002"),
            "EVASION-002 should allow System32 lsass.exe; matches: {system32_matches:?}"
        );

        let public_matches = engine
            .evaluate(&process_event("lsass.exe", "D:\\Users\\Public\\lsass.exe"))
            .await;
        assert!(
            has_rule(&public_matches, "EVASION-002"),
            "EVASION-002 should flag lsass.exe outside System32; matches: {public_matches:?}"
        );
    }
}
