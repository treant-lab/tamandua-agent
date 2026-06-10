//! Behavioral Chain Analyzer
//!
//! Multi-process attack chain correlation engine for detecting coordinated attacks.
//! Correlates behavioral events across process boundaries and time windows.
//!
//! MITRE ATT&CK:
//! - Multiple tactics: Correlates events across Initial Access → Execution → Privilege Escalation → Exfiltration
//!
//! Features:
//! - Temporal correlation (events within configurable time windows)
//! - Process ancestry tracking
//! - Attack chain pattern matching
//! - Confidence scoring based on event combinations

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Maximum events to track per chain
const MAX_CHAIN_EVENTS: usize = 100;
/// Default correlation window (5 minutes)
const DEFAULT_WINDOW_MS: u64 = 300_000;
/// Maximum concurrent chains to track
const MAX_ACTIVE_CHAINS: usize = 1000;

/// A timestamped behavioral event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedEvent {
    /// Event timestamp
    pub timestamp: u64,
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub parent_pid: u32,
    /// Process name
    pub process_name: String,
    /// Event type/category
    pub event_type: BehavioralEventType,
    /// MITRE technique if applicable
    pub mitre_technique: Option<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Types of behavioral events we track
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehavioralEventType {
    // Discovery phase
    ProcessEnumeration,
    NetworkEnumeration,
    FileEnumeration,
    RegistryEnumeration,
    AccountEnumeration,
    ServiceEnumeration,

    // Credential access
    CredentialDump,
    LsassAccess,
    SamAccess,
    TokenManipulation,

    // Execution
    ShellExecution,
    ScriptExecution,
    LolbinExecution,
    RemoteExecution,

    // Privilege escalation
    PrivilegeEscalation,
    UacBypass,
    TokenElevation,
    KernelExploit,

    // Lateral movement
    RdpConnection,
    SmbConnection,
    WmiExecution,
    PsexecExecution,
    SshConnection,

    // Collection/staging
    DataStaging,
    ArchiveCreation,
    FileAggregation,
    ClipboardAccess,

    // Exfiltration
    LargeDataTransfer,
    DnsExfiltration,
    HttpExfiltration,
    CloudUpload,

    // Defense evasion
    EtwTampering,
    AmsiBypass,
    LogClearing,
    TimestampModification,
    ProcessHollowing,

    // Persistence
    RegistryPersistence,
    ScheduledTaskCreation,
    ServiceInstallation,
    StartupModification,

    // C2 communication
    BeaconCallback,
    C2Communication,
    DomainGeneration,

    // Generic
    SuspiciousActivity,
}

impl BehavioralEventType {
    /// Get the MITRE tactic for this event type
    pub fn mitre_tactic(&self) -> &'static str {
        match self {
            Self::ProcessEnumeration
            | Self::NetworkEnumeration
            | Self::FileEnumeration
            | Self::RegistryEnumeration
            | Self::AccountEnumeration
            | Self::ServiceEnumeration => "TA0007", // Discovery

            Self::CredentialDump
            | Self::LsassAccess
            | Self::SamAccess
            | Self::TokenManipulation => "TA0006", // Credential Access

            Self::ShellExecution
            | Self::ScriptExecution
            | Self::LolbinExecution
            | Self::RemoteExecution => "TA0002", // Execution

            Self::PrivilegeEscalation
            | Self::UacBypass
            | Self::TokenElevation
            | Self::KernelExploit => "TA0004", // Privilege Escalation

            Self::RdpConnection
            | Self::SmbConnection
            | Self::WmiExecution
            | Self::PsexecExecution
            | Self::SshConnection => "TA0008", // Lateral Movement

            Self::DataStaging
            | Self::ArchiveCreation
            | Self::FileAggregation
            | Self::ClipboardAccess => "TA0009", // Collection

            Self::LargeDataTransfer
            | Self::DnsExfiltration
            | Self::HttpExfiltration
            | Self::CloudUpload => "TA0010", // Exfiltration

            Self::EtwTampering
            | Self::AmsiBypass
            | Self::LogClearing
            | Self::TimestampModification
            | Self::ProcessHollowing => "TA0005", // Defense Evasion

            Self::RegistryPersistence
            | Self::ScheduledTaskCreation
            | Self::ServiceInstallation
            | Self::StartupModification => "TA0003", // Persistence

            Self::BeaconCallback | Self::C2Communication | Self::DomainGeneration => "TA0011", // Command and Control

            Self::SuspiciousActivity => "TA0000", // Unknown
        }
    }
}

/// A behavioral attack chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralChain {
    /// Unique chain ID
    pub id: String,
    /// Events in the chain
    pub events: Vec<TimestampedEvent>,
    /// Process IDs involved
    pub processes: HashSet<u32>,
    /// MITRE techniques observed
    pub techniques: Vec<String>,
    /// MITRE tactics observed
    pub tactics: Vec<String>,
    /// Chain creation time
    pub created_at: u64,
    /// Last event time
    pub last_event_at: u64,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Chain pattern if matched
    pub matched_pattern: Option<AttackChainPattern>,
    /// Severity assessment
    pub severity: ChainSeverity,
}

/// Attack chain pattern for detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainPattern {
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Required event sequence (in order)
    pub sequence: Vec<BehavioralEventType>,
    /// Minimum events to match
    pub min_events: usize,
    /// MITRE ATT&CK mapping
    pub mitre_techniques: Vec<String>,
    /// Base confidence for this pattern
    pub base_confidence: f32,
}

/// Chain severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ChainSeverity {
    fn from_confidence(confidence: f32, tactics_count: usize) -> Self {
        if confidence >= 0.9 || tactics_count >= 4 {
            Self::Critical
        } else if confidence >= 0.7 || tactics_count >= 3 {
            Self::High
        } else if confidence >= 0.5 || tactics_count >= 2 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Behavioral chain analyzer
pub struct BehavioralChainAnalyzer {
    /// Active chains being tracked
    chains: Arc<RwLock<HashMap<String, BehavioralChain>>>,
    /// Event buffer for correlation
    event_buffer: Arc<RwLock<VecDeque<TimestampedEvent>>>,
    /// Process ancestry map (child -> parent)
    process_ancestry: Arc<RwLock<HashMap<u32, u32>>>,
    /// Known attack patterns
    patterns: Vec<AttackChainPattern>,
    /// Correlation window in milliseconds
    window_ms: u64,
}

impl BehavioralChainAnalyzer {
    /// Create a new analyzer with default settings
    pub fn new() -> Self {
        Self::with_window(DEFAULT_WINDOW_MS)
    }

    /// Create analyzer with custom correlation window
    pub fn with_window(window_ms: u64) -> Self {
        Self {
            chains: Arc::new(RwLock::new(HashMap::new())),
            event_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_CHAIN_EVENTS * 10))),
            process_ancestry: Arc::new(RwLock::new(HashMap::new())),
            patterns: Self::load_attack_patterns(),
            window_ms,
        }
    }

    /// Load predefined attack chain patterns
    fn load_attack_patterns() -> Vec<AttackChainPattern> {
        vec![
            // Discovery → Credential Access → Lateral Movement chain
            AttackChainPattern {
                name: "Credential Theft Chain".to_string(),
                description: "Discovery followed by credential dumping and lateral movement"
                    .to_string(),
                sequence: vec![
                    BehavioralEventType::ProcessEnumeration,
                    BehavioralEventType::CredentialDump,
                    BehavioralEventType::SmbConnection,
                ],
                min_events: 3,
                mitre_techniques: vec![
                    "T1087".to_string(),
                    "T1003".to_string(),
                    "T1021.002".to_string(),
                ],
                base_confidence: 0.85,
            },
            // Execution → Privilege Escalation → Persistence chain
            AttackChainPattern {
                name: "Privilege Escalation Chain".to_string(),
                description: "Initial execution followed by privilege escalation and persistence"
                    .to_string(),
                sequence: vec![
                    BehavioralEventType::ScriptExecution,
                    BehavioralEventType::UacBypass,
                    BehavioralEventType::RegistryPersistence,
                ],
                min_events: 3,
                mitre_techniques: vec![
                    "T1059".to_string(),
                    "T1548.002".to_string(),
                    "T1547.001".to_string(),
                ],
                base_confidence: 0.80,
            },
            // Data Collection → Staging → Exfiltration chain
            AttackChainPattern {
                name: "Data Exfiltration Chain".to_string(),
                description: "File enumeration followed by staging and exfiltration".to_string(),
                sequence: vec![
                    BehavioralEventType::FileEnumeration,
                    BehavioralEventType::DataStaging,
                    BehavioralEventType::ArchiveCreation,
                    BehavioralEventType::LargeDataTransfer,
                ],
                min_events: 3,
                mitre_techniques: vec![
                    "T1083".to_string(),
                    "T1074".to_string(),
                    "T1560".to_string(),
                    "T1041".to_string(),
                ],
                base_confidence: 0.90,
            },
            // Defense Evasion → Credential Access → Exfiltration
            AttackChainPattern {
                name: "Evasive Data Theft".to_string(),
                description: "Defense evasion followed by credential theft and data exfiltration"
                    .to_string(),
                sequence: vec![
                    BehavioralEventType::EtwTampering,
                    BehavioralEventType::LsassAccess,
                    BehavioralEventType::HttpExfiltration,
                ],
                min_events: 3,
                mitre_techniques: vec![
                    "T1562.006".to_string(),
                    "T1003.001".to_string(),
                    "T1048".to_string(),
                ],
                base_confidence: 0.95,
            },
            // Ransomware chain
            AttackChainPattern {
                name: "Ransomware Chain".to_string(),
                description: "Typical ransomware attack sequence".to_string(),
                sequence: vec![
                    BehavioralEventType::ServiceEnumeration,
                    BehavioralEventType::LogClearing,
                    BehavioralEventType::FileEnumeration,
                    BehavioralEventType::ArchiveCreation,
                ],
                min_events: 3,
                mitre_techniques: vec![
                    "T1007".to_string(),
                    "T1070.001".to_string(),
                    "T1486".to_string(),
                ],
                base_confidence: 0.90,
            },
            // LOLBin chain
            AttackChainPattern {
                name: "Living-off-the-Land Chain".to_string(),
                description: "Multiple LOLBin executions indicating malicious activity".to_string(),
                sequence: vec![
                    BehavioralEventType::LolbinExecution,
                    BehavioralEventType::LolbinExecution,
                    BehavioralEventType::LolbinExecution,
                ],
                min_events: 3,
                mitre_techniques: vec!["T1218".to_string()],
                base_confidence: 0.75,
            },
            // C2 establishment chain
            AttackChainPattern {
                name: "C2 Establishment Chain".to_string(),
                description: "Process execution followed by C2 communication".to_string(),
                sequence: vec![
                    BehavioralEventType::ScriptExecution,
                    BehavioralEventType::DomainGeneration,
                    BehavioralEventType::BeaconCallback,
                ],
                min_events: 2,
                mitre_techniques: vec![
                    "T1059".to_string(),
                    "T1568".to_string(),
                    "T1071".to_string(),
                ],
                base_confidence: 0.85,
            },
            // Token manipulation chain
            AttackChainPattern {
                name: "Token Manipulation Chain".to_string(),
                description: "Token theft followed by privileged operations".to_string(),
                sequence: vec![
                    BehavioralEventType::TokenManipulation,
                    BehavioralEventType::TokenElevation,
                    BehavioralEventType::ServiceInstallation,
                ],
                min_events: 2,
                mitre_techniques: vec!["T1134".to_string(), "T1543.003".to_string()],
                base_confidence: 0.85,
            },
        ]
    }

    /// Add an event to the analyzer
    pub fn add_event(&self, event: TimestampedEvent) {
        let mut buffer = self.event_buffer.write();

        // Update process ancestry
        if event.parent_pid != 0 {
            let mut ancestry = self.process_ancestry.write();
            ancestry.insert(event.pid, event.parent_pid);
        }

        // Add to buffer
        buffer.push_back(event.clone());

        // Trim old events
        let cutoff = event.timestamp.saturating_sub(self.window_ms);
        while let Some(front) = buffer.front() {
            if front.timestamp < cutoff {
                buffer.pop_front();
            } else {
                break;
            }
        }

        drop(buffer);

        // Try to correlate into chains
        self.correlate_event(&event);
    }

    /// Correlate an event into existing or new chains
    fn correlate_event(&self, event: &TimestampedEvent) {
        let mut chains = self.chains.write();

        // Find related chains by process relationship
        let related_pids = self.get_related_processes(event.pid);

        let mut matched_chain: Option<String> = None;

        for (chain_id, chain) in chains.iter_mut() {
            // Check if event belongs to this chain (process relationship or temporal proximity)
            let process_related = chain.processes.iter().any(|p| related_pids.contains(p));
            let temporal_related =
                event.timestamp.saturating_sub(chain.last_event_at) < self.window_ms;

            if process_related || temporal_related {
                // Add event to chain
                chain.events.push(event.clone());
                chain.processes.insert(event.pid);
                chain.last_event_at = event.timestamp;

                if let Some(tech) = &event.mitre_technique {
                    if !chain.techniques.contains(tech) {
                        chain.techniques.push(tech.clone());
                    }
                }

                let tactic = event.event_type.mitre_tactic().to_string();
                if !chain.tactics.contains(&tactic) {
                    chain.tactics.push(tactic);
                }

                // Update confidence and pattern matching
                self.update_chain_analysis(chain);
                matched_chain = Some(chain_id.clone());
                break;
            }
        }

        // If no existing chain matched, create new one
        if matched_chain.is_none() {
            let chain_id = format!("chain_{}", uuid::Uuid::new_v4());
            let tactic = event.event_type.mitre_tactic().to_string();

            let mut techniques = Vec::new();
            if let Some(tech) = &event.mitre_technique {
                techniques.push(tech.clone());
            }

            let mut processes = HashSet::new();
            processes.insert(event.pid);

            let new_chain = BehavioralChain {
                id: chain_id.clone(),
                events: vec![event.clone()],
                processes,
                techniques,
                tactics: vec![tactic],
                created_at: event.timestamp,
                last_event_at: event.timestamp,
                confidence: 0.1,
                matched_pattern: None,
                severity: ChainSeverity::Low,
            };

            chains.insert(chain_id, new_chain);
        }

        // Cleanup old chains
        let cutoff = event.timestamp.saturating_sub(self.window_ms * 2);
        chains.retain(|_, chain| chain.last_event_at >= cutoff);

        // Limit total chains
        while chains.len() > MAX_ACTIVE_CHAINS {
            // Remove oldest chain
            if let Some(oldest_id) = chains
                .iter()
                .min_by_key(|(_, c)| c.last_event_at)
                .map(|(id, _)| id.clone())
            {
                chains.remove(&oldest_id);
            } else {
                break;
            }
        }
    }

    /// Get all processes related to a given PID (ancestors and descendants)
    fn get_related_processes(&self, pid: u32) -> HashSet<u32> {
        let mut related = HashSet::new();
        related.insert(pid);

        let ancestry = self.process_ancestry.read();

        // Get ancestors
        let mut current = pid;
        while let Some(&parent) = ancestry.get(&current) {
            if parent == 0 || related.contains(&parent) {
                break;
            }
            related.insert(parent);
            current = parent;
        }

        // Get descendants (children)
        for (&child, &parent) in ancestry.iter() {
            if related.contains(&parent) {
                related.insert(child);
            }
        }

        related
    }

    /// Update chain analysis (confidence, pattern matching, severity)
    fn update_chain_analysis(&self, chain: &mut BehavioralChain) {
        // Check for pattern matches
        let event_types: Vec<BehavioralEventType> =
            chain.events.iter().map(|e| e.event_type).collect();

        let mut best_match: Option<(&AttackChainPattern, f32)> = None;

        for pattern in &self.patterns {
            if let Some(match_confidence) = self.match_pattern(pattern, &event_types) {
                if best_match.is_none() || match_confidence > best_match.unwrap().1 {
                    best_match = Some((pattern, match_confidence));
                }
            }
        }

        if let Some((pattern, confidence)) = best_match {
            chain.matched_pattern = Some(pattern.clone());
            chain.confidence = confidence;
        } else {
            // Calculate confidence based on tactics diversity and event count
            let tactics_factor = (chain.tactics.len() as f32 / 5.0).min(1.0);
            let events_factor = (chain.events.len() as f32 / 10.0).min(1.0);
            let processes_factor = (chain.processes.len() as f32 / 5.0).min(1.0);

            chain.confidence =
                (tactics_factor * 0.5 + events_factor * 0.3 + processes_factor * 0.2).min(0.7);
        }

        // Update severity
        chain.severity = ChainSeverity::from_confidence(chain.confidence, chain.tactics.len());
    }

    /// Match a pattern against event sequence
    fn match_pattern(
        &self,
        pattern: &AttackChainPattern,
        events: &[BehavioralEventType],
    ) -> Option<f32> {
        if events.len() < pattern.min_events {
            return None;
        }

        // Check if pattern sequence is present (in order, but not necessarily contiguous)
        let mut pattern_idx = 0;
        let mut matched_count = 0;

        for event in events {
            if pattern_idx < pattern.sequence.len() && *event == pattern.sequence[pattern_idx] {
                pattern_idx += 1;
                matched_count += 1;
            }
        }

        // Calculate match ratio
        let match_ratio = matched_count as f32 / pattern.sequence.len() as f32;

        if match_ratio >= 0.6 {
            // Scale confidence by match quality
            Some(pattern.base_confidence * match_ratio)
        } else {
            None
        }
    }

    /// Get all active chains
    pub fn get_chains(&self) -> Vec<BehavioralChain> {
        self.chains.read().values().cloned().collect()
    }

    /// Get high-severity chains (for alerting)
    pub fn get_high_severity_chains(&self) -> Vec<BehavioralChain> {
        self.chains
            .read()
            .values()
            .filter(|c| matches!(c.severity, ChainSeverity::High | ChainSeverity::Critical))
            .cloned()
            .collect()
    }

    /// Get chains matching a specific pattern
    pub fn get_chains_by_pattern(&self, pattern_name: &str) -> Vec<BehavioralChain> {
        self.chains
            .read()
            .values()
            .filter(|c| c.matched_pattern.as_ref().map(|p| p.name.as_str()) == Some(pattern_name))
            .cloned()
            .collect()
    }

    /// Export chains for alerting
    pub fn export_for_alert(&self) -> Vec<ChainAlert> {
        self.get_high_severity_chains()
            .into_iter()
            .map(|chain| ChainAlert {
                chain_id: chain.id,
                severity: chain.severity,
                confidence: chain.confidence,
                pattern: chain.matched_pattern.map(|p| p.name),
                process_count: chain.processes.len(),
                event_count: chain.events.len(),
                tactics: chain.tactics,
                techniques: chain.techniques,
                duration_ms: chain.last_event_at.saturating_sub(chain.created_at),
                summary: self.generate_summary(&chain.events),
            })
            .collect()
    }

    /// Generate a human-readable summary of chain events
    fn generate_summary(&self, events: &[TimestampedEvent]) -> String {
        if events.is_empty() {
            return "No events".to_string();
        }

        let unique_types: HashSet<_> = events.iter().map(|e| e.event_type).collect();
        let process_names: HashSet<_> = events.iter().map(|e| e.process_name.as_str()).collect();

        format!(
            "{} events across {} processes: {:?}",
            events.len(),
            process_names.len(),
            unique_types.iter().take(5).collect::<Vec<_>>()
        )
    }
}

impl Default for BehavioralChainAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Alert structure for chain detections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAlert {
    pub chain_id: String,
    pub severity: ChainSeverity,
    pub confidence: f32,
    pub pattern: Option<String>,
    pub process_count: usize,
    pub event_count: usize,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub duration_ms: u64,
    pub summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_analyzer() {
        let analyzer = BehavioralChainAnalyzer::new();
        assert!(analyzer.get_chains().is_empty());
    }

    #[test]
    fn test_add_single_event() {
        let analyzer = BehavioralChainAnalyzer::new();

        let event = TimestampedEvent {
            timestamp: 1000,
            pid: 1234,
            parent_pid: 1000,
            process_name: "test.exe".to_string(),
            event_type: BehavioralEventType::ProcessEnumeration,
            mitre_technique: Some("T1087".to_string()),
            context: HashMap::new(),
        };

        analyzer.add_event(event);

        let chains = analyzer.get_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].events.len(), 1);
    }

    #[test]
    fn test_chain_correlation() {
        let analyzer = BehavioralChainAnalyzer::new();

        // Add related events from same process
        let events = vec![
            TimestampedEvent {
                timestamp: 1000,
                pid: 1234,
                parent_pid: 1000,
                process_name: "test.exe".to_string(),
                event_type: BehavioralEventType::ProcessEnumeration,
                mitre_technique: Some("T1087".to_string()),
                context: HashMap::new(),
            },
            TimestampedEvent {
                timestamp: 2000,
                pid: 1234,
                parent_pid: 1000,
                process_name: "test.exe".to_string(),
                event_type: BehavioralEventType::CredentialDump,
                mitre_technique: Some("T1003".to_string()),
                context: HashMap::new(),
            },
            TimestampedEvent {
                timestamp: 3000,
                pid: 1234,
                parent_pid: 1000,
                process_name: "test.exe".to_string(),
                event_type: BehavioralEventType::SmbConnection,
                mitre_technique: Some("T1021.002".to_string()),
                context: HashMap::new(),
            },
        ];

        for event in events {
            analyzer.add_event(event);
        }

        let chains = analyzer.get_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].events.len(), 3);
        assert!(chains[0].matched_pattern.is_some());
    }

    #[test]
    fn test_pattern_matching() {
        let analyzer = BehavioralChainAnalyzer::new();

        let pattern = &analyzer.patterns[0]; // Credential Theft Chain
        let events = vec![
            BehavioralEventType::ProcessEnumeration,
            BehavioralEventType::CredentialDump,
            BehavioralEventType::SmbConnection,
        ];

        let confidence = analyzer.match_pattern(pattern, &events);
        assert!(confidence.is_some());
        assert!(confidence.unwrap() > 0.8);
    }

    #[test]
    fn test_severity_calculation() {
        assert_eq!(
            ChainSeverity::from_confidence(0.95, 4),
            ChainSeverity::Critical
        );
        assert_eq!(ChainSeverity::from_confidence(0.75, 3), ChainSeverity::High);
        assert_eq!(
            ChainSeverity::from_confidence(0.55, 2),
            ChainSeverity::Medium
        );
        assert_eq!(ChainSeverity::from_confidence(0.3, 1), ChainSeverity::Low);
    }
}
