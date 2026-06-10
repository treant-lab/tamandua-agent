//! MITRE ATT&CK Coverage Tracking Module
//!
//! Provides comprehensive MITRE ATT&CK framework integration:
//! - Technique detection mapping
//! - Coverage tracking per tactic
//! - Gap analysis and identification
//! - Attack chain analysis and correlation
//! - Sub-technique support with confidence levels
//! - Reporting and statistics

use crate::collectors::{EventPayload, EventType, TelemetryEvent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
#[allow(unused_imports)]
use tracing::{debug, info, warn};

// ============================================================================
// Core Data Structures
// ============================================================================

/// MITRE ATT&CK Tactic identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tactic {
    InitialAccess,       // TA0001
    Execution,           // TA0002
    Persistence,         // TA0003
    PrivilegeEscalation, // TA0004
    DefenseEvasion,      // TA0005
    CredentialAccess,    // TA0006
    Discovery,           // TA0007
    LateralMovement,     // TA0008
    Collection,          // TA0009
    Exfiltration,        // TA0010
    CommandAndControl,   // TA0011
    Impact,              // TA0040
}

impl Tactic {
    /// Get the MITRE ATT&CK ID
    pub fn id(&self) -> &'static str {
        match self {
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::Exfiltration => "TA0010",
            Self::CommandAndControl => "TA0011",
            Self::Impact => "TA0040",
        }
    }

    /// Get the display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::Exfiltration => "Exfiltration",
            Self::CommandAndControl => "Command and Control",
            Self::Impact => "Impact",
        }
    }

    /// Get all tactics in kill chain order
    pub fn all() -> Vec<Tactic> {
        vec![
            Self::InitialAccess,
            Self::Execution,
            Self::Persistence,
            Self::PrivilegeEscalation,
            Self::DefenseEvasion,
            Self::CredentialAccess,
            Self::Discovery,
            Self::LateralMovement,
            Self::Collection,
            Self::CommandAndControl,
            Self::Exfiltration,
            Self::Impact,
        ]
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "TA0001" | "INITIAL_ACCESS" | "INITIAL ACCESS" => Some(Self::InitialAccess),
            "TA0002" | "EXECUTION" => Some(Self::Execution),
            "TA0003" | "PERSISTENCE" => Some(Self::Persistence),
            "TA0004" | "PRIVILEGE_ESCALATION" | "PRIVILEGE ESCALATION" => {
                Some(Self::PrivilegeEscalation)
            }
            "TA0005" | "DEFENSE_EVASION" | "DEFENSE EVASION" => Some(Self::DefenseEvasion),
            "TA0006" | "CREDENTIAL_ACCESS" | "CREDENTIAL ACCESS" => Some(Self::CredentialAccess),
            "TA0007" | "DISCOVERY" => Some(Self::Discovery),
            "TA0008" | "LATERAL_MOVEMENT" | "LATERAL MOVEMENT" => Some(Self::LateralMovement),
            "TA0009" | "COLLECTION" => Some(Self::Collection),
            "TA0010" | "EXFILTRATION" => Some(Self::Exfiltration),
            "TA0011" | "COMMAND_AND_CONTROL" | "COMMAND AND CONTROL" | "C2" => {
                Some(Self::CommandAndControl)
            }
            "TA0040" | "IMPACT" => Some(Self::Impact),
            _ => None,
        }
    }
}

/// Confidence level for detection capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DetectionConfidence {
    /// No detection capability
    None = 0,
    /// Basic/limited detection
    Low = 1,
    /// Moderate detection with some gaps
    Medium = 2,
    /// Good detection coverage
    High = 3,
    /// Comprehensive detection with multiple data sources
    VeryHigh = 4,
}

impl DetectionConfidence {
    pub fn from_score(score: f32) -> Self {
        if score >= 0.9 {
            Self::VeryHigh
        } else if score >= 0.7 {
            Self::High
        } else if score >= 0.5 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::None
        }
    }

    pub fn as_score(&self) -> f32 {
        match self {
            Self::None => 0.0,
            Self::Low => 0.25,
            Self::Medium => 0.5,
            Self::High => 0.75,
            Self::VeryHigh => 1.0,
        }
    }
}

/// A sub-technique definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubTechnique {
    /// Sub-technique ID (e.g., "T1059.001")
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Detection logic indicators
    pub detection_indicators: Vec<String>,
    /// Detection confidence level
    pub detection_confidence: DetectionConfidence,
    /// Data sources required for detection
    pub data_sources: Vec<String>,
    /// Platform applicability
    pub platforms: Vec<String>,
}

/// A technique definition with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    /// Technique ID (e.g., "T1059")
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Associated tactics
    pub tactics: Vec<Tactic>,
    /// Sub-techniques
    pub sub_techniques: Vec<SubTechnique>,
    /// Detection logic/indicators
    pub detection_indicators: Vec<String>,
    /// Detection confidence level
    pub detection_confidence: DetectionConfidence,
    /// Data sources required for detection
    pub data_sources: Vec<String>,
    /// Platform applicability
    pub platforms: Vec<String>,
    /// Related techniques (for attack chain analysis)
    pub related_techniques: Vec<String>,
    /// Typical predecessor techniques in attack chains
    pub predecessors: Vec<String>,
    /// Typical successor techniques in attack chains
    pub successors: Vec<String>,
}

/// A detected technique instance with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTechnique {
    /// Technique ID
    pub technique_id: String,
    /// Sub-technique ID if applicable
    pub sub_technique_id: Option<String>,
    /// Detection confidence
    pub confidence: f32,
    /// Timestamp of detection
    pub timestamp: u64,
    /// Associated event ID
    pub event_id: String,
    /// Process context
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    /// Evidence description
    pub evidence: String,
    /// Associated detection rule
    pub rule_name: Option<String>,
}

/// Attack chain representing a sequence of related techniques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Unique chain identifier
    pub chain_id: String,
    /// Detected techniques in order
    pub techniques: Vec<DetectedTechnique>,
    /// Start timestamp
    pub start_time: u64,
    /// Last update timestamp
    pub last_update: u64,
    /// Overall chain confidence
    pub confidence: f32,
    /// Tactics covered
    pub tactics_covered: Vec<Tactic>,
    /// Attack stage assessment
    pub attack_stage: AttackStage,
    /// Related process IDs
    pub process_ids: HashSet<u32>,
    /// Related users
    pub users: HashSet<String>,
}

/// Attack progression stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackStage {
    /// Initial foothold being established
    Initial,
    /// Establishing persistence and escalating
    Establishment,
    /// Moving laterally and discovering
    Expansion,
    /// Collecting data and preparing exfil
    Collection,
    /// Active exfiltration or impact
    Objective,
    /// Unknown/unclear stage
    Unknown,
}

impl AttackStage {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Initial => "Initial Access",
            Self::Establishment => "Establishment",
            Self::Expansion => "Expansion",
            Self::Collection => "Collection",
            Self::Objective => "Objective",
            Self::Unknown => "Unknown",
        }
    }

    /// Determine stage from covered tactics
    pub fn from_tactics(tactics: &[Tactic]) -> Self {
        let has_initial = tactics.contains(&Tactic::InitialAccess);
        let has_execution = tactics.contains(&Tactic::Execution);
        let has_persistence = tactics.contains(&Tactic::Persistence);
        let has_priv_esc = tactics.contains(&Tactic::PrivilegeEscalation);
        let has_lateral = tactics.contains(&Tactic::LateralMovement);
        let has_discovery = tactics.contains(&Tactic::Discovery);
        let has_collection = tactics.contains(&Tactic::Collection);
        let has_exfil = tactics.contains(&Tactic::Exfiltration);
        let has_impact = tactics.contains(&Tactic::Impact);
        let has_c2 = tactics.contains(&Tactic::CommandAndControl);

        if has_exfil || has_impact {
            Self::Objective
        } else if has_collection || (has_c2 && (has_lateral || has_discovery)) {
            Self::Collection
        } else if has_lateral || has_discovery {
            Self::Expansion
        } else if has_persistence || has_priv_esc || has_execution {
            Self::Establishment
        } else if has_initial {
            Self::Initial
        } else {
            Self::Unknown
        }
    }
}

/// Coverage statistics for a tactic
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TacticCoverage {
    /// Total techniques in this tactic
    pub total_techniques: usize,
    /// Techniques with any detection coverage
    pub covered_techniques: usize,
    /// Techniques with high confidence detection
    pub high_confidence_techniques: usize,
    /// Detection count per technique
    pub technique_detections: HashMap<String, u64>,
    /// Coverage percentage
    pub coverage_percent: f32,
}

/// Gap analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    /// Technique ID
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Associated tactic
    pub tactic: Tactic,
    /// Current detection confidence
    pub current_confidence: DetectionConfidence,
    /// Reason for gap
    pub gap_reason: String,
    /// Recommended improvements
    pub recommendations: Vec<String>,
    /// Priority (1-5, 1 being highest)
    pub priority: u8,
}

/// Coverage report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Report generation timestamp
    pub generated_at: u64,
    /// Overall coverage percentage
    pub overall_coverage: f32,
    /// Coverage by tactic
    pub tactic_coverage: HashMap<String, TacticCoverage>,
    /// Identified gaps
    pub gaps: Vec<CoverageGap>,
    /// Top detected techniques
    pub top_techniques: Vec<(String, u64)>,
    /// Attack chains detected
    pub attack_chains_count: usize,
    /// Detection statistics
    pub detection_stats: DetectionStats,
}

/// Detection statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionStats {
    pub total_detections: u64,
    pub detections_by_tactic: HashMap<String, u64>,
    pub detections_by_confidence: HashMap<String, u64>,
    pub unique_techniques_detected: usize,
    pub unique_sub_techniques_detected: usize,
}

// ============================================================================
// MITRE Coverage Tracker
// ============================================================================

/// Main MITRE ATT&CK coverage tracker
pub struct MitreCoverageTracker {
    /// Technique definitions
    techniques: Arc<RwLock<HashMap<String, Technique>>>,
    /// Detection history
    detections: Arc<RwLock<VecDeque<DetectedTechnique>>>,
    /// Active attack chains
    attack_chains: Arc<RwLock<HashMap<String, AttackChain>>>,
    /// Detection counts per technique
    technique_counts: Arc<RwLock<HashMap<String, u64>>>,
    /// Maximum detection history size
    max_history: usize,
    /// Attack chain timeout (ms) - chains inactive longer are closed
    chain_timeout_ms: u64,
}

impl MitreCoverageTracker {
    /// Create a new coverage tracker with default techniques
    pub fn new() -> Self {
        // Build the technique database up-front and construct the lock already
        // populated. This avoids acquiring the tokio RwLock during construction,
        // which would panic ("Cannot block current thread from within a runtime")
        // if `new()` is called from within a tokio runtime context.
        let techniques = Self::build_technique_database();

        Self {
            techniques: Arc::new(RwLock::new(techniques)),
            detections: Arc::new(RwLock::new(VecDeque::new())),
            attack_chains: Arc::new(RwLock::new(HashMap::new())),
            technique_counts: Arc::new(RwLock::new(HashMap::new())),
            max_history: 10000,
            chain_timeout_ms: 3600000, // 1 hour
        }
    }

    /// Create with custom settings
    pub fn with_settings(max_history: usize, chain_timeout_ms: u64) -> Self {
        let mut tracker = Self::new();
        tracker.max_history = max_history;
        tracker.chain_timeout_ms = chain_timeout_ms;
        tracker
    }

    // ========================================================================
    // Technique Detection Mapping
    // ========================================================================

    /// Map a telemetry event to MITRE techniques
    pub async fn map_event_to_techniques(&self, event: &TelemetryEvent) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();
        let techniques = self.techniques.read().await;

        // Check existing detections on the event
        for detection in &event.detections {
            for technique_id in &detection.mitre_techniques {
                if let Some(_technique) = techniques.get(technique_id) {
                    detected.push(DetectedTechnique {
                        technique_id: technique_id.clone(),
                        sub_technique_id: Self::extract_sub_technique(technique_id),
                        confidence: detection.confidence,
                        timestamp: event.timestamp,
                        event_id: event.event_id.clone(),
                        process_name: Self::extract_process_name(event),
                        process_id: Self::extract_process_id(event),
                        evidence: detection.description.clone(),
                        rule_name: Some(detection.rule_name.clone()),
                    });
                }
            }
        }

        // Additionally analyze the event for technique indicators
        detected.extend(self.analyze_event_for_techniques(event, &techniques).await);

        // Record detections
        self.record_detections(&detected).await;

        detected
    }

    /// Analyze event payload for technique indicators
    async fn analyze_event_for_techniques(
        &self,
        event: &TelemetryEvent,
        techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();

        match &event.payload {
            EventPayload::Process(proc) => {
                detected.extend(self.analyze_process_for_techniques(event, proc, techniques));
            }
            EventPayload::File(file) => {
                detected.extend(self.analyze_file_for_techniques(event, file, techniques));
            }
            EventPayload::Network(net) => {
                detected.extend(self.analyze_network_for_techniques(event, net, techniques));
            }
            EventPayload::Registry(reg) => {
                detected.extend(self.analyze_registry_for_techniques(event, reg, techniques));
            }
            EventPayload::Dns(dns) => {
                detected.extend(self.analyze_dns_for_techniques(event, dns, techniques));
            }
            EventPayload::Wmi(wmi) => {
                detected.extend(self.analyze_wmi_for_techniques(event, wmi, techniques));
            }
            _ => {}
        }

        detected
    }

    fn analyze_process_for_techniques(
        &self,
        event: &TelemetryEvent,
        proc: &crate::collectors::ProcessEvent,
        _techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();
        let cmdline_lower = proc.cmdline.to_lowercase();
        let name_lower = proc.name.to_lowercase();

        // T1059 - Command and Scripting Interpreter
        if name_lower.contains("cmd.exe")
            || name_lower.contains("powershell")
            || name_lower.contains("bash")
            || name_lower.contains("python")
            || name_lower.contains("wscript")
            || name_lower.contains("cscript")
        {
            let sub_id = if name_lower.contains("powershell") {
                Some("T1059.001".to_string())
            } else if name_lower.contains("cmd") {
                Some("T1059.003".to_string())
            } else if name_lower.contains("bash") || name_lower.contains("sh") {
                Some("T1059.004".to_string())
            } else if name_lower.contains("python") {
                Some("T1059.006".to_string())
            } else if name_lower.contains("wscript") || name_lower.contains("cscript") {
                Some("T1059.005".to_string())
            } else {
                None
            };

            let confidence =
                if cmdline_lower.contains("-enc") || cmdline_lower.contains("-encodedcommand") {
                    0.85
                } else if cmdline_lower.contains("bypass") || cmdline_lower.contains("-nop") {
                    0.75
                } else {
                    0.5
                };

            detected.push(DetectedTechnique {
                technique_id: "T1059".to_string(),
                sub_technique_id: sub_id,
                confidence,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!(
                    "Script interpreter execution: {} - {}",
                    proc.name, proc.cmdline
                ),
                rule_name: None,
            });
        }

        // T1055 - Process Injection (detected via event type)
        if matches!(event.event_type, EventType::ProcessInject) {
            detected.push(DetectedTechnique {
                technique_id: "T1055".to_string(),
                sub_technique_id: None,
                confidence: 0.9,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("Process injection detected from {}", proc.name),
                rule_name: None,
            });
        }

        // T1047 - WMI execution
        if name_lower.contains("wmic") || name_lower.contains("wmiprvse") {
            detected.push(DetectedTechnique {
                technique_id: "T1047".to_string(),
                sub_technique_id: None,
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("WMI execution: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1082 - System Information Discovery
        if cmdline_lower.contains("systeminfo")
            || cmdline_lower.contains("hostname")
            || cmdline_lower.contains("ver ")
            || cmdline_lower.contains("uname")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1082".to_string(),
                sub_technique_id: None,
                confidence: 0.6,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("System information discovery: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1057 - Process Discovery
        if cmdline_lower.contains("tasklist")
            || cmdline_lower.contains("ps ")
            || cmdline_lower.contains("get-process")
            || cmdline_lower.contains("wmic process")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1057".to_string(),
                sub_technique_id: None,
                confidence: 0.6,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("Process discovery: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1083 - File and Directory Discovery
        if cmdline_lower.contains("dir ")
            || cmdline_lower.contains("ls ")
            || cmdline_lower.contains("find ")
            || cmdline_lower.contains("tree ")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1083".to_string(),
                sub_technique_id: None,
                confidence: 0.5,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("File/directory discovery: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1003 - Credential Dumping indicators
        if name_lower.contains("mimikatz")
            || name_lower.contains("procdump")
            || cmdline_lower.contains("lsass")
            || cmdline_lower.contains("sekurlsa")
            || cmdline_lower.contains("hashdump")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1003".to_string(),
                sub_technique_id: Some("T1003.001".to_string()), // LSASS Memory
                confidence: 0.95,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("Credential dumping indicators: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1548 - Abuse Elevation Control
        if cmdline_lower.contains("runas")
            || cmdline_lower.contains("sudo ")
            || cmdline_lower.contains("uac")
            || cmdline_lower.contains("bypassuac")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1548".to_string(),
                sub_technique_id: Some("T1548.002".to_string()), // Bypass UAC
                confidence: 0.8,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("Elevation abuse indicators: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1562 - Impair Defenses
        if cmdline_lower.contains("disable")
            && (cmdline_lower.contains("defender")
                || cmdline_lower.contains("firewall")
                || cmdline_lower.contains("antivirus"))
        {
            detected.push(DetectedTechnique {
                technique_id: "T1562".to_string(),
                sub_technique_id: Some("T1562.001".to_string()), // Disable or Modify Tools
                confidence: 0.85,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("Defense impairment: {}", proc.cmdline),
                rule_name: None,
            });
        }

        // T1070 - Indicator Removal
        if cmdline_lower.contains("wevtutil")
            || cmdline_lower.contains("clear-eventlog")
            || (cmdline_lower.contains("del ") && cmdline_lower.contains("log"))
        {
            detected.push(DetectedTechnique {
                technique_id: "T1070".to_string(),
                sub_technique_id: Some("T1070.001".to_string()), // Clear Windows Event Logs
                confidence: 0.9,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(proc.name.clone()),
                process_id: Some(proc.pid),
                evidence: format!("Log clearing: {}", proc.cmdline),
                rule_name: None,
            });
        }

        detected
    }

    fn analyze_file_for_techniques(
        &self,
        event: &TelemetryEvent,
        file: &crate::collectors::FileEvent,
        _techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();
        let path_lower = file.path.to_lowercase();

        // T1486 - Data Encrypted for Impact (ransomware indicators)
        if file.entropy > 7.8
            && (path_lower.ends_with(".encrypted")
                || path_lower.ends_with(".locked")
                || path_lower.ends_with(".crypt"))
        {
            detected.push(DetectedTechnique {
                technique_id: "T1486".to_string(),
                sub_technique_id: None,
                confidence: 0.9,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(file.process_name.clone()),
                process_id: Some(file.pid),
                evidence: format!(
                    "High entropy file with suspicious extension: {} (entropy: {:.2})",
                    file.path, file.entropy
                ),
                rule_name: None,
            });
        }

        // T1005 - Data from Local System
        if path_lower.contains("documents")
            || path_lower.contains("desktop")
            || path_lower.contains(".pst")
            || path_lower.contains(".doc")
        {
            if file.operation == "read" || file.operation == "copy" {
                detected.push(DetectedTechnique {
                    technique_id: "T1005".to_string(),
                    sub_technique_id: None,
                    confidence: 0.5,
                    timestamp: event.timestamp,
                    event_id: event.event_id.clone(),
                    process_name: Some(file.process_name.clone()),
                    process_id: Some(file.pid),
                    evidence: format!("Data collection from local system: {}", file.path),
                    rule_name: None,
                });
            }
        }

        // T1114 - Email Collection
        if path_lower.contains(".pst")
            || path_lower.contains(".ost")
            || path_lower.contains("outlook")
            || path_lower.contains("mail")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1114".to_string(),
                sub_technique_id: Some("T1114.001".to_string()), // Local Email Collection
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(file.process_name.clone()),
                process_id: Some(file.pid),
                evidence: format!("Email data access: {}", file.path),
                rule_name: None,
            });
        }

        // T1027 - Obfuscated Files
        if file.entropy > 7.5 && (path_lower.ends_with(".exe") || path_lower.ends_with(".dll")) {
            detected.push(DetectedTechnique {
                technique_id: "T1027".to_string(),
                sub_technique_id: None,
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(file.process_name.clone()),
                process_id: Some(file.pid),
                evidence: format!(
                    "High entropy executable: {} (entropy: {:.2})",
                    file.path, file.entropy
                ),
                rule_name: None,
            });
        }

        // T1547 - Boot/Logon Autostart Execution
        if path_lower.contains("\\startup\\")
            || path_lower.contains("/autostart/")
            || path_lower.contains("\\start menu\\programs\\startup")
        {
            detected.push(DetectedTechnique {
                technique_id: "T1547".to_string(),
                sub_technique_id: Some("T1547.001".to_string()), // Registry Run Keys / Startup Folder
                confidence: 0.8,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(file.process_name.clone()),
                process_id: Some(file.pid),
                evidence: format!("Startup folder modification: {}", file.path),
                rule_name: None,
            });
        }

        detected
    }

    fn analyze_network_for_techniques(
        &self,
        event: &TelemetryEvent,
        net: &crate::collectors::NetworkEvent,
        _techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();

        // T1071 - Application Layer Protocol
        let is_http = net.remote_port == 80 || net.remote_port == 443;
        let is_dns = net.remote_port == 53;
        let _is_smtp = net.remote_port == 25 || net.remote_port == 587 || net.remote_port == 465;

        if is_http {
            detected.push(DetectedTechnique {
                technique_id: "T1071".to_string(),
                sub_technique_id: Some("T1071.001".to_string()), // Web Protocols
                confidence: 0.4,                                 // Low confidence - HTTP is normal
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(net.process_name.clone()),
                process_id: Some(net.pid),
                evidence: format!(
                    "HTTP/HTTPS connection to {}:{}",
                    net.remote_ip, net.remote_port
                ),
                rule_name: None,
            });
        }

        if is_dns {
            detected.push(DetectedTechnique {
                technique_id: "T1071".to_string(),
                sub_technique_id: Some("T1071.004".to_string()), // DNS
                confidence: 0.3,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(net.process_name.clone()),
                process_id: Some(net.pid),
                evidence: format!("DNS connection to {}", net.remote_ip),
                rule_name: None,
            });
        }

        // T1105 - Ingress Tool Transfer
        if is_http && net.direction == "outbound" {
            detected.push(DetectedTechnique {
                technique_id: "T1105".to_string(),
                sub_technique_id: None,
                confidence: 0.3,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(net.process_name.clone()),
                process_id: Some(net.pid),
                evidence: format!(
                    "Potential tool transfer via {}:{}",
                    net.remote_ip, net.remote_port
                ),
                rule_name: None,
            });
        }

        // T1021 - Remote Services
        let remote_service_ports = [22, 23, 3389, 5985, 5986, 445, 135];
        if remote_service_ports.contains(&net.remote_port) {
            let sub_id = match net.remote_port {
                22 => Some("T1021.004".to_string()),          // SSH
                3389 => Some("T1021.001".to_string()),        // RDP
                445 | 135 => Some("T1021.002".to_string()),   // SMB
                5985 | 5986 => Some("T1021.006".to_string()), // WinRM
                _ => None,
            };

            detected.push(DetectedTechnique {
                technique_id: "T1021".to_string(),
                sub_technique_id: sub_id,
                confidence: 0.6,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(net.process_name.clone()),
                process_id: Some(net.pid),
                evidence: format!(
                    "Remote service connection: {}:{}",
                    net.remote_ip, net.remote_port
                ),
                rule_name: None,
            });
        }

        // T1048 - Exfiltration Over Alternative Protocol
        let uncommon_ports = ![80, 443, 53, 22, 23, 25, 110, 143].contains(&net.remote_port);
        if uncommon_ports && net.direction == "outbound" {
            detected.push(DetectedTechnique {
                technique_id: "T1048".to_string(),
                sub_technique_id: None,
                confidence: 0.4,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(net.process_name.clone()),
                process_id: Some(net.pid),
                evidence: format!(
                    "Outbound connection on uncommon port: {}:{}",
                    net.remote_ip, net.remote_port
                ),
                rule_name: None,
            });
        }

        detected
    }

    fn analyze_registry_for_techniques(
        &self,
        event: &TelemetryEvent,
        reg: &crate::collectors::RegistryEvent,
        _techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();
        let key_lower = reg.key_path.to_lowercase();

        // T1547 - Boot/Logon Autostart
        let run_keys = [
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\currentversion\\runservices",
            "\\currentversion\\policies\\explorer\\run",
        ];
        if run_keys.iter().any(|k| key_lower.contains(k)) {
            detected.push(DetectedTechnique {
                technique_id: "T1547".to_string(),
                sub_technique_id: Some("T1547.001".to_string()),
                confidence: 0.8,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(reg.process_name.clone()),
                process_id: Some(reg.pid),
                evidence: format!("Registry autostart modification: {}", reg.key_path),
                rule_name: None,
            });
        }

        // T1543 - Create or Modify System Process
        if key_lower.contains("\\services\\") {
            detected.push(DetectedTechnique {
                technique_id: "T1543".to_string(),
                sub_technique_id: Some("T1543.003".to_string()), // Windows Service
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(reg.process_name.clone()),
                process_id: Some(reg.pid),
                evidence: format!("Service registry modification: {}", reg.key_path),
                rule_name: None,
            });
        }

        // T1053 - Scheduled Task/Job
        if key_lower.contains("\\schedule\\taskcache") {
            detected.push(DetectedTechnique {
                technique_id: "T1053".to_string(),
                sub_technique_id: Some("T1053.005".to_string()), // Scheduled Task
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(reg.process_name.clone()),
                process_id: Some(reg.pid),
                evidence: format!("Scheduled task registry modification: {}", reg.key_path),
                rule_name: None,
            });
        }

        // T1112 - Modify Registry (generic)
        if reg.operation == "SetValue" || reg.operation == "CreateKey" {
            detected.push(DetectedTechnique {
                technique_id: "T1112".to_string(),
                sub_technique_id: None,
                confidence: 0.3,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(reg.process_name.clone()),
                process_id: Some(reg.pid),
                evidence: format!(
                    "Registry modification: {} - {}",
                    reg.operation, reg.key_path
                ),
                rule_name: None,
            });
        }

        detected
    }

    fn analyze_dns_for_techniques(
        &self,
        event: &TelemetryEvent,
        dns: &crate::collectors::DnsEvent,
        _techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();
        let query_lower = dns.query.to_lowercase();

        // T1071.004 - DNS Protocol (for C2)
        // Check for suspicious DNS patterns
        let is_suspicious = query_lower.len() > 50 // Long subdomain
            || query_lower.matches('.').count() > 5 // Many subdomains
            || query_lower.chars().filter(|c| c.is_numeric()).count() > 10; // High numeric content

        if is_suspicious {
            detected.push(DetectedTechnique {
                technique_id: "T1071".to_string(),
                sub_technique_id: Some("T1071.004".to_string()),
                confidence: 0.6,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(dns.process_name.clone()),
                process_id: Some(dns.pid),
                evidence: format!("Suspicious DNS query pattern: {}", dns.query),
                rule_name: None,
            });
        }

        // T1568 - Dynamic Resolution (DGA-like patterns)
        let consonants = "bcdfghjklmnpqrstvwxz";
        let _vowels = "aeiou";
        let mut consonant_count = 0;
        for c in query_lower.chars() {
            if consonants.contains(c) {
                consonant_count += 1;
            }
        }
        // High consonant ratio suggests DGA
        if query_lower.len() > 10 && consonant_count as f32 / query_lower.len() as f32 > 0.7 {
            detected.push(DetectedTechnique {
                technique_id: "T1568".to_string(),
                sub_technique_id: Some("T1568.002".to_string()), // Domain Generation Algorithms
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(dns.process_name.clone()),
                process_id: Some(dns.pid),
                evidence: format!("Potential DGA domain: {}", dns.query),
                rule_name: None,
            });
        }

        detected
    }

    fn analyze_wmi_for_techniques(
        &self,
        event: &TelemetryEvent,
        wmi: &crate::collectors::WmiEvent,
        _techniques: &HashMap<String, Technique>,
    ) -> Vec<DetectedTechnique> {
        let mut detected = Vec::new();

        // T1047 - WMI
        detected.push(DetectedTechnique {
            technique_id: "T1047".to_string(),
            sub_technique_id: None,
            confidence: 0.7,
            timestamp: event.timestamp,
            event_id: event.event_id.clone(),
            process_name: Some(wmi.process_name.clone()),
            process_id: Some(wmi.pid),
            evidence: format!("WMI activity: {} in {}", wmi.activity_type, wmi.namespace),
            rule_name: None,
        });

        // T1546.003 - WMI Event Subscription (persistence)
        if wmi.activity_type.contains("subscription") || wmi.wmi_class.contains("__Event") {
            detected.push(DetectedTechnique {
                technique_id: "T1546".to_string(),
                sub_technique_id: Some("T1546.003".to_string()),
                confidence: 0.85,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(wmi.process_name.clone()),
                process_id: Some(wmi.pid),
                evidence: format!(
                    "WMI event subscription: {} - {}",
                    wmi.wmi_class, wmi.object_name
                ),
                rule_name: None,
            });
        }

        // T1021.006 - WinRM (if remote)
        if wmi.remote_host.is_some() {
            detected.push(DetectedTechnique {
                technique_id: "T1021".to_string(),
                sub_technique_id: Some("T1021.006".to_string()),
                confidence: 0.7,
                timestamp: event.timestamp,
                event_id: event.event_id.clone(),
                process_name: Some(wmi.process_name.clone()),
                process_id: Some(wmi.pid),
                evidence: format!(
                    "Remote WMI to {}",
                    wmi.remote_host.as_deref().unwrap_or("unknown")
                ),
                rule_name: None,
            });
        }

        detected
    }

    /// Record detections and update counts
    async fn record_detections(&self, detected: &[DetectedTechnique]) {
        if detected.is_empty() {
            return;
        }

        // Add to history
        let mut history = self.detections.write().await;
        for det in detected {
            history.push_back(det.clone());

            // Update counts
            let mut counts = self.technique_counts.write().await;
            *counts.entry(det.technique_id.clone()).or_insert(0) += 1;
            if let Some(ref sub_id) = det.sub_technique_id {
                *counts.entry(sub_id.clone()).or_insert(0) += 1;
            }
        }

        // Trim history
        while history.len() > self.max_history {
            history.pop_front();
        }

        drop(history);

        // Update attack chains
        self.update_attack_chains(detected).await;
    }

    // ========================================================================
    // Attack Chain Analysis
    // ========================================================================

    /// Update attack chains with new detections
    async fn update_attack_chains(&self, detected: &[DetectedTechnique]) {
        let mut chains = self.attack_chains.write().await;
        let techniques = self.techniques.read().await;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Clean up old chains
        chains.retain(|_, chain| current_time - chain.last_update < self.chain_timeout_ms);

        for det in detected {
            let mut found_chain = false;

            // Try to add to existing chain
            for (_, chain) in chains.iter_mut() {
                // Check if this detection relates to the chain
                let relates = det
                    .process_id
                    .map(|pid| chain.process_ids.contains(&pid))
                    .unwrap_or(false)
                    || chain.techniques.iter().any(|t| {
                        if let Some(tech) = techniques.get(&t.technique_id) {
                            tech.related_techniques.contains(&det.technique_id)
                                || tech.successors.contains(&det.technique_id)
                        } else {
                            false
                        }
                    });

                if relates {
                    chain.techniques.push(det.clone());
                    chain.last_update = current_time;
                    if let Some(pid) = det.process_id {
                        chain.process_ids.insert(pid);
                    }

                    // Update tactics covered
                    if let Some(tech) = techniques.get(&det.technique_id) {
                        for tactic in &tech.tactics {
                            if !chain.tactics_covered.contains(tactic) {
                                chain.tactics_covered.push(*tactic);
                            }
                        }
                    }
                    chain.attack_stage = AttackStage::from_tactics(&chain.tactics_covered);

                    // Update confidence
                    let total_conf: f32 = chain.techniques.iter().map(|t| t.confidence).sum();
                    chain.confidence = (total_conf / chain.techniques.len() as f32).min(1.0);

                    found_chain = true;
                    break;
                }
            }

            // Create new chain if no match
            if !found_chain {
                let chain_id = uuid::Uuid::new_v4().to_string();
                let mut tactics = Vec::new();
                if let Some(tech) = techniques.get(&det.technique_id) {
                    tactics = tech.tactics.clone();
                }

                let mut process_ids = HashSet::new();
                if let Some(pid) = det.process_id {
                    process_ids.insert(pid);
                }

                let chain = AttackChain {
                    chain_id: chain_id.clone(),
                    techniques: vec![det.clone()],
                    start_time: det.timestamp,
                    last_update: current_time,
                    confidence: det.confidence,
                    tactics_covered: tactics.clone(),
                    attack_stage: AttackStage::from_tactics(&tactics),
                    process_ids,
                    users: HashSet::new(),
                };

                chains.insert(chain_id, chain);
            }
        }
    }

    /// Get active attack chains
    pub async fn get_attack_chains(&self) -> Vec<AttackChain> {
        self.attack_chains.read().await.values().cloned().collect()
    }

    /// Alert on dangerous technique combinations
    pub async fn check_dangerous_combinations(&self) -> Vec<(AttackChain, String)> {
        let chains = self.attack_chains.read().await;
        let mut alerts = Vec::new();

        for chain in chains.values() {
            let technique_ids: HashSet<_> = chain
                .techniques
                .iter()
                .map(|t| t.technique_id.as_str())
                .collect();

            // Credential dumping + lateral movement
            if technique_ids.contains("T1003") && technique_ids.contains("T1021") {
                alerts.push((
                    chain.clone(),
                    "Credential dumping followed by lateral movement - active compromise"
                        .to_string(),
                ));
            }

            // Defense evasion + persistence
            if technique_ids.contains("T1562")
                && (technique_ids.contains("T1547") || technique_ids.contains("T1053"))
            {
                alerts.push((
                    chain.clone(),
                    "Defense impairment with persistence - establishing foothold".to_string(),
                ));
            }

            // Discovery + collection + exfil
            if (technique_ids.contains("T1082") || technique_ids.contains("T1083"))
                && technique_ids.contains("T1005")
                && (technique_ids.contains("T1041") || technique_ids.contains("T1048"))
            {
                alerts.push((
                    chain.clone(),
                    "Discovery, collection, and exfiltration - data theft in progress".to_string(),
                ));
            }

            // Ransomware pattern
            if technique_ids.contains("T1486")
                && (technique_ids.contains("T1489") || technique_ids.contains("T1490"))
            {
                alerts.push((
                    chain.clone(),
                    "Ransomware attack - encryption and service disruption".to_string(),
                ));
            }
        }

        alerts
    }

    // ========================================================================
    // Coverage Tracking
    // ========================================================================

    /// Get coverage statistics per tactic
    pub async fn get_tactic_coverage(&self) -> HashMap<Tactic, TacticCoverage> {
        let techniques = self.techniques.read().await;
        let counts = self.technique_counts.read().await;
        let mut coverage: HashMap<Tactic, TacticCoverage> = HashMap::new();

        // Initialize coverage for all tactics
        for tactic in Tactic::all() {
            coverage.insert(tactic, TacticCoverage::default());
        }

        // Count techniques per tactic
        for (tech_id, tech) in techniques.iter() {
            for tactic in &tech.tactics {
                if let Some(cov) = coverage.get_mut(tactic) {
                    cov.total_techniques += 1;

                    if tech.detection_confidence != DetectionConfidence::None {
                        cov.covered_techniques += 1;
                    }

                    if tech.detection_confidence >= DetectionConfidence::High {
                        cov.high_confidence_techniques += 1;
                    }

                    if let Some(&count) = counts.get(tech_id) {
                        cov.technique_detections.insert(tech_id.clone(), count);
                    }
                }
            }
        }

        // Calculate coverage percentages
        for cov in coverage.values_mut() {
            if cov.total_techniques > 0 {
                cov.coverage_percent =
                    (cov.covered_techniques as f32 / cov.total_techniques as f32) * 100.0;
            }
        }

        coverage
    }

    /// Identify coverage gaps
    pub async fn get_coverage_gaps(&self) -> Vec<CoverageGap> {
        let techniques = self.techniques.read().await;
        let mut gaps = Vec::new();

        for (tech_id, tech) in techniques.iter() {
            if tech.detection_confidence < DetectionConfidence::Medium {
                let priority = match tech.detection_confidence {
                    DetectionConfidence::None => 1,
                    DetectionConfidence::Low => 2,
                    _ => 3,
                };

                let gap_reason = if tech.detection_confidence == DetectionConfidence::None {
                    "No detection capability implemented".to_string()
                } else {
                    "Limited detection coverage".to_string()
                };

                let recommendations = self.generate_recommendations(tech);

                gaps.push(CoverageGap {
                    technique_id: tech_id.clone(),
                    technique_name: tech.name.clone(),
                    tactic: tech.tactics.first().cloned().unwrap_or(Tactic::Execution),
                    current_confidence: tech.detection_confidence,
                    gap_reason,
                    recommendations,
                    priority,
                });
            }
        }

        // Sort by priority
        gaps.sort_by_key(|g| g.priority);
        gaps
    }

    fn generate_recommendations(&self, tech: &Technique) -> Vec<String> {
        let mut recs = Vec::new();

        for ds in &tech.data_sources {
            recs.push(format!("Implement data collection for: {}", ds));
        }

        for indicator in &tech.detection_indicators {
            recs.push(format!("Add detection logic for: {}", indicator));
        }

        if tech
            .sub_techniques
            .iter()
            .any(|s| s.detection_confidence < DetectionConfidence::Medium)
        {
            recs.push("Improve sub-technique detection coverage".to_string());
        }

        recs
    }

    /// Generate full coverage report
    pub async fn generate_coverage_report(&self) -> CoverageReport {
        let tactic_coverage = self.get_tactic_coverage().await;
        let gaps = self.get_coverage_gaps().await;
        let counts = self.technique_counts.read().await;
        let chains = self.attack_chains.read().await;
        let detections = self.detections.read().await;

        // Calculate overall coverage
        let total_techniques: usize = tactic_coverage.values().map(|c| c.total_techniques).sum();
        let covered_techniques: usize =
            tactic_coverage.values().map(|c| c.covered_techniques).sum();
        let overall_coverage = if total_techniques > 0 {
            (covered_techniques as f32 / total_techniques as f32) * 100.0
        } else {
            0.0
        };

        // Top techniques
        let mut top_techniques: Vec<_> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        top_techniques.sort_by(|a, b| b.1.cmp(&a.1));
        top_techniques.truncate(10);

        // Detection stats
        let mut stats = DetectionStats::default();
        stats.total_detections = detections.len() as u64;
        stats.unique_techniques_detected = counts.keys().filter(|k| !k.contains('.')).count();
        stats.unique_sub_techniques_detected = counts.keys().filter(|k| k.contains('.')).count();

        // Build tactic coverage map with string keys
        let tactic_coverage_map: HashMap<String, TacticCoverage> = tactic_coverage
            .into_iter()
            .map(|(t, c)| (t.id().to_string(), c))
            .collect();

        CoverageReport {
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            overall_coverage,
            tactic_coverage: tactic_coverage_map,
            gaps,
            top_techniques,
            attack_chains_count: chains.len(),
            detection_stats: stats,
        }
    }

    /// Export coverage matrix as CSV
    pub async fn export_coverage_matrix(&self) -> String {
        let techniques = self.techniques.read().await;
        let counts = self.technique_counts.read().await;

        let mut csv = String::from(
            "Technique ID,Name,Tactics,Detection Confidence,Detection Count,Data Sources\n",
        );

        let mut sorted_techniques: Vec<_> = techniques.iter().collect();
        sorted_techniques.sort_by_key(|(id, _)| *id);

        for (id, tech) in sorted_techniques {
            let tactics: Vec<_> = tech.tactics.iter().map(|t| t.name()).collect();
            let count = counts.get(id).unwrap_or(&0);
            let data_sources = tech.data_sources.join("; ");

            csv.push_str(&format!(
                "{},{},{},{:?},{},{}\n",
                id,
                tech.name.replace(',', ";"),
                tactics.join("; "),
                tech.detection_confidence,
                count,
                data_sources
            ));
        }

        csv
    }

    /// Get technique frequency statistics
    pub async fn get_technique_statistics(&self) -> HashMap<String, TechniqueStats> {
        let _counts = self.technique_counts.read().await;
        let detections = self.detections.read().await;
        let techniques = self.techniques.read().await;

        let mut stats: HashMap<String, TechniqueStats> = HashMap::new();

        for det in detections.iter() {
            let stat = stats.entry(det.technique_id.clone()).or_insert_with(|| {
                let tech = techniques.get(&det.technique_id);
                TechniqueStats {
                    technique_id: det.technique_id.clone(),
                    technique_name: tech.map(|t| t.name.clone()).unwrap_or_default(),
                    total_detections: 0,
                    avg_confidence: 0.0,
                    first_seen: det.timestamp,
                    last_seen: det.timestamp,
                    unique_processes: HashSet::new(),
                    confidence_sum: 0.0,
                }
            });

            stat.total_detections += 1;
            stat.confidence_sum += det.confidence;
            stat.last_seen = stat.last_seen.max(det.timestamp);
            stat.first_seen = stat.first_seen.min(det.timestamp);
            if let Some(pid) = det.process_id {
                stat.unique_processes.insert(pid);
            }
        }

        // Calculate averages
        for stat in stats.values_mut() {
            if stat.total_detections > 0 {
                stat.avg_confidence = stat.confidence_sum / stat.total_detections as f32;
            }
        }

        stats
    }

    // ========================================================================
    // Utility Functions
    // ========================================================================

    fn extract_sub_technique(technique_id: &str) -> Option<String> {
        if technique_id.contains('.') {
            Some(technique_id.to_string())
        } else {
            None
        }
    }

    fn extract_process_name(event: &TelemetryEvent) -> Option<String> {
        match &event.payload {
            EventPayload::Process(p) => Some(p.name.clone()),
            EventPayload::File(f) => Some(f.process_name.clone()),
            EventPayload::Network(n) => Some(n.process_name.clone()),
            EventPayload::Registry(r) => Some(r.process_name.clone()),
            EventPayload::Dns(d) => Some(d.process_name.clone()),
            EventPayload::Wmi(w) => Some(w.process_name.clone()),
            _ => None,
        }
    }

    fn extract_process_id(event: &TelemetryEvent) -> Option<u32> {
        match &event.payload {
            EventPayload::Process(p) => Some(p.pid),
            EventPayload::File(f) => Some(f.pid),
            EventPayload::Network(n) => Some(n.pid),
            EventPayload::Registry(r) => Some(r.pid),
            EventPayload::Dns(d) => Some(d.pid),
            EventPayload::Wmi(w) => Some(w.pid),
            _ => None,
        }
    }

    /// Get technique by ID
    pub async fn get_technique(&self, id: &str) -> Option<Technique> {
        self.techniques.read().await.get(id).cloned()
    }

    /// Get all techniques for a tactic
    pub async fn get_techniques_for_tactic(&self, tactic: Tactic) -> Vec<Technique> {
        self.techniques
            .read()
            .await
            .values()
            .filter(|t| t.tactics.contains(&tactic))
            .cloned()
            .collect()
    }

    // ========================================================================
    // Technique Database Builder
    // ========================================================================

    fn build_technique_database() -> HashMap<String, Technique> {
        let mut techniques = HashMap::new();

        // Initial Access (TA0001)
        techniques.insert(
            "T1566".to_string(),
            Technique {
                id: "T1566".to_string(),
                name: "Phishing".to_string(),
                description:
                    "Adversaries may send phishing messages to gain access to victim systems"
                        .to_string(),
                tactics: vec![Tactic::InitialAccess],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1566.001".to_string(),
                        name: "Spearphishing Attachment".to_string(),
                        description:
                            "Adversaries may send spearphishing emails with a malicious attachment"
                                .to_string(),
                        detection_indicators: vec![
                            "Email with suspicious attachment".to_string(),
                            "Office document with macros".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec!["Email".to_string(), "File".to_string()],
                        platforms: vec![
                            "Windows".to_string(),
                            "macOS".to_string(),
                            "Linux".to_string(),
                        ],
                    },
                    SubTechnique {
                        id: "T1566.002".to_string(),
                        name: "Spearphishing Link".to_string(),
                        description:
                            "Adversaries may send spearphishing emails with a malicious link"
                                .to_string(),
                        detection_indicators: vec!["Email with suspicious URL".to_string()],
                        detection_confidence: DetectionConfidence::Low,
                        data_sources: vec!["Email".to_string(), "Network Traffic".to_string()],
                        platforms: vec![
                            "Windows".to_string(),
                            "macOS".to_string(),
                            "Linux".to_string(),
                        ],
                    },
                ],
                detection_indicators: vec!["Email-based initial access".to_string()],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec![
                    "Email".to_string(),
                    "File".to_string(),
                    "Network Traffic".to_string(),
                ],
                platforms: vec![
                    "Windows".to_string(),
                    "macOS".to_string(),
                    "Linux".to_string(),
                ],
                related_techniques: vec!["T1059".to_string(), "T1204".to_string()],
                predecessors: vec![],
                successors: vec!["T1059".to_string(), "T1204".to_string()],
            },
        );

        techniques.insert(
            "T1190".to_string(),
            Technique {
                id: "T1190".to_string(),
                name: "Exploit Public-Facing Application".to_string(),
                description:
                    "Adversaries may attempt to exploit a weakness in an Internet-facing host"
                        .to_string(),
                tactics: vec![Tactic::InitialAccess],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Unusual web server activity".to_string(),
                    "Web shell indicators".to_string(),
                    "SQL injection patterns".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Application Log".to_string(), "Network Traffic".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1059".to_string()],
                predecessors: vec![],
                successors: vec!["T1059".to_string(), "T1505".to_string()],
            },
        );

        techniques.insert(
            "T1133".to_string(),
            Technique {
                id: "T1133".to_string(),
                name: "External Remote Services".to_string(),
                description:
                    "Adversaries may leverage external-facing remote services to gain access"
                        .to_string(),
                tactics: vec![Tactic::InitialAccess, Tactic::Persistence],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Unusual VPN connections".to_string(),
                    "RDP from unusual sources".to_string(),
                    "SSH brute force attempts".to_string(),
                ],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Network Traffic".to_string(), "Logon Session".to_string()],
                platforms: vec!["Windows".to_string(), "Linux".to_string()],
                related_techniques: vec!["T1021".to_string()],
                predecessors: vec![],
                successors: vec!["T1059".to_string(), "T1082".to_string()],
            },
        );

        // Execution (TA0002)
        techniques.insert(
            "T1059".to_string(),
            Technique {
                id: "T1059".to_string(),
                name: "Command and Scripting Interpreter".to_string(),
                description:
                    "Adversaries may abuse command and script interpreters to execute commands"
                        .to_string(),
                tactics: vec![Tactic::Execution],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1059.001".to_string(),
                        name: "PowerShell".to_string(),
                        description: "Adversaries may abuse PowerShell commands and scripts"
                            .to_string(),
                        detection_indicators: vec![
                            "powershell.exe execution".to_string(),
                            "-EncodedCommand flag".to_string(),
                            "Bypass execution policy".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Process".to_string(), "Script".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1059.003".to_string(),
                        name: "Windows Command Shell".to_string(),
                        description: "Adversaries may abuse cmd.exe to execute commands"
                            .to_string(),
                        detection_indicators: vec!["cmd.exe execution".to_string()],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec!["Process".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1059.004".to_string(),
                        name: "Unix Shell".to_string(),
                        description: "Adversaries may abuse Unix shell commands".to_string(),
                        detection_indicators: vec![
                            "bash/sh execution".to_string(),
                            "Reverse shell patterns".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec!["Process".to_string()],
                        platforms: vec!["Linux".to_string(), "macOS".to_string()],
                    },
                    SubTechnique {
                        id: "T1059.005".to_string(),
                        name: "Visual Basic".to_string(),
                        description: "Adversaries may abuse VBS to execute malicious commands"
                            .to_string(),
                        detection_indicators: vec![
                            "wscript.exe execution".to_string(),
                            "cscript.exe execution".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Process".to_string(), "Script".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1059.006".to_string(),
                        name: "Python".to_string(),
                        description: "Adversaries may abuse Python to execute malicious scripts"
                            .to_string(),
                        detection_indicators: vec!["python.exe execution".to_string()],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec!["Process".to_string()],
                        platforms: vec![
                            "Windows".to_string(),
                            "Linux".to_string(),
                            "macOS".to_string(),
                        ],
                    },
                ],
                detection_indicators: vec![
                    "Script interpreter execution".to_string(),
                    "Encoded/obfuscated commands".to_string(),
                ],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec![
                    "Process".to_string(),
                    "Script".to_string(),
                    "Command".to_string(),
                ],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1027".to_string(), "T1055".to_string()],
                predecessors: vec!["T1566".to_string(), "T1204".to_string()],
                successors: vec![
                    "T1055".to_string(),
                    "T1003".to_string(),
                    "T1082".to_string(),
                ],
            },
        );

        techniques.insert("T1204".to_string(), Technique {
            id: "T1204".to_string(),
            name: "User Execution".to_string(),
            description: "Adversary relies upon specific actions by a user to gain execution".to_string(),
            tactics: vec![Tactic::Execution],
            sub_techniques: vec![
                SubTechnique {
                    id: "T1204.001".to_string(),
                    name: "Malicious Link".to_string(),
                    description: "User clicks on a malicious link".to_string(),
                    detection_indicators: vec!["Browser spawning unusual processes".to_string()],
                    detection_confidence: DetectionConfidence::Medium,
                    data_sources: vec!["Process".to_string(), "Network Traffic".to_string()],
                    platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                },
                SubTechnique {
                    id: "T1204.002".to_string(),
                    name: "Malicious File".to_string(),
                    description: "User opens a malicious file".to_string(),
                    detection_indicators: vec![
                        "Office spawning shell".to_string(),
                        "Macro execution".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["Process".to_string(), "File".to_string()],
                    platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                },
            ],
            detection_indicators: vec!["User-initiated execution".to_string()],
            detection_confidence: DetectionConfidence::Medium,
            data_sources: vec!["Process".to_string(), "File".to_string()],
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            related_techniques: vec!["T1566".to_string()],
            predecessors: vec!["T1566".to_string()],
            successors: vec!["T1059".to_string()],
        });

        techniques.insert(
            "T1047".to_string(),
            Technique {
                id: "T1047".to_string(),
                name: "Windows Management Instrumentation".to_string(),
                description: "Adversaries may abuse WMI to execute malicious commands".to_string(),
                tactics: vec![Tactic::Execution],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "wmic.exe execution".to_string(),
                    "WMI process creation".to_string(),
                    "WMI event subscription".to_string(),
                ],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Process".to_string(), "WMI".to_string()],
                platforms: vec!["Windows".to_string()],
                related_techniques: vec!["T1059".to_string(), "T1021".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1055".to_string(), "T1003".to_string()],
            },
        );

        // Persistence (TA0003)
        techniques.insert("T1547".to_string(), Technique {
            id: "T1547".to_string(),
            name: "Boot or Logon Autostart Execution".to_string(),
            description: "Adversaries may configure system settings to automatically execute a program".to_string(),
            tactics: vec![Tactic::Persistence, Tactic::PrivilegeEscalation],
            sub_techniques: vec![
                SubTechnique {
                    id: "T1547.001".to_string(),
                    name: "Registry Run Keys / Startup Folder".to_string(),
                    description: "Adversaries may achieve persistence by adding to Registry run keys or Startup folder".to_string(),
                    detection_indicators: vec![
                        "Registry Run key modification".to_string(),
                        "Startup folder modification".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["Registry".to_string(), "File".to_string()],
                    platforms: vec!["Windows".to_string()],
                },
            ],
            detection_indicators: vec!["Autostart mechanism modification".to_string()],
            detection_confidence: DetectionConfidence::High,
            data_sources: vec!["Registry".to_string(), "File".to_string(), "Process".to_string()],
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            related_techniques: vec!["T1053".to_string()],
            predecessors: vec!["T1059".to_string()],
            successors: vec![],
        });

        techniques.insert(
            "T1053".to_string(),
            Technique {
                id: "T1053".to_string(),
                name: "Scheduled Task/Job".to_string(),
                description: "Adversaries may abuse task scheduling to facilitate persistence"
                    .to_string(),
                tactics: vec![
                    Tactic::Persistence,
                    Tactic::PrivilegeEscalation,
                    Tactic::Execution,
                ],
                sub_techniques: vec![SubTechnique {
                    id: "T1053.005".to_string(),
                    name: "Scheduled Task".to_string(),
                    description: "Adversaries may abuse Windows Task Scheduler".to_string(),
                    detection_indicators: vec![
                        "schtasks.exe execution".to_string(),
                        "Task creation events".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["Process".to_string(), "Scheduled Job".to_string()],
                    platforms: vec!["Windows".to_string()],
                }],
                detection_indicators: vec!["Task/job creation".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Process".to_string(), "Scheduled Job".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1547".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec![],
            },
        );

        techniques.insert(
            "T1543".to_string(),
            Technique {
                id: "T1543".to_string(),
                name: "Create or Modify System Process".to_string(),
                description: "Adversaries may create or modify system-level processes to persist"
                    .to_string(),
                tactics: vec![Tactic::Persistence, Tactic::PrivilegeEscalation],
                sub_techniques: vec![SubTechnique {
                    id: "T1543.003".to_string(),
                    name: "Windows Service".to_string(),
                    description: "Adversaries may create or modify Windows services".to_string(),
                    detection_indicators: vec![
                        "Service creation".to_string(),
                        "sc.exe usage".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["Service".to_string(), "Process".to_string()],
                    platforms: vec!["Windows".to_string()],
                }],
                detection_indicators: vec!["System service modification".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec![
                    "Service".to_string(),
                    "Process".to_string(),
                    "Registry".to_string(),
                ],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1547".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec![],
            },
        );

        // Privilege Escalation (TA0004)
        techniques.insert(
            "T1055".to_string(),
            Technique {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                description: "Adversaries may inject code into processes to evade defenses"
                    .to_string(),
                tactics: vec![Tactic::PrivilegeEscalation, Tactic::DefenseEvasion],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1055.001".to_string(),
                        name: "Dynamic-link Library Injection".to_string(),
                        description: "Adversaries may inject DLLs into processes".to_string(),
                        detection_indicators: vec!["DLL injection API calls".to_string()],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Process".to_string(), "Module".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1055.012".to_string(),
                        name: "Process Hollowing".to_string(),
                        description:
                            "Adversaries may inject malicious code into suspended processes"
                                .to_string(),
                        detection_indicators: vec!["Process hollowing patterns".to_string()],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Process".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                ],
                detection_indicators: vec![
                    "Cross-process memory operations".to_string(),
                    "CreateRemoteThread usage".to_string(),
                    "WriteProcessMemory usage".to_string(),
                ],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Process".to_string(), "Module".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1059".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1003".to_string()],
            },
        );

        techniques.insert(
            "T1068".to_string(),
            Technique {
                id: "T1068".to_string(),
                name: "Exploitation for Privilege Escalation".to_string(),
                description: "Adversaries may exploit vulnerabilities to escalate privileges"
                    .to_string(),
                tactics: vec![Tactic::PrivilegeEscalation],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Known exploit patterns".to_string(),
                    "Privilege escalation from low to high".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Process".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1055".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1003".to_string()],
            },
        );

        techniques.insert(
            "T1548".to_string(),
            Technique {
                id: "T1548".to_string(),
                name: "Abuse Elevation Control Mechanism".to_string(),
                description: "Adversaries may bypass UAC or other elevation mechanisms".to_string(),
                tactics: vec![Tactic::PrivilegeEscalation, Tactic::DefenseEvasion],
                sub_techniques: vec![SubTechnique {
                    id: "T1548.002".to_string(),
                    name: "Bypass User Account Control".to_string(),
                    description: "Adversaries may bypass UAC mechanisms".to_string(),
                    detection_indicators: vec![
                        "UAC bypass techniques".to_string(),
                        "Auto-elevate abuse".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["Process".to_string(), "Registry".to_string()],
                    platforms: vec!["Windows".to_string()],
                }],
                detection_indicators: vec!["Elevation control bypass".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Process".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1055".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1003".to_string()],
            },
        );

        // Defense Evasion (TA0005)
        techniques.insert(
            "T1027".to_string(),
            Technique {
                id: "T1027".to_string(),
                name: "Obfuscated Files or Information".to_string(),
                description: "Adversaries may obfuscate files or information to evade detection"
                    .to_string(),
                tactics: vec![Tactic::DefenseEvasion],
                sub_techniques: vec![SubTechnique {
                    id: "T1027.001".to_string(),
                    name: "Binary Padding".to_string(),
                    description: "Adversaries may pad binaries to change hash".to_string(),
                    detection_indicators: vec!["Unusual binary size".to_string()],
                    detection_confidence: DetectionConfidence::Low,
                    data_sources: vec!["File".to_string()],
                    platforms: vec![
                        "Windows".to_string(),
                        "Linux".to_string(),
                        "macOS".to_string(),
                    ],
                }],
                detection_indicators: vec![
                    "High entropy files".to_string(),
                    "Packed executables".to_string(),
                    "Encoded scripts".to_string(),
                ],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["File".to_string(), "Process".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1059".to_string()],
                predecessors: vec!["T1566".to_string()],
                successors: vec!["T1059".to_string()],
            },
        );

        techniques.insert(
            "T1070".to_string(),
            Technique {
                id: "T1070".to_string(),
                name: "Indicator Removal".to_string(),
                description: "Adversaries may remove indicators of compromise".to_string(),
                tactics: vec![Tactic::DefenseEvasion],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1070.001".to_string(),
                        name: "Clear Windows Event Logs".to_string(),
                        description: "Adversaries may clear Windows Event Logs".to_string(),
                        detection_indicators: vec![
                            "wevtutil cl execution".to_string(),
                            "Event log cleared events".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::VeryHigh,
                        data_sources: vec!["Process".to_string(), "Windows Event Log".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1070.004".to_string(),
                        name: "File Deletion".to_string(),
                        description: "Adversaries may delete files to remove evidence".to_string(),
                        detection_indicators: vec!["File deletion activity".to_string()],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec!["File".to_string()],
                        platforms: vec![
                            "Windows".to_string(),
                            "Linux".to_string(),
                            "macOS".to_string(),
                        ],
                    },
                ],
                detection_indicators: vec!["Log clearing".to_string(), "File deletion".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec![
                    "Process".to_string(),
                    "File".to_string(),
                    "Windows Event Log".to_string(),
                ],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec![],
                predecessors: vec!["T1059".to_string()],
                successors: vec![],
            },
        );

        techniques.insert(
            "T1562".to_string(),
            Technique {
                id: "T1562".to_string(),
                name: "Impair Defenses".to_string(),
                description: "Adversaries may disable security tools and logging".to_string(),
                tactics: vec![Tactic::DefenseEvasion],
                sub_techniques: vec![SubTechnique {
                    id: "T1562.001".to_string(),
                    name: "Disable or Modify Tools".to_string(),
                    description: "Adversaries may disable security software".to_string(),
                    detection_indicators: vec![
                        "Security service stop".to_string(),
                        "AV/EDR tampering".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::VeryHigh,
                    data_sources: vec!["Process".to_string(), "Service".to_string()],
                    platforms: vec![
                        "Windows".to_string(),
                        "Linux".to_string(),
                        "macOS".to_string(),
                    ],
                }],
                detection_indicators: vec!["Security tool modification".to_string()],
                detection_confidence: DetectionConfidence::VeryHigh,
                data_sources: vec!["Process".to_string(), "Service".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec![],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1003".to_string()],
            },
        );

        // Credential Access (TA0006)
        techniques.insert(
            "T1003".to_string(),
            Technique {
                id: "T1003".to_string(),
                name: "OS Credential Dumping".to_string(),
                description: "Adversaries may dump credentials from the operating system"
                    .to_string(),
                tactics: vec![Tactic::CredentialAccess],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1003.001".to_string(),
                        name: "LSASS Memory".to_string(),
                        description: "Adversaries may access LSASS memory for credentials"
                            .to_string(),
                        detection_indicators: vec![
                            "LSASS access".to_string(),
                            "Mimikatz usage".to_string(),
                            "Procdump on LSASS".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::VeryHigh,
                        data_sources: vec!["Process".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1003.002".to_string(),
                        name: "Security Account Manager".to_string(),
                        description: "Adversaries may dump the SAM database".to_string(),
                        detection_indicators: vec!["SAM database access".to_string()],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["File".to_string(), "Registry".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                ],
                detection_indicators: vec![
                    "Credential dumping tools".to_string(),
                    "LSASS memory access".to_string(),
                ],
                detection_confidence: DetectionConfidence::VeryHigh,
                data_sources: vec!["Process".to_string(), "File".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1055".to_string()],
                predecessors: vec!["T1059".to_string(), "T1055".to_string()],
                successors: vec!["T1021".to_string()],
            },
        );

        techniques.insert(
            "T1558".to_string(),
            Technique {
                id: "T1558".to_string(),
                name: "Steal or Forge Kerberos Tickets".to_string(),
                description: "Adversaries may steal or forge Kerberos tickets".to_string(),
                tactics: vec![Tactic::CredentialAccess],
                sub_techniques: vec![SubTechnique {
                    id: "T1558.003".to_string(),
                    name: "Kerberoasting".to_string(),
                    description: "Adversaries may request service tickets for offline cracking"
                        .to_string(),
                    detection_indicators: vec!["TGS requests for SPNs".to_string()],
                    detection_confidence: DetectionConfidence::Medium,
                    data_sources: vec!["Windows Event Log".to_string()],
                    platforms: vec!["Windows".to_string()],
                }],
                detection_indicators: vec!["Kerberos ticket manipulation".to_string()],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Windows Event Log".to_string()],
                platforms: vec!["Windows".to_string()],
                related_techniques: vec!["T1003".to_string()],
                predecessors: vec!["T1003".to_string()],
                successors: vec!["T1021".to_string()],
            },
        );

        techniques.insert(
            "T1555".to_string(),
            Technique {
                id: "T1555".to_string(),
                name: "Credentials from Password Stores".to_string(),
                description: "Adversaries may search for credentials in password stores"
                    .to_string(),
                tactics: vec![Tactic::CredentialAccess],
                sub_techniques: vec![SubTechnique {
                    id: "T1555.003".to_string(),
                    name: "Credentials from Web Browsers".to_string(),
                    description: "Adversaries may acquire credentials from web browsers"
                        .to_string(),
                    detection_indicators: vec![
                        "Browser credential file access".to_string(),
                        "Chrome Login Data access".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["File".to_string(), "Process".to_string()],
                    platforms: vec![
                        "Windows".to_string(),
                        "Linux".to_string(),
                        "macOS".to_string(),
                    ],
                }],
                detection_indicators: vec!["Password store access".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["File".to_string(), "Process".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1003".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1021".to_string()],
            },
        );

        // Discovery (TA0007)
        techniques.insert(
            "T1082".to_string(),
            Technique {
                id: "T1082".to_string(),
                name: "System Information Discovery".to_string(),
                description: "Adversaries may gather system information".to_string(),
                tactics: vec![Tactic::Discovery],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "systeminfo.exe execution".to_string(),
                    "hostname execution".to_string(),
                    "uname execution".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Process".to_string(), "Command".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1083".to_string(), "T1057".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1083".to_string(), "T1057".to_string()],
            },
        );

        techniques.insert(
            "T1083".to_string(),
            Technique {
                id: "T1083".to_string(),
                name: "File and Directory Discovery".to_string(),
                description: "Adversaries may enumerate files and directories".to_string(),
                tactics: vec![Tactic::Discovery],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "dir/ls execution".to_string(),
                    "tree execution".to_string(),
                    "find execution".to_string(),
                ],
                detection_confidence: DetectionConfidence::Low,
                data_sources: vec!["Process".to_string(), "Command".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1082".to_string()],
                predecessors: vec!["T1082".to_string()],
                successors: vec!["T1005".to_string()],
            },
        );

        techniques.insert(
            "T1057".to_string(),
            Technique {
                id: "T1057".to_string(),
                name: "Process Discovery".to_string(),
                description: "Adversaries may enumerate running processes".to_string(),
                tactics: vec![Tactic::Discovery],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "tasklist execution".to_string(),
                    "ps execution".to_string(),
                    "Get-Process execution".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Process".to_string(), "Command".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1082".to_string()],
                predecessors: vec!["T1082".to_string()],
                successors: vec!["T1055".to_string()],
            },
        );

        // Lateral Movement (TA0008)
        techniques.insert(
            "T1021".to_string(),
            Technique {
                id: "T1021".to_string(),
                name: "Remote Services".to_string(),
                description: "Adversaries may use valid accounts to log into remote services"
                    .to_string(),
                tactics: vec![Tactic::LateralMovement],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1021.001".to_string(),
                        name: "Remote Desktop Protocol".to_string(),
                        description: "Adversaries may use RDP to move laterally".to_string(),
                        detection_indicators: vec![
                            "RDP connection".to_string(),
                            "mstsc.exe execution".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec![
                            "Network Traffic".to_string(),
                            "Logon Session".to_string(),
                        ],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1021.002".to_string(),
                        name: "SMB/Windows Admin Shares".to_string(),
                        description: "Adversaries may use SMB to move laterally".to_string(),
                        detection_indicators: vec!["SMB connection to admin shares".to_string()],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Network Traffic".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                    SubTechnique {
                        id: "T1021.004".to_string(),
                        name: "SSH".to_string(),
                        description: "Adversaries may use SSH to move laterally".to_string(),
                        detection_indicators: vec!["SSH connection".to_string()],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec![
                            "Network Traffic".to_string(),
                            "Logon Session".to_string(),
                        ],
                        platforms: vec!["Linux".to_string(), "macOS".to_string()],
                    },
                    SubTechnique {
                        id: "T1021.006".to_string(),
                        name: "Windows Remote Management".to_string(),
                        description: "Adversaries may use WinRM to move laterally".to_string(),
                        detection_indicators: vec!["WinRM connection".to_string()],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Network Traffic".to_string(), "Process".to_string()],
                        platforms: vec!["Windows".to_string()],
                    },
                ],
                detection_indicators: vec!["Remote service authentication".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Network Traffic".to_string(), "Logon Session".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1003".to_string()],
                predecessors: vec!["T1003".to_string()],
                successors: vec!["T1059".to_string()],
            },
        );

        techniques.insert(
            "T1570".to_string(),
            Technique {
                id: "T1570".to_string(),
                name: "Lateral Tool Transfer".to_string(),
                description: "Adversaries may transfer tools between systems".to_string(),
                tactics: vec![Tactic::LateralMovement],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "SMB file copy".to_string(),
                    "Tool transfer via admin shares".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Network Traffic".to_string(), "File".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1021".to_string()],
                predecessors: vec!["T1021".to_string()],
                successors: vec!["T1059".to_string()],
            },
        );

        // Collection (TA0009)
        techniques.insert(
            "T1005".to_string(),
            Technique {
                id: "T1005".to_string(),
                name: "Data from Local System".to_string(),
                description: "Adversaries may search local system sources for data".to_string(),
                tactics: vec![Tactic::Collection],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Sensitive file access".to_string(),
                    "Document collection".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["File".to_string(), "Process".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1083".to_string()],
                predecessors: vec!["T1083".to_string()],
                successors: vec!["T1041".to_string()],
            },
        );

        techniques.insert(
            "T1114".to_string(),
            Technique {
                id: "T1114".to_string(),
                name: "Email Collection".to_string(),
                description: "Adversaries may target email to collect sensitive information"
                    .to_string(),
                tactics: vec![Tactic::Collection],
                sub_techniques: vec![SubTechnique {
                    id: "T1114.001".to_string(),
                    name: "Local Email Collection".to_string(),
                    description: "Adversaries may collect email from local storage".to_string(),
                    detection_indicators: vec![
                        "PST/OST file access".to_string(),
                        "Email database access".to_string(),
                    ],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["File".to_string()],
                    platforms: vec!["Windows".to_string()],
                }],
                detection_indicators: vec!["Email data access".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["File".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1005".to_string()],
                predecessors: vec!["T1083".to_string()],
                successors: vec!["T1041".to_string()],
            },
        );

        // Command and Control (TA0011)
        techniques.insert(
            "T1071".to_string(),
            Technique {
                id: "T1071".to_string(),
                name: "Application Layer Protocol".to_string(),
                description: "Adversaries may communicate using application layer protocols"
                    .to_string(),
                tactics: vec![Tactic::CommandAndControl],
                sub_techniques: vec![
                    SubTechnique {
                        id: "T1071.001".to_string(),
                        name: "Web Protocols".to_string(),
                        description: "Adversaries may communicate using HTTP/HTTPS".to_string(),
                        detection_indicators: vec!["HTTP/HTTPS C2 traffic".to_string()],
                        detection_confidence: DetectionConfidence::Medium,
                        data_sources: vec!["Network Traffic".to_string()],
                        platforms: vec![
                            "Windows".to_string(),
                            "Linux".to_string(),
                            "macOS".to_string(),
                        ],
                    },
                    SubTechnique {
                        id: "T1071.004".to_string(),
                        name: "DNS".to_string(),
                        description: "Adversaries may communicate using DNS protocol".to_string(),
                        detection_indicators: vec![
                            "DNS tunneling".to_string(),
                            "Suspicious DNS queries".to_string(),
                        ],
                        detection_confidence: DetectionConfidence::High,
                        data_sources: vec!["Network Traffic".to_string()],
                        platforms: vec![
                            "Windows".to_string(),
                            "Linux".to_string(),
                            "macOS".to_string(),
                        ],
                    },
                ],
                detection_indicators: vec!["C2 protocol usage".to_string()],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Network Traffic".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1105".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1105".to_string()],
            },
        );

        techniques.insert(
            "T1105".to_string(),
            Technique {
                id: "T1105".to_string(),
                name: "Ingress Tool Transfer".to_string(),
                description: "Adversaries may transfer tools from external systems".to_string(),
                tactics: vec![Tactic::CommandAndControl],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "File download from external source".to_string(),
                    "curl/wget usage".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Network Traffic".to_string(), "File".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1071".to_string()],
                predecessors: vec!["T1071".to_string()],
                successors: vec!["T1059".to_string()],
            },
        );

        techniques.insert(
            "T1568".to_string(),
            Technique {
                id: "T1568".to_string(),
                name: "Dynamic Resolution".to_string(),
                description: "Adversaries may dynamically establish C2 infrastructure".to_string(),
                tactics: vec![Tactic::CommandAndControl],
                sub_techniques: vec![SubTechnique {
                    id: "T1568.002".to_string(),
                    name: "Domain Generation Algorithms".to_string(),
                    description: "Adversaries may use DGAs for C2".to_string(),
                    detection_indicators: vec!["DGA domain patterns".to_string()],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["Network Traffic".to_string()],
                    platforms: vec![
                        "Windows".to_string(),
                        "Linux".to_string(),
                        "macOS".to_string(),
                    ],
                }],
                detection_indicators: vec!["Dynamic C2 resolution".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Network Traffic".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1071".to_string()],
                predecessors: vec![],
                successors: vec!["T1071".to_string()],
            },
        );

        // Exfiltration (TA0010)
        techniques.insert(
            "T1041".to_string(),
            Technique {
                id: "T1041".to_string(),
                name: "Exfiltration Over C2 Channel".to_string(),
                description: "Adversaries may exfiltrate data over the C2 channel".to_string(),
                tactics: vec![Tactic::Exfiltration],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Large outbound data transfers".to_string(),
                    "Data exfil over HTTP/HTTPS".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Network Traffic".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1071".to_string()],
                predecessors: vec!["T1005".to_string()],
                successors: vec![],
            },
        );

        techniques.insert(
            "T1048".to_string(),
            Technique {
                id: "T1048".to_string(),
                name: "Exfiltration Over Alternative Protocol".to_string(),
                description: "Adversaries may exfiltrate data over a different protocol than C2"
                    .to_string(),
                tactics: vec![Tactic::Exfiltration],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Data transfer over non-standard ports".to_string(),
                    "DNS exfiltration".to_string(),
                ],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Network Traffic".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1041".to_string()],
                predecessors: vec!["T1005".to_string()],
                successors: vec![],
            },
        );

        // Impact (TA0040)
        techniques.insert(
            "T1486".to_string(),
            Technique {
                id: "T1486".to_string(),
                name: "Data Encrypted for Impact".to_string(),
                description: "Adversaries may encrypt data to interrupt availability (ransomware)"
                    .to_string(),
                tactics: vec![Tactic::Impact],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Mass file encryption".to_string(),
                    "Ransom note creation".to_string(),
                    "File extension changes".to_string(),
                ],
                detection_confidence: DetectionConfidence::VeryHigh,
                data_sources: vec!["File".to_string(), "Process".to_string()],
                platforms: vec![
                    "Windows".to_string(),
                    "Linux".to_string(),
                    "macOS".to_string(),
                ],
                related_techniques: vec!["T1489".to_string()],
                predecessors: vec!["T1005".to_string()],
                successors: vec![],
            },
        );

        techniques.insert(
            "T1489".to_string(),
            Technique {
                id: "T1489".to_string(),
                name: "Service Stop".to_string(),
                description: "Adversaries may stop services to render systems useless".to_string(),
                tactics: vec![Tactic::Impact],
                sub_techniques: vec![],
                detection_indicators: vec![
                    "Service stop commands".to_string(),
                    "Critical service termination".to_string(),
                ],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["Service".to_string(), "Process".to_string()],
                platforms: vec!["Windows".to_string(), "Linux".to_string()],
                related_techniques: vec!["T1486".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec!["T1486".to_string()],
            },
        );

        // Additional commonly detected techniques
        techniques.insert(
            "T1112".to_string(),
            Technique {
                id: "T1112".to_string(),
                name: "Modify Registry".to_string(),
                description: "Adversaries may modify the Registry for persistence or configuration"
                    .to_string(),
                tactics: vec![Tactic::DefenseEvasion],
                sub_techniques: vec![],
                detection_indicators: vec!["Registry modification".to_string()],
                detection_confidence: DetectionConfidence::Medium,
                data_sources: vec!["Registry".to_string()],
                platforms: vec!["Windows".to_string()],
                related_techniques: vec!["T1547".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec![],
            },
        );

        techniques.insert(
            "T1546".to_string(),
            Technique {
                id: "T1546".to_string(),
                name: "Event Triggered Execution".to_string(),
                description: "Adversaries may establish persistence using event triggers"
                    .to_string(),
                tactics: vec![Tactic::Persistence, Tactic::PrivilegeEscalation],
                sub_techniques: vec![SubTechnique {
                    id: "T1546.003".to_string(),
                    name: "WMI Event Subscription".to_string(),
                    description: "Adversaries may establish persistence via WMI event subscription"
                        .to_string(),
                    detection_indicators: vec!["WMI event filter/consumer creation".to_string()],
                    detection_confidence: DetectionConfidence::High,
                    data_sources: vec!["WMI".to_string()],
                    platforms: vec!["Windows".to_string()],
                }],
                detection_indicators: vec!["Event-based persistence".to_string()],
                detection_confidence: DetectionConfidence::High,
                data_sources: vec!["WMI".to_string(), "Registry".to_string()],
                platforms: vec!["Windows".to_string()],
                related_techniques: vec!["T1047".to_string()],
                predecessors: vec!["T1059".to_string()],
                successors: vec![],
            },
        );

        techniques
    }
}

impl Default for MitreCoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Technique statistics
#[derive(Debug, Clone)]
pub struct TechniqueStats {
    pub technique_id: String,
    pub technique_name: String,
    pub total_detections: u64,
    pub avg_confidence: f32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub unique_processes: HashSet<u32>,
    confidence_sum: f32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_technique_database_loaded() {
        let tracker = MitreCoverageTracker::new();
        let techniques = tracker.techniques.read().await;
        assert!(!techniques.is_empty());
        assert!(techniques.contains_key("T1059"));
        assert!(techniques.contains_key("T1055"));
        assert!(techniques.contains_key("T1003"));
    }

    #[tokio::test]
    async fn test_tactic_coverage() {
        let tracker = MitreCoverageTracker::new();
        let coverage = tracker.get_tactic_coverage().await;

        // Should have coverage for all tactics
        assert!(coverage.contains_key(&Tactic::Execution));
        assert!(coverage.contains_key(&Tactic::Persistence));
        assert!(coverage.contains_key(&Tactic::CredentialAccess));
    }

    #[tokio::test]
    async fn test_coverage_gaps() {
        let tracker = MitreCoverageTracker::new();
        let gaps = tracker.get_coverage_gaps().await;

        // Should identify some gaps
        // Note: This depends on the confidence levels set in the database
        assert!(gaps
            .iter()
            .all(|g| g.current_confidence < DetectionConfidence::Medium));
    }

    #[test]
    fn test_attack_stage_detection() {
        let tactics = vec![Tactic::InitialAccess, Tactic::Execution];
        assert_eq!(
            AttackStage::from_tactics(&tactics),
            AttackStage::Establishment
        );

        let tactics = vec![Tactic::LateralMovement, Tactic::Discovery];
        assert_eq!(AttackStage::from_tactics(&tactics), AttackStage::Expansion);

        let tactics = vec![Tactic::Exfiltration];
        assert_eq!(AttackStage::from_tactics(&tactics), AttackStage::Objective);
    }

    #[test]
    fn test_tactic_parsing() {
        assert_eq!(Tactic::from_str("TA0001"), Some(Tactic::InitialAccess));
        assert_eq!(Tactic::from_str("EXECUTION"), Some(Tactic::Execution));
        assert_eq!(Tactic::from_str("invalid"), None);
    }

    #[test]
    fn test_detection_confidence_from_score() {
        assert_eq!(
            DetectionConfidence::from_score(0.95),
            DetectionConfidence::VeryHigh
        );
        assert_eq!(
            DetectionConfidence::from_score(0.75),
            DetectionConfidence::High
        );
        assert_eq!(
            DetectionConfidence::from_score(0.5),
            DetectionConfidence::Medium
        );
        assert_eq!(
            DetectionConfidence::from_score(0.25),
            DetectionConfidence::Low
        );
        assert_eq!(
            DetectionConfidence::from_score(0.0),
            DetectionConfidence::None
        );
    }

    #[tokio::test]
    async fn test_coverage_report_generation() {
        let tracker = MitreCoverageTracker::new();
        let report = tracker.generate_coverage_report().await;

        assert!(report.overall_coverage >= 0.0);
        assert!(!report.tactic_coverage.is_empty());
    }

    #[tokio::test]
    async fn test_csv_export() {
        let tracker = MitreCoverageTracker::new();
        let csv = tracker.export_coverage_matrix().await;

        assert!(csv.contains("Technique ID"));
        assert!(csv.contains("T1059"));
    }
}
