//! Detection Explainability Engine
//!
//! UNIQUE FEATURE: Provides human-readable explanations for why
//! detections were triggered, including:
//! - Feature importance for ML decisions
//! - Rule matching details
//! - Behavioral pattern analysis
//! - Historical context
//! - Attack chain reconstruction
//!
//! This helps analysts understand:
//! - WHY was this flagged?
//! - WHAT specific behaviors triggered the alert?
//! - HOW confident should we be?
//! - WHAT should we investigate next?

// Detection explainability engine. Scaffolded baseline fields and parameters
// are retained for upcoming feature-attribution code paths.
#![allow(dead_code, unused_variables)]

use crate::collectors::{Detection, DetectionType, EventPayload, TelemetryEvent};
use std::collections::HashMap;

/// Explanation entry
#[derive(Debug, Clone)]
pub struct ExplanationEntry {
    /// Factor name
    pub factor: String,
    /// Contribution to detection (0.0 - 1.0)
    pub contribution: f32,
    /// Human-readable description
    pub description: String,
    /// Evidence supporting this factor
    pub evidence: Vec<String>,
    /// Recommended investigation action
    pub investigation_hint: Option<String>,
}

/// Full explanation for a detection
#[derive(Debug, Clone)]
pub struct DetectionExplanation {
    /// Summary in plain language
    pub summary: String,
    /// Individual contributing factors
    pub factors: Vec<ExplanationEntry>,
    /// Overall confidence explanation
    pub confidence_explanation: String,
    /// Suggested investigation steps
    pub investigation_steps: Vec<String>,
    /// Related MITRE ATT&CK context
    pub mitre_context: MitreContext,
    /// Similar historical incidents
    pub similar_incidents: Vec<String>,
    /// False positive indicators (things that suggest this might be benign)
    pub fp_indicators: Vec<String>,
    /// True positive indicators (things that suggest this is malicious)
    pub tp_indicators: Vec<String>,
}

/// MITRE ATT&CK context
#[derive(Debug, Clone, Default)]
pub struct MitreContext {
    pub tactics: Vec<TacticInfo>,
    pub techniques: Vec<TechniqueInfo>,
    pub attack_stage: String,
    pub typical_next_steps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TacticInfo {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct TechniqueInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub detection_tips: Vec<String>,
}

/// Detection explainer
pub struct DetectionExplainer {
    /// MITRE ATT&CK knowledge base
    mitre_kb: MitreKnowledgeBase,
    /// Process behavior baseline
    process_baselines: HashMap<String, ProcessBaseline>,
}

#[derive(Debug, Clone, Default)]
struct ProcessBaseline {
    typical_children: Vec<String>,
    typical_network_destinations: Vec<String>,
    typical_file_operations: Vec<String>,
    typical_registry_operations: Vec<String>,
}

impl DetectionExplainer {
    /// Create a new explainer
    pub fn new() -> Self {
        Self {
            mitre_kb: MitreKnowledgeBase::new(),
            process_baselines: Self::load_baselines(),
        }
    }

    /// Generate explanation for a detection
    pub fn explain(&self, event: &TelemetryEvent, detection: &Detection) -> DetectionExplanation {
        let mut factors = Vec::new();
        let mut tp_indicators = Vec::new();
        let mut fp_indicators = Vec::new();
        let mut investigation_steps = Vec::new();

        // Analyze based on detection type
        match detection.detection_type {
            DetectionType::Behavioral => {
                self.explain_behavioral(
                    event,
                    detection,
                    &mut factors,
                    &mut tp_indicators,
                    &mut fp_indicators,
                );
            }
            DetectionType::Yara => {
                self.explain_yara(event, detection, &mut factors, &mut tp_indicators);
            }
            DetectionType::Sigma => {
                self.explain_sigma(event, detection, &mut factors, &mut tp_indicators);
            }
            DetectionType::Ioc | DetectionType::ThreatIntel => {
                self.explain_ioc(event, detection, &mut factors, &mut tp_indicators);
            }
            DetectionType::Honeyfile => {
                self.explain_honeyfile(event, detection, &mut factors, &mut tp_indicators);
            }
            DetectionType::Entropy => {
                self.explain_entropy(
                    event,
                    detection,
                    &mut factors,
                    &mut tp_indicators,
                    &mut fp_indicators,
                );
            }
            DetectionType::Ransomware => {
                factors.push(ExplanationEntry {
                    factor: "ransomware_detection".to_string(),
                    contribution: 0.95,
                    description: "Ransomware behavior detected - file encryption patterns observed"
                        .to_string(),
                    evidence: vec![detection.description.clone()],
                    investigation_hint: Some(
                        "Check for ransom notes and encrypted file extensions".to_string(),
                    ),
                });
                tp_indicators
                    .push("Rapid file modification with encryption signatures".to_string());
                tp_indicators.push("Extension changes to known ransomware patterns".to_string());
            }
            DetectionType::Malware => {
                factors.push(ExplanationEntry {
                    factor: "malware_detection".to_string(),
                    contribution: 0.9,
                    description: "Malware signatures or behavior detected".to_string(),
                    evidence: vec![detection.description.clone()],
                    investigation_hint: Some(
                        "Submit sample to sandbox for full analysis".to_string(),
                    ),
                });
                tp_indicators.push("Known malware signature match".to_string());
            }
            DetectionType::MemoryThreat => {
                factors.push(ExplanationEntry {
                    factor: "memory_threat".to_string(),
                    contribution: 0.85,
                    description: "Suspicious memory patterns detected - possible fileless malware"
                        .to_string(),
                    evidence: vec![detection.description.clone()],
                    investigation_hint: Some(
                        "Capture memory dump for forensic analysis".to_string(),
                    ),
                });
                tp_indicators.push("Shellcode or injection patterns in memory".to_string());
                tp_indicators.push("Suspicious memory region permissions".to_string());
            }
            DetectionType::DriverThreat => {
                factors.push(ExplanationEntry {
                    factor: "driver_threat".to_string(),
                    contribution: 0.9,
                    description: "Malicious or vulnerable driver detected".to_string(),
                    evidence: vec![detection.description.clone()],
                    investigation_hint: Some(
                        "Block driver and check for kernel-level persistence".to_string(),
                    ),
                });
                tp_indicators.push("Driver matches known BYOVD blocklist".to_string());
                tp_indicators.push("Driver has known vulnerabilities".to_string());
            }
            // Handle other detection types with generic explanation
            _ => {
                factors.push(ExplanationEntry {
                    factor: format!("{:?}_detection", detection.detection_type).to_lowercase(),
                    contribution: detection.confidence,
                    description: detection.description.clone(),
                    evidence: vec![detection.description.clone()],
                    investigation_hint: Some(
                        "Review detection details and correlate with other events".to_string(),
                    ),
                });
                tp_indicators.push("Detection matched configured rules".to_string());
            }
        }

        // Generate investigation steps
        investigation_steps.extend(self.generate_investigation_steps(event, detection));

        // Get MITRE context
        let mitre_context =
            self.get_mitre_context(&detection.mitre_techniques, &detection.mitre_tactics);

        // Generate summary
        let summary = self.generate_summary(event, detection, &factors);

        // Generate confidence explanation
        let confidence_explanation = self.explain_confidence(detection.confidence, &factors);

        DetectionExplanation {
            summary,
            factors,
            confidence_explanation,
            investigation_steps,
            mitre_context,
            similar_incidents: Vec::new(), // Would be populated from historical data
            fp_indicators,
            tp_indicators,
        }
    }

    fn explain_behavioral(
        &self,
        event: &TelemetryEvent,
        detection: &Detection,
        factors: &mut Vec<ExplanationEntry>,
        tp_indicators: &mut Vec<String>,
        fp_indicators: &mut Vec<String>,
    ) {
        match &event.payload {
            EventPayload::Process(proc) => {
                // Parent-child relationship analysis
                if let Some(ref parent_name) = proc.parent_name {
                    let parent_lower = parent_name.to_lowercase();
                    let child_lower = proc.name.to_lowercase();

                    // Office spawning shell
                    if (parent_lower.contains("word")
                        || parent_lower.contains("excel")
                        || parent_lower.contains("outlook"))
                        && (child_lower.contains("cmd") || child_lower.contains("powershell"))
                    {
                        factors.push(ExplanationEntry {
                            factor: "Suspicious Parent-Child".to_string(),
                            contribution: 0.4,
                            description: format!(
                                "Office application ({}) spawned a command shell ({}) - common malware delivery technique",
                                parent_name, proc.name
                            ),
                            evidence: vec![
                                format!("Parent: {}", parent_name),
                                format!("Child: {}", proc.name),
                            ],
                            investigation_hint: Some("Check for recent email attachments or downloaded documents".to_string()),
                        });
                        tp_indicators.push(
                            "Office application spawning shell is a common macro malware indicator"
                                .to_string(),
                        );
                    }

                    // Known baseline deviation
                    if let Some(baseline) = self.process_baselines.get(&parent_lower) {
                        if !baseline
                            .typical_children
                            .iter()
                            .any(|c| child_lower.contains(c))
                        {
                            factors.push(ExplanationEntry {
                                factor: "Baseline Deviation".to_string(),
                                contribution: 0.2,
                                description: format!(
                                    "{} doesn't typically spawn {} based on learned behavior",
                                    parent_name, proc.name
                                ),
                                evidence: vec![format!(
                                    "Typical children: {:?}",
                                    baseline.typical_children
                                )],
                                investigation_hint: Some(
                                    "Verify if this is a new legitimate behavior".to_string(),
                                ),
                            });
                        }
                    }
                }

                // Command line analysis
                let cmdline_lower = proc.cmdline.to_lowercase();

                if cmdline_lower.contains("-enc") || cmdline_lower.contains("-encodedcommand") {
                    factors.push(ExplanationEntry {
                        factor: "Encoded Command".to_string(),
                        contribution: 0.35,
                        description: "PowerShell executed with encoded/obfuscated command - often used to hide malicious intent".to_string(),
                        evidence: vec![
                            "Command contains -enc or -encodedcommand flag".to_string(),
                            format!("Full command: {}", if proc.cmdline.len() > 100 { &proc.cmdline[..100] } else { &proc.cmdline }),
                        ],
                        investigation_hint: Some("Decode the Base64 command to see actual payload".to_string()),
                    });
                    tp_indicators.push(
                        "Base64 encoded PowerShell is a strong malware indicator".to_string(),
                    );
                }

                if cmdline_lower.contains("bypass") || cmdline_lower.contains("-nop") {
                    factors.push(ExplanationEntry {
                        factor: "Execution Policy Bypass".to_string(),
                        contribution: 0.25,
                        description: "Command attempts to bypass security controls".to_string(),
                        evidence: vec!["Contains bypass/nop flags".to_string()],
                        investigation_hint: None,
                    });
                }

                // Execution location
                let path_lower = proc.path.to_lowercase();
                if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp")
                {
                    factors.push(ExplanationEntry {
                        factor: "Temp Execution".to_string(),
                        contribution: 0.15,
                        description:
                            "Process running from temporary directory - common for malware"
                                .to_string(),
                        evidence: vec![format!("Path: {}", proc.path)],
                        investigation_hint: Some(
                            "Check how the file arrived in temp directory".to_string(),
                        ),
                    });
                    tp_indicators.push("Execution from temp directory is suspicious".to_string());
                } else if path_lower.contains("\\system32\\")
                    || path_lower.contains("\\program files")
                {
                    fp_indicators.push("Running from standard system location".to_string());
                }

                // Signature status
                if !proc.is_signed {
                    factors.push(ExplanationEntry {
                        factor: "Unsigned Binary".to_string(),
                        contribution: 0.15,
                        description: "Executable is not digitally signed".to_string(),
                        evidence: vec!["No valid digital signature".to_string()],
                        investigation_hint: Some(
                            "Legitimate software is usually signed".to_string(),
                        ),
                    });
                } else if let Some(ref signer) = proc.signer {
                    if signer.contains("Microsoft")
                        || signer.contains("Google")
                        || signer.contains("Apple")
                    {
                        fp_indicators.push(format!("Signed by trusted vendor: {}", signer));
                    }
                }
            }
            _ => {}
        }
    }

    fn explain_yara(
        &self,
        _event: &TelemetryEvent,
        detection: &Detection,
        factors: &mut Vec<ExplanationEntry>,
        tp_indicators: &mut Vec<String>,
    ) {
        factors.push(ExplanationEntry {
            factor: "YARA Rule Match".to_string(),
            contribution: 0.8,
            description: format!("Matched YARA rule: {}", detection.rule_name),
            evidence: vec![detection.description.clone()],
            investigation_hint: Some(
                "Review the matched file content and rule definition".to_string(),
            ),
        });
        tp_indicators.push(format!(
            "YARA rule '{}' designed to detect known malware patterns",
            detection.rule_name
        ));
    }

    fn explain_sigma(
        &self,
        _event: &TelemetryEvent,
        detection: &Detection,
        factors: &mut Vec<ExplanationEntry>,
        tp_indicators: &mut Vec<String>,
    ) {
        factors.push(ExplanationEntry {
            factor: "Sigma Rule Match".to_string(),
            contribution: 0.7,
            description: format!("Matched Sigma rule: {}", detection.rule_name),
            evidence: vec![detection.description.clone()],
            investigation_hint: Some("Check the full event context and timeline".to_string()),
        });
        tp_indicators.push(format!(
            "Sigma rule '{}' detects known attack patterns",
            detection.rule_name
        ));
    }

    fn explain_ioc(
        &self,
        event: &TelemetryEvent,
        detection: &Detection,
        factors: &mut Vec<ExplanationEntry>,
        tp_indicators: &mut Vec<String>,
    ) {
        factors.push(ExplanationEntry {
            factor: "Known Indicator Match".to_string(),
            contribution: detection.confidence,
            description: format!(
                "Matched known threat intelligence indicator: {}",
                detection.rule_name
            ),
            evidence: vec![detection.description.clone()],
            investigation_hint: Some(
                "Check threat intel source for additional context".to_string(),
            ),
        });
        tp_indicators.push("Match against curated threat intelligence".to_string());
    }

    fn explain_honeyfile(
        &self,
        _event: &TelemetryEvent,
        detection: &Detection,
        factors: &mut Vec<ExplanationEntry>,
        tp_indicators: &mut Vec<String>,
    ) {
        factors.push(ExplanationEntry {
            factor: "Deception Triggered".to_string(),
            contribution: 0.95,
            description: "Honeyfile/honeytoken access detected - no legitimate process should access these files".to_string(),
            evidence: vec![
                detection.description.clone(),
            ],
            investigation_hint: Some("Immediately investigate the accessing process - this is high confidence".to_string()),
        });
        tp_indicators.push("Honeyfile access has near-zero false positive rate".to_string());
    }

    fn explain_entropy(
        &self,
        event: &TelemetryEvent,
        detection: &Detection,
        factors: &mut Vec<ExplanationEntry>,
        tp_indicators: &mut Vec<String>,
        fp_indicators: &mut Vec<String>,
    ) {
        if let EventPayload::File(file_event) = &event.payload {
            factors.push(ExplanationEntry {
                factor: "High Entropy".to_string(),
                contribution: 0.5,
                description: format!(
                    "File has entropy of {:.2} bits - indicates encrypted/compressed content",
                    file_event.entropy
                ),
                evidence: vec![
                    format!("Entropy: {:.2}", file_event.entropy),
                    format!("File: {}", file_event.path),
                ],
                investigation_hint: Some(
                    "Check if file was recently encrypted by a suspicious process".to_string(),
                ),
            });

            if file_event.entropy > 7.9 {
                tp_indicators.push("Entropy > 7.9 strongly indicates encryption".to_string());
            }

            // Check if it's a known compressed format
            if file_event.path.ends_with(".zip")
                || file_event.path.ends_with(".7z")
                || file_event.path.ends_with(".gz")
            {
                fp_indicators
                    .push("File is a known archive format - high entropy is expected".to_string());
            }
        }
    }

    fn generate_investigation_steps(
        &self,
        event: &TelemetryEvent,
        detection: &Detection,
    ) -> Vec<String> {
        let mut steps = Vec::new();

        match &event.payload {
            EventPayload::Process(proc) => {
                steps.push(format!(
                    "1. Examine process tree for PID {} to understand execution context",
                    proc.pid
                ));
                steps.push(
                    "2. Check for related file and network activity in the same timeframe"
                        .to_string(),
                );
                if !proc.sha256.is_empty() {
                    steps.push(format!(
                        "3. Search VirusTotal for hash: {}",
                        hex::encode(&proc.sha256)
                    ));
                }
                if let Some(ref parent) = proc.parent_name {
                    steps.push(format!("4. Investigate parent process: {}", parent));
                }
            }
            EventPayload::Network(net) => {
                steps.push(format!(
                    "1. Check reputation of remote IP: {}",
                    net.remote_ip
                ));
                steps.push(format!(
                    "2. Look for other connections to {}:{}",
                    net.remote_ip, net.remote_port
                ));
                steps.push(format!(
                    "3. Examine process {} (PID: {}) for other suspicious activity",
                    net.process_name, net.pid
                ));
            }
            EventPayload::File(file) => {
                steps.push(format!("1. Collect and analyze file: {}", file.path));
                steps.push(format!(
                    "2. Identify process {} that performed the operation",
                    file.process_name
                ));
                steps.push("3. Check for bulk file operations by the same process".to_string());
            }
            _ => {
                steps.push("1. Review full event details".to_string());
                steps.push("2. Check related events in timeline".to_string());
            }
        }

        // Add MITRE-specific steps
        for technique in &detection.mitre_techniques {
            if let Some(info) = self.mitre_kb.get_technique(technique) {
                for tip in &info.detection_tips {
                    steps.push(format!("[{}] {}", technique, tip));
                }
            }
        }

        steps
    }

    fn get_mitre_context(&self, techniques: &[String], tactics: &[String]) -> MitreContext {
        let mut context = MitreContext::default();

        for tactic in tactics {
            if let Some(info) = self.mitre_kb.get_tactic(tactic) {
                context.tactics.push(info.clone());
            }
        }

        for technique in techniques {
            if let Some(info) = self.mitre_kb.get_technique(technique) {
                context.techniques.push(info.clone());
            }
        }

        // Determine attack stage
        context.attack_stage = self.determine_attack_stage(tactics);
        context.typical_next_steps = self.predict_next_steps(tactics, techniques);

        context
    }

    fn determine_attack_stage(&self, tactics: &[String]) -> String {
        for tactic in tactics {
            let tactic_lower = tactic.to_lowercase();
            if tactic_lower.contains("initial") {
                return "Early Stage - Initial Access".to_string();
            }
            if tactic_lower.contains("execution") || tactic_lower.contains("persistence") {
                return "Establishment Phase".to_string();
            }
            if tactic_lower.contains("privilege") || tactic_lower.contains("credential") {
                return "Escalation Phase".to_string();
            }
            if tactic_lower.contains("lateral") || tactic_lower.contains("discovery") {
                return "Expansion Phase".to_string();
            }
            if tactic_lower.contains("collection") || tactic_lower.contains("exfiltration") {
                return "Objective Phase - Data Theft".to_string();
            }
            if tactic_lower.contains("impact") {
                return "Final Phase - Impact".to_string();
            }
        }
        "Unknown Stage".to_string()
    }

    fn predict_next_steps(&self, _tactics: &[String], techniques: &[String]) -> Vec<String> {
        let mut predictions = Vec::new();

        for technique in techniques {
            match technique.as_str() {
                "T1059" | "T1059.001" => {
                    predictions.push(
                        "Watch for: Persistence mechanisms (scheduled tasks, registry run keys)"
                            .to_string(),
                    );
                    predictions.push("Watch for: Credential dumping attempts".to_string());
                }
                "T1055" => {
                    predictions
                        .push("Watch for: Network connections from injected processes".to_string());
                    predictions.push("Watch for: Privilege escalation attempts".to_string());
                }
                "T1003" => {
                    predictions
                        .push("Watch for: Lateral movement using stolen credentials".to_string());
                    predictions.push("Watch for: Access to sensitive file shares".to_string());
                }
                _ => {}
            }
        }

        if predictions.is_empty() {
            predictions.push("Monitor for follow-up suspicious activity".to_string());
        }

        predictions
    }

    fn generate_summary(
        &self,
        event: &TelemetryEvent,
        detection: &Detection,
        factors: &[ExplanationEntry],
    ) -> String {
        let top_factor = factors
            .iter()
            .max_by(|a, b| {
                a.contribution
                    .partial_cmp(&b.contribution)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|f| f.factor.as_str())
            .unwrap_or("Unknown");

        match &event.payload {
            EventPayload::Process(proc) => {
                format!(
                    "Process '{}' (PID: {}) triggered detection '{}'. Primary factor: {}. Confidence: {:.0}%",
                    proc.name, proc.pid, detection.rule_name, top_factor, detection.confidence * 100.0
                )
            }
            EventPayload::File(file) => {
                format!(
                    "File operation on '{}' by '{}' triggered detection '{}'. Primary factor: {}",
                    file.path, file.process_name, detection.rule_name, top_factor
                )
            }
            EventPayload::Network(net) => {
                format!(
                    "Network connection to {}:{} by '{}' triggered detection '{}'. Primary factor: {}",
                    net.remote_ip, net.remote_port, net.process_name, detection.rule_name, top_factor
                )
            }
            _ => {
                format!(
                    "Detection '{}' triggered. Primary factor: {}",
                    detection.rule_name, top_factor
                )
            }
        }
    }

    fn explain_confidence(&self, confidence: f32, factors: &[ExplanationEntry]) -> String {
        let total_contribution: f32 = factors.iter().map(|f| f.contribution).sum();
        let factor_count = factors.len();

        let confidence_level = if confidence >= 0.9 {
            "Very High"
        } else if confidence >= 0.75 {
            "High"
        } else if confidence >= 0.5 {
            "Medium"
        } else {
            "Low"
        };

        format!(
            "{} confidence ({:.0}%) based on {} contributing factors with combined weight of {:.2}",
            confidence_level,
            confidence * 100.0,
            factor_count,
            total_contribution
        )
    }

    fn load_baselines() -> HashMap<String, ProcessBaseline> {
        let mut baselines = HashMap::new();

        // Windows baselines
        baselines.insert(
            "explorer.exe".to_string(),
            ProcessBaseline {
                typical_children: vec!["chrome.exe", "firefox.exe", "notepad.exe", "cmd.exe"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                typical_network_destinations: vec![],
                typical_file_operations: vec![],
                typical_registry_operations: vec![],
            },
        );

        baselines.insert(
            "services.exe".to_string(),
            ProcessBaseline {
                typical_children: vec!["svchost.exe"].iter().map(|s| s.to_string()).collect(),
                typical_network_destinations: vec![],
                typical_file_operations: vec![],
                typical_registry_operations: vec![],
            },
        );

        baselines
    }
}

/// MITRE ATT&CK knowledge base
struct MitreKnowledgeBase {
    tactics: HashMap<String, TacticInfo>,
    techniques: HashMap<String, TechniqueInfo>,
}

impl MitreKnowledgeBase {
    fn new() -> Self {
        let mut kb = Self {
            tactics: HashMap::new(),
            techniques: HashMap::new(),
        };
        kb.load_knowledge();
        kb
    }

    fn load_knowledge(&mut self) {
        // Tactics
        self.tactics.insert(
            "TA0001".to_string(),
            TacticInfo {
                id: "TA0001".to_string(),
                name: "Initial Access".to_string(),
                description: "Techniques to gain initial foothold in the network".to_string(),
            },
        );

        self.tactics.insert(
            "TA0002".to_string(),
            TacticInfo {
                id: "TA0002".to_string(),
                name: "Execution".to_string(),
                description: "Techniques to run malicious code".to_string(),
            },
        );

        // Techniques
        self.techniques.insert(
            "T1059".to_string(),
            TechniqueInfo {
                id: "T1059".to_string(),
                name: "Command and Scripting Interpreter".to_string(),
                description: "Abuse of command and script interpreters to execute commands"
                    .to_string(),
                detection_tips: vec![
                    "Monitor command-line arguments for obfuscation".to_string(),
                    "Check parent process relationships".to_string(),
                ],
            },
        );

        self.techniques.insert(
            "T1055".to_string(),
            TechniqueInfo {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                description: "Inject code into processes to evade defenses".to_string(),
                detection_tips: vec![
                    "Monitor for cross-process memory operations".to_string(),
                    "Check for suspicious API calls (WriteProcessMemory, CreateRemoteThread)"
                        .to_string(),
                ],
            },
        );

        self.techniques.insert(
            "T1003".to_string(),
            TechniqueInfo {
                id: "T1003".to_string(),
                name: "OS Credential Dumping".to_string(),
                description: "Dump credentials from OS for lateral movement".to_string(),
                detection_tips: vec![
                    "Monitor LSASS access".to_string(),
                    "Watch for known credential dumping tools".to_string(),
                ],
            },
        );
    }

    fn get_tactic(&self, id: &str) -> Option<&TacticInfo> {
        self.tactics.get(id)
    }

    fn get_technique(&self, id: &str) -> Option<&TechniqueInfo> {
        self.techniques.get(id)
    }
}
