//! Analysis Pipeline
//!
//! Integrates all analyzers into a unified event processing pipeline.
//! This is the CRITICAL missing piece that connects collectors to analysis.
//!
//! ## Offline detection integration
//!
//! When an `OfflineDetector` is attached (via [`set_offline_detector`]) the
//! pipeline will:
//! - Check backend availability for each file event.
//! - If the backend is unreachable, run local ML + YARA via `OfflineDetector`.
//! - Always run local YARA regardless of backend status (fast, no network).
//! - Queue offline verdicts for later sync.

use super::behavioral::{BehavioralAnalyzer, BehavioralConfig};
use super::behavioral_chains::BehavioralEventType;
use super::data_staging::{FileAccessEvent, FileAccessType};
use super::integrated_detector::{
    DetectionEvent as IntegratedDetectionEvent, DetectionType as IntegratedDetectionType,
    IntegratedDetector, IntegratedDetectorConfig,
};
use super::offline_detection::OfflineDetector;
use super::supply_chain;
use super::threat_intel::{Ioc, IocType, ThreatIntelDb};
use crate::collectors::{Detection, DetectionType, EventPayload, EventType, TelemetryEvent};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Analysis pipeline that processes events through all analyzers
pub struct AnalysisPipeline {
    /// Behavioral analyzer for baseline/anomaly detection
    behavioral: Arc<BehavioralAnalyzer>,
    /// IOC database for threat intel matching
    ioc_db: Arc<ThreatIntelDb>,
    /// Offline detector for local ML + YARA when backend is unreachable
    offline_detector: Option<Arc<OfflineDetector>>,
    /// Integrated detector for behavioral chains, data staging, and ETW tampering
    integrated_detector: IntegratedDetector,
    /// Backend server URL (used for availability checks)
    backend_url: String,
    /// Enable local analysis
    enabled: bool,
    /// Statistics
    events_processed: Arc<std::sync::atomic::AtomicU64>,
    detections_added: Arc<std::sync::atomic::AtomicU64>,
}

impl AnalysisPipeline {
    /// Create a new analysis pipeline
    pub async fn new(enabled: bool) -> Self {
        info!("Initializing analysis pipeline (enabled: {})", enabled);

        // Initialize behavioral analyzer with default config
        let behavioral_config = BehavioralConfig::default();
        let behavioral = Arc::new(BehavioralAnalyzer::new(behavioral_config));

        // Initialize IOC database with default cache path
        let cache_path = if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\Tamandua\\cache\\iocs.db")
        } else {
            PathBuf::from("/var/lib/tamandua/cache/iocs.db")
        };
        let ioc_db = Arc::new(ThreatIntelDb::new(cache_path));

        // Initialize the database (creates tables if needed)
        if let Err(e) = ioc_db.init().await {
            tracing::warn!(error = %e, "Failed to initialize IOC database, will operate without persistent cache");
        }

        // Initialize integrated detector (behavioral chains, data staging, ETW tampering)
        let integrated_detector =
            IntegratedDetector::with_config(IntegratedDetectorConfig::default());

        // Note: behavioral analyzer starts its own background tasks in new()

        info!("Analysis pipeline initialized");

        Self {
            behavioral,
            ioc_db,
            offline_detector: None,
            integrated_detector,
            backend_url: String::new(),
            enabled,
            events_processed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            detections_added: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Attach an offline detector for local ML + YARA analysis.
    pub fn set_offline_detector(&mut self, detector: Arc<OfflineDetector>, backend_url: String) {
        self.offline_detector = Some(detector);
        self.backend_url = backend_url;
        info!("Offline detector attached to analysis pipeline");
    }

    /// Get a reference to the offline detector (if attached).
    pub fn offline_detector(&self) -> Option<&Arc<OfflineDetector>> {
        self.offline_detector.as_ref()
    }

    /// Process an event through the analysis pipeline
    /// Returns the event with added detections
    pub async fn analyze(&self, mut event: TelemetryEvent) -> TelemetryEvent {
        if !self.enabled {
            return event;
        }

        self.events_processed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // =====================================================================
        // 1. Behavioral Analysis - Check against learned baselines
        // =====================================================================
        let behavioral_detections = self.behavioral.analyze(&event).await;
        for detection in behavioral_detections {
            debug!(
                rule = %detection.rule_name,
                confidence = detection.confidence,
                "Behavioral detection"
            );
            event.detections.push(detection);
            self.detections_added
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // =====================================================================
        // 2. IOC Matching - Check hashes, IPs, domains against threat intel
        // =====================================================================
        let ioc_detections = self.check_iocs(&event).await;
        for detection in ioc_detections {
            debug!(
                rule = %detection.rule_name,
                confidence = detection.confidence,
                "IOC detection"
            );
            event.detections.push(detection);
            self.detections_added
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // =====================================================================
        // 3. Offline Detection - Local ML + YARA for file events
        // =====================================================================
        if let Some(ref detector) = self.offline_detector {
            let offline_detections = self.run_offline_detection(detector, &event).await;
            for detection in offline_detections {
                debug!(
                    rule = %detection.rule_name,
                    confidence = detection.confidence,
                    "Offline detection"
                );
                event.detections.push(detection);
                self.detections_added
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // =====================================================================
        // 4. Integrated Detection - Behavioral chains, data staging, ETW tampering
        // =====================================================================
        let integrated_detections = self.run_integrated_detection(&event);
        for detection in integrated_detections {
            debug!(
                rule = %detection.rule_name,
                confidence = detection.confidence,
                "Integrated detection"
            );
            event.detections.push(detection);
            self.detections_added
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // =====================================================================
        // 5. Supply Chain Detection - local package-manager/install behavior
        // =====================================================================
        let supply_chain_detections = supply_chain::analyze_event(&event);
        for detection in supply_chain_detections {
            debug!(
                rule = %detection.rule_name,
                confidence = detection.confidence,
                "Supply-chain detection"
            );
            event.detections.push(detection);
            self.detections_added
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // =====================================================================
        // 6. Update severity based on detections
        // =====================================================================
        if !event.detections.is_empty() {
            // Find highest confidence detection
            let max_confidence = event
                .detections
                .iter()
                .map(|d| d.confidence)
                .fold(0.0f32, f32::max);

            // Upgrade severity based on detections
            if max_confidence >= 0.9 {
                event.severity = crate::collectors::Severity::Critical;
            } else if max_confidence >= 0.7 {
                event.severity = crate::collectors::Severity::High;
            } else if max_confidence >= 0.5 {
                event.severity = crate::collectors::Severity::Medium;
            } else if max_confidence >= 0.3 {
                event.severity = crate::collectors::Severity::Low;
            }
        }

        event
    }

    /// Run offline detection for file-related events.
    ///
    /// For `FileCreate`, `FileModify`, and `FileExecute` events this checks
    /// backend availability and, when the backend is unreachable, falls back
    /// to the local ML + YARA pipeline.  Local YARA is always run as an
    /// additional layer regardless of backend status.
    async fn run_offline_detection(
        &self,
        detector: &Arc<OfflineDetector>,
        event: &TelemetryEvent,
    ) -> Vec<Detection> {
        if !Self::is_file_content_event(&event.event_type) {
            return Vec::new();
        }

        // Only process file events that have a path.
        let file_path = match &event.payload {
            EventPayload::File(f) => Some(&f.path),
            _ => None,
        };

        let file_path = match file_path {
            Some(p) if !p.is_empty() => p,
            _ => return Vec::new(),
        };
        let path = Path::new(file_path);

        // Check if the backend ML service is available.
        let backend_up = if !self.backend_url.is_empty() {
            detector.is_backend_available(&self.backend_url).await
        } else {
            false
        };

        if backend_up {
            // Backend available -- the remote ML path handles the heavy
            // lifting.  We still run local YARA as a fast extra layer.
            debug!(path = %file_path, "Backend available, skipping full offline detection");
            return match detector.analyze_file_yara_only(path).await {
                Ok(detections) => detections,
                Err(e) => {
                    debug!(
                        path = %file_path,
                        error = %e,
                        "Local YARA detection skipped for file"
                    );
                    Vec::new()
                }
            };
        }

        // Backend unreachable -- run full offline detection (ML + YARA).
        match detector.analyze_file(path).await {
            Ok((_verdict, detections)) => detections,
            Err(e) => {
                debug!(
                    path = %file_path,
                    error = %e,
                    "Offline detection skipped for file"
                );
                Vec::new()
            }
        }
    }

    /// Run integrated detection for appropriate event types.
    ///
    /// This invokes the IntegratedDetector which orchestrates:
    /// - BehavioralChainAnalyzer for multi-stage attack detection
    /// - DataStagingDetector for exfiltration preparation detection
    /// - EtwTamperingDetector for defense evasion detection (Windows)
    fn run_integrated_detection(&self, event: &TelemetryEvent) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Process events for behavioral chain analysis
        if let EventPayload::Process(proc) = &event.payload {
            let behavioral_event_type = self.map_event_to_behavioral_type(&event.event_type, proc);
            if let Some(event_type) = behavioral_event_type {
                let mitre_technique = self.get_mitre_technique_for_event(&event.event_type);
                self.integrated_detector.process_behavioral_event(
                    proc.pid,
                    proc.ppid,
                    &proc.name,
                    event_type,
                    mitre_technique,
                );
            }

            // Also run ETW tampering detection on process events (Windows only)
            #[cfg(target_os = "windows")]
            {
                let etw_detections = self.integrated_detector.scan_process_etw(proc.pid);
                for det in etw_detections {
                    detections.push(Self::convert_integrated_detection(&det));
                }
            }
        }

        // File content/activity events for data staging detection. ModuleLoad
        // also uses FileEvent payload for path/size compatibility, but a DLL
        // image load is not a file collection/read signal.
        if Self::is_file_content_event(&event.event_type) {
            let EventPayload::File(file) = &event.payload else {
                return detections;
            };

            let access_type = match event.event_type {
                EventType::FileCreate => FileAccessType::Create,
                EventType::FileModify => FileAccessType::Write,
                EventType::FileDelete => FileAccessType::Delete,
                EventType::FileRename => FileAccessType::Rename,
                EventType::FileExecute | EventType::FileExecuteBlocked => FileAccessType::Read,
                _ => FileAccessType::Read,
            };

            let file_event = FileAccessEvent {
                timestamp: event.timestamp,
                pid: file.pid,
                process_name: file.process_name.clone(),
                file_path: file.path.clone(),
                access_type,
                bytes_read: if file.size > 0 { Some(file.size) } else { None },
                bytes_written: if (access_type == FileAccessType::Write
                    || access_type == FileAccessType::Create)
                    && file.size > 0
                {
                    Some(file.size)
                } else {
                    None
                },
            };

            let staging_detections = self.integrated_detector.process_file_event(file_event);
            for det in staging_detections {
                detections.push(Self::convert_integrated_detection(&det));
            }
        }

        detections
    }

    fn is_file_content_event(event_type: &EventType) -> bool {
        matches!(
            event_type,
            EventType::FileCreate
                | EventType::FileModify
                | EventType::FileDelete
                | EventType::FileRename
                | EventType::FileExecute
                | EventType::FileExecuteBlocked
                | EventType::HoneyfileAccess
        )
    }

    /// Map event type and process info to a behavioral event type for chain analysis.
    fn map_event_to_behavioral_type(
        &self,
        event_type: &EventType,
        proc: &crate::collectors::ProcessEvent,
    ) -> Option<BehavioralEventType> {
        match event_type {
            // Discovery events
            EventType::ProcessCreate => {
                let name_lower = proc.name.to_lowercase();
                let cmdline_lower = proc.cmdline.to_lowercase();

                // Process enumeration tools
                if name_lower.contains("tasklist")
                    || name_lower.contains("ps")
                    || cmdline_lower.contains("get-process")
                {
                    return Some(BehavioralEventType::ProcessEnumeration);
                }

                // Network enumeration
                if name_lower.contains("netstat")
                    || name_lower.contains("net")
                    || cmdline_lower.contains("get-netadapter")
                    || cmdline_lower.contains("ipconfig")
                    || cmdline_lower.contains("ifconfig")
                {
                    return Some(BehavioralEventType::NetworkEnumeration);
                }

                // Account enumeration
                if cmdline_lower.contains("net user")
                    || cmdline_lower.contains("net localgroup")
                    || cmdline_lower.contains("get-localuser")
                    || cmdline_lower.contains("whoami")
                {
                    return Some(BehavioralEventType::AccountEnumeration);
                }

                // Service enumeration
                if name_lower.contains("sc") && cmdline_lower.contains("query")
                    || cmdline_lower.contains("get-service")
                {
                    return Some(BehavioralEventType::ServiceEnumeration);
                }

                // Shell execution
                if name_lower.contains("cmd")
                    || name_lower.contains("powershell")
                    || name_lower.contains("bash")
                    || name_lower.contains("sh")
                {
                    return Some(BehavioralEventType::ShellExecution);
                }

                // Script execution
                if name_lower.contains("wscript")
                    || name_lower.contains("cscript")
                    || name_lower.contains("mshta")
                    || name_lower.contains("python")
                {
                    return Some(BehavioralEventType::ScriptExecution);
                }

                // LOLBIN execution
                if name_lower.contains("certutil")
                    || name_lower.contains("bitsadmin")
                    || name_lower.contains("msiexec")
                    || name_lower.contains("regsvr32")
                    || name_lower.contains("rundll32")
                    || name_lower.contains("msbuild")
                {
                    return Some(BehavioralEventType::LolbinExecution);
                }

                None
            }

            // Credential access events
            EventType::CredentialAccess | EventType::CredentialTheft => {
                Some(BehavioralEventType::CredentialDump)
            }

            // Lateral movement events
            EventType::LateralMovement => {
                let cmdline_lower = proc.cmdline.to_lowercase();
                if cmdline_lower.contains("psexec") {
                    Some(BehavioralEventType::PsexecExecution)
                } else if cmdline_lower.contains("wmic") {
                    Some(BehavioralEventType::WmiExecution)
                } else {
                    Some(BehavioralEventType::RemoteExecution)
                }
            }

            // Defense evasion
            EventType::DefenseEvasion | EventType::ETWTamper | EventType::AMSIBypass => {
                Some(BehavioralEventType::ScriptExecution) // Map to script as a proxy
            }

            _ => None,
        }
    }

    /// Get MITRE technique for event type.
    fn get_mitre_technique_for_event(&self, event_type: &EventType) -> Option<String> {
        match event_type {
            EventType::ProcessCreate => Some("T1059".to_string()), // Command and Scripting Interpreter
            EventType::CredentialAccess => Some("T1003".to_string()), // OS Credential Dumping
            EventType::CredentialTheft => Some("T1555".to_string()), // Credentials from Password Stores
            EventType::LateralMovement => Some("T1021".to_string()), // Remote Services
            EventType::DefenseEvasion => Some("T1562".to_string()),  // Impair Defenses
            EventType::ETWTamper => Some("T1562.001".to_string()),   // Disable or Modify Tools
            EventType::AMSIBypass => Some("T1562.001".to_string()),  // Disable or Modify Tools
            EventType::PersistenceInstall => Some("T1547".to_string()), // Boot or Logon Autostart Execution
            _ => None,
        }
    }

    /// Convert IntegratedDetectionEvent to the pipeline's Detection type.
    fn convert_integrated_detection(event: &IntegratedDetectionEvent) -> Detection {
        let detection_type = match event.detection_type {
            IntegratedDetectionType::BehavioralChain => DetectionType::Behavioral,
            IntegratedDetectionType::DataStaging => DetectionType::Behavioral,
            IntegratedDetectionType::DefenseEvasion => DetectionType::DefenseEvasion,
            IntegratedDetectionType::MemoryEvasion => DetectionType::MemoryThreat,
            IntegratedDetectionType::ProcessInjection => DetectionType::ProcessHollowing,
            IntegratedDetectionType::CredentialAccess => DetectionType::CredentialTheft,
            IntegratedDetectionType::LateralMovement => DetectionType::LateralMovement,
            IntegratedDetectionType::Persistence => DetectionType::Persistence,
            IntegratedDetectionType::Correlated => DetectionType::Behavioral,
        };

        Detection {
            detection_type,
            rule_name: event.detection_id.clone(),
            confidence: event.confidence,
            description: event.description.clone(),
            mitre_tactics: event.mitre_tactics.clone(),
            mitre_techniques: event.mitre_techniques.clone(),
        }
    }

    /// Check IOCs in the event payload
    async fn check_iocs(&self, event: &TelemetryEvent) -> Vec<Detection> {
        let mut detections = Vec::new();

        match &event.payload {
            EventPayload::Process(proc) => {
                // Check process hash
                if !proc.sha256.is_empty() {
                    let hash_hex = hex::encode(&proc.sha256);
                    let matches = self.ioc_db.check(IocType::Sha256, &hash_hex).await;
                    for ioc in matches {
                        detections.push(Detection {
                            detection_type: DetectionType::Ioc,
                            rule_name: format!("IOC_SHA256_{}", ioc.source),
                            confidence: ioc.confidence,
                            description: format!(
                                "Process hash matches known malicious IOC: {} ({})",
                                hash_hex,
                                ioc.description.unwrap_or_default()
                            ),
                            mitre_tactics: ioc.mitre_tactics.clone(),
                            mitre_techniques: ioc.mitre_techniques.clone(),
                        });
                    }
                }

                detections.extend(Self::detect_suspicious_powershell(proc));

                // Check process path for suspicious indicators
                let path_lower = proc.path.to_lowercase();
                if path_lower.contains("\\temp\\") || path_lower.contains("/tmp/") {
                    if proc.is_elevated {
                        detections.push(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "ELEVATED_FROM_TEMP".to_string(),
                            confidence: 0.7,
                            description: format!(
                                "Elevated process running from temp directory: {}",
                                proc.path
                            ),
                            mitre_tactics: vec![
                                "Execution".to_string(),
                                "Defense Evasion".to_string(),
                            ],
                            mitre_techniques: vec!["T1204".to_string()],
                        });
                    }
                }
            }

            EventPayload::Network(net) => {
                // Check remote IP
                if !net.remote_ip.is_empty() && net.remote_ip != "0.0.0.0" && net.remote_ip != "::"
                {
                    let matches = self.ioc_db.check(IocType::IPv4, &net.remote_ip).await;
                    for ioc in matches {
                        detections.push(Detection {
                            detection_type: DetectionType::Ioc,
                            rule_name: format!("IOC_IP_{}", ioc.source),
                            confidence: ioc.confidence,
                            description: format!(
                                "Connection to known malicious IP: {} ({})",
                                net.remote_ip,
                                ioc.description.unwrap_or_default()
                            ),
                            mitre_tactics: vec!["Command and Control".to_string()],
                            mitre_techniques: vec!["T1071".to_string()],
                        });
                    }

                    // Check for known C2 ports
                    let suspicious_ports = [4444, 5555, 8080, 1337, 31337, 6666, 6667];
                    if suspicious_ports.contains(&net.remote_port) {
                        detections.push(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "SUSPICIOUS_PORT".to_string(),
                            confidence: 0.5,
                            description: format!(
                                "Connection to suspicious port: {}:{} by {}",
                                net.remote_ip, net.remote_port, net.process_name
                            ),
                            mitre_tactics: vec!["Command and Control".to_string()],
                            mitre_techniques: vec!["T1571".to_string()],
                        });
                    }
                }
            }

            EventPayload::Dns(dns) => {
                // Check domain against IOCs
                let matches = self.ioc_db.check(IocType::Domain, &dns.query).await;
                for ioc in matches {
                    detections.push(Detection {
                        detection_type: DetectionType::Ioc,
                        rule_name: format!("IOC_DOMAIN_{}", ioc.source),
                        confidence: ioc.confidence,
                        description: format!(
                            "DNS query for known malicious domain: {} ({})",
                            dns.query,
                            ioc.description.unwrap_or_default()
                        ),
                        mitre_tactics: vec!["Command and Control".to_string()],
                        mitre_techniques: vec!["T1071.004".to_string()],
                    });
                }

                // Check for .onion domains (Tor)
                if dns.query.ends_with(".onion") {
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "TOR_DOMAIN".to_string(),
                        confidence: 0.8,
                        description: format!(
                            "DNS query for Tor hidden service: {} by {}",
                            dns.query, dns.process_name
                        ),
                        mitre_tactics: vec!["Command and Control".to_string()],
                        mitre_techniques: vec!["T1090.003".to_string()],
                    });
                }

                // Check for DGA-like domains (high entropy, random-looking)
                if Self::looks_like_dga(&dns.query) {
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "POTENTIAL_DGA".to_string(),
                        confidence: 0.6,
                        description: format!(
                            "DNS query for potential DGA domain: {} by {}",
                            dns.query, dns.process_name
                        ),
                        mitre_tactics: vec!["Command and Control".to_string()],
                        mitre_techniques: vec!["T1568.002".to_string()],
                    });
                }
            }

            EventPayload::File(file) => {
                // Check file hash
                if !file.sha256.is_empty() {
                    let hash_hex = hex::encode(&file.sha256);
                    let matches = self.ioc_db.check(IocType::Sha256, &hash_hex).await;
                    for ioc in matches {
                        detections.push(Detection {
                            detection_type: DetectionType::Ioc,
                            rule_name: format!("IOC_FILE_{}", ioc.source),
                            confidence: ioc.confidence,
                            description: format!(
                                "File hash matches known malware: {} ({})",
                                file.path,
                                ioc.description.unwrap_or_default()
                            ),
                            mitre_tactics: ioc.mitre_tactics.clone(),
                            mitre_techniques: ioc.mitre_techniques.clone(),
                        });
                    }
                }

                // Check for high entropy (possible packed/encrypted malware)
                if file.entropy > 7.5 {
                    detections.push(Detection {
                        detection_type: DetectionType::Entropy,
                        rule_name: "HIGH_ENTROPY_FILE".to_string(),
                        confidence: 0.5,
                        description: format!(
                            "File with very high entropy ({:.2}): {} - possible packed/encrypted content",
                            file.entropy, file.path
                        ),
                        mitre_tactics: vec!["Defense Evasion".to_string()],
                        mitre_techniques: vec!["T1027".to_string()],
                    });
                }
            }

            EventPayload::Registry(reg) => {
                // Check for persistence locations
                let key_lower = reg.key_path.to_lowercase();
                let persistence_keys = [
                    "\\currentversion\\run",
                    "\\currentversion\\runonce",
                    "\\currentversion\\runservices",
                    "\\currentversion\\policies\\explorer\\run",
                    "\\currentversion\\winlogon",
                    "\\currentversion\\windows\\appinit_dlls",
                    "\\image file execution options",
                    "\\currentversion\\explorer\\shell folders",
                ];

                for persist_key in &persistence_keys {
                    if key_lower.contains(persist_key) {
                        detections.push(Detection {
                            detection_type: DetectionType::Persistence,
                            rule_name: "REGISTRY_PERSISTENCE".to_string(),
                            confidence: 0.7,
                            description: format!(
                                "Registry modification to persistence location: {} by {}",
                                reg.key_path, reg.process_name
                            ),
                            mitre_tactics: vec!["Persistence".to_string()],
                            mitre_techniques: vec!["T1547.001".to_string()],
                        });
                        break;
                    }
                }
            }

            _ => {}
        }

        detections
    }

    fn detect_suspicious_powershell(proc: &crate::collectors::ProcessEvent) -> Vec<Detection> {
        let name = proc.name.to_ascii_lowercase();
        let path = proc.path.to_ascii_lowercase();
        let cmdline = proc.cmdline.to_ascii_lowercase();

        let is_powershell = name == "powershell.exe"
            || name == "pwsh.exe"
            || path.ends_with("\\powershell.exe")
            || path.ends_with("/powershell")
            || path.ends_with("\\pwsh.exe")
            || path.ends_with("/pwsh")
            || Self::has_powershell_launcher(&cmdline);

        if !is_powershell || cmdline.trim().is_empty() {
            return Vec::new();
        }

        let mut detections = Vec::new();

        if Self::has_powershell_execution_policy_bypass(&cmdline) {
            detections.push(Detection {
                detection_type: DetectionType::ScriptThreat,
                rule_name: "powershell_execution_policy_bypass".to_string(),
                confidence: 0.55,
                description: format!(
                    "PowerShell started with ExecutionPolicy Bypass: {}",
                    proc.cmdline
                ),
                mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                mitre_techniques: vec!["T1059.001".to_string(), "T1562".to_string()],
            });
        }

        if Self::has_powershell_encoded_command(&cmdline) {
            detections.push(Detection {
                detection_type: DetectionType::ScriptThreat,
                rule_name: "powershell_encoded_command".to_string(),
                confidence: 0.75,
                description: format!("PowerShell started with encoded command: {}", proc.cmdline),
                mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                mitre_techniques: vec!["T1059.001".to_string(), "T1027".to_string()],
            });
        }

        detections
    }

    fn has_powershell_execution_policy_bypass(cmdline: &str) -> bool {
        let normalized = cmdline.replace(':', " ");
        normalized.contains("-executionpolicy bypass")
            || normalized.contains("-executionpolicy unrestricted")
            || normalized.contains("-ep bypass")
            || normalized.contains("-ep unrestricted")
            || normalized.contains("-exec bypass")
            || normalized.contains("-exec unrestricted")
    }

    fn has_powershell_encoded_command(cmdline: &str) -> bool {
        cmdline.contains("-encodedcommand")
            || cmdline.contains("-encoded ")
            || cmdline.contains("-enc ")
            || cmdline.contains("-e ")
    }

    fn has_powershell_launcher(cmdline: &str) -> bool {
        cmdline.contains("powershell.exe")
            || cmdline.contains("\\powershell ")
            || cmdline.contains("/powershell ")
            || cmdline.contains(" pwsh.exe")
            || cmdline.contains("\\pwsh ")
            || cmdline.contains("/pwsh ")
    }

    /// Simple DGA detection heuristic
    fn looks_like_dga(domain: &str) -> bool {
        let domain_lower = domain.trim_end_matches('.').to_ascii_lowercase();
        if Self::is_common_or_structured_domain(&domain_lower) {
            return false;
        }

        // Extract the main domain part (before TLD)
        let parts: Vec<&str> = domain_lower.split('.').collect();
        if parts.len() < 2 {
            return false;
        }

        // Score the registrable label instead of the first subdomain. CDN and
        // vendor hostnames often use consonant-heavy prefixes such as
        // spclient, world-gen, clients4, or blacklist that are not DGAs.
        let main_part = if parts.len() >= 2 {
            parts[parts.len().saturating_sub(2)]
        } else {
            parts[0]
        };

        // Skip if too short
        if main_part.len() < 12 {
            return false;
        }

        // Calculate consonant ratio
        let consonants = "bcdfghjklmnpqrstvwxyz";
        let vowels = "aeiou";

        let consonant_count = main_part
            .chars()
            .filter(|c| consonants.contains(c.to_ascii_lowercase()))
            .count();
        let vowel_count = main_part
            .chars()
            .filter(|c| vowels.contains(c.to_ascii_lowercase()))
            .count();

        let total_letters = consonant_count + vowel_count;
        if total_letters == 0 {
            return false;
        }

        let consonant_ratio = consonant_count as f64 / total_letters as f64;

        // High consonant ratio suggests random generation
        if consonant_ratio > 0.78 {
            return true;
        }

        // Check for digit patterns typical of DGA
        let digit_count = main_part.chars().filter(|c| c.is_ascii_digit()).count();
        let digit_ratio = digit_count as f64 / main_part.len() as f64;

        if digit_ratio > 0.35 && main_part.len() > 12 {
            return true;
        }

        false
    }

    fn is_common_or_structured_domain(domain: &str) -> bool {
        const TRUSTED_SUFFIXES: &[&str] = &[
            ".apple.com",
            ".aaplimg.com",
            ".icloud.com",
            ".google.com",
            ".gstatic.com",
            ".googleapis.com",
            ".amazon.com",
            ".amazonaws.com",
            ".aws.amazon.com",
            ".cloudfront.net",
            ".cloudflare.com",
            ".githubusercontent.com",
            ".github.com",
            ".mozilla.org",
            ".spotify.com",
            ".binance.com",
            ".tampermonkey.net",
            ".microsoft.com",
            ".office.com",
            ".windows.com",
        ];

        domain.starts_with("dns-server:")
            || TRUSTED_SUFFIXES
                .iter()
                .any(|suffix| domain == suffix.trim_start_matches('.') || domain.ends_with(suffix))
    }

    /// Get analysis statistics
    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.events_processed
                .load(std::sync::atomic::Ordering::Relaxed),
            self.detections_added
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Add IOCs to the database
    pub async fn add_iocs(&self, iocs: Vec<Ioc>) {
        for ioc in iocs {
            self.ioc_db.add_ioc(ioc).await;
        }
    }

    /// Replace the in-memory IOC set with values received from the backend.
    pub async fn replace_ioc_values(&self, values: &[serde_json::Value]) -> usize {
        let mut parsed = Vec::new();

        for value in values {
            if let Some(ioc) = ThreatIntelDb::parse_ioc_json(value) {
                parsed.push(ioc);
            } else {
                warn!(ioc = %value, "Skipping invalid IOC from backend update");
            }
        }

        let count = parsed.len();
        self.ioc_db.clear().await;
        self.ioc_db.add_iocs(parsed).await;
        info!(
            count = count,
            "Runtime IOC database replaced from backend update"
        );
        count
    }

    /// Get behavioral analyzer reference
    pub fn get_behavioral(&self) -> Arc<BehavioralAnalyzer> {
        self.behavioral.clone()
    }

    /// Check if behavioral analyzer is in learning mode
    pub async fn is_learning(&self) -> bool {
        self.behavioral.is_learning().await
    }

    /// Export behavioral risk score events if the feature + runtime flag are both enabled.
    /// Returns an empty Vec if either fence is off (the default).
    #[cfg(feature = "export_risk_score")]
    pub async fn export_risk_score_events(&self) -> Vec<TelemetryEvent> {
        self.behavioral.export_risk_score_events().await
    }

    /// No-op stub when the feature is not compiled in.
    #[cfg(not(feature = "export_risk_score"))]
    pub async fn export_risk_score_events(&self) -> Vec<TelemetryEvent> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dga_detection() {
        // Should detect as DGA
        assert!(AnalysisPipeline::looks_like_dga("xkjhgfdsaqwerty123.com"));
        assert!(AnalysisPipeline::looks_like_dga("bcdfghjklmnp12345.net"));

        // Should NOT detect as DGA
        assert!(!AnalysisPipeline::looks_like_dga("google.com"));
        assert!(!AnalysisPipeline::looks_like_dga("microsoft.com"));
        assert!(!AnalysisPipeline::looks_like_dga("amazon.com"));
    }
}
