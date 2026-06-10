//! Integrated Detection Module
//!
//! Combines all detection capabilities into a unified detection pipeline:
//! - Behavioral chain analysis
//! - Data staging detection
//! - ETW tampering detection
//! - Memory evasion detection
//!
//! This module orchestrates the various detection engines and correlates
//! their outputs for comprehensive threat detection.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use super::behavioral_chains::{
    BehavioralChainAnalyzer, BehavioralEventType, ChainAlert, TimestampedEvent,
};
use super::data_staging::{
    DataStagingDetector, FileAccessEvent, StagingDetection, StagingDetectionType,
};
use super::etw_tampering::{EtwTamperingDetection, EtwTamperingDetector};

/// Unified detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub detection_id: String,
    pub detection_type: DetectionType,
    pub severity: DetectionSeverity,
    pub confidence: f32,
    pub mitre_techniques: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub process_info: Option<ProcessInfo>,
    pub description: String,
    pub timestamp: u64,
    pub raw_data: serde_json::Value,
}

/// Type of detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionType {
    /// Multi-stage behavioral chain
    BehavioralChain,
    /// Data staging/exfiltration preparation
    DataStaging,
    /// ETW/AMSI tampering
    DefenseEvasion,
    /// Memory-based evasion
    MemoryEvasion,
    /// Process injection
    ProcessInjection,
    /// Credential access
    CredentialAccess,
    /// Lateral movement
    LateralMovement,
    /// Persistence mechanism
    Persistence,
    /// Combined/correlated detection
    Correlated,
}

/// Detection severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Process information for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub command_line: Option<String>,
}

/// Configuration for integrated detector
#[derive(Debug, Clone)]
pub struct IntegratedDetectorConfig {
    /// Enable behavioral chain detection
    pub enable_behavioral_chains: bool,
    /// Enable data staging detection
    pub enable_data_staging: bool,
    /// Enable ETW tampering detection
    pub enable_etw_detection: bool,
    /// Minimum confidence to report
    pub min_confidence: f32,
    /// Correlation window in milliseconds
    pub correlation_window_ms: u64,
}

impl Default for IntegratedDetectorConfig {
    fn default() -> Self {
        Self {
            enable_behavioral_chains: true,
            enable_data_staging: true,
            enable_etw_detection: true,
            min_confidence: 0.5,
            correlation_window_ms: 300_000, // 5 minutes
        }
    }
}

/// Integrated detection engine
pub struct IntegratedDetector {
    config: IntegratedDetectorConfig,
    behavioral_analyzer: BehavioralChainAnalyzer,
    staging_detector: DataStagingDetector,
    etw_detector: EtwTamperingDetector,
    detections: Arc<RwLock<Vec<DetectionEvent>>>,
}

impl IntegratedDetector {
    /// Create new integrated detector with default config
    pub fn new() -> Self {
        Self::with_config(IntegratedDetectorConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: IntegratedDetectorConfig) -> Self {
        Self {
            behavioral_analyzer: BehavioralChainAnalyzer::with_window(config.correlation_window_ms),
            staging_detector: DataStagingDetector::new(),
            etw_detector: EtwTamperingDetector::new(),
            detections: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// Process a process event for behavioral analysis
    pub fn process_behavioral_event(
        &self,
        pid: u32,
        parent_pid: u32,
        process_name: &str,
        event_type: BehavioralEventType,
        mitre_technique: Option<String>,
    ) {
        if !self.config.enable_behavioral_chains {
            return;
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let event = TimestampedEvent {
            timestamp,
            pid,
            parent_pid,
            process_name: process_name.to_string(),
            event_type,
            mitre_technique,
            context: std::collections::HashMap::new(),
        };

        self.behavioral_analyzer.add_event(event);

        // Check for high-severity chains
        self.check_behavioral_alerts();
    }

    /// Process a file access event for staging detection
    pub fn process_file_event(&self, event: FileAccessEvent) -> Vec<DetectionEvent> {
        if !self.config.enable_data_staging {
            return Vec::new();
        }

        let staging_detections = self.staging_detector.process_event(event);

        let mut results = Vec::new();
        for detection in staging_detections {
            if detection.confidence >= self.config.min_confidence {
                let event = self.convert_staging_detection(detection);
                self.store_detection(event.clone());
                results.push(event);
            }
        }

        results
    }

    /// Scan for ETW tampering in current process
    #[cfg(target_os = "windows")]
    pub fn scan_etw_tampering(&self) -> Vec<DetectionEvent> {
        if !self.config.enable_etw_detection {
            return Vec::new();
        }

        let etw_detections = self.etw_detector.scan_current_process();

        let mut results = Vec::new();
        for detection in etw_detections {
            if detection.confidence >= self.config.min_confidence {
                let event = self.convert_etw_detection(detection);
                self.store_detection(event.clone());
                results.push(event);
            }
        }

        results
    }

    /// Scan a specific process for ETW tampering
    #[cfg(target_os = "windows")]
    pub fn scan_process_etw(&self, pid: u32) -> Vec<DetectionEvent> {
        if !self.config.enable_etw_detection {
            return Vec::new();
        }

        let etw_detections = self.etw_detector.scan_process(pid);

        let mut results = Vec::new();
        for detection in etw_detections {
            if detection.confidence >= self.config.min_confidence {
                let event = self.convert_etw_detection(detection);
                self.store_detection(event.clone());
                results.push(event);
            }
        }

        results
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_etw_tampering(&self) -> Vec<DetectionEvent> {
        Vec::new()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_process_etw(&self, _pid: u32) -> Vec<DetectionEvent> {
        Vec::new()
    }

    /// Scan process for indirect syscall patterns (SysWhispers, Hell's Gate, etc.)
    ///
    /// This detects EDR evasion techniques that bypass usermode hooks by:
    /// - Using JMP to ntdll syscall stubs from non-ntdll memory
    /// - Executing mov r10, rcx + syscall sequences outside ntdll
    /// - Dynamic syscall number resolution (Hell's Gate, Halo's Gate)
    /// - Full syscall stub replication in private memory
    #[cfg(target_os = "windows")]
    pub async fn scan_indirect_syscalls(&self, pid: u32) -> Vec<DetectionEvent> {
        use crate::memory::indirect_syscall_detector::scan_for_indirect_syscalls;

        let detections = match scan_for_indirect_syscalls(pid).await {
            Ok(d) => d,
            Err(e) => {
                warn!(pid = pid, error = %e, "Failed to scan for indirect syscalls");
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        for detection in detections {
            if detection.confidence >= self.config.min_confidence {
                let event = self.convert_indirect_syscall_detection(detection);
                self.store_detection(event.clone());
                results.push(event);
            }
        }

        if !results.is_empty() {
            info!(
                pid = pid,
                detections = results.len(),
                "Indirect syscall evasion detected"
            );
        }

        results
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn scan_indirect_syscalls(&self, _pid: u32) -> Vec<DetectionEvent> {
        // Indirect syscalls are Windows-specific
        Vec::new()
    }

    /// Convert indirect syscall detection to unified event
    #[cfg(target_os = "windows")]
    fn convert_indirect_syscall_detection(
        &self,
        detection: crate::memory::indirect_syscall_detector::IndirectSyscallDetection,
    ) -> DetectionEvent {
        let severity = match detection.pattern_type.severity() {
            "critical" => DetectionSeverity::Critical,
            "high" => DetectionSeverity::High,
            "medium" => DetectionSeverity::Medium,
            _ => DetectionSeverity::Low,
        };

        DetectionEvent {
            detection_id: format!("indirect_syscall_{}", uuid::Uuid::new_v4()),
            detection_type: DetectionType::MemoryEvasion,
            severity,
            confidence: detection.confidence,
            mitre_techniques: vec![detection.mitre_id.to_string()],
            mitre_tactics: vec!["TA0005".to_string(), "TA0002".to_string()], // Defense Evasion, Execution
            process_info: Some(ProcessInfo {
                pid: detection.pid,
                name: detection.process_name.clone(),
                path: None,
                parent_pid: None,
                parent_name: None,
                command_line: None,
            }),
            description: detection.description,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            raw_data: serde_json::json!({
                "pattern_type": format!("{:?}", detection.pattern_type),
                "address": format!("0x{:X}", detection.address),
                "target_address": detection.target_address.map(|a| format!("0x{:X}", a)),
                "pattern_bytes": hex::encode(&detection.pattern_bytes),
                "evidence": detection.evidence,
            }),
        }
    }

    /// Check for behavioral chain alerts
    fn check_behavioral_alerts(&self) {
        let alerts = self.behavioral_analyzer.export_for_alert();

        for alert in alerts {
            if alert.confidence >= self.config.min_confidence {
                let event = self.convert_chain_alert(alert);
                self.store_detection(event);
            }
        }
    }

    /// Convert staging detection to unified event
    fn convert_staging_detection(&self, detection: StagingDetection) -> DetectionEvent {
        let severity = if detection.confidence >= 0.9 {
            DetectionSeverity::Critical
        } else if detection.confidence >= 0.7 {
            DetectionSeverity::High
        } else if detection.confidence >= 0.5 {
            DetectionSeverity::Medium
        } else {
            DetectionSeverity::Low
        };

        DetectionEvent {
            detection_id: format!("staging_{}", detection.detection_type.stable_id()),
            detection_type: DetectionType::DataStaging,
            severity,
            confidence: detection.confidence,
            mitre_techniques: vec![detection.mitre_technique],
            mitre_tactics: vec!["TA0009".to_string(), "TA0010".to_string()], // Collection, Exfiltration
            process_info: Some(ProcessInfo {
                pid: detection.pid,
                name: detection.process_name,
                path: None,
                parent_pid: None,
                parent_name: None,
                command_line: None,
            }),
            description: detection.description,
            timestamp: detection.timestamp,
            raw_data: serde_json::json!({
                "detection_type": format!("{:?}", detection.detection_type),
                "files_involved": detection.files_involved,
                "staging_location": detection.staging_location,
            }),
        }
    }

    /// Convert ETW detection to unified event
    fn convert_etw_detection(&self, detection: EtwTamperingDetection) -> DetectionEvent {
        let severity = if detection.confidence >= 0.9 {
            DetectionSeverity::Critical
        } else if detection.confidence >= 0.7 {
            DetectionSeverity::High
        } else {
            DetectionSeverity::Medium
        };

        DetectionEvent {
            detection_id: format!("etw_{}", uuid::Uuid::new_v4()),
            detection_type: DetectionType::DefenseEvasion,
            severity,
            confidence: detection.confidence,
            mitre_techniques: vec![detection.mitre_technique],
            mitre_tactics: vec!["TA0005".to_string()], // Defense Evasion
            process_info: None,
            description: detection.description,
            timestamp: detection.timestamp,
            raw_data: serde_json::json!({
                "detection_type": format!("{:?}", detection.detection_type),
                "details": detection.details,
            }),
        }
    }

    /// Convert behavioral chain alert to unified event
    fn convert_chain_alert(&self, alert: ChainAlert) -> DetectionEvent {
        let severity = match alert.severity {
            super::behavioral_chains::ChainSeverity::Critical => DetectionSeverity::Critical,
            super::behavioral_chains::ChainSeverity::High => DetectionSeverity::High,
            super::behavioral_chains::ChainSeverity::Medium => DetectionSeverity::Medium,
            super::behavioral_chains::ChainSeverity::Low => DetectionSeverity::Low,
        };

        DetectionEvent {
            detection_id: alert.chain_id,
            detection_type: DetectionType::BehavioralChain,
            severity,
            confidence: alert.confidence,
            mitre_techniques: alert.techniques,
            mitre_tactics: alert.tactics,
            process_info: None,
            description: alert.summary,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            raw_data: serde_json::json!({
                "pattern": alert.pattern,
                "process_count": alert.process_count,
                "event_count": alert.event_count,
                "duration_ms": alert.duration_ms,
            }),
        }
    }

    /// Store detection internally
    fn store_detection(&self, event: DetectionEvent) {
        let mut detections = self.detections.write();
        detections.push(event);

        // Keep last 1000 detections
        while detections.len() > 1000 {
            detections.remove(0);
        }
    }

    /// Get all recent detections
    pub fn get_detections(&self) -> Vec<DetectionEvent> {
        self.detections.read().clone()
    }

    /// Get detections filtered by severity
    pub fn get_detections_by_severity(
        &self,
        min_severity: DetectionSeverity,
    ) -> Vec<DetectionEvent> {
        self.detections
            .read()
            .iter()
            .filter(|d| d.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Get detections filtered by type
    pub fn get_detections_by_type(&self, detection_type: DetectionType) -> Vec<DetectionEvent> {
        self.detections
            .read()
            .iter()
            .filter(|d| d.detection_type == detection_type)
            .cloned()
            .collect()
    }

    /// Clear stored detections
    pub fn clear_detections(&self) {
        self.detections.write().clear();
    }

    /// Get behavioral analyzer reference
    pub fn behavioral_analyzer(&self) -> &BehavioralChainAnalyzer {
        &self.behavioral_analyzer
    }

    /// Get staging detector reference
    pub fn staging_detector(&self) -> &DataStagingDetector {
        &self.staging_detector
    }

    /// Get ETW detector reference
    pub fn etw_detector(&self) -> &EtwTamperingDetector {
        &self.etw_detector
    }
}

impl Default for IntegratedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StagingDetectionType {
    fn stable_id(&self) -> &'static str {
        match self {
            Self::BulkEnumeration => "bulk_enumeration",
            Self::HighValueFileCollection => "high_value_file_collection",
            Self::StagingDirectoryWrite => "staging_directory_write",
            Self::ArchiveCreation => "archive_creation",
            Self::CredentialStoreAccess => "credential_store_access",
            Self::DatabaseAccess => "database_access",
            Self::EmailStoreAccess => "email_store_access",
            Self::NetworkShareStaging => "network_share_staging",
            Self::RemovableMediaStaging => "removable_media_staging",
            Self::CrossDirectoryCollection => "cross_directory_collection",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::data_staging::FileAccessType;

    #[test]
    fn test_integrated_detector_creation() {
        let detector = IntegratedDetector::new();
        assert!(detector.get_detections().is_empty());
    }

    #[test]
    fn test_behavioral_event_processing() {
        let detector = IntegratedDetector::new();

        detector.process_behavioral_event(
            1234,
            1000,
            "test.exe",
            BehavioralEventType::ProcessEnumeration,
            Some("T1087".to_string()),
        );

        // Should have created a chain (even with single event)
        let chains = detector.behavioral_analyzer().get_chains();
        assert!(!chains.is_empty());
    }

    #[test]
    fn test_file_event_processing() {
        let detector = IntegratedDetector::new();

        // Simulate multiple file reads
        for i in 0..20 {
            let event = FileAccessEvent {
                timestamp: 1000 + i * 100,
                pid: 1234,
                process_name: "test.exe".to_string(),
                file_path: format!("C:\\Users\\test\\Documents\\document{}.docx", i),
                access_type: FileAccessType::Read,
                bytes_read: Some(10000),
                bytes_written: None,
            };
            detector.process_file_event(event);
        }

        // Should have staging detections
        let staging = detector.staging_detector().get_detections();
        assert!(!staging.is_empty());
    }

    #[test]
    fn test_severity_filtering() {
        let detector = IntegratedDetector::new();

        // Add a detection manually for testing
        let event = DetectionEvent {
            detection_id: "test_1".to_string(),
            detection_type: DetectionType::DataStaging,
            severity: DetectionSeverity::High,
            confidence: 0.85,
            mitre_techniques: vec!["T1005".to_string()],
            mitre_tactics: vec!["TA0009".to_string()],
            process_info: None,
            description: "Test detection".to_string(),
            timestamp: 1000,
            raw_data: serde_json::json!({}),
        };

        detector.store_detection(event);

        let high_severity = detector.get_detections_by_severity(DetectionSeverity::High);
        assert_eq!(high_severity.len(), 1);

        let critical_severity = detector.get_detections_by_severity(DetectionSeverity::Critical);
        assert!(critical_severity.is_empty());
    }
}
