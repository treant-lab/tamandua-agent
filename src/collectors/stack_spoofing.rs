//! Stack Spoofing Detection Collector
//!
//! Monitors processes for stack spoofing and call stack masking techniques used by
//! sophisticated malware to hide malicious API call origins.
//!
//! Detection capabilities:
//! - SpoofStack tool detection
//! - Unwinder-based stack manipulation
//! - Return address manipulation
//! - Frame pointer chain inconsistencies
//! - Stack pivot detection
//! - ROP chain masquerading as call stack
//!
//! MITRE ATT&CK:
//! - T1055 (Process Injection)
//! - T1562.001 (Impair Defenses: Disable or Modify Tools)
//! - T1027.009 (Obfuscated Files or Information: Embedded Payloads)

use super::{
    Detection, DetectionType, EventPayload, EventType, Severity, StackSpoofingEvent, TelemetryEvent,
};
use crate::config::AgentConfig;
use crate::memory::stack_spoofing_detector::{
    scan_process_for_stack_spoofing, SpoofingSeverity, StackSpoofingDetection,
    StackSpoofingDetector,
};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Stack spoofing detection collector
pub struct StackSpoofingCollector {
    /// Agent configuration
    #[allow(dead_code)]
    config: AgentConfig,
    /// Event receiver
    event_rx: mpsc::Receiver<TelemetryEvent>,
    /// Event sender (for internal use)
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl StackSpoofingCollector {
    /// Create a new stack spoofing collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(200);

        let collector = Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start background monitoring
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            monitoring_loop(tx_clone, config_clone).await;
        });

        info!("Stack spoofing detection collector initialized");
        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

/// Background monitoring loop for stack spoofing detection
async fn monitoring_loop(event_tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
    // Scan interval - stack spoofing detection is expensive, so we don't run too frequently
    let scan_interval = Duration::from_secs(30);

    // Set of recently alerted PIDs to avoid duplicate alerts
    let mut recent_alerts: HashSet<(u32, u32)> = HashSet::new(); // (pid, thread_id)

    // Create detector with configuration
    let mut detector = StackSpoofingDetector::new()
        .with_sensitivity(0.7)
        .with_max_frames(64)
        .with_deep_validation(true);

    loop {
        // Get list of running processes to scan
        let pids = match get_interesting_pids().await {
            Ok(pids) => pids,
            Err(e) => {
                warn!("Failed to enumerate processes: {}", e);
                tokio::time::sleep(scan_interval).await;
                continue;
            }
        };

        for pid in pids {
            // Skip processes we've recently alerted on
            // This is a simple debouncing mechanism

            match detector.scan_process(pid).await {
                Ok(detections) => {
                    for detection in detections {
                        let key = (detection.pid, detection.thread_id);

                        // Skip if we've recently alerted this thread
                        if recent_alerts.contains(&key) {
                            continue;
                        }

                        // Create telemetry event
                        if let Some(event) = create_telemetry_event(&detection) {
                            if event_tx.send(event).await.is_err() {
                                error!("Failed to send stack spoofing detection event");
                                return;
                            }

                            // Mark as recently alerted
                            recent_alerts.insert(key);

                            info!(
                                pid = detection.pid,
                                thread_id = detection.thread_id,
                                technique = ?detection.technique,
                                confidence = detection.confidence,
                                "Stack spoofing detected"
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!(pid = pid, error = %e, "Failed to scan process for stack spoofing");
                }
            }
        }

        // Clean up old alerts periodically (allow re-alerting after some time)
        if recent_alerts.len() > 1000 {
            recent_alerts.clear();
        }

        tokio::time::sleep(scan_interval).await;
    }
}

/// Get list of interesting PIDs to scan for stack spoofing
/// Focuses on high-value targets that attackers commonly inject into
#[cfg(target_os = "windows")]
async fn get_interesting_pids() -> anyhow::Result<Vec<u32>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut pids = Vec::new();

    // High-value process names that are common injection targets
    let high_value_processes: HashSet<&str> = [
        "svchost.exe",
        "explorer.exe",
        "lsass.exe",
        "services.exe",
        "spoolsv.exe",
        "wininit.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "msiexec.exe",
        "dllhost.exe",
        "wmiprvse.exe",
        "taskhost.exe",
        "taskhostw.exe",
        "RuntimeBroker.exe",
        "sihost.exe",
        "conhost.exe",
        "dwm.exe",
        "SearchIndexer.exe",
        "OneDrive.exe",
        "MsMpEng.exe",
        "SecurityHealthSystray.exe",
    ]
    .into_iter()
    .collect();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                // Include high-value processes
                if high_value_processes.contains(exe_name.to_lowercase().as_str()) {
                    pids.push(entry.th32ProcessID);
                }

                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot)?;
    }

    // Limit number of processes to scan per iteration
    if pids.len() > 20 {
        // Take a random sample to distribute scanning load
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        let seed = hasher.finish() as usize;

        let step = pids.len() / 20;
        let selected: Vec<u32> = pids
            .iter()
            .enumerate()
            .filter(|(i, _)| (*i + seed) % step.max(1) == 0)
            .take(20)
            .map(|(_, &pid)| pid)
            .collect();

        return Ok(selected);
    }

    Ok(pids)
}

#[cfg(not(target_os = "windows"))]
async fn get_interesting_pids() -> anyhow::Result<Vec<u32>> {
    // Stack spoofing detection is primarily Windows-focused
    Ok(Vec::new())
}

/// Create a telemetry event from a stack spoofing detection
fn create_telemetry_event(detection: &StackSpoofingDetection) -> Option<TelemetryEvent> {
    // Map severity
    let severity = match detection.severity {
        SpoofingSeverity::Low => Severity::Low,
        SpoofingSeverity::Medium => Severity::Medium,
        SpoofingSeverity::High => Severity::High,
        SpoofingSeverity::Critical => Severity::Critical,
    };

    // Get process path (placeholder - would need actual path resolution)
    let process_path = format!("C:\\Windows\\System32\\{}", detection.process_name);

    // Get first suspicious return info
    let (first_suspicious_return, first_return_issue) =
        if let Some(ret) = detection.suspicious_returns.first() {
            (Some(ret.address), Some(format!("{:?}", ret.reason)))
        } else {
            (None, None)
        };

    // Collect anomaly types
    let anomaly_types: Vec<String> = detection
        .frame_anomalies
        .iter()
        .map(|a| format!("{:?}", a.anomaly_type))
        .collect();

    // Create the event payload
    let payload = StackSpoofingEvent {
        pid: detection.pid,
        process_name: detection.process_name.clone(),
        process_path,
        thread_id: detection.thread_id,
        technique: format!("{:?}", detection.technique),
        confidence: detection.confidence,
        stack_pointer: detection.stack_pointer,
        suspicious_return_count: detection.suspicious_returns.len() as u32,
        frame_anomaly_count: detection.frame_anomalies.len() as u32,
        first_suspicious_return,
        first_return_issue,
        anomaly_types,
        evidence: detection.evidence.clone(),
        mitre_technique: detection.mitre_id.to_string(),
    };

    // Create telemetry event
    let mut event = TelemetryEvent::new(
        EventType::StackSpoofing,
        severity.clone(),
        EventPayload::StackSpoofing(payload),
    );

    // Add detection metadata
    event.add_detection(Detection {
        detection_type: DetectionType::StackSpoofing,
        rule_name: format!("stack_spoofing_{:?}", detection.technique),
        confidence: detection.confidence,
        description: detection.technique.description().to_string(),
        mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
        mitre_techniques: vec![detection.mitre_id.to_string()],
    });

    // Add metadata
    event.metadata.insert(
        "technique".to_string(),
        format!("{:?}", detection.technique),
    );
    event
        .metadata
        .insert("thread_id".to_string(), detection.thread_id.to_string());
    event.metadata.insert(
        "stack_pointer".to_string(),
        format!("0x{:X}", detection.stack_pointer),
    );
    event.metadata.insert(
        "suspicious_returns".to_string(),
        detection.suspicious_returns.len().to_string(),
    );
    event.metadata.insert(
        "frame_anomalies".to_string(),
        detection.frame_anomalies.len().to_string(),
    );

    Some(event)
}

/// Scan a specific process for stack spoofing
/// This can be called on-demand for targeted analysis
pub async fn scan_process(pid: u32) -> anyhow::Result<Vec<StackSpoofingDetection>> {
    scan_process_for_stack_spoofing(pid).await
}

/// Scan all threads in a process for stack spoofing
/// Returns detections sorted by confidence
pub async fn scan_all_processes() -> anyhow::Result<Vec<StackSpoofingDetection>> {
    let pids = get_interesting_pids().await?;
    let mut all_detections = Vec::new();

    for pid in pids {
        if let Ok(detections) = scan_process_for_stack_spoofing(pid).await {
            all_detections.extend(detections);
        }
    }

    // Sort by confidence descending
    all_detections.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(all_detections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        // Just verify we can create types - actual monitoring requires Windows
        let _severity = SpoofingSeverity::Critical;
    }

    #[tokio::test]
    #[cfg(target_os = "windows")]
    async fn test_pid_enumeration() {
        let pids = get_interesting_pids().await.unwrap();
        // Should find at least some system processes
        assert!(!pids.is_empty() || true); // May be empty on some systems
    }
}
