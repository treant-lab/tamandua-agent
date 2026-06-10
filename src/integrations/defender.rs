//! Windows Defender Integration
//!
//! Provides integration with Windows Defender for:
//! - Reading Defender scan results via WMI and ETW
//! - Coordinating exclusions to avoid duplicate scanning
//! - Leveraging Defender's cloud reputation (MAPS)
//! - Subscribing to Defender threat events
//!
//! This allows Tamandua EDR to complement Defender rather than duplicate its work.
//!
//! ## Architecture
//!
//! ```text
//! +-----------------+     +------------------+     +------------------+
//! | Tamandua Agent  |<--->| Defender ETW     |<--->| Windows Defender |
//! |                 |     | Provider         |     | (MsMpEng.exe)    |
//! +-----------------+     +------------------+     +------------------+
//!         |                       |
//!         v                       v
//! +------------------+     +------------------+
//! | Exclusion        |     | Threat Intel     |
//! | Coordinator      |     | Sharing          |
//! +------------------+     +------------------+
//! ```
//!
//! ## ETW Providers
//!
//! - Microsoft-Windows-Windows Defender: Main Defender telemetry
//! - Microsoft-Antimalware-Scan-Interface: AMSI events
//! - Microsoft-Antimalware-Engine: Engine events
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1562.001 (Disable or Modify Tools) - Detect Defender tampering
//! - T1070 (Indicator Removal) - Detect Defender exclusion abuse

#![cfg(target_os = "windows")]
// Registry path, WMI namespace, and ETW provider constants for Windows
// Defender integration are retained as a complete reference table even when
// not currently read; suppress dead-code lint file-wide.
#![allow(dead_code)]

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use windows::core::HSTRING;
use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ};

/// Windows Defender ETW Provider GUIDs
mod defender_providers {
    use windows::core::GUID;

    /// Microsoft-Windows-Windows Defender
    /// Main Defender telemetry provider
    pub const WINDOWS_DEFENDER: GUID = GUID::from_u128(0x11cd958a_c507_4ef3_b3f2_5fd9dfbd2c78);

    /// Microsoft-Antimalware-Scan-Interface (AMSI)
    pub const AMSI: GUID = GUID::from_u128(0x2a576b87_09a7_520e_c21a_4942f0271d67);

    /// Microsoft-Antimalware-Engine
    pub const ANTIMALWARE_ENGINE: GUID = GUID::from_u128(0x0a002690_3839_4e3a_b3b6_96d8df868d99);

    /// Microsoft-Windows-Security-Auditing
    pub const SECURITY_AUDITING: GUID = GUID::from_u128(0x54849625_5478_4994_a5ba_3e3b0328c30d);
}

/// Defender event IDs
mod defender_event_ids {
    /// Malware detected
    pub const DETECTION: u16 = 1116;
    /// Malware action taken
    pub const ACTION_TAKEN: u16 = 1117;
    /// Scan started
    pub const SCAN_STARTED: u16 = 1000;
    /// Scan completed
    pub const SCAN_COMPLETED: u16 = 1001;
    /// Real-time protection event
    pub const REALTIME_DETECTION: u16 = 1006;
    /// Signature update
    pub const SIGNATURE_UPDATE: u16 = 2000;
    /// Cloud protection (MAPS) response
    pub const CLOUD_RESPONSE: u16 = 1150;
    /// Exclusion added
    pub const EXCLUSION_ADDED: u16 = 5007;
    /// Service state change
    pub const SERVICE_STATE: u16 = 5001;
    /// Engine state change
    pub const ENGINE_STATE: u16 = 5010;
    /// Behavior monitoring detection
    pub const BEHAVIOR_DETECTION: u16 = 1015;
    /// Exploit protection event
    pub const EXPLOIT_PROTECTION: u16 = 1121;
    /// Controlled folder access blocked
    pub const CFA_BLOCKED: u16 = 1123;
    /// Network protection blocked
    pub const NETWORK_BLOCKED: u16 = 1125;
    /// ASR rule triggered
    pub const ASR_TRIGGERED: u16 = 1121;
}

/// Configuration for Defender integration
#[derive(Debug, Clone)]
pub struct DefenderConfig {
    /// Enable ETW subscription to Defender events
    pub enable_etw: bool,
    /// Enable WMI querying for Defender status
    pub enable_wmi: bool,
    /// Coordinate exclusions with Defender
    pub coordinate_exclusions: bool,
    /// Trust Defender's cloud verdict for files it already scanned
    pub trust_cloud_verdict: bool,
    /// Monitor Defender exclusion changes
    pub monitor_exclusions: bool,
    /// ETW buffer size in KB
    pub etw_buffer_size_kb: u32,
}

impl Default for DefenderConfig {
    fn default() -> Self {
        Self {
            enable_etw: true,
            enable_wmi: true,
            coordinate_exclusions: true,
            trust_cloud_verdict: true,
            monitor_exclusions: true,
            etw_buffer_size_kb: 256,
        }
    }
}

/// Threat event from Windows Defender
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderThreatEvent {
    /// Threat ID
    pub threat_id: u64,
    /// Threat name (e.g., "Trojan:Win32/AgentTesla")
    pub threat_name: String,
    /// Threat severity (1=low, 2=medium, 4=high, 5=severe)
    pub severity: u32,
    /// Threat category (e.g., "Trojan", "Ransomware")
    pub category: String,
    /// Affected file path
    pub file_path: String,
    /// Process that triggered detection
    pub process_name: String,
    /// Process ID
    pub pid: u32,
    /// User account
    pub user: String,
    /// Action taken (e.g., "Quarantine", "Remove", "Allow")
    pub action_taken: String,
    /// Detection source (e.g., "Real-time", "Scan", "IOAV")
    pub detection_source: String,
    /// Cloud verdict (if available)
    pub cloud_verdict: Option<String>,
    /// SHA256 hash of the file
    pub sha256: Option<String>,
    /// Timestamp
    pub timestamp: u64,
    /// Additional properties
    pub properties: HashMap<String, String>,
}

impl DefenderThreatEvent {
    /// Convert to Tamandua severity
    pub fn to_severity(&self) -> Severity {
        match self.severity {
            5 => Severity::Critical,
            4 => Severity::High,
            2 => Severity::Medium,
            1 => Severity::Low,
            _ => Severity::Medium,
        }
    }

    /// Get MITRE technique based on category
    pub fn mitre_technique(&self) -> Option<&'static str> {
        let cat_lower = self.category.to_lowercase();
        match cat_lower.as_str() {
            "trojan" => Some("T1204"),
            "ransomware" => Some("T1486"),
            "backdoor" => Some("T1059"),
            "exploit" => Some("T1203"),
            "worm" => Some("T1091"),
            "adware" => Some("T1176"),
            "spyware" => Some("T1005"),
            "hacktool" => Some("S0552"),
            "pua" => None,
            _ => None,
        }
    }
}

/// Defender protection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderStatus {
    /// Real-time protection enabled
    pub realtime_protection: bool,
    /// Cloud protection (MAPS) enabled
    pub cloud_protection: bool,
    /// Behavior monitoring enabled
    pub behavior_monitoring: bool,
    /// IOAV protection enabled
    pub ioav_protection: bool,
    /// Tamper protection enabled
    pub tamper_protection: bool,
    /// Signature version
    pub signature_version: String,
    /// Engine version
    pub engine_version: String,
    /// Last scan time
    pub last_scan_time: Option<u64>,
    /// Exclusion paths
    pub exclusion_paths: Vec<String>,
    /// Exclusion processes
    pub exclusion_processes: Vec<String>,
    /// Exclusion extensions
    pub exclusion_extensions: Vec<String>,
}

/// Defender integration statistics
#[derive(Debug, Default)]
pub struct DefenderStats {
    /// Threats detected via ETW
    pub threats_detected: AtomicU64,
    /// Cloud verdicts received
    pub cloud_verdicts: AtomicU64,
    /// Exclusions monitored
    pub exclusion_events: AtomicU64,
    /// Files skipped (already scanned by Defender)
    pub files_deduped: AtomicU64,
    /// ETW events processed
    pub etw_events: AtomicU64,
}

/// Main Defender integration handler
pub struct DefenderIntegration {
    config: DefenderConfig,
    event_tx: mpsc::Sender<TelemetryEvent>,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    running: Arc<AtomicBool>,
    stats: Arc<DefenderStats>,
    /// Files recently scanned by Defender (hash -> verdict)
    defender_cache: Arc<RwLock<HashMap<String, (bool, Instant)>>>,
    /// Current Defender exclusions
    exclusions: Arc<RwLock<DefenderExclusions>>,
    /// ETW session handle
    etw_handle: Option<u64>,
}

/// Defender exclusion configuration
#[derive(Debug, Clone, Default)]
pub struct DefenderExclusions {
    pub paths: HashSet<String>,
    pub processes: HashSet<String>,
    pub extensions: HashSet<String>,
    pub last_updated: Option<Instant>,
}

impl DefenderIntegration {
    /// Create new Defender integration
    pub fn new(config: DefenderConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);

        Ok(Self {
            config,
            event_tx: tx,
            event_rx: rx,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(DefenderStats::default()),
            defender_cache: Arc::new(RwLock::new(HashMap::new())),
            exclusions: Arc::new(RwLock::new(DefenderExclusions::default())),
            etw_handle: None,
        })
    }

    /// Start the Defender integration
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Windows Defender integration");

        self.running.store(true, Ordering::SeqCst);

        // Check if Defender is available
        if !Self::is_defender_available() {
            warn!("Windows Defender not available or disabled");
            return Ok(());
        }

        // Load current exclusions
        self.load_exclusions()?;

        // Start ETW subscription
        if self.config.enable_etw {
            let tx = self.event_tx.clone();
            let running = self.running.clone();
            let stats = self.stats.clone();
            let cache = self.defender_cache.clone();
            let exclusions = self.exclusions.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::run_etw_listener(tx, running, stats, cache, exclusions).await
                {
                    error!(error = %e, "Defender ETW listener error");
                }
            });
        }

        // Start exclusion monitor
        if self.config.monitor_exclusions {
            let tx = self.event_tx.clone();
            let running = self.running.clone();
            let exclusions = self.exclusions.clone();

            tokio::spawn(async move {
                Self::monitor_exclusion_changes(tx, running, exclusions).await;
            });
        }

        // Start periodic status check
        if self.config.enable_wmi {
            let tx = self.event_tx.clone();
            let running = self.running.clone();

            tokio::spawn(async move {
                Self::periodic_status_check(tx, running).await;
            });
        }

        info!("Windows Defender integration started");
        Ok(())
    }

    /// Stop the integration
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        // Stop ETW session if running
        if let Some(handle) = self.etw_handle.take() {
            unsafe {
                // Stop the ETW session
                let _ = Self::stop_etw_session(handle);
            }
        }
    }

    /// Get next event from Defender
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Check if a file path is excluded by Defender
    pub fn is_excluded(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        let exclusions = self.exclusions.read().unwrap_or_else(|e| e.into_inner());

        // Check path exclusions
        for excl in &exclusions.paths {
            if path_lower.starts_with(&excl.to_lowercase()) {
                return true;
            }
        }

        // Check extension exclusions
        for ext in &exclusions.extensions {
            if path_lower.ends_with(&format!(".{}", ext.to_lowercase())) {
                return true;
            }
        }

        false
    }

    /// Check if a process is excluded by Defender
    pub fn is_process_excluded(&self, process_name: &str) -> bool {
        let exclusions = self.exclusions.read().unwrap_or_else(|e| e.into_inner());
        exclusions.processes.contains(&process_name.to_lowercase())
    }

    /// Check if file was recently scanned by Defender (avoid duplicate work)
    pub fn was_scanned_by_defender(&self, sha256: &str) -> Option<bool> {
        let cache = self
            .defender_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((is_clean, timestamp)) = cache.get(sha256) {
            // Cache valid for 5 minutes
            if timestamp.elapsed() < Duration::from_secs(300) {
                self.stats.files_deduped.fetch_add(1, Ordering::Relaxed);
                return Some(*is_clean);
            }
        }
        None
    }

    /// Get current Defender status
    pub fn get_status(&self) -> Result<DefenderStatus> {
        Self::query_defender_status()
    }

    /// Get integration statistics
    pub fn get_stats(&self) -> &DefenderStats {
        &self.stats
    }

    // ========================================================================
    // Private Implementation
    // ========================================================================

    /// Check if Defender is available
    fn is_defender_available() -> bool {
        unsafe {
            let key_path = HSTRING::from("SOFTWARE\\Microsoft\\Windows Defender");

            let mut key_handle: windows::Win32::System::Registry::HKEY =
                windows::Win32::System::Registry::HKEY::default();

            let result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, &key_path, 0, KEY_READ, &mut key_handle);

            if result.is_ok() {
                let _ = windows::Win32::System::Registry::RegCloseKey(key_handle);
                true
            } else {
                false
            }
        }
    }

    /// Load current Defender exclusions from registry
    fn load_exclusions(&self) -> Result<()> {
        let mut exclusions = self.exclusions.write().unwrap_or_else(|e| e.into_inner());

        // Load from registry
        let paths = Self::read_registry_multi_string(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        )?;

        let processes = Self::read_registry_multi_string(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        )?;

        let extensions = Self::read_registry_multi_string(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
        )?;

        exclusions.paths = paths.into_iter().map(|s| s.to_lowercase()).collect();
        exclusions.processes = processes.into_iter().map(|s| s.to_lowercase()).collect();
        exclusions.extensions = extensions.into_iter().map(|s| s.to_lowercase()).collect();
        exclusions.last_updated = Some(Instant::now());

        info!(
            paths = exclusions.paths.len(),
            processes = exclusions.processes.len(),
            extensions = exclusions.extensions.len(),
            "Loaded Defender exclusions"
        );

        Ok(())
    }

    /// Read multi-string values from registry
    fn read_registry_multi_string(key_path: &str) -> Result<Vec<String>> {
        let mut results = Vec::new();

        unsafe {
            let key_path_hstring = HSTRING::from(key_path);
            let mut key_handle: windows::Win32::System::Registry::HKEY =
                windows::Win32::System::Registry::HKEY::default();

            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                &key_path_hstring,
                0,
                KEY_READ,
                &mut key_handle,
            );

            if result.is_err() {
                return Ok(results);
            }

            // Enumerate values
            let mut index = 0u32;
            let mut value_name = vec![0u16; 256];
            let mut value_name_len;

            loop {
                value_name_len = 256;
                let enum_result = windows::Win32::System::Registry::RegEnumValueW(
                    key_handle,
                    index,
                    windows::core::PWSTR::from_raw(value_name.as_mut_ptr()),
                    &mut value_name_len,
                    None,
                    None,
                    None,
                    None,
                );

                if enum_result.is_err() {
                    break;
                }

                // Extract the value name (which is the exclusion path/process/extension)
                let name = String::from_utf16_lossy(&value_name[..value_name_len as usize]);
                if !name.is_empty() {
                    results.push(name);
                }

                index += 1;
            }

            let _ = windows::Win32::System::Registry::RegCloseKey(key_handle);
        }

        Ok(results)
    }

    /// Query Defender status via WMI
    fn query_defender_status() -> Result<DefenderStatus> {
        // Use PowerShell to query Defender status (more reliable than direct WMI)
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-MpComputerStatus | ConvertTo-Json -Depth 2",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to query Defender status"));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);

        // Parse JSON response
        let status: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| anyhow!("Failed to parse Defender status: {}", e))?;

        Ok(DefenderStatus {
            realtime_protection: status["RealTimeProtectionEnabled"]
                .as_bool()
                .unwrap_or(false),
            cloud_protection: status["IsTamperProtected"].as_bool().unwrap_or(false),
            behavior_monitoring: status["BehaviorMonitorEnabled"].as_bool().unwrap_or(false),
            ioav_protection: status["IoavProtectionEnabled"].as_bool().unwrap_or(false),
            tamper_protection: status["IsTamperProtected"].as_bool().unwrap_or(false),
            signature_version: status["AntivirusSignatureVersion"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            engine_version: status["AMEngineVersion"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            last_scan_time: None,
            exclusion_paths: Vec::new(),
            exclusion_processes: Vec::new(),
            exclusion_extensions: Vec::new(),
        })
    }

    /// Run ETW listener for Defender events
    async fn run_etw_listener(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        stats: Arc<DefenderStats>,
        cache: Arc<RwLock<HashMap<String, (bool, Instant)>>>,
        _exclusions: Arc<RwLock<DefenderExclusions>>,
    ) -> Result<()> {
        info!("Starting Defender ETW listener");

        // For simplicity, we'll use Event Log subscription instead of raw ETW
        // (Event Log is more reliable for security events)
        let rt = tokio::runtime::Handle::current();

        std::thread::spawn(move || {
            Self::event_log_monitor(tx, running, stats, cache, rt);
        });

        Ok(())
    }

    /// Monitor Windows Event Log for Defender events
    fn event_log_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        stats: Arc<DefenderStats>,
        cache: Arc<RwLock<HashMap<String, (bool, Instant)>>>,
        rt: tokio::runtime::Handle,
    ) {
        use windows::Win32::System::EventLog::{EvtClose, EvtNext, EvtSubscribe, EVT_HANDLE};

        // Subscribe to Windows Defender event channel
        let channel = HSTRING::from("Microsoft-Windows-Windows Defender/Operational");

        unsafe {
            let query = HSTRING::from("*[System[(EventID=1116 or EventID=1117 or EventID=1006 or EventID=5007 or EventID=1150)]]");

            // EvtSubscribeStartAtOldestRecord = 2
            let subscription = match EvtSubscribe(
                None, None, &channel, &query, None, None, None,
                2u32, // EvtSubscribeStartAtOldestRecord
            ) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "Failed to subscribe to Defender events");
                    return;
                }
            };

            let mut events: [isize; 10] = [0; 10];

            while running.load(Ordering::SeqCst) {
                let mut returned = 0u32;

                let result = EvtNext(
                    subscription,
                    &mut events,
                    1000, // 1 second timeout
                    0,
                    &mut returned,
                );

                if result.is_ok() && returned > 0 {
                    for i in 0..returned as usize {
                        let evt_handle = EVT_HANDLE(events[i] as isize);
                        if let Some(event) = Self::parse_defender_event(evt_handle) {
                            stats.etw_events.fetch_add(1, Ordering::Relaxed);

                            // Update cache if we got a verdict
                            if let Some(ref sha256) = event.sha256 {
                                match cache.write() {
                                    Ok(mut cache) => {
                                        let is_clean = event.action_taken == "Allow";
                                        cache.insert(sha256.clone(), (is_clean, Instant::now()));
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Defender verdict cache lock poisoned; skipping cache update");
                                    }
                                }
                            }

                            // Convert to TelemetryEvent
                            let telemetry_event = Self::defender_event_to_telemetry(&event);

                            // Send via runtime
                            let tx_clone = tx.clone();
                            rt.spawn(async move {
                                let _ = tx_clone.send(telemetry_event).await;
                            });

                            stats.threats_detected.fetch_add(1, Ordering::Relaxed);
                        }

                        let _ = EvtClose(evt_handle);
                    }
                }

                std::thread::sleep(Duration::from_millis(100));
            }

            let _ = EvtClose(subscription);
        }
    }

    /// Parse a Defender event from Event Log
    fn parse_defender_event(
        _event_handle: windows::Win32::System::EventLog::EVT_HANDLE,
    ) -> Option<DefenderThreatEvent> {
        // Simplified parsing - in production use EvtRender
        Some(DefenderThreatEvent {
            threat_id: 0,
            threat_name: "Unknown".to_string(),
            severity: 2,
            category: "Unknown".to_string(),
            file_path: String::new(),
            process_name: String::new(),
            pid: 0,
            user: String::new(),
            action_taken: "Unknown".to_string(),
            detection_source: "Defender".to_string(),
            cloud_verdict: None,
            sha256: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            properties: HashMap::new(),
        })
    }

    /// Convert Defender event to Tamandua telemetry event
    fn defender_event_to_telemetry(defender_event: &DefenderThreatEvent) -> TelemetryEvent {
        let severity = defender_event.to_severity();

        let mut event = TelemetryEvent::new(
            EventType::MalwareDetection,
            severity,
            EventPayload::DefenderThreat(defender_event.clone()),
        );

        // Add detection
        let detection = Detection {
            detection_type: DetectionType::Malware,
            rule_name: format!("DEFENDER_{}", defender_event.threat_name.replace(":", "_")),
            confidence: 0.95,
            description: format!(
                "Windows Defender detected: {} ({})",
                defender_event.threat_name, defender_event.category
            ),
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: defender_event
                .mitre_technique()
                .map(|t| vec![t.to_string()])
                .unwrap_or_default(),
        };

        event.add_detection(detection);

        // Add metadata
        event.metadata.insert(
            "defender_action".to_string(),
            defender_event.action_taken.clone(),
        );
        event.metadata.insert(
            "detection_source".to_string(),
            defender_event.detection_source.clone(),
        );

        if let Some(ref sha256) = defender_event.sha256 {
            event.metadata.insert("sha256".to_string(), sha256.clone());
        }

        event
    }

    /// Monitor exclusion changes
    async fn monitor_exclusion_changes(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        exclusions: Arc<RwLock<DefenderExclusions>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut previous_exclusions: Option<DefenderExclusions> = None;

        while running.load(Ordering::SeqCst) {
            interval.tick().await;

            // Load current exclusions
            let current = match Self::load_exclusions_static() {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Compare with previous
            if let Some(ref prev) = previous_exclusions {
                // Check for new paths
                for path in current.paths.difference(&prev.paths) {
                    warn!(path = %path, "New Defender exclusion path detected");

                    let event =
                        Self::create_exclusion_event("path", path, "Defender exclusion path added");
                    let _ = tx.send(event).await;
                }

                // Check for new processes
                for proc in current.processes.difference(&prev.processes) {
                    warn!(process = %proc, "New Defender exclusion process detected");

                    let event = Self::create_exclusion_event(
                        "process",
                        proc,
                        "Defender exclusion process added",
                    );
                    let _ = tx.send(event).await;
                }
            }

            // Update shared state
            match exclusions.write() {
                Ok(mut excl) => *excl = current.clone(),
                Err(e) => {
                    error!(error = %e, "Defender exclusions lock poisoned; stopping monitor");
                    break;
                }
            }

            previous_exclusions = Some(current);
        }
    }

    /// Load exclusions (static method)
    fn load_exclusions_static() -> Result<DefenderExclusions> {
        let paths = Self::read_registry_multi_string(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        )?;

        let processes = Self::read_registry_multi_string(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        )?;

        let extensions = Self::read_registry_multi_string(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
        )?;

        Ok(DefenderExclusions {
            paths: paths.into_iter().map(|s| s.to_lowercase()).collect(),
            processes: processes.into_iter().map(|s| s.to_lowercase()).collect(),
            extensions: extensions.into_iter().map(|s| s.to_lowercase()).collect(),
            last_updated: Some(Instant::now()),
        })
    }

    /// Create exclusion change event
    fn create_exclusion_event(
        exclusion_type: &str,
        value: &str,
        description: &str,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::DefenseEvasion,
            Severity::High,
            EventPayload::Generic(serde_json::json!({
                "type": "defender_exclusion",
                "exclusion_type": exclusion_type,
                "value": value,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: "DEFENDER_EXCLUSION_ADDED".to_string(),
            confidence: 0.85,
            description: description.to_string(),
            mitre_tactics: vec!["defense-evasion".to_string()],
            mitre_techniques: vec!["T1562.001".to_string()],
        });

        event
            .metadata
            .insert("exclusion_type".to_string(), exclusion_type.to_string());
        event
            .metadata
            .insert("exclusion_value".to_string(), value.to_string());

        event
    }

    /// Periodic Defender status check
    async fn periodic_status_check(tx: mpsc::Sender<TelemetryEvent>, running: Arc<AtomicBool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let mut previous_status: Option<DefenderStatus> = None;

        while running.load(Ordering::SeqCst) {
            interval.tick().await;

            match Self::query_defender_status() {
                Ok(status) => {
                    // Check for protection status changes
                    if let Some(ref prev) = previous_status {
                        if prev.realtime_protection && !status.realtime_protection {
                            warn!("Defender real-time protection disabled!");

                            let event = Self::create_protection_change_event(
                                "realtime_protection",
                                true,
                                false,
                            );
                            let _ = tx.send(event).await;
                        }

                        if prev.tamper_protection && !status.tamper_protection {
                            warn!("Defender tamper protection disabled!");

                            let event = Self::create_protection_change_event(
                                "tamper_protection",
                                true,
                                false,
                            );
                            let _ = tx.send(event).await;
                        }
                    }

                    previous_status = Some(status);
                }
                Err(e) => {
                    debug!(error = %e, "Failed to query Defender status");
                }
            }
        }
    }

    /// Create protection status change event
    fn create_protection_change_event(
        protection_type: &str,
        was_enabled: bool,
        is_enabled: bool,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::SecurityToolTamper,
            Severity::Critical,
            EventPayload::Generic(serde_json::json!({
                "type": "defender_protection_change",
                "protection_type": protection_type,
                "was_enabled": was_enabled,
                "is_enabled": is_enabled,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("DEFENDER_{}_DISABLED", protection_type.to_uppercase()),
            confidence: 0.95,
            description: format!("Windows Defender {} was disabled", protection_type),
            mitre_tactics: vec!["defense-evasion".to_string()],
            mitre_techniques: vec!["T1562.001".to_string()],
        });

        event
    }

    /// Stop ETW session
    unsafe fn stop_etw_session(_handle: u64) -> Result<()> {
        // ETW cleanup would go here
        Ok(())
    }
}

impl Drop for DefenderIntegration {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_severity_conversion() {
        let event = DefenderThreatEvent {
            threat_id: 1,
            threat_name: "Test".to_string(),
            severity: 5,
            category: "Trojan".to_string(),
            file_path: String::new(),
            process_name: String::new(),
            pid: 0,
            user: String::new(),
            action_taken: "Quarantine".to_string(),
            detection_source: "Real-time".to_string(),
            cloud_verdict: None,
            sha256: None,
            timestamp: 0,
            properties: HashMap::new(),
        };

        assert!(matches!(event.to_severity(), Severity::Critical));
    }

    #[test]
    fn test_mitre_mapping() {
        let event = DefenderThreatEvent {
            threat_id: 1,
            threat_name: "Test".to_string(),
            severity: 5,
            category: "Ransomware".to_string(),
            file_path: String::new(),
            process_name: String::new(),
            pid: 0,
            user: String::new(),
            action_taken: "Quarantine".to_string(),
            detection_source: "Real-time".to_string(),
            cloud_verdict: None,
            sha256: None,
            timestamp: 0,
            properties: HashMap::new(),
        };

        assert_eq!(event.mitre_technique(), Some("T1486"));
    }

    #[test]
    fn test_config_defaults() {
        let config = DefenderConfig::default();
        assert!(config.enable_etw);
        assert!(config.enable_wmi);
        assert!(config.coordinate_exclusions);
    }
}
