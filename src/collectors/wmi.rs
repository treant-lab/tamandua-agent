//! WMI (Windows Management Instrumentation) Monitoring Collector
//!
//! Monitors WMI for suspicious activity that indicates:
//! - Persistence mechanisms (Event Subscriptions)
//! - Lateral movement (Remote WMI execution)
//! - Reconnaissance (WMI queries for system information)
//! - Code execution (Win32_Process.Create)
//!
//! WMI is heavily abused for persistence (T1546.003) and lateral movement (T1047).
//!
//! Known Attack Patterns Detected:
//! - APT29 WMI persistence
//! - POSHSPY WMI backdoor
//! - WMIGhost
//! - WMImplant
//! - Cobalt Strike WMI execution
//!
//! MITRE ATT&CK Coverage:
//! - T1546.003 (Event Triggered Execution: WMI Event Subscription)
//! - T1047 (Windows Management Instrumentation)
//! - T1059.001 (Command and Scripting Interpreter: PowerShell)

#![cfg(target_os = "windows")]
// This collector enumerates WMI namespaces, suspicious query patterns and
// known APT/Cobalt-Strike WMI persistence signatures. Reserved tracker
// fields are kept exhaustive for downstream correlation even when not yet
// dispatched.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent, WmiEvent,
};
use crate::config::AgentConfig;
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use windows::core::PCWSTR;

/// Known malicious WMI subscription names and patterns
const KNOWN_MALICIOUS_PATTERNS: &[(&str, &str, &str)] = &[
    // APT29 / Cozy Bear patterns
    ("SystemCoreService", "APT29", "APT29 WMI persistence"),
    (
        "SystemPowerManager",
        "APT29",
        "APT29 WMI persistence variant",
    ),
    ("BVTFilter", "APT29", "APT29 WMI persistence indicator"),
    // POSHSPY patterns
    ("POSHSPY", "POSHSPY", "POSHSPY WMI backdoor"),
    ("SystemPerformance", "POSHSPY", "POSHSPY backdoor variant"),
    // WMIGhost patterns
    ("WMIGhost", "WMIGhost", "WMIGhost malware"),
    ("GhostSpec", "WMIGhost", "WMIGhost persistence"),
    // WMImplant patterns
    ("WMImplant", "WMImplant", "WMImplant C2 framework"),
    // Generic malicious patterns
    ("SCM Event Log", "Generic", "Suspicious WMI persistence"),
    ("DSCTimer", "Generic", "Suspicious WMI timer subscription"),
    ("LogFileEvent", "Generic", "Suspicious log file monitoring"),
];

/// Suspicious WMI query patterns for reconnaissance
const RECON_QUERY_PATTERNS: &[(&str, &str, &str)] = &[
    ("Win32_Process", "T1057", "Process Discovery"),
    (
        "Win32_ComputerSystem",
        "T1082",
        "System Information Discovery",
    ),
    (
        "Win32_OperatingSystem",
        "T1082",
        "System Information Discovery",
    ),
    (
        "Win32_NetworkAdapterConfiguration",
        "T1016",
        "System Network Configuration Discovery",
    ),
    ("Win32_UserAccount", "T1087", "Account Discovery"),
    ("Win32_Group", "T1069", "Permission Groups Discovery"),
    ("Win32_Service", "T1007", "System Service Discovery"),
    ("Win32_Share", "T1135", "Network Share Discovery"),
    ("Win32_LoggedOnUser", "T1087", "Account Discovery"),
    ("Win32_Product", "T1518", "Software Discovery"),
    (
        "AntiVirusProduct",
        "T1518.001",
        "Security Software Discovery",
    ),
    (
        "FirewallProduct",
        "T1518.001",
        "Security Software Discovery",
    ),
    ("Win32_ShadowCopy", "T1490", "Shadow Copy Discovery"),
    ("Win32_BIOS", "T1082", "System Information Discovery"),
    ("Win32_DiskDrive", "T1082", "Hardware Discovery"),
];

/// Suspicious command patterns in WMI consumers
const SUSPICIOUS_CONSUMER_PATTERNS: &[(&str, &str)] = &[
    ("powershell", "PowerShell execution"),
    ("cmd.exe", "Command shell execution"),
    ("-encodedcommand", "Encoded PowerShell command"),
    ("-enc ", "Encoded PowerShell command"),
    ("-e ", "Encoded PowerShell command short"),
    ("invoke-expression", "Dynamic code execution"),
    ("iex(", "IEX invocation"),
    ("downloadstring", "Download operation"),
    ("webclient", "Web download"),
    ("net.webclient", "Web download class"),
    ("bitstransfer", "BITS download"),
    ("certutil", "Certutil execution"),
    ("mshta", "MSHTA execution"),
    ("wscript", "Windows Script Host"),
    ("cscript", "Console Script Host"),
    ("regsvr32", "RegSvr32 execution"),
    ("rundll32", "RunDLL32 execution"),
    ("http://", "HTTP URL"),
    ("https://", "HTTPS URL"),
    ("base64", "Base64 encoding"),
    ("[convert]::", "PowerShell conversion"),
    ("frombase64", "Base64 decoding"),
    ("-noprofile", "PowerShell no profile"),
    ("-windowstyle hidden", "Hidden window"),
    ("-w hidden", "Hidden window short"),
];

/// WMI namespaces to monitor
#[allow(dead_code)]
pub const MONITORED_NAMESPACES: &[&str] = &[r"ROOT\subscription", r"ROOT\default", r"ROOT\CIMV2"];

/// WMI subscription classes
#[allow(dead_code)]
pub const SUBSCRIPTION_CLASSES: &[&str] = &[
    "__EventFilter",
    "__EventConsumer",
    "__FilterToConsumerBinding",
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "LogFileEventConsumer",
    "NtEventLogEventConsumer",
    "SMTPEventConsumer",
];

/// ETW Provider GUID for Microsoft-Windows-WMI-Activity
#[allow(dead_code)]
pub const WMI_ACTIVITY_PROVIDER: &str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";

/// WMI Activity Collector
pub struct WmiCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    known_subscriptions: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

impl WmiCollector {
    /// Create a new WMI collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);
        let running = Arc::new(AtomicBool::new(true));
        let known_subscriptions = Arc::new(tokio::sync::Mutex::new(HashSet::new()));

        info!("Initializing WMI Activity Collector");

        // Clone for monitoring threads
        let tx_sub = tx.clone();
        let tx_etw = tx.clone();
        let tx_process = tx.clone();
        let running_sub = running.clone();
        let running_etw = running.clone();
        let running_process = running.clone();
        let known_subs = known_subscriptions.clone();
        let config_clone = config.clone();

        // Check performance profile
        if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
            info!("Lightweight profile: WMI monitoring disabled");
            return Ok(Self {
                config: config.clone(),
                event_rx: rx,
                running,
                known_subscriptions,
            });
        }

        // Start WMI subscription monitoring (periodic enumeration)
        std::thread::spawn(move || {
            if let Err(e) = Self::monitor_wmi_subscriptions(tx_sub, running_sub, known_subs) {
                error!(error = %e, "WMI subscription monitor error");
            }
        });

        // Start ETW monitoring for WMI activity
        let config_etw = config.clone();
        std::thread::spawn(move || {
            if let Err(e) = Self::monitor_wmi_etw(tx_etw, running_etw, config_etw) {
                warn!(error = %e, "WMI ETW monitor not available, using polling fallback");
            }
        });

        // Start process monitoring for WMI-related processes
        std::thread::spawn(move || {
            if let Err(e) = Self::monitor_wmi_processes(tx_process, running_process, config_clone) {
                error!(error = %e, "WMI process monitor error");
            }
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            running,
            known_subscriptions,
        })
    }

    /// Monitor WMI event subscriptions via COM enumeration
    fn monitor_wmi_subscriptions(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        known_subs: Arc<tokio::sync::Mutex<HashSet<String>>>,
    ) -> Result<()> {
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
            COINIT_MULTITHREADED,
        };
        use windows::Win32::System::Wmi::{IWbemLocator, WbemLocator};

        info!("Starting WMI subscription enumeration monitor");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        unsafe {
            // Initialize COM
            CoInitializeEx(None, COINIT_MULTITHREADED)?;

            let _guard = scopeguard::guard((), |_| {
                CoUninitialize();
            });

            // Create WMI locator
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;

            // Main monitoring loop
            while running.load(Ordering::SeqCst) {
                // Monitor ROOT\subscription namespace for event subscriptions
                if let Err(e) = Self::enumerate_subscriptions(&locator, &tx, &known_subs, &rt) {
                    debug!(error = %e, "Subscription enumeration error");
                }

                // Sleep between scans (5 seconds)
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }

        Ok(())
    }

    /// Enumerate WMI subscriptions in the subscription namespace
    unsafe fn enumerate_subscriptions(
        locator: &windows::Win32::System::Wmi::IWbemLocator,
        tx: &mpsc::Sender<TelemetryEvent>,
        known_subs: &Arc<tokio::sync::Mutex<HashSet<String>>>,
        rt: &tokio::runtime::Runtime,
    ) -> Result<()> {
        use windows::Win32::System::Com::{
            CoSetProxyBlanket, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        };

        use windows::core::BSTR;

        // Connect to ROOT\subscription namespace
        let namespace = BSTR::from(r"ROOT\subscription");
        let services = locator.ConnectServer(
            &namespace,
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )?;

        // Set security on the proxy
        CoSetProxyBlanket(
            &services,
            windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT as u32,
            windows::Win32::System::Rpc::RPC_C_AUTHZ_NONE as u32,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            windows::Win32::System::Com::EOAC_NONE,
        )?;

        // Query for EventFilters
        Self::query_wmi_class(&services, "__EventFilter", "filter", tx, known_subs, rt)?;

        // Query for EventConsumers
        for consumer_class in &[
            "CommandLineEventConsumer",
            "ActiveScriptEventConsumer",
            "LogFileEventConsumer",
            "NtEventLogEventConsumer",
            "SMTPEventConsumer",
        ] {
            Self::query_wmi_class(&services, consumer_class, "consumer", tx, known_subs, rt)?;
        }

        // Query for FilterToConsumerBindings
        Self::query_wmi_class(
            &services,
            "__FilterToConsumerBinding",
            "binding",
            tx,
            known_subs,
            rt,
        )?;

        Ok(())
    }

    /// Query a specific WMI class and detect new objects
    unsafe fn query_wmi_class(
        services: &windows::Win32::System::Wmi::IWbemServices,
        class_name: &str,
        object_type: &str,
        tx: &mpsc::Sender<TelemetryEvent>,
        known_subs: &Arc<tokio::sync::Mutex<HashSet<String>>>,
        rt: &tokio::runtime::Runtime,
    ) -> Result<()> {
        use windows::core::BSTR;
        use windows::Win32::System::Wmi::{WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY};

        let query = BSTR::from(format!("SELECT * FROM {}", class_name));
        let language = BSTR::from("WQL");

        let enumerator = match services.ExecQuery(
            &language,
            &query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        ) {
            Ok(e) => e,
            Err(_) => return Ok(()), // Class may not exist
        };

        loop {
            let mut objects = [None; 1];
            let mut returned: u32 = 0;

            if enumerator
                .Next(
                    windows::Win32::System::Wmi::WBEM_INFINITE,
                    &mut objects,
                    &mut returned,
                )
                .is_err()
                || returned == 0
            {
                break;
            }

            if let Some(obj) = objects[0].take() {
                // Extract object properties
                let name = Self::get_wmi_property(&obj, "Name")
                    .or_else(|| Self::get_wmi_property(&obj, "__RELPATH"))
                    .unwrap_or_else(|| "Unknown".to_string());

                let details = Self::get_consumer_details(&obj, class_name);
                let unique_key = format!(
                    "{}:{}:{}",
                    class_name,
                    name,
                    details.clone().unwrap_or_default()
                );

                // Check if this is a new subscription
                let is_new = rt.block_on(async {
                    let mut known = known_subs.lock().await;
                    if known.contains(&unique_key) {
                        false
                    } else {
                        known.insert(unique_key.clone());
                        true
                    }
                });

                if is_new {
                    // Analyze for threats
                    let (severity, attack_pattern, detections) =
                        Self::analyze_subscription(&name, class_name, details.as_deref());

                    // Create event
                    let mut event = TelemetryEvent::new(
                        EventType::WmiActivity,
                        severity,
                        EventPayload::Wmi(WmiEvent {
                            activity_type: format!("{}_created", object_type),
                            namespace: "ROOT\\subscription".to_string(),
                            wmi_class: class_name.to_string(),
                            object_name: name.clone(),
                            object_details: details,
                            pid: 0, // Will be populated from ETW if available
                            process_name: String::new(),
                            process_cmdline: None,
                            remote_host: None,
                            user: Self::get_current_user(),
                            attack_pattern,
                        }),
                    );

                    // Add detections
                    for detection in detections {
                        event.add_detection(detection);
                    }

                    // Always add base persistence detection for subscription objects
                    if object_type == "consumer" || object_type == "binding" {
                        event.add_detection(Detection {
                            detection_type: DetectionType::WmiPersistence,
                            rule_name: "wmi_subscription_persistence".to_string(),
                            confidence: 0.85,
                            description: format!("WMI {} detected: {}", object_type, name),
                            mitre_tactics: vec![
                                "Persistence".to_string(),
                                "Privilege Escalation".to_string(),
                            ],
                            mitre_techniques: vec!["T1546.003".to_string()],
                        });
                    }

                    info!(
                        class = %class_name,
                        name = %name,
                        severity = ?event.severity,
                        "New WMI subscription detected"
                    );

                    let _ = rt.block_on(tx.send(event));
                }
            }
        }

        Ok(())
    }

    /// Get a property value from a WMI object
    unsafe fn get_wmi_property(
        obj: &windows::Win32::System::Wmi::IWbemClassObject,
        property: &str,
    ) -> Option<String> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Variant::{VariantToStringAlloc, VARIANT};

        let prop_name: Vec<u16> = property.encode_utf16().chain(std::iter::once(0)).collect();
        let mut value = VARIANT::default();

        if obj
            .Get(PCWSTR(prop_name.as_ptr()), 0, &mut value, None, None)
            .is_ok()
        {
            // Use VariantToStringAlloc to convert VARIANT to PWSTR
            if let Ok(str_val) = VariantToStringAlloc(&value) {
                let s = str_val.to_string().unwrap_or_default();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }

        None
    }

    /// Get consumer details (command line, script, etc.)
    unsafe fn get_consumer_details(
        obj: &windows::Win32::System::Wmi::IWbemClassObject,
        class_name: &str,
    ) -> Option<String> {
        match class_name {
            "CommandLineEventConsumer" => {
                let cmd = Self::get_wmi_property(obj, "CommandLineTemplate");
                let exec = Self::get_wmi_property(obj, "ExecutablePath");
                if cmd.is_some() || exec.is_some() {
                    Some(format!("Exec: {:?}, Cmd: {:?}", exec, cmd))
                } else {
                    None
                }
            }
            "ActiveScriptEventConsumer" => {
                let text = Self::get_wmi_property(obj, "ScriptText");
                let file = Self::get_wmi_property(obj, "ScriptFileName");
                let engine = Self::get_wmi_property(obj, "ScriptingEngine");
                Some(format!(
                    "Engine: {:?}, Text: {:?}, File: {:?}",
                    engine, text, file
                ))
            }
            "__EventFilter" => Self::get_wmi_property(obj, "Query"),
            "__FilterToConsumerBinding" => {
                let filter = Self::get_wmi_property(obj, "Filter");
                let consumer = Self::get_wmi_property(obj, "Consumer");
                Some(format!("Filter: {:?}, Consumer: {:?}", filter, consumer))
            }
            _ => None,
        }
    }

    /// Analyze a subscription for threats
    fn analyze_subscription(
        name: &str,
        class_name: &str,
        details: Option<&str>,
    ) -> (Severity, Option<String>, Vec<Detection>) {
        let mut severity = Severity::Medium;
        let mut attack_pattern = None;
        let mut detections = Vec::new();

        let name_lower = name.to_lowercase();
        let details_lower = details.map(|d| d.to_lowercase()).unwrap_or_default();

        // Check for known malicious patterns
        for (pattern, apt_name, description) in KNOWN_MALICIOUS_PATTERNS {
            if name_lower.contains(&pattern.to_lowercase()) {
                severity = Severity::Critical;
                attack_pattern = Some(apt_name.to_string());
                detections.push(Detection {
                    detection_type: DetectionType::WmiPersistence,
                    rule_name: format!("wmi_known_malicious_{}", apt_name.to_lowercase()),
                    confidence: 0.95,
                    description: description.to_string(),
                    mitre_tactics: vec!["Persistence".to_string()],
                    mitre_techniques: vec!["T1546.003".to_string()],
                });
                break;
            }
        }

        // Check consumer details for suspicious patterns
        if let Some(details) = details {
            for (pattern, desc) in SUSPICIOUS_CONSUMER_PATTERNS {
                if details_lower.contains(pattern) {
                    if severity != Severity::Critical {
                        severity = Severity::High;
                    }
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: format!(
                            "wmi_suspicious_consumer_{}",
                            pattern.replace(".", "_").replace(" ", "_")
                        ),
                        confidence: 0.80,
                        description: format!("Suspicious pattern in WMI consumer: {}", desc),
                        mitre_tactics: vec!["Execution".to_string(), "Persistence".to_string()],
                        mitre_techniques: vec!["T1546.003".to_string(), "T1059".to_string()],
                    });
                }
            }
        }

        // CommandLineEventConsumer and ActiveScriptEventConsumer are inherently suspicious
        if class_name == "CommandLineEventConsumer" || class_name == "ActiveScriptEventConsumer" {
            if severity == Severity::Medium {
                severity = Severity::High;
            }
            detections.push(Detection {
                detection_type: DetectionType::WmiPersistence,
                rule_name: format!("wmi_{}_detected", class_name.to_lowercase()),
                confidence: 0.75,
                description: format!("{} is commonly abused for persistence", class_name),
                mitre_tactics: vec!["Persistence".to_string(), "Execution".to_string()],
                mitre_techniques: vec!["T1546.003".to_string()],
            });
        }

        (severity, attack_pattern, detections)
    }

    /// Monitor WMI activity via ETW
    fn monitor_wmi_etw(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        _config: AgentConfig,
    ) -> Result<()> {
        use super::win_compat::SystemCapabilities;

        let caps = SystemCapabilities::detect();
        if !caps.has_etw || !caps.is_elevated {
            return Err(anyhow!("ETW requires elevation for WMI monitoring"));
        }

        info!("Starting WMI ETW monitor (Microsoft-Windows-WMI-Activity)");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        // WMI Activity ETW monitoring would be implemented here
        // For now, we rely on the process monitoring and subscription enumeration
        // A full implementation would:
        // 1. Create an ETW session for Microsoft-Windows-WMI-Activity provider
        // 2. Parse WMI operation events (query, method calls, etc.)
        // 3. Correlate with process information

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        Ok(())
    }

    /// Monitor WMI-related processes (wmiprvse.exe, wmic.exe, etc.)
    fn monitor_wmi_processes(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        _config: AgentConfig,
    ) -> Result<()> {
        use windows::Win32::Foundation::CloseHandle;

        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting WMI process monitor");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut known_wmi_pids: HashSet<u32> = HashSet::new();

        while running.load(Ordering::SeqCst) {
            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        continue;
                    }
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile[..entry
                                .szExeFile
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(entry.szExeFile.len())],
                        );
                        let name_lower = name.to_lowercase();

                        // Check for WMI-related processes
                        if name_lower == "wmic.exe" || name_lower == "wmiprvse.exe" {
                            let pid = entry.th32ProcessID;

                            if !known_wmi_pids.contains(&pid) {
                                known_wmi_pids.insert(pid);

                                // Get command line for wmic.exe
                                let cmdline = Self::get_process_cmdline(pid);

                                if name_lower == "wmic.exe" {
                                    // Analyze WMIC command for suspicious activity
                                    if let Some(ref cmd) = cmdline {
                                        if let Some(event) =
                                            Self::analyze_wmic_command(pid, &name, cmd)
                                        {
                                            let _ = rt.block_on(tx.send(event));
                                        }
                                    }
                                }
                            }
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            // Clean up terminated PIDs periodically
            known_wmi_pids.retain(|&pid| Self::is_process_alive(pid));

            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        Ok(())
    }

    /// Analyze WMIC command for suspicious activity
    fn analyze_wmic_command(pid: u32, process_name: &str, cmdline: &str) -> Option<TelemetryEvent> {
        let cmd_lower = cmdline.to_lowercase();
        let mut severity = Severity::Low;
        let mut detections = Vec::new();
        let mut activity_type = "wmic_execution".to_string();
        let mut remote_host = None;

        // Check for remote execution (/node:)
        if cmd_lower.contains("/node:") || cmd_lower.contains("-node:") {
            severity = Severity::High;
            activity_type = "remote_wmi_execution".to_string();

            // Extract remote host
            if let Some(node_pos) = cmd_lower
                .find("/node:")
                .or_else(|| cmd_lower.find("-node:"))
            {
                let rest = &cmdline[node_pos + 6..];
                let host = rest.split_whitespace().next().unwrap_or("");
                remote_host = Some(host.trim_matches('"').to_string());
            }

            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "wmic_remote_execution".to_string(),
                confidence: 0.85,
                description: "Remote WMI execution detected".to_string(),
                mitre_tactics: vec!["Lateral Movement".to_string(), "Execution".to_string()],
                mitre_techniques: vec!["T1047".to_string()],
            });
        }

        // Check for process creation
        if cmd_lower.contains("process")
            && cmd_lower.contains("call")
            && cmd_lower.contains("create")
        {
            severity = Severity::High;
            activity_type = "wmi_process_creation".to_string();

            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "wmic_process_create".to_string(),
                confidence: 0.90,
                description: "Process creation via WMIC detected".to_string(),
                mitre_tactics: vec!["Execution".to_string()],
                mitre_techniques: vec!["T1047".to_string()],
            });
        }

        // Check for reconnaissance queries
        for (pattern, technique, description) in RECON_QUERY_PATTERNS {
            if cmd_lower.contains(&pattern.to_lowercase()) {
                if severity == Severity::Low {
                    severity = Severity::Medium;
                }
                activity_type = "wmi_reconnaissance".to_string();

                detections.push(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: format!("wmic_recon_{}", technique.to_lowercase()),
                    confidence: 0.60,
                    description: format!("WMI reconnaissance: {}", description),
                    mitre_tactics: vec!["Discovery".to_string()],
                    mitre_techniques: vec![technique.to_string()],
                });
                break;
            }
        }

        // Check for shadow copy deletion
        if cmd_lower.contains("shadowcopy") && cmd_lower.contains("delete") {
            severity = Severity::Critical;
            activity_type = "shadow_copy_deletion".to_string();

            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "wmic_shadow_delete".to_string(),
                confidence: 0.95,
                description: "Shadow copy deletion via WMIC (possible ransomware)".to_string(),
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1490".to_string()],
            });
        }

        // Only return event if there are detections
        if detections.is_empty() {
            return None;
        }

        let mut event = TelemetryEvent::new(
            EventType::WmiActivity,
            severity,
            EventPayload::Wmi(WmiEvent {
                activity_type,
                namespace: "ROOT\\CIMV2".to_string(),
                wmi_class: "WMIC".to_string(),
                object_name: "Command".to_string(),
                object_details: Some(cmdline.to_string()),
                pid,
                process_name: process_name.to_string(),
                process_cmdline: Some(cmdline.to_string()),
                remote_host,
                user: Self::get_current_user(),
                attack_pattern: None,
            }),
        );

        for detection in detections {
            event.add_detection(detection);
        }

        Some(event)
    }

    /// Get process command line using NT API
    fn get_process_cmdline(pid: u32) -> Option<String> {
        use super::win_compat::ntapi::get_process_command_line;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
            .ok()?;
            let cmdline = get_process_command_line(std::mem::transmute::<_, *mut c_void>(handle));
            let _ = CloseHandle(handle);
            cmdline
        }
    }

    /// Check if a process is still running
    fn is_process_alive(pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let _ = CloseHandle(handle);
                true
            } else {
                false
            }
        }
    }

    /// Get current username
    fn get_current_user() -> String {
        use windows::Win32::System::WindowsProgramming::GetUserNameW;

        unsafe {
            let mut size = 256u32;
            let mut buffer = vec![0u16; size as usize];

            if GetUserNameW(windows::core::PWSTR(buffer.as_mut_ptr()), &mut size).is_ok() {
                String::from_utf16_lossy(&buffer[..(size - 1) as usize])
            } else {
                "UNKNOWN".to_string()
            }
        }
    }

    /// Enumerate existing WMI subscriptions (for initial baseline)
    pub async fn enumerate_existing_subscriptions(&self) -> Vec<WmiEvent> {
        let subscriptions = Vec::new();

        // This would query existing subscriptions and return them
        // Implementation would be similar to monitor_wmi_subscriptions
        // but returns immediately instead of monitoring

        subscriptions
    }

    /// Check if a specific WMI subscription exists
    pub fn subscription_exists(&self, name: &str, class: &str) -> bool {
        // Implementation would query WMI to check if subscription exists
        false
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

impl Drop for WmiCollector {
    fn drop(&mut self) {
        info!("Shutting down WMI collector");
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Helper to extract attack patterns for logging
pub fn get_known_attack_patterns() -> Vec<(&'static str, &'static str)> {
    KNOWN_MALICIOUS_PATTERNS
        .iter()
        .map(|(name, apt, _)| (*name, *apt))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_subscription_known_malicious() {
        let (severity, pattern, detections) = WmiCollector::analyze_subscription(
            "SystemCoreService",
            "CommandLineEventConsumer",
            Some("powershell.exe -enc ZW5jb2RlZA=="),
        );

        assert_eq!(severity, Severity::Critical);
        assert!(pattern.is_some());
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_analyze_subscription_suspicious_content() {
        let (severity, pattern, detections) = WmiCollector::analyze_subscription(
            "MySubscription",
            "CommandLineEventConsumer",
            Some("cmd.exe /c powershell -encodedcommand ABC123"),
        );

        assert!(severity >= Severity::High);
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_analyze_wmic_remote() {
        let event = WmiCollector::analyze_wmic_command(
            1234,
            "wmic.exe",
            "wmic /node:192.168.1.100 process call create \"cmd.exe\"",
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn test_analyze_wmic_shadow_delete() {
        let event = WmiCollector::analyze_wmic_command(
            1234,
            "wmic.exe",
            "wmic shadowcopy delete /nointeractive",
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.severity, Severity::Critical);
    }
}
