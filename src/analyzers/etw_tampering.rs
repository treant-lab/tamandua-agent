//! ETW Tampering Detection Module
//!
//! Detects attempts to tamper with Event Tracing for Windows (ETW) for evasion.
//!
//! MITRE ATT&CK:
//! - T1562.006: Impair Defenses: Indicator Blocking
//!
//! Detection Methods:
//! - EtwEventWrite function patching detection
//! - ETW provider disabling via registry
//! - Trace session manipulation
//! - ntdll!EtwEventWrite hook detection
//! - Provider unregistration attacks (EtwEventUnregister abuse)
//! - TraceLogging provider tampering
//! - EventWrite hooking/bypass
//! - ETW session manipulation
//! - Threat Intelligence ETW provider targeting
//! - Microsoft-Windows-Threat-Intelligence provider disabling
//! - EtwNotificationRegister callback removal
//! - Private logger session hijacking

// ETW tampering detector. EventWrite prologue baselines and tracked-session
// fields are retained for upcoming kernel verification stages.
#![allow(dead_code, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info};

#[cfg(target_os = "windows")]
use windows::core::PCSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HMODULE;
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

/// Expected first bytes of EtwEventWrite (varies by Windows version)
/// These are the known good prologue bytes
#[cfg(target_os = "windows")]
const ETW_EVENTWRITE_PROLOGUE_WIN10: &[u8] = &[0x4C, 0x8B, 0xDC]; // mov r11, rsp
#[cfg(target_os = "windows")]
const ETW_EVENTWRITE_PROLOGUE_WIN11: &[u8] = &[0x48, 0x89, 0x5C]; // mov [rsp+...], rbx

/// ETW tampering detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwTamperingDetection {
    pub detection_type: EtwTamperingType,
    pub confidence: f32,
    pub mitre_technique: String,
    pub description: String,
    pub details: HashMap<String, String>,
    pub timestamp: u64,
}

/// Types of ETW tampering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwTamperingType {
    /// EtwEventWrite function patched
    FunctionPatch,
    /// ETW provider disabled in registry
    ProviderDisabled,
    /// Trace session stopped
    TraceSessionStopped,
    /// ETW provider unregistered
    ProviderUnregistered,
    /// AMSI bypass detected (often paired with ETW)
    AmsiBypass,
    /// Suspicious NOP sled in ETW functions
    NopSled,
    /// Provider unregistration attack (EtwEventUnregister abuse)
    ProviderUnregistrationAttack,
    /// TraceLogging provider tampering
    TraceLoggingTampering,
    /// EventWrite function hooked
    EventWriteHook,
    /// ETW session manipulation
    SessionManipulation,
    /// Threat Intelligence provider targeted
    ThreatIntelProviderTargeted,
    /// Microsoft-Windows-Threat-Intelligence disabled
    ThreatIntelProviderDisabled,
    /// EtwNotificationRegister callback removed
    NotificationCallbackRemoved,
    /// Private logger session hijacking
    PrivateLoggerHijack,
    /// Critical provider missing or corrupted
    CriticalProviderMissing,
    /// ETW registry tampering
    RegistryTampering,
    /// Syscall hooking detected on ETW functions
    SyscallHook,
}

impl EtwTamperingType {
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::FunctionPatch | Self::NopSled => "T1562.006",
            Self::ProviderDisabled | Self::ProviderUnregistered => "T1562.006",
            Self::TraceSessionStopped => "T1562.006",
            Self::AmsiBypass => "T1562.001",
            Self::ProviderUnregistrationAttack => "T1562.006",
            Self::TraceLoggingTampering => "T1562.006",
            Self::EventWriteHook => "T1562.006",
            Self::SessionManipulation => "T1562.006",
            Self::ThreatIntelProviderTargeted => "T1562.006",
            Self::ThreatIntelProviderDisabled => "T1562.006",
            Self::NotificationCallbackRemoved => "T1562.006",
            Self::PrivateLoggerHijack => "T1562.006",
            Self::CriticalProviderMissing => "T1562.006",
            Self::RegistryTampering => "T1562.006",
            Self::SyscallHook => "T1562.006",
        }
    }

    /// Returns a human-readable description of the tampering type
    pub fn description(&self) -> &'static str {
        match self {
            Self::FunctionPatch => "ETW function has been patched to disable event logging",
            Self::ProviderDisabled => "ETW provider has been disabled via registry",
            Self::TraceSessionStopped => "ETW trace session has been stopped",
            Self::ProviderUnregistered => "ETW provider has been unregistered",
            Self::AmsiBypass => "AMSI scanning has been bypassed",
            Self::NopSled => "NOP sled detected in ETW function (potential patch)",
            Self::ProviderUnregistrationAttack => {
                "Abuse of EtwEventUnregister to disable providers"
            }
            Self::TraceLoggingTampering => "TraceLogging provider metadata has been tampered",
            Self::EventWriteHook => "EventWrite function has been hooked/redirected",
            Self::SessionManipulation => "ETW session configuration has been manipulated",
            Self::ThreatIntelProviderTargeted => {
                "Threat Intelligence ETW provider is being targeted"
            }
            Self::ThreatIntelProviderDisabled => {
                "Microsoft-Windows-Threat-Intelligence provider is disabled"
            }
            Self::NotificationCallbackRemoved => "ETW notification callbacks have been removed",
            Self::PrivateLoggerHijack => "Private ETW logger session has been hijacked",
            Self::CriticalProviderMissing => "Critical ETW provider is missing or corrupted",
            Self::RegistryTampering => "ETW configuration registry keys have been tampered",
            Self::SyscallHook => "Direct syscall hook detected on ETW functions",
        }
    }

    /// Returns the severity level (0.0-1.0) of the tampering type
    pub fn severity(&self) -> f32 {
        match self {
            Self::ThreatIntelProviderDisabled => 1.0,
            Self::ThreatIntelProviderTargeted => 0.95,
            Self::NotificationCallbackRemoved => 0.95,
            Self::FunctionPatch => 0.90,
            Self::EventWriteHook => 0.90,
            Self::SyscallHook => 0.90,
            Self::ProviderUnregistrationAttack => 0.85,
            Self::PrivateLoggerHijack => 0.85,
            Self::CriticalProviderMissing => 0.85,
            Self::SessionManipulation => 0.80,
            Self::TraceLoggingTampering => 0.75,
            Self::AmsiBypass => 0.75,
            Self::NopSled => 0.70,
            Self::ProviderDisabled => 0.70,
            Self::RegistryTampering => 0.70,
            Self::TraceSessionStopped => 0.65,
            Self::ProviderUnregistered => 0.60,
        }
    }
}

/// Critical ETW provider GUIDs that attackers commonly target
pub mod critical_providers {
    /// Microsoft-Windows-Threat-Intelligence provider GUID
    /// This provider exposes kernel-mode telemetry for security tools
    pub const THREAT_INTEL_GUID: &str = "{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}";

    /// Microsoft-Windows-Security-Auditing provider
    pub const SECURITY_AUDITING_GUID: &str = "{54849625-5478-4994-a5ba-3e3b0328c30d}";

    /// Microsoft-Antimalware-Scan-Interface provider
    pub const AMSI_GUID: &str = "{2a576b87-09a7-520e-c21a-4942f0271d67}";

    /// Microsoft-Windows-PowerShell provider
    pub const POWERSHELL_GUID: &str = "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}";

    /// Microsoft-Windows-DNS-Client provider
    pub const DNS_CLIENT_GUID: &str = "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}";

    /// Microsoft-Windows-Kernel-Process provider
    pub const KERNEL_PROCESS_GUID: &str = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}";

    /// Microsoft-Windows-Kernel-File provider
    pub const KERNEL_FILE_GUID: &str = "{edd08927-9cc4-4e65-b970-c2560fb5c289}";

    /// Microsoft-Windows-Kernel-Network provider
    pub const KERNEL_NETWORK_GUID: &str = "{7dd42a49-5329-4832-8dfd-43d979153a88}";

    /// Windows Defender provider
    pub const DEFENDER_GUID: &str = "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}";

    /// Sysmon provider
    pub const SYSMON_GUID: &str = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}";

    /// Get all critical provider GUIDs
    pub fn all_critical_guids() -> Vec<&'static str> {
        vec![
            THREAT_INTEL_GUID,
            SECURITY_AUDITING_GUID,
            AMSI_GUID,
            POWERSHELL_GUID,
            DNS_CLIENT_GUID,
            KERNEL_PROCESS_GUID,
            KERNEL_FILE_GUID,
            KERNEL_NETWORK_GUID,
            DEFENDER_GUID,
            SYSMON_GUID,
        ]
    }

    /// Get provider name from GUID
    pub fn name_from_guid(guid: &str) -> &'static str {
        match guid.to_lowercase().as_str() {
            s if s.contains("f4e1897c-bb5d-5668-f1d8-040f4d8dd344") => {
                "Microsoft-Windows-Threat-Intelligence"
            }
            s if s.contains("54849625-5478-4994-a5ba-3e3b0328c30d") => {
                "Microsoft-Windows-Security-Auditing"
            }
            s if s.contains("2a576b87-09a7-520e-c21a-4942f0271d67") => {
                "Microsoft-Antimalware-Scan-Interface"
            }
            s if s.contains("a0c1853b-5c40-4b15-8766-3cf1c58f985a") => {
                "Microsoft-Windows-PowerShell"
            }
            s if s.contains("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") => {
                "Microsoft-Windows-DNS-Client"
            }
            s if s.contains("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") => {
                "Microsoft-Windows-Kernel-Process"
            }
            s if s.contains("edd08927-9cc4-4e65-b970-c2560fb5c289") => {
                "Microsoft-Windows-Kernel-File"
            }
            s if s.contains("7dd42a49-5329-4832-8dfd-43d979153a88") => {
                "Microsoft-Windows-Kernel-Network"
            }
            s if s.contains("11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78") => "Windows-Defender",
            s if s.contains("5770385f-c22a-43e0-bf4c-06f5698ffbd9") => "Sysmon",
            _ => "Unknown",
        }
    }
}

/// ETW session information for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwSessionInfo {
    /// Session name
    pub name: String,
    /// Session GUID (if available)
    pub guid: Option<String>,
    /// Whether session is running
    pub is_running: bool,
    /// Last known state timestamp
    pub last_seen: u64,
    /// Number of enabled providers
    pub provider_count: u32,
}

/// Provider registration state for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderState {
    /// Provider GUID
    pub guid: String,
    /// Provider name
    pub name: String,
    /// Whether provider is currently registered
    pub is_registered: bool,
    /// Registration handle (if available)
    pub handle: Option<u64>,
    /// Last check timestamp
    pub last_check: u64,
}

/// Comprehensive ETW scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwScanReport {
    /// Scan timestamp
    pub timestamp: u64,
    /// All detections found
    pub detections: Vec<EtwTamperingDetection>,
    /// Status of critical ETW providers
    pub provider_status: Vec<ProviderState>,
    /// Status of ETW sessions
    pub session_status: Vec<EtwSessionInfo>,
    /// Function integrity check results (function name -> is_intact)
    pub function_integrity: HashMap<String, bool>,
    /// Overall ETW health score (0.0 = compromised, 1.0 = healthy)
    pub overall_health: f32,
}

impl EtwScanReport {
    /// Check if any critical issues were detected
    pub fn has_critical_issues(&self) -> bool {
        self.detections
            .iter()
            .any(|d| d.detection_type.severity() >= 0.90)
    }

    /// Get count of detections by type
    pub fn detection_count_by_type(&self) -> HashMap<EtwTamperingType, usize> {
        let mut counts = HashMap::new();
        for detection in &self.detections {
            *counts.entry(detection.detection_type).or_insert(0) += 1;
        }
        counts
    }

    /// Get the highest severity detection
    pub fn highest_severity_detection(&self) -> Option<&EtwTamperingDetection> {
        self.detections.iter().max_by(|a, b| {
            a.detection_type
                .severity()
                .partial_cmp(&b.detection_type.severity())
                .unwrap()
        })
    }

    /// Get list of compromised functions
    pub fn compromised_functions(&self) -> Vec<&String> {
        self.function_integrity
            .iter()
            .filter(|(_, intact)| !**intact)
            .map(|(name, _)| name)
            .collect()
    }

    /// Get list of unregistered critical providers
    pub fn unregistered_providers(&self) -> Vec<&ProviderState> {
        self.provider_status
            .iter()
            .filter(|p| !p.is_registered)
            .collect()
    }

    /// Check if Threat Intelligence provider is compromised
    pub fn is_threat_intel_compromised(&self) -> bool {
        self.detections.iter().any(|d| {
            matches!(
                d.detection_type,
                EtwTamperingType::ThreatIntelProviderDisabled
                    | EtwTamperingType::ThreatIntelProviderTargeted
            )
        })
    }

    /// Generate a summary string
    pub fn summary(&self) -> String {
        let critical = self
            .detections
            .iter()
            .filter(|d| d.detection_type.severity() >= 0.90)
            .count();
        let high = self
            .detections
            .iter()
            .filter(|d| d.detection_type.severity() >= 0.75 && d.detection_type.severity() < 0.90)
            .count();
        let medium = self
            .detections
            .iter()
            .filter(|d| d.detection_type.severity() >= 0.50 && d.detection_type.severity() < 0.75)
            .count();

        format!(
            "ETW Health: {:.0}% | Detections: {} (Critical: {}, High: {}, Medium: {}) | Providers: {}/{} OK",
            self.overall_health * 100.0,
            self.detections.len(),
            critical,
            high,
            medium,
            self.provider_status.iter().filter(|p| p.is_registered).count(),
            self.provider_status.len()
        )
    }
}

/// ETW Tampering Detector
pub struct EtwTamperingDetector {
    /// Known good function bytes (cached on first check)
    known_good_bytes: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Detections found
    detections: Arc<RwLock<Vec<EtwTamperingDetection>>>,
    /// Tracked ETW sessions
    tracked_sessions: Arc<RwLock<HashMap<String, EtwSessionInfo>>>,
    /// Tracked provider states
    tracked_providers: Arc<RwLock<HashMap<String, ProviderState>>>,
    /// Known provider registration handles (for monitoring unregistration)
    provider_handles: Arc<RwLock<HashSet<u64>>>,
    /// Baseline function bytes from clean system
    baseline_functions: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl EtwTamperingDetector {
    pub fn new() -> Self {
        let detector = Self {
            known_good_bytes: Arc::new(RwLock::new(HashMap::new())),
            detections: Arc::new(RwLock::new(Vec::new())),
            tracked_sessions: Arc::new(RwLock::new(HashMap::new())),
            tracked_providers: Arc::new(RwLock::new(HashMap::new())),
            provider_handles: Arc::new(RwLock::new(HashSet::new())),
            baseline_functions: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize baseline function bytes on first creation
        #[cfg(target_os = "windows")]
        detector.capture_baseline_bytes();

        detector
    }

    /// Capture baseline function bytes from a clean system state
    #[cfg(target_os = "windows")]
    fn capture_baseline_bytes(&self) {
        let etw_functions = [
            "EtwEventWrite",
            "EtwEventWriteFull",
            "EtwEventWriteTransfer",
            "EtwEventRegister",
            "EtwEventUnregister",
            "EtwNotificationRegister",
            "EtwNotificationUnregister",
            "NtTraceEvent",
            "NtTraceControl",
        ];

        let mut baseline = self.baseline_functions.write();

        for func_name in etw_functions.iter() {
            if let Some(bytes) = self.read_function_bytes("ntdll.dll", func_name, 32) {
                baseline.insert(func_name.to_string(), bytes);
                debug!(function = %func_name, "Captured baseline bytes for ETW function");
            }
        }
    }

    /// Read bytes from a function in a module
    #[cfg(target_os = "windows")]
    fn read_function_bytes(
        &self,
        module_name: &str,
        func_name: &str,
        count: usize,
    ) -> Option<Vec<u8>> {
        unsafe {
            let module_wide = match module_name {
                "ntdll.dll" => windows::core::w!("ntdll.dll"),
                "kernelbase.dll" => windows::core::w!("kernelbase.dll"),
                "kernel32.dll" => windows::core::w!("kernel32.dll"),
                "amsi.dll" => windows::core::w!("amsi.dll"),
                _ => return None,
            };

            let module = GetModuleHandleW(module_wide).ok()?;
            let func_name_cstr = format!("{}\0", func_name);
            let func_name_pcstr = PCSTR::from_raw(func_name_cstr.as_ptr());
            let func_addr = GetProcAddress(module, func_name_pcstr)?;

            let func_ptr = func_addr as *const u8;
            let mut bytes = vec![0u8; count];
            std::ptr::copy_nonoverlapping(func_ptr, bytes.as_mut_ptr(), count);
            Some(bytes)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn read_function_bytes(
        &self,
        _module_name: &str,
        _func_name: &str,
        _count: usize,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Scan for ETW tampering in current process
    /// This is the main comprehensive detection entry point
    #[cfg(target_os = "windows")]
    pub fn scan_current_process(&self) -> Vec<EtwTamperingDetection> {
        let mut detections = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Check EtwEventWrite patching
        if let Some(detection) = self.check_etw_eventwrite(timestamp) {
            detections.push(detection);
        }

        // 2. Check NtTraceEvent patching
        if let Some(detection) = self.check_nt_trace_event(timestamp) {
            detections.push(detection);
        }

        // 3. Check AMSI (commonly tampered alongside ETW)
        if let Some(detection) = self.check_amsi_scan_buffer(timestamp) {
            detections.push(detection);
        }

        // 4. Check additional ETW functions for patching
        detections.extend(self.check_etw_function_family(timestamp));

        // 5. Check for provider unregistration attacks
        detections.extend(self.check_provider_unregistration_attacks(timestamp));

        // 6. Check TraceLogging provider tampering
        if let Some(detection) = self.check_tracelogging_tampering(timestamp) {
            detections.push(detection);
        }

        // 7. Check EventWrite hooking/bypass
        detections.extend(self.check_eventwrite_hooks(timestamp));

        // 8. Check ETW session manipulation
        detections.extend(self.check_session_manipulation(timestamp));

        // 9. Check Threat Intelligence provider targeting
        detections.extend(self.check_threat_intel_provider(timestamp));

        // 10. Check EtwNotificationRegister callback removal
        if let Some(detection) = self.check_notification_callbacks(timestamp) {
            detections.push(detection);
        }

        // 11. Check private logger session hijacking
        detections.extend(self.check_private_logger_hijacking(timestamp));

        // 12. Check registry tampering for ETW providers
        detections.extend(self.check_registry_tampering(timestamp));

        // 13. Check for syscall hooking on ETW functions
        detections.extend(self.check_syscall_hooks(timestamp));

        // Store detections
        if !detections.is_empty() {
            self.detections.write().extend(detections.clone());
            info!(count = detections.len(), "ETW tampering detections found");
        }

        detections
    }

    /// Comprehensive scan with detailed reporting
    #[cfg(target_os = "windows")]
    pub fn deep_scan(&self) -> EtwScanReport {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let detections = self.scan_current_process();
        let provider_status = self.get_critical_provider_status();
        let session_status = self.get_session_status();
        let function_integrity = self.check_all_function_integrity();

        EtwScanReport {
            timestamp,
            detections,
            provider_status,
            session_status,
            function_integrity,
            overall_health: self.calculate_overall_health(),
        }
    }

    /// Check the entire ETW function family for patching
    #[cfg(target_os = "windows")]
    fn check_etw_function_family(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        let mut detections = Vec::new();

        let etw_functions = [
            ("EtwEventWriteFull", "Extended event write function"),
            (
                "EtwEventWriteTransfer",
                "Event write with activity transfer",
            ),
            ("EtwEventRegister", "Provider registration function"),
            ("EtwEventUnregister", "Provider unregistration function"),
            ("EtwNotificationRegister", "ETW callback registration"),
            ("EtwNotificationUnregister", "ETW callback unregistration"),
            ("NtTraceControl", "Trace session control syscall"),
            ("EtwEventWriteEx", "Extended event write"),
            ("EtwEventWriteString", "String event write"),
            ("EtwEventWriteNoRegistration", "Unregistered event write"),
        ];

        for (func_name, description) in etw_functions.iter() {
            if let Some(bytes) = self.read_function_bytes("ntdll.dll", func_name, 16) {
                if self.is_patched(&bytes) {
                    let mut details = HashMap::new();
                    details.insert("function".to_string(), func_name.to_string());
                    details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..8]));
                    details.insert("purpose".to_string(), description.to_string());

                    detections.push(EtwTamperingDetection {
                        detection_type: EtwTamperingType::FunctionPatch,
                        confidence: 0.90,
                        mitre_technique: "T1562.006".to_string(),
                        description: format!("{} function appears to be patched", func_name),
                        details,
                        timestamp,
                    });
                } else if self.is_nop_sled(&bytes) {
                    let mut details = HashMap::new();
                    details.insert("function".to_string(), func_name.to_string());
                    details.insert("pattern".to_string(), "NOP sled detected".to_string());

                    detections.push(EtwTamperingDetection {
                        detection_type: EtwTamperingType::NopSled,
                        confidence: 0.85,
                        mitre_technique: "T1562.006".to_string(),
                        description: format!("{} function contains NOP sled", func_name),
                        details,
                        timestamp,
                    });
                }
            }
        }

        detections
    }

    /// Check for provider unregistration attacks (EtwEventUnregister abuse)
    #[cfg(target_os = "windows")]
    fn check_provider_unregistration_attacks(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        let mut detections = Vec::new();

        // Check if EtwEventUnregister has been hooked to intercept handles
        if let Some(bytes) = self.read_function_bytes("ntdll.dll", "EtwEventUnregister", 32) {
            // Check for hooking patterns that capture provider handles
            if self.is_instrumented(&bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "EtwEventUnregister".to_string());
                details.insert(
                    "pattern".to_string(),
                    "Instrumentation detected".to_string(),
                );
                details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..16]));

                detections.push(EtwTamperingDetection {
                    detection_type: EtwTamperingType::ProviderUnregistrationAttack,
                    confidence: 0.85,
                    mitre_technique: "T1562.006".to_string(),
                    description: "EtwEventUnregister appears to be instrumented for handle capture"
                        .to_string(),
                    details,
                    timestamp,
                });
            }
        }

        // Check critical provider registration status via registry
        for guid in critical_providers::all_critical_guids() {
            if !self.is_provider_registered_in_registry(guid) {
                let provider_name = critical_providers::name_from_guid(guid);
                let mut details = HashMap::new();
                details.insert("provider_guid".to_string(), guid.to_string());
                details.insert("provider_name".to_string(), provider_name.to_string());

                let (detection_type, confidence) = if guid == critical_providers::THREAT_INTEL_GUID
                {
                    (EtwTamperingType::ThreatIntelProviderDisabled, 0.98)
                } else {
                    (EtwTamperingType::ProviderUnregistered, 0.80)
                };

                detections.push(EtwTamperingDetection {
                    detection_type,
                    confidence,
                    mitre_technique: "T1562.006".to_string(),
                    description: format!(
                        "Critical ETW provider '{}' appears unregistered",
                        provider_name
                    ),
                    details,
                    timestamp,
                });
            }
        }

        detections
    }

    /// Check if a function has been instrumented (detours, hooks)
    fn is_instrumented(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 16 {
            return false;
        }

        // Check for trampoline patterns
        // Pattern 1: mov r10, rcx + mov eax, syscall_num (syscall stub modification)
        if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
            // Check if syscall number has been changed
            if bytes[3] == 0xB8 {
                // mov eax, imm32 - check if followed by unexpected instructions
                if bytes[8] != 0x0F || bytes[9] != 0x05 {
                    return true; // Expected syscall instruction not found
                }
            }
        }

        // Pattern 2: push/pop sequences that save state (common in hooks)
        let push_count = bytes
            .iter()
            .take(8)
            .filter(|&&b| b >= 0x50 && b <= 0x57)
            .count();
        if push_count >= 3 {
            return true;
        }

        // Pattern 3: mov [rsp], ... patterns that set up stack frames
        if bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0x44 {
            return true;
        }

        false
    }

    /// Check if provider is registered in the registry
    #[cfg(target_os = "windows")]
    fn is_provider_registered_in_registry(&self, guid: &str) -> bool {
        use winreg::enums::*;
        use winreg::RegKey;

        let guid_clean = guid.trim_matches(|c| c == '{' || c == '}');
        let key_path = format!(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{{{}}}",
            guid_clean
        );

        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&key_path) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn is_provider_registered_in_registry(&self, _guid: &str) -> bool {
        true // Non-Windows always returns true
    }

    /// Check TraceLogging provider tampering
    #[cfg(target_os = "windows")]
    fn check_tracelogging_tampering(&self, timestamp: u64) -> Option<EtwTamperingDetection> {
        // TraceLogging uses _tlgDefineProvider which embeds metadata
        // Check if TraceLogging registration functions are patched

        if let Some(bytes) = self.read_function_bytes("ntdll.dll", "TlgWrite", 16) {
            if self.is_patched(&bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "TlgWrite".to_string());
                details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..8]));

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::TraceLoggingTampering,
                    confidence: 0.85,
                    mitre_technique: "T1562.006".to_string(),
                    description: "TraceLogging TlgWrite function appears to be patched".to_string(),
                    details,
                    timestamp,
                });
            }
        }

        // Also check ntdll!_TlgDefineProvider if accessible
        if let Some(bytes) = self.read_function_bytes("ntdll.dll", "_TlgDefineProvider", 16) {
            if self.is_patched(&bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "_TlgDefineProvider".to_string());
                details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..8]));

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::TraceLoggingTampering,
                    confidence: 0.80,
                    mitre_technique: "T1562.006".to_string(),
                    description: "TraceLogging provider definition function appears to be patched"
                        .to_string(),
                    details,
                    timestamp,
                });
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    fn check_tracelogging_tampering(&self, _timestamp: u64) -> Option<EtwTamperingDetection> {
        None
    }

    /// Check EventWrite hooking/bypass across kernel32 and ntdll
    #[cfg(target_os = "windows")]
    fn check_eventwrite_hooks(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        let mut detections = Vec::new();

        // Check kernelbase!EventWrite (user-mode entry point)
        if let Some(kb_bytes) = self.read_function_bytes("kernelbase.dll", "EventWrite", 32) {
            if self.is_patched(&kb_bytes) || self.is_hooked(&kb_bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "kernelbase!EventWrite".to_string());
                details.insert(
                    "first_bytes".to_string(),
                    format!("{:02X?}", &kb_bytes[..16]),
                );

                detections.push(EtwTamperingDetection {
                    detection_type: EtwTamperingType::EventWriteHook,
                    confidence: 0.90,
                    mitre_technique: "T1562.006".to_string(),
                    description: "kernelbase!EventWrite appears to be hooked".to_string(),
                    details,
                    timestamp,
                });
            }
        }

        // Compare ntdll EventWrite functions against baseline
        let baseline = self.baseline_functions.read();
        for func_name in [
            "EtwEventWrite",
            "EtwEventWriteFull",
            "EtwEventWriteTransfer",
        ]
        .iter()
        {
            if let Some(baseline_bytes) = baseline.get(*func_name) {
                if let Some(current_bytes) = self.read_function_bytes("ntdll.dll", func_name, 32) {
                    if !self.bytes_match(baseline_bytes, &current_bytes) {
                        let mut details = HashMap::new();
                        details.insert("function".to_string(), func_name.to_string());
                        details.insert(
                            "baseline_bytes".to_string(),
                            format!("{:02X?}", &baseline_bytes[..8]),
                        );
                        details.insert(
                            "current_bytes".to_string(),
                            format!("{:02X?}", &current_bytes[..8]),
                        );

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::EventWriteHook,
                            confidence: 0.95,
                            mitre_technique: "T1562.006".to_string(),
                            description: format!("{} bytes differ from baseline", func_name),
                            details,
                            timestamp,
                        });
                    }
                }
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn check_eventwrite_hooks(&self, _timestamp: u64) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Check if function bytes indicate a hook (different from patch)
    fn is_hooked(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 16 {
            return false;
        }

        // Pattern 1: Far jump (jmp qword ptr [rip+offset])
        // 0xFF 0x25 followed by 4-byte offset
        if bytes[0] == 0xFF && bytes[1] == 0x25 {
            return true;
        }

        // Pattern 2: mov rax, addr; jmp rax
        // 48 B8 xx xx xx xx xx xx xx xx FF E0
        if bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0 {
            return true;
        }

        // Pattern 3: push addr (low); mov dword [rsp+4], addr (high); ret
        // Commonly used for 64-bit jumps
        if bytes[0] == 0x68 && bytes[5] == 0xC7 && bytes[6] == 0x44 && bytes[7] == 0x24 {
            return true;
        }

        // Pattern 4: mov r11, addr; jmp r11
        // 49 BB xx xx xx xx xx xx xx xx 41 FF E3
        if bytes[0] == 0x49 && bytes[1] == 0xBB && bytes[10] == 0x41 && bytes[11] == 0xFF {
            return true;
        }

        false
    }

    /// Compare two byte sequences with some tolerance for relocations
    fn bytes_match(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        // Check first 8 bytes exactly (prologue should match)
        if a.len() >= 8 {
            for i in 0..8 {
                if a[i] != b[i] {
                    return false;
                }
            }
        }

        true
    }

    /// Check ETW session manipulation
    #[cfg(target_os = "windows")]
    fn check_session_manipulation(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut detections = Vec::new();

        // Check for Autologger sessions being disabled
        let autologger_path = "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";
        if let Ok(autologger_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(autologger_path)
        {
            // Check critical autologger sessions
            let critical_sessions = [
                "EventLog-Security",
                "EventLog-System",
                "EventLog-Application",
                "DefenderApiLogger",
                "DefenderAuditLogger",
                "DiagTrack",
            ];

            for session_name in critical_sessions.iter() {
                match autologger_key.open_subkey(session_name) {
                    Ok(session_key) => {
                        // Check if session is disabled (Start = 0)
                        if let Ok(start_value) = session_key.get_value::<u32, _>("Start") {
                            if start_value == 0 {
                                let mut details = HashMap::new();
                                details
                                    .insert("session_name".to_string(), session_name.to_string());
                                details.insert("status".to_string(), "Disabled".to_string());

                                detections.push(EtwTamperingDetection {
                                    detection_type: EtwTamperingType::SessionManipulation,
                                    confidence: 0.85,
                                    mitre_technique: "T1562.006".to_string(),
                                    description: format!(
                                        "Critical ETW Autologger session '{}' is disabled",
                                        session_name
                                    ),
                                    details,
                                    timestamp,
                                });
                            }
                        }
                    }
                    Err(_) => {
                        // Session key missing entirely
                        let mut details = HashMap::new();
                        details.insert("session_name".to_string(), session_name.to_string());
                        details.insert("status".to_string(), "Missing".to_string());

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::SessionManipulation,
                            confidence: 0.75,
                            mitre_technique: "T1562.006".to_string(),
                            description: format!(
                                "Critical ETW Autologger session '{}' registry key is missing",
                                session_name
                            ),
                            details,
                            timestamp,
                        });
                    }
                }
            }
        }

        // Check NtTraceControl for manipulation
        if let Some(bytes) = self.read_function_bytes("ntdll.dll", "NtTraceControl", 32) {
            if self.is_patched(&bytes) || self.is_hooked(&bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "NtTraceControl".to_string());
                details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..16]));

                detections.push(EtwTamperingDetection {
                    detection_type: EtwTamperingType::SessionManipulation,
                    confidence: 0.90,
                    mitre_technique: "T1562.006".to_string(),
                    description:
                        "NtTraceControl appears to be tampered - session control compromised"
                            .to_string(),
                    details,
                    timestamp,
                });
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn check_session_manipulation(&self, _timestamp: u64) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Check Threat Intelligence ETW provider status
    #[cfg(target_os = "windows")]
    fn check_threat_intel_provider(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut detections = Vec::new();

        // Microsoft-Windows-Threat-Intelligence provider GUID
        let ti_guid = "f4e1897c-bb5d-5668-f1d8-040f4d8dd344";
        let ti_publisher_path = format!(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{{{}}}",
            ti_guid
        );

        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&ti_publisher_path) {
            Ok(ti_key) => {
                // Check if the provider is enabled
                if let Ok(enabled) = ti_key.get_value::<u32, _>("Enabled") {
                    if enabled == 0 {
                        let mut details = HashMap::new();
                        details.insert(
                            "provider".to_string(),
                            "Microsoft-Windows-Threat-Intelligence".to_string(),
                        );
                        details.insert("guid".to_string(), ti_guid.to_string());
                        details.insert("status".to_string(), "Explicitly disabled".to_string());

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::ThreatIntelProviderDisabled,
                            confidence: 0.98,
                            mitre_technique: "T1562.006".to_string(),
                            description: "Microsoft-Windows-Threat-Intelligence ETW provider is explicitly disabled".to_string(),
                            details,
                            timestamp,
                        });
                    }
                }

                // Check for MessageFileName tampering (DLL path modification)
                if let Ok(msg_file) = ti_key.get_value::<String, _>("MessageFileName") {
                    if !msg_file.to_lowercase().contains("system32") {
                        let mut details = HashMap::new();
                        details.insert(
                            "provider".to_string(),
                            "Microsoft-Windows-Threat-Intelligence".to_string(),
                        );
                        details.insert("message_file".to_string(), msg_file.clone());

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::ThreatIntelProviderTargeted,
                            confidence: 0.90,
                            mitre_technique: "T1562.006".to_string(),
                            description: "Threat Intelligence provider MessageFileName points to unexpected location".to_string(),
                            details,
                            timestamp,
                        });
                    }
                }
            }
            Err(_) => {
                // Provider registry key is missing entirely - very suspicious
                let mut details = HashMap::new();
                details.insert(
                    "provider".to_string(),
                    "Microsoft-Windows-Threat-Intelligence".to_string(),
                );
                details.insert("guid".to_string(), ti_guid.to_string());
                details.insert("status".to_string(), "Registry key missing".to_string());

                detections.push(EtwTamperingDetection {
                    detection_type: EtwTamperingType::ThreatIntelProviderDisabled,
                    confidence: 0.95,
                    mitre_technique: "T1562.006".to_string(),
                    description:
                        "Microsoft-Windows-Threat-Intelligence ETW provider registry key is missing"
                            .to_string(),
                    details,
                    timestamp,
                });
            }
        }

        // Also check if any process is trying to access TI provider handles
        // by monitoring NtTraceControl calls with TI-related session GUIDs
        // This would require ETW monitoring itself, which is a chicken-and-egg problem

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn check_threat_intel_provider(&self, _timestamp: u64) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Check EtwNotificationRegister callback removal
    #[cfg(target_os = "windows")]
    fn check_notification_callbacks(&self, timestamp: u64) -> Option<EtwTamperingDetection> {
        // EtwNotificationRegister allows processes to receive ETW notifications
        // Attackers may patch this to prevent security tools from receiving alerts

        if let Some(bytes) = self.read_function_bytes("ntdll.dll", "EtwNotificationRegister", 32) {
            if self.is_patched(&bytes) {
                let mut details = HashMap::new();
                details.insert(
                    "function".to_string(),
                    "EtwNotificationRegister".to_string(),
                );
                details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..16]));

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::NotificationCallbackRemoved,
                    confidence: 0.95,
                    mitre_technique: "T1562.006".to_string(),
                    description:
                        "EtwNotificationRegister is patched - callback registration disabled"
                            .to_string(),
                    details,
                    timestamp,
                });
            }
        }

        // Also check EtwNotificationUnregister for abuse
        if let Some(bytes) = self.read_function_bytes("ntdll.dll", "EtwNotificationUnregister", 32)
        {
            if self.is_instrumented(&bytes) {
                let mut details = HashMap::new();
                details.insert(
                    "function".to_string(),
                    "EtwNotificationUnregister".to_string(),
                );
                details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..16]));

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::NotificationCallbackRemoved,
                    confidence: 0.85,
                    mitre_technique: "T1562.006".to_string(),
                    description:
                        "EtwNotificationUnregister appears instrumented for callback enumeration"
                            .to_string(),
                    details,
                    timestamp,
                });
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    fn check_notification_callbacks(&self, _timestamp: u64) -> Option<EtwTamperingDetection> {
        None
    }

    /// Check for private logger session hijacking
    #[cfg(target_os = "windows")]
    fn check_private_logger_hijacking(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut detections = Vec::new();

        // Private loggers are used by security tools for real-time monitoring
        // Check for suspicious modifications to private logger configurations

        let private_logger_path = "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";
        if let Ok(logger_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(private_logger_path)
        {
            // Enumerate all loggers
            for session_name in logger_key.enum_keys().filter_map(|k| k.ok()) {
                if let Ok(session_key) = logger_key.open_subkey(&session_name) {
                    // Check for private logger flag manipulation
                    if let Ok(buffer_size) = session_key.get_value::<u32, _>("BufferSize") {
                        // Suspiciously small buffer sizes can cause event loss
                        if buffer_size < 64 && buffer_size > 0 {
                            let mut details = HashMap::new();
                            details.insert("session_name".to_string(), session_name.clone());
                            details.insert("buffer_size".to_string(), buffer_size.to_string());

                            detections.push(EtwTamperingDetection {
                                detection_type: EtwTamperingType::PrivateLoggerHijack,
                                confidence: 0.70,
                                mitre_technique: "T1562.006".to_string(),
                                description: format!(
                                    "Logger '{}' has suspiciously small buffer size ({}KB)",
                                    session_name, buffer_size
                                ),
                                details,
                                timestamp,
                            });
                        }
                    }

                    // Check for FileMode manipulation (circular mode can lose events)
                    if let Ok(file_mode) = session_key.get_value::<u32, _>("LogFileMode") {
                        // EVENT_TRACE_FILE_MODE_CIRCULAR = 0x2
                        // Combined with small buffer = potential event loss attack
                        if file_mode & 0x2 != 0 {
                            if let Ok(max_size) = session_key.get_value::<u32, _>("MaxFileSize") {
                                if max_size < 10 && max_size > 0 {
                                    let mut details = HashMap::new();
                                    details
                                        .insert("session_name".to_string(), session_name.clone());
                                    details.insert("file_mode".to_string(), "Circular".to_string());
                                    details.insert("max_size_mb".to_string(), max_size.to_string());

                                    detections.push(EtwTamperingDetection {
                                        detection_type: EtwTamperingType::PrivateLoggerHijack,
                                        confidence: 0.75,
                                        mitre_technique: "T1562.006".to_string(),
                                        description: format!(
                                            "Logger '{}' has circular mode with tiny max size ({}MB) - events will be lost",
                                            session_name, max_size
                                        ),
                                        details,
                                        timestamp,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn check_private_logger_hijacking(&self, _timestamp: u64) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Check for registry tampering affecting ETW providers
    #[cfg(target_os = "windows")]
    fn check_registry_tampering(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut detections = Vec::new();

        // Check WINEVT\Channels for suspicious modifications
        let channels_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels";
        if let Ok(channels_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(channels_path) {
            // Critical channels that should always be enabled
            let critical_channels = [
                "Microsoft-Windows-Security-Auditing/Audit",
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-Windows Defender/Operational",
            ];

            for channel_name in critical_channels.iter() {
                if let Ok(channel_key) = channels_key.open_subkey(channel_name) {
                    // Check if channel is disabled
                    if let Ok(enabled) = channel_key.get_value::<u32, _>("Enabled") {
                        if enabled == 0 {
                            let mut details = HashMap::new();
                            details.insert("channel".to_string(), channel_name.to_string());
                            details.insert("status".to_string(), "Disabled".to_string());

                            detections.push(EtwTamperingDetection {
                                detection_type: EtwTamperingType::RegistryTampering,
                                confidence: 0.85,
                                mitre_technique: "T1562.006".to_string(),
                                description: format!(
                                    "Critical ETW channel '{}' is disabled",
                                    channel_name
                                ),
                                details,
                                timestamp,
                            });
                        }
                    }

                    // Check for suspiciously small max size
                    if let Ok(max_size) = channel_key.get_value::<u32, _>("MaxSize") {
                        if max_size < 1048576 && max_size > 0 {
                            // Less than 1MB
                            let mut details = HashMap::new();
                            details.insert("channel".to_string(), channel_name.to_string());
                            details.insert("max_size_bytes".to_string(), max_size.to_string());

                            detections.push(EtwTamperingDetection {
                                detection_type: EtwTamperingType::RegistryTampering,
                                confidence: 0.70,
                                mitre_technique: "T1562.006".to_string(),
                                description: format!(
                                    "ETW channel '{}' has suspiciously small max size ({} bytes)",
                                    channel_name, max_size
                                ),
                                details,
                                timestamp,
                            });
                        }
                    }
                }
            }
        }

        // Check for modified EventLog service configuration
        let eventlog_path = "SYSTEM\\CurrentControlSet\\Services\\EventLog";
        if let Ok(eventlog_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(eventlog_path) {
            // Check Security log specifically
            if let Ok(security_key) = eventlog_key.open_subkey("Security") {
                if let Ok(max_size) = security_key.get_value::<u32, _>("MaxSize") {
                    if max_size < 5242880 {
                        // Less than 5MB
                        let mut details = HashMap::new();
                        details.insert("log".to_string(), "Security".to_string());
                        details.insert("max_size".to_string(), format!("{} bytes", max_size));

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::RegistryTampering,
                            confidence: 0.75,
                            mitre_technique: "T1562.006".to_string(),
                            description: format!(
                                "Security Event Log has small max size ({} bytes)",
                                max_size
                            ),
                            details,
                            timestamp,
                        });
                    }
                }

                // Check retention policy
                if let Ok(retention) = security_key.get_value::<u32, _>("Retention") {
                    if retention == 0 {
                        let mut details = HashMap::new();
                        details.insert("log".to_string(), "Security".to_string());
                        details.insert("retention".to_string(), "Overwrite as needed".to_string());

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::RegistryTampering,
                            confidence: 0.60,
                            mitre_technique: "T1562.006".to_string(),
                            description:
                                "Security Event Log set to overwrite events (no retention)"
                                    .to_string(),
                            details,
                            timestamp,
                        });
                    }
                }
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn check_registry_tampering(&self, _timestamp: u64) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Check for syscall hooks on ETW-related functions
    #[cfg(target_os = "windows")]
    fn check_syscall_hooks(&self, timestamp: u64) -> Vec<EtwTamperingDetection> {
        let mut detections = Vec::new();

        // ETW functions that use syscalls
        let syscall_functions = [
            ("NtTraceEvent", "Primary ETW event write syscall"),
            ("NtTraceControl", "ETW session control syscall"),
            (
                "NtQuerySystemInformation",
                "System info (used for ETW enumeration)",
            ),
        ];

        for (func_name, description) in syscall_functions.iter() {
            if let Some(bytes) = self.read_function_bytes("ntdll.dll", func_name, 32) {
                // Check for syscall stub tampering
                // Normal: mov r10, rcx; mov eax, syscall_num; syscall; ret
                // 4C 8B D1 B8 xx xx xx xx 0F 05 C3

                if bytes.len() >= 12 {
                    let has_valid_stub = bytes[0] == 0x4C
                        && bytes[1] == 0x8B
                        && bytes[2] == 0xD1  // mov r10, rcx
                        && bytes[3] == 0xB8  // mov eax, imm32
                        && bytes[8] == 0x0F
                        && bytes[9] == 0x05  // syscall
                        && (bytes[10] == 0xC3 || bytes[10] == 0xC2); // ret

                    if !has_valid_stub {
                        // Check what kind of tampering
                        let tamper_type = if bytes[0] == 0xE9 || bytes[0] == 0xFF {
                            "Jump/hook detected"
                        } else if bytes[0] == 0x4C && bytes[3] != 0xB8 {
                            "Syscall number obfuscation"
                        } else if bytes[8] != 0x0F || bytes[9] != 0x05 {
                            "Syscall instruction replaced"
                        } else {
                            "Unknown modification"
                        };

                        let mut details = HashMap::new();
                        details.insert("function".to_string(), func_name.to_string());
                        details.insert("description".to_string(), description.to_string());
                        details.insert("tampering_type".to_string(), tamper_type.to_string());
                        details.insert("first_bytes".to_string(), format!("{:02X?}", &bytes[..12]));

                        detections.push(EtwTamperingDetection {
                            detection_type: EtwTamperingType::SyscallHook,
                            confidence: 0.90,
                            mitre_technique: "T1562.006".to_string(),
                            description: format!(
                                "{} syscall stub has been modified: {}",
                                func_name, tamper_type
                            ),
                            details,
                            timestamp,
                        });
                    }
                }
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn check_syscall_hooks(&self, _timestamp: u64) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Get status of critical ETW providers
    #[cfg(target_os = "windows")]
    pub fn get_critical_provider_status(&self) -> Vec<ProviderState> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        critical_providers::all_critical_guids()
            .iter()
            .map(|guid| {
                let is_registered = self.is_provider_registered_in_registry(guid);
                ProviderState {
                    guid: guid.to_string(),
                    name: critical_providers::name_from_guid(guid).to_string(),
                    is_registered,
                    handle: None,
                    last_check: timestamp,
                }
            })
            .collect()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_critical_provider_status(&self) -> Vec<ProviderState> {
        Vec::new()
    }

    /// Get status of ETW sessions
    #[cfg(target_os = "windows")]
    pub fn get_session_status(&self) -> Vec<EtwSessionInfo> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut sessions = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let autologger_path = "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";
        if let Ok(autologger_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(autologger_path)
        {
            for session_name in autologger_key.enum_keys().filter_map(|k| k.ok()) {
                if let Ok(session_key) = autologger_key.open_subkey(&session_name) {
                    let is_running = session_key
                        .get_value::<u32, _>("Start")
                        .map(|v| v != 0)
                        .unwrap_or(false);

                    let guid = session_key.get_value::<String, _>("GUID").ok();

                    sessions.push(EtwSessionInfo {
                        name: session_name,
                        guid,
                        is_running,
                        last_seen: timestamp,
                        provider_count: 0, // Would need enumeration to determine
                    });
                }
            }
        }

        sessions
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_session_status(&self) -> Vec<EtwSessionInfo> {
        Vec::new()
    }

    /// Check integrity of all ETW functions against baseline
    #[cfg(target_os = "windows")]
    pub fn check_all_function_integrity(&self) -> HashMap<String, bool> {
        let mut integrity = HashMap::new();
        let baseline = self.baseline_functions.read();

        for (func_name, baseline_bytes) in baseline.iter() {
            if let Some(current_bytes) =
                self.read_function_bytes("ntdll.dll", func_name, baseline_bytes.len())
            {
                integrity.insert(
                    func_name.clone(),
                    self.bytes_match(baseline_bytes, &current_bytes),
                );
            } else {
                integrity.insert(func_name.clone(), false);
            }
        }

        integrity
    }

    #[cfg(not(target_os = "windows"))]
    pub fn check_all_function_integrity(&self) -> HashMap<String, bool> {
        HashMap::new()
    }

    /// Calculate overall ETW health score (0.0 = compromised, 1.0 = healthy)
    pub fn calculate_overall_health(&self) -> f32 {
        let detections = self.detections.read();

        if detections.is_empty() {
            return 1.0;
        }

        // Weight detections by severity
        let total_severity: f32 = detections.iter().map(|d| d.detection_type.severity()).sum();

        // Cap at 1.0 total severity impact
        let severity_impact = (total_severity / 2.0).min(1.0);

        1.0 - severity_impact
    }

    /// Check EtwEventWrite for patches
    #[cfg(target_os = "windows")]
    fn check_etw_eventwrite(&self, timestamp: u64) -> Option<EtwTamperingDetection> {
        unsafe {
            let ntdll = GetModuleHandleW(windows::core::w!("ntdll.dll")).ok()?;
            let func_name = PCSTR::from_raw(b"EtwEventWrite\0".as_ptr());
            let func_addr = GetProcAddress(ntdll, func_name)?;

            let func_ptr = func_addr as *const u8;
            let first_bytes: [u8; 16] = std::ptr::read(func_ptr as *const [u8; 16]);

            // Check for common patch patterns
            if self.is_patched(&first_bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "EtwEventWrite".to_string());
                details.insert(
                    "first_bytes".to_string(),
                    format!("{:02X?}", &first_bytes[..8]),
                );

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::FunctionPatch,
                    confidence: 0.95,
                    mitre_technique: "T1562.006".to_string(),
                    description: "EtwEventWrite function appears to be patched".to_string(),
                    details,
                    timestamp,
                });
            }

            // Check for NOP sled
            if self.is_nop_sled(&first_bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "EtwEventWrite".to_string());
                details.insert("pattern".to_string(), "NOP sled detected".to_string());

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::NopSled,
                    confidence: 0.90,
                    mitre_technique: "T1562.006".to_string(),
                    description: "EtwEventWrite function contains NOP sled".to_string(),
                    details,
                    timestamp,
                });
            }
        }

        None
    }

    /// Check NtTraceEvent for patches
    #[cfg(target_os = "windows")]
    fn check_nt_trace_event(&self, timestamp: u64) -> Option<EtwTamperingDetection> {
        unsafe {
            let ntdll = GetModuleHandleW(windows::core::w!("ntdll.dll")).ok()?;
            let func_name = PCSTR::from_raw(b"NtTraceEvent\0".as_ptr());
            let func_addr = GetProcAddress(ntdll, func_name)?;

            let func_ptr = func_addr as *const u8;
            let first_bytes: [u8; 16] = std::ptr::read(func_ptr as *const [u8; 16]);

            if self.is_patched(&first_bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "NtTraceEvent".to_string());
                details.insert(
                    "first_bytes".to_string(),
                    format!("{:02X?}", &first_bytes[..8]),
                );

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::FunctionPatch,
                    confidence: 0.90,
                    mitre_technique: "T1562.006".to_string(),
                    description: "NtTraceEvent function appears to be patched".to_string(),
                    details,
                    timestamp,
                });
            }
        }

        None
    }

    /// Check AMSI for patches
    #[cfg(target_os = "windows")]
    fn check_amsi_scan_buffer(&self, timestamp: u64) -> Option<EtwTamperingDetection> {
        unsafe {
            let amsi = GetModuleHandleW(windows::core::w!("amsi.dll")).ok()?;
            let func_name = PCSTR::from_raw(b"AmsiScanBuffer\0".as_ptr());
            let func_addr = GetProcAddress(amsi, func_name)?;

            let func_ptr = func_addr as *const u8;
            let first_bytes: [u8; 16] = std::ptr::read(func_ptr as *const [u8; 16]);

            // Check for common AMSI bypass patterns
            // Pattern 1: mov eax, 0x80070057 (E_INVALIDARG) + ret
            // Pattern 2: xor eax, eax + ret (return S_OK always)
            let is_amsi_bypass = first_bytes[0] == 0xB8 || // mov eax, imm32
                                 first_bytes[0] == 0x31 || // xor
                                 first_bytes[0] == 0x33 || // xor
                                 first_bytes[0] == 0xC3; // ret

            if is_amsi_bypass {
                let mut details = HashMap::new();
                details.insert("function".to_string(), "AmsiScanBuffer".to_string());
                details.insert(
                    "first_bytes".to_string(),
                    format!("{:02X?}", &first_bytes[..8]),
                );

                return Some(EtwTamperingDetection {
                    detection_type: EtwTamperingType::AmsiBypass,
                    confidence: 0.95,
                    mitre_technique: "T1562.001".to_string(),
                    description: "AmsiScanBuffer function appears to be patched".to_string(),
                    details,
                    timestamp,
                });
            }
        }

        None
    }

    /// Check if bytes indicate a patched function
    fn is_patched(&self, bytes: &[u8]) -> bool {
        // Check for common patch patterns

        // Pattern 1: ret (0xC3) at start - immediate return
        if bytes[0] == 0xC3 {
            return true;
        }

        // Pattern 2: xor eax, eax + ret (return 0)
        if bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return true;
        }
        if bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return true;
        }

        // Pattern 3: mov eax, imm32 + ret (return specific value)
        if bytes[0] == 0xB8 && bytes[5] == 0xC3 {
            return true;
        }

        // Pattern 4: jmp to somewhere else (hook)
        if bytes[0] == 0xE9 || bytes[0] == 0xFF {
            return true;
        }

        // Pattern 5: push addr + ret (indirect jump)
        if bytes[0] == 0x68 && bytes[5] == 0xC3 {
            return true;
        }

        false
    }

    /// Check for NOP sled pattern
    fn is_nop_sled(&self, bytes: &[u8]) -> bool {
        // Count NOPs in first 8 bytes
        let nop_count = bytes.iter().take(8).filter(|&&b| b == 0x90).count();
        nop_count >= 4
    }

    /// Scan a specific process for ETW tampering
    #[cfg(target_os = "windows")]
    pub fn scan_process(&self, pid: u32) -> Vec<EtwTamperingDetection> {
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut detections = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        unsafe {
            let process = match OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            {
                Ok(h) => h,
                Err(_) => return detections,
            };

            // Get ntdll base address in target process
            let mut modules: [HMODULE; 1024] = [HMODULE::default(); 1024];
            let mut needed: u32 = 0;

            if EnumProcessModulesEx(
                process,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
            .is_ok()
            {
                let count = (needed as usize) / std::mem::size_of::<HMODULE>();

                for i in 0..count {
                    let mut name_buf = [0u16; 260];
                    if GetModuleFileNameExW(process, modules[i], &mut name_buf) > 0 {
                        let name = String::from_utf16_lossy(&name_buf);
                        let name_lower = name.to_lowercase();

                        if name_lower.contains("ntdll.dll") {
                            // Found ntdll, check EtwEventWrite
                            if let Some(detection) = self.check_remote_function(
                                process,
                                modules[i],
                                "EtwEventWrite",
                                timestamp,
                                pid,
                            ) {
                                detections.push(detection);
                            }
                        }

                        if name_lower.contains("amsi.dll") {
                            // Found amsi, check AmsiScanBuffer
                            if let Some(detection) = self.check_remote_function(
                                process,
                                modules[i],
                                "AmsiScanBuffer",
                                timestamp,
                                pid,
                            ) {
                                detections.push(detection);
                            }
                        }
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(process);
        }

        detections
    }

    /// Check a function in a remote process
    #[cfg(target_os = "windows")]
    fn check_remote_function(
        &self,
        process: windows::Win32::Foundation::HANDLE,
        module: HMODULE,
        func_name: &str,
        timestamp: u64,
        pid: u32,
    ) -> Option<EtwTamperingDetection> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        unsafe {
            // Get our local copy of the function address as an offset
            let local_module = match func_name {
                "EtwEventWrite" => GetModuleHandleW(windows::core::w!("ntdll.dll")).ok()?,
                "AmsiScanBuffer" => GetModuleHandleW(windows::core::w!("amsi.dll")).ok()?,
                _ => return None,
            };

            let func_name_cstr = format!("{}\0", func_name);
            let func_name_pcstr = PCSTR::from_raw(func_name_cstr.as_ptr());
            let local_addr = GetProcAddress(local_module, func_name_pcstr)?;

            // Calculate offset from module base
            let offset = (local_addr as usize) - (local_module.0 as usize);

            // Calculate remote function address
            let remote_addr = (module.0 as usize) + offset;

            // Read remote function bytes
            let mut remote_bytes = [0u8; 16];
            let mut bytes_read: usize = 0;

            if ReadProcessMemory(
                process,
                remote_addr as *const std::ffi::c_void,
                remote_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                16,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read < 8
            {
                return None;
            }

            // Check for patches
            if self.is_patched(&remote_bytes) {
                let mut details = HashMap::new();
                details.insert("function".to_string(), func_name.to_string());
                details.insert("pid".to_string(), pid.to_string());
                details.insert(
                    "first_bytes".to_string(),
                    format!("{:02X?}", &remote_bytes[..8]),
                );

                let detection_type = if func_name == "AmsiScanBuffer" {
                    EtwTamperingType::AmsiBypass
                } else {
                    EtwTamperingType::FunctionPatch
                };

                return Some(EtwTamperingDetection {
                    detection_type,
                    confidence: 0.90,
                    mitre_technique: detection_type.mitre_technique().to_string(),
                    description: format!("{} appears patched in PID {}", func_name, pid),
                    details,
                    timestamp,
                });
            }
        }

        None
    }

    /// Get all detections
    pub fn get_detections(&self) -> Vec<EtwTamperingDetection> {
        self.detections.read().clone()
    }

    /// Clear detections
    pub fn clear_detections(&self) {
        self.detections.write().clear();
    }

    /// Linux/macOS stub
    #[cfg(not(target_os = "windows"))]
    pub fn scan_current_process(&self) -> Vec<EtwTamperingDetection> {
        // ETW is Windows-specific
        Vec::new()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_process(&self, _pid: u32) -> Vec<EtwTamperingDetection> {
        Vec::new()
    }

    /// Non-Windows deep_scan stub
    #[cfg(not(target_os = "windows"))]
    pub fn deep_scan(&self) -> EtwScanReport {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        EtwScanReport {
            timestamp,
            detections: Vec::new(),
            provider_status: Vec::new(),
            session_status: Vec::new(),
            function_integrity: HashMap::new(),
            overall_health: 1.0,
        }
    }
}

impl Default for EtwTamperingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_detection() {
        let detector = EtwTamperingDetector::new();

        // ret instruction
        assert!(detector.is_patched(&[0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

        // xor eax, eax + ret
        assert!(detector.is_patched(&[0x33, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00]));

        // jmp
        assert!(detector.is_patched(&[0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

        // Normal function prologue (should not be detected as patch)
        assert!(!detector.is_patched(&[0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49]));
    }

    #[test]
    fn test_nop_sled_detection() {
        let detector = EtwTamperingDetector::new();

        // NOP sled
        assert!(detector.is_nop_sled(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]));

        // Normal code
        assert!(!detector.is_nop_sled(&[0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49]));
    }

    #[test]
    fn test_hook_detection() {
        let detector = EtwTamperingDetector::new();

        // Far jump (jmp qword ptr [rip+offset])
        assert!(detector.is_hooked(&[
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ]));

        // mov rax, addr; jmp rax
        assert!(detector.is_hooked(&[
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x00, 0x00,
            0x00, 0x00
        ]));

        // Normal code should not be detected as hook
        assert!(!detector.is_hooked(&[
            0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x73, 0x10, 0x49, 0x89, 0x7B,
            0x18, 0x55
        ]));
    }

    #[test]
    fn test_instrumentation_detection() {
        let detector = EtwTamperingDetector::new();

        // Multiple push instructions (common in detours)
        assert!(detector.is_instrumented(&[
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ]));

        // mov [rsp], ... pattern
        assert!(detector.is_instrumented(&[
            0x48, 0x89, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ]));

        // Normal syscall stub should not be detected
        assert!(!detector.is_instrumented(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x23, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x00, 0x00, 0x00,
            0x00, 0x00
        ]));
    }

    #[test]
    fn test_tampering_type_severity() {
        // Critical severity types
        assert_eq!(
            EtwTamperingType::ThreatIntelProviderDisabled.severity(),
            1.0
        );
        assert!(EtwTamperingType::ThreatIntelProviderTargeted.severity() >= 0.90);
        assert!(EtwTamperingType::NotificationCallbackRemoved.severity() >= 0.90);

        // High severity types
        assert!(EtwTamperingType::FunctionPatch.severity() >= 0.85);
        assert!(EtwTamperingType::EventWriteHook.severity() >= 0.85);

        // Medium severity types
        assert!(EtwTamperingType::ProviderUnregistered.severity() >= 0.50);
    }

    #[test]
    fn test_tampering_type_mitre_technique() {
        // All ETW tampering should map to T1562.006 except AMSI
        assert_eq!(
            EtwTamperingType::FunctionPatch.mitre_technique(),
            "T1562.006"
        );
        assert_eq!(
            EtwTamperingType::ProviderDisabled.mitre_technique(),
            "T1562.006"
        );
        assert_eq!(
            EtwTamperingType::ThreatIntelProviderDisabled.mitre_technique(),
            "T1562.006"
        );
        assert_eq!(EtwTamperingType::SyscallHook.mitre_technique(), "T1562.006");

        // AMSI bypass is T1562.001
        assert_eq!(EtwTamperingType::AmsiBypass.mitre_technique(), "T1562.001");
    }

    #[test]
    fn test_bytes_match() {
        let detector = EtwTamperingDetector::new();

        // Identical bytes should match
        let bytes1 = vec![0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49];
        let bytes2 = vec![0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49];
        assert!(detector.bytes_match(&bytes1, &bytes2));

        // Different bytes should not match
        let bytes3 = vec![0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!detector.bytes_match(&bytes1, &bytes3));
    }

    #[test]
    fn test_overall_health_calculation() {
        let detector = EtwTamperingDetector::new();

        // With no detections, health should be 1.0
        assert_eq!(detector.calculate_overall_health(), 1.0);
    }

    #[test]
    fn test_critical_providers() {
        // Verify provider GUIDs are defined
        assert!(!critical_providers::THREAT_INTEL_GUID.is_empty());
        assert!(!critical_providers::SECURITY_AUDITING_GUID.is_empty());
        assert!(!critical_providers::AMSI_GUID.is_empty());

        // Verify all critical GUIDs are returned
        let all_guids = critical_providers::all_critical_guids();
        assert!(all_guids.len() >= 10);

        // Verify name lookup works
        let ti_name = critical_providers::name_from_guid(critical_providers::THREAT_INTEL_GUID);
        assert_eq!(ti_name, "Microsoft-Windows-Threat-Intelligence");
    }

    #[test]
    fn test_scan_report_methods() {
        let report = EtwScanReport {
            timestamp: 0,
            detections: vec![],
            provider_status: vec![ProviderState {
                guid: "test-guid".to_string(),
                name: "Test Provider".to_string(),
                is_registered: true,
                handle: None,
                last_check: 0,
            }],
            session_status: vec![],
            function_integrity: HashMap::new(),
            overall_health: 1.0,
        };

        // No critical issues with empty detections
        assert!(!report.has_critical_issues());

        // No unregistered providers when all are registered
        assert!(report.unregistered_providers().is_empty());

        // Threat intel not compromised
        assert!(!report.is_threat_intel_compromised());

        // Summary should be generated
        let summary = report.summary();
        assert!(summary.contains("ETW Health: 100%"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_scan_current_process() {
        let detector = EtwTamperingDetector::new();
        let detections = detector.scan_current_process();
        // In a normal process, should have no detections
        // (unless running in a compromised environment)
        println!("Found {} detections", detections.len());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_deep_scan() {
        let detector = EtwTamperingDetector::new();
        let report = detector.deep_scan();

        // Should return a valid report
        assert!(report.timestamp > 0);
        assert!(report.overall_health >= 0.0 && report.overall_health <= 1.0);

        // Print report summary
        println!("Deep scan report: {}", report.summary());
    }
}
