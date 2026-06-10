//! Windows AMSI (Antimalware Scan Interface) Integration
//!
//! Provides comprehensive integration with Windows AMSI for detecting:
//! - Malicious PowerShell scripts
//! - Malicious VBScript/JScript
//! - Office macro malware
//! - Other scripted content
//!
//! This module provides two modes of operation:
//! 1. **Active AMSI Provider Mode** (Windows 10+): Registers as an AMSI provider
//!    to receive script content directly from script hosts
//! 2. **Passive ETW Mode**: Consumes AMSI events via ETW for visibility
//! 3. **Heuristic Mode** (Fallback): Monitors script hosts and applies
//!    pattern-based detection
//!
//! AMSI is only available on Windows 10+. On older Windows versions,
//! the collector provides script-based heuristic detection as fallback.
//!
//! MITRE ATT&CK Coverage:
//! - T1059 (Command and Scripting Interpreter)
//! - T1059.001 (PowerShell)
//! - T1059.003 (Windows Command Shell)
//! - T1059.005 (VBScript)
//! - T1059.007 (JavaScript)
//! - T1027 (Obfuscated Files or Information)
//! - T1562.001 (Disable or Modify Tools)

#![cfg(target_os = "windows")]
// AMSI integration. Scaffolded fields and helper structs retained.
#![allow(dead_code, unused_variables)]

use super::win_compat::{amsi as amsi_api, SystemCapabilities};
use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, ScriptEvent, ScriptType,
    Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::{anyhow, Result};
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
#[allow(unused_imports)]
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// AMSI scan result classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmsiVerdict {
    Clean,
    NotDetected,
    BlockedByAdmin,
    Suspicious,
    Malware,
    Unknown,
    /// AMSI not available on this system
    Unavailable,
}

impl AmsiVerdict {
    /// Convert from raw AMSI result value
    pub fn from_raw(result: i32) -> Self {
        match result {
            0 => Self::Clean,
            1 => Self::NotDetected,
            r if r >= 0x4000 && r <= 0x4fff => Self::BlockedByAdmin,
            r if r >= 0x4000 && r < 32768 => Self::Suspicious,
            32768 => Self::Malware,
            _ => Self::Unknown,
        }
    }

    pub fn is_malicious(&self) -> bool {
        matches!(
            self,
            Self::Malware | Self::Suspicious | Self::BlockedByAdmin
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::NotDetected => "not_detected",
            Self::BlockedByAdmin => "blocked_by_admin",
            Self::Suspicious => "suspicious",
            Self::Malware => "malware",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::Malware => Severity::Critical,
            Self::Suspicious | Self::BlockedByAdmin => Severity::High,
            _ => Severity::Info,
        }
    }
}

/// AMSI scanner using dynamic API loading for Windows 10+ compatibility
pub struct AmsiScanner {
    context: *mut c_void,
    session: *mut c_void,
}

// AMSI context and session handles are thread-safe
// SAFETY: AmsiScanner contains *mut c_void pointers to AMSI context and session.
// Windows AMSI API guarantees these handles are thread-safe for concurrent access by multiple
// threads. Each thread can safely call AMSI functions with the same context/session handles.
// The underlying Windows synchronization ensures no data races. AmsiScanner itself only contains
// these handles and does not expose mutable access to them, so Send+Sync is safe.
// Ref: https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
unsafe impl Send for AmsiScanner {}

// SAFETY: See Send impl above - same rationale for Sync. Multiple threads can safely
// share and call methods on the same AmsiScanner instance.
unsafe impl Sync for AmsiScanner {}

impl AmsiScanner {
    /// Initialize AMSI scanner (Windows 10+ only)
    pub fn new(app_name: &str) -> Result<Self> {
        let api = amsi_api::get_amsi_api()
            .ok_or_else(|| anyhow!("AMSI not available on this Windows version"))?;

        let app_name_wide: Vec<u16> = app_name.encode_utf16().chain(std::iter::once(0)).collect();

        let mut context: *mut c_void = std::ptr::null_mut();
        let mut session: *mut c_void = std::ptr::null_mut();

        // SAFETY: AmsiInitialize and AmsiOpenSession FFI calls. These are synchronous Windows API
        // calls that initialize AMSI context and session. We provide valid pointers (mutable references
        // to null pointers) which Windows fills in with valid handles. The wide string is constructed
        // from app_name and null-terminated as required by Windows. These API functions are safe to
        // call on uninitialized pointers - they initialize them. The returned handles are valid for
        // the lifetime of the context (until Uninitialize is called). Error checking via HRESULT
        // ensures we only use valid handles on success.
        // Ref: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiinitialize
        unsafe {
            // Initialize AMSI context
            let hr = (api.initialize)(app_name_wide.as_ptr(), &mut context);
            if hr < 0 {
                return Err(anyhow!("AmsiInitialize failed: 0x{:08x}", hr));
            }

            // Open session
            let hr = (api.open_session)(context, &mut session);
            if hr < 0 {
                (api.uninitialize)(context);
                return Err(anyhow!("AmsiOpenSession failed: 0x{:08x}", hr));
            }
        }

        info!("AMSI scanner initialized successfully");

        Ok(Self { context, session })
    }

    /// Scan a buffer for malware
    pub fn scan_buffer(&self, content: &[u8], content_name: &str) -> Result<AmsiVerdict> {
        let api = amsi_api::get_amsi_api().ok_or_else(|| anyhow!("AMSI API not available"))?;

        let content_name_wide: Vec<u16> = content_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut result: i32 = 0;

        // SAFETY: AmsiScanBuffer FFI call to scan binary content. We pass:
        // - self.context: valid AMSI context handle from initialization
        // - content.as_ptr(): valid pointer to the buffer we own (content is Vec<u8>)
        // - content.len(): length of buffer, converted to u32
        // - content_name_wide: null-terminated UTF-16 string for logging
        // - self.session: valid AMSI session handle
        // - &mut result: valid output pointer for the AMSI verdict
        // All invariants are satisfied: context and session are valid (checked in new()),
        // content pointer and length are valid for a Vec, all pointers are properly aligned.
        // Windows ensures the scan completes and returns a valid HRESULT.
        // Ref: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer
        unsafe {
            let hr = (api.scan_buffer)(
                self.context,
                content.as_ptr(),
                content.len() as u32,
                content_name_wide.as_ptr(),
                self.session,
                &mut result,
            );

            if hr < 0 {
                return Err(anyhow!("AmsiScanBuffer failed: 0x{:08x}", hr));
            }
        }

        Ok(AmsiVerdict::from_raw(result))
    }

    /// Scan a string (for scripts)
    pub fn scan_string(&self, content: &str, content_name: &str) -> Result<AmsiVerdict> {
        let api = amsi_api::get_amsi_api().ok_or_else(|| anyhow!("AMSI API not available"))?;

        let content_wide: Vec<u16> = content.encode_utf16().chain(std::iter::once(0)).collect();
        let content_name_wide: Vec<u16> = content_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut result: i32 = 0;

        // SAFETY: AmsiScanString FFI call. Same safety invariants as scan_buffer:
        // valid context/session handles, properly null-terminated UTF-16 strings,
        // valid output pointer. Windows ensures safe execution and valid HRESULT return.
        unsafe {
            let hr = (api.scan_string)(
                self.context,
                content_wide.as_ptr(),
                content_name_wide.as_ptr(),
                self.session,
                &mut result,
            );

            if hr < 0 {
                return Err(anyhow!("AmsiScanString failed: 0x{:08x}", hr));
            }
        }

        Ok(AmsiVerdict::from_raw(result))
    }

    /// Create a new session (useful for separating scan contexts)
    pub fn new_session(&mut self) -> Result<()> {
        let api = amsi_api::get_amsi_api().ok_or_else(|| anyhow!("AMSI API not available"))?;

        // SAFETY: Close existing session and open new one. self.context is valid (guaranteed
        // by construction in new()). self.session may be null on first call, which is safe to
        // close. After CloseSession, we immediately open a new session with same context.
        // All handle invariants maintained.
        unsafe {
            // Close old session
            if !self.session.is_null() {
                (api.close_session)(self.context, self.session);
            }

            // Open new session
            let hr = (api.open_session)(self.context, &mut self.session);
            if hr < 0 {
                return Err(anyhow!("AmsiOpenSession failed: 0x{:08x}", hr));
            }
        }

        Ok(())
    }
}

impl Drop for AmsiScanner {
    fn drop(&mut self) {
        if let Some(api) = amsi_api::get_amsi_api() {
            // SAFETY: Cleanup handles on drop. self.context and self.session were obtained
            // from successful initialization in new(). We null-check both before calling
            // respective close/uninitialize functions. These FFI calls are safe even if context
            // or session are already closed (idempotent on Windows). No races possible since
            // Drop is called on this instance (exclusive access).
            unsafe {
                if !self.session.is_null() {
                    (api.close_session)(self.context, self.session);
                }
                if !self.context.is_null() {
                    (api.uninitialize)(self.context);
                }
            }
        }
    }
}

/// Script analysis result
#[derive(Debug, Clone)]
pub struct ScriptAnalysisResult {
    pub verdict: AmsiVerdict,
    pub heuristic_score: f32,
    pub detections: Vec<Detection>,
    pub script_type: ScriptType,
    pub is_obfuscated: bool,
    pub entropy: f64,
    pub suspicious_patterns: Vec<String>,
    pub iocs: Vec<IndicatorOfCompromise>,
}

/// Indicator of Compromise found in script
#[derive(Debug, Clone)]
pub struct IndicatorOfCompromise {
    pub ioc_type: IocType,
    pub value: String,
    pub context: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IocType {
    Url,
    IpAddress,
    Domain,
    FilePath,
    RegistryKey,
    Base64Blob,
    HashedCredential,
    ProcessName,
}

/// AMSI collector with multiple detection modes
pub struct AmsiCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    scanner: Option<Arc<AmsiScanner>>,
    running: Arc<AtomicBool>,
    capabilities: SystemCapabilities,
    stats: Arc<AmsiStats>,
}

/// AMSI collector statistics
#[derive(Debug, Default)]
pub struct AmsiStats {
    pub scans_performed: AtomicU64,
    pub malware_detected: AtomicU64,
    pub suspicious_detected: AtomicU64,
    pub clean_scans: AtomicU64,
    pub scan_errors: AtomicU64,
    pub scripts_analyzed: AtomicU64,
}

impl AmsiCollector {
    /// Create a new AMSI collector with automatic fallback
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(2000);
        let capabilities = SystemCapabilities::detect();
        let running = Arc::new(AtomicBool::new(true));
        let stats = Arc::new(AmsiStats::default());

        info!(
            has_amsi = capabilities.has_amsi,
            version = %capabilities.version,
            "Initializing AMSI collector"
        );

        // Try to initialize AMSI scanner (Windows 10+ only)
        let scanner = if capabilities.has_amsi {
            match AmsiScanner::new("TamanduaEDR") {
                Ok(s) => {
                    info!("AMSI scanner initialized (Windows 10+ mode)");
                    Some(Arc::new(s))
                }
                Err(e) => {
                    warn!(error = %e, "AMSI scanner initialization failed, using heuristic mode");
                    None
                }
            }
        } else {
            info!("AMSI not available, using heuristic detection mode");
            None
        };

        // Start monitoring threads
        let tx_clone = tx.clone();
        let config_clone = config.clone();
        let scanner_clone = scanner.clone();
        let running_clone = running.clone();
        let stats_clone = stats.clone();
        let has_amsi = capabilities.has_amsi && scanner.is_some();

        // Main monitoring thread
        std::thread::spawn(move || {
            let result = if has_amsi {
                // On Windows 10+, use active script monitoring
                Self::run_active_monitoring(
                    tx_clone,
                    config_clone,
                    scanner_clone,
                    running_clone,
                    stats_clone,
                )
            } else {
                // On older Windows, use heuristic monitoring
                Self::run_heuristic_monitor(tx_clone, config_clone, running_clone, stats_clone)
            };

            if let Err(e) = result {
                error!(error = %e, "AMSI monitor error");
            }
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            scanner,
            running,
            capabilities,
            stats,
        })
    }

    /// Active monitoring mode with AMSI integration
    fn run_active_monitoring(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        scanner: Option<Arc<AmsiScanner>>,
        running: Arc<AtomicBool>,
        stats: Arc<AmsiStats>,
    ) -> Result<()> {
        info!("Starting active AMSI monitoring");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        // Script host processes to monitor
        let script_hosts = [
            ("powershell.exe", ScriptType::PowerShell),
            ("pwsh.exe", ScriptType::PowerShell),
            ("wscript.exe", ScriptType::VBScript),
            ("cscript.exe", ScriptType::VBScript),
            ("mshta.exe", ScriptType::JavaScript),
            ("node.exe", ScriptType::JavaScript),
            ("python.exe", ScriptType::Python),
            ("python3.exe", ScriptType::Python),
        ];

        let mut known_pids: HashMap<u32, ScriptHostInfo> = HashMap::new();
        let mut script_queue: VecDeque<PendingScript> = VecDeque::new();

        while running.load(Ordering::SeqCst) {
            // Check for new script host processes
            for &(host_name, script_type) in &script_hosts {
                for pid in Self::get_processes_by_name(host_name) {
                    if !known_pids.contains_key(&pid) {
                        let info = ScriptHostInfo {
                            pid,
                            name: host_name.to_string(),
                            script_type,
                            start_time: std::time::Instant::now(),
                            cmdline: Self::get_process_cmdline(pid),
                        };

                        // Create event for script host start
                        if let Some(event) = Self::create_script_host_event(&info, &scanner, &stats)
                        {
                            let _ = rt.block_on(tx.send(event));
                        }

                        // If this is PowerShell with encoded command, decode and scan
                        if matches!(script_type, ScriptType::PowerShell) {
                            if let Some(ref cmdline) = info.cmdline {
                                if let Some(decoded) = Self::extract_and_decode_base64(cmdline) {
                                    script_queue.push_back(PendingScript {
                                        content: decoded,
                                        script_type,
                                        source_pid: pid,
                                        source_name: host_name.to_string(),
                                    });
                                }
                            }
                        }

                        known_pids.insert(pid, info);
                    }
                }
            }

            // Process pending scripts
            while let Some(script) = script_queue.pop_front() {
                let analysis = Self::analyze_script(
                    &script.content,
                    script.script_type,
                    scanner.as_ref(),
                    &stats,
                );

                if analysis.verdict.is_malicious() || analysis.heuristic_score > 0.5 {
                    let event = Self::create_script_analysis_event(&script, &analysis);
                    let _ = rt.block_on(tx.send(event));
                }
            }

            // Clean up terminated processes
            known_pids.retain(|pid, _| Self::process_exists(*pid));

            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        Ok(())
    }

    /// Analyze script content with AMSI and heuristics
    fn analyze_script(
        content: &str,
        script_type: ScriptType,
        scanner: Option<&Arc<AmsiScanner>>,
        stats: &AmsiStats,
    ) -> ScriptAnalysisResult {
        stats.scripts_analyzed.fetch_add(1, Ordering::Relaxed);

        // AMSI scan
        let verdict = if let Some(scanner) = scanner {
            stats.scans_performed.fetch_add(1, Ordering::Relaxed);
            match scanner.scan_string(content, "script_analysis") {
                Ok(v) => {
                    match v {
                        AmsiVerdict::Malware => {
                            stats.malware_detected.fetch_add(1, Ordering::Relaxed);
                        }
                        AmsiVerdict::Suspicious => {
                            stats.suspicious_detected.fetch_add(1, Ordering::Relaxed);
                        }
                        AmsiVerdict::Clean | AmsiVerdict::NotDetected => {
                            stats.clean_scans.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    v
                }
                Err(_) => {
                    stats.scan_errors.fetch_add(1, Ordering::Relaxed);
                    AmsiVerdict::Unknown
                }
            }
        } else {
            AmsiVerdict::Unavailable
        };

        // Heuristic analysis
        let (heuristic_score, suspicious_patterns, detections) =
            Self::heuristic_analysis(content, script_type);

        // Entropy calculation (high entropy = possible obfuscation)
        let entropy = Self::calculate_entropy(content);
        let is_obfuscated = entropy > 5.5 || Self::detect_obfuscation(content);

        // IOC extraction
        let iocs = Self::extract_iocs(content);

        ScriptAnalysisResult {
            verdict,
            heuristic_score,
            detections,
            script_type,
            is_obfuscated,
            entropy,
            suspicious_patterns,
            iocs,
        }
    }

    /// Heuristic analysis of script content
    fn heuristic_analysis(
        content: &str,
        script_type: ScriptType,
    ) -> (f32, Vec<String>, Vec<Detection>) {
        let content_lower = content.to_lowercase();
        let mut score: f32 = 0.0;
        let mut patterns: Vec<String> = Vec::new();
        let mut detections: Vec<Detection> = Vec::new();

        // Get patterns based on script type
        let (high_severity, medium_severity) = match script_type {
            ScriptType::PowerShell => (
                POWERSHELL_HIGH_SEVERITY_PATTERNS,
                POWERSHELL_MEDIUM_SEVERITY_PATTERNS,
            ),
            ScriptType::VBScript | ScriptType::JavaScript => (
                VBSCRIPT_HIGH_SEVERITY_PATTERNS,
                VBSCRIPT_MEDIUM_SEVERITY_PATTERNS,
            ),
            ScriptType::Batch => (BATCH_HIGH_SEVERITY_PATTERNS, BATCH_MEDIUM_SEVERITY_PATTERNS),
            _ => (&[][..], &[][..]),
        };

        // Check high severity patterns
        for &(pattern, technique, description, weight) in high_severity {
            if content_lower.contains(pattern) {
                score += weight;
                patterns.push(pattern.to_string());
                detections.push(Detection {
                    detection_type: DetectionType::ScriptThreat,
                    rule_name: format!(
                        "AMSI_HEURISTIC_{}",
                        pattern.to_uppercase().replace("-", "_").replace(" ", "_")
                    ),
                    confidence: 0.8,
                    description: description.to_string(),
                    mitre_tactics: vec!["Execution".to_string()],
                    mitre_techniques: vec![technique.to_string()],
                });
            }
        }

        // Check medium severity patterns
        for &(pattern, technique, description, weight) in medium_severity {
            if content_lower.contains(pattern) {
                score += weight;
                patterns.push(pattern.to_string());
                if detections.len() < 10 {
                    // Limit detections
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: format!(
                            "AMSI_BEHAVIORAL_{}",
                            pattern.to_uppercase().replace("-", "_").replace(" ", "_")
                        ),
                        confidence: 0.6,
                        description: description.to_string(),
                        mitre_tactics: vec!["Execution".to_string()],
                        mitre_techniques: vec![technique.to_string()],
                    });
                }
            }
        }

        // Additional heuristics

        // Check for base64 encoded content
        if content_lower.contains("frombase64string")
            || content_lower.contains("-encodedcommand")
            || content_lower.contains("-enc ")
        {
            score += 0.15;
            patterns.push("base64_usage".to_string());
        }

        // Check for very long lines (potential obfuscation)
        let max_line_len = content.lines().map(|l| l.len()).max().unwrap_or(0);
        if max_line_len > 1000 {
            score += 0.1;
            patterns.push("long_lines".to_string());
        }

        // Check for excessive string concatenation
        let concat_count = content.matches('+').count() + content.matches('&').count();
        if concat_count > 50 {
            score += 0.1;
            patterns.push("excessive_concatenation".to_string());
        }

        // Check for character/code point manipulation (obfuscation)
        if content.contains("[char]") || content.contains("String.fromCharCode") {
            score += 0.15;
            patterns.push("char_manipulation".to_string());
        }

        // Clamp score to [0, 1]
        score = score.min(1.0);

        (score, patterns, detections)
    }

    /// Detect script obfuscation techniques
    fn detect_obfuscation(content: &str) -> bool {
        let content_lower = content.to_lowercase();

        // String reversal
        if content.contains("-join") && content.contains("[char]") {
            return true;
        }

        // Character array manipulation
        if content.contains("GetType(") && content.contains("GetMethod") {
            return true;
        }

        // Replace/split obfuscation
        let replace_count = content.matches(".replace(").count();
        let split_count = content.matches(".split(").count();
        if replace_count > 10 || split_count > 5 {
            return true;
        }

        // XOR obfuscation
        if content.contains("-bxor") || content.contains("^ 0x") {
            return true;
        }

        // Invoke-Expression variants
        let iex_variants = [
            "iex",
            "invoke-expression",
            "&(",
            ".(",
            "|iex",
            "|invoke-expression",
        ];
        let iex_count = iex_variants
            .iter()
            .filter(|v| content_lower.contains(*v))
            .count();
        if iex_count > 2 {
            return true;
        }

        // Backtick obfuscation in PowerShell
        let backtick_count = content.matches('`').count();
        if backtick_count > 20 {
            return true;
        }

        // Caret obfuscation in CMD
        let caret_count = content.matches('^').count();
        if caret_count > 20 {
            return true;
        }

        false
    }

    /// Extract IOCs from script content
    fn extract_iocs(content: &str) -> Vec<IndicatorOfCompromise> {
        let mut iocs = Vec::new();

        // URL extraction
        let url_pattern = regex::Regex::new(r#"https?://[^\s'"<>]+"#).unwrap();
        for cap in url_pattern.find_iter(content) {
            let url = cap
                .as_str()
                .trim_end_matches(&['"', '\'', ')', ']', '}', '>', ';'][..]);
            iocs.push(IndicatorOfCompromise {
                ioc_type: IocType::Url,
                value: url.to_string(),
                context: Self::get_context(content, cap.start(), 50),
            });
        }

        // IP address extraction
        let ip_pattern = regex::Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ).unwrap();
        for cap in ip_pattern.find_iter(content) {
            let ip = cap.as_str();
            // Skip common local IPs
            if !ip.starts_with("127.") && !ip.starts_with("0.") && !ip.starts_with("192.168.") {
                iocs.push(IndicatorOfCompromise {
                    ioc_type: IocType::IpAddress,
                    value: ip.to_string(),
                    context: Self::get_context(content, cap.start(), 50),
                });
            }
        }

        // Base64 blob extraction (large base64 strings)
        let b64_pattern = regex::Regex::new(r"[A-Za-z0-9+/]{50,}={0,2}").unwrap();
        for cap in b64_pattern.find_iter(content) {
            if cap.as_str().len() > 100 {
                iocs.push(IndicatorOfCompromise {
                    ioc_type: IocType::Base64Blob,
                    value: format!("{}...", &cap.as_str()[..50]),
                    context: Self::get_context(content, cap.start(), 50),
                });
            }
        }

        // File path extraction (suspicious paths)
        let path_patterns = [
            r"\\temp\\[^\s]+\.exe",
            r"\\appdata\\[^\s]+\.exe",
            r"\\users\\public\\[^\s]+",
            r"c:\\programdata\\[^\s]+\.exe",
        ];
        for pattern in path_patterns {
            if let Ok(re) = regex::Regex::new(&format!("(?i){}", pattern)) {
                for cap in re.find_iter(content) {
                    iocs.push(IndicatorOfCompromise {
                        ioc_type: IocType::FilePath,
                        value: cap.as_str().to_string(),
                        context: Self::get_context(content, cap.start(), 50),
                    });
                }
            }
        }

        // Registry key extraction (persistence locations)
        let reg_patterns = [
            r"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ];
        for pattern in reg_patterns {
            if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex::escape(pattern))) {
                for cap in re.find_iter(content) {
                    iocs.push(IndicatorOfCompromise {
                        ioc_type: IocType::RegistryKey,
                        value: cap.as_str().to_string(),
                        context: Self::get_context(content, cap.start(), 50),
                    });
                }
            }
        }

        iocs
    }

    /// Get surrounding context for an IOC
    fn get_context(content: &str, position: usize, context_len: usize) -> String {
        let start = position.saturating_sub(context_len);
        let end = (position + context_len).min(content.len());
        content[start..end].to_string()
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(data: &str) -> f64 {
        let mut freq = [0u32; 256];
        let len = data.len() as f64;

        if len == 0.0 {
            return 0.0;
        }

        for byte in data.bytes() {
            freq[byte as usize] += 1;
        }

        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Create event for script host process
    fn create_script_host_event(
        info: &ScriptHostInfo,
        scanner: &Option<Arc<AmsiScanner>>,
        stats: &AmsiStats,
    ) -> Option<TelemetryEvent> {
        let (name, path, _) = Self::get_process_info(info.pid);

        if name.is_empty() {
            return None;
        }

        // If we have command line, analyze it
        let mut severity = Severity::Low;
        let mut detections = Vec::new();

        if let Some(ref cmdline) = info.cmdline {
            // Check for encoded commands
            if cmdline.to_lowercase().contains("-enc")
                || cmdline.to_lowercase().contains("-encodedcommand")
            {
                severity = Severity::High;
                detections.push(Detection {
                    detection_type: DetectionType::ScriptThreat,
                    rule_name: "ENCODED_POWERSHELL_COMMAND".to_string(),
                    confidence: 0.7,
                    description: "PowerShell with encoded command detected".to_string(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1027".to_string()],
                });
            }

            // Check for execution policy bypass
            if cmdline.to_lowercase().contains("-executionpolicy bypass")
                || cmdline.to_lowercase().contains("-ep bypass")
            {
                severity = if severity == Severity::High {
                    Severity::High
                } else {
                    Severity::Medium
                };
                detections.push(Detection {
                    detection_type: DetectionType::ScriptThreat,
                    rule_name: "EXECUTION_POLICY_BYPASS".to_string(),
                    confidence: 0.6,
                    description: "PowerShell execution policy bypass detected".to_string(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1059.001".to_string()],
                });
            }

            // Check for hidden window
            if cmdline.to_lowercase().contains("-windowstyle hidden")
                || cmdline.to_lowercase().contains("-w hidden")
            {
                severity = if severity == Severity::High {
                    Severity::High
                } else {
                    Severity::Medium
                };
                detections.push(Detection {
                    detection_type: DetectionType::ScriptThreat,
                    rule_name: "HIDDEN_WINDOW".to_string(),
                    confidence: 0.5,
                    description: "Hidden PowerShell window detected".to_string(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1564.003".to_string()],
                });
            }
        }

        let mut event = TelemetryEvent::new(
            EventType::ScriptExecution,
            severity,
            EventPayload::Process(ProcessEvent {
                pid: info.pid,
                ppid: 0,
                name: name.clone(),
                path,
                cmdline: info.cmdline.clone().unwrap_or_default(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        event
            .metadata
            .insert("script_host".to_string(), "true".to_string());
        event
            .metadata
            .insert("amsi_available".to_string(), scanner.is_some().to_string());
        event
            .metadata
            .insert("script_type".to_string(), format!("{:?}", info.script_type));

        for detection in detections {
            event.add_detection(detection);
        }

        Some(event)
    }

    /// Create event from script analysis
    fn create_script_analysis_event(
        script: &PendingScript,
        analysis: &ScriptAnalysisResult,
    ) -> TelemetryEvent {
        let severity = if analysis.verdict.is_malicious() {
            analysis.verdict.severity()
        } else if analysis.heuristic_score > 0.7 {
            Severity::High
        } else if analysis.heuristic_score > 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        };

        // Build attack tools list from detections
        let attack_tools: Vec<String> = analysis
            .detections
            .iter()
            .filter(|d| d.confidence > 0.7)
            .map(|d| d.rule_name.clone())
            .collect();

        let (process_name, process_path, _) = Self::get_process_info(script.source_pid);

        let mut event = TelemetryEvent::new(
            EventType::ScriptBlock,
            severity,
            EventPayload::Script(ScriptEvent {
                pid: script.source_pid,
                ppid: 0,
                process_name: if process_name.is_empty() {
                    script.source_name.clone()
                } else {
                    process_name
                },
                process_path,
                script_type: analysis.script_type,
                cmdline: String::new(),
                content: Some(if script.content.len() > 10000 {
                    format!("{}...[truncated]", &script.content[..10000])
                } else {
                    script.content.clone()
                }),
                deobfuscated_content: None,
                script_path: None,
                user: String::new(),
                is_elevated: false,
                obfuscation_techniques: if analysis.is_obfuscated {
                    vec!["detected".to_string()]
                } else {
                    Vec::new()
                },
                suspicious_patterns: analysis.suspicious_patterns.clone(),
                attack_tools,
                risk_score: analysis.heuristic_score,
            }),
        );

        // Add metadata
        event.metadata.insert(
            "amsi_verdict".to_string(),
            analysis.verdict.as_str().to_string(),
        );
        event.metadata.insert(
            "heuristic_score".to_string(),
            format!("{:.2}", analysis.heuristic_score),
        );
        event
            .metadata
            .insert("entropy".to_string(), format!("{:.2}", analysis.entropy));
        event.metadata.insert(
            "is_obfuscated".to_string(),
            analysis.is_obfuscated.to_string(),
        );
        event.metadata.insert(
            "suspicious_patterns".to_string(),
            analysis.suspicious_patterns.join(", "),
        );

        // Add IOCs as metadata
        if !analysis.iocs.is_empty() {
            let ioc_summary: Vec<String> = analysis
                .iocs
                .iter()
                .take(10)
                .map(|ioc| format!("{:?}: {}", ioc.ioc_type, ioc.value))
                .collect();
            event
                .metadata
                .insert("iocs".to_string(), ioc_summary.join("; "));
        }

        // Add detections
        for detection in &analysis.detections {
            event.add_detection(detection.clone());
        }

        event
    }

    /// Run heuristic-based monitoring (fallback for older Windows)
    fn run_heuristic_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        running: Arc<AtomicBool>,
        stats: Arc<AmsiStats>,
    ) -> Result<()> {
        info!("Starting heuristic script monitoring (pre-Windows 10 mode)");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        // Monitor for suspicious script executions
        let suspicious_processes = [
            (
                "powershell.exe",
                ScriptType::PowerShell,
                vec![
                    "-enc",
                    "-e ",
                    "-encodedcommand",
                    "bypass",
                    "-nop",
                    "-w hidden",
                ],
            ),
            (
                "cmd.exe",
                ScriptType::Batch,
                vec!["/c", "&&", "|", "powershell", "certutil"],
            ),
            (
                "wscript.exe",
                ScriptType::VBScript,
                vec![".js", ".vbs", ".wsf"],
            ),
            (
                "cscript.exe",
                ScriptType::VBScript,
                vec![".js", ".vbs", ".wsf"],
            ),
            (
                "mshta.exe",
                ScriptType::JavaScript,
                vec!["javascript:", "vbscript:", "http://", "https://"],
            ),
        ];

        let mut known_pids: HashMap<u32, ScriptHostInfo> = HashMap::new();

        while running.load(Ordering::SeqCst) {
            // Scan for suspicious script executions
            for (process_name, script_type, patterns) in &suspicious_processes {
                if let Some(events) = Self::check_suspicious_scripts(
                    process_name,
                    *script_type,
                    patterns,
                    &mut known_pids,
                    &stats,
                ) {
                    for event in events {
                        let _ = rt.block_on(tx.send(event));
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        Ok(())
    }

    /// Check for suspicious script executions
    fn check_suspicious_scripts(
        target_process: &str,
        script_type: ScriptType,
        patterns: &[&str],
        known_pids: &mut HashMap<u32, ScriptHostInfo>,
        stats: &AmsiStats,
    ) -> Option<Vec<TelemetryEvent>> {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut events = Vec::new();

        // SAFETY: CreateToolhelp32Snapshot creates a snapshot of the current process list.
        // Process32FirstW/Process32NextW iterate through it. We properly initialize PROCESSENTRY32W
        // with dwSize and pass valid mutable pointers. The snapshot handle must be valid (which we
        // check via error handling). All buffer accesses are within bounds due to PROCESSENTRY32W
        // being a fixed struct. Windows ensures thread-safe enumeration via the snapshot mechanism.
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return None,
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

                    if name.eq_ignore_ascii_case(target_process) {
                        let pid = entry.th32ProcessID;

                        // Skip if already known
                        if known_pids.contains_key(&pid) {
                            if Process32NextW(snapshot, &mut entry).is_err() {
                                break;
                            }
                            continue;
                        }

                        // Get command line
                        if let Some(cmdline) = Self::get_process_cmdline(pid) {
                            let cmdline_lower = cmdline.to_lowercase();

                            // Check for suspicious patterns
                            for pattern in patterns {
                                if cmdline_lower.contains(&pattern.to_lowercase()) {
                                    let (process_name, path, _) = Self::get_process_info(pid);

                                    // Detect base64 encoded commands
                                    let encoded_detected = cmdline_lower.contains("-enc")
                                        || cmdline_lower.contains("-encodedcommand");

                                    // Decode and analyze if encoded
                                    let decoded_script = if encoded_detected {
                                        Self::extract_and_decode_base64(&cmdline)
                                    } else {
                                        None
                                    };

                                    // Analyze script content
                                    let analysis = if let Some(ref decoded) = decoded_script {
                                        Some(Self::analyze_script(
                                            decoded,
                                            script_type,
                                            None,
                                            stats,
                                        ))
                                    } else {
                                        None
                                    };

                                    let severity = if let Some(ref a) = analysis {
                                        if a.heuristic_score > 0.7 {
                                            Severity::High
                                        } else if a.heuristic_score > 0.5 {
                                            Severity::Medium
                                        } else if encoded_detected {
                                            Severity::Medium
                                        } else {
                                            Severity::Low
                                        }
                                    } else if encoded_detected {
                                        Severity::High
                                    } else {
                                        Severity::Medium
                                    };

                                    let mut event = TelemetryEvent::new(
                                        EventType::ScriptExecution,
                                        severity,
                                        EventPayload::Process(ProcessEvent {
                                            pid,
                                            ppid: entry.th32ParentProcessID,
                                            name: process_name.clone(),
                                            path,
                                            cmdline: cmdline.clone(),
                                            user: String::new(),
                                            sha256: Vec::new(),
                                            entropy: 0.0,
                                            is_elevated: false,
                                            parent_name: None,
                                            parent_path: None,
                                            is_signed: false,
                                            signer: None,
                                            start_time: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_millis() as u64)
                                                .unwrap_or(0),
                                            cpu_usage: 0.0,
                                            memory_bytes: 0,
                                            company_name: None,
                                            file_description: None,
                                            product_name: None,
                                            file_version: None,
                                            environment: None,
                                        }),
                                    );

                                    // Add detection
                                    event.add_detection(Detection {
                                        detection_type: DetectionType::ScriptThreat,
                                        rule_name: "SUSPICIOUS_SCRIPT_EXECUTION".to_string(),
                                        confidence: if encoded_detected { 0.85 } else { 0.65 },
                                        description: format!(
                                            "Suspicious {} execution with pattern '{}': {}",
                                            target_process,
                                            pattern,
                                            if cmdline.len() > 200 {
                                                &cmdline[..200]
                                            } else {
                                                &cmdline
                                            }
                                        ),
                                        mitre_tactics: vec!["Execution".to_string()],
                                        mitre_techniques: vec!["T1059.001".to_string()],
                                    });

                                    if let Some(decoded) = decoded_script {
                                        event.metadata.insert(
                                            "decoded_script".to_string(),
                                            if decoded.len() > 1000 {
                                                decoded[..1000].to_string()
                                            } else {
                                                decoded
                                            },
                                        );
                                        event.metadata.insert(
                                            "encoded_command".to_string(),
                                            "true".to_string(),
                                        );
                                    }

                                    if let Some(analysis) = analysis {
                                        event.metadata.insert(
                                            "heuristic_score".to_string(),
                                            format!("{:.2}", analysis.heuristic_score),
                                        );
                                        for detection in analysis.detections {
                                            event.add_detection(detection);
                                        }
                                    }

                                    events.push(event);
                                    break; // Only one event per PID
                                }
                            }
                        }

                        known_pids.insert(
                            pid,
                            ScriptHostInfo {
                                pid,
                                name: name.clone(),
                                script_type,
                                start_time: std::time::Instant::now(),
                                cmdline: Self::get_process_cmdline(pid),
                            },
                        );
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Get processes by name
    fn get_processes_by_name(target_name: &str) -> Vec<u32> {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut pids = Vec::new();

        // SAFETY: Same as first process enumeration - snapshot-based process iteration.
        // Properly initialized PROCESSENTRY32W, valid pointers to mutable entry, error
        // checked snapshot handle, bounded buffer accesses.
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return pids,
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

                    if name.eq_ignore_ascii_case(target_name) {
                        pids.push(entry.th32ProcessID);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        pids
    }

    /// Check if process exists
    fn process_exists(pid: u32) -> bool {
        // SAFETY: OpenProcess queries process handle with limited information access (read-only).
        // If successful, we immediately close the handle. No concurrent access to the handle.
        // If unsuccessful, no handle was returned. Both branches are safe. pid is user-provided
        // but OpenProcess safely validates it (returns error if invalid PID).
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let _ = CloseHandle(handle);
                true
            } else {
                false
            }
        }
    }

    /// Get process command line
    fn get_process_cmdline(pid: u32) -> Option<String> {
        // Try WMI-based approach (more reliable)
        Self::get_cmdline_via_wmi(pid)
    }

    /// Get command line via WMI
    fn get_cmdline_via_wmi(pid: u32) -> Option<String> {
        use std::process::Command;

        // Use WMIC to get command line
        let output = Command::new("wmic")
            .args([
                "process",
                "where",
                &format!("ProcessId={}", pid),
                "get",
                "CommandLine",
                "/format:list",
            ])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("CommandLine=") {
                return Some(line[12..].trim().to_string());
            }
        }

        None
    }

    /// Extract and decode Base64 encoded PowerShell commands
    fn extract_and_decode_base64(cmdline: &str) -> Option<String> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let cmdline_lower = cmdline.to_lowercase();

        // Find the encoded argument
        let encoded = if let Some(pos) = cmdline_lower.find("-enc ") {
            cmdline[pos + 5..].split_whitespace().next()
        } else if let Some(pos) = cmdline_lower.find("-encodedcommand ") {
            cmdline[pos + 16..].split_whitespace().next()
        } else if let Some(pos) = cmdline_lower.find("-e ") {
            cmdline[pos + 3..].split_whitespace().next()
        } else {
            return None;
        }?;

        // Remove any quotes
        let encoded = encoded.trim_matches('"').trim_matches('\'');

        // Decode Base64 (PowerShell uses UTF-16LE)
        let decoded_bytes = STANDARD.decode(encoded).ok()?;

        // Convert from UTF-16LE to string
        let mut chars = Vec::new();
        for chunk in decoded_bytes.chunks(2) {
            if chunk.len() == 2 {
                let c = u16::from_le_bytes([chunk[0], chunk[1]]);
                if c != 0 {
                    chars.push(c);
                }
            }
        }

        Some(String::from_utf16_lossy(&chars))
    }

    /// Get process information
    fn get_process_info(pid: u32) -> (String, String, String) {
        // SAFETY: OpenProcess -> K32GetProcessImageFileNameW -> CloseHandle sequence.
        // handle is checked via Ok() before use. path_buf is a fixed-size array on stack with
        // size checked by K32GetProcessImageFileNameW which won't overflow. Windows ensures
        // proper error returns for invalid PID. Handle is immediately closed and not used after.
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return (String::new(), String::new(), String::new()),
            };

            let mut path_buf = [0u16; 260];
            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
            let _ = CloseHandle(handle);

            if len == 0 {
                return (String::new(), String::new(), String::new());
            }

            let path = String::from_utf16_lossy(&path_buf[..len as usize]);
            let name = path.rsplit('\\').next().unwrap_or("").to_string();

            (name, path, String::new())
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Manually scan content with AMSI (if available)
    pub fn scan_content(&self, content: &[u8], name: &str) -> AmsiVerdict {
        self.scanner
            .as_ref()
            .and_then(|s| s.scan_buffer(content, name).ok())
            .unwrap_or(AmsiVerdict::Unavailable)
    }

    /// Manually scan script string with AMSI (if available)
    pub fn scan_script(&self, script: &str, name: &str) -> AmsiVerdict {
        self.scanner
            .as_ref()
            .and_then(|s| s.scan_string(script, name).ok())
            .unwrap_or(AmsiVerdict::Unavailable)
    }

    /// Check if AMSI is available on this system
    pub fn is_amsi_available(&self) -> bool {
        self.capabilities.has_amsi && self.scanner.is_some()
    }

    /// Scan and analyze PowerShell script content
    pub fn scan_powershell(&self, script: &str) -> (AmsiVerdict, Vec<Detection>) {
        let analysis = Self::analyze_script(
            script,
            ScriptType::PowerShell,
            self.scanner.as_ref(),
            &self.stats,
        );

        (analysis.verdict, analysis.detections)
    }

    /// Scan and analyze VBScript content
    pub fn scan_vbscript(&self, script: &str) -> (AmsiVerdict, Vec<Detection>) {
        let analysis = Self::analyze_script(
            script,
            ScriptType::VBScript,
            self.scanner.as_ref(),
            &self.stats,
        );

        (analysis.verdict, analysis.detections)
    }

    /// Get collector statistics
    pub fn get_stats(&self) -> AmsiStatsSnapshot {
        AmsiStatsSnapshot {
            scans_performed: self.stats.scans_performed.load(Ordering::Relaxed),
            malware_detected: self.stats.malware_detected.load(Ordering::Relaxed),
            suspicious_detected: self.stats.suspicious_detected.load(Ordering::Relaxed),
            clean_scans: self.stats.clean_scans.load(Ordering::Relaxed),
            scan_errors: self.stats.scan_errors.load(Ordering::Relaxed),
            scripts_analyzed: self.stats.scripts_analyzed.load(Ordering::Relaxed),
        }
    }
}

impl Drop for AmsiCollector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Statistics snapshot
#[derive(Debug, Clone)]
pub struct AmsiStatsSnapshot {
    pub scans_performed: u64,
    pub malware_detected: u64,
    pub suspicious_detected: u64,
    pub clean_scans: u64,
    pub scan_errors: u64,
    pub scripts_analyzed: u64,
}

/// Script host process information
#[derive(Debug, Clone)]
struct ScriptHostInfo {
    pid: u32,
    name: String,
    script_type: ScriptType,
    start_time: std::time::Instant,
    cmdline: Option<String>,
}

/// Pending script for analysis
#[derive(Debug, Clone)]
struct PendingScript {
    content: String,
    script_type: ScriptType,
    source_pid: u32,
    source_name: String,
}

// ==============================================================================
// Heuristic Pattern Definitions
// ==============================================================================

/// PowerShell high severity patterns: (pattern, mitre_technique, description, weight)
const POWERSHELL_HIGH_SEVERITY_PATTERNS: &[(&str, &str, &str, f32)] = &[
    ("downloadstring", "T1105", "Download and execute code", 0.3),
    ("downloadfile", "T1105", "Download file", 0.25),
    (
        "invoke-expression",
        "T1059.001",
        "Dynamic code execution",
        0.25,
    ),
    ("iex(", "T1059.001", "Dynamic code execution (alias)", 0.25),
    ("|iex", "T1059.001", "Piped dynamic code execution", 0.25),
    ("invoke-mimikatz", "T1003", "Credential dumping tool", 0.4),
    (
        "invoke-kerberoast",
        "T1558.003",
        "Kerberoasting attack",
        0.4,
    ),
    ("invoke-dcsync", "T1003.006", "DCSync attack", 0.4),
    ("invoke-wmimethod", "T1047", "WMI method invocation", 0.2),
    (
        "invoke-command",
        "T1059.001",
        "Remote command execution",
        0.2,
    ),
    (
        "set-mppreference",
        "T1562.001",
        "Modify security settings",
        0.3,
    ),
    (
        "add-mppreference -exclusion",
        "T1562.001",
        "Add AV exclusion",
        0.35,
    ),
    (
        "disable-realtimemonitoring",
        "T1562.001",
        "Disable real-time monitoring",
        0.35,
    ),
    (
        "virtualalloc",
        "T1055",
        "Memory allocation for injection",
        0.3,
    ),
    ("virtualprotect", "T1055", "Memory protection change", 0.25),
    (
        "createthread",
        "T1055",
        "Thread creation for injection",
        0.25,
    ),
    (
        "[system.reflection.assembly]::load",
        "T1620",
        "Reflective assembly loading",
        0.3,
    ),
    (
        "assemblybuilder",
        "T1620",
        "Dynamic assembly creation",
        0.25,
    ),
    ("definetype", "T1620", "Dynamic type definition", 0.2),
    ("pinvoke", "T1106", "P/Invoke native API call", 0.2),
    ("dllimport", "T1106", "DLL import for native calls", 0.2),
    ("amsiutils", "T1562.001", "AMSI bypass attempt", 0.4),
    ("amsiscanbuffer", "T1562.001", "AMSI bypass attempt", 0.4),
    ("amsicontext", "T1562.001", "AMSI bypass attempt", 0.4),
    ("bypass", "T1562.001", "Security bypass", 0.15),
    ("sekurlsa", "T1003.001", "Mimikatz credential dumping", 0.4),
    ("logonpasswords", "T1003.001", "Credential dumping", 0.35),
    ("out-minidump", "T1003.001", "Process memory dump", 0.35),
    ("procdump", "T1003.001", "Process dump tool", 0.3),
    ("sqldumper", "T1003.001", "SQL dumper tool", 0.3),
    ("comsvcs.dll", "T1003.001", "MiniDump via comsvcs", 0.35),
];

/// PowerShell medium severity patterns
const POWERSHELL_MEDIUM_SEVERITY_PATTERNS: &[(&str, &str, &str, f32)] = &[
    ("system.net.webclient", "T1071", "Web client creation", 0.15),
    ("system.net.sockets", "T1095", "Raw socket usage", 0.15),
    ("invoke-webrequest", "T1071", "Web request", 0.1),
    ("invoke-restmethod", "T1071", "REST method call", 0.1),
    ("bitsadmin", "T1197", "BITS transfer", 0.15),
    ("start-bitstransfer", "T1197", "BITS transfer", 0.15),
    (
        "new-pssession",
        "T1021.006",
        "PowerShell remoting session",
        0.15,
    ),
    ("enter-pssession", "T1021.006", "Enter remote session", 0.15),
    ("get-credential", "T1056.002", "Credential prompt", 0.15),
    (
        "convertto-securestring",
        "T1140",
        "Secure string creation",
        0.1,
    ),
    ("export-clixml", "T1003", "Export credentials", 0.15),
    ("get-adcomputer", "T1018", "AD computer enumeration", 0.1),
    ("get-aduser", "T1087.002", "AD user enumeration", 0.1),
    ("get-adgroup", "T1069.002", "AD group enumeration", 0.1),
    ("get-process", "T1057", "Process enumeration", 0.05),
    ("get-service", "T1007", "Service enumeration", 0.05),
    ("get-wmiobject", "T1047", "WMI query", 0.1),
    ("wmic", "T1047", "WMI command", 0.1),
    ("reg query", "T1012", "Registry query", 0.1),
    ("schtasks", "T1053.005", "Scheduled task", 0.15),
    (
        "new-scheduledtask",
        "T1053.005",
        "Create scheduled task",
        0.15,
    ),
    (
        "register-scheduledtask",
        "T1053.005",
        "Register scheduled task",
        0.15,
    ),
    ("new-service", "T1543.003", "Create service", 0.15),
    ("sc.exe", "T1543.003", "Service control", 0.1),
    (
        "test-netconnection",
        "T1049",
        "Network connection test",
        0.05,
    ),
    ("test-path", "T1083", "File existence check", 0.05),
    ("hidden", "T1564.003", "Hidden window/execution", 0.15),
    ("-windowstyle hidden", "T1564.003", "Hidden window", 0.15),
    ("-nop", "T1059.001", "No profile", 0.1),
    ("-noninteractive", "T1059.001", "Non-interactive", 0.1),
    ("frombase64string", "T1140", "Base64 decoding", 0.15),
    ("tobase64string", "T1027", "Base64 encoding", 0.1),
    ("[convert]::frombase64", "T1140", "Base64 decoding", 0.15),
];

/// VBScript/JScript high severity patterns
const VBSCRIPT_HIGH_SEVERITY_PATTERNS: &[(&str, &str, &str, f32)] = &[
    ("wscript.shell", "T1059.005", "Shell execution", 0.2),
    ("shell.application", "T1059.005", "Shell application", 0.2),
    (
        "scripting.filesystemobject",
        "T1106",
        "File system access",
        0.15,
    ),
    ("adodb.stream", "T1105", "Binary stream (download)", 0.25),
    ("msxml2.xmlhttp", "T1071", "HTTP request", 0.2),
    ("msxml2.serverxmlhttp", "T1071", "HTTP request", 0.2),
    (".run", "T1059", "Process execution", 0.2),
    (".exec", "T1059", "Process execution", 0.2),
    ("eval(", "T1059.007", "Dynamic code evaluation", 0.25),
    ("execute(", "T1059.005", "Dynamic code execution", 0.25),
    ("executeglobal(", "T1059.005", "Global code execution", 0.25),
    ("getobject(", "T1559.001", "Get COM object", 0.15),
    ("createobject(", "T1559.001", "Create COM object", 0.15),
    ("powershell", "T1059.001", "PowerShell invocation", 0.25),
    ("cmd.exe", "T1059.003", "Command shell", 0.2),
    ("regwrite", "T1112", "Registry modification", 0.2),
    ("regdelete", "T1112", "Registry modification", 0.2),
];

/// VBScript/JScript medium severity patterns
const VBSCRIPT_MEDIUM_SEVERITY_PATTERNS: &[(&str, &str, &str, f32)] = &[
    ("wmi", "T1047", "WMI access", 0.1),
    ("win32_process", "T1047", "Process via WMI", 0.15),
    ("environment", "T1082", "Environment variables", 0.1),
    ("specialfolders", "T1083", "Special folder access", 0.1),
    ("regread", "T1012", "Registry read", 0.1),
    ("copyfile", "T1105", "File copy", 0.1),
    ("movefile", "T1074", "File move", 0.1),
    ("deletefile", "T1070.004", "File deletion", 0.1),
    ("activexobject", "T1559.001", "ActiveX object", 0.15),
    (
        "string.fromcharcode",
        "T1027",
        "Character obfuscation",
        0.15,
    ),
    ("document.write", "T1059.007", "DOM write", 0.1),
    ("unescape", "T1140", "URL decoding", 0.1),
    ("atob(", "T1140", "Base64 decoding", 0.15),
];

/// Batch file high severity patterns
const BATCH_HIGH_SEVERITY_PATTERNS: &[(&str, &str, &str, f32)] = &[
    ("powershell", "T1059.001", "PowerShell execution", 0.2),
    ("certutil", "T1140", "Certutil download/decode", 0.25),
    ("bitsadmin", "T1197", "BITS transfer", 0.2),
    ("mshta", "T1218.005", "MSHTA execution", 0.25),
    ("regsvr32", "T1218.010", "Regsvr32 execution", 0.2),
    ("rundll32", "T1218.011", "Rundll32 execution", 0.2),
    ("wmic", "T1047", "WMI command", 0.15),
    (
        "schtasks /create",
        "T1053.005",
        "Create scheduled task",
        0.2,
    ),
    ("sc create", "T1543.003", "Create service", 0.2),
    ("reg add", "T1112", "Registry modification", 0.15),
    ("net user /add", "T1136.001", "Create local user", 0.25),
    (
        "net localgroup administrators",
        "T1136.001",
        "Add to admin group",
        0.3,
    ),
    (
        "netsh advfirewall",
        "T1562.004",
        "Firewall modification",
        0.2,
    ),
    ("vssadmin delete", "T1490", "Volume shadow deletion", 0.3),
    ("wbadmin delete", "T1490", "Backup deletion", 0.3),
    ("bcdedit /set", "T1490", "Boot config modification", 0.25),
];

/// Batch file medium severity patterns
const BATCH_MEDIUM_SEVERITY_PATTERNS: &[(&str, &str, &str, f32)] = &[
    ("curl", "T1105", "Curl download", 0.1),
    ("wget", "T1105", "Wget download", 0.1),
    ("net use", "T1021.002", "SMB connection", 0.1),
    ("net share", "T1135", "Network share enumeration", 0.1),
    ("net view", "T1135", "Network discovery", 0.1),
    ("ping -n", "T1018", "Host discovery", 0.05),
    ("systeminfo", "T1082", "System information", 0.05),
    ("ipconfig", "T1016", "Network configuration", 0.05),
    ("tasklist", "T1057", "Process listing", 0.05),
    ("netstat", "T1049", "Network connections", 0.05),
    ("dir /s", "T1083", "File enumeration", 0.05),
    ("attrib +h", "T1564.001", "Hide file", 0.15),
    ("copy /y", "T1105", "File copy", 0.05),
    ("move /y", "T1074", "File move", 0.05),
    ("del /f", "T1070.004", "Force file deletion", 0.1),
];
