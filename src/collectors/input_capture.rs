//! Input Capture Detection Collector
//!
//! Detects keylogger and input capture activities including:
//! - Windows keyboard hooks (SetWindowsHookEx WH_KEYBOARD/WH_KEYBOARD_LL)
//! - GetAsyncKeyState polling detection
//! - Raw Input API abuse
//! - Screen capture detection (BitBlt, PrintWindow, DWM)
//! - Input injection (SendInput, keybd_event)
//! - Linux /dev/input monitoring
//! - Known malware patterns (FormBook, Agent Tesla, Snake, HawkEye)
//!
//! MITRE ATT&CK: T1056 (Input Capture)
//!   - T1056.001 (Keylogging)
//!   - T1056.002 (GUI Input Capture)
//!   - T1113 (Screen Capture)

// Detector for keylogger and screen-capture malware families (FormBook, Agent
// Tesla, Snake, HawkEye). Several fields/parameters are scaffolded for
// upcoming detection stages and platform-specific code paths.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Input capture event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputCaptureEvent {
    /// Process ID performing input capture
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Type of input capture detected
    pub capture_type: InputCaptureType,
    /// Specific technique used
    pub technique: String,
    /// Additional details
    pub details: String,
    /// Whether process has visible UI
    pub has_visible_window: bool,
    /// Whether process is from suspicious location
    pub suspicious_location: bool,
    /// Matched malware family (if any)
    pub malware_family: Option<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// Types of input capture detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputCaptureType {
    /// Keyboard hook (SetWindowsHookEx WH_KEYBOARD*)
    KeyboardHook,
    /// GetAsyncKeyState polling
    KeyStatePolling,
    /// Raw Input API
    RawInput,
    /// Keyboard driver chain manipulation
    DriverChain,
    /// Screen capture (BitBlt, PrintWindow, etc.)
    ScreenCapture,
    /// Input injection (SendInput, keybd_event)
    InputInjection,
    /// Mouse hook
    MouseHook,
    /// UI Automation abuse
    UiAutomation,
    /// Linux evdev/input monitoring
    LinuxInput,
    /// Clipboard monitoring
    ClipboardMonitor,
    /// Known malware pattern
    MalwarePattern,
}

impl InputCaptureType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KeyboardHook => "keyboard_hook",
            Self::KeyStatePolling => "key_state_polling",
            Self::RawInput => "raw_input",
            Self::DriverChain => "driver_chain",
            Self::ScreenCapture => "screen_capture",
            Self::InputInjection => "input_injection",
            Self::MouseHook => "mouse_hook",
            Self::UiAutomation => "ui_automation",
            Self::LinuxInput => "linux_input",
            Self::ClipboardMonitor => "clipboard_monitor",
            Self::MalwarePattern => "malware_pattern",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::KeyboardHook => "T1056.001",
            Self::KeyStatePolling => "T1056.001",
            Self::RawInput => "T1056.001",
            Self::DriverChain => "T1056.001",
            Self::ScreenCapture => "T1113",
            Self::InputInjection => "T1056.002",
            Self::MouseHook => "T1056.002",
            Self::UiAutomation => "T1056.002",
            Self::LinuxInput => "T1056.001",
            Self::ClipboardMonitor => "T1115",
            Self::MalwarePattern => "T1056",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::KeyboardHook => Severity::High,
            Self::KeyStatePolling => Severity::High,
            Self::RawInput => Severity::Medium,
            Self::DriverChain => Severity::Critical,
            Self::ScreenCapture => Severity::Medium,
            Self::InputInjection => Severity::Medium,
            Self::MouseHook => Severity::Low,
            Self::UiAutomation => Severity::Low,
            Self::LinuxInput => Severity::High,
            Self::ClipboardMonitor => Severity::Medium,
            Self::MalwarePattern => Severity::Critical,
        }
    }
}

/// Known malware signatures for keyloggers
#[derive(Debug, Clone)]
struct MalwareSignature {
    family: &'static str,
    patterns: Vec<&'static str>,
    dll_names: Vec<&'static str>,
    registry_keys: Vec<&'static str>,
    file_patterns: Vec<&'static str>,
}

/// Legitimate processes that may use input capture APIs
static LEGITIMATE_PROCESSES: &[&str] = &[
    // Remote desktop software
    "mstsc.exe",
    "teamviewer",
    "anydesk",
    "vnc",
    "rdp",
    "citrix",
    "logmein",
    "splashtop",
    "parsec",
    "nomachine",
    // Accessibility tools
    "narrator.exe",
    "magnify.exe",
    "osk.exe",
    "tabtip.exe",
    "utilman.exe",
    "atbroker.exe",
    "displayswitch.exe",
    // Antivirus/security products
    "mbam",
    "malwarebytes",
    "avast",
    "avg",
    "kaspersky",
    "mcafee",
    "norton",
    "bitdefender",
    "eset",
    "sophos",
    "crowdstrike",
    "sentinel",
    "carbonblack",
    "defender",
    "msmpeng.exe",
    // Password managers
    "1password",
    "lastpass",
    "keepass",
    "bitwarden",
    "dashlane",
    "roboform",
    // Input/gaming software
    "autohotkey",
    "razer",
    "logitech",
    "corsair",
    "steelseries",
    "hyperx",
    // Virtual machines
    "vmtoolsd",
    "vboxservice",
    "vmwaretray",
    // IDEs and development tools
    "devenv.exe",
    "code.exe",
    "idea64.exe",
    "eclipse.exe",
    // Productivity
    "snagit",
    "camtasia",
    "obs64.exe",
    "sharex",
    "greenshot",
    "lightshot",
    // System utilities
    "dwm.exe",
    "explorer.exe",
    "searchui.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "runtimebroker.exe",
    "applicationframehost.exe",
    "systemsettings.exe",
    "textinputhost.exe",
    "ctfmon.exe",
    // Linux tools
    "xdotool",
    "xclip",
    "xsel",
    "ydotool",
    "wl-copy",
    "wl-paste",
];

/// Suspicious paths where keyloggers often reside
static SUSPICIOUS_PATHS: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "~/.local/share/",
    "~/.cache/",
];

/// Input capture collector
pub struct InputCaptureCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl InputCaptureCollector {
    /// Create a new input capture collector
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

    /// Check if a process is whitelisted
    fn is_whitelisted(process_name: &str, process_path: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        let path_lower = process_path.to_lowercase();

        LEGITIMATE_PROCESSES
            .iter()
            .any(|&legit| name_lower.contains(legit) || path_lower.contains(legit))
    }

    /// Check if path is suspicious
    fn is_suspicious_path(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        SUSPICIOUS_PATHS
            .iter()
            .any(|&susp| path_lower.contains(susp))
    }

    /// Get known malware signatures
    fn get_malware_signatures() -> Vec<MalwareSignature> {
        vec![
            // FormBook keylogger
            MalwareSignature {
                family: "FormBook",
                patterns: vec!["formbook", "xloader"],
                dll_names: vec!["ntdll_", "kernel32_"],
                registry_keys: vec!["Software\\AppDataLow\\Software\\"],
                file_patterns: vec!["ms*.exe", "my*.exe"],
            },
            // Agent Tesla
            MalwareSignature {
                family: "AgentTesla",
                patterns: vec!["agenttesla", "agent tesla", "teslaagent"],
                dll_names: vec!["webclient", "smtp"],
                registry_keys: vec!["Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                file_patterns: vec!["*.scr", "*document*.exe"],
            },
            // Snake Keylogger
            MalwareSignature {
                family: "SnakeKeylogger",
                patterns: vec!["snake", "404keylogger"],
                dll_names: vec!["costura"],
                registry_keys: vec!["Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                file_patterns: vec!["*snake*.exe"],
            },
            // HawkEye Keylogger
            MalwareSignature {
                family: "HawkEye",
                patterns: vec!["hawkeye", "hawk eye", "predator"],
                dll_names: vec!["hawkeye"],
                registry_keys: vec!["Software\\HawkEye"],
                file_patterns: vec!["*hawk*.exe"],
            },
            // Remcos RAT (has keylogging)
            MalwareSignature {
                family: "Remcos",
                patterns: vec!["remcos"],
                dll_names: vec![],
                registry_keys: vec!["Software\\Remcos"],
                file_patterns: vec!["*remcos*.exe"],
            },
            // LokiBot
            MalwareSignature {
                family: "LokiBot",
                patterns: vec!["lokibot", "loki bot"],
                dll_names: vec![],
                registry_keys: vec![],
                file_patterns: vec!["*loki*.exe"],
            },
            // Azorult
            MalwareSignature {
                family: "Azorult",
                patterns: vec!["azorult", "azor"],
                dll_names: vec![],
                registry_keys: vec![],
                file_patterns: vec!["*azor*.exe"],
            },
        ]
    }

    /// Check for known malware patterns
    fn check_malware_patterns(
        process_name: &str,
        process_path: &str,
        _loaded_dlls: &[String],
    ) -> Option<String> {
        let name_lower = process_name.to_lowercase();
        let path_lower = process_path.to_lowercase();

        for sig in Self::get_malware_signatures() {
            // Check name patterns
            for pattern in &sig.patterns {
                if name_lower.contains(pattern) || path_lower.contains(pattern) {
                    return Some(sig.family.to_string());
                }
            }

            // Check file patterns (basic glob matching)
            for file_pattern in &sig.file_patterns {
                let pattern = file_pattern.replace("*", "");
                if !pattern.is_empty() && path_lower.contains(&pattern) {
                    return Some(sig.family.to_string());
                }
            }
        }

        None
    }

    /// Create telemetry event from input capture detection
    fn create_input_capture_event(capture: &InputCaptureEvent) -> TelemetryEvent {
        let severity = if capture.malware_family.is_some() {
            Severity::Critical
        } else if capture.suspicious_location && !capture.has_visible_window {
            Severity::High
        } else {
            capture.capture_type.severity()
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate, // Using ProcessCreate as InputCapture is not defined
            severity,
            EventPayload::Process(ProcessEvent {
                pid: capture.pid,
                ppid: 0,
                name: capture.process_name.clone(),
                path: capture.process_path.clone(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        // Build detection description
        let description = if let Some(ref family) = capture.malware_family {
            format!(
                "Known keylogger malware detected: {} - {} from {} (PID: {})",
                family, capture.process_name, capture.process_path, capture.pid
            )
        } else {
            format!(
                "Input capture activity detected: {} using {} - {} (PID: {}). {}",
                capture.capture_type.as_str(),
                capture.technique,
                capture.process_name,
                capture.pid,
                capture.details
            )
        };

        event.add_detection(Detection {
            detection_type: if capture.malware_family.is_some() {
                DetectionType::Malware
            } else {
                DetectionType::Behavioral
            },
            rule_name: format!("input_capture_{}", capture.capture_type.as_str()),
            confidence: capture.confidence,
            description,
            mitre_tactics: vec!["collection".to_string(), "credential-access".to_string()],
            mitre_techniques: vec![capture.capture_type.mitre_technique().to_string()],
        });

        // Add metadata
        event.metadata.insert(
            "capture_type".to_string(),
            capture.capture_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("technique".to_string(), capture.technique.clone());
        event.metadata.insert(
            "has_visible_window".to_string(),
            capture.has_visible_window.to_string(),
        );
        event.metadata.insert(
            "suspicious_location".to_string(),
            capture.suspicious_location.to_string(),
        );

        if let Some(ref family) = capture.malware_family {
            event
                .metadata
                .insert("malware_family".to_string(), family.clone());
        }

        event
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Windows input capture monitor");

        // Track processes with suspicious behavior
        let suspicious_processes: Arc<Mutex<HashMap<u32, ProcessBehavior>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Start hook enumeration task
        let tx_clone = tx.clone();
        let sp_clone = suspicious_processes.clone();
        tokio::spawn(async move {
            Self::enumerate_hooks_loop(tx_clone, sp_clone).await;
        });

        // Start API monitoring task
        let tx_clone = tx.clone();
        let sp_clone = suspicious_processes.clone();
        tokio::spawn(async move {
            Self::monitor_input_apis_loop(tx_clone, sp_clone).await;
        });

        // Start screen capture detection task
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::detect_screen_capture_loop(tx_clone).await;
        });

        // Main behavior analysis loop
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            let mut procs = suspicious_processes.lock().await;

            // Analyze behavior patterns
            for (pid, behavior) in procs.iter_mut() {
                if let Some(capture) = Self::analyze_process_behavior(*pid, behavior) {
                    // Check whitelist
                    if Self::is_whitelisted(&capture.process_name, &capture.process_path) {
                        debug!(
                            pid = *pid,
                            name = %capture.process_name,
                            "Whitelisted process using input capture APIs"
                        );
                        continue;
                    }

                    let event = Self::create_input_capture_event(&capture);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }

                    // Mark as reported
                    behavior.reported = true;
                }
            }

            // Clean up old entries
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            procs.retain(|_, b| now - b.last_activity < 60 && !b.reported);
        }
    }

    #[cfg(target_os = "windows")]
    async fn enumerate_hooks_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        suspicious_processes: std::sync::Arc<tokio::sync::Mutex<HashMap<u32, ProcessBehavior>>>,
    ) {
        info!("Starting keyboard hook enumeration");

        let mut known_hooks: HashSet<u32> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        loop {
            interval.tick().await;

            // Enumerate global hooks by checking for hook DLLs
            // Also check for hidden windows with keyboard hooks
            let processes_with_hooks = Self::find_processes_with_hooks();

            for (pid, hook_type, process_name, process_path) in processes_with_hooks {
                if known_hooks.contains(&pid) {
                    continue;
                }

                // Check if process has visible window
                let has_visible_window = Self::process_has_visible_window(pid);

                // Check if from suspicious location
                let suspicious_location = Self::is_suspicious_path(&process_path);

                // Skip whitelisted processes
                if Self::is_whitelisted(&process_name, &process_path) {
                    debug!(
                        pid = pid,
                        name = %process_name,
                        "Whitelisted process with keyboard hook"
                    );
                    continue;
                }

                // Check for malware patterns
                let loaded_dlls = Self::get_loaded_dlls(pid);
                let malware_family =
                    Self::check_malware_patterns(&process_name, &process_path, &loaded_dlls);

                // Determine if suspicious
                let is_suspicious = malware_family.is_some()
                    || (suspicious_location && !has_visible_window)
                    || (!has_visible_window && hook_type == "WH_KEYBOARD_LL");

                if is_suspicious {
                    known_hooks.insert(pid);

                    // Reduced confidence for generic pattern matches to
                    // avoid false positives from legitimate software
                    let confidence = if malware_family.is_some() {
                        0.9
                    } else if !has_visible_window && suspicious_location {
                        0.7
                    } else {
                        0.5
                    };

                    let capture = InputCaptureEvent {
                        pid,
                        process_name: process_name.clone(),
                        process_path: process_path.clone(),
                        capture_type: InputCaptureType::KeyboardHook,
                        technique: hook_type.clone(),
                        details: format!(
                            "Process installed {} keyboard hook{}",
                            hook_type,
                            if !has_visible_window {
                                " without visible window"
                            } else {
                                ""
                            }
                        ),
                        has_visible_window,
                        suspicious_location,
                        malware_family,
                        confidence,
                    };

                    let event = Self::create_input_capture_event(&capture);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Cleanup old entries
            if known_hooks.len() > 1000 {
                known_hooks.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn find_processes_with_hooks() -> Vec<(u32, String, String, String)> {
        use sysinfo::{ProcessRefreshKind, System};

        let mut results = Vec::new();
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            let process_name = process.name().to_string();
            let process_path = process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // Check if process has loaded hook-related DLLs or patterns
            let loaded_dlls = Self::get_loaded_dlls(pid_u32);

            // Check for SetWindowsHookEx patterns
            let has_user32 = loaded_dlls
                .iter()
                .any(|d| d.to_lowercase().contains("user32"));

            // Check for suspicious imports/patterns that indicate keylogging.
            // NOTE: "monitor" and "logger" were removed because they are
            // extremely generic and match many legitimate applications
            // (e.g., "resource monitor", "event logger", "performance monitor").
            let suspicious_patterns = ["hook", "keyboard", "keylog", "capture", "spy"];

            let path_lower = process_path.to_lowercase();
            let name_lower = process_name.to_lowercase();

            let matches_pattern = suspicious_patterns
                .iter()
                .any(|p| path_lower.contains(p) || name_lower.contains(p));

            if has_user32 && matches_pattern {
                results.push((
                    pid_u32,
                    "WH_KEYBOARD_LL".to_string(),
                    process_name,
                    process_path,
                ));
            }
        }

        // Also check via NtQuerySystemInformation for global hooks
        // This requires elevated privileges
        if let Some(hooks) = Self::enumerate_global_hooks() {
            for (pid, hook_type) in hooks {
                let (name, path) = Self::get_process_info(pid);
                if !results.iter().any(|(p, _, _, _)| *p == pid) {
                    results.push((pid, hook_type, name, path));
                }
            }
        }

        results
    }

    #[cfg(target_os = "windows")]
    fn enumerate_global_hooks() -> Option<Vec<(u32, String)>> {
        // Scan for processes with hooked input-related APIs
        // This uses proper IAT scanning and inline hook detection
        use sysinfo::{ProcessRefreshKind, System};

        let mut results = Vec::new();
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        for (pid, _process) in system.processes() {
            let pid_u32 = pid.as_u32();

            // Check for hooks in this process
            if let Some(hooks) = HookScanner::scan_process(pid_u32) {
                for hook in hooks {
                    // Only report hooks on input-related functions
                    if hook.is_input_related() {
                        results.push((
                            pid_u32,
                            format!("{}:{}", hook.hook_type.as_str(), hook.function_name),
                        ));
                    }
                }
            }
        }

        if results.is_empty() {
            None
        } else {
            Some(results)
        }
    }

    #[cfg(target_os = "windows")]
    fn get_loaded_dlls(pid: u32) -> Vec<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        };

        let mut dlls = Vec::new();

        unsafe {
            let snapshot =
                match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
                    Ok(h) => h,
                    Err(_) => return dlls,
                };

            let mut entry = MODULEENTRY32W {
                dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            if Module32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szModule[..entry.szModule.iter().position(|&c| c == 0).unwrap_or(0)],
                    );
                    dlls.push(name);

                    if Module32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        dlls
    }

    #[cfg(target_os = "windows")]
    fn process_has_visible_window(pid: u32) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
        };

        static HAS_VISIBLE: AtomicBool = AtomicBool::new(false);
        static TARGET_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

        TARGET_PID.store(pid, Ordering::SeqCst);
        HAS_VISIBLE.store(false, Ordering::SeqCst);

        unsafe extern "system" fn enum_callback(hwnd: HWND, _: LPARAM) -> BOOL {
            let mut window_pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut window_pid));

            if window_pid == TARGET_PID.load(Ordering::SeqCst) {
                if IsWindowVisible(hwnd).as_bool() {
                    HAS_VISIBLE.store(true, Ordering::SeqCst);
                    return BOOL(0); // Stop enumeration
                }
            }
            BOOL(1) // Continue enumeration
        }

        unsafe {
            let _ = EnumWindows(Some(enum_callback), LPARAM(0));
        }

        HAS_VISIBLE.load(Ordering::SeqCst)
    }

    #[cfg(target_os = "windows")]
    fn get_process_info(pid: u32) -> (String, String) {
        use sysinfo::{Pid, ProcessRefreshKind, System};

        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::new());

        if let Some(process) = system.process(Pid::from_u32(pid)) {
            (
                process.name().to_string(),
                process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
            )
        } else {
            ("unknown".to_string(), String::new())
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_input_apis_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        suspicious_processes: std::sync::Arc<tokio::sync::Mutex<HashMap<u32, ProcessBehavior>>>,
    ) {
        use sysinfo::{ProcessRefreshKind, System};

        info!("Starting input API monitoring");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));

        loop {
            interval.tick().await;

            let mut system = System::new();
            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let process_name = process.name().to_string();
                let process_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip whitelisted processes early
                if Self::is_whitelisted(&process_name, &process_path) {
                    continue;
                }

                // Check for suspicious API usage patterns
                let api_usage = Self::detect_api_usage(pid_u32);

                if api_usage.has_suspicious_activity {
                    let mut procs = suspicious_processes.lock().await;
                    let behavior = procs.entry(pid_u32).or_insert_with(|| ProcessBehavior {
                        process_name: process_name.clone(),
                        process_path: process_path.clone(),
                        api_calls: HashMap::new(),
                        first_seen: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        last_activity: 0,
                        reported: false,
                    });

                    behavior.last_activity = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Update API call counts
                    for (api, count) in &api_usage.api_calls {
                        *behavior.api_calls.entry(api.clone()).or_insert(0) += count;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn detect_api_usage(pid: u32) -> ApiUsageResult {
        // This would ideally use ETW or API hooking for accurate detection
        // Simplified version checks for imported APIs and memory patterns

        let mut result = ApiUsageResult {
            has_suspicious_activity: false,
            api_calls: HashMap::new(),
        };

        // Check for suspicious imported functions
        let dlls = Self::get_loaded_dlls(pid);

        // Check for keyboard/input related DLLs
        let input_dlls = ["user32.dll", "imm32.dll", "hid.dll"];
        let has_input_dlls = dlls.iter().any(|d| {
            let lower = d.to_lowercase();
            input_dlls.iter().any(|i| lower == *i)
        });

        if has_input_dlls {
            // In production, would check for specific API imports:
            // - SetWindowsHookExW/A
            // - GetAsyncKeyState
            // - RegisterRawInputDevices
            // - GetRawInputData
            // - SendInput
            // - keybd_event
            // - GetKeyboardState
            // - GetKeyState

            // Simplified check based on process characteristics
            result.has_suspicious_activity = true;
            result.api_calls.insert("user32_loaded".to_string(), 1);
        }

        result
    }

    #[cfg(target_os = "windows")]
    async fn detect_screen_capture_loop(tx: mpsc::Sender<TelemetryEvent>) {
        use sysinfo::{ProcessRefreshKind, System};

        info!("Starting screen capture detection");

        let mut known_captures: HashSet<u32> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            let mut system = System::new();
            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();

                if known_captures.contains(&pid_u32) {
                    continue;
                }

                let process_name = process.name().to_string();
                let process_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip whitelisted processes
                if Self::is_whitelisted(&process_name, &process_path) {
                    continue;
                }

                // Check for screen capture indicators
                let dlls = Self::get_loaded_dlls(pid_u32);

                let has_gdi = dlls.iter().any(|d| d.to_lowercase() == "gdi32.dll");
                let has_dwm = dlls.iter().any(|d| d.to_lowercase().contains("dwmapi"));
                let has_d3d = dlls.iter().any(|d| {
                    let lower = d.to_lowercase();
                    lower.contains("d3d") || lower.contains("dxgi")
                });

                // Check for suspicious patterns suggesting screen capture
                let path_lower = process_path.to_lowercase();
                let name_lower = process_name.to_lowercase();

                let capture_patterns = ["capture", "screen", "shot", "grab", "record", "spy"];
                let matches_pattern = capture_patterns
                    .iter()
                    .any(|p| path_lower.contains(p) || name_lower.contains(p));

                let suspicious_location = Self::is_suspicious_path(&process_path);
                let has_visible_window = Self::process_has_visible_window(pid_u32);

                // Suspicious if: has GDI/DWM/D3D + pattern match + suspicious location
                let is_suspicious = (has_gdi || has_dwm || has_d3d)
                    && matches_pattern
                    && (suspicious_location || !has_visible_window);

                if is_suspicious {
                    known_captures.insert(pid_u32);

                    let technique = if has_dwm {
                        "DWM Capture API"
                    } else if has_d3d {
                        "DirectX Capture"
                    } else {
                        "GDI Capture (BitBlt/StretchBlt)"
                    };

                    let capture = InputCaptureEvent {
                        pid: pid_u32,
                        process_name: process_name.clone(),
                        process_path: process_path.clone(),
                        capture_type: InputCaptureType::ScreenCapture,
                        technique: technique.to_string(),
                        details: format!(
                            "Suspected screen capture activity from {}",
                            if suspicious_location {
                                "suspicious location"
                            } else {
                                "hidden window"
                            }
                        ),
                        has_visible_window,
                        suspicious_location,
                        malware_family: Self::check_malware_patterns(
                            &process_name,
                            &process_path,
                            &dlls,
                        ),
                        confidence: 0.6,
                    };

                    let event = Self::create_input_capture_event(&capture);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Cleanup
            if known_captures.len() > 1000 {
                known_captures.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn analyze_process_behavior(pid: u32, behavior: &ProcessBehavior) -> Option<InputCaptureEvent> {
        if behavior.reported {
            return None;
        }

        // Check for high-frequency GetAsyncKeyState polling
        if let Some(&count) = behavior.api_calls.get("GetAsyncKeyState") {
            let duration = behavior.last_activity - behavior.first_seen;
            if duration > 0 {
                let calls_per_second = count as f64 / duration as f64;

                // More than 10 calls/second is suspicious
                if calls_per_second > 10.0 {
                    return Some(InputCaptureEvent {
                        pid,
                        process_name: behavior.process_name.clone(),
                        process_path: behavior.process_path.clone(),
                        capture_type: InputCaptureType::KeyStatePolling,
                        technique: "GetAsyncKeyState".to_string(),
                        details: format!(
                            "High-frequency key state polling: {:.1} calls/second",
                            calls_per_second
                        ),
                        has_visible_window: Self::process_has_visible_window(pid),
                        suspicious_location: Self::is_suspicious_path(&behavior.process_path),
                        malware_family: Self::check_malware_patterns(
                            &behavior.process_name,
                            &behavior.process_path,
                            &[],
                        ),
                        confidence: 0.85,
                    });
                }
            }
        }

        None
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn linux_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        info!("Starting Linux input capture monitor");

        // Monitor /dev/input access
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_dev_input(tx_clone).await;
        });

        // Monitor xinput/evdev usage
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_xinput(tx_clone).await;
        });

        // Monitor for keylogger processes
        Self::monitor_keylogger_processes(tx, config).await;
    }

    #[cfg(target_os = "linux")]
    async fn monitor_dev_input(tx: mpsc::Sender<TelemetryEvent>) {
        use std::collections::HashSet;
        use std::fs;

        info!("Starting /dev/input monitor");

        let mut known_readers: HashSet<(u32, String)> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        loop {
            interval.tick().await;

            // Check which processes have /dev/input/* open
            if let Ok(proc_entries) = fs::read_dir("/proc") {
                for entry in proc_entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        let fd_path = format!("/proc/{}/fd", pid);

                        if let Ok(fds) = fs::read_dir(&fd_path) {
                            for fd in fds.flatten() {
                                if let Ok(target) = fs::read_link(fd.path()) {
                                    let target_str = target.to_string_lossy();

                                    // Check for /dev/input/event* or /dev/input/mice
                                    if target_str.starts_with("/dev/input/") {
                                        let key = (pid, target_str.to_string());

                                        if !known_readers.contains(&key) {
                                            known_readers.insert(key.clone());

                                            let process_name = Self::get_process_name(pid);
                                            let process_path = Self::get_process_path(pid);

                                            // Skip whitelisted processes
                                            if Self::is_whitelisted(&process_name, &process_path) {
                                                debug!(
                                                    pid = pid,
                                                    name = %process_name,
                                                    "Whitelisted process reading /dev/input"
                                                );
                                                continue;
                                            }

                                            // Skip X server and input drivers
                                            if process_name.contains("Xorg")
                                                || process_name.contains("Xwayland")
                                                || process_name.contains("libinput")
                                                || process_name.contains("inputattach")
                                            {
                                                continue;
                                            }

                                            let suspicious_location =
                                                Self::is_suspicious_path(&process_path);

                                            let capture = InputCaptureEvent {
                                                pid,
                                                process_name: process_name.clone(),
                                                process_path: process_path.clone(),
                                                capture_type: InputCaptureType::LinuxInput,
                                                technique: "evdev".to_string(),
                                                details: format!(
                                                    "Process reading input device: {}",
                                                    target_str
                                                ),
                                                has_visible_window: true, // Can't easily check on Linux
                                                suspicious_location,
                                                malware_family: Self::check_malware_patterns(
                                                    &process_name,
                                                    &process_path,
                                                    &[],
                                                ),
                                                confidence: if suspicious_location {
                                                    0.8
                                                } else {
                                                    0.5
                                                },
                                            };

                                            let event = Self::create_input_capture_event(&capture);
                                            if tx.send(event).await.is_err() {
                                                warn!("Event channel closed");
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if known_readers.len() > 1000 {
                known_readers.clear();
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_xinput(tx: mpsc::Sender<TelemetryEvent>) {
        use std::collections::HashSet;
        use std::fs;

        info!("Starting xinput/libinput monitor");

        let mut known_processes: HashSet<u32> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Check for processes using xinput or xlib input functions
            if let Ok(proc_entries) = fs::read_dir("/proc") {
                for entry in proc_entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        if known_processes.contains(&pid) {
                            continue;
                        }

                        let maps_path = format!("/proc/{}/maps", pid);

                        if let Ok(content) = fs::read_to_string(&maps_path) {
                            // Check for suspicious library mappings
                            let has_xrecord = content.contains("libXtst");
                            let has_xinput = content.contains("libXi");
                            let has_evdev = content.contains("libevdev");

                            if has_xrecord || has_xinput || has_evdev {
                                let process_name = Self::get_process_name(pid);
                                let process_path = Self::get_process_path(pid);

                                // Skip whitelisted
                                if Self::is_whitelisted(&process_name, &process_path) {
                                    continue;
                                }

                                // Skip desktop environments and common tools
                                let skip_patterns = [
                                    "gnome", "kde", "xfce", "mate", "cinnamon", "mutter", "kwin",
                                    "compiz", "marco",
                                ];

                                if skip_patterns
                                    .iter()
                                    .any(|p| process_name.to_lowercase().contains(p))
                                {
                                    continue;
                                }

                                let suspicious_location = Self::is_suspicious_path(&process_path);

                                let technique = if has_xrecord {
                                    "XRecord Extension"
                                } else if has_xinput {
                                    "XInput Extension"
                                } else {
                                    "libevdev"
                                };

                                // Only report if from suspicious location
                                if suspicious_location {
                                    known_processes.insert(pid);

                                    let capture = InputCaptureEvent {
                                        pid,
                                        process_name: process_name.clone(),
                                        process_path: process_path.clone(),
                                        capture_type: InputCaptureType::LinuxInput,
                                        technique: technique.to_string(),
                                        details: format!(
                                            "Process using {} from suspicious location",
                                            technique
                                        ),
                                        has_visible_window: true,
                                        suspicious_location,
                                        malware_family: Self::check_malware_patterns(
                                            &process_name,
                                            &process_path,
                                            &[],
                                        ),
                                        confidence: 0.7,
                                    };

                                    let event = Self::create_input_capture_event(&capture);
                                    if tx.send(event).await.is_err() {
                                        warn!("Event channel closed");
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if known_processes.len() > 1000 {
                known_processes.clear();
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_keylogger_processes(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        use std::collections::HashSet;
        use std::fs;

        info!("Starting keylogger process detection");

        let mut known_keyloggers: HashSet<u32> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

        // Known keylogger patterns
        let keylogger_patterns = [
            "logkeys",
            "lkl",
            "xspy",
            "keylogger",
            "kbdlog",
            "pylogger",
            "keysniff",
        ];

        loop {
            interval.tick().await;

            if let Ok(proc_entries) = fs::read_dir("/proc") {
                for entry in proc_entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        if known_keyloggers.contains(&pid) {
                            continue;
                        }

                        let process_name = Self::get_process_name(pid);
                        let process_path = Self::get_process_path(pid);
                        let cmdline = Self::get_process_cmdline(pid);

                        let name_lower = process_name.to_lowercase();
                        let path_lower = process_path.to_lowercase();
                        let cmd_lower = cmdline.to_lowercase();

                        // Check for known keylogger names
                        let matches = keylogger_patterns.iter().any(|p| {
                            name_lower.contains(p)
                                || path_lower.contains(p)
                                || cmd_lower.contains(p)
                        });

                        if matches {
                            known_keyloggers.insert(pid);

                            let capture = InputCaptureEvent {
                                pid,
                                process_name: process_name.clone(),
                                process_path: process_path.clone(),
                                capture_type: InputCaptureType::MalwarePattern,
                                technique: "Known Keylogger".to_string(),
                                details: format!("Known keylogger tool detected: {}", process_name),
                                has_visible_window: false,
                                suspicious_location: Self::is_suspicious_path(&process_path),
                                malware_family: Some("LinuxKeylogger".to_string()),
                                confidence: 0.95,
                            };

                            let event = Self::create_input_capture_event(&capture);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }
            }

            // Cleanup
            if known_keyloggers.len() > 500 {
                known_keyloggers.clear();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn get_process_name(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(target_os = "linux")]
    fn get_process_path(pid: u32) -> String {
        std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| String::new())
    }

    #[cfg(target_os = "linux")]
    fn get_process_cmdline(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .map(|s| s.replace('\0', " ").trim().to_string())
            .unwrap_or_default()
    }
}

// ==================== Hook Detection Implementation ====================

/// Type of hook detected
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// Import Address Table hook - IAT entry points to unexpected location
    IatHook,
    /// Inline hook - JMP instruction at function start
    InlineHook,
    /// Detours-style trampoline hook
    DetoursHook,
    /// Hardware breakpoint on debug register
    HardwareBreakpoint,
    /// Export Address Table hook
    EatHook,
}

#[cfg(target_os = "windows")]
impl HookType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IatHook => "iat_hook",
            Self::InlineHook => "inline_hook",
            Self::DetoursHook => "detours_hook",
            Self::HardwareBreakpoint => "hardware_bp",
            Self::EatHook => "eat_hook",
        }
    }
}

/// Detected hook information
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct HookInfo {
    /// Type of hook detected
    pub hook_type: HookType,
    /// Name of the hooked function
    pub function_name: String,
    /// DLL containing the hooked function
    pub module_name: String,
    /// Original function address (expected)
    pub original_address: u64,
    /// Current/hooked address (actual)
    pub hooked_address: u64,
    /// Target module that the hook points to (if identifiable)
    pub target_module: Option<String>,
    /// Hook instruction bytes (for inline hooks)
    pub hook_bytes: Option<Vec<u8>>,
}

#[cfg(target_os = "windows")]
impl HookInfo {
    /// Check if this hook is on an input-related function
    pub fn is_input_related(&self) -> bool {
        static INPUT_FUNCTIONS: &[&str] = &[
            // User32 keyboard/input functions
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "SetWindowsHookExW",
            "SetWindowsHookExA",
            "CallNextHookEx",
            "UnhookWindowsHookEx",
            "RegisterRawInputDevices",
            "GetRawInputData",
            "GetRawInputBuffer",
            "SendInput",
            "keybd_event",
            "mouse_event",
            "BlockInput",
            "GetKeyNameTextW",
            "GetKeyNameTextA",
            "MapVirtualKeyW",
            "MapVirtualKeyA",
            "ToUnicode",
            "ToAscii",
            "ToUnicodeEx",
            "ToAsciiEx",
            // Credential-related functions
            "CredReadW",
            "CredReadA",
            "CredWriteW",
            "CredWriteA",
            "CredEnumerateW",
            "CredEnumerateA",
            "CredFree",
            "LsaRetrievePrivateData",
            "LsaStorePrivateData",
            "CryptUnprotectData",
            "CryptProtectData",
            // Ntdll functions that keyloggers hook
            "NtQuerySystemInformation",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "LdrLoadDll",
            "NtUserGetAsyncKeyState",
            "NtUserGetKeyState",
            // Kernel32 functions
            "ReadProcessMemory",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "VirtualAllocEx",
            "VirtualProtectEx",
        ];

        let func_upper = self.function_name.to_uppercase();
        INPUT_FUNCTIONS
            .iter()
            .any(|f| func_upper == f.to_uppercase())
    }
}

/// PE Import Directory Entry (IMAGE_IMPORT_DESCRIPTOR)
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct ImageImportDescriptor {
    original_first_thunk: u32, // RVA to INT (Import Name Table)
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,        // RVA to DLL name
    first_thunk: u32, // RVA to IAT (Import Address Table)
}

/// Module information for hook validation
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct ModuleInfo {
    name: String,
    base_address: u64,
    size: u64,
}

/// Hook scanner for detecting API hooks in processes
#[cfg(target_os = "windows")]
pub struct HookScanner;

#[cfg(target_os = "windows")]
impl HookScanner {
    /// Critical functions to monitor for hooks
    const CRITICAL_FUNCTIONS: &'static [(&'static str, &'static str)] = &[
        // User32 - keyboard and input
        ("user32.dll", "GetAsyncKeyState"),
        ("user32.dll", "GetKeyState"),
        ("user32.dll", "GetKeyboardState"),
        ("user32.dll", "SetWindowsHookExW"),
        ("user32.dll", "SetWindowsHookExA"),
        ("user32.dll", "RegisterRawInputDevices"),
        ("user32.dll", "GetRawInputData"),
        ("user32.dll", "SendInput"),
        // Ntdll - low-level operations
        ("ntdll.dll", "NtQuerySystemInformation"),
        ("ntdll.dll", "NtReadVirtualMemory"),
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "LdrLoadDll"),
        // Kernel32 - process operations
        ("kernel32.dll", "ReadProcessMemory"),
        ("kernel32.dll", "WriteProcessMemory"),
        ("kernel32.dll", "CreateRemoteThread"),
        ("kernel32.dll", "VirtualAllocEx"),
        // Advapi32 - credentials
        ("advapi32.dll", "CredReadW"),
        ("advapi32.dll", "CredReadA"),
        ("advapi32.dll", "LsaRetrievePrivateData"),
        // Crypt32 - data protection
        ("crypt32.dll", "CryptUnprotectData"),
        ("crypt32.dll", "CryptProtectData"),
    ];

    /// Scan a process for API hooks
    pub fn scan_process(pid: u32) -> Option<Vec<HookInfo>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut hooks = Vec::new();

        // SAFETY: Opening process handle with minimal required permissions
        // Handle is properly closed at the end of the function
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get list of loaded modules for address validation
            let modules = Self::get_module_list(pid);

            // Scan IAT for hooks
            if let Some(iat_hooks) = Self::scan_iat_hooks(handle, pid, &modules) {
                hooks.extend(iat_hooks);
            }

            // Scan for inline hooks on critical functions
            if let Some(inline_hooks) = Self::scan_inline_hooks(handle, &modules) {
                hooks.extend(inline_hooks);
            }

            // Check for hardware breakpoints (debug registers)
            if let Some(hw_hooks) = Self::scan_hardware_breakpoints(pid) {
                hooks.extend(hw_hooks);
            }

            let _ = CloseHandle(handle);
        }

        if hooks.is_empty() {
            None
        } else {
            Some(hooks)
        }
    }

    /// Get list of loaded modules with their address ranges
    fn get_module_list(pid: u32) -> Vec<ModuleInfo> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        };

        let mut modules = Vec::new();

        // SAFETY: Creating snapshot of process modules
        // Snapshot handle is properly closed at the end
        unsafe {
            let snapshot =
                match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
                    Ok(h) => h,
                    Err(_) => return modules,
                };

            let mut entry = MODULEENTRY32W {
                dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            if Module32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szModule[..entry.szModule.iter().position(|&c| c == 0).unwrap_or(0)],
                    );

                    modules.push(ModuleInfo {
                        name: name.to_lowercase(),
                        base_address: entry.modBaseAddr as u64,
                        size: entry.modBaseSize as u64,
                    });

                    if Module32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        modules
    }

    /// Check if an address falls within any known module
    fn find_module_for_address(address: u64, modules: &[ModuleInfo]) -> Option<&ModuleInfo> {
        modules
            .iter()
            .find(|m| address >= m.base_address && address < m.base_address + m.size)
    }

    /// Scan Import Address Table for hooks
    fn scan_iat_hooks(
        handle: windows::Win32::Foundation::HANDLE,
        pid: u32,
        modules: &[ModuleInfo],
    ) -> Option<Vec<HookInfo>> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let mut hooks = Vec::new();

        // Get the main module (first in the list is usually the exe)
        let main_module = modules.first()?;

        // Read DOS header to find PE header
        let mut dos_header = [0u8; 64];
        let mut bytes_read = 0usize;

        // SAFETY: Reading DOS header from process memory
        // Buffer is properly sized and bytes_read is checked
        unsafe {
            if ReadProcessMemory(
                handle,
                main_module.base_address as *const _,
                dos_header.as_mut_ptr() as *mut _,
                64,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read < 64
            {
                return None;
            }
        }

        // Verify MZ signature
        if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
            return None;
        }

        // Get e_lfanew (offset to PE header)
        let e_lfanew = u32::from_le_bytes([
            dos_header[60],
            dos_header[61],
            dos_header[62],
            dos_header[63],
        ]) as u64;

        // Read PE header
        let mut pe_header = [0u8; 512];

        // SAFETY: Reading PE header from process memory
        // e_lfanew is validated from DOS header, buffer is sized for typical PE headers
        unsafe {
            if ReadProcessMemory(
                handle,
                (main_module.base_address + e_lfanew) as *const _,
                pe_header.as_mut_ptr() as *mut _,
                512,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read < 256
            {
                return None;
            }
        }

        // Verify PE signature
        if pe_header[0] != 0x50 || pe_header[1] != 0x45 || pe_header[2] != 0 || pe_header[3] != 0 {
            return None;
        }

        // Get optional header magic to determine PE32 or PE32+
        let magic = u16::from_le_bytes([pe_header[24], pe_header[25]]);
        let is_pe64 = magic == 0x20B;

        // Get import directory RVA and size
        let (import_dir_rva, _import_dir_size) = if is_pe64 {
            // PE32+: Import directory is at offset 120 in optional header (offset 144 from PE sig)
            let rva = u32::from_le_bytes([
                pe_header[144],
                pe_header[145],
                pe_header[146],
                pe_header[147],
            ]);
            let size = u32::from_le_bytes([
                pe_header[148],
                pe_header[149],
                pe_header[150],
                pe_header[151],
            ]);
            (rva, size)
        } else {
            // PE32: Import directory is at offset 104 in optional header (offset 128 from PE sig)
            let rva = u32::from_le_bytes([
                pe_header[128],
                pe_header[129],
                pe_header[130],
                pe_header[131],
            ]);
            let size = u32::from_le_bytes([
                pe_header[132],
                pe_header[133],
                pe_header[134],
                pe_header[135],
            ]);
            (rva, size)
        };

        if import_dir_rva == 0 {
            return None;
        }

        // Read import descriptors
        let import_dir_addr = main_module.base_address + import_dir_rva as u64;
        let descriptor_size = std::mem::size_of::<ImageImportDescriptor>();
        let mut descriptor_offset = 0u64;

        loop {
            let mut descriptor = ImageImportDescriptor::default();

            // SAFETY: Reading import descriptor from process memory
            // Each descriptor is validated before use
            unsafe {
                if ReadProcessMemory(
                    handle,
                    (import_dir_addr + descriptor_offset) as *const _,
                    &mut descriptor as *mut _ as *mut _,
                    descriptor_size,
                    Some(&mut bytes_read),
                )
                .is_err()
                    || bytes_read < descriptor_size
                {
                    break;
                }
            }

            // Check for null terminator
            if descriptor.first_thunk == 0 && descriptor.name == 0 {
                break;
            }

            // Read DLL name
            let dll_name = Self::read_string_from_process(
                handle,
                main_module.base_address + descriptor.name as u64,
                256,
            );

            if dll_name.is_empty() {
                descriptor_offset += descriptor_size as u64;
                continue;
            }

            // Find the expected module for this DLL
            let expected_module = modules
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(&dll_name));

            // Read IAT entries
            let iat_addr = main_module.base_address + descriptor.first_thunk as u64;
            let int_addr = if descriptor.original_first_thunk != 0 {
                main_module.base_address + descriptor.original_first_thunk as u64
            } else {
                iat_addr
            };

            let entry_size = if is_pe64 { 8usize } else { 4usize };
            let mut entry_offset = 0u64;

            loop {
                // Read IAT entry (actual address)
                let mut iat_entry = 0u64;
                // SAFETY: Reading IAT entry from process memory
                unsafe {
                    if ReadProcessMemory(
                        handle,
                        (iat_addr + entry_offset) as *const _,
                        &mut iat_entry as *mut _ as *mut _,
                        entry_size,
                        Some(&mut bytes_read),
                    )
                    .is_err()
                        || bytes_read < entry_size
                    {
                        break;
                    }
                }

                if iat_entry == 0 {
                    break;
                }

                // Mask for PE32
                if !is_pe64 {
                    iat_entry &= 0xFFFFFFFF;
                }

                // Read INT entry to get function name
                let mut int_entry = 0u64;
                // SAFETY: Reading INT entry from process memory
                unsafe {
                    if ReadProcessMemory(
                        handle,
                        (int_addr + entry_offset) as *const _,
                        &mut int_entry as *mut _ as *mut _,
                        entry_size,
                        Some(&mut bytes_read),
                    )
                    .is_err()
                    {
                        entry_offset += entry_size as u64;
                        continue;
                    }
                }

                // Check if import by ordinal (high bit set)
                let is_ordinal = if is_pe64 {
                    (int_entry & 0x8000000000000000) != 0
                } else {
                    (int_entry & 0x80000000) != 0
                };

                let func_name = if is_ordinal {
                    let ordinal = (int_entry & 0xFFFF) as u16;
                    format!("Ordinal_{}", ordinal)
                } else {
                    // Read function name from IMAGE_IMPORT_BY_NAME
                    let hint_name_rva = if is_pe64 {
                        int_entry & 0x7FFFFFFFFFFFFFFF
                    } else {
                        int_entry & 0x7FFFFFFF
                    };
                    // Skip hint (2 bytes) and read name
                    Self::read_string_from_process(
                        handle,
                        main_module.base_address + hint_name_rva + 2,
                        256,
                    )
                };

                // Check if IAT entry points to expected module
                if let Some(expected_mod) = expected_module {
                    let in_expected_module = iat_entry >= expected_mod.base_address
                        && iat_entry < expected_mod.base_address + expected_mod.size;

                    if !in_expected_module {
                        // This is potentially a hook - find where it actually points
                        let target_module = Self::find_module_for_address(iat_entry, modules)
                            .map(|m| m.name.clone());

                        hooks.push(HookInfo {
                            hook_type: HookType::IatHook,
                            function_name: func_name.clone(),
                            module_name: dll_name.clone(),
                            original_address: expected_mod.base_address, // We don't know exact original
                            hooked_address: iat_entry,
                            target_module,
                            hook_bytes: None,
                        });
                    }
                }

                entry_offset += entry_size as u64;
            }

            descriptor_offset += descriptor_size as u64;
        }

        if hooks.is_empty() {
            None
        } else {
            Some(hooks)
        }
    }

    /// Scan for inline hooks on critical functions
    fn scan_inline_hooks(
        handle: windows::Win32::Foundation::HANDLE,
        modules: &[ModuleInfo],
    ) -> Option<Vec<HookInfo>> {
        use windows::core::PCSTR;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        let mut hooks = Vec::new();

        for (dll_name, func_name) in Self::CRITICAL_FUNCTIONS {
            // Find the module in the target process
            let target_module = match modules
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(dll_name))
            {
                Some(m) => m,
                None => continue,
            };

            // Get the function address in our own process for comparison
            // This gives us the expected function offset within the DLL
            let func_offset = unsafe {
                // SAFETY: Loading system DLL to get function offset
                // These are trusted Windows system DLLs
                let dll_wide: Vec<u16> =
                    dll_name.encode_utf16().chain(std::iter::once(0)).collect();
                let local_module =
                    match GetModuleHandleW(windows::core::PCWSTR::from_raw(dll_wide.as_ptr())) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                let func_cstr = format!("{}\0", func_name);
                let func_addr =
                    match GetProcAddress(local_module, PCSTR::from_raw(func_cstr.as_ptr())) {
                        Some(addr) => addr as u64,
                        None => continue,
                    };

                // Calculate offset from module base
                func_addr - (local_module.0 as u64)
            };

            // Calculate expected address in target process
            let expected_addr = target_module.base_address + func_offset;

            // Read first 16 bytes of function
            let mut func_bytes = [0u8; 16];
            let mut bytes_read = 0usize;

            // SAFETY: Reading function prologue from process memory
            // Buffer is fixed size and validated
            unsafe {
                if ReadProcessMemory(
                    handle,
                    expected_addr as *const _,
                    func_bytes.as_mut_ptr() as *mut _,
                    16,
                    Some(&mut bytes_read),
                )
                .is_err()
                    || bytes_read < 5
                {
                    continue;
                }
            }

            // Check for common hook patterns
            if let Some(hook_info) = Self::detect_inline_hook(&func_bytes, expected_addr, modules) {
                hooks.push(HookInfo {
                    hook_type: hook_info.0,
                    function_name: func_name.to_string(),
                    module_name: dll_name.to_string(),
                    original_address: expected_addr,
                    hooked_address: hook_info.1,
                    target_module: hook_info.2,
                    hook_bytes: Some(func_bytes[..bytes_read].to_vec()),
                });
            }
        }

        if hooks.is_empty() {
            None
        } else {
            Some(hooks)
        }
    }

    /// Detect inline hook patterns in function prologue
    fn detect_inline_hook(
        bytes: &[u8],
        func_addr: u64,
        modules: &[ModuleInfo],
    ) -> Option<(HookType, u64, Option<String>)> {
        if bytes.len() < 5 {
            return None;
        }

        // Pattern 1: E9 xx xx xx xx - Near JMP (rel32)
        if bytes[0] == 0xE9 {
            let rel_offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let target = (func_addr as i64 + 5 + rel_offset as i64) as u64;
            let target_module =
                Self::find_module_for_address(target, modules).map(|m| m.name.clone());
            return Some((HookType::InlineHook, target, target_module));
        }

        // Pattern 2: E8 xx xx xx xx - Near CALL (rel32) at function start is suspicious
        if bytes[0] == 0xE8 {
            let rel_offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let target = (func_addr as i64 + 5 + rel_offset as i64) as u64;
            let target_module =
                Self::find_module_for_address(target, modules).map(|m| m.name.clone());
            // CALL at function start is unusual but could be legitimate
            // Only flag if target is outside expected modules
            if target_module.is_none() {
                return Some((HookType::InlineHook, target, target_module));
            }
        }

        // Pattern 3: FF 25 xx xx xx xx - JMP [mem] (absolute indirect)
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            // On x64, this is RIP-relative: target = [RIP + rel32]
            // We can't easily resolve this without reading the memory location
            let rel_offset = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            let target_ptr = (func_addr as i64 + 6 + rel_offset as i64) as u64;
            return Some((HookType::InlineHook, target_ptr, None));
        }

        // Pattern 4: 48 B8 xx xx xx xx xx xx xx xx 50 C3 - MOV RAX, imm64; PUSH RAX; RET
        // (Detours-style on x64)
        if bytes.len() >= 12
            && bytes[0] == 0x48
            && bytes[1] == 0xB8
            && bytes[10] == 0x50
            && bytes[11] == 0xC3
        {
            let target = u64::from_le_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]);
            let target_module =
                Self::find_module_for_address(target, modules).map(|m| m.name.clone());
            return Some((HookType::DetoursHook, target, target_module));
        }

        // Pattern 5: 68 xx xx xx xx C3 - PUSH imm32; RET (x86 trampoline)
        if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
            let target = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            let target_module =
                Self::find_module_for_address(target, modules).map(|m| m.name.clone());
            return Some((HookType::DetoursHook, target, target_module));
        }

        // Pattern 6: EB xx - Short JMP (rel8) at function start
        if bytes[0] == 0xEB {
            let rel_offset = bytes[1] as i8;
            let target = (func_addr as i64 + 2 + rel_offset as i64) as u64;
            let target_module =
                Self::find_module_for_address(target, modules).map(|m| m.name.clone());
            return Some((HookType::InlineHook, target, target_module));
        }

        None
    }

    /// Scan for hardware breakpoints using debug registers
    fn scan_hardware_breakpoints(pid: u32) -> Option<Vec<HookInfo>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        let mut hooks = Vec::new();

        // SAFETY: Creating snapshot of process threads
        // Snapshot handle is properly closed
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut te = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid {
                        // Open thread to get context
                        if let Ok(thread_handle) =
                            OpenThread(THREAD_GET_CONTEXT, false, te.th32ThreadID)
                        {
                            // Get thread context including debug registers
                            // Use CONTEXT_AMD64_DEBUG_REGISTERS for x64 or CONTEXT_i386_DEBUG_REGISTERS for x86
                            let mut context: CONTEXT = std::mem::zeroed();
                            #[cfg(target_arch = "x86_64")]
                            {
                                // On x64: CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
                                // CONTEXT_AMD64 = 0x00100000
                                context.ContextFlags =
                                    windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(
                                        0x00100010,
                                    );
                            }
                            #[cfg(target_arch = "x86")]
                            {
                                // On x86: CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10
                                // CONTEXT_i386 = 0x00010000
                                context.ContextFlags =
                                    windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(
                                        0x00010010,
                                    );
                            }

                            if GetThreadContext(thread_handle, &mut context).is_ok() {
                                // Check debug registers DR0-DR3 for breakpoints
                                let dr_values =
                                    [context.Dr0, context.Dr1, context.Dr2, context.Dr3];
                                let dr7 = context.Dr7;

                                for (i, &dr_value) in dr_values.iter().enumerate() {
                                    if dr_value != 0 {
                                        // Check if this breakpoint is enabled in DR7
                                        let local_enable = (dr7 >> (i * 2)) & 1;
                                        let global_enable = (dr7 >> (i * 2 + 1)) & 1;

                                        if local_enable != 0 || global_enable != 0 {
                                            hooks.push(HookInfo {
                                                hook_type: HookType::HardwareBreakpoint,
                                                function_name: format!("DR{}", i),
                                                module_name: "debug_register".to_string(),
                                                original_address: 0,
                                                hooked_address: dr_value as u64,
                                                target_module: None,
                                                hook_bytes: None,
                                            });
                                        }
                                    }
                                }
                            }

                            let _ = CloseHandle(thread_handle);
                        }
                    }

                    if Thread32Next(snapshot, &mut te).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        if hooks.is_empty() {
            None
        } else {
            Some(hooks)
        }
    }

    /// Read null-terminated string from process memory
    fn read_string_from_process(
        handle: windows::Win32::Foundation::HANDLE,
        address: u64,
        max_len: usize,
    ) -> String {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let mut buffer = vec![0u8; max_len];
        let mut bytes_read = 0usize;

        // SAFETY: Reading string from process memory
        // Buffer is properly allocated and sized
        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                max_len,
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return String::new();
            }
        }

        // Find null terminator
        let len = buffer.iter().position(|&b| b == 0).unwrap_or(bytes_read);
        String::from_utf8_lossy(&buffer[..len]).to_string()
    }
}

/// Process behavior tracking (Windows)
#[cfg(target_os = "windows")]
#[derive(Debug)]
struct ProcessBehavior {
    process_name: String,
    process_path: String,
    api_calls: HashMap<String, u64>,
    first_seen: u64,
    last_activity: u64,
    reported: bool,
}

/// API usage detection result (Windows)
#[cfg(target_os = "windows")]
#[derive(Debug)]
struct ApiUsageResult {
    has_suspicious_activity: bool,
    api_calls: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_detection() {
        assert!(InputCaptureCollector::is_whitelisted("teamviewer.exe", ""));
        assert!(InputCaptureCollector::is_whitelisted(
            "",
            "C:\\Program Files\\TeamViewer\\teamviewer.exe"
        ));
        assert!(!InputCaptureCollector::is_whitelisted(
            "malware.exe",
            "C:\\temp\\malware.exe"
        ));
    }

    #[test]
    fn test_suspicious_path_detection() {
        assert!(InputCaptureCollector::is_suspicious_path(
            "C:\\Users\\test\\AppData\\Local\\Temp\\keylog.exe"
        ));
        assert!(InputCaptureCollector::is_suspicious_path("/tmp/evil"));
        assert!(!InputCaptureCollector::is_suspicious_path(
            "C:\\Program Files\\App\\app.exe"
        ));
        assert!(!InputCaptureCollector::is_suspicious_path(
            "/usr/bin/program"
        ));
    }

    #[test]
    fn test_malware_pattern_detection() {
        assert!(InputCaptureCollector::check_malware_patterns("formbook.exe", "", &[]).is_some());
        assert!(InputCaptureCollector::check_malware_patterns("agenttesla.exe", "", &[]).is_some());
        assert!(
            InputCaptureCollector::check_malware_patterns("snake_keylogger.exe", "", &[]).is_some()
        );
        assert!(InputCaptureCollector::check_malware_patterns("notepad.exe", "", &[]).is_none());
    }

    #[test]
    fn test_capture_type_mitre_mapping() {
        assert_eq!(
            InputCaptureType::KeyboardHook.mitre_technique(),
            "T1056.001"
        );
        assert_eq!(InputCaptureType::ScreenCapture.mitre_technique(), "T1113");
        assert_eq!(
            InputCaptureType::ClipboardMonitor.mitre_technique(),
            "T1115"
        );
    }

    #[cfg(target_os = "windows")]
    mod hook_detection_tests {
        use super::*;

        #[test]
        fn test_hook_type_as_str() {
            assert_eq!(HookType::IatHook.as_str(), "iat_hook");
            assert_eq!(HookType::InlineHook.as_str(), "inline_hook");
            assert_eq!(HookType::DetoursHook.as_str(), "detours_hook");
            assert_eq!(HookType::HardwareBreakpoint.as_str(), "hardware_bp");
            assert_eq!(HookType::EatHook.as_str(), "eat_hook");
        }

        #[test]
        fn test_hook_info_is_input_related() {
            let input_hook = HookInfo {
                hook_type: HookType::IatHook,
                function_name: "GetAsyncKeyState".to_string(),
                module_name: "user32.dll".to_string(),
                original_address: 0x12345678,
                hooked_address: 0x87654321,
                target_module: Some("malware.dll".to_string()),
                hook_bytes: None,
            };
            assert!(input_hook.is_input_related());

            let non_input_hook = HookInfo {
                hook_type: HookType::IatHook,
                function_name: "CreateFileW".to_string(),
                module_name: "kernel32.dll".to_string(),
                original_address: 0x12345678,
                hooked_address: 0x87654321,
                target_module: Some("malware.dll".to_string()),
                hook_bytes: None,
            };
            assert!(!non_input_hook.is_input_related());

            // Test credential-related functions
            let cred_hook = HookInfo {
                hook_type: HookType::InlineHook,
                function_name: "CryptUnprotectData".to_string(),
                module_name: "crypt32.dll".to_string(),
                original_address: 0x12345678,
                hooked_address: 0x87654321,
                target_module: None,
                hook_bytes: Some(vec![0xE9, 0x00, 0x00, 0x00, 0x00]),
            };
            assert!(cred_hook.is_input_related());
        }

        #[test]
        fn test_detect_inline_hook_patterns() {
            // Test near JMP (E9)
            let jmp_bytes = [
                0xE9, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90,
            ];
            let result = HookScanner::detect_inline_hook(&jmp_bytes, 0x10000, &[]);
            assert!(result.is_some());
            let (hook_type, target, _) = result.unwrap();
            assert_eq!(hook_type, HookType::InlineHook);
            // Target = 0x10000 + 5 + 0x10 = 0x10015
            assert_eq!(target, 0x10015);

            // Test short JMP (EB)
            let short_jmp = [
                0xEB, 0x0A, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90,
            ];
            let result = HookScanner::detect_inline_hook(&short_jmp, 0x10000, &[]);
            assert!(result.is_some());
            let (hook_type, target, _) = result.unwrap();
            assert_eq!(hook_type, HookType::InlineHook);
            // Target = 0x10000 + 2 + 0x0A = 0x1000C
            assert_eq!(target, 0x1000C);

            // Test PUSH/RET trampoline (x86)
            let push_ret = [
                0x68, 0x78, 0x56, 0x34, 0x12, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90,
            ];
            let result = HookScanner::detect_inline_hook(&push_ret, 0x10000, &[]);
            assert!(result.is_some());
            let (hook_type, target, _) = result.unwrap();
            assert_eq!(hook_type, HookType::DetoursHook);
            assert_eq!(target, 0x12345678);

            // Test normal function prologue (should not detect as hook)
            let normal_prologue = [
                0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90,
            ];
            let result = HookScanner::detect_inline_hook(&normal_prologue, 0x10000, &[]);
            assert!(result.is_none());
        }

        #[test]
        fn test_find_module_for_address() {
            let modules = vec![
                ModuleInfo {
                    name: "ntdll.dll".to_string(),
                    base_address: 0x77000000,
                    size: 0x100000,
                },
                ModuleInfo {
                    name: "kernel32.dll".to_string(),
                    base_address: 0x76000000,
                    size: 0x80000,
                },
            ];

            // Address in ntdll
            let result = HookScanner::find_module_for_address(0x77050000, &modules);
            assert!(result.is_some());
            assert_eq!(result.unwrap().name, "ntdll.dll");

            // Address in kernel32
            let result = HookScanner::find_module_for_address(0x76040000, &modules);
            assert!(result.is_some());
            assert_eq!(result.unwrap().name, "kernel32.dll");

            // Address not in any module
            let result = HookScanner::find_module_for_address(0x50000000, &modules);
            assert!(result.is_none());
        }
    }
}
