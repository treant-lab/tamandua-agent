//! Scheduled Tasks collector
//!
//! Monitors scheduled task creation, modification, and deletion for persistence detection.
//!
//! Platform support:
//! - Windows: Task Scheduler via COM (ITaskService), schtasks.exe/at.exe monitoring
//! - Linux: cron (system/user), systemd timers, at jobs
//! - macOS: launchd plists, cron
//!
//! MITRE ATT&CK Mapping:
//! - T1053: Scheduled Task/Job
//! - T1053.002: At (Windows/Linux)
//! - T1053.003: Cron
//! - T1053.005: Scheduled Task (Windows)
//! - T1053.006: Systemd Timers

// Scheduled task persistence detector. Stub params retained for upcoming
// platform-specific dispatch.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Scheduled task event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTaskEvent {
    /// Task name/identifier
    pub task_name: String,
    /// Task path/location
    pub task_path: String,
    /// Operation type (create, modify, delete, execute)
    pub operation: String,
    /// Command/action to execute
    pub command: String,
    /// Arguments/parameters
    pub arguments: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
    /// User context the task runs as
    pub run_as_user: String,
    /// Privilege level (highest, limited, etc.)
    pub privilege_level: String,
    /// Trigger type (boot, logon, time, event, etc.)
    pub trigger_type: String,
    /// Trigger details
    pub trigger_details: Option<String>,
    /// Is task hidden
    pub is_hidden: bool,
    /// Is task enabled
    pub is_enabled: bool,
    /// Task state (ready, running, disabled)
    pub state: String,
    /// Task author/creator
    pub author: Option<String>,
    /// Task description
    pub description: Option<String>,
    /// Creation date
    pub date_created: Option<String>,
    /// Last modified date
    pub date_modified: Option<String>,
    /// Last run time
    pub last_run_time: Option<String>,
    /// Next run time
    pub next_run_time: Option<String>,
    /// Process that created/modified the task
    pub source_pid: u32,
    /// Process name that created/modified the task
    pub source_process: String,
    /// Raw task definition (XML on Windows, crontab entry on Linux)
    pub raw_definition: Option<String>,
    /// Detected risk indicators
    pub risk_indicators: Vec<String>,
    /// Risk score (0-100)
    pub risk_score: u32,
}

/// Scheduled Tasks collector
pub struct ScheduledTaskCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl ScheduledTaskCollector {
    /// Create a new scheduled task collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::monitor_loop(tx, config_clone).await {
                error!(error = %e, "Scheduled task monitor error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
                info!("Lightweight profile: Scheduled task monitoring disabled");
                return Ok(());
            }
            Self::monitor_windows(tx, config).await
        }

        #[cfg(target_os = "linux")]
        {
            Self::monitor_linux(tx, config).await
        }

        #[cfg(target_os = "macos")]
        {
            Self::monitor_macos(tx, config).await
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            warn!("Scheduled task monitoring not supported on this platform");
            Ok(())
        }
    }

    /// Analyze task for suspicious patterns and calculate risk score
    fn analyze_task(task: &mut ScheduledTaskEvent) {
        let mut indicators: Vec<String> = Vec::new();
        let mut score: u32 = 0;

        // Check for encoded/obfuscated commands
        let cmd_lower = task.command.to_lowercase();
        let args_lower = task
            .arguments
            .as_ref()
            .map(|a| a.to_lowercase())
            .unwrap_or_default();
        let combined = format!("{} {}", cmd_lower, args_lower);

        // PowerShell with encoded command
        if combined.contains("-enc") || combined.contains("-encodedcommand") {
            indicators.push("PowerShell encoded command (-enc/-encodedcommand)".to_string());
            score += 40;
        }

        // PowerShell bypass execution policy
        if combined.contains("-ep bypass")
            || combined.contains("-executionpolicy bypass")
            || combined.contains("set-executionpolicy")
        {
            indicators.push("PowerShell execution policy bypass".to_string());
            score += 25;
        }

        // PowerShell hidden window
        if combined.contains("-windowstyle hidden") || combined.contains("-w hidden") {
            indicators.push("PowerShell hidden window".to_string());
            score += 20;
        }

        // Base64 patterns in command
        if Self::contains_base64(&combined) {
            indicators.push("Possible Base64 encoded content".to_string());
            score += 30;
        }

        // Suspicious script hosts
        let suspicious_hosts = [
            "mshta",
            "wscript",
            "cscript",
            "regsvr32",
            "rundll32",
            "certutil",
            "bitsadmin",
            "msiexec",
        ];
        for host in suspicious_hosts {
            if cmd_lower.contains(host) {
                indicators.push(format!("Suspicious script host: {}", host));
                score += 25;
            }
        }

        // Network-related actions
        if combined.contains("http://")
            || combined.contains("https://")
            || combined.contains("ftp://")
        {
            indicators.push("Network URL in command".to_string());
            score += 15;
        }
        if combined.contains("invoke-webrequest")
            || combined.contains("iwr")
            || combined.contains("wget")
            || combined.contains("curl")
            || combined.contains("downloadstring")
            || combined.contains("downloadfile")
        {
            indicators.push("Network download command".to_string());
            score += 25;
        }

        // Suspicious paths (Temp, AppData, etc.)
        let suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp",
            "\\appdata\\roaming\\",
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
        ];
        let path_check = format!(
            "{} {} {}",
            cmd_lower,
            args_lower,
            task.working_directory
                .as_ref()
                .unwrap_or(&String::new())
                .to_lowercase()
        );
        for path in suspicious_paths {
            if path_check.contains(path) {
                indicators.push(format!("Suspicious path: {}", path));
                score += 20;
                break;
            }
        }

        // Random/UUID-like task names
        if Self::is_random_name(&task.task_name) {
            indicators.push("Random/UUID-like task name".to_string());
            score += 30;
        }

        // Hidden task
        if task.is_hidden {
            indicators.push("Task is hidden".to_string());
            score += 35;
        }

        // SYSTEM privileges
        let run_as_lower = task.run_as_user.to_lowercase();
        if run_as_lower.contains("system")
            || run_as_lower.contains("nt authority")
            || run_as_lower == "root"
        {
            indicators.push("Runs with SYSTEM/root privileges".to_string());
            score += 15;
        }

        // Highest privilege level
        if task.privilege_level.to_lowercase().contains("highest") {
            indicators.push("Runs with highest privileges".to_string());
            score += 15;
        }

        // Boot/Logon triggers (common persistence mechanism)
        let trigger_lower = task.trigger_type.to_lowercase();
        if trigger_lower.contains("boot")
            || trigger_lower.contains("logon")
            || trigger_lower.contains("startup")
        {
            indicators.push("Triggered on boot/logon (persistence)".to_string());
            score += 10;
        }

        // WMI event triggers
        if trigger_lower.contains("wmi") || trigger_lower.contains("event") {
            indicators.push("WMI/Event-based trigger".to_string());
            score += 15;
        }

        // Very frequent execution (every minute or less)
        if let Some(ref details) = task.trigger_details {
            if details.contains("PT1M") || details.contains("every minute") {
                indicators.push("Very frequent execution schedule".to_string());
                score += 20;
            }
        }

        // Reverse shell patterns
        if combined.contains("nc ")
            || combined.contains("ncat")
            || combined.contains("netcat")
            || combined.contains("reverse")
            || combined.contains("-e /bin/")
            || combined.contains("bash -i")
        {
            indicators.push("Possible reverse shell pattern".to_string());
            score += 50;
        }

        // Linux-specific cron abuse patterns
        #[cfg(target_os = "linux")]
        {
            // Cron job writing to /etc/cron.d or other system cron locations
            if task.task_path.starts_with("/etc/cron")
                || task.task_path.starts_with("/var/spool/cron")
            {
                if task.operation == "create" {
                    indicators.push("New system cron job created".to_string());
                    score += 10;
                }
            }

            // Piping output to bash/sh
            if combined.contains("| bash") || combined.contains("| sh") {
                indicators.push("Command output piped to shell".to_string());
                score += 30;
            }
        }

        // Cap score at 100
        task.risk_score = score.min(100);
        task.risk_indicators = indicators;
    }

    /// Check if string contains base64-like patterns
    fn contains_base64(s: &str) -> bool {
        // Look for base64 patterns: long alphanumeric strings with +/= characters
        // Minimum 40 chars to reduce false positives
        let base64_pattern = regex::Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").ok();
        if let Some(re) = base64_pattern {
            return re.is_match(s);
        }
        false
    }

    /// Check if task name appears to be random/generated
    fn is_random_name(name: &str) -> bool {
        // Check for UUID pattern
        if regex::Regex::new(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        )
        .map(|re| re.is_match(name))
        .unwrap_or(false)
        {
            return true;
        }

        // Check for random-looking alphanumeric strings (high entropy)
        if name.len() >= 8 && name.chars().all(|c| c.is_alphanumeric()) {
            let has_mixed_case =
                name.chars().any(|c| c.is_uppercase()) && name.chars().any(|c| c.is_lowercase());
            let has_digits = name.chars().any(|c| c.is_numeric());
            let has_letters = name.chars().any(|c| c.is_alphabetic());

            if has_mixed_case && has_digits && has_letters {
                // Calculate character entropy
                let unique_chars: HashSet<char> = name.chars().collect();
                let entropy_ratio = unique_chars.len() as f32 / name.len() as f32;
                if entropy_ratio > 0.6 {
                    return true;
                }
            }
        }

        false
    }

    /// Create telemetry event from scheduled task event
    fn create_telemetry_event(mut task_event: ScheduledTaskEvent) -> TelemetryEvent {
        // Analyze for suspicious patterns
        Self::analyze_task(&mut task_event);

        // Determine severity based on risk score
        let severity = match task_event.risk_score {
            0..=20 => Severity::Info,
            21..=40 => Severity::Low,
            41..=60 => Severity::Medium,
            61..=80 => Severity::High,
            _ => Severity::Critical,
        };

        let mut event = TelemetryEvent::new(
            EventType::ScheduledTask,
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&task_event).unwrap_or_default()),
        );

        // Add MITRE mapping
        event
            .metadata
            .insert("mitre_technique".to_string(), "T1053".to_string());

        // Add platform-specific sub-technique
        #[cfg(target_os = "windows")]
        {
            if task_event.task_path.contains("at.exe") || task_event.command.contains("at.exe") {
                event
                    .metadata
                    .insert("mitre_sub_technique".to_string(), "T1053.002".to_string());
            } else {
                event
                    .metadata
                    .insert("mitre_sub_technique".to_string(), "T1053.005".to_string());
            }
        }

        #[cfg(target_os = "linux")]
        {
            if task_event.task_path.contains("cron") || task_event.trigger_type == "cron" {
                event
                    .metadata
                    .insert("mitre_sub_technique".to_string(), "T1053.003".to_string());
            } else if task_event.task_path.contains("systemd")
                || task_event.trigger_type == "systemd"
            {
                event
                    .metadata
                    .insert("mitre_sub_technique".to_string(), "T1053.006".to_string());
            } else if task_event.task_path.contains("/var/spool/at")
                || task_event.command.contains("at ")
            {
                event
                    .metadata
                    .insert("mitre_sub_technique".to_string(), "T1053.002".to_string());
            }
        }

        // Add detections if risk indicators found
        if !task_event.risk_indicators.is_empty() {
            let description = task_event.risk_indicators.join("; ");
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "suspicious_scheduled_task".to_string(),
                confidence: (task_event.risk_score as f32) / 100.0,
                description: format!(
                    "Suspicious scheduled task detected: {} (risk score: {}). Indicators: {}",
                    task_event.task_name, task_event.risk_score, description
                ),
                mitre_tactics: vec!["persistence".to_string(), "execution".to_string()],
                mitre_techniques: vec!["T1053".to_string()],
            });
        }

        event
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn monitor_windows(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) -> Result<()> {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Windows scheduled task monitoring");

        // Track known tasks for change detection
        let known_tasks: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        // Initial scan
        {
            let mut tasks = known_tasks.lock().await;
            if let Ok(current_tasks) = Self::enumerate_windows_tasks().await {
                for task in current_tasks {
                    // Use task path + name as key, hash of definition as value
                    let key = format!("{}\\{}", task.task_path, task.task_name);
                    let hash = Self::hash_task_definition(&task);
                    tasks.insert(key, hash);
                }
            }
            info!(
                count = tasks.len(),
                "Enumerated existing Windows scheduled tasks"
            );
        }

        // Start COM-based Task Scheduler monitoring
        let tx_clone = tx.clone();
        let known_clone = known_tasks.clone();
        let _com_handle = tokio::spawn(async move {
            loop {
                if let Err(e) = Self::poll_windows_tasks(&tx_clone, &known_clone).await {
                    warn!(error = %e, "Task scheduler polling error");
                }
                // Use 5 minute interval for polling to avoid high CPU usage
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            }
        });

        // Monitor schtasks.exe and at.exe execution via process monitoring
        let tx_clone = tx.clone();
        let _proc_handle = tokio::spawn(async move {
            Self::monitor_schtasks_process(tx_clone).await;
        });

        // Monitor Task Scheduler event log (Event ID 106, 140, 141, 200, 201)
        let tx_clone = tx.clone();
        let _evt_handle = tokio::spawn(async move {
            Self::monitor_task_scheduler_events(tx_clone).await;
        });

        // Keep main task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "windows")]
    async fn enumerate_windows_tasks() -> Result<Vec<ScheduledTaskEvent>> {
        use std::process::Command;

        let mut tasks = Vec::new();

        // Use schtasks to export all tasks as XML
        let output = Command::new("schtasks")
            .args(["/query", "/xml", "ONE"])
            .output()?;

        if output.status.success() {
            let xml_output = String::from_utf8_lossy(&output.stdout);

            // Parse basic task info from schtasks /query /fo CSV
            let csv_output = Command::new("schtasks")
                .args(["/query", "/fo", "CSV", "/v"])
                .output()?;

            if csv_output.status.success() {
                let csv_str = String::from_utf8_lossy(&csv_output.stdout);
                for line in csv_str.lines().skip(1) {
                    // Skip header
                    if let Some(task) = Self::parse_schtasks_csv_line(line) {
                        tasks.push(task);
                    }
                }
            }
        }

        // Also enumerate via PowerShell for more detail
        let ps_output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author,Description | ConvertTo-Json -Depth 3",
            ])
            .output();

        if let Ok(output) = ps_output {
            if output.status.success() {
                let json_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    if let Some(arr) = json.as_array() {
                        for item in arr {
                            if let Some(task) = Self::parse_ps_task_json(item) {
                                // Merge with existing or add new
                                let key = format!("{}\\{}", task.task_path, task.task_name);
                                if let Some(existing) = tasks
                                    .iter_mut()
                                    .find(|t| format!("{}\\{}", t.task_path, t.task_name) == key)
                                {
                                    // Merge additional info
                                    if existing.author.is_none() {
                                        existing.author = task.author;
                                    }
                                    if existing.description.is_none() {
                                        existing.description = task.description;
                                    }
                                } else {
                                    tasks.push(task);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(tasks)
    }

    #[cfg(target_os = "windows")]
    fn parse_schtasks_csv_line(line: &str) -> Option<ScheduledTaskEvent> {
        // CSV format: "HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
        let parts: Vec<&str> = line.split("\",\"").collect();
        if parts.len() < 15 {
            return None;
        }

        let task_name = parts.get(1)?.trim_matches('"').to_string();
        let full_path = parts.get(1)?.trim_matches('"');
        let task_path = if let Some(pos) = full_path.rfind('\\') {
            full_path[..pos].to_string()
        } else {
            String::new()
        };

        let status = parts
            .get(3)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        let last_run = parts.get(5).map(|s| s.trim_matches('"').to_string());
        let author = parts
            .get(7)
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty());
        let command = parts
            .get(8)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        let working_dir = parts
            .get(9)
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty() && s != "N/A");
        let description = parts
            .get(10)
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty() && s != "N/A");
        let state = parts
            .get(11)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        let run_as = parts
            .get(14)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        let schedule_type = parts
            .get(17)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        Some(ScheduledTaskEvent {
            task_name,
            task_path,
            operation: "enumerate".to_string(),
            command,
            arguments: None,
            working_directory: working_dir,
            run_as_user: run_as,
            privilege_level: "unknown".to_string(),
            trigger_type: schedule_type,
            trigger_details: None,
            is_hidden: false,
            is_enabled: state.to_lowercase() == "enabled",
            state: status,
            author,
            description,
            date_created: None,
            date_modified: None,
            last_run_time: last_run,
            next_run_time: parts
                .get(2)
                .map(|s| s.trim_matches('"').to_string())
                .filter(|s| s != "N/A"),
            source_pid: 0,
            source_process: String::new(),
            raw_definition: None,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "windows")]
    fn parse_ps_task_json(json: &serde_json::Value) -> Option<ScheduledTaskEvent> {
        Some(ScheduledTaskEvent {
            task_name: json.get("TaskName")?.as_str()?.to_string(),
            task_path: json.get("TaskPath")?.as_str()?.to_string(),
            operation: "enumerate".to_string(),
            command: String::new(),
            arguments: None,
            working_directory: None,
            run_as_user: String::new(),
            privilege_level: "unknown".to_string(),
            trigger_type: String::new(),
            trigger_details: None,
            is_hidden: false,
            is_enabled: json
                .get("State")
                .and_then(|s| s.as_i64())
                .map(|s| s == 3)
                .unwrap_or(false),
            state: json
                .get("State")
                .and_then(|s| s.as_i64())
                .map(|s| {
                    match s {
                        0 => "Unknown",
                        1 => "Disabled",
                        2 => "Queued",
                        3 => "Ready",
                        4 => "Running",
                        _ => "Unknown",
                    }
                    .to_string()
                })
                .unwrap_or_default(),
            author: json
                .get("Author")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string()),
            description: json
                .get("Description")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string()),
            date_created: None,
            date_modified: None,
            last_run_time: None,
            next_run_time: None,
            source_pid: 0,
            source_process: String::new(),
            raw_definition: None,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "windows")]
    async fn poll_windows_tasks(
        tx: &mpsc::Sender<TelemetryEvent>,
        known_tasks: &tokio::sync::Mutex<HashMap<String, String>>,
    ) -> Result<()> {
        let current_tasks = Self::enumerate_windows_tasks().await?;
        let mut tasks_map = known_tasks.lock().await;

        let mut current_keys: HashSet<String> = HashSet::new();

        for mut task in current_tasks {
            let key = format!("{}\\{}", task.task_path, task.task_name);
            let hash = Self::hash_task_definition(&task);
            current_keys.insert(key.clone());

            if let Some(existing_hash) = tasks_map.get(&key) {
                if existing_hash != &hash {
                    // Task was modified
                    task.operation = "modify".to_string();
                    let event = Self::create_telemetry_event(task);
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                    tasks_map.insert(key, hash);
                }
            } else {
                // New task
                task.operation = "create".to_string();
                let event = Self::create_telemetry_event(task);
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
                tasks_map.insert(key, hash);
            }
        }

        // Check for deleted tasks
        let deleted_keys: Vec<String> = tasks_map
            .keys()
            .filter(|k| !current_keys.contains(*k))
            .cloned()
            .collect();

        for key in deleted_keys {
            tasks_map.remove(&key);

            // Parse key back to task info
            let parts: Vec<&str> = key.rsplitn(2, '\\').collect();
            let task_name = parts.first().unwrap_or(&"unknown").to_string();
            let task_path = parts.get(1).unwrap_or(&"").to_string();

            let task = ScheduledTaskEvent {
                task_name,
                task_path,
                operation: "delete".to_string(),
                command: String::new(),
                arguments: None,
                working_directory: None,
                run_as_user: String::new(),
                privilege_level: String::new(),
                trigger_type: String::new(),
                trigger_details: None,
                is_hidden: false,
                is_enabled: false,
                state: "Deleted".to_string(),
                author: None,
                description: None,
                date_created: None,
                date_modified: None,
                last_run_time: None,
                next_run_time: None,
                source_pid: 0,
                source_process: String::new(),
                raw_definition: None,
                risk_indicators: Vec::new(),
                risk_score: 0,
            };

            let event = Self::create_telemetry_event(task);
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn hash_task_definition(task: &ScheduledTaskEvent) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        task.task_name.hash(&mut hasher);
        task.command.hash(&mut hasher);
        task.arguments.hash(&mut hasher);
        task.run_as_user.hash(&mut hasher);
        task.trigger_type.hash(&mut hasher);
        task.is_enabled.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    #[cfg(target_os = "windows")]
    async fn monitor_schtasks_process(tx: mpsc::Sender<TelemetryEvent>) {
        use std::collections::HashSet;
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        let mut seen_pids: HashSet<u32> = HashSet::new();

        loop {
            system.refresh_processes_specifics(ProcessRefreshKind::new());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                if seen_pids.contains(&pid_u32) {
                    continue;
                }

                let name = process.name().to_lowercase();
                if name == "schtasks.exe" || name == "at.exe" {
                    seen_pids.insert(pid_u32);

                    let cmdline = process.cmd().join(" ");

                    // Determine operation from command line
                    let operation = if cmdline.to_lowercase().contains("/create")
                        || cmdline.to_lowercase().contains("/add")
                    {
                        "create"
                    } else if cmdline.to_lowercase().contains("/delete")
                        || cmdline.to_lowercase().contains("/remove")
                    {
                        "delete"
                    } else if cmdline.to_lowercase().contains("/change") {
                        "modify"
                    } else if cmdline.to_lowercase().contains("/run") {
                        "execute"
                    } else {
                        "query"
                    };

                    // Extract task name from cmdline if present
                    let task_name = Self::extract_task_name_from_cmdline(&cmdline)
                        .unwrap_or_else(|| format!("schtasks_pid_{}", pid_u32));

                    let task = ScheduledTaskEvent {
                        task_name,
                        task_path: name.to_string(),
                        operation: operation.to_string(),
                        command: cmdline.clone(),
                        arguments: None,
                        working_directory: None,
                        run_as_user: process
                            .user_id()
                            .map(|u| u.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        privilege_level: "unknown".to_string(),
                        trigger_type: "process".to_string(),
                        trigger_details: Some(cmdline),
                        is_hidden: false,
                        is_enabled: true,
                        state: "Running".to_string(),
                        author: None,
                        description: None,
                        date_created: None,
                        date_modified: None,
                        last_run_time: None,
                        next_run_time: None,
                        source_pid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                        source_process: process
                            .parent()
                            .and_then(|ppid| system.process(ppid))
                            .map(|p| p.name().to_string())
                            .unwrap_or_default(),
                        raw_definition: None,
                        risk_indicators: Vec::new(),
                        risk_score: 0,
                    };

                    let event = Self::create_telemetry_event(task);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Clean up old PIDs periodically
            if seen_pids.len() > 1000 {
                let current_pids: HashSet<u32> =
                    system.processes().keys().map(|p| p.as_u32()).collect();
                seen_pids.retain(|p| current_pids.contains(p));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }

    #[cfg(target_os = "windows")]
    fn extract_task_name_from_cmdline(cmdline: &str) -> Option<String> {
        // Look for /tn "TaskName" or /tn TaskName
        let lower = cmdline.to_lowercase();
        if let Some(pos) = lower.find("/tn ") {
            let rest = &cmdline[pos + 4..];
            let trimmed = rest.trim_start();
            if trimmed.starts_with('"') {
                // Quoted task name
                if let Some(end) = trimmed[1..].find('"') {
                    return Some(trimmed[1..end + 1].to_string());
                }
            } else {
                // Unquoted - take until next space or flag
                let end = trimmed.find(' ').unwrap_or(trimmed.len());
                return Some(trimmed[..end].to_string());
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    async fn monitor_task_scheduler_events(tx: mpsc::Sender<TelemetryEvent>) {
        use std::process::Command;

        // Query Task Scheduler operational log for recent events
        let mut last_check = std::time::Instant::now();

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            // Query events from the last check interval
            let elapsed = last_check.elapsed().as_secs() + 1;
            last_check = std::time::Instant::now();

            // Use wevtutil to get Task Scheduler events
            // Event IDs: 106 (task registered), 140 (task updated), 141 (task deleted), 200 (action started), 201 (action completed)
            let query = format!(
                "*[System[TimeCreated[timediff(@SystemTime) <= {}000] and (EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]",
                elapsed
            );

            let output = Command::new("wevtutil")
                .args([
                    "qe",
                    "Microsoft-Windows-TaskScheduler/Operational",
                    "/q",
                    &query,
                    "/f:xml",
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let xml_str = String::from_utf8_lossy(&output.stdout);

                    // Parse events from XML
                    for event_xml in xml_str.split("</Event>") {
                        if let Some(task_event) = Self::parse_task_scheduler_event_xml(event_xml) {
                            let event = Self::create_telemetry_event(task_event);
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
    fn parse_task_scheduler_event_xml(xml: &str) -> Option<ScheduledTaskEvent> {
        // Simple XML parsing for task scheduler events
        let event_id = Self::extract_xml_value(xml, "EventID")?;
        let task_name = Self::extract_xml_value(xml, "TaskName")
            .or_else(|| Self::extract_xml_value(xml, "Name"))?;

        let operation = match event_id.as_str() {
            "106" => "create",
            "140" => "modify",
            "141" => "delete",
            "200" => "execute_start",
            "201" => "execute_complete",
            _ => return None,
        };

        let user = Self::extract_xml_value(xml, "UserContext")
            .or_else(|| Self::extract_xml_value(xml, "UserId"))
            .unwrap_or_else(|| "unknown".to_string());

        let action = Self::extract_xml_value(xml, "ActionName")
            .or_else(|| Self::extract_xml_value(xml, "Path"))
            .unwrap_or_default();

        Some(ScheduledTaskEvent {
            task_name: task_name.clone(),
            task_path: Self::extract_xml_value(xml, "TaskPath").unwrap_or_default(),
            operation: operation.to_string(),
            command: action,
            arguments: Self::extract_xml_value(xml, "Arguments"),
            working_directory: Self::extract_xml_value(xml, "WorkingDirectory"),
            run_as_user: user,
            privilege_level: "unknown".to_string(),
            trigger_type: "event_log".to_string(),
            trigger_details: Some(format!("EventID: {}", event_id)),
            is_hidden: false,
            is_enabled: true,
            state: "EventLog".to_string(),
            author: None,
            description: None,
            date_created: Self::extract_xml_value(xml, "TimeCreated"),
            date_modified: None,
            last_run_time: if operation == "execute_complete" {
                Self::extract_xml_value(xml, "TimeCreated")
            } else {
                None
            },
            next_run_time: None,
            source_pid: Self::extract_xml_value(xml, "ProcessId")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
            source_process: Self::extract_xml_value(xml, "ProcessName").unwrap_or_default(),
            raw_definition: Some(xml.to_string()),
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "windows")]
    fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{}", tag);
        if let Some(start) = xml.find(&start_tag) {
            let rest = &xml[start..];
            if let Some(gt) = rest.find('>') {
                let after_tag = &rest[gt + 1..];
                let end_tag = format!("</{}>", tag);
                if let Some(end) = after_tag.find(&end_tag) {
                    let value = after_tag[..end].trim();
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
        None
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn monitor_linux(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) -> Result<()> {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Linux scheduled task monitoring (cron/systemd/at)");

        // Track known cron entries
        let known_crons: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        // Initial scan of cron directories
        {
            let mut crons = known_crons.lock().await;
            Self::scan_cron_directories(&mut crons).await;
            info!(count = crons.len(), "Scanned existing cron entries");
        }

        // Monitor cron directories with inotify
        let cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
        ];

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        })?;

        for path in cron_paths {
            if Path::new(path).exists() {
                if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                    warn!(path = path, error = %e, "Failed to watch cron path");
                }
            }
        }

        // Monitor systemd timer units
        let systemd_paths = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
            "~/.config/systemd/user",
        ];

        for path in systemd_paths {
            let expanded = shellexpand::tilde(path).to_string();
            if Path::new(&expanded).exists() {
                if let Err(e) = watcher.watch(Path::new(&expanded), RecursiveMode::Recursive) {
                    debug!(path = path, error = %e, "Failed to watch systemd path");
                }
            }
        }

        // Monitor at jobs
        if Path::new("/var/spool/at").exists() {
            let _ = watcher.watch(Path::new("/var/spool/at"), RecursiveMode::Recursive);
        }

        // Spawn crontab command monitor
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_crontab_commands(tx_clone).await;
        });

        // Spawn systemctl timer monitor
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_systemd_timers(tx_clone).await;
        });

        // Process file system events
        let runtime = tokio::runtime::Handle::current();
        let tx_clone = tx.clone();
        let known_clone = known_crons.clone();

        std::thread::spawn(move || {
            for event in notify_rx {
                for path in event.paths {
                    let path_str = path.to_string_lossy().to_string();

                    // Determine if this is a cron, systemd, or at job
                    let task_type = if path_str.contains("systemd") && path_str.ends_with(".timer")
                    {
                        "systemd"
                    } else if path_str.contains("/var/spool/at") {
                        "at"
                    } else if path_str.contains("cron") {
                        "cron"
                    } else {
                        continue;
                    };

                    let operation = match &event.kind {
                        EventKind::Create(_) => "create",
                        EventKind::Modify(_) => "modify",
                        EventKind::Remove(_) => "delete",
                        _ => continue,
                    };

                    runtime.block_on(async {
                        let task_event = match task_type {
                            "cron" => Self::parse_cron_file(&path_str, operation).await,
                            "systemd" => Self::parse_systemd_timer(&path_str, operation).await,
                            "at" => Self::parse_at_job(&path_str, operation).await,
                            _ => None,
                        };

                        if let Some(task) = task_event {
                            let event = Self::create_telemetry_event(task);
                            let _ = tx_clone.send(event).await;
                        }
                    });
                }
            }
        });

        // Keep main task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn scan_cron_directories(known: &mut HashMap<String, String>) {
        use std::fs;

        let cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
        ];

        for path in cron_paths {
            if !Path::new(path).exists() {
                continue;
            }

            if Path::new(path).is_file() {
                if let Ok(content) = fs::read_to_string(path) {
                    let hash = Self::hash_content(&content);
                    known.insert(path.to_string(), hash);
                }
            } else if Path::new(path).is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let file_path = entry.path();
                        if file_path.is_file() {
                            if let Ok(content) = fs::read_to_string(&file_path) {
                                let hash = Self::hash_content(&content);
                                known.insert(file_path.to_string_lossy().to_string(), hash);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn hash_content(content: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    #[cfg(target_os = "linux")]
    async fn parse_cron_file(path: &str, operation: &str) -> Option<ScheduledTaskEvent> {
        use std::fs;

        let content = if operation != "delete" {
            fs::read_to_string(path).ok()
        } else {
            None
        };

        // Extract username from path if user crontab
        let user = if path.contains("/var/spool/cron") {
            Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        } else {
            None
        };

        // Parse cron entries
        let mut commands = Vec::new();
        let mut schedule = String::new();

        if let Some(ref content) = content {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Parse cron format: min hour dom mon dow [user] command
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    schedule = parts[..5].join(" ");
                    let cmd_start = if path == "/etc/crontab" { 6 } else { 5 };
                    if parts.len() > cmd_start {
                        commands.push(parts[cmd_start..].join(" "));
                    }
                }
            }
        }

        let task_name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "cron_entry".to_string());

        Some(ScheduledTaskEvent {
            task_name,
            task_path: path.to_string(),
            operation: operation.to_string(),
            command: commands.join("; "),
            arguments: None,
            working_directory: None,
            run_as_user: user.clone().unwrap_or_else(|| "root".to_string()),
            privilege_level: if path.starts_with("/etc/") || user.as_deref() == Some("root") {
                "root".to_string()
            } else {
                "user".to_string()
            },
            trigger_type: "cron".to_string(),
            trigger_details: Some(schedule),
            is_hidden: false,
            is_enabled: true,
            state: if operation == "delete" {
                "Deleted"
            } else {
                "Active"
            }
            .to_string(),
            author: user.clone(),
            description: None,
            date_created: None,
            date_modified: fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| format!("{:?}", t)),
            last_run_time: None,
            next_run_time: None,
            source_pid: 0,
            source_process: String::new(),
            raw_definition: content,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "linux")]
    async fn parse_systemd_timer(path: &str, operation: &str) -> Option<ScheduledTaskEvent> {
        use std::fs;
        use std::process::Command;

        let content = if operation != "delete" {
            fs::read_to_string(path).ok()
        } else {
            None
        };

        let timer_name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())?;

        // Get associated service unit
        let service_name = timer_name.replace(".timer", ".service");
        let service_path = Path::new(path)
            .parent()
            .map(|p| p.join(&service_name))
            .filter(|p| p.exists());

        let service_content = service_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok());

        // Parse OnCalendar or OnBootSec etc from timer
        let schedule = content
            .as_ref()
            .and_then(|c| {
                c.lines()
                    .find(|l| {
                        l.starts_with("OnCalendar=")
                            || l.starts_with("OnBootSec=")
                            || l.starts_with("OnUnitActiveSec=")
                    })
                    .map(|l| l.to_string())
            })
            .unwrap_or_default();

        // Parse ExecStart from service
        let exec_start = service_content
            .as_ref()
            .and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("ExecStart="))
                    .map(|l| l.trim_start_matches("ExecStart=").to_string())
            })
            .unwrap_or_default();

        // Get timer status
        let status = Command::new("systemctl")
            .args(["is-active", &timer_name])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let is_enabled = Command::new("systemctl")
            .args(["is-enabled", &timer_name])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
            .unwrap_or(false);

        // Get user from service
        let user = service_content
            .as_ref()
            .and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("User="))
                    .map(|l| l.trim_start_matches("User=").to_string())
            })
            .unwrap_or_else(|| "root".to_string());

        Some(ScheduledTaskEvent {
            task_name: timer_name,
            task_path: path.to_string(),
            operation: operation.to_string(),
            command: exec_start,
            arguments: None,
            working_directory: service_content.as_ref().and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("WorkingDirectory="))
                    .map(|l| l.trim_start_matches("WorkingDirectory=").to_string())
            }),
            run_as_user: user,
            privilege_level: if path.starts_with("/etc/systemd/system")
                || path.starts_with("/usr/lib/systemd/system")
            {
                "system".to_string()
            } else {
                "user".to_string()
            },
            trigger_type: "systemd".to_string(),
            trigger_details: Some(schedule),
            is_hidden: false,
            is_enabled,
            state: status,
            author: None,
            description: service_content.as_ref().and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("Description="))
                    .map(|l| l.trim_start_matches("Description=").to_string())
            }),
            date_created: None,
            date_modified: fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| format!("{:?}", t)),
            last_run_time: None,
            next_run_time: None,
            source_pid: 0,
            source_process: String::new(),
            raw_definition: content,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "linux")]
    async fn parse_at_job(path: &str, operation: &str) -> Option<ScheduledTaskEvent> {
        use std::fs;

        let content = if operation != "delete" {
            fs::read_to_string(path).ok()
        } else {
            None
        };

        let job_name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())?;

        // at job files contain shell commands
        let command = content
            .as_ref()
            .map(|c| {
                c.lines()
                    .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();

        Some(ScheduledTaskEvent {
            task_name: job_name,
            task_path: path.to_string(),
            operation: operation.to_string(),
            command,
            arguments: None,
            working_directory: None,
            run_as_user: fs::metadata(path)
                .ok()
                .and_then(|m| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        let uid = m.uid();
                        unsafe {
                            let pwd = libc::getpwuid(uid);
                            if !pwd.is_null() {
                                std::ffi::CStr::from_ptr((*pwd).pw_name)
                                    .to_str()
                                    .ok()
                                    .map(|s| s.to_string())
                            } else {
                                None
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    None
                })
                .unwrap_or_else(|| "unknown".to_string()),
            privilege_level: "user".to_string(),
            trigger_type: "at".to_string(),
            trigger_details: None,
            is_hidden: false,
            is_enabled: true,
            state: if operation == "delete" {
                "Deleted"
            } else {
                "Pending"
            }
            .to_string(),
            author: None,
            description: None,
            date_created: fs::metadata(path)
                .ok()
                .and_then(|m| m.created().ok())
                .map(|t| format!("{:?}", t)),
            date_modified: None,
            last_run_time: None,
            next_run_time: None,
            source_pid: 0,
            source_process: String::new(),
            raw_definition: content,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "linux")]
    async fn monitor_crontab_commands(tx: mpsc::Sender<TelemetryEvent>) {
        use std::collections::HashSet;
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        let mut seen_pids: HashSet<u32> = HashSet::new();

        loop {
            system.refresh_processes_specifics(ProcessRefreshKind::new());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                if seen_pids.contains(&pid_u32) {
                    continue;
                }

                let name = process.name().to_lowercase();
                if name == "crontab" || name == "at" || name == "atd" || name == "batch" {
                    seen_pids.insert(pid_u32);

                    let cmdline = process.cmd().join(" ");

                    // Determine operation
                    let operation = if cmdline.contains("-e") {
                        "edit"
                    } else if cmdline.contains("-r") || cmdline.contains("-d") {
                        "delete"
                    } else if cmdline.contains("-l") {
                        "list"
                    } else {
                        "create"
                    };

                    let user = process
                        .user_id()
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    let task = ScheduledTaskEvent {
                        task_name: format!("{}_{}", name, pid_u32),
                        task_path: name.clone(),
                        operation: operation.to_string(),
                        command: cmdline.clone(),
                        arguments: None,
                        working_directory: process.cwd().map(|p| p.to_string_lossy().to_string()),
                        run_as_user: user,
                        privilege_level: "user".to_string(),
                        trigger_type: "process".to_string(),
                        trigger_details: Some(cmdline),
                        is_hidden: false,
                        is_enabled: true,
                        state: "Running".to_string(),
                        author: None,
                        description: None,
                        date_created: None,
                        date_modified: None,
                        last_run_time: None,
                        next_run_time: None,
                        source_pid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                        source_process: process
                            .parent()
                            .and_then(|ppid| system.process(ppid))
                            .map(|p| p.name().to_string())
                            .unwrap_or_default(),
                        raw_definition: None,
                        risk_indicators: Vec::new(),
                        risk_score: 0,
                    };

                    let event = Self::create_telemetry_event(task);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Clean up old PIDs
            if seen_pids.len() > 1000 {
                let current_pids: HashSet<u32> =
                    system.processes().keys().map(|p| p.as_u32()).collect();
                seen_pids.retain(|p| current_pids.contains(p));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_systemd_timers(tx: mpsc::Sender<TelemetryEvent>) {
        use std::collections::HashMap;
        use std::process::Command;

        let mut known_timers: HashMap<String, String> = HashMap::new();

        loop {
            // List all timers using systemctl
            let output = Command::new("systemctl")
                .args(["list-timers", "--all", "--no-pager", "--plain"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let mut current_timers: HashMap<String, String> = HashMap::new();

                    for line in stdout.lines().skip(1) {
                        // Skip header
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 5 {
                            // NEXT LEFT LAST PASSED UNIT ACTIVATES
                            if let Some(unit) = parts.get(4) {
                                if unit.ends_with(".timer") {
                                    let state = parts.get(5).unwrap_or(&"unknown").to_string();
                                    current_timers.insert(unit.to_string(), state.clone());

                                    // Check if timer is new or changed
                                    if !known_timers.contains_key(*unit) {
                                        // New timer detected at runtime
                                        if let Some(task) =
                                            Self::parse_systemd_timer_runtime(unit).await
                                        {
                                            let event = Self::create_telemetry_event(task);
                                            let _ = tx.send(event).await;
                                        }
                                    } else if known_timers.get(*unit) != Some(&state) {
                                        // Timer state changed
                                        if let Some(mut task) =
                                            Self::parse_systemd_timer_runtime(unit).await
                                        {
                                            task.operation = "state_change".to_string();
                                            let event = Self::create_telemetry_event(task);
                                            let _ = tx.send(event).await;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Check for removed timers
                    for (timer, _) in &known_timers {
                        if !current_timers.contains_key(timer) {
                            let task = ScheduledTaskEvent {
                                task_name: timer.clone(),
                                task_path: String::new(),
                                operation: "delete".to_string(),
                                command: String::new(),
                                arguments: None,
                                working_directory: None,
                                run_as_user: String::new(),
                                privilege_level: String::new(),
                                trigger_type: "systemd".to_string(),
                                trigger_details: None,
                                is_hidden: false,
                                is_enabled: false,
                                state: "Removed".to_string(),
                                author: None,
                                description: None,
                                date_created: None,
                                date_modified: None,
                                last_run_time: None,
                                next_run_time: None,
                                source_pid: 0,
                                source_process: String::new(),
                                raw_definition: None,
                                risk_indicators: Vec::new(),
                                risk_score: 0,
                            };
                            let event = Self::create_telemetry_event(task);
                            let _ = tx.send(event).await;
                        }
                    }

                    known_timers = current_timers;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn parse_systemd_timer_runtime(timer_name: &str) -> Option<ScheduledTaskEvent> {
        use std::process::Command;

        // Get timer details using systemctl show
        let output = Command::new("systemctl")
            .args(["show", timer_name, "--no-pager"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut properties: HashMap<String, String> = HashMap::new();

        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                properties.insert(key.to_string(), value.to_string());
            }
        }

        // Get associated service
        let service_name = timer_name.replace(".timer", ".service");
        let service_output = Command::new("systemctl")
            .args(["show", &service_name, "--no-pager"])
            .output()
            .ok();

        let service_props: HashMap<String, String> = service_output
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout
                    .lines()
                    .filter_map(|l| l.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Some(ScheduledTaskEvent {
            task_name: timer_name.to_string(),
            task_path: properties.get("FragmentPath").cloned().unwrap_or_default(),
            operation: "runtime_detect".to_string(),
            command: service_props.get("ExecStart").cloned().unwrap_or_default(),
            arguments: None,
            working_directory: service_props.get("WorkingDirectory").cloned(),
            run_as_user: service_props
                .get("User")
                .cloned()
                .unwrap_or_else(|| "root".to_string()),
            privilege_level: if properties
                .get("FragmentPath")
                .map(|p| {
                    p.starts_with("/etc/systemd/system") || p.starts_with("/usr/lib/systemd/system")
                })
                .unwrap_or(false)
            {
                "system".to_string()
            } else {
                "user".to_string()
            },
            trigger_type: "systemd".to_string(),
            trigger_details: properties.get("TimersCalendar").cloned(),
            is_hidden: false,
            is_enabled: properties
                .get("UnitFileState")
                .map(|s| s == "enabled")
                .unwrap_or(false),
            state: properties.get("ActiveState").cloned().unwrap_or_default(),
            author: None,
            description: properties.get("Description").cloned(),
            date_created: None,
            date_modified: None,
            last_run_time: properties.get("LastTriggerUSec").cloned(),
            next_run_time: properties.get("NextElapseUSecRealtime").cloned(),
            source_pid: 0,
            source_process: String::new(),
            raw_definition: None,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    // ==================== macOS Implementation ====================
    #[cfg(target_os = "macos")]
    async fn monitor_macos(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) -> Result<()> {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};

        info!("Starting macOS scheduled task monitoring (launchd/cron)");

        // launchd plist directories
        let launchd_paths = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "~/Library/LaunchAgents",
        ];

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        })?;

        for path in launchd_paths {
            let expanded = shellexpand::tilde(path).to_string();
            if Path::new(&expanded).exists() {
                if let Err(e) = watcher.watch(Path::new(&expanded), RecursiveMode::Recursive) {
                    debug!(path = path, error = %e, "Failed to watch launchd path");
                }
            }
        }

        // Also monitor cron
        if Path::new("/var/at/tabs").exists() {
            let _ = watcher.watch(Path::new("/var/at/tabs"), RecursiveMode::Recursive);
        }

        // Monitor launchctl commands
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_launchctl_commands(tx_clone).await;
        });

        // Process file system events
        let runtime = tokio::runtime::Handle::current();
        let tx_clone = tx.clone();

        std::thread::spawn(move || {
            for event in notify_rx {
                for path in event.paths {
                    let path_str = path.to_string_lossy().to_string();

                    // Only process .plist files for launchd
                    if path_str.contains("Launch") && !path_str.ends_with(".plist") {
                        continue;
                    }

                    let operation = match &event.kind {
                        EventKind::Create(_) => "create",
                        EventKind::Modify(_) => "modify",
                        EventKind::Remove(_) => "delete",
                        _ => continue,
                    };

                    runtime.block_on(async {
                        let task_event = if path_str.contains("Launch") {
                            Self::parse_launchd_plist(&path_str, operation).await
                        } else {
                            Self::parse_cron_file(&path_str, operation).await
                        };

                        if let Some(task) = task_event {
                            let event = Self::create_telemetry_event(task);
                            let _ = tx_clone.send(event).await;
                        }
                    });
                }
            }
        });

        // Keep main task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "macos")]
    async fn parse_launchd_plist(path: &str, operation: &str) -> Option<ScheduledTaskEvent> {
        use std::fs;
        use std::process::Command;

        let content = if operation != "delete" {
            fs::read_to_string(path).ok()
        } else {
            None
        };

        let label = Path::new(path)
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())?;

        // Try to parse plist using plutil
        let mut program = String::new();
        let mut program_args: Option<String> = None;
        let mut working_dir: Option<String> = None;
        let mut user_name: Option<String> = None;
        let mut run_at_load = false;
        let mut start_interval: Option<String> = None;
        let mut start_calendar_interval: Option<String> = None;

        if operation != "delete" {
            // Convert plist to JSON for easier parsing
            let output = Command::new("plutil")
                .args(["-convert", "json", "-o", "-", path])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let json_str = String::from_utf8_lossy(&output.stdout);
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        program = json
                            .get("Program")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_default();

                        program_args =
                            json.get("ProgramArguments")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                });

                        working_dir = json
                            .get("WorkingDirectory")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        user_name = json
                            .get("UserName")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        run_at_load = json
                            .get("RunAtLoad")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        start_interval = json
                            .get("StartInterval")
                            .and_then(|v| v.as_i64())
                            .map(|i| format!("every {} seconds", i));

                        start_calendar_interval = json
                            .get("StartCalendarInterval")
                            .map(|v| format!("{:?}", v));

                        if program.is_empty() && program_args.is_some() {
                            program = program_args
                                .as_ref()
                                .and_then(|a| a.split_whitespace().next())
                                .unwrap_or("")
                                .to_string();
                        }
                    }
                }
            }
        }

        // Determine privilege level based on path
        let privilege_level =
            if path.contains("/System/") || path.contains("/Library/LaunchDaemons") {
                "system".to_string()
            } else if path.contains("/Library/LaunchAgents") {
                "admin".to_string()
            } else {
                "user".to_string()
            };

        // Determine trigger type
        let trigger_type = if run_at_load {
            "RunAtLoad"
        } else if start_interval.is_some() {
            "StartInterval"
        } else if start_calendar_interval.is_some() {
            "StartCalendarInterval"
        } else {
            "OnDemand"
        };

        Some(ScheduledTaskEvent {
            task_name: label,
            task_path: path.to_string(),
            operation: operation.to_string(),
            command: program,
            arguments: program_args,
            working_directory: working_dir,
            run_as_user: user_name.unwrap_or_else(|| {
                if path.contains("LaunchDaemons") {
                    "root".to_string()
                } else {
                    whoami::username()
                }
            }),
            privilege_level,
            trigger_type: trigger_type.to_string(),
            trigger_details: start_interval.or(start_calendar_interval),
            is_hidden: false,
            is_enabled: true,
            state: if operation == "delete" {
                "Deleted"
            } else {
                "Loaded"
            }
            .to_string(),
            author: None,
            description: None,
            date_created: fs::metadata(path)
                .ok()
                .and_then(|m| m.created().ok())
                .map(|t| format!("{:?}", t)),
            date_modified: fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| format!("{:?}", t)),
            last_run_time: None,
            next_run_time: None,
            source_pid: 0,
            source_process: String::new(),
            raw_definition: content,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "macos")]
    async fn parse_cron_file(path: &str, operation: &str) -> Option<ScheduledTaskEvent> {
        // Reuse Linux cron parsing logic
        use std::fs;

        let content = if operation != "delete" {
            fs::read_to_string(path).ok()
        } else {
            None
        };

        let user = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string());

        let mut commands = Vec::new();
        let mut schedule = String::new();

        if let Some(ref content) = content {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    schedule = parts[..5].join(" ");
                    commands.push(parts[5..].join(" "));
                }
            }
        }

        let task_name = user.clone().unwrap_or_else(|| "cron_entry".to_string());

        Some(ScheduledTaskEvent {
            task_name,
            task_path: path.to_string(),
            operation: operation.to_string(),
            command: commands.join("; "),
            arguments: None,
            working_directory: None,
            run_as_user: user.unwrap_or_else(|| "unknown".to_string()),
            privilege_level: "user".to_string(),
            trigger_type: "cron".to_string(),
            trigger_details: Some(schedule),
            is_hidden: false,
            is_enabled: true,
            state: if operation == "delete" {
                "Deleted"
            } else {
                "Active"
            }
            .to_string(),
            author: None,
            description: None,
            date_created: None,
            date_modified: None,
            last_run_time: None,
            next_run_time: None,
            source_pid: 0,
            source_process: String::new(),
            raw_definition: content,
            risk_indicators: Vec::new(),
            risk_score: 0,
        })
    }

    #[cfg(target_os = "macos")]
    async fn monitor_launchctl_commands(tx: mpsc::Sender<TelemetryEvent>) {
        use std::collections::HashSet;
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        let mut seen_pids: HashSet<u32> = HashSet::new();

        loop {
            system.refresh_processes_specifics(ProcessRefreshKind::new());

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                if seen_pids.contains(&pid_u32) {
                    continue;
                }

                let name = process.name().to_lowercase();
                if name == "launchctl" {
                    seen_pids.insert(pid_u32);

                    let cmdline = process.cmd().join(" ");

                    // Determine operation from command line
                    let operation = if cmdline.contains("load") {
                        "load"
                    } else if cmdline.contains("unload") {
                        "unload"
                    } else if cmdline.contains("submit") {
                        "submit"
                    } else if cmdline.contains("remove") {
                        "remove"
                    } else if cmdline.contains("bootstrap") {
                        "bootstrap"
                    } else if cmdline.contains("bootout") {
                        "bootout"
                    } else {
                        "query"
                    };

                    // Extract plist path from cmdline
                    let plist_path = cmdline
                        .split_whitespace()
                        .find(|s| {
                            s.ends_with(".plist")
                                || s.contains("LaunchAgents")
                                || s.contains("LaunchDaemons")
                        })
                        .unwrap_or("")
                        .to_string();

                    let task = ScheduledTaskEvent {
                        task_name: Path::new(&plist_path)
                            .file_stem()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| format!("launchctl_{}", pid_u32)),
                        task_path: plist_path,
                        operation: operation.to_string(),
                        command: cmdline.clone(),
                        arguments: None,
                        working_directory: None,
                        run_as_user: process
                            .user_id()
                            .map(|u| u.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        privilege_level: "unknown".to_string(),
                        trigger_type: "process".to_string(),
                        trigger_details: Some(cmdline),
                        is_hidden: false,
                        is_enabled: true,
                        state: "Running".to_string(),
                        author: None,
                        description: None,
                        date_created: None,
                        date_modified: None,
                        last_run_time: None,
                        next_run_time: None,
                        source_pid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                        source_process: process
                            .parent()
                            .and_then(|ppid| system.process(ppid))
                            .map(|p| p.name().to_string())
                            .unwrap_or_default(),
                        raw_definition: None,
                        risk_indicators: Vec::new(),
                        risk_score: 0,
                    };

                    let event = Self::create_telemetry_event(task);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Clean up old PIDs
            if seen_pids.len() > 1000 {
                let current_pids: HashSet<u32> =
                    system.processes().keys().map(|p| p.as_u32()).collect();
                seen_pids.retain(|p| current_pids.contains(p));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}
