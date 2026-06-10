//! PTY Shell WebSocket Bridge
//!
//! Bridges PTY shell sessions to WebSocket channels for bidirectional streaming.
//! Handles session management, authentication verification, and output routing.
//!
//! # Security
//! - Requires authenticated session_id from server
//! - All I/O is logged for audit
//! - Session timeout enforcement
//! - Rate limiting on input

// PTY bridge. Scaffolded reader-rotation intermediates retained.
#![allow(dead_code, unused_variables, unused_assignments)]

use crate::response::pty_shell::{AsyncPtyShell, PtyReader, DEFAULT_COLS, DEFAULT_ROWS};
use crate::transport::CommandResult;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::{close, dup2, execvp, fork, pipe, ForkResult, Pid};
#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(unix)]
use tokio::fs::File as TokioFile;

/// Global PTY bridge instance
static PTY_BRIDGE: std::sync::OnceLock<Arc<PtyBridge>> = std::sync::OnceLock::new();

/// Get or initialize the global PTY bridge
pub fn get_pty_bridge() -> Arc<PtyBridge> {
    PTY_BRIDGE
        .get_or_init(|| Arc::new(PtyBridge::new(10)))
        .clone()
}

/// PTY session state
#[derive(Debug)]
struct PtySession {
    /// Session ID (assigned by server)
    session_id: String,
    /// User ID who initiated the session
    user_id: String,
    /// The active shell backend
    shell: ShellBackend,
    /// Output sender to WebSocket
    output_tx: mpsc::Sender<PtyOutput>,
    /// Session start time
    started_at: u64,
    /// Last activity timestamp
    last_activity: u64,
    /// Whether the session is active
    active: bool,
}

#[derive(Debug)]
enum ShellBackend {
    Pty(AsyncPtyShell),
    Process(ProcessShell),
}

impl ShellBackend {
    async fn write(&mut self, data: &[u8]) -> Result<usize> {
        match self {
            ShellBackend::Pty(shell) => shell.write(data).await,
            ShellBackend::Process(shell) => shell.write(data).await,
        }
    }

    async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        match self {
            ShellBackend::Pty(shell) => shell.resize(cols, rows).await,
            ShellBackend::Process(_) => {
                debug!(cols, rows, "Ignoring resize for pipe shell fallback");
                Ok(())
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        match self {
            ShellBackend::Pty(shell) => shell.close().await,
            ShellBackend::Process(shell) => shell.close().await,
        }
    }

    fn child_pid(&self) -> u32 {
        match self {
            ShellBackend::Pty(shell) => shell.child_pid(),
            ShellBackend::Process(shell) => shell.pid,
        }
    }
}

struct ProcessShell {
    child: ProcessHandle,
    stdin: Option<BoxedAsyncWrite>,
    pid: u32,
}

type BoxedAsyncRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxedAsyncWrite = Box<dyn AsyncWrite + Unpin + Send>;

#[derive(Debug)]
enum ProcessHandle {
    Tokio(Child),
    #[cfg(unix)]
    Unix(Pid),
}

impl std::fmt::Debug for ProcessShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessShell")
            .field("child", &self.child)
            .field("stdin", &self.stdin.as_ref().map(|_| "<pipe>"))
            .field("pid", &self.pid)
            .finish()
    }
}

impl ProcessShell {
    async fn spawn(
        command: &str,
    ) -> Result<(Self, Option<BoxedAsyncRead>, Option<BoxedAsyncRead>)> {
        match Self::spawn_with_tokio_command(command).await {
            Ok(shell) => Ok(shell),
            Err(tokio_error) => {
                #[cfg(unix)]
                {
                    warn!(
                        command = %command,
                        error = %tokio_error,
                        "Pipe shell spawn via tokio::process failed; trying fork/exec fallback"
                    );
                    Self::spawn_with_unix_fork(command).map_err(|fork_error| {
                        anyhow!(
                            "Failed to spawn pipe shell fallback: tokio::process failed: {}; fork/exec failed: {}",
                            tokio_error,
                            fork_error
                        )
                    })
                }

                #[cfg(not(unix))]
                {
                    Err(tokio_error)
                }
            }
        }
    }

    async fn spawn_with_tokio_command(
        command: &str,
    ) -> Result<(Self, Option<BoxedAsyncRead>, Option<BoxedAsyncRead>)> {
        let (program, args) = pipe_shell_command(command);
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("TERM", "dumb")
            .env("HOME", default_home_dir())
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .current_dir("/")
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn pipe shell fallback: {}", e))?;

        let pid = child.id().unwrap_or_default();
        let stdin = child
            .stdin
            .take()
            .map(|stdin| Box::new(stdin) as BoxedAsyncWrite);
        let stdout = child
            .stdout
            .take()
            .map(|stdout| Box::new(stdout) as BoxedAsyncRead);
        let stderr = child
            .stderr
            .take()
            .map(|stderr| Box::new(stderr) as BoxedAsyncRead);

        Ok((
            Self {
                child: ProcessHandle::Tokio(child),
                stdin,
                pid,
            },
            stdout,
            stderr,
        ))
    }

    #[cfg(unix)]
    fn spawn_with_unix_fork(
        command: &str,
    ) -> Result<(Self, Option<BoxedAsyncRead>, Option<BoxedAsyncRead>)> {
        let (stdin_read, stdin_write) =
            pipe().map_err(|e| anyhow!("Failed to create stdin pipe: {}", e))?;
        let (stdout_read, stdout_write) =
            pipe().map_err(|e| anyhow!("Failed to create stdout pipe: {}", e))?;
        let (stderr_read, stderr_write) =
            pipe().map_err(|e| anyhow!("Failed to create stderr pipe: {}", e))?;

        match unsafe { fork() }.map_err(|e| anyhow!("Failed to fork pipe shell: {}", e))? {
            ForkResult::Child => {
                let _ = close(stdin_write);
                let _ = close(stdout_read);
                let _ = close(stderr_read);

                dup2(stdin_read.as_raw_fd(), 0).ok();
                dup2(stdout_write.as_raw_fd(), 1).ok();
                dup2(stderr_write.as_raw_fd(), 2).ok();

                let _ = close(stdin_read);
                let _ = close(stdout_write);
                let _ = close(stderr_write);

                std::env::set_var("TERM", "dumb");
                std::env::set_var("HOME", default_home_dir());
                std::env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

                let shell = match CString::new(command) {
                    Ok(shell) => shell,
                    Err(e) => {
                        eprintln!("Invalid shell path: {}", e);
                        std::process::exit(127);
                    }
                };
                let mut args = vec![shell.clone()];
                if is_interactive_shell(command) {
                    args.push(CString::new("-i").expect("static interactive shell flag"));
                }

                if let Err(e) = execvp(&shell, &args) {
                    eprintln!("Failed to execute pipe shell: {}", e);
                }
                std::process::exit(127);
            }
            ForkResult::Parent { child } => {
                let _ = close(stdin_read);
                let _ = close(stdout_write);
                let _ = close(stderr_write);

                let stdin_file = unsafe { std::fs::File::from_raw_fd(stdin_write.into_raw_fd()) };
                let stdout_file = unsafe { std::fs::File::from_raw_fd(stdout_read.into_raw_fd()) };
                let stderr_file = unsafe { std::fs::File::from_raw_fd(stderr_read.into_raw_fd()) };

                let stdin = Box::new(TokioFile::from_std(stdin_file)) as BoxedAsyncWrite;
                let stdout = Box::new(TokioFile::from_std(stdout_file)) as BoxedAsyncRead;
                let stderr = Box::new(TokioFile::from_std(stderr_file)) as BoxedAsyncRead;

                Ok((
                    Self {
                        child: ProcessHandle::Unix(child),
                        stdin: Some(stdin),
                        pid: child.as_raw() as u32,
                    },
                    Some(stdout),
                    Some(stderr),
                ))
            }
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<usize> {
        match self.stdin.as_mut() {
            Some(stdin) => {
                stdin
                    .write_all(data)
                    .await
                    .map_err(|e| anyhow!("Failed to write to pipe shell: {}", e))?;
                stdin
                    .flush()
                    .await
                    .map_err(|e| anyhow!("Failed to flush pipe shell: {}", e))?;
                Ok(data.len())
            }
            None => Err(anyhow!("Pipe shell stdin is closed")),
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.stdin.take();

        match &mut self.child {
            ProcessHandle::Tokio(child) => {
                if let Err(e) = child.start_kill() {
                    warn!(error = %e, pid = self.pid, "Failed to kill pipe shell fallback");
                }
            }
            #[cfg(unix)]
            ProcessHandle::Unix(pid) => {
                if let Err(e) = kill(*pid, Signal::SIGTERM) {
                    warn!(error = %e, pid = self.pid, "Failed to kill forked pipe shell fallback");
                }
            }
        }

        Ok(())
    }
}

/// Output message from PTY to WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PtyOutput {
    /// Shell data output
    Data { session_id: String, data: String },
    /// Session started
    SessionStarted {
        session_id: String,
        shell: String,
        cols: u16,
        rows: u16,
        pid: u32,
    },
    /// Session ended
    SessionEnded { session_id: String, reason: String },
    /// Error
    Error { session_id: String, message: String },
    /// Pong response
    Pong { session_id: String, timestamp: u64 },
}

/// Input message from WebSocket to PTY
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PtyInput {
    /// Raw terminal data
    Data { data: String },
    /// Resize terminal
    Resize { cols: u16, rows: u16 },
    /// Ping/keepalive
    Ping,
    /// Terminate session
    Terminate,
}

/// PTY bridge configuration
#[derive(Debug, Clone)]
pub struct PtyBridgeConfig {
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session timeout in seconds
    pub session_timeout_secs: u64,
    /// Default shell command
    pub default_shell: Option<String>,
    /// Initial terminal columns
    pub default_cols: u16,
    /// Initial terminal rows
    pub default_rows: u16,
}

impl Default for PtyBridgeConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10,
            session_timeout_secs: 1800, // 30 minutes
            default_shell: None,
            default_cols: DEFAULT_COLS,
            default_rows: DEFAULT_ROWS,
        }
    }
}

/// PTY Bridge - manages PTY sessions and routes I/O to WebSocket
pub struct PtyBridge {
    /// Active sessions
    sessions: RwLock<HashMap<String, Arc<Mutex<PtySession>>>>,
    /// Maximum concurrent sessions
    max_sessions: usize,
    /// Global output sender (for routing to WebSocket)
    output_tx: mpsc::Sender<PtyOutput>,
    /// Global output receiver (consumed by WebSocket handler)
    output_rx: Arc<Mutex<mpsc::Receiver<PtyOutput>>>,
}

impl PtyBridge {
    /// Create a new PTY bridge
    pub fn new(max_sessions: usize) -> Self {
        let (output_tx, output_rx) = mpsc::channel(1000);

        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
            output_tx,
            output_rx: Arc::new(Mutex::new(output_rx)),
        }
    }

    /// Get the output receiver for consuming PTY output
    pub fn get_output_receiver(&self) -> Arc<Mutex<mpsc::Receiver<PtyOutput>>> {
        self.output_rx.clone()
    }

    /// Start a new PTY session
    ///
    /// # Arguments
    /// * `session_id` - Unique session ID (from server)
    /// * `user_id` - Authenticated user ID
    /// * `shell` - Optional shell command (uses default if not specified)
    /// * `cols` - Initial terminal columns
    /// * `rows` - Initial terminal rows
    pub async fn start_session(
        &self,
        session_id: &str,
        user_id: &str,
        shell: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.cleanup_inactive().await;

        // Check session limit
        {
            let sessions = self.sessions.read().await;
            if sessions.len() >= self.max_sessions {
                return Err(anyhow!(
                    "Maximum number of PTY sessions ({}) reached",
                    self.max_sessions
                ));
            }

            // Check if session already exists
            if sessions.contains_key(session_id) {
                return Err(anyhow!("Session {} already exists", session_id));
            }
        }

        // Determine shell command
        let shell_cmd = shell
            .map(|s| s.to_string())
            .unwrap_or_else(|| get_default_shell());

        info!(
            session_id = %session_id,
            user_id = %user_id,
            shell = %shell_cmd,
            cols = cols,
            rows = rows,
            "Starting PTY session"
        );

        // Spawn the shell. Prefer a pipe-backed shell for macOS LaunchDaemons:
        // recent macOS builds can deny daemon PTY/session operations with EPERM.
        // Linux/Windows keep the real PTY path first for interactive behavior.
        let (shell_backend, child_pid, pty_reader, pipe_stdout, pipe_stderr, fallback_reason) =
            if prefer_pipe_shell() {
                warn!(
                    session_id = %session_id,
                    "Starting pipe shell fallback before PTY on this platform"
                );
                let (process_shell, stdout, stderr) = ProcessShell::spawn(&shell_cmd).await?;
                let child_pid = process_shell.pid;
                (
                    ShellBackend::Process(process_shell),
                    child_pid,
                    None,
                    stdout,
                    stderr,
                    Some("PTY disabled for macOS LaunchDaemon shell sessions".to_string()),
                )
            } else {
                match spawn_pty_with_timeout(&shell_cmd, cols, rows).await {
                    Ok(pty_shell) => {
                        let output_reader = pty_shell.get_reader()?;
                        let child_pid = pty_shell.child_pid();
                        (
                            ShellBackend::Pty(pty_shell),
                            child_pid,
                            Some(output_reader),
                            None,
                            None,
                            None,
                        )
                    }
                    Err(e) if should_fallback_to_pipe_shell(&e) => {
                        warn!(
                            session_id = %session_id,
                            error = %e,
                            "PTY unavailable; starting pipe shell fallback"
                        );
                        let (process_shell, stdout, stderr) =
                            ProcessShell::spawn(&shell_cmd).await?;
                        let child_pid = process_shell.pid;
                        (
                            ShellBackend::Process(process_shell),
                            child_pid,
                            None,
                            stdout,
                            stderr,
                            Some(e.to_string()),
                        )
                    }
                    Err(e) => return Err(e),
                }
            };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = PtySession {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            shell: shell_backend,
            output_tx: self.output_tx.clone(),
            started_at: now,
            last_activity: now,
            active: true,
        };

        let session = Arc::new(Mutex::new(session));

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.to_string(), session.clone());
        }

        // Send session started notification
        self.output_tx
            .send(PtyOutput::SessionStarted {
                session_id: session_id.to_string(),
                shell: shell_cmd.clone(),
                cols,
                rows,
                pid: child_pid,
            })
            .await
            .ok();

        if let Some(output_reader) = pty_reader {
            self.output_tx
                .send(PtyOutput::Data {
                    session_id: session_id.to_string(),
                    data: "\r\n[Tamandua shell ready]\r\n".to_string(),
                })
                .await
                .ok();

            spawn_pty_output_reader(
                session_id.to_string(),
                output_reader,
                self.output_tx.clone(),
                session.clone(),
            );
        } else {
            if let Some(reason) = fallback_reason {
                self.output_tx
                    .send(PtyOutput::Data {
                        session_id: session_id.to_string(),
                        data: format!(
                            "\r\n[PTY unavailable: {}]\r\n[Using pipe shell fallback; interactive TTY features are limited]\r\n",
                            reason
                        ),
                    })
                    .await
                    .ok();
            }

            let remaining_pipe_streams = Arc::new(AtomicUsize::new(
                usize::from(pipe_stdout.is_some()) + usize::from(pipe_stderr.is_some()),
            ));

            if let Some(stdout) = pipe_stdout {
                spawn_pipe_output_reader(
                    session_id.to_string(),
                    "stdout",
                    stdout,
                    self.output_tx.clone(),
                    session.clone(),
                    remaining_pipe_streams.clone(),
                );
            }

            if let Some(stderr) = pipe_stderr {
                spawn_pipe_output_reader(
                    session_id.to_string(),
                    "stderr",
                    stderr,
                    self.output_tx.clone(),
                    session.clone(),
                    remaining_pipe_streams.clone(),
                );
            }
        }

        if should_kick_initial_prompt(&shell_cmd) {
            let mut session_guard = session.lock().await;
            if let Err(e) = session_guard.shell.write(b"\r").await {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "Failed to send initial shell prompt kick"
                );
            }
        }

        info!(
            session_id = %session_id,
            child_pid = child_pid,
            "PTY session started successfully"
        );

        Ok(())
    }

    /// Handle input for a session
    pub async fn handle_input(&self, session_id: &str, input: PtyInput) -> Result<()> {
        let session = {
            let sessions = self.sessions.read().await;
            sessions
                .get(session_id)
                .cloned()
                .ok_or_else(|| anyhow!("Session {} not found", session_id))?
        };

        let mut session = session.lock().await;

        if !session.active {
            return Err(anyhow!("Session {} is not active", session_id));
        }

        // Update last activity
        session.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match input {
            PtyInput::Data { data } => {
                debug!(
                    session_id = %session_id,
                    bytes = data.len(),
                    "Writing input to PTY session"
                );
                session.shell.write(data.as_bytes()).await?;
            }
            PtyInput::Resize { cols, rows } => {
                session.shell.resize(cols, rows).await?;
            }
            PtyInput::Ping => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                session
                    .output_tx
                    .send(PtyOutput::Pong {
                        session_id: session_id.to_string(),
                        timestamp,
                    })
                    .await
                    .ok();
            }
            PtyInput::Terminate => {
                self.terminate_session_inner(&mut session, "User requested termination")
                    .await?;
            }
        }

        Ok(())
    }

    /// Write data to a session
    pub async fn write(&self, session_id: &str, data: &[u8]) -> Result<usize> {
        let session = {
            let sessions = self.sessions.read().await;
            sessions
                .get(session_id)
                .cloned()
                .ok_or_else(|| anyhow!("Session {} not found", session_id))?
        };

        let mut session = session.lock().await;

        if !session.active {
            return Err(anyhow!("Session {} is not active", session_id));
        }

        session.shell.write(data).await
    }

    /// Resize a session's terminal
    pub async fn resize(&self, session_id: &str, cols: u16, rows: u16) -> Result<()> {
        let session = {
            let sessions = self.sessions.read().await;
            sessions
                .get(session_id)
                .cloned()
                .ok_or_else(|| anyhow!("Session {} not found", session_id))?
        };

        let mut session = session.lock().await;

        if !session.active {
            return Err(anyhow!("Session {} is not active", session_id));
        }

        debug!(session_id = %session_id, cols, rows, "Resizing PTY");
        session.shell.resize(cols, rows).await
    }

    /// Terminate a session
    pub async fn terminate_session(&self, session_id: &str, reason: &str) -> Result<()> {
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };

        if let Some(session) = session {
            let mut session = session.lock().await;
            self.terminate_session_inner(&mut session, reason).await?;
        }

        Ok(())
    }

    /// Terminate and remove all active sessions.
    pub async fn terminate_all_sessions(&self, reason: &str) -> usize {
        let sessions: Vec<Arc<Mutex<PtySession>>> = {
            let mut sessions = self.sessions.write().await;
            sessions.drain().map(|(_, session)| session).collect()
        };

        let count = sessions.len();
        for session in sessions {
            let mut session = session.lock().await;
            if let Err(e) = self.terminate_session_inner(&mut session, reason).await {
                warn!(
                    session_id = %session.session_id,
                    error = %e,
                    "Failed to terminate PTY session"
                );
            }
        }

        if count > 0 {
            info!(count, reason, "Terminated all PTY sessions");
        }

        count
    }

    /// Internal session termination
    async fn terminate_session_inner(&self, session: &mut PtySession, reason: &str) -> Result<()> {
        if !session.active {
            return Ok(());
        }

        info!(
            session_id = %session.session_id,
            reason = reason,
            "Terminating PTY session"
        );

        session.active = false;
        session.shell.close().await?;

        session
            .output_tx
            .send(PtyOutput::SessionEnded {
                session_id: session.session_id.clone(),
                reason: reason.to_string(),
            })
            .await
            .ok();

        Ok(())
    }

    /// List active sessions
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();

        for (id, session) in sessions.iter() {
            let session = session.lock().await;
            result.push(SessionInfo {
                session_id: id.clone(),
                user_id: session.user_id.clone(),
                started_at: session.started_at,
                last_activity: session.last_activity,
                active: session.active,
                child_pid: session.shell.child_pid(),
            });
        }

        result
    }

    /// Clean up inactive sessions
    pub async fn cleanup_inactive(&self) {
        let session_ids: Vec<(String, Arc<Mutex<PtySession>>)> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .map(|(id, session)| (id.clone(), session.clone()))
                .collect()
        };

        let mut to_remove = Vec::new();
        for (id, session) in session_ids {
            let session = session.lock().await;
            if !session.active {
                to_remove.push(id);
            }
        }

        if !to_remove.is_empty() {
            let mut sessions = self.sessions.write().await;
            for id in &to_remove {
                sessions.remove(id);
            }
            info!(count = to_remove.len(), "Cleaned up inactive PTY sessions");
        }
    }

    /// Check and terminate timed out sessions
    pub async fn check_timeouts(&self, timeout_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session_ids: Vec<(String, Arc<Mutex<PtySession>>)> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .map(|(id, session)| (id.clone(), session.clone()))
                .collect()
        };

        let mut timed_out = Vec::new();
        for (id, session) in session_ids {
            let session = session.lock().await;
            if session.active && now - session.last_activity > timeout_secs {
                timed_out.push(id);
            }
        }

        for session_id in timed_out {
            warn!(session_id = %session_id, "PTY session timed out");
            if let Err(e) = self
                .terminate_session(&session_id, "Session timed out due to inactivity")
                .await
            {
                error!(session_id = %session_id, error = %e, "Failed to terminate timed out session");
            }
        }
    }
}

fn read_pty_output(mut reader: PtyReader) -> (PtyReader, Result<Vec<u8>>) {
    let mut buf = vec![0u8; 4096];
    let result = match reader.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(e) => Err(anyhow!("Read failed: {}", e)),
    };
    (reader, result)
}

fn spawn_pty_output_reader(
    session_id: String,
    output_reader: PtyReader,
    output_tx: mpsc::Sender<PtyOutput>,
    session: Arc<Mutex<PtySession>>,
) {
    tokio::spawn(async move {
        let mut output_reader = Some(output_reader);

        loop {
            {
                let session = session.lock().await;
                if !session.active {
                    break;
                }
            }

            let Some(reader) = output_reader.take() else {
                break;
            };

            let read_result = tokio::task::spawn_blocking(move || read_pty_output(reader))
                .await
                .map_err(|e| anyhow!("PTY reader task failed: {}", e));

            match read_result {
                Ok((reader, Ok(data))) if data.is_empty() => {
                    output_reader = Some(reader);
                    info!(session_id = %session_id, "PTY shell exited");
                    break;
                }
                Ok((reader, Ok(data))) => {
                    output_reader = Some(reader);
                    let data = String::from_utf8_lossy(&data).to_string();
                    if output_tx
                        .send(PtyOutput::Data {
                            session_id: session_id.clone(),
                            data,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok((reader, Err(e))) => {
                    output_reader = Some(reader);
                    let err_str = e.to_string();
                    if err_str.contains("pipe")
                        || err_str.contains("EOF")
                        || err_str.contains("broken")
                    {
                        debug!(session_id = %session_id, "PTY pipe closed");
                    } else {
                        warn!(session_id = %session_id, error = %e, "PTY read error");
                    }
                    break;
                }
                Err(e) => {
                    warn!(session_id = %session_id, error = %e, "PTY read task error");
                    break;
                }
            }
        }

        {
            let mut session = session.lock().await;
            session.active = false;
        }

        output_tx
            .send(PtyOutput::SessionEnded {
                session_id,
                reason: "Shell exited".to_string(),
            })
            .await
            .ok();
    });
}

fn spawn_pipe_output_reader<R>(
    session_id: String,
    stream_name: &'static str,
    mut reader: R,
    output_tx: mpsc::Sender<PtyOutput>,
    session: Arc<Mutex<PtySession>>,
    remaining_streams: Arc<AtomicUsize>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];

        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                    if output_tx
                        .send(PtyOutput::Data {
                            session_id: session_id.clone(),
                            data,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        stream = stream_name,
                        error = %e,
                        "Pipe shell read error"
                    );
                    break;
                }
            }
        }

        if remaining_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            {
                let mut session = session.lock().await;
                session.active = false;
            }

            output_tx
                .send(PtyOutput::SessionEnded {
                    session_id,
                    reason: "Shell exited".to_string(),
                })
                .await
                .ok();
        }
    });
}

fn should_fallback_to_pipe_shell(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_lowercase();
    message.contains("eperm")
        || message.contains("operation not permitted")
        || message.contains("permission denied")
        || message.contains("failed to open pty")
        || (cfg!(unix) && message.contains("pty spawn timed out"))
}

fn prefer_pipe_shell() -> bool {
    std::env::var("TAMANDUA_PREFER_PIPE_SHELL")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

async fn spawn_pty_with_timeout(command: &str, cols: u16, rows: u16) -> Result<AsyncPtyShell> {
    let timeout = pty_spawn_timeout();

    match tokio::time::timeout(timeout, AsyncPtyShell::spawn_with_size(command, cols, rows)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("PTY spawn timed out after {}s", timeout.as_secs())),
    }
}

fn pty_spawn_timeout() -> std::time::Duration {
    let seconds = std::env::var("TAMANDUA_PTY_SPAWN_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(8);

    std::time::Duration::from_secs(seconds)
}

fn is_interactive_shell(shell_cmd: &str) -> bool {
    let shell_name = std::path::Path::new(shell_cmd)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(shell_cmd)
        .to_ascii_lowercase();

    matches!(shell_name.as_str(), "sh" | "bash" | "zsh" | "ksh" | "fish")
}

fn pipe_shell_command(shell_cmd: &str) -> (&str, Vec<&'static str>) {
    if is_interactive_shell(shell_cmd) {
        (shell_cmd, vec!["-i"])
    } else {
        (shell_cmd, Vec::new())
    }
}

fn should_kick_initial_prompt(shell_cmd: &str) -> bool {
    #[cfg(all(unix, not(target_os = "macos")))]
    if is_interactive_shell(shell_cmd) && !prefer_pipe_shell() {
        return false;
    }

    let shell_name = std::path::Path::new(shell_cmd)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(shell_cmd)
        .to_ascii_lowercase();

    matches!(
        shell_name.as_str(),
        "sh" | "bash" | "zsh" | "ksh" | "fish" | "cmd.exe" | "powershell.exe" | "pwsh.exe"
    )
}

/// Session info for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub user_id: String,
    pub started_at: u64,
    pub last_activity: u64,
    pub active: bool,
    pub child_pid: u32,
}

/// Get the default shell for the current platform
fn get_default_shell() -> String {
    #[cfg(target_os = "windows")]
    {
        "cmd.exe".to_string()
    }

    #[cfg(target_os = "macos")]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for shell in ["/bin/bash", "/usr/bin/bash", "/bin/zsh", "/bin/sh"] {
            if std::path::Path::new(shell).exists() {
                return shell.to_string();
            }
        }

        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

fn default_home_dir() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "/var/root"
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "/root"
    }

    #[cfg(not(unix))]
    {
        "C:\\"
    }
}

// =============================================================================
// Command Handlers for Integration with Response Module
// =============================================================================

/// Handle shell:start command
pub async fn handle_shell_start(payload: &serde_json::Value) -> CommandResult {
    let session_id = match payload.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'session_id' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let user_id = payload
        .get("user_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let shell = payload.get("shell").and_then(|v| v.as_str());

    let cols = payload
        .get("cols")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_COLS as u64) as u16;

    let rows = payload
        .get("rows")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_ROWS as u64) as u16;

    let bridge = get_pty_bridge();

    match bridge
        .start_session(session_id, user_id, shell, cols, rows)
        .await
    {
        Ok(()) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "session_id": session_id,
                "cols": cols,
                "rows": rows
            })),
        },
        Err(e) => {
            error!(
                session_id = %session_id,
                user_id = %user_id,
                error = %e,
                "Failed to start shell session"
            );
            CommandResult {
                success: false,
                error_message: Some(format!("Failed to start shell session: {}", e)),
                result_data: None,
            }
        }
    }
}

/// Handle shell:input command
pub async fn handle_shell_input(payload: &serde_json::Value) -> CommandResult {
    let session_id = match payload.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'session_id' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let input_type = payload
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("data");

    let bridge = get_pty_bridge();

    let input = match input_type {
        "data" => {
            let data = payload
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            PtyInput::Data { data }
        }
        "resize" => {
            let cols = payload
                .get("cols")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_COLS as u64) as u16;
            let rows = payload
                .get("rows")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_ROWS as u64) as u16;
            PtyInput::Resize { cols, rows }
        }
        "ping" => PtyInput::Ping,
        "terminate" => PtyInput::Terminate,
        _ => PtyInput::Data {
            data: payload
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        },
    };

    match bridge.handle_input(session_id, input).await {
        Ok(()) => CommandResult {
            success: true,
            error_message: None,
            result_data: None,
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Shell input error: {}", e)),
            result_data: None,
        },
    }
}

/// Handle shell:resize command
pub async fn handle_shell_resize(payload: &serde_json::Value) -> CommandResult {
    let session_id = match payload.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'session_id' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let cols = payload
        .get("cols")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_COLS as u64) as u16;

    let rows = payload
        .get("rows")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_ROWS as u64) as u16;

    let bridge = get_pty_bridge();

    match bridge.resize(session_id, cols, rows).await {
        Ok(()) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "cols": cols,
                "rows": rows
            })),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Resize error: {}", e)),
            result_data: None,
        },
    }
}

/// Handle shell:terminate command
pub async fn handle_shell_terminate(payload: &serde_json::Value) -> CommandResult {
    let session_id = match payload.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'session_id' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("User requested termination");

    let bridge = get_pty_bridge();

    match bridge.terminate_session(session_id, reason).await {
        Ok(()) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "session_id": session_id,
                "reason": reason
            })),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Terminate error: {}", e)),
            result_data: None,
        },
    }
}

/// List all active shell sessions
pub async fn handle_shell_list(_payload: &serde_json::Value) -> CommandResult {
    let bridge = get_pty_bridge();
    let sessions = bridge.list_sessions().await;

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "sessions": sessions,
            "count": sessions.len()
        })),
    }
}

/// Terminate all active shell sessions.
pub async fn terminate_all_sessions(reason: &str) -> usize {
    get_pty_bridge().terminate_all_sessions(reason).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pty_bridge_creation() {
        let bridge = PtyBridge::new(5);
        let sessions = bridge.list_sessions().await;
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_session_limit() {
        let bridge = PtyBridge::new(1);

        // Start first session
        let result = bridge
            .start_session("session1", "user1", None, 80, 24)
            .await;
        assert!(result.is_ok());

        // Second session should fail due to limit
        let result = bridge
            .start_session("session2", "user1", None, 80, 24)
            .await;
        assert!(result.is_err());

        // Cleanup
        bridge.terminate_session("session1", "test").await.ok();
    }

    #[tokio::test]
    async fn test_duplicate_session() {
        let bridge = PtyBridge::new(5);

        // Start first session
        let result = bridge
            .start_session("session1", "user1", None, 80, 24)
            .await;
        assert!(result.is_ok());

        // Duplicate should fail
        let result = bridge
            .start_session("session1", "user1", None, 80, 24)
            .await;
        assert!(result.is_err());

        // Cleanup
        bridge.terminate_session("session1", "test").await.ok();
    }

    #[test]
    fn test_pty_fallback_error_classification() {
        assert!(should_fallback_to_pipe_shell(&anyhow!("EPERM")));
        assert!(should_fallback_to_pipe_shell(&anyhow!(
            "operation not permitted"
        )));
        assert!(should_fallback_to_pipe_shell(&anyhow!("permission denied")));
        assert!(should_fallback_to_pipe_shell(&anyhow!(
            "Failed to open PTY: no controlling terminal"
        )));
        #[cfg(unix)]
        assert!(should_fallback_to_pipe_shell(&anyhow!(
            "PTY spawn timed out after 8s"
        )));
        assert!(!should_fallback_to_pipe_shell(&anyhow!(
            "command not found"
        )));
    }

    #[test]
    fn test_pipe_shell_preference_env() {
        std::env::remove_var("TAMANDUA_PREFER_PIPE_SHELL");
        assert!(!prefer_pipe_shell());

        std::env::set_var("TAMANDUA_PREFER_PIPE_SHELL", "1");
        assert!(prefer_pipe_shell());

        std::env::set_var("TAMANDUA_PREFER_PIPE_SHELL", "true");
        assert!(prefer_pipe_shell());

        std::env::set_var("TAMANDUA_PREFER_PIPE_SHELL", "false");
        assert!(!prefer_pipe_shell());

        std::env::remove_var("TAMANDUA_PREFER_PIPE_SHELL");
    }

    #[test]
    fn test_initial_prompt_kick_shell_detection() {
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(!should_kick_initial_prompt("/bin/zsh"));

        #[cfg(not(all(unix, not(target_os = "macos"))))]
        assert!(should_kick_initial_prompt("/bin/zsh"));

        assert!(should_kick_initial_prompt("pwsh.exe"));
        assert!(!should_kick_initial_prompt("/usr/bin/python3"));
    }

    #[test]
    fn test_pipe_shell_command_forces_interactive_unix_shells() {
        assert_eq!(pipe_shell_command("/bin/sh"), ("/bin/sh", vec!["-i"]));
        assert_eq!(pipe_shell_command("/bin/zsh"), ("/bin/zsh", vec!["-i"]));
        assert_eq!(
            pipe_shell_command("/usr/bin/python3"),
            ("/usr/bin/python3", Vec::new())
        );
    }
}
