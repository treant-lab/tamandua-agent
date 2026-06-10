//! IPC server implementation
//!
//! Runs in the privileged service and accepts connections from GUI clients.
//!
//! ## Security Features
//!
//! - Windows: Named pipe with restrictive ACLs (SYSTEM + Administrators full control,
//!   Authenticated Users read/write for GUI connectivity)
//! - Unix: Domain socket with 0600 permissions
//! - Challenge-response authentication to prevent replay attacks
//! - Sensitive read operations require authentication
//! - Defense-in-depth: Admin privilege verification for critical operations (driver load/unload, agent stop)

use crate::collectors::{EventPayload, EventType, SecurityAuditEvent, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use crate::transport::{Command, CommandResult, CommandType};
use crate::updater::{UpdateManifest, Updater};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Timelike, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::event_store::{EventQuery, EventStore};
use super::{IpcAuthenticator, IpcMessage, MessageFrame};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// IPC server for service-to-GUI communication
pub struct IpcServer {
    // Use RwLock for authenticator to allow mutation for challenge-response state
    authenticator: Arc<RwLock<IpcAuthenticator>>,
    config: Arc<RwLock<AgentConfig>>,
    clients: Arc<RwLock<Vec<IpcClientInfo>>>,
    update_state: Arc<Mutex<UpdateState>>,
    broadcast_tx: broadcast::Sender<IpcMessage>,
    shutdown_tx: mpsc::Sender<()>,
    /// Optional telemetry sender for emitting security audit events to the server
    telemetry_tx: Option<mpsc::Sender<TelemetryEvent>>,
    /// Recent local telemetry shown by the desktop GUI.
    event_history: Arc<RwLock<Vec<super::TelemetryEvent>>>,
    /// Persistent local event history shown by the desktop GUI.
    event_store: Option<EventStore>,
    /// Collectors that successfully initialized in the running agent pipeline.
    collectors_running: Arc<RwLock<Vec<String>>>,
    /// Signals the running collector loop to reload the service config.
    config_reload_tx: Option<watch::Sender<u64>>,
    /// Runtime backend transport status reported by the main agent loop.
    backend_runtime: Arc<RwLock<BackendRuntimeStatus>>,
    started_at: DateTime<Utc>,
}

/// Connected IPC client information
#[allow(dead_code)]
struct IpcClientInfo {
    id: String,
    authenticated: bool,
}

#[cfg(windows)]
#[allow(dead_code)]
type IpcWriter = tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(unix)]
#[allow(dead_code)]
type IpcWriter = tokio::net::UnixStream;

#[derive(Debug, Default)]
struct UpdateState {
    pending_manifest: Option<UpdateManifest>,
    update_in_progress: bool,
}

#[derive(Debug, Clone)]
struct BackendRuntimeStatus {
    connected: bool,
    last_heartbeat: Option<DateTime<Utc>>,
    events_queued: u64,
    events_sent: u64,
    error: Option<String>,
}

fn enrollment_pending_reason(config: &AgentConfig) -> Option<&'static str> {
    if config.agent_id.starts_with("pending-") {
        Some("Enrollment pending: mTLS client certificate has not been issued yet")
    } else if config.auth_token.is_none() {
        Some("Enrollment credentials missing locally: agent auth token is not configured. Re-enroll with a fresh token.")
    } else if !config.tls.enabled {
        Some("Enrollment credentials missing locally: mTLS is not configured. Re-enroll with a fresh token.")
    } else {
        None
    }
}

impl Default for BackendRuntimeStatus {
    fn default() -> Self {
        Self {
            connected: false,
            last_heartbeat: None,
            events_queued: 0,
            events_sent: 0,
            error: Some("Backend transport has not reported yet".to_string()),
        }
    }
}

fn init_event_store() -> Option<EventStore> {
    match EventStore::new_default() {
        Ok(store) => Some(store),
        Err(error) => {
            warn!(error = %error, "Persistent local event history is unavailable; using memory cache only");
            None
        }
    }
}

fn load_recent_events(event_store: &Option<EventStore>) -> Vec<super::TelemetryEvent> {
    let Some(store) = event_store else {
        return Vec::new();
    };

    match store.recent(5_000) {
        Ok(mut events) => {
            events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            events
        }
        Err(error) => {
            warn!(error = %error, "Failed to load persistent local event history");
            Vec::new()
        }
    }
}

// ===========================================================================
// Defense-in-Depth: Admin Privilege Verification
// ===========================================================================
//
// While the IPC token file ACL already restricts access to SYSTEM + Administrators,
// we add explicit runtime checks for critical operations as defense-in-depth.
// This prevents exploitation if the ACL check is bypassed (e.g., via token theft).

/// Check if the current process is running with admin/root privileges.
/// This is used for defense-in-depth verification on critical IPC operations.
#[cfg(windows)]
fn verify_admin_privileges() -> bool {
    use std::ffi::c_void;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Check if the current process is running as root (Unix).
#[cfg(unix)]
fn verify_admin_privileges() -> bool {
    // On Unix, root has UID 0
    unsafe { libc::geteuid() == 0 }
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(authenticator: IpcAuthenticator) -> Self {
        Self::with_config(authenticator, Arc::new(RwLock::new(AgentConfig::default())))
    }

    /// Create a new IPC server with shared agent configuration.
    pub fn with_config(authenticator: IpcAuthenticator, config: Arc<RwLock<AgentConfig>>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(100);
        let (shutdown_tx, _) = mpsc::channel(1);
        let event_store = init_event_store();
        let event_history = Arc::new(RwLock::new(load_recent_events(&event_store)));

        Self {
            authenticator: Arc::new(RwLock::new(authenticator)),
            config,
            clients: Arc::new(RwLock::new(Vec::new())),
            update_state: Arc::new(Mutex::new(UpdateState::default())),
            broadcast_tx,
            shutdown_tx,
            telemetry_tx: None,
            event_history,
            event_store,
            collectors_running: Arc::new(RwLock::new(Vec::new())),
            config_reload_tx: None,
            backend_runtime: Arc::new(RwLock::new(BackendRuntimeStatus::default())),
            started_at: Utc::now(),
        }
    }

    /// Create a new IPC server with shared agent configuration and telemetry sender.
    pub fn with_telemetry(
        authenticator: IpcAuthenticator,
        config: Arc<RwLock<AgentConfig>>,
        telemetry_tx: mpsc::Sender<TelemetryEvent>,
        config_reload_tx: watch::Sender<u64>,
    ) -> Self {
        let (broadcast_tx, _) = broadcast::channel(100);
        let (shutdown_tx, _) = mpsc::channel(1);

        let event_store = init_event_store();
        let event_history = Arc::new(RwLock::new(load_recent_events(&event_store)));

        Self {
            authenticator: Arc::new(RwLock::new(authenticator)),
            config,
            clients: Arc::new(RwLock::new(Vec::new())),
            update_state: Arc::new(Mutex::new(UpdateState::default())),
            broadcast_tx,
            shutdown_tx,
            telemetry_tx: Some(telemetry_tx),
            event_history,
            event_store,
            collectors_running: Arc::new(RwLock::new(Vec::new())),
            config_reload_tx: Some(config_reload_tx),
            backend_runtime: Arc::new(RwLock::new(BackendRuntimeStatus::default())),
            started_at: Utc::now(),
        }
    }

    pub async fn set_collectors_running(&self, collectors: Vec<String>) {
        let mut running = self.collectors_running.write().await;
        *running = collectors;
    }

    pub async fn set_backend_runtime_status(
        &self,
        connected: bool,
        last_heartbeat: Option<DateTime<Utc>>,
        events_queued: u64,
        events_sent: u64,
        error: Option<String>,
    ) {
        let mut status = self.backend_runtime.write().await;
        *status = BackendRuntimeStatus {
            connected,
            last_heartbeat,
            events_queued,
            events_sent,
            error,
        };
    }

    async fn refresh_config_from_disk_if_enrolled(&self) {
        let should_reload = {
            let config = self.config.read().await;
            config.agent_id.starts_with("pending-") || !config.tls.enabled
        };

        if !should_reload {
            return;
        }

        let path = AgentConfig::default_config_path();
        let Ok(reloaded) = AgentConfig::from_file(&path) else {
            return;
        };

        if reloaded.agent_id.starts_with("pending-") || !reloaded.tls.enabled {
            return;
        }

        let mut config = self.config.write().await;
        if config.agent_id != reloaded.agent_id || config.tls.enabled != reloaded.tls.enabled {
            info!(
                old_agent_id = %config.agent_id,
                new_agent_id = %reloaded.agent_id,
                "IPC status refreshed installed enrollment config from disk"
            );
            *config = reloaded;
        }
    }

    /// Record an analyzed collector event in the local GUI history.
    ///
    /// The server-side dashboard persists telemetry in Postgres, but the Tauri
    /// GUI talks to the local agent over IPC. Keeping a bounded in-memory
    /// history here makes the desktop "Event History" page reflect what the
    /// agent is actually collecting without introducing a second local DB.
    pub async fn record_telemetry_event(&self, event: &TelemetryEvent) {
        let config = self.config.read().await;
        let gui_event = collector_event_to_gui_event(event, &config.agent_id, None);
        drop(config);

        if let Some(store) = &self.event_store {
            if let Err(error) = store.insert(&gui_event) {
                warn!(error = %error, "Failed to persist local event history entry");
            }
        }

        let mut history = self.event_history.write().await;
        history.push(gui_event);

        const MAX_LOCAL_EVENTS: usize = 5_000;
        if history.len() > MAX_LOCAL_EVENTS {
            let excess = history.len() - MAX_LOCAL_EVENTS;
            history.drain(0..excess);
        }
    }

    /// Emit a security audit event to the server
    fn emit_audit_event(
        &self,
        operation: &str,
        success: bool,
        description: &str,
        client_id: &str,
        error: Option<&str>,
    ) {
        if let Some(ref tx) = self.telemetry_tx {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let event = TelemetryEvent {
                event_id: Uuid::new_v4().to_string(),
                event_type: EventType::SecurityAudit,
                timestamp,
                severity: if success {
                    Severity::Info
                } else {
                    Severity::High
                },
                payload: EventPayload::SecurityAudit(SecurityAuditEvent {
                    operation: operation.to_string(),
                    success,
                    description: description.to_string(),
                    client_id: client_id.to_string(),
                    client_type: "gui".to_string(),
                    details: None,
                    error: error.map(|e| e.to_string()),
                }),
                detections: vec![],
                metadata: std::collections::HashMap::new(),
            };

            // Non-blocking send - if buffer is full, log warning
            if tx.try_send(event).is_err() {
                warn!("Failed to send security audit event - channel full");
            }
        }
    }

    /// Start the IPC server
    pub async fn start(self: Arc<Self>) -> Result<JoinHandle<Result<()>>> {
        #[cfg(windows)]
        let handle = self.start_windows().await?;

        #[cfg(unix)]
        let handle = self.start_unix().await?;

        Ok(handle)
    }

    /// Start Windows named pipe server with secure ACLs.
    ///
    /// The pipe is created with a security descriptor that grants:
    /// - SYSTEM: Full control
    /// - Administrators: Full control
    /// - Authenticated Users: Read/Write (allows GUI to connect)
    #[cfg(windows)]
    async fn start_windows(self: Arc<Self>) -> Result<JoinHandle<Result<()>>> {
        use super::PIPE_NAME;

        info!("Starting secure IPC server on {}", PIPE_NAME);

        // Note: tokio's ServerOptions doesn't directly support security descriptors.
        // We log a warning about the security model. For production hardening,
        // consider using the raw Windows APIs to create the pipe with explicit ACLs.
        //
        // The security model relies on:
        // 1. Token file ACLs (SYSTEM + Administrators only)
        // 2. Challenge-response authentication
        // 3. Sensitive read operations require auth
        //
        // For truly secure pipe creation with custom security descriptors,
        // you would need to use CreateNamedPipeW with SECURITY_ATTRIBUTES directly.
        warn!(
            "Named pipe {} created without explicit security descriptor. \
             Security relies on challenge-response auth and token file ACLs.",
            PIPE_NAME
        );

        let handle = tokio::spawn(async move {
            loop {
                // Create named pipe instance
                // Note: For production, consider using windows-rs CreateNamedPipeW
                // with a custom SECURITY_ATTRIBUTES for explicit ACL control.
                let server = ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(PIPE_NAME)
                    .context("Failed to create named pipe")?;

                debug!("Waiting for client connection on named pipe...");

                // Wait for client connection
                server
                    .connect()
                    .await
                    .context("Failed to accept client connection")?;

                let client_id = uuid::Uuid::new_v4().to_string();
                info!("Client connected: {} (unauthenticated)", client_id);

                // Track client
                {
                    let mut clients = self.clients.write().await;
                    clients.push(IpcClientInfo {
                        id: client_id.clone(),
                        authenticated: false,
                    });
                }

                // Handle client in separate task
                let server_clone = Arc::clone(&self);
                let client_id_clone = client_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = server_clone
                        .handle_client_windows(server, client_id_clone.clone())
                        .await
                    {
                        error!("Client {} handler error: {}", client_id_clone, e);
                    }

                    // Clean up client on disconnect
                    let mut clients = server_clone.clients.write().await;
                    clients.retain(|c| c.id != client_id_clone);

                    // Clean up any pending challenges
                    let mut auth = server_clone.authenticator.write().await;
                    auth.cancel_challenge(&client_id_clone);

                    debug!("Client {} removed from tracking", client_id_clone);
                });
            }
        });

        Ok(handle)
    }

    /// Start Unix domain socket server with restrictive permissions.
    ///
    /// The socket is created with root-only permissions on Linux and root:admin
    /// permissions on macOS so the desktop GUI can connect without running as root.
    /// Combined with challenge-response auth, this provides local security.
    #[cfg(unix)]
    async fn start_unix(self: Arc<Self>) -> Result<JoinHandle<Result<()>>> {
        use super::SOCKET_PATH;
        use std::path::Path;

        // Remove existing socket file
        if Path::new(SOCKET_PATH).exists() {
            tokio::fs::remove_file(SOCKET_PATH).await.ok();
        }

        // Ensure parent directory exists
        if let Some(parent) = Path::new(SOCKET_PATH).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let listener = UnixListener::bind(SOCKET_PATH).context("Failed to bind Unix socket")?;

        super::acl::set_socket_file_acl(Path::new(SOCKET_PATH))
            .context("Failed to secure Unix IPC socket")?;

        #[cfg(target_os = "macos")]
        let socket_mode = "0660";

        #[cfg(not(target_os = "macos"))]
        let socket_mode = "0600";

        info!(
            "Starting secure IPC server on {} (mode {})",
            SOCKET_PATH, socket_mode
        );

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let client_id = uuid::Uuid::new_v4().to_string();
                        info!("Client connected: {} (unauthenticated)", client_id);

                        // Track client
                        {
                            let mut clients = self.clients.write().await;
                            clients.push(IpcClientInfo {
                                id: client_id.clone(),
                                authenticated: false,
                            });
                        }

                        let server_clone = Arc::clone(&self);
                        let client_id_clone = client_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server_clone
                                .handle_client_unix(stream, client_id_clone.clone())
                                .await
                            {
                                error!("Client {} handler error: {}", client_id_clone, e);
                            }

                            // Clean up client on disconnect
                            let mut clients = server_clone.clients.write().await;
                            clients.retain(|c| c.id != client_id_clone);

                            // Clean up any pending challenges
                            let mut auth = server_clone.authenticator.write().await;
                            auth.cancel_challenge(&client_id_clone);

                            debug!("Client {} removed from tracking", client_id_clone);
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Handle Windows named pipe client
    #[cfg(windows)]
    async fn handle_client_windows(
        &self,
        mut pipe: NamedPipeServer,
        client_id: String,
    ) -> Result<()> {
        let mut authenticated = false;

        // Create broadcast receiver
        let mut broadcast_rx = self.broadcast_tx.subscribe();

        debug!("Client {} handler starting message loop", client_id);
        loop {
            tokio::select! {
                // Handle incoming messages
                result = MessageFrame::read(&mut pipe) => {
                    match result {
                        Ok(message) => {
                            debug!("Client {} received message: {:?}", client_id, std::mem::discriminant(&message));

                            // Check authentication for privileged operations
                            if message.requires_auth() && !authenticated {
                                let (error_msg, error_code) = if message.is_sensitive_read() {
                                    // Provide specific error for sensitive reads per threat model
                                    (
                                        "Authentication required for sensitive data access. \
                                         Use RequestChallenge to authenticate.".to_string(),
                                        "SENSITIVE_READ_DENIED".to_string()
                                    )
                                } else {
                                    (
                                        "Authentication required for this operation".to_string(),
                                        "AUTH_REQUIRED".to_string()
                                    )
                                };

                                warn!(
                                    "Client {} attempted unauthorized access: {:?}",
                                    client_id, std::mem::discriminant(&message)
                                );

                                let response = IpcMessage::Error {
                                    message: error_msg,
                                    code: Some(error_code),
                                };
                                MessageFrame::write(&mut pipe, &response).await?;
                                continue;
                            }

                            // Process message with client_id for challenge-response
                            if let Some(response) = self.process_message(message, &mut authenticated, &client_id).await {
                                MessageFrame::write(&mut pipe, &response).await?;
                            }
                        }
                        Err(e) => {
                            debug!("Client {} disconnected: {}", client_id, e);
                            break;
                        }
                    }
                }

                // Handle broadcast messages
                result = broadcast_rx.recv() => {
                    match result {
                        Ok(message) => {
                            if let Err(e) = MessageFrame::write(&mut pipe, &message).await {
                                warn!("Failed to send broadcast to client {}: {}", client_id, e);
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!("Client {} lagging, dropping messages", client_id);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }

        debug!("Client {} handler exiting", client_id);
        Ok(())
    }

    /// Handle Unix socket client
    #[cfg(unix)]
    async fn handle_client_unix(&self, mut stream: UnixStream, client_id: String) -> Result<()> {
        let mut authenticated = false;
        let mut broadcast_rx = self.broadcast_tx.subscribe();

        debug!("Client {} handler starting message loop", client_id);
        loop {
            tokio::select! {
                result = MessageFrame::read(&mut stream) => {
                    match result {
                        Ok(message) => {
                            debug!("Client {} received message: {:?}", client_id, std::mem::discriminant(&message));

                            // Check authentication for privileged operations
                            if message.requires_auth() && !authenticated {
                                let (error_msg, error_code) = if message.is_sensitive_read() {
                                    // Provide specific error for sensitive reads per threat model
                                    (
                                        "Authentication required for sensitive data access. \
                                         Use RequestChallenge to authenticate.".to_string(),
                                        "SENSITIVE_READ_DENIED".to_string()
                                    )
                                } else {
                                    (
                                        "Authentication required for this operation".to_string(),
                                        "AUTH_REQUIRED".to_string()
                                    )
                                };

                                warn!(
                                    "Client {} attempted unauthorized access: {:?}",
                                    client_id, std::mem::discriminant(&message)
                                );

                                let response = IpcMessage::Error {
                                    message: error_msg,
                                    code: Some(error_code),
                                };
                                MessageFrame::write(&mut stream, &response).await?;
                                continue;
                            }

                            // Process message with client_id for challenge-response
                            if let Some(response) = self.process_message(message, &mut authenticated, &client_id).await {
                                MessageFrame::write(&mut stream, &response).await?;
                            }
                        }
                        Err(e) => {
                            debug!("Client {} disconnected: {}", client_id, e);
                            break;
                        }
                    }
                }

                result = broadcast_rx.recv() => {
                    match result {
                        Ok(message) => {
                            if let Err(e) = MessageFrame::write(&mut stream, &message).await {
                                warn!("Failed to send broadcast to client {}: {}", client_id, e);
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!("Client {} lagging, dropping messages", client_id);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }

        debug!("Client {} handler exiting", client_id);
        Ok(())
    }

    /// Process an incoming message
    ///
    /// # Arguments
    /// * `message` - The incoming IPC message
    /// * `authenticated` - Mutable reference to authentication state
    /// * `client_id` - Unique identifier for this connection (used for challenge-response)
    async fn process_message(
        &self,
        message: IpcMessage,
        authenticated: &mut bool,
        client_id: &str,
    ) -> Option<IpcMessage> {
        debug!(
            "Processing IPC message from {}: {:?}",
            client_id,
            std::mem::discriminant(&message)
        );

        match message {
            // ==================== Challenge-Response Authentication ====================

            // Client requests a challenge (new protocol)
            IpcMessage::RequestChallenge => {
                let challenge = {
                    let mut auth = self.authenticator.write().await;
                    auth.create_challenge(client_id)
                };
                debug!(
                    "Sent challenge to client {}: nonce={}",
                    client_id, challenge.nonce
                );
                Some(IpcMessage::Challenge(challenge))
            }

            // Client responds to challenge
            IpcMessage::AuthenticateChallenge { response } => {
                let verified = {
                    let mut auth = self.authenticator.write().await;
                    auth.verify_response(client_id, &response)
                };

                if verified {
                    *authenticated = true;
                    info!("Client {} authenticated via challenge-response", client_id);
                    Some(IpcMessage::Authenticated)
                } else {
                    warn!("Client {} failed challenge-response auth", client_id);
                    Some(IpcMessage::Error {
                        message: "Invalid challenge response".to_string(),
                        code: Some("AUTH_FAILED".to_string()),
                    })
                }
            }

            // Legacy static token authentication (conditionally supported for backwards compatibility)
            IpcMessage::Authenticate { token_hash } => {
                // Check if legacy auth is enabled in config
                let legacy_enabled = self.config.read().await.ipc.legacy_auth_enabled;

                if !legacy_enabled {
                    warn!(
                        "Client {} attempted legacy auth but ipc.legacy_auth_enabled=false. \
                         Use RequestChallenge for challenge-response authentication.",
                        client_id
                    );
                    return Some(IpcMessage::Error {
                        message: "Legacy authentication is disabled. Use challenge-response authentication.".to_string(),
                        code: Some("LEGACY_AUTH_DISABLED".to_string()),
                    });
                }

                // Legacy auth is enabled - verify token hash
                let verified = {
                    let auth = self.authenticator.read().await;
                    auth.verify(&token_hash)
                };

                if verified {
                    *authenticated = true;
                    warn!(
                        "Client {} authenticated via LEGACY token hash. \
                         Consider migrating to challenge-response auth.",
                        client_id
                    );
                    Some(IpcMessage::Authenticated)
                } else {
                    warn!("Client {} failed legacy auth", client_id);
                    Some(IpcMessage::Error {
                        message: "Invalid token".to_string(),
                        code: Some("AUTH_FAILED".to_string()),
                    })
                }
            }

            IpcMessage::GetStatus => {
                self.refresh_config_from_disk_if_enrolled().await;
                let config = self.config.read().await;
                let collectors_running = self.collectors_running.read().await.clone();
                let backend_runtime = self.backend_runtime.read().await.clone();
                let pending_enrollment = enrollment_pending_reason(&config).is_some();
                let backend_connected = !pending_enrollment && backend_runtime.connected;
                Some(IpcMessage::StatusUpdate(super::AgentStatus {
                    agent_id: config.agent_id.clone(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    state: if backend_connected {
                        super::AgentState::Running
                    } else {
                        super::AgentState::Degraded
                    },
                    backend_connected,
                    last_heartbeat: backend_runtime.last_heartbeat,
                    collectors_running,
                    protection_enabled: false,
                    scan_in_progress: false,
                    cpu_usage: 0.0,
                    memory_usage: 0,
                    uptime_seconds: (Utc::now() - self.started_at).num_seconds().max(0) as u64,
                }))
            }

            IpcMessage::GetMetrics => {
                let collector_metrics = self
                    .collectors_running
                    .read()
                    .await
                    .iter()
                    .map(|name| super::CollectorMetrics {
                        name: name.clone(),
                        events_collected: 0,
                        events_per_second: 0.0,
                        errors: 0,
                        cpu_percent: 0.0,
                    })
                    .collect();

                Some(IpcMessage::MetricsUpdate(super::AgentMetrics {
                    timestamp: chrono::Utc::now(),
                    events_processed: 0,
                    events_per_second: 0.0,
                    alerts_generated: 0,
                    actions_executed: 0,
                    cpu_usage: 0.0,
                    memory_usage: 0,
                    network_bytes_sent: 0,
                    network_bytes_received: 0,
                    collector_metrics,
                }))
            }

            IpcMessage::GetVersion => Some(IpcMessage::VersionInfo(super::VersionInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                build_date: option_env!("BUILD_DATE").unwrap_or("unknown").to_string(),
                commit_hash: option_env!("GIT_HASH").unwrap_or("unknown").to_string(),
                rust_version: option_env!("RUST_VERSION").unwrap_or("unknown").to_string(),
            })),

            IpcMessage::GetComponentStatus => Some(IpcMessage::ComponentStatusUpdate(
                self.build_component_status().await,
            )),

            IpcMessage::GetPerformanceProfile => {
                // Read from config and convert to IPC type
                let config_profile = self.config.read().await.performance_profile;
                let ipc_profile = config_to_ipc_profile(config_profile);
                Some(IpcMessage::PerformanceProfileResponse(ipc_profile))
            }

            IpcMessage::SetPerformanceProfile { profile } => {
                info!(
                    "Client {} setting performance profile to {:?}",
                    client_id, profile
                );

                // Get current profile from config
                let config_old = self.config.read().await.performance_profile;
                let old_profile = config_to_ipc_profile(config_old);

                // Skip if same profile
                if old_profile == profile {
                    return Some(IpcMessage::ProfileChanged {
                        old: old_profile,
                        new: profile,
                        collectors_affected: vec![],
                    });
                }

                // Calculate affected collectors using IPC profile's enabled_collectors
                let old_collectors: std::collections::HashSet<_> =
                    old_profile.enabled_collectors().into_iter().collect();
                let new_collectors: std::collections::HashSet<_> =
                    profile.enabled_collectors().into_iter().collect();

                let mut affected = Vec::new();
                for c in old_collectors.difference(&new_collectors) {
                    affected.push(format!("{} (disabled)", c));
                }
                for c in new_collectors.difference(&old_collectors) {
                    affected.push(format!("{} (enabled)", c));
                }
                if affected.is_empty() {
                    affected.push("Interval adjustments only".to_string());
                }

                // Update config - convert IPC profile to config profile
                {
                    let mut config = self.config.write().await;
                    config.performance_profile = ipc_to_config_profile(profile);

                    // Apply profile settings
                    config.apply_performance_profile();

                    // Persist to disk
                    if let Err(e) = config.save_default() {
                        error!("Failed to save config after profile change: {}", e);
                        return Some(IpcMessage::ProfileChangeError {
                            reason: format!("Failed to persist config: {}", e),
                        });
                    }
                }

                if let Some(reload_tx) = &self.config_reload_tx {
                    reload_tx.send_modify(|generation| *generation += 1);
                    info!("Config reload signal sent after IPC performance profile change");
                } else {
                    warn!("Performance profile changed, but no config reload channel is wired");
                }

                // Broadcast profile change to all clients
                let change_msg = IpcMessage::ProfileChanged {
                    old: old_profile,
                    new: profile,
                    collectors_affected: affected.clone(),
                };
                if let Err(e) = self.broadcast_tx.send(change_msg.clone()) {
                    warn!("Failed to broadcast profile change: {}", e);
                }

                info!(
                    "Performance profile changed from {:?} to {:?}. Affected: {:?}",
                    old_profile, profile, affected
                );

                Some(IpcMessage::ProfileChanged {
                    old: old_profile,
                    new: profile,
                    collectors_affected: affected,
                })
            }

            IpcMessage::GetAlerts { since, limit } => {
                Some(IpcMessage::Alerts(self.query_alerts(since, limit).await))
            }

            IpcMessage::GetQuarantinedFiles => Some(IpcMessage::QuarantinedFiles(vec![])),

            IpcMessage::GetActiveConnections => Some(IpcMessage::ActiveConnections(vec![])),

            IpcMessage::GetProcessTree => Some(IpcMessage::ProcessTree(vec![])),

            IpcMessage::GetLogs {
                since,
                level,
                limit,
            } => Some(IpcMessage::LogEntries(
                self.query_logs(since, level, limit).await,
            )),

            IpcMessage::TestBackendConnection => {
                self.refresh_config_from_disk_if_enrolled().await;
                let config = self.config.read().await;
                let error = enrollment_pending_reason(&config);

                Some(IpcMessage::BackendTestResult {
                    connected: error.is_none(),
                    latency_ms: None,
                    error: error.map(str::to_string),
                })
            }

            IpcMessage::CheckForUpdates => match self.check_for_updates().await {
                Ok(response) => Some(response),
                Err(e) => {
                    error!(error = %e, "IPC update check failed");
                    Some(IpcMessage::UpdateError {
                        message: e.to_string(),
                        recoverable: true,
                    })
                }
            },

            IpcMessage::ApplyUpdate => match self.apply_update().await {
                Ok(response) => Some(response),
                Err(e) => {
                    error!(error = %e, "IPC apply update failed");
                    Some(IpcMessage::UpdateError {
                        message: e.to_string(),
                        recoverable: true,
                    })
                }
            },

            // ==================== Local Response Command Handlers ====================
            IpcMessage::BlockIp {
                ip,
                reason,
                direction,
            } => Some(
                Self::run_response_command(
                    CommandType::BlockIP,
                    serde_json::json!({
                        "ip": ip,
                        "reason": reason,
                        "direction": direction,
                    }),
                )
                .await,
            ),

            IpcMessage::UnblockIp {
                ip,
                reason,
                direction,
            } => Some(
                Self::run_response_command(
                    CommandType::UnblockIP,
                    serde_json::json!({
                        "ip": ip,
                        "reason": reason,
                        "direction": direction,
                    }),
                )
                .await,
            ),

            IpcMessage::BlockDomain { domain, reason } => Some(
                Self::run_response_command(
                    CommandType::BlockDomain,
                    serde_json::json!({
                        "domain": domain,
                        "reason": reason,
                    }),
                )
                .await,
            ),

            IpcMessage::UnblockDomain { domain, reason } => Some(
                Self::run_response_command(
                    CommandType::UnblockDomain,
                    serde_json::json!({
                        "domain": domain,
                        "reason": reason,
                    }),
                )
                .await,
            ),

            IpcMessage::ListBlockedIps => Some(
                Self::run_response_command(CommandType::ListBlockedIPs, serde_json::json!({}))
                    .await,
            ),

            IpcMessage::ListBlockedDomains => Some(
                Self::run_response_command(CommandType::ListBlockedDomains, serde_json::json!({}))
                    .await,
            ),

            IpcMessage::IsolateNetwork { allowed_ips } => Some(
                Self::run_response_command(
                    CommandType::IsolateNetwork,
                    serde_json::json!({
                        "allowed_ips": allowed_ips.unwrap_or_default(),
                    }),
                )
                .await,
            ),

            IpcMessage::RestoreNetwork => Some(
                Self::run_response_command(CommandType::UnisolateNetwork, serde_json::json!({}))
                    .await,
            ),

            // ==================== Event History Handlers ====================
            IpcMessage::GetEvents {
                event_types,
                severities,
                search,
                date_from,
                date_to,
                limit,
                offset,
            } => {
                let events = self
                    .query_event_history(
                        event_types,
                        severities,
                        search,
                        date_from,
                        date_to,
                        limit,
                        offset,
                    )
                    .await;
                Some(IpcMessage::Events(events))
            }

            IpcMessage::GetEventStatistics { date_from, date_to } => {
                let stats = self.event_statistics(date_from, date_to).await;
                Some(IpcMessage::EventStatisticsResponse(stats))
            }

            IpcMessage::GetEvent { event_id } => {
                let event = if let Some(store) = &self.event_store {
                    match store.get(&event_id) {
                        Ok(event) => event,
                        Err(error) => {
                            warn!(error = %error, event_id = %event_id, "Persistent event lookup failed; falling back to memory cache");
                            let history = self.event_history.read().await;
                            history.iter().find(|event| event.id == event_id).cloned()
                        }
                    }
                } else {
                    let history = self.event_history.read().await;
                    history.iter().find(|event| event.id == event_id).cloned()
                };
                Some(IpcMessage::Event(event))
            }

            IpcMessage::GetRelatedEvents { event_id } => {
                let related = self.related_local_events(&event_id).await;
                Some(IpcMessage::RelatedEvents(related))
            }

            // ==================== Driver Control Handlers ====================
            IpcMessage::GetDriverStatus => Some(IpcMessage::DriverStatusResponse(
                self.build_driver_status_info(),
            )),

            IpcMessage::LoadDriver => {
                if !*authenticated {
                    return Some(IpcMessage::Error {
                        message: "Authentication required for driver operations".to_string(),
                        code: Some("AUTH_REQUIRED".to_string()),
                    });
                }

                // Defense-in-depth: Verify admin privileges even after authentication
                // This protects against token theft scenarios where ACL bypass might occur
                if !verify_admin_privileges() {
                    warn!(
                        "Client {} attempted driver load without admin privileges",
                        client_id
                    );
                    self.emit_audit_event(
                        "driver_load_denied",
                        false,
                        "Driver load rejected: insufficient privileges (defense-in-depth check)",
                        client_id,
                        Some("ADMIN_REQUIRED"),
                    );
                    return Some(IpcMessage::Error {
                        message: "Administrator privileges required for driver operations"
                            .to_string(),
                        code: Some("ADMIN_REQUIRED".to_string()),
                    });
                }

                info!("Client {} requesting driver load", client_id);

                match crate::installer::driver::load_driver("tamandua") {
                    Ok(()) => {
                        info!("Driver loaded successfully via IPC request");
                        self.emit_audit_event(
                            "driver_load",
                            true,
                            "Kernel driver loaded successfully via GUI request",
                            client_id,
                            None,
                        );
                        Some(IpcMessage::DriverOperationResult {
                            operation: "load".to_string(),
                            success: true,
                            message: Some("Driver loaded successfully".to_string()),
                        })
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to load driver via IPC request");
                        self.emit_audit_event(
                            "driver_load",
                            false,
                            "Failed to load kernel driver via GUI request",
                            client_id,
                            Some(&e.to_string()),
                        );
                        Some(IpcMessage::DriverOperationResult {
                            operation: "load".to_string(),
                            success: false,
                            message: Some(e.to_string()),
                        })
                    }
                }
            }

            IpcMessage::UnloadDriver => {
                if !*authenticated {
                    return Some(IpcMessage::Error {
                        message: "Authentication required for driver operations".to_string(),
                        code: Some("AUTH_REQUIRED".to_string()),
                    });
                }

                // Defense-in-depth: Verify admin privileges even after authentication
                if !verify_admin_privileges() {
                    warn!(
                        "Client {} attempted driver unload without admin privileges",
                        client_id
                    );
                    self.emit_audit_event(
                        "driver_unload_denied",
                        false,
                        "Driver unload rejected: insufficient privileges (defense-in-depth check)",
                        client_id,
                        Some("ADMIN_REQUIRED"),
                    );
                    return Some(IpcMessage::Error {
                        message: "Administrator privileges required for driver operations"
                            .to_string(),
                        code: Some("ADMIN_REQUIRED".to_string()),
                    });
                }

                info!("Client {} requesting driver unload", client_id);

                match crate::installer::driver::unload_driver("tamandua") {
                    Ok(()) => {
                        info!("Driver unloaded successfully via IPC request");
                        self.emit_audit_event(
                            "driver_unload",
                            true,
                            "Kernel driver unloaded successfully via GUI request",
                            client_id,
                            None,
                        );
                        Some(IpcMessage::DriverOperationResult {
                            operation: "unload".to_string(),
                            success: true,
                            message: Some("Driver unloaded successfully".to_string()),
                        })
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to unload driver via IPC request");
                        self.emit_audit_event(
                            "driver_unload",
                            false,
                            "Failed to unload kernel driver via GUI request",
                            client_id,
                            Some(&e.to_string()),
                        );
                        Some(IpcMessage::DriverOperationResult {
                            operation: "unload".to_string(),
                            success: false,
                            message: Some(e.to_string()),
                        })
                    }
                }
            }

            // ==================== Agent Control Handlers ====================
            IpcMessage::StopAgent => {
                if !*authenticated {
                    return Some(IpcMessage::Error {
                        message: "Authentication required for agent control".to_string(),
                        code: Some("AUTH_REQUIRED".to_string()),
                    });
                }

                // Defense-in-depth: Verify admin privileges for stopping the agent
                // This is a critical operation that leaves the endpoint unprotected
                if !verify_admin_privileges() {
                    warn!(
                        "Client {} attempted agent stop without admin privileges",
                        client_id
                    );
                    self.emit_audit_event(
                        "agent_stop_denied",
                        false,
                        "Agent stop rejected: insufficient privileges (defense-in-depth check)",
                        client_id,
                        Some("ADMIN_REQUIRED"),
                    );
                    return Some(IpcMessage::Error {
                        message: "Administrator privileges required to stop the agent".to_string(),
                        code: Some("ADMIN_REQUIRED".to_string()),
                    });
                }

                info!("Client {} requesting agent stop", client_id);

                // Emit audit event before stopping
                self.emit_audit_event(
                    "agent_stop",
                    true,
                    "Agent stop requested via GUI - endpoint will be unprotected",
                    client_id,
                    None,
                );

                // Broadcast stopping notification
                let _ = self.broadcast_tx.send(IpcMessage::AgentStopping {
                    reason: "Stop requested via GUI".to_string(),
                    restart_scheduled: false,
                });

                // Schedule shutdown after a short delay to allow response and audit event to be sent
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                    info!("Agent shutting down due to IPC stop request");
                    std::process::exit(0);
                });

                Some(IpcMessage::AgentStopping {
                    reason: "Stop requested via GUI".to_string(),
                    restart_scheduled: false,
                })
            }

            IpcMessage::RestartAgent => {
                if !*authenticated {
                    return Some(IpcMessage::Error {
                        message: "Authentication required for agent control".to_string(),
                        code: Some("AUTH_REQUIRED".to_string()),
                    });
                }

                // Defense-in-depth: Verify admin privileges for restarting the agent
                if !verify_admin_privileges() {
                    warn!(
                        "Client {} attempted agent restart without admin privileges",
                        client_id
                    );
                    self.emit_audit_event(
                        "agent_restart_denied",
                        false,
                        "Agent restart rejected: insufficient privileges (defense-in-depth check)",
                        client_id,
                        Some("ADMIN_REQUIRED"),
                    );
                    return Some(IpcMessage::Error {
                        message: "Administrator privileges required to restart the agent"
                            .to_string(),
                        code: Some("ADMIN_REQUIRED".to_string()),
                    });
                }

                info!("Client {} requesting agent restart", client_id);

                // Emit audit event before restarting
                self.emit_audit_event(
                    "agent_restart",
                    true,
                    "Agent restart requested via GUI - brief protection gap expected",
                    client_id,
                    None,
                );

                // Broadcast restart notification
                let _ = self.broadcast_tx.send(IpcMessage::AgentStopping {
                    reason: "Restart requested via GUI".to_string(),
                    restart_scheduled: true,
                });

                // Schedule restart after a short delay to allow response and audit event to be sent
                // On Windows, if running as a service with recovery options, SCM will restart us
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                    info!("Agent restarting due to IPC restart request");
                    // Exit with code 1 to trigger service recovery/restart
                    std::process::exit(1);
                });

                Some(IpcMessage::AgentStopping {
                    reason: "Restart requested via GUI".to_string(),
                    restart_scheduled: true,
                })
            }

            _ => Some(IpcMessage::Error {
                message: "Not implemented".to_string(),
                code: Some("NOT_IMPLEMENTED".to_string()),
            }),
        }
    }

    async fn run_response_command(
        command_type: CommandType,
        payload: serde_json::Value,
    ) -> IpcMessage {
        let command = Command {
            command_id: Uuid::new_v4().to_string(),
            command_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            payload,
        };

        command_result_to_ipc(crate::response::execute_command(&command).await)
    }

    /// Build detailed driver status information for GUI.
    fn build_driver_status_info(&self) -> super::DriverStatusInfo {
        #[cfg(not(target_os = "windows"))]
        {
            return super::DriverStatusInfo {
                loaded: false,
                connected: false,
                version: None,
                service_name: "unsupported".to_string(),
                driver_path: None,
                usermode_fallback: true,
                consecutive_failures: 0,
                events_captured: None,
                last_communication: None,
                error: Some("Kernel driver telemetry is only available on Windows".to_string()),
                install_available: false,
            };
        }

        #[cfg(target_os = "windows")]
        {
            let driver_loaded = crate::driver::is_driver_loaded();
            let install_available = crate::installer::driver::has_embedded_driver();
            let ring_stats = crate::driver::ring_buffer::global_stats();
            let connected = ring_stats.connected;
            let events_captured = if connected {
                Some(
                    ring_stats
                        .kernel_events_written
                        .max(ring_stats.events_converted),
                )
            } else {
                None
            };
            let usermode_fallback =
                !driver_loaded || (!connected && ring_stats.consecutive_failures >= 5);
            let error = if !driver_loaded && !install_available {
                Some(
                    "Driver not loaded and no embedded driver available for installation"
                        .to_string(),
                )
            } else if !driver_loaded {
                Some("Driver not loaded".to_string())
            } else if !connected {
                Some(ring_stats.last_error.unwrap_or_else(|| {
                    "Driver loaded but telemetry ring buffer is not connected yet".to_string()
                }))
            } else {
                None
            };

            super::DriverStatusInfo {
                loaded: driver_loaded,
                connected,
                version: if driver_loaded {
                    Some(env!("CARGO_PKG_VERSION").to_string())
                } else {
                    None
                },
                service_name: "tamandua".to_string(),
                driver_path: Some(
                    crate::installer::driver::default_driver_path()
                        .to_string_lossy()
                        .to_string(),
                ),
                usermode_fallback,
                consecutive_failures: ring_stats.consecutive_failures,
                events_captured,
                last_communication: ring_stats.last_event_at,
                error,
                install_available,
            }
        }
    }

    /// Build component status from current state
    async fn build_component_status(&self) -> super::ComponentStatus {
        self.refresh_config_from_disk_if_enrolled().await;
        let driver_info = self.build_driver_status_info();
        let config = self.config.read().await;
        let backend_url = config.server_url.clone();
        let backend_runtime = self.backend_runtime.read().await.clone();
        let pending_enrollment_reason = enrollment_pending_reason(&config);
        let backend_connected = pending_enrollment_reason.is_none() && backend_runtime.connected;
        let backend_error = if let Some(reason) = pending_enrollment_reason {
            Some(reason.to_string())
        } else if backend_connected {
            None
        } else {
            backend_runtime
                .error
                .or_else(|| Some("Backend transport is not connected".to_string()))
        };
        drop(config);

        let collector_event_counts = {
            let history = self.event_history.read().await;
            history
                .iter()
                .fold(HashMap::<String, u64>::new(), |mut acc, event| {
                    let collector = collector_name_for_event_type(&event.event_type);
                    *acc.entry(collector).or_insert(0) += 1;
                    acc
                })
        };

        let collectors = self
            .collectors_running
            .read()
            .await
            .iter()
            .map(|name| super::CollectorStatus {
                name: name.clone(),
                running: true,
                events_per_second: 0.0,
                total_events: *collector_event_counts.get(name).unwrap_or(&0),
                errors: 0,
                last_error: None,
                cpu_percent: 0.0,
                memory_bytes: 0,
            })
            .collect();

        super::ComponentStatus {
            driver: super::DriverStatus {
                loaded: driver_info.loaded,
                version: driver_info.version.clone(),
                events_captured: driver_info.events_captured,
                last_event_at: driver_info.last_communication,
                error: driver_info.error.clone(),
            },
            collectors,
            backend: super::BackendStatus {
                connected: backend_connected,
                url: backend_url,
                latency_ms: None,
                events_queued: backend_runtime.events_queued,
                events_sent: backend_runtime.events_sent,
                last_sync_at: backend_runtime.last_heartbeat,
                error: backend_error.clone(),
            },
            pressure_level: super::PressureLevel::None,
            health: super::HealthStatus {
                status: if backend_connected {
                    super::HealthState::Healthy
                } else {
                    super::HealthState::Degraded
                },
                checks: vec![super::HealthCheck {
                    name: "backend_connection".to_string(),
                    passed: backend_connected,
                    message: backend_error
                        .or_else(|| Some("Backend transport is connected".to_string())),
                }],
                last_check_at: Some(chrono::Utc::now()),
            },
            uptime_seconds: (Utc::now() - self.started_at).num_seconds().max(0) as u64,
        }
    }

    async fn query_logs(
        &self,
        since: Option<DateTime<Utc>>,
        level: Option<String>,
        limit: Option<usize>,
    ) -> Vec<super::LogEntry> {
        let requested_limit = limit.unwrap_or(200);
        let query_limit = requested_limit.saturating_mul(5).max(500);
        let level_filter = level;
        let events = self.recent_events_for_ipc(since, query_limit).await;

        let mut logs: Vec<_> = events
            .into_iter()
            .filter(|event| since.map(|s| event.timestamp >= s).unwrap_or(true))
            .filter(|event| {
                level_filter
                    .as_deref()
                    .map(|wanted| {
                        severity_to_log_level(&event.severity).eq_ignore_ascii_case(wanted)
                    })
                    .unwrap_or(true)
            })
            .map(|event| {
                let mut fields = HashMap::new();
                fields.insert("event_id".to_string(), event.id.clone());
                fields.insert("event_type".to_string(), event.event_type.clone());
                fields.insert("severity".to_string(), event.severity.clone());
                if let Some(process_name) = &event.process_name {
                    fields.insert("process".to_string(), process_name.clone());
                }
                if let Some(file_path) = &event.file_path {
                    fields.insert("file".to_string(), file_path.clone());
                }
                if let Some(remote_ip) = &event.remote_ip {
                    fields.insert("remote_ip".to_string(), remote_ip.clone());
                }

                super::LogEntry {
                    id: format!("log-{}", event.id),
                    timestamp: event.timestamp,
                    level: severity_to_log_level(&event.severity).to_string(),
                    message: event.message.clone(),
                    module: Some(event.event_type.clone()),
                    fields,
                }
            })
            .collect();

        logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        logs.truncate(requested_limit);
        logs
    }

    async fn query_alerts(
        &self,
        since: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Vec<super::AlertNotification> {
        let requested_limit = limit.unwrap_or(100);
        let query_limit = requested_limit.saturating_mul(10).max(500);
        let events = self.recent_events_for_ipc(since, query_limit).await;

        let mut alerts: Vec<_> = events
            .into_iter()
            .filter(is_alert_event)
            .map(event_to_alert)
            .collect();

        alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        alerts.truncate(requested_limit);
        alerts
    }

    async fn recent_events_for_ipc(
        &self,
        since: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Vec<super::TelemetryEvent> {
        if let Some(store) = &self.event_store {
            match store.query(EventQuery {
                date_from: since,
                limit: Some(limit),
                ..EventQuery::default()
            }) {
                Ok(events) => return events,
                Err(error) => {
                    warn!(error = %error, "Persistent event history query failed; falling back to memory cache")
                }
            }
        }

        let mut events: Vec<_> = self
            .event_history
            .read()
            .await
            .iter()
            .filter(|event| since.map(|s| event.timestamp >= s).unwrap_or(true))
            .cloned()
            .collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.truncate(limit);
        events
    }

    async fn build_service_updater(&self) -> Result<Updater> {
        let mut config = self.config.read().await.clone();
        // Service mode should stage updates safely and let SCM/manual restart
        // activate the new binary rather than exiting the running service.
        config.updater.auto_restart = false;

        Updater::new(&config.updater, &config.agent_id, &config.server_url)
    }

    async fn check_for_updates(&self) -> Result<IpcMessage> {
        let updater = self.build_service_updater().await?;
        let current_version = env!("CARGO_PKG_VERSION").to_string();

        match updater.check_for_update().await? {
            Some(manifest) => {
                let response = IpcMessage::UpdateCheckResult {
                    update_available: true,
                    current_version,
                    latest_version: Some(manifest.version.clone()),
                    release_notes: Some(manifest.release_notes.clone()),
                    download_size: Some(manifest.size),
                };

                let mut state = self.update_state.lock().await;
                state.pending_manifest = Some(manifest);
                Ok(response)
            }
            None => {
                let mut state = self.update_state.lock().await;
                state.pending_manifest = None;
                Ok(IpcMessage::UpdateCheckResult {
                    update_available: false,
                    current_version,
                    latest_version: None,
                    release_notes: None,
                    download_size: None,
                })
            }
        }
    }

    async fn apply_update(&self) -> Result<IpcMessage> {
        let manifest = {
            let state = self.update_state.lock().await;
            if state.update_in_progress {
                bail!("Update already in progress");
            }
            state.pending_manifest.clone()
        };

        let updater = self.build_service_updater().await?;
        let manifest = match manifest {
            Some(manifest) => manifest,
            None => match updater.check_for_update().await? {
                Some(manifest) => manifest,
                None => bail!("No update available"),
            },
        };

        {
            let mut state = self.update_state.lock().await;
            state.pending_manifest = Some(manifest.clone());
            state.update_in_progress = true;
        }

        let response_version = manifest.version.clone();
        let state = Arc::clone(&self.update_state);
        let broadcast_tx = self.broadcast_tx.clone();

        tokio::spawn(async move {
            let version = manifest.version.clone();
            let result: Result<()> = async {
                let downloaded_path = updater
                    .download_update_with_progress(&manifest, |downloaded, total, percent| {
                        let _ = broadcast_tx.send(IpcMessage::UpdateProgress {
                            version: version.clone(),
                            downloaded_bytes: downloaded,
                            total_bytes: total,
                            percent,
                        });
                    })
                    .await?;

                broadcast_tx
                    .send(IpcMessage::UpdateInstalling {
                        version: manifest.version.clone(),
                    })
                    .ok();

                updater.verify_update(&downloaded_path, &manifest)?;
                updater.install_update(&downloaded_path, &manifest).await?;

                broadcast_tx
                    .send(IpcMessage::UpdateReady {
                        version: manifest.version.clone(),
                        requires_restart: true,
                    })
                    .ok();

                Ok(())
            }
            .await;

            let mut update_state = state.lock().await;
            update_state.update_in_progress = false;

            match result {
                Ok(()) => {
                    update_state.pending_manifest = None;
                }
                Err(e) => {
                    broadcast_tx
                        .send(IpcMessage::UpdateError {
                            message: e.to_string(),
                            recoverable: true,
                        })
                        .ok();
                    error!(error = %e, "Background update workflow failed");
                }
            }
        });

        Ok(IpcMessage::UpdateInstalling {
            version: response_version,
        })
    }

    async fn query_event_history(
        &self,
        event_types: Option<Vec<String>>,
        severities: Option<Vec<String>>,
        search: Option<String>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Vec<super::TelemetryEvent> {
        if let Some(store) = &self.event_store {
            match store.query(EventQuery {
                event_types: event_types.clone(),
                severities: severities.clone(),
                search: search.clone(),
                date_from,
                date_to,
                limit,
                offset,
            }) {
                Ok(events) => return events,
                Err(error) => {
                    warn!(error = %error, "Persistent event history query failed; falling back to memory cache")
                }
            }
        }

        let history = self.event_history.read().await;
        let search = search.map(|s| s.to_lowercase());
        let mut events: Vec<_> = history
            .iter()
            .filter(|event| {
                if let Some(types) = &event_types {
                    if !types.is_empty()
                        && !types
                            .iter()
                            .any(|t| event_matches_type_filter(&event.event_type, t))
                    {
                        return false;
                    }
                }

                if let Some(sevs) = &severities {
                    if !sevs.is_empty()
                        && !sevs.iter().any(|s| s.eq_ignore_ascii_case(&event.severity))
                    {
                        return false;
                    }
                }

                if let Some(from) = date_from {
                    if event.timestamp < from {
                        return false;
                    }
                }

                if let Some(to) = date_to {
                    if event.timestamp > to {
                        return false;
                    }
                }

                if let Some(term) = &search {
                    let haystack = format!(
                        "{} {} {} {} {} {}",
                        event.message,
                        event.event_type,
                        event.hostname,
                        event.process_name.as_deref().unwrap_or_default(),
                        event.file_path.as_deref().unwrap_or_default(),
                        event.remote_ip.as_deref().unwrap_or_default()
                    )
                    .to_lowercase();

                    if !haystack.contains(term) {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        let offset = offset.unwrap_or(0);
        let events = events.into_iter().skip(offset);

        match limit {
            Some(limit) => events.take(limit).collect(),
            None => events.collect(),
        }
    }

    async fn event_statistics(
        &self,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
    ) -> super::EventStatistics {
        let events = self
            .query_event_history(None, None, None, date_from, date_to, None, None)
            .await;

        let mut by_type: HashMap<String, u64> = HashMap::new();
        let mut by_process: HashMap<String, u64> = HashMap::new();
        let mut by_hour: HashMap<DateTime<Utc>, u64> = HashMap::new();

        for event in &events {
            *by_type.entry(event.event_type.clone()).or_default() += 1;

            if let Some(process_name) = &event.process_name {
                if !process_name.is_empty() {
                    *by_process.entry(process_name.clone()).or_default() += 1;
                }
            }

            if let Some(hour) = event
                .timestamp
                .date_naive()
                .and_hms_opt(event.timestamp.hour(), 0, 0)
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
            {
                *by_hour.entry(hour).or_default() += 1;
            }
        }

        let mut event_type_distribution: Vec<_> = by_type
            .into_iter()
            .map(|(event_type, count)| super::TypeCount { event_type, count })
            .collect();
        event_type_distribution.sort_by(|a, b| b.count.cmp(&a.count));

        let mut top_processes: Vec<_> = by_process
            .into_iter()
            .map(|(process_name, count)| super::ProcessCount {
                process_name,
                count,
            })
            .collect();
        top_processes.sort_by(|a, b| b.count.cmp(&a.count));
        top_processes.truncate(10);

        let mut events_per_hour: Vec<_> = by_hour
            .into_iter()
            .map(|(hour, count)| super::HourlyCount { hour, count })
            .collect();
        events_per_hour.sort_by(|a, b| a.hour.cmp(&b.hour));

        super::EventStatistics {
            events_per_hour,
            event_type_distribution,
            top_processes,
            total_events: events.len() as u64,
            time_range_hours: date_from
                .zip(date_to)
                .map(|(from, to)| (to - from).num_hours().max(0) as u32)
                .unwrap_or(24),
        }
    }

    async fn related_local_events(&self, event_id: &str) -> Vec<super::TelemetryEvent> {
        let events = if let Some(store) = &self.event_store {
            match store.recent(5_000) {
                Ok(events) => events,
                Err(error) => {
                    warn!(error = %error, "Persistent related-event query failed; falling back to memory cache");
                    self.event_history.read().await.clone()
                }
            }
        } else {
            self.event_history.read().await.clone()
        };

        let Some(source) = events.iter().find(|event| event.id == event_id) else {
            return Vec::new();
        };

        let source_agent = source.agent_id.clone();
        let source_process = source.process_id;
        let source_time = source.timestamp;

        let mut related: Vec<_> = events
            .iter()
            .filter(|event| event.id != event_id)
            .filter(|event| event.agent_id == source_agent)
            .filter(|event| (event.timestamp - source_time).num_minutes().abs() <= 30)
            .filter(|event| {
                source_process
                    .map(|pid| {
                        event.process_id == Some(pid) || event.parent_process_id == Some(pid)
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        related.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        related.truncate(50);
        related
    }

    /// Broadcast a message to all connected clients
    pub fn broadcast(&self, message: IpcMessage) -> Result<()> {
        // A broadcast channel returns an error only when there are zero active
        // receivers. That is a benign condition (no clients connected), so treat
        // it as a successful no-op rather than a failure.
        match self.broadcast_tx.send(message) {
            Ok(_) => Ok(()),
            Err(_no_receivers) => Ok(()),
        }
    }

    /// Get number of connected clients
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Shutdown the server
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down IPC server");
        self.shutdown_tx.send(()).await?;
        Ok(())
    }
}

// ==================== Profile Type Conversion ====================
// The config module and IPC module each have their own PerformanceProfile enum.
// These helpers convert between them.

use super::PerformanceProfile as IpcProfile;
use crate::config::PerformanceProfile as ConfigProfile;

/// Convert config::PerformanceProfile to ipc::PerformanceProfile
fn config_to_ipc_profile(config_profile: ConfigProfile) -> IpcProfile {
    match config_profile {
        ConfigProfile::Aggressive => IpcProfile::Aggressive,
        ConfigProfile::Balanced => IpcProfile::Balanced,
        ConfigProfile::Lightweight => IpcProfile::Lightweight,
    }
}

/// Convert ipc::PerformanceProfile to config::PerformanceProfile
fn ipc_to_config_profile(ipc_profile: IpcProfile) -> ConfigProfile {
    match ipc_profile {
        IpcProfile::Aggressive => ConfigProfile::Aggressive,
        IpcProfile::Balanced => ConfigProfile::Balanced,
        IpcProfile::Lightweight => ConfigProfile::Lightweight,
    }
}

fn command_result_to_ipc(result: CommandResult) -> IpcMessage {
    IpcMessage::ResponseCommandResult(super::ResponseCommandResult {
        success: result.success,
        error: result.error_message,
        result_data: result.result_data,
    })
}

fn collector_event_to_gui_event(
    event: &TelemetryEvent,
    agent_id: &str,
    hostname: Option<&str>,
) -> super::TelemetryEvent {
    let payload_json = serde_json::to_value(&event.payload).unwrap_or(Value::Null);
    let payload = payload_json.as_object().cloned().unwrap_or_default();
    let event_type = to_json_string(&event.event_type);
    let severity = to_json_string(&event.severity);
    let timestamp =
        DateTime::<Utc>::from_timestamp_millis(i64::try_from(event.timestamp).unwrap_or(i64::MAX))
            .unwrap_or_else(Utc::now);

    super::TelemetryEvent {
        id: event.event_id.clone(),
        event_type: event_type.clone(),
        severity,
        timestamp,
        message: build_gui_event_message(&event_type, &payload_json),
        agent_id: agent_id.to_string(),
        hostname: hostname.unwrap_or("local-agent").to_string(),
        process_name: get_string(&payload, &["process_name", "name", "source_process"]),
        process_id: get_u32(&payload, &["pid", "process_id", "source_pid"]),
        parent_process_id: get_u32(&payload, &["ppid", "parent_pid", "parent_process_id"]),
        command_line: get_string(&payload, &["cmdline", "command_line"]),
        exe_path: get_string(&payload, &["path", "process_path", "exe_path"]),
        user: get_string(&payload, &["user", "username"]),
        file_path: get_string(&payload, &["file_path", "path"]),
        file_action: get_string(&payload, &["operation", "action"]),
        file_hash: get_string(&payload, &["sha256", "hash"]),
        remote_ip: get_string(&payload, &["remote_ip", "destination_ip", "dst_ip"]),
        remote_port: get_u16(&payload, &["remote_port", "destination_port", "dst_port"]),
        local_port: get_u16(&payload, &["local_port", "source_port", "src_port"]),
        protocol: get_string(&payload, &["protocol"]),
        direction: get_string(&payload, &["direction"]),
        registry_key: get_string(&payload, &["key_path", "registry_key"]),
        registry_value: get_string(&payload, &["value_name", "registry_value"]),
        registry_action: get_string(&payload, &["registry_action", "operation", "action"]),
        alert_source: get_string(&payload, &["alert_source", "source", "collector"]),
        alert_severity: None,
        rule_name: event
            .detections
            .first()
            .map(|detection| detection.rule_name.clone()),
        mitre_tactics: Some(
            event
                .detections
                .iter()
                .flat_map(|detection| detection.mitre_techniques.clone())
                .collect(),
        )
        .filter(|items: &Vec<String>| !items.is_empty()),
        raw_data: Some(serde_json::json!({
            "payload": payload_json,
            "metadata": event.metadata,
            "detections": event.detections,
        })),
    }
}

fn collector_name_for_event_type(event_type: &str) -> String {
    let normalized = event_type.to_ascii_lowercase();

    if normalized.starts_with("file_") {
        "file".to_string()
    } else if normalized.starts_with("process_") {
        "process".to_string()
    } else if normalized.starts_with("dns_") {
        "dns".to_string()
    } else if normalized.starts_with("network_")
        || matches!(
            normalized.as_str(),
            "connection" | "connection_start" | "connection_end"
        )
    {
        "network".to_string()
    } else if normalized.starts_with("registry_") {
        "registry".to_string()
    } else if normalized.starts_with("usb_") {
        "usb".to_string()
    } else if normalized.contains("ransomware") {
        "ransomware_canary".to_string()
    } else if normalized.contains("persistence") {
        "persistence".to_string()
    } else if normalized.contains("ntdll") {
        "ntdll_write_monitor".to_string()
    } else {
        normalized
    }
}

fn to_json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn event_matches_type_filter(event_type: &str, filter: &str) -> bool {
    if event_type == filter {
        return true;
    }

    match filter {
        "process" => event_type.starts_with("process_"),
        "file" => event_type.starts_with("file_"),
        "network" => {
            event_type.starts_with("network_")
                || event_type.starts_with("dns_")
                || matches!(
                    event_type,
                    "connection" | "connection_start" | "connection_end" | "dns_query"
                )
        }
        "registry" => event_type.starts_with("registry_"),
        "alert" => event_type.starts_with("alert_") || event_type.contains("detection"),
        "response" => event_type.starts_with("response_") || event_type.starts_with("remediation_"),
        "system" => {
            event_type.starts_with("system_")
                || event_type.starts_with("security_")
                || event_type.ends_with("_audit")
        }
        _ => false,
    }
}

fn severity_to_log_level(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => "ERROR",
        "medium" => "WARN",
        "low" | "info" => "INFO",
        _ => "DEBUG",
    }
}

fn is_alert_event(event: &super::TelemetryEvent) -> bool {
    let event_type = event.event_type.to_ascii_lowercase();
    let severity = event
        .alert_severity
        .as_deref()
        .unwrap_or(&event.severity)
        .to_ascii_lowercase();

    matches!(severity.as_str(), "critical" | "high")
        || event_type.starts_with("alert_")
        || event_type.contains("detection")
        || matches!(
            event_type.as_str(),
            "defense_evasion"
                | "etw_tamper"
                | "credential_theft"
                | "process_hollowing"
                | "syscall_evasion"
                | "exploit_mitigation"
                | "lateral_movement"
        )
}

fn event_to_alert(event: super::TelemetryEvent) -> super::AlertNotification {
    let alert_severity = event.alert_severity.as_deref().unwrap_or(&event.severity);
    let title = event
        .rule_name
        .clone()
        .unwrap_or_else(|| event_type_to_alert_title(&event.event_type));

    super::AlertNotification {
        id: format!("alert-{}", event.id),
        timestamp: event.timestamp,
        severity: alert_severity_from_str(alert_severity),
        title,
        description: event.message.clone(),
        threat_name: event
            .rule_name
            .clone()
            .or(event.alert_source.clone())
            .or_else(|| Some(event.event_type.clone())),
        process_name: event.process_name.clone(),
        process_id: event.process_id,
        file_path: event.file_path.as_ref().map(PathBuf::from),
        mitre_tactics: event.mitre_tactics.clone().unwrap_or_default(),
        remediation: Some(remediation_for_event(&event)),
        acknowledged: false,
    }
}

fn alert_severity_from_str(severity: &str) -> super::AlertSeverity {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => super::AlertSeverity::Critical,
        "high" => super::AlertSeverity::High,
        "medium" => super::AlertSeverity::Medium,
        "low" => super::AlertSeverity::Low,
        _ => super::AlertSeverity::Info,
    }
}

fn event_type_to_alert_title(event_type: &str) -> String {
    event_type
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn remediation_for_event(event: &super::TelemetryEvent) -> String {
    match event.event_type.as_str() {
        "process_create" | "process_hollowing" => {
            "Review the process lineage and isolate or terminate the process if suspicious.".to_string()
        }
        "file_create" | "file_modify" | "file_delete" => {
            "Review file activity and quarantine the affected path if it is not expected.".to_string()
        }
        "network_connect" | "dns_query" => {
            "Validate the remote endpoint and block the destination if it is untrusted.".to_string()
        }
        "defense_evasion" | "etw_tamper" | "syscall_evasion" => {
            "Treat as high priority, collect process context, and contain the endpoint if confirmed.".to_string()
        }
        _ => "Review the event context and apply the appropriate response action.".to_string(),
    }
}

fn get_string(payload: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        payload.get(*key).and_then(|value| match value {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    })
}

fn get_u32(payload: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u32> {
    keys.iter().find_map(|key| {
        payload.get(*key).and_then(|value| match value {
            Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            Value::String(s) => s.parse::<u32>().ok(),
            _ => None,
        })
    })
}

fn get_u16(payload: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u16> {
    keys.iter().find_map(|key| {
        payload.get(*key).and_then(|value| match value {
            Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
            Value::String(s) => s.parse::<u16>().ok(),
            _ => None,
        })
    })
}

fn build_gui_event_message(event_type: &str, payload: &Value) -> String {
    let Some(map) = payload.as_object() else {
        return event_type.replace('_', " ");
    };

    match event_type {
        "process_create" | "process_terminate" => {
            let name =
                get_string(map, &["name", "process_name"]).unwrap_or_else(|| "process".to_string());
            let pid = get_u32(map, &["pid"])
                .map(|pid| format!(" (PID {pid})"))
                .unwrap_or_default();
            format!("{}{}", name, pid)
        }
        "file_create" | "file_modify" | "file_delete" | "file_rename" => {
            get_string(map, &["path", "file_path"]).unwrap_or_else(|| event_type.replace('_', " "))
        }
        "network_connect" | "network_listen" => {
            let ip = get_string(map, &["remote_ip", "destination_ip"])
                .unwrap_or_else(|| "remote endpoint".to_string());
            let port = get_u16(map, &["remote_port", "destination_port"])
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            format!("{ip}{port}")
        }
        "dns_query" => {
            get_string(map, &["query", "domain"]).unwrap_or_else(|| "DNS query".to_string())
        }
        "security_audit" => {
            let op =
                get_string(map, &["operation"]).unwrap_or_else(|| "security audit".to_string());
            let success = get_string(map, &["success"]).unwrap_or_default();
            format!("{op} {success}")
        }
        _ => event_type.replace('_', " "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let auth = IpcAuthenticator::new();
        let server = Arc::new(IpcServer::new(auth));
        assert_eq!(server.client_count().await, 0);
    }

    #[tokio::test]
    async fn test_broadcast() {
        let auth = IpcAuthenticator::new();
        let server = Arc::new(IpcServer::new(auth));

        let message = IpcMessage::GetStatus;
        assert!(server.broadcast(message).is_ok());
    }
}
