//! Decoy Network Services - Honeypot Service Emulation
//!
//! Provides fake network services that attract and detect attackers:
//! - SSH Honeypot: Logs authentication attempts
//! - RDP Honeypot: Logs connection attempts
//! - HTTP Honeypot: Fake vulnerable web application
//! - SMB Honeypot: Fake network share
//! - FTP Honeypot: Fake file server
//! - MySQL/MSSQL Honeypot: Fake database servers
//!
//! These services log all interaction attempts to detect:
//! - Lateral movement (T1021)
//! - Brute force attacks (T1110)
//! - Network service scanning (T1046)
//! - Credential access (T1552)

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ============================================================================
// Decoy Service Types
// ============================================================================

/// Types of decoy services available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecoyServiceType {
    /// SSH honeypot (port 22 or custom)
    SSH,
    /// RDP honeypot (port 3389 or custom)
    RDP,
    /// HTTP honeypot web server
    HTTP,
    /// HTTPS honeypot web server
    HTTPS,
    /// SMB honeypot file share
    SMB,
    /// FTP honeypot file server
    FTP,
    /// MySQL honeypot database
    MySQL,
    /// MSSQL honeypot database
    MSSQL,
    /// PostgreSQL honeypot database
    PostgreSQL,
    /// Telnet honeypot
    Telnet,
    /// LDAP honeypot (Active Directory)
    LDAP,
    /// VNC honeypot
    VNC,
    /// Redis honeypot
    Redis,
    /// MongoDB honeypot
    MongoDB,
}

impl DecoyServiceType {
    /// Get default port for this service type
    pub fn default_port(&self) -> u16 {
        match self {
            Self::SSH => 22,
            Self::RDP => 3389,
            Self::HTTP => 80,
            Self::HTTPS => 443,
            Self::SMB => 445,
            Self::FTP => 21,
            Self::MySQL => 3306,
            Self::MSSQL => 1433,
            Self::PostgreSQL => 5432,
            Self::Telnet => 23,
            Self::LDAP => 389,
            Self::VNC => 5900,
            Self::Redis => 6379,
            Self::MongoDB => 27017,
        }
    }

    /// Get MITRE techniques associated with this service type
    pub fn mitre_techniques(&self) -> Vec<String> {
        match self {
            Self::SSH => vec!["T1021.004".to_string(), "T1110".to_string()],
            Self::RDP => vec!["T1021.001".to_string(), "T1110".to_string()],
            Self::HTTP | Self::HTTPS => vec!["T1190".to_string(), "T1595".to_string()],
            Self::SMB => vec!["T1021.002".to_string(), "T1135".to_string()],
            Self::FTP => vec!["T1021".to_string(), "T1110".to_string()],
            Self::MySQL | Self::MSSQL | Self::PostgreSQL => {
                vec!["T1190".to_string(), "T1110".to_string()]
            }
            Self::Telnet => vec!["T1021".to_string(), "T1110".to_string()],
            Self::LDAP => vec!["T1087.002".to_string(), "T1069.002".to_string()],
            Self::VNC => vec!["T1021.005".to_string(), "T1110".to_string()],
            Self::Redis | Self::MongoDB => vec!["T1190".to_string(), "T1110".to_string()],
        }
    }

    /// Get service banner/greeting
    pub fn banner(&self) -> &'static str {
        match self {
            Self::SSH => "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
            Self::RDP => "", // Binary protocol
            Self::HTTP => "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n",
            Self::HTTPS => "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n",
            Self::SMB => "", // Binary protocol
            Self::FTP => "220 FTP Server Ready\r\n",
            Self::MySQL => "",      // Binary protocol
            Self::MSSQL => "",      // Binary protocol
            Self::PostgreSQL => "", // Binary protocol
            Self::Telnet => "Welcome to Ubuntu 22.04 LTS\r\nlogin: ",
            Self::LDAP => "", // Binary protocol
            Self::VNC => "RFB 003.008\n",
            Self::Redis => "+PONG\r\n",
            Self::MongoDB => "", // Binary protocol
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Simple URL decode function (handles %XX encoding and + as space)
fn simple_url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                // Try to parse two hex digits
                let hex1 = chars.next();
                let hex2 = chars.next();
                if let (Some(h1), Some(h2)) = (hex1, hex2) {
                    let hex_str: String = [h1, h2].iter().collect();
                    if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                        result.push(byte as char);
                    } else {
                        // Invalid hex, keep as-is
                        result.push('%');
                        result.push(h1);
                        result.push(h2);
                    }
                } else {
                    // Not enough chars, keep percent
                    result.push('%');
                    if let Some(h1) = hex1 {
                        result.push(h1);
                    }
                }
            }
            '+' => result.push(' '),
            _ => result.push(c),
        }
    }

    result
}

// ============================================================================
// Decoy Service Event
// ============================================================================

/// Event generated by decoy service interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyServiceEvent {
    /// Unique event ID
    pub event_id: String,
    /// Service type
    pub service_type: DecoyServiceType,
    /// Service port
    pub port: u16,
    /// Source IP address
    pub source_ip: String,
    /// Source port
    pub source_port: u16,
    /// Timestamp (epoch ms)
    pub timestamp: u64,
    /// Interaction type (connect, authenticate, command, etc.)
    pub interaction_type: String,
    /// Captured credentials (username/password)
    pub credentials: Option<CapturedCredentials>,
    /// Captured commands/data
    pub captured_data: Option<String>,
    /// Session duration in ms
    pub session_duration_ms: u64,
    /// Number of failed attempts
    pub failed_attempts: u32,
    /// Whether the attacker successfully authenticated (always false for honeypots)
    pub auth_success: bool,
    /// User agent or client info
    pub client_info: Option<String>,
    /// TLS/SSL info if applicable
    pub tls_info: Option<String>,
}

/// Captured authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedCredentials {
    pub username: String,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub auth_method: String,
}

// ============================================================================
// Decoy Service Configuration
// ============================================================================

/// Configuration for a single decoy service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyServiceConfig {
    /// Service type
    pub service_type: DecoyServiceType,
    /// Port to listen on (0 = use default)
    pub port: u16,
    /// Bind address (0.0.0.0 for all interfaces)
    pub bind_address: String,
    /// Enable this service
    pub enabled: bool,
    /// Custom banner (optional)
    pub custom_banner: Option<String>,
    /// Delay responses to slow down attacks (ms)
    pub response_delay_ms: u64,
    /// Maximum connections before rejecting
    pub max_connections: u32,
    /// Log full captured data
    pub capture_full_data: bool,
    /// Simulate successful auth for deeper interaction capture
    pub simulate_success: bool,
}

impl Default for DecoyServiceConfig {
    fn default() -> Self {
        Self {
            service_type: DecoyServiceType::SSH,
            port: 0,
            bind_address: "0.0.0.0".to_string(),
            enabled: true,
            custom_banner: None,
            response_delay_ms: 100,
            max_connections: 100,
            capture_full_data: true,
            simulate_success: false,
        }
    }
}

// ============================================================================
// Decoy Service Manager
// ============================================================================

/// Manages all decoy network services
pub struct DecoyServiceManager {
    config: AgentConfig,
    services: HashMap<DecoyServiceType, DecoyServiceConfig>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    active_connections: Arc<std::sync::atomic::AtomicU32>,
}

impl DecoyServiceManager {
    /// Create a new decoy service manager
    pub fn new(config: &AgentConfig, event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        Self {
            config: config.clone(),
            services: HashMap::new(),
            event_tx,
            active_connections: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Add a decoy service configuration
    pub fn add_service(&mut self, config: DecoyServiceConfig) {
        self.services.insert(config.service_type, config);
    }

    /// Add default services (SSH, RDP, HTTP, SMB)
    pub fn add_default_services(&mut self) {
        // SSH honeypot on alternate port (attackers scan for non-standard ports too)
        self.add_service(DecoyServiceConfig {
            service_type: DecoyServiceType::SSH,
            port: 2222,
            ..Default::default()
        });

        // HTTP honeypot
        self.add_service(DecoyServiceConfig {
            service_type: DecoyServiceType::HTTP,
            port: 8080,
            ..Default::default()
        });

        // FTP honeypot
        self.add_service(DecoyServiceConfig {
            service_type: DecoyServiceType::FTP,
            port: 2121,
            ..Default::default()
        });

        // Redis honeypot (commonly targeted)
        self.add_service(DecoyServiceConfig {
            service_type: DecoyServiceType::Redis,
            port: 6380,
            ..Default::default()
        });

        // Telnet honeypot
        self.add_service(DecoyServiceConfig {
            service_type: DecoyServiceType::Telnet,
            port: 2323,
            ..Default::default()
        });
    }

    /// Start all configured decoy services
    pub async fn start_all(&self) -> Result<()> {
        info!(
            count = self.services.len(),
            "Starting decoy network services"
        );

        for (service_type, config) in &self.services {
            if !config.enabled {
                continue;
            }

            let port = if config.port == 0 {
                service_type.default_port()
            } else {
                config.port
            };

            let bind_addr = format!("{}:{}", config.bind_address, port);
            let event_tx = self.event_tx.clone();
            let config = config.clone();
            let active_connections = self.active_connections.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    Self::run_service(&bind_addr, &config, event_tx, active_connections).await
                {
                    error!(
                        service = ?config.service_type,
                        port = port,
                        error = %e,
                        "Decoy service failed"
                    );
                }
            });

            info!(
                service = ?service_type,
                port = port,
                "Started decoy service"
            );
        }

        Ok(())
    }

    /// Run a single decoy service
    async fn run_service(
        bind_addr: &str,
        config: &DecoyServiceConfig,
        event_tx: mpsc::Sender<TelemetryEvent>,
        active_connections: Arc<std::sync::atomic::AtomicU32>,
    ) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;

        loop {
            let (stream, addr) = listener.accept().await?;

            let current = active_connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if current >= config.max_connections {
                active_connections.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                continue;
            }

            let event_tx = event_tx.clone();
            let config = config.clone();
            let active_connections = active_connections.clone();

            tokio::spawn(async move {
                let result = Self::handle_connection(stream, addr, &config, &event_tx).await;
                active_connections.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

                if let Err(e) = result {
                    debug!(
                        service = ?config.service_type,
                        addr = %addr,
                        error = %e,
                        "Connection handler error"
                    );
                }
            });
        }
    }

    /// Handle a connection to a decoy service
    async fn handle_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        config: &DecoyServiceConfig,
        event_tx: &mpsc::Sender<TelemetryEvent>,
    ) -> Result<()> {
        let start_time = std::time::Instant::now();
        let session_id = Uuid::new_v4().to_string();

        info!(
            service = ?config.service_type,
            source = %addr,
            session = %session_id,
            "Decoy service connection received"
        );

        // Apply response delay
        if config.response_delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(config.response_delay_ms)).await;
        }

        // Send banner
        let banner = config
            .custom_banner
            .as_deref()
            .unwrap_or_else(|| config.service_type.banner());
        if !banner.is_empty() {
            stream.write_all(banner.as_bytes()).await?;
        }

        // Handle based on service type
        let (credentials, captured_data, interaction_type) = match config.service_type {
            DecoyServiceType::SSH => Self::handle_ssh(&mut stream, config).await?,
            DecoyServiceType::FTP => Self::handle_ftp(&mut stream, config).await?,
            DecoyServiceType::Telnet => Self::handle_telnet(&mut stream, config).await?,
            DecoyServiceType::HTTP | DecoyServiceType::HTTPS => {
                Self::handle_http(&mut stream, config).await?
            }
            DecoyServiceType::Redis => Self::handle_redis(&mut stream, config).await?,
            DecoyServiceType::VNC => Self::handle_vnc(&mut stream, config).await?,
            _ => Self::handle_generic(&mut stream, config).await?,
        };

        let duration = start_time.elapsed();

        // Create event
        let decoy_event = DecoyServiceEvent {
            event_id: session_id.clone(),
            service_type: config.service_type,
            port: stream.local_addr()?.port(),
            source_ip: addr.ip().to_string(),
            source_port: addr.port(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            interaction_type,
            credentials,
            captured_data,
            session_duration_ms: duration.as_millis() as u64,
            failed_attempts: 1,
            auth_success: false,
            client_info: None,
            tls_info: None,
        };

        // Create telemetry event
        let mut event = TelemetryEvent::new(
            EventType::DecoyServiceAccess,
            Severity::Critical,
            EventPayload::Custom(serde_json::to_value(&decoy_event)?),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Honeyfile, // Reuse for deception
            rule_name: format!("decoy_service_{:?}", config.service_type).to_lowercase(),
            confidence: 1.0,
            description: format!(
                "DECEPTION TRIGGERED: {} connection from {} to {:?} honeypot",
                decoy_event.interaction_type,
                addr.ip(),
                config.service_type
            ),
            mitre_tactics: vec![
                "lateral-movement".to_string(),
                "credential-access".to_string(),
            ],
            mitre_techniques: config.service_type.mitre_techniques(),
        });

        event.metadata.insert("session_id".to_string(), session_id);
        event
            .metadata
            .insert("source_ip".to_string(), addr.ip().to_string());
        event.metadata.insert(
            "service_type".to_string(),
            format!("{:?}", config.service_type),
        );

        let _ = event_tx.send(event).await;

        Ok(())
    }

    /// Handle SSH honeypot interaction
    async fn handle_ssh(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 4096];
        let mut captured = String::new();

        // Read client version string
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                captured.push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
        }

        // Simulate key exchange delay
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Send fake key exchange (simplified)
        let fake_kex = b"\x00\x00\x00\x14\x14SSH-2.0-tamandua-honeypot\r\n";
        let _ = stream.write_all(fake_kex).await;

        // Try to capture more data
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                captured.push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
        }

        // Extract credentials if present (from password auth attempt)
        let credentials = Self::extract_ssh_credentials(&captured);

        Ok((
            credentials,
            if config.capture_full_data {
                Some(captured)
            } else {
                None
            },
            "ssh_auth_attempt".to_string(),
        ))
    }

    /// Extract SSH credentials from captured data
    fn extract_ssh_credentials(data: &str) -> Option<CapturedCredentials> {
        // Look for username in SSH auth data
        // This is simplified - real SSH auth is binary
        if data.contains("userauth") || data.contains("password") {
            Some(CapturedCredentials {
                username: "unknown".to_string(),
                password: Some("captured_binary".to_string()),
                domain: None,
                auth_method: "password".to_string(),
            })
        } else {
            None
        }
    }

    /// Handle FTP honeypot interaction
    async fn handle_ftp(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 4096];
        let mut username = String::new();
        let mut password = String::new();
        let mut captured = String::new();
        let mut interaction_type = "ftp_connect".to_string();

        loop {
            let n = match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let data = String::from_utf8_lossy(&buffer[..n]);
            captured.push_str(&data);

            for line in data.lines() {
                let line_upper = line.to_uppercase();

                if line_upper.starts_with("USER ") {
                    username = line[5..].trim().to_string();
                    stream
                        .write_all(b"331 Password required for user.\r\n")
                        .await?;
                    interaction_type = "ftp_auth_attempt".to_string();
                } else if line_upper.starts_with("PASS ") {
                    password = line[5..].trim().to_string();
                    // Always reject
                    stream.write_all(b"530 Login incorrect.\r\n").await?;
                } else if line_upper.starts_with("QUIT") {
                    stream.write_all(b"221 Goodbye.\r\n").await?;
                    break;
                } else if line_upper.starts_with("LIST") || line_upper.starts_with("RETR") {
                    stream
                        .write_all(b"530 Please login with USER and PASS.\r\n")
                        .await?;
                } else {
                    stream.write_all(b"500 Unknown command.\r\n").await?;
                }
            }
        }

        let credentials = if !username.is_empty() {
            Some(CapturedCredentials {
                username,
                password: if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                domain: None,
                auth_method: "plaintext".to_string(),
            })
        } else {
            None
        };

        Ok((
            credentials,
            if config.capture_full_data {
                Some(captured)
            } else {
                None
            },
            interaction_type,
        ))
    }

    /// Handle Telnet honeypot interaction
    async fn handle_telnet(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 4096];
        let mut username = String::new();
        let mut password = String::new();
        let mut captured = String::new();

        // Wait for username
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                username = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                captured.push_str(&format!("USER: {}\n", username));
            }
        }

        // Prompt for password
        stream.write_all(b"Password: ").await?;

        // Wait for password
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                password = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                captured.push_str("PASS: [captured]\n");
            }
        }

        // Reject login
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        stream.write_all(b"\r\nLogin incorrect\r\n").await?;

        let credentials = if !username.is_empty() {
            Some(CapturedCredentials {
                username,
                password: if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                domain: None,
                auth_method: "plaintext".to_string(),
            })
        } else {
            None
        };

        Ok((
            credentials,
            if config.capture_full_data {
                Some(captured)
            } else {
                None
            },
            "telnet_auth_attempt".to_string(),
        ))
    }

    /// Handle HTTP honeypot interaction
    async fn handle_http(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 8192];
        let n = stream.read(&mut buffer).await?;
        let request = String::from_utf8_lossy(&buffer[..n]).to_string();

        // Parse HTTP request
        let mut interaction_type = "http_request".to_string();
        let mut credentials = None;

        // Check for basic auth
        if request.contains("Authorization: Basic ") {
            interaction_type = "http_auth_attempt".to_string();
            if let Some(auth_line) = request
                .lines()
                .find(|l| l.contains("Authorization: Basic "))
            {
                if let Some(b64) = auth_line.split("Basic ").nth(1) {
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        b64.trim(),
                    ) {
                        if let Ok(creds_str) = String::from_utf8(decoded) {
                            let parts: Vec<&str> = creds_str.splitn(2, ':').collect();
                            if parts.len() == 2 {
                                credentials = Some(CapturedCredentials {
                                    username: parts[0].to_string(),
                                    password: Some(parts[1].to_string()),
                                    domain: None,
                                    auth_method: "basic".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for login form POST
        if request.contains("POST") && (request.contains("login") || request.contains("password")) {
            interaction_type = "http_login_attempt".to_string();
            // Try to extract form data
            if let Some(body_start) = request.find("\r\n\r\n") {
                let body = &request[body_start + 4..];
                // Parse form data (username=xxx&password=xxx)
                let mut username = String::new();
                let mut password = String::new();
                for param in body.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key.to_lowercase().as_str() {
                            "username" | "user" | "email" | "login" => {
                                username = simple_url_decode(value);
                            }
                            "password" | "pass" | "pwd" => {
                                password = simple_url_decode(value);
                            }
                            _ => {}
                        }
                    }
                }
                if !username.is_empty() {
                    credentials = Some(CapturedCredentials {
                        username,
                        password: if password.is_empty() {
                            None
                        } else {
                            Some(password)
                        },
                        domain: None,
                        auth_method: "form".to_string(),
                    });
                }
            }
        }

        // Send fake response
        let response: &[u8] = if credentials.is_some() {
            // Login failed response
            b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nWWW-Authenticate: Basic realm=\"Secure Area\"\r\n\r\n<html><body><h1>401 Unauthorized</h1><p>Invalid credentials</p></body></html>"
        } else {
            // Fake admin panel
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Admin Panel</title></head><body><h1>Admin Panel</h1><form method='POST' action='/login'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button>Login</button></form></body></html>"
        };

        stream.write_all(response).await?;

        Ok((
            credentials,
            if config.capture_full_data {
                Some(request)
            } else {
                None
            },
            interaction_type,
        ))
    }

    /// Handle Redis honeypot interaction
    async fn handle_redis(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 4096];
        let mut captured = String::new();
        let mut interaction_type = "redis_connect".to_string();
        let mut credentials = None;

        loop {
            let n = match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let data = String::from_utf8_lossy(&buffer[..n]).to_string();
            captured.push_str(&data);

            // Parse Redis commands
            for line in data.lines() {
                let line_upper = line.to_uppercase();

                if line_upper.starts_with("AUTH ") {
                    let password = line[5..].trim().to_string();
                    credentials = Some(CapturedCredentials {
                        username: "default".to_string(),
                        password: Some(password),
                        domain: None,
                        auth_method: "redis_auth".to_string(),
                    });
                    interaction_type = "redis_auth_attempt".to_string();
                    stream.write_all(b"-ERR invalid password\r\n").await?;
                } else if line_upper == "PING" {
                    stream.write_all(b"+PONG\r\n").await?;
                } else if line_upper == "INFO" {
                    stream
                        .write_all(b"-NOAUTH Authentication required.\r\n")
                        .await?;
                } else if line_upper == "QUIT" {
                    stream.write_all(b"+OK\r\n").await?;
                    break;
                } else if !line.starts_with('*') && !line.starts_with('$') {
                    stream
                        .write_all(b"-NOAUTH Authentication required.\r\n")
                        .await?;
                }
            }
        }

        Ok((
            credentials,
            if config.capture_full_data {
                Some(captured)
            } else {
                None
            },
            interaction_type,
        ))
    }

    /// Handle VNC honeypot interaction
    async fn handle_vnc(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 4096];
        let mut captured = Vec::new();

        // Read client response to version
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                captured.extend_from_slice(&buffer[..n]);
            }
        }

        // Send security types (VNC Authentication)
        stream.write_all(&[1, 2]).await?; // 1 type, VNC auth (2)

        // Read client choice
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                captured.extend_from_slice(&buffer[..n]);
            }
        }

        // Send challenge (16 random bytes)
        let challenge: [u8; 16] = rand::random();
        stream.write_all(&challenge).await?;

        // Read response (encrypted password)
        if let Ok(n) = stream.read(&mut buffer).await {
            if n > 0 {
                captured.extend_from_slice(&buffer[..n]);
            }
        }

        // Always reject
        stream.write_all(&[0, 0, 0, 1]).await?; // Failed

        Ok((
            Some(CapturedCredentials {
                username: "vnc_user".to_string(),
                password: Some(format!("encrypted:{}", hex::encode(&captured))),
                domain: None,
                auth_method: "vnc_challenge".to_string(),
            }),
            if config.capture_full_data {
                Some(hex::encode(&captured))
            } else {
                None
            },
            "vnc_auth_attempt".to_string(),
        ))
    }

    /// Handle generic protocol (capture data only)
    async fn handle_generic(
        stream: &mut TcpStream,
        config: &DecoyServiceConfig,
    ) -> Result<(Option<CapturedCredentials>, Option<String>, String)> {
        let mut buffer = [0u8; 4096];
        let mut captured = Vec::new();

        // Read initial data with timeout
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            stream.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                captured.extend_from_slice(&buffer[..n]);
            }
            _ => {}
        }

        Ok((
            None,
            if config.capture_full_data {
                Some(hex::encode(&captured))
            } else {
                None
            },
            "generic_connect".to_string(),
        ))
    }

    /// Get service statistics
    pub fn get_stats(&self) -> DecoyServiceStats {
        DecoyServiceStats {
            active_services: self.services.iter().filter(|(_, c)| c.enabled).count(),
            active_connections: self
                .active_connections
                .load(std::sync::atomic::Ordering::SeqCst),
            service_types: self.services.keys().cloned().collect(),
        }
    }
}

/// Statistics for decoy services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyServiceStats {
    pub active_services: usize,
    pub active_connections: u32,
    pub service_types: Vec<DecoyServiceType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_default_ports() {
        assert_eq!(DecoyServiceType::SSH.default_port(), 22);
        assert_eq!(DecoyServiceType::RDP.default_port(), 3389);
        assert_eq!(DecoyServiceType::HTTP.default_port(), 80);
        assert_eq!(DecoyServiceType::SMB.default_port(), 445);
    }

    #[test]
    fn test_service_mitre_techniques() {
        let ssh_techniques = DecoyServiceType::SSH.mitre_techniques();
        assert!(ssh_techniques.contains(&"T1021.004".to_string()));
        assert!(ssh_techniques.contains(&"T1110".to_string()));
    }

    #[test]
    fn test_decoy_config_default() {
        let config = DecoyServiceConfig::default();
        assert!(config.enabled);
        assert_eq!(config.port, 0);
        assert!(config.capture_full_data);
    }
}
