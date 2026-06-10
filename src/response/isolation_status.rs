//! Detailed network isolation status reporting
//!
//! Provides structured status types that give the server and dashboard full
//! visibility into the current isolation state, which rules are applied,
//! which connections are allowlisted, and whether isolation is effective.
//!
//! After isolation rules are applied (WFP on Windows, nftables/iptables on
//! Linux), this module runs connectivity verification tests and packages
//! everything into an `IsolationStatus` struct that is serialized to JSON
//! and returned as the `result_data` field of the command response.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Isolation state enum
// ---------------------------------------------------------------------------

/// High-level isolation state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsolationState {
    /// All traffic blocked except explicitly allowlisted connections.
    Isolated,
    /// Partially isolated -- some rules failed to apply.
    Partial,
    /// Isolation was attempted but failed entirely.
    Failed,
    /// No isolation is active.
    Disabled,
}

impl std::fmt::Display for IsolationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationState::Isolated => write!(f, "isolated"),
            IsolationState::Partial => write!(f, "partial"),
            IsolationState::Failed => write!(f, "failed"),
            IsolationState::Disabled => write!(f, "disabled"),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule direction and protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleDirection {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Allow,
}

// ---------------------------------------------------------------------------
// IsolationRule
// ---------------------------------------------------------------------------

/// Describes a single firewall rule that was applied during isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationRule {
    /// Human-readable description of the rule.
    pub description: String,
    /// Direction the rule applies to.
    pub direction: RuleDirection,
    /// Protocol the rule matches.
    pub protocol: RuleProtocol,
    /// Port range (None means all ports).
    pub port_range: Option<(u16, u16)>,
    /// Action taken when the rule matches.
    pub action: RuleAction,
    /// Platform-specific filter ID (WFP filter_id on Windows, nft handle on Linux).
    pub filter_id: Option<String>,
}

// ---------------------------------------------------------------------------
// AllowlistEntry
// ---------------------------------------------------------------------------

/// An entry in the isolation allowlist that keeps specific connectivity alive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Destination IP address or hostname.
    pub destination: String,
    /// Destination port (None means all ports for this destination).
    pub port: Option<u16>,
    /// Reason this destination is allowlisted.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// ConnectivityResult
// ---------------------------------------------------------------------------

/// Results from the post-isolation connectivity verification tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityResult {
    /// Whether the Tamandua server is reachable.
    pub server_reachable: bool,
    /// Whether DNS resolution works.
    pub dns_works: bool,
    /// Whether general internet connectivity is blocked (expected: true).
    pub internet_blocked: bool,
    /// Latency to server in milliseconds (None if unreachable).
    pub server_latency_ms: Option<u64>,
    /// Additional diagnostic details.
    pub details: Option<String>,
}

// ---------------------------------------------------------------------------
// IsolationStatus
// ---------------------------------------------------------------------------

/// Comprehensive isolation status returned by isolate/unisolate commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationStatus {
    /// Current isolation state.
    pub state: IsolationState,
    /// The firewall backend used (wfp, nftables, iptables, pf).
    pub method: String,
    /// List of all rules that were applied.
    pub rules_applied: Vec<IsolationRule>,
    /// Connections that are allowed through the isolation.
    pub allowlisted_connections: Vec<AllowlistEntry>,
    /// Results of connectivity verification.
    pub connectivity_test: ConnectivityResult,
    /// Unix timestamp when isolation was applied (None if disabled).
    pub applied_at: Option<u64>,
    /// Total number of platform-level filters/rules active.
    pub filter_count: usize,
    /// Error message if isolation failed or is partial.
    pub error: Option<String>,
}

impl IsolationStatus {
    /// Convert to serde_json::Value for embedding in CommandResult.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|e| {
            serde_json::json!({
                "error": format!("Failed to serialize isolation status: {}", e)
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Connectivity testing
// ---------------------------------------------------------------------------

/// Run connectivity verification tests after isolation is applied.
///
/// Tests:
/// 1. DNS resolution -- resolve a well-known hostname.
/// 2. Server reachability -- TCP connect to the Tamandua server.
/// 3. Internet block -- attempt TCP connect to a public host (should fail).
pub fn run_connectivity_test(server_host: &str, server_port: u16) -> ConnectivityResult {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    let timeout = Duration::from_secs(5);

    // 1. DNS test: try to resolve a well-known hostname
    let dns_works = {
        let test_host = if !server_host.is_empty() {
            format!("{}:443", server_host)
        } else {
            "dns.google:443".to_string()
        };
        test_host
            .to_socket_addrs()
            .map(|mut addrs| addrs.next().is_some())
            .unwrap_or(false)
    };

    // 2. Server reachability: TCP connect to the server
    let (server_reachable, server_latency_ms) = {
        let addr_str = format!("{}:{}", server_host, server_port);
        match addr_str.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let start = Instant::now();
                    match TcpStream::connect_timeout(&addr, timeout) {
                        Ok(_stream) => {
                            let latency = start.elapsed().as_millis() as u64;
                            debug!(
                                server = %addr_str,
                                latency_ms = latency,
                                "Server connectivity test passed"
                            );
                            (true, Some(latency))
                        }
                        Err(e) => {
                            warn!(
                                server = %addr_str,
                                error = %e,
                                "Server connectivity test failed"
                            );
                            (false, None)
                        }
                    }
                } else {
                    warn!(server = %addr_str, "Could not resolve server address");
                    (false, None)
                }
            }
            Err(e) => {
                warn!(
                    server = %addr_str,
                    error = %e,
                    "DNS resolution failed for server"
                );
                (false, None)
            }
        }
    };

    // 3. Internet block test: try to reach an external host (should fail if isolated)
    let internet_blocked = {
        let test_targets = [
            ("1.1.1.1", 80),
            ("8.8.8.8", 53),
            ("93.184.216.34", 80), // example.com
        ];

        let mut all_blocked = true;
        for (ip, port) in &test_targets {
            let addr_str = format!("{}:{}", ip, port);
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                        debug!(target_ip = %ip, port = port, "External connection succeeded (isolation may not be effective)");
                        all_blocked = false;
                        break;
                    }
                }
            }
        }
        all_blocked
    };

    let details = if !server_reachable {
        Some("WARNING: Server is not reachable through isolation rules".to_string())
    } else if !dns_works {
        Some("WARNING: DNS resolution is not working".to_string())
    } else if !internet_blocked {
        Some(
            "WARNING: External internet is still reachable (isolation may not be effective)"
                .to_string(),
        )
    } else {
        None
    };

    ConnectivityResult {
        server_reachable,
        dns_works,
        internet_blocked,
        server_latency_ms,
        details,
    }
}

// ---------------------------------------------------------------------------
// Build helpers for isolation rules list
// ---------------------------------------------------------------------------

/// Build the list of IsolationRule entries for a full isolation application.
///
/// This describes what was applied without exposing internal filter IDs
/// unless provided.
pub fn build_isolation_rules(
    server_ip: &str,
    server_port: Option<u16>,
    allowed_ips: &[String],
    method: &str,
) -> (Vec<IsolationRule>, Vec<AllowlistEntry>) {
    let mut rules = Vec::new();
    let mut allowlist = Vec::new();

    // Block-all rules
    rules.push(IsolationRule {
        description: "Block all outbound IPv4 traffic".to_string(),
        direction: RuleDirection::Outbound,
        protocol: RuleProtocol::Any,
        port_range: None,
        action: RuleAction::Block,
        filter_id: None,
    });

    rules.push(IsolationRule {
        description: "Block all inbound IPv4 traffic".to_string(),
        direction: RuleDirection::Inbound,
        protocol: RuleProtocol::Any,
        port_range: None,
        action: RuleAction::Block,
        filter_id: None,
    });

    if method == "wfp" {
        rules.push(IsolationRule {
            description: "Block all outbound IPv6 traffic".to_string(),
            direction: RuleDirection::Outbound,
            protocol: RuleProtocol::Any,
            port_range: None,
            action: RuleAction::Block,
            filter_id: None,
        });

        rules.push(IsolationRule {
            description: "Block all inbound IPv6 traffic".to_string(),
            direction: RuleDirection::Inbound,
            protocol: RuleProtocol::Any,
            port_range: None,
            action: RuleAction::Block,
            filter_id: None,
        });
    }

    // Loopback permit
    rules.push(IsolationRule {
        description: "Allow loopback traffic".to_string(),
        direction: RuleDirection::Both,
        protocol: RuleProtocol::Any,
        port_range: None,
        action: RuleAction::Allow,
        filter_id: None,
    });

    allowlist.push(AllowlistEntry {
        destination: "127.0.0.1 / ::1".to_string(),
        port: None,
        reason: "Loopback (local services)".to_string(),
    });

    // DNS permit
    rules.push(IsolationRule {
        description: "Allow DNS (UDP port 53)".to_string(),
        direction: RuleDirection::Outbound,
        protocol: RuleProtocol::Udp,
        port_range: Some((53, 53)),
        action: RuleAction::Allow,
        filter_id: None,
    });

    allowlist.push(AllowlistEntry {
        destination: "any".to_string(),
        port: Some(53),
        reason: "DNS resolution (required for server communication)".to_string(),
    });

    // Server permit
    if !server_ip.is_empty() {
        let desc = if let Some(port) = server_port {
            format!("Allow Tamandua server {}:{}", server_ip, port)
        } else {
            format!("Allow Tamandua server {}", server_ip)
        };

        rules.push(IsolationRule {
            description: desc,
            direction: RuleDirection::Both,
            protocol: RuleProtocol::Tcp,
            port_range: server_port.map(|p| (p, p)),
            action: RuleAction::Allow,
            filter_id: None,
        });

        allowlist.push(AllowlistEntry {
            destination: server_ip.to_string(),
            port: server_port,
            reason: "Tamandua server communication".to_string(),
        });
    }

    // Additional allowed IPs
    for ip in allowed_ips {
        if !ip.is_empty() {
            rules.push(IsolationRule {
                description: format!("Allow additional IP {}", ip),
                direction: RuleDirection::Both,
                protocol: RuleProtocol::Any,
                port_range: None,
                action: RuleAction::Allow,
                filter_id: None,
            });

            allowlist.push(AllowlistEntry {
                destination: ip.clone(),
                port: None,
                reason: "Explicitly allowlisted by isolation command".to_string(),
            });
        }
    }

    (rules, allowlist)
}

// ---------------------------------------------------------------------------
// Global isolation status tracking
// ---------------------------------------------------------------------------

/// Globally tracked isolation status for heartbeat reporting and periodic verification.
static GLOBAL_ISOLATION_STATUS: OnceLock<Arc<Mutex<Option<IsolationStatus>>>> = OnceLock::new();

fn get_global_status() -> Arc<Mutex<Option<IsolationStatus>>> {
    GLOBAL_ISOLATION_STATUS
        .get_or_init(|| Arc::new(Mutex::new(None)))
        .clone()
}

/// Store the current isolation status globally.
pub fn set_current_status(status: IsolationStatus) {
    if let Ok(mut guard) = get_global_status().lock() {
        *guard = Some(status);
    }
}

/// Clear the global isolation status (after de-isolation).
pub fn clear_current_status() {
    if let Ok(mut guard) = get_global_status().lock() {
        *guard = None;
    }
}

/// Retrieve the current isolation status for heartbeat reporting.
pub fn get_current_status() -> Option<IsolationStatus> {
    get_global_status()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Check if isolation is currently active based on stored status.
pub fn is_currently_isolated() -> bool {
    get_current_status()
        .map(|s| s.state == IsolationState::Isolated || s.state == IsolationState::Partial)
        .unwrap_or(false)
}

/// Return an isolation status summary for inclusion in heartbeat payloads.
pub fn heartbeat_isolation_payload() -> serde_json::Value {
    match get_current_status() {
        Some(status) => {
            serde_json::json!({
                "isolated": status.state == IsolationState::Isolated || status.state == IsolationState::Partial,
                "state": status.state,
                "method": status.method,
                "filter_count": status.filter_count,
                "applied_at": status.applied_at,
                "server_reachable": status.connectivity_test.server_reachable,
                "dns_works": status.connectivity_test.dns_works,
                "internet_blocked": status.connectivity_test.internet_blocked,
            })
        }
        None => {
            serde_json::json!({
                "isolated": false,
                "state": "disabled",
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Periodic isolation verification
// ---------------------------------------------------------------------------

/// Parameters needed to periodically re-verify isolation effectiveness.
#[derive(Debug, Clone)]
pub struct IsolationVerifyParams {
    pub server_host: String,
    pub server_port: u16,
    pub method: String,
}

static VERIFY_PARAMS: OnceLock<Arc<Mutex<Option<IsolationVerifyParams>>>> = OnceLock::new();

fn get_verify_params_store() -> Arc<Mutex<Option<IsolationVerifyParams>>> {
    VERIFY_PARAMS
        .get_or_init(|| Arc::new(Mutex::new(None)))
        .clone()
}

/// Store verification parameters for periodic checks.
pub fn set_verify_params(params: IsolationVerifyParams) {
    if let Ok(mut guard) = get_verify_params_store().lock() {
        *guard = Some(params);
    }
}

/// Clear verification parameters (after de-isolation).
pub fn clear_verify_params() {
    if let Ok(mut guard) = get_verify_params_store().lock() {
        *guard = None;
    }
}

/// Run a periodic isolation verification.
///
/// Checks whether isolation is still effective by running connectivity tests.
/// If isolation rules were removed externally (e.g., by malware), this reports
/// the degradation so the server can alert and the agent can attempt re-application.
///
/// Returns `Some(status_update)` if the isolation state changed, `None` if unchanged.
pub fn verify_isolation() -> Option<IsolationStatus> {
    let params = get_verify_params_store()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())?;

    let current = get_current_status()?;

    // Only verify if we believe isolation is active
    if current.state != IsolationState::Isolated && current.state != IsolationState::Partial {
        return None;
    }

    // Also check the platform-level isolation flag
    let platform_isolated = {
        #[cfg(target_os = "windows")]
        {
            super::wfp_isolation::get_wfp().is_isolated()
        }
        #[cfg(target_os = "linux")]
        {
            super::linux_isolation::is_isolated()
        }
        #[cfg(target_os = "macos")]
        {
            super::macos_isolation::is_isolated()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            // Cannot verify on unsupported platforms
            true
        }
    };

    if !platform_isolated {
        // Isolation rules were removed externally!
        warn!("Isolation rules appear to have been removed externally");

        let updated_status = IsolationStatus {
            state: IsolationState::Failed,
            method: params.method.clone(),
            rules_applied: Vec::new(),
            allowlisted_connections: Vec::new(),
            connectivity_test: run_connectivity_test(&params.server_host, params.server_port),
            applied_at: current.applied_at,
            filter_count: 0,
            error: Some("Isolation rules were removed externally (possible tampering)".to_string()),
        };

        set_current_status(updated_status.clone());
        return Some(updated_status);
    }

    // Rules are still in place -- run connectivity check to verify effectiveness
    let connectivity = run_connectivity_test(&params.server_host, params.server_port);

    if !connectivity.internet_blocked {
        warn!("Periodic verification: external internet is reachable despite isolation rules");

        let updated_status = IsolationStatus {
            state: IsolationState::Partial,
            method: params.method.clone(),
            rules_applied: current.rules_applied.clone(),
            allowlisted_connections: current.allowlisted_connections.clone(),
            connectivity_test: connectivity,
            applied_at: current.applied_at,
            filter_count: current.filter_count,
            error: Some(
                "External internet still reachable -- isolation may be ineffective".to_string(),
            ),
        };

        set_current_status(updated_status.clone());
        return Some(updated_status);
    }

    debug!("Periodic isolation verification passed -- isolation is effective");
    None
}

/// Get the current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// De-isolation status builder
// ---------------------------------------------------------------------------

/// Build a de-isolation status after rules have been successfully removed.
pub fn build_deisolation_status(
    method: &str,
    _filters_removed: usize,
    server_host: &str,
    server_port: u16,
) -> IsolationStatus {
    let connectivity = run_connectivity_test(server_host, server_port);

    let state = if connectivity.server_reachable && !connectivity.internet_blocked {
        // Internet is no longer blocked and server is reachable -- good
        IsolationState::Disabled
    } else if connectivity.server_reachable {
        // Server reachable but internet still blocked -- partial cleanup
        IsolationState::Partial
    } else {
        // Nothing works -- something went wrong
        IsolationState::Failed
    };

    let error = match state {
        IsolationState::Disabled => None,
        IsolationState::Partial => Some("Some isolation rules may still be active".to_string()),
        IsolationState::Failed => Some("Server is unreachable after de-isolation".to_string()),
        _ => None,
    };

    IsolationStatus {
        state,
        method: method.to_string(),
        rules_applied: Vec::new(),
        allowlisted_connections: Vec::new(),
        connectivity_test: connectivity,
        applied_at: None,
        filter_count: 0,
        error,
    }
}
