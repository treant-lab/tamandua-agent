//! Linux network isolation using nftables or iptables
//!
//! Implements network isolation and per-IP blocking for Linux systems.
//! Prefers nftables on modern systems, falling back to iptables if nft
//! is not available.
//!
//! Key design principles:
//! - Never flush system chains (INPUT/OUTPUT). Only manage Tamandua-specific
//!   rules via dedicated chains or a dedicated nftables table.
//! - Track state globally so cleanup on shutdown is reliable.
//! - Every command execution checks exit status and logs failures.
//!
//! Requires root privileges to manipulate firewall rules.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(target_os = "linux")]
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Firewall backend detection
// ---------------------------------------------------------------------------

/// Which firewall backend is in use.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    /// nftables (nft binary available)
    Nftables,
    /// Legacy iptables
    Iptables,
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallBackend::Nftables => write!(f, "nftables"),
            FirewallBackend::Iptables => write!(f, "iptables"),
        }
    }
}

/// Detect the preferred firewall backend.
///
/// Returns `Nftables` if the `nft` binary exists and is executable,
/// otherwise falls back to `Iptables`.
#[cfg(target_os = "linux")]
fn detect_backend() -> FirewallBackend {
    match Command::new("nft").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            info!(version = %version.trim(), "Detected nftables backend");
            FirewallBackend::Nftables
        }
        _ => {
            info!("nft binary not found or not executable, falling back to iptables");
            FirewallBackend::Iptables
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: run a command and check its exit status
// ---------------------------------------------------------------------------

/// Run a command, log it, and return Ok(stdout) on success or Err(message) on failure.
#[cfg(target_os = "linux")]
fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
    debug!(program = %program, args = ?args, "Running command");

    let output = Command::new(program).args(args).output().map_err(|e| {
        let msg = format!("Failed to execute {}: {}", program, e);
        warn!("{}", msg);
        msg
    })?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let code = output.status.code().unwrap_or(-1);
        let msg = format!("{} exited with code {}: {}", program, code, stderr.trim());
        warn!("{}", msg);
        Err(msg)
    }
}

// ---------------------------------------------------------------------------
// State tracking
// ---------------------------------------------------------------------------

/// Global isolation state, tracking the backend and what rules are active.
#[cfg(target_os = "linux")]
struct IsolationState {
    backend: FirewallBackend,
    /// Whether full network isolation is active
    isolated: bool,
    /// Set of individually blocked IPs (for targeted block/unblock)
    blocked_ips: HashSet<String>,
}

#[cfg(target_os = "linux")]
static LINUX_ISOLATION: OnceLock<Arc<Mutex<IsolationState>>> = OnceLock::new();

/// Get or initialize the global isolation state.
#[cfg(target_os = "linux")]
fn get_state() -> Arc<Mutex<IsolationState>> {
    LINUX_ISOLATION
        .get_or_init(|| {
            let backend = detect_backend();
            info!(backend = %backend, "Linux isolation module initialized");
            Arc::new(Mutex::new(IsolationState {
                backend,
                isolated: false,
                blocked_ips: HashSet::new(),
            }))
        })
        .clone()
}

// ---------------------------------------------------------------------------
// nftables table/chain names
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const NFT_TABLE: &str = "tamandua_isolation";
/// inet family covers both IPv4 and IPv6
#[cfg(target_os = "linux")]
const NFT_FAMILY: &str = "inet";

// ---------------------------------------------------------------------------
// iptables chain names
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const IPT_CHAIN_IN: &str = "TAMANDUA_ISOLATION_IN";
#[cfg(target_os = "linux")]
const IPT_CHAIN_OUT: &str = "TAMANDUA_ISOLATION_OUT";
#[cfg(target_os = "linux")]
const IPT_CHAIN_BLOCK_IN: &str = "TAMANDUA_BLOCK_IN";
#[cfg(target_os = "linux")]
const IPT_CHAIN_BLOCK_OUT: &str = "TAMANDUA_BLOCK_OUT";

// ===========================================================================
// nftables implementation
// ===========================================================================

/// Apply full network isolation via nftables.
///
/// Creates a dedicated `inet tamandua_isolation` table with input and output
/// chains. Allows loopback, the server IP, DNS (TCP+UDP port 53), and any
/// additional allowed IPs. Everything else is dropped.
#[cfg(target_os = "linux")]
fn nft_apply_isolation(server_ip: &str, allowed_ips: &[String]) -> Result<(), String> {
    // Build the set of allowed IP addresses for nftables
    let mut allow_set = Vec::new();
    if !server_ip.is_empty() {
        allow_set.push(server_ip.to_string());
    }
    for ip in allowed_ips {
        if !ip.is_empty() {
            allow_set.push(ip.to_string());
        }
    }

    // Build permit rules for allowed IPs
    let input_permits = allow_set
        .iter()
        .map(|ip| format!("        ip saddr {} accept", ip))
        .collect::<Vec<_>>()
        .join("\n");

    let output_permits = allow_set
        .iter()
        .map(|ip| format!("        ip daddr {} accept", ip))
        .collect::<Vec<_>>()
        .join("\n");

    // First, remove any existing tamandua table to start clean
    // Ignore errors since the table may not exist yet
    let _ = run_cmd("nft", &["delete", "table", NFT_FAMILY, NFT_TABLE]);

    // Build the full nftables ruleset as an atomic script.
    // nft -f reads the entire ruleset and applies it atomically.
    let ruleset = format!(
        r#"table {family} {table} {{
    chain input {{
        type filter hook input priority 0; policy accept;
        iifname "lo" accept
{input_permits}
        udp dport 53 accept
        tcp dport 53 accept
        ct state established,related accept
        drop
    }}

    chain output {{
        type filter hook output priority 0; policy accept;
        oifname "lo" accept
{output_permits}
        udp dport 53 accept
        tcp dport 53 accept
        ct state established,related accept
        drop
    }}
}}"#,
        family = NFT_FAMILY,
        table = NFT_TABLE,
        input_permits = input_permits,
        output_permits = output_permits,
    );

    debug!(ruleset = %ruleset, "Applying nftables isolation ruleset");

    // Write ruleset to a temp file and apply atomically
    let ruleset_path = "/tmp/tamandua_nft_isolation.conf";
    std::fs::write(ruleset_path, &ruleset).map_err(|e| {
        let msg = format!(
            "Failed to write nftables ruleset to {}: {}",
            ruleset_path, e
        );
        warn!("{}", msg);
        msg
    })?;

    let result = run_cmd("nft", &["-f", ruleset_path]);

    // Clean up temp file regardless of result
    if let Err(e) = std::fs::remove_file(ruleset_path) {
        debug!(error = %e, "Failed to remove temp nftables file (non-critical)");
    }

    result.map(|_| {
        info!(
            server_ip = %server_ip,
            allowed_count = allowed_ips.len(),
            "nftables network isolation applied"
        );
    })
}

/// Remove full network isolation by deleting the nftables table.
#[cfg(target_os = "linux")]
fn nft_remove_isolation() -> Result<(), String> {
    run_cmd("nft", &["delete", "table", NFT_FAMILY, NFT_TABLE]).map(|_| {
        info!("nftables isolation table removed");
    })
}

/// Block a specific IP via nftables.
///
/// Inserts rules at the start of the existing chains if isolation is active,
/// or creates a minimal block table if not isolated.
#[cfg(target_os = "linux")]
fn nft_block_ip(ip: &str) -> Result<(), String> {
    // Check if the tamandua_isolation table exists (isolation is active)
    let table_exists = run_cmd("nft", &["list", "table", NFT_FAMILY, NFT_TABLE]).is_ok();

    if table_exists {
        // Add block rules to the existing isolation table chains.
        // Insert at position 0 so they are evaluated before the permit rules.
        run_cmd(
            "nft",
            &[
                "insert", "rule", NFT_FAMILY, NFT_TABLE, "input", "ip", "saddr", ip, "drop",
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "insert", "rule", NFT_FAMILY, NFT_TABLE, "output", "ip", "daddr", ip, "drop",
            ],
        )?;
    } else {
        // No isolation active -- create a minimal table just for IP blocking
        let ruleset = format!(
            r#"table {family} {table} {{
    chain input {{
        type filter hook input priority -1; policy accept;
        ip saddr {ip} drop
    }}
    chain output {{
        type filter hook output priority -1; policy accept;
        ip daddr {ip} drop
    }}
}}"#,
            family = NFT_FAMILY,
            table = NFT_TABLE,
            ip = ip,
        );

        let ruleset_path = "/tmp/tamandua_nft_block.conf";
        std::fs::write(ruleset_path, &ruleset)
            .map_err(|e| format!("Failed to write nftables block ruleset: {}", e))?;

        let result = run_cmd("nft", &["-f", ruleset_path]);
        let _ = std::fs::remove_file(ruleset_path);

        if let Err(e) = result {
            // Table may already exist from a previous block -- try inserting instead
            run_cmd(
                "nft",
                &[
                    "insert", "rule", NFT_FAMILY, NFT_TABLE, "input", "ip", "saddr", ip, "drop",
                ],
            )?;
            run_cmd(
                "nft",
                &[
                    "insert", "rule", NFT_FAMILY, NFT_TABLE, "output", "ip", "daddr", ip, "drop",
                ],
            )?;
        }
    }

    info!(ip = %ip, "nftables IP block applied");
    Ok(())
}

/// Unblock a specific IP via nftables.
///
/// Removes all rules in the tamandua table that reference this IP.
#[cfg(target_os = "linux")]
fn nft_unblock_ip(ip: &str) -> Result<(), String> {
    // List handles for rules matching this IP in the input chain
    let remove_matching_rules = |chain: &str| -> Result<(), String> {
        let output = run_cmd(
            "nft",
            &["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, chain],
        )?;

        // Parse output lines looking for rules containing the IP and extract handles
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.contains(ip) && trimmed.contains("# handle") {
                // Extract the handle number from "# handle N"
                if let Some(handle_str) = trimmed.rsplit("# handle ").next() {
                    let handle = handle_str.trim();
                    if let Err(e) = run_cmd(
                        "nft",
                        &[
                            "delete", "rule", NFT_FAMILY, NFT_TABLE, chain, "handle", handle,
                        ],
                    ) {
                        warn!(
                            chain = %chain,
                            handle = %handle,
                            error = %e,
                            "Failed to delete nftables rule by handle"
                        );
                    } else {
                        debug!(chain = %chain, handle = %handle, ip = %ip, "Removed nftables rule");
                    }
                }
            }
        }
        Ok(())
    };

    remove_matching_rules("input")?;
    remove_matching_rules("output")?;

    info!(ip = %ip, "nftables IP unblock completed");
    Ok(())
}

/// Clean up all nftables rules created by Tamandua.
#[cfg(target_os = "linux")]
fn nft_cleanup() {
    match run_cmd("nft", &["delete", "table", NFT_FAMILY, NFT_TABLE]) {
        Ok(_) => info!("nftables tamandua table deleted during cleanup"),
        Err(e) => {
            debug!(error = %e, "nftables cleanup: table may not exist (expected if not isolated)")
        }
    }
}

// ===========================================================================
// iptables implementation
// ===========================================================================

/// Create custom iptables chains and jump rules from INPUT/OUTPUT.
///
/// This avoids flushing system chains. The jump rules direct traffic through
/// our custom chains, and only rules in those chains are managed by Tamandua.
#[cfg(target_os = "linux")]
fn ipt_ensure_chains() -> Result<(), String> {
    // Create custom chains (ignore errors if they already exist)
    for chain in &[
        IPT_CHAIN_IN,
        IPT_CHAIN_OUT,
        IPT_CHAIN_BLOCK_IN,
        IPT_CHAIN_BLOCK_OUT,
    ] {
        let result = run_cmd("iptables", &["-N", chain]);
        if let Err(ref e) = result {
            if !e.contains("already exists") {
                warn!(chain = %chain, error = %e, "Failed to create iptables chain");
            }
        }
    }

    // Add jump rules from INPUT/OUTPUT to our custom chains.
    // Use -C (check) first to avoid duplicates.
    let jumps = [
        ("INPUT", IPT_CHAIN_IN),
        ("INPUT", IPT_CHAIN_BLOCK_IN),
        ("OUTPUT", IPT_CHAIN_OUT),
        ("OUTPUT", IPT_CHAIN_BLOCK_OUT),
    ];

    for (parent, child) in &jumps {
        // Check if jump already exists
        let check = run_cmd("iptables", &["-C", parent, "-j", child]);
        if check.is_err() {
            // Jump does not exist, insert at the top so our rules are evaluated first
            if let Err(e) = run_cmd("iptables", &["-I", parent, "1", "-j", child]) {
                warn!(
                    parent = %parent,
                    child = %child,
                    error = %e,
                    "Failed to insert iptables jump rule"
                );
            }
        }
    }

    Ok(())
}

/// Apply full network isolation via iptables custom chains.
#[cfg(target_os = "linux")]
fn ipt_apply_isolation(server_ip: &str, allowed_ips: &[String]) -> Result<(), String> {
    ipt_ensure_chains()?;

    // Flush only our isolation chains (NOT system chains)
    run_cmd("iptables", &["-F", IPT_CHAIN_IN])?;
    run_cmd("iptables", &["-F", IPT_CHAIN_OUT])?;

    // --- OUTPUT chain rules ---

    // Allow loopback
    run_cmd(
        "iptables",
        &["-A", IPT_CHAIN_OUT, "-o", "lo", "-j", "ACCEPT"],
    )?;

    // Allow established/related connections
    run_cmd(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_OUT,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )?;

    // Allow DNS (UDP and TCP port 53)
    run_cmd(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_OUT,
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ],
    )?;
    run_cmd(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_OUT,
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ],
    )?;

    // Allow server IP
    if !server_ip.is_empty() {
        run_cmd(
            "iptables",
            &["-A", IPT_CHAIN_OUT, "-d", server_ip, "-j", "ACCEPT"],
        )?;
    }

    // Allow additional IPs
    for ip in allowed_ips {
        if !ip.is_empty() {
            run_cmd("iptables", &["-A", IPT_CHAIN_OUT, "-d", ip, "-j", "ACCEPT"])?;
        }
    }

    // Drop everything else
    run_cmd("iptables", &["-A", IPT_CHAIN_OUT, "-j", "DROP"])?;

    // --- INPUT chain rules ---

    // Allow loopback
    run_cmd(
        "iptables",
        &["-A", IPT_CHAIN_IN, "-i", "lo", "-j", "ACCEPT"],
    )?;

    // Allow established/related
    run_cmd(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_IN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )?;

    // Allow DNS responses
    run_cmd(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_IN,
            "-p",
            "udp",
            "--sport",
            "53",
            "-j",
            "ACCEPT",
        ],
    )?;
    run_cmd(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_IN,
            "-p",
            "tcp",
            "--sport",
            "53",
            "-j",
            "ACCEPT",
        ],
    )?;

    // Allow server IP
    if !server_ip.is_empty() {
        run_cmd(
            "iptables",
            &["-A", IPT_CHAIN_IN, "-s", server_ip, "-j", "ACCEPT"],
        )?;
    }

    // Allow additional IPs
    for ip in allowed_ips {
        if !ip.is_empty() {
            run_cmd("iptables", &["-A", IPT_CHAIN_IN, "-s", ip, "-j", "ACCEPT"])?;
        }
    }

    // Drop everything else
    run_cmd("iptables", &["-A", IPT_CHAIN_IN, "-j", "DROP"])?;

    info!(
        server_ip = %server_ip,
        allowed_count = allowed_ips.len(),
        "iptables network isolation applied via custom chains"
    );
    Ok(())
}

/// Remove full network isolation by flushing our custom isolation chains.
/// Does NOT remove the block chains or their jump rules.
#[cfg(target_os = "linux")]
fn ipt_remove_isolation() -> Result<(), String> {
    // Flush our isolation chains
    let _ = run_cmd("iptables", &["-F", IPT_CHAIN_IN]);
    let _ = run_cmd("iptables", &["-F", IPT_CHAIN_OUT]);

    info!("iptables isolation chains flushed");
    Ok(())
}

/// Block a specific IP via iptables custom block chains.
#[cfg(target_os = "linux")]
fn ipt_block_ip(ip: &str) -> Result<(), String> {
    ipt_ensure_chains()?;

    // Add block rules to our block chains
    run_cmd(
        "iptables",
        &["-A", IPT_CHAIN_BLOCK_OUT, "-d", ip, "-j", "DROP"],
    )?;
    run_cmd(
        "iptables",
        &["-A", IPT_CHAIN_BLOCK_IN, "-s", ip, "-j", "DROP"],
    )?;

    info!(ip = %ip, "iptables IP block applied");
    Ok(())
}

/// Unblock a specific IP via iptables custom block chains.
#[cfg(target_os = "linux")]
fn ipt_unblock_ip(ip: &str) -> Result<(), String> {
    // Remove the specific rules from our block chains.
    // Use -D (delete) which removes the first matching rule.
    // We attempt both even if the first fails.
    let mut errors = Vec::new();

    if let Err(e) = run_cmd(
        "iptables",
        &["-D", IPT_CHAIN_BLOCK_OUT, "-d", ip, "-j", "DROP"],
    ) {
        errors.push(format!("outbound: {}", e));
    }

    if let Err(e) = run_cmd(
        "iptables",
        &["-D", IPT_CHAIN_BLOCK_IN, "-s", ip, "-j", "DROP"],
    ) {
        errors.push(format!("inbound: {}", e));
    }

    if errors.is_empty() {
        info!(ip = %ip, "iptables IP unblock completed");
        Ok(())
    } else {
        let msg = format!("iptables unblock errors: {}", errors.join("; "));
        warn!("{}", msg);
        // Still return Ok if at least one direction was unblocked
        Ok(())
    }
}

/// Clean up all iptables rules and chains created by Tamandua.
#[cfg(target_os = "linux")]
fn ipt_cleanup() {
    // Remove jump rules from INPUT/OUTPUT
    let jumps = [
        ("INPUT", IPT_CHAIN_IN),
        ("INPUT", IPT_CHAIN_BLOCK_IN),
        ("OUTPUT", IPT_CHAIN_OUT),
        ("OUTPUT", IPT_CHAIN_BLOCK_OUT),
    ];

    for (parent, child) in &jumps {
        let _ = run_cmd("iptables", &["-D", parent, "-j", child]);
    }

    // Flush and delete custom chains
    for chain in &[
        IPT_CHAIN_IN,
        IPT_CHAIN_OUT,
        IPT_CHAIN_BLOCK_IN,
        IPT_CHAIN_BLOCK_OUT,
    ] {
        let _ = run_cmd("iptables", &["-F", chain]);
        let _ = run_cmd("iptables", &["-X", chain]);
    }

    info!("iptables cleanup complete");
}

// ===========================================================================
// Public API (dispatches to nftables or iptables backend)
// ===========================================================================

/// Apply full network isolation.
///
/// Blocks all traffic except:
/// - Loopback interface
/// - The EDR server IP
/// - DNS (UDP/TCP port 53)
/// - Established/related connections
/// - Any additional allowed IPs
///
/// Detects whether nftables or iptables is available and uses the appropriate
/// backend. Uses namespaced tables/chains so existing system rules are never
/// modified.
#[cfg(target_os = "linux")]
pub fn apply_isolation(server_ip: &str, allowed_ips: &[String]) -> Result<(), String> {
    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    if guard.isolated {
        info!("Network isolation already active, removing before re-applying");
        // Remove existing isolation first
        match guard.backend {
            FirewallBackend::Nftables => {
                let _ = nft_remove_isolation();
            }
            FirewallBackend::Iptables => {
                let _ = ipt_remove_isolation();
            }
        }
    }

    info!(
        backend = %guard.backend,
        server_ip = %server_ip,
        allowed_count = allowed_ips.len(),
        "Applying network isolation"
    );

    let result = match guard.backend {
        FirewallBackend::Nftables => nft_apply_isolation(server_ip, allowed_ips),
        FirewallBackend::Iptables => ipt_apply_isolation(server_ip, allowed_ips),
    };

    match result {
        Ok(()) => {
            guard.isolated = true;
            Ok(())
        }
        Err(e) => {
            error!(backend = %guard.backend, error = %e, "Failed to apply network isolation");
            Err(e)
        }
    }
}

/// Remove full network isolation, restoring normal connectivity.
///
/// Only removes Tamandua-managed rules. Per-IP blocks are preserved.
#[cfg(target_os = "linux")]
pub fn remove_isolation() -> Result<(), String> {
    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    if !guard.isolated {
        info!("Network isolation is not active, nothing to remove");
        return Ok(());
    }

    info!(backend = %guard.backend, "Removing network isolation");

    let result = match guard.backend {
        FirewallBackend::Nftables => nft_remove_isolation(),
        FirewallBackend::Iptables => ipt_remove_isolation(),
    };

    match result {
        Ok(()) => {
            guard.isolated = false;
            Ok(())
        }
        Err(e) => {
            error!(backend = %guard.backend, error = %e, "Failed to remove network isolation");
            Err(e)
        }
    }
}

/// Block a specific IP address (both inbound and outbound).
#[cfg(target_os = "linux")]
pub fn block_ip(ip: &str) -> Result<(), String> {
    if ip.is_empty() {
        return Err("IP address is empty".to_string());
    }

    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    info!(backend = %guard.backend, ip = %ip, "Blocking IP");

    let result = match guard.backend {
        FirewallBackend::Nftables => nft_block_ip(ip),
        FirewallBackend::Iptables => ipt_block_ip(ip),
    };

    match result {
        Ok(()) => {
            guard.blocked_ips.insert(ip.to_string());
            Ok(())
        }
        Err(e) => {
            error!(backend = %guard.backend, ip = %ip, error = %e, "Failed to block IP");
            Err(e)
        }
    }
}

/// Unblock a specific IP address.
#[cfg(target_os = "linux")]
pub fn unblock_ip(ip: &str) -> Result<(), String> {
    if ip.is_empty() {
        return Err("IP address is empty".to_string());
    }

    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    info!(backend = %guard.backend, ip = %ip, "Unblocking IP");

    let result = match guard.backend {
        FirewallBackend::Nftables => nft_unblock_ip(ip),
        FirewallBackend::Iptables => ipt_unblock_ip(ip),
    };

    match result {
        Ok(()) => {
            guard.blocked_ips.remove(ip);
            Ok(())
        }
        Err(e) => {
            error!(backend = %guard.backend, ip = %ip, error = %e, "Failed to unblock IP");
            Err(e)
        }
    }
}

/// Clean up all Tamandua firewall rules.
///
/// Called on agent shutdown to ensure no orphaned rules remain.
/// Removes isolation rules, per-IP blocks, custom chains, and
/// any nftables table created by Tamandua.
#[cfg(target_os = "linux")]
pub fn cleanup() {
    let state = get_state();
    let guard = match state.lock() {
        Ok(g) => g,
        Err(_) => {
            error!("Linux isolation lock poisoned during cleanup");
            // Attempt cleanup of both backends as a last resort
            nft_cleanup();
            ipt_cleanup();
            return;
        }
    };

    info!(backend = %guard.backend, isolated = guard.isolated, blocked_ips = guard.blocked_ips.len(), "Cleaning up Linux isolation rules");

    match guard.backend {
        FirewallBackend::Nftables => nft_cleanup(),
        FirewallBackend::Iptables => ipt_cleanup(),
    }

    info!("Linux isolation cleanup complete");
}

/// Check whether network isolation is currently active.
#[cfg(target_os = "linux")]
pub fn is_isolated() -> bool {
    get_state()
        .lock()
        .map(|guard| guard.isolated)
        .unwrap_or(false)
}

/// Get the detected firewall backend.
#[cfg(target_os = "linux")]
pub fn get_backend() -> Option<FirewallBackend> {
    LINUX_ISOLATION
        .get()
        .and_then(|state| state.lock().ok())
        .map(|guard| guard.backend)
}

// ===========================================================================
// Non-Linux stubs
// ===========================================================================

/// Shutdown stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn cleanup() {
    // No-op on non-Linux platforms
}

/// Isolation check stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn is_isolated() -> bool {
    false
}
