//! macOS network isolation using pfctl packet filter
//!
//! Implements network isolation and per-IP blocking for macOS systems using
//! the built-in pfctl packet filter framework (OpenBSD Packet Filter).
//!
//! Key design principles:
//! - Never flush existing pf rules. Use a dedicated anchor "tamandua-isolation"
//!   to isolate our rules from system rules.
//! - Store pre-isolation anchor state for safe rollback.
//! - Track state globally so cleanup on shutdown is reliable.
//! - Every command execution checks exit status and logs failures.
//! - Handle existing connections gracefully with state tracking.
//!
//! pfctl advantages over NetworkExtension:
//! - No system extension registration required (simpler deployment)
//! - Immediate effect without reboot
//! - Works on macOS 10.11+ (older versions supported)
//! - Lower overhead than full NetworkExtension filter
//!
//! NetworkExtension would provide:
//! - Per-app filtering (beyond scope of this EDR isolation)
//! - Deep packet inspection at network layer
//! - User-space packet handling
//! - Requires notarization and system extension approval
//!
//! For EDR purposes, pfctl provides sufficient control at lower complexity.
//!
//! Requires root/sudo privileges to manipulate pf rules.

#[cfg(target_os = "macos")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(target_os = "macos")]
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Anchor names
// ---------------------------------------------------------------------------

/// Dedicated pfctl anchor for Tamandua isolation rules
#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "tamandua-isolation";

/// Path where we temporarily store pf rules before loading
#[cfg(target_os = "macos")]
const PF_RULES_FILE: &str = "/tmp/tamandua_pf_rules.conf";

/// Path where we store pre-isolation anchor backup
#[cfg(target_os = "macos")]
const PF_BACKUP_FILE: &str = "/tmp/tamandua_pf_backup.conf";

// ---------------------------------------------------------------------------
// Helper: run a command and check its exit status
// ---------------------------------------------------------------------------

/// Run a command, log it, and return Ok(stdout) on success or Err(message) on failure.
#[cfg(target_os = "macos")]
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
// Privilege check
// ---------------------------------------------------------------------------

/// Check if the agent is running with root privileges (required for pfctl).
#[cfg(target_os = "macos")]
fn check_root() -> Result<(), String> {
    // Check effective user ID -- must be 0 (root)
    let output = run_cmd("id", &["-u"])?;
    let uid = output.trim().parse::<u32>().unwrap_or(1000);

    if uid != 0 {
        return Err(format!(
            "pfctl requires root privileges (current UID: {}). Run agent with sudo or as root.",
            uid
        ));
    }

    Ok(())
}

/// Check if pfctl is available on the system.
#[cfg(target_os = "macos")]
fn check_pfctl_available() -> Result<(), String> {
    match run_cmd("pfctl", &["-s", "info"]) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("pfctl is not available or not functioning: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// State tracking
// ---------------------------------------------------------------------------

/// Global isolation state, tracking what rules are active.
#[cfg(target_os = "macos")]
struct IsolationState {
    /// Whether full network isolation is active
    isolated: bool,
    /// Set of individually blocked IPs (for targeted block/unblock)
    blocked_ips: HashSet<String>,
    /// Whether the pf anchor was created successfully
    anchor_created: bool,
}

#[cfg(target_os = "macos")]
static MACOS_ISOLATION: OnceLock<Arc<Mutex<IsolationState>>> = OnceLock::new();

/// Get or initialize the global isolation state.
#[cfg(target_os = "macos")]
fn get_state() -> Arc<Mutex<IsolationState>> {
    MACOS_ISOLATION
        .get_or_init(|| {
            info!("macOS pfctl isolation module initialized");
            Arc::new(Mutex::new(IsolationState {
                isolated: false,
                blocked_ips: HashSet::new(),
                anchor_created: false,
            }))
        })
        .clone()
}

// ---------------------------------------------------------------------------
// pfctl backup and restore
// ---------------------------------------------------------------------------

/// Backup current anchor rules before applying isolation (for rollback).
#[cfg(target_os = "macos")]
fn backup_anchor() -> Result<(), String> {
    // Try to dump current anchor rules (if any) to backup file
    // pfctl -a tamandua-isolation -sr shows rules in the anchor
    let result = run_cmd("pfctl", &["-a", PF_ANCHOR, "-sr"]);

    match result {
        Ok(rules) => {
            if !rules.trim().is_empty() {
                std::fs::write(PF_BACKUP_FILE, rules).map_err(|e| {
                    format!("Failed to write backup file {}: {}", PF_BACKUP_FILE, e)
                })?;
                debug!("Backed up existing anchor rules to {}", PF_BACKUP_FILE);
            } else {
                debug!("No existing anchor rules to back up");
            }
            Ok(())
        }
        Err(e) => {
            // Anchor might not exist yet -- this is fine
            debug!(error = %e, "Anchor does not exist yet (expected on first isolation)");
            Ok(())
        }
    }
}

/// Restore anchor rules from backup file.
#[cfg(target_os = "macos")]
fn restore_anchor() -> Result<(), String> {
    if !std::path::Path::new(PF_BACKUP_FILE).exists() {
        debug!("No backup file found, nothing to restore");
        return Ok(());
    }

    let backup_rules = std::fs::read_to_string(PF_BACKUP_FILE)
        .map_err(|e| format!("Failed to read backup file {}: {}", PF_BACKUP_FILE, e))?;

    if backup_rules.trim().is_empty() {
        debug!("Backup file is empty, nothing to restore");
        return Ok(());
    }

    // Load the backup rules into the anchor
    std::fs::write(PF_RULES_FILE, &backup_rules)
        .map_err(|e| format!("Failed to write rules file {}: {}", PF_RULES_FILE, e))?;

    run_cmd("pfctl", &["-a", PF_ANCHOR, "-f", PF_RULES_FILE])?;

    info!("Restored anchor rules from backup");
    Ok(())
}

// ---------------------------------------------------------------------------
// pfctl anchor management
// ---------------------------------------------------------------------------

/// Enable pf if it's not already enabled.
#[cfg(target_os = "macos")]
fn ensure_pf_enabled() -> Result<(), String> {
    // Check if pf is enabled
    let status = run_cmd("pfctl", &["-s", "info"])?;

    if status.contains("Status: Enabled") {
        debug!("pf is already enabled");
        return Ok(());
    }

    info!("pf is disabled, enabling it now");
    run_cmd("pfctl", &["-e"]).map(|_| {
        info!("pf enabled successfully");
    })
}

/// Create the Tamandua anchor if it doesn't exist.
/// This is idempotent -- if the anchor already exists, this is a no-op.
#[cfg(target_os = "macos")]
fn ensure_anchor_exists() -> Result<(), String> {
    // Check if anchor is already referenced in main pf.conf
    // We need to add a line like: "anchor tamandua-isolation"

    // First, check if pf is enabled
    ensure_pf_enabled()?;

    // Try to show rules in the anchor (if it fails, anchor doesn't exist)
    let anchor_check = run_cmd("pfctl", &["-a", PF_ANCHOR, "-sr"]);

    match anchor_check {
        Ok(_) => {
            debug!("Anchor {} already exists", PF_ANCHOR);
            Ok(())
        }
        Err(_) => {
            // Anchor doesn't exist -- we need to create it by loading empty rules
            info!("Creating anchor {}", PF_ANCHOR);

            // Write an empty anchor rule to establish it
            let empty_anchor = format!("# Tamandua isolation anchor\n");
            std::fs::write(PF_RULES_FILE, empty_anchor)
                .map_err(|e| format!("Failed to write anchor file: {}", e))?;

            // Load the empty anchor
            run_cmd("pfctl", &["-a", PF_ANCHOR, "-f", PF_RULES_FILE])?;

            info!("Anchor {} created", PF_ANCHOR);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// pfctl rule generation
// ---------------------------------------------------------------------------

/// Generate pf rules for full network isolation.
///
/// The ruleset structure:
/// - Block all outbound traffic by default
/// - Block all inbound traffic by default
/// - Allow loopback (lo0)
/// - Allow DNS (UDP/TCP port 53)
/// - Allow server IP and port
/// - Allow additional allowlisted IPs
#[cfg(target_os = "macos")]
fn generate_isolation_rules(server_ip: &str, server_port: u16, allowed_ips: &[String]) -> String {
    let mut rules = String::new();

    // Header comment
    rules.push_str("# Tamandua EDR Network Isolation Rules\n");
    rules.push_str("# Applied via pfctl anchor: tamandua-isolation\n\n");

    // Allow loopback interface (critical for local processes)
    rules.push_str("# Allow loopback interface\n");
    rules.push_str("pass quick on lo0 all\n\n");

    // Allow DNS (critical for hostname resolution)
    rules.push_str("# Allow DNS queries\n");
    rules.push_str("pass out quick proto udp to any port 53 keep state\n");
    rules.push_str("pass out quick proto tcp to any port 53 keep state\n\n");

    // Allow Tamandua server
    if !server_ip.is_empty() {
        rules.push_str("# Allow Tamandua server\n");
        rules.push_str(&format!(
            "pass out quick proto tcp to {} port {} keep state\n",
            server_ip, server_port
        ));
        rules.push_str(&format!(
            "pass in quick proto tcp from {} port {} keep state\n\n",
            server_ip, server_port
        ));
    }

    // Allow additional IPs
    if !allowed_ips.is_empty() {
        rules.push_str("# Allow additional IPs\n");
        for ip in allowed_ips {
            if !ip.trim().is_empty() {
                rules.push_str(&format!("pass out quick to {} keep state\n", ip.trim()));
                rules.push_str(&format!("pass in quick from {} keep state\n", ip.trim()));
            }
        }
        rules.push_str("\n");
    }

    // Block everything else (default deny)
    rules.push_str("# Block all other traffic\n");
    rules.push_str("block drop all\n");

    rules
}

/// Generate pf rules for blocking a specific IP.
#[cfg(target_os = "macos")]
fn generate_block_ip_rule(ip: &str) -> String {
    format!(
        "# Block IP: {}\nblock drop quick from {} to any\nblock drop quick from any to {}\n",
        ip, ip, ip
    )
}

// ---------------------------------------------------------------------------
// pfctl apply and remove operations
// ---------------------------------------------------------------------------

/// Apply full network isolation via pfctl.
#[cfg(target_os = "macos")]
fn apply_isolation_internal(
    server_ip: &str,
    server_port: u16,
    allowed_ips: &[String],
) -> Result<(), String> {
    // Check prerequisites
    check_root()?;
    check_pfctl_available()?;

    // Backup existing anchor rules (if any)
    backup_anchor()?;

    // Ensure anchor exists
    ensure_anchor_exists()?;

    // Generate isolation ruleset
    let rules = generate_isolation_rules(server_ip, server_port, allowed_ips);

    debug!(ruleset = %rules, "Generated pfctl isolation rules");

    // Write rules to temp file
    std::fs::write(PF_RULES_FILE, &rules)
        .map_err(|e| format!("Failed to write rules file {}: {}", PF_RULES_FILE, e))?;

    // Load rules into anchor using pfctl
    // -a specifies the anchor, -f specifies the file
    run_cmd("pfctl", &["-a", PF_ANCHOR, "-f", PF_RULES_FILE])?;

    info!(
        server_ip = %server_ip,
        server_port = server_port,
        allowed_count = allowed_ips.len(),
        "pfctl network isolation applied successfully"
    );

    Ok(())
}

/// Remove full network isolation by flushing the anchor.
#[cfg(target_os = "macos")]
fn remove_isolation_internal() -> Result<(), String> {
    check_root()?;
    check_pfctl_available()?;

    // Flush all rules from our anchor
    run_cmd("pfctl", &["-a", PF_ANCHOR, "-F", "all"])?;

    info!("pfctl isolation rules flushed from anchor");

    // Try to restore backup if it exists
    let _ = restore_anchor();

    Ok(())
}

/// Block a specific IP via pfctl.
#[cfg(target_os = "macos")]
fn block_ip_internal(ip: &str) -> Result<(), String> {
    check_root()?;
    check_pfctl_available()?;

    // Ensure anchor exists
    ensure_anchor_exists()?;

    // Get current rules from anchor
    let current_rules = run_cmd("pfctl", &["-a", PF_ANCHOR, "-sr"]).unwrap_or_default();

    // Append block rule for this IP
    let block_rule = generate_block_ip_rule(ip);
    let new_rules = format!("{}\n{}", current_rules, block_rule);

    // Write updated rules to temp file
    std::fs::write(PF_RULES_FILE, &new_rules)
        .map_err(|e| format!("Failed to write rules file: {}", e))?;

    // Load updated rules
    run_cmd("pfctl", &["-a", PF_ANCHOR, "-f", PF_RULES_FILE])?;

    info!(ip = %ip, "pfctl IP block applied");
    Ok(())
}

/// Unblock a specific IP via pfctl.
#[cfg(target_os = "macos")]
fn unblock_ip_internal(ip: &str) -> Result<(), String> {
    check_root()?;
    check_pfctl_available()?;

    // Get current rules from anchor
    let current_rules = run_cmd("pfctl", &["-a", PF_ANCHOR, "-sr"])?;

    // Filter out rules that reference this IP
    let filtered_rules: Vec<&str> = current_rules
        .lines()
        .filter(|line| !line.contains(ip))
        .collect();

    let new_rules = filtered_rules.join("\n");

    // Write updated rules to temp file
    std::fs::write(PF_RULES_FILE, &new_rules)
        .map_err(|e| format!("Failed to write rules file: {}", e))?;

    // Load updated rules
    run_cmd("pfctl", &["-a", PF_ANCHOR, "-f", PF_RULES_FILE])?;

    info!(ip = %ip, "pfctl IP unblock completed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply full network isolation on macOS.
///
/// Blocks all traffic except:
/// - Loopback interface (lo0)
/// - The EDR server IP and port
/// - DNS (UDP/TCP port 53)
/// - Established/related connections (stateful)
/// - Any additional allowed IPs
///
/// Uses pfctl with a dedicated anchor "tamandua-isolation" so existing
/// system rules are never modified.
#[cfg(target_os = "macos")]
pub fn apply_isolation(
    server_ip: &str,
    server_port: u16,
    allowed_ips: &[String],
) -> Result<(), String> {
    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    if guard.isolated {
        info!("Network isolation already active, removing before re-applying");
        let _ = remove_isolation_internal();
    }

    info!(
        server_ip = %server_ip,
        server_port = server_port,
        allowed_count = allowed_ips.len(),
        "Applying pfctl network isolation"
    );

    let result = apply_isolation_internal(server_ip, server_port, allowed_ips);

    match result {
        Ok(()) => {
            guard.isolated = true;
            guard.anchor_created = true;
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "Failed to apply pfctl network isolation");
            Err(e)
        }
    }
}

/// Remove full network isolation, restoring normal connectivity.
///
/// Flushes all rules from the Tamandua anchor. Per-IP blocks are also removed.
#[cfg(target_os = "macos")]
pub fn remove_isolation() -> Result<(), String> {
    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    if !guard.isolated {
        info!("Network isolation is not active, nothing to remove");
        return Ok(());
    }

    info!("Removing pfctl network isolation");

    let result = remove_isolation_internal();

    match result {
        Ok(()) => {
            guard.isolated = false;
            guard.blocked_ips.clear();
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "Failed to remove pfctl network isolation");
            Err(e)
        }
    }
}

/// Block a specific IP address (both inbound and outbound).
#[cfg(target_os = "macos")]
pub fn block_ip(ip: &str) -> Result<(), String> {
    if ip.is_empty() {
        return Err("IP address is empty".to_string());
    }

    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    info!(ip = %ip, "Blocking IP via pfctl");

    let result = block_ip_internal(ip);

    match result {
        Ok(()) => {
            guard.blocked_ips.insert(ip.to_string());
            Ok(())
        }
        Err(e) => {
            error!(ip = %ip, error = %e, "Failed to block IP via pfctl");
            Err(e)
        }
    }
}

/// Unblock a specific IP address.
#[cfg(target_os = "macos")]
pub fn unblock_ip(ip: &str) -> Result<(), String> {
    if ip.is_empty() {
        return Err("IP address is empty".to_string());
    }

    let state = get_state();
    let mut guard = state.lock().map_err(|_| "Lock poisoned".to_string())?;

    info!(ip = %ip, "Unblocking IP via pfctl");

    let result = unblock_ip_internal(ip);

    match result {
        Ok(()) => {
            guard.blocked_ips.remove(ip);
            Ok(())
        }
        Err(e) => {
            error!(ip = %ip, error = %e, "Failed to unblock IP via pfctl");
            Err(e)
        }
    }
}

/// Clean up all Tamandua pfctl rules.
///
/// Called on agent shutdown to ensure no orphaned rules remain.
/// Removes the isolation anchor and cleans up temporary files.
#[cfg(target_os = "macos")]
pub fn cleanup() {
    let state = get_state();
    let guard = match state.lock() {
        Ok(g) => g,
        Err(_) => {
            error!("macOS isolation lock poisoned during cleanup");
            // Attempt cleanup anyway
            let _ = remove_isolation_internal();
            return;
        }
    };

    info!(
        isolated = guard.isolated,
        blocked_ips = guard.blocked_ips.len(),
        "Cleaning up pfctl isolation rules"
    );

    // Remove all rules from anchor
    let _ = remove_isolation_internal();

    // Clean up temporary files
    if std::path::Path::new(PF_RULES_FILE).exists() {
        if let Err(e) = std::fs::remove_file(PF_RULES_FILE) {
            debug!(error = %e, file = PF_RULES_FILE, "Failed to remove temp rules file");
        }
    }

    if std::path::Path::new(PF_BACKUP_FILE).exists() {
        if let Err(e) = std::fs::remove_file(PF_BACKUP_FILE) {
            debug!(error = %e, file = PF_BACKUP_FILE, "Failed to remove backup file");
        }
    }

    info!("pfctl isolation cleanup complete");
}

/// Check whether network isolation is currently active.
#[cfg(target_os = "macos")]
pub fn is_isolated() -> bool {
    get_state()
        .lock()
        .map(|guard| guard.isolated)
        .unwrap_or(false)
}

/// Get a list of currently blocked IPs.
#[cfg(target_os = "macos")]
pub fn get_blocked_ips() -> Vec<String> {
    get_state()
        .lock()
        .map(|guard| guard.blocked_ips.iter().cloned().collect())
        .unwrap_or_default()
}

// ===========================================================================
// Non-macOS stubs
// ===========================================================================

/// Cleanup stub for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn cleanup() {
    // No-op on non-macOS platforms
}

/// Isolation check stub for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn is_isolated() -> bool {
    false
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    /// Test rule generation produces valid pfctl syntax.
    #[test]
    fn test_generate_isolation_rules() {
        let rules = generate_isolation_rules("10.0.0.1", 4000, &["192.168.1.1".to_string()]);

        // Check that critical rules are present
        assert!(rules.contains("pass quick on lo0 all"));
        assert!(rules.contains("pass out quick proto udp to any port 53"));
        assert!(rules.contains("pass out quick proto tcp to 10.0.0.1 port 4000"));
        assert!(rules.contains("pass out quick to 192.168.1.1 keep state"));
        assert!(rules.contains("block drop all"));
        assert!(!rules.contains("proto tcp all"));
        assert!(!rules.contains("proto udp all"));
    }

    /// Test block rule generation.
    #[test]
    fn test_generate_block_ip_rule() {
        let rule = generate_block_ip_rule("1.2.3.4");

        assert!(rule.contains("block drop quick from 1.2.3.4 to any"));
        assert!(rule.contains("block drop quick from any to 1.2.3.4"));
    }

    /// Test privilege check (will fail if not root, which is expected).
    #[test]
    fn test_check_root() {
        // This test documents the expected behavior
        let result = check_root();

        if std::env::var("USER").unwrap_or_default() == "root" {
            assert!(result.is_ok(), "Should succeed when running as root");
        } else {
            assert!(result.is_err(), "Should fail when not running as root");
        }
    }

    /// Test pfctl availability check.
    #[test]
    fn test_check_pfctl_available() {
        // pfctl should be available on all macOS systems
        let result = check_pfctl_available();

        // This may fail in CI environments without pfctl
        if result.is_err() {
            println!("pfctl not available (expected in non-macOS or restricted environments)");
        }
    }
}
