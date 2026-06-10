//! XPC service introspection and monitoring
//!
//! Monitors XPC (Inter-Process Communication) services on macOS for:
//! - New XPC service registrations
//! - XPC connections between processes
//! - Suspicious privilege escalation via XPC
//! - Unauthorized XPC service creation
//!
//! ## XPC Service Types
//! - **Launch Daemons**: System-level services (launchd plist in /Library/LaunchDaemons)
//! - **Launch Agents**: User-level services (launchd plist in /Library/LaunchAgents)
//! - **Application XPC Services**: Bundled within app (.app/Contents/XPCServices)
//!
//! ## Detection Strategies
//! 1. Parse `launchctl list` output to enumerate active XPC services
//! 2. Monitor launchd plist directories for new service registrations
//! 3. Track XPC connections via process command-line arguments and environment
//! 4. Correlate with process events to detect privilege escalation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{debug, info, warn};

/// XPC service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpcService {
    /// Service label (e.g., com.apple.xpc.example)
    pub label: String,
    /// Process ID (if running, 0 if not running, -1 if unknown)
    pub pid: i32,
    /// Last exit status (0 if not exited, -1 if unknown)
    pub status: i32,
    /// Service type (daemon, agent, application)
    pub service_type: XpcServiceType,
    /// Path to the service executable (if available)
    pub executable_path: Option<String>,
    /// Path to the launchd plist file (if available)
    pub plist_path: Option<String>,
    /// Whether the service is currently loaded
    pub is_loaded: bool,
}

/// XPC service type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XpcServiceType {
    /// System daemon (/Library/LaunchDaemons, runs as root)
    SystemDaemon,
    /// System agent (/Library/LaunchAgents, runs per-user)
    SystemAgent,
    /// User agent (~/Library/LaunchAgents)
    UserAgent,
    /// Application XPC service (.app/Contents/XPCServices)
    ApplicationService,
    /// Unknown service type
    Unknown,
}

/// XPC connection (logical representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpcConnection {
    /// Client process ID
    pub client_pid: u32,
    /// Client process name
    pub client_name: String,
    /// Client process path
    pub client_path: String,
    /// XPC service name being connected to
    pub service_name: String,
    /// Server process ID (if known)
    pub server_pid: Option<u32>,
    /// Server process name (if known)
    pub server_name: Option<String>,
    /// Timestamp of connection
    pub timestamp: u64,
}

/// Enumerate all XPC services visible via `launchctl list`
///
/// Parses the output of `launchctl list` to extract service labels, PIDs, and status codes.
///
/// ## Output format
/// ```text
/// PID     Status  Label
/// -       0       com.apple.example.service
/// 12345   0       com.apple.another.service
/// ```
///
/// ## Returns
/// * `Ok(Vec<XpcService>)` - List of discovered XPC services
/// * `Err(String)` - Command execution error
pub fn enumerate_xpc_services() -> Result<Vec<XpcService>, String> {
    debug!("Enumerating XPC services via launchctl list");

    let output = Command::new("launchctl")
        .arg("list")
        .output()
        .map_err(|e| format!("Failed to execute launchctl: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "launchctl list failed with status: {}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();

    for (idx, line) in stdout.lines().enumerate() {
        // Skip header line
        if idx == 0 {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let pid_str = parts[0];
        let status_str = parts[1];
        let label = parts[2].to_string();

        let pid = if pid_str == "-" {
            0
        } else {
            pid_str.parse::<i32>().unwrap_or(-1)
        };

        let status = status_str.parse::<i32>().unwrap_or(-1);

        // Determine service type from label prefix
        let service_type = classify_service_type(&label);

        services.push(XpcService {
            label,
            pid,
            status,
            service_type,
            executable_path: None, // Requires plist parsing
            plist_path: None,      // Requires filesystem search
            is_loaded: pid > 0,
        });
    }

    debug!(count = services.len(), "Enumerated XPC services");
    Ok(services)
}

/// Classify service type based on label and known conventions
fn classify_service_type(label: &str) -> XpcServiceType {
    // System daemons typically use reverse-DNS notation starting with com.apple
    // and are loaded from /Library/LaunchDaemons
    if label.starts_with("com.apple.") {
        // Heuristic: if label contains ".xpc." or ".agent.", classify accordingly
        if label.contains(".agent.") {
            XpcServiceType::SystemAgent
        } else {
            XpcServiceType::SystemDaemon
        }
    } else if label.starts_with("application.") {
        XpcServiceType::ApplicationService
    } else {
        // User agents and third-party services
        XpcServiceType::UserAgent
    }
}

/// Get detailed service information by label
///
/// Uses `launchctl print` to extract full service details including executable path,
/// program arguments, environment variables, and security attributes.
///
/// ## Arguments
/// * `label` - Service label (e.g., "com.apple.example")
///
/// ## Returns
/// * `Ok(HashMap<String, String>)` - Key-value pairs extracted from launchctl print
/// * `Err(String)` - Command execution error
pub fn get_service_details(label: &str) -> Result<HashMap<String, String>, String> {
    debug!(label = %label, "Getting XPC service details");

    let output = Command::new("launchctl")
        .arg("print")
        .arg(format!("gui/{}/", std::process::id())) // User domain for agents
        .arg(label)
        .output()
        .map_err(|e| format!("Failed to execute launchctl print: {}", e))?;

    if !output.status.success() {
        // Try system domain
        let output = Command::new("launchctl")
            .arg("print")
            .arg("system/")
            .arg(label)
            .output()
            .map_err(|e| format!("Failed to execute launchctl print (system): {}", e))?;

        if !output.status.success() {
            return Err(format!("launchctl print failed for label: {}", label));
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut details = HashMap::new();

    // Parse key-value pairs from output (simplified parser)
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            details.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }

    Ok(details)
}

/// Monitor launchd plist directories for new service registrations
///
/// Watches the following directories:
/// - /Library/LaunchDaemons (system daemons)
/// - /Library/LaunchAgents (system agents)
/// - ~/Library/LaunchAgents (user agents) - CRITICAL for persistence detection
///
/// Returns newly created plist files since last scan.
pub fn scan_launchd_plists() -> Result<Vec<std::path::PathBuf>, String> {
    let mut dirs = vec![
        std::path::PathBuf::from("/Library/LaunchDaemons"),
        std::path::PathBuf::from("/Library/LaunchAgents"),
    ];

    // Add user-specific directory - CRITICAL: This is the most common persistence location
    if let Some(home) = dirs::home_dir() {
        let user_agents = home.join("Library").join("LaunchAgents");
        if user_agents.exists() {
            dirs.push(user_agents);
        }

        // Also check per-user overrides (rare but possible attack vector)
        let user_daemons = home.join("Library").join("LaunchDaemons");
        if user_daemons.exists() {
            dirs.push(user_daemons);
        }
    }

    let mut plist_files = Vec::new();

    for dir in &dirs {
        if !dir.exists() {
            continue;
        }

        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("plist") {
                        plist_files.push(path);
                    }
                }
            }
            Err(e) => {
                // Permission errors on system directories are expected for non-root
                if dir.starts_with("/Library") {
                    debug!(error = %e, dir = %dir.display(), "Cannot read system launchd directory (expected without root)");
                } else {
                    warn!(error = %e, dir = %dir.display(), "Failed to read launchd directory");
                }
            }
        }
    }

    info!(
        count = plist_files.len(),
        dirs = dirs.len(),
        "Scanned launchd plist directories"
    );
    Ok(plist_files)
}

/// Parsed launchd plist configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LaunchdPlistConfig {
    /// Service label (required)
    pub label: String,
    /// Path to the plist file
    pub plist_path: String,
    /// Program to execute (if single executable)
    pub program: Option<String>,
    /// Program arguments (if using ProgramArguments)
    pub program_arguments: Vec<String>,
    /// Whether to run at load (persistence indicator)
    pub run_at_load: bool,
    /// Whether to keep alive (respawn on exit)
    pub keep_alive: bool,
    /// User to run as
    pub user_name: Option<String>,
    /// Group to run as
    pub group_name: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
    /// Environment variables
    pub environment_variables: HashMap<String, String>,
    /// Standard output path
    pub standard_out_path: Option<String>,
    /// Standard error path
    pub standard_error_path: Option<String>,
    /// Start interval (seconds)
    pub start_interval: Option<u64>,
    /// Watch paths (file-triggered execution)
    pub watch_paths: Vec<String>,
    /// Queue directories
    pub queue_directories: Vec<String>,
    /// Mach services registered
    pub mach_services: Vec<String>,
    /// Is disabled
    pub disabled: bool,
    /// Root directory (chroot)
    pub root_directory: Option<String>,
    /// Sockets (for on-demand activation)
    pub sockets: Vec<String>,
    /// Raw plist for additional inspection
    pub raw_keys: Vec<String>,
}

/// Parse a launchd plist file to extract service configuration
///
/// Returns key fields like Label, Program, ProgramArguments, RunAtLoad, etc.
/// Handles both XML and binary plist formats.
pub fn parse_launchd_plist<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<LaunchdPlistConfig, String> {
    let path = path.as_ref();
    debug!(path = %path.display(), "Parsing launchd plist");

    // Read and parse the plist file (handles both XML and binary formats)
    let plist_value: plist::Value = plist::from_file(path)
        .map_err(|e| format!("Failed to parse plist {}: {}", path.display(), e))?;

    let dict = plist_value
        .as_dictionary()
        .ok_or_else(|| format!("Plist root is not a dictionary: {}", path.display()))?;

    let mut config = LaunchdPlistConfig {
        plist_path: path.display().to_string(),
        ..Default::default()
    };

    // Extract Label (required)
    config.label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Fallback to filename without extension
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string()
        });

    // Extract Program
    config.program = dict
        .get("Program")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract ProgramArguments
    if let Some(args) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
        config.program_arguments = args
            .iter()
            .filter_map(|v| v.as_string().map(|s| s.to_string()))
            .collect();
    }

    // Extract RunAtLoad (persistence indicator!)
    config.run_at_load = dict
        .get("RunAtLoad")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    // Extract KeepAlive
    config.keep_alive = match dict.get("KeepAlive") {
        Some(plist::Value::Boolean(b)) => *b,
        Some(plist::Value::Dictionary(_)) => true, // Complex KeepAlive dict means it's enabled
        _ => false,
    };

    // Extract UserName
    config.user_name = dict
        .get("UserName")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract GroupName
    config.group_name = dict
        .get("GroupName")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract WorkingDirectory
    config.working_directory = dict
        .get("WorkingDirectory")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract EnvironmentVariables
    if let Some(env) = dict
        .get("EnvironmentVariables")
        .and_then(|v| v.as_dictionary())
    {
        for (key, value) in env {
            if let Some(val_str) = value.as_string() {
                config
                    .environment_variables
                    .insert(key.clone(), val_str.to_string());
            }
        }
    }

    // Extract StandardOutPath
    config.standard_out_path = dict
        .get("StandardOutPath")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract StandardErrorPath
    config.standard_error_path = dict
        .get("StandardErrorPath")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract StartInterval
    config.start_interval = dict
        .get("StartInterval")
        .and_then(|v| v.as_unsigned_integer());

    // Extract WatchPaths (file-triggered persistence)
    if let Some(paths) = dict.get("WatchPaths").and_then(|v| v.as_array()) {
        config.watch_paths = paths
            .iter()
            .filter_map(|v| v.as_string().map(|s| s.to_string()))
            .collect();
    }

    // Extract QueueDirectories
    if let Some(dirs) = dict.get("QueueDirectories").and_then(|v| v.as_array()) {
        config.queue_directories = dirs
            .iter()
            .filter_map(|v| v.as_string().map(|s| s.to_string()))
            .collect();
    }

    // Extract MachServices
    if let Some(services) = dict.get("MachServices").and_then(|v| v.as_dictionary()) {
        config.mach_services = services.keys().cloned().collect();
    }

    // Extract Disabled
    config.disabled = dict
        .get("Disabled")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    // Extract RootDirectory (chroot - suspicious if set)
    config.root_directory = dict
        .get("RootDirectory")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Extract Sockets
    if let Some(sockets) = dict.get("Sockets").and_then(|v| v.as_dictionary()) {
        config.sockets = sockets.keys().cloned().collect();
    }

    // Store all keys for additional inspection
    config.raw_keys = dict.keys().cloned().collect();

    debug!(
        label = %config.label,
        run_at_load = config.run_at_load,
        keep_alive = config.keep_alive,
        program = ?config.program,
        "Parsed launchd plist"
    );

    Ok(config)
}

/// Parse a launchd plist and return a simplified HashMap for backward compatibility
pub fn parse_launchd_plist_simple<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<HashMap<String, String>, String> {
    let config = parse_launchd_plist(path)?;

    let mut map = HashMap::new();
    map.insert("label".to_string(), config.label);
    map.insert("plist_path".to_string(), config.plist_path);

    if let Some(program) = config.program {
        map.insert("program".to_string(), program);
    }
    if !config.program_arguments.is_empty() {
        map.insert(
            "program_arguments".to_string(),
            config.program_arguments.join(" "),
        );
    }
    map.insert("run_at_load".to_string(), config.run_at_load.to_string());
    map.insert("keep_alive".to_string(), config.keep_alive.to_string());
    if let Some(user) = config.user_name {
        map.insert("user_name".to_string(), user);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_classification() {
        assert_eq!(
            classify_service_type("com.apple.example.daemon"),
            XpcServiceType::SystemDaemon
        );
        assert_eq!(
            classify_service_type("com.apple.example.agent.helper"),
            XpcServiceType::SystemAgent
        );
        assert_eq!(
            classify_service_type("application.com.example.app.service"),
            XpcServiceType::ApplicationService
        );
    }

    #[test]
    fn parses_launchd_persistence_and_mach_service_fields() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.persistence</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>id</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key><false/>
  </dict>
  <key>MachServices</key>
  <dict>
    <key>com.example.persistence.xpc</key><true/>
  </dict>
  <key>WatchPaths</key>
  <array>
    <string>/Users/shared/drop</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/tmp:/usr/bin:/bin</string>
  </dict>
</dict>
</plist>
"#,
        )
        .unwrap();

        let config = parse_launchd_plist(file.path()).unwrap();
        assert_eq!(config.label, "com.example.persistence");
        assert_eq!(config.program_arguments, vec!["/bin/sh", "-c", "id"]);
        assert!(config.run_at_load);
        assert!(config.keep_alive);
        assert_eq!(
            config.mach_services,
            vec!["com.example.persistence.xpc".to_string()]
        );
        assert_eq!(config.watch_paths, vec!["/Users/shared/drop".to_string()]);
        assert_eq!(
            config.environment_variables.get("PATH").map(String::as_str),
            Some("/tmp:/usr/bin:/bin")
        );
    }
}
