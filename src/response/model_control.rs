//! Model control commands for AI/ML model isolation and management
//!
//! This module handles commands from the backend to isolate, release, or
//! kill ML model processes on the agent. It provides platform-specific
//! implementations for network blocking, process suspension, and memory
//! wiping.

use crate::transport::CommandResult;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Global model tracker for active models
static MODEL_TRACKER: LazyLock<DashMap<String, ModelInfo>> = LazyLock::new(DashMap::new);

/// Global isolated models set
static ISOLATED_MODELS: LazyLock<DashMap<String, IsolationState>> = LazyLock::new(DashMap::new);

/// Isolation modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    Network,
    Process,
    Memory,
    Full,
}

impl Default for IsolationMode {
    fn default() -> Self {
        IsolationMode::Full
    }
}

impl std::str::FromStr for IsolationMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "network" => Ok(IsolationMode::Network),
            "process" => Ok(IsolationMode::Process),
            "memory" => Ok(IsolationMode::Memory),
            "full" => Ok(IsolationMode::Full),
            _ => Err(()),
        }
    }
}

/// Information about a tracked model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub model_id: String,
    pub process_path: Option<String>,
    pub api_endpoint: Option<String>,
    pub pids: HashSet<u32>,
    pub ports: HashSet<u16>,
    pub registered_at: u64,
}

/// Current isolation state for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationState {
    pub model_id: String,
    pub mode: IsolationMode,
    pub isolated_at: u64,
    pub affected_pids: Vec<u32>,
    pub blocked_ports: Vec<u16>,
    pub reason: Option<String>,
}

/// Parameters for isolate model command
#[derive(Debug, Deserialize)]
pub struct IsolateModelParams {
    pub model_id: String,
    #[serde(default)]
    pub mode: Option<String>,
    pub reason: Option<String>,
}

/// Parameters for release model command
#[derive(Debug, Deserialize)]
pub struct ReleaseModelParams {
    pub model_id: String,
}

/// Parameters for kill model command
#[derive(Debug, Deserialize)]
pub struct KillModelParams {
    pub model_id: String,
    #[serde(default)]
    pub force: bool,
}

/// Register a model for tracking
pub fn register_model(model_id: &str, info: ModelInfo) {
    MODEL_TRACKER.insert(model_id.to_string(), info);
    debug!(model_id = model_id, "Model registered for tracking");
}

/// Update model process information (e.g., when a new PID is detected)
pub fn update_model_pids(model_id: &str, pids: &[u32]) {
    if let Some(mut info) = MODEL_TRACKER.get_mut(model_id) {
        for pid in pids {
            info.pids.insert(*pid);
        }
    }
}

/// Update model port information
pub fn update_model_ports(model_id: &str, ports: &[u16]) {
    if let Some(mut info) = MODEL_TRACKER.get_mut(model_id) {
        for port in ports {
            info.ports.insert(*port);
        }
    }
}

/// Handle isolate model command
pub async fn handle_isolate_model(payload: &serde_json::Value) -> CommandResult {
    let start = Instant::now();

    let params: IsolateModelParams = match serde_json::from_value(payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Invalid parameters: {}", e)),
                result_data: None,
            }
        }
    };

    let mode = params
        .mode
        .as_ref()
        .and_then(|m| m.parse().ok())
        .unwrap_or(IsolationMode::Full);

    info!(
        model_id = %params.model_id,
        mode = ?mode,
        "Isolating model"
    );

    // Check if already isolated
    if ISOLATED_MODELS.contains_key(&params.model_id) {
        return CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "model_id": params.model_id,
                "action": "isolate",
                "status": "already_isolated",
                "latency_ms": start.elapsed().as_millis()
            })),
        };
    }

    // Get model info (or create minimal entry)
    let model_info = MODEL_TRACKER
        .get(&params.model_id)
        .map(|r| r.clone())
        .unwrap_or_else(|| ModelInfo {
            model_id: params.model_id.clone(),
            process_path: None,
            api_endpoint: None,
            pids: HashSet::new(),
            ports: HashSet::new(),
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

    let mut affected_pids = Vec::new();
    let mut blocked_ports = Vec::new();
    let mut errors = Vec::new();

    // Apply isolation based on mode
    match mode {
        IsolationMode::Network | IsolationMode::Full => {
            // Block network access for model ports
            for port in &model_info.ports {
                match block_model_port(*port).await {
                    Ok(_) => blocked_ports.push(*port),
                    Err(e) => errors.push(format!("Failed to block port {}: {}", port, e)),
                }
            }
        }
        _ => {}
    }

    match mode {
        IsolationMode::Process | IsolationMode::Full => {
            // Suspend model processes
            for pid in &model_info.pids {
                match suspend_process(*pid).await {
                    Ok(_) => affected_pids.push(*pid),
                    Err(e) => errors.push(format!("Failed to suspend PID {}: {}", pid, e)),
                }
            }
        }
        _ => {}
    }

    match mode {
        IsolationMode::Memory | IsolationMode::Full => {
            // Signal model to clear state/context
            for pid in &model_info.pids {
                if let Err(e) = signal_memory_wipe(*pid).await {
                    errors.push(format!(
                        "Failed to signal memory wipe for PID {}: {}",
                        pid, e
                    ));
                }
            }
        }
        _ => {}
    }

    // Record isolation state
    let isolation_state = IsolationState {
        model_id: params.model_id.clone(),
        mode,
        isolated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        affected_pids: affected_pids.clone(),
        blocked_ports: blocked_ports.clone(),
        reason: params.reason,
    };

    ISOLATED_MODELS.insert(params.model_id.clone(), isolation_state);

    let latency_ms = start.elapsed().as_millis();

    info!(
        model_id = %params.model_id,
        latency_ms = latency_ms,
        affected_pids = ?affected_pids,
        blocked_ports = ?blocked_ports,
        "Model isolated"
    );

    CommandResult {
        success: errors.is_empty(),
        error_message: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        result_data: Some(serde_json::json!({
            "model_id": params.model_id,
            "action": "isolate",
            "mode": format!("{:?}", mode).to_lowercase(),
            "latency_ms": latency_ms,
            "affected_pids": affected_pids,
            "blocked_ports": blocked_ports
        })),
    }
}

/// Handle release model command
pub async fn handle_release_model(payload: &serde_json::Value) -> CommandResult {
    let start = Instant::now();

    let params: ReleaseModelParams = match serde_json::from_value(payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Invalid parameters: {}", e)),
                result_data: None,
            }
        }
    };

    info!(model_id = %params.model_id, "Releasing model from isolation");

    // Get isolation state
    let isolation_state = match ISOLATED_MODELS.remove(&params.model_id) {
        Some((_, state)) => state,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Model is not isolated".to_string()),
                result_data: None,
            }
        }
    };

    let mut errors = Vec::new();

    // Reverse isolation actions
    match isolation_state.mode {
        IsolationMode::Network | IsolationMode::Full => {
            // Unblock ports
            for port in &isolation_state.blocked_ports {
                if let Err(e) = unblock_model_port(*port).await {
                    errors.push(format!("Failed to unblock port {}: {}", port, e));
                }
            }
        }
        _ => {}
    }

    match isolation_state.mode {
        IsolationMode::Process | IsolationMode::Full => {
            // Resume processes
            for pid in &isolation_state.affected_pids {
                if let Err(e) = resume_process(*pid).await {
                    errors.push(format!("Failed to resume PID {}: {}", pid, e));
                }
            }
        }
        _ => {}
    }

    let latency_ms = start.elapsed().as_millis();

    info!(
        model_id = %params.model_id,
        latency_ms = latency_ms,
        "Model released from isolation"
    );

    CommandResult {
        success: errors.is_empty(),
        error_message: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        result_data: Some(serde_json::json!({
            "model_id": params.model_id,
            "action": "release",
            "latency_ms": latency_ms,
            "released_pids": isolation_state.affected_pids,
            "unblocked_ports": isolation_state.blocked_ports
        })),
    }
}

/// Handle kill model command
pub async fn handle_kill_model(payload: &serde_json::Value) -> CommandResult {
    let start = Instant::now();

    let params: KillModelParams = match serde_json::from_value(payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Invalid parameters: {}", e)),
                result_data: None,
            }
        }
    };

    info!(
        model_id = %params.model_id,
        force = params.force,
        "Killing model process"
    );

    // Get model info
    let model_info = MODEL_TRACKER.get(&params.model_id);
    let pids: Vec<u32> = model_info
        .as_ref()
        .map(|info| info.pids.iter().copied().collect())
        .unwrap_or_default();

    if pids.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("No processes found for model".to_string()),
            result_data: None,
        };
    }

    let mut killed_pids = Vec::new();
    let mut errors = Vec::new();

    for pid in &pids {
        match kill_process(*pid, params.force).await {
            Ok(_) => killed_pids.push(*pid),
            Err(e) => errors.push(format!("Failed to kill PID {}: {}", pid, e)),
        }
    }

    // Remove from tracking
    MODEL_TRACKER.remove(&params.model_id);
    ISOLATED_MODELS.remove(&params.model_id);

    let latency_ms = start.elapsed().as_millis();

    info!(
        model_id = %params.model_id,
        latency_ms = latency_ms,
        killed_pids = ?killed_pids,
        "Model process killed"
    );

    CommandResult {
        success: !killed_pids.is_empty() || errors.is_empty(),
        error_message: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        result_data: Some(serde_json::json!({
            "model_id": params.model_id,
            "action": "kill",
            "latency_ms": latency_ms,
            "killed_pids": killed_pids,
            "force": params.force
        })),
    }
}

/// Handle list models command
pub async fn handle_list_models(_payload: &serde_json::Value) -> CommandResult {
    let models: Vec<serde_json::Value> = MODEL_TRACKER
        .iter()
        .map(|entry| {
            let info = entry.value();
            let isolated = ISOLATED_MODELS.contains_key(&info.model_id);

            serde_json::json!({
                "model_id": info.model_id,
                "process_path": info.process_path,
                "api_endpoint": info.api_endpoint,
                "pids": info.pids.iter().collect::<Vec<_>>(),
                "ports": info.ports.iter().collect::<Vec<_>>(),
                "registered_at": info.registered_at,
                "isolated": isolated
            })
        })
        .collect();

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "models": models,
            "total": models.len(),
            "isolated_count": ISOLATED_MODELS.len()
        })),
    }
}

// ── Platform-specific implementations ──────────────────────────────

/// Block a port used by a model
#[cfg(target_os = "linux")]
async fn block_model_port(port: u16) -> anyhow::Result<()> {
    use tokio::process::Command;

    // Add iptables rule to block outbound traffic on port
    let output = Command::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!(
            "iptables failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    debug!(port = port, "Blocked port via iptables");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn block_model_port(port: u16) -> anyhow::Result<()> {
    use tokio::process::Command;

    // Add Windows Firewall rule
    let rule_name = format!("TamanduaModelBlock_{}", port);
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=out",
            "action=block",
            "protocol=tcp",
            &format!("remoteport={}", port),
        ])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("netsh failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    debug!(port = port, "Blocked port via Windows Firewall");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn block_model_port(port: u16) -> anyhow::Result<()> {
    use tokio::process::Command;

    // Add pf rule (requires pfctl configuration)
    let rule = format!("block out proto tcp from any to any port {}", port);
    let output = Command::new("sh")
        .args(["-c", &format!("echo '{}' | pfctl -ef -", rule)])
        .output()
        .await?;

    if !output.status.success() {
        warn!(port = port, "pfctl may not be configured for dynamic rules");
    }

    debug!(port = port, "Blocked port via pf");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn block_model_port(_port: u16) -> anyhow::Result<()> {
    warn!("Port blocking not implemented for this platform");
    Ok(())
}

/// Unblock a previously blocked port
#[cfg(target_os = "linux")]
async fn unblock_model_port(port: u16) -> anyhow::Result<()> {
    use tokio::process::Command;

    let output = Command::new("iptables")
        .args([
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .output()
        .await?;

    if !output.status.success() {
        warn!(
            port = port,
            "Failed to remove iptables rule (may not exist)"
        );
    }

    debug!(port = port, "Unblocked port via iptables");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn unblock_model_port(port: u16) -> anyhow::Result<()> {
    use tokio::process::Command;

    let rule_name = format!("TamanduaModelBlock_{}", port);
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ])
        .output()
        .await?;

    if !output.status.success() {
        warn!(
            port = port,
            "Failed to remove firewall rule (may not exist)"
        );
    }

    debug!(port = port, "Unblocked port via Windows Firewall");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn unblock_model_port(port: u16) -> anyhow::Result<()> {
    // macOS pf rules are typically managed via anchor files
    // This is a simplified implementation
    debug!(
        port = port,
        "Port unblock on macOS requires pf reconfiguration"
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn unblock_model_port(_port: u16) -> anyhow::Result<()> {
    warn!("Port unblocking not implemented for this platform");
    Ok(())
}

/// Suspend a process
#[cfg(target_os = "linux")]
async fn suspend_process(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid as i32), Signal::SIGSTOP)?;
    debug!(pid = pid, "Suspended process via SIGSTOP");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn suspend_process(pid: u32) -> anyhow::Result<()> {
    use windows::Win32::System::Diagnostics::Debug::DebugActiveProcess;

    unsafe {
        // Use debug attach to suspend the process
        // Alternative: enumerate threads and call SuspendThread on each
        DebugActiveProcess(pid).map_err(|e| {
            anyhow::anyhow!("Failed to suspend process via DebugActiveProcess: {}", e)
        })?;
    }

    debug!(pid = pid, "Suspended process via DebugActiveProcess");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn suspend_process(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid as i32), Signal::SIGSTOP)?;
    debug!(pid = pid, "Suspended process via SIGSTOP");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn suspend_process(_pid: u32) -> anyhow::Result<()> {
    warn!("Process suspension not implemented for this platform");
    Ok(())
}

/// Resume a suspended process
#[cfg(target_os = "linux")]
async fn resume_process(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid as i32), Signal::SIGCONT)?;
    debug!(pid = pid, "Resumed process via SIGCONT");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn resume_process(pid: u32) -> anyhow::Result<()> {
    use windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;

    unsafe {
        // Detach debugger to resume the process
        DebugActiveProcessStop(pid).map_err(|e| {
            anyhow::anyhow!("Failed to resume process via DebugActiveProcessStop: {}", e)
        })?;
    }

    debug!(pid = pid, "Resumed process via DebugActiveProcessStop");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn resume_process(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid as i32), Signal::SIGCONT)?;
    debug!(pid = pid, "Resumed process via SIGCONT");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn resume_process(_pid: u32) -> anyhow::Result<()> {
    warn!("Process resumption not implemented for this platform");
    Ok(())
}

/// Signal a process to clear memory/context (sends SIGUSR1 as convention)
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn signal_memory_wipe(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    // SIGUSR1 is used as a convention for "clear context" in our model processes
    kill(Pid::from_raw(pid as i32), Signal::SIGUSR1)?;
    debug!(pid = pid, "Sent memory wipe signal (SIGUSR1)");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn signal_memory_wipe(pid: u32) -> anyhow::Result<()> {
    // On Windows, we send a custom message or use named pipe
    // This is a simplified implementation that relies on model process cooperation
    debug!(
        pid = pid,
        "Memory wipe on Windows requires model process IPC"
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn signal_memory_wipe(_pid: u32) -> anyhow::Result<()> {
    warn!("Memory wipe signaling not implemented for this platform");
    Ok(())
}

/// Kill a process
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn kill_process(pid: u32, force: bool) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let signal = if force {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };
    kill(Pid::from_raw(pid as i32), signal)?;
    debug!(pid = pid, force = force, "Killed process");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn kill_process(pid: u32, _force: bool) -> anyhow::Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;

        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);

        result.map_err(|e| anyhow::anyhow!("TerminateProcess failed: {}", e))?;
    }

    debug!(pid = pid, "Killed process via TerminateProcess");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn kill_process(_pid: u32, _force: bool) -> anyhow::Result<()> {
    warn!("Process killing not implemented for this platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_mode_parsing() {
        assert_eq!(
            "network".parse::<IsolationMode>().unwrap(),
            IsolationMode::Network
        );
        assert_eq!(
            "process".parse::<IsolationMode>().unwrap(),
            IsolationMode::Process
        );
        assert_eq!(
            "memory".parse::<IsolationMode>().unwrap(),
            IsolationMode::Memory
        );
        assert_eq!(
            "full".parse::<IsolationMode>().unwrap(),
            IsolationMode::Full
        );
        assert_eq!(
            "FULL".parse::<IsolationMode>().unwrap(),
            IsolationMode::Full
        );
        assert!("invalid".parse::<IsolationMode>().is_err());
    }

    #[test]
    fn test_model_registration() {
        let model_id = format!("test-model-{}", std::process::id());
        let info = ModelInfo {
            model_id: model_id.clone(),
            process_path: Some("/usr/bin/python".to_string()),
            api_endpoint: Some("http://localhost:8000".to_string()),
            pids: HashSet::from([1234, 5678]),
            ports: HashSet::from([8000]),
            registered_at: 0,
        };

        register_model(&model_id, info.clone());

        assert!(MODEL_TRACKER.contains_key(&model_id));
        let retrieved = MODEL_TRACKER.get(&model_id).unwrap();
        assert_eq!(retrieved.pids.len(), 2);
    }

    #[test]
    fn test_update_model_pids() {
        let model_id = format!("test-model-pids-{}", std::process::id());
        let info = ModelInfo {
            model_id: model_id.clone(),
            process_path: None,
            api_endpoint: None,
            pids: HashSet::from([1000]),
            ports: HashSet::new(),
            registered_at: 0,
        };

        register_model(&model_id, info);
        update_model_pids(&model_id, &[2000, 3000]);

        let retrieved = MODEL_TRACKER.get(&model_id).unwrap();
        assert!(retrieved.pids.contains(&1000));
        assert!(retrieved.pids.contains(&2000));
        assert!(retrieved.pids.contains(&3000));
    }

    #[tokio::test]
    async fn test_handle_list_models() {
        let result = handle_list_models(&serde_json::json!({})).await;
        assert!(result.success);
        assert!(result.result_data.is_some());
    }

    #[tokio::test]
    async fn test_isolate_model_invalid_params() {
        let result = handle_isolate_model(&serde_json::json!({})).await;
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_release_model_not_isolated() {
        let result = handle_release_model(&serde_json::json!({
            "model_id": "nonexistent-model"
        }))
        .await;

        assert!(!result.success);
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("not isolated"));
    }

    #[tokio::test]
    async fn test_isolate_release_cycle() {
        let model_id = format!("test-cycle-{}", std::process::id());

        // Register model with no PIDs/ports (for testing without side effects)
        let info = ModelInfo {
            model_id: model_id.clone(),
            process_path: None,
            api_endpoint: None,
            pids: HashSet::new(),
            ports: HashSet::new(),
            registered_at: 0,
        };
        register_model(&model_id, info);

        // Isolate
        let isolate_result = handle_isolate_model(&serde_json::json!({
            "model_id": model_id,
            "mode": "full",
            "reason": "test"
        }))
        .await;

        assert!(isolate_result.success);

        // Verify isolated
        assert!(ISOLATED_MODELS.contains_key(&model_id));

        // Release
        let release_result = handle_release_model(&serde_json::json!({
            "model_id": model_id
        }))
        .await;

        assert!(release_result.success);

        // Verify released
        assert!(!ISOLATED_MODELS.contains_key(&model_id));
    }
}
