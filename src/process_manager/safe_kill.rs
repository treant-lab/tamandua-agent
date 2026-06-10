//! Safe Process Termination Module
//!
//! Implements safe process termination with multiple safety checks:
//! - Critical process detection (blocks with reason)
//! - Tamandua self-protection (blocks)
//! - System-signed process warnings
//! - Graceful termination first (WM_CLOSE/SIGTERM)
//! - Wait 5 seconds, then force kill (TerminateProcess/SIGKILL)
//! - Full logging of all kill attempts with context

use super::{
    critical_processes::{CriticalProcessDb, CriticalityLevel},
    explorer::get_process_details,
    ProcessManagerError, Result,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, BOOL, HANDLE, HWND, LPARAM, WPARAM},
    System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    },
    UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE, WM_QUIT,
    },
};

/// Timeout for graceful termination (5 seconds)
const GRACEFUL_TIMEOUT_SECS: u64 = 5;

/// Result of a safe kill operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafeKillResult {
    /// Process was successfully terminated
    Killed {
        pid: u32,
        graceful: bool,
        message: String,
    },
    /// Kill was blocked for safety reasons
    Blocked(KillBlockReason),
    /// Warning was generated but kill could proceed
    Warning {
        pid: u32,
        warning: String,
        killed: bool,
    },
    /// Kill failed due to an error
    Failed { pid: u32, error: String },
}

/// Reasons why a kill might be blocked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KillBlockReason {
    /// Process is a Tamandua agent process
    IsTamandua,
    /// Process is critical to system operation
    CriticalProcess {
        name: String,
        level: CriticalityLevel,
        reason: String,
    },
    /// Process not found
    ProcessNotFound(u32),
    /// Insufficient permissions
    InsufficientPermissions(String),
}

impl std::fmt::Display for KillBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsTamandua => write!(f, "Cannot kill Tamandua agent processes"),
            Self::CriticalProcess {
                name,
                level,
                reason,
            } => {
                write!(f, "Critical process '{}' ({:?}): {}", name, level, reason)
            }
            Self::ProcessNotFound(pid) => write!(f, "Process {} not found", pid),
            Self::InsufficientPermissions(msg) => write!(f, "Insufficient permissions: {}", msg),
        }
    }
}

/// Safely kill a process with all safety checks
///
/// This function performs the following steps:
/// 1. Check if process is Tamandua (block)
/// 2. Check if process is critical (block system-critical, warn others)
/// 3. Check if process is system-signed (warn)
/// 4. Attempt graceful termination (WM_CLOSE/SIGTERM)
/// 5. Wait up to 5 seconds for process to exit
/// 6. If still running, force kill (TerminateProcess/SIGKILL)
pub async fn safe_kill_process(pid: u32) -> SafeKillResult {
    info!(pid = pid, "Safe kill requested");

    // Get process details for logging
    let details = match get_process_details(pid).await {
        Ok(d) => d,
        Err(_) => {
            warn!(pid = pid, "Process not found");
            return SafeKillResult::Blocked(KillBlockReason::ProcessNotFound(pid));
        }
    };

    // Log full context
    info!(
        pid = pid,
        name = %details.name,
        path = ?details.path,
        cmdline = ?details.cmdline,
        user = ?details.user,
        is_elevated = details.is_elevated,
        is_signed = details.is_signed,
        signer = ?details.signer,
        "Kill target details"
    );

    // Check if it's a Tamandua process
    if is_tamandua_process(&details.name, details.path.as_deref()) {
        warn!(pid = pid, name = %details.name, "Kill blocked: Tamandua process");
        return SafeKillResult::Blocked(KillBlockReason::IsTamandua);
    }

    // Check if it's a critical process
    let critical_db = CriticalProcessDb::new();
    if let Some(info) = critical_db.get_info_by_name(&details.name) {
        if info.level == CriticalityLevel::SystemCritical {
            warn!(
                pid = pid,
                name = %details.name,
                level = ?info.level,
                reason = %info.protection_reason,
                "Kill blocked: System-critical process"
            );
            return SafeKillResult::Blocked(KillBlockReason::CriticalProcess {
                name: details.name.clone(),
                level: info.level,
                reason: info.protection_reason.clone(),
            });
        }

        // Warn for service-critical processes but allow kill
        if info.level == CriticalityLevel::ServiceCritical {
            warn!(
                pid = pid,
                name = %details.name,
                level = ?info.level,
                reason = %info.protection_reason,
                "Warning: Killing service-critical process"
            );
        }
    }

    // Warn for system-signed processes
    if details.is_signed {
        if let Some(signer) = &details.signer {
            let is_system_signed = is_system_signer(signer);
            if is_system_signed {
                warn!(
                    pid = pid,
                    name = %details.name,
                    signer = %signer,
                    "Warning: Killing system-signed process"
                );
            }
        }
    }

    // Perform the kill
    let result = perform_safe_kill(pid, &details.name).await;

    // Log the result
    match &result {
        SafeKillResult::Killed {
            graceful, message, ..
        } => {
            info!(
                pid = pid,
                name = %details.name,
                graceful = graceful,
                message = %message,
                "Process killed successfully"
            );
        }
        SafeKillResult::Failed { error, .. } => {
            error!(
                pid = pid,
                name = %details.name,
                error = %error,
                "Failed to kill process"
            );
        }
        _ => {}
    }

    result
}

/// Check if a process is a Tamandua agent process
fn is_tamandua_process(name: &str, path: Option<&str>) -> bool {
    let name_lower = name.to_lowercase();

    // Check by name
    if name_lower.contains("tamandua") {
        return true;
    }

    // Check our own PID
    let self_pid = std::process::id();
    // Note: We'd need to compare PIDs here, but this function doesn't have the PID
    // The ProcessManager handles this check separately

    // Check by path
    if let Some(path) = path {
        let path_lower = path.to_lowercase();
        if path_lower.contains("tamandua") {
            return true;
        }
    }

    false
}

/// Check if a signer is a system signer
fn is_system_signer(signer: &str) -> bool {
    let signer_lower = signer.to_lowercase();

    let system_signers = [
        "microsoft",
        "apple inc",
        "apple computer",
        "canonical",
        "red hat",
        "suse",
        "debian",
        "ubuntu",
        "fedora",
    ];

    system_signers.iter().any(|&s| signer_lower.contains(s))
}

/// Perform the actual kill operation with graceful -> force fallback
async fn perform_safe_kill(pid: u32, name: &str) -> SafeKillResult {
    #[cfg(target_os = "windows")]
    {
        perform_safe_kill_windows(pid, name).await
    }

    #[cfg(unix)]
    {
        perform_safe_kill_unix(pid, name).await
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        SafeKillResult::Failed {
            pid,
            error: "Unsupported platform".to_string(),
        }
    }
}

#[cfg(target_os = "windows")]
async fn perform_safe_kill_windows(pid: u32, name: &str) -> SafeKillResult {
    unsafe {
        // Open the process
        let access = PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE;
        let handle = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                return SafeKillResult::Failed {
                    pid,
                    error: format!("Failed to open process: {}", e),
                };
            }
        };

        // Try graceful termination first - send WM_CLOSE to all windows
        let graceful_result = send_close_to_windows(pid);

        if graceful_result {
            // Wait for the process to exit
            let wait_result = WaitForSingleObject(handle, (GRACEFUL_TIMEOUT_SECS * 1000) as u32);

            // Check if process exited
            if wait_result.0 == 0 {
                // WAIT_OBJECT_0
                let _ = CloseHandle(handle);
                return SafeKillResult::Killed {
                    pid,
                    graceful: true,
                    message: format!("Process '{}' terminated gracefully via WM_CLOSE", name),
                };
            }
        }

        // Graceful termination failed or timed out, force kill
        info!(
            pid = pid,
            name = %name,
            "Graceful termination failed, force killing"
        );

        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);

        if result.is_ok() {
            SafeKillResult::Killed {
                pid,
                graceful: false,
                message: format!(
                    "Process '{}' force terminated after {} second timeout",
                    name, GRACEFUL_TIMEOUT_SECS
                ),
            }
        } else {
            SafeKillResult::Failed {
                pid,
                error: "TerminateProcess failed".to_string(),
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn send_close_to_windows(pid: u32) -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FOUND_WINDOW: AtomicBool = AtomicBool::new(false);
    FOUND_WINDOW.store(false, Ordering::SeqCst);

    struct EnumContext {
        target_pid: u32,
    }

    // Thread-local storage for the context (since we can't pass data through EnumWindows easily)
    thread_local! {
        static ENUM_PID: std::cell::RefCell<u32> = std::cell::RefCell::new(0);
    }

    ENUM_PID.with(|p| *p.borrow_mut() = pid);

    unsafe extern "system" fn enum_callback(hwnd: HWND, _lparam: LPARAM) -> BOOL {
        let mut window_pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut window_pid));

        ENUM_PID.with(|p| {
            if window_pid == *p.borrow() {
                // Send WM_CLOSE to this window
                let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
                FOUND_WINDOW.store(true, Ordering::SeqCst);
            }
        });

        BOOL::from(true) // Continue enumeration
    }

    unsafe {
        let _ = EnumWindows(Some(enum_callback), LPARAM(0));
    }

    FOUND_WINDOW.load(Ordering::SeqCst)
}

#[cfg(unix)]
async fn perform_safe_kill_unix(pid: u32, name: &str) -> SafeKillResult {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);

    // Try graceful termination first (SIGTERM)
    info!(pid = pid, name = %name, "Sending SIGTERM");

    if let Err(e) = kill(nix_pid, Signal::SIGTERM) {
        if e == nix::errno::Errno::ESRCH {
            return SafeKillResult::Blocked(KillBlockReason::ProcessNotFound(pid));
        }
        return SafeKillResult::Failed {
            pid,
            error: format!("Failed to send SIGTERM: {}", e),
        };
    }

    // Wait for process to exit
    for _ in 0..(GRACEFUL_TIMEOUT_SECS * 10) {
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check if process still exists
        if kill(nix_pid, None).is_err() {
            // Process no longer exists
            return SafeKillResult::Killed {
                pid,
                graceful: true,
                message: format!("Process '{}' terminated gracefully via SIGTERM", name),
            };
        }
    }

    // Graceful termination timed out, force kill
    info!(
        pid = pid,
        name = %name,
        "SIGTERM timeout, sending SIGKILL"
    );

    if let Err(e) = kill(nix_pid, Signal::SIGKILL) {
        if e == nix::errno::Errno::ESRCH {
            // Process already gone
            return SafeKillResult::Killed {
                pid,
                graceful: true,
                message: format!("Process '{}' terminated during SIGKILL attempt", name),
            };
        }
        return SafeKillResult::Failed {
            pid,
            error: format!("Failed to send SIGKILL: {}", e),
        };
    }

    // Wait a bit for SIGKILL to take effect
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify the process is gone
    if kill(nix_pid, None).is_err() {
        SafeKillResult::Killed {
            pid,
            graceful: false,
            message: format!(
                "Process '{}' force terminated after {} second timeout",
                name, GRACEFUL_TIMEOUT_SECS
            ),
        }
    } else {
        SafeKillResult::Failed {
            pid,
            error: "Process survived SIGKILL".to_string(),
        }
    }
}

/// Force kill a process without safety checks (use with caution)
///
/// This bypasses all safety checks and immediately terminates the process.
/// Only use this for processes that have been vetted through other means.
pub async fn force_kill_process(pid: u32) -> SafeKillResult {
    warn!(pid = pid, "Force kill requested (bypassing safety checks)");

    #[cfg(target_os = "windows")]
    {
        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);

                    if result.is_ok() {
                        SafeKillResult::Killed {
                            pid,
                            graceful: false,
                            message: "Process force terminated (safety checks bypassed)"
                                .to_string(),
                        }
                    } else {
                        SafeKillResult::Failed {
                            pid,
                            error: "TerminateProcess failed".to_string(),
                        }
                    }
                }
                Err(e) => SafeKillResult::Failed {
                    pid,
                    error: format!("Failed to open process: {}", e),
                },
            }
        }
    }

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
            Ok(_) => SafeKillResult::Killed {
                pid,
                graceful: false,
                message: "Process force terminated (safety checks bypassed)".to_string(),
            },
            Err(e) => SafeKillResult::Failed {
                pid,
                error: format!("Failed to send SIGKILL: {}", e),
            },
        }
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        SafeKillResult::Failed {
            pid,
            error: "Unsupported platform".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tamandua_process() {
        assert!(is_tamandua_process("tamandua-agent", None));
        assert!(is_tamandua_process("TamanduaAgent.exe", None));
        assert!(is_tamandua_process(
            "agent",
            Some("C:\\Program Files\\Tamandua\\agent.exe")
        ));
        assert!(!is_tamandua_process("notepad.exe", None));
        assert!(!is_tamandua_process(
            "chrome.exe",
            Some("C:\\Program Files\\Google\\Chrome\\chrome.exe")
        ));
    }

    #[test]
    fn test_is_system_signer() {
        assert!(is_system_signer("Microsoft Corporation"));
        assert!(is_system_signer("Microsoft Windows"));
        assert!(is_system_signer("Apple Inc."));
        assert!(is_system_signer("Canonical Ltd."));
        assert!(!is_system_signer("Some Random Company"));
        assert!(!is_system_signer(""));
    }

    #[test]
    fn test_kill_block_reason_display() {
        let reason = KillBlockReason::IsTamandua;
        assert!(reason.to_string().contains("Tamandua"));

        let reason = KillBlockReason::CriticalProcess {
            name: "csrss.exe".to_string(),
            level: CriticalityLevel::SystemCritical,
            reason: "Required for Windows".to_string(),
        };
        assert!(reason.to_string().contains("csrss.exe"));
        assert!(reason.to_string().contains("SystemCritical"));
    }
}
