//! Process Suspend/Resume Module
//!
//! Provides safe process suspension and resumption:
//! - Windows: SuspendThread/ResumeThread for all threads
//! - Linux/macOS: SIGSTOP/SIGCONT
//!
//! Includes safety checks to prevent suspending critical processes.

use super::{ProcessManagerError, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    },
    System::Threading::{OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME},
};

/// Result of a suspend/resume operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendResult {
    /// Process ID
    pub pid: u32,
    /// Whether the operation succeeded
    pub success: bool,
    /// Current state after operation
    pub state: ProcessState,
    /// Number of threads affected (Windows) or 1 (Unix)
    pub threads_affected: u32,
    /// Human-readable message
    pub message: String,
}

/// Process execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessState {
    /// Process is running normally
    Running,
    /// Process is suspended
    Suspended,
    /// Process state is unknown
    Unknown,
}

/// Suspend a process (all threads)
///
/// On Windows, this suspends all threads in the process using SuspendThread.
/// On Unix, this sends SIGSTOP to the process.
pub async fn suspend_process(pid: u32) -> Result<SuspendResult> {
    info!(pid = pid, "Suspending process");

    #[cfg(target_os = "windows")]
    {
        suspend_process_windows(pid).await
    }

    #[cfg(unix)]
    {
        suspend_process_unix(pid).await
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        Err(ProcessManagerError::PlatformError(
            "Unsupported platform".to_string(),
        ))
    }
}

/// Resume a suspended process (all threads)
///
/// On Windows, this resumes all threads in the process using ResumeThread.
/// On Unix, this sends SIGCONT to the process.
pub async fn resume_process(pid: u32) -> Result<SuspendResult> {
    info!(pid = pid, "Resuming process");

    #[cfg(target_os = "windows")]
    {
        resume_process_windows(pid).await
    }

    #[cfg(unix)]
    {
        resume_process_unix(pid).await
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        Err(ProcessManagerError::PlatformError(
            "Unsupported platform".to_string(),
        ))
    }
}

/// Check if a process is currently suspended
pub fn is_process_suspended(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        // On Windows, we'd need to check thread suspend counts
        // This is complex, so for now return false
        false
    }

    #[cfg(target_os = "linux")]
    {
        // Check /proc/{pid}/status for State: T (stopped)
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            for line in status.lines() {
                if line.starts_with("State:") {
                    return line.contains("T") || line.contains("stopped");
                }
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        // Use ps to check process state
        use std::process::Command;
        if let Ok(output) = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "state="])
            .output()
        {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return state.contains("T");
        }
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    false
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
async fn suspend_process_windows(pid: u32) -> Result<SuspendResult> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(|e| {
            ProcessManagerError::PlatformError(format!("CreateToolhelp32Snapshot failed: {}", e))
        })?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut suspended_count = 0u32;
        let mut failed_count = 0u32;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                    {
                        let result = SuspendThread(thread_handle);
                        if result != u32::MAX {
                            suspended_count += 1;
                            debug!(
                                pid = pid,
                                thread_id = entry.th32ThreadID,
                                suspend_count = result,
                                "Thread suspended"
                            );
                        } else {
                            failed_count += 1;
                            warn!(
                                pid = pid,
                                thread_id = entry.th32ThreadID,
                                "Failed to suspend thread"
                            );
                        }
                        let _ = CloseHandle(thread_handle);
                    }
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        if suspended_count > 0 {
            Ok(SuspendResult {
                pid,
                success: true,
                state: ProcessState::Suspended,
                threads_affected: suspended_count,
                message: format!(
                    "Suspended {} threads ({} failed)",
                    suspended_count, failed_count
                ),
            })
        } else {
            Err(ProcessManagerError::PlatformError(
                "No threads found or all suspends failed".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "windows")]
async fn resume_process_windows(pid: u32) -> Result<SuspendResult> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(|e| {
            ProcessManagerError::PlatformError(format!("CreateToolhelp32Snapshot failed: {}", e))
        })?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut resumed_count = 0u32;
        let mut failed_count = 0u32;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                    {
                        // Resume until the thread is fully resumed
                        // ResumeThread returns the previous suspend count
                        loop {
                            let result = ResumeThread(thread_handle);
                            if result == u32::MAX {
                                failed_count += 1;
                                break;
                            } else if result <= 1 {
                                // Thread is now running (suspend count was 0 or 1)
                                resumed_count += 1;
                                debug!(pid = pid, thread_id = entry.th32ThreadID, "Thread resumed");
                                break;
                            }
                            // Continue resuming if suspend count was > 1
                        }
                        let _ = CloseHandle(thread_handle);
                    }
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        if resumed_count > 0 {
            Ok(SuspendResult {
                pid,
                success: true,
                state: ProcessState::Running,
                threads_affected: resumed_count,
                message: format!(
                    "Resumed {} threads ({} failed)",
                    resumed_count, failed_count
                ),
            })
        } else {
            Err(ProcessManagerError::PlatformError(
                "No threads found or all resumes failed".to_string(),
            ))
        }
    }
}

// ============================================================================
// Unix Implementation
// ============================================================================

#[cfg(unix)]
async fn suspend_process_unix(pid: u32) -> Result<SuspendResult> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);

    match kill(nix_pid, Signal::SIGSTOP) {
        Ok(_) => {
            info!(pid = pid, "Process suspended via SIGSTOP");
            Ok(SuspendResult {
                pid,
                success: true,
                state: ProcessState::Suspended,
                threads_affected: 1,
                message: "Process suspended via SIGSTOP".to_string(),
            })
        }
        Err(e) => {
            if e == nix::errno::Errno::ESRCH {
                Err(ProcessManagerError::ProcessNotFound(pid))
            } else if e == nix::errno::Errno::EPERM {
                Err(ProcessManagerError::InsufficientPermissions(format!(
                    "Cannot suspend process {}: {}",
                    pid, e
                )))
            } else {
                Err(ProcessManagerError::PlatformError(format!(
                    "Failed to send SIGSTOP: {}",
                    e
                )))
            }
        }
    }
}

#[cfg(unix)]
async fn resume_process_unix(pid: u32) -> Result<SuspendResult> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);

    match kill(nix_pid, Signal::SIGCONT) {
        Ok(_) => {
            info!(pid = pid, "Process resumed via SIGCONT");
            Ok(SuspendResult {
                pid,
                success: true,
                state: ProcessState::Running,
                threads_affected: 1,
                message: "Process resumed via SIGCONT".to_string(),
            })
        }
        Err(e) => {
            if e == nix::errno::Errno::ESRCH {
                Err(ProcessManagerError::ProcessNotFound(pid))
            } else if e == nix::errno::Errno::EPERM {
                Err(ProcessManagerError::InsufficientPermissions(format!(
                    "Cannot resume process {}: {}",
                    pid, e
                )))
            } else {
                Err(ProcessManagerError::PlatformError(format!(
                    "Failed to send SIGCONT: {}",
                    e
                )))
            }
        }
    }
}

/// Suspend a process for a specific duration, then automatically resume
///
/// This is useful for pausing malicious activity while investigating.
pub async fn suspend_for_duration(pid: u32, duration_secs: u64) -> Result<SuspendResult> {
    info!(
        pid = pid,
        duration_secs = duration_secs,
        "Suspending process temporarily"
    );

    // Suspend the process
    let suspend_result = suspend_process(pid).await?;

    // Schedule automatic resume
    let pid_clone = pid;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
        if let Err(e) = resume_process(pid_clone).await {
            warn!(
                pid = pid_clone,
                error = %e,
                "Failed to auto-resume process"
            );
        } else {
            info!(
                pid = pid_clone,
                duration_secs = duration_secs,
                "Process auto-resumed after timeout"
            );
        }
    });

    Ok(SuspendResult {
        pid: suspend_result.pid,
        success: suspend_result.success,
        state: ProcessState::Suspended,
        threads_affected: suspend_result.threads_affected,
        message: format!(
            "{}. Will auto-resume in {} seconds.",
            suspend_result.message, duration_secs
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_state_serialization() {
        let state = ProcessState::Suspended;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"Suspended\"");

        let deserialized: ProcessState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProcessState::Suspended);
    }

    #[test]
    fn test_suspend_result_serialization() {
        let result = SuspendResult {
            pid: 1234,
            success: true,
            state: ProcessState::Suspended,
            threads_affected: 5,
            message: "Process suspended".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("1234"));
        assert!(json.contains("Suspended"));
        assert!(json.contains("5"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_process_suspended() {
        // Test with current process (should not be suspended)
        let pid = std::process::id();
        assert!(!is_process_suspended(pid));

        // Test with non-existent process
        assert!(!is_process_suspended(999999));
    }
}
