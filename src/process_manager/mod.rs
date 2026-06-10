//! Safe Process Manager for Tamandua EDR
//!
//! Provides comprehensive process management with safety features:
//! - Full process tree enumeration with explorer functionality
//! - Critical process protection (system-critical, service-critical, user-critical)
//! - Safe process termination with graceful shutdown
//! - Suspend/resume process management
//! - Trust management for behavioral scoring
//!
//! # Safety
//!
//! This module implements multiple safety checks before performing any
//! destructive operations:
//! - Critical process detection blocks termination of system processes
//! - Self-protection prevents killing Tamandua processes
//! - System-signed process warnings
//! - Graceful termination with timeout before force kill

pub mod critical_processes;
pub mod explorer;
pub mod safe_kill;
pub mod suspend_resume;
pub mod trust_manager;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use critical_processes::{
    get_criticality_level, is_critical_process, CriticalProcessDb, CriticalProcessInfo,
    CriticalityLevel,
};
pub use explorer::{
    get_all_processes, get_process_details, get_process_tree, NetworkConnectionInfo,
    ProcessDetails, ProcessTreeNode,
};
pub use safe_kill::{safe_kill_process, KillBlockReason, SafeKillResult};
pub use suspend_resume::{resume_process, suspend_process, SuspendResult};
pub use trust_manager::{ProcessTrustInfo, TrustDecision, TrustLevel, TrustManager};

/// Process Manager result type
pub type Result<T> = std::result::Result<T, ProcessManagerError>;

/// Process Manager errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessManagerError {
    /// Process not found
    ProcessNotFound(u32),
    /// Operation blocked for safety
    OperationBlocked(String),
    /// Insufficient permissions
    InsufficientPermissions(String),
    /// Platform-specific error
    PlatformError(String),
    /// Trust database error
    TrustDbError(String),
    /// Process is critical and cannot be modified
    CriticalProcess(String),
    /// Process is Tamandua agent
    SelfProtection,
    /// Operation timeout
    Timeout,
    /// Generic error
    Other(String),
}

impl std::fmt::Display for ProcessManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessNotFound(pid) => write!(f, "Process not found: {}", pid),
            Self::OperationBlocked(reason) => write!(f, "Operation blocked: {}", reason),
            Self::InsufficientPermissions(msg) => write!(f, "Insufficient permissions: {}", msg),
            Self::PlatformError(msg) => write!(f, "Platform error: {}", msg),
            Self::TrustDbError(msg) => write!(f, "Trust database error: {}", msg),
            Self::CriticalProcess(msg) => write!(f, "Critical process protection: {}", msg),
            Self::SelfProtection => write!(f, "Cannot modify Tamandua agent processes"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for ProcessManagerError {}

/// Safe Process Manager
///
/// Provides a unified interface for all process management operations
/// with built-in safety checks and logging.
pub struct ProcessManager {
    /// Critical process database
    critical_db: CriticalProcessDb,
    /// Trust manager for behavioral scoring
    trust_manager: Arc<RwLock<TrustManager>>,
    /// Our own PID for self-protection
    self_pid: u32,
    /// Cache of known Tamandua child processes
    tamandua_pids: Arc<RwLock<Vec<u32>>>,
}

impl ProcessManager {
    /// Create a new ProcessManager
    pub async fn new() -> Result<Self> {
        let trust_manager = TrustManager::new()
            .await
            .map_err(|e| ProcessManagerError::TrustDbError(e.to_string()))?;

        Ok(Self {
            critical_db: CriticalProcessDb::new(),
            trust_manager: Arc::new(RwLock::new(trust_manager)),
            self_pid: std::process::id(),
            tamandua_pids: Arc::new(RwLock::new(vec![std::process::id()])),
        })
    }

    /// Get the full process tree
    pub async fn get_process_tree(&self) -> Result<Vec<ProcessTreeNode>> {
        get_process_tree().await
    }

    /// Get detailed information about a specific process
    pub async fn get_process_details(&self, pid: u32) -> Result<ProcessDetails> {
        get_process_details(pid).await
    }

    /// Safely kill a process with all safety checks
    pub async fn safe_kill(&self, pid: u32) -> SafeKillResult {
        // Check if it's a Tamandua process
        if self.is_tamandua_process(pid).await {
            return SafeKillResult::Blocked(KillBlockReason::IsTamandua);
        }

        // Check if it's a critical process
        if let Some(info) = self.critical_db.get_critical_info(pid).await {
            return SafeKillResult::Blocked(KillBlockReason::CriticalProcess {
                name: info.name.clone(),
                level: info.level,
                reason: info.protection_reason.clone(),
            });
        }

        // Perform the safe kill with graceful termination
        safe_kill_process(pid).await
    }

    /// Suspend a process safely
    pub async fn suspend(&self, pid: u32) -> Result<SuspendResult> {
        // Check if it's a Tamandua process
        if self.is_tamandua_process(pid).await {
            return Err(ProcessManagerError::SelfProtection);
        }

        // Check if it's a critical process
        if let Some(info) = self.critical_db.get_critical_info(pid).await {
            if info.level == CriticalityLevel::SystemCritical {
                return Err(ProcessManagerError::CriticalProcess(format!(
                    "Cannot suspend system-critical process: {}",
                    info.name
                )));
            }
        }

        suspend_process(pid).await
    }

    /// Resume a suspended process
    pub async fn resume(&self, pid: u32) -> Result<SuspendResult> {
        resume_process(pid).await
    }

    /// Set trust level for a process
    pub async fn set_trust(&self, pid: u32, level: TrustLevel, reason: &str) -> Result<()> {
        let mut trust_manager = self.trust_manager.write().await;
        trust_manager
            .set_trust(pid, level, reason)
            .await
            .map_err(|e| ProcessManagerError::TrustDbError(e.to_string()))
    }

    /// Get trust information for a process
    pub async fn get_trust(&self, pid: u32) -> Result<Option<ProcessTrustInfo>> {
        let trust_manager = self.trust_manager.read().await;
        trust_manager
            .get_trust(pid)
            .await
            .map_err(|e| ProcessManagerError::TrustDbError(e.to_string()))
    }

    /// Check if a process is a Tamandua agent process
    async fn is_tamandua_process(&self, pid: u32) -> bool {
        if pid == self.self_pid {
            return true;
        }

        let tamandua_pids = self.tamandua_pids.read().await;
        if tamandua_pids.contains(&pid) {
            return true;
        }

        // Check if the process name indicates Tamandua
        if let Ok(details) = get_process_details(pid).await {
            let name_lower = details.name.to_lowercase();
            if name_lower.contains("tamandua") || name_lower.contains("tamandua-agent") {
                return true;
            }

            // Check if parent is a Tamandua process
            if let Some(ppid) = details.ppid {
                if ppid == self.self_pid || tamandua_pids.contains(&ppid) {
                    return true;
                }
            }
        }

        false
    }

    /// Register a child process as a Tamandua process (for spawned helpers)
    pub async fn register_tamandua_child(&self, pid: u32) {
        let mut pids = self.tamandua_pids.write().await;
        if !pids.contains(&pid) {
            pids.push(pid);
            info!(pid = pid, "Registered Tamandua child process");
        }
    }

    /// Unregister a Tamandua child process
    pub async fn unregister_tamandua_child(&self, pid: u32) {
        let mut pids = self.tamandua_pids.write().await;
        pids.retain(|&p| p != pid);
        debug!(pid = pid, "Unregistered Tamandua child process");
    }

    /// Get process criticality level
    pub async fn get_criticality(&self, pid: u32) -> Option<CriticalityLevel> {
        self.critical_db.get_criticality_level(pid).await
    }

    /// Check if a process binary hash matches known-good hashes
    pub async fn verify_process_hash(&self, pid: u32) -> Result<bool> {
        let details = get_process_details(pid).await?;
        if let Some(path) = &details.path {
            self.critical_db
                .verify_hash(path)
                .await
                .map_err(|e| ProcessManagerError::Other(e.to_string()))
        } else {
            Ok(false)
        }
    }
}

/// Global process manager instance
static PROCESS_MANAGER: std::sync::OnceLock<Arc<RwLock<Option<ProcessManager>>>> =
    std::sync::OnceLock::new();

/// Initialize the global process manager
pub async fn init_process_manager() -> Result<()> {
    let manager = ProcessManager::new().await?;

    let lock = PROCESS_MANAGER.get_or_init(|| Arc::new(RwLock::new(None)));

    let mut guard = lock.write().await;
    *guard = Some(manager);

    info!("Process manager initialized");
    Ok(())
}

/// Get the global process manager
pub async fn get_process_manager() -> Option<Arc<RwLock<Option<ProcessManager>>>> {
    PROCESS_MANAGER.get().cloned()
}

// ============================================================================
// Tauri Commands for GUI Integration
// ============================================================================

/// Tauri command: Get the full process tree
pub async fn cmd_get_process_tree() -> std::result::Result<Vec<ProcessTreeNode>, String> {
    get_process_tree().await.map_err(|e| e.to_string())
}

/// Tauri command: Get process details
pub async fn cmd_get_process_details(pid: u32) -> std::result::Result<ProcessDetails, String> {
    get_process_details(pid).await.map_err(|e| e.to_string())
}

/// Tauri command: Safely kill a process
pub async fn cmd_safe_kill_process(pid: u32) -> std::result::Result<SafeKillResult, String> {
    if let Some(manager_lock) = get_process_manager().await {
        let manager = manager_lock.read().await;
        if let Some(ref pm) = *manager {
            return Ok(pm.safe_kill(pid).await);
        }
    }

    // Fallback to direct safe_kill if manager not initialized
    Ok(safe_kill_process(pid).await)
}

/// Tauri command: Suspend a process
pub async fn cmd_suspend_process(pid: u32) -> std::result::Result<SuspendResult, String> {
    if let Some(manager_lock) = get_process_manager().await {
        let manager = manager_lock.read().await;
        if let Some(ref pm) = *manager {
            return pm.suspend(pid).await.map_err(|e| e.to_string());
        }
    }

    suspend_process(pid).await.map_err(|e| e.to_string())
}

/// Tauri command: Resume a process
pub async fn cmd_resume_process(pid: u32) -> std::result::Result<SuspendResult, String> {
    if let Some(manager_lock) = get_process_manager().await {
        let manager = manager_lock.read().await;
        if let Some(ref pm) = *manager {
            return pm.resume(pid).await.map_err(|e| e.to_string());
        }
    }

    resume_process(pid).await.map_err(|e| e.to_string())
}

/// Tauri command: Set process trust level
pub async fn cmd_set_process_trust(
    pid: u32,
    level: TrustLevel,
    reason: String,
) -> std::result::Result<(), String> {
    if let Some(manager_lock) = get_process_manager().await {
        let manager = manager_lock.read().await;
        if let Some(ref pm) = *manager {
            return pm
                .set_trust(pid, level, &reason)
                .await
                .map_err(|e| e.to_string());
        }
    }

    Err("Process manager not initialized".to_string())
}

/// Tauri command: Get process trust information
pub async fn cmd_get_process_trust(
    pid: u32,
) -> std::result::Result<Option<ProcessTrustInfo>, String> {
    if let Some(manager_lock) = get_process_manager().await {
        let manager = manager_lock.read().await;
        if let Some(ref pm) = *manager {
            return pm.get_trust(pid).await.map_err(|e| e.to_string());
        }
    }

    Err("Process manager not initialized".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_manager_creation() {
        let manager = ProcessManager::new().await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_self_protection() {
        let manager = ProcessManager::new().await.unwrap();
        let self_pid = std::process::id();

        // Should detect self as Tamandua process
        assert!(manager.is_tamandua_process(self_pid).await);

        // Safe kill should block
        let result = manager.safe_kill(self_pid).await;
        assert!(matches!(
            result,
            SafeKillResult::Blocked(KillBlockReason::IsTamandua)
        ));
    }
}
