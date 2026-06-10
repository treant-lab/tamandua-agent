//! Self-Healing Engine
//!
//! Automatic remediation and system restoration capabilities.
//! This is a UNIQUE FEATURE not found in most competitors.
//!
//! Features:
//! - Automatic malware removal
//! - Registry restoration
//! - Service restoration
//! - File quarantine with rollback
//! - Process tree termination
//! - Persistence mechanism removal
//! - Scheduled task cleanup
//! - Browser hijacker removal

// Self-healing engine. Scaffolded config fields retained for upcoming
// platform-specific remediation paths.
#![allow(dead_code, unused_variables)]

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Healing action types
#[derive(Debug, Clone, PartialEq)]
pub enum HealingAction {
    /// Kill a malicious process and its children
    KillProcessTree { pid: u32, name: String },
    /// Quarantine a malicious file
    QuarantineFile { path: PathBuf, sha256: String },
    /// Remove a persistence mechanism
    RemovePersistence {
        persistence_type: PersistenceType,
        location: String,
    },
    /// Restore a registry key to known-good state
    RestoreRegistry { key: String, backup_path: PathBuf },
    /// Restore a file from backup
    RestoreFile { path: PathBuf, backup_path: PathBuf },
    /// Remove a malicious scheduled task
    RemoveScheduledTask { name: String },
    /// Block a network connection
    BlockNetwork { ip: String, port: u16 },
    /// Restart a legitimate service that was stopped
    RestartService { name: String },
    /// Clean browser hijacker
    CleanBrowser { browser: String, artifact: String },
}

/// Types of persistence mechanisms
#[derive(Debug, Clone, PartialEq)]
pub enum PersistenceType {
    RegistryRunKey,
    RegistryRunOnce,
    Service,
    ScheduledTask,
    StartupFolder,
    WinlogonHelper,
    ImageFileExecution,
    AppInitDll,
    ComHijack,
    BrowserExtension,
}

impl PersistenceType {
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            PersistenceType::RegistryRunKey => "T1547.001",
            PersistenceType::RegistryRunOnce => "T1547.001",
            PersistenceType::Service => "T1543.003",
            PersistenceType::ScheduledTask => "T1053.005",
            PersistenceType::StartupFolder => "T1547.001",
            PersistenceType::WinlogonHelper => "T1547.004",
            PersistenceType::ImageFileExecution => "T1546.012",
            PersistenceType::AppInitDll => "T1546.010",
            PersistenceType::ComHijack => "T1546.015",
            PersistenceType::BrowserExtension => "T1176",
        }
    }
}

/// Healing result
#[derive(Debug, Clone)]
pub struct HealingResult {
    pub action: HealingAction,
    pub success: bool,
    pub message: String,
    pub rollback_available: bool,
    pub rollback_id: Option<String>,
}

/// System snapshot for rollback
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub id: String,
    pub timestamp: u64,
    pub registry_backup: HashMap<String, Vec<u8>>,
    pub file_backups: HashMap<PathBuf, PathBuf>,
    pub service_states: HashMap<String, bool>,
    pub scheduled_tasks: Vec<String>,
}

/// Self-Healing Engine
pub struct SelfHealingEngine {
    config: AgentConfig,
    quarantine_dir: PathBuf,
    backup_dir: PathBuf,
    snapshots: HashMap<String, SystemSnapshot>,
    action_history: Vec<HealingResult>,
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl SelfHealingEngine {
    /// Create a new self-healing engine
    pub fn new(config: &AgentConfig, event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        let base_dir = if cfg!(windows) {
            PathBuf::from(r"C:\ProgramData\Tamandua")
        } else {
            PathBuf::from("/var/lib/tamandua")
        };

        let quarantine_dir = base_dir.join("quarantine");
        let backup_dir = base_dir.join("backups");

        // Create directories
        let _ = std::fs::create_dir_all(&quarantine_dir);
        let _ = std::fs::create_dir_all(&backup_dir);

        Self {
            config: config.clone(),
            quarantine_dir,
            backup_dir,
            snapshots: HashMap::new(),
            action_history: Vec::new(),
            event_tx,
        }
    }

    /// Execute a healing action
    pub async fn heal(&mut self, action: HealingAction) -> HealingResult {
        info!(action = ?action, "Executing healing action");

        let result = match &action {
            HealingAction::KillProcessTree { pid, name } => {
                self.kill_process_tree(*pid, name).await
            }
            HealingAction::QuarantineFile { path, sha256 } => {
                self.quarantine_file(path, sha256).await
            }
            HealingAction::RemovePersistence {
                persistence_type,
                location,
            } => self.remove_persistence(persistence_type, location).await,
            HealingAction::RestoreRegistry { key, backup_path } => {
                self.restore_registry(key, backup_path).await
            }
            HealingAction::RestoreFile { path, backup_path } => {
                self.restore_file(path, backup_path).await
            }
            HealingAction::RemoveScheduledTask { name } => self.remove_scheduled_task(name).await,
            HealingAction::BlockNetwork { ip, port } => self.block_network(ip, *port).await,
            HealingAction::RestartService { name } => self.restart_service(name).await,
            HealingAction::CleanBrowser { browser, artifact } => {
                self.clean_browser(browser, artifact).await
            }
        };

        let healing_result = HealingResult {
            action: action.clone(),
            success: result.is_ok(),
            message: result
                .as_ref()
                .map(|s| s.clone())
                .unwrap_or_else(|e| e.to_string()),
            rollback_available: self.is_rollback_available(&action),
            rollback_id: self.get_rollback_id(&action),
        };

        // Log the action
        self.action_history.push(healing_result.clone());

        // Send telemetry event
        self.send_healing_event(&healing_result).await;

        healing_result
    }

    /// Kill a process and all its children
    async fn kill_process_tree(&self, pid: u32, name: &str) -> Result<String> {
        info!(pid = pid, name = name, "Killing process tree");

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            // Use taskkill with /T flag to kill process tree
            let output = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .output()?;

            if output.status.success() {
                Ok(format!("Killed process tree: {} (PID {})", name, pid))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(anyhow::anyhow!("Failed to kill process: {}", stderr))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            // Get child PIDs
            let children = self.get_child_pids(pid)?;

            // Kill children first (reverse order)
            for child_pid in children.iter().rev() {
                let _ = kill(Pid::from_raw(*child_pid as i32), Signal::SIGKILL);
            }

            // Kill parent
            kill(Pid::from_raw(pid as i32), Signal::SIGKILL)?;

            Ok(format!(
                "Killed process tree: {} (PID {}) with {} children",
                name,
                pid,
                children.len()
            ))
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn get_child_pids(&self, parent_pid: u32) -> Result<Vec<u32>> {
        use std::fs;

        let mut children = Vec::new();

        // Read /proc to find children
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        let stat_path = format!("/proc/{}/stat", pid);
                        if let Ok(stat) = fs::read_to_string(&stat_path) {
                            let parts: Vec<&str> = stat.split_whitespace().collect();
                            if parts.len() > 3 {
                                if let Ok(ppid) = parts[3].parse::<u32>() {
                                    if ppid == parent_pid {
                                        children.push(pid);
                                        // Recursively get grandchildren
                                        if let Ok(grandchildren) = self.get_child_pids(pid) {
                                            children.extend(grandchildren);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(children)
    }

    /// Quarantine a malicious file
    async fn quarantine_file(&self, path: &Path, sha256: &str) -> Result<String> {
        info!(path = %path.display(), sha256 = sha256, "Quarantining file");

        if !path.exists() {
            return Err(anyhow::anyhow!("File not found: {}", path.display()));
        }

        // Create quarantine filename with timestamp and hash
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let quarantine_name = format!("{}_{}.quarantine", timestamp, &sha256[..16]);
        let quarantine_path = self.quarantine_dir.join(&quarantine_name);

        // Read original file
        let content = std::fs::read(path)?;

        // XOR encrypt (simple obfuscation to prevent accidental execution)
        let key: u8 = 0x5A;
        let encrypted: Vec<u8> = content.iter().map(|b| b ^ key).collect();

        // Write quarantine metadata
        let metadata = serde_json::json!({
            "original_path": path.to_string_lossy(),
            "sha256": sha256,
            "quarantine_time": timestamp,
            "size": content.len(),
        });

        let metadata_path = self
            .quarantine_dir
            .join(format!("{}.meta", quarantine_name));
        std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;

        // Write encrypted file
        std::fs::write(&quarantine_path, encrypted)?;

        // Delete original
        std::fs::remove_file(path)?;

        Ok(format!(
            "Quarantined: {} -> {}",
            path.display(),
            quarantine_path.display()
        ))
    }

    /// Remove a persistence mechanism
    async fn remove_persistence(
        &self,
        persistence_type: &PersistenceType,
        location: &str,
    ) -> Result<String> {
        info!(persistence_type = ?persistence_type, location = location, "Removing persistence");

        match persistence_type {
            PersistenceType::RegistryRunKey | PersistenceType::RegistryRunOnce => {
                self.remove_registry_persistence(location).await
            }
            PersistenceType::Service => self.remove_service_persistence(location).await,
            PersistenceType::ScheduledTask => self.remove_scheduled_task(location).await,
            PersistenceType::StartupFolder => self.remove_startup_folder_item(location).await,
            PersistenceType::WinlogonHelper => self.remove_winlogon_helper(location).await,
            PersistenceType::ImageFileExecution => self.remove_ifeo(location).await,
            PersistenceType::AppInitDll => self.remove_appinit_dll(location).await,
            PersistenceType::ComHijack => self.remove_com_hijack(location).await,
            PersistenceType::BrowserExtension => self.remove_browser_extension(location).await,
        }
    }

    #[cfg(target_os = "windows")]
    async fn remove_registry_persistence(&self, location: &str) -> Result<String> {
        use std::process::Command;

        // Backup first
        let backup_file = self.backup_dir.join(format!(
            "reg_backup_{}.reg",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        ));

        // Export backup
        let _ = Command::new("reg")
            .args(["export", location, &backup_file.to_string_lossy(), "/y"])
            .output();

        // Delete the key/value
        let output = Command::new("reg")
            .args(["delete", location, "/f"])
            .output()?;

        if output.status.success() {
            Ok(format!("Removed registry persistence: {}", location))
        } else {
            Err(anyhow::anyhow!(
                "Failed to remove registry: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn remove_registry_persistence(&self, _location: &str) -> Result<String> {
        Err(anyhow::anyhow!(
            "Registry persistence removal only available on Windows"
        ))
    }

    #[cfg(target_os = "windows")]
    async fn remove_service_persistence(&self, service_name: &str) -> Result<String> {
        use std::process::Command;

        // Stop service first
        let _ = Command::new("sc").args(["stop", service_name]).output();

        // Delete service
        let output = Command::new("sc").args(["delete", service_name]).output()?;

        if output.status.success() {
            Ok(format!("Removed malicious service: {}", service_name))
        } else {
            Err(anyhow::anyhow!(
                "Failed to remove service: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn remove_service_persistence(&self, service_name: &str) -> Result<String> {
        use std::process::Command;

        // Disable and stop systemd service
        let _ = Command::new("systemctl")
            .args(["stop", service_name])
            .output();

        let _ = Command::new("systemctl")
            .args(["disable", service_name])
            .output();

        // Remove service file if exists
        let service_file = format!("/etc/systemd/system/{}.service", service_name);
        if Path::new(&service_file).exists() {
            std::fs::remove_file(&service_file)?;
        }

        Ok(format!("Removed malicious service: {}", service_name))
    }

    async fn remove_scheduled_task(&self, task_name: &str) -> Result<String> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("schtasks")
                .args(["/Delete", "/TN", task_name, "/F"])
                .output()?;

            if output.status.success() {
                Ok(format!("Removed scheduled task: {}", task_name))
            } else {
                Err(anyhow::anyhow!(
                    "Failed to remove task: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Remove cron job
            use std::process::Command;

            let output = Command::new("crontab").args(["-l"]).output()?;

            let crontab = String::from_utf8_lossy(&output.stdout);
            let new_crontab: String = crontab
                .lines()
                .filter(|line| !line.contains(task_name))
                .collect::<Vec<_>>()
                .join("\n");

            // Write back without the task
            let mut child = Command::new("crontab")
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                stdin.write_all(new_crontab.as_bytes())?;
            }

            child.wait()?;

            Ok(format!("Removed cron job: {}", task_name))
        }
    }

    async fn remove_startup_folder_item(&self, path: &str) -> Result<String> {
        let file_path = Path::new(path);
        if file_path.exists() {
            std::fs::remove_file(file_path)?;
            Ok(format!("Removed startup item: {}", path))
        } else {
            Err(anyhow::anyhow!("Startup item not found: {}", path))
        }
    }

    #[cfg(target_os = "windows")]
    async fn remove_winlogon_helper(&self, location: &str) -> Result<String> {
        self.remove_registry_persistence(location).await
    }

    #[cfg(not(target_os = "windows"))]
    async fn remove_winlogon_helper(&self, _location: &str) -> Result<String> {
        Err(anyhow::anyhow!(
            "Winlogon helper removal only available on Windows"
        ))
    }

    #[cfg(target_os = "windows")]
    async fn remove_ifeo(&self, location: &str) -> Result<String> {
        self.remove_registry_persistence(location).await
    }

    #[cfg(not(target_os = "windows"))]
    async fn remove_ifeo(&self, _location: &str) -> Result<String> {
        Err(anyhow::anyhow!("IFEO removal only available on Windows"))
    }

    async fn restore_registry(&self, _key: &str, backup_path: &Path) -> Result<String> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("reg")
                .args(["import", &backup_path.to_string_lossy()])
                .output()?;

            if output.status.success() {
                Ok(format!("Restored registry from: {}", backup_path.display()))
            } else {
                Err(anyhow::anyhow!("Failed to restore registry"))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow::anyhow!(
                "Registry restoration only available on Windows"
            ))
        }
    }

    async fn restore_file(&self, target_path: &Path, backup_path: &Path) -> Result<String> {
        if !backup_path.exists() {
            return Err(anyhow::anyhow!(
                "Backup file not found: {}",
                backup_path.display()
            ));
        }

        // Create parent directories if needed
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::copy(backup_path, target_path)?;

        Ok(format!(
            "Restored file: {} from {}",
            target_path.display(),
            backup_path.display()
        ))
    }

    async fn block_network(&self, ip: &str, port: u16) -> Result<String> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let rule_name = format!("Tamandua_Block_{}_{}", ip.replace(".", "_"), port);

            let output = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={}", ip),
                    &format!("remoteport={}", port),
                    "protocol=tcp",
                ])
                .output()?;

            if output.status.success() {
                Ok(format!("Blocked outbound connection to {}:{}", ip, port))
            } else {
                Err(anyhow::anyhow!("Failed to add firewall rule"))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;

            let output = Command::new("iptables")
                .args([
                    "-A",
                    "OUTPUT",
                    "-d",
                    ip,
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "DROP",
                ])
                .output()?;

            if output.status.success() {
                Ok(format!("Blocked outbound connection to {}:{}", ip, port))
            } else {
                Err(anyhow::anyhow!("Failed to add iptables rule"))
            }
        }
    }

    async fn restart_service(&self, name: &str) -> Result<String> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("net").args(["start", name]).output()?;

            if output.status.success() {
                Ok(format!("Restarted service: {}", name))
            } else {
                Err(anyhow::anyhow!("Failed to start service: {}", name))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;

            let output = Command::new("systemctl").args(["restart", name]).output()?;

            if output.status.success() {
                Ok(format!("Restarted service: {}", name))
            } else {
                Err(anyhow::anyhow!("Failed to restart service: {}", name))
            }
        }
    }

    async fn clean_browser(&self, browser: &str, artifact: &str) -> Result<String> {
        info!(
            browser = browser,
            artifact = artifact,
            "Cleaning browser artifact"
        );

        // Get browser profile paths
        let profile_paths = self.get_browser_profile_paths(browser);

        let mut cleaned = 0;
        for profile_path in profile_paths {
            let artifact_path = profile_path.join(artifact);
            if artifact_path.exists() {
                if artifact_path.is_dir() {
                    std::fs::remove_dir_all(&artifact_path)?;
                } else {
                    std::fs::remove_file(&artifact_path)?;
                }
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            Ok(format!(
                "Cleaned {} browser artifacts from {}",
                cleaned, browser
            ))
        } else {
            Err(anyhow::anyhow!("No artifacts found to clean"))
        }
    }

    fn get_browser_profile_paths(&self, browser: &str) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
            let app_data = std::env::var("APPDATA").unwrap_or_default();

            match browser.to_lowercase().as_str() {
                "chrome" => {
                    paths.push(
                        PathBuf::from(&local_app_data).join("Google\\Chrome\\User Data\\Default"),
                    );
                }
                "firefox" => {
                    let profiles_path = PathBuf::from(&app_data).join("Mozilla\\Firefox\\Profiles");
                    if let Ok(entries) = std::fs::read_dir(&profiles_path) {
                        for entry in entries.flatten() {
                            if entry.path().is_dir() {
                                paths.push(entry.path());
                            }
                        }
                    }
                }
                "edge" => {
                    paths.push(
                        PathBuf::from(&local_app_data).join("Microsoft\\Edge\\User Data\\Default"),
                    );
                }
                _ => {}
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let home = std::env::var("HOME").unwrap_or_default();

            match browser.to_lowercase().as_str() {
                "chrome" => {
                    paths.push(PathBuf::from(&home).join(".config/google-chrome/Default"));
                }
                "firefox" => {
                    let profiles_path = PathBuf::from(&home).join(".mozilla/firefox");
                    if let Ok(entries) = std::fs::read_dir(&profiles_path) {
                        for entry in entries.flatten() {
                            if entry.path().is_dir()
                                && entry.file_name().to_string_lossy().ends_with(".default")
                            {
                                paths.push(entry.path());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        paths
    }

    /// Remove a malicious DLL from AppInit_DLLs registry value
    #[cfg(target_os = "windows")]
    async fn remove_appinit_dll(&self, dll_path: &str) -> Result<String> {
        use winreg::enums::*;
        use winreg::RegKey;

        info!(dll_path = dll_path, "Removing AppInit_DLL persistence");

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

        let key = hklm.open_subkey_with_flags(key_path, KEY_READ | KEY_WRITE)?;

        // Read current AppInit_DLLs value
        let current_value: String = key.get_value("AppInit_DLLs").unwrap_or_default();

        // Backup current value before modifying
        let backup_file = self.backup_dir.join(format!(
            "appinit_dlls_backup_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        ));
        std::fs::write(&backup_file, &current_value)?;

        // The AppInit_DLLs value is a space-delimited or comma-delimited list of DLL paths
        let separator = if current_value.contains(',') {
            ','
        } else {
            ' '
        };
        let cleaned: Vec<&str> = current_value
            .split(separator)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter(|s| !s.eq_ignore_ascii_case(dll_path))
            .collect();

        let new_value = cleaned.join(&separator.to_string());

        // Write the cleaned value back
        key.set_value("AppInit_DLLs", &new_value)?;

        // Also ensure LoadAppInit_DLLs is set to 0 if list is now empty
        if new_value.is_empty() {
            let _ = key.set_value("LoadAppInit_DLLs", &0u32);
        }

        info!(
            old_value = %current_value,
            new_value = %new_value,
            "AppInit_DLLs cleaned"
        );

        Ok(format!(
            "Removed '{}' from AppInit_DLLs. Previous value backed up to {}",
            dll_path,
            backup_file.display()
        ))
    }

    #[cfg(not(target_os = "windows"))]
    async fn remove_appinit_dll(&self, _dll_path: &str) -> Result<String> {
        Err(anyhow::anyhow!(
            "AppInit_DLL persistence removal is only available on Windows"
        ))
    }

    /// Remove a COM hijack by cleaning the CLSID InprocServer32 registry key
    #[cfg(target_os = "windows")]
    async fn remove_com_hijack(&self, clsid: &str) -> Result<String> {
        use winreg::enums::*;
        use winreg::RegKey;

        info!(clsid = clsid, "Removing COM hijack persistence");

        // COM hijacks typically target HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32
        // to override a legitimate system COM object with a malicious DLL.
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let clsid_key_path = format!(r"SOFTWARE\Classes\CLSID\{}\InprocServer32", clsid);

        // Try to read and backup the hijacked value first
        let backup_file = self.backup_dir.join(format!(
            "com_hijack_backup_{}_{}.reg",
            clsid.replace('{', "").replace('}', ""),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        ));

        // Backup: export using reg.exe for a restorable backup
        let _ = std::process::Command::new("reg")
            .args([
                "export",
                &format!(r"HKCU\SOFTWARE\Classes\CLSID\{}", clsid),
                backup_file.to_str().unwrap_or_default(),
                "/y",
            ])
            .output();

        // Check if the HKCU key exists (hijacked key)
        match hkcu.open_subkey(&clsid_key_path) {
            Ok(_) => {
                // Delete the HKCU InprocServer32 key to remove the hijack.
                // This restores the system to using the legitimate HKLM COM registration.
                hkcu.delete_subkey_all(&format!(r"SOFTWARE\Classes\CLSID\{}", clsid))?;

                info!(clsid = clsid, "COM hijack CLSID key deleted from HKCU");
                Ok(format!(
                    "Removed COM hijack for CLSID {}. Backup saved to {}",
                    clsid,
                    backup_file.display()
                ))
            }
            Err(_) => {
                // If not in HKCU, check HKLM (requires elevated privileges)
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                let hklm_clsid_path = format!(r"SOFTWARE\Classes\CLSID\{}\InprocServer32", clsid);

                match hklm.open_subkey_with_flags(&hklm_clsid_path, KEY_READ | KEY_WRITE) {
                    Ok(key) => {
                        // Read the current InprocServer32 default value
                        let current_dll: String = key.get_value("").unwrap_or_default();
                        warn!(
                            clsid = clsid,
                            dll = %current_dll,
                            "COM object found in HKLM; manual review recommended"
                        );
                        Err(anyhow::anyhow!(
                            "COM CLSID {} found in HKLM with DLL '{}'. \
                             Automated removal from HKLM is not safe without \
                             knowing the legitimate value. Manual review required.",
                            clsid,
                            current_dll
                        ))
                    }
                    Err(_) => Err(anyhow::anyhow!(
                        "COM CLSID {} not found in HKCU or HKLM",
                        clsid
                    )),
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn remove_com_hijack(&self, _clsid: &str) -> Result<String> {
        Err(anyhow::anyhow!(
            "COM hijack removal is only available on Windows"
        ))
    }

    /// Remove a malicious browser extension
    /// The `location` parameter should be the extension ID
    async fn remove_browser_extension(&self, extension_id: &str) -> Result<String> {
        info!(
            extension_id = extension_id,
            "Removing browser extension persistence"
        );

        let mut removed_count = 0;
        let mut errors = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
            let app_data = std::env::var("APPDATA").unwrap_or_default();

            // Chrome: remove extension folder and update Preferences
            let chrome_ext_dir = PathBuf::from(&local_app_data)
                .join(r"Google\Chrome\User Data\Default\Extensions")
                .join(extension_id);
            if chrome_ext_dir.exists() {
                match std::fs::remove_dir_all(&chrome_ext_dir) {
                    Ok(_) => {
                        info!(browser = "chrome", path = %chrome_ext_dir.display(), "Removed Chrome extension directory");
                        removed_count += 1;
                    }
                    Err(e) => errors.push(format!("Chrome extension dir removal failed: {}", e)),
                }
            }

            // Chrome Preferences: remove extension entry from JSON
            let chrome_prefs =
                PathBuf::from(&local_app_data).join(r"Google\Chrome\User Data\Default\Preferences");
            if chrome_prefs.exists() {
                if let Err(e) =
                    Self::remove_extension_from_chrome_prefs(&chrome_prefs, extension_id)
                {
                    errors.push(format!("Chrome Preferences update failed: {}", e));
                } else {
                    info!(
                        browser = "chrome",
                        "Removed extension from Chrome Preferences JSON"
                    );
                }
            }

            // Edge: remove extension folder (same Chromium layout as Chrome)
            let edge_ext_dir = PathBuf::from(&local_app_data)
                .join(r"Microsoft\Edge\User Data\Default\Extensions")
                .join(extension_id);
            if edge_ext_dir.exists() {
                match std::fs::remove_dir_all(&edge_ext_dir) {
                    Ok(_) => {
                        info!(browser = "edge", path = %edge_ext_dir.display(), "Removed Edge extension directory");
                        removed_count += 1;
                    }
                    Err(e) => errors.push(format!("Edge extension dir removal failed: {}", e)),
                }
            }

            // Edge Preferences
            let edge_prefs = PathBuf::from(&local_app_data)
                .join(r"Microsoft\Edge\User Data\Default\Preferences");
            if edge_prefs.exists() {
                if let Err(e) = Self::remove_extension_from_chrome_prefs(&edge_prefs, extension_id)
                {
                    errors.push(format!("Edge Preferences update failed: {}", e));
                } else {
                    info!(
                        browser = "edge",
                        "Removed extension from Edge Preferences JSON"
                    );
                }
            }

            // Firefox: extensions are stored as .xpi files in the profile extensions folder
            let firefox_profiles_dir = PathBuf::from(&app_data).join(r"Mozilla\Firefox\Profiles");
            if firefox_profiles_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&firefox_profiles_dir) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            let ext_dir = entry.path().join("extensions");
                            if ext_dir.exists() {
                                // Firefox extensions are named <id>.xpi or stored as directories
                                let xpi_path = ext_dir.join(format!("{}.xpi", extension_id));
                                let dir_path = ext_dir.join(extension_id);

                                if xpi_path.exists() {
                                    match std::fs::remove_file(&xpi_path) {
                                        Ok(_) => {
                                            info!(browser = "firefox", path = %xpi_path.display(), "Removed Firefox extension .xpi");
                                            removed_count += 1;
                                        }
                                        Err(e) => errors
                                            .push(format!("Firefox .xpi removal failed: {}", e)),
                                    }
                                }
                                if dir_path.exists() && dir_path.is_dir() {
                                    match std::fs::remove_dir_all(&dir_path) {
                                        Ok(_) => {
                                            info!(browser = "firefox", path = %dir_path.display(), "Removed Firefox extension directory");
                                            removed_count += 1;
                                        }
                                        Err(e) => errors
                                            .push(format!("Firefox dir removal failed: {}", e)),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let home = std::env::var("HOME").unwrap_or_default();

            // Chrome on Linux/macOS
            #[cfg(target_os = "macos")]
            let chrome_base =
                PathBuf::from(&home).join("Library/Application Support/Google/Chrome/Default");
            #[cfg(target_os = "linux")]
            let chrome_base = PathBuf::from(&home).join(".config/google-chrome/Default");

            let chrome_ext_dir = chrome_base.join("Extensions").join(extension_id);
            if chrome_ext_dir.exists() {
                match std::fs::remove_dir_all(&chrome_ext_dir) {
                    Ok(_) => {
                        info!(browser = "chrome", "Removed Chrome extension directory");
                        removed_count += 1;
                    }
                    Err(e) => errors.push(format!("Chrome extension dir removal failed: {}", e)),
                }
            }

            let chrome_prefs = chrome_base.join("Preferences");
            if chrome_prefs.exists() {
                if let Err(e) =
                    Self::remove_extension_from_chrome_prefs(&chrome_prefs, extension_id)
                {
                    errors.push(format!("Chrome Preferences update failed: {}", e));
                }
            }

            // Firefox on Linux/macOS
            #[cfg(target_os = "macos")]
            let firefox_profiles_base =
                PathBuf::from(&home).join("Library/Application Support/Firefox/Profiles");
            #[cfg(target_os = "linux")]
            let firefox_profiles_base = PathBuf::from(&home).join(".mozilla/firefox");

            if firefox_profiles_base.exists() {
                if let Ok(entries) = std::fs::read_dir(&firefox_profiles_base) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            let ext_dir = entry.path().join("extensions");
                            let xpi_path = ext_dir.join(format!("{}.xpi", extension_id));
                            let dir_path = ext_dir.join(extension_id);

                            if xpi_path.exists() {
                                match std::fs::remove_file(&xpi_path) {
                                    Ok(_) => {
                                        removed_count += 1;
                                    }
                                    Err(e) => {
                                        errors.push(format!("Firefox .xpi removal failed: {}", e))
                                    }
                                }
                            }
                            if dir_path.exists() && dir_path.is_dir() {
                                match std::fs::remove_dir_all(&dir_path) {
                                    Ok(_) => {
                                        removed_count += 1;
                                    }
                                    Err(e) => {
                                        errors.push(format!("Firefox dir removal failed: {}", e))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if removed_count > 0 {
            let msg = format!(
                "Removed browser extension '{}' from {} location(s)",
                extension_id, removed_count
            );
            if !errors.is_empty() {
                Ok(format!("{}. Partial errors: {}", msg, errors.join("; ")))
            } else {
                Ok(msg)
            }
        } else if !errors.is_empty() {
            Err(anyhow::anyhow!(
                "Failed to remove browser extension '{}': {}",
                extension_id,
                errors.join("; ")
            ))
        } else {
            Err(anyhow::anyhow!(
                "Browser extension '{}' not found in any browser",
                extension_id
            ))
        }
    }

    /// Helper: Remove an extension entry from a Chromium-based browser's Preferences JSON
    fn remove_extension_from_chrome_prefs(prefs_path: &Path, extension_id: &str) -> Result<()> {
        let content = std::fs::read_to_string(prefs_path)?;
        let mut prefs: serde_json::Value = serde_json::from_str(&content)?;

        let mut modified = false;

        // Remove from "extensions.settings"
        if let Some(settings) = prefs
            .pointer_mut("/extensions/settings")
            .and_then(|v| v.as_object_mut())
        {
            if settings.remove(extension_id).is_some() {
                modified = true;
            }
        }

        // Remove from "extensions.pinned_extensions" if present
        if let Some(pinned) = prefs
            .pointer_mut("/extensions/pinned_extensions")
            .and_then(|v| v.as_array_mut())
        {
            let before_len = pinned.len();
            pinned.retain(|v| v.as_str() != Some(extension_id));
            if pinned.len() != before_len {
                modified = true;
            }
        }

        if modified {
            let updated = serde_json::to_string_pretty(&prefs)?;
            std::fs::write(prefs_path, updated)?;
        }

        Ok(())
    }

    fn is_rollback_available(&self, action: &HealingAction) -> bool {
        matches!(
            action,
            HealingAction::QuarantineFile { .. }
                | HealingAction::RemovePersistence { .. }
                | HealingAction::RestoreRegistry { .. }
        )
    }

    fn get_rollback_id(&self, _action: &HealingAction) -> Option<String> {
        // Generate rollback ID
        Some(uuid::Uuid::new_v4().to_string())
    }

    async fn send_healing_event(&self, result: &HealingResult) {
        let severity = if result.success {
            Severity::Info
        } else {
            Severity::High
        };

        let event = TelemetryEvent::new(
            EventType::ResponseAction,
            severity,
            EventPayload::Custom(serde_json::json!({
                "type": "self_healing",
                "action": format!("{:?}", result.action),
                "success": result.success,
                "message": result.message,
                "rollback_available": result.rollback_available,
                "rollback_id": result.rollback_id,
            })),
        );

        let _ = self.event_tx.send(event).await;
    }

    /// Create a system snapshot for potential rollback
    pub async fn create_snapshot(&mut self) -> Result<String> {
        let snapshot_id = uuid::Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let snapshot = SystemSnapshot {
            id: snapshot_id.clone(),
            timestamp,
            registry_backup: HashMap::new(), // Would populate with key registry values
            file_backups: HashMap::new(),
            service_states: HashMap::new(),
            scheduled_tasks: Vec::new(),
        };

        self.snapshots.insert(snapshot_id.clone(), snapshot);

        info!(snapshot_id = %snapshot_id, "Created system snapshot");
        Ok(snapshot_id)
    }

    /// Rollback to a previous snapshot
    pub async fn rollback(&mut self, snapshot_id: &str) -> Result<()> {
        let snapshot = self
            .snapshots
            .get(snapshot_id)
            .ok_or_else(|| anyhow::anyhow!("Snapshot not found: {}", snapshot_id))?
            .clone();

        info!(snapshot_id = snapshot_id, "Rolling back to snapshot");

        // Restore files
        for (original, backup) in &snapshot.file_backups {
            if let Err(e) = self.restore_file(original, backup).await {
                warn!(error = %e, path = %original.display(), "Failed to restore file");
            }
        }

        // Restore services
        for (service, was_running) in &snapshot.service_states {
            if *was_running {
                if let Err(e) = self.restart_service(service).await {
                    warn!(error = %e, service = service, "Failed to restore service");
                }
            }
        }

        Ok(())
    }

    /// Get healing action history
    pub fn get_history(&self) -> &[HealingResult] {
        &self.action_history
    }

    /// Auto-heal based on detection
    pub async fn auto_heal(&mut self, event: &TelemetryEvent) -> Vec<HealingResult> {
        let mut results = Vec::new();

        // Check detections
        for detection in &event.detections {
            let actions = self.determine_healing_actions(detection, event);

            for action in actions {
                let result = self.heal(action).await;
                results.push(result);
            }
        }

        results
    }

    fn determine_healing_actions(
        &self,
        detection: &Detection,
        event: &TelemetryEvent,
    ) -> Vec<HealingAction> {
        let mut actions = Vec::new();

        match detection.detection_type {
            DetectionType::Ransomware => {
                // Kill the process immediately
                if let EventPayload::Process(proc) = &event.payload {
                    actions.push(HealingAction::KillProcessTree {
                        pid: proc.pid,
                        name: proc.name.clone(),
                    });
                }
            }
            DetectionType::Behavioral => {
                // Check for persistence
                for technique in &detection.mitre_techniques {
                    if technique.starts_with("T1547") || technique.starts_with("T1543") {
                        // This is a persistence mechanism
                        if let EventPayload::Registry(reg) = &event.payload {
                            actions.push(HealingAction::RemovePersistence {
                                persistence_type: PersistenceType::RegistryRunKey,
                                location: reg.key_path.clone(),
                            });
                        }
                    }
                }
            }
            DetectionType::Malware => {
                // Quarantine the file
                if let EventPayload::File(file) = &event.payload {
                    actions.push(HealingAction::QuarantineFile {
                        path: PathBuf::from(&file.path),
                        sha256: hex::encode(&file.sha256),
                    });
                }
            }
            _ => {}
        }

        actions
    }
}
