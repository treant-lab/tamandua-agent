//! Forensic Evidence Collection Module
//!
//! Automated collection of forensic artifacts for incident response.
//! This enables rapid triage and comprehensive evidence preservation.
//!
//! Features:
//! - Memory dump collection
//! - Process memory acquisition
//! - File timeline generation
//! - Registry hive extraction
//! - Event log collection
//! - Network connection snapshots
//! - Browser artifact collection
//! - Prefetch file analysis
//! - MFT extraction
//! - Evidence packaging with chain of custody

use crate::config::AgentConfig;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::info;

/// Forensic artifact types
#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactType {
    /// Full memory dump
    MemoryDump,
    /// Process-specific memory
    ProcessMemory { pid: u32 },
    /// Registry hive
    RegistryHive { hive: String },
    /// Event logs
    EventLogs { log_name: String },
    /// File system timeline
    FileTimeline { path: PathBuf },
    /// Network connections
    NetworkSnapshot,
    /// Browser history/cookies
    BrowserArtifacts { browser: String },
    /// Prefetch files
    PrefetchFiles,
    /// Master File Table
    MftExtract,
    /// Running processes
    ProcessList,
    /// Loaded modules/DLLs
    LoadedModules { pid: Option<u32> },
    /// Startup items
    StartupItems,
    /// Scheduled tasks
    ScheduledTasks,
    /// Services list
    ServicesList,
    /// User accounts
    UserAccounts,
    /// Custom file collection
    CustomFile { path: PathBuf },
}

/// Collected forensic artifact
#[derive(Debug, Clone)]
pub struct ForensicArtifact {
    pub artifact_type: ArtifactType,
    pub timestamp: u64,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub metadata: HashMap<String, String>,
}

/// Evidence package metadata
#[derive(Debug, Clone)]
pub struct EvidencePackage {
    pub case_id: String,
    pub collection_time: u64,
    pub agent_id: String,
    pub hostname: String,
    pub artifacts: Vec<ForensicArtifact>,
    pub total_size: u64,
    pub package_hash: String,
}

/// Forensic collector
pub struct ForensicCollector {
    config: AgentConfig,
    output_dir: PathBuf,
    artifacts: Vec<ForensicArtifact>,
}

impl ForensicCollector {
    /// Create a new forensic collector
    pub fn new(config: &AgentConfig) -> Self {
        let output_dir = if cfg!(windows) {
            PathBuf::from(r"C:\ProgramData\Tamandua\forensics")
        } else {
            PathBuf::from("/var/lib/tamandua/forensics")
        };

        let _ = std::fs::create_dir_all(&output_dir);

        Self {
            config: config.clone(),
            output_dir,
            artifacts: Vec::new(),
        }
    }

    /// Start a new forensic collection session
    pub fn start_collection(&mut self, case_id: &str) -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let collection_dir = self.output_dir.join(format!("{}_{}", case_id, timestamp));
        let _ = std::fs::create_dir_all(&collection_dir);

        self.artifacts.clear();

        info!(case_id = case_id, path = %collection_dir.display(), "Started forensic collection");
        collection_dir
    }

    /// Collect a specific artifact type
    pub async fn collect(
        &mut self,
        artifact_type: ArtifactType,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        info!(artifact = ?artifact_type, "Collecting forensic artifact");

        match artifact_type {
            ArtifactType::ProcessList => self.collect_process_list(output_dir).await,
            ArtifactType::NetworkSnapshot => self.collect_network_snapshot(output_dir).await,
            ArtifactType::ProcessMemory { pid } => {
                self.collect_process_memory(pid, output_dir).await
            }
            ArtifactType::RegistryHive { ref hive } => {
                self.collect_registry_hive(hive, output_dir).await
            }
            ArtifactType::EventLogs { ref log_name } => {
                self.collect_event_logs(log_name, output_dir).await
            }
            ArtifactType::BrowserArtifacts { ref browser } => {
                self.collect_browser_artifacts(browser, output_dir).await
            }
            ArtifactType::PrefetchFiles => self.collect_prefetch(output_dir).await,
            ArtifactType::StartupItems => self.collect_startup_items(output_dir).await,
            ArtifactType::ScheduledTasks => self.collect_scheduled_tasks(output_dir).await,
            ArtifactType::ServicesList => self.collect_services(output_dir).await,
            ArtifactType::LoadedModules { pid } => {
                self.collect_loaded_modules(pid, output_dir).await
            }
            ArtifactType::CustomFile { ref path } => {
                self.collect_custom_file(path, output_dir).await
            }
            ArtifactType::MemoryDump => self.collect_memory_dump(output_dir).await,
            ArtifactType::FileTimeline { ref path } => {
                self.collect_file_timeline(path, output_dir).await
            }
            ArtifactType::MftExtract => self.collect_mft_extract(output_dir).await,
            ArtifactType::UserAccounts => self.collect_user_accounts(output_dir).await,
        }
    }

    /// Collect running process list
    async fn collect_process_list(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        let output_path = output_dir.join("process_list.json");
        let mut processes = Vec::new();

        let sys = sysinfo::System::new_all();

        for (pid, process) in sys.processes() {
            processes.push(serde_json::json!({
                "pid": pid.as_u32(),
                "name": process.name(),
                "exe": process.exe().map(|p| p.to_string_lossy().to_string()),
                "cmd": process.cmd(),
                "cwd": process.cwd().map(|p| p.to_string_lossy().to_string()),
                "status": format!("{:?}", process.status()),
                "start_time": process.start_time(),
                "cpu_usage": process.cpu_usage(),
                "memory": process.memory(),
                "parent": process.parent().map(|p| p.as_u32()),
                "user_id": process.user_id().map(|u| u.to_string()),
            }));
        }

        let content = serde_json::to_string_pretty(&processes)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        let artifact = ForensicArtifact {
            artifact_type: ArtifactType::ProcessList,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([("process_count".to_string(), processes.len().to_string())]),
        };

        Ok(artifact)
    }

    /// Collect network connection snapshot
    async fn collect_network_snapshot(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        let output_path = output_dir.join("network_connections.json");

        #[cfg(target_os = "windows")]
        let connections = self.get_windows_connections()?;

        #[cfg(not(target_os = "windows"))]
        let connections = self.get_unix_connections()?;

        let content = serde_json::to_string_pretty(&connections)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        let artifact = ForensicArtifact {
            artifact_type: ArtifactType::NetworkSnapshot,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([(
                "connection_count".to_string(),
                connections.len().to_string(),
            )]),
        };

        Ok(artifact)
    }

    #[cfg(target_os = "windows")]
    fn get_windows_connections(&self) -> Result<Vec<serde_json::Value>> {
        use std::process::Command;

        let output = Command::new("netstat").args(["-ano"]).output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut connections = Vec::new();

        for line in stdout.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                connections.push(serde_json::json!({
                    "protocol": parts[0],
                    "local_address": parts[1],
                    "remote_address": parts[2],
                    "state": parts.get(3).unwrap_or(&""),
                    "pid": parts.last().unwrap_or(&""),
                }));
            }
        }

        Ok(connections)
    }

    #[cfg(not(target_os = "windows"))]
    fn get_unix_connections(&self) -> Result<Vec<serde_json::Value>> {
        use std::process::Command;

        let output = Command::new("ss").args(["-tunapO"]).output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut connections = Vec::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                connections.push(serde_json::json!({
                    "state": parts.get(0).unwrap_or(&""),
                    "recv_q": parts.get(1).unwrap_or(&""),
                    "send_q": parts.get(2).unwrap_or(&""),
                    "local_address": parts.get(3).unwrap_or(&""),
                    "remote_address": parts.get(4).unwrap_or(&""),
                    "process": parts.get(5).unwrap_or(&""),
                }));
            }
        }

        Ok(connections)
    }

    /// Collect process memory
    async fn collect_process_memory(
        &self,
        pid: u32,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        let output_path = output_dir.join(format!("process_{}_memory.dmp", pid));

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            // Use procdump or built-in minidump
            let path_str = output_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Memory dump output path contains invalid UTF-8"))?;
            let _ = Command::new("rundll32")
                .args([
                    "C:\\Windows\\System32\\comsvcs.dll",
                    "MiniDump",
                    &pid.to_string(),
                    path_str,
                    "full",
                ])
                .output();
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Read from /proc/[pid]/mem
            let maps_path = format!("/proc/{}/maps", pid);
            let mem_path = format!("/proc/{}/mem", pid);

            if Path::new(&maps_path).exists() {
                // Create dump file with mapped regions info
                let maps_content = std::fs::read_to_string(&maps_path)?;
                std::fs::write(&output_path, maps_content)?;
            } else {
                return Err(anyhow::anyhow!("Process {} not found", pid));
            }
        }

        if output_path.exists() {
            let metadata = std::fs::metadata(&output_path)?;
            let hash = self.calculate_file_hash(&output_path)?;

            Ok(ForensicArtifact {
                artifact_type: ArtifactType::ProcessMemory { pid },
                timestamp: Self::current_timestamp(),
                path: output_path,
                size: metadata.len(),
                sha256: hash,
                metadata: HashMap::from([("pid".to_string(), pid.to_string())]),
            })
        } else {
            Err(anyhow::anyhow!("Failed to dump process memory"))
        }
    }

    /// Collect registry hive
    #[cfg(target_os = "windows")]
    async fn collect_registry_hive(
        &self,
        hive: &str,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        use std::process::Command;

        let output_path = output_dir.join(format!("{}.reg", hive.replace("\\", "_")));

        let path_str = output_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Registry export path contains invalid UTF-8"))?;
        let output = Command::new("reg")
            .args(["export", hive, path_str, "/y"])
            .output()?;

        if output.status.success() && output_path.exists() {
            let metadata = std::fs::metadata(&output_path)?;
            let hash = self.calculate_file_hash(&output_path)?;

            Ok(ForensicArtifact {
                artifact_type: ArtifactType::RegistryHive {
                    hive: hive.to_string(),
                },
                timestamp: Self::current_timestamp(),
                path: output_path,
                size: metadata.len(),
                sha256: hash,
                metadata: HashMap::from([("hive".to_string(), hive.to_string())]),
            })
        } else {
            Err(anyhow::anyhow!("Failed to export registry hive: {}", hive))
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn collect_registry_hive(
        &self,
        _hive: &str,
        _output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        Err(anyhow::anyhow!(
            "Registry collection only available on Windows"
        ))
    }

    /// Collect event logs
    async fn collect_event_logs(
        &self,
        log_name: &str,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        let output_path = output_dir.join(format!("{}.evtx", log_name.replace("/", "_")));

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let path_str = output_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Event log export path contains invalid UTF-8"))?;
            let output = Command::new("wevtutil")
                .args(["epl", log_name, path_str])
                .output()?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to export event log: {}", log_name));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Copy syslog or journald logs
            let log_sources = ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages"];

            for source in log_sources {
                if Path::new(source).exists() && source.contains(log_name) {
                    std::fs::copy(source, &output_path)?;
                    break;
                }
            }
        }

        if output_path.exists() {
            let metadata = std::fs::metadata(&output_path)?;
            let hash = self.calculate_file_hash(&output_path)?;

            Ok(ForensicArtifact {
                artifact_type: ArtifactType::EventLogs {
                    log_name: log_name.to_string(),
                },
                timestamp: Self::current_timestamp(),
                path: output_path,
                size: metadata.len(),
                sha256: hash,
                metadata: HashMap::from([("log_name".to_string(), log_name.to_string())]),
            })
        } else {
            Err(anyhow::anyhow!("Event log not found: {}", log_name))
        }
    }

    /// Collect browser artifacts
    async fn collect_browser_artifacts(
        &self,
        browser: &str,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        let browser_dir = output_dir.join(format!("browser_{}", browser));
        let _ = std::fs::create_dir_all(&browser_dir);

        let profile_paths = self.get_browser_profile_paths(browser);
        let artifacts_to_copy = [
            "History",
            "Cookies",
            "Login Data",
            "Bookmarks",
            "Preferences",
        ];

        let mut total_size = 0u64;
        let mut copied_files = Vec::new();

        for profile in profile_paths {
            for artifact in &artifacts_to_copy {
                let source = profile.join(artifact);
                if source.exists() {
                    let profile_name = profile
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "unknown".into());
                    let dest = browser_dir.join(format!("{}_{}", profile_name, artifact));
                    if let Ok(_) = std::fs::copy(&source, &dest) {
                        if let Ok(meta) = std::fs::metadata(&dest) {
                            total_size += meta.len();
                            copied_files.push(artifact.to_string());
                        }
                    }
                }
            }
        }

        if total_size > 0 {
            Ok(ForensicArtifact {
                artifact_type: ArtifactType::BrowserArtifacts {
                    browser: browser.to_string(),
                },
                timestamp: Self::current_timestamp(),
                path: browser_dir,
                size: total_size,
                sha256: "directory".to_string(),
                metadata: HashMap::from([
                    ("browser".to_string(), browser.to_string()),
                    ("artifacts".to_string(), copied_files.join(", ")),
                ]),
            })
        } else {
            Err(anyhow::anyhow!(
                "No browser artifacts found for: {}",
                browser
            ))
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
                        PathBuf::from(&local_app_data).join(r"Google\Chrome\User Data\Default"),
                    );
                }
                "firefox" => {
                    let profiles = PathBuf::from(&app_data).join(r"Mozilla\Firefox\Profiles");
                    if let Ok(entries) = std::fs::read_dir(&profiles) {
                        for entry in entries.flatten() {
                            paths.push(entry.path());
                        }
                    }
                }
                "edge" => {
                    paths.push(
                        PathBuf::from(&local_app_data).join(r"Microsoft\Edge\User Data\Default"),
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
                    let profiles = PathBuf::from(&home).join(".mozilla/firefox");
                    if let Ok(entries) = std::fs::read_dir(&profiles) {
                        for entry in entries.flatten() {
                            if entry.file_name().to_string_lossy().contains(".default") {
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

    /// Collect prefetch files (Windows)
    #[cfg(target_os = "windows")]
    async fn collect_prefetch(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        let prefetch_dir = Path::new(r"C:\Windows\Prefetch");
        let output_path = output_dir.join("prefetch");
        let _ = std::fs::create_dir_all(&output_path);

        let mut total_size = 0u64;
        let mut file_count = 0;

        if let Ok(entries) = std::fs::read_dir(prefetch_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "pf").unwrap_or(false) {
                    let fname = match path.file_name() {
                        Some(n) => n.to_owned(),
                        None => continue,
                    };
                    let dest = output_path.join(fname);
                    if let Ok(_) = std::fs::copy(&path, &dest) {
                        if let Ok(meta) = std::fs::metadata(&dest) {
                            total_size += meta.len();
                            file_count += 1;
                        }
                    }
                }
            }
        }

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::PrefetchFiles,
            timestamp: Self::current_timestamp(),
            path: output_path,
            size: total_size,
            sha256: "directory".to_string(),
            metadata: HashMap::from([("file_count".to_string(), file_count.to_string())]),
        })
    }

    #[cfg(not(target_os = "windows"))]
    async fn collect_prefetch(&self, _output_dir: &Path) -> Result<ForensicArtifact> {
        Err(anyhow::anyhow!(
            "Prefetch collection only available on Windows"
        ))
    }

    /// Collect startup items
    async fn collect_startup_items(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        let output_path = output_dir.join("startup_items.json");
        let mut items = Vec::new();

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            // Registry run keys
            for key in &[
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ] {
                let output = Command::new("reg").args(["query", key]).output();

                if let Ok(output) = output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    items.push(serde_json::json!({
                        "type": "registry",
                        "location": key,
                        "content": stdout.to_string(),
                    }));
                }
            }

            // Startup folders
            let startup_folders = [
                std::env::var("APPDATA")
                    .map(|p| format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", p)),
                Ok(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup".to_string()),
            ];

            for folder in startup_folders.iter().flatten() {
                if let Ok(entries) = std::fs::read_dir(folder) {
                    for entry in entries.flatten() {
                        items.push(serde_json::json!({
                            "type": "startup_folder",
                            "path": entry.path().to_string_lossy(),
                        }));
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // /etc/rc.local, systemd services, cron
            let locations = ["/etc/rc.local", "/etc/init.d", "/etc/systemd/system"];

            for loc in locations {
                if Path::new(loc).exists() {
                    items.push(serde_json::json!({
                        "type": "startup",
                        "location": loc,
                    }));
                }
            }
        }

        let content = serde_json::to_string_pretty(&items)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::StartupItems,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([("item_count".to_string(), items.len().to_string())]),
        })
    }

    /// Collect scheduled tasks
    async fn collect_scheduled_tasks(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        let output_path = output_dir.join("scheduled_tasks.json");

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("schtasks")
                .args(["/Query", "/FO", "CSV", "/V"])
                .output()?;

            let content = String::from_utf8_lossy(&output.stdout);
            let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

            return Ok(ForensicArtifact {
                artifact_type: ArtifactType::ScheduledTasks,
                timestamp: Self::current_timestamp(),
                path,
                size,
                sha256: hash,
                metadata: HashMap::new(),
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;

            let mut tasks = Vec::new();

            // System crontab
            if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
                tasks.push(serde_json::json!({
                    "type": "crontab",
                    "location": "/etc/crontab",
                    "content": content,
                }));
            }

            // User crontabs
            let output = Command::new("crontab").args(["-l"]).output();
            if let Ok(output) = output {
                tasks.push(serde_json::json!({
                    "type": "user_crontab",
                    "content": String::from_utf8_lossy(&output.stdout).to_string(),
                }));
            }

            let content = serde_json::to_string_pretty(&tasks)?;
            let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

            Ok(ForensicArtifact {
                artifact_type: ArtifactType::ScheduledTasks,
                timestamp: Self::current_timestamp(),
                path,
                size,
                sha256: hash,
                metadata: HashMap::new(),
            })
        }
    }

    /// Collect services list
    async fn collect_services(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        let output_path = output_dir.join("services.json");

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("sc")
                .args(["query", "state=", "all"])
                .output()?;

            let content = String::from_utf8_lossy(&output.stdout);
            let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

            return Ok(ForensicArtifact {
                artifact_type: ArtifactType::ServicesList,
                timestamp: Self::current_timestamp(),
                path,
                size,
                sha256: hash,
                metadata: HashMap::new(),
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;

            let output = Command::new("systemctl")
                .args(["list-units", "--type=service", "--all"])
                .output()?;

            let content = String::from_utf8_lossy(&output.stdout);
            let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

            Ok(ForensicArtifact {
                artifact_type: ArtifactType::ServicesList,
                timestamp: Self::current_timestamp(),
                path,
                size,
                sha256: hash,
                metadata: HashMap::new(),
            })
        }
    }

    /// Collect loaded modules
    async fn collect_loaded_modules(
        &self,
        pid: Option<u32>,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        let output_path = output_dir.join(format!(
            "modules_{}.json",
            pid.map(|p| p.to_string()).unwrap_or("all".to_string())
        ));

        let sys = sysinfo::System::new_all();
        let mut modules = Vec::new();

        // Collect modules based on whether we're filtering by PID
        match pid {
            Some(p) => {
                let target_pid = sysinfo::Pid::from_u32(p);
                if let Some(process) = sys.process(target_pid) {
                    modules.push(serde_json::json!({
                        "pid": p,
                        "name": process.name(),
                        "exe": process.exe().map(|path| path.to_string_lossy().to_string()),
                    }));
                }
            }
            None => {
                for (pid, process) in sys.processes() {
                    modules.push(serde_json::json!({
                        "pid": pid.as_u32(),
                        "name": process.name(),
                        "exe": process.exe().map(|path| path.to_string_lossy().to_string()),
                    }));
                }
            }
        };

        let content = serde_json::to_string_pretty(&modules)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::LoadedModules { pid },
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::new(),
        })
    }

    /// Collect a custom file
    async fn collect_custom_file(
        &self,
        source: &Path,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        if !source.exists() {
            return Err(anyhow::anyhow!("File not found: {}", source.display()));
        }

        let filename = source.file_name().unwrap_or_default();
        let output_path = output_dir.join(filename);

        std::fs::copy(source, &output_path)?;

        let metadata = std::fs::metadata(&output_path)?;
        let hash = self.calculate_file_hash(&output_path)?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::CustomFile {
                path: source.to_path_buf(),
            },
            timestamp: Self::current_timestamp(),
            path: output_path,
            size: metadata.len(),
            sha256: hash,
            metadata: HashMap::from([(
                "original_path".to_string(),
                source.to_string_lossy().to_string(),
            )]),
        })
    }

    /// Collect a full memory dump (process dump approach)
    ///
    /// On Windows, uses MiniDumpWriteDump via comsvcs.dll for the current process
    /// or lsass for a full system snapshot. A true full-RAM dump requires a kernel
    /// driver, so we dump the current agent process memory as a baseline artifact.
    /// On Linux, reads /proc/self/maps and /proc/self/mem.
    #[cfg(target_os = "windows")]
    async fn collect_memory_dump(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        info!("Collecting memory dump (Windows MiniDumpWriteDump)");

        let output_path = output_dir.join("memory_dump.dmp");

        // Use the Windows API directly for MiniDumpWriteDump
        // We dump the current process as a forensic snapshot of the agent state.
        // For dumping arbitrary processes, the PID-based ProcessMemory variant should be used.
        unsafe {
            use windows::core::HSTRING;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
            };
            use windows::Win32::System::Diagnostics::Debug::{
                MiniDumpWithFullMemory, MiniDumpWriteDump,
            };
            use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

            let file_path_w = HSTRING::from(output_path.to_string_lossy().as_ref());
            let file_handle = CreateFileW(
                &file_path_w,
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?;

            let process_handle = GetCurrentProcess();
            let process_id = GetCurrentProcessId();

            let result = MiniDumpWriteDump(
                process_handle,
                process_id,
                file_handle,
                MiniDumpWithFullMemory,
                None,
                None,
                None,
            );

            CloseHandle(file_handle)?;

            if result.is_err() {
                return Err(anyhow::anyhow!("MiniDumpWriteDump failed"));
            }
        }

        if output_path.exists() {
            let metadata = std::fs::metadata(&output_path)?;
            let hash = self.calculate_file_hash(&output_path)?;

            Ok(ForensicArtifact {
                artifact_type: ArtifactType::MemoryDump,
                timestamp: Self::current_timestamp(),
                path: output_path,
                size: metadata.len(),
                sha256: hash,
                metadata: HashMap::from([
                    (
                        "dump_type".to_string(),
                        "MiniDumpWithFullMemory".to_string(),
                    ),
                    ("source".to_string(), "current_process".to_string()),
                ]),
            })
        } else {
            Err(anyhow::anyhow!("Memory dump file was not created"))
        }
    }

    #[cfg(target_os = "linux")]
    async fn collect_memory_dump(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        info!("Collecting memory dump (Linux /proc/self/mem)");

        let output_path = output_dir.join("memory_dump.bin");
        let pid = std::process::id();

        let maps_path = format!("/proc/{}/maps", pid);
        let mem_path = format!("/proc/{}/mem", pid);

        let maps_content = std::fs::read_to_string(&maps_path)?;

        // Parse memory maps and dump readable regions
        let mut dump_file = std::fs::File::create(&output_path)?;
        let mut mem_file = std::fs::File::open(&mem_path)?;
        let mut total_bytes = 0u64;
        let mut regions_dumped = 0u64;

        use std::io::{Seek, SeekFrom, Write};

        for line in maps_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() != 2 {
                continue;
            }

            let perms = parts.get(1).unwrap_or(&"");
            // Only dump readable regions
            if !perms.starts_with('r') {
                continue;
            }

            let start = u64::from_str_radix(addr_range[0], 16).unwrap_or(0);
            let end = u64::from_str_radix(addr_range[1], 16).unwrap_or(0);
            let region_size = end - start;

            // Skip very large regions (e.g., VDSO, vsyscall) or zero-size
            if region_size == 0 || region_size > 256 * 1024 * 1024 {
                continue;
            }

            // Write a region header
            let header = format!("=== REGION {:#x}-{:#x} {} ===\n", start, end, perms);
            let _ = dump_file.write_all(header.as_bytes());

            if mem_file.seek(SeekFrom::Start(start)).is_ok() {
                let mut buf = vec![0u8; region_size.min(4 * 1024 * 1024) as usize];
                match mem_file.read(&mut buf) {
                    Ok(n) => {
                        let _ = dump_file.write_all(&buf[..n]);
                        total_bytes += n as u64;
                        regions_dumped += 1;
                    }
                    Err(_) => continue, // permission denied on some regions is expected
                }
            }
        }

        // Also save the maps file alongside the dump
        let maps_output = output_dir.join("memory_maps.txt");
        std::fs::write(&maps_output, &maps_content)?;

        let file_meta = std::fs::metadata(&output_path)?;
        let hash = self.calculate_file_hash(&output_path)?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::MemoryDump,
            timestamp: Self::current_timestamp(),
            path: output_path,
            size: file_meta.len(),
            sha256: hash,
            metadata: HashMap::from([
                ("dump_type".to_string(), "proc_mem".to_string()),
                ("pid".to_string(), pid.to_string()),
                ("regions_dumped".to_string(), regions_dumped.to_string()),
                ("total_bytes".to_string(), total_bytes.to_string()),
            ]),
        })
    }

    #[cfg(target_os = "macos")]
    async fn collect_memory_dump(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        // macOS does not expose /proc/pid/mem. Use vmmap or similar.
        info!("Collecting memory dump (macOS vmmap)");

        let output_path = output_dir.join("memory_dump_vmmap.txt");
        let pid = std::process::id();

        let output = std::process::Command::new("vmmap")
            .args([&pid.to_string()])
            .output()?;

        let content = String::from_utf8_lossy(&output.stdout);
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::MemoryDump,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([
                ("dump_type".to_string(), "vmmap".to_string()),
                ("pid".to_string(), pid.to_string()),
            ]),
        })
    }

    /// Collect file timeline: walk a directory and gather file metadata sorted by modification time
    async fn collect_file_timeline(
        &self,
        target_path: &Path,
        output_dir: &Path,
    ) -> Result<ForensicArtifact> {
        use walkdir::WalkDir;

        info!(path = %target_path.display(), "Collecting file timeline");

        if !target_path.exists() {
            return Err(anyhow::anyhow!(
                "Target path does not exist: {}",
                target_path.display()
            ));
        }

        let output_path = output_dir.join("file_timeline.json");

        let mut entries: Vec<serde_json::Value> = Vec::new();
        let max_entries: usize = 50_000; // Limit to prevent excessive memory usage

        for entry in WalkDir::new(target_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .take(max_entries)
        {
            let path = entry.path();
            let metadata = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let created = metadata
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            let accessed = metadata
                .accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            let mut entry_json = serde_json::json!({
                "path": path.to_string_lossy(),
                "size": metadata.len(),
                "is_dir": metadata.is_dir(),
                "is_file": metadata.is_file(),
                "is_symlink": metadata.file_type().is_symlink(),
                "readonly": metadata.permissions().readonly(),
                "created": created,
                "modified": modified,
                "accessed": accessed,
            });

            // Platform-specific owner information
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                entry_json["uid"] = serde_json::json!(metadata.uid());
                entry_json["gid"] = serde_json::json!(metadata.gid());
                entry_json["mode"] = serde_json::json!(format!("{:o}", metadata.mode()));
                entry_json["inode"] = serde_json::json!(metadata.ino());
            }

            entries.push(entry_json);
        }

        // Sort by modification time (most recent first)
        entries.sort_by(|a, b| {
            let a_mod = a.get("modified").and_then(|v| v.as_u64()).unwrap_or(0);
            let b_mod = b.get("modified").and_then(|v| v.as_u64()).unwrap_or(0);
            b_mod.cmp(&a_mod)
        });

        let content = serde_json::to_string_pretty(&serde_json::json!({
            "target_path": target_path.to_string_lossy(),
            "collection_time": Self::current_timestamp(),
            "total_entries": entries.len(),
            "entries": entries,
        }))?;

        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::FileTimeline {
                path: target_path.to_path_buf(),
            },
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([
                (
                    "target_path".to_string(),
                    target_path.to_string_lossy().to_string(),
                ),
                ("entry_count".to_string(), entries.len().to_string()),
            ]),
        })
    }

    /// Extract Master File Table (MFT) records - Windows only
    ///
    /// Reads raw MFT entries from \\.\C: using CreateFile with FILE_READ_DATA.
    /// Requires administrator privileges.
    #[cfg(target_os = "windows")]
    async fn collect_mft_extract(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        info!("Extracting MFT (Windows)");

        let output_path = output_dir.join("mft_extract.bin");

        unsafe {
            use windows::core::HSTRING;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, ReadFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            };
            use windows::Win32::System::Ioctl::{
                FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER,
            };
            use windows::Win32::System::IO::DeviceIoControl;

            let volume_path = HSTRING::from(r"\\.\C:");

            // Open the volume handle
            let volume_handle = CreateFileW(
                &volume_path,
                0x80000000, // GENERIC_READ
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )?;

            // Get NTFS volume data to find MFT location
            let mut volume_data: NTFS_VOLUME_DATA_BUFFER = std::mem::zeroed();
            let mut bytes_returned: u32 = 0;

            let ioctl_result = DeviceIoControl(
                volume_handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                None,
                0,
                Some(&mut volume_data as *mut _ as *mut _),
                std::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
                Some(&mut bytes_returned),
                None,
            );

            if ioctl_result.is_err() {
                CloseHandle(volume_handle)?;
                return Err(anyhow::anyhow!(
                    "Failed to get NTFS volume data. Ensure agent is running with administrator privileges."
                ));
            }

            let mft_start_lcn = volume_data.MftStartLcn;
            let bytes_per_cluster = volume_data.BytesPerCluster;
            let bytes_per_mft_record = if volume_data.BytesPerFileRecordSegment > 0 {
                volume_data.BytesPerFileRecordSegment as u32
            } else {
                1024 // Default MFT record size
            };

            // Calculate MFT start offset in bytes
            let mft_offset = mft_start_lcn as u64 * bytes_per_cluster as u64;

            // Seek to MFT start
            use windows::Win32::Storage::FileSystem::SetFilePointerEx;
            use windows::Win32::Storage::FileSystem::FILE_BEGIN;

            let mut new_pos: i64 = 0;
            SetFilePointerEx(
                volume_handle,
                mft_offset as i64,
                Some(&mut new_pos),
                FILE_BEGIN,
            )?;

            // Read first N MFT records (first 1000 records capture core system files)
            let records_to_read: u32 = 1000;
            let total_read_size = records_to_read * bytes_per_mft_record;
            let mut mft_buffer = vec![0u8; total_read_size as usize];
            let mut bytes_read: u32 = 0;

            let read_result = ReadFile(
                volume_handle,
                Some(&mut mft_buffer),
                Some(&mut bytes_read),
                None,
            );

            CloseHandle(volume_handle)?;

            if read_result.is_err() || bytes_read == 0 {
                return Err(anyhow::anyhow!(
                    "Failed to read MFT data from volume. Ensure administrator privileges."
                ));
            }

            // Truncate buffer to actual bytes read
            mft_buffer.truncate(bytes_read as usize);

            // Write raw MFT data
            std::fs::write(&output_path, &mft_buffer)?;

            // Also create a parsed summary of file records
            let summary_path = output_dir.join("mft_summary.json");
            let mut mft_records = Vec::new();

            let record_size = bytes_per_mft_record as usize;
            for i in 0..(bytes_read as usize / record_size) {
                let offset = i * record_size;
                let record = &mft_buffer[offset..offset + record_size];

                // Check for FILE signature (0x46494C45)
                if record.len() >= 4 && &record[0..4] == b"FILE" {
                    // Extract basic MFT record info
                    let flags = if record.len() > 23 {
                        u16::from_le_bytes([record[22], record[23]])
                    } else {
                        0
                    };

                    let in_use = (flags & 0x01) != 0;
                    let is_directory = (flags & 0x02) != 0;

                    mft_records.push(serde_json::json!({
                        "record_number": i,
                        "offset": offset,
                        "in_use": in_use,
                        "is_directory": is_directory,
                        "flags": flags,
                    }));
                }
            }

            let summary = serde_json::to_string_pretty(&serde_json::json!({
                "mft_start_offset": mft_offset,
                "bytes_per_cluster": bytes_per_cluster,
                "bytes_per_mft_record": bytes_per_mft_record,
                "records_read": mft_records.len(),
                "total_bytes": bytes_read,
                "records": mft_records,
            }))?;
            std::fs::write(&summary_path, &summary)?;
        }

        let file_meta = std::fs::metadata(&output_path)?;
        let hash = self.calculate_file_hash(&output_path)?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::MftExtract,
            timestamp: Self::current_timestamp(),
            path: output_path,
            size: file_meta.len(),
            sha256: hash,
            metadata: HashMap::from([
                ("source".to_string(), "raw_mft".to_string()),
                ("volume".to_string(), r"\\.\C:".to_string()),
            ]),
        })
    }

    #[cfg(not(target_os = "windows"))]
    async fn collect_mft_extract(&self, _output_dir: &Path) -> Result<ForensicArtifact> {
        Err(anyhow::anyhow!(
            "MFT extraction is only available on Windows (NTFS). \
             On Linux, consider using ext4 inode analysis or debugfs instead."
        ))
    }

    /// Collect user account information
    #[cfg(target_os = "windows")]
    async fn collect_user_accounts(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        use std::process::Command;

        info!("Collecting user accounts (Windows)");

        let output_path = output_dir.join("user_accounts.json");
        let mut accounts = Vec::new();

        // Use "net user" to enumerate local accounts
        let output = Command::new("net").args(["user"]).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the net user output: usernames are listed between the header/footer dashes
        let mut in_user_section = false;
        for line in stdout.lines() {
            if line.starts_with("---") {
                in_user_section = !in_user_section;
                continue;
            }
            if in_user_section && !line.trim().is_empty() {
                // net user output has usernames in columns separated by spaces
                for username in line.split_whitespace() {
                    if username.is_empty() {
                        continue;
                    }

                    // Get detailed info for each user
                    let detail_output = Command::new("net").args(["user", username]).output();

                    let mut user_info = serde_json::json!({
                        "username": username,
                    });

                    if let Ok(detail) = detail_output {
                        let detail_str = String::from_utf8_lossy(&detail.stdout);
                        for detail_line in detail_str.lines() {
                            let trimmed = detail_line.trim();
                            if let Some((key, value)) = trimmed.split_once("  ") {
                                let key = key.trim().to_lowercase().replace(' ', "_");
                                let value = value.trim();
                                if !key.is_empty() && !value.is_empty() {
                                    user_info[&key] = serde_json::json!(value);
                                }
                            }
                        }
                    }

                    accounts.push(user_info);
                }
            }
        }

        // Also get group membership info via "net localgroup"
        let group_output = Command::new("net").args(["localgroup"]).output();
        let mut groups = Vec::new();
        if let Ok(go) = group_output {
            let go_str = String::from_utf8_lossy(&go.stdout);
            let mut in_group_section = false;
            for line in go_str.lines() {
                if line.starts_with("---") {
                    in_group_section = !in_group_section;
                    continue;
                }
                if in_group_section {
                    let group_name = line.trim().trim_start_matches('*');
                    if !group_name.is_empty() {
                        // Get group members
                        let members_output = Command::new("net")
                            .args(["localgroup", group_name])
                            .output();

                        let mut members = Vec::new();
                        if let Ok(mo) = members_output {
                            let mo_str = String::from_utf8_lossy(&mo.stdout);
                            let mut in_members = false;
                            for member_line in mo_str.lines() {
                                if member_line.starts_with("---") {
                                    in_members = !in_members;
                                    continue;
                                }
                                if in_members
                                    && !member_line.trim().is_empty()
                                    && !member_line.contains("completed successfully")
                                {
                                    members.push(member_line.trim().to_string());
                                }
                            }
                        }

                        groups.push(serde_json::json!({
                            "group": group_name,
                            "members": members,
                        }));
                    }
                }
            }
        }

        let result = serde_json::json!({
            "collection_time": Self::current_timestamp(),
            "platform": "windows",
            "accounts": accounts,
            "groups": groups,
        });

        let content = serde_json::to_string_pretty(&result)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::UserAccounts,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([
                ("account_count".to_string(), accounts.len().to_string()),
                ("group_count".to_string(), groups.len().to_string()),
            ]),
        })
    }

    #[cfg(target_os = "linux")]
    async fn collect_user_accounts(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        info!("Collecting user accounts (Linux)");

        let output_path = output_dir.join("user_accounts.json");
        let mut accounts = Vec::new();

        // Parse /etc/passwd
        let passwd_content = std::fs::read_to_string("/etc/passwd")?;
        for line in passwd_content.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7 {
                let mut account = serde_json::json!({
                    "username": fields[0],
                    "uid": fields[2].parse::<u32>().unwrap_or(0),
                    "gid": fields[3].parse::<u32>().unwrap_or(0),
                    "gecos": fields[4],
                    "home": fields[5],
                    "shell": fields[6],
                });

                // Check if shell is a valid login shell (not /sbin/nologin, /bin/false)
                let shell = fields[6];
                let has_login = !shell.contains("nologin")
                    && !shell.contains("/bin/false")
                    && !shell.is_empty();
                account["has_login_shell"] = serde_json::json!(has_login);

                accounts.push(account);
            }
        }

        // Try to read /etc/shadow for password status (requires root)
        let shadow_info: Vec<serde_json::Value> =
            if let Ok(shadow_content) = std::fs::read_to_string("/etc/shadow") {
                shadow_content
                    .lines()
                    .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                    .filter_map(|line| {
                        let fields: Vec<&str> = line.split(':').collect();
                        if fields.len() >= 9 {
                            let password_hash = fields[1];
                            let password_status = if password_hash == "!" || password_hash == "*" {
                                "locked"
                            } else if password_hash.is_empty() {
                                "no_password"
                            } else {
                                "set"
                            };

                            Some(serde_json::json!({
                                "username": fields[0],
                                "password_status": password_status,
                                "last_change": fields[2],
                                "min_age": fields[3],
                                "max_age": fields[4],
                                "warn_days": fields[5],
                                "inactive_days": fields[6],
                                "expire_date": fields[7],
                            }))
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };

        // Parse /etc/group
        let mut groups = Vec::new();
        if let Ok(group_content) = std::fs::read_to_string("/etc/group") {
            for line in group_content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 4 {
                    let members: Vec<&str> =
                        fields[3].split(',').filter(|m| !m.is_empty()).collect();
                    groups.push(serde_json::json!({
                        "group": fields[0],
                        "gid": fields[2].parse::<u32>().unwrap_or(0),
                        "members": members,
                    }));
                }
            }
        }

        let result = serde_json::json!({
            "collection_time": Self::current_timestamp(),
            "platform": "linux",
            "accounts": accounts,
            "shadow_info": shadow_info,
            "groups": groups,
        });

        let content = serde_json::to_string_pretty(&result)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::UserAccounts,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([
                ("account_count".to_string(), accounts.len().to_string()),
                ("group_count".to_string(), groups.len().to_string()),
                (
                    "shadow_readable".to_string(),
                    (!shadow_info.is_empty()).to_string(),
                ),
            ]),
        })
    }

    #[cfg(target_os = "macos")]
    async fn collect_user_accounts(&self, output_dir: &Path) -> Result<ForensicArtifact> {
        use std::process::Command;

        info!("Collecting user accounts (macOS)");

        let output_path = output_dir.join("user_accounts.json");
        let mut accounts = Vec::new();

        // Use dscl to list users
        let output = Command::new("dscl")
            .args([".", "-list", "/Users"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for username in stdout.lines() {
            let username = username.trim();
            if username.is_empty() {
                continue;
            }

            let mut user_info = serde_json::json!({
                "username": username,
            });

            // Get detailed info for each user
            let detail = Command::new("dscl")
                .args([".", "-read", &format!("/Users/{}", username)])
                .output();

            if let Ok(detail) = detail {
                let detail_str = String::from_utf8_lossy(&detail.stdout);
                for line in detail_str.lines() {
                    if let Some((key, value)) = line.split_once(": ") {
                        let key = key.trim().to_lowercase().replace(' ', "_");
                        let value = value.trim();
                        match key.as_str() {
                            "uniqueid" => {
                                user_info["uid"] = serde_json::json!(value);
                            }
                            "primarygroupid" => {
                                user_info["gid"] = serde_json::json!(value);
                            }
                            "nfshomedirectory" => {
                                user_info["home"] = serde_json::json!(value);
                            }
                            "usershell" => {
                                user_info["shell"] = serde_json::json!(value);
                            }
                            "realname" => {
                                user_info["realname"] = serde_json::json!(value);
                            }
                            _ => {}
                        }
                    }
                }
            }

            accounts.push(user_info);
        }

        // Get groups
        let mut groups = Vec::new();
        let group_output = Command::new("dscl")
            .args([".", "-list", "/Groups"])
            .output();

        if let Ok(go) = group_output {
            let go_str = String::from_utf8_lossy(&go.stdout);
            for group_name in go_str.lines() {
                let group_name = group_name.trim();
                if group_name.is_empty() {
                    continue;
                }

                let members_output = Command::new("dscl")
                    .args([
                        ".",
                        "-read",
                        &format!("/Groups/{}", group_name),
                        "GroupMembership",
                    ])
                    .output();

                let members = if let Ok(mo) = members_output {
                    let mo_str = String::from_utf8_lossy(&mo.stdout);
                    mo_str
                        .strip_prefix("GroupMembership: ")
                        .unwrap_or(&mo_str)
                        .split_whitespace()
                        .map(String::from)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                groups.push(serde_json::json!({
                    "group": group_name,
                    "members": members,
                }));
            }
        }

        let result = serde_json::json!({
            "collection_time": Self::current_timestamp(),
            "platform": "macos",
            "accounts": accounts,
            "groups": groups,
        });

        let content = serde_json::to_string_pretty(&result)?;
        let (path, size, hash) = self.write_artifact(&output_path, content.as_bytes())?;

        Ok(ForensicArtifact {
            artifact_type: ArtifactType::UserAccounts,
            timestamp: Self::current_timestamp(),
            path,
            size,
            sha256: hash,
            metadata: HashMap::from([
                ("account_count".to_string(), accounts.len().to_string()),
                ("group_count".to_string(), groups.len().to_string()),
            ]),
        })
    }

    /// Package all collected artifacts
    pub fn package_evidence(
        &self,
        case_id: &str,
        collection_dir: &Path,
    ) -> Result<EvidencePackage> {
        let timestamp = Self::current_timestamp();

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let total_size: u64 = self.artifacts.iter().map(|a| a.size).sum();

        // Create manifest
        let manifest = serde_json::json!({
            "case_id": case_id,
            "collection_time": timestamp,
            "agent_id": self.config.agent_id,
            "hostname": hostname,
            "artifacts": self.artifacts.iter().map(|a| {
                serde_json::json!({
                    "type": format!("{:?}", a.artifact_type),
                    "path": a.path.to_string_lossy(),
                    "size": a.size,
                    "sha256": a.sha256,
                    "metadata": a.metadata,
                })
            }).collect::<Vec<_>>(),
        });

        let manifest_path = collection_dir.join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

        // Calculate overall package hash
        let package_hash = self.calculate_file_hash(&manifest_path)?;

        Ok(EvidencePackage {
            case_id: case_id.to_string(),
            collection_time: timestamp,
            agent_id: self.config.agent_id.clone(),
            hostname,
            artifacts: self.artifacts.clone(),
            total_size,
            package_hash,
        })
    }

    // Helper functions

    fn write_artifact(&self, path: &Path, content: &[u8]) -> Result<(PathBuf, u64, String)> {
        std::fs::write(path, content)?;
        let size = content.len() as u64;
        let hash = self.hash_bytes(content);
        Ok((path.to_path_buf(), size, hash))
    }

    fn hash_bytes(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn calculate_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
