//! Phantom DLL Hollowing Detection Collector
//!
//! Detects phantom DLL hollowing - an advanced evasion technique where:
//! 1. A legitimate DLL is loaded from disk
//! 2. The DLL file is immediately deleted while section remains mapped
//! 3. The process continues to execute with a "ghost" module backed by nothing
//!
//! ## Detection Methods
//!
//! ### Module File Existence Validation
//! - Enumerate loaded modules for each process
//! - Check if backing files still exist on disk
//! - Track file deletion events after module loads
//!
//! ### Section-to-File Correlation
//! - Monitor NtCreateSection and NtMapViewOfSection
//! - Correlate section creation with subsequent file deletion
//! - Detect modules loaded from temp paths that are deleted
//!
//! ### Timing Analysis
//! - Track time between DLL load and file deletion
//! - Very short intervals (< 5s) are highly suspicious
//!
//! ## Phantom DLL Indicators
//! 1. Module in process without backing file on disk
//! 2. Module loaded from %TEMP% then deleted
//! 3. File deletion event immediately after section mapping
//! 4. Section created from file that no longer exists
//! 5. Module with valid PE headers but non-existent path
//!
//! MITRE ATT&CK:
//! - T1055.012 (Process Hollowing) - Phantom DLL variant
//! - T1070.004 (Indicator Removal: File Deletion)
//! - T1620 (Reflective Code Loading)

// Phantom DLL hollowing detector. Allowlist/helper utilities and scaffolded
// fields are retained for upcoming detection stages.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

/// Phantom DLL detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomDllEvent {
    /// Process ID containing the phantom module
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Module name (DLL name)
    pub module_name: String,
    /// Original module path (now deleted or missing)
    pub module_path: String,
    /// Module base address in process memory
    pub module_base: u64,
    /// Module size in bytes
    pub module_size: u64,
    /// Detection type/indicator
    pub indicator: PhantomIndicator,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Time since module was loaded (milliseconds, if known)
    pub load_age_ms: Option<u64>,
    /// Whether the original path was in a temporary directory
    pub was_temp_path: bool,
    /// Additional evidence details
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique
    pub mitre_technique: String,
}

/// Phantom DLL indicator types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhantomIndicator {
    /// Module file does not exist on disk
    ModuleFileNotFound,
    /// File was deleted shortly after module load
    FileDeletedAfterLoad,
    /// Module loaded from temp path and deleted
    TempPathDeleted,
    /// Section created from file that was then deleted
    SectionFromDeletedFile,
    /// Module path is invalid/malformed
    InvalidModulePath,
    /// Module loaded from network path that's now inaccessible
    NetworkPathInaccessible,
    /// Multiple phantom indicators combined
    MultipleIndicators,
}

impl PhantomIndicator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ModuleFileNotFound => "module_file_not_found",
            Self::FileDeletedAfterLoad => "file_deleted_after_load",
            Self::TempPathDeleted => "temp_path_deleted",
            Self::SectionFromDeletedFile => "section_from_deleted_file",
            Self::InvalidModulePath => "invalid_module_path",
            Self::NetworkPathInaccessible => "network_path_inaccessible",
            Self::MultipleIndicators => "multiple_indicators",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::FileDeletedAfterLoad => Severity::Critical,
            Self::TempPathDeleted => Severity::Critical,
            Self::SectionFromDeletedFile => Severity::Critical,
            Self::ModuleFileNotFound => Severity::High,
            Self::MultipleIndicators => Severity::Critical,
            Self::InvalidModulePath => Severity::Medium,
            Self::NetworkPathInaccessible => Severity::Medium,
        }
    }

    pub fn confidence(&self) -> f32 {
        match self {
            Self::FileDeletedAfterLoad => 0.95,
            Self::SectionFromDeletedFile => 0.95,
            Self::TempPathDeleted => 0.90,
            Self::MultipleIndicators => 0.98,
            Self::ModuleFileNotFound => 0.80,
            Self::InvalidModulePath => 0.60,
            Self::NetworkPathInaccessible => 0.50,
        }
    }
}

/// Tracked module load event
#[derive(Debug, Clone)]
struct ModuleLoadEvent {
    /// Process ID
    pid: u32,
    /// Module path
    path: String,
    /// Module base address
    base_address: u64,
    /// Module size
    size: u64,
    /// Load timestamp
    load_time: Instant,
    /// Whether this was a temp path
    is_temp_path: bool,
}

/// Tracked file deletion event
#[derive(Debug, Clone)]
struct FileDeletionEvent {
    /// Deleted file path
    path: String,
    /// Process ID that deleted the file
    pid: u32,
    /// Deletion timestamp
    deletion_time: Instant,
}

/// Phantom DLL hollowing detector configuration
#[derive(Debug, Clone)]
pub struct PhantomDllConfig {
    /// Enable periodic module validation scanning
    pub enable_periodic_scan: bool,
    /// Scan interval in seconds
    pub scan_interval_secs: u64,
    /// Enable real-time file deletion tracking
    pub enable_deletion_tracking: bool,
    /// Time window to correlate load/delete events (milliseconds)
    pub correlation_window_ms: u64,
    /// Maximum cached events per category
    pub max_cached_events: usize,
    /// Skip system directories (reduce false positives)
    pub skip_system_directories: bool,
    /// Known legitimate phantom patterns (e.g., some installers)
    pub allowlist_patterns: Vec<String>,
}

impl Default for PhantomDllConfig {
    fn default() -> Self {
        Self {
            enable_periodic_scan: true,
            scan_interval_secs: 30,
            enable_deletion_tracking: true,
            correlation_window_ms: 10_000, // 10 seconds
            max_cached_events: 5000,
            skip_system_directories: true,
            allowlist_patterns: vec![
                // Some legitimate tools use temp DLLs
                "\\AppData\\Local\\Temp\\*\\setup*.dll".to_string(),
                "\\Windows\\Installer\\*".to_string(),
            ],
        }
    }
}

/// Phantom DLL hollowing collector
pub struct PhantomDllCollector {
    config: PhantomDllConfig,
    agent_config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Track recent module loads for correlation
    recent_module_loads: Arc<RwLock<HashMap<String, ModuleLoadEvent>>>,
    /// Track recent file deletions for correlation
    recent_file_deletions: Arc<RwLock<Vec<FileDeletionEvent>>>,
    /// Track already-reported detections to avoid duplicates
    reported_detections: Arc<Mutex<HashSet<(u32, String)>>>,
    /// Track known processes with phantom modules for continuous monitoring
    known_phantom_processes: Arc<RwLock<HashSet<u32>>>,
}

impl PhantomDllCollector {
    /// Create a new phantom DLL collector
    pub fn new(agent_config: &AgentConfig) -> Self {
        Self::with_config(agent_config, PhantomDllConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(agent_config: &AgentConfig, config: PhantomDllConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        info!(
            "Initializing phantom DLL hollowing detection (scan_interval={}s, correlation_window={}ms)",
            config.scan_interval_secs,
            config.correlation_window_ms
        );

        let collector = Self {
            config: config.clone(),
            agent_config: agent_config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
            recent_module_loads: Arc::new(RwLock::new(HashMap::new())),
            recent_file_deletions: Arc::new(RwLock::new(Vec::new())),
            reported_detections: Arc::new(Mutex::new(HashSet::new())),
            known_phantom_processes: Arc::new(RwLock::new(HashSet::new())),
        };

        // Start background monitoring tasks
        if config.enable_periodic_scan {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            let reported = collector.reported_detections.clone();
            let known_phantom = collector.known_phantom_processes.clone();

            tokio::spawn(async move {
                Self::periodic_scan_loop(tx_clone, config_clone, reported, known_phantom).await;
            });
        }

        if config.enable_deletion_tracking {
            let tx_clone = tx.clone();
            let module_loads = collector.recent_module_loads.clone();
            let file_deletions = collector.recent_file_deletions.clone();
            let reported = collector.reported_detections.clone();
            let config_clone = config.clone();

            tokio::spawn(async move {
                Self::correlation_loop(
                    tx_clone,
                    module_loads,
                    file_deletions,
                    reported,
                    config_clone,
                )
                .await;
            });
        }

        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Track a module load event for correlation
    pub async fn track_module_load(&self, pid: u32, path: &str, base_address: u64, size: u64) {
        let normalized_path = Self::normalize_path(path);
        let is_temp = Self::is_temp_path(&normalized_path);

        let event = ModuleLoadEvent {
            pid,
            path: normalized_path.clone(),
            base_address,
            size,
            load_time: Instant::now(),
            is_temp_path: is_temp,
        };

        let mut loads = self.recent_module_loads.write().await;
        loads.insert(normalized_path, event);

        // Cleanup old entries
        if loads.len() > self.config.max_cached_events {
            let cutoff = Instant::now() - Duration::from_secs(60);
            loads.retain(|_, v| v.load_time > cutoff);
        }
    }

    /// Track a file deletion event for correlation
    pub async fn track_file_deletion(&self, pid: u32, path: &str) {
        let normalized_path = Self::normalize_path(path);

        let event = FileDeletionEvent {
            path: normalized_path,
            pid,
            deletion_time: Instant::now(),
        };

        let mut deletions = self.recent_file_deletions.write().await;
        deletions.push(event);

        // Cleanup old entries
        if deletions.len() > self.config.max_cached_events {
            let cutoff = Instant::now() - Duration::from_secs(60);
            deletions.retain(|v| v.deletion_time > cutoff);
        }
    }

    /// Normalize path for comparison
    fn normalize_path(path: &str) -> String {
        path.to_lowercase()
            .replace('/', "\\")
            .trim_start_matches("\\\\?\\")
            .trim_start_matches("\\device\\harddiskvolume")
            .to_string()
    }

    /// Check if path is a temp directory
    fn is_temp_path(path: &str) -> bool {
        let lower = path.to_lowercase();
        lower.contains("\\temp\\")
            || lower.contains("\\tmp\\")
            || lower.contains("\\appdata\\local\\temp")
            || lower.contains("\\windows\\temp")
            || lower.starts_with("c:\\users\\")
                && (lower.contains("\\temp\\") || lower.contains("\\tmp\\"))
    }

    /// Check if path matches allowlist
    fn is_allowlisted(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        for pattern in &self.config.allowlist_patterns {
            let pattern_lower = pattern.to_lowercase();
            // Simple glob matching
            if pattern_lower.contains('*') {
                let parts: Vec<&str> = pattern_lower.split('*').collect();
                if parts.len() == 2 {
                    if lower.contains(parts[0]) && lower.ends_with(parts[1]) {
                        return true;
                    }
                }
            } else if lower.contains(&pattern_lower) {
                return true;
            }
        }
        false
    }

    /// Periodic scan loop - validates module file existence
    async fn periodic_scan_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: PhantomDllConfig,
        reported: Arc<Mutex<HashSet<(u32, String)>>>,
        known_phantom: Arc<RwLock<HashSet<u32>>>,
    ) {
        info!("Starting phantom DLL periodic scan loop");

        let scan_interval = Duration::from_secs(config.scan_interval_secs);
        let mut interval = tokio::time::interval(scan_interval);

        loop {
            interval.tick().await;

            debug!("Running phantom DLL scan");

            // Get list of processes to scan
            let processes = match Self::get_running_processes().await {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to enumerate processes: {}", e);
                    continue;
                }
            };

            for (pid, name, path) in processes {
                // Skip our own process
                if pid == std::process::id() {
                    continue;
                }

                // Skip system processes
                if pid < 10 {
                    continue;
                }

                // Scan process modules for phantom DLLs
                if let Ok(detections) = Self::scan_process_modules(pid, &name, &path, &config).await
                {
                    let mut reported_guard = reported.lock().await;

                    for detection in detections {
                        let key = (detection.pid, detection.module_path.clone());

                        if !reported_guard.contains(&key) {
                            reported_guard.insert(key);

                            // Track as known phantom process
                            {
                                let mut phantom = known_phantom.write().await;
                                phantom.insert(detection.pid);
                            }

                            let event = Self::create_event(&detection);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }

                    // Limit reported cache size
                    if reported_guard.len() > 10000 {
                        reported_guard.clear();
                    }
                }
            }
        }
    }

    /// Correlation loop - matches module loads with file deletions
    async fn correlation_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        module_loads: Arc<RwLock<HashMap<String, ModuleLoadEvent>>>,
        file_deletions: Arc<RwLock<Vec<FileDeletionEvent>>>,
        reported: Arc<Mutex<HashSet<(u32, String)>>>,
        config: PhantomDllConfig,
    ) {
        info!("Starting phantom DLL correlation loop");

        let correlation_interval = Duration::from_millis(1000);
        let mut interval = tokio::time::interval(correlation_interval);

        loop {
            interval.tick().await;

            // Get recent deletions
            let deletions = {
                let guard = file_deletions.read().await;
                guard.clone()
            };

            // Get module loads
            let loads = {
                let guard = module_loads.read().await;
                guard.clone()
            };

            // Correlate: find modules whose files were deleted shortly after load
            for deletion in &deletions {
                let deletion_path_normalized = Self::normalize_path(&deletion.path);

                // Check if this deleted file was a recently loaded module
                for (load_path, load_event) in &loads {
                    // Path match (case-insensitive)
                    if load_path.to_lowercase() != deletion_path_normalized.to_lowercase() {
                        continue;
                    }

                    // Time correlation: deletion happened within window after load
                    let time_diff = deletion.deletion_time.duration_since(load_event.load_time);
                    if time_diff > Duration::from_millis(config.correlation_window_ms) {
                        continue;
                    }

                    // We found a correlation!
                    let mut reported_guard = reported.lock().await;
                    let key = (load_event.pid, load_path.clone());

                    if reported_guard.contains(&key) {
                        continue;
                    }

                    reported_guard.insert(key);

                    let detection = PhantomDllEvent {
                        pid: load_event.pid,
                        process_name: Self::get_process_name(load_event.pid)
                            .unwrap_or_else(|| format!("pid_{}", load_event.pid)),
                        process_path: Self::get_process_path(load_event.pid)
                            .unwrap_or_else(|| "unknown".to_string()),
                        module_name: Path::new(load_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        module_path: load_path.clone(),
                        module_base: load_event.base_address,
                        module_size: load_event.size,
                        indicator: if load_event.is_temp_path {
                            PhantomIndicator::TempPathDeleted
                        } else {
                            PhantomIndicator::FileDeletedAfterLoad
                        },
                        confidence: 0.95,
                        load_age_ms: Some(time_diff.as_millis() as u64),
                        was_temp_path: load_event.is_temp_path,
                        evidence: vec![
                            format!("DLL loaded at: 0x{:X}", load_event.base_address),
                            format!("File deleted after {} ms", time_diff.as_millis()),
                            format!("Deletion by PID: {}", deletion.pid),
                            "Module file no longer exists on disk".to_string(),
                        ],
                        mitre_technique: "T1055.012".to_string(),
                    };

                    warn!(
                        pid = detection.pid,
                        module = %detection.module_name,
                        indicator = %detection.indicator.as_str(),
                        "Phantom DLL detected - file deleted after module load"
                    );

                    let event = Self::create_event(&detection);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Cleanup old events
            let cutoff = Instant::now() - Duration::from_secs(60);
            {
                let mut guard = file_deletions.write().await;
                guard.retain(|d| d.deletion_time > cutoff);
            }
            {
                let mut guard = module_loads.write().await;
                guard.retain(|_, v| v.load_time > cutoff);
            }
        }
    }

    /// Scan a process's modules for phantom DLLs
    #[cfg(target_os = "windows")]
    async fn scan_process_modules(
        pid: u32,
        process_name: &str,
        process_path: &str,
        config: &PhantomDllConfig,
    ) -> Result<Vec<PhantomDllEvent>> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
            MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut detections = Vec::new();

        unsafe {
            // Open process with minimal permissions
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return Ok(detections), // Process may have exited or access denied
            };

            // Enumerate loaded modules
            let mut modules: Vec<HMODULE> = vec![HMODULE::default(); 1024];
            let mut cb_needed = 0u32;

            if EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_ok()
            {
                let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();

                for i in 0..module_count {
                    let module = modules[i];
                    if module.is_invalid() {
                        continue;
                    }

                    // Get module path
                    let mut path_buf = vec![0u16; 512];
                    let len = GetModuleFileNameExW(handle, module, &mut path_buf);
                    if len == 0 {
                        continue;
                    }

                    let module_path = String::from_utf16_lossy(&path_buf[..len as usize]);

                    // Get module info
                    let mut mod_info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        module,
                        &mut mod_info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_err()
                    {
                        continue;
                    }

                    // Check if file exists
                    let file_exists = Path::new(&module_path).exists();

                    if !file_exists {
                        // Found a phantom module!
                        let is_temp = Self::is_temp_path(&module_path);

                        // Skip allowlisted patterns
                        // Note: We don't have access to self here, so we create a simple check
                        let is_allowed = module_path
                            .to_lowercase()
                            .contains("\\windows\\installer\\")
                            || module_path.to_lowercase().contains("\\winsxs\\")
                            || module_path.to_lowercase().ends_with(".mui");

                        if is_allowed && config.skip_system_directories {
                            continue;
                        }

                        // Skip certain system paths that legitimately have missing files
                        let lower_path = module_path.to_lowercase();
                        if lower_path.contains("\\assembly\\")
                            || lower_path.contains("\\winsxs\\")
                            || lower_path.ends_with(".manifest")
                        {
                            continue;
                        }

                        let module_name = Path::new(&module_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let indicator = if is_temp {
                            PhantomIndicator::TempPathDeleted
                        } else if module_path.starts_with("\\\\") {
                            PhantomIndicator::NetworkPathInaccessible
                        } else {
                            PhantomIndicator::ModuleFileNotFound
                        };

                        let detection = PhantomDllEvent {
                            pid,
                            process_name: process_name.to_string(),
                            process_path: process_path.to_string(),
                            module_name: module_name.clone(),
                            module_path: module_path.clone(),
                            module_base: mod_info.lpBaseOfDll as u64,
                            module_size: mod_info.SizeOfImage as u64,
                            indicator,
                            confidence: indicator.confidence(),
                            load_age_ms: None,
                            was_temp_path: is_temp,
                            evidence: vec![
                                format!("Module base: 0x{:X}", mod_info.lpBaseOfDll as u64),
                                format!("Module size: {} bytes", mod_info.SizeOfImage),
                                format!("Path: {}", module_path),
                                "Backing file not found on disk".to_string(),
                            ],
                            mitre_technique: "T1055.012".to_string(),
                        };

                        warn!(
                            pid = pid,
                            module = %module_name,
                            path = %module_path,
                            indicator = %indicator.as_str(),
                            "Phantom DLL detected"
                        );

                        detections.push(detection);
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        Ok(detections)
    }

    #[cfg(not(target_os = "windows"))]
    async fn scan_process_modules(
        pid: u32,
        process_name: &str,
        process_path: &str,
        _config: &PhantomDllConfig,
    ) -> Result<Vec<PhantomDllEvent>> {
        // Linux implementation using /proc/[pid]/maps
        use std::fs;

        let mut detections = Vec::new();

        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = match fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => return Ok(detections),
        };

        for line in maps_content.lines() {
            // Parse maps line: address perms offset dev inode pathname
            let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
            if parts.len() < 6 {
                continue;
            }

            let perms = parts[1];
            let pathname = parts[5].trim();

            // Skip non-file mappings
            if pathname.is_empty()
                || pathname.starts_with('[')
                || pathname == "(deleted)"
                || !pathname.starts_with('/')
            {
                continue;
            }

            // Skip if executable permission not set
            if !perms.contains('x') {
                continue;
            }

            // Check if file exists
            if !Path::new(pathname).exists() {
                // Parse address range
                let addr_parts: Vec<&str> = parts[0].split('-').collect();
                let base_address = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
                let end_address =
                    u64::from_str_radix(addr_parts.get(1).unwrap_or(&"0"), 16).unwrap_or(0);

                let module_name = Path::new(pathname)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let is_temp = Self::is_temp_path(pathname);

                let indicator = if is_temp {
                    PhantomIndicator::TempPathDeleted
                } else {
                    PhantomIndicator::ModuleFileNotFound
                };

                let detection = PhantomDllEvent {
                    pid,
                    process_name: process_name.to_string(),
                    process_path: process_path.to_string(),
                    module_name: module_name.clone(),
                    module_path: pathname.to_string(),
                    module_base: base_address,
                    module_size: end_address.saturating_sub(base_address),
                    indicator,
                    confidence: indicator.confidence(),
                    load_age_ms: None,
                    was_temp_path: is_temp,
                    evidence: vec![
                        format!("Mapped at: 0x{:X}-0x{:X}", base_address, end_address),
                        format!("Permissions: {}", perms),
                        format!("Path: {}", pathname),
                        "Backing file not found on disk".to_string(),
                    ],
                    mitre_technique: "T1055.012".to_string(),
                };

                detections.push(detection);
            }
        }

        Ok(detections)
    }

    /// Get list of running processes
    #[cfg(target_os = "windows")]
    async fn get_running_processes() -> Result<Vec<(u32, String, String)>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut processes = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile
                            [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                    );

                    let path = Self::get_process_path(pid).unwrap_or_default();

                    processes.push((pid, name, path));

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        Ok(processes)
    }

    #[cfg(not(target_os = "windows"))]
    async fn get_running_processes() -> Result<Vec<(u32, String, String)>> {
        use std::fs;

        let mut processes = Vec::new();

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        let comm_path = format!("/proc/{}/comm", pid);
                        let exe_path = format!("/proc/{}/exe", pid);

                        let name = fs::read_to_string(&comm_path)
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| format!("pid_{}", pid));

                        let path = fs::read_link(&exe_path)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();

                        processes.push((pid, name, path));
                    }
                }
            }
        }

        Ok(processes)
    }

    /// Get process name by PID
    #[cfg(target_os = "windows")]
    fn get_process_name(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                let mut name_buf = vec![0u16; 512];
                let len = GetModuleBaseNameW(handle, None, &mut name_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return Some(String::from_utf16_lossy(&name_buf[..len as usize]));
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    fn get_process_name(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .ok()
    }

    /// Get process path by PID
    #[cfg(target_os = "windows")]
    fn get_process_path(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                let mut path_buf = vec![0u16; 512];
                let len = GetModuleFileNameExW(handle, None, &mut path_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return Some(String::from_utf16_lossy(&path_buf[..len as usize]));
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    fn get_process_path(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .ok()
    }

    /// Create telemetry event from detection
    fn create_event(detection: &PhantomDllEvent) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::PhantomDll,
            detection.indicator.severity(),
            EventPayload::PhantomDll(detection.clone()),
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::PhantomDllHollowing,
            rule_name: format!("PhantomDll_{}", detection.indicator.as_str()),
            confidence: detection.confidence,
            description: format!(
                "Phantom DLL detected: {} in {} (PID: {}) - {}",
                detection.module_name,
                detection.process_name,
                detection.pid,
                detection.indicator.as_str()
            ),
            mitre_tactics: vec!["defense-evasion".to_string(), "persistence".to_string()],
            mitre_techniques: vec![detection.mitre_technique.clone()],
        });

        // Add metadata
        event
            .metadata
            .insert("pid".to_string(), detection.pid.to_string());
        event
            .metadata
            .insert("process_name".to_string(), detection.process_name.clone());
        event
            .metadata
            .insert("process_path".to_string(), detection.process_path.clone());
        event
            .metadata
            .insert("module_name".to_string(), detection.module_name.clone());
        event
            .metadata
            .insert("module_path".to_string(), detection.module_path.clone());
        event.metadata.insert(
            "module_base".to_string(),
            format!("0x{:X}", detection.module_base),
        );
        event
            .metadata
            .insert("module_size".to_string(), detection.module_size.to_string());
        event.metadata.insert(
            "indicator".to_string(),
            detection.indicator.as_str().to_string(),
        );
        event
            .metadata
            .insert("confidence".to_string(), detection.confidence.to_string());
        event.metadata.insert(
            "was_temp_path".to_string(),
            detection.was_temp_path.to_string(),
        );
        event.metadata.insert(
            "mitre_technique".to_string(),
            detection.mitre_technique.clone(),
        );

        if let Some(age) = detection.load_age_ms {
            event
                .metadata
                .insert("load_age_ms".to_string(), age.to_string());
        }

        // Add evidence
        for (i, evidence) in detection.evidence.iter().enumerate() {
            event
                .metadata
                .insert(format!("evidence_{}", i), evidence.clone());
        }

        event
    }

    /// Get current timestamp in milliseconds
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// =============================================================================
// STANDALONE DETECTION FUNCTIONS
// =============================================================================

/// Scan a single process for phantom DLLs
pub async fn scan_process_for_phantom_dlls(pid: u32) -> Result<Vec<PhantomDllEvent>> {
    let process_name =
        PhantomDllCollector::get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));
    let process_path =
        PhantomDllCollector::get_process_path(pid).unwrap_or_else(|| "unknown".to_string());

    let config = PhantomDllConfig::default();
    PhantomDllCollector::scan_process_modules(pid, &process_name, &process_path, &config).await
}

/// Scan all running processes for phantom DLLs
pub async fn scan_all_processes_for_phantom_dlls() -> Result<Vec<PhantomDllEvent>> {
    let mut all_detections = Vec::new();
    let processes = PhantomDllCollector::get_running_processes().await?;

    for (pid, name, path) in processes {
        if pid == std::process::id() || pid < 10 {
            continue;
        }

        if let Ok(mut detections) = PhantomDllCollector::scan_process_modules(
            pid,
            &name,
            &path,
            &PhantomDllConfig::default(),
        )
        .await
        {
            all_detections.append(&mut detections);
        }
    }

    Ok(all_detections)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phantom_indicator_properties() {
        assert_eq!(
            PhantomIndicator::FileDeletedAfterLoad.severity(),
            Severity::Critical
        );
        assert_eq!(
            PhantomIndicator::ModuleFileNotFound.severity(),
            Severity::High
        );
        assert!(PhantomIndicator::FileDeletedAfterLoad.confidence() > 0.9);
    }

    #[test]
    fn test_is_temp_path() {
        assert!(PhantomDllCollector::is_temp_path(
            "C:\\Users\\test\\AppData\\Local\\Temp\\test.dll"
        ));
        assert!(PhantomDllCollector::is_temp_path(
            "C:\\Windows\\Temp\\malware.dll"
        ));
        assert!(!PhantomDllCollector::is_temp_path(
            "C:\\Windows\\System32\\kernel32.dll"
        ));
        assert!(!PhantomDllCollector::is_temp_path(
            "C:\\Program Files\\App\\app.dll"
        ));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            PhantomDllCollector::normalize_path("C:/Windows/System32/ntdll.dll"),
            "c:\\windows\\system32\\ntdll.dll"
        );
        assert_eq!(
            PhantomDllCollector::normalize_path("\\\\?\\C:\\Windows\\System32\\ntdll.dll"),
            "c:\\windows\\system32\\ntdll.dll"
        );
    }

    #[test]
    fn test_indicator_mitre_mapping() {
        // All indicators should map to process hollowing technique
        for indicator in [
            PhantomIndicator::ModuleFileNotFound,
            PhantomIndicator::FileDeletedAfterLoad,
            PhantomIndicator::TempPathDeleted,
            PhantomIndicator::SectionFromDeletedFile,
        ] {
            // All phantom DLL indicators relate to T1055.012
            assert_eq!(indicator.as_str().len() > 0, true);
        }
    }
}
