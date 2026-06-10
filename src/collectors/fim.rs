//! File Integrity Monitoring (FIM) Collector
//!
//! Provides comprehensive file integrity monitoring for critical system files,
//! configuration files, and compliance requirements (PCI-DSS, HIPAA, SOC2).
//!
//! Features:
//! - Real-time monitoring using platform-specific APIs
//!   - Windows: ReadDirectoryChangesW
//!   - Linux: inotify/fanotify
//!   - macOS: FSEvents
//! - SHA256 baseline comparison
//! - File permissions/ACL tracking
//! - Ownership change detection
//! - Scheduled differential scans
//! - Compliance reporting
//!
//! MITRE ATT&CK: T1565 (Data Manipulation)

// FIM collector. Scaffolded config/event_tx retained for compliance pipeline.
#![allow(dead_code, unused_variables)]

use super::file::FileCollector;
use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::analyzers;
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// File integrity event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityEvent {
    /// Path to the file
    pub path: String,

    /// Type of integrity change detected
    pub change_type: IntegrityChangeType,

    /// Previous SHA256 hash (if available)
    #[serde(with = "hex::serde")]
    pub previous_hash: Vec<u8>,

    /// Current SHA256 hash
    #[serde(with = "hex::serde")]
    pub current_hash: Vec<u8>,

    /// Previous file size
    pub previous_size: u64,

    /// Current file size
    pub current_size: u64,

    /// Previous file permissions (octal on Unix, ACL summary on Windows)
    pub previous_permissions: String,

    /// Current file permissions
    pub current_permissions: String,

    /// Previous owner
    pub previous_owner: String,

    /// Current owner
    pub current_owner: String,

    /// Previous modification time (Unix timestamp ms)
    pub previous_mtime: u64,

    /// Current modification time (Unix timestamp ms)
    pub current_mtime: u64,

    /// File category (system, config, boot, security, application)
    pub category: FileCategory,

    /// Compliance frameworks affected
    pub compliance_impact: Vec<ComplianceFramework>,

    /// Whether the change is whitelisted
    pub whitelisted: bool,

    /// Whitelist reason if applicable
    pub whitelist_reason: Option<String>,

    /// Process ID that modified the file (if detected)
    pub modifier_pid: Option<u32>,

    /// Process name that modified the file (if detected)
    pub modifier_process: Option<String>,

    /// Process path that modified the file (if detected)
    pub modifier_path: Option<String>,

    /// Entropy of the file
    pub entropy: f32,

    /// File attributes (hidden, system, readonly, etc.)
    pub attributes: Vec<String>,
}

/// Type of integrity change detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityChangeType {
    /// File content was modified (hash changed)
    ContentModified,
    /// File was created
    Created,
    /// File was deleted
    Deleted,
    /// File permissions changed
    PermissionsChanged,
    /// File ownership changed
    OwnershipChanged,
    /// File attributes changed
    AttributesChanged,
    /// File was renamed
    Renamed,
    /// Multiple changes detected
    MultipleChanges,
    /// Baseline established (initial scan)
    BaselineEstablished,
}

/// File category for monitoring prioritization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    /// System executables and libraries
    System,
    /// System configuration files
    Config,
    /// Boot files and bootloader
    Boot,
    /// Security-related files (SAM, shadow, sudoers)
    Security,
    /// Application binaries and configs
    Application,
    /// Database files
    Database,
    /// Web server files
    WebServer,
    /// Custom monitored files
    Custom,
}

/// Compliance framework
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    /// PCI-DSS requirement 11.5
    PciDss,
    /// HIPAA Security Rule
    Hipaa,
    /// SOC2 Type II
    Soc2,
    /// NIST 800-53
    Nist80053,
    /// CIS Benchmark
    CisBenchmark,
    /// Custom compliance requirement
    Custom(String),
}

/// File baseline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBaseline {
    /// SHA256 hash of the file
    pub hash: Vec<u8>,
    /// File size in bytes
    pub size: u64,
    /// File permissions
    pub permissions: String,
    /// File owner
    pub owner: String,
    /// File group (Unix only)
    pub group: String,
    /// Modification time (Unix timestamp ms)
    pub mtime: u64,
    /// Creation time (Unix timestamp ms)
    pub ctime: u64,
    /// File attributes
    pub attributes: Vec<String>,
    /// When the baseline was last updated
    pub baseline_updated: u64,
    /// File category
    pub category: FileCategory,
    /// Is this a known-good file
    pub known_good: bool,
}

/// Whitelist entry for expected changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    /// Path pattern (glob-style)
    pub pattern: String,
    /// Allowed change types
    pub allowed_changes: Vec<IntegrityChangeType>,
    /// Reason for whitelisting
    pub reason: String,
    /// Expiration time (0 = never expires)
    pub expires: u64,
    /// Who added this entry
    pub added_by: String,
}

/// Policy action type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow change silently (no alert)
    Allow,
    /// Generate alert but allow change
    Alert,
    /// Generate alert and quarantine file
    Block,
}

/// Auto-response action for policy violations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutoResponse {
    /// No automatic action
    None,
    /// Generate alert only
    Notify,
    /// Move file to quarantine
    Quarantine,
}

/// FIM policy with allow/block/alert actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimPolicy {
    /// Unique policy ID
    pub id: String,
    /// Path pattern (glob-style, like WhitelistEntry)
    pub pattern: String,
    /// Action to take on match
    pub action: PolicyAction,
    /// Minimum severity to trigger (None = all severities)
    pub severity_threshold: Option<Severity>,
    /// Auto-response action
    pub auto_response: AutoResponse,
    /// Policy priority (lower = higher priority, evaluated first)
    pub priority: u32,
    /// Expiration time (Unix timestamp ms, 0 = never expires)
    pub expires: u64,
    /// Reason for policy
    pub reason: String,
    /// Who added this policy
    pub added_by: String,
    /// Whether policy is enabled
    pub enabled: bool,
}

impl Default for FimPolicy {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: String::new(),
            action: PolicyAction::Alert,
            severity_threshold: None,
            auto_response: AutoResponse::Notify,
            priority: 100,
            expires: 0,
            reason: String::new(),
            added_by: String::new(),
            enabled: true,
        }
    }
}

/// FIM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    /// Enable real-time monitoring
    pub realtime_enabled: bool,
    /// Scheduled scan interval in seconds (0 = disabled)
    pub scan_interval_seconds: u64,
    /// Enable baseline management
    pub baseline_enabled: bool,
    /// Path to baseline database
    pub baseline_path: String,
    /// Paths to monitor (supports glob patterns)
    pub monitored_paths: Vec<MonitoredPath>,
    /// Paths to exclude
    pub excluded_paths: Vec<String>,
    /// Enable compliance reporting
    pub compliance_enabled: bool,
    /// Compliance frameworks to track
    pub compliance_frameworks: Vec<ComplianceFramework>,
    /// Maximum file size to hash (bytes)
    pub max_file_size: u64,
    /// FIM policies (evaluated before whitelist)
    pub policies: Vec<FimPolicy>,
    /// Whitelist entries
    pub whitelist: Vec<WhitelistEntry>,
    /// Alert on baseline deviation
    pub alert_on_deviation: bool,
    /// Auto-update baseline for known package updates
    pub auto_update_baseline: bool,
}

/// Monitored path configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredPath {
    /// Path or glob pattern
    pub path: String,
    /// Whether to monitor recursively
    pub recursive: bool,
    /// File category
    pub category: FileCategory,
    /// Compliance frameworks this path affects
    pub compliance: Vec<ComplianceFramework>,
    /// File extensions to include (empty = all)
    pub extensions: Vec<String>,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            realtime_enabled: true,
            scan_interval_seconds: 3600, // 1 hour
            baseline_enabled: true,
            baseline_path: Self::default_baseline_path(),
            monitored_paths: Self::default_monitored_paths(),
            excluded_paths: Self::default_excluded_paths(),
            compliance_enabled: true,
            compliance_frameworks: vec![
                ComplianceFramework::PciDss,
                ComplianceFramework::Hipaa,
                ComplianceFramework::Soc2,
            ],
            max_file_size: 100 * 1024 * 1024, // 100MB
            policies: Vec::new(),
            whitelist: Vec::new(),
            alert_on_deviation: true,
            auto_update_baseline: true,
        }
    }
}

impl FimConfig {
    fn default_baseline_path() -> String {
        #[cfg(target_os = "windows")]
        return "C:\\ProgramData\\Tamandua\\fim_baseline.json".to_string();

        #[cfg(not(target_os = "windows"))]
        return "/var/lib/tamandua/fim_baseline.json".to_string();
    }

    fn default_monitored_paths() -> Vec<MonitoredPath> {
        #[cfg(target_os = "windows")]
        return vec![
            // System32 executables
            MonitoredPath {
                path: "C:\\Windows\\System32\\*.dll".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec!["dll".to_string()],
            },
            MonitoredPath {
                path: "C:\\Windows\\System32\\*.exe".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec!["exe".to_string()],
            },
            MonitoredPath {
                path: "C:\\Windows\\System32\\*.sys".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec!["sys".to_string()],
            },
            // Registry hives
            MonitoredPath {
                path: "C:\\Windows\\System32\\config".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            // Drivers
            MonitoredPath {
                path: "C:\\Windows\\System32\\drivers".to_string(),
                recursive: true,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec!["sys".to_string()],
            },
            // Boot files
            MonitoredPath {
                path: "C:\\Windows\\Boot".to_string(),
                recursive: true,
                category: FileCategory::Boot,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "C:\\bootmgr".to_string(),
                recursive: false,
                category: FileCategory::Boot,
                compliance: vec![ComplianceFramework::PciDss],
                extensions: vec![],
            },
            // SAM, SECURITY, SYSTEM hives
            MonitoredPath {
                path: "C:\\Windows\\System32\\config\\SAM".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            MonitoredPath {
                path: "C:\\Windows\\System32\\config\\SECURITY".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            MonitoredPath {
                path: "C:\\Windows\\System32\\config\\SYSTEM".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
        ];

        #[cfg(target_os = "linux")]
        return vec![
            // System binaries
            MonitoredPath {
                path: "/bin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/sbin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/usr/bin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/usr/sbin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            // System libraries
            MonitoredPath {
                path: "/lib".to_string(),
                recursive: true,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec!["so".to_string()],
            },
            MonitoredPath {
                path: "/usr/lib".to_string(),
                recursive: true,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec!["so".to_string()],
            },
            // Security files
            MonitoredPath {
                path: "/etc/passwd".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/etc/shadow".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/etc/sudoers".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/etc/sudoers.d".to_string(),
                recursive: true,
                category: FileCategory::Security,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            // Boot files
            MonitoredPath {
                path: "/boot".to_string(),
                recursive: true,
                category: FileCategory::Boot,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            // SSH configuration
            MonitoredPath {
                path: "/etc/ssh".to_string(),
                recursive: true,
                category: FileCategory::Config,
                compliance: vec![
                    ComplianceFramework::PciDss,
                    ComplianceFramework::Hipaa,
                    ComplianceFramework::Soc2,
                ],
                extensions: vec![],
            },
            // PAM configuration
            MonitoredPath {
                path: "/etc/pam.d".to_string(),
                recursive: true,
                category: FileCategory::Security,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Hipaa],
                extensions: vec![],
            },
        ];

        #[cfg(target_os = "macos")]
        return vec![
            MonitoredPath {
                path: "/bin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/sbin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/usr/bin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/usr/sbin".to_string(),
                recursive: false,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Soc2],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/etc/passwd".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Hipaa],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/etc/sudoers".to_string(),
                recursive: false,
                category: FileCategory::Security,
                compliance: vec![ComplianceFramework::PciDss, ComplianceFramework::Hipaa],
                extensions: vec![],
            },
            MonitoredPath {
                path: "/System/Library".to_string(),
                recursive: true,
                category: FileCategory::System,
                compliance: vec![ComplianceFramework::PciDss],
                extensions: vec!["dylib".to_string()],
            },
        ];

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return vec![];
    }

    fn default_excluded_paths() -> Vec<String> {
        #[cfg(target_os = "windows")]
        return vec![
            "C:\\Windows\\Logs".to_string(),
            "C:\\Windows\\Temp".to_string(),
            "C:\\Windows\\SoftwareDistribution".to_string(),
            "C:\\Windows\\Prefetch".to_string(),
        ];

        #[cfg(not(target_os = "windows"))]
        return vec![
            "/proc".to_string(),
            "/sys".to_string(),
            "/dev".to_string(),
            "/run".to_string(),
            "/var/log".to_string(),
            "/var/cache".to_string(),
            "/tmp".to_string(),
        ];
    }
}

/// File Integrity Monitoring collector
pub struct FimCollector {
    config: AgentConfig,
    fim_config: FimConfig,
    baseline: Arc<RwLock<HashMap<String, FileBaseline>>>,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl FimCollector {
    /// Create a new FIM collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);

        let fim_config = FimConfig::default();
        let baseline = Arc::new(RwLock::new(HashMap::new()));

        let collector = Self {
            config: config.clone(),
            fim_config: fim_config.clone(),
            baseline: baseline.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Load existing baseline
        if let Err(e) = collector.load_baseline() {
            warn!(error = %e, "Failed to load FIM baseline, will create new one");
        }

        // Start real-time monitoring
        if fim_config.realtime_enabled {
            let tx_clone = tx.clone();
            let baseline_clone = baseline.clone();
            let fim_config_clone = fim_config.clone();
            let agent_config_clone = config.clone();

            std::thread::spawn(move || {
                if let Err(e) = Self::start_realtime_monitor(
                    tx_clone,
                    baseline_clone,
                    fim_config_clone,
                    agent_config_clone,
                ) {
                    error!(error = %e, "Real-time FIM monitor error");
                }
            });
        }

        // Start scheduled scanner
        if fim_config.scan_interval_seconds > 0 {
            let tx_clone = tx.clone();
            let baseline_clone = baseline.clone();
            let fim_config_clone = fim_config.clone();

            tokio::spawn(async move {
                Self::scheduled_scan_loop(tx_clone, baseline_clone, fim_config_clone).await;
            });
        }

        info!("FIM collector initialized");
        Ok(collector)
    }

    /// Load baseline from disk
    fn load_baseline(&self) -> Result<()> {
        let path = Path::new(&self.fim_config.baseline_path);

        if !path.exists() {
            info!("No existing FIM baseline found, will create on first scan");
            return Ok(());
        }

        let content = std::fs::read_to_string(path)?;
        let loaded: HashMap<String, FileBaseline> = serde_json::from_str(&content)?;

        let mut baseline = self
            .baseline
            .write()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        *baseline = loaded;

        info!(count = baseline.len(), "FIM baseline loaded");
        Ok(())
    }

    /// Save baseline to disk
    fn save_baseline(&self) -> Result<()> {
        let baseline = self.baseline.read().map_err(|e| anyhow::anyhow!("{}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&self.fim_config.baseline_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&*baseline)?;
        std::fs::write(&self.fim_config.baseline_path, content)?;

        debug!(path = %self.fim_config.baseline_path, "FIM baseline saved");
        Ok(())
    }

    /// Start real-time monitoring
    fn start_realtime_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        baseline: Arc<RwLock<HashMap<String, FileBaseline>>>,
        fim_config: FimConfig,
        _agent_config: AgentConfig,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            Self::start_windows_monitor(tx, baseline, fim_config)
        }

        #[cfg(target_os = "linux")]
        {
            Self::start_linux_monitor(tx, baseline, fim_config)
        }

        #[cfg(target_os = "macos")]
        {
            Self::start_macos_monitor(tx, baseline, fim_config)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            warn!("Real-time FIM monitoring not supported on this platform");
            Ok(())
        }
    }

    /// Windows-specific real-time monitoring using ReadDirectoryChangesW
    #[cfg(target_os = "windows")]
    fn start_windows_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        baseline: Arc<RwLock<HashMap<String, FileBaseline>>>,
        fim_config: FimConfig,
    ) -> Result<()> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc as std_mpsc;

        let (notify_tx, notify_rx) = std_mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            },
            Config::default(),
        )?;

        // Watch all configured paths
        for monitored in &fim_config.monitored_paths {
            let path = Path::new(&monitored.path);

            // Handle glob patterns
            if monitored.path.contains('*') {
                // For glob patterns, watch the parent directory
                if let Some(parent) = path.parent() {
                    if parent.exists() {
                        let mode = if monitored.recursive {
                            RecursiveMode::Recursive
                        } else {
                            RecursiveMode::NonRecursive
                        };
                        if let Err(e) = watcher.watch(parent, mode) {
                            warn!(path = %parent.display(), error = %e, "Failed to watch FIM path");
                        } else {
                            debug!(path = %parent.display(), "Watching FIM path");
                        }
                    }
                }
            } else if path.exists() {
                let mode = if monitored.recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                if let Err(e) = watcher.watch(path, mode) {
                    warn!(path = %monitored.path, error = %e, "Failed to watch FIM path");
                } else {
                    debug!(path = %monitored.path, "Watching FIM path");
                }
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        info!("Windows FIM real-time monitor started");

        for event in notify_rx {
            for path in &event.paths {
                // Check if path should be monitored
                if !Self::should_monitor_path(path, &fim_config) {
                    continue;
                }

                // Check exclusions
                let path_str = path.to_string_lossy().to_string();
                if fim_config
                    .excluded_paths
                    .iter()
                    .any(|p| path_str.starts_with(p))
                {
                    continue;
                }

                // Process the change
                if let Some(event) = runtime.block_on(Self::process_file_change(
                    path,
                    &event.kind,
                    &baseline,
                    &fim_config,
                )) {
                    if tx.blocking_send(event).is_err() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// Linux-specific real-time monitoring using inotify
    #[cfg(target_os = "linux")]
    fn start_linux_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        baseline: Arc<RwLock<HashMap<String, FileBaseline>>>,
        fim_config: FimConfig,
    ) -> Result<()> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc as std_mpsc;

        let (notify_tx, notify_rx) = std_mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            },
            Config::default(),
        )?;

        // Watch all configured paths
        for monitored in &fim_config.monitored_paths {
            let path = Path::new(&monitored.path);

            if monitored.path.contains('*') {
                // Handle glob patterns
                if let Some(parent) = path.parent() {
                    if parent.exists() {
                        let mode = if monitored.recursive {
                            RecursiveMode::Recursive
                        } else {
                            RecursiveMode::NonRecursive
                        };
                        if let Err(e) = watcher.watch(parent, mode) {
                            warn!(path = %parent.display(), error = %e, "Failed to watch FIM path");
                        } else {
                            debug!(path = %parent.display(), "Watching FIM path");
                        }
                    }
                }
            } else if path.exists() {
                let mode = if monitored.recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                if let Err(e) = watcher.watch(path, mode) {
                    warn!(path = %monitored.path, error = %e, "Failed to watch FIM path");
                } else {
                    debug!(path = %monitored.path, "Watching FIM path");
                }
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        info!("Linux FIM real-time monitor started (inotify)");

        for event in notify_rx {
            for path in &event.paths {
                if !Self::should_monitor_path(path, &fim_config) {
                    continue;
                }

                let path_str = path.to_string_lossy().to_string();
                if fim_config
                    .excluded_paths
                    .iter()
                    .any(|p| path_str.starts_with(p))
                {
                    continue;
                }

                if let Some(event) = runtime.block_on(Self::process_file_change(
                    path,
                    &event.kind,
                    &baseline,
                    &fim_config,
                )) {
                    if tx.blocking_send(event).is_err() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// macOS-specific real-time monitoring using FSEvents
    #[cfg(target_os = "macos")]
    fn start_macos_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        baseline: Arc<RwLock<HashMap<String, FileBaseline>>>,
        fim_config: FimConfig,
    ) -> Result<()> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc as std_mpsc;

        let (notify_tx, notify_rx) = std_mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            },
            Config::default(),
        )?;

        for monitored in &fim_config.monitored_paths {
            let path = Path::new(&monitored.path);

            if monitored.path.contains('*') {
                if let Some(parent) = path.parent() {
                    if parent.exists() {
                        let mode = if monitored.recursive {
                            RecursiveMode::Recursive
                        } else {
                            RecursiveMode::NonRecursive
                        };
                        let _ = watcher.watch(parent, mode);
                    }
                }
            } else if path.exists() {
                let mode = if monitored.recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                let _ = watcher.watch(path, mode);
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        info!("macOS FIM real-time monitor started (FSEvents)");

        for event in notify_rx {
            for path in &event.paths {
                if !Self::should_monitor_path(path, &fim_config) {
                    continue;
                }

                let path_str = path.to_string_lossy().to_string();
                if fim_config
                    .excluded_paths
                    .iter()
                    .any(|p| path_str.starts_with(p))
                {
                    continue;
                }

                if let Some(event) = runtime.block_on(Self::process_file_change(
                    path,
                    &event.kind,
                    &baseline,
                    &fim_config,
                )) {
                    if tx.blocking_send(event).is_err() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a path should be monitored based on configuration
    fn should_monitor_path(path: &Path, config: &FimConfig) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();

        for monitored in &config.monitored_paths {
            let pattern = monitored.path.to_lowercase();

            // Handle glob patterns
            if pattern.contains('*') {
                // Simple glob matching
                let pattern_parts: Vec<&str> = pattern.split('*').collect();
                if pattern_parts.len() == 2 {
                    let prefix = pattern_parts[0];
                    let suffix = pattern_parts[1];

                    if path_str.starts_with(&prefix) && path_str.ends_with(&suffix) {
                        // Check extension filter
                        if !monitored.extensions.is_empty() {
                            if let Some(ext) = path.extension() {
                                let ext_str = ext.to_string_lossy().to_lowercase();
                                if monitored
                                    .extensions
                                    .iter()
                                    .any(|e| e.to_lowercase() == ext_str)
                                {
                                    return true;
                                }
                            }
                            continue;
                        }
                        return true;
                    }
                }
            } else {
                // Exact path or prefix match
                if path_str.starts_with(&pattern) {
                    // Check extension filter
                    if !monitored.extensions.is_empty() {
                        if let Some(ext) = path.extension() {
                            let ext_str = ext.to_string_lossy().to_lowercase();
                            if monitored
                                .extensions
                                .iter()
                                .any(|e| e.to_lowercase() == ext_str)
                            {
                                return true;
                            }
                        }
                        continue;
                    }
                    return true;
                }
            }
        }

        false
    }

    /// Process a file change event
    async fn process_file_change(
        path: &Path,
        event_kind: &notify::EventKind,
        baseline: &Arc<RwLock<HashMap<String, FileBaseline>>>,
        fim_config: &FimConfig,
    ) -> Option<TelemetryEvent> {
        let path_str = path.to_string_lossy().to_string();

        // Determine change type from event
        let initial_change_type = match event_kind {
            notify::EventKind::Create(_) => IntegrityChangeType::Created,
            notify::EventKind::Modify(_) => IntegrityChangeType::ContentModified,
            notify::EventKind::Remove(_) => IntegrityChangeType::Deleted,
            _ => return None,
        };

        // Get current file info
        let current_info = Self::get_file_info(path).await;

        // Get baseline info
        let baseline_info = {
            let bl = baseline.read().ok()?;
            bl.get(&path_str).cloned()
        };

        // Determine actual changes
        let (change_type, previous_info) =
            match (&initial_change_type, &baseline_info, &current_info) {
                (IntegrityChangeType::Deleted, Some(prev), _) => {
                    (IntegrityChangeType::Deleted, Some(prev.clone()))
                }
                (IntegrityChangeType::Created, None, Some(curr)) => {
                    // New file, establish baseline
                    if let Ok(mut bl) = baseline.write() {
                        bl.insert(path_str.clone(), curr.clone());
                    }
                    (IntegrityChangeType::Created, None)
                }
                (IntegrityChangeType::ContentModified, Some(prev), Some(curr)) => {
                    // Determine what changed
                    let mut changes = Vec::new();

                    if prev.hash != curr.hash {
                        changes.push(IntegrityChangeType::ContentModified);
                    }
                    if prev.permissions != curr.permissions {
                        changes.push(IntegrityChangeType::PermissionsChanged);
                    }
                    if prev.owner != curr.owner {
                        changes.push(IntegrityChangeType::OwnershipChanged);
                    }
                    if prev.attributes != curr.attributes {
                        changes.push(IntegrityChangeType::AttributesChanged);
                    }

                    let change = if changes.len() > 1 {
                        IntegrityChangeType::MultipleChanges
                    } else if changes.len() == 1 {
                        changes[0].clone()
                    } else {
                        // No actual change detected (timestamp only)
                        return None;
                    };

                    // Update baseline
                    if let Ok(mut bl) = baseline.write() {
                        bl.insert(path_str.clone(), curr.clone());
                    }

                    (change, Some(prev.clone()))
                }
                (_, None, Some(curr)) => {
                    // No baseline, establish one
                    if let Ok(mut bl) = baseline.write() {
                        bl.insert(path_str.clone(), curr.clone());
                    }
                    (IntegrityChangeType::BaselineEstablished, None)
                }
                _ => return None,
            };

        // Get file category
        let category = Self::determine_category(path, fim_config);

        // Get compliance impact
        let compliance_impact = Self::get_compliance_impact(path, fim_config);

        // Determine base severity (without whitelist status)
        let base_severity = Self::determine_severity(&change_type, &category, false);

        // Evaluate policies first (takes precedence over whitelist)
        let policy_result = Self::evaluate_policies(path, &change_type, &base_severity, fim_config);

        // If policy matches, use policy action; otherwise fall back to whitelist
        let (whitelisted, whitelist_reason, policy_action) = match policy_result {
            Some((policy, _should_alert)) => {
                if policy.action == PolicyAction::Allow {
                    (true, Some(policy.reason.clone()), Some(policy))
                } else {
                    (false, None, Some(policy))
                }
            }
            None => {
                // Fall back to whitelist check
                let (wl, reason) = Self::check_whitelist(path, &change_type, fim_config);
                (wl, reason, None)
            }
        };

        // Final severity considers whitelist status
        let severity = Self::determine_severity(&change_type, &category, whitelisted);

        // Get current info or create empty
        let current = current_info.unwrap_or_else(|| FileBaseline {
            hash: Vec::new(),
            size: 0,
            permissions: String::new(),
            owner: String::new(),
            group: String::new(),
            mtime: 0,
            ctime: 0,
            attributes: Vec::new(),
            baseline_updated: 0,
            category: category.clone(),
            known_good: false,
        });

        let previous = previous_info.unwrap_or_else(|| FileBaseline {
            hash: Vec::new(),
            size: 0,
            permissions: String::new(),
            owner: String::new(),
            group: String::new(),
            mtime: 0,
            ctime: 0,
            attributes: Vec::new(),
            baseline_updated: 0,
            category: category.clone(),
            known_good: false,
        });

        // Calculate entropy
        let entropy = if path.exists() {
            analyzers::hash_file(&path_str)
                .await
                .map(|(_, e)| e)
                .unwrap_or(0.0)
        } else {
            0.0
        };

        // Look up the process that has the file open
        let modifier_info = FileCollector::find_process_for_file(path);
        let (modifier_pid, modifier_process, modifier_path) = match modifier_info {
            Some((pid, name, proc_path)) => (Some(pid), Some(name), Some(proc_path)),
            None => (None, None, None),
        };

        // Create event
        let fim_event = FileIntegrityEvent {
            path: path_str.clone(),
            change_type: change_type.clone(),
            previous_hash: previous.hash,
            current_hash: current.hash,
            previous_size: previous.size,
            current_size: current.size,
            previous_permissions: previous.permissions,
            current_permissions: current.permissions,
            previous_owner: previous.owner,
            current_owner: current.owner,
            previous_mtime: previous.mtime,
            current_mtime: current.mtime,
            category,
            compliance_impact,
            whitelisted,
            whitelist_reason,
            modifier_pid,
            modifier_process,
            modifier_path,
            entropy,
            attributes: current.attributes,
        };

        let mut event = TelemetryEvent::new(
            EventType::FileModify, // Use FileModify as base event type
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&fim_event).ok()?),
        );

        // Add metadata
        event
            .metadata
            .insert("event_subtype".to_string(), "file_integrity".to_string());
        event
            .metadata
            .insert("change_type".to_string(), format!("{:?}", change_type));

        // Add detection for integrity violations
        if !whitelisted && change_type != IntegrityChangeType::BaselineEstablished {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "file_integrity_violation".to_string(),
                confidence: match severity {
                    Severity::Critical => 1.0,
                    Severity::High => 0.9,
                    Severity::Medium => 0.7,
                    Severity::Low => 0.5,
                    Severity::Info => 0.3,
                },
                description: format!(
                    "File integrity change detected: {:?} on {}",
                    change_type, path_str
                ),
                mitre_tactics: vec!["persistence".to_string(), "defense-evasion".to_string()],
                mitre_techniques: vec!["T1565".to_string(), "T1565.001".to_string()],
            });
        }

        // Handle auto-response for policy violations
        if let Some(ref policy) = policy_action {
            if policy.action == PolicyAction::Block
                && policy.auto_response == AutoResponse::Quarantine
            {
                // Spawn quarantine task
                let path_str_clone = path_str.clone();
                let reason = format!("FIM policy violation: {}", policy.reason);
                tokio::spawn(async move {
                    match crate::response::fim::quarantine_file_internal(&path_str_clone, &reason)
                        .await
                    {
                        Ok(result) => {
                            info!(
                                path = %path_str_clone,
                                quarantine_path = %result.quarantine_path,
                                "File auto-quarantined by FIM policy"
                            );
                        }
                        Err(e) => {
                            error!(
                                path = %path_str_clone,
                                error = %e,
                                "Failed to auto-quarantine file"
                            );
                        }
                    }
                });
            }

            // Add policy info to event metadata
            event
                .metadata
                .insert("policy_id".to_string(), policy.id.clone());
            event
                .metadata
                .insert("policy_action".to_string(), format!("{:?}", policy.action));
            event.metadata.insert(
                "auto_response".to_string(),
                format!("{:?}", policy.auto_response),
            );
        }

        Some(event)
    }

    /// Get file information for baseline
    async fn get_file_info(path: &Path) -> Option<FileBaseline> {
        let path_str = path.to_string_lossy().to_string();

        // Get file metadata
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return None,
        };

        // Get hash and entropy
        let (hash, _entropy) = analyzers::hash_file(&path_str)
            .await
            .unwrap_or((Vec::new(), 0.0));

        // Get permissions
        let permissions = Self::get_permissions(path);

        // Get owner
        let (owner, group) = Self::get_owner(path);

        // Get attributes
        let attributes = Self::get_attributes(path);

        // Get times
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ctime = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Some(FileBaseline {
            hash,
            size: metadata.len(),
            permissions,
            owner,
            group,
            mtime,
            ctime,
            attributes,
            baseline_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            category: FileCategory::Custom,
            known_good: false,
        })
    }

    /// Get file permissions as string
    #[cfg(unix)]
    fn get_permissions(path: &Path) -> String {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path)
            .map(|m| format!("{:o}", m.permissions().mode() & 0o7777))
            .unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(windows)]
    fn get_permissions(path: &Path) -> String {
        // On Windows, we report basic attributes
        std::fs::metadata(path)
            .map(|m| {
                let mut perms = Vec::new();
                if m.permissions().readonly() {
                    perms.push("readonly");
                }
                if perms.is_empty() {
                    "normal".to_string()
                } else {
                    perms.join(",")
                }
            })
            .unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(not(any(unix, windows)))]
    fn get_permissions(_path: &Path) -> String {
        "unknown".to_string()
    }

    /// Get file owner
    #[cfg(unix)]
    fn get_owner(path: &Path) -> (String, String) {
        use std::os::unix::fs::MetadataExt;

        match std::fs::metadata(path) {
            Ok(m) => {
                let uid = m.uid();
                let gid = m.gid();

                // Try to resolve username
                let owner = unsafe {
                    let pwd = libc::getpwuid(uid);
                    if !pwd.is_null() {
                        std::ffi::CStr::from_ptr((*pwd).pw_name)
                            .to_string_lossy()
                            .to_string()
                    } else {
                        uid.to_string()
                    }
                };

                // Try to resolve group
                let group = unsafe {
                    let grp = libc::getgrgid(gid);
                    if !grp.is_null() {
                        std::ffi::CStr::from_ptr((*grp).gr_name)
                            .to_string_lossy()
                            .to_string()
                    } else {
                        gid.to_string()
                    }
                };

                (owner, group)
            }
            Err(_) => ("unknown".to_string(), "unknown".to_string()),
        }
    }

    #[cfg(windows)]
    fn get_owner(path: &Path) -> (String, String) {
        use std::process::Command;

        // Use icacls to get owner info
        let output = Command::new("cmd")
            .args(["/C", "icacls", &path.to_string_lossy(), "/q"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Parse owner from icacls output
                if let Some(line) = stdout.lines().next() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return (parts[1].to_string(), String::new());
                    }
                }
                ("unknown".to_string(), String::new())
            }
            _ => ("unknown".to_string(), String::new()),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn get_owner(_path: &Path) -> (String, String) {
        ("unknown".to_string(), "unknown".to_string())
    }

    /// Get file attributes
    #[cfg(windows)]
    fn get_attributes(path: &Path) -> Vec<String> {
        use std::os::windows::fs::MetadataExt;

        let mut attrs = Vec::new();

        if let Ok(metadata) = std::fs::metadata(path) {
            let file_attrs = metadata.file_attributes();

            const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
            const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
            const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
            const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;

            if file_attrs & FILE_ATTRIBUTE_READONLY != 0 {
                attrs.push("readonly".to_string());
            }
            if file_attrs & FILE_ATTRIBUTE_HIDDEN != 0 {
                attrs.push("hidden".to_string());
            }
            if file_attrs & FILE_ATTRIBUTE_SYSTEM != 0 {
                attrs.push("system".to_string());
            }
            if file_attrs & FILE_ATTRIBUTE_ARCHIVE != 0 {
                attrs.push("archive".to_string());
            }
            if file_attrs & FILE_ATTRIBUTE_ENCRYPTED != 0 {
                attrs.push("encrypted".to_string());
            }
            if file_attrs & FILE_ATTRIBUTE_COMPRESSED != 0 {
                attrs.push("compressed".to_string());
            }
        }

        attrs
    }

    #[cfg(unix)]
    fn get_attributes(path: &Path) -> Vec<String> {
        use std::process::Command;

        let mut attrs = Vec::new();

        // Check immutable and other attributes using lsattr
        if let Ok(output) = Command::new("lsattr").arg(path).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().next() {
                    let attr_str = line.split_whitespace().next().unwrap_or("");
                    if attr_str.contains('i') {
                        attrs.push("immutable".to_string());
                    }
                    if attr_str.contains('a') {
                        attrs.push("append-only".to_string());
                    }
                    if attr_str.contains('s') {
                        attrs.push("secure-deletion".to_string());
                    }
                    if attr_str.contains('u') {
                        attrs.push("undeletable".to_string());
                    }
                }
            }
        }

        // Check if file is a symlink
        if path.is_symlink() {
            attrs.push("symlink".to_string());
        }

        // Check setuid/setgid
        if let Ok(metadata) = std::fs::metadata(path) {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o4000 != 0 {
                attrs.push("setuid".to_string());
            }
            if mode & 0o2000 != 0 {
                attrs.push("setgid".to_string());
            }
            if mode & 0o1000 != 0 {
                attrs.push("sticky".to_string());
            }
        }

        attrs
    }

    #[cfg(not(any(unix, windows)))]
    fn get_attributes(_path: &Path) -> Vec<String> {
        Vec::new()
    }

    /// Determine file category based on path
    fn determine_category(path: &Path, config: &FimConfig) -> FileCategory {
        let path_str = path.to_string_lossy().to_lowercase();

        for monitored in &config.monitored_paths {
            let pattern = monitored.path.to_lowercase();

            if pattern.contains('*') {
                let pattern_parts: Vec<&str> = pattern.split('*').collect();
                if pattern_parts.len() == 2 {
                    let prefix = pattern_parts[0];
                    let suffix = pattern_parts[1];
                    if path_str.starts_with(&prefix) && path_str.ends_with(&suffix) {
                        return monitored.category.clone();
                    }
                }
            } else if path_str.starts_with(&pattern) {
                return monitored.category.clone();
            }
        }

        FileCategory::Custom
    }

    /// Get compliance frameworks impacted by this file
    fn get_compliance_impact(path: &Path, config: &FimConfig) -> Vec<ComplianceFramework> {
        let path_str = path.to_string_lossy().to_lowercase();

        for monitored in &config.monitored_paths {
            let pattern = monitored.path.to_lowercase();

            if pattern.contains('*') {
                let pattern_parts: Vec<&str> = pattern.split('*').collect();
                if pattern_parts.len() == 2 {
                    let prefix = pattern_parts[0];
                    let suffix = pattern_parts[1];
                    if path_str.starts_with(&prefix) && path_str.ends_with(&suffix) {
                        return monitored.compliance.clone();
                    }
                }
            } else if path_str.starts_with(&pattern) {
                return monitored.compliance.clone();
            }
        }

        Vec::new()
    }

    /// Check if change is whitelisted
    fn check_whitelist(
        path: &Path,
        change_type: &IntegrityChangeType,
        config: &FimConfig,
    ) -> (bool, Option<String>) {
        let path_str = path.to_string_lossy().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        for entry in &config.whitelist {
            // Check expiration
            if entry.expires > 0 && entry.expires < now {
                continue;
            }

            // Check pattern match
            let pattern = &entry.pattern;
            let matches = if pattern.contains('*') {
                // Simple glob matching
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.len() == 2 {
                    path_str.starts_with(parts[0]) && path_str.ends_with(parts[1])
                } else if parts.len() == 1 {
                    if pattern.starts_with('*') {
                        path_str.ends_with(parts[0])
                    } else {
                        path_str.starts_with(parts[0])
                    }
                } else {
                    false
                }
            } else {
                path_str == *pattern
            };

            if matches {
                // Check if change type is allowed
                if entry.allowed_changes.is_empty() || entry.allowed_changes.contains(change_type) {
                    return (true, Some(entry.reason.clone()));
                }
            }
        }

        (false, None)
    }

    /// Evaluate policies for a file change, returning the first matching policy
    fn evaluate_policies(
        path: &Path,
        _change_type: &IntegrityChangeType,
        severity: &Severity,
        config: &FimConfig,
    ) -> Option<(FimPolicy, bool)> {
        let path_str = path.to_string_lossy().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Sort policies by priority (lower = higher priority)
        let mut sorted_policies: Vec<_> = config
            .policies
            .iter()
            .filter(|p| p.enabled)
            .filter(|p| p.expires == 0 || p.expires > now)
            .collect();
        sorted_policies.sort_by_key(|p| p.priority);

        for policy in sorted_policies {
            // Check severity threshold
            if let Some(ref threshold) = policy.severity_threshold {
                if !Self::severity_meets_threshold(severity, threshold) {
                    continue;
                }
            }

            // Check pattern match (reuse whitelist pattern matching logic)
            let pattern = &policy.pattern;
            let matches = if pattern.contains('*') {
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.len() == 2 {
                    path_str.starts_with(parts[0]) && path_str.ends_with(parts[1])
                } else if parts.len() == 1 {
                    if pattern.starts_with('*') {
                        path_str.ends_with(parts[0])
                    } else {
                        path_str.starts_with(parts[0])
                    }
                } else {
                    false
                }
            } else {
                path_str == *pattern || path_str.starts_with(pattern)
            };

            if matches {
                let should_alert = policy.action != PolicyAction::Allow;
                return Some((policy.clone(), should_alert));
            }
        }

        None
    }

    /// Check if severity meets or exceeds threshold
    fn severity_meets_threshold(actual: &Severity, threshold: &Severity) -> bool {
        let severity_order = |s: &Severity| match s {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
        severity_order(actual) >= severity_order(threshold)
    }

    /// Determine event severity
    fn determine_severity(
        change_type: &IntegrityChangeType,
        category: &FileCategory,
        whitelisted: bool,
    ) -> Severity {
        if whitelisted {
            return Severity::Info;
        }

        match (change_type, category) {
            // Critical: Security file content changes
            (IntegrityChangeType::ContentModified, FileCategory::Security) => Severity::Critical,
            (IntegrityChangeType::Deleted, FileCategory::Security) => Severity::Critical,
            (IntegrityChangeType::Created, FileCategory::Security) => Severity::High,

            // Critical: Boot file modifications
            (IntegrityChangeType::ContentModified, FileCategory::Boot) => Severity::Critical,
            (IntegrityChangeType::Deleted, FileCategory::Boot) => Severity::Critical,

            // High: System binary modifications
            (IntegrityChangeType::ContentModified, FileCategory::System) => Severity::High,
            (IntegrityChangeType::Deleted, FileCategory::System) => Severity::High,
            (IntegrityChangeType::PermissionsChanged, FileCategory::System) => Severity::High,

            // Medium: Config changes
            (IntegrityChangeType::ContentModified, FileCategory::Config) => Severity::Medium,
            (IntegrityChangeType::PermissionsChanged, FileCategory::Config) => Severity::Medium,
            (IntegrityChangeType::OwnershipChanged, FileCategory::Config) => Severity::Medium,

            // Low: New files in monitored areas
            (IntegrityChangeType::Created, _) => Severity::Low,

            // Info: Baseline establishment and attributes
            (IntegrityChangeType::BaselineEstablished, _) => Severity::Info,
            (IntegrityChangeType::AttributesChanged, _) => Severity::Low,

            // Default
            (IntegrityChangeType::MultipleChanges, FileCategory::Security) => Severity::Critical,
            (IntegrityChangeType::MultipleChanges, FileCategory::Boot) => Severity::Critical,
            (IntegrityChangeType::MultipleChanges, _) => Severity::High,

            _ => Severity::Medium,
        }
    }

    /// Scheduled scan loop
    async fn scheduled_scan_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        baseline: Arc<RwLock<HashMap<String, FileBaseline>>>,
        config: FimConfig,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(config.scan_interval_seconds));

        loop {
            interval.tick().await;

            info!("Starting scheduled FIM scan");

            let scan_start = std::time::Instant::now();
            let mut files_scanned = 0u64;
            let mut changes_detected = 0u64;

            // Scan all configured paths
            for monitored in &config.monitored_paths {
                let path = Path::new(&monitored.path);

                // Handle glob patterns
                if monitored.path.contains('*') {
                    // For glob patterns, we need to expand them
                    if let Some(parent) = path.parent() {
                        if parent.exists() {
                            if let Ok(entries) = std::fs::read_dir(parent) {
                                for entry in entries.filter_map(|e| e.ok()) {
                                    let entry_path = entry.path();

                                    if !Self::should_monitor_path(&entry_path, &config) {
                                        continue;
                                    }

                                    if let Some(event) =
                                        Self::scan_file(&entry_path, &baseline, &config).await
                                    {
                                        changes_detected += 1;
                                        if tx.send(event).await.is_err() {
                                            return;
                                        }
                                    }
                                    files_scanned += 1;
                                }
                            }
                        }
                    }
                } else if path.exists() {
                    if path.is_file() {
                        if let Some(event) = Self::scan_file(path, &baseline, &config).await {
                            changes_detected += 1;
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                        files_scanned += 1;
                    } else if path.is_dir() {
                        // Walk directory
                        let walker = if monitored.recursive {
                            walkdir::WalkDir::new(path)
                        } else {
                            walkdir::WalkDir::new(path).max_depth(1)
                        };

                        for entry in walker.into_iter().filter_map(|e| e.ok()) {
                            let entry_path = entry.path();

                            if !entry_path.is_file() {
                                continue;
                            }

                            // Check extension filter
                            if !monitored.extensions.is_empty() {
                                if let Some(ext) = entry_path.extension() {
                                    let ext_str = ext.to_string_lossy().to_lowercase();
                                    if !monitored
                                        .extensions
                                        .iter()
                                        .any(|e| e.to_lowercase() == ext_str)
                                    {
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                            }

                            // Check exclusions
                            let path_str = entry_path.to_string_lossy().to_string();
                            if config
                                .excluded_paths
                                .iter()
                                .any(|p| path_str.starts_with(p))
                            {
                                continue;
                            }

                            if let Some(event) =
                                Self::scan_file(entry_path, &baseline, &config).await
                            {
                                changes_detected += 1;
                                if tx.send(event).await.is_err() {
                                    return;
                                }
                            }
                            files_scanned += 1;
                        }
                    }
                }
            }

            // Check for deleted files (files in baseline but no longer exist)
            let deleted_files: Vec<String> = {
                let bl = match baseline.read() {
                    Ok(bl) => bl,
                    Err(_) => continue,
                };

                bl.keys()
                    .filter(|p| !Path::new(p).exists())
                    .cloned()
                    .collect()
            };

            for path_str in deleted_files {
                let path = Path::new(&path_str);

                if let Some(event) = Self::process_file_change(
                    path,
                    &notify::EventKind::Remove(notify::event::RemoveKind::File),
                    &baseline,
                    &config,
                )
                .await
                {
                    changes_detected += 1;
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }

                // Remove from baseline
                if let Ok(mut bl) = baseline.write() {
                    bl.remove(&path_str);
                }
            }

            let duration = scan_start.elapsed();
            info!(
                files = files_scanned,
                changes = changes_detected,
                duration_ms = duration.as_millis(),
                "FIM scheduled scan completed"
            );
        }
    }

    /// Scan a single file and compare to baseline
    async fn scan_file(
        path: &Path,
        baseline: &Arc<RwLock<HashMap<String, FileBaseline>>>,
        config: &FimConfig,
    ) -> Option<TelemetryEvent> {
        let path_str = path.to_string_lossy().to_string();

        // Check file size limit
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > config.max_file_size {
                debug!(path = %path_str, size = metadata.len(), "Skipping large file");
                return None;
            }
        }

        // Get current file info
        let current_info = Self::get_file_info(path).await?;

        // Get baseline info
        let baseline_info = {
            let bl = baseline.read().ok()?;
            bl.get(&path_str).cloned()
        };

        match baseline_info {
            Some(prev) => {
                // Compare with baseline
                let mut changes = Vec::new();

                if prev.hash != current_info.hash {
                    changes.push(IntegrityChangeType::ContentModified);
                }
                if prev.permissions != current_info.permissions {
                    changes.push(IntegrityChangeType::PermissionsChanged);
                }
                if prev.owner != current_info.owner {
                    changes.push(IntegrityChangeType::OwnershipChanged);
                }
                if prev.attributes != current_info.attributes {
                    changes.push(IntegrityChangeType::AttributesChanged);
                }

                if changes.is_empty() {
                    // No changes
                    return None;
                }

                // Update baseline
                if let Ok(mut bl) = baseline.write() {
                    bl.insert(path_str.clone(), current_info.clone());
                }

                let change_type = if changes.len() > 1 {
                    IntegrityChangeType::MultipleChanges
                } else {
                    changes[0].clone()
                };

                // Create event
                Self::create_fim_event(path, &change_type, Some(&prev), &current_info, config).await
            }
            None => {
                // No baseline, establish one
                if let Ok(mut bl) = baseline.write() {
                    bl.insert(path_str.clone(), current_info.clone());
                }

                // Only report if we want to track new baselines
                if config.alert_on_deviation {
                    Self::create_fim_event(
                        path,
                        &IntegrityChangeType::BaselineEstablished,
                        None,
                        &current_info,
                        config,
                    )
                    .await
                } else {
                    None
                }
            }
        }
    }

    /// Create a FIM telemetry event
    async fn create_fim_event(
        path: &Path,
        change_type: &IntegrityChangeType,
        previous: Option<&FileBaseline>,
        current: &FileBaseline,
        config: &FimConfig,
    ) -> Option<TelemetryEvent> {
        let path_str = path.to_string_lossy().to_string();

        let category = Self::determine_category(path, config);
        let compliance_impact = Self::get_compliance_impact(path, config);
        let (whitelisted, whitelist_reason) = Self::check_whitelist(path, change_type, config);
        let severity = Self::determine_severity(change_type, &category, whitelisted);

        let entropy = if path.exists() {
            analyzers::hash_file(&path_str)
                .await
                .map(|(_, e)| e)
                .unwrap_or(0.0)
        } else {
            0.0
        };

        let fim_event = FileIntegrityEvent {
            path: path_str.clone(),
            change_type: change_type.clone(),
            previous_hash: previous.map(|p| p.hash.clone()).unwrap_or_default(),
            current_hash: current.hash.clone(),
            previous_size: previous.map(|p| p.size).unwrap_or(0),
            current_size: current.size,
            previous_permissions: previous.map(|p| p.permissions.clone()).unwrap_or_default(),
            current_permissions: current.permissions.clone(),
            previous_owner: previous.map(|p| p.owner.clone()).unwrap_or_default(),
            current_owner: current.owner.clone(),
            previous_mtime: previous.map(|p| p.mtime).unwrap_or(0),
            current_mtime: current.mtime,
            category,
            compliance_impact,
            whitelisted,
            whitelist_reason,
            modifier_pid: None,
            modifier_process: None,
            modifier_path: None,
            entropy,
            attributes: current.attributes.clone(),
        };

        let mut event = TelemetryEvent::new(
            EventType::FileModify,
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&fim_event).ok()?),
        );

        event
            .metadata
            .insert("event_subtype".to_string(), "file_integrity".to_string());
        event
            .metadata
            .insert("change_type".to_string(), format!("{:?}", change_type));

        if !whitelisted && change_type != &IntegrityChangeType::BaselineEstablished {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "file_integrity_violation".to_string(),
                confidence: match severity {
                    Severity::Critical => 1.0,
                    Severity::High => 0.9,
                    Severity::Medium => 0.7,
                    Severity::Low => 0.5,
                    Severity::Info => 0.3,
                },
                description: format!(
                    "File integrity change detected: {:?} on {}",
                    change_type, path_str
                ),
                mitre_tactics: vec!["persistence".to_string(), "defense-evasion".to_string()],
                mitre_techniques: vec!["T1565".to_string(), "T1565.001".to_string()],
            });
        }

        Some(event)
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Force a full baseline scan
    pub async fn force_baseline_scan(&self) -> Result<u64> {
        info!("Forcing full FIM baseline scan");

        let mut files_scanned = 0u64;

        for monitored in &self.fim_config.monitored_paths {
            let path = Path::new(&monitored.path);

            if monitored.path.contains('*') {
                if let Some(parent) = path.parent() {
                    if parent.exists() {
                        if let Ok(entries) = std::fs::read_dir(parent) {
                            for entry in entries.filter_map(|e| e.ok()) {
                                let entry_path = entry.path();
                                if Self::should_monitor_path(&entry_path, &self.fim_config) {
                                    if let Some(info) = Self::get_file_info(&entry_path).await {
                                        if let Ok(mut bl) = self.baseline.write() {
                                            bl.insert(
                                                entry_path.to_string_lossy().to_string(),
                                                info,
                                            );
                                        }
                                        files_scanned += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            } else if path.exists() {
                if path.is_file() {
                    if let Some(info) = Self::get_file_info(path).await {
                        if let Ok(mut bl) = self.baseline.write() {
                            bl.insert(path.to_string_lossy().to_string(), info);
                        }
                        files_scanned += 1;
                    }
                } else if path.is_dir() {
                    let walker = if monitored.recursive {
                        walkdir::WalkDir::new(path)
                    } else {
                        walkdir::WalkDir::new(path).max_depth(1)
                    };

                    for entry in walker.into_iter().filter_map(|e| e.ok()) {
                        let entry_path = entry.path();

                        if !entry_path.is_file() {
                            continue;
                        }

                        if !monitored.extensions.is_empty() {
                            if let Some(ext) = entry_path.extension() {
                                let ext_str = ext.to_string_lossy().to_lowercase();
                                if !monitored
                                    .extensions
                                    .iter()
                                    .any(|e| e.to_lowercase() == ext_str)
                                {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }

                        let path_str = entry_path.to_string_lossy().to_string();
                        if self
                            .fim_config
                            .excluded_paths
                            .iter()
                            .any(|p| path_str.starts_with(p))
                        {
                            continue;
                        }

                        if let Some(info) = Self::get_file_info(entry_path).await {
                            if let Ok(mut bl) = self.baseline.write() {
                                bl.insert(path_str, info);
                            }
                            files_scanned += 1;
                        }
                    }
                }
            }
        }

        // Save baseline
        self.save_baseline()?;

        info!(files = files_scanned, "FIM baseline scan completed");
        Ok(files_scanned)
    }

    /// Get baseline statistics
    pub fn get_baseline_stats(&self) -> Option<BaselineStats> {
        let bl = self.baseline.read().ok()?;

        let mut stats = BaselineStats {
            total_files: bl.len() as u64,
            total_size: 0,
            categories: HashMap::new(),
            oldest_baseline: u64::MAX,
            newest_baseline: 0,
        };

        for (_, info) in bl.iter() {
            stats.total_size += info.size;

            *stats
                .categories
                .entry(format!("{:?}", info.category))
                .or_insert(0) += 1;

            if info.baseline_updated < stats.oldest_baseline {
                stats.oldest_baseline = info.baseline_updated;
            }
            if info.baseline_updated > stats.newest_baseline {
                stats.newest_baseline = info.baseline_updated;
            }
        }

        if stats.oldest_baseline == u64::MAX {
            stats.oldest_baseline = 0;
        }

        Some(stats)
    }

    /// Get a cloned baseline entry for a specific path.
    pub fn get_baseline_entry(&self, path: &str) -> Option<FileBaseline> {
        let bl = self.baseline.read().ok()?;
        bl.get(path).cloned()
    }

    /// Add a whitelist entry
    pub fn add_whitelist_entry(&mut self, entry: WhitelistEntry) {
        self.fim_config.whitelist.push(entry);
    }

    /// Generate compliance report
    pub fn generate_compliance_report(
        &self,
        framework: &ComplianceFramework,
    ) -> Option<ComplianceReport> {
        let bl = self.baseline.read().ok()?;

        let mut report = ComplianceReport {
            framework: framework.clone(),
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            total_monitored_files: 0,
            compliant_files: 0,
            non_compliant_files: 0,
            missing_baseline: 0,
            issues: Vec::new(),
        };

        for monitored in &self.fim_config.monitored_paths {
            if monitored.compliance.contains(framework) {
                // Count files matching this path
                for (path, _info) in bl.iter() {
                    let path_lower = path.to_lowercase();
                    let pattern = monitored.path.to_lowercase();

                    let matches = if pattern.contains('*') {
                        let parts: Vec<&str> = pattern.split('*').collect();
                        if parts.len() == 2 {
                            path_lower.starts_with(parts[0]) && path_lower.ends_with(parts[1])
                        } else {
                            false
                        }
                    } else {
                        path_lower.starts_with(&pattern)
                    };

                    if matches {
                        report.total_monitored_files += 1;
                        report.compliant_files += 1;
                    }
                }
            }
        }

        Some(report)
    }
}

/// Baseline statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    pub total_files: u64,
    pub total_size: u64,
    pub categories: HashMap<String, u64>,
    pub oldest_baseline: u64,
    pub newest_baseline: u64,
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub generated_at: u64,
    pub total_monitored_files: u64,
    pub compliant_files: u64,
    pub non_compliant_files: u64,
    pub missing_baseline: u64,
    pub issues: Vec<String>,
}
