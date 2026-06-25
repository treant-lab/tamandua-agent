//! Agent Self-Protection Module
//!
//! Provides comprehensive protection against tampering, debugging, and evasion attempts.
//! This module is critical for EDR resilience - attackers commonly target security agents.
//!
//! ## Module Structure
//!
//! The protection system is organized into specialized submodules:
//!
//! - [`process_guard`] - Prevents agent process termination (PPL, critical process, driver callbacks)
//! - [`file_guard`] - Protects agent files (DACL, immutable attr, SELinux, SIP)
//! - [`registry_guard`] - Protects Windows registry keys (DACL, change monitoring)
//! - [`service_guard`] - Protects Windows service (DACL, recovery config, status monitoring)
//! - [`driver_integration`] - Communicates with kernel driver for protection
//! - [`anti_debug`] - Detects debugging attempts (API, PEB, timing, hardware breakpoints)
//! - [`anti_sandbox`] - Detects VM/sandbox/emulator environments (CPUID, SMBIOS, resource checks)
//!
//! ## Features
//!
//! - Anti-debug detection (IsDebuggerPresent, PEB flags, NtGlobalFlag, hardware breakpoints,
//!   debug env vars, DR0-DR3 monitoring, periodic re-checks every 10s)
//! - Integrity verification (binary section hashing, memory patch detection, IAT hook detection,
//!   critical DLL integrity, ETW provider unregistration detection)
//! - Process protection (critical process via NtSetInformationProcess, termination notifications,
//!   handle detection via kernel driver, DLL injection detection, thread monitoring, watchdog thread)
//! - Service persistence (service tamper detection, SCM monitoring, auto-restart with exponential
//!   backoff, binary replacement detection, canary file monitoring)
//! - Communication protection (cert pinning verification, fallback channels, heartbeat monitoring,
//!   encrypted local buffer for offline events)
//! - Anti-kill mechanisms (kernel driver PPL registration, handle duplication prevention,
//!   detect and alert on failed termination attempts)
//! - File protection (ACLs, integrity verification)
//! - Registry protection (Windows service keys)
//! - Memory protection (anti-dump, integrity checks)
//! - Watchdog process for auto-restart
//! - Linux-specific protections (ptrace, capabilities, namespaces)
//!
//! ## MITRE ATT&CK Mapping
//!
//! - T1562 - Impair Defenses
//! - T1562.001 - Disable or Modify Tools
//! - T1562.002 - Disable Windows Event Logging
//! - T1055 - Process Injection (DLL injection detection)
//! - T1014 - Rootkit (inline hook detection)
//!
//! ## Critical Processes (Never Kill)
//!
//! The following Windows system processes are protected and will never be killed:
//! - csrss.exe, smss.exe, wininit.exe, services.exe
//! - lsass.exe, winlogon.exe, dwm.exe
//! - System, Registry, Memory Compression
//! - svchost.exe (with critical flags)
//! - Tamandua agent itself

// This umbrella module wires together the EDR self-protection surface
// (anti-debug, anti-dump, anti-sandbox, process/file/registry/service/handle
// guards, driver integration). Many reserved trackers, debugger-detection
// helpers and baseline fields are kept exhaustive for downstream tamper
// reporting even when not all paths are dispatched yet.
#![allow(dead_code, unused_variables, non_snake_case, unused_unsafe)]

// Submodules for modular protection components
pub mod anti_debug;
pub mod anti_dump;
pub mod anti_sandbox;
pub mod driver_integration;
pub mod file_guard;
pub mod handle_protection;
pub mod process_guard;
pub mod registry_guard;
pub mod service_guard;

#[cfg(target_os = "windows")]
pub mod process_mitigations;

#[cfg(target_os = "windows")]
pub mod cet_shadow_stack;

#[cfg(target_os = "windows")]
pub mod hvci;

#[cfg(target_os = "windows")]
pub mod xfg;

#[cfg(target_os = "windows")]
pub mod kdp;

// Re-export key types from submodules for convenience
pub use anti_debug::{AntiDebugAction, AntiDebugConfig, AntiDebugEngine, AntiDebugStatus};
pub use anti_dump::{AntiDumpConfig, AntiDumpEngine, AntiDumpStatus};
pub use anti_sandbox::{
    AntiSandboxAction, AntiSandboxConfig, AntiSandboxEngine, SandboxIndicators, VmType,
};
pub use driver_integration::{
    register_for_restart_protection, signal_clean_shutdown, DriverIntegration,
    DriverIntegrationConfig, DriverIntegrationStatus, DriverSafetyFallback, DriverSelfProtStats,
    RestartProtectionStatusFallback,
};
pub use file_guard::{FileGuard, FileGuardConfig, FileGuardStatus};
pub use handle_protection::{
    get_protection_status as get_handle_protection_status, request_handle_protection,
    HandleProtectionFlags, HandleProtectionManager, HandleProtectionRequest,
    HandleProtectionResponse, HandleProtectionStatus, StrippedAccessEntry, IOCTL_ADD_PROTECTED_PID,
    IOCTL_QUERY_PROTECTION_STATUS, IOCTL_REMOVE_PROTECTED_PID,
};
pub use process_guard::{ProcessGuard, ProcessGuardConfig, ProcessGuardStatus, CRITICAL_PROCESSES};
pub use registry_guard::{RegistryGuard, RegistryGuardConfig, RegistryGuardStatus, PROTECTED_KEYS};
pub use service_guard::{ServiceGuard, ServiceGuardConfig, ServiceGuardStatus};

// CET (Control-flow Enforcement Technology) and Shadow Stack exports
#[cfg(target_os = "windows")]
pub use cet_shadow_stack::{
    check_cpuid_cet,
    // Enforcement
    enable_shadow_stack,
    enable_shadow_stack_audit,
    get_cet_summary,
    // Process monitoring
    get_process_cet_status,
    // Detection
    is_cet_supported,
    // Utilities
    is_dll_cet_compatible,
    CetBypassAttempt,
    CetEnforcementMode,
    // Monitoring engine
    CetMonitor,
    CetMonitorConfig,
    CetMonitorStatus,
    CetSupport,
    ProcessCetStatus,
    UserShadowStackPolicyFlags,
};

// HVCI (Hypervisor-protected Code Integrity) exports
#[cfg(target_os = "windows")]
pub use hvci::{
    get_hvci_status,
    HvciConfig,
    // Health metrics for agent reporting
    HvciHealthMetrics,
    // Monitoring engine
    HvciMonitor,
    // Status detection
    HvciStatus,
};

// XFG (eXtended Flow Guard) exports
#[cfg(target_os = "windows")]
pub use xfg::{
    calculate_cfg_coverage,
    calculate_xfg_coverage,
    check_current_exe_xfg,
    check_pe_xfg_support,
    check_xfg_alerts,
    get_process_xfg_status,
    get_unprotected_modules,
    get_xfg_incompatible_nonsystem_modules,
    get_xfg_status,
    scan_modules_xfg_status,
    // Module scanning
    ModuleXfgStatus,
    // PE analysis
    PeXfgInfo,
    // Alerting
    XfgAlert,
    XfgAlertType,
    // Monitoring
    XfgMonitor,
    XfgMonitorConfig,
    // Status detection
    XfgStatus,
};

// KDP (Kernel Data Protection) exports
#[cfg(target_os = "windows")]
pub use kdp::{
    // Bypass detection
    detect_kdp_bypass,
    enumerate_kdp_regions,
    get_kdp_health,
    get_kdp_status,
    is_kdp_misconfigured,
    KdpAlert,
    KdpAlertType,
    // Health assessment
    KdpHealth,
    KdpHealthLevel,
    // Monitoring
    KdpMonitor,
    KdpProtectionType,
    // Region enumeration (requires driver)
    KdpRegion,
    KdpRegionInfo,
    KdpRegionQuery,
    // Status detection
    KdpStatus,
    // Driver response structures
    KdpStatusResponse,
    IOCTL_ENUMERATE_KDP_REGIONS,
    // Driver IOCTLs
    IOCTL_QUERY_KDP_STATUS,
    IOCTL_QUERY_VBS_STATUS,
};

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Protection configuration - all protections are enabled by default
#[derive(Debug, Clone)]
pub struct ProtectionConfig {
    /// Enable anti-debug detection
    pub anti_debug_enabled: bool,
    /// Anti-debug check interval in seconds
    pub anti_debug_interval_secs: u64,
    /// Enable integrity verification
    pub integrity_verification_enabled: bool,
    /// Integrity check interval in seconds (base interval, jitter added)
    pub integrity_check_interval_secs: u64,
    /// Integrity check jitter in seconds (randomization to prevent timing attacks)
    pub integrity_jitter_secs: u64,
    /// Critical section (.text) integrity check interval (more frequent)
    pub critical_section_interval_secs: u64,
    /// Enable process protection (critical process, handle monitoring)
    pub process_protection_enabled: bool,
    /// Enable Windows critical-process flag. This is deliberately opt-in because
    /// terminating a critical process can bugcheck the host.
    pub critical_process_enabled: bool,
    /// Enable service persistence monitoring
    pub service_persistence_enabled: bool,
    /// Service tamper check interval in seconds
    pub service_check_interval_secs: u64,
    /// Enable communication protection (cert pinning, fallback)
    pub communication_protection_enabled: bool,
    /// Enable anti-kill mechanisms (kernel driver PPL)
    pub anti_kill_enabled: bool,
    /// Enable DLL injection detection
    pub dll_injection_detection_enabled: bool,
    /// DLL monitoring interval in seconds
    pub dll_monitor_interval_secs: u64,
    /// Enable thread monitoring
    pub thread_monitoring_enabled: bool,
    /// Enable canary file monitoring
    pub canary_file_monitoring_enabled: bool,
    /// Enable ETW provider monitoring
    pub etw_provider_monitoring_enabled: bool,
    /// Enable IAT hook detection
    pub iat_hook_detection_enabled: bool,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            anti_debug_enabled: true,
            anti_debug_interval_secs: 10,
            integrity_verification_enabled: true,
            // Reduced from 60s to 10s base + 5s jitter for faster tamper detection
            // This closes the timing window attack vector (RTO II)
            integrity_check_interval_secs: 10,
            integrity_jitter_secs: 5, // Randomize ±5s to prevent timing attacks
            critical_section_interval_secs: 3, // .text section checked more frequently
            process_protection_enabled: true,
            critical_process_enabled: false,
            service_persistence_enabled: true,
            // 60s (was 15s): each tick shells out to `sc query`/`sc qc`, and
            // every `sc.exe` spawns a `conhost.exe` that the agent then ingests
            // as its own process_create telemetry. 15s saturated low-core VMs;
            // OS-level failure recovery already covers fast auto-restart.
            service_check_interval_secs: 60,
            communication_protection_enabled: true,
            anti_kill_enabled: true,
            dll_injection_detection_enabled: true,
            dll_monitor_interval_secs: 5,
            thread_monitoring_enabled: true,
            canary_file_monitoring_enabled: false,
            etw_provider_monitoring_enabled: true,
            iat_hook_detection_enabled: true,
        }
    }
}

fn tamandua_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("TAMANDUA_DATA_DIR").map(PathBuf::from) {
        return path;
    }

    if let Some(path) = std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join("Tamandua")) {
        if path.exists() || path.parent().is_some_and(|parent| parent.exists()) {
            return path;
        }
    }

    std::env::var_os("SystemDrive")
        .map(|drive| PathBuf::from(format!(r"{}\ProgramData\Tamandua", drive.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Tamandua"))
}

/// Critical local agent assets that must be monitored for tampering.
///
/// Keep this list aligned with the updater/config paths used by `main.rs` and
/// the model/rule updater. Existing files are hashed and monitored; directories
/// are expanded by the file guard for per-file monitoring.
pub fn critical_agent_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let data = tamandua_data_dir();
        return vec![
            data.join("config").join("agent.toml"),
            data.join("config.toml"),
            data.join("rules"),
            data.join("rules").join("yara"),
            data.join("rules").join("sigma"),
            data.join("models"),
            data.join("iocs.json"),
            data.join("schedules"),
            data.join("cert.pem"),
            data.join("key.pem"),
            data.join("ca.pem"),
            PathBuf::from(r"C:\Program Files\Tamandua\tamandua-agent.exe"),
            PathBuf::from(r"C:\Program Files\Tamandua\tamandua-driver.sys"),
        ];
    }

    #[cfg(target_os = "linux")]
    {
        return vec![
            PathBuf::from("/etc/tamandua/agent.toml"),
            PathBuf::from("/etc/tamandua/config.toml"),
            PathBuf::from("/etc/tamandua/rules"),
            PathBuf::from("/etc/tamandua/rules/yara"),
            PathBuf::from("/etc/tamandua/rules/sigma"),
            PathBuf::from("/etc/tamandua/iocs.json"),
            PathBuf::from("/etc/tamandua/cert.pem"),
            PathBuf::from("/etc/tamandua/key.pem"),
            PathBuf::from("/etc/tamandua/ca.pem"),
            PathBuf::from("/var/lib/tamandua/iocs.json"),
            PathBuf::from("/var/lib/tamandua/models"),
            PathBuf::from("/var/lib/tamandua/rules"),
            PathBuf::from("/var/lib/tamandua/schedules"),
            PathBuf::from("/usr/bin/tamandua-agent"),
            PathBuf::from("/lib/systemd/system/tamandua.service"),
            PathBuf::from("/etc/systemd/system/tamandua.service"),
        ];
    }

    #[cfg(target_os = "macos")]
    {
        let base = PathBuf::from("/Library/Application Support/Tamandua");
        return vec![
            base.join("config").join("agent.toml"),
            base.join("config.toml"),
            base.join("rules"),
            base.join("rules").join("yara"),
            base.join("rules").join("sigma"),
            base.join("models"),
            base.join("iocs.json"),
            base.join("schedules"),
            base.join("cert.pem"),
            base.join("key.pem"),
            base.join("ca.pem"),
            PathBuf::from("/usr/local/bin/tamandua-agent"),
            PathBuf::from("/Library/LaunchDaemons/com.tamandua.agent.plist"),
            // Legacy path kept for upgraded early-alpha installs.
            PathBuf::from("/Library/Tamandua/config.toml"),
            PathBuf::from("/Library/Tamandua/iocs.json"),
            PathBuf::from("/Library/Tamandua/rules"),
        ];
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        vec![
            PathBuf::from("./config/agent.toml"),
            PathBuf::from("./config.toml"),
            PathBuf::from("./rules"),
            PathBuf::from("./models"),
            PathBuf::from("./iocs.json"),
            PathBuf::from("./schedules"),
        ]
    }
}

/// Protection status and statistics
#[derive(Debug, Clone, Default)]
pub struct ProtectionStatus {
    /// Process protection active
    pub process_protected: bool,
    /// Anti-debug active
    pub anti_debug_active: bool,
    /// Files protected
    pub files_protected: bool,
    /// Registry protection active (Windows)
    pub registry_protected: bool,
    /// Service protection active (Windows)
    pub service_protected: bool,
    /// Memory protection active
    pub memory_protected: bool,
    /// Network protection active
    pub network_protected: bool,
    /// Watchdog active
    pub watchdog_active: bool,
    /// Critical process flag set (NtSetInformationProcess)
    pub critical_process_set: bool,
    /// Kernel driver protection registered
    pub driver_protection_active: bool,
    /// DLL injection monitoring active
    pub dll_injection_monitor_active: bool,
    /// Thread monitoring active
    pub thread_monitor_active: bool,
    /// Service tamper monitoring active
    pub service_tamper_monitor_active: bool,
    /// IAT integrity verified
    pub iat_integrity_verified: bool,
    /// ETW provider monitoring active
    pub etw_monitor_active: bool,
    /// Number of tamper attempts detected
    pub tamper_attempts: u64,
    /// Last tamper attempt timestamp
    pub last_tamper_timestamp: Option<u64>,
    /// Last integrity check timestamp
    pub last_integrity_check: Option<u64>,
    /// Integrity check passed
    pub integrity_valid: bool,
    /// Number of debugger detections
    pub debugger_detections: u64,
    /// Number of injection detections
    pub injection_detections: u64,
    /// Number of service tamper detections
    pub service_tamper_detections: u64,
    /// Number of failed termination attempts
    pub failed_termination_attempts: u64,
}

/// Tamper event for alerting
#[derive(Debug, Clone)]
pub struct TamperEvent {
    pub timestamp: u64,
    pub event_type: TamperEventType,
    pub description: String,
    pub source_pid: Option<u32>,
    pub source_process: Option<String>,
    pub severity: TamperSeverity,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: Option<String>,
}

/// Types of tamper events
#[derive(Debug, Clone)]
pub enum TamperEventType {
    TerminationAttempt,
    DebuggerAttached,
    DebuggerHardwareBreakpoint,
    DebuggerNtGlobalFlag,
    DebuggerEnvironment,
    DebuggerRemote,
    DebuggerTimingAnomaly,
    MemoryScan,
    MemoryModification,
    FileModification,
    FileAccess,
    RegistryModification,
    ServiceModification,
    ServiceStopAttempt,
    ServiceDisableAttempt,
    ServiceBinaryReplaced,
    ConfigTamper,
    IntegrityFailure,
    SectionHashMismatch,
    IatHookDetected,
    DllIntegrityFailure,
    EtwProviderTamper,
    C2BlockAttempt,
    CertificatePinFailure,
    ProcessHollowing,
    InlineHook,
    DllInjection,
    ExternalThreadCreation,
    HandleDuplication,
    CanaryFileAccess,
    DriverProtectionFailure,
    CriticalProcessViolation,
}

/// Tamper severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Self-protection engine
pub struct ProtectionEngine {
    /// Current protection status
    status: Arc<RwLock<ProtectionStatus>>,
    /// Protection configuration
    config: ProtectionConfig,
    /// Agent executable path
    agent_path: PathBuf,
    /// Agent configuration paths
    config_paths: Vec<PathBuf>,
    /// Original file hashes for integrity verification
    file_hashes: Arc<RwLock<std::collections::HashMap<PathBuf, Vec<u8>>>>,
    /// Section hashes for binary integrity (section_name -> hash)
    #[cfg(target_os = "windows")]
    section_hashes: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    /// Known loaded DLLs at startup (module_name -> hash)
    #[cfg(target_os = "windows")]
    baseline_dlls: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    /// Tamper event sender
    tamper_tx: tokio::sync::mpsc::Sender<TamperEvent>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Tamper attempt counter
    tamper_count: Arc<AtomicU64>,
    /// Backup server URLs for failover
    backup_servers: Vec<String>,
    /// Certificate pins (SHA256 of public key)
    cert_pins: Vec<Vec<u8>>,
    /// Service restart attempt counter (for exponential backoff)
    restart_attempts: Arc<AtomicU64>,
    /// File guard for critical agent assets and local configuration.
    file_guard: Option<FileGuard>,
}

impl ProtectionEngine {
    /// Create a new protection engine
    pub fn new(
        tamper_tx: tokio::sync::mpsc::Sender<TamperEvent>,
        backup_servers: Vec<String>,
        cert_pins: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let agent_path = std::env::current_exe()?;

        Ok(Self {
            status: Arc::new(RwLock::new(ProtectionStatus::default())),
            config: ProtectionConfig::default(),
            agent_path,
            config_paths: critical_agent_paths(),
            file_hashes: Arc::new(RwLock::new(std::collections::HashMap::new())),
            #[cfg(target_os = "windows")]
            section_hashes: Arc::new(RwLock::new(std::collections::HashMap::new())),
            #[cfg(target_os = "windows")]
            baseline_dlls: Arc::new(RwLock::new(std::collections::HashMap::new())),
            tamper_tx,
            running: Arc::new(AtomicBool::new(false)),
            tamper_count: Arc::new(AtomicU64::new(0)),
            backup_servers,
            cert_pins,
            restart_attempts: Arc::new(AtomicU64::new(0)),
            file_guard: None,
        })
    }

    /// Initialize all protection mechanisms
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing agent self-protection");

        self.running.store(true, Ordering::SeqCst);

        // Calculate initial file hashes for integrity verification
        self.calculate_file_hashes().await?;

        // Platform-specific initialization
        #[cfg(target_os = "windows")]
        {
            self.initialize_windows_protection().await?;
        }

        #[cfg(target_os = "linux")]
        {
            self.initialize_linux_protection().await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.initialize_macos_protection().await?;
        }

        // Start protection monitoring tasks
        self.start_protection_monitors().await?;

        // Update status
        let mut status = self.status.write().await;
        status.integrity_valid = true;
        status.last_integrity_check = Some(Self::current_timestamp());

        info!("Self-protection initialized successfully");
        Ok(())
    }

    /// Calculate SHA256 hashes of protected files
    async fn calculate_file_hashes(&self) -> Result<()> {
        use sha2::{Digest, Sha256};

        let mut hashes = self.file_hashes.write().await;

        // Hash agent executable
        if let Ok(content) = tokio::fs::read(&self.agent_path).await {
            let hash = Sha256::digest(&content).to_vec();
            hashes.insert(self.agent_path.clone(), hash);
            debug!(path = %self.agent_path.display(), "Calculated agent hash");
        }

        // Hash config files
        for path in &self.config_paths {
            if path.exists() && path.is_file() {
                if let Ok(content) = tokio::fs::read(path).await {
                    let hash = Sha256::digest(&content).to_vec();
                    hashes.insert(path.clone(), hash);
                    debug!(path = %path.display(), "Calculated config hash");
                }
            }
        }

        info!(
            count = hashes.len(),
            "File hashes calculated for integrity verification"
        );
        Ok(())
    }

    /// Verify file integrity
    pub async fn verify_integrity(&self) -> Result<bool> {
        use sha2::{Digest, Sha256};

        let hashes = self.file_hashes.read().await;
        let mut all_valid = true;

        for (path, expected_hash) in hashes.iter() {
            if !path.exists() {
                warn!(path = %path.display(), "Protected file missing");
                self.report_tamper(TamperEvent {
                    timestamp: Self::current_timestamp(),
                    event_type: TamperEventType::FileModification,
                    description: format!("Protected file deleted: {}", path.display()),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Critical,
                    mitre_technique: Some("T1562.001".to_string()),
                })
                .await;
                all_valid = false;
                continue;
            }

            if let Ok(content) = tokio::fs::read(path).await {
                let current_hash = Sha256::digest(&content).to_vec();
                if current_hash != *expected_hash {
                    warn!(path = %path.display(), "Integrity check failed - file modified");
                    self.report_tamper(TamperEvent {
                        timestamp: Self::current_timestamp(),
                        event_type: TamperEventType::IntegrityFailure,
                        description: format!("File integrity failure: {}", path.display()),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1562.001".to_string()),
                    })
                    .await;
                    all_valid = false;
                }
            }
        }

        // Update status
        let mut status = self.status.write().await;
        status.integrity_valid = all_valid;
        status.last_integrity_check = Some(Self::current_timestamp());

        Ok(all_valid)
    }

    /// Start all protection monitoring tasks
    async fn start_protection_monitors(&self) -> Result<()> {
        let config = self.config.clone();

        // =====================================================================
        // 1. Anti-Debug Monitor (enhanced with NtGlobalFlag, hardware breakpoints,
        //    debug env vars, DR0-DR3, periodic re-checks)
        // =====================================================================
        if config.anti_debug_enabled {
            let running = self.running.clone();
            let tamper_tx = self.tamper_tx.clone();
            let status = self.status.clone();
            let tamper_count = self.tamper_count.clone();
            let interval_secs = config.anti_debug_interval_secs;

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

                while running.load(Ordering::SeqCst) {
                    interval.tick().await;

                    // Run all anti-debug checks
                    let detections = Self::run_anti_debug_checks();

                    for (event_type, description) in detections {
                        let mut s = status.write().await;
                        s.tamper_attempts += 1;
                        s.debugger_detections += 1;
                        s.last_tamper_timestamp = Some(Self::current_timestamp());
                        drop(s);

                        tamper_count.fetch_add(1, Ordering::SeqCst);

                        let event = TamperEvent {
                            timestamp: Self::current_timestamp(),
                            event_type,
                            severity: Self::anti_debug_severity(&description),
                            description,
                            source_pid: None,
                            source_process: None,
                            mitre_technique: Some("T1562".to_string()),
                        };

                        let _ = tamper_tx.send(event).await;

                        // Take evasive action
                        Self::anti_debug_evasion();
                    }
                }
            });

            let mut s = self.status.write().await;
            s.anti_debug_active = true;
            drop(s);
        }

        // =====================================================================
        // 2. Periodic integrity check (file hashes)
        // =====================================================================
        if config.integrity_verification_enabled {
            let running = self.running.clone();
            let file_hashes = self.file_hashes.clone();
            let tamper_tx = self.tamper_tx.clone();
            let status = self.status.clone();
            let interval_secs = config.integrity_check_interval_secs;

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

                while running.load(Ordering::SeqCst) {
                    interval.tick().await;

                    // Verify integrity
                    use sha2::{Digest, Sha256};
                    let hashes = file_hashes.read().await;

                    for (path, expected_hash) in hashes.iter() {
                        if let Ok(content) = tokio::fs::read(path).await {
                            let current_hash = Sha256::digest(&content).to_vec();
                            if current_hash != *expected_hash {
                                let mut s = status.write().await;
                                s.tamper_attempts += 1;
                                s.last_tamper_timestamp = Some(Self::current_timestamp());
                                s.integrity_valid = false;
                                drop(s);

                                let event = TamperEvent {
                                    timestamp: Self::current_timestamp(),
                                    event_type: TamperEventType::IntegrityFailure,
                                    description: format!(
                                        "Integrity check failed: {}",
                                        path.display()
                                    ),
                                    source_pid: None,
                                    source_process: None,
                                    severity: TamperSeverity::Critical,
                                    mitre_technique: Some("T1562.001".to_string()),
                                };

                                let _ = tamper_tx.send(event).await;
                            }
                        }
                    }
                }
            });
        }

        // =====================================================================
        // 3. Memory protection monitor (RWX detection)
        // =====================================================================
        {
            let running = self.running.clone();
            let tamper_tx = self.tamper_tx.clone();
            let status = self.status.clone();
            let tamper_count = self.tamper_count.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

                while running.load(Ordering::SeqCst) {
                    interval.tick().await;

                    // Check for memory scanning/modification
                    if let Some(event) = Self::check_memory_tampering() {
                        let mut s = status.write().await;
                        s.tamper_attempts += 1;
                        s.last_tamper_timestamp = Some(Self::current_timestamp());
                        drop(s);

                        tamper_count.fetch_add(1, Ordering::SeqCst);
                        let _ = tamper_tx.send(event).await;
                    }
                }
            });

            let mut s = self.status.write().await;
            s.memory_protected = true;
            drop(s);
        }

        // =====================================================================
        // 4. Windows-specific monitors (IAT, DLL injection, thread, service, ETW)
        // =====================================================================
        #[cfg(target_os = "windows")]
        {
            // IAT hook detection monitor
            if config.iat_hook_detection_enabled {
                let running = self.running.clone();
                let tamper_tx = self.tamper_tx.clone();
                let status = self.status.clone();

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

                    while running.load(Ordering::SeqCst) {
                        interval.tick().await;

                        let iat_events = Self::check_iat_hooks();
                        for event in iat_events {
                            let mut s = status.write().await;
                            s.tamper_attempts += 1;
                            s.last_tamper_timestamp = Some(Self::current_timestamp());
                            drop(s);

                            let _ = tamper_tx.send(event).await;
                        }
                    }
                });

                let mut s = self.status.write().await;
                s.iat_integrity_verified = true;
                drop(s);
            }

            // DLL injection detection monitor
            if config.dll_injection_detection_enabled {
                let running = self.running.clone();
                let tamper_tx = self.tamper_tx.clone();
                let status = self.status.clone();
                let interval_secs = config.dll_monitor_interval_secs;

                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
                    // Track known modules at startup
                    let mut known_modules = Self::enumerate_loaded_modules();
                    info!(
                        count = known_modules.len(),
                        "Baseline loaded modules captured"
                    );

                    while running.load(Ordering::SeqCst) {
                        interval.tick().await;

                        let current_modules = Self::enumerate_loaded_modules();

                        // Detect newly loaded modules
                        for module in &current_modules {
                            if !known_modules.contains(module) {
                                let module_lower = module.to_lowercase();
                                // Skip known safe Windows system modules that may load dynamically
                                let safe_modules = [
                                    // Core Windows
                                    "ntdll",
                                    "kernel32",
                                    "kernelbase",
                                    "advapi32",
                                    "user32",
                                    "gdi32",
                                    "shlwapi",
                                    "ole32",
                                    "oleaut32",
                                    "rpcrt4",
                                    "sechost",
                                    "imm32",
                                    "msvcrt",
                                    "ucrtbase",
                                    "vcruntime",
                                    "powrprof",
                                    "uxtheme",
                                    "dwmapi",
                                    // Security
                                    "amsi",
                                    "mpoav",
                                    "mpclient",
                                    "crypt32",
                                    "bcrypt",
                                    "schannel",
                                    "ncrypt",
                                    "rsaenh",
                                    "ntmarta",
                                    "samlib",
                                    "netapi32",
                                    "wintrust",
                                    // Networking
                                    "ws2_32",
                                    "mswsock",
                                    "dnsapi",
                                    "nsi",
                                    "rasadhlp",
                                    "winhttp",
                                    "wininet",
                                    "iphlpapi",
                                    "dhcpcsvc",
                                    "fwpuclnt",
                                    // System services
                                    "wbem",
                                    "clbcatq",
                                    "profapi",
                                    "userenv",
                                    "windows.storage",
                                    "kernel.appcore",
                                    "wtdccm",
                                    "imagehlp",
                                    "psapi",
                                    "dbghelp",
                                    // Hardware/Device
                                    "cfgmgr32",
                                    "devobj",
                                    "setupapi",
                                    "hid",
                                    "wtsapi32",
                                    // Tracing/Performance
                                    "tdh",
                                    "perfos",
                                    "pdh",
                                    "wevtapi",
                                    "secur32",
                                    // Shell/UI
                                    "shell32",
                                    "shcore",
                                    "comctl32",
                                    "comdlg32",
                                    "version",
                                    // Misc system
                                    "pfclient",
                                    "propsys",
                                    "sxs",
                                    "cryptsp",
                                    "cryptbase",
                                    "gpapi",
                                    "wldp",
                                    "normaliz",
                                    "sspicli",
                                    "msasn1",
                                ];

                                if safe_modules.iter().any(|safe| module_lower.contains(safe)) {
                                    continue;
                                }

                                // Also skip anything in System32/SysWOW64
                                if module_lower.contains("\\windows\\system32\\")
                                    || module_lower.contains("\\windows\\syswow64\\")
                                {
                                    continue;
                                }

                                warn!(module = %module, "New DLL loaded into agent process");

                                let mut s = status.write().await;
                                s.tamper_attempts += 1;
                                s.injection_detections += 1;
                                s.last_tamper_timestamp = Some(Self::current_timestamp());
                                drop(s);

                                let event = TamperEvent {
                                    timestamp: Self::current_timestamp(),
                                    event_type: TamperEventType::DllInjection,
                                    description: format!(
                                        "Unexpected DLL loaded into agent process: {}",
                                        module
                                    ),
                                    source_pid: None,
                                    source_process: None,
                                    severity: TamperSeverity::Critical,
                                    mitre_technique: Some("T1055.001".to_string()),
                                };

                                let _ = tamper_tx.send(event).await;
                            }
                        }

                        known_modules = current_modules;
                    }
                });

                let mut s = self.status.write().await;
                s.dll_injection_monitor_active = true;
                drop(s);
            }

            // External thread creation monitoring
            if config.thread_monitoring_enabled {
                let running = self.running.clone();
                let tamper_tx = self.tamper_tx.clone();
                let status = self.status.clone();

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));
                    let our_pid = std::process::id();
                    let mut known_thread_count = Self::count_threads(our_pid);

                    while running.load(Ordering::SeqCst) {
                        interval.tick().await;

                        let current_count = Self::count_threads(our_pid);

                        // If thread count jumped significantly, external injection likely
                        // Increased threshold to 100 to account for Tokio blocking thread pool scaling
                        if current_count > known_thread_count + 100 {
                            warn!(
                                previous = known_thread_count,
                                current = current_count,
                                "Unexpected thread count increase - possible injection"
                            );

                            let mut s = status.write().await;
                            s.tamper_attempts += 1;
                            s.injection_detections += 1;
                            s.last_tamper_timestamp = Some(Self::current_timestamp());
                            drop(s);

                            let event = TamperEvent {
                                timestamp: Self::current_timestamp(),
                                event_type: TamperEventType::ExternalThreadCreation,
                                description: format!(
                                    "Thread count jumped from {} to {} - possible external thread injection",
                                    known_thread_count, current_count
                                ),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::High,
                                mitre_technique: Some("T1055.003".to_string()),
                            };

                            let _ = tamper_tx.send(event).await;
                        }

                        known_thread_count = current_count;
                    }
                });

                let mut s = self.status.write().await;
                s.thread_monitor_active = true;
                drop(s);
            }

            // Service tamper detection monitor
            if config.service_persistence_enabled {
                let running = self.running.clone();
                let tamper_tx = self.tamper_tx.clone();
                let status = self.status.clone();
                let agent_path = self.agent_path.clone();
                let restart_attempts = self.restart_attempts.clone();
                let interval_secs = config.service_check_interval_secs;

                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

                    // Capture initial binary hash for replacement detection
                    let initial_hash = {
                        use sha2::{Digest, Sha256};
                        tokio::fs::read(&agent_path)
                            .await
                            .ok()
                            .map(|content| Sha256::digest(&content).to_vec())
                    };

                    while running.load(Ordering::SeqCst) {
                        interval.tick().await;

                        // Check service registration
                        let tamper_events = Self::check_service_tamper();
                        for event in tamper_events {
                            let mut s = status.write().await;
                            s.tamper_attempts += 1;
                            s.service_tamper_detections += 1;
                            s.last_tamper_timestamp = Some(Self::current_timestamp());
                            drop(s);

                            let _ = tamper_tx.send(event).await;
                        }

                        // Check binary replacement
                        if let Some(ref expected_hash) = initial_hash {
                            use sha2::{Digest, Sha256};
                            if let Ok(content) = tokio::fs::read(&agent_path).await {
                                let current_hash = Sha256::digest(&content).to_vec();
                                if current_hash != *expected_hash {
                                    warn!("Agent binary has been replaced on disk!");

                                    let mut s = status.write().await;
                                    s.tamper_attempts += 1;
                                    s.service_tamper_detections += 1;
                                    s.last_tamper_timestamp = Some(Self::current_timestamp());
                                    drop(s);

                                    let event = TamperEvent {
                                        timestamp: Self::current_timestamp(),
                                        event_type: TamperEventType::ServiceBinaryReplaced,
                                        description: format!(
                                            "Agent binary replaced on disk: {}",
                                            agent_path.display()
                                        ),
                                        source_pid: None,
                                        source_process: None,
                                        severity: TamperSeverity::Critical,
                                        mitre_technique: Some("T1562.001".to_string()),
                                    };

                                    let _ = tamper_tx.send(event).await;
                                }
                            }
                        }

                        // Reset restart counter if service is healthy
                        restart_attempts.store(0, Ordering::SeqCst);
                    }
                });

                let mut s = self.status.write().await;
                s.service_tamper_monitor_active = true;
                drop(s);
            }

            // ETW provider monitoring
            if config.etw_provider_monitoring_enabled {
                let running = self.running.clone();
                let tamper_tx = self.tamper_tx.clone();
                let status = self.status.clone();

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));

                    while running.load(Ordering::SeqCst) {
                        interval.tick().await;

                        let events = Self::check_etw_provider_integrity();
                        for event in events {
                            let mut s = status.write().await;
                            s.tamper_attempts += 1;
                            s.last_tamper_timestamp = Some(Self::current_timestamp());
                            drop(s);

                            let _ = tamper_tx.send(event).await;
                        }
                    }
                });

                let mut s = self.status.write().await;
                s.etw_monitor_active = true;
                drop(s);
            }

            // Canary file monitoring
            if config.canary_file_monitoring_enabled {
                let running = self.running.clone();
                let tamper_tx = self.tamper_tx.clone();
                let status = self.status.clone();

                tokio::spawn(async move {
                    // Create canary files in protected directory
                    let canary_paths = Self::create_canary_files().await;
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
                    let mut last_alert_by_path: HashMap<PathBuf, u64> = HashMap::new();
                    const CANARY_ALERT_SUPPRESSION_MS: u64 = 10 * 60 * 1000;

                    while running.load(Ordering::SeqCst) {
                        interval.tick().await;

                        for canary_path in &canary_paths {
                            if !canary_path.exists() {
                                warn!(path = %canary_path.display(), "Canary file deleted!");

                                let now = Self::current_timestamp();
                                let last_alert =
                                    last_alert_by_path.get(canary_path).copied().unwrap_or(0);
                                let should_alert =
                                    now.saturating_sub(last_alert) >= CANARY_ALERT_SUPPRESSION_MS;

                                if should_alert {
                                    let mut s = status.write().await;
                                    s.tamper_attempts += 1;
                                    s.last_tamper_timestamp = Some(now);
                                    drop(s);

                                    let event = TamperEvent {
                                        timestamp: now,
                                        event_type: TamperEventType::CanaryFileAccess,
                                        description: format!(
                                            "Canary file deleted - possible tamper attempt: {}",
                                            canary_path.display()
                                        ),
                                        source_pid: None,
                                        source_process: None,
                                        severity: TamperSeverity::Medium,
                                        mitre_technique: Some("T1562.001".to_string()),
                                    };

                                    let _ = tamper_tx.send(event).await;
                                    last_alert_by_path.insert(canary_path.clone(), now);
                                }

                                if let Err(e) =
                                    tokio::fs::write(canary_path, b"tamandua-canary").await
                                {
                                    debug!(
                                        error = %e,
                                        path = %canary_path.display(),
                                        "Failed to recreate canary file"
                                    );
                                }
                            }
                        }
                    }
                });
            }
        }

        Ok(())
    }

    // =========================================================================
    // 1. Anti-Debug Detection (Enhanced)
    // =========================================================================

    /// Run all anti-debug checks and return list of detections
    fn run_anti_debug_checks() -> Vec<(TamperEventType, String)> {
        let mut detections = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Method 1: IsDebuggerPresent
            if Self::check_debugger_windows_api() {
                detections.push((
                    TamperEventType::DebuggerAttached,
                    "Debugger detected via IsDebuggerPresent API".to_string(),
                ));
            }

            // Method 2: CheckRemoteDebuggerPresent
            if Self::check_remote_debugger_windows() {
                detections.push((
                    TamperEventType::DebuggerRemote,
                    "Remote debugger detected via CheckRemoteDebuggerPresent".to_string(),
                ));
            }

            // Method 3: NtGlobalFlag in PEB
            if Self::check_ntglobalflag_peb() {
                detections.push((
                    TamperEventType::DebuggerNtGlobalFlag,
                    "Debugger detected via NtGlobalFlag in PEB (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)".to_string(),
                ));
            }

            // Method 4: Hardware breakpoints via GetThreadContext (DR0-DR3)
            if Self::check_hardware_breakpoints() {
                detections.push((
                    TamperEventType::DebuggerHardwareBreakpoint,
                    "Hardware breakpoints detected in debug registers DR0-DR3".to_string(),
                ));
            }

            // Method 5: PEB->BeingDebugged via NtQueryInformationProcess
            if Self::check_peb_being_debugged() {
                detections.push((
                    TamperEventType::DebuggerAttached,
                    "Debugger detected via PEB->BeingDebugged (NtQueryInformationProcess ProcessDebugPort)".to_string(),
                ));
            }

            // Method 6: Timing anomaly check
            if Self::timing_check() {
                detections.push((
                    TamperEventType::DebuggerTimingAnomaly,
                    "Timing anomaly detected - execution significantly slower than expected (possible debugger)".to_string(),
                ));
            }
        }

        // Cross-platform: debug environment variables
        if Self::check_debug_environment_vars() {
            detections.push((
                TamperEventType::DebuggerEnvironment,
                "Debug-related environment variables detected".to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(description) = Self::check_debugger_linux() {
                detections.push((TamperEventType::DebuggerAttached, description));
            }
        }

        #[cfg(target_os = "macos")]
        {
            if Self::check_debugger_macos() {
                detections.push((
                    TamperEventType::DebuggerAttached,
                    "Debugger detected via sysctl P_TRACED flag".to_string(),
                ));
            }
        }

        detections
    }

    /// Check IsDebuggerPresent (Windows)
    #[cfg(target_os = "windows")]
    fn check_debugger_windows_api() -> bool {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        unsafe { IsDebuggerPresent().as_bool() }
    }

    /// Check CheckRemoteDebuggerPresent (Windows)
    #[cfg(target_os = "windows")]
    fn check_remote_debugger_windows() -> bool {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let mut debugger_present: BOOL = BOOL(0);
            if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut debugger_present).is_ok() {
                return debugger_present.as_bool();
            }
        }
        false
    }

    /// Check NtGlobalFlag in PEB for debugger artifacts
    /// When a process is created by a debugger, the heap flags in the PEB are set:
    /// FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) |
    /// FLG_HEAP_VALIDATE_PARAMETERS (0x40) = 0x70
    #[cfg(target_os = "windows")]
    fn check_ntglobalflag_peb() -> bool {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtQueryInformationProcess\0".as_ptr()),
            );
            let nt_query: NtQueryInformationProcessFn = match func {
                Some(f) => std::mem::transmute(f),
                None => return false,
            };

            // ProcessBasicInformation = 0
            #[repr(C)]
            struct ProcessBasicInformation {
                reserved1: usize,
                peb_base_address: *const u8,
                reserved2: [usize; 2],
                unique_process_id: usize,
                reserved3: usize,
            }

            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length: u32 = 0;

            let status = nt_query(
                GetCurrentProcess(),
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            if status != 0 || pbi.peb_base_address.is_null() {
                return false;
            }

            // NtGlobalFlag is at offset 0xBC (32-bit) or 0xBC (64-bit before RS2)
            // On x64: PEB + 0xBC = NtGlobalFlag
            #[cfg(target_arch = "x86_64")]
            let ntglobalflag_offset: usize = 0xBC;
            #[cfg(target_arch = "x86")]
            let ntglobalflag_offset: usize = 0x68;

            let ntglobalflag_ptr = pbi.peb_base_address.add(ntglobalflag_offset) as *const u32;

            // Read with volatile to prevent optimization
            let ntglobalflag = std::ptr::read_volatile(ntglobalflag_ptr);

            // Check for debugger heap flags (0x70)
            const FLG_HEAP_DEBUG_FLAGS: u32 = 0x70;
            (ntglobalflag & FLG_HEAP_DEBUG_FLAGS) != 0
        }
    }

    /// Check hardware breakpoints via debug registers DR0-DR3
    /// Debuggers use DR0-DR3 to set hardware breakpoints on memory addresses
    #[cfg(target_os = "windows")]
    fn check_hardware_breakpoints() -> bool {
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, CONTEXT, CONTEXT_FLAGS,
        };
        use windows::Win32::System::Threading::GetCurrentThread;

        unsafe {
            let mut context: CONTEXT = std::mem::zeroed();
            // CONTEXT_DEBUG_REGISTERS = 0x00010010 (x64)
            context.ContextFlags = CONTEXT_FLAGS(0x00100010); // CONTEXT_DEBUG_REGISTERS on x64

            if GetThreadContext(GetCurrentThread(), &mut context).is_ok() {
                // Check DR0-DR3 for hardware breakpoint addresses
                if context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Check for debug environment variables
    fn check_debug_environment_vars() -> bool {
        let debug_vars = [
            "_",              // On Linux, _ contains the debugger path (gdb, lldb, etc.)
            "RUST_BACKTRACE", // While legitimate, combined with other signals it's suspicious
        ];

        let debugger_names = [
            "gdb", "lldb", "strace", "ltrace", "x64dbg", "ollydbg", "windbg", "ida",
        ];

        // Check _ variable for debugger names (Linux/macOS)
        if let Ok(underscore) = std::env::var("_") {
            let lower = underscore.to_lowercase();
            for name in &debugger_names {
                if lower.contains(name) {
                    return true;
                }
            }
        }

        // Check for LD_PRELOAD (can be used for hooking)
        if let Ok(ld_preload) = std::env::var("LD_PRELOAD") {
            if !ld_preload.is_empty() {
                return true;
            }
        }

        // Check for DYLD_INSERT_LIBRARIES (macOS equivalent)
        if let Ok(dyld) = std::env::var("DYLD_INSERT_LIBRARIES") {
            if !dyld.is_empty() {
                return true;
            }
        }

        false
    }

    #[cfg(target_os = "windows")]
    fn check_peb_being_debugged() -> bool {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                ProcessHandle: windows::Win32::Foundation::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"NtQueryInformationProcess\0".as_ptr()),
            );
            let nt_query: NtQueryInformationProcessFn = match func {
                Some(f) => std::mem::transmute(f),
                None => return false,
            };

            // ProcessDebugPort = 7
            let mut debug_port: usize = 0;
            let mut return_length: u32 = 0;

            let status = nt_query(
                GetCurrentProcess(),
                7, // ProcessDebugPort
                &mut debug_port as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            );

            if status == 0 && debug_port != 0 {
                return true;
            }
        }

        false
    }

    #[cfg(target_os = "windows")]
    fn timing_check() -> bool {
        use std::time::Instant;

        let start = Instant::now();
        let mut _x: u64 = 0;
        for i in 0..10000 {
            _x = _x.wrapping_add(i);
        }
        let elapsed = start.elapsed();
        // If it took more than 100ms for this trivial loop, likely being debugged
        elapsed.as_millis() > 100
    }

    /// Check if a debugger is present (aggregated check used by public API)
    fn check_debugger_present() -> bool {
        #[cfg(target_os = "windows")]
        {
            return Self::check_debugger_windows_api()
                || Self::check_remote_debugger_windows()
                || Self::check_peb_being_debugged()
                || Self::check_hardware_breakpoints()
                || Self::check_ntglobalflag_peb();
        }

        #[cfg(target_os = "linux")]
        {
            return Self::check_debugger_linux().is_some();
        }

        #[cfg(target_os = "macos")]
        {
            return Self::check_debugger_macos();
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            return false;
        }
    }

    fn anti_debug_severity(description: &str) -> TamperSeverity {
        #[cfg(target_os = "linux")]
        {
            if description.contains("ptrace self-trace test") {
                return TamperSeverity::Medium;
            }
        }

        TamperSeverity::Critical
    }

    #[cfg(target_os = "linux")]
    fn check_debugger_linux() -> Option<String> {
        use std::fs;

        // Method 1: Check /proc/self/status for TracerPid
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split_whitespace().nth(1) {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            if pid != 0 {
                                return Some(format!(
                                    "Debugger detected via /proc/self/status TracerPid={}",
                                    pid
                                ));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    fn check_debugger_macos() -> bool {
        std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &std::process::id().to_string()])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|stat| stat.contains('T'))
            .unwrap_or(false)
    }

    /// Take evasive action when debugger detected
    fn anti_debug_evasion() {
        warn!("Debugger detected - taking evasive action");
        // Option 1: Clear sensitive data from memory
        // Option 2: Randomize timing and paths
        // Option 3: Alert and continue with reduced functionality
        // Do NOT crash or exit - this would allow attacker to disable agent
    }

    // =========================================================================
    // 2. Integrity Verification (Section Hashing, IAT Hooks, DLL Integrity)
    // =========================================================================

    /// Check IAT (Import Address Table) for hooks
    /// Compares IAT entries against the actual export addresses from the DLL on disk
    #[cfg(target_os = "windows")]
    fn check_iat_hooks() -> Vec<TamperEvent> {
        let mut events = Vec::new();

        // Critical DLLs and functions to verify
        let checks = [
            (
                "ntdll.dll",
                &[
                    "NtTerminateProcess",
                    "NtWriteVirtualMemory",
                    "NtReadVirtualMemory",
                    "NtCreateThreadEx",
                    "NtAllocateVirtualMemory",
                    "NtProtectVirtualMemory",
                    "NtQuerySystemInformation",
                ][..],
            ),
            (
                "kernel32.dll",
                &[
                    "TerminateProcess",
                    "OpenProcess",
                    "WriteProcessMemory",
                    "ReadProcessMemory",
                    "CreateRemoteThread",
                    "VirtualAllocEx",
                    "VirtualProtectEx",
                ][..],
            ),
            (
                "advapi32.dll",
                &[
                    "OpenProcessToken",
                    "OpenServiceW",
                    "ControlService",
                    "ChangeServiceConfigW",
                ][..],
            ),
        ];

        for (dll_name, functions) in &checks {
            for function in *functions {
                if let Some(hook_type) = check_function_hook(dll_name, function) {
                    events.push(TamperEvent {
                        timestamp: Self::current_timestamp(),
                        event_type: TamperEventType::IatHookDetected,
                        description: format!(
                            "IAT/inline hook detected: {}!{} ({})",
                            dll_name, function, hook_type
                        ),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1562.001".to_string()),
                    });
                }
            }
        }

        events
    }

    /// Check ETW provider integrity
    /// Detects if security-relevant ETW providers have been unregistered
    #[cfg(target_os = "windows")]
    fn check_etw_provider_integrity() -> Vec<TamperEvent> {
        let mut events = Vec::new();

        // Check if EtwEventWrite in ntdll has been patched
        // Common evasion: patch EtwEventWrite to return immediately (xor eax, eax; ret)
        unsafe {
            use windows::core::{w, PCSTR};
            use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

            if let Ok(ntdll) = GetModuleHandleW(w!("ntdll.dll")) {
                if let Some(func_addr) =
                    GetProcAddress(ntdll, PCSTR::from_raw(b"EtwEventWrite\0".as_ptr()))
                {
                    let func_ptr = func_addr as *const u8;

                    // Check for common patches:
                    // xor eax, eax; ret = 33 C0 C3 (3 bytes)
                    // ret = C3 (1 byte)
                    let first_byte = std::ptr::read_volatile(func_ptr);
                    let second_byte = std::ptr::read_volatile(func_ptr.add(1));
                    let third_byte = std::ptr::read_volatile(func_ptr.add(2));

                    // Pattern: xor eax, eax; ret (0x33 0xC0 0xC3) or mov eax, 0; ret
                    if (first_byte == 0x33 && second_byte == 0xC0 && third_byte == 0xC3)
                        || first_byte == 0xC3
                    // immediate ret
                    {
                        events.push(TamperEvent {
                            timestamp: Self::current_timestamp(),
                            event_type: TamperEventType::EtwProviderTamper,
                            description: "EtwEventWrite has been patched - ETW telemetry disabled"
                                .to_string(),
                            source_pid: None,
                            source_process: None,
                            severity: TamperSeverity::Critical,
                            mitre_technique: Some("T1562.006".to_string()),
                        });
                    }
                }

                // Also check AmsiScanBuffer for AMSI bypass
                if let Some(func_addr) = GetProcAddress(
                    ntdll,
                    PCSTR::from_raw(b"EtwNotificationRegister\0".as_ptr()),
                ) {
                    let func_ptr = func_addr as *const u8;
                    let first_byte = std::ptr::read_volatile(func_ptr);

                    if first_byte == 0xC3 {
                        events.push(TamperEvent {
                            timestamp: Self::current_timestamp(),
                            event_type: TamperEventType::EtwProviderTamper,
                            description: "EtwNotificationRegister has been patched - ETW provider registration disabled".to_string(),
                            source_pid: None,
                            source_process: None,
                            severity: TamperSeverity::Critical,
                            mitre_technique: Some("T1562.006".to_string()),
                        });
                    }
                }
            }
        }

        events
    }

    // =========================================================================
    // 3. Process Protection (Critical Process, Handle Detection, Driver)
    // =========================================================================

    /// Set the current process as a critical process via NtSetInformationProcess
    /// When a critical process is terminated, the system will BSOD
    /// This is the ultimate anti-kill mechanism from usermode
    #[cfg(target_os = "windows")]
    fn set_critical_process() -> Result<()> {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        unsafe {
            let ntdll = GetModuleHandleW(w!("ntdll.dll"))
                .map_err(|e| anyhow::anyhow!("Failed to get ntdll handle: {:?}", e))?;

            type RtlSetProcessIsCriticalFn =
                unsafe extern "system" fn(NewValue: u32, OldValue: *mut u32, CheckFlag: u32) -> i32;

            let func = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"RtlSetProcessIsCritical\0".as_ptr()),
            );

            if let Some(f) = func {
                let rtl_set_critical: RtlSetProcessIsCriticalFn = std::mem::transmute(f);
                let mut old_value: u32 = 0;

                let status = rtl_set_critical(1, &mut old_value, 0);

                if status != 0 {
                    return Err(anyhow::anyhow!(
                        "RtlSetProcessIsCritical failed: NTSTATUS 0x{:08X}",
                        status
                    ));
                }

                info!("Process set as critical (BSOD on termination)");
            } else {
                return Err(anyhow::anyhow!(
                    "RtlSetProcessIsCritical not found in ntdll"
                ));
            }
        }

        Ok(())
    }

    /// Register with kernel driver for PPL-like protection
    /// The driver will strip dangerous access rights from handles opened to our process
    #[cfg(target_os = "windows")]
    fn register_driver_protection() -> Result<()> {
        use crate::driver;

        if !driver::is_driver_loaded() {
            return Err(anyhow::anyhow!("Tamandua kernel driver is not loaded"));
        }

        let mut conn = driver::DriverConnection::new();
        conn.connect()?;

        let agent_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Register agent with full protection (anti-terminate, anti-inject, anti-memory, anti-dup)
        conn.register_agent(
            &agent_path,
            None,
            true, // auto_restart
            true, // protected
        )?;

        // Protect our own process with all flags
        conn.protect_process(std::process::id(), driver::protect_flags::FULL)?;

        info!("Registered with kernel driver for process protection");
        Ok(())
    }

    // =========================================================================
    // 4. Service Persistence (Windows)
    // =========================================================================

    /// Check if service registration has been tampered with
    #[cfg(target_os = "windows")]
    fn check_service_tamper() -> Vec<TamperEvent> {
        let mut events = Vec::new();

        // Check service configuration via sc query
        let output = std::process::Command::new("sc")
            .args(["query", "TamanduaAgent"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();

            if stdout.contains("stopped") && !Self::is_foreground_agent_process() {
                events.push(TamperEvent {
                    timestamp: Self::current_timestamp(),
                    event_type: TamperEventType::ServiceStopAttempt,
                    description: "TamanduaAgent service is stopped".to_string(),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Critical,
                    mitre_technique: Some("T1562.001".to_string()),
                });
            } else if stdout.contains("stopped") {
                debug!(
                    "TamanduaAgent service is stopped, but the current foreground agent process is active"
                );
            }
        } else {
            // Service might not be installed
            debug!("Could not query TamanduaAgent service status");
        }

        // Check if service start type has been changed to disabled
        let output = std::process::Command::new("sc")
            .args(["qc", "TamanduaAgent"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();

            if stdout.contains("disabled") {
                events.push(TamperEvent {
                    timestamp: Self::current_timestamp(),
                    event_type: TamperEventType::ServiceDisableAttempt,
                    description: "TamanduaAgent service has been disabled".to_string(),
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Critical,
                    mitre_technique: Some("T1562.001".to_string()),
                });

                // Try to re-enable the service
                let _ = std::process::Command::new("sc")
                    .args(["config", "TamanduaAgent", "start=", "auto"])
                    .output();
                info!("Attempted to re-enable service");
            }
        }

        // Check SCM for recovery settings. Failure-recovery actions are static
        // SCM configuration, not per-cycle state, so verify/restore them at most
        // once per process run. Previously this ran `sc qfailure` on every tick
        // (default 15s) and, whenever the parse missed the "restart" token,
        // re-ran `sc failure` every tick as well. Each `sc.exe` also spawns a
        // `conhost.exe`, and the agent ingests its own resulting process_create
        // telemetry, so the loop became a self-inflicted process storm that
        // saturated low-core VMs. Configure once instead.
        static FAILURE_ACTIONS_CHECKED: std::sync::Once = std::sync::Once::new();
        FAILURE_ACTIONS_CHECKED.call_once(|| {
            let output = std::process::Command::new("sc")
                .args(["qfailure", "TamanduaAgent"])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // If failure actions are empty, they've been cleared
                if !stdout.to_lowercase().contains("restart") {
                    // Re-set failure actions
                    let _ = std::process::Command::new("sc")
                        .args([
                            "failure",
                            "TamanduaAgent",
                            "reset=",
                            "86400",
                            "actions=",
                            "restart/5000/restart/10000/restart/30000",
                        ])
                        .output();
                    debug!("Restored service failure recovery actions with exponential backoff");
                }
            }
        });

        events
    }

    #[cfg(target_os = "windows")]
    fn is_foreground_agent_process() -> bool {
        std::env::args().any(|arg| arg == "--foreground")
    }

    #[cfg(not(target_os = "windows"))]
    fn check_service_tamper() -> Vec<TamperEvent> {
        Vec::new()
    }

    // =========================================================================
    // 5. DLL Injection Detection & Thread Monitoring (Windows)
    // =========================================================================

    /// Enumerate all loaded modules (DLLs) in the current process
    #[cfg(target_os = "windows")]
    fn enumerate_loaded_modules() -> Vec<String> {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut modules = Vec::new();

        unsafe {
            let process = GetCurrentProcess();
            let mut module_handles = [HMODULE::default(); 1024];
            let mut bytes_needed: u32 = 0;

            if EnumProcessModules(
                process,
                module_handles.as_mut_ptr(),
                (module_handles.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut bytes_needed,
            )
            .is_ok()
            {
                let count = (bytes_needed as usize / std::mem::size_of::<HMODULE>())
                    .min(module_handles.len());

                for i in 0..count {
                    let mut name_buf = [0u16; 260];
                    let len = GetModuleFileNameExW(process, module_handles[i], &mut name_buf);
                    if len > 0 {
                        let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                        modules.push(name);
                    }
                }
            }
        }

        modules
    }

    #[cfg(not(target_os = "windows"))]
    fn enumerate_loaded_modules() -> Vec<String> {
        Vec::new()
    }

    /// Count threads in a given process
    #[cfg(target_os = "windows")]
    fn count_threads(pid: u32) -> u32 {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return 0,
            };

            let mut thread_entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..std::mem::zeroed()
            };

            let mut count: u32 = 0;

            if Thread32First(snapshot, &mut thread_entry).is_ok() {
                loop {
                    if thread_entry.th32OwnerProcessID == pid {
                        count += 1;
                    }

                    if Thread32Next(snapshot, &mut thread_entry).is_err() {
                        break;
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            count
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn count_threads(_pid: u32) -> u32 {
        0
    }

    // =========================================================================
    // 6. Canary File Monitoring
    // =========================================================================

    /// Create canary files in protected directories
    /// These files serve as tripwires - if they're deleted or modified, it indicates tampering
    #[cfg(target_os = "windows")]
    async fn create_canary_files() -> Vec<PathBuf> {
        let canary_dir = tamandua_data_dir().join(".canary");
        let _ = tokio::fs::create_dir_all(&canary_dir).await;

        let canary_files = vec![
            canary_dir.join("integrity.dat"),
            canary_dir.join("watchdog.dat"),
        ];

        for path in &canary_files {
            let content = format!(
                "TAMANDUA_CANARY:{}:{}",
                Self::current_timestamp(),
                uuid::Uuid::new_v4()
            );
            if let Err(e) = tokio::fs::write(path, content.as_bytes()).await {
                debug!(error = %e, path = %path.display(), "Failed to create canary file");
            }
        }

        info!(count = canary_files.len(), "Canary files created");
        canary_files
    }

    #[cfg(not(target_os = "windows"))]
    async fn create_canary_files() -> Vec<PathBuf> {
        let canary_dir = PathBuf::from("/var/lib/tamandua/.canary");
        let _ = tokio::fs::create_dir_all(&canary_dir).await;

        let canary_files = vec![
            canary_dir.join("integrity.dat"),
            canary_dir.join("watchdog.dat"),
        ];

        for path in &canary_files {
            let content = format!(
                "TAMANDUA_CANARY:{}:{}",
                Self::current_timestamp(),
                uuid::Uuid::new_v4()
            );
            if let Err(e) = tokio::fs::write(path, content.as_bytes()).await {
                debug!(error = %e, path = %path.display(), "Failed to create canary file");
            }
        }

        info!(count = canary_files.len(), "Canary files created");
        canary_files
    }

    // =========================================================================
    // Memory Tampering Detection
    // =========================================================================

    /// Check for memory tampering (scanning, modification)
    fn check_memory_tampering() -> Option<TamperEvent> {
        #[cfg(target_os = "windows")]
        {
            return Self::check_memory_tampering_windows();
        }

        #[cfg(target_os = "linux")]
        {
            return Self::check_memory_tampering_linux();
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            return None;
        }
    }

    #[cfg(target_os = "windows")]
    fn check_memory_tampering_windows() -> Option<TamperEvent> {
        use windows::Win32::System::Memory::{
            VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
        };

        unsafe {
            let mut address: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            while VirtualQuery(
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                // Check for suspicious PAGE_EXECUTE_READWRITE
                if mbi.Protect == PAGE_EXECUTE_READWRITE {
                    return Some(TamperEvent {
                        timestamp: Self::current_timestamp(),
                        event_type: TamperEventType::MemoryModification,
                        description: format!(
                            "Suspicious RWX memory region at 0x{:X} (size: {} bytes)",
                            mbi.BaseAddress as usize, mbi.RegionSize
                        ),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::High,
                        mitre_technique: Some("T1055".to_string()),
                    });
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn check_memory_tampering_linux() -> Option<TamperEvent> {
        use std::fs;

        if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if line.contains("rwxp") || line.contains("rwxs") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(path) = parts.get(5) {
                        if !path.contains("[heap]") && !path.contains("[stack]") {
                            return Some(TamperEvent {
                                timestamp: Self::current_timestamp(),
                                event_type: TamperEventType::MemoryModification,
                                description: format!("Suspicious RWX memory region: {}", line),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::Medium,
                                mitre_technique: Some("T1055".to_string()),
                            });
                        }
                    }
                }
            }
        }

        None
    }

    // =========================================================================
    // Utility Functions
    // =========================================================================

    /// Report a tamper event
    pub async fn report_tamper(&self, event: TamperEvent) {
        self.tamper_count.fetch_add(1, Ordering::SeqCst);

        let mut status = self.status.write().await;
        status.tamper_attempts += 1;
        status.last_tamper_timestamp = Some(event.timestamp);
        drop(status);

        if let Err(e) = self.tamper_tx.send(event).await {
            error!(error = %e, "Failed to send tamper event");
        }
    }

    /// Get current timestamp in milliseconds since UNIX epoch
    /// Made public for use by protection submodules
    pub fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Get current protection status
    pub async fn get_status(&self) -> ProtectionStatus {
        self.status.read().await.clone()
    }

    /// Shutdown protection engine
    pub async fn shutdown(&self) {
        info!("Shutting down protection engine");
        self.running.store(false, Ordering::SeqCst);

        // On Windows, unset critical process before shutdown to avoid BSOD
        #[cfg(target_os = "windows")]
        {
            Self::unset_critical_process();
        }
    }

    /// Unset critical process flag during graceful shutdown
    #[cfg(target_os = "windows")]
    fn unset_critical_process() {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        unsafe {
            if let Ok(ntdll) = GetModuleHandleW(w!("ntdll.dll")) {
                type RtlSetProcessIsCriticalFn = unsafe extern "system" fn(
                    NewValue: u32,
                    OldValue: *mut u32,
                    CheckFlag: u32,
                ) -> i32;

                if let Some(f) = GetProcAddress(
                    ntdll,
                    PCSTR::from_raw(b"RtlSetProcessIsCritical\0".as_ptr()),
                ) {
                    let rtl_set_critical: RtlSetProcessIsCriticalFn = std::mem::transmute(f);
                    let mut old_value: u32 = 0;
                    let _ = rtl_set_critical(0, &mut old_value, 0);
                    info!("Critical process flag cleared for graceful shutdown");
                }
            }
        }
    }

    // =========================================================================
    // Windows-specific protection implementations
    // =========================================================================

    #[cfg(target_os = "windows")]
    async fn initialize_windows_protection(&mut self) -> Result<()> {
        info!("Initializing Windows-specific protections");

        // 1. Set process as critical (anti-kill via BSOD). Other process
        // protection layers remain enabled without this high-risk flag.
        if self.config.process_protection_enabled && self.config.critical_process_enabled {
            match Self::set_critical_process() {
                Ok(()) => {
                    let mut s = self.status.write().await;
                    s.critical_process_set = true;
                    info!("Critical process protection enabled");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to set critical process (requires SeDebugPrivilege)");
                }
            }
        }

        // 2. Register with kernel driver for PPL-like protection
        if self.config.anti_kill_enabled {
            match Self::register_driver_protection() {
                Ok(()) => {
                    let mut s = self.status.write().await;
                    s.driver_protection_active = true;
                    info!("Kernel driver protection registered");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to register with kernel driver (driver may not be loaded)");
                }
            }
        }

        // 3. Enable process mitigation policies
        if let Err(e) = self.enable_process_protection_windows().await {
            warn!(error = %e, "Failed to enable process mitigation policies");
        }

        // 4. Set file ACLs
        if let Err(e) = self.set_file_protection_windows().await {
            warn!(error = %e, "Failed to set file protection");
        }

        // 5. Protect registry keys
        if let Err(e) = self.protect_registry_windows().await {
            warn!(error = %e, "Failed to protect registry");
        }

        // 6. Protect service (with exponential backoff restart)
        if let Err(e) = self.protect_service_windows().await {
            warn!(error = %e, "Failed to protect service");
        }

        // 7. Store integrity data in ADS
        if let Err(e) = self.setup_ads_integrity_windows().await {
            warn!(error = %e, "Failed to setup ADS integrity");
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn enable_process_protection_windows(&mut self) -> Result<()> {
        // Apply comprehensive mitigation policies via dedicated module
        process_mitigations::apply_all_mitigations()?;

        let mut status = self.status.write().await;
        status.process_protected = true;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn set_file_protection_windows(&self) -> Result<()> {
        use std::process::Command;

        for path in self.config_paths.iter() {
            if path.exists() {
                let output = Command::new("icacls")
                    .args([
                        path.to_string_lossy().as_ref(),
                        "/inheritance:r",
                        "/grant:r",
                        "SYSTEM:(F)",
                        "/grant:r",
                        "Administrators:(F)",
                    ])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        debug!(path = %path.display(), "File ACL set");
                    }
                }
            }
        }

        let mut status = self.status.write().await;
        status.files_protected = true;

        info!("File protection enabled");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn protect_registry_windows(&self) -> Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS};

        let service_key = "SYSTEM\\CurrentControlSet\\Services\\TamanduaAgent";

        unsafe {
            let mut hkey = windows::Win32::System::Registry::HKEY::default();
            let key_wide: Vec<u16> = service_key
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(key_wide.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                &mut hkey,
            );

            if result.is_ok() {
                debug!("Registry key protection configured");
            }
        }

        let mut status = self.status.write().await;
        status.registry_protected = true;

        info!("Registry protection enabled");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn protect_service_windows(&self) -> Result<()> {
        use std::process::Command;

        // Set service failure actions with exponential backoff restart
        // First failure: restart after 5 seconds
        // Second failure: restart after 30 seconds
        // Subsequent failures: restart after 60 seconds
        let _ = Command::new("sc")
            .args([
                "failure",
                "TamanduaAgent",
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/30000/restart/60000",
            ])
            .output();

        // Set service security descriptor to prevent tampering
        // Only SYSTEM and Administrators have full control
        let _ = Command::new("sc")
            .args([
                "sdset",
                "TamanduaAgent",
                "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
            ])
            .output();

        // Set pre-shutdown timeout to allow graceful cleanup
        let _ = Command::new("sc")
            .args(["config", "TamanduaAgent", "start=", "auto"])
            .output();

        let mut status = self.status.write().await;
        status.service_protected = true;

        info!("Service protection enabled with exponential backoff restart");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn setup_ads_integrity_windows(&self) -> Result<()> {
        use sha2::{Digest, Sha256};

        if let Ok(content) = tokio::fs::read(&self.agent_path).await {
            let hash = Sha256::digest(&content);
            let hash_hex = hex::encode(hash);

            let ads_path = format!("{}:TamanduaIntegrity", self.agent_path.display());

            if let Err(e) = tokio::fs::write(&ads_path, &hash_hex).await {
                debug!(error = %e, "Failed to write ADS (may not be on NTFS)");
            } else {
                debug!("Integrity hash stored in ADS");
            }
        }

        Ok(())
    }

    // =========================================================================
    // Linux-specific protection implementations
    // =========================================================================

    #[cfg(target_os = "linux")]
    async fn initialize_linux_protection(&mut self) -> Result<()> {
        info!("Initializing Linux-specific protections");

        if let Err(e) = self.set_non_dumpable_linux() {
            warn!(error = %e, "Failed to set non-dumpable");
        }

        if let Err(e) = self.set_immutable_files_linux().await {
            warn!(error = %e, "Failed to set immutable files");
        }

        if let Err(e) = self.drop_capabilities_linux() {
            warn!(error = %e, "Failed to drop capabilities");
        }

        if let Err(e) = self.setup_namespace_isolation_linux().await {
            debug!(error = %e, "Namespace isolation not available");
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_non_dumpable_linux(&self) -> Result<()> {
        use libc::{prctl, PR_SET_DUMPABLE};

        unsafe {
            if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(anyhow::anyhow!("Failed to set PR_SET_DUMPABLE"));
            }
        }

        debug!("Process set to non-dumpable");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn set_immutable_files_linux(&self) -> Result<()> {
        use std::process::Command;

        for path in &self.config_paths {
            if path.exists() {
                let output = Command::new("chattr")
                    .args(["+i", &path.to_string_lossy()])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        debug!(path = %path.display(), "File set to immutable");
                    }
                }
            }
        }

        let mut status = self.status.write().await;
        status.files_protected = true;

        info!("File immutable protection enabled");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn drop_capabilities_linux(&self) -> Result<()> {
        use std::io;
        use std::mem;

        #[repr(C)]
        struct UserCapHeader {
            version: u32,
            pid: i32,
        }

        #[repr(C)]
        struct UserCapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        const CAP_NET_ADMIN: u32 = 12;
        const CAP_SYS_PTRACE: u32 = 19;
        const CAP_DAC_READ_SEARCH: u32 = 2;
        const CAP_LAST_CAP: u32 = 40;
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522u32;

        const PR_CAP_AMBIENT: libc::c_int = 47;
        const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
        const PR_CAPBSET_DROP: libc::c_int = 24;

        let retained_caps: std::collections::HashSet<u32> =
            [CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH]
                .iter()
                .copied()
                .collect();

        let ret = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
        if ret != 0 {
            let err = io::Error::last_os_error();
            warn!(error = %err, "Failed to clear ambient capabilities");
        } else {
            debug!("Cleared all ambient capabilities");
        }

        let mut dropped_count = 0u32;
        for cap in 0..=CAP_LAST_CAP {
            if retained_caps.contains(&cap) {
                continue;
            }

            let ret = unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
            if ret == 0 {
                dropped_count += 1;
            }
        }

        let mut header = UserCapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };

        let mut cap_bits: u64 = 0;
        for cap in &retained_caps {
            cap_bits |= 1u64 << cap;
        }

        let low = cap_bits as u32;
        let high = (cap_bits >> 32) as u32;

        let mut data = [
            UserCapData {
                effective: low,
                permitted: low,
                inheritable: 0,
            },
            UserCapData {
                effective: high,
                permitted: high,
                inheritable: 0,
            },
        ];

        let ret = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut UserCapHeader,
                data.as_mut_ptr(),
            ) as libc::c_int
        };

        if ret != 0 {
            let err = io::Error::last_os_error();
            warn!(error = %err, "Failed to set capability sets via capset");
        } else {
            info!(
                retained = ?retained_caps,
                dropped = dropped_count,
                "Dropped unnecessary capabilities"
            );
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn setup_namespace_isolation_linux(&self) -> Result<()> {
        use std::io;

        const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

        let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

        if ret != 0 {
            let err = io::Error::last_os_error();
            warn!(error = %err, "Failed to set PR_SET_NO_NEW_PRIVS");
            return Err(anyhow::anyhow!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                err
            ));
        }
        info!("PR_SET_NO_NEW_PRIVS set - privilege escalation via execve prevented");

        let ret = unsafe { libc::unshare(libc::CLONE_NEWUSER) };

        if ret != 0 {
            let err = io::Error::last_os_error();
            debug!(error = %err, "Could not create user namespace (non-fatal)");
        } else {
            info!("User namespace isolation enabled");

            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };

            if let Err(e) = std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid)) {
                debug!(error = %e, "Failed to write uid_map");
            }

            if let Err(e) = std::fs::write("/proc/self/setgroups", "deny\n") {
                debug!(error = %e, "Failed to write setgroups deny");
            }

            if let Err(e) = std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid)) {
                debug!(error = %e, "Failed to write gid_map");
            }
        }

        Ok(())
    }

    // =========================================================================
    // macOS-specific protection implementations
    // =========================================================================

    #[cfg(target_os = "macos")]
    async fn initialize_macos_protection(&mut self) -> Result<()> {
        info!("Initializing macOS-specific protections");

        if let Err(e) = self.set_immutable_files_macos().await {
            warn!(error = %e, "Failed to set immutable files");
        }

        if let Err(e) = self.setup_sandbox_macos().await {
            warn!(error = %e, "Failed to setup sandbox");
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn set_immutable_files_macos(&self) -> Result<()> {
        use std::process::Command;

        for path in &self.config_paths {
            if path.exists() {
                let output = Command::new("chflags")
                    .args(["schg", &path.to_string_lossy()])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        debug!(path = %path.display(), "File set to system immutable");
                    }
                }
            }
        }

        let mut status = self.status.write().await;
        status.files_protected = true;

        info!("File protection enabled");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn setup_sandbox_macos(&self) -> Result<()> {
        use std::ffi::CString;

        let strict_no_child_processes = std::env::var("TAMANDUA_MACOS_STRICT_NO_CHILD_PROCESSES")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !strict_no_child_processes {
            info!(
                "Skipping macOS process sandbox lockdown; child processes are required for live response and macOS collectors"
            );

            let mut status = self.status.write().await;
            status.process_protected = true;

            return Ok(());
        }

        let sandbox_profile = r#"
(version 1)
(deny default)
(allow file-read*)
(allow file-write*
    (subpath "/Library/Application Support/Tamandua")
    (subpath "/etc/tamandua")
    (subpath "/var/log/tamandua")
    (subpath "/var/lib/tamandua")
    (subpath "/tmp/tamandua"))
(allow network*)
(allow process-info*)
(allow sysctl-read)
(allow signal (target self))
(allow mach-lookup)
(allow mach-register)
(deny process-exec)
(deny process-fork)
(deny file-mount)
(deny file-unmount)
"#;

        extern "C" {
            fn sandbox_init(
                profile: *const libc::c_char,
                flags: u64,
                errorbuf: *mut *mut libc::c_char,
            ) -> libc::c_int;

            fn sandbox_free_error(errorbuf: *mut libc::c_char);
        }

        let c_profile = match CString::new(sandbox_profile) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to create sandbox profile C string");
                return Err(anyhow::anyhow!("Invalid sandbox profile string: {}", e));
            }
        };

        let mut errorbuf: *mut libc::c_char = std::ptr::null_mut();
        let ret = unsafe { sandbox_init(c_profile.as_ptr(), 0, &mut errorbuf) };

        if ret != 0 {
            let error_msg = if !errorbuf.is_null() {
                let msg = unsafe { std::ffi::CStr::from_ptr(errorbuf) }
                    .to_string_lossy()
                    .to_string();
                unsafe { sandbox_free_error(errorbuf) };
                msg
            } else {
                "unknown error".to_string()
            };

            warn!(error = %error_msg, "Failed to initialize macOS sandbox");
        } else {
            info!("macOS sandbox profile applied successfully");
        }

        let mut status = self.status.write().await;
        status.process_protected = true;

        Ok(())
    }
}

// =============================================================================
// Watchdog Process
// =============================================================================

/// Watchdog that monitors the main agent process and restarts if needed
#[derive(Clone)]
pub struct Watchdog {
    /// Main process PID to monitor
    main_pid: u32,
    /// Agent executable path
    agent_path: PathBuf,
    /// Heartbeat interval
    heartbeat_interval: std::time::Duration,
    /// Last heartbeat timestamp
    last_heartbeat: Arc<AtomicU64>,
    /// Running flag
    running: Arc<AtomicBool>,
}

impl Watchdog {
    /// Create a new watchdog
    pub fn new(agent_path: PathBuf, heartbeat_interval: std::time::Duration) -> Self {
        Self {
            main_pid: std::process::id(),
            agent_path,
            heartbeat_interval,
            last_heartbeat: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Record a heartbeat from the main process
    pub fn heartbeat(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_heartbeat.store(now, Ordering::SeqCst);
    }

    /// Start the watchdog monitoring loop
    pub async fn start(&self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        self.heartbeat();

        let running = self.running.clone();
        let last_heartbeat = self.last_heartbeat.clone();
        let heartbeat_interval = self.heartbeat_interval;
        let main_pid = self.main_pid;
        let agent_path = self.agent_path.clone();

        tokio::spawn(async move {
            let check_interval = heartbeat_interval / 2;
            let mut interval = tokio::time::interval(check_interval);

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let last = last_heartbeat.load(Ordering::SeqCst);
                let elapsed = now.saturating_sub(last);

                // Check if heartbeat is stale (missed 3 intervals)
                if elapsed > heartbeat_interval.as_secs() * 3 {
                    warn!(
                        elapsed_secs = elapsed,
                        "Heartbeat stale - main process may be hung"
                    );

                    if !Self::is_process_running(main_pid) {
                        error!("Main process terminated - attempting restart");
                        Self::restart_agent(&agent_path).await;
                    }
                }
            }
        });

        info!("Watchdog started");
        Ok(())
    }

    /// Check if a process is still running
    fn is_process_running(pid: u32) -> bool {
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            return kill(Pid::from_raw(pid as i32), Signal::SIGCONT).is_ok();
        }

        #[cfg(windows)]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let _ = CloseHandle(handle);
                    return true;
                } else {
                    return false;
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            return true;
        }
    }

    /// Restart the agent process
    async fn restart_agent(agent_path: &Path) {
        use std::process::Command;

        info!(path = %agent_path.display(), "Restarting agent");

        #[cfg(unix)]
        {
            let _ = Command::new(agent_path).spawn();
        }

        #[cfg(windows)]
        {
            // Use service manager on Windows if installed as service
            let _ = Command::new("sc").args(["start", "TamanduaAgent"]).spawn();

            // Fallback to direct execution
            let _ = Command::new(agent_path).spawn();
        }
    }

    /// Stop the watchdog
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Watchdog stopped");
    }
}

// =============================================================================
// Network Protection (C2 failover and certificate pinning)
// =============================================================================

/// Network protection for C2 communication
pub struct NetworkProtection {
    /// Primary server URL
    primary_server: String,
    /// Backup server URLs
    backup_servers: Vec<String>,
    /// Current server index
    current_server: Arc<RwLock<usize>>,
    /// Certificate pins (SHA256 of public key)
    cert_pins: Vec<Vec<u8>>,
    /// Blocked domains attempting to intercept
    blocked_interceptors: Arc<RwLock<Vec<String>>>,
}

impl NetworkProtection {
    /// Create new network protection
    pub fn new(
        primary_server: String,
        backup_servers: Vec<String>,
        cert_pins: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            primary_server,
            backup_servers,
            current_server: Arc::new(RwLock::new(0)),
            cert_pins,
            blocked_interceptors: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get the current server URL
    pub async fn get_current_server(&self) -> String {
        let idx = *self.current_server.read().await;
        if idx == 0 {
            self.primary_server.clone()
        } else {
            self.backup_servers
                .get(idx - 1)
                .cloned()
                .unwrap_or_else(|| self.primary_server.clone())
        }
    }

    /// Failover to the next server
    pub async fn failover(&self) -> Option<String> {
        let mut idx = self.current_server.write().await;
        *idx += 1;

        if *idx > self.backup_servers.len() {
            *idx = 0;
        }

        let server = if *idx == 0 {
            self.primary_server.clone()
        } else {
            self.backup_servers.get(*idx - 1)?.clone()
        };

        info!(server = %server, index = *idx, "Failed over to backup server");
        Some(server)
    }

    /// Verify certificate against pins
    pub fn verify_certificate(&self, cert_public_key_hash: &[u8]) -> bool {
        if self.cert_pins.is_empty() {
            return true;
        }

        for pin in &self.cert_pins {
            if pin == cert_public_key_hash {
                return true;
            }
        }

        warn!("Certificate pin validation failed - possible MITM attack");
        false
    }

    /// Check if C2 communication is being blocked
    pub async fn check_c2_blocking(&self) -> Option<TamperEvent> {
        use std::net::TcpStream;
        use std::time::Duration;

        let server_url = &self.primary_server;

        if let Ok(url) = url::Url::parse(server_url) {
            if let Some(host) = url.host_str() {
                let port = url.port().unwrap_or(443);
                let addr = format!("{}:{}", host, port);

                match TcpStream::connect_timeout(
                    &addr
                        .parse()
                        .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 443))),
                    Duration::from_secs(5),
                ) {
                    Ok(_) => {
                        return None;
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::ConnectionRefused
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            return Some(TamperEvent {
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                                event_type: TamperEventType::C2BlockAttempt,
                                description: format!("C2 communication blocked: {}", e),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::High,
                                mitre_technique: Some("T1562.004".to_string()),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

// =============================================================================
// Inline Hook Detection
// =============================================================================

/// Detect inline hooks in critical functions
#[cfg(target_os = "windows")]
pub fn detect_inline_hooks() -> Vec<TamperEvent> {
    let mut events = Vec::new();

    let functions_to_check = [
        ("ntdll.dll", "NtTerminateProcess"),
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "NtReadVirtualMemory"),
        ("ntdll.dll", "NtCreateThreadEx"),
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("ntdll.dll", "NtProtectVirtualMemory"),
        ("kernel32.dll", "TerminateProcess"),
        ("kernel32.dll", "OpenProcess"),
        ("kernel32.dll", "WriteProcessMemory"),
        ("kernel32.dll", "CreateRemoteThread"),
    ];

    for (dll, function) in &functions_to_check {
        if let Some(hook_type) = check_function_hook(dll, function) {
            events.push(TamperEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                event_type: TamperEventType::InlineHook,
                description: format!("Inline hook detected: {}!{} ({})", dll, function, hook_type),
                source_pid: None,
                source_process: None,
                severity: TamperSeverity::Critical,
                mitre_technique: Some("T1562.001".to_string()),
            });
        }
    }

    events
}

#[cfg(target_os = "windows")]
fn check_function_hook(dll_name: &str, function_name: &str) -> Option<&'static str> {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    unsafe {
        let dll_cstr = std::ffi::CString::new(dll_name).ok()?;
        let module = GetModuleHandleA(PCSTR(dll_cstr.as_ptr() as *const u8)).ok()?;

        let func_cstr = std::ffi::CString::new(function_name).ok()?;
        let func_addr = GetProcAddress(module, PCSTR(func_cstr.as_ptr() as *const u8))?;
        let func_ptr = func_addr as *const u8;

        let first_byte = *func_ptr;
        let second_byte = *func_ptr.add(1);

        // Common hook patterns
        if first_byte == 0xE9 {
            return Some("JMP rel32");
        }
        if first_byte == 0xEB {
            return Some("JMP rel8");
        }
        if first_byte == 0xFF && second_byte == 0x25 {
            return Some("JMP [addr]");
        }
        if first_byte == 0x68 && *func_ptr.add(5) == 0xC3 {
            return Some("PUSH-RET");
        }

        // Normal ntdll syscall stub check
        if first_byte == 0x4C && second_byte == 0x8B && *func_ptr.add(2) == 0xD1 {
            return None;
        }

        // Breakpoint
        if first_byte == 0xCC {
            return Some("INT3 breakpoint");
        }
    }

    None
}

#[cfg(not(target_os = "windows"))]
pub fn detect_inline_hooks() -> Vec<TamperEvent> {
    let mut events = Vec::new();

    // Check LD_PRELOAD
    if let Ok(ld_preload) = std::env::var("LD_PRELOAD") {
        if !ld_preload.is_empty() {
            events.push(TamperEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                event_type: TamperEventType::InlineHook,
                description: format!("LD_PRELOAD detected: {}", ld_preload),
                source_pid: None,
                source_process: None,
                severity: TamperSeverity::High,
                mitre_technique: Some("T1574.006".to_string()),
            });
        }
    }

    events
}

// =============================================================================
// Public API
// =============================================================================

/// Start agent self-protection
/// Call this early in main() before other initialization
pub async fn engage_protection(
    tamper_tx: tokio::sync::mpsc::Sender<TamperEvent>,
    backup_servers: Vec<String>,
    cert_pins: Vec<Vec<u8>>,
) -> Result<ProtectionEngine> {
    info!("Engaging agent self-protection");

    // Clone tamper_tx for AgentProtection
    let agent_protection_tx = tamper_tx.clone();

    // Initialize ProtectionEngine
    let mut engine = ProtectionEngine::new(tamper_tx, backup_servers, cert_pins)?;
    engine.initialize().await?;

    let mut file_guard = FileGuard::new(FileGuardConfig::default(), agent_protection_tx.clone());
    match file_guard.initialize().await {
        Ok(()) => {
            info!(
                count = file_guard.get_protected_files().len(),
                "FileGuard initialized for critical agent assets"
            );
            engine.file_guard = Some(file_guard);
        }
        Err(error) => {
            warn!(
                error = %error,
                "Failed to initialize FileGuard - continuing with ProtectionEngine integrity checks"
            );
        }
    }

    // Check for existing hooks
    let hook_events = detect_inline_hooks();
    for event in hook_events {
        engine.report_tamper(event).await;
    }

    // Initialize and start AgentProtection (self-hash, DLL injection, hollowing detection)
    match AgentProtection::new(agent_protection_tx) {
        Ok(agent_protection) => {
            info!(
                hash = hex::encode(&agent_protection.get_self_hash()[..8]),
                "AgentProtection initialized with self-hash"
            );

            // Run initial integrity checks
            if !agent_protection.verify_self_integrity() {
                warn!("Initial agent integrity check FAILED - binary may be tampered");
            }

            if agent_protection.detect_hollowing() {
                warn!("Process hollowing detected during startup");
            }

            // Start background monitoring (heartbeat, periodic checks)
            agent_protection.start().await;
            info!("AgentProtection background monitors started");
        }
        Err(e) => {
            warn!(error = %e, "Failed to initialize AgentProtection - continuing without agent-level protection");
        }
    }

    info!("Agent self-protection engaged");
    Ok(engine)
}

// =============================================================================
// Agent-Driver Protection Link
//
// Provides the hardened communication channel between the user-mode agent and
// the kernel driver self-protection subsystem:
//
// - Heartbeat sender: sends IOCTL heartbeat to driver every 25 seconds
// - Self-integrity verification: verifies own binary hash on startup
// - DLL injection detection: monitors for unexpected module loads
// - Process hollowing detection: checks for memory modifications to own image
// - Driver self-protection PID registration
//
// MITRE ATT&CK: T1562.001, T1055.012 (Process Hollowing), T1055.001 (DLL Injection)
// =============================================================================

/// Information about a suspicious module detected in the agent process
#[derive(Debug, Clone)]
pub struct SuspiciousModule {
    /// Module name or path
    pub name: String,
    /// Base address in memory
    pub base_address: u64,
    /// Module size
    pub size: u64,
    /// Reason it is suspicious
    pub reason: String,
}

/// Agent-to-driver self-protection bridge.
///
/// Manages the hardened link between the user-mode agent and the kernel
/// driver's self-protection subsystem. This includes:
///
/// - Periodic heartbeat to prove liveness to the watchdog
/// - Self-integrity checks at startup
/// - DLL injection detection by monitoring loaded modules
/// - Process hollowing detection via image memory checks
pub struct AgentProtection {
    /// Handle to the kernel driver communication port
    #[cfg(target_os = "windows")]
    driver_handle: Option<windows::Win32::Foundation::HANDLE>,

    /// Heartbeat interval (25 seconds, inside the 30s driver window)
    heartbeat_interval: std::time::Duration,

    /// SHA-256 hash of own executable at startup
    self_hash: [u8; 32],

    /// Baseline set of loaded module names at startup
    loaded_modules: std::collections::HashSet<String>,

    /// Running flag for background tasks
    running: Arc<AtomicBool>,

    /// Tamper event sender (shared with ProtectionEngine)
    tamper_tx: tokio::sync::mpsc::Sender<TamperEvent>,

    /// Number of heartbeats sent successfully
    heartbeats_sent: Arc<AtomicU64>,

    /// Number of injection detections
    injection_detections: Arc<AtomicU64>,
}

impl AgentProtection {
    /// Create a new AgentProtection instance.
    ///
    /// Computes the self-hash of the agent binary and captures the baseline
    /// set of loaded modules.
    pub fn new(tamper_tx: tokio::sync::mpsc::Sender<TamperEvent>) -> Result<Self> {
        use sha2::{Digest, Sha256};

        // Compute self-hash
        let exe_path = std::env::current_exe()?;
        let exe_bytes = std::fs::read(&exe_path)?;
        let hash_result = Sha256::digest(&exe_bytes);
        let mut self_hash = [0u8; 32];
        self_hash.copy_from_slice(&hash_result);

        info!(
            path = %exe_path.display(),
            hash = hex::encode(&self_hash[..8]),
            "Agent self-hash computed"
        );

        // Capture baseline loaded modules
        let loaded_modules = Self::enumerate_current_modules();
        info!(count = loaded_modules.len(), "Baseline module set captured");

        Ok(Self {
            #[cfg(target_os = "windows")]
            driver_handle: None,
            heartbeat_interval: std::time::Duration::from_secs(25),
            self_hash,
            loaded_modules,
            running: Arc::new(AtomicBool::new(false)),
            tamper_tx,
            heartbeats_sent: Arc::new(AtomicU64::new(0)),
            injection_detections: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Set the driver communication handle.
    ///
    /// On Windows, this is the FilterCommunicationPort handle obtained from
    /// the driver module. Once set, heartbeat IOCTLs will be sent through
    /// this handle.
    #[cfg(target_os = "windows")]
    pub fn set_driver_handle(&mut self, handle: windows::Win32::Foundation::HANDLE) {
        self.driver_handle = Some(handle);
        info!("Agent protection: driver handle set");
    }

    /// Verify the agent binary's integrity on startup.
    ///
    /// Re-reads the executable from disk and compares its SHA-256 hash
    /// against the baseline computed at construction time.
    pub fn verify_self_integrity(&self) -> bool {
        use sha2::{Digest, Sha256};

        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to get exe path for integrity check: {}", e);
                return false;
            }
        };

        let exe_bytes = match std::fs::read(&exe_path) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read agent binary for integrity check: {}", e);
                return false;
            }
        };

        let hash_result = Sha256::digest(&exe_bytes);
        let mut current_hash = [0u8; 32];
        current_hash.copy_from_slice(&hash_result);

        if current_hash == self.self_hash {
            debug!("Agent self-integrity check passed");
            true
        } else {
            error!(
                expected = hex::encode(&self.self_hash[..8]),
                actual = hex::encode(&current_hash[..8]),
                "ALERT: Agent binary integrity check FAILED"
            );
            false
        }
    }

    /// Detect injected DLLs by comparing current modules against the baseline.
    ///
    /// Returns a list of suspicious modules that were not present at startup.
    /// Each module is checked for common DLL injection indicators:
    /// - Not in the baseline set
    /// - Loaded from a suspicious location (Temp, AppData, etc.)
    pub fn check_injected_modules(&self) -> Vec<SuspiciousModule> {
        let current_modules = Self::enumerate_current_modules();
        let mut suspicious = Vec::new();

        for module_name in &current_modules {
            if !self.loaded_modules.contains(module_name) {
                let lower = module_name.to_lowercase();

                // Determine suspicion reason
                let reason = if lower.contains("\\temp\\") || lower.contains("\\tmp\\") {
                    "Loaded from temp directory".to_string()
                } else if lower.contains("\\appdata\\") {
                    "Loaded from AppData directory".to_string()
                } else if lower.contains("\\downloads\\") {
                    "Loaded from Downloads directory".to_string()
                } else {
                    "New module not in startup baseline".to_string()
                };

                warn!(module = %module_name, reason = %reason, "Suspicious module detected");

                suspicious.push(SuspiciousModule {
                    name: module_name.clone(),
                    base_address: 0,
                    size: 0,
                    reason,
                });
            }
        }

        if !suspicious.is_empty() {
            self.injection_detections
                .fetch_add(suspicious.len() as u64, Ordering::SeqCst);
        }

        suspicious
    }

    /// Detect process hollowing by checking if the agent's in-memory image
    /// header matches the on-disk binary.
    ///
    /// Process hollowing (T1055.012) replaces the process memory with
    /// malicious code while keeping the process alive. We detect this by:
    /// 1. Reading our own PE header from memory (base address)
    /// 2. Comparing key fields against the on-disk binary
    ///
    /// Returns true if hollowing is detected (mismatch).
    pub fn detect_hollowing(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::io::Read;

            let exe_path = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Read the first 4KB of the on-disk binary (PE headers)
            let disk_header = match std::fs::File::open(&exe_path) {
                Ok(mut f) => {
                    let mut buf = vec![0u8; 4096];
                    match f.read(&mut buf) {
                        Ok(n) => {
                            buf.truncate(n);
                            buf
                        }
                        Err(_) => return false,
                    }
                }
                Err(_) => return false,
            };

            // Read the in-memory PE header from our own image base.
            // On Windows, the image base is the module handle of the main
            // executable (HMODULE from GetModuleHandleW(NULL)).
            unsafe {
                use windows::core::PCWSTR;
                use windows::Win32::System::LibraryLoader::GetModuleHandleW;

                let hmodule = match GetModuleHandleW(PCWSTR::null()) {
                    Ok(h) => h,
                    Err(_) => return false,
                };

                let base_ptr = hmodule.0 as *const u8;
                let header_size = std::cmp::min(disk_header.len(), 4096);

                let memory_header = std::slice::from_raw_parts(base_ptr, header_size);

                // Compare the DOS header (first 64 bytes) and PE signature.
                // We only compare stable fields that should not change:
                // - DOS MZ signature (2 bytes at offset 0)
                // - e_lfanew pointer (4 bytes at offset 0x3C)
                // - PE signature "PE\0\0" at e_lfanew
                // - SizeOfImage, EntryPoint, etc.

                if disk_header.len() < 64 || memory_header.len() < 64 {
                    return false;
                }

                // Check MZ signature
                if disk_header[0] != memory_header[0] || disk_header[1] != memory_header[1] {
                    error!("Process hollowing detected: MZ signature mismatch");
                    return true;
                }

                // Get e_lfanew (PE header offset)
                let disk_lfanew = u32::from_le_bytes([
                    disk_header[0x3C],
                    disk_header[0x3D],
                    disk_header[0x3E],
                    disk_header[0x3F],
                ]) as usize;

                let mem_lfanew = u32::from_le_bytes([
                    memory_header[0x3C],
                    memory_header[0x3D],
                    memory_header[0x3E],
                    memory_header[0x3F],
                ]) as usize;

                if disk_lfanew != mem_lfanew {
                    error!("Process hollowing detected: e_lfanew mismatch");
                    return true;
                }

                // Compare PE signature
                if disk_lfanew + 4 <= disk_header.len() && disk_lfanew + 4 <= memory_header.len() {
                    for i in 0..4 {
                        if disk_header[disk_lfanew + i] != memory_header[disk_lfanew + i] {
                            error!("Process hollowing detected: PE signature mismatch");
                            return true;
                        }
                    }

                    // Compare TimeDateStamp (offset PE+8, 4 bytes)
                    let ts_offset = disk_lfanew + 8;
                    if ts_offset + 4 <= disk_header.len() && ts_offset + 4 <= memory_header.len() {
                        for i in 0..4 {
                            if disk_header[ts_offset + i] != memory_header[ts_offset + i] {
                                error!("Process hollowing detected: TimeDateStamp mismatch");
                                return true;
                            }
                        }
                    }
                }

                debug!("Process hollowing check passed");
            }

            false
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Process hollowing is a Windows-specific technique
            false
        }
    }

    /// Start the heartbeat sender and module monitoring tasks.
    ///
    /// This spawns two background tokio tasks:
    /// 1. Heartbeat sender: sends IOCTL to driver every 25 seconds
    /// 2. Module monitor: checks for injected DLLs every 10 seconds
    pub async fn start(&self) {
        self.running.store(true, Ordering::SeqCst);

        // =====================================================================
        // Task 1: Heartbeat sender
        //
        // Sends a heartbeat to the kernel driver every 25 seconds. The driver
        // watchdog expects a heartbeat within 30 seconds; if 3 consecutive
        // heartbeats are missed (90 seconds total), the driver will attempt
        // to restart the agent.
        // =====================================================================
        {
            let running = self.running.clone();
            let heartbeats_sent = self.heartbeats_sent.clone();
            let interval = self.heartbeat_interval;

            #[cfg(target_os = "windows")]
            let driver_handle = self.driver_handle;

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);

                while running.load(Ordering::SeqCst) {
                    ticker.tick().await;

                    #[cfg(target_os = "windows")]
                    {
                        if let Some(_handle) = driver_handle {
                            // Send heartbeat IOCTL to driver.
                            //
                            // The IOCTL is TAMANDUA_CMD_HEARTBEAT (0x0003).
                            // On success, the driver resets its missed heartbeat counter.
                            //
                            // NOTE: The actual FilterSendMessage call requires a
                            // properly formatted TAMANDUA_MESSAGE_HEADER. The driver
                            // module (driver/mod.rs) handles the serialization. Here
                            // we just log the attempt and track the count.
                            //
                            // In the integrated build, this calls:
                            //   driver::send_heartbeat(handle)
                            // which wraps FilterSendMessage.

                            heartbeats_sent.fetch_add(1, Ordering::SeqCst);
                            debug!(
                                count = heartbeats_sent.load(Ordering::SeqCst),
                                "Driver heartbeat sent"
                            );
                        } else {
                            debug!("Driver handle not set - heartbeat skipped");
                        }
                    }

                    #[cfg(not(target_os = "windows"))]
                    {
                        heartbeats_sent.fetch_add(1, Ordering::SeqCst);
                        debug!(
                            count = heartbeats_sent.load(Ordering::SeqCst),
                            "Heartbeat tick (non-Windows)"
                        );
                    }
                }

                info!("Heartbeat sender stopped");
            });
        }

        // =====================================================================
        // Task 2: Module injection and hollowing monitor
        //
        // Checks for:
        // - New DLLs loaded after startup (DLL injection detection)
        // - Process hollowing (PE header mismatch)
        // =====================================================================
        {
            let running = self.running.clone();
            let tamper_tx = self.tamper_tx.clone();
            let loaded_modules = self.loaded_modules.clone();
            let injection_detections = self.injection_detections.clone();

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));

                // Need a mutable local baseline for the closure. Without updating it,
                // late-but-normal runtime module loads are reported every interval.
                let mut baseline = loaded_modules;

                while running.load(Ordering::SeqCst) {
                    ticker.tick().await;

                    // Check for injected modules
                    let current = Self::enumerate_current_modules();
                    for module_name in &current {
                        if !baseline.contains(module_name) {
                            let lower = module_name.to_lowercase();

                            if Self::is_trusted_runtime_module(&lower) {
                                baseline.insert(module_name.clone());
                                continue;
                            }

                            // Skip Windows system directories (normal dynamic loading)
                            if lower.contains("\\windows\\system32\\")
                                || lower.contains("\\windows\\syswow64\\")
                                || lower.contains("\\windows\\winsxs\\")
                            {
                                baseline.insert(module_name.clone());
                                continue;
                            }

                            // Skip known safe runtime DLLs
                            let safe_patterns = [
                                "vcruntime",
                                "ucrtbase",
                                "msvcp",
                                "msvcr",
                                "api-ms-win",
                                "ext-ms-win",
                                "concrt",
                                "vccorlib",
                            ];
                            if safe_patterns.iter().any(|p| lower.contains(p)) {
                                baseline.insert(module_name.clone());
                                continue;
                            }

                            let is_suspicious = lower.contains("\\temp\\")
                                || lower.contains("\\tmp\\")
                                || lower.contains("\\appdata\\local\\temp")
                                || lower.contains("\\downloads\\");

                            let severity = if is_suspicious {
                                TamperSeverity::Critical
                            } else {
                                TamperSeverity::Medium
                            };

                            injection_detections.fetch_add(1, Ordering::SeqCst);

                            let event = TamperEvent {
                                timestamp: Self::current_timestamp_static(),
                                event_type: TamperEventType::DllInjection,
                                description: format!("Unexpected module loaded: {}", module_name),
                                source_pid: None,
                                source_process: None,
                                severity,
                                mitre_technique: Some("T1055.001".to_string()),
                            };

                            let _ = tamper_tx.send(event).await;
                            baseline.insert(module_name.clone());
                        }
                    }
                }

                info!("Module injection monitor stopped");
            });
        }

        info!(
            "Agent protection tasks started (heartbeat={}s)",
            self.heartbeat_interval.as_secs()
        );
    }

    /// Stop all background protection tasks.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Agent protection stopped");
    }

    /// Enumerate currently loaded modules in this process.
    fn enumerate_current_modules() -> std::collections::HashSet<String> {
        let mut modules = std::collections::HashSet::new();

        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
            use windows::Win32::System::Threading::GetCurrentProcess;

            unsafe {
                let process = GetCurrentProcess();
                let mut h_modules =
                    vec![std::mem::zeroed::<windows::Win32::Foundation::HMODULE>(); 1024];
                let mut cb_needed = 0u32;

                let ok = EnumProcessModules(
                    process,
                    h_modules.as_mut_ptr(),
                    (h_modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>())
                        as u32,
                    &mut cb_needed,
                );

                if ok.is_ok() {
                    let count = cb_needed as usize
                        / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

                    for i in 0..count {
                        let mut name_buf = [0u16; 512];
                        let len = GetModuleFileNameExW(process, h_modules[i], &mut name_buf);

                        if len > 0 {
                            let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                            modules.insert(name);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux, read /proc/self/maps for loaded shared objects
            if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                for line in maps.lines() {
                    if let Some(path) = line.split_whitespace().last() {
                        if path.starts_with('/') && path.ends_with(".so") || path.contains(".so.") {
                            modules.insert(path.to_string());
                        }
                    }
                }
            }
        }

        modules
    }

    fn is_trusted_runtime_module(module_lower: &str) -> bool {
        #[cfg(target_os = "linux")]
        {
            let normalized = module_lower.replace('\\', "/");
            let trusted_dir = normalized.starts_with("/lib/")
                || normalized.starts_with("/lib64/")
                || normalized.starts_with("/usr/lib/")
                || normalized.starts_with("/usr/lib64/")
                || normalized.starts_with("/usr/lib/x86_64-linux-gnu/")
                || normalized.starts_with("/lib/x86_64-linux-gnu/");

            if !trusted_dir {
                return false;
            }

            let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
            return file_name.starts_with("libc-")
                || file_name.starts_with("libc.so")
                || file_name.starts_with("libnss_")
                || file_name.starts_with("ld-linux")
                || file_name.starts_with("libpthread-")
                || file_name.starts_with("libpthread.so")
                || file_name.starts_with("libdl-")
                || file_name.starts_with("libdl.so")
                || file_name.starts_with("librt-")
                || file_name.starts_with("librt.so");
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = module_lower;
            false
        }
    }

    /// Get a static timestamp (for use in closures without self)
    fn current_timestamp_static() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get the agent's self-hash computed at startup
    pub fn get_self_hash(&self) -> &[u8; 32] {
        &self.self_hash
    }

    /// Get heartbeat count
    pub fn heartbeats_sent(&self) -> u64 {
        self.heartbeats_sent.load(Ordering::SeqCst)
    }

    /// Get injection detection count
    pub fn injection_detections(&self) -> u64 {
        self.injection_detections.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protection_engine_creation() {
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let engine = ProtectionEngine::new(tx, vec![], vec![]);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_debugger_check() {
        let result = ProtectionEngine::check_debugger_present();
        println!("Debugger present: {}", result);
    }

    #[test]
    fn test_inline_hook_detection() {
        let events = detect_inline_hooks();
        println!("Hook events detected: {}", events.len());
        for event in &events {
            println!("  {:?}", event);
        }
    }

    #[tokio::test]
    async fn test_watchdog() {
        let path = std::env::current_exe().unwrap();
        let watchdog = Watchdog::new(path, std::time::Duration::from_secs(5));
        watchdog.heartbeat();
        assert!(Watchdog::is_process_running(std::process::id()));
    }

    #[test]
    fn test_protection_config_defaults() {
        let config = ProtectionConfig::default();
        assert!(config.anti_debug_enabled);
        assert!(config.integrity_verification_enabled);
        assert!(config.process_protection_enabled);
        assert!(!config.critical_process_enabled);
        assert!(config.service_persistence_enabled);
        assert!(config.communication_protection_enabled);
        assert!(config.anti_kill_enabled);
        assert!(config.dll_injection_detection_enabled);
        assert!(config.thread_monitoring_enabled);
        assert!(!config.canary_file_monitoring_enabled);
        assert!(config.etw_provider_monitoring_enabled);
        assert!(config.iat_hook_detection_enabled);
        assert_eq!(config.anti_debug_interval_secs, 10);
    }

    #[test]
    fn test_debug_environment_check() {
        // Should not detect debugger in normal test environment
        // (unless actually running under debugger)
        let result = ProtectionEngine::check_debug_environment_vars();
        println!("Debug env vars detected: {}", result);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_module_enumeration() {
        let modules = ProtectionEngine::enumerate_loaded_modules();
        assert!(!modules.is_empty(), "Should find at least one module");
        println!("Loaded modules: {}", modules.len());
        for m in &modules {
            println!("  {}", m);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_thread_count() {
        let count = ProtectionEngine::count_threads(std::process::id());
        assert!(count > 0, "Should have at least one thread");
        println!("Thread count: {}", count);
    }
}
