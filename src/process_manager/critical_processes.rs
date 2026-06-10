//! Critical Process Database
//!
//! Maintains a hardcoded list of critical system processes across platforms:
//! - Windows: csrss.exe, lsass.exe, services.exe, svchost.exe, etc.
//! - Linux: init, systemd, kthreadd, kernel threads
//! - macOS: launchd, kernel_task, WindowServer
//!
//! Provides hash verification for known-good system processes and
//! criticality levels for access control.

use super::{ProcessManagerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Criticality level for processes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CriticalityLevel {
    /// System-critical: Killing would crash or destabilize the system
    /// Examples: csrss.exe, lsass.exe, init, launchd
    SystemCritical,

    /// Service-critical: Killing would disrupt important services
    /// Examples: svchost.exe, systemd services, daemons
    ServiceCritical,

    /// User-critical: Killing would disrupt user experience significantly
    /// Examples: explorer.exe, WindowServer, desktop environments
    UserCritical,

    /// Not critical - can be safely terminated
    NonCritical,
}

impl CriticalityLevel {
    /// Check if this level should block termination
    pub fn should_block_kill(&self) -> bool {
        matches!(self, Self::SystemCritical)
    }

    /// Check if this level should show a warning
    pub fn should_warn(&self) -> bool {
        matches!(self, Self::SystemCritical | Self::ServiceCritical)
    }
}

/// Information about a critical process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalProcessInfo {
    /// Process name (case-insensitive match)
    pub name: String,
    /// Criticality level
    pub level: CriticalityLevel,
    /// Reason for protection
    pub protection_reason: String,
    /// Known-good SHA256 hashes (for verification)
    pub known_hashes: Vec<String>,
    /// Expected paths (for verification)
    pub expected_paths: Vec<String>,
    /// Platform this applies to
    pub platform: ProcessPlatform,
}

/// Platform identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessPlatform {
    Windows,
    Linux,
    MacOS,
    All,
}

impl ProcessPlatform {
    fn matches_current(&self) -> bool {
        match self {
            Self::All => true,
            Self::Windows => cfg!(target_os = "windows"),
            Self::Linux => cfg!(target_os = "linux"),
            Self::MacOS => cfg!(target_os = "macos"),
        }
    }
}

/// Critical Process Database
pub struct CriticalProcessDb {
    /// Critical processes by name (lowercase)
    by_name: HashMap<String, CriticalProcessInfo>,
    /// Known-good hashes
    known_hashes: HashSet<String>,
    /// Cache of PID -> criticality lookups
    pid_cache: Arc<RwLock<HashMap<u32, Option<CriticalProcessInfo>>>>,
}

impl CriticalProcessDb {
    /// Create a new critical process database
    pub fn new() -> Self {
        let mut db = Self {
            by_name: HashMap::new(),
            known_hashes: HashSet::new(),
            pid_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize with hardcoded critical processes
        db.init_windows_critical();
        db.init_linux_critical();
        db.init_macos_critical();

        db
    }

    /// Initialize Windows critical processes
    fn init_windows_critical(&mut self) {
        let windows_critical = vec![
            // System Critical
            CriticalProcessInfo {
                name: "csrss.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason:
                    "Client/Server Runtime Subsystem - Required for Windows subsystem".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\csrss.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "lsass.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason:
                    "Local Security Authority - Handles authentication and security policies"
                        .to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\lsass.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "smss.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Session Manager Subsystem - Initializes user sessions"
                    .to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\smss.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "wininit.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Windows Initialization Process - Starts critical services"
                    .to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\wininit.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "services.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Service Control Manager - Manages Windows services".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\services.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "winlogon.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Windows Logon Process - Handles user logon/logoff".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\winlogon.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "System".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Windows kernel and system process".to_string(),
                known_hashes: vec![],
                expected_paths: vec![],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "ntoskrnl.exe".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Windows NT Kernel".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\ntoskrnl.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            // Service Critical
            CriticalProcessInfo {
                name: "svchost.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Service Host - Hosts Windows services".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\svchost.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "spoolsv.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Print Spooler Service".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\spoolsv.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "lsm.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Local Session Manager".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\lsm.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "dllhost.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "COM Surrogate - Hosts COM objects".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\dllhost.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "taskhost.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Task Host Process".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\taskhost.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "taskhostw.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Task Host Window".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\taskhostw.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "msdtc.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Distributed Transaction Coordinator".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\msdtc.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "dwm.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Desktop Window Manager - Handles visual effects".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\dwm.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            // User Critical
            CriticalProcessInfo {
                name: "explorer.exe".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "Windows Explorer - Desktop and file management shell"
                    .to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\explorer.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "sihost.exe".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "Shell Infrastructure Host".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\sihost.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "ctfmon.exe".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "CTF Loader - Text input and language bar".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Windows\\System32\\ctfmon.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            // Windows Defender / Security
            CriticalProcessInfo {
                name: "MsMpEng.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Windows Defender Antimalware Service".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["C:\\Program Files\\Windows Defender\\MsMpEng.exe".to_string()],
                platform: ProcessPlatform::Windows,
            },
            CriticalProcessInfo {
                name: "SecurityHealthService.exe".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Windows Security Health Service".to_string(),
                known_hashes: vec![],
                expected_paths: vec![],
                platform: ProcessPlatform::Windows,
            },
        ];

        for info in windows_critical {
            self.add_critical_process(info);
        }
    }

    /// Initialize Linux critical processes
    fn init_linux_critical(&mut self) {
        let linux_critical = vec![
            // System Critical
            CriticalProcessInfo {
                name: "init".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Init process - Parent of all processes (PID 1)".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/sbin/init".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "systemd".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Systemd - System and service manager (PID 1)".to_string(),
                known_hashes: vec![],
                expected_paths: vec![
                    "/lib/systemd/systemd".to_string(),
                    "/usr/lib/systemd/systemd".to_string(),
                ],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "kthreadd".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Kernel thread daemon (PID 2)".to_string(),
                known_hashes: vec![],
                expected_paths: vec![],
                platform: ProcessPlatform::Linux,
            },
            // Service Critical
            CriticalProcessInfo {
                name: "systemd-journald".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Systemd journal logging service".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/lib/systemd/systemd-journald".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "systemd-logind".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Systemd login manager".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/lib/systemd/systemd-logind".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "systemd-udevd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Systemd device manager".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/lib/systemd/systemd-udevd".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "dbus-daemon".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "D-Bus message bus daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/bin/dbus-daemon".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "sshd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "SSH daemon - Remote access".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/sshd".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "cron".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Cron scheduler daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/cron".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "rsyslogd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "System logging daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/rsyslogd".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "auditd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Linux Audit daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/sbin/auditd".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "polkitd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "PolicyKit authorization daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/lib/polkit-1/polkitd".to_string()],
                platform: ProcessPlatform::Linux,
            },
            // User Critical (Desktop)
            CriticalProcessInfo {
                name: "gdm".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "GNOME Display Manager".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/gdm".to_string(), "/usr/sbin/gdm3".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "lightdm".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "Light Display Manager".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/lightdm".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "Xorg".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "X.Org display server".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/lib/xorg/Xorg".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "gnome-shell".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "GNOME desktop shell".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/bin/gnome-shell".to_string()],
                platform: ProcessPlatform::Linux,
            },
            CriticalProcessInfo {
                name: "plasmashell".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "KDE Plasma desktop shell".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/bin/plasmashell".to_string()],
                platform: ProcessPlatform::Linux,
            },
        ];

        for info in linux_critical {
            self.add_critical_process(info);
        }
    }

    /// Initialize macOS critical processes
    fn init_macos_critical(&mut self) {
        let macos_critical = vec![
            // System Critical
            CriticalProcessInfo {
                name: "launchd".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Launch daemon - Parent of all processes (PID 1)".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/sbin/launchd".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "kernel_task".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "macOS kernel process".to_string(),
                known_hashes: vec![],
                expected_paths: vec![],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "loginwindow".to_string(),
                level: CriticalityLevel::SystemCritical,
                protection_reason: "Login window manager".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow".to_string()],
                platform: ProcessPlatform::MacOS,
            },

            // Service Critical
            CriticalProcessInfo {
                name: "mds".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Metadata Server - Spotlight indexing".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "mds_stores".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Metadata stores for Spotlight".to_string(),
                known_hashes: vec![],
                expected_paths: vec![],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "fseventsd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "File system events daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/FSEvents.framework/Versions/A/Support/fseventsd".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "coreaudiod".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Core Audio daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/coreaudiod".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "cfprefsd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Preferences daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/cfprefsd".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "configd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "System Configuration daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/libexec/configd".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "diskarbitrationd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Disk Arbitration daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/libexec/diskarbitrationd".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "notifyd".to_string(),
                level: CriticalityLevel::ServiceCritical,
                protection_reason: "Notification daemon".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/usr/sbin/notifyd".to_string()],
                platform: ProcessPlatform::MacOS,
            },

            // User Critical
            CriticalProcessInfo {
                name: "WindowServer".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "macOS window server - Manages display and GUI".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "Finder".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "macOS Finder - File management and desktop".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "Dock".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "macOS Dock".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock".to_string()],
                platform: ProcessPlatform::MacOS,
            },
            CriticalProcessInfo {
                name: "SystemUIServer".to_string(),
                level: CriticalityLevel::UserCritical,
                protection_reason: "System UI Server - Menu bar and system UI".to_string(),
                known_hashes: vec![],
                expected_paths: vec!["/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer".to_string()],
                platform: ProcessPlatform::MacOS,
            },
        ];

        for info in macos_critical {
            self.add_critical_process(info);
        }
    }

    /// Add a critical process to the database
    fn add_critical_process(&mut self, info: CriticalProcessInfo) {
        if info.platform.matches_current() {
            let name_lower = info.name.to_lowercase();

            // Add known hashes
            for hash in &info.known_hashes {
                self.known_hashes.insert(hash.to_lowercase());
            }

            self.by_name.insert(name_lower, info);
        }
    }

    /// Check if a process name is critical
    pub fn is_critical_by_name(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.by_name.contains_key(&name_lower)
    }

    /// Get criticality level for a process name
    pub fn get_level_by_name(&self, name: &str) -> CriticalityLevel {
        let name_lower = name.to_lowercase();
        self.by_name
            .get(&name_lower)
            .map(|info| info.level)
            .unwrap_or(CriticalityLevel::NonCritical)
    }

    /// Get full critical info by name
    pub fn get_info_by_name(&self, name: &str) -> Option<&CriticalProcessInfo> {
        let name_lower = name.to_lowercase();
        self.by_name.get(&name_lower)
    }

    /// Get critical info for a PID (with caching)
    pub async fn get_critical_info(&self, pid: u32) -> Option<CriticalProcessInfo> {
        // Check cache first
        {
            let cache = self.pid_cache.read().await;
            if let Some(cached) = cache.get(&pid) {
                return cached.clone();
            }
        }

        // Look up process name
        let process_name = get_process_name(pid);
        let info = process_name.and_then(|name| self.get_info_by_name(&name).cloned());

        // Cache the result
        {
            let mut cache = self.pid_cache.write().await;
            cache.insert(pid, info.clone());

            // Limit cache size
            if cache.len() > 10000 {
                cache.clear();
            }
        }

        info
    }

    /// Get criticality level for a PID
    pub async fn get_criticality_level(&self, pid: u32) -> Option<CriticalityLevel> {
        self.get_critical_info(pid).await.map(|info| info.level)
    }

    /// Verify a file hash against known-good hashes
    pub async fn verify_hash(&self, path: &str) -> Result<bool> {
        let hash = calculate_file_sha256(path)?;
        Ok(self.known_hashes.contains(&hash.to_lowercase()))
    }

    /// Verify a process path matches expected paths
    pub fn verify_path(&self, name: &str, path: &str) -> bool {
        if let Some(info) = self.get_info_by_name(name) {
            if info.expected_paths.is_empty() {
                return true; // No path verification required
            }

            let path_lower = path.to_lowercase();
            info.expected_paths
                .iter()
                .any(|expected| path_lower == expected.to_lowercase())
        } else {
            true // Not a critical process, no verification needed
        }
    }

    /// Clear the PID cache
    pub async fn clear_cache(&self) {
        let mut cache = self.pid_cache.write().await;
        cache.clear();
    }
}

impl Default for CriticalProcessDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Get process name by PID
fn get_process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use sysinfo::{Pid, System};
        let mut system = System::new();
        system.refresh_process(Pid::from_u32(pid));
        system
            .process(Pid::from_u32(pid))
            .map(|p| p.name().to_string())
    }

    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[cfg(target_os = "macos")]
    {
        use sysinfo::{Pid, System};
        let mut system = System::new();
        system.refresh_process(Pid::from_u32(pid));
        system
            .process(Pid::from_u32(pid))
            .map(|p| p.name().to_string())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Calculate SHA256 hash of a file
fn calculate_file_sha256(path: &str) -> Result<String> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(path)
        .map_err(|e| ProcessManagerError::Other(format!("Failed to read file: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();

    Ok(format!("{:x}", hash))
}

/// Standalone function to check if a process is critical
pub fn is_critical_process(name: &str) -> bool {
    let db = CriticalProcessDb::new();
    db.is_critical_by_name(name)
}

/// Standalone function to get criticality level
pub fn get_criticality_level(name: &str) -> CriticalityLevel {
    let db = CriticalProcessDb::new();
    db.get_level_by_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_process_db_creation() {
        let db = CriticalProcessDb::new();
        // Should have entries based on current platform
        #[cfg(target_os = "windows")]
        {
            assert!(db.is_critical_by_name("csrss.exe"));
            assert!(db.is_critical_by_name("lsass.exe"));
            assert!(db.is_critical_by_name("svchost.exe"));
        }

        #[cfg(target_os = "linux")]
        {
            assert!(db.is_critical_by_name("init"));
            assert!(db.is_critical_by_name("systemd"));
        }

        #[cfg(target_os = "macos")]
        {
            assert!(db.is_critical_by_name("launchd"));
            assert!(db.is_critical_by_name("WindowServer"));
        }
    }

    #[test]
    fn test_criticality_levels() {
        let db = CriticalProcessDb::new();

        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                db.get_level_by_name("csrss.exe"),
                CriticalityLevel::SystemCritical
            );
            assert_eq!(
                db.get_level_by_name("svchost.exe"),
                CriticalityLevel::ServiceCritical
            );
            assert_eq!(
                db.get_level_by_name("explorer.exe"),
                CriticalityLevel::UserCritical
            );
            assert_eq!(
                db.get_level_by_name("notepad.exe"),
                CriticalityLevel::NonCritical
            );
        }

        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                db.get_level_by_name("systemd"),
                CriticalityLevel::SystemCritical
            );
            assert_eq!(
                db.get_level_by_name("sshd"),
                CriticalityLevel::ServiceCritical
            );
            assert_eq!(
                db.get_level_by_name("gnome-shell"),
                CriticalityLevel::UserCritical
            );
        }
    }

    #[test]
    fn test_case_insensitivity() {
        let db = CriticalProcessDb::new();

        #[cfg(target_os = "windows")]
        {
            assert!(db.is_critical_by_name("CSRSS.EXE"));
            assert!(db.is_critical_by_name("Csrss.Exe"));
            assert!(db.is_critical_by_name("csrss.exe"));
        }
    }

    #[test]
    fn test_should_block_kill() {
        assert!(CriticalityLevel::SystemCritical.should_block_kill());
        assert!(!CriticalityLevel::ServiceCritical.should_block_kill());
        assert!(!CriticalityLevel::UserCritical.should_block_kill());
        assert!(!CriticalityLevel::NonCritical.should_block_kill());
    }

    #[test]
    fn test_should_warn() {
        assert!(CriticalityLevel::SystemCritical.should_warn());
        assert!(CriticalityLevel::ServiceCritical.should_warn());
        assert!(!CriticalityLevel::UserCritical.should_warn());
        assert!(!CriticalityLevel::NonCritical.should_warn());
    }
}
