//! Data Staging Detection Module
//!
//! Detects data collection, aggregation, and staging behaviors that often
//! precede exfiltration attempts.
//!
//! MITRE ATT&CK:
//! - T1005: Data from Local System
//! - T1039: Data from Network Shared Drive
//! - T1074: Data Staged
//! - T1560: Archive Collected Data
//! - T1119: Automated Collection

// This analyzer enumerates pre-exfil staging thresholds (aggregation window,
// bulk access, archive signatures) and per-process activity state. Reserved
// fields and constants are kept exhaustive for downstream correlation even
// when not yet consumed by every dispatch path.
#![allow(dead_code, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

/// Maximum file access events to track per process
const MAX_FILE_EVENTS: usize = 1000;
/// Time window for aggregation detection (5 minutes)
const AGGREGATION_WINDOW_MS: u64 = 300_000;
/// Minimum files for bulk access alert
const BULK_ACCESS_THRESHOLD: usize = 50;
/// High-value file extensions for targeting
const HIGH_VALUE_EXTENSIONS: &[&str] = &[
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "pdf",
    "txt",
    "rtf",
    "csv",
    "json",
    "xml",
    "sql",
    "db",
    "sqlite",
    "mdb",
    "accdb",
    "key",
    "pem",
    "crt",
    "cer",
    "pfx",
    "p12",
    "jks",
    "kdbx",
    "1pux",
    "agilekeychain",
    "keychain",
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "bz2",
    "pst",
    "ost",
    "msg",
    "eml",
    "bak",
    "backup",
    "old",
];
/// Staging directory patterns
const STAGING_PATTERNS: &[&str] = &[
    "temp",
    "tmp",
    "appdata\\local\\temp",
    "programdata",
    "public",
    "downloads",
    "desktop",
    "recycler",
    "recycle.bin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

/// File access event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub file_path: String,
    pub access_type: FileAccessType,
    pub bytes_read: Option<u64>,
    pub bytes_written: Option<u64>,
}

/// Type of file access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAccessType {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Copy,
    Enumerate,
}

/// Data staging detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingDetection {
    pub detection_type: StagingDetectionType,
    pub pid: u32,
    pub process_name: String,
    pub confidence: f32,
    pub mitre_technique: String,
    pub description: String,
    pub files_involved: Vec<String>,
    pub staging_location: Option<String>,
    pub timestamp: u64,
}

/// Types of staging behavior detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagingDetectionType {
    /// Mass file enumeration (FindFirstFile loops)
    BulkEnumeration,
    /// Reading many high-value files
    HighValueFileCollection,
    /// Writing collected data to staging directory
    StagingDirectoryWrite,
    /// Archive creation with collected files
    ArchiveCreation,
    /// Copying files to removable media
    RemovableMediaStaging,
    /// Copying files to network share
    NetworkShareStaging,
    /// Collecting from multiple directories
    CrossDirectoryCollection,
    /// Accessing credential stores
    CredentialStoreAccess,
    /// Database file access
    DatabaseAccess,
    /// Email store access
    EmailStoreAccess,
}

impl StagingDetectionType {
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::BulkEnumeration => "T1083",
            Self::HighValueFileCollection => "T1005",
            Self::StagingDirectoryWrite => "T1074",
            Self::ArchiveCreation => "T1560",
            Self::RemovableMediaStaging => "T1052",
            Self::NetworkShareStaging => "T1039",
            Self::CrossDirectoryCollection => "T1119",
            Self::CredentialStoreAccess => "T1555",
            Self::DatabaseAccess => "T1005",
            Self::EmailStoreAccess => "T1114",
        }
    }
}

/// Process file activity tracker
#[derive(Debug, Default)]
struct ProcessActivity {
    /// Files read by this process
    files_read: HashSet<String>,
    /// Files written by this process
    files_written: HashSet<String>,
    /// Directories enumerated
    dirs_enumerated: HashSet<String>,
    /// High-value files accessed
    high_value_files: HashSet<String>,
    /// Staging directory writes
    staging_writes: HashSet<String>,
    /// Total bytes read
    bytes_read: u64,
    /// Total bytes written
    bytes_written: u64,
    /// Recent events
    recent_events: VecDeque<FileAccessEvent>,
    /// First activity timestamp
    first_activity: u64,
    /// Last activity timestamp
    last_activity: u64,
}

/// Data staging detector
pub struct DataStagingDetector {
    /// Per-process activity tracking
    process_activity: Arc<RwLock<HashMap<u32, ProcessActivity>>>,
    /// Recently detected staging behaviors
    detections: Arc<RwLock<VecDeque<StagingDetection>>>,
}

impl DataStagingDetector {
    pub fn new() -> Self {
        Self {
            process_activity: Arc::new(RwLock::new(HashMap::new())),
            detections: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        }
    }

    /// Process a file access event
    pub fn process_event(&self, event: FileAccessEvent) -> Vec<StagingDetection> {
        if self.is_low_signal_path(&event.file_path) {
            return Vec::new();
        }

        let mut activity_map = self.process_activity.write();

        let activity = activity_map
            .entry(event.pid)
            .or_insert_with(|| ProcessActivity {
                first_activity: event.timestamp,
                ..Default::default()
            });

        activity.last_activity = event.timestamp;

        // Track by access type
        match event.access_type {
            FileAccessType::Read => {
                activity.files_read.insert(event.file_path.clone());
                if let Some(bytes) = event.bytes_read {
                    activity.bytes_read += bytes;
                }
            }
            FileAccessType::Write | FileAccessType::Create => {
                activity.files_written.insert(event.file_path.clone());
                if let Some(bytes) = event.bytes_written {
                    activity.bytes_written += bytes;
                }
            }
            FileAccessType::Enumerate => {
                if let Some(parent) = Path::new(&event.file_path).parent() {
                    activity
                        .dirs_enumerated
                        .insert(parent.to_string_lossy().to_string());
                }
            }
            _ => {}
        }

        // Check if high-value file
        if self.is_high_value_file(&event.file_path) {
            activity.high_value_files.insert(event.file_path.clone());
        }

        // Check if staging location
        if self.is_staging_location(&event.file_path) {
            if matches!(
                event.access_type,
                FileAccessType::Write | FileAccessType::Create
            ) {
                activity.staging_writes.insert(event.file_path.clone());
            }
        }

        // Add to recent events
        activity.recent_events.push_back(event.clone());
        while activity.recent_events.len() > MAX_FILE_EVENTS {
            activity.recent_events.pop_front();
        }

        // Analyze for detections
        let mut detections = Vec::new();

        // Clone data needed for analysis to release the lock
        let activity_snapshot = (
            activity.files_read.len(),
            activity.files_written.len(),
            activity.dirs_enumerated.len(),
            activity.high_value_files.clone(),
            activity.staging_writes.clone(),
            activity.bytes_read,
            activity.bytes_written,
        );

        drop(activity_map);

        // Analyze patterns
        detections.extend(self.analyze_patterns(&event, &activity_snapshot));

        // Store detections
        if !detections.is_empty() {
            let mut stored = self.detections.write();
            for det in &detections {
                stored.push_back(det.clone());
                while stored.len() > 100 {
                    stored.pop_front();
                }
            }
        }

        detections
    }

    /// Analyze activity patterns for staging behaviors
    fn analyze_patterns(
        &self,
        event: &FileAccessEvent,
        activity: &(
            usize,
            usize,
            usize,
            HashSet<String>,
            HashSet<String>,
            u64,
            u64,
        ),
    ) -> Vec<StagingDetection> {
        let (
            files_read,
            files_written,
            dirs_enumerated,
            high_value_files,
            staging_writes,
            bytes_read,
            bytes_written,
        ) = activity;
        let mut detections = Vec::new();

        // Bulk enumeration detection
        if *dirs_enumerated > 10 {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::BulkEnumeration,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: (*dirs_enumerated as f32 / 50.0).min(1.0),
                mitre_technique: "T1083".to_string(),
                description: format!("Process enumerated {} directories", dirs_enumerated),
                files_involved: vec![],
                staging_location: None,
                timestamp: event.timestamp,
            });
        }

        // High-value file collection
        if high_value_files.len() >= 5 {
            let confidence = (high_value_files.len() as f32 / 20.0).min(1.0);
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::HighValueFileCollection,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence,
                mitre_technique: "T1005".to_string(),
                description: format!(
                    "Process accessed {} high-value files",
                    high_value_files.len()
                ),
                files_involved: high_value_files.iter().take(10).cloned().collect(),
                staging_location: None,
                timestamp: event.timestamp,
            });
        }

        // Staging directory write detection
        if !staging_writes.is_empty() && *files_read > 10 {
            let staging_loc = staging_writes.iter().next().and_then(|p| {
                Path::new(p)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
            });

            detections.push(StagingDetection {
                detection_type: StagingDetectionType::StagingDirectoryWrite,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.7,
                mitre_technique: "T1074".to_string(),
                description: format!(
                    "Process read {} files and wrote to staging location",
                    files_read
                ),
                files_involved: staging_writes.iter().take(10).cloned().collect(),
                staging_location: staging_loc,
                timestamp: event.timestamp,
            });
        }

        // Archive creation detection
        if self.is_archive_file(&event.file_path)
            && matches!(
                event.access_type,
                FileAccessType::Write | FileAccessType::Create
            )
            && *files_read > 5
        {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::ArchiveCreation,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.85,
                mitre_technique: "T1560".to_string(),
                description: format!("Process created archive after reading {} files", files_read),
                files_involved: vec![event.file_path.clone()],
                staging_location: Path::new(&event.file_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string()),
                timestamp: event.timestamp,
            });
        }

        // Credential store access
        if self.is_credential_store(&event.file_path) {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::CredentialStoreAccess,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.9,
                mitre_technique: "T1555".to_string(),
                description: "Process accessed credential store".to_string(),
                files_involved: vec![event.file_path.clone()],
                staging_location: None,
                timestamp: event.timestamp,
            });
        }

        // Database file access
        if self.is_database_file(&event.file_path)
            && self.is_sensitive_database_path(&event.file_path)
        {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::DatabaseAccess,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.75,
                mitre_technique: "T1005".to_string(),
                description: "Process accessed database file".to_string(),
                files_involved: vec![event.file_path.clone()],
                staging_location: None,
                timestamp: event.timestamp,
            });
        }

        // Email store access
        if self.is_email_store(&event.file_path) {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::EmailStoreAccess,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.85,
                mitre_technique: "T1114".to_string(),
                description: "Process accessed email store".to_string(),
                files_involved: vec![event.file_path.clone()],
                staging_location: None,
                timestamp: event.timestamp,
            });
        }

        // Network share staging
        if self.is_network_path(&event.file_path)
            && matches!(
                event.access_type,
                FileAccessType::Write | FileAccessType::Copy
            )
        {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::NetworkShareStaging,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.8,
                mitre_technique: "T1039".to_string(),
                description: "Process wrote to network share".to_string(),
                files_involved: vec![event.file_path.clone()],
                staging_location: Some(event.file_path.clone()),
                timestamp: event.timestamp,
            });
        }

        // Removable media staging
        if self.is_removable_media(&event.file_path)
            && matches!(
                event.access_type,
                FileAccessType::Write | FileAccessType::Copy
            )
        {
            detections.push(StagingDetection {
                detection_type: StagingDetectionType::RemovableMediaStaging,
                pid: event.pid,
                process_name: event.process_name.clone(),
                confidence: 0.8,
                mitre_technique: "T1052".to_string(),
                description: "Process wrote to removable media".to_string(),
                files_involved: vec![event.file_path.clone()],
                staging_location: Some(event.file_path.clone()),
                timestamp: event.timestamp,
            });
        }

        detections
    }

    /// Check if file is high-value based on extension
    fn is_high_value_file(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();

        if self.is_low_signal_path(&path_lower) {
            return false;
        }

        if self.is_credential_store(&path_lower)
            || self.is_email_store(&path_lower)
            || self.is_database_file(&path_lower) && self.is_sensitive_database_path(&path_lower)
        {
            return true;
        }

        HIGH_VALUE_EXTENSIONS
            .iter()
            .any(|ext| path_lower.ends_with(&format!(".{}", ext)))
            && self.is_sensitive_document_path(&path_lower)
    }

    /// Ignore high-volume development, build, media, and application cache paths.
    /// These paths are still collected as telemetry elsewhere, but they should not
    /// drive data-staging alerts without a stronger correlated signal.
    fn is_low_signal_path(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase().replace('\\', "/");
        let low_signal_patterns = [
            "/target/debug/",
            "/target/release/",
            "/target/.rustc_info.json",
            "/node_modules/",
            "/.git/",
            "/.cargo/registry/",
            "/.cargo/git/",
            "/.codex/",
            "/library/caches/",
            "/library/assistant/sirivocabulary/",
            "/library/identityservices/",
            "/library/application support/spotify/",
            "/library/application support/com.apple.ap.promotedcontentd/",
            "/pictures/photos library.photoslibrary/private/com.apple.photoanalysisd/caches/",
            "/movies/tv/tv library.tvlibrary/",
            "/cache/cache_data/",
            "/appdata/local/steam/htmlcache/",
            "/appdata/local/microsoft/windows/inetcache/",
            "/windows/system32/winevt/logs/",
            "/windows/system32/logfiles/wmi/rtbackup/",
            "/windows/system32/tasks/microsoft/windows/",
            "/programdata/microsoft/network/downloader/",
            "/programdata/microsoft/windows defender/scans/",
        ];

        low_signal_patterns
            .iter()
            .any(|pattern| path_lower.contains(pattern))
    }

    fn is_sensitive_document_path(&self, path: &str) -> bool {
        let normalized = path.replace('\\', "/");
        if !normalized.contains('/') {
            return true;
        }

        let sensitive_roots = [
            "/documents/",
            "/desktop/",
            "/downloads/",
            "/onedrive/",
            "/dropbox/",
            "/google drive/",
            "/icloud drive/",
            "/users/public/",
            "/home/",
            "/srv/",
            "/var/www/",
        ];

        sensitive_roots.iter().any(|root| normalized.contains(root))
    }

    fn is_sensitive_database_path(&self, path: &str) -> bool {
        let normalized = path.replace('\\', "/");
        if !normalized.contains('/') {
            return true;
        }

        self.is_credential_store(&normalized)
            || normalized.contains("/documents/")
            || normalized.contains("/desktop/")
            || normalized.contains("/downloads/")
            || normalized.contains("/appdata/roaming/")
            || (normalized.contains("/library/application support/")
                && !normalized.contains("/library/application support/google/chrome/")
                && !normalized.contains("/library/application support/firefox/"))
    }

    /// Check if path is a staging location
    fn is_staging_location(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        STAGING_PATTERNS
            .iter()
            .any(|pattern| path_lower.contains(pattern))
    }

    /// Check if file is an archive
    fn is_archive_file(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        let archive_exts = ["zip", "7z", "rar", "tar", "gz", "bz2", "xz", "cab"];
        archive_exts
            .iter()
            .any(|ext| path_lower.ends_with(&format!(".{}", ext)))
    }

    /// Check if file is a credential store
    fn is_credential_store(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        let normalized = path_lower.replace('\\', "/");

        if self.is_low_signal_path(&normalized) {
            return false;
        }

        let protected_os_stores = [
            "/windows/system32/config/sam",
            "/windows/system32/config/security",
            "/windows/system32/config/system",
            "/windows/ntds/ntds.dit",
            "/etc/shadow",
            "/etc/security/passwd",
        ];

        if protected_os_stores
            .iter()
            .any(|pattern| normalized == *pattern || normalized.ends_with(pattern))
        {
            return true;
        }

        let cred_patterns = [
            "login data",
            "cookies",
            "key3.db",
            "key4.db",
            "logins.json",
            "signons.sqlite",
            "credentials",
            ".kdbx",
            "vault",
            "keychain",
            "credential manager",
            "ntds.dit",
        ];
        cred_patterns.iter().any(|p| path_lower.contains(p))
    }

    /// Check if file is a database
    fn is_database_file(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        let db_exts = [
            "db", "sqlite", "sqlite3", "mdb", "accdb", "sql", "mdf", "ldf",
        ];
        db_exts
            .iter()
            .any(|ext| path_lower.ends_with(&format!(".{}", ext)))
    }

    /// Check if file is an email store
    fn is_email_store(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        let email_patterns = [
            ".pst",
            ".ost",
            ".msg",
            ".eml",
            ".mbox",
            "mail",
            "thunderbird",
        ];
        email_patterns.iter().any(|p| path_lower.contains(p))
    }

    /// Check if path is a network share
    fn is_network_path(&self, path: &str) -> bool {
        path.starts_with("\\\\") || path.starts_with("//") || path.contains(":/")
    }

    /// Check if path is removable media (simple heuristic)
    fn is_removable_media(&self, path: &str) -> bool {
        // Windows: Check for drive letters D-Z (common for removable), but never
        // classify the actual system drive as removable. Some lab and enterprise
        // images install Windows on D: or another non-C drive.
        // Linux/Mac: Check for /media, /mnt patterns
        let path_upper = path.to_uppercase();

        if cfg!(target_os = "windows") {
            let system_drive = std::env::var("SystemDrive")
                .ok()
                .filter(|drive| drive.len() >= 2)
                .or_else(|| {
                    std::env::var("SystemRoot")
                        .ok()
                        .and_then(|root| root.get(0..2).map(|drive| drive.to_string()))
                })
                .unwrap_or_else(|| "C:".to_string())
                .to_uppercase();

            if path_upper.starts_with(&system_drive) {
                return false;
            }
        }

        // Skip Unix absolute paths unless they are known removable mount roots.
        if path_upper.starts_with("/") {
            // Check Linux mount points
            if path.starts_with("/media/")
                || path.starts_with("/mnt/")
                || path.starts_with("/run/media/")
            {
                return true;
            }
            return false;
        }

        // Windows removable drives (D: through Z:)
        if path_upper.len() >= 2 {
            let first_char = path_upper.chars().next().unwrap_or(' ');
            if first_char >= 'D' && first_char <= 'Z' && path_upper.chars().nth(1) == Some(':') {
                return true;
            }
        }

        false
    }

    /// Get recent detections
    pub fn get_detections(&self) -> Vec<StagingDetection> {
        self.detections.read().iter().cloned().collect()
    }

    /// Get high-confidence detections
    pub fn get_high_confidence_detections(&self) -> Vec<StagingDetection> {
        self.detections
            .read()
            .iter()
            .filter(|d| d.confidence >= 0.7)
            .cloned()
            .collect()
    }

    /// Clear activity for a process (on process exit)
    pub fn clear_process(&self, pid: u32) {
        self.process_activity.write().remove(&pid);
    }
}

impl Default for DataStagingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_value_detection() {
        let detector = DataStagingDetector::new();
        assert!(detector.is_high_value_file("document.docx"));
        assert!(detector.is_high_value_file("credentials.json"));
        assert!(detector.is_high_value_file("database.sqlite"));
        assert!(!detector.is_high_value_file("program.exe"));
    }

    #[test]
    fn test_staging_location() {
        let detector = DataStagingDetector::new();
        assert!(detector.is_staging_location("C:\\Windows\\Temp\\data.zip"));
        assert!(detector.is_staging_location("/tmp/collected.tar"));
        assert!(!detector.is_staging_location("C:\\Program Files\\app.exe"));
    }

    #[test]
    fn test_credential_store() {
        let detector = DataStagingDetector::new();
        assert!(detector.is_credential_store("Login Data"));
        assert!(detector.is_credential_store("passwords.kdbx"));
        assert!(detector.is_credential_store("C:\\Windows\\System32\\config\\SAM"));
        assert!(!detector.is_credential_store(
            "\\Device\\HarddiskVolume2\\Windows\\System32\\winevt\\Logs\\Application.evtx"
        ));
        assert!(!detector.is_credential_store(
            "\\Device\\HarddiskVolume2\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask"
        ));
        assert!(!detector.is_credential_store(
            "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive"
        ));
    }

    #[test]
    fn test_operating_system_database_paths_are_low_signal() {
        let detector = DataStagingDetector::new();

        assert!(detector.is_low_signal_path(
            "\\Device\\HarddiskVolume2\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db"
        ));
        assert!(detector.is_low_signal_path(
            "\\Device\\HarddiskVolume2\\ProgramData\\Microsoft\\Windows Defender\\Scans\\mpenginedb.db"
        ));
        assert!(!detector.is_sensitive_database_path(
            "\\Device\\HarddiskVolume2\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db"
        ));
    }

    #[test]
    fn test_database_detection_requires_sensitive_path() {
        let detector = DataStagingDetector::new();

        let os_database_event = FileAccessEvent {
            timestamp: 1000,
            pid: 4,
            process_name: "System".to_string(),
            file_path:
                "\\Device\\HarddiskVolume2\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db"
                    .to_string(),
            access_type: FileAccessType::Write,
            bytes_read: None,
            bytes_written: Some(4096),
        };

        let detections = detector.process_event(os_database_event);
        assert!(detections
            .iter()
            .all(|d| !matches!(d.detection_type, StagingDetectionType::DatabaseAccess)));
    }

    #[test]
    fn test_archive_detection() {
        let detector = DataStagingDetector::new();

        // Simulate reading files then creating archive
        for i in 0..10 {
            let event = FileAccessEvent {
                timestamp: 1000 + i * 100,
                pid: 1234,
                process_name: "test.exe".to_string(),
                file_path: format!("C:\\Users\\test\\doc{}.docx", i),
                access_type: FileAccessType::Read,
                bytes_read: Some(10000),
                bytes_written: None,
            };
            detector.process_event(event);
        }

        // Create archive
        let archive_event = FileAccessEvent {
            timestamp: 2000,
            pid: 1234,
            process_name: "test.exe".to_string(),
            file_path: "C:\\Windows\\Temp\\collected.zip".to_string(),
            access_type: FileAccessType::Write,
            bytes_read: None,
            bytes_written: Some(100000),
        };

        let detections = detector.process_event(archive_event);
        assert!(!detections.is_empty());
        assert!(detections
            .iter()
            .any(|d| matches!(d.detection_type, StagingDetectionType::ArchiveCreation)));
    }
}
