//! Ransomware Canary/Tripwire Detection System
//!
//! Provides high-confidence ransomware detection through strategically deployed
//! canary files (tripwires) that monitor for ransomware-indicative behavior:
//!
//! - File content modification (encryption)
//! - File renaming (common ransomware behavior)
//! - File deletion
//! - Mass file changes (multiple canaries touched in short timeframe)
//!
//! Detection triggers automatic response actions including process termination
//! and network isolation.

// This collector enumerates canary file types, attack-state machine
// transitions and tripwire telemetry. Reserved correlation fields are kept
// exhaustive for downstream automatic response even when not all paths are
// dispatched yet.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::analyzers;
use crate::config::AgentConfig;
use anyhow::Result;
use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Canary file types with tempting names for ransomware
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanaryFileType {
    /// Microsoft Word document
    Docx,
    /// Microsoft Excel spreadsheet
    Xlsx,
    /// PDF document
    Pdf,
    /// JPEG image
    Jpg,
    /// Plain text file
    Txt,
    /// Zip archive
    Zip,
    /// Database backup
    Sql,
    /// Bitcoin wallet (high-value target)
    Wallet,
}

impl CanaryFileType {
    fn extension(&self) -> &'static str {
        match self {
            CanaryFileType::Docx => "docx",
            CanaryFileType::Xlsx => "xlsx",
            CanaryFileType::Pdf => "pdf",
            CanaryFileType::Jpg => "jpg",
            CanaryFileType::Txt => "txt",
            CanaryFileType::Zip => "zip",
            CanaryFileType::Sql => "sql",
            CanaryFileType::Wallet => "wallet",
        }
    }

    fn mime_magic(&self) -> &'static [u8] {
        match self {
            CanaryFileType::Docx => b"PK\x03\x04", // ZIP-based Office format
            CanaryFileType::Xlsx => b"PK\x03\x04",
            CanaryFileType::Pdf => b"%PDF-1.7",
            CanaryFileType::Jpg => &[0xFF, 0xD8, 0xFF, 0xE0],
            CanaryFileType::Txt => b"",
            CanaryFileType::Zip => b"PK\x03\x04",
            CanaryFileType::Sql => b"-- SQL Backup",
            CanaryFileType::Wallet => b"\x00wallet",
        }
    }
}

/// Processes whitelisted from canary access alerts.
/// These are known system processes (AV scanners, search indexers, etc.)
/// that routinely access files and would otherwise cause false positives.
const CANARY_WHITELIST: &[&str] = &[
    "msmpeng.exe",       // Windows Defender
    "mssense.exe",       // Defender ATP
    "searchindexer.exe", // Windows Search
    "searchprotocolhost.exe",
    "explorer.exe",         // Windows Explorer
    "svchost.exe",          // Service Host
    "system",               // System process
    "vssvc.exe",            // Volume Shadow Copy
    "tiworker.exe",         // Windows Module Installer
    "trustedinstaller.exe", // Windows Trusted Installer
];

/// Tempting canary file names that attract ransomware
const TEMPTING_NAMES: &[(&str, CanaryFileType)] = &[
    // High-value financial documents
    ("passwords", CanaryFileType::Xlsx),
    ("bank_accounts", CanaryFileType::Xlsx),
    ("credit_cards", CanaryFileType::Xlsx),
    ("tax_returns_2024", CanaryFileType::Pdf),
    ("financial_report_Q4", CanaryFileType::Xlsx),
    ("payroll_data", CanaryFileType::Xlsx),
    // Backup files (ransomware loves these)
    ("backup", CanaryFileType::Zip),
    ("full_backup_2024", CanaryFileType::Zip),
    ("database_backup", CanaryFileType::Sql),
    ("important_backup", CanaryFileType::Zip),
    // Personal documents
    ("family_photos", CanaryFileType::Jpg),
    ("wedding_photos", CanaryFileType::Jpg),
    ("passport_scan", CanaryFileType::Pdf),
    ("drivers_license", CanaryFileType::Pdf),
    ("social_security", CanaryFileType::Pdf),
    // Business documents
    ("contracts", CanaryFileType::Docx),
    ("employee_records", CanaryFileType::Xlsx),
    ("customer_database", CanaryFileType::Xlsx),
    ("confidential", CanaryFileType::Docx),
    ("trade_secrets", CanaryFileType::Docx),
    // Crypto wallets (high-value target)
    ("bitcoin_wallet", CanaryFileType::Wallet),
    ("crypto_keys", CanaryFileType::Txt),
    ("seed_phrase", CanaryFileType::Txt),
    // Recovery files
    ("recovery_key", CanaryFileType::Txt),
    ("master_password", CanaryFileType::Txt),
    // Driver Tripwire (Matches kernel hardcoded check)
    ("DO_NOT_DELETE", CanaryFileType::Txt),
];

/// Ransomware canary event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareCanaryEvent {
    /// Path to the canary file
    pub canary_path: String,
    /// Original canary file name
    pub canary_name: String,
    /// Type of operation detected
    pub operation: String,
    /// New path if renamed
    pub new_path: Option<String>,
    /// PID of the offending process
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process executable path
    pub process_path: String,
    /// Process SHA256 hash
    #[serde(with = "hex::serde")]
    pub process_sha256: Vec<u8>,
    /// Process command line
    pub cmdline: String,
    /// Original file hash
    pub original_hash: String,
    /// Current file hash (if modified)
    pub current_hash: Option<String>,
    /// Number of canaries affected in this attack
    pub affected_canary_count: u32,
    /// Time window of the attack in seconds
    pub attack_window_seconds: f64,
    /// Is this part of a mass attack
    pub is_mass_attack: bool,
    /// Automatic response actions taken
    pub response_actions: Vec<String>,
}

/// Individual canary file metadata
#[derive(Debug, Clone)]
struct CanaryFile {
    path: PathBuf,
    file_type: CanaryFileType,
    original_hash: String,
    created_at: Instant,
    last_checked: Instant,
}

/// Mass attack detection state
#[derive(Debug, Clone)]
struct AttackState {
    /// Canaries touched in current window
    touched_canaries: Vec<(PathBuf, Instant, u32)>, // (path, time, pid)
    /// Window start time
    window_start: Instant,
    /// Attack in progress
    attack_in_progress: bool,
}

impl Default for AttackState {
    fn default() -> Self {
        Self {
            touched_canaries: Vec::new(),
            window_start: Instant::now(),
            attack_in_progress: false,
        }
    }
}

/// Ransomware canary collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryConfig {
    /// Enable canary deployment
    pub enabled: bool,
    /// Auto-kill offending process on detection
    pub auto_kill_process: bool,
    /// Auto-isolate network on mass attack
    pub auto_isolate_network: bool,
    /// Mass attack threshold (canaries touched)
    pub mass_attack_threshold: u32,
    /// Mass attack time window in seconds
    pub mass_attack_window_seconds: u64,
    /// Hash check interval in seconds
    pub hash_check_interval_seconds: u64,
    /// Deploy to user directories
    pub deploy_user_dirs: bool,
    /// Deploy to root directories
    pub deploy_root_dirs: bool,
    /// Deploy to network shares
    pub deploy_network_shares: bool,
    /// Custom deployment paths
    pub custom_paths: Vec<String>,
    /// Server URL for backend reporting
    pub server_url: Option<String>,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_kill_process: true,
            auto_isolate_network: true,
            mass_attack_threshold: 5,
            mass_attack_window_seconds: 10,
            hash_check_interval_seconds: 30,
            deploy_user_dirs: true,
            deploy_root_dirs: true,
            deploy_network_shares: false,
            custom_paths: Vec::new(),
            server_url: None,
        }
    }
}

/// Ransomware Canary Collector
pub struct RansomwareCanaryCollector {
    config: AgentConfig,
    canary_config: CanaryConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    canaries: Arc<Mutex<HashMap<PathBuf, CanaryFile>>>,
    attack_state: Arc<Mutex<AttackState>>,
}

impl RansomwareCanaryCollector {
    /// Create a new ransomware canary collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        let canary_config = CanaryConfig::default();

        let canaries: Arc<Mutex<HashMap<PathBuf, CanaryFile>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let attack_state = Arc::new(Mutex::new(AttackState::default()));

        // Deploy canaries and start monitoring
        let config_clone = config.clone();
        let canary_config_clone = canary_config.clone();
        let canaries_clone = canaries.clone();
        let attack_state_clone = attack_state.clone();

        std::thread::spawn(move || {
            // Deploy canary files
            if let Err(e) = Self::deploy_canaries(&canary_config_clone, &canaries_clone) {
                error!(error = %e, "Failed to deploy canary files");
            }

            // Start file system monitoring
            if let Err(e) = Self::start_monitoring(
                tx,
                config_clone,
                canary_config_clone,
                canaries_clone,
                attack_state_clone,
            ) {
                error!(error = %e, "Canary monitoring error");
            }
        });

        Self {
            config: config.clone(),
            canary_config,
            event_rx: rx,
            canaries,
            attack_state,
        }
    }

    /// Create with custom canary configuration
    pub fn with_config(config: &AgentConfig, canary_config: CanaryConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        let canaries: Arc<Mutex<HashMap<PathBuf, CanaryFile>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let attack_state = Arc::new(Mutex::new(AttackState::default()));

        let config_clone = config.clone();
        let canary_config_clone = canary_config.clone();
        let canaries_clone = canaries.clone();
        let attack_state_clone = attack_state.clone();

        std::thread::spawn(move || {
            if let Err(e) = Self::deploy_canaries(&canary_config_clone, &canaries_clone) {
                error!(error = %e, "Failed to deploy canary files");
            }

            if let Err(e) = Self::start_monitoring(
                tx,
                config_clone,
                canary_config_clone,
                canaries_clone,
                attack_state_clone,
            ) {
                error!(error = %e, "Canary monitoring error");
            }
        });

        Self {
            config: config.clone(),
            canary_config,
            event_rx: rx,
            canaries,
            attack_state,
        }
    }

    /// Deploy canary files to strategic locations
    fn deploy_canaries(
        canary_config: &CanaryConfig,
        canaries: &Arc<Mutex<HashMap<PathBuf, CanaryFile>>>,
    ) -> Result<()> {
        let mut deployment_paths = Vec::new();

        // Get user directories
        if canary_config.deploy_user_dirs {
            deployment_paths.extend(Self::get_user_directories());
        }

        // Get root directories
        if canary_config.deploy_root_dirs {
            deployment_paths.extend(Self::get_root_directories());
        }

        // Get network shares
        if canary_config.deploy_network_shares {
            deployment_paths.extend(Self::get_network_shares());
        }

        // Add custom paths
        for path in &canary_config.custom_paths {
            if Path::new(path).exists() {
                deployment_paths.push(PathBuf::from(path));
            }
        }

        info!(
            count = deployment_paths.len(),
            "Deploying canaries to directories"
        );

        // Deploy canaries to each path
        let mut deployed_count = 0;
        for base_path in deployment_paths {
            match Self::deploy_canaries_to_path(&base_path, canaries) {
                Ok(count) => {
                    deployed_count += count;
                    debug!(path = %base_path.display(), count = count, "Deployed canaries");
                }
                Err(e) => {
                    warn!(path = %base_path.display(), error = %e, "Failed to deploy canaries");
                }
            }
        }

        info!(total = deployed_count, "Total canary files deployed");

        Ok(())
    }

    /// Deploy canary files to a specific path
    fn deploy_canaries_to_path(
        base_path: &Path,
        canaries: &Arc<Mutex<HashMap<PathBuf, CanaryFile>>>,
    ) -> Result<usize> {
        if !base_path.exists() {
            return Ok(0);
        }

        let mut deployed = 0;

        // Create hidden canary directory
        let canary_dir = base_path.join(".tamandua_canaries");

        // Also deploy some directly in the target directory (more visible to ransomware)
        let deployment_locations = vec![
            (canary_dir.clone(), true),       // Hidden directory
            (base_path.to_path_buf(), false), // Direct in target
        ];

        for (deploy_path, create_dir) in deployment_locations {
            if create_dir && !deploy_path.exists() {
                if let Err(e) = std::fs::create_dir_all(&deploy_path) {
                    debug!(path = %deploy_path.display(), error = %e, "Could not create canary directory");
                    continue;
                }

                // Set hidden attribute on Windows
                #[cfg(target_os = "windows")]
                Self::set_hidden_attribute(&deploy_path);
            }

            // Select a subset of tempting names based on path hash for variety
            let path_hash = {
                let mut hasher = Sha256::new();
                hasher.update(deploy_path.to_string_lossy().as_bytes());
                hasher.finalize()
            };

            let start_idx = (path_hash[0] as usize) % TEMPTING_NAMES.len();
            let names_to_deploy = 3.min(TEMPTING_NAMES.len());

            for i in 0..names_to_deploy {
                let idx = (start_idx + i) % TEMPTING_NAMES.len();
                let (name, file_type) = TEMPTING_NAMES[idx];

                // Add randomization suffix
                let suffix = &hex::encode(&path_hash[1..4]);
                let filename = format!("{}_{}.{}", name, suffix, file_type.extension());
                let canary_path = deploy_path.join(&filename);

                if canary_path.exists() {
                    // Already deployed, update tracking
                    if let Ok(hash) = Self::compute_file_hash(&canary_path) {
                        let mut canaries_guard = canaries.lock().unwrap_or_else(|e| e.into_inner());
                        canaries_guard.insert(
                            canary_path.clone(),
                            CanaryFile {
                                path: canary_path,
                                file_type: file_type,
                                original_hash: hash,
                                created_at: Instant::now(),
                                last_checked: Instant::now(),
                            },
                        );
                    }
                    deployed += 1;
                    continue;
                }

                // Generate realistic file content
                let content = Self::generate_canary_content(file_type);

                match std::fs::write(&canary_path, &content) {
                    Ok(_) => {
                        // Compute and store hash
                        let hash = {
                            let mut hasher = Sha256::new();
                            hasher.update(&content);
                            hex::encode(hasher.finalize())
                        };

                        // Set file attributes
                        #[cfg(target_os = "windows")]
                        Self::set_file_attributes(&canary_path);

                        // Set realistic timestamps
                        Self::set_realistic_timestamps(&canary_path);

                        let mut canaries_guard = canaries.lock().unwrap_or_else(|e| e.into_inner());
                        canaries_guard.insert(
                            canary_path.clone(),
                            CanaryFile {
                                path: canary_path,
                                file_type: file_type,
                                original_hash: hash,
                                created_at: Instant::now(),
                                last_checked: Instant::now(),
                            },
                        );

                        deployed += 1;
                    }
                    Err(e) => {
                        debug!(path = %canary_path.display(), error = %e, "Could not create canary file");
                    }
                }
            }
        }

        Ok(deployed)
    }

    /// Generate realistic file content based on type
    fn generate_canary_content(file_type: CanaryFileType) -> Vec<u8> {
        let mut content = Vec::new();

        // Add magic bytes
        content.extend_from_slice(file_type.mime_magic());

        // Add realistic content based on type
        match file_type {
            CanaryFileType::Docx | CanaryFileType::Xlsx | CanaryFileType::Zip => {
                // Minimal ZIP/Office structure
                content.extend_from_slice(b"\x14\x00\x06\x00\x08\x00\x00\x00!\x00");
                content.extend_from_slice(b"[Content_Types].xml");
                // Add some realistic-looking encrypted data
                content.extend_from_slice(&Self::generate_fake_encrypted_data(2048));
            }
            CanaryFileType::Pdf => {
                content.extend_from_slice(
                    br#"
%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (CONFIDENTIAL DOCUMENT) Tj ET
endstream
endobj
xref
0 5
trailer
<< /Size 5 /Root 1 0 R >>
startxref
EOF"#,
                );
            }
            CanaryFileType::Jpg => {
                // JPEG with minimal valid structure
                content.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
                content.extend_from_slice(b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
                content.extend_from_slice(&Self::generate_fake_encrypted_data(4096));
                content.extend_from_slice(&[0xFF, 0xD9]); // JPEG end marker
            }
            CanaryFileType::Txt => {
                content.extend_from_slice(
                    br#"CONFIDENTIAL - DO NOT SHARE

Bank Account Information:
Account: 4532-8876-2341-9087
Routing: 021000089
PIN: 7734

Bitcoin Wallet Recovery Phrase:
abandon ability able about above absent absorb abstract absurd abuse

Master Password: Tr0ub4dor&3!Complex2024

SSH Private Key:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA
-----END OPENSSH PRIVATE KEY-----
"#,
                );
            }
            CanaryFileType::Sql => {
                content.extend_from_slice(
                    br#"-- Database Backup - CONFIDENTIAL
-- Generated: 2024-01-15 03:00:00 UTC
-- Server: prod-db-master.internal

CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    ssn VARCHAR(11),
    credit_card VARCHAR(19),
    cvv VARCHAR(4)
);

INSERT INTO customers VALUES
(1, 'John Smith', 'john@example.com', '123-45-6789', '4111-1111-1111-1111', '123'),
(2, 'Jane Doe', 'jane@example.com', '987-65-4321', '5500-0000-0000-0004', '456');

-- Encryption keys
-- AES-256: K3y$ecr3t!2024M@sterK3y
"#,
                );
            }
            CanaryFileType::Wallet => {
                content.extend_from_slice(b"\x00wallet\x01\x00");
                // Fake wallet data structure
                content.extend_from_slice(&Self::generate_fake_encrypted_data(1024));
            }
        }

        // Add unique identifier for tracking (hidden in content)
        let canary_id = format!("\n<!-- TAMANDUA_CANARY:{} -->\n", Uuid::new_v4());
        content.extend_from_slice(canary_id.as_bytes());

        content
    }

    /// Generate fake encrypted-looking data
    fn generate_fake_encrypted_data(size: usize) -> Vec<u8> {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Use time-based seed for pseudo-random but reproducible data
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut data = Vec::with_capacity(size);
        let mut state = seed;

        for _ in 0..size {
            // Simple LCG for pseudo-random bytes
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            data.push((state >> 33) as u8);
        }

        data
    }

    /// Get user directories for canary deployment
    fn get_user_directories() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                let user_path = PathBuf::from(&user_profile);
                paths.push(user_path.join("Documents"));
                paths.push(user_path.join("Desktop"));
                paths.push(user_path.join("Downloads"));
                paths.push(user_path.join("Pictures"));
                paths.push(user_path.join("Videos"));
            }

            // Also check common user paths
            if let Ok(users_dir) = std::fs::read_dir("C:\\Users") {
                for entry in users_dir.filter_map(|e| e.ok()) {
                    let user_path = entry.path();
                    if user_path.is_dir() {
                        let name = user_path.file_name().unwrap_or_default().to_string_lossy();
                        if !["Public", "Default", "Default User", "All Users"]
                            .contains(&name.as_ref())
                        {
                            paths.push(user_path.join("Documents"));
                            paths.push(user_path.join("Desktop"));
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(home) = std::env::var("HOME") {
                let home_path = PathBuf::from(&home);
                paths.push(home_path.join("Documents"));
                paths.push(home_path.join("Desktop"));
                paths.push(home_path.join("Downloads"));
                paths.push(home_path.clone());
            }

            // Check /home for all users
            if let Ok(home_dir) = std::fs::read_dir("/home") {
                for entry in home_dir.filter_map(|e| e.ok()) {
                    let user_path = entry.path();
                    if user_path.is_dir() {
                        paths.push(user_path.join("Documents"));
                        paths.push(user_path.join("Desktop"));
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                let home_path = PathBuf::from(&home);
                paths.push(home_path.join("Documents"));
                paths.push(home_path.join("Desktop"));
                paths.push(home_path.join("Downloads"));
            }

            // Check /Users for all users
            if let Ok(users_dir) = std::fs::read_dir("/Users") {
                for entry in users_dir.filter_map(|e| e.ok()) {
                    let user_path = entry.path();
                    if user_path.is_dir() {
                        let name = user_path.file_name().unwrap_or_default().to_string_lossy();
                        if !["Shared", "Guest"].contains(&name.as_ref()) {
                            paths.push(user_path.join("Documents"));
                            paths.push(user_path.join("Desktop"));
                        }
                    }
                }
            }
        }

        // Filter to existing paths
        paths.into_iter().filter(|p| p.exists()).collect()
    }

    /// Get root directories for canary deployment
    fn get_root_directories() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Check all drive letters
            for drive in b'C'..=b'Z' {
                let drive_path = PathBuf::from(format!("{}:\\", drive as char));
                if drive_path.exists() {
                    paths.push(drive_path);
                }
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            paths.push(PathBuf::from("/"));
            paths.push(PathBuf::from("/tmp"));
            paths.push(PathBuf::from("/var/tmp"));
            paths.push(PathBuf::from("/opt"));
        }

        paths.into_iter().filter(|p| p.exists()).collect()
    }

    /// Get network shares for canary deployment
    fn get_network_shares() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Common network share locations
            paths.push(PathBuf::from("\\\\localhost\\share"));

            // Enumerate network connections
            // Note: In production, use WNetEnumResource
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Check common mount points
            for mount_point in &["/mnt", "/media", "/Volumes"] {
                if let Ok(entries) = std::fs::read_dir(mount_point) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        if entry.path().is_dir() {
                            paths.push(entry.path());
                        }
                    }
                }
            }
        }

        paths.into_iter().filter(|p| p.exists()).collect()
    }

    /// Set hidden attribute on Windows
    #[cfg(target_os = "windows")]
    fn set_hidden_attribute(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM,
        };

        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let _ = SetFileAttributesW(
                PCWSTR(path_wide.as_ptr()),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            );
        }
    }

    /// Set file attributes on Windows
    #[cfg(target_os = "windows")]
    fn set_file_attributes(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM,
        };

        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let _ = SetFileAttributesW(
                PCWSTR(path_wide.as_ptr()),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            );
        }
    }

    /// Set realistic timestamps on canary files
    fn set_realistic_timestamps(path: &Path) {
        // Set modification time to a few weeks ago
        let weeks_ago = SystemTime::now()
            .checked_sub(Duration::from_secs(60 * 60 * 24 * 21))
            .unwrap_or(SystemTime::now());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Set reasonable permissions
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));

            // Use filetime crate in production for setting mtime/atime
        }

        // In production, use platform-specific APIs to set file times
        let _ = weeks_ago;
    }

    /// Compute SHA256 hash of a file
    fn compute_file_hash(path: &Path) -> Result<String> {
        let content = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Start file system monitoring for canary files
    fn start_monitoring(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        canary_config: CanaryConfig,
        canaries: Arc<Mutex<HashMap<PathBuf, CanaryFile>>>,
        attack_state: Arc<Mutex<AttackState>>,
    ) -> Result<()> {
        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        })?;

        // Watch all canary file parent directories
        let mut watched_dirs = std::collections::HashSet::new();
        {
            let canaries_guard = canaries.lock().unwrap_or_else(|e| e.into_inner());
            for canary_path in canaries_guard.keys() {
                if let Some(parent) = canary_path.parent() {
                    if watched_dirs.insert(parent.to_path_buf()) {
                        if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
                            warn!(path = %parent.display(), error = %e, "Failed to watch canary directory");
                        }
                    }
                }
            }
        }

        debug!(dirs = watched_dirs.len(), "Watching canary directories");

        // Create runtime for async operations
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        // Also start periodic hash checking
        let canaries_for_hash_check = canaries.clone();
        let tx_for_hash_check = tx.clone();
        let canary_config_for_hash = canary_config.clone();
        let attack_state_for_hash = attack_state.clone();

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "Failed to create tokio runtime for ransomware-canary hash check");
                    return;
                }
            };

            loop {
                std::thread::sleep(Duration::from_secs(
                    canary_config_for_hash.hash_check_interval_seconds,
                ));

                let mut canaries_guard = match canaries_for_hash_check.lock() {
                    Ok(guard) => guard,
                    Err(e) => {
                        error!(error = %e, "Poisoned canary lock in hash-check loop; stopping monitor");
                        break;
                    }
                };
                let mut modified_canaries = Vec::new();

                for (path, canary) in canaries_guard.iter_mut() {
                    if let Ok(current_hash) = Self::compute_file_hash(path) {
                        if current_hash != canary.original_hash {
                            modified_canaries.push((path.clone(), current_hash));
                        }
                        canary.last_checked = Instant::now();
                    } else if !path.exists() {
                        // File was deleted
                        modified_canaries.push((path.clone(), String::new()));
                    }
                }

                drop(canaries_guard);

                // Process detected modifications
                for (path, new_hash) in modified_canaries {
                    let operation = if new_hash.is_empty() {
                        "deleted"
                    } else {
                        "modified"
                    };

                    if let Some(event) = rt.block_on(Self::create_canary_event(
                        &path,
                        operation,
                        None,
                        &canaries_for_hash_check,
                        &attack_state_for_hash,
                        &canary_config_for_hash,
                    )) {
                        if tx_for_hash_check.blocking_send(event).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        // Process file system events
        for event in notify_rx {
            let canaries_guard = match canaries.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(error = %e, "Poisoned canary lock in file-event loop; stopping monitor");
                    break;
                }
            };

            for path in &event.paths {
                // Check if this is a canary file
                let is_canary = canaries_guard.contains_key(path)
                    || canaries_guard.keys().any(|k| {
                        event.paths.iter().any(|p| {
                            p.to_string_lossy()
                                .contains(&k.to_string_lossy().to_string())
                        })
                    });

                if !is_canary {
                    continue;
                }

                let (operation, new_path) = match &event.kind {
                    EventKind::Modify(_) => ("modified", None),
                    EventKind::Remove(_) => ("deleted", None),
                    EventKind::Create(_) => continue, // Ignore creates (our own deployment)
                    EventKind::Access(_) => ("accessed", None),
                    _ => {
                        // Check for rename
                        if event.paths.len() == 2 {
                            ("renamed", Some(event.paths[1].clone()))
                        } else {
                            continue;
                        }
                    }
                };

                drop(canaries_guard);

                if let Some(telemetry_event) = runtime.block_on(Self::create_canary_event(
                    path,
                    operation,
                    new_path,
                    &canaries,
                    &attack_state,
                    &canary_config,
                )) {
                    if tx.blocking_send(telemetry_event).is_err() {
                        return Ok(());
                    }
                }

                break; // Only process once per event
            }
        }

        Ok(())
    }

    /// Create a canary detection event
    async fn create_canary_event(
        path: &Path,
        operation: &str,
        new_path: Option<PathBuf>,
        canaries: &Arc<Mutex<HashMap<PathBuf, CanaryFile>>>,
        attack_state: &Arc<Mutex<AttackState>>,
        canary_config: &CanaryConfig,
    ) -> Option<TelemetryEvent> {
        // Get canary info
        let (canary_name, original_hash) = {
            let canaries_guard = match canaries.lock() {
                Ok(g) => g,
                Err(e) => {
                    error!(error = %e, "Canary map lock poisoned; skipping canary event");
                    return None;
                }
            };
            if let Some(canary) = canaries_guard.get(path) {
                (
                    path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    canary.original_hash.clone(),
                )
            } else {
                return None;
            }
        };

        // Find offending process
        let (pid, process_name, process_path, process_sha256, cmdline) =
            Self::find_offending_process(path).await;

        // Skip whitelisted processes (AV scanners, search indexers, etc.)
        // to avoid false positives from routine file access
        let process_name_lower = process_name.to_lowercase();
        if CANARY_WHITELIST.iter().any(|&w| process_name_lower == w) {
            debug!(
                pid = pid,
                process = %process_name,
                canary = %path.display(),
                "Whitelisted process accessed canary file, skipping alert"
            );
            return None;
        }

        // Update attack state
        let (affected_count, attack_window, is_mass_attack) = {
            let mut state = match attack_state.lock() {
                Ok(g) => g,
                Err(e) => {
                    error!(error = %e, "Attack state lock poisoned; skipping canary event");
                    return None;
                }
            };
            let now = Instant::now();

            // Clean old entries
            let window = Duration::from_secs(canary_config.mass_attack_window_seconds);
            state
                .touched_canaries
                .retain(|(_, time, _)| now.duration_since(*time) < window);

            // Add current
            state.touched_canaries.push((path.to_path_buf(), now, pid));

            // Reset window if needed
            if state.touched_canaries.len() == 1 {
                state.window_start = now;
            }

            let affected_count = state.touched_canaries.len() as u32;
            let attack_window = now.duration_since(state.window_start).as_secs_f64();
            let is_mass_attack = affected_count >= canary_config.mass_attack_threshold;

            if is_mass_attack && !state.attack_in_progress {
                state.attack_in_progress = true;
            }

            (affected_count, attack_window, is_mass_attack)
        };

        // Execute automatic response actions
        let mut response_actions = Vec::new();

        if canary_config.auto_kill_process && pid > 0 {
            if Self::kill_process(pid).await {
                response_actions.push(format!("Killed process {} (PID: {})", process_name, pid));
                info!(pid = pid, process = %process_name, "Auto-killed ransomware process");
            }
        }

        if canary_config.auto_isolate_network && is_mass_attack {
            if Self::isolate_network().await {
                response_actions.push("Network isolation activated".to_string());
                warn!("Mass ransomware attack detected - network isolated");
            }
        }

        // Get current hash if file still exists
        let current_hash = if path.exists() {
            Self::compute_file_hash(path).ok()
        } else {
            None
        };

        // Create event payload
        let canary_event = RansomwareCanaryEvent {
            canary_path: path.to_string_lossy().to_string(),
            canary_name,
            operation: operation.to_string(),
            new_path: new_path.map(|p| p.to_string_lossy().to_string()),
            pid,
            process_name: process_name.clone(),
            process_path: process_path.clone(),
            process_sha256: process_sha256.clone(),
            cmdline,
            original_hash,
            current_hash,
            affected_canary_count: affected_count,
            attack_window_seconds: attack_window,
            is_mass_attack,
            response_actions: response_actions.clone(),
        };

        // Determine severity
        let severity = if is_mass_attack {
            Severity::Critical
        } else {
            match operation {
                "modified" | "deleted" | "renamed" => Severity::Critical,
                "accessed" => Severity::High,
                _ => Severity::Medium,
            }
        };

        // Create telemetry event
        let mut event = TelemetryEvent::new(
            EventType::HoneyfileAccess, // Using existing EventType for compatibility
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&canary_event).unwrap()),
        );

        // Add ransomware detection
        let description = if is_mass_attack {
            format!(
                "MASS RANSOMWARE ATTACK: {} canaries affected in {:.1}s by process '{}' (PID: {})",
                affected_count, attack_window, process_name, pid
            )
        } else {
            format!(
                "Ransomware canary {} by process '{}' (PID: {})",
                operation, process_name, pid
            )
        };

        event.add_detection(Detection {
            detection_type: DetectionType::Ransomware,
            rule_name: format!("ransomware_canary_{}", operation),
            confidence: 1.0,
            description,
            mitre_tactics: vec!["impact".to_string()],
            mitre_techniques: vec![
                "T1486".to_string(), // Data Encrypted for Impact
                "T1490".to_string(), // Inhibit System Recovery
            ],
        });

        // Add metadata
        event.metadata.insert(
            "canary_path".to_string(),
            path.to_string_lossy().to_string(),
        );
        event
            .metadata
            .insert("operation".to_string(), operation.to_string());
        event.metadata.insert("pid".to_string(), pid.to_string());
        event
            .metadata
            .insert("process_name".to_string(), process_name);
        event
            .metadata
            .insert("is_mass_attack".to_string(), is_mass_attack.to_string());
        event
            .metadata
            .insert("affected_count".to_string(), affected_count.to_string());

        for (i, action) in response_actions.iter().enumerate() {
            event
                .metadata
                .insert(format!("response_action_{}", i), action.clone());
        }

        Some(event)
    }

    /// Find the process that modified the canary file
    async fn find_offending_process(path: &Path) -> (u32, String, String, Vec<u8>, String) {
        #[cfg(target_os = "windows")]
        return Self::find_process_windows(path).await;

        #[cfg(target_os = "linux")]
        return Self::find_process_linux(path).await;

        #[cfg(target_os = "macos")]
        return Self::find_process_macos(path).await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return (0, String::new(), String::new(), Vec::new(), String::new());
    }

    #[cfg(target_os = "linux")]
    async fn find_process_linux(path: &Path) -> (u32, String, String, Vec<u8>, String) {
        use std::fs;

        let path_str = path.to_string_lossy();

        // Scan /proc for processes with the file open
        if let Ok(proc_dir) = fs::read_dir("/proc") {
            for entry in proc_dir.filter_map(|e| e.ok()) {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Check /proc/[pid]/fd
                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                    for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                        if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                            if link_target.to_string_lossy().contains(&*path_str) {
                                // Found the process
                                let comm_path = format!("/proc/{}/comm", pid);
                                let exe_path = format!("/proc/{}/exe", pid);
                                let cmdline_path = format!("/proc/{}/cmdline", pid);

                                let process_name = fs::read_to_string(&comm_path)
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_else(|_| format!("pid:{}", pid));

                                let process_path = fs::read_link(&exe_path)
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                let cmdline = fs::read_to_string(&cmdline_path)
                                    .map(|s| s.replace('\0', " ").trim().to_string())
                                    .unwrap_or_default();

                                let process_sha256 = if !process_path.is_empty() {
                                    analyzers::hash_file(&process_path)
                                        .await
                                        .map(|(h, _)| h)
                                        .unwrap_or_default()
                                } else {
                                    Vec::new()
                                };

                                return (pid, process_name, process_path, process_sha256, cmdline);
                            }
                        }
                    }
                }
            }
        }

        // Fallback: use lsof
        if let Ok(output) = std::process::Command::new("lsof")
            .args(["-t", &path_str])
            .output()
        {
            if let Ok(pid_str) = String::from_utf8(output.stdout) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let comm_path = format!("/proc/{}/comm", pid);
                    let exe_path = format!("/proc/{}/exe", pid);

                    let process_name = fs::read_to_string(&comm_path)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|_| format!("pid:{}", pid));

                    let process_path = fs::read_link(&exe_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();

                    return (pid, process_name, process_path, Vec::new(), String::new());
                }
            }
        }

        (
            0,
            "unknown".to_string(),
            String::new(),
            Vec::new(),
            String::new(),
        )
    }

    #[cfg(target_os = "windows")]
    async fn find_process_windows(path: &Path) -> (u32, String, String, Vec<u8>, String) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::{EnumProcesses, GetModuleFileNameExW};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let path_str = path.to_string_lossy().to_lowercase();

        unsafe {
            let mut pids = vec![0u32; 4096];
            let mut bytes_returned: u32 = 0;

            if EnumProcesses(
                pids.as_mut_ptr(),
                (pids.len() * std::mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            )
            .is_err()
            {
                return (
                    0,
                    "unknown".to_string(),
                    String::new(),
                    Vec::new(),
                    String::new(),
                );
            }

            let num_processes = bytes_returned as usize / std::mem::size_of::<u32>();

            for &pid in &pids[..num_processes] {
                if pid == 0 {
                    continue;
                }

                let handle =
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                // Get process executable path
                let mut filename = [0u16; 512];
                let len = GetModuleFileNameExW(handle, None, &mut filename);

                if len > 0 {
                    let process_path =
                        String::from_utf16_lossy(&filename[..len as usize]).to_lowercase();

                    // Check if process has file open (simplified check)
                    // In production, use NtQuerySystemInformation or RestartManager
                    let process_name = std::path::Path::new(&process_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    let _ = CloseHandle(handle);

                    // For now, return first matching suspicious process
                    // In production, use proper handle enumeration
                    if process_name.to_lowercase().contains("ransom")
                        || process_name.to_lowercase().contains("crypt")
                        || process_name.to_lowercase().ends_with(".tmp")
                    {
                        let process_sha256 = analyzers::hash_file(&process_path)
                            .await
                            .map(|(h, _)| h)
                            .unwrap_or_default();

                        return (
                            pid,
                            process_name,
                            process_path,
                            process_sha256,
                            String::new(),
                        );
                    }
                } else {
                    let _ = CloseHandle(handle);
                }
            }
        }

        (
            0,
            "unknown".to_string(),
            String::new(),
            Vec::new(),
            String::new(),
        )
    }

    #[cfg(target_os = "macos")]
    async fn find_process_macos(path: &Path) -> (u32, String, String, Vec<u8>, String) {
        // Use lsof to find process
        let path_str = path.to_string_lossy();

        if let Ok(output) = std::process::Command::new("lsof")
            .args(["-F", "pcn", &path_str])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut pid: Option<u32> = None;
                let mut process_name = String::new();

                for line in stdout.lines() {
                    if line.starts_with('p') {
                        pid = line[1..].parse().ok();
                    } else if line.starts_with('c') {
                        process_name = line[1..].to_string();
                    }
                }

                if let Some(pid) = pid {
                    // Get process path using ps
                    let process_path = std::process::Command::new("ps")
                        .args(["-p", &pid.to_string(), "-o", "comm="])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();

                    return (pid, process_name, process_path, Vec::new(), String::new());
                }
            }
        }

        (
            0,
            "unknown".to_string(),
            String::new(),
            Vec::new(),
            String::new(),
        )
    }

    /// Kill the offending process
    async fn kill_process(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }

        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            // Try SIGKILL for immediate termination
            match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
                Ok(_) => {
                    info!(pid = pid, "Killed ransomware process");
                    return true;
                }
                Err(e) => {
                    error!(pid = pid, error = %e, "Failed to kill process");
                    return false;
                }
            }
        }

        #[cfg(windows)]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                match OpenProcess(PROCESS_TERMINATE, false, pid) {
                    Ok(handle) => {
                        let result = TerminateProcess(handle, 1);
                        let _ = CloseHandle(handle);

                        if result.is_ok() {
                            info!(pid = pid, "Killed ransomware process");
                            return true;
                        } else {
                            error!(pid = pid, "Failed to terminate process");
                            return false;
                        }
                    }
                    Err(e) => {
                        error!(pid = pid, error = %e, "Failed to open process for termination");
                        return false;
                    }
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        false
    }

    /// Isolate the network to prevent ransomware spread
    async fn isolate_network() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Block all outbound traffic except established connections
            let commands = [
                ("iptables", ["-F", "OUTPUT"].as_slice()),
                (
                    "iptables",
                    ["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"].as_slice(),
                ),
                (
                    "iptables",
                    [
                        "-A",
                        "OUTPUT",
                        "-m",
                        "state",
                        "--state",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ]
                    .as_slice(),
                ),
                ("iptables", ["-A", "OUTPUT", "-j", "DROP"].as_slice()),
            ];

            for (cmd, args) in commands {
                if std::process::Command::new(cmd).args(args).output().is_err() {
                    return false;
                }
            }

            return true;
        }

        #[cfg(target_os = "windows")]
        {
            // Use Windows Firewall to block all outbound
            let result = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=TamanduaRansomwareBlock",
                    "dir=out",
                    "action=block",
                    "enable=yes",
                ])
                .output();

            return result.map(|o| o.status.success()).unwrap_or(false);
        }

        #[cfg(target_os = "macos")]
        {
            // Use pf to block outbound
            let pf_rules = "block out all\npass out on lo0 all\n";
            let rules_path = "/tmp/tamandua_ransomware_block.conf";

            if std::fs::write(rules_path, pf_rules).is_err() {
                return false;
            }

            return std::process::Command::new("pfctl")
                .args(["-f", rules_path, "-e"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        false
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Get list of deployed canaries
    pub fn list_canaries(&self) -> Vec<PathBuf> {
        self.canaries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Get canary count
    pub fn canary_count(&self) -> usize {
        self.canaries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Redeploy canaries (useful after attack cleanup)
    pub fn redeploy(&self) -> Result<()> {
        Self::deploy_canaries(&self.canary_config, &self.canaries)
    }

    /// Remove all canary files
    pub fn cleanup(&self) -> Result<()> {
        let canaries_guard = self.canaries.lock().unwrap_or_else(|e| e.into_inner());

        for path in canaries_guard.keys() {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }

        Ok(())
    }
}

impl Drop for RansomwareCanaryCollector {
    fn drop(&mut self) {
        // Optionally clean up canary files on shutdown
        // Uncomment if you want canaries removed when agent stops:
        // let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_content_generation() {
        for (name, file_type) in TEMPTING_NAMES {
            let content = RansomwareCanaryCollector::generate_canary_content(*file_type);
            assert!(
                !content.is_empty(),
                "Content for {} should not be empty",
                name
            );

            // Verify magic bytes
            let magic = file_type.mime_magic();
            if !magic.is_empty() {
                assert!(
                    content.starts_with(magic),
                    "Content for {} should start with magic bytes",
                    name
                );
            }
        }
    }

    #[test]
    fn test_file_hash_computation() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("tamandua_test_canary.txt");

        std::fs::write(&test_file, "test content").unwrap();

        let hash = RansomwareCanaryCollector::compute_file_hash(&test_file).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 hex = 64 chars

        std::fs::remove_file(&test_file).unwrap();
    }

    #[tokio::test]
    async fn test_canary_deployment_paths() {
        let user_dirs = RansomwareCanaryCollector::get_user_directories();
        // Should find at least one directory on any system
        assert!(
            !user_dirs.is_empty() || cfg!(target_os = "unknown"),
            "Should find user directories"
        );

        let root_dirs = RansomwareCanaryCollector::get_root_directories();
        assert!(
            !root_dirs.is_empty() || cfg!(target_os = "unknown"),
            "Should find root directories"
        );
    }
}
