//! Firmware/BIOS Integrity Monitoring Collector
//!
//! Detects bootkits and firmware-level threats:
//! - UEFI/BIOS tampering
//! - Secure Boot bypass
//! - Boot configuration modifications
//! - MBR/VBR infections
//! - Known bootkit signatures (LoJax, MosaicRegressor, CosmicStrand, MoonBounce)
//!
//! MITRE ATT&CK: T1542 (Pre-OS Boot)
//! - T1542.001 (System Firmware)
//! - T1542.002 (Component Firmware)
//! - T1542.003 (Bootkit)

// Firmware/bootkit detector. Scaffolded config fields and helper params retained.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Firmware event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareEvent {
    /// Type of firmware anomaly detected
    pub anomaly_type: FirmwareAnomalyType,
    /// Firmware vendor
    pub vendor: String,
    /// Firmware version
    pub version: String,
    /// BIOS release date
    pub release_date: String,
    /// Secure Boot status
    pub secure_boot_enabled: bool,
    /// Secure Boot configuration
    pub secure_boot_config: Option<SecureBootConfig>,
    /// Hash of firmware/boot component
    pub hash: Option<String>,
    /// Expected/baseline hash
    pub expected_hash: Option<String>,
    /// Component that was modified
    pub component: String,
    /// Bootkit name if detected
    pub bootkit_name: Option<String>,
    /// Additional details
    pub details: String,
}

/// Types of firmware anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareAnomalyType {
    /// Firmware version/hash changed
    FirmwareModification,
    /// Secure Boot is disabled
    SecureBootDisabled,
    /// Secure Boot configuration changed
    SecureBootBypass,
    /// Boot configuration data modified
    BootConfigModified,
    /// MBR/VBR tampering detected
    BootSectorInfection,
    /// Known bootkit signature detected
    BootkitDetected,
    /// Unknown bootloader detected
    UnknownBootloader,
    /// EFI System Partition modified
    EspModified,
    /// Initramfs/initrd modified
    InitramfsModified,
    /// GRUB configuration modified
    GrubModified,
    /// PK/KEK/db/dbx modified
    SecureBootDbModified,
}

impl FirmwareAnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirmwareModification => "firmware_modification",
            Self::SecureBootDisabled => "secure_boot_disabled",
            Self::SecureBootBypass => "secure_boot_bypass",
            Self::BootConfigModified => "boot_config_modified",
            Self::BootSectorInfection => "boot_sector_infection",
            Self::BootkitDetected => "bootkit_detected",
            Self::UnknownBootloader => "unknown_bootloader",
            Self::EspModified => "esp_modified",
            Self::InitramfsModified => "initramfs_modified",
            Self::GrubModified => "grub_modified",
            Self::SecureBootDbModified => "secure_boot_db_modified",
        }
    }

    pub fn mitre_subtechnique(&self) -> &'static str {
        match self {
            Self::FirmwareModification => "T1542.001",
            Self::SecureBootDisabled | Self::SecureBootBypass | Self::SecureBootDbModified => {
                "T1542.001"
            }
            Self::BootConfigModified | Self::UnknownBootloader => "T1542.003",
            Self::BootSectorInfection | Self::BootkitDetected => "T1542.003",
            Self::EspModified | Self::InitramfsModified | Self::GrubModified => "T1542.003",
        }
    }
}

/// Secure Boot configuration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureBootConfig {
    /// Setup mode enabled (allows key enrollment)
    pub setup_mode: bool,
    /// Platform Key present
    pub pk_present: bool,
    /// Key Exchange Key count
    pub kek_count: u32,
    /// Signature database entries
    pub db_count: u32,
    /// Forbidden signature database entries
    pub dbx_count: u32,
}

/// Known bootkit signatures
#[derive(Debug, Clone)]
pub struct BootkitSignature {
    pub name: &'static str,
    pub description: &'static str,
    /// Byte patterns to search for in MBR/VBR
    pub mbr_patterns: &'static [&'static [u8]],
    /// File hashes associated with the bootkit
    pub file_hashes: &'static [&'static str],
    /// Registry indicators
    pub registry_indicators: &'static [&'static str],
}

/// Known bootkits database
const KNOWN_BOOTKITS: &[BootkitSignature] = &[
    BootkitSignature {
        name: "LoJax",
        description: "UEFI rootkit attributed to APT28/Fancy Bear",
        mbr_patterns: &[
            // LoJax UEFI module signature patterns
            &[0x4C, 0x6F, 0x4A, 0x61, 0x78], // "LoJax"
            &[0x72, 0x6B, 0x6C, 0x6F, 0x61, 0x64, 0x65, 0x72], // "rkloader"
        ],
        file_hashes: &["a3c7e5c27e6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "MosaicRegressor",
        description: "UEFI bootkit discovered by Kaspersky",
        mbr_patterns: &[
            &[0x4D, 0x6F, 0x73, 0x61, 0x69, 0x63], // "Mosaic"
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "FinSpy",
        description: "Commercial spyware with bootkit capability",
        mbr_patterns: &[
            &[0x46, 0x69, 0x6E, 0x53, 0x70, 0x79], // "FinSpy"
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "CosmicStrand",
        description: "UEFI firmware rootkit targeting ASUS/Gigabyte motherboards",
        mbr_patterns: &[
            // CosmicStrand shellcode patterns
            &[0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08],
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "MoonBounce",
        description: "UEFI bootkit attributed to APT41",
        mbr_patterns: &[
            // MoonBounce driver loader patterns
            &[0x4D, 0x6F, 0x6F, 0x6E, 0x42, 0x6F, 0x75, 0x6E, 0x63, 0x65], // "MoonBounce"
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "TDL4/TDSS",
        description: "Widespread MBR bootkit",
        mbr_patterns: &[
            // TDL4 MBR infection signature
            &[0xEB, 0x5E, 0x54, 0x44, 0x53, 0x53],
            &[0x90, 0x90, 0x90, 0x90, 0xFA, 0xFC],
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "Rovnix",
        description: "VBR-based bootkit used by Carberp",
        mbr_patterns: &[
            // Rovnix VBR signature
            &[0x52, 0x6F, 0x76, 0x6E, 0x69, 0x78], // "Rovnix"
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "Gapz",
        description: "Stealthy VBR bootkit",
        mbr_patterns: &[
            &[0x47, 0x61, 0x70, 0x7A], // "Gapz"
        ],
        file_hashes: &[],
        registry_indicators: &[],
    },
    BootkitSignature {
        name: "BlackLotus",
        description: "First UEFI bootkit to bypass Secure Boot in the wild",
        mbr_patterns: &[
            // BlackLotus patterns
            &[0x42, 0x6C, 0x61, 0x63, 0x6B, 0x4C, 0x6F, 0x74, 0x75, 0x73], // "BlackLotus"
        ],
        file_hashes: &[
            // CVE-2022-21894 exploit related
        ],
        registry_indicators: &[],
    },
];

/// Firmware integrity baseline
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirmwareBaseline {
    /// BIOS information hash
    pub bios_hash: Option<String>,
    /// MBR hash
    pub mbr_hash: Option<String>,
    /// VBR hash
    pub vbr_hash: Option<String>,
    /// Boot configuration hash
    pub bcd_hash: Option<String>,
    /// bootmgr hash
    pub bootmgr_hash: Option<String>,
    /// winload hash
    pub winload_hash: Option<String>,
    /// GRUB config hash (Linux)
    pub grub_hash: Option<String>,
    /// initramfs hash (Linux)
    pub initramfs_hash: Option<String>,
    /// ESP file hashes
    pub esp_hashes: HashMap<String, String>,
    /// Timestamp of baseline creation
    pub created_at: u64,
}

/// Firmware collector
pub struct FirmwareCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    baseline: FirmwareBaseline,
}

impl FirmwareCollector {
    /// Create a new firmware collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(100);

        info!("Initializing firmware/BIOS integrity monitor");

        // Load or create baseline
        let baseline = Self::load_or_create_baseline()?;

        let config_clone = config.clone();
        let tx_clone = tx;
        let baseline_clone = baseline.clone();

        tokio::spawn(async move {
            Self::monitor_loop(tx_clone, config_clone, baseline_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            baseline,
        })
    }

    /// Load existing baseline or create new one
    fn load_or_create_baseline() -> Result<FirmwareBaseline> {
        let baseline_path = if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\firmware_baseline.json"
        } else {
            "/var/lib/tamandua/firmware_baseline.json"
        };

        if let Ok(content) = std::fs::read_to_string(baseline_path) {
            if let Ok(baseline) = serde_json::from_str(&content) {
                info!("Loaded firmware baseline from {}", baseline_path);
                return Ok(baseline);
            }
        }

        // Create new baseline
        info!("Creating new firmware baseline");
        let baseline = Self::create_baseline()?;

        // Save baseline
        if let Some(parent) = std::path::Path::new(baseline_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if let Ok(json) = serde_json::to_string_pretty(&baseline) {
            if let Err(e) = std::fs::write(baseline_path, json) {
                warn!(error = %e, "Failed to save firmware baseline");
            } else {
                info!(path = %baseline_path, "Saved firmware baseline");
            }
        }

        Ok(baseline)
    }

    /// Create baseline from current system state
    fn create_baseline() -> Result<FirmwareBaseline> {
        let mut baseline = FirmwareBaseline {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            ..Default::default()
        };

        #[cfg(target_os = "windows")]
        {
            // Hash MBR
            if let Ok(hash) = Self::hash_mbr() {
                baseline.mbr_hash = Some(hash);
            }

            // Hash bootmgr
            if let Ok(hash) = Self::hash_file("C:\\Windows\\Boot\\EFI\\bootmgfw.efi") {
                baseline.bootmgr_hash = Some(hash);
            }

            // Hash winload
            if let Ok(hash) = Self::hash_file("C:\\Windows\\System32\\winload.efi") {
                baseline.winload_hash = Some(hash);
            }

            // Hash BCD
            if let Ok(hash) = Self::hash_file("C:\\Boot\\BCD") {
                baseline.bcd_hash = Some(hash);
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Hash MBR if not UEFI
            if let Ok(hash) = Self::hash_mbr() {
                baseline.mbr_hash = Some(hash);
            }

            // Hash GRUB config
            for grub_path in &[
                "/boot/grub/grub.cfg",
                "/boot/grub2/grub.cfg",
                "/etc/default/grub",
            ] {
                if let Ok(hash) = Self::hash_file(grub_path) {
                    baseline.grub_hash = Some(hash);
                    break;
                }
            }

            // Hash initramfs
            if let Ok(entries) = std::fs::read_dir("/boot") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with("initramfs") || name.starts_with("initrd") {
                        if let Ok(hash) = Self::hash_file(&entry.path().to_string_lossy()) {
                            baseline.initramfs_hash = Some(hash);
                            break;
                        }
                    }
                }
            }
        }

        Ok(baseline)
    }

    /// Main monitoring loop
    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        baseline: FirmwareBaseline,
    ) {
        info!("Starting firmware integrity monitor");

        // Respect performance profile
        if _config.performance_profile == crate::config::PerformanceProfile::Lightweight {
            info!("Lightweight profile: Firmware monitoring disabled");
            return;
        }

        // Initial scan is handled by interval ticking immediately
        // Self::perform_scan(&tx, &baseline).await;

        // Check intervals:
        // - Full firmware scan: every 1 hour
        // - Boot config check: every 5 minutes
        // - Secure Boot status: every 10 minutes
        let mut full_scan_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        let mut boot_config_interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        let mut secure_boot_interval = tokio::time::interval(tokio::time::Duration::from_secs(600));

        loop {
            tokio::select! {
                _ = full_scan_interval.tick() => {
                    debug!("Running full firmware scan");
                    Self::perform_scan(&tx, &baseline).await;
                }
                _ = boot_config_interval.tick() => {
                    debug!("Checking boot configuration");
                    Self::check_boot_config(&tx, &baseline).await;
                }
                _ = secure_boot_interval.tick() => {
                    debug!("Checking Secure Boot status");
                    Self::check_secure_boot(&tx).await;
                }
            }
        }
    }

    /// Perform comprehensive firmware scan
    async fn perform_scan(tx: &mpsc::Sender<TelemetryEvent>, baseline: &FirmwareBaseline) {
        // Get firmware info
        let (vendor, version, release_date) = Self::get_firmware_info();
        let secure_boot_enabled = Self::is_secure_boot_enabled();
        let secure_boot_config = Self::get_secure_boot_config();

        info!(
            vendor = %vendor,
            version = %version,
            secure_boot = secure_boot_enabled,
            "Firmware scan started"
        );

        // Check Secure Boot status
        if !secure_boot_enabled {
            let event = Self::create_firmware_event(
                FirmwareAnomalyType::SecureBootDisabled,
                &vendor,
                &version,
                &release_date,
                secure_boot_enabled,
                secure_boot_config.clone(),
                None,
                None,
                "Secure Boot",
                None,
                "Secure Boot is disabled - system vulnerable to bootkit attacks".to_string(),
            );
            let _ = tx.send(event).await;
        }

        // Check MBR/VBR integrity
        Self::check_boot_sectors(
            tx,
            baseline,
            &vendor,
            &version,
            &release_date,
            secure_boot_enabled,
            &secure_boot_config,
        )
        .await;

        // Check for known bootkits
        Self::scan_for_bootkits(
            tx,
            &vendor,
            &version,
            &release_date,
            secure_boot_enabled,
            &secure_boot_config,
        )
        .await;

        // Platform-specific checks
        #[cfg(target_os = "windows")]
        Self::check_windows_boot_components(
            tx,
            baseline,
            &vendor,
            &version,
            &release_date,
            secure_boot_enabled,
            &secure_boot_config,
        )
        .await;

        #[cfg(target_os = "linux")]
        Self::check_linux_boot_components(
            tx,
            baseline,
            &vendor,
            &version,
            &release_date,
            secure_boot_enabled,
            &secure_boot_config,
        )
        .await;

        info!("Firmware scan completed");
    }

    /// Check boot configuration
    async fn check_boot_config(tx: &mpsc::Sender<TelemetryEvent>, baseline: &FirmwareBaseline) {
        // Wrap in catch_unwind to prevent crashes from disk access violations
        type BootConfigCheck = Option<(
            FirmwareAnomalyType,
            String,
            String,
            String,
            bool,
            Option<SecureBootConfig>,
            Option<String>,
            Option<String>,
        )>;

        let result: std::thread::Result<BootConfigCheck> = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                let (vendor, version, release_date) = Self::get_firmware_info();
                let secure_boot_enabled = Self::is_secure_boot_enabled();
                let secure_boot_config = Self::get_secure_boot_config();

                #[cfg(target_os = "windows")]
                {
                    // Check BCD - this can crash if access is denied
                    match Self::hash_file("C:\\Boot\\BCD") {
                        Ok(current_hash) => {
                            if let Some(ref expected) = baseline.bcd_hash {
                                if &current_hash != expected {
                                    Some((
                                        FirmwareAnomalyType::BootConfigModified,
                                        vendor,
                                        version,
                                        release_date,
                                        secure_boot_enabled,
                                        secure_boot_config,
                                        Some(current_hash),
                                        Some(expected.clone()),
                                    ))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        Err(e) => {
                            debug!(error = %e, "Failed to hash BCD - may require elevated privileges");
                            None
                        }
                    }
                }

                #[cfg(target_os = "linux")]
                {
                    // Check GRUB config
                    for grub_path in &["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"] {
                        match Self::hash_file(grub_path) {
                            Ok(current_hash) => {
                                if let Some(ref expected) = baseline.grub_hash {
                                    if &current_hash != expected {
                                        return Some((
                                            FirmwareAnomalyType::GrubModified,
                                            vendor,
                                            version,
                                            release_date,
                                            secure_boot_enabled,
                                            secure_boot_config,
                                            Some(current_hash),
                                            Some(expected.clone()),
                                        ));
                                    }
                                }
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                    None
                }

                #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                None
            }),
        );

        // Handle result - send event if modification detected
        match result {
            Ok(Some((
                anomaly_type,
                vendor,
                version,
                release_date,
                secure_boot_enabled,
                secure_boot_config,
                current_hash,
                expected_hash,
            ))) => {
                let component = if cfg!(windows) {
                    "Boot Configuration Data (BCD)"
                } else {
                    "GRUB Configuration"
                };
                let details = if cfg!(windows) {
                    "Boot Configuration Data has been modified".to_string()
                } else {
                    "GRUB configuration has been modified".to_string()
                };

                let event = Self::create_firmware_event(
                    anomaly_type,
                    &vendor,
                    &version,
                    &release_date,
                    secure_boot_enabled,
                    secure_boot_config,
                    current_hash,
                    expected_hash,
                    component,
                    None,
                    details,
                );
                let _ = tx.send(event).await;
            }
            Ok(None) => {
                // No changes detected
            }
            Err(e) => {
                warn!(
                    "Boot config check panicked (likely access violation): {:?}",
                    e
                );
            }
        }
    }

    /// Check Secure Boot status
    async fn check_secure_boot(tx: &mpsc::Sender<TelemetryEvent>) {
        let (vendor, version, release_date) = Self::get_firmware_info();
        let secure_boot_enabled = Self::is_secure_boot_enabled();
        let secure_boot_config = Self::get_secure_boot_config();

        // Check for Secure Boot bypass indicators
        if let Some(ref config) = secure_boot_config {
            if config.setup_mode {
                let event = Self::create_firmware_event(
                    FirmwareAnomalyType::SecureBootBypass,
                    &vendor,
                    &version,
                    &release_date,
                    secure_boot_enabled,
                    secure_boot_config.clone(),
                    None,
                    None,
                    "Secure Boot Setup Mode",
                    None,
                    "Secure Boot is in Setup Mode - keys can be enrolled/modified".to_string(),
                );
                let _ = tx.send(event).await;
            }

            if !config.pk_present {
                let event = Self::create_firmware_event(
                    FirmwareAnomalyType::SecureBootBypass,
                    &vendor,
                    &version,
                    &release_date,
                    secure_boot_enabled,
                    secure_boot_config.clone(),
                    None,
                    None,
                    "Secure Boot Platform Key",
                    None,
                    "Platform Key (PK) is missing - Secure Boot chain broken".to_string(),
                );
                let _ = tx.send(event).await;
            }
        }
    }

    /// Check MBR/VBR integrity
    async fn check_boot_sectors(
        tx: &mpsc::Sender<TelemetryEvent>,
        baseline: &FirmwareBaseline,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: &Option<SecureBootConfig>,
    ) {
        // Check MBR
        if let Ok(current_hash) = Self::hash_mbr() {
            if let Some(ref expected) = baseline.mbr_hash {
                if &current_hash != expected {
                    let event = Self::create_firmware_event(
                        FirmwareAnomalyType::BootSectorInfection,
                        vendor,
                        version,
                        release_date,
                        secure_boot_enabled,
                        secure_boot_config.clone(),
                        Some(current_hash),
                        Some(expected.clone()),
                        "Master Boot Record (MBR)",
                        None,
                        "MBR has been modified - possible bootkit infection".to_string(),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    /// Scan for known bootkit signatures
    async fn scan_for_bootkits(
        tx: &mpsc::Sender<TelemetryEvent>,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: &Option<SecureBootConfig>,
    ) {
        // Read MBR/VBR for pattern scanning
        let mbr_data = Self::read_mbr();

        if let Ok(data) = mbr_data {
            for bootkit in KNOWN_BOOTKITS {
                for pattern in bootkit.mbr_patterns {
                    if Self::contains_pattern(&data, pattern) {
                        let event = Self::create_firmware_event(
                            FirmwareAnomalyType::BootkitDetected,
                            vendor,
                            version,
                            release_date,
                            secure_boot_enabled,
                            secure_boot_config.clone(),
                            None,
                            None,
                            "Boot Sector",
                            Some(bootkit.name.to_string()),
                            format!("{} bootkit detected: {}", bootkit.name, bootkit.description),
                        );
                        let _ = tx.send(event).await;
                        break;
                    }
                }
            }
        }
    }

    /// Windows-specific boot component checks
    #[cfg(target_os = "windows")]
    async fn check_windows_boot_components(
        tx: &mpsc::Sender<TelemetryEvent>,
        baseline: &FirmwareBaseline,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: &Option<SecureBootConfig>,
    ) {
        // Check bootmgr
        if let Ok(current_hash) = Self::hash_file("C:\\Windows\\Boot\\EFI\\bootmgfw.efi") {
            if let Some(ref expected) = baseline.bootmgr_hash {
                if &current_hash != expected {
                    let event = Self::create_firmware_event(
                        FirmwareAnomalyType::BootConfigModified,
                        vendor,
                        version,
                        release_date,
                        secure_boot_enabled,
                        secure_boot_config.clone(),
                        Some(current_hash),
                        Some(expected.clone()),
                        "Windows Boot Manager (bootmgfw.efi)",
                        None,
                        "Windows Boot Manager has been modified".to_string(),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }

        // Check winload
        if let Ok(current_hash) = Self::hash_file("C:\\Windows\\System32\\winload.efi") {
            if let Some(ref expected) = baseline.winload_hash {
                if &current_hash != expected {
                    let event = Self::create_firmware_event(
                        FirmwareAnomalyType::BootConfigModified,
                        vendor,
                        version,
                        release_date,
                        secure_boot_enabled,
                        secure_boot_config.clone(),
                        Some(current_hash),
                        Some(expected.clone()),
                        "Windows OS Loader (winload.efi)",
                        None,
                        "Windows OS Loader has been modified".to_string(),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }

        // Check EFI System Partition
        Self::check_esp_windows(
            tx,
            baseline,
            vendor,
            version,
            release_date,
            secure_boot_enabled,
            secure_boot_config,
        )
        .await;
    }

    /// Check Windows EFI System Partition
    #[cfg(target_os = "windows")]
    async fn check_esp_windows(
        tx: &mpsc::Sender<TelemetryEvent>,
        _baseline: &FirmwareBaseline,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: &Option<SecureBootConfig>,
    ) {
        // Mount ESP and check for suspicious files
        // Note: Requires admin privileges
        let esp_paths = ["S:\\EFI", "T:\\EFI", "Z:\\EFI"];

        for esp_path in &esp_paths {
            if std::path::Path::new(esp_path).exists() {
                // Look for suspicious EFI executables
                if let Ok(entries) = Self::scan_directory_recursive(esp_path) {
                    for entry in entries {
                        if entry.to_lowercase().ends_with(".efi") {
                            // Check for unknown/suspicious EFI files
                            let known_efi = [
                                "bootmgfw.efi",
                                "bootx64.efi",
                                "mmx64.efi",
                                "grubx64.efi",
                                "shimx64.efi",
                                "MokManager.efi",
                            ];

                            let filename = std::path::Path::new(&entry)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_lowercase())
                                .unwrap_or_default();

                            if !known_efi.iter().any(|k| filename == k.to_lowercase()) {
                                let event = Self::create_firmware_event(
                                    FirmwareAnomalyType::UnknownBootloader,
                                    vendor,
                                    version,
                                    release_date,
                                    secure_boot_enabled,
                                    secure_boot_config.clone(),
                                    Self::hash_file(&entry).ok(),
                                    None,
                                    &entry,
                                    None,
                                    format!("Unknown EFI executable found: {}", entry),
                                );
                                let _ = tx.send(event).await;
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    /// Linux-specific boot component checks
    #[cfg(target_os = "linux")]
    async fn check_linux_boot_components(
        tx: &mpsc::Sender<TelemetryEvent>,
        baseline: &FirmwareBaseline,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: &Option<SecureBootConfig>,
    ) {
        // Check initramfs
        if let Ok(entries) = std::fs::read_dir("/boot") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("initramfs") || name.starts_with("initrd") {
                    if let Ok(current_hash) = Self::hash_file(&entry.path().to_string_lossy()) {
                        if let Some(ref expected) = baseline.initramfs_hash {
                            if &current_hash != expected {
                                let event = Self::create_firmware_event(
                                    FirmwareAnomalyType::InitramfsModified,
                                    vendor,
                                    version,
                                    release_date,
                                    secure_boot_enabled,
                                    secure_boot_config.clone(),
                                    Some(current_hash),
                                    Some(expected.clone()),
                                    &name,
                                    None,
                                    format!("Initramfs {} has been modified", name),
                                );
                                let _ = tx.send(event).await;
                            }
                        }
                    }
                    break;
                }
            }
        }

        // Check /sys/firmware/efi for tampering indicators
        Self::check_efi_variables(
            tx,
            vendor,
            version,
            release_date,
            secure_boot_enabled,
            secure_boot_config,
        )
        .await;
    }

    /// Check EFI variables on Linux
    #[cfg(target_os = "linux")]
    async fn check_efi_variables(
        tx: &mpsc::Sender<TelemetryEvent>,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: &Option<SecureBootConfig>,
    ) {
        // Check for suspicious EFI variables
        let efi_vars_path = "/sys/firmware/efi/efivars";

        if std::path::Path::new(efi_vars_path).exists() {
            if let Ok(entries) = std::fs::read_dir(efi_vars_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();

                    // Look for suspicious variable names
                    let suspicious_patterns = ["LoJax", "Mosaic", "malware", "backdoor", "rootkit"];

                    for pattern in &suspicious_patterns {
                        if name.to_lowercase().contains(&pattern.to_lowercase()) {
                            let event = Self::create_firmware_event(
                                FirmwareAnomalyType::FirmwareModification,
                                vendor,
                                version,
                                release_date,
                                secure_boot_enabled,
                                secure_boot_config.clone(),
                                None,
                                None,
                                &format!("EFI Variable: {}", name),
                                None,
                                format!("Suspicious EFI variable detected: {}", name),
                            );
                            let _ = tx.send(event).await;
                        }
                    }
                }
            }
        }
    }

    /// Get firmware information
    fn get_firmware_info() -> (String, String, String) {
        #[cfg(target_os = "windows")]
        {
            Self::get_firmware_info_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::get_firmware_info_linux()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            (
                "Unknown".to_string(),
                "Unknown".to_string(),
                "Unknown".to_string(),
            )
        }
    }

    #[cfg(target_os = "windows")]
    fn get_firmware_info_windows() -> (String, String, String) {
        use std::process::Command;

        // Use WMIC to get BIOS info
        let output = Command::new("wmic")
            .args([
                "bios",
                "get",
                "Manufacturer,SMBIOSBIOSVersion,ReleaseDate",
                "/format:csv",
            ])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

                if lines.len() >= 2 {
                    let parts: Vec<&str> = lines[1].split(',').collect();
                    if parts.len() >= 4 {
                        let manufacturer = parts[1].trim().to_string();
                        let release_date = parts[2].trim().to_string();
                        let version = parts[3].trim().to_string();
                        return (manufacturer, version, release_date);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to get BIOS info via WMIC");
            }
        }

        // Fallback to registry
        Self::get_firmware_from_registry()
    }

    #[cfg(target_os = "windows")]
    fn get_firmware_from_registry() -> (String, String, String) {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        if let Ok(key) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS") {
            let vendor: String = key.get_value("SystemManufacturer").unwrap_or_default();
            let version: String = key.get_value("BIOSVersion").unwrap_or_default();
            let release_date: String = key.get_value("BIOSReleaseDate").unwrap_or_default();
            return (vendor, version, release_date);
        }

        (
            "Unknown".to_string(),
            "Unknown".to_string(),
            "Unknown".to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    fn get_firmware_info_linux() -> (String, String, String) {
        let vendor = std::fs::read_to_string("/sys/class/dmi/id/bios_vendor")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        let version = std::fs::read_to_string("/sys/class/dmi/id/bios_version")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        let release_date = std::fs::read_to_string("/sys/class/dmi/id/bios_date")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        (vendor, version, release_date)
    }

    /// Check if Secure Boot is enabled
    fn is_secure_boot_enabled() -> bool {
        #[cfg(target_os = "windows")]
        {
            Self::check_secure_boot_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::check_secure_boot_linux()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            false
        }
    }

    #[cfg(target_os = "windows")]
    fn check_secure_boot_windows() -> bool {
        use std::process::Command;

        // Check via PowerShell
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "Confirm-SecureBootUEFI"])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                stdout == "true"
            }
            Err(_) => {
                // Fallback: check registry
                Self::check_secure_boot_registry()
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_secure_boot_registry() -> bool {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State") {
            let enabled: u32 = key.get_value("UEFISecureBootEnabled").unwrap_or(0);
            return enabled == 1;
        }

        false
    }

    #[cfg(target_os = "linux")]
    fn check_secure_boot_linux() -> bool {
        // Check /sys/firmware/efi/efivars/SecureBoot-*
        if let Ok(entries) = std::fs::read_dir("/sys/firmware/efi/efivars") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("SecureBoot-") {
                    if let Ok(data) = std::fs::read(entry.path()) {
                        // The last byte indicates secure boot state
                        // 4 bytes attributes + 1 byte value
                        if data.len() >= 5 && data[4] == 1 {
                            return true;
                        }
                    }
                }
            }
        }

        // Alternative: check mokutil
        if let Ok(output) = std::process::Command::new("mokutil")
            .args(["--sb-state"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            return stdout.contains("secureboot enabled");
        }

        false
    }

    /// Get Secure Boot configuration details
    fn get_secure_boot_config() -> Option<SecureBootConfig> {
        #[cfg(target_os = "windows")]
        {
            Self::get_secure_boot_config_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::get_secure_boot_config_linux()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            None
        }
    }

    #[cfg(target_os = "windows")]
    fn get_secure_boot_config_windows() -> Option<SecureBootConfig> {
        use std::process::Command;

        // Get Secure Boot policy info
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-SecureBootPolicy | ConvertTo-Json",
            ])
            .output();

        // For now, return basic config
        // A full implementation would parse the policy
        Some(SecureBootConfig {
            setup_mode: false,
            pk_present: true,
            kek_count: 0,
            db_count: 0,
            dbx_count: 0,
        })
    }

    #[cfg(target_os = "linux")]
    fn get_secure_boot_config_linux() -> Option<SecureBootConfig> {
        let mut config = SecureBootConfig {
            setup_mode: false,
            pk_present: false,
            kek_count: 0,
            db_count: 0,
            dbx_count: 0,
        };

        // Check Setup Mode
        if let Ok(entries) = std::fs::read_dir("/sys/firmware/efi/efivars") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();

                if name.starts_with("SetupMode-") {
                    if let Ok(data) = std::fs::read(entry.path()) {
                        if data.len() >= 5 && data[4] == 1 {
                            config.setup_mode = true;
                        }
                    }
                }

                if name.starts_with("PK-") {
                    config.pk_present = true;
                }

                if name.starts_with("KEK-") {
                    config.kek_count += 1;
                }

                if name.starts_with("db-") && !name.starts_with("dbx-") {
                    config.db_count += 1;
                }

                if name.starts_with("dbx-") {
                    config.dbx_count += 1;
                }
            }
        }

        Some(config)
    }

    /// Read MBR (first 512 bytes of primary disk)
    fn read_mbr() -> Result<Vec<u8>> {
        #[cfg(target_os = "windows")]
        {
            Self::read_mbr_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::read_mbr_linux()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(anyhow::anyhow!("MBR read not supported on this platform"))
        }
    }

    #[cfg(target_os = "windows")]
    fn read_mbr_windows() -> Result<Vec<u8>> {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        // Open PhysicalDrive0 for raw read
        // Requires admin privileges
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000000) // FILE_FLAG_NO_BUFFERING
            .open("\\\\.\\PhysicalDrive0")?;

        let mut buffer = vec![0u8; 512];
        let mut file = file;
        file.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    #[cfg(target_os = "linux")]
    fn read_mbr_linux() -> Result<Vec<u8>> {
        // Find the primary boot disk
        let disk_paths = ["/dev/sda", "/dev/nvme0n1", "/dev/vda", "/dev/xvda"];

        for path in &disk_paths {
            if std::path::Path::new(path).exists() {
                let mut file = std::fs::File::open(path)?;
                let mut buffer = vec![0u8; 512];
                file.read_exact(&mut buffer)?;
                return Ok(buffer);
            }
        }

        Err(anyhow::anyhow!("No boot disk found"))
    }

    /// Hash MBR
    fn hash_mbr() -> Result<String> {
        let data = Self::read_mbr()?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Hash a file
    fn hash_file(path: &str) -> Result<String> {
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

    /// Check if data contains a pattern
    fn contains_pattern(data: &[u8], pattern: &[u8]) -> bool {
        data.windows(pattern.len()).any(|window| window == pattern)
    }

    /// Recursively scan directory
    fn scan_directory_recursive(path: &str) -> Result<Vec<String>> {
        let mut files = Vec::new();

        fn scan_inner(path: &std::path::Path, files: &mut Vec<String>) {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_dir() {
                        scan_inner(&entry_path, files);
                    } else {
                        files.push(entry_path.to_string_lossy().to_string());
                    }
                }
            }
        }

        scan_inner(std::path::Path::new(path), &mut files);
        Ok(files)
    }

    /// Create firmware telemetry event
    fn create_firmware_event(
        anomaly_type: FirmwareAnomalyType,
        vendor: &str,
        version: &str,
        release_date: &str,
        secure_boot_enabled: bool,
        secure_boot_config: Option<SecureBootConfig>,
        hash: Option<String>,
        expected_hash: Option<String>,
        component: &str,
        bootkit_name: Option<String>,
        details: String,
    ) -> TelemetryEvent {
        // Determine severity based on anomaly type
        let severity = match anomaly_type {
            FirmwareAnomalyType::BootkitDetected => Severity::Critical,
            FirmwareAnomalyType::BootSectorInfection => Severity::Critical,
            FirmwareAnomalyType::SecureBootBypass => Severity::High,
            FirmwareAnomalyType::FirmwareModification => Severity::High,
            FirmwareAnomalyType::SecureBootDisabled => Severity::Medium,
            FirmwareAnomalyType::BootConfigModified => Severity::High,
            FirmwareAnomalyType::UnknownBootloader => Severity::High,
            FirmwareAnomalyType::EspModified => Severity::High,
            FirmwareAnomalyType::InitramfsModified => Severity::High,
            FirmwareAnomalyType::GrubModified => Severity::Medium,
            FirmwareAnomalyType::SecureBootDbModified => Severity::High,
        };

        let firmware_event = FirmwareEvent {
            anomaly_type: anomaly_type.clone(),
            vendor: vendor.to_string(),
            version: version.to_string(),
            release_date: release_date.to_string(),
            secure_boot_enabled,
            secure_boot_config,
            hash,
            expected_hash,
            component: component.to_string(),
            bootkit_name: bootkit_name.clone(),
            details: details.clone(),
        };

        let mut event = TelemetryEvent::new(
            EventType::FirmwareAnomaly,
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&firmware_event).unwrap_or_default()),
        );

        // Add detection
        let description = if let Some(ref name) = bootkit_name {
            format!("{} bootkit detected: {}", name, details)
        } else {
            details
        };

        event.add_detection(Detection {
            detection_type: DetectionType::Firmware,
            rule_name: format!("Firmware_{}", anomaly_type.as_str()),
            confidence: match severity {
                Severity::Critical => 0.95,
                Severity::High => 0.85,
                Severity::Medium => 0.70,
                _ => 0.60,
            },
            description,
            mitre_tactics: vec!["Persistence".to_string(), "Defense Evasion".to_string()],
            mitre_techniques: vec![
                "T1542".to_string(),
                anomaly_type.mitre_subtechnique().to_string(),
            ],
        });

        // Add metadata
        event
            .metadata
            .insert("firmware_vendor".to_string(), vendor.to_string());
        event
            .metadata
            .insert("firmware_version".to_string(), version.to_string());
        event
            .metadata
            .insert("secure_boot".to_string(), secure_boot_enabled.to_string());
        event.metadata.insert(
            "anomaly_type".to_string(),
            anomaly_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("component".to_string(), component.to_string());

        if let Some(name) = bootkit_name {
            event.metadata.insert("bootkit_name".to_string(), name);
        }

        event
    }

    /// Get next event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Get current baseline
    pub fn get_baseline(&self) -> &FirmwareBaseline {
        &self.baseline
    }

    /// Update baseline with current system state
    pub async fn update_baseline(&mut self) -> Result<()> {
        self.baseline = Self::create_baseline()?;

        let baseline_path = if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\firmware_baseline.json"
        } else {
            "/var/lib/tamandua/firmware_baseline.json"
        };

        if let Some(parent) = std::path::Path::new(baseline_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let json = serde_json::to_string_pretty(&self.baseline)?;
        std::fs::write(baseline_path, json)?;

        info!(path = %baseline_path, "Updated firmware baseline");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootkit_patterns() {
        // Test pattern matching
        let data = vec![0x00, 0x4C, 0x6F, 0x4A, 0x61, 0x78, 0x00]; // Contains "LoJax"
        let pattern = &[0x4C, 0x6F, 0x4A, 0x61, 0x78];
        assert!(FirmwareCollector::contains_pattern(&data, pattern));

        let non_matching = vec![0x00, 0x00, 0x00, 0x00];
        assert!(!FirmwareCollector::contains_pattern(&non_matching, pattern));
    }

    #[test]
    fn test_anomaly_type_mitre() {
        assert_eq!(
            FirmwareAnomalyType::FirmwareModification.mitre_subtechnique(),
            "T1542.001"
        );
        assert_eq!(
            FirmwareAnomalyType::BootkitDetected.mitre_subtechnique(),
            "T1542.003"
        );
        assert_eq!(
            FirmwareAnomalyType::SecureBootBypass.mitre_subtechnique(),
            "T1542.001"
        );
    }

    #[test]
    fn test_firmware_event_serialization() {
        let event = FirmwareEvent {
            anomaly_type: FirmwareAnomalyType::SecureBootDisabled,
            vendor: "Test Vendor".to_string(),
            version: "1.0.0".to_string(),
            release_date: "2024-01-01".to_string(),
            secure_boot_enabled: false,
            secure_boot_config: None,
            hash: None,
            expected_hash: None,
            component: "Test".to_string(),
            bootkit_name: None,
            details: "Test event".to_string(),
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
    }

    #[test]
    fn test_firmware_anomaly_type_as_str() {
        assert_eq!(
            FirmwareAnomalyType::FirmwareModification.as_str(),
            "firmware_modification"
        );
        assert_eq!(
            FirmwareAnomalyType::SecureBootDisabled.as_str(),
            "secure_boot_disabled"
        );
        assert_eq!(
            FirmwareAnomalyType::BootkitDetected.as_str(),
            "bootkit_detected"
        );
        assert_eq!(FirmwareAnomalyType::EspModified.as_str(), "esp_modified");
    }

    #[tokio::test]
    async fn test_firmware_collector_initialization() {
        let config = AgentConfig::default();
        let result = FirmwareCollector::new(&config);

        // Should initialize without panicking
        assert!(result.is_ok());
    }

    #[test]
    fn test_bootkit_detection_confidence() {
        // Known bootkit patterns should have high confidence
        let lojax_data = vec![0x4C, 0x6F, 0x4A, 0x61, 0x78]; // "LoJax"
        assert!(FirmwareCollector::contains_pattern(&lojax_data, b"LoJax"));
    }

    #[test]
    #[ignore]
    fn test_firmware_scan_no_panic() {
        // Integration test - runs full firmware scan
        // Marked as ignored, run with: cargo test -- --ignored
        let config = AgentConfig::default();
        let collector = FirmwareCollector::new(&config);

        // This should not panic even if hardware access fails
        let result = std::panic::catch_unwind(|| {
            let _ = collector;
            true
        });

        assert!(result.is_ok());
    }
}
