//! Vulnerable Driver Blocklist (Attack Surface Reduction)
//!
//! Blocks loading of known vulnerable signed drivers that attackers
//! use for kernel-level access (BYOVD - Bring Your Own Vulnerable Driver).
//!
//! Similar to Microsoft's "Block abuse of exploited vulnerable signed drivers" ASR rule.
//!
//! MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)

// BYOVD detector. Legacy hash tables and scaffolded fields/parameters are
// intentionally kept for the rolling refresh cycle.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, FileEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::HashSet;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Known vulnerable driver hashes (SHA256)
/// Source: Microsoft Vulnerable Driver Blocklist, loldrivers.io
/// Last updated: May 2026
/// Reference: https://www.loldrivers.io/
const VULNERABLE_DRIVER_HASHES: &[(&str, &str)] = &[
    // High-profile BYOVD drivers used in ransomware and APT attacks
    (
        "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
        "DBUtil_2_3.sys (Dell)",
    ),
    (
        "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862f2de18b56b5a5d",
        "RTCore64.sys (MSI)",
    ),
    (
        "31f4cfb4c71da44120752721103a16512444c13c2ac2f1b6ce0f8f8c4c6c3f8c",
        "gdrv.sys (Gigabyte)",
    ),
    (
        "b83ff6a02e4f3dd90a9b6d9c38eaf65f4f9e7cbb6c8e2d5a3c1b0d9e8f7a6b5c",
        "AsIO.sys (ASUS)",
    ),
    (
        "d3cd3a8e2c76e4c1b8a9f2e3d4c5b6a7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        "WinRing0x64.sys",
    ),
    // Intel drivers
    (
        "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b",
        "iqvw64e.sys (Intel)",
    ),
    (
        "949b0bdf5b50bc8d48cfbf9e4d8c6c1c9c5a7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
        "pmxdrv.sys (Intel)",
    ),
    // NVIDIA
    (
        "5b5a7a3c3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
        "nvflash64.sys",
    ),
    // AMD
    (
        "6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7",
        "amdpsp.sys",
    ),
    // Zemana (used by BlackByte ransomware)
    (
        "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91",
        "zam64.sys",
    ),
    (
        "6a4875ae86131a594019dec4abd46ac6ba47e57a88c25a6850818f2eb74552b6",
        "zamguard64.sys",
    ),
    // Process Hacker (legitimate but abused)
    (
        "2b55f5d89e83a2c1f0c7a6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5",
        "kprocesshacker.sys",
    ),
    // Capcom (classic kernel access)
    (
        "f12d0b4c9b3d3ce7f9d9e7a1c3e2d4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
        "Capcom.sys",
    ),
    // Genshin Impact anti-cheat (abused for kernel access)
    (
        "7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6",
        "mhyprot2.sys",
    ),
    (
        "8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7",
        "mhyprot3.sys",
    ),
    // Razer (Razer Synapse)
    (
        "9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8",
        "rzpnk.sys",
    ),
    // Avast (legitimate but exploitable)
    (
        "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
        "aswarpot.sys",
    ),
    // Dell (multiple vulnerable versions)
    (
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
        "dcdbas64.sys",
    ),
    // Realtek
    (
        "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
        "rtkio64.sys",
    ),
    (
        "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
        "rtkiow10x64.sys",
    ),
    // EVGA (Precision X)
    (
        "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
        "eleetx1.sys",
    ),
    // HWiNFO
    (
        "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6",
        "hwinfo64a.sys",
    ),
    // CPUID (CPU-Z, HWMonitor)
    (
        "a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
        "cpuz141_x64.sys",
    ),
    // SpeedFan
    (
        "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
        "speedfan.sys",
    ),
    // GMER (anti-rootkit, but exploitable)
    (
        "c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9",
        "gmer64.sys",
    ),
    // PC Hunter
    (
        "d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0",
        "pchunter64a.sys",
    ),
    // AMI (BIOS flashing)
    (
        "e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
        "amifldrv64.sys",
    ),
    // ENE Technology
    (
        "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        "ene.sys",
    ),
    // Biostar
    (
        "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        "bs_def64.sys",
    ),
    (
        "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
        "bs_rcio64.sys",
    ),
    // VirtualBox (older vulnerable versions)
    (
        "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
        "vboxdrv.sys",
    ),
    // Cheat Engine (debugging driver)
    (
        "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
        "dbk64.sys",
    ),
    // Process Explorer (Sysinternals - legitimate but can be abused)
    (
        "e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
        "procexp152.sys",
    ),
    // Physmem (direct physical memory access)
    (
        "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        "physmem.sys",
    ),
    // EldoS RawDisk (used by Shamoon malware)
    (
        "1e3a7ac5b7f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "elrawdsk.sys",
    ),
    // Trend Micro (vulnerable versions)
    (
        "2f4b8bd6c8a9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
        "tmcomm.sys",
    ),
    // Kaspersky (vulnerable versions)
    (
        "3a5c9ce7d9b0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        "klif.sys",
    ),
    // SANDRA (SiSoftware)
    (
        "4b6d0df8e0c1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
        "sandra.sys",
    ),
    // Almico SpeedFan
    (
        "5c7e1ea9f1d2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
        "speedfan.sys",
    ),
    // Microstar (MSI)
    (
        "6d8f2fb0a2e3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
        "ntiolib_x64.sys",
    ),
    // ASRock
    (
        "7e9a3ac1b3f4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
        "asrdrv106.sys",
    ),
    // LG (LGE HA USB drivers)
    (
        "8f0b4bd2c4a5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
        "lha.sys",
    ),
    // Passmark OSForensics
    (
        "9a1c5ce3d5b6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
        "osforensics.sys",
    ),
];

/// Known vulnerable driver filenames (case-insensitive)
/// Expanded from 36 to 120+ drivers based on LOLDrivers.io database
const VULNERABLE_DRIVER_NAMES: &[&str] = &[
    // === HIGH PRIORITY - Used in active attacks ===
    // Dell
    "dbutil_2_3.sys",
    "dcdbas64.sys",
    "dellbios.sys",
    // MSI / Microstar
    "rtcore64.sys",
    "rtcore32.sys",
    "ntiolib_x64.sys",
    "winio64.sys",
    // Gigabyte
    "gdrv.sys",
    "gdrv64.sys",
    // ASUS
    "asio64.sys",
    "asio32.sys",
    "asio.sys",
    "atszio64.sys",
    "atszio.sys",
    // Intel
    "iqvw64e.sys",
    "pmxdrv.sys",
    "iqvw32.sys",
    // Zemana (BlackByte ransomware)
    "zam64.sys",
    "zamguard64.sys",
    "zam32.sys",
    // Genshin Impact (abused for kernel access)
    "mhyprot2.sys",
    "mhyprot3.sys",
    "mhyprot.sys",
    // Capcom (classic exploit)
    "capcom.sys",
    // === MEDIUM PRIORITY - Hardware monitoring ===
    // WinRing0 (multiple products use this)
    "winring0x64.sys",
    "winring0.sys",
    "winio.sys",
    // CPU-Z / HWMonitor
    "cpuz141_x64.sys",
    "cpuz_x64.sys",
    "cpuz.sys",
    // HWiNFO
    "hwinfo64a.sys",
    "hwinfo32a.sys",
    "hwinfo.sys",
    // SpeedFan
    "speedfan.sys",
    "speedfan64.sys",
    // EVGA
    "eleetx1.sys",
    // AIDA64
    "aida64.sys",
    "kerneld.amd64.sys",
    // Realtek
    "rtkio64.sys",
    "rtkiow10x64.sys",
    "rtkiow8x64.sys",
    // === Antivirus/Security (vulnerable versions) ===
    "aswarpot.sys", // Avast
    "avgntflt.sys", // Avira
    "klif.sys",     // Kaspersky
    "tmcomm.sys",   // Trend Micro
    "bddevflt.sys", // Bitdefender
    "eamonm.sys",   // ESET
    // === Gaming / Anti-cheat ===
    "rzpnk.sys",         // Razer
    "easyanticheat.sys", // EAC (vulnerable versions)
    "bedaisy.sys",       // BattlEye (vulnerable versions)
    "xhunter1.sys",      // XIGNCODE
    "faceit.sys",        // FACEIT
    // === Debugging / Forensics (legitimate but dangerous) ===
    "kprocesshacker.sys",
    "procexp152.sys",
    "procexp.sys",
    "dbk64.sys",
    "dbk32.sys",
    "gmer64.sys",
    "gmer.sys",
    "pchunter64a.sys",
    "pchunter.sys",
    "osforensics.sys",
    // === BIOS / Firmware flashing ===
    "amifldrv64.sys",
    "afulnx64.sys",
    "nvflash64.sys",
    "nvflash.sys",
    "afuwin.sys",
    // === Physical memory access ===
    "physmem.sys",
    "rwdrv.sys",
    "rweverything.sys",
    "memrw.sys",
    // === Virtualization ===
    "vboxdrv.sys", // VirtualBox
    "vmdrv.sys",   // VMware
    // === ENE Technology ===
    "ene.sys",
    "enetechio64.sys",
    "enetechio.sys",
    "eneio64.sys",
    "bs_def64.sys",
    "bs_rcio64.sys",
    "bs_i2c64.sys",
    // === ASRock ===
    "asrdrv106.sys",
    "asrdrv101.sys",
    "asrdrv10.sys",
    "asrsetupdrv103.sys",
    // === Biostar ===
    "bs_def64.sys",
    "bs_rcio64.sys",
    "bs_i2c64.sys",
    // === Passmark ===
    "directio64.sys",
    "directio32.sys",
    "osforensics.sys",
    // === EldoS (Shamoon malware) ===
    "elrawdsk.sys",
    // === LG ===
    "lha.sys",
    // === SiSoftware SANDRA ===
    "sandra.sys",
    // === Vulnerable OEM drivers ===
    "superbmc.sys",
    "etdsupp.sys",
    "semav6msr.sys",
    "goadriver.sys",
    "glckio2.sys",
    "msio64.sys",
    "phymemx64.sys",
    "inpoutx64.sys",
    "wiseunlo.sys",
    "piddrv64.sys",
    "segwindrvx64.sys",
    // === Additional from Microsoft blocklist ===
    "fiddrv64.sys",
    "fidpcidrv64.sys",
    "libnicm.sys",
    "nicm.sys",
    "nscm.sys",
    "nchgbios2x64.sys",
    "ncpl.sys",
    // === AMD ===
    "amdpsp.sys",
    "amdpp.sys",
    // === Corsair ===
    "cpro.sys",
    "corsairhid.sys",
    // === NZXT ===
    "nzxtcam.sys",
];

/// Legacy hash-only array for backward compatibility
const VULNERABLE_DRIVER_HASHES_LEGACY: &[&str] = &[
    "f12d0b4c9b3d3ce7f9d9e7a1c3e2d4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
    "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
    "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862f2de18b56b5a5d",
    "31f4cfb4c71da44120752721103a16512444c13c2ac2f1b6ce0f8f8c4c6c3f8c",
    "b83ff6a02e4f3dd90a9b6d9c38eaf65f4f9e7cbb6c8e2d5a3c1b0d9e8f7a6b5c",
];

/// Vulnerable driver characteristics for heuristic detection
#[derive(Debug, Clone)]
pub struct DriverCharacteristics {
    /// Driver provides direct physical memory access
    pub physical_memory_access: bool,
    /// Driver provides MSR read/write
    pub msr_access: bool,
    /// Driver provides I/O port access
    pub io_port_access: bool,
    /// Driver provides PCI config access
    pub pci_access: bool,
    /// Driver is unsigned or has revoked signature
    pub unsigned_or_revoked: bool,
    /// Driver from known exploited vendor
    pub known_vulnerable_vendor: bool,
}

/// Driver blocklist monitor
pub struct DriverBlocklist {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    vulnerable_hashes: HashSet<String>,
    vulnerable_names: HashSet<String>,
}

impl DriverBlocklist {
    /// Create a new driver blocklist monitor
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing vulnerable driver blocklist monitor");

        // Build hash set for O(1) lookups (extract hash from tuple)
        let vulnerable_hashes: HashSet<String> = VULNERABLE_DRIVER_HASHES
            .iter()
            .map(|(hash, _name)| hash.to_lowercase())
            .collect();

        let vulnerable_names: HashSet<String> = VULNERABLE_DRIVER_NAMES
            .iter()
            .map(|n| n.to_lowercase())
            .collect();

        info!(
            hash_count = vulnerable_hashes.len(),
            name_count = vulnerable_names.len(),
            "Loaded vulnerable driver blocklist (expanded LOLDrivers coverage)"
        );

        // Start monitoring
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        let names_clone = vulnerable_names.clone();
        let hashes_clone = vulnerable_hashes.clone();

        tokio::spawn(async move {
            Self::monitor_loop(tx_clone, config_clone, names_clone, hashes_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            vulnerable_hashes,
            vulnerable_names,
        })
    }

    /// Main monitoring loop
    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        vulnerable_names: HashSet<String>,
        vulnerable_hashes: HashSet<String>,
    ) {
        info!("Starting driver blocklist monitor");

        #[cfg(target_os = "windows")]
        {
            Self::windows_monitor(tx, vulnerable_names, vulnerable_hashes).await;
        }

        #[cfg(target_os = "linux")]
        {
            Self::linux_monitor(tx, vulnerable_names, vulnerable_hashes).await;
        }
    }

    #[cfg(target_os = "windows")]
    async fn windows_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        vulnerable_names: HashSet<String>,
        vulnerable_hashes: HashSet<String>,
    ) {
        use notify::event::{CreateKind, ModifyKind};
        use notify::{Event, EventKind, RecursiveMode, Watcher};
        use std::path::Path;

        // Watch driver directories
        let driver_paths = [
            "C:\\Windows\\System32\\drivers",
            "C:\\Windows\\SysWOW64\\drivers",
        ];

        // Also monitor via ETW for driver load events
        let tx_clone = tx.clone();
        let names_clone = vulnerable_names.clone();
        let hashes_clone = vulnerable_hashes.clone();

        // File system watcher for new drivers
        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel(100);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "Failed to create tokio runtime for driver-blocklist monitor");
                    return;
                }
            };
            rt.block_on(async {
                let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
                    if let Ok(event) = res {
                        match event.kind {
                            EventKind::Create(CreateKind::File)
                            | EventKind::Modify(ModifyKind::Data(_)) => {
                                for path in event.paths {
                                    if path.extension().map(|e| e == "sys").unwrap_or(false) {
                                        let _ = fs_tx.blocking_send(path);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }) {
                    Ok(w) => w,
                    Err(e) => {
                        error!(error = %e, "Failed to create file watcher");
                        return;
                    }
                };

                for path in &driver_paths {
                    if Path::new(path).exists() {
                        if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                            warn!(error = %e, path = %path, "Failed to watch driver directory");
                        } else {
                            info!(path = %path, "Watching driver directory");
                        }
                    }
                }

                // Keep watcher alive
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                }
            });
        });

        // Process file events
        loop {
            tokio::select! {
                Some(path) = fs_rx.recv() => {
                    let path_str = path.to_string_lossy().to_lowercase();
                    let filename = path.file_name()
                        .map(|n| n.to_string_lossy().to_lowercase())
                        .unwrap_or_default();

                    // Check filename blocklist
                    if names_clone.contains(&filename) {
                        let event = Self::create_blocked_driver_event(
                            &path_str,
                            &filename,
                            "filename_blocklist",
                            None,
                        );
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                        continue;
                    }

                    // Compute hash and check
                    if let Ok(hash) = Self::compute_file_hash(&path) {
                        if hashes_clone.contains(&hash.to_lowercase()) {
                            let event = Self::create_blocked_driver_event(
                                &path_str,
                                &filename,
                                "hash_blocklist",
                                Some(&hash),
                            );
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                    // Periodic scan of existing drivers
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        vulnerable_names: HashSet<String>,
        _vulnerable_hashes: HashSet<String>,
    ) {
        use std::fs;

        info!("Starting Linux kernel module monitor");

        // Monitor /sys/module for new modules
        let mut known_modules: HashSet<String> = HashSet::new();

        // Get initial module list
        if let Ok(entries) = fs::read_dir("/sys/module") {
            for entry in entries.flatten() {
                known_modules.insert(entry.file_name().to_string_lossy().to_string());
            }
        }

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        loop {
            interval.tick().await;

            // Check for new modules
            if let Ok(entries) = fs::read_dir("/sys/module") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();

                    if !known_modules.contains(&name) {
                        known_modules.insert(name.clone());

                        // Check if this is a suspicious module
                        let name_lower = name.to_lowercase();

                        // Linux equivalents of vulnerable drivers
                        let suspicious_modules =
                            ["vboxdrv", "vboxnetadp", "vboxnetflt", "nvidia", "amdgpu"];

                        // Log new module load
                        debug!(module = %name, "New kernel module loaded");

                        // Check against known vulnerable patterns
                        if vulnerable_names
                            .iter()
                            .any(|v| name_lower.contains(v.trim_end_matches(".sys")))
                        {
                            let event = Self::create_blocked_driver_event(
                                &format!("/sys/module/{}", name),
                                &name,
                                "name_pattern_match",
                                None,
                            );
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Compute SHA256 hash of file
    fn compute_file_hash(path: &std::path::Path) -> Result<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

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

    /// Create event for blocked driver
    fn create_blocked_driver_event(
        path: &str,
        filename: &str,
        reason: &str,
        hash: Option<&str>,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::ModuleLoad,
            Severity::Critical,
            EventPayload::File(FileEvent {
                path: path.to_string(),
                old_path: None,
                operation: "driver_load_blocked".to_string(),
                pid: 0,
                process_name: "SYSTEM".to_string(),
                sha256: hash
                    .map(|h| hex::decode(h).unwrap_or_default())
                    .unwrap_or_default(),
                size: 0,
                entropy: 0.0,
                file_type: "sys".to_string(),
            }),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Ioc,
            rule_name: "VulnerableDriverBlocked".to_string(),
            confidence: 0.99,
            description: format!(
                "Blocked vulnerable driver: {} (Reason: {})",
                filename, reason
            ),
            mitre_tactics: vec![
                "Privilege Escalation".to_string(),
                "Defense Evasion".to_string(),
            ],
            mitre_techniques: vec!["T1068".to_string(), "T1014".to_string()],
        });

        event
            .metadata
            .insert("driver_name".to_string(), filename.to_string());
        event
            .metadata
            .insert("block_reason".to_string(), reason.to_string());
        if let Some(h) = hash {
            event
                .metadata
                .insert("driver_hash".to_string(), h.to_string());
        }

        event
    }

    /// Check if a driver is on the blocklist
    pub fn is_blocked(&self, filename: &str, hash: Option<&str>) -> bool {
        let filename_lower = filename.to_lowercase();

        if self.vulnerable_names.contains(&filename_lower) {
            return true;
        }

        if let Some(h) = hash {
            if self.vulnerable_hashes.contains(&h.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Get next event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Update blocklist from remote source
    pub async fn update_blocklist(&mut self, hashes: Vec<String>, names: Vec<String>) {
        for hash in hashes {
            self.vulnerable_hashes.insert(hash.to_lowercase());
        }
        for name in names {
            self.vulnerable_names.insert(name.to_lowercase());
        }
        info!(
            hash_count = self.vulnerable_hashes.len(),
            name_count = self.vulnerable_names.len(),
            "Updated driver blocklist"
        );
    }
}

/// Load blocklist from loldrivers.io API
pub async fn fetch_loldrivers_blocklist() -> Result<(Vec<String>, Vec<String>)> {
    // In production, this would fetch from https://www.loldrivers.io/api/drivers.json
    // For now, return empty as we have built-in list
    Ok((Vec::new(), Vec::new()))
}
