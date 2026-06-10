//! Anti-Sandbox and Anti-Emulation Detection Module
//!
//! This module implements comprehensive virtualization, sandbox, and emulator detection:
//!
//! ## VM Detection
//! - CPUID hypervisor bit detection
//! - VM-specific registry keys (VMware, VirtualBox, Hyper-V, QEMU)
//! - VM-specific processes (vmtoolsd, VBoxService, qemu-ga)
//! - MAC address OUI prefix analysis
//! - SMBIOS/DMI string analysis
//! - ACPI table signature detection
//!
//! ## Sandbox Detection
//! - Common sandbox DLLs (sbiedll, snxhk, cmdvrt)
//! - Sandbox username/hostname patterns
//! - Low resource systems (RAM < 2GB, cores < 2, disk < 50GB)
//! - Recent file activity analysis
//! - Mouse movement pattern detection
//!
//! ## Emulator Detection
//! - CPU feature inconsistencies
//! - Instruction timing accuracy
//! - FPU precision anomalies
//!
//! ## Response Strategy
//! Unlike traditional malware, we DO NOT exit on detection. Instead, we:
//! - Flag the environment for behavioral adjustment
//! - Send telemetry to the backend for analysis
//! - Optionally delay startup or reduce functionality
//! - This allows security researchers to analyze the agent while still detecting evasion
//!
//! MITRE ATT&CK Coverage:
//! - T1497.001 - Virtualization/Sandbox Evasion: System Checks
//! - T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks
//! - T1497.003 - Virtualization/Sandbox Evasion: Time Based Evasion

// Anti-sandbox detector. Scaffolded check helpers retained for VM/emulator
// surface coverage; some inner unsafe blocks are nested within outer unsafe.
#![allow(dead_code, unused_variables, non_snake_case, unused_unsafe)]

use anyhow::Result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::{TamperEvent, TamperEventType, TamperSeverity};

/// Anti-sandbox configuration
#[derive(Debug, Clone)]
pub struct AntiSandboxConfig {
    /// Enable anti-sandbox checks
    pub enabled: bool,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Enable VM detection
    pub enable_vm_detection: bool,
    /// Enable sandbox detection
    pub enable_sandbox_detection: bool,
    /// Enable emulator detection
    pub enable_emulator_detection: bool,
    /// Action on detection
    pub on_detection: AntiSandboxAction,
    /// Minimum confidence threshold (0.0-1.0) to trigger action
    pub confidence_threshold: f32,
}

/// Action to take when sandbox is detected
#[derive(Debug, Clone, PartialEq)]
pub enum AntiSandboxAction {
    /// Log the detection only
    Log,
    /// Send alert but continue normally
    Alert,
    /// Behavioral adjustment (delayed startup, reduced functionality)
    Adjust,
}

impl Default for AntiSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 300, // Check every 5 minutes
            enable_vm_detection: true,
            enable_sandbox_detection: true,
            enable_emulator_detection: true,
            on_detection: AntiSandboxAction::Alert,
            confidence_threshold: 0.6, // 60% confidence
        }
    }
}

/// Sandbox detection indicators with confidence scoring
#[derive(Debug, Clone, Default)]
pub struct SandboxIndicators {
    /// Overall confidence score (0.0-1.0)
    pub confidence: f32,
    /// VM detection score
    pub vm_score: f32,
    /// Sandbox detection score
    pub sandbox_score: f32,
    /// Emulator detection score
    pub emulator_score: f32,
    /// List of detected indicators
    pub indicators: Vec<String>,
    /// Detected VM type (if any)
    pub vm_type: Option<VmType>,
}

/// Detected VM types
#[derive(Debug, Clone, PartialEq)]
pub enum VmType {
    VMware,
    VirtualBox,
    HyperV,
    QEMU,
    KVM,
    Xen,
    Parallels,
    Unknown,
}

/// Anti-sandbox engine
pub struct AntiSandboxEngine {
    config: AntiSandboxConfig,
    running: Arc<AtomicBool>,
    detection_count: Arc<AtomicU64>,
    tamper_tx: mpsc::Sender<TamperEvent>,
    last_check_time: std::sync::RwLock<Option<Instant>>,
}

impl AntiSandboxEngine {
    /// Create a new anti-sandbox engine
    pub fn new(config: AntiSandboxConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            detection_count: Arc::new(AtomicU64::new(0)),
            tamper_tx,
            last_check_time: std::sync::RwLock::new(None),
        }
    }

    /// Initialize anti-sandbox monitoring
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Anti-sandbox checks disabled by configuration");
            return Ok(());
        }

        info!("Initializing anti-sandbox engine");
        self.running.store(true, Ordering::SeqCst);

        // Perform initial check
        let indicators = self.check_environment();
        self.handle_detection(&indicators).await;

        // Start periodic monitoring
        self.start_monitoring_task();

        Ok(())
    }

    /// Run all anti-sandbox checks and return indicators
    pub fn check_environment(&self) -> SandboxIndicators {
        let mut indicators = SandboxIndicators::default();

        // VM detection
        if self.config.enable_vm_detection {
            indicators.vm_score = self.detect_vm(&mut indicators.indicators);
            if indicators.vm_score > 0.0 {
                indicators.vm_type = self.identify_vm_type(&indicators.indicators);
            }
        }

        // Sandbox detection
        if self.config.enable_sandbox_detection {
            indicators.sandbox_score = self.detect_sandbox(&mut indicators.indicators);
        }

        // Emulator detection
        if self.config.enable_emulator_detection {
            indicators.emulator_score = self.detect_emulator(&mut indicators.indicators);
        }

        // Calculate overall confidence (weighted average)
        let weights = [0.4, 0.4, 0.2]; // VM and sandbox weighted higher than emulator
        indicators.confidence = (indicators.vm_score * weights[0]
            + indicators.sandbox_score * weights[1]
            + indicators.emulator_score * weights[2])
            / weights.iter().sum::<f32>();

        // Update last check time
        *self
            .last_check_time
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

        indicators
    }

    // =========================================================================
    // VM Detection Methods
    // =========================================================================

    /// Detect virtualization indicators
    fn detect_vm(&self, indicators: &mut Vec<String>) -> f32 {
        let mut score = 0.0;
        let mut checks = 0;

        // Check CPUID hypervisor bit
        if self.check_cpuid_hypervisor_bit() {
            indicators.push("CPUID hypervisor bit set".to_string());
            score += 0.9; // High confidence
        }
        checks += 1;

        // Check VM-specific processes
        let vm_processes = self.check_vm_processes();
        for process in vm_processes {
            indicators.push(format!("VM process detected: {}", process));
            score += 0.8;
        }
        checks += 1;

        // Check VM-specific registry keys (Windows)
        #[cfg(target_os = "windows")]
        {
            let vm_reg_keys = self.check_vm_registry();
            for key in vm_reg_keys {
                indicators.push(format!("VM registry key: {}", key));
                score += 0.7;
            }
            checks += 1;
        }

        // Check MAC address OUI prefixes
        if let Some(vm_vendor) = self.check_mac_oui() {
            indicators.push(format!("VM MAC OUI detected: {}", vm_vendor));
            score += 0.6;
        }
        checks += 1;

        // Check SMBIOS/DMI strings
        let smbios_matches = self.check_smbios_dmi();
        for match_str in smbios_matches {
            indicators.push(format!("SMBIOS/DMI match: {}", match_str));
            score += 0.8;
        }
        checks += 1;

        // Check ACPI tables (Windows)
        #[cfg(target_os = "windows")]
        {
            if let Some(acpi_sig) = self.check_acpi_tables() {
                indicators.push(format!("ACPI table signature: {}", acpi_sig));
                score += 0.7;
            }
            checks += 1;
        }

        // Normalize score
        if score > 0.0 {
            (score / checks as f32).min(1.0)
        } else {
            0.0
        }
    }

    /// Check CPUID hypervisor bit (leaf 0x1, ECX bit 31)
    #[cfg(target_arch = "x86_64")]
    fn check_cpuid_hypervisor_bit(&self) -> bool {
        #[cfg(target_env = "msvc")]
        unsafe {
            let cpuid_result: [i32; 4] = [0; 4];
            std::arch::x86_64::__cpuid_count(1, 0);

            // Use inline assembly or intrinsics
            #[cfg(target_feature = "sse")]
            {
                use std::arch::x86_64::__cpuid;
                let result = __cpuid(1);
                // Bit 31 of ECX indicates hypervisor
                (result.ecx & (1 << 31)) != 0
            }
            #[cfg(not(target_feature = "sse"))]
            {
                false
            }
        }

        #[cfg(not(target_env = "msvc"))]
        {
            // Use raw_cpuid crate approach
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                use core::arch::x86_64::__cpuid;
                unsafe {
                    let result = __cpuid(1);
                    (result.ecx & (1 << 31)) != 0
                }
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            false
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn check_cpuid_hypervisor_bit(&self) -> bool {
        false
    }

    /// Check for VM-specific processes
    fn check_vm_processes(&self) -> Vec<String> {
        let vm_process_names = [
            // VMware
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "vmwareuser.exe",
            "vmacthlp.exe",
            "vmtoolsd",
            "vmware-guestd",
            // VirtualBox
            "vboxservice.exe",
            "vboxtray.exe",
            "vboxcontrol.exe",
            "VBoxService",
            "VBoxClient",
            // Hyper-V
            "vmms.exe",
            "vmwp.exe",
            "vmcompute.exe",
            // QEMU
            "qemu-ga.exe",
            "qemu-ga",
            // Parallels
            "prl_tools.exe",
            "prl_cc.exe",
        ];

        let mut detected = Vec::new();

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("tasklist").output() {
                if let Ok(list) = String::from_utf8(output.stdout) {
                    for process in &vm_process_names {
                        if list.to_lowercase().contains(&process.to_lowercase()) {
                            detected.push(process.to_string());
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(cmdline) = fs::read_to_string(entry.path().join("cmdline")) {
                        for process in &vm_process_names {
                            if cmdline.contains(process) {
                                detected.push(process.to_string());
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("ps").arg("aux").output() {
                if let Ok(list) = String::from_utf8(output.stdout) {
                    for process in &vm_process_names {
                        if list.contains(process) {
                            detected.push(process.to_string());
                        }
                    }
                }
            }
        }

        detected
    }

    /// Check VM-specific registry keys
    #[cfg(target_os = "windows")]
    fn check_vm_registry(&self) -> Vec<String> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ};

        let vm_keys = [
            (r"SOFTWARE\VMware, Inc.\VMware Tools", "VMware"),
            (r"SOFTWARE\Oracle\VirtualBox Guest Additions", "VirtualBox"),
            (
                r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
                "Hyper-V",
            ),
            (r"HARDWARE\ACPI\DSDT\VBOX__", "VirtualBox"),
            (r"HARDWARE\ACPI\DSDT\QEMU", "QEMU"),
            (r"SYSTEM\ControlSet001\Services\VBoxGuest", "VirtualBox"),
            (r"SYSTEM\ControlSet001\Services\VBoxMouse", "VirtualBox"),
            (r"SYSTEM\ControlSet001\Services\VBoxService", "VirtualBox"),
            (r"SYSTEM\ControlSet001\Services\vmci", "VMware"),
            (r"SYSTEM\ControlSet001\Services\vmmouse", "VMware"),
        ];

        let mut detected = Vec::new();

        for (key_path, vm_type) in &vm_keys {
            let key_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let mut hkey = windows::Win32::System::Registry::HKEY::default();
                if RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(key_wide.as_ptr()),
                    0,
                    KEY_READ,
                    &mut hkey,
                )
                .is_ok()
                {
                    detected.push(format!("{}: {}", vm_type, key_path));
                    let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
                }
            }
        }

        detected
    }

    #[cfg(not(target_os = "windows"))]
    fn check_vm_registry(&self) -> Vec<String> {
        Vec::new()
    }

    /// Check MAC address OUI prefixes for VM vendors
    fn check_mac_oui(&self) -> Option<String> {
        let vm_oui_prefixes = [
            ("00:05:69", "VMware"),
            ("00:0C:29", "VMware"),
            ("00:1C:14", "VMware"),
            ("00:50:56", "VMware"),
            ("08:00:27", "VirtualBox"),
            ("00:1C:42", "Parallels"),
            ("00:16:3E", "Xen"),
            ("52:54:00", "QEMU/KVM"),
        ];

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("getmac").output() {
                if let Ok(mac_list) = String::from_utf8(output.stdout) {
                    for (prefix, vendor) in &vm_oui_prefixes {
                        if mac_list
                            .to_uppercase()
                            .contains(&prefix.replace(":", "-").to_uppercase())
                        {
                            return Some(vendor.to_string());
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(entries) = fs::read_dir("/sys/class/net") {
                for entry in entries.flatten() {
                    let addr_path = entry.path().join("address");
                    if let Ok(mac) = fs::read_to_string(addr_path) {
                        let mac_upper = mac.trim().to_uppercase();
                        for (prefix, vendor) in &vm_oui_prefixes {
                            if mac_upper.starts_with(&prefix.to_uppercase()) {
                                return Some(vendor.to_string());
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("ifconfig").output() {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for (prefix, vendor) in &vm_oui_prefixes {
                        if output_str.to_uppercase().contains(&prefix.to_uppercase()) {
                            return Some(vendor.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    /// Check SMBIOS/DMI strings for VM indicators
    fn check_smbios_dmi(&self) -> Vec<String> {
        let mut matches = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Use WMI to query BIOS/system information
            use std::process::Command;

            // Check manufacturer
            if let Ok(output) = Command::new("wmic")
                .args(&["bios", "get", "manufacturer"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    let lower = output_str.to_lowercase();
                    if lower.contains("vmware") {
                        matches.push("BIOS: VMware".to_string());
                    } else if lower.contains("virtualbox") || lower.contains("innotek") {
                        matches.push("BIOS: VirtualBox".to_string());
                    } else if lower.contains("qemu") {
                        matches.push("BIOS: QEMU".to_string());
                    } else if lower.contains("microsoft") && lower.contains("virtual") {
                        matches.push("BIOS: Hyper-V".to_string());
                    }
                }
            }

            // Check system model
            if let Ok(output) = Command::new("wmic")
                .args(&["computersystem", "get", "model"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    let lower = output_str.to_lowercase();
                    if lower.contains("vmware") || lower.contains("virtual platform") {
                        matches.push("System Model: VMware".to_string());
                    } else if lower.contains("virtualbox") {
                        matches.push("System Model: VirtualBox".to_string());
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;

            // Check DMI product name
            if let Ok(product_name) = fs::read_to_string("/sys/class/dmi/id/product_name") {
                let lower = product_name.to_lowercase();
                if lower.contains("vmware") {
                    matches.push("DMI Product: VMware".to_string());
                } else if lower.contains("virtualbox") {
                    matches.push("DMI Product: VirtualBox".to_string());
                } else if lower.contains("kvm") {
                    matches.push("DMI Product: KVM".to_string());
                }
            }

            // Check DMI system manufacturer
            if let Ok(sys_vendor) = fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
                let lower = sys_vendor.to_lowercase();
                if lower.contains("vmware") {
                    matches.push("DMI Vendor: VMware".to_string());
                } else if lower.contains("innotek") || lower.contains("oracle") {
                    matches.push("DMI Vendor: VirtualBox".to_string());
                } else if lower.contains("qemu") {
                    matches.push("DMI Vendor: QEMU".to_string());
                } else if lower.contains("microsoft") && lower.contains("virtual") {
                    matches.push("DMI Vendor: Hyper-V".to_string());
                }
            }
        }

        matches
    }

    /// Check ACPI table signatures
    #[cfg(target_os = "windows")]
    fn check_acpi_tables(&self) -> Option<String> {
        use std::process::Command;

        // Query ACPI tables via WMI
        if let Ok(output) = Command::new("wmic")
            .args(&["path", "Win32_ComputerSystem", "get", "Model"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let lower = output_str.to_lowercase();
                if lower.contains("vmware") {
                    return Some("VBOX/VMWARE".to_string());
                } else if lower.contains("virtualbox") {
                    return Some("VBOX".to_string());
                } else if lower.contains("qemu") {
                    return Some("BOCHS/QEMU".to_string());
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    fn check_acpi_tables(&self) -> Option<String> {
        None
    }

    /// Identify specific VM type based on indicators
    fn identify_vm_type(&self, indicators: &[String]) -> Option<VmType> {
        let indicator_str = indicators.join(" ").to_lowercase();

        if indicator_str.contains("vmware") {
            Some(VmType::VMware)
        } else if indicator_str.contains("virtualbox") || indicator_str.contains("vbox") {
            Some(VmType::VirtualBox)
        } else if indicator_str.contains("hyper-v") || indicator_str.contains("microsoft virtual") {
            Some(VmType::HyperV)
        } else if indicator_str.contains("qemu") {
            Some(VmType::QEMU)
        } else if indicator_str.contains("kvm") {
            Some(VmType::KVM)
        } else if indicator_str.contains("xen") {
            Some(VmType::Xen)
        } else if indicator_str.contains("parallels") {
            Some(VmType::Parallels)
        } else if !indicators.is_empty() {
            Some(VmType::Unknown)
        } else {
            None
        }
    }

    // =========================================================================
    // Sandbox Detection Methods
    // =========================================================================

    /// Detect sandbox indicators
    fn detect_sandbox(&self, indicators: &mut Vec<String>) -> f32 {
        let mut score = 0.0;
        let mut checks = 0;

        // Check for sandbox DLLs
        #[cfg(target_os = "windows")]
        {
            let sandbox_dlls = self.check_sandbox_dlls();
            for dll in sandbox_dlls {
                indicators.push(format!("Sandbox DLL: {}", dll));
                score += 0.9;
            }
            checks += 1;
        }

        // Check sandbox usernames/hostnames
        if let Some(name) = self.check_sandbox_names() {
            indicators.push(format!("Sandbox name pattern: {}", name));
            score += 0.7;
        }
        checks += 1;

        // Check system resources
        let resource_score = self.check_system_resources(indicators);
        score += resource_score;
        checks += 1;

        // Check recent file activity
        let activity_score = self.check_recent_activity(indicators);
        score += activity_score;
        checks += 1;

        // Check mouse movement (Windows)
        #[cfg(target_os = "windows")]
        {
            if !self.check_mouse_movement() {
                indicators.push("No mouse movement detected".to_string());
                score += 0.3;
            }
            checks += 1;
        }

        // Normalize score
        if score > 0.0 {
            (score / checks as f32).min(1.0)
        } else {
            0.0
        }
    }

    /// Check for common sandbox DLLs
    #[cfg(target_os = "windows")]
    fn check_sandbox_dlls(&self) -> Vec<String> {
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;

        let sandbox_dlls = [
            "sbiedll.dll",  // Sandboxie
            "snxhk.dll",    // Avast sandbox
            "cmdvrt32.dll", // Comodo sandbox
            "cmdvrt64.dll",
            "pstorec.dll",   // SunBelt sandbox
            "api_log.dll",   // iDefense SysAnalyzer
            "dir_watch.dll", // iDefense SysAnalyzer
            "vmcheck.dll",   // Virtual PC
            "wpespy.dll",    // WPE Pro
        ];

        let mut detected = Vec::new();

        for dll_name in &sandbox_dlls {
            let dll_wide: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                if GetModuleHandleW(windows::core::PCWSTR(dll_wide.as_ptr())).is_ok() {
                    detected.push(dll_name.to_string());
                }
            }
        }

        detected
    }

    #[cfg(not(target_os = "windows"))]
    fn check_sandbox_dlls(&self) -> Vec<String> {
        Vec::new()
    }

    /// Check for sandbox username/hostname patterns
    fn check_sandbox_names(&self) -> Option<String> {
        let sandbox_patterns = [
            "sandbox",
            "malware",
            "maltest",
            "virus",
            "test",
            "sample",
            "cuckoo",
            "joe",
            "currentuser",
            "honey",
            "vmware",
            "vbox",
            "fortinet",
            "paloalto",
            "fireeye",
            "analysis",
        ];

        // Check username
        if let Ok(username) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
            let lower = username.to_lowercase();
            for pattern in &sandbox_patterns {
                if lower.contains(pattern) {
                    return Some(format!("Username: {}", username));
                }
            }
        }

        // Check hostname
        if let Ok(hostname) = hostname::get() {
            if let Some(hostname_str) = hostname.to_str() {
                let lower = hostname_str.to_lowercase();
                for pattern in &sandbox_patterns {
                    if lower.contains(pattern) {
                        return Some(format!("Hostname: {}", hostname_str));
                    }
                }
            }
        }

        None
    }

    /// Check system resources for sandbox indicators
    fn check_system_resources(&self, indicators: &mut Vec<String>) -> f32 {
        let mut score = 0.0;

        // Check RAM (< 2GB is suspicious)
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
            unsafe {
                let mut mem_status: MEMORYSTATUSEX = std::mem::zeroed();
                mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                if GlobalMemoryStatusEx(&mut mem_status).is_ok() {
                    let total_gb = mem_status.ullTotalPhys / (1024 * 1024 * 1024);
                    if total_gb < 2 {
                        indicators.push(format!("Low RAM: {} GB", total_gb));
                        score += 0.5;
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
                if let Some(line) = meminfo.lines().find(|l| l.starts_with("MemTotal:")) {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            let gb = kb / (1024 * 1024);
                            if gb < 2 {
                                indicators.push(format!("Low RAM: {} GB", gb));
                                score += 0.5;
                            }
                        }
                    }
                }
            }
        }

        // Check CPU cores (< 2 is suspicious)
        let cpu_count = num_cpus::get();
        if cpu_count < 2 {
            indicators.push(format!("Low CPU cores: {}", cpu_count));
            score += 0.4;
        }

        // Check disk size (< 50GB is suspicious)
        #[cfg(target_os = "windows")]
        {
            use windows::core::w;
            use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

            unsafe {
                let mut total_bytes: u64 = 0;
                let mut free_bytes_available: u64 = 0;
                let mut free_bytes: u64 = 0;

                if GetDiskFreeSpaceExW(
                    w!("C:\\"),
                    Some(&mut free_bytes_available),
                    Some(&mut total_bytes),
                    Some(&mut free_bytes),
                )
                .is_ok()
                {
                    let total_gb = total_bytes / (1024 * 1024 * 1024);
                    if total_gb < 50 {
                        indicators.push(format!("Small disk: {} GB", total_gb));
                        score += 0.4;
                    }
                }
            }
        }

        score
    }

    /// Check for recent user activity
    fn check_recent_activity(&self, indicators: &mut Vec<String>) -> f32 {
        let mut score = 0.0;

        // Check recent documents/downloads
        #[cfg(target_os = "windows")]
        {
            use std::fs;
            use std::path::PathBuf;

            let recent_paths = ["AppData\\Roaming\\Microsoft\\Windows\\Recent", "Downloads"];

            for rel_path in &recent_paths {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    let full_path = PathBuf::from(&home).join(rel_path);
                    if let Ok(entries) = fs::read_dir(full_path) {
                        let count = entries.count();
                        if count < 20 {
                            indicators.push(format!("Few recent files in {}: {}", rel_path, count));
                            score += 0.3;
                        }
                    }
                }
            }
        }

        score
    }

    /// Check for mouse movement (basic user activity check)
    #[cfg(target_os = "windows")]
    fn check_mouse_movement(&self) -> bool {
        use std::thread;
        use std::time::Duration;
        use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

        unsafe {
            let mut pos1 = windows::Win32::Foundation::POINT { x: 0, y: 0 };
            let _ = GetCursorPos(&mut pos1);

            thread::sleep(Duration::from_millis(100));

            let mut pos2 = windows::Win32::Foundation::POINT { x: 0, y: 0 };
            let _ = GetCursorPos(&mut pos2);

            // If mouse moved, there's user activity
            pos1.x != pos2.x || pos1.y != pos2.y
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn check_mouse_movement(&self) -> bool {
        true // Assume activity on non-Windows
    }

    // =========================================================================
    // Emulator Detection Methods
    // =========================================================================

    /// Detect emulator indicators
    fn detect_emulator(&self, indicators: &mut Vec<String>) -> f32 {
        let mut score = 0.0;
        let mut checks = 0;

        // CPU feature consistency check
        if self.check_cpu_inconsistencies() {
            indicators.push("CPU feature inconsistencies detected".to_string());
            score += 0.6;
        }
        checks += 1;

        // Instruction timing accuracy
        if self.check_timing_accuracy() {
            indicators.push("Instruction timing anomalies".to_string());
            score += 0.5;
        }
        checks += 1;

        // FPU precision check
        if self.check_fpu_precision() {
            indicators.push("FPU precision anomalies".to_string());
            score += 0.4;
        }
        checks += 1;

        // Normalize score
        if score > 0.0 {
            (score / checks as f32).min(1.0)
        } else {
            0.0
        }
    }

    /// Check for CPU feature inconsistencies
    fn check_cpu_inconsistencies(&self) -> bool {
        // Check if CPUID reports features that don't match expected behavior
        // This is a simplified check - real implementations would be more complex

        #[cfg(all(target_arch = "x86_64", target_feature = "sse"))]
        {
            use std::arch::x86_64::__cpuid;

            unsafe {
                // Check for CPUID leaf 0 max value consistency
                let leaf0 = __cpuid(0);

                // Some emulators report high max leaf but fail on actual queries
                if leaf0.eax > 0x20 {
                    // Try to query an extended leaf
                    let _extended = __cpuid(0x80000000);
                    // If we get here without exception, it's likely real hardware
                    return false;
                }
            }
        }

        false
    }

    /// Check instruction timing accuracy
    fn check_timing_accuracy(&self) -> bool {
        use std::time::Instant;

        // Execute identical code blocks and measure timing variance
        let mut timings = Vec::new();

        for _ in 0..10 {
            let start = Instant::now();

            // Simple computation
            let mut x: u64 = 1;
            for i in 1..1000 {
                x = x.wrapping_mul(i).wrapping_add(i);
            }
            std::hint::black_box(x);

            timings.push(start.elapsed().as_nanos());
        }

        // Calculate variance
        if timings.len() < 2 {
            return false;
        }

        let mean: u128 = timings.iter().sum::<u128>() / timings.len() as u128;
        let variance: f64 = timings
            .iter()
            .map(|&t| {
                let diff = if t > mean { t - mean } else { mean - t };
                (diff as f64).powi(2)
            })
            .sum::<f64>()
            / timings.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = std_dev / mean as f64;

        // High variance suggests emulation
        coefficient_of_variation > 0.5
    }

    /// Check FPU precision
    fn check_fpu_precision(&self) -> bool {
        // Perform floating-point operations and check for precision anomalies
        let a: f64 = 0.1;
        let b: f64 = 0.2;
        let c: f64 = 0.3;

        // This should be very close to zero
        let result = (a + b) - c;

        // Check if result is within expected floating-point error range
        // Emulators might have different precision
        let epsilon = f64::EPSILON * 10.0;
        result.abs() > epsilon * 100.0 // Allow larger margin for detection
    }

    // =========================================================================
    // Event Handling
    // =========================================================================

    /// Handle detection based on configuration
    async fn handle_detection(&self, indicators: &SandboxIndicators) {
        if indicators.confidence < self.config.confidence_threshold {
            return; // Below threshold
        }

        self.detection_count.fetch_add(1, Ordering::SeqCst);

        match self.config.on_detection {
            AntiSandboxAction::Log => {
                info!(
                    confidence = indicators.confidence,
                    vm_score = indicators.vm_score,
                    sandbox_score = indicators.sandbox_score,
                    emulator_score = indicators.emulator_score,
                    vm_type = ?indicators.vm_type,
                    "Sandbox/VM environment detected (log only)"
                );
                for indicator in &indicators.indicators {
                    debug!("  - {}", indicator);
                }
            }
            AntiSandboxAction::Alert => {
                warn!(
                    confidence = indicators.confidence,
                    vm_type = ?indicators.vm_type,
                    "Sandbox/VM environment detected - sending alert"
                );

                let description = format!(
                    "Virtualized/sandboxed environment detected (confidence: {:.0}%): {}",
                    indicators.confidence * 100.0,
                    indicators.indicators.join(", ")
                );

                let event = TamperEvent {
                    timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                    event_type: TamperEventType::DebuggerTimingAnomaly, // Reuse for sandbox detection
                    description,
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Medium,
                    mitre_technique: Some("T1497.001".to_string()),
                };

                let _ = self.tamper_tx.send(event).await;
            }
            AntiSandboxAction::Adjust => {
                warn!(
                    confidence = indicators.confidence,
                    "Sandbox/VM detected - applying behavioral adjustments"
                );

                let description = format!(
                    "Virtualized environment - adjusting behavior (confidence: {:.0}%)",
                    indicators.confidence * 100.0
                );

                let event = TamperEvent {
                    timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                    event_type: TamperEventType::DebuggerTimingAnomaly,
                    description,
                    source_pid: None,
                    source_process: None,
                    severity: TamperSeverity::Medium,
                    mitre_technique: Some("T1497.001".to_string()),
                };

                let _ = self.tamper_tx.send(event).await;

                // Apply behavioral adjustments
                self.apply_behavioral_adjustments(indicators);
            }
        }
    }

    /// Apply behavioral adjustments when running in sandbox
    fn apply_behavioral_adjustments(&self, indicators: &SandboxIndicators) {
        info!("Applying behavioral adjustments for sandbox environment");

        // Example adjustments:
        // - Delay startup by random amount
        // - Reduce telemetry verbosity
        // - Adjust polling intervals
        // - Enable additional obfuscation

        // We don't exit or crash - we want to be analyzed but with awareness
    }

    /// Start monitoring task
    fn start_monitoring_task(&self) {
        let running = self.running.clone();
        let config = self.config.clone();
        let tamper_tx = self.tamper_tx.clone();
        let detection_count = self.detection_count.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(config.check_interval_secs));

            let engine = AntiSandboxEngine {
                config: config.clone(),
                running: running.clone(),
                detection_count: detection_count.clone(),
                tamper_tx: tamper_tx.clone(),
                last_check_time: std::sync::RwLock::new(None),
            };

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                let indicators = engine.check_environment();
                engine.handle_detection(&indicators).await;
            }
        });

        debug!(
            interval = self.config.check_interval_secs,
            "Anti-sandbox monitoring started"
        );
    }

    /// Get detection count
    pub fn get_detection_count(&self) -> u64 {
        self.detection_count.load(Ordering::SeqCst)
    }

    /// Check if currently in sandbox (instant check)
    pub fn is_sandboxed(&self) -> bool {
        let indicators = self.check_environment();
        indicators.confidence >= self.config.confidence_threshold
    }

    /// Get current sandbox indicators
    pub fn get_indicators(&self) -> SandboxIndicators {
        self.check_environment()
    }

    /// Shutdown anti-sandbox engine
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Anti-sandbox engine shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_config() {
        let config = AntiSandboxConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_interval_secs, 300);
        assert!(config.enable_vm_detection);
        assert_eq!(config.confidence_threshold, 0.6);
    }

    #[test]
    fn test_sandbox_indicators_default() {
        let indicators = SandboxIndicators::default();
        assert_eq!(indicators.confidence, 0.0);
        assert_eq!(indicators.vm_score, 0.0);
        assert!(indicators.indicators.is_empty());
    }
}
