//! BOF (Beacon Object File) Collector
//!
//! This collector monitors memory for BOF execution patterns commonly used by
//! Cobalt Strike and other C2 frameworks. It integrates with the memory scanner
//! to detect COFF object files loaded in unusual memory regions.
//!
//! ## Detection Capabilities
//!
//! 1. **COFF Header Detection**: Identifies COFF object file headers in MEM_PRIVATE
//!    or unbacked memory regions, which is abnormal behavior indicating BOF loading.
//!
//! 2. **Beacon API Pattern Detection**: Detects characteristic Cobalt Strike Beacon
//!    API patterns like BeaconPrintf, BeaconOutput, BeaconDataParse.
//!
//! 3. **API Hashing Detection**: Identifies ROR13 and other API hashing techniques
//!    used for dynamic function resolution in BOFs.
//!
//! 4. **COFF Relocation Detection**: Detects runtime COFF relocation fixup patterns
//!    indicating in-memory object file loading.
//!
//! ## Integration
//!
//! This collector uses the `BofDetector` from the analyzers module and the
//! `MemoryScanner` for memory region enumeration.
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1055: Process Injection
//! - T1620: Reflective Code Loading
//! - T1106: Native API
//! - T1071.001: Application Layer Protocol (C2)
//! - T1027: Obfuscated Files or Information

use super::TelemetryEvent;
use crate::analyzers::bof_detector::{BofDetection, BofDetector, BofDetectorConfig};
use crate::config::AgentConfig;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Configuration for the BOF collector
#[derive(Debug, Clone)]
pub struct BofCollectorConfig {
    /// Enable the collector
    pub enabled: bool,
    /// Scan interval
    pub scan_interval: Duration,
    /// Target specific PIDs (empty = all processes)
    pub target_pids: HashSet<u32>,
    /// Skip these process names
    pub skip_processes: HashSet<String>,
    /// Maximum memory region size to scan (bytes)
    pub max_region_size: usize,
    /// Minimum confidence threshold for alerts
    pub confidence_threshold: f32,
    /// Focus on high-risk processes only
    pub high_risk_only: bool,
}

impl Default for BofCollectorConfig {
    fn default() -> Self {
        let mut skip = HashSet::new();
        // Legitimate development tools that handle COFF files
        skip.insert("link.exe".to_lowercase());
        skip.insert("cl.exe".to_lowercase());
        skip.insert("lib.exe".to_lowercase());
        skip.insert("dumpbin.exe".to_lowercase());
        skip.insert("ml64.exe".to_lowercase());
        skip.insert("objcopy.exe".to_lowercase());
        skip.insert("objdump.exe".to_lowercase());

        Self {
            enabled: true,
            scan_interval: Duration::from_secs(30),
            target_pids: HashSet::new(),
            skip_processes: skip,
            max_region_size: 10 * 1024 * 1024, // 10MB
            confidence_threshold: 0.65,
            high_risk_only: false,
        }
    }
}

/// High-risk processes commonly targeted by BOF injection
const HIGH_RISK_PROCESSES: &[&str] = &[
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "notepad.exe",
    "explorer.exe",
    "svchost.exe",
    "spoolsv.exe",
    "wuauclt.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "werfault.exe",
    "searchprotocolhost.exe",
    "backgroundtaskhost.exe",
    "runtimebroker.exe",
    "smartscreen.exe",
    "mobsync.exe",
    "gpscript.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
];

/// BOF Collector for monitoring memory for BOF execution
#[allow(dead_code)]
pub struct BofCollector {
    config: BofCollectorConfig,
    bof_detector: BofDetector,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    last_scan: Instant,
}

impl BofCollector {
    /// Create a new BOF collector with default configuration
    pub fn new(agent_config: &AgentConfig) -> Self {
        Self::with_config(agent_config, BofCollectorConfig::default())
    }

    /// Create a new BOF collector with custom configuration
    pub fn with_config(_agent_config: &AgentConfig, config: BofCollectorConfig) -> Self {
        let (tx, rx) = mpsc::channel(100);

        let bof_detector_config = BofDetectorConfig {
            scan_coff_headers: true,
            scan_beacon_apis: true,
            scan_api_hashing: true,
            confidence_threshold: config.confidence_threshold,
            max_scan_size: config.max_region_size,
            scan_interval: config.scan_interval,
            skip_processes: config.skip_processes.clone(),
        };

        let collector = Self {
            config,
            bof_detector: BofDetector::with_config(bof_detector_config),
            event_rx: rx,
            event_tx: tx.clone(),
            last_scan: Instant::now() - Duration::from_secs(60), // Allow immediate first scan
        };

        // Start the monitoring task
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx;
            let config_clone = collector.config.clone();
            let detector = BofDetector::with_config(BofDetectorConfig {
                confidence_threshold: config_clone.confidence_threshold,
                ..Default::default()
            });
            tokio::spawn(async move {
                windows_impl::monitor_loop(tx_clone, config_clone, detector).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx;
            let config_clone = collector.config.clone();
            let detector = BofDetector::with_config(BofDetectorConfig {
                confidence_threshold: config_clone.confidence_threshold,
                ..Default::default()
            });
            tokio::spawn(async move {
                linux_impl::monitor_loop(tx_clone, config_clone, detector).await;
            });
        }

        info!("BOF collector initialized");
        collector
    }

    /// Get the next telemetry event from the collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Check if a process is high-risk (commonly targeted for injection)
    pub fn is_high_risk_process(process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        HIGH_RISK_PROCESSES.iter().any(|p| name_lower.contains(p))
    }

    /// Create a telemetry event from BOF detection
    pub fn create_event(detection: &BofDetection) -> TelemetryEvent {
        BofDetector::create_telemetry_event(detection)
    }
}

/// Windows-specific implementation
#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use crate::analyzers::bof_detector::BofDetector;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// Main monitoring loop for Windows
    pub async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: BofCollectorConfig,
        mut detector: BofDetector,
    ) {
        let mut interval = tokio::time::interval(config.scan_interval);

        loop {
            interval.tick().await;

            if !config.enabled {
                continue;
            }

            // Clean up detector cache periodically
            detector.cleanup_cache();

            // Enumerate processes
            match enumerate_processes() {
                Ok(processes) => {
                    for (pid, process_name) in processes {
                        // Skip if in skip list
                        if config.skip_processes.contains(&process_name.to_lowercase()) {
                            continue;
                        }

                        // If target PIDs specified, only scan those
                        if !config.target_pids.is_empty() && !config.target_pids.contains(&pid) {
                            continue;
                        }

                        // If high_risk_only, filter to high-risk processes
                        if config.high_risk_only
                            && !BofCollector::is_high_risk_process(&process_name)
                        {
                            continue;
                        }

                        // Scan process memory
                        if let Some(detections) =
                            scan_process_memory(pid, &process_name, &config, &mut detector)
                        {
                            for detection in detections {
                                let event = BofCollector::create_event(&detection);
                                if tx.send(event).await.is_err() {
                                    warn!("BOF collector channel closed");
                                    return;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to enumerate processes: {}", e);
                }
            }
        }
    }

    /// Enumerate all running processes
    fn enumerate_processes() -> anyhow::Result<Vec<(u32, String)>> {
        let mut processes = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = OsString::from_wide(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    )
                    .to_string_lossy()
                    .to_string();

                    processes.push((entry.th32ProcessID, name));

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        Ok(processes)
    }

    /// Scan a process's memory regions for BOF indicators
    fn scan_process_memory(
        pid: u32,
        process_name: &str,
        config: &BofCollectorConfig,
        detector: &mut BofDetector,
    ) -> Option<Vec<BofDetection>> {
        // Skip self and system processes
        if pid == 0 || pid == 4 || pid == std::process::id() {
            return None;
        }

        let handle = unsafe {
            match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            }
        };

        let mut detections = Vec::new();
        let mut address: usize = 0;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        // Get process path
        let process_path = get_process_path(handle).unwrap_or_default();

        unsafe {
            while VirtualQueryEx(handle, Some(address as *const _), &mut mbi, mbi_size) > 0 {
                // Check for suspicious memory: executable + private/uncommitted
                let is_executable = matches!(
                    mbi.Protect,
                    PAGE_EXECUTE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_EXECUTE_WRITECOPY
                );
                let is_private = mbi.Type == MEM_PRIVATE;
                let is_committed = mbi.State == MEM_COMMIT;

                // Focus on executable private memory (potential BOF location)
                if is_executable && is_private && is_committed {
                    let region_size = mbi.RegionSize;

                    // Skip if too large
                    if region_size <= config.max_region_size {
                        // Read memory content
                        if let Some(buffer) = read_process_memory(
                            handle,
                            mbi.BaseAddress as u64,
                            region_size.min(8192), // Read first 8KB
                        ) {
                            // Scan for BOF indicators
                            if let Some(detection) = detector.scan_buffer(
                                pid,
                                process_name,
                                &process_path,
                                mbi.BaseAddress as u64,
                                &buffer,
                            ) {
                                detections.push(detection);
                            }
                        }
                    }
                }

                // Move to next region
                address = (mbi.BaseAddress as usize) + mbi.RegionSize;

                // Prevent overflow
                if address <= mbi.BaseAddress as usize {
                    break;
                }
            }

            let _ = CloseHandle(handle);
        }

        if detections.is_empty() {
            None
        } else {
            Some(detections)
        }
    }

    /// Read memory from a process
    fn read_process_memory(handle: HANDLE, address: u64, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )
            .is_ok()
            {
                buffer.truncate(bytes_read);
                Some(buffer)
            } else {
                None
            }
        }
    }

    /// Get process executable path
    fn get_process_path(handle: HANDLE) -> Option<String> {
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;

        let mut path = vec![0u16; 260];
        unsafe {
            let len = GetModuleFileNameExW(handle, None, &mut path) as usize;
            if len > 0 {
                Some(String::from_utf16_lossy(&path[..len]))
            } else {
                None
            }
        }
    }
}

/// Linux-specific implementation
#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::analyzers::bof_detector::BofDetector;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

    /// Main monitoring loop for Linux
    pub async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: BofCollectorConfig,
        mut detector: BofDetector,
    ) {
        let mut interval = tokio::time::interval(config.scan_interval);

        loop {
            interval.tick().await;

            if !config.enabled {
                continue;
            }

            // Clean up detector cache
            detector.cleanup_cache();

            // Enumerate processes from /proc
            match enumerate_processes() {
                Ok(processes) => {
                    for (pid, process_name) in processes {
                        // Skip if in skip list
                        if config.skip_processes.contains(&process_name.to_lowercase()) {
                            continue;
                        }

                        // If target PIDs specified, only scan those
                        if !config.target_pids.is_empty() && !config.target_pids.contains(&pid) {
                            continue;
                        }

                        // If high_risk_only, skip (Linux doesn't have same high-risk binaries)
                        // but could still check for specific interpreters
                        if config.high_risk_only {
                            let high_risk = ["python", "perl", "ruby", "bash", "sh", "dash", "php"];
                            if !high_risk.iter().any(|p| process_name.contains(p)) {
                                continue;
                            }
                        }

                        // Scan process memory
                        if let Some(detections) =
                            scan_process_memory(pid, &process_name, &config, &mut detector)
                        {
                            for detection in detections {
                                let event = BofCollector::create_event(&detection);
                                if tx.send(event).await.is_err() {
                                    warn!("BOF collector channel closed");
                                    return;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to enumerate processes: {}", e);
                }
            }
        }
    }

    /// Enumerate processes from /proc
    fn enumerate_processes() -> anyhow::Result<Vec<(u32, String)>> {
        let mut processes = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Check if directory name is a PID
            if let Ok(pid) = name_str.parse::<u32>() {
                // Read process name from /proc/[pid]/comm
                let comm_path = format!("/proc/{}/comm", pid);
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    processes.push((pid, comm.trim().to_string()));
                }
            }
        }

        Ok(processes)
    }

    /// Scan a process's memory regions for BOF indicators
    fn scan_process_memory(
        pid: u32,
        process_name: &str,
        config: &BofCollectorConfig,
        detector: &mut BofDetector,
    ) -> Option<Vec<BofDetection>> {
        // Skip self
        if pid == std::process::id() {
            return None;
        }

        let maps_path = format!("/proc/{}/maps", pid);
        let mem_path = format!("/proc/{}/mem", pid);
        let exe_path = format!("/proc/{}/exe", pid);

        // Get process executable path
        let process_path = fs::read_link(&exe_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Open maps file
        let maps_file = match File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        // Open mem file
        let mut mem_file = match File::open(&mem_path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut detections = Vec::new();
        let reader = BufReader::new(maps_file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            // Parse maps line: address perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            // Parse address range
            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() != 2 {
                continue;
            }

            let start = match u64::from_str_radix(addr_parts[0], 16) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let end = match u64::from_str_radix(addr_parts[1], 16) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let size = (end - start) as usize;
            let perms = parts[1];

            // Check for executable anonymous/private memory
            let is_executable = perms.contains('x');
            let is_private = perms.contains('p');
            // Anonymous if no pathname (parts.len() < 6) or [heap]/[stack]/[vdso] etc
            let is_anonymous = parts.len() < 6 || parts[5].is_empty() || parts[5].starts_with('[');

            // Focus on executable private anonymous memory
            if is_executable && is_private && is_anonymous && size <= config.max_region_size {
                // Read memory content
                if mem_file.seek(SeekFrom::Start(start)).is_ok() {
                    let read_size = size.min(8192);
                    let mut buffer = vec![0u8; read_size];

                    if let Ok(bytes_read) = mem_file.read(&mut buffer) {
                        if bytes_read > 0 {
                            buffer.truncate(bytes_read);

                            // Scan for BOF indicators
                            if let Some(detection) = detector.scan_buffer(
                                pid,
                                process_name,
                                &process_path,
                                start,
                                &buffer,
                            ) {
                                detections.push(detection);
                            }
                        }
                    }
                }
            }
        }

        if detections.is_empty() {
            None
        } else {
            Some(detections)
        }
    }
}

/// macOS-specific implementation (stub)
#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    // macOS BOF detection would use mach_vm_read and task_for_pid
    // Similar to Windows but using Mach APIs
    // Left as stub for now - BOF is primarily a Windows concern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_risk_process_detection() {
        assert!(BofCollector::is_high_risk_process("rundll32.exe"));
        assert!(BofCollector::is_high_risk_process("RUNDLL32.EXE"));
        assert!(BofCollector::is_high_risk_process("powershell.exe"));
        assert!(!BofCollector::is_high_risk_process("custom_app.exe"));
    }

    #[test]
    fn test_config_defaults() {
        let config = BofCollectorConfig::default();
        assert!(config.enabled);
        assert_eq!(config.scan_interval, Duration::from_secs(30));
        assert!(config.skip_processes.contains(&"link.exe".to_string()));
    }
}
