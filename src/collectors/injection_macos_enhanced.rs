// Enhanced macOS Injection Detection
//
// This module provides advanced macOS-specific injection detection including:
// - MachO parsing for suspicious load commands
// - Dyld interposing detection
// - RWX memory region scanning
// - task_for_pid abuse monitoring
// - Code cave detection
// - Reflective dylib loading detection

use super::{InjectionEvent, InjectionTechnique, TelemetryEvent};
use crate::analyzers::macho_parser::{parse_macho_from_memory, MachOParser};
use crate::collectors::memory::macos_memory;
use crate::config::AgentConfig;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

/// Monitor for MachO binaries with suspicious load commands
pub async fn macho_load_command_monitor(
    tx: mpsc::Sender<TelemetryEvent>,
    known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
    interval_ms: u64,
) {
    info!("Starting MachO load command monitor");

    loop {
        // Get list of running processes
        if let Ok(output) = Command::new("ps").args(["-A", "-o", "pid=,comm="]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.trim().splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    continue;
                }

                let pid = match parts[0].trim().parse::<u32>() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let process_path = get_process_path(pid);
                if process_path.is_empty() {
                    continue;
                }

                // Skip system processes
                if process_path.starts_with("/System/") || process_path.starts_with("/usr/libexec/")
                {
                    continue;
                }

                // Parse the MachO binary
                match MachOParser::parse_file(&process_path) {
                    Ok(features) => {
                        if features.is_suspicious() {
                            let key = (0, pid, InjectionTechnique::SuspiciousDylib);
                            let mut known_guard = known.lock().await;
                            if known_guard.contains(&key) {
                                continue;
                            }
                            known_guard.insert(key);
                            drop(known_guard);

                            warn!(
                                pid = pid,
                                path = %process_path,
                                score = features.suspicion_score,
                                "Suspicious MachO binary detected"
                            );

                            let mut evidence = Vec::new();
                            if features.has_dyld_environment {
                                evidence
                                    .push("LC_DYLD_ENVIRONMENT load command present".to_string());
                            }
                            if !features.dyld_env_vars.is_empty() {
                                evidence.push(format!(
                                    "DYLD env vars: {}",
                                    features.dyld_env_vars.join(", ")
                                ));
                            }
                            if features.has_interpose_section {
                                evidence.push("__interpose section found".to_string());
                            }
                            if !features.suspicious_dylibs.is_empty() {
                                evidence.push(format!(
                                    "Suspicious dylibs: {}",
                                    features.suspicious_dylibs.join(", ")
                                ));
                            }
                            if features.unsigned_or_invalid {
                                evidence.push("Unsigned or invalid signature".to_string());
                            }

                            let injection = InjectionEvent {
                                source_pid: 0,
                                source_name: "unknown".to_string(),
                                source_path: String::new(),
                                target_pid: pid,
                                target_name: parts[1].trim().to_string(),
                                target_path: process_path.clone(),
                                technique: InjectionTechnique::SuspiciousDylib,
                                memory_address: None,
                                memory_size: None,
                                memory_protection: None,
                                evidence,
                            };

                            let event =
                                super::InjectionCollector::create_injection_event(&injection);
                            let _ = tx.send(event).await;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse MachO for PID {}: {}", pid, e);
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

/// Scan for RWX (read-write-execute) memory regions in processes
pub async fn rwx_memory_scanner(
    tx: mpsc::Sender<TelemetryEvent>,
    known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
    interval_ms: u64,
) {
    info!("Starting RWX memory scanner");

    // Processes known to legitimately use JIT (Just-In-Time compilation)
    let jit_processes: HashSet<&str> = [
        "Safari",
        "Google Chrome",
        "firefox",
        "node",
        "python",
        "ruby",
        "java",
        "dotnet",
        "Chromium",
        "WebKitWebContent",
        "com.apple.WebKit.WebContent",
    ]
    .iter()
    .copied()
    .collect();

    loop {
        // Get list of running processes
        if let Ok(output) = Command::new("ps").args(["-A", "-o", "pid="]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let pid = match line.trim().parse::<u32>() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Skip low PIDs (system processes)
                if pid <= 1 {
                    continue;
                }

                let process_name = get_process_name(pid);
                let process_path = get_process_path(pid);

                // Skip known JIT processes
                if jit_processes.iter().any(|jit| process_name.contains(jit)) {
                    continue;
                }

                // Get task port for the process
                let task = match macos_memory::get_task_for_pid(pid as i32) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                // Enumerate memory regions
                let regions = macos_memory::enumerate_regions(task);

                for region in regions {
                    // Check for RWX memory (very suspicious outside of JIT)
                    if region.is_readable && region.is_writable && region.is_executable {
                        let key = (0, pid, InjectionTechnique::SuspiciousRwxMemory);
                        let mut known_guard = known.lock().await;
                        if known_guard.contains(&key) {
                            continue;
                        }
                        known_guard.insert(key);
                        drop(known_guard);

                        // Read a sample for entropy calculation
                        let entropy = if let Some(data) = macos_memory::read_memory(
                            task,
                            region.base_address,
                            region.size.min(16384) as usize,
                        ) {
                            calculate_entropy(&data)
                        } else {
                            0.0
                        };

                        warn!(
                            pid = pid,
                            process = %process_name,
                            address = format!("0x{:x}", region.base_address),
                            size = region.size,
                            entropy = entropy,
                            "RWX memory region detected in non-JIT process"
                        );

                        let injection = InjectionEvent {
                            source_pid: 0,
                            source_name: "unknown".to_string(),
                            source_path: String::new(),
                            target_pid: pid,
                            target_name: process_name.clone(),
                            target_path: process_path.clone(),
                            technique: InjectionTechnique::SuspiciousRwxMemory,
                            memory_address: Some(region.base_address),
                            memory_size: Some(region.size),
                            memory_protection: Some(region.protection as u32),
                            evidence: vec![
                                format!("RWX memory at 0x{:x}", region.base_address),
                                format!("Size: {} bytes", region.size),
                                format!("Entropy: {:.2}", entropy),
                                format!("Region type: {}", region.region_type),
                            ],
                        };

                        let event = super::InjectionCollector::create_injection_event(&injection);
                        let _ = tx.send(event).await;
                    }

                    // Check for code caves (small executable regions with low entropy)
                    if region.is_executable
                        && region.size >= 512
                        && region.size <= 8192
                        && region.is_private
                    {
                        if let Some(data) = macos_memory::read_memory(
                            task,
                            region.base_address,
                            region.size.min(8192) as usize,
                        ) {
                            let entropy = calculate_entropy(&data);

                            // Low entropy in executable regions might indicate code caves
                            if entropy < 2.0 {
                                let key = (0, pid, InjectionTechnique::SuspiciousMemoryMapping);
                                let mut known_guard = known.lock().await;
                                if known_guard.contains(&key) {
                                    continue;
                                }
                                known_guard.insert(key);
                                drop(known_guard);

                                debug!(
                                    pid = pid,
                                    address = format!("0x{:x}", region.base_address),
                                    "Potential code cave detected (low entropy executable region)"
                                );

                                let injection = InjectionEvent {
                                    source_pid: 0,
                                    source_name: "unknown".to_string(),
                                    source_path: String::new(),
                                    target_pid: pid,
                                    target_name: process_name.clone(),
                                    target_path: process_path.clone(),
                                    technique: InjectionTechnique::SuspiciousMemoryMapping,
                                    memory_address: Some(region.base_address),
                                    memory_size: Some(region.size),
                                    memory_protection: Some(region.protection as u32),
                                    evidence: vec![
                                        format!("Code cave at 0x{:x}", region.base_address),
                                        format!("Low entropy: {:.2}", entropy),
                                    ],
                                };

                                let event =
                                    super::InjectionCollector::create_injection_event(&injection);
                                let _ = tx.send(event).await;
                            }
                        }
                    }

                    // Check for reflectively loaded MachO binaries in private memory
                    if region.is_executable && region.is_private && region.size >= 16384 {
                        if let Some(data) = macos_memory::read_memory(
                            task,
                            region.base_address,
                            region.size.min(4096) as usize,
                        ) {
                            // Check for MachO magic bytes
                            if is_macho_magic(&data) {
                                let key = (0, pid, InjectionTechnique::ProcessHollowing);
                                let mut known_guard = known.lock().await;
                                if known_guard.contains(&key) {
                                    continue;
                                }
                                known_guard.insert(key);
                                drop(known_guard);

                                warn!(
                                    pid = pid,
                                    address = format!("0x{:x}", region.base_address),
                                    "MachO binary detected in private memory (reflective loading)"
                                );

                                // Try to parse the MachO from memory
                                let mut evidence = vec![
                                    format!("MachO binary at 0x{:x}", region.base_address),
                                    "Potential reflective dylib loading".to_string(),
                                ];

                                if let Ok(features) = parse_macho_from_memory(
                                    pid,
                                    region.base_address,
                                    region.size as usize,
                                ) {
                                    evidence.push(format!(
                                        "Suspicion score: {:.2}",
                                        features.suspicion_score
                                    ));
                                    if !features.suspicious_dylibs.is_empty() {
                                        evidence.push(format!(
                                            "Suspicious dylibs: {}",
                                            features.suspicious_dylibs.join(", ")
                                        ));
                                    }
                                }

                                let injection = InjectionEvent {
                                    source_pid: 0,
                                    source_name: "unknown".to_string(),
                                    source_path: String::new(),
                                    target_pid: pid,
                                    target_name: process_name.clone(),
                                    target_path: process_path.clone(),
                                    technique: InjectionTechnique::ProcessHollowing,
                                    memory_address: Some(region.base_address),
                                    memory_size: Some(region.size),
                                    memory_protection: Some(region.protection as u32),
                                    evidence,
                                };

                                let event =
                                    super::InjectionCollector::create_injection_event(&injection);
                                let _ = tx.send(event).await;
                            }
                        }
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

/// Detect dyld interposing attacks
pub async fn dyld_interposing_detector(
    tx: mpsc::Sender<TelemetryEvent>,
    known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
    interval_ms: u64,
) {
    info!("Starting dyld interposing detector");

    // System processes that might legitimately use interposing
    let legitimate_interposers: HashSet<&str> =
        ["dtrace", "dtruss", "Instruments", "sample", "lldb"]
            .iter()
            .copied()
            .collect();

    loop {
        // Get list of running processes
        if let Ok(output) = Command::new("ps").args(["-A", "-o", "pid=,comm="]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.trim().splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    continue;
                }

                let pid = match parts[0].trim().parse::<u32>() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let process_name = parts[1].trim();

                // Skip legitimate interposers
                if legitimate_interposers
                    .iter()
                    .any(|name| process_name.contains(name))
                {
                    continue;
                }

                let process_path = get_process_path(pid);
                if process_path.is_empty() {
                    continue;
                }

                // Parse the binary and check for interpose sections
                match MachOParser::parse_file(&process_path) {
                    Ok(features) => {
                        if features.has_interpose_section {
                            let key = (0, pid, InjectionTechnique::DyldInsertLibraries);
                            let mut known_guard = known.lock().await;
                            if known_guard.contains(&key) {
                                continue;
                            }
                            known_guard.insert(key);
                            drop(known_guard);

                            warn!(
                                pid = pid,
                                process = %process_name,
                                "Process with __interpose section detected"
                            );

                            let injection = InjectionEvent {
                                source_pid: 0,
                                source_name: "unknown".to_string(),
                                source_path: String::new(),
                                target_pid: pid,
                                target_name: process_name.to_string(),
                                target_path: process_path.clone(),
                                technique: InjectionTechnique::DyldInsertLibraries,
                                memory_address: None,
                                memory_size: None,
                                memory_protection: None,
                                evidence: vec![
                                    "__interpose section present".to_string(),
                                    "Possible function interposing for code injection".to_string(),
                                ],
                            };

                            let event =
                                super::InjectionCollector::create_injection_event(&injection);
                            let _ = tx.send(event).await;
                        }

                        // Also check for unusual library load order
                        match MachOParser::check_load_order(&process_path) {
                            Ok(true) => {
                                let key = (0, pid, InjectionTechnique::SuspiciousDylib);
                                let mut known_guard = known.lock().await;
                                if !known_guard.contains(&key) {
                                    known_guard.insert(key);
                                    drop(known_guard);

                                    debug!(
                                        pid = pid,
                                        process = %process_name,
                                        "Unusual library load order detected"
                                    );

                                    let injection = InjectionEvent {
                                        source_pid: 0,
                                        source_name: "unknown".to_string(),
                                        source_path: String::new(),
                                        target_pid: pid,
                                        target_name: process_name.to_string(),
                                        target_path: process_path,
                                        technique: InjectionTechnique::SuspiciousDylib,
                                        memory_address: None,
                                        memory_size: None,
                                        memory_protection: None,
                                        evidence: vec![
                                            "Unusual dylib load order".to_string(),
                                            "User libraries loaded before system libraries"
                                                .to_string(),
                                        ],
                                    };

                                    let event = super::InjectionCollector::create_injection_event(
                                        &injection,
                                    );
                                    let _ = tx.send(event).await;
                                }
                            }
                            Ok(false) => {}
                            Err(e) => debug!("Failed to check load order for PID {}: {}", pid, e),
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse MachO for PID {}: {}", pid, e);
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

/// Calculate Shannon entropy of byte data
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_counts = [0u64; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy as f32
}

/// Check if data starts with MachO magic bytes
fn is_macho_magic(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // MachO magic numbers (32-bit and 64-bit, little and big endian)
    const MH_MAGIC: u32 = 0xfeedface;
    const MH_CIGAM: u32 = 0xcefaedfe;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const MH_CIGAM_64: u32 = 0xcffaedfe;
    const FAT_MAGIC: u32 = 0xcafebabe;
    const FAT_CIGAM: u32 = 0xbebafeca;

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    matches!(
        magic,
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 | FAT_MAGIC | FAT_CIGAM
    )
}

/// Get process name from PID on macOS
fn get_process_name(pid: u32) -> String {
    Command::new("ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|out| {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
        .unwrap_or_else(|| format!("pid:{}", pid))
}

/// Get process path from PID on macOS
fn get_process_path(pid: u32) -> String {
    // Try using lsof to get the executable path
    if let Ok(output) = Command::new("lsof")
        .args(["-p", &pid.to_string(), "-Fn"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("n/") && !line.contains("(") {
                let path = &line[1..];
                // Check if it's an executable file
                if std::path::Path::new(path).exists() {
                    return path.to_string();
                }
            }
        }
    }

    // Fallback to ps
    Command::new("ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let data = vec![0u8; 256];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0); // All zeros should have 0 entropy

        let random_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_entropy(&random_data);
        assert!(entropy > 7.0); // Uniform distribution should have high entropy
    }

    #[test]
    fn test_macho_magic_detection() {
        // MH_MAGIC_64 (0xfeedfacf in little endian)
        let macho_data = vec![0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00];
        assert!(is_macho_magic(&macho_data));

        // Not MachO
        let not_macho = vec![0x00, 0x01, 0x02, 0x03];
        assert!(!is_macho_magic(&not_macho));
    }
}
