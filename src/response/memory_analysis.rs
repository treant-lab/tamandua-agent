//! Memory analysis response actions
//!
//! Handles memory dump, YARA scanning, and forensic analysis commands

use crate::memory::{
    analyze_hooks, analyze_memory, detect_suspicious_regions, dump_process_memory, extract_strings,
    get_memory_regions, indirect_syscall_detector::scan_for_indirect_syscalls, DumpOptions,
    DumpType,
};
use crate::transport::CommandResult;
use anyhow::Result;
use tracing::{error, info};

/// Handle memory dump command
pub async fn handle_dump_memory(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let dump_type_str = payload
        .get("dump_type")
        .and_then(|v| v.as_str())
        .unwrap_or("suspicious");

    let compress = payload
        .get("compress")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let upload = payload
        .get("upload")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, dump_type = %dump_type_str, "Dumping process memory");

    // Parse dump type
    let dump_type = match dump_type_str {
        "full" => DumpType::Full,
        "rwx" => DumpType::RwxRegions,
        "private_executable" => DumpType::PrivateExecutable,
        "suspicious" => DumpType::Suspicious,
        _ => DumpType::Suspicious,
    };

    let options = DumpOptions {
        dump_type,
        compress,
        upload,
        output_path: None,
    };

    match perform_memory_dump(pid, options).await {
        Ok((dump_data, regions_dumped)) => {
            let dump_size = dump_data.len();

            // If upload is requested, stream to backend
            // For now, we'll include metadata in the response
            let result = serde_json::json!({
                "pid": pid,
                "dump_type": dump_type_str,
                "dump_size": dump_size,
                "regions_dumped": regions_dumped,
                "compressed": compress,
                "uploaded": false, // Set to true after implementing upload
            });

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "Memory dump failed");
            CommandResult {
                success: false,
                error_message: Some(format!("Memory dump failed: {}", e)),
                result_data: None,
            }
        }
    }
}

/// Perform memory dump
async fn perform_memory_dump(pid: u32, options: DumpOptions) -> Result<(Vec<u8>, usize)> {
    // Get memory regions
    let all_regions = get_memory_regions(pid).await?;

    // Filter regions based on dump type
    let regions_to_dump: Vec<_> = match options.dump_type {
        DumpType::Full => all_regions,
        DumpType::RwxRegions => all_regions
            .into_iter()
            .filter(|r| r.is_executable && r.is_writable)
            .collect(),
        DumpType::PrivateExecutable => all_regions
            .into_iter()
            .filter(|r| r.is_private && r.is_executable)
            .collect(),
        DumpType::Suspicious => {
            // Get suspicious regions
            let suspicious = detect_suspicious_regions(pid).await?;
            let suspicious_addrs: std::collections::HashSet<u64> =
                suspicious.iter().map(|s| s.region.base_address).collect();

            all_regions
                .into_iter()
                .filter(|r| suspicious_addrs.contains(&r.base_address))
                .collect()
        }
    };

    let regions_count = regions_to_dump.len();

    // Dump memory
    let mut dump_data = dump_process_memory(pid, regions_to_dump, &options).await?;

    // Compress if requested
    #[cfg(feature = "compression")]
    if options.compress {
        dump_data = crate::memory::dump::compress_dump(dump_data)?;
    }

    Ok((dump_data, regions_count))
}

/// Handle YARA memory scan command
#[cfg(feature = "yara")]
pub async fn handle_scan_memory_yara(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let rules_path = payload
        .get("rules_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, rules_path = %rules_path, "Scanning memory with YARA");

    // Get memory regions
    let regions = match get_memory_regions(pid).await {
        Ok(r) => r,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to get memory regions: {}", e)),
                result_data: None,
            }
        }
    };

    // Scan with YARA
    match crate::memory::scan_memory_yara(pid, regions, rules_path).await {
        Ok(matches) => {
            let result = serde_json::json!({
                "pid": pid,
                "matches": matches,
                "match_count": matches.len(),
            });

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "YARA memory scan failed");
            CommandResult {
                success: false,
                error_message: Some(format!("YARA scan failed: {}", e)),
                result_data: None,
            }
        }
    }
}

#[cfg(not(feature = "yara"))]
pub async fn handle_scan_memory_yara(_payload: &serde_json::Value) -> CommandResult {
    CommandResult {
        success: false,
        error_message: Some("YARA feature not enabled".to_string()),
        result_data: None,
    }
}

/// Handle suspicious region analysis command
pub async fn handle_analyze_suspicious_regions(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, "Analyzing suspicious memory regions");

    match detect_suspicious_regions(pid).await {
        Ok(suspicious) => {
            let result = serde_json::json!({
                "pid": pid,
                "suspicious_regions": suspicious,
                "count": suspicious.len(),
            });

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "Suspicious region analysis failed");
            CommandResult {
                success: false,
                error_message: Some(format!("Analysis failed: {}", e)),
                result_data: None,
            }
        }
    }
}

/// Handle memory hook analysis command
pub async fn handle_analyze_memory_hooks(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, "Analyzing memory hooks");

    match analyze_hooks(pid).await {
        Ok((iat_hooks, inline_hooks)) => {
            let result = serde_json::json!({
                "pid": pid,
                "iat_hooks": iat_hooks,
                "inline_hooks": inline_hooks,
                "iat_hook_count": iat_hooks.len(),
                "inline_hook_count": inline_hooks.len(),
            });

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "Hook analysis failed");
            CommandResult {
                success: false,
                error_message: Some(format!("Hook analysis failed: {}", e)),
                result_data: None,
            }
        }
    }
}

/// Handle memory string extraction command
pub async fn handle_extract_memory_strings(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let min_length = payload
        .get("min_length")
        .and_then(|v| v.as_u64())
        .unwrap_or(4) as usize;

    let max_strings = payload
        .get("max_strings")
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(
        pid = pid,
        min_length = min_length,
        "Extracting memory strings"
    );

    // Get memory regions
    let regions = match get_memory_regions(pid).await {
        Ok(r) => r,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to get memory regions: {}", e)),
                result_data: None,
            }
        }
    };

    match extract_strings(pid, regions, min_length).await {
        Ok(mut strings) => {
            // Sort by relevance and limit
            strings.sort_by(|a, b| {
                b.relevance
                    .partial_cmp(&a.relevance)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            strings.truncate(max_strings);

            let result = serde_json::json!({
                "pid": pid,
                "strings": strings,
                "count": strings.len(),
            });

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "String extraction failed");
            CommandResult {
                success: false,
                error_message: Some(format!("String extraction failed: {}", e)),
                result_data: None,
            }
        }
    }
}

/// Handle full memory analysis command
pub async fn handle_full_memory_analysis(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let process_name = payload
        .get("process_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, process_name = %process_name, "Performing full memory analysis");

    match analyze_memory(pid, process_name).await {
        Ok(report) => {
            let result = serde_json::json!({
                "report": report,
                "summary": {
                    "regions_scanned": report.regions_scanned,
                    "suspicious_regions": report.suspicious_regions.len(),
                    "yara_matches": report.yara_matches.len(),
                    "iat_hooks": report.iat_hooks.len(),
                    "inline_hooks": report.inline_hooks.len(),
                    "top_strings": report.strings.len(),
                }
            });

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "Full memory analysis failed");
            CommandResult {
                success: false,
                error_message: Some(format!("Analysis failed: {}", e)),
                result_data: None,
            }
        }
    }
}

/// Handle indirect syscall detection command (SysWhispers, Hell's Gate, etc.)
///
/// Scans process memory for patterns indicative of EDR bypass techniques:
/// - SysWhispers-style syscall stubs outside ntdll
/// - JMP/CALL to ntdll syscall instructions from private memory
/// - Hell's Gate dynamic SSN resolution via PEB walking
/// - Halo's Gate clean syscall technique
/// - Full syscall stub replication
pub async fn handle_scan_indirect_syscalls(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, "Scanning for indirect syscall patterns");

    match scan_for_indirect_syscalls(pid).await {
        Ok(detections) => {
            let detection_count = detections.len();
            let has_critical = detections
                .iter()
                .any(|d| d.pattern_type.severity() == "critical");
            let has_high = detections
                .iter()
                .any(|d| d.pattern_type.severity() == "high");

            let severity_summary = if has_critical {
                "critical"
            } else if has_high {
                "high"
            } else if detection_count > 0 {
                "medium"
            } else {
                "none"
            };

            let result = serde_json::json!({
                "pid": pid,
                "detections": detections,
                "detection_count": detection_count,
                "severity": severity_summary,
                "mitre_technique": "T1106",
                "mitre_tactic": "Defense Evasion",
            });

            if detection_count > 0 {
                info!(
                    pid = pid,
                    detections = detection_count,
                    severity = severity_summary,
                    "Indirect syscall patterns detected"
                );
            }

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(result),
            }
        }
        Err(e) => {
            error!(error = %e, pid = pid, "Indirect syscall scan failed");
            CommandResult {
                success: false,
                error_message: Some(format!("Scan failed: {}", e)),
                result_data: None,
            }
        }
    }
}
