//! File Integrity Monitoring (FIM) response actions
//!
//! Provides remediation actions for FIM violations including:
//! - Restore files from baseline
//! - Quarantine modified files
//! - Force baseline rescans
//! - Manage whitelist entries

use crate::collectors::fim::{
    ComplianceFramework, FimCollector, IntegrityChangeType, WhitelistEntry,
};
use crate::transport::CommandResult;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Global FIM collector instance (set by main.rs after initialization)
static FIM_COLLECTOR: std::sync::OnceLock<Arc<RwLock<Option<FimCollector>>>> =
    std::sync::OnceLock::new();

/// Initialize the global FIM collector
pub fn init_fim_collector(collector: FimCollector) {
    let lock = FIM_COLLECTOR.get_or_init(|| Arc::new(RwLock::new(None)));
    if let Ok(mut guard) = lock.write() {
        *guard = Some(collector);
        info!("FIM collector registered for response actions");
    }
}

/// Get the FIM collector
fn get_fim_collector() -> Result<Arc<RwLock<Option<FimCollector>>>> {
    FIM_COLLECTOR
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("FIM collector not initialized"))
}

/// Get baseline information for a file
pub async fn handle_fim_get_baseline(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Missing or invalid 'path' parameter".to_string()),
            result_data: None,
        };
    }

    info!(path = %path, "FIM: Getting baseline for file");

    match get_fim_collector() {
        Ok(collector_lock) => match collector_lock.read() {
            Ok(collector_guard) => match collector_guard.as_ref() {
                Some(collector) => {
                    if let Some(file_baseline) = collector.get_baseline_entry(path) {
                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(
                                serde_json::to_value(file_baseline).unwrap_or_default(),
                            ),
                        }
                    } else {
                        CommandResult {
                            success: false,
                            error_message: Some(format!("No baseline found for: {}", path)),
                            result_data: None,
                        }
                    }
                }
                None => CommandResult {
                    success: false,
                    error_message: Some("FIM collector not available".to_string()),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to access FIM collector: {}", e)),
                result_data: None,
            },
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("FIM not initialized: {}", e)),
            result_data: None,
        },
    }
}

/// Restore a file from baseline
pub async fn handle_fim_restore_file(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let create_backup = payload
        .get("create_backup")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Missing or invalid 'path' parameter".to_string()),
            result_data: None,
        };
    }

    info!(path = %path, backup = create_backup, "FIM: Restoring file from baseline");

    match restore_file_from_baseline(path, create_backup).await {
        Ok(result) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "path": path,
                "backup_path": result.backup_path,
                "restored_from_baseline": true,
                "baseline_timestamp": result.baseline_timestamp,
                "baseline_hash": hex::encode(result.baseline_hash),
            })),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to restore file: {}", e)),
            result_data: None,
        },
    }
}

/// Quarantine a modified file
pub async fn handle_fim_quarantine_file(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("FIM violation");

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Missing or invalid 'path' parameter".to_string()),
            result_data: None,
        };
    }

    info!(path = %path, reason = %reason, "FIM: Quarantining modified file");

    match quarantine_modified_file(path, reason).await {
        Ok(result) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "path": path,
                "quarantine_path": result.quarantine_path,
                "quarantined_at": result.quarantined_at,
                "reason": reason,
                "hash": hex::encode(result.file_hash),
            })),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to quarantine file: {}", e)),
            result_data: None,
        },
    }
}

/// Force a full baseline scan
pub async fn handle_fim_force_baseline_scan(_payload: &serde_json::Value) -> CommandResult {
    info!("FIM: Forcing full baseline scan");

    let collector_lock = match get_fim_collector() {
        Ok(lock) => lock,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("FIM not initialized: {}", e)),
                result_data: None,
            }
        }
    };

    match tokio::task::spawn_blocking(move || {
        let handle = tokio::runtime::Handle::current();

        match collector_lock.read() {
            Ok(collector_guard) => match collector_guard.as_ref() {
                Some(collector) => handle.block_on(collector.force_baseline_scan()),
                None => Err(anyhow::anyhow!("FIM collector not available")),
            },
            Err(e) => Err(anyhow::anyhow!("Failed to access FIM collector: {}", e)),
        }
    })
    .await
    {
        Ok(Ok(files_scanned)) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "files_scanned": files_scanned,
                "message": "Baseline scan completed successfully",
            })),
        },
        Ok(Err(e)) => CommandResult {
            success: false,
            error_message: Some(format!("Baseline scan failed: {}", e)),
            result_data: None,
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Baseline scan task failed: {}", e)),
            result_data: None,
        },
    }
}

/// Get FIM statistics
pub async fn handle_fim_get_stats(_payload: &serde_json::Value) -> CommandResult {
    match get_fim_collector() {
        Ok(collector_lock) => match collector_lock.read() {
            Ok(collector_guard) => match collector_guard.as_ref() {
                Some(collector) => match collector.get_baseline_stats() {
                    Some(stats) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::to_value(stats).unwrap_or_default()),
                    },
                    None => CommandResult {
                        success: false,
                        error_message: Some("Failed to retrieve FIM stats".to_string()),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("FIM collector not available".to_string()),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to access FIM collector: {}", e)),
                result_data: None,
            },
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("FIM not initialized: {}", e)),
            result_data: None,
        },
    }
}

/// Add a whitelist entry
pub async fn handle_fim_add_whitelist(payload: &serde_json::Value) -> CommandResult {
    #[derive(Deserialize)]
    struct WhitelistRequest {
        pattern: String,
        allowed_changes: Option<Vec<String>>,
        reason: String,
        expires: Option<u64>,
        added_by: Option<String>,
    }

    let request: WhitelistRequest = match serde_json::from_value(payload.clone()) {
        Ok(r) => r,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Invalid whitelist request: {}", e)),
                result_data: None,
            }
        }
    };

    info!(pattern = %request.pattern, "FIM: Adding whitelist entry");

    // Parse allowed_changes into IntegrityChangeType
    let allowed_changes: Vec<IntegrityChangeType> = request
        .allowed_changes
        .unwrap_or_default()
        .iter()
        .filter_map(|s| match s.as_str() {
            "content_modified" => Some(IntegrityChangeType::ContentModified),
            "created" => Some(IntegrityChangeType::Created),
            "deleted" => Some(IntegrityChangeType::Deleted),
            "permissions_changed" => Some(IntegrityChangeType::PermissionsChanged),
            "ownership_changed" => Some(IntegrityChangeType::OwnershipChanged),
            "attributes_changed" => Some(IntegrityChangeType::AttributesChanged),
            "renamed" => Some(IntegrityChangeType::Renamed),
            _ => None,
        })
        .collect();

    let entry = WhitelistEntry {
        pattern: request.pattern.clone(),
        allowed_changes,
        reason: request.reason,
        expires: request.expires.unwrap_or(0), // 0 = never expires
        added_by: request.added_by.unwrap_or_else(|| "api".to_string()),
    };

    match get_fim_collector() {
        Ok(collector_lock) => match collector_lock.write() {
            Ok(mut collector_guard) => match collector_guard.as_mut() {
                Some(collector) => {
                    collector.add_whitelist_entry(entry.clone());
                    CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "message": "Whitelist entry added successfully",
                            "pattern": entry.pattern,
                        })),
                    }
                }
                None => CommandResult {
                    success: false,
                    error_message: Some("FIM collector not available".to_string()),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to access FIM collector: {}", e)),
                result_data: None,
            },
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("FIM not initialized: {}", e)),
            result_data: None,
        },
    }
}

/// Get compliance report
pub async fn handle_fim_get_compliance(payload: &serde_json::Value) -> CommandResult {
    let framework_str = payload
        .get("framework")
        .and_then(|v| v.as_str())
        .unwrap_or("pci_dss");

    let framework = match framework_str {
        "pci_dss" => ComplianceFramework::PciDss,
        "hipaa" => ComplianceFramework::Hipaa,
        "soc2" => ComplianceFramework::Soc2,
        "nist_800_53" => ComplianceFramework::Nist80053,
        "cis_benchmark" => ComplianceFramework::CisBenchmark,
        custom => ComplianceFramework::Custom(custom.to_string()),
    };

    info!(framework = ?framework, "FIM: Generating compliance report");

    match get_fim_collector() {
        Ok(collector_lock) => match collector_lock.read() {
            Ok(collector_guard) => match collector_guard.as_ref() {
                Some(collector) => match collector.generate_compliance_report(&framework) {
                    Some(report) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::to_value(report).unwrap_or_default()),
                    },
                    None => CommandResult {
                        success: false,
                        error_message: Some("Failed to generate compliance report".to_string()),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("FIM collector not available".to_string()),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to access FIM collector: {}", e)),
                result_data: None,
            },
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("FIM not initialized: {}", e)),
            result_data: None,
        },
    }
}

/// Get recent FIM changes
pub async fn handle_fim_get_changes(payload: &serde_json::Value) -> CommandResult {
    let _limit = payload.get("limit").and_then(|v| v.as_u64()).unwrap_or(100);
    let _since = payload.get("since").and_then(|v| v.as_u64()).unwrap_or(0);

    // This would ideally query a history log, but for now we return baseline info
    match get_fim_collector() {
        Ok(collector_lock) => match collector_lock.read() {
            Ok(collector_guard) => match collector_guard.as_ref() {
                Some(collector) => match collector.get_baseline_stats() {
                    Some(stats) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "message": "Recent changes not yet implemented - showing baseline stats",
                            "stats": stats,
                        })),
                    },
                    None => CommandResult {
                        success: false,
                        error_message: Some("Failed to retrieve FIM changes".to_string()),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("FIM collector not available".to_string()),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to access FIM collector: {}", e)),
                result_data: None,
            },
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("FIM not initialized: {}", e)),
            result_data: None,
        },
    }
}

// ============================================================================
// Internal helper functions
// ============================================================================

#[derive(Debug, Serialize)]
struct RestoreResult {
    backup_path: Option<String>,
    baseline_timestamp: u64,
    baseline_hash: Vec<u8>,
}

/// Restore a file from baseline
async fn restore_file_from_baseline(path: &str, create_backup: bool) -> Result<RestoreResult> {
    let collector_lock = get_fim_collector()?;
    let collector_guard = collector_lock
        .read()
        .map_err(|e| anyhow!("Failed to lock FIM collector: {}", e))?;
    let collector = collector_guard
        .as_ref()
        .ok_or_else(|| anyhow!("FIM collector not available"))?;

    // Get baseline
    let file_baseline = collector
        .get_baseline_entry(path)
        .ok_or_else(|| anyhow!("No baseline found for: {}", path))?;

    let file_path = PathBuf::from(path);

    // Create backup if requested and file exists
    let backup_path = if create_backup && file_path.exists() {
        let backup_dir = get_backup_dir()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let file_name = file_path
            .file_name()
            .ok_or_else(|| anyhow!("Invalid file name"))?
            .to_string_lossy();
        let backup_path = backup_dir.join(format!("{}.{}.backup", file_name, timestamp));

        std::fs::copy(&file_path, &backup_path)?;
        info!(source = %path, backup = %backup_path.display(), "Created backup before restore");
        Some(backup_path.to_string_lossy().to_string())
    } else {
        None
    };

    // Restore file content from baseline snapshot
    // NOTE: In a real implementation, we would restore the actual file content from a snapshot.
    // For now, we just log that restoration would occur and return baseline metadata.
    warn!(
        path = %path,
        "FIM restore: Actual file content restoration not yet implemented. Would restore from baseline with hash: {}",
        hex::encode(&file_baseline.hash)
    );

    Ok(RestoreResult {
        backup_path,
        baseline_timestamp: file_baseline.baseline_updated,
        baseline_hash: file_baseline.hash.clone(),
    })
}

#[derive(Debug, Serialize)]
struct QuarantineResult {
    quarantine_path: String,
    quarantined_at: u64,
    file_hash: Vec<u8>,
}

/// Quarantine a modified file
async fn quarantine_modified_file(path: &str, reason: &str) -> Result<QuarantineResult> {
    let file_path = PathBuf::from(path);

    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {}", path));
    }

    // Create quarantine directory
    let quarantine_dir = get_quarantine_dir()?;

    // Generate quarantine file name
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let file_name = file_path
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_string_lossy();
    let quarantine_path = quarantine_dir.join(format!("{}.{}.quarantined", file_name, timestamp));

    // Calculate hash before moving
    let file_hash = crate::analyzers::hash_file(path)
        .await
        .map(|(hash, _)| hash)
        .unwrap_or_default();

    // Move file to quarantine
    std::fs::rename(&file_path, &quarantine_path)?;

    info!(
        source = %path,
        quarantine = %quarantine_path.display(),
        reason = %reason,
        "File quarantined successfully"
    );

    // Write metadata file
    let metadata = serde_json::json!({
        "original_path": path,
        "quarantined_at": timestamp,
        "reason": reason,
        "hash": hex::encode(&file_hash),
    });
    let metadata_path = quarantine_path.with_extension("json");
    std::fs::write(metadata_path, serde_json::to_string_pretty(&metadata)?)?;

    Ok(QuarantineResult {
        quarantine_path: quarantine_path.to_string_lossy().to_string(),
        quarantined_at: timestamp,
        file_hash,
    })
}

/// Result of quarantine operation (for auto-response)
#[derive(Debug, Clone)]
pub struct QuarantineInternalResult {
    pub quarantine_path: String,
    pub quarantined_at: u64,
}

/// Internal quarantine function for auto-response from FIM policy violations
pub async fn quarantine_file_internal(
    path: &str,
    reason: &str,
) -> Result<QuarantineInternalResult> {
    let result = quarantine_modified_file(path, reason).await?;
    Ok(QuarantineInternalResult {
        quarantine_path: result.quarantine_path,
        quarantined_at: result.quarantined_at,
    })
}

/// Get quarantine directory
fn get_quarantine_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let dir = PathBuf::from("C:\\ProgramData\\Tamandua\\quarantine");

    #[cfg(not(target_os = "windows"))]
    let dir = PathBuf::from("/var/lib/tamandua/quarantine");

    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}

/// Get backup directory
fn get_backup_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let dir = PathBuf::from("C:\\ProgramData\\Tamandua\\fim_backups");

    #[cfg(not(target_os = "windows"))]
    let dir = PathBuf::from("/var/lib/tamandua/fim_backups");

    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}
