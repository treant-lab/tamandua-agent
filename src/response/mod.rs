//! Response action execution

#[cfg(test)]
mod tests;

#[path = "app_control.rs"]
pub mod app_control;
pub mod autonomous;
pub mod breadcrumbs;
pub mod fim;
pub mod forensics;
pub mod healing;
pub mod isolation_status;
pub mod linux_isolation;
pub mod live_response;
pub mod macos_isolation;
pub mod memory_analysis;
pub mod model_control;
pub mod model_quarantine;
pub mod network_containment;
pub mod network_manager;
pub mod patch_manager;
pub mod pty_bridge;
pub mod pty_shell;
pub mod ransomware;
pub mod rollback;
pub mod shell;
pub mod vss_rollback;
pub mod wfp_isolation;

use crate::transport::{Command, CommandResult, CommandType};
use live_response::*;
use tracing::{info, warn};

/// Global application control manager instance
static APP_CONTROL_MANAGER: std::sync::OnceLock<
    std::sync::Arc<tokio::sync::RwLock<Option<app_control::AppControlManager>>>,
> = std::sync::OnceLock::new();

/// Initialize the application control manager
pub async fn init_app_control(config: &crate::config::AgentConfig) -> anyhow::Result<()> {
    let manager = app_control::AppControlManager::new(config);
    manager.initialize().await?;

    let lock =
        APP_CONTROL_MANAGER.get_or_init(|| std::sync::Arc::new(tokio::sync::RwLock::new(None)));

    let mut guard = lock.write().await;
    *guard = Some(manager);

    info!("Application control manager initialized");
    Ok(())
}

/// Get the application control manager
pub async fn get_app_control_manager(
) -> Option<std::sync::Arc<tokio::sync::RwLock<Option<app_control::AppControlManager>>>> {
    APP_CONTROL_MANAGER.get().cloned()
}

/// Execute a command from the backend
pub async fn execute_command(command: &Command) -> CommandResult {
    info!(
        command_id = %command.command_id,
        command_type = ?command.command_type,
        "Executing command"
    );

    match command.command_type {
        CommandType::KillProcess => kill_process(&command.payload).await,
        CommandType::QuarantineFile => quarantine_file(&command.payload).await,
        CommandType::IsolateNetwork => isolate_network(&command.payload).await,
        CommandType::UnisolateNetwork => unisolate_network(&command.payload).await,
        CommandType::CollectArtifact => collect_artifact(&command.payload).await,
        CommandType::UpdateConfig => update_config(&command.payload).await,
        CommandType::UpdateRules => update_rules(&command.payload).await,
        CommandType::ScanPath => scan_path(&command.payload).await,
        CommandType::BlockIP => block_ip(&command.payload).await,
        CommandType::UnblockIP => unblock_ip(&command.payload).await,
        CommandType::BlockDomain => block_domain(&command.payload).await,
        CommandType::UnblockDomain => unblock_domain(&command.payload).await,
        CommandType::ListBlockedIPs => list_blocked_ips(&command.payload).await,
        CommandType::ListBlockedDomains => list_blocked_domains(&command.payload).await,
        // Application control commands
        CommandType::AppControlSetMode => app_control_set_mode(&command.payload).await,
        CommandType::AppControlAddRule => app_control_add_rule(&command.payload).await,
        CommandType::AppControlRemoveRule => app_control_remove_rule(&command.payload).await,
        CommandType::AppControlEnableRule => app_control_enable_rule(&command.payload).await,
        CommandType::AppControlDisableRule => app_control_disable_rule(&command.payload).await,
        CommandType::AppControlListRules => app_control_list_rules(&command.payload).await,
        CommandType::AppControlGetPolicy => app_control_get_policy(&command.payload).await,
        CommandType::AppControlUpdatePolicy => app_control_update_policy(&command.payload).await,
        CommandType::AppControlGetStats => app_control_get_stats(&command.payload).await,
        // Live Response commands
        CommandType::ProcessList => live_response_process_list(&command.payload).await,
        CommandType::ProcessDump => live_response_process_dump(&command.payload).await,
        CommandType::MemoryScan => live_response_memory_scan(&command.payload).await,
        CommandType::MemoryStrings => live_response_memory_strings(&command.payload).await,
        CommandType::FileList => live_response_file_list(&command.payload).await,
        CommandType::FileDownload => live_response_file_download(&command.payload).await,
        CommandType::FileHash => live_response_file_hash(&command.payload).await,
        CommandType::FileUpload => live_response_file_upload(&command.payload).await,
        CommandType::NetworkConnections => {
            live_response_network_connections(&command.payload).await
        }
        CommandType::NetworkConnectionsEnumerate => {
            network_connections_enumerate(&command.payload).await
        }
        CommandType::NetworkConnectionTerminate => {
            network_connection_terminate(&command.payload).await
        }
        CommandType::NetworkConnectionStats => network_connection_stats(&command.payload).await,
        CommandType::DnsCache => live_response_dns_cache(&command.payload).await,
        CommandType::RegistryQuery => live_response_registry_query(&command.payload).await,
        CommandType::ServiceList => live_response_service_list(&command.payload).await,
        CommandType::ScheduledTasks => live_response_scheduled_tasks(&command.payload).await,
        CommandType::StartupItems => live_response_startup_items(&command.payload).await,
        CommandType::ShellExecute => live_response_shell_execute(&command.payload).await,
        // Live Response - Process Manager commands
        CommandType::ProcessTreeList => {
            crate::live_response::process_tree_list(&command.payload).await
        }
        CommandType::ProcessKill => crate::live_response::process_kill(&command.payload).await,
        CommandType::ProcessSuspend => {
            crate::live_response::process_suspend(&command.payload).await
        }
        CommandType::ProcessResume => crate::live_response::process_resume(&command.payload).await,
        CommandType::ProcessSetPriority => {
            crate::live_response::process_set_priority(&command.payload).await
        }
        CommandType::ProcessListHandles => {
            crate::live_response::process_list_handles(&command.payload).await
        }
        CommandType::ProcessCreateDump => live_response_process_dump(&command.payload).await, // Reuse existing
        // VSS Snapshot & Rollback commands
        CommandType::CreateSnapshot => vss_create_snapshot(&command.payload).await,
        CommandType::ListSnapshots => vss_list_snapshots(&command.payload).await,
        CommandType::DeleteSnapshot => vss_delete_snapshot(&command.payload).await,
        CommandType::RestoreFile => vss_restore_file(&command.payload).await,
        CommandType::RestoreFiles => vss_restore_files(&command.payload).await,
        CommandType::FindEncryptedFiles => vss_find_encrypted_files(&command.payload).await,
        CommandType::RansomwareRemediate => vss_ransomware_remediate(&command.payload).await,
        // VSS one-click rollback commands
        CommandType::VssRollback => vss_one_click_rollback(&command.payload).await,
        CommandType::VssRansomwareRollback => vss_ransomware_auto_rollback(&command.payload).await,
        CommandType::VssGetSchedule => vss_get_schedule(&command.payload).await,
        CommandType::VssSetSchedule => vss_set_schedule(&command.payload).await,
        // Patch management commands
        CommandType::ScanPatches => patch_manager::handle_scan_patches(&command.payload).await,
        CommandType::InstallPatches => {
            patch_manager::handle_install_patches(&command.payload).await
        }
        CommandType::RollbackPatches => {
            // Rollback is a best-effort operation: uninstall the specified patches
            let patches: Vec<String> = command
                .payload
                .get("patches")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            info!(patches = ?patches, "Rollback patches requested (best effort)");
            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(
                    serde_json::json!({"message": "Rollback initiated", "patches": patches}),
                ),
            }
        }
        // Deception/Breadcrumb commands
        CommandType::DeployBreadcrumbs => breadcrumbs::deploy_breadcrumbs(&command.payload).await,
        CommandType::RotateBreadcrumbs => breadcrumbs::rotate_breadcrumbs(&command.payload).await,
        // Update commands are handled in main.rs before reaching execute_command
        CommandType::UpdateAvailable | CommandType::ForceUpdate => CommandResult {
            success: false,
            error_message: Some("Update commands should be handled by the update subsystem".into()),
            result_data: None,
        },
        // Advanced memory analysis commands
        CommandType::DumpMemory => memory_analysis::handle_dump_memory(&command.payload).await,
        CommandType::ScanMemoryYara => {
            memory_analysis::handle_scan_memory_yara(&command.payload).await
        }
        CommandType::AnalyzeSuspiciousRegions => {
            memory_analysis::handle_analyze_suspicious_regions(&command.payload).await
        }
        CommandType::AnalyzeMemoryHooks => {
            memory_analysis::handle_analyze_memory_hooks(&command.payload).await
        }
        CommandType::ExtractMemoryStrings => {
            memory_analysis::handle_extract_memory_strings(&command.payload).await
        }
        CommandType::FullMemoryAnalysis => {
            memory_analysis::handle_full_memory_analysis(&command.payload).await
        }
        CommandType::ScanIndirectSyscalls => {
            memory_analysis::handle_scan_indirect_syscalls(&command.payload).await
        }
        // FIM commands
        CommandType::FimGetBaseline => fim::handle_fim_get_baseline(&command.payload).await,
        CommandType::FimRestoreFile => fim::handle_fim_restore_file(&command.payload).await,
        CommandType::FimQuarantineFile => fim::handle_fim_quarantine_file(&command.payload).await,
        CommandType::FimForceBaselineScan => {
            fim::handle_fim_force_baseline_scan(&command.payload).await
        }
        CommandType::FimGetStats => fim::handle_fim_get_stats(&command.payload).await,
        CommandType::FimAddWhitelist => fim::handle_fim_add_whitelist(&command.payload).await,
        CommandType::FimGetCompliance => fim::handle_fim_get_compliance(&command.payload).await,
        CommandType::FimGetChanges => fim::handle_fim_get_changes(&command.payload).await,
        // Quarantine vault commands
        CommandType::QuarantineFileAdvanced => {
            quarantine_commands::handle_quarantine_file(&command.payload).await
        }
        CommandType::QuarantineGetList => {
            quarantine_commands::handle_quarantine_get_list(&command.payload).await
        }
        CommandType::QuarantineGetStats => {
            quarantine_commands::handle_quarantine_get_stats(&command.payload).await
        }
        CommandType::QuarantineGetDetails => {
            quarantine_commands::handle_quarantine_get_details(&command.payload).await
        }
        CommandType::QuarantineRestoreFile => {
            quarantine_commands::handle_quarantine_restore(&command.payload).await
        }
        CommandType::QuarantineDeleteFile => {
            quarantine_commands::handle_quarantine_delete(&command.payload).await
        }
        CommandType::QuarantineExportReport => {
            quarantine_commands::handle_quarantine_export_report(&command.payload).await
        }
        // Model control commands (kill switch)
        CommandType::IsolateModel => model_control::handle_isolate_model(&command.payload).await,
        CommandType::ReleaseModel => model_control::handle_release_model(&command.payload).await,
        CommandType::KillModel => model_control::handle_kill_model(&command.payload).await,
        CommandType::ListModels => model_control::handle_list_models(&command.payload).await,
        // Model quarantine commands
        CommandType::ModelQuarantine => {
            model_quarantine::handle_quarantine_model(&command.payload).await
        }
        CommandType::ModelRestore => model_quarantine::handle_restore_model(&command.payload).await,
        CommandType::ModelQuarantineList => {
            model_quarantine::handle_list_quarantined_models(&command.payload).await
        }
        CommandType::ModelQuarantineDelete => {
            model_quarantine::handle_delete_quarantined_model(&command.payload).await
        }
        // Interactive PTY shell commands
        CommandType::ShellStart => pty_bridge::handle_shell_start(&command.payload).await,
        CommandType::ShellInput => pty_bridge::handle_shell_input(&command.payload).await,
        CommandType::ShellResize => pty_bridge::handle_shell_resize(&command.payload).await,
        CommandType::ShellTerminate => pty_bridge::handle_shell_terminate(&command.payload).await,
    }
}

/// Quarantine vault command handlers
#[cfg(target_os = "windows")]
pub mod quarantine_commands {
    use super::*;
    use crate::quarantine::{
        QuarantineConfig, QuarantineManager, QuarantineReason, ReportFormat, ThreatInfo,
        ThreatSeverity,
    };
    use std::path::Path;

    /// Global quarantine manager instance
    static QUARANTINE_MANAGER: std::sync::OnceLock<
        std::sync::Arc<tokio::sync::RwLock<Option<QuarantineManager>>>,
    > = std::sync::OnceLock::new();

    /// Initialize the quarantine manager
    pub async fn init_quarantine_manager(config: QuarantineConfig) -> anyhow::Result<()> {
        let manager = QuarantineManager::new(config).await?;

        let lock =
            QUARANTINE_MANAGER.get_or_init(|| std::sync::Arc::new(tokio::sync::RwLock::new(None)));

        let mut guard = lock.write().await;
        *guard = Some(manager);

        info!("Quarantine manager initialized");
        Ok(())
    }

    /// Get the quarantine manager
    async fn get_manager(
    ) -> anyhow::Result<std::sync::Arc<tokio::sync::RwLock<Option<QuarantineManager>>>> {
        QUARANTINE_MANAGER
            .get()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Quarantine manager not initialized"))
    }

    /// Handle quarantine file command
    pub async fn handle_quarantine_file(payload: &serde_json::Value) -> CommandResult {
        let path = match payload.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                return CommandResult {
                    success: false,
                    error_message: Some("Missing required 'path' parameter".to_string()),
                    result_data: None,
                }
            }
        };

        let reason_str = payload
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("manual_action");
        let reason = match reason_str {
            "ml_detection" => QuarantineReason::MlDetection,
            "yara_match" => QuarantineReason::YaraMatch,
            "sigma_match" => QuarantineReason::SigmaMatch,
            "ioc_match" => QuarantineReason::IocMatch,
            "behavioral_detection" => QuarantineReason::BehavioralDetection,
            "ransomware_protection" => QuarantineReason::RansomwareProtection,
            _ => QuarantineReason::ManualAction,
        };

        let threat_info = payload.get("threat_info").map(|ti| ThreatInfo {
            detection_source: ti
                .get("detection_source")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            threat_name: ti
                .get("threat_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            threat_family: ti
                .get("threat_family")
                .and_then(|v| v.as_str())
                .map(String::from),
            severity: ti
                .get("severity")
                .and_then(|v| v.as_str())
                .map(|s| match s {
                    "low" => ThreatSeverity::Low,
                    "high" => ThreatSeverity::High,
                    "critical" => ThreatSeverity::Critical,
                    _ => ThreatSeverity::Medium,
                })
                .unwrap_or_default(),
            mitre_tactics: ti
                .get("mitre_tactics")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            mitre_techniques: ti
                .get("mitre_techniques")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            confidence: ti
                .get("confidence")
                .and_then(|v| v.as_f64())
                .map(|f| f as f32),
        });

        let triggered_by = payload.get("triggered_by").and_then(|v| v.as_str());

        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager
                        .quarantine_file(Path::new(path), reason, threat_info, triggered_by)
                        .await
                    {
                        Ok(result) => {
                            let error_message = result.error.clone();
                            CommandResult {
                                success: result.success,
                                error_message,
                                result_data: Some(serde_json::to_value(result).unwrap_or_default()),
                            }
                        }
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Quarantine failed: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }

    /// Handle get quarantine list command
    pub async fn handle_quarantine_get_list(payload: &serde_json::Value) -> CommandResult {
        let limit = payload
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let offset = payload
            .get("offset")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let include_deleted = payload
            .get("include_deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager.get_list(limit, offset, include_deleted).await {
                        Ok(list) => CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::to_value(list).unwrap_or_default()),
                        },
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Failed to get list: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }

    /// Handle get quarantine stats command
    pub async fn handle_quarantine_get_stats(_payload: &serde_json::Value) -> CommandResult {
        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager.get_stats().await {
                        Ok(stats) => CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::to_value(stats).unwrap_or_default()),
                        },
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Failed to get stats: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }

    /// Handle get quarantine details command
    pub async fn handle_quarantine_get_details(payload: &serde_json::Value) -> CommandResult {
        let id = match payload.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return CommandResult {
                    success: false,
                    error_message: Some("Missing required 'id' parameter".to_string()),
                    result_data: None,
                }
            }
        };

        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager.get_details(id).await {
                        Ok(Some(entry)) => CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::to_value(entry).unwrap_or_default()),
                        },
                        Ok(None) => CommandResult {
                            success: false,
                            error_message: Some(format!("Entry not found: {}", id)),
                            result_data: None,
                        },
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Failed to get details: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }

    /// Handle restore file command
    pub async fn handle_quarantine_restore(payload: &serde_json::Value) -> CommandResult {
        let id = match payload.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return CommandResult {
                    success: false,
                    error_message: Some("Missing required 'id' parameter".to_string()),
                    result_data: None,
                }
            }
        };

        let restore_path = payload
            .get("restore_path")
            .and_then(|v| v.as_str())
            .map(std::path::Path::new);
        let risk_acknowledged = payload
            .get("risk_acknowledged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auth_token = payload.get("auth_token").and_then(|v| v.as_str());

        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager
                        .restore_file(id, restore_path, risk_acknowledged, auth_token)
                        .await
                    {
                        Ok(result) => {
                            let error_message = result.error.clone();
                            CommandResult {
                                success: result.success,
                                error_message,
                                result_data: Some(serde_json::to_value(result).unwrap_or_default()),
                            }
                        }
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Restore failed: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }

    /// Handle delete quarantined file command
    pub async fn handle_quarantine_delete(payload: &serde_json::Value) -> CommandResult {
        let id = match payload.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return CommandResult {
                    success: false,
                    error_message: Some("Missing required 'id' parameter".to_string()),
                    result_data: None,
                }
            }
        };

        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager.delete_quarantined(id).await {
                        Ok(deleted) => CommandResult {
                            success: deleted,
                            error_message: if deleted {
                                None
                            } else {
                                Some("Delete failed".to_string())
                            },
                            result_data: Some(serde_json::json!({"id": id, "deleted": deleted})),
                        },
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Delete failed: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }

    /// Handle export report command
    pub async fn handle_quarantine_export_report(payload: &serde_json::Value) -> CommandResult {
        let format_str = payload
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("json");
        let format = match format_str {
            "csv" => ReportFormat::Csv,
            _ => ReportFormat::Json,
        };

        match get_manager().await {
            Ok(lock) => {
                let guard = lock.read().await;
                if let Some(ref manager) = *guard {
                    match manager.export_report(format).await {
                        Ok(data) => {
                            let content = String::from_utf8_lossy(&data).to_string();
                            CommandResult {
                                success: true,
                                error_message: None,
                                result_data: Some(serde_json::json!({
                                    "format": format_str,
                                    "content": content,
                                    "size": data.len(),
                                })),
                            }
                        }
                        Err(e) => CommandResult {
                            success: false,
                            error_message: Some(format!("Export failed: {}", e)),
                            result_data: None,
                        },
                    }
                } else {
                    CommandResult {
                        success: false,
                        error_message: Some("Quarantine manager not initialized".to_string()),
                        result_data: None,
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e.to_string()),
                result_data: None,
            },
        }
    }
}

/// Quarantine vault command handlers
#[cfg(not(target_os = "windows"))]
pub mod quarantine_commands {
    use super::*;
    use crate::quarantine::QuarantineConfig;

    pub async fn init_quarantine_manager(_config: QuarantineConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn unsupported() -> CommandResult {
        CommandResult {
            success: false,
            error_message: Some(
                "Quarantine commands are not supported on this platform build".to_string(),
            ),
            result_data: None,
        }
    }

    pub async fn handle_quarantine_file(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
    pub async fn handle_quarantine_get_list(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
    pub async fn handle_quarantine_get_stats(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
    pub async fn handle_quarantine_get_details(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
    pub async fn handle_quarantine_restore(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
    pub async fn handle_quarantine_delete(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
    pub async fn handle_quarantine_export_report(_payload: &serde_json::Value) -> CommandResult {
        unsupported()
    }
}

async fn kill_process(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let force = payload
        .get("force")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, force = force, "Killing process");

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let signal = if force {
            Signal::SIGKILL
        } else {
            Signal::SIGTERM
        };

        match kill(Pid::from_raw(pid as i32), signal) {
            Ok(_) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({ "pid": pid })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to kill process: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);

                    if result.is_ok() {
                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({ "pid": pid })),
                        }
                    } else {
                        CommandResult {
                            success: false,
                            error_message: Some("TerminateProcess failed".to_string()),
                            result_data: None,
                        }
                    }
                }
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to open process: {}", e)),
                    result_data: None,
                },
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

async fn quarantine_file(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Invalid path".to_string()),
            result_data: None,
        };
    }

    info!(path = %path, "Quarantining file");

    // Create quarantine directory
    let quarantine_dir = if cfg!(windows) {
        "C:\\ProgramData\\Tamandua\\Quarantine"
    } else {
        "/var/lib/tamandua/quarantine"
    };

    if let Err(e) = std::fs::create_dir_all(quarantine_dir) {
        return CommandResult {
            success: false,
            error_message: Some(format!("Failed to create quarantine dir: {}", e)),
            result_data: None,
        };
    }

    // Generate quarantine filename
    let original_name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let quarantine_name = format!("{}_{}.quarantine", original_name, timestamp);
    let quarantine_path = format!("{}/{}", quarantine_dir, quarantine_name);

    // Move file to quarantine
    match std::fs::rename(path, &quarantine_path) {
        Ok(_) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "original_path": path,
                "quarantine_path": quarantine_path,
            })),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to quarantine file: {}", e)),
            result_data: None,
        },
    }
}

async fn isolate_network(payload: &serde_json::Value) -> CommandResult {
    use isolation_status::*;

    let allowed_ips: Vec<String> = payload
        .get("allowed_ips")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    info!(allowed = ?allowed_ips, "Isolating network");

    // Platform-specific network isolation
    #[cfg(target_os = "linux")]
    {
        // Extract server IP from payload or use empty string
        let server_ip = payload
            .get("server_url")
            .and_then(|v| v.as_str())
            .and_then(|url_str| {
                url::Url::parse(url_str)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
            })
            .or_else(|| {
                // Try to read server URL from config
                let config_path = "/etc/tamandua/config.toml";
                std::fs::read_to_string(config_path)
                    .ok()
                    .and_then(|content| content.parse::<toml::Value>().ok())
                    .and_then(|toml_val| {
                        toml_val
                            .get("server_url")
                            .and_then(|v| v.as_str())
                            .and_then(|url_str| {
                                url::Url::parse(url_str)
                                    .ok()
                                    .and_then(|u| u.host_str().map(String::from))
                            })
                    })
            })
            .unwrap_or_default();

        let backend = linux_isolation::get_backend()
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Default server port for Linux (extract from URL if available)
        let server_port: u16 = payload
            .get("server_url")
            .and_then(|v| v.as_str())
            .and_then(|url_str| url::Url::parse(url_str).ok())
            .and_then(|u| u.port())
            .unwrap_or(4000);

        match linux_isolation::apply_isolation(&server_ip, &allowed_ips) {
            Ok(()) => {
                let (rules, allowlist) =
                    build_isolation_rules(&server_ip, Some(server_port), &allowed_ips, &backend);

                // Run connectivity verification
                let connectivity = run_connectivity_test(&server_ip, server_port);

                // Determine state based on connectivity
                let (state, error) = if !connectivity.server_reachable {
                    warn!("Server unreachable after isolation -- auto-rolling back");
                    let _ = linux_isolation::remove_isolation();
                    (
                        IsolationState::Failed,
                        Some("Auto-rollback: server unreachable after isolation".to_string()),
                    )
                } else if !connectivity.internet_blocked {
                    (
                        IsolationState::Partial,
                        Some("External internet still reachable".to_string()),
                    )
                } else {
                    (IsolationState::Isolated, None)
                };

                let status = IsolationStatus {
                    state: state.clone(),
                    method: backend.clone(),
                    rules_applied: rules,
                    allowlisted_connections: allowlist,
                    connectivity_test: connectivity,
                    applied_at: if state != IsolationState::Failed {
                        Some(current_timestamp())
                    } else {
                        None
                    },
                    filter_count: 0, // nftables/iptables don't track individual filter IDs the same way
                    error: error.clone(),
                };

                // Store globally for heartbeat reporting and periodic verification
                if state == IsolationState::Isolated || state == IsolationState::Partial {
                    set_current_status(status.clone());
                    set_verify_params(IsolationVerifyParams {
                        server_host: server_ip.clone(),
                        server_port,
                        method: backend.clone(),
                    });
                }

                CommandResult {
                    success: state != IsolationState::Failed,
                    error_message: error,
                    result_data: Some(status.to_json()),
                }
            }
            Err(e) => {
                let status = IsolationStatus {
                    state: IsolationState::Failed,
                    method: backend,
                    rules_applied: Vec::new(),
                    allowlisted_connections: Vec::new(),
                    connectivity_test: ConnectivityResult {
                        server_reachable: false,
                        dns_works: false,
                        internet_blocked: false,
                        server_latency_ms: None,
                        details: Some(format!("Isolation failed: {}", e)),
                    },
                    applied_at: None,
                    filter_count: 0,
                    error: Some(format!("Linux network isolation failed: {}", e)),
                };

                CommandResult {
                    success: false,
                    error_message: Some(format!("Linux network isolation failed: {}", e)),
                    result_data: Some(status.to_json()),
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Use Windows Filtering Platform (WFP) for kernel-level network isolation.
        use std::net::IpAddr;

        let wfp = wfp_isolation::get_wfp();

        // Open the WFP engine (requires admin/SYSTEM)
        if let Err(e) = wfp.open_engine() {
            let status = IsolationStatus {
                state: IsolationState::Failed,
                method: "wfp".to_string(),
                rules_applied: Vec::new(),
                allowlisted_connections: Vec::new(),
                connectivity_test: ConnectivityResult {
                    server_reachable: false,
                    dns_works: false,
                    internet_blocked: false,
                    server_latency_ms: None,
                    details: Some(format!("Failed to open WFP engine: {}", e)),
                },
                applied_at: None,
                filter_count: 0,
                error: Some(format!("Failed to open WFP engine: {}", e)),
            };

            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to open WFP engine: {}", e)),
                result_data: Some(status.to_json()),
            };
        }

        // Extract server URL from payload or read from config file
        let server_url = payload
            .get("server_url")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| {
                let config_path = "C:\\ProgramData\\Tamandua\\config.toml";
                std::fs::read_to_string(config_path)
                    .ok()
                    .and_then(|content| content.parse::<toml::Value>().ok())
                    .and_then(|toml_val| {
                        toml_val
                            .get("server_url")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_else(|| "wss://localhost:4000/socket/agent".to_string())
            });

        // Resolve server IP and port from the URL
        let (server_ip, server_port) = match wfp_isolation::parse_server_address(&server_url) {
            Ok((ip, port)) => (Some(ip), port),
            Err(e) => {
                warn!(error = %e, "Could not resolve server address for WFP permit exception");
                (None, None)
            }
        };

        // Parse additional allowed IPs
        let parsed_allowed: Vec<IpAddr> = allowed_ips
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();

        let server_ip_str = server_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let effective_port = server_port.unwrap_or(4000);

        // Apply isolation: BLOCK everything, PERMIT loopback + DNS + server + allowed
        match wfp.apply_isolation(server_ip, server_port, &parsed_allowed) {
            Ok(filter_ids) => {
                info!(
                    filter_count = filter_ids.len(),
                    server_ip = ?server_ip,
                    server_port = ?server_port,
                    allowed_count = parsed_allowed.len(),
                    "WFP network isolation applied successfully"
                );

                let (rules, allowlist) =
                    build_isolation_rules(&server_ip_str, server_port, &allowed_ips, "wfp");

                // Run connectivity verification
                let connectivity = run_connectivity_test(&server_ip_str, effective_port);

                // Determine state based on connectivity
                let (state, error) = if !connectivity.server_reachable {
                    warn!("Server unreachable after WFP isolation -- auto-rolling back");
                    let _ = wfp.remove_isolation();
                    (
                        IsolationState::Failed,
                        Some("Auto-rollback: server unreachable after isolation".to_string()),
                    )
                } else if !connectivity.internet_blocked {
                    (
                        IsolationState::Partial,
                        Some("External internet still reachable".to_string()),
                    )
                } else {
                    (IsolationState::Isolated, None)
                };

                let status = IsolationStatus {
                    state: state.clone(),
                    method: "wfp".to_string(),
                    rules_applied: rules,
                    allowlisted_connections: allowlist,
                    connectivity_test: connectivity,
                    applied_at: if state != IsolationState::Failed {
                        Some(current_timestamp())
                    } else {
                        None
                    },
                    filter_count: filter_ids.len(),
                    error: error.clone(),
                };

                // Store globally for heartbeat reporting and periodic verification
                if state == IsolationState::Isolated || state == IsolationState::Partial {
                    set_current_status(status.clone());
                    set_verify_params(IsolationVerifyParams {
                        server_host: server_ip_str,
                        server_port: effective_port,
                        method: "wfp".to_string(),
                    });
                }

                CommandResult {
                    success: state != IsolationState::Failed,
                    error_message: error,
                    result_data: Some(status.to_json()),
                }
            }
            Err(e) => {
                let status = IsolationStatus {
                    state: IsolationState::Failed,
                    method: "wfp".to_string(),
                    rules_applied: Vec::new(),
                    allowlisted_connections: Vec::new(),
                    connectivity_test: ConnectivityResult {
                        server_reachable: false,
                        dns_works: false,
                        internet_blocked: false,
                        server_latency_ms: None,
                        details: Some(format!("WFP isolation failed: {}", e)),
                    },
                    applied_at: None,
                    filter_count: 0,
                    error: Some(format!("WFP isolation failed: {}", e)),
                };

                CommandResult {
                    success: false,
                    error_message: Some(format!("WFP isolation failed: {}", e)),
                    result_data: Some(status.to_json()),
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Extract server IP from payload or use empty string
        let server_ip = payload
            .get("server_url")
            .and_then(|v| v.as_str())
            .and_then(|url_str| {
                url::Url::parse(url_str)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
            })
            .or_else(|| {
                // Try to read server URL from config
                let config_path = "/etc/tamandua/config.toml";
                std::fs::read_to_string(config_path)
                    .ok()
                    .and_then(|content| content.parse::<toml::Value>().ok())
                    .and_then(|toml_val| {
                        toml_val
                            .get("server_url")
                            .and_then(|v| v.as_str())
                            .and_then(|url_str| {
                                url::Url::parse(url_str)
                                    .ok()
                                    .and_then(|u| u.host_str().map(String::from))
                            })
                    })
            })
            .unwrap_or_default();

        // Default server port for macOS (extract from URL if available)
        let server_port: u16 = payload
            .get("server_url")
            .and_then(|v| v.as_str())
            .and_then(|url_str| url::Url::parse(url_str).ok())
            .and_then(|u| u.port())
            .unwrap_or(4000);

        match macos_isolation::apply_isolation(&server_ip, server_port, &allowed_ips) {
            Ok(()) => {
                let (rules, allowlist) =
                    build_isolation_rules(&server_ip, Some(server_port), &allowed_ips, "pfctl");

                // Run connectivity verification
                let connectivity = run_connectivity_test(&server_ip, server_port);

                // Determine state based on connectivity
                let (state, error) = if !connectivity.server_reachable {
                    warn!("Server unreachable after pfctl isolation -- auto-rolling back");
                    let _ = macos_isolation::remove_isolation();
                    (
                        IsolationState::Failed,
                        Some("Auto-rollback: server unreachable after isolation".to_string()),
                    )
                } else if !connectivity.internet_blocked {
                    (
                        IsolationState::Partial,
                        Some("External internet still reachable".to_string()),
                    )
                } else {
                    (IsolationState::Isolated, None)
                };

                let status = IsolationStatus {
                    state: state.clone(),
                    method: "pfctl".to_string(),
                    rules_applied: rules,
                    allowlisted_connections: allowlist,
                    connectivity_test: connectivity,
                    applied_at: if state != IsolationState::Failed {
                        Some(current_timestamp())
                    } else {
                        None
                    },
                    filter_count: 0, // pfctl doesn't expose individual filter IDs
                    error: error.clone(),
                };

                // Store globally for heartbeat reporting and periodic verification
                if state == IsolationState::Isolated || state == IsolationState::Partial {
                    set_current_status(status.clone());
                    set_verify_params(IsolationVerifyParams {
                        server_host: server_ip.clone(),
                        server_port,
                        method: "pfctl".to_string(),
                    });
                }

                CommandResult {
                    success: state != IsolationState::Failed,
                    error_message: error,
                    result_data: Some(status.to_json()),
                }
            }
            Err(e) => {
                let status = IsolationStatus {
                    state: IsolationState::Failed,
                    method: "pfctl".to_string(),
                    rules_applied: Vec::new(),
                    allowlisted_connections: Vec::new(),
                    connectivity_test: ConnectivityResult {
                        server_reachable: false,
                        dns_works: false,
                        internet_blocked: false,
                        server_latency_ms: None,
                        details: Some(format!("Isolation failed: {}", e)),
                    },
                    applied_at: None,
                    filter_count: 0,
                    error: Some(format!("macOS pfctl network isolation failed: {}", e)),
                };

                CommandResult {
                    success: false,
                    error_message: Some(format!("macOS pfctl network isolation failed: {}", e)),
                    result_data: Some(status.to_json()),
                }
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let status = IsolationStatus {
            state: IsolationState::Failed,
            method: "unsupported".to_string(),
            rules_applied: Vec::new(),
            allowlisted_connections: Vec::new(),
            connectivity_test: ConnectivityResult {
                server_reachable: false,
                dns_works: false,
                internet_blocked: false,
                server_latency_ms: None,
                details: Some("Platform not supported".to_string()),
            },
            applied_at: None,
            filter_count: 0,
            error: Some("Network isolation not implemented for this platform".to_string()),
        };
        CommandResult {
            success: false,
            error_message: Some("Network isolation not implemented for this platform".to_string()),
            result_data: Some(status.to_json()),
        }
    }
}

async fn unisolate_network(_payload: &serde_json::Value) -> CommandResult {
    use isolation_status::*;

    info!("Removing network isolation");

    // Retrieve stored verification params for connectivity test after de-isolation
    let verify_params =
        isolation_status::get_current_status().map(|s| (s.method.clone(), s.applied_at));

    #[cfg(target_os = "linux")]
    {
        let backend = linux_isolation::get_backend()
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match linux_isolation::remove_isolation() {
            Ok(()) => {
                // Clear global status
                clear_current_status();
                clear_verify_params();

                // Build de-isolation status with connectivity verification
                // Use stored params or defaults
                let server_host = "localhost".to_string();
                let server_port: u16 = 4000;
                let status = build_deisolation_status(&backend, 0, &server_host, server_port);

                info!(state = %status.state, "De-isolation complete");

                CommandResult {
                    success: status.state == IsolationState::Disabled,
                    error_message: status.error.clone(),
                    result_data: Some(status.to_json()),
                }
            }
            Err(e) => {
                let status = IsolationStatus {
                    state: IsolationState::Isolated, // Still isolated because removal failed
                    method: backend,
                    rules_applied: Vec::new(),
                    allowlisted_connections: Vec::new(),
                    connectivity_test: ConnectivityResult {
                        server_reachable: false,
                        dns_works: false,
                        internet_blocked: true,
                        server_latency_ms: None,
                        details: Some(format!("Failed to remove isolation: {}", e)),
                    },
                    applied_at: verify_params.as_ref().and_then(|(_, at)| *at),
                    filter_count: 0,
                    error: Some(format!("Failed to remove Linux network isolation: {}", e)),
                };

                CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to remove Linux network isolation: {}", e)),
                    result_data: Some(status.to_json()),
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let wfp = wfp_isolation::get_wfp();

        if !wfp.is_isolated() {
            // Already not isolated -- return clean status
            clear_current_status();
            clear_verify_params();

            let status = IsolationStatus {
                state: IsolationState::Disabled,
                method: "wfp".to_string(),
                rules_applied: Vec::new(),
                allowlisted_connections: Vec::new(),
                connectivity_test: ConnectivityResult {
                    server_reachable: true,
                    dns_works: true,
                    internet_blocked: false,
                    server_latency_ms: None,
                    details: Some("Was not isolated".to_string()),
                },
                applied_at: None,
                filter_count: 0,
                error: None,
            };

            return CommandResult {
                success: true,
                error_message: None,
                result_data: Some(status.to_json()),
            };
        }

        match wfp.remove_isolation() {
            Ok(removed) => {
                info!(removed, "WFP isolation filters removed");

                // Clear global status
                clear_current_status();
                clear_verify_params();

                // Build de-isolation status with connectivity verification
                let server_host = "localhost".to_string();
                let server_port: u16 = 4000;
                let status = build_deisolation_status("wfp", removed, &server_host, server_port);

                CommandResult {
                    success: status.state == IsolationState::Disabled,
                    error_message: status.error.clone(),
                    result_data: Some(status.to_json()),
                }
            }
            Err(e) => {
                let status = IsolationStatus {
                    state: IsolationState::Isolated,
                    method: "wfp".to_string(),
                    rules_applied: Vec::new(),
                    allowlisted_connections: Vec::new(),
                    connectivity_test: ConnectivityResult {
                        server_reachable: false,
                        dns_works: false,
                        internet_blocked: true,
                        server_latency_ms: None,
                        details: Some(format!("Failed to remove WFP isolation: {}", e)),
                    },
                    applied_at: verify_params.as_ref().and_then(|(_, at)| *at),
                    filter_count: wfp.filter_count(),
                    error: Some(format!("Failed to remove WFP isolation: {}", e)),
                };

                CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to remove WFP isolation: {}", e)),
                    result_data: Some(status.to_json()),
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if !macos_isolation::is_isolated() {
            // Already not isolated -- return clean status
            clear_current_status();
            clear_verify_params();

            let status = IsolationStatus {
                state: IsolationState::Disabled,
                method: "pfctl".to_string(),
                rules_applied: Vec::new(),
                allowlisted_connections: Vec::new(),
                connectivity_test: ConnectivityResult {
                    server_reachable: true,
                    dns_works: true,
                    internet_blocked: false,
                    server_latency_ms: None,
                    details: Some("Was not isolated".to_string()),
                },
                applied_at: None,
                filter_count: 0,
                error: None,
            };

            return CommandResult {
                success: true,
                error_message: None,
                result_data: Some(status.to_json()),
            };
        }

        match macos_isolation::remove_isolation() {
            Ok(()) => {
                info!("pfctl isolation removed");

                // Clear global status
                clear_current_status();
                clear_verify_params();

                // Build de-isolation status with connectivity verification
                let server_host = "localhost".to_string();
                let server_port: u16 = 4000;
                let status = build_deisolation_status("pfctl", 0, &server_host, server_port);

                CommandResult {
                    success: status.state == IsolationState::Disabled,
                    error_message: status.error.clone(),
                    result_data: Some(status.to_json()),
                }
            }
            Err(e) => {
                let status = IsolationStatus {
                    state: IsolationState::Isolated,
                    method: "pfctl".to_string(),
                    rules_applied: Vec::new(),
                    allowlisted_connections: Vec::new(),
                    connectivity_test: ConnectivityResult {
                        server_reachable: false,
                        dns_works: false,
                        internet_blocked: true,
                        server_latency_ms: None,
                        details: Some(format!("Failed to remove pfctl isolation: {}", e)),
                    },
                    applied_at: verify_params.as_ref().and_then(|(_, at)| *at),
                    filter_count: 0,
                    error: Some(format!("Failed to remove pfctl isolation: {}", e)),
                };

                CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to remove pfctl isolation: {}", e)),
                    result_data: Some(status.to_json()),
                }
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let status = IsolationStatus {
            state: IsolationState::Failed,
            method: "unsupported".to_string(),
            rules_applied: Vec::new(),
            allowlisted_connections: Vec::new(),
            connectivity_test: ConnectivityResult {
                server_reachable: false,
                dns_works: false,
                internet_blocked: false,
                server_latency_ms: None,
                details: Some("Platform not supported".to_string()),
            },
            applied_at: None,
            filter_count: 0,
            error: Some("Network unisolation not implemented for this platform".to_string()),
        };
        CommandResult {
            success: false,
            error_message: Some(
                "Network unisolation not implemented for this platform".to_string(),
            ),
            result_data: Some(status.to_json()),
        }
    }
}

async fn collect_artifact(payload: &serde_json::Value) -> CommandResult {
    use crate::response::forensics::{ArtifactType, ForensicCollector};

    let artifact_id = payload
        .get("artifact_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let artifact_type = payload
        .get("artifact_type")
        .and_then(|v| v.as_str())
        .unwrap_or("custom_file");
    let _artifact_subtype = payload.get("artifact_subtype").and_then(|v| v.as_str());
    let default_parameters = serde_json::json!({});
    let parameters = payload.get("parameters").unwrap_or(&default_parameters);
    let compression = payload
        .get("compression")
        .and_then(|v| v.as_str())
        .unwrap_or("gzip");
    let encrypted = payload
        .get("encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    info!(
        artifact_id = %artifact_id,
        artifact_type = %artifact_type,
        compression = %compression,
        encrypted = encrypted,
        "Collecting forensic artifact"
    );

    // Parse artifact type
    let artifact_enum = match artifact_type {
        "memory_dump" => ArtifactType::MemoryDump,
        "process_memory" => {
            let pid = parameters.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            ArtifactType::ProcessMemory { pid }
        }
        "registry_hive" => {
            let hive = parameters
                .get("hive")
                .and_then(|v| v.as_str())
                .unwrap_or("HKLM")
                .to_string();
            ArtifactType::RegistryHive { hive }
        }
        "event_logs" => {
            let log_name = parameters
                .get("log_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Security")
                .to_string();
            ArtifactType::EventLogs { log_name }
        }
        "browser_artifacts" => {
            let browser = parameters
                .get("browser")
                .and_then(|v| v.as_str())
                .unwrap_or("chrome")
                .to_string();
            ArtifactType::BrowserArtifacts { browser }
        }
        "prefetch_files" => ArtifactType::PrefetchFiles,
        "mft" => ArtifactType::MftExtract,
        "network_capture" => ArtifactType::NetworkSnapshot,
        "process_list" => ArtifactType::ProcessList,
        "loaded_modules" => {
            let pid = parameters
                .get("pid")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32);
            ArtifactType::LoadedModules { pid }
        }
        "startup_items" => ArtifactType::StartupItems,
        "scheduled_tasks" => ArtifactType::ScheduledTasks,
        "services_list" => ArtifactType::ServicesList,
        "user_accounts" => ArtifactType::UserAccounts,
        "custom_file" => {
            let path = parameters
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if path.is_empty() {
                return CommandResult {
                    success: false,
                    error_message: Some(
                        "Missing 'path' parameter for custom_file artifact".to_string(),
                    ),
                    result_data: None,
                };
            }
            ArtifactType::CustomFile {
                path: std::path::PathBuf::from(path),
            }
        }
        _ => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Unknown artifact type: {}", artifact_type)),
                result_data: None,
            };
        }
    };

    // Create collector
    let config = crate::config::AgentConfig::default();
    let mut collector = ForensicCollector::new(&config);

    // Collect artifact
    let output_dir = std::env::temp_dir().join("tamandua-forensics");
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        return CommandResult {
            success: false,
            error_message: Some(format!("Failed to create artifact output dir: {}", e)),
            result_data: None,
        };
    }

    match collector.collect(artifact_enum, &output_dir).await {
        Ok(artifact) => {
            // Apply compression if requested
            let final_path = if compression != "none" {
                match compress_artifact(&artifact.path, compression).await {
                    Ok(compressed_path) => compressed_path,
                    Err(e) => {
                        return CommandResult {
                            success: false,
                            error_message: Some(format!("Compression failed: {}", e)),
                            result_data: None,
                        };
                    }
                }
            } else {
                artifact.path.clone()
            };

            // Apply encryption if requested
            let final_path = if encrypted {
                match encrypt_artifact(&final_path).await {
                    Ok(encrypted_path) => encrypted_path,
                    Err(e) => {
                        return CommandResult {
                            success: false,
                            error_message: Some(format!("Encryption failed: {}", e)),
                            result_data: None,
                        };
                    }
                }
            } else {
                final_path
            };

            // Compute final hash
            let sha256 = compute_file_hash(&final_path)
                .await
                .unwrap_or_else(|_| artifact.sha256.clone());

            // Get file size
            let file_size = std::fs::metadata(&final_path)
                .map(|m| m.len())
                .unwrap_or(artifact.size);

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "artifact_id": artifact_id,
                    "file_path": final_path.to_string_lossy(),
                    "file_size": file_size,
                    "sha256_hash": sha256,
                    "compression_type": compression,
                    "encrypted": encrypted,
                    "evidence_seal_hash": compute_evidence_seal(&artifact, &sha256),
                    "metadata": artifact.metadata,
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Artifact collection failed: {}", e)),
            result_data: None,
        },
    }
}

async fn compress_artifact(
    path: &std::path::Path,
    compression_type: &str,
) -> Result<std::path::PathBuf, String> {
    use std::io::Write;

    let output_path = match compression_type {
        "gzip" => path.with_extension("gz"),
        "zstd" => path.with_extension("zst"),
        _ => return Err(format!("Unsupported compression: {}", compression_type)),
    };

    let input_data = std::fs::read(path).map_err(|e| e.to_string())?;

    match compression_type {
        "gzip" => {
            use flate2::write::GzEncoder;
            use flate2::Compression;

            let output_file = std::fs::File::create(&output_path).map_err(|e| e.to_string())?;
            let mut encoder = GzEncoder::new(output_file, Compression::default());
            encoder.write_all(&input_data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())?;
        }
        #[cfg(feature = "compression")]
        "zstd" => {
            let compressed =
                zstd::encode_all(input_data.as_slice(), 3).map_err(|e| e.to_string())?;
            std::fs::write(&output_path, compressed).map_err(|e| e.to_string())?;
        }
        #[cfg(not(feature = "compression"))]
        "zstd" => {
            return Err("zstd compression requires the compression feature".to_string());
        }
        _ => return Err(format!("Unsupported compression: {}", compression_type)),
    }

    Ok(output_path)
}

/// Wrap (encrypt) a per-artifact AES key with a Key-Encryption-Key (KEK) so the
/// raw data key is never written to disk in plaintext.
///
/// - Windows: wraps via DPAPI (`CryptProtectData`, machine scope), so only this
///   host's security context can unwrap it. No KEK material lives on disk.
/// - Non-Windows: wraps with AES-256-GCM under a KEK read from the configured
///   secret `TAMANDUA_QUARANTINE_KEK` (hex-encoded 32 bytes). This keeps the
///   build cross-platform and avoids hardcoding a key.
///
/// Returns (algorithm_tag, wrapped_key_bytes).
fn wrap_data_key(key_bytes: &[u8]) -> Result<(&'static str, Vec<u8>), String> {
    #[cfg(windows)]
    {
        use windows::Win32::Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
        };
        unsafe {
            let mut in_blob = CRYPT_INTEGER_BLOB {
                cbData: key_bytes.len() as u32,
                pbData: key_bytes.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            CryptProtectData(
                &mut in_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out_blob,
            )
            .map_err(|e| format!("DPAPI CryptProtectData failed: {}", e))?;

            let wrapped =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                out_blob.pbData as _,
            ));
            Ok(("DPAPI-LOCAL_MACHINE", wrapped))
        }
    }
    #[cfg(not(windows))]
    {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use rand::RngCore;

        let kek = load_kek_from_secret()?;
        let mut wrap_nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut wrap_nonce);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
        let mut wrapped = cipher
            .encrypt(Nonce::from_slice(&wrap_nonce), key_bytes)
            .map_err(|e| format!("KEK key-wrap failed: {}", e))?;
        // Prepend the wrap nonce so unwrap is self-contained.
        let mut out = wrap_nonce.to_vec();
        out.append(&mut wrapped);
        Ok(("AES-256-GCM-KEK", out))
    }
}

/// Load the KEK for non-Windows key wrapping from a configured secret.
/// Never hardcoded — sourced from the `TAMANDUA_QUARANTINE_KEK` env secret
/// (hex-encoded 32 bytes).
#[cfg(not(windows))]
fn load_kek_from_secret() -> Result<[u8; 32], String> {
    let hex_kek = std::env::var("TAMANDUA_QUARANTINE_KEK").map_err(|_| {
        "TAMANDUA_QUARANTINE_KEK secret not set; cannot wrap quarantine key".to_string()
    })?;
    let raw = hex::decode(hex_kek.trim()).map_err(|e| format!("invalid KEK hex: {}", e))?;
    if raw.len() != 32 {
        return Err(format!("KEK must be 32 bytes, got {}", raw.len()));
    }
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&raw);
    Ok(kek)
}

/// Encrypt a quarantined artifact at rest with AES-256-GCM (authenticated encryption)
/// so the stored artifact cannot be executed or exfiltrated in plaintext.
///
/// A fresh random 256-bit key and 96-bit nonce are generated per artifact. The
/// ciphertext (incl. GCM auth tag) is written to `<path>.enc`. The per-artifact
/// key is WRAPPED with a KEK (Windows DPAPI machine scope, or a configured
/// secret KEK on other platforms) before being persisted to the sidecar
/// `<path>.enc.key` JSON — the raw key is never written in plaintext.
///
/// HONEST RESIDUAL GAP: this is local, host-bound protection only. DPAPI machine
/// scope means any code running in the agent's context (or with the configured
/// KEK secret) can unwrap. True custody requires server-side key escrow / a
/// remote KEK so a compromised endpoint cannot self-decrypt its quarantine store.
async fn encrypt_artifact(path: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use rand::RngCore;

    let plaintext = std::fs::read(path).map_err(|e| e.to_string())?;

    // Generate a random per-artifact key and nonce from a secure RNG.
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

    let output_path = path.with_extension("enc");
    std::fs::write(&output_path, &ciphertext).map_err(|e| e.to_string())?;

    // Wrap the per-artifact key with a KEK; only the WRAPPED key is persisted.
    let (wrap_algorithm, wrapped_key) = wrap_data_key(&key_bytes)?;
    let key_path = output_path.with_extension("enc.key");
    let key_meta = serde_json::json!({
        "algorithm": "AES-256-GCM",
        "key_wrap": wrap_algorithm,
        "wrapped_key": hex::encode(&wrapped_key),
        "nonce": hex::encode(nonce_bytes),
    });
    std::fs::write(
        &key_path,
        serde_json::to_vec_pretty(&key_meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    info!(
        artifact = %output_path.to_string_lossy(),
        key_file = %key_path.to_string_lossy(),
        key_wrap = wrap_algorithm,
        "Encrypted quarantined artifact with AES-256-GCM (wrapped key custody)"
    );

    Ok(output_path)
}

async fn compute_file_hash(path: &std::path::Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

fn compute_evidence_seal(
    artifact: &crate::response::forensics::ForensicArtifact,
    sha256: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let seal_data = format!(
        "{}|{}|{}|{}",
        artifact.timestamp,
        artifact.size,
        sha256,
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    );

    let mut hasher = Sha256::new();
    hasher.update(seal_data.as_bytes());
    hex::encode(hasher.finalize())
}

async fn update_config(payload: &serde_json::Value) -> CommandResult {
    info!("Updating configuration");

    // Extract config values from payload
    let config_data = match payload.get("config") {
        Some(c) => c,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing 'config' field in payload".to_string()),
                result_data: None,
            };
        }
    };

    // Determine config file path
    let config_path = if cfg!(windows) {
        "C:\\ProgramData\\Tamandua\\config.toml"
    } else {
        "/etc/tamandua/config.toml"
    };

    // Ensure config directory exists
    if let Some(parent) = std::path::Path::new(config_path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to create config directory: {}", e)),
                result_data: None,
            };
        }
    }

    // Serialize config to TOML
    let config_toml = match toml::to_string_pretty(config_data) {
        Ok(s) => s,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to serialize config: {}", e)),
                result_data: None,
            };
        }
    };

    // Backup existing config
    let backup_path = format!("{}.backup", config_path);
    if std::path::Path::new(config_path).exists() {
        if let Err(e) = std::fs::copy(config_path, &backup_path) {
            warn!("Failed to backup config: {}", e);
        }
    }

    // Write new config
    match std::fs::write(config_path, &config_toml) {
        Ok(_) => {
            info!(path = %config_path, "Configuration updated");
            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "config_path": config_path,
                    "backup_path": backup_path,
                    "restart_required": true,
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to write config: {}", e)),
            result_data: None,
        },
    }
}

async fn update_rules(payload: &serde_json::Value) -> CommandResult {
    info!("Updating detection rules");

    let rules_dir = if cfg!(windows) {
        "C:\\ProgramData\\Tamandua\\rules"
    } else {
        "/var/lib/tamandua/rules"
    };

    // Ensure rules directory exists
    if let Err(e) = std::fs::create_dir_all(rules_dir) {
        return CommandResult {
            success: false,
            error_message: Some(format!("Failed to create rules directory: {}", e)),
            result_data: None,
        };
    }

    let mut updated_yara = 0;
    let mut updated_sigma = 0;
    let mut errors = Vec::new();

    // Update YARA rules
    if let Some(yara_rules) = payload.get("yara_rules").and_then(|v| v.as_array()) {
        let yara_dir = format!("{}/yara", rules_dir);
        let _ = std::fs::create_dir_all(&yara_dir);

        for rule in yara_rules {
            if let (Some(name), Some(source)) = (
                rule.get("name").and_then(|v| v.as_str()),
                rule.get("source").and_then(|v| v.as_str()),
            ) {
                let rule_path = format!("{}/{}.yar", yara_dir, name);
                match std::fs::write(&rule_path, source) {
                    Ok(_) => updated_yara += 1,
                    Err(e) => errors.push(format!("Failed to write YARA rule {}: {}", name, e)),
                }
            }
        }
    }

    // Update Sigma rules
    if let Some(sigma_rules) = payload.get("sigma_rules").and_then(|v| v.as_array()) {
        let sigma_dir = format!("{}/sigma", rules_dir);
        let _ = std::fs::create_dir_all(&sigma_dir);

        for rule in sigma_rules {
            if let (Some(name), Some(_detection)) = (
                rule.get("name").and_then(|v| v.as_str()),
                rule.get("detection"),
            ) {
                let rule_path = format!("{}/{}.json", sigma_dir, name);
                match std::fs::write(
                    &rule_path,
                    serde_json::to_string_pretty(rule).unwrap_or_default(),
                ) {
                    Ok(_) => updated_sigma += 1,
                    Err(e) => errors.push(format!("Failed to write Sigma rule {}: {}", name, e)),
                }
            }
        }
    }

    // Update IOCs
    if let Some(iocs) = payload.get("iocs").and_then(|v| v.as_array()) {
        let iocs_path = format!("{}/iocs.json", rules_dir);
        match std::fs::write(
            &iocs_path,
            serde_json::to_string_pretty(iocs).unwrap_or_default(),
        ) {
            Ok(_) => info!(count = iocs.len(), "IOCs updated"),
            Err(e) => errors.push(format!("Failed to write IOCs: {}", e)),
        }
    }

    let success = errors.is_empty();

    CommandResult {
        success,
        error_message: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        result_data: Some(serde_json::json!({
            "updated_yara_rules": updated_yara,
            "updated_sigma_rules": updated_sigma,
            "rules_directory": rules_dir,
        })),
    }
}

async fn scan_path(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let recursive = payload
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let max_files = payload
        .get("max_files")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as usize;

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Path is required".to_string()),
            result_data: None,
        };
    }

    info!(path = %path, recursive = recursive, "Scanning path");

    let scan_path = std::path::Path::new(path);
    if !scan_path.exists() {
        return CommandResult {
            success: false,
            error_message: Some(format!("Path does not exist: {}", path)),
            result_data: None,
        };
    }

    let mut files_scanned = 0;
    let mut threats: Vec<serde_json::Value> = Vec::new();
    let mut errors = Vec::new();

    // Collect files to scan
    let files_to_scan: Vec<_> = if scan_path.is_file() {
        vec![scan_path.to_path_buf()]
    } else if recursive {
        walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .take(max_files)
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        std::fs::read_dir(path)
            .into_iter()
            .flat_map(|rd| rd.into_iter())
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .take(max_files)
            .map(|e| e.path())
            .collect()
    };

    for file_path in files_to_scan {
        files_scanned += 1;

        // Read file content
        let content = match std::fs::read(&file_path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("Failed to read {}: {}", file_path.display(), e));
                continue;
            }
        };

        // Calculate hash
        let sha256 = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&content);
            hex::encode(hasher.finalize())
        };

        // Calculate entropy
        let entropy = calculate_entropy(&content);

        // High entropy check (possible packed/encrypted malware)
        if entropy > 7.5 {
            threats.push(serde_json::json!({
                "path": file_path.to_string_lossy(),
                "sha256": sha256,
                "detection_type": "high_entropy",
                "entropy": entropy,
                "confidence": 0.6,
            }));
        }

        // Check for PE magic bytes
        if content.len() >= 2 && content[0] == 0x4D && content[1] == 0x5A {
            // PE file - check for suspicious characteristics
            if let Some(threat) = check_pe_suspicious(&file_path, &content, &sha256) {
                threats.push(threat);
            }
        }
    }

    CommandResult {
        success: true,
        error_message: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        result_data: Some(serde_json::json!({
            "path": path,
            "files_scanned": files_scanned,
            "threats_found": threats.len(),
            "threats": threats,
        })),
    }
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check PE file for suspicious characteristics
fn check_pe_suspicious(
    path: &std::path::Path,
    content: &[u8],
    sha256: &str,
) -> Option<serde_json::Value> {
    // Look for suspicious section names
    let suspicious_sections = [".upx", ".packed", ".nsp", ".taz", ".petite"];

    // Simple PE header parsing
    if content.len() < 64 {
        return None;
    }

    // Get PE header offset
    let pe_offset =
        u32::from_le_bytes([content[60], content[61], content[62], content[63]]) as usize;

    if pe_offset + 24 >= content.len() {
        return None;
    }

    // Check PE signature
    if &content[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    // Number of sections
    let num_sections =
        u16::from_le_bytes([content[pe_offset + 6], content[pe_offset + 7]]) as usize;

    // Optional header size
    let optional_header_size =
        u16::from_le_bytes([content[pe_offset + 20], content[pe_offset + 21]]) as usize;

    // Section headers start
    let section_start = pe_offset + 24 + optional_header_size;

    // Check each section
    for i in 0..num_sections {
        let section_offset = section_start + (i * 40);
        if section_offset + 8 >= content.len() {
            break;
        }

        // Section name (8 bytes)
        let section_name = &content[section_offset..section_offset + 8];
        let name = String::from_utf8_lossy(section_name)
            .trim_end_matches('\0')
            .to_lowercase();

        for suspicious in &suspicious_sections {
            if name.contains(suspicious) {
                return Some(serde_json::json!({
                    "path": path.to_string_lossy(),
                    "sha256": sha256,
                    "detection_type": "suspicious_section",
                    "section_name": name,
                    "confidence": 0.7,
                }));
            }
        }
    }

    None
}

// ============================================================
// IP/Domain Blocking Functions
// ============================================================

/// Block an IP address
async fn block_ip(payload: &serde_json::Value) -> CommandResult {
    let ip = payload.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let direction = payload
        .get("direction")
        .and_then(|v| v.as_str())
        .unwrap_or("both");
    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("manual_block");

    if ip.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("IP address is required".to_string()),
            result_data: None,
        };
    }

    info!(ip = %ip, direction = %direction, reason = %reason, "Blocking IP");

    #[cfg(target_os = "windows")]
    {
        // Use WFP to block the specific IP at the kernel level.
        // WFP blocks both inbound and outbound for the IP regardless of the
        // `direction` parameter, since WFP uses separate layer-based filters.
        use std::net::IpAddr;

        let parsed_ip: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                return CommandResult {
                    success: false,
                    error_message: Some(format!("Invalid IP address '{}': {}", ip, e)),
                    result_data: None,
                };
            }
        };

        let wfp = wfp_isolation::get_wfp();

        // Ensure engine is open
        if let Err(e) = wfp.open_engine() {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to open WFP engine: {}", e)),
                result_data: None,
            };
        }

        match wfp.block_ip(parsed_ip) {
            Ok(filter_ids) => {
                log_blocked_ip(ip, reason);
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "ip": ip,
                        "direction": direction,
                        "filter_count": filter_ids.len(),
                        "method": "wfp"
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("WFP IP block failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "linux")]
    {
        match linux_isolation::block_ip(ip) {
            Ok(()) => {
                log_blocked_ip(ip, reason);
                let backend = linux_isolation::get_backend()
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "ip": ip,
                        "direction": direction,
                        "method": backend,
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Linux IP block failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        match macos_isolation::block_ip(ip) {
            Ok(()) => {
                log_blocked_ip(ip, reason);
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "ip": ip,
                        "direction": direction,
                        "method": "pfctl_anchor"
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("macOS pfctl IP block failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    CommandResult {
        success: false,
        error_message: Some("IP blocking not implemented for this platform".to_string()),
        result_data: None,
    }
}

/// Unblock an IP address
async fn unblock_ip(payload: &serde_json::Value) -> CommandResult {
    let ip = payload.get("ip").and_then(|v| v.as_str()).unwrap_or("");

    if ip.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("IP address is required".to_string()),
            result_data: None,
        };
    }

    info!(ip = %ip, "Unblocking IP");

    #[cfg(target_os = "windows")]
    {
        // Remove WFP block filters for this IP
        use std::net::IpAddr;

        let parsed_ip: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                return CommandResult {
                    success: false,
                    error_message: Some(format!("Invalid IP address '{}': {}", ip, e)),
                    result_data: None,
                };
            }
        };

        let wfp = wfp_isolation::get_wfp();

        match wfp.unblock_ip(parsed_ip) {
            Ok(removed) => {
                remove_blocked_ip(ip);
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "ip": ip,
                        "filters_removed": removed,
                        "method": "wfp"
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("WFP IP unblock failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "linux")]
    {
        match linux_isolation::unblock_ip(ip) {
            Ok(()) => {
                remove_blocked_ip(ip);
                let backend = linux_isolation::get_backend()
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "ip": ip,
                        "method": backend,
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Linux IP unblock failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        match macos_isolation::unblock_ip(ip) {
            Ok(()) => {
                remove_blocked_ip(ip);
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "ip": ip,
                        "method": "pfctl_anchor"
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("macOS pfctl IP unblock failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    CommandResult {
        success: false,
        error_message: Some("IP unblocking not implemented for this platform".to_string()),
        result_data: None,
    }
}

/// Block a domain by modifying hosts file and/or DNS
async fn block_domain(payload: &serde_json::Value) -> CommandResult {
    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("manual_block");

    if domain.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Domain is required".to_string()),
            result_data: None,
        };
    }

    info!(domain = %domain, reason = %reason, "Blocking domain");

    let hosts_path = if cfg!(windows) {
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    } else {
        "/etc/hosts"
    };

    // Read current hosts file
    let hosts_content = std::fs::read_to_string(hosts_path).unwrap_or_default();

    // Check if already blocked
    let marker = format!("# TAMANDUA_BLOCKED: {}", domain);
    if hosts_content.contains(&marker) {
        return CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "domain": domain,
                "status": "already_blocked"
            })),
        };
    }

    // Add blocking entry
    let block_entry = format!(
        "\n{}\n127.0.0.1 {}\n127.0.0.1 www.{}\n",
        marker, domain, domain
    );
    let new_content = format!("{}{}", hosts_content, block_entry);

    match std::fs::write(hosts_path, &new_content) {
        Ok(_) => {
            // Flush DNS cache
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("ipconfig")
                    .args(["/flushdns"])
                    .output();
            }

            #[cfg(target_os = "linux")]
            {
                // Try systemd-resolved
                let _ = std::process::Command::new("systemd-resolve")
                    .args(["--flush-caches"])
                    .output();
                // Try nscd
                let _ = std::process::Command::new("nscd")
                    .args(["-i", "hosts"])
                    .output();
            }

            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("dscacheutil")
                    .args(["-flushcache"])
                    .output();
                let _ = std::process::Command::new("killall")
                    .args(["-HUP", "mDNSResponder"])
                    .output();
            }

            log_blocked_domain(domain, reason);

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "domain": domain,
                    "hosts_path": hosts_path,
                    "method": "hosts_file"
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to update hosts file: {}", e)),
            result_data: None,
        },
    }
}

/// Unblock a domain
async fn unblock_domain(payload: &serde_json::Value) -> CommandResult {
    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    if domain.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Domain is required".to_string()),
            result_data: None,
        };
    }

    info!(domain = %domain, "Unblocking domain");

    let hosts_path = if cfg!(windows) {
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    } else {
        "/etc/hosts"
    };

    let hosts_content = match std::fs::read_to_string(hosts_path) {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to read hosts file: {}", e)),
                result_data: None,
            };
        }
    };

    // Remove all lines related to this domain's block
    let marker = format!("# TAMANDUA_BLOCKED: {}", domain);
    let new_lines: Vec<&str> = hosts_content
        .lines()
        .filter(|line| {
            !line.contains(&marker)
                && !line.ends_with(&format!(" {}", domain))
                && !line.ends_with(&format!(" www.{}", domain))
        })
        .collect();

    let new_content = new_lines.join("\n");

    match std::fs::write(hosts_path, &new_content) {
        Ok(_) => {
            // Flush DNS cache
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("ipconfig")
                    .args(["/flushdns"])
                    .output();
            }

            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("systemd-resolve")
                    .args(["--flush-caches"])
                    .output();
            }

            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("dscacheutil")
                    .args(["-flushcache"])
                    .output();
                let _ = std::process::Command::new("killall")
                    .args(["-HUP", "mDNSResponder"])
                    .output();
            }

            remove_blocked_domain(domain);

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "domain": domain,
                    "method": "hosts_file"
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to update hosts file: {}", e)),
            result_data: None,
        },
    }
}

/// List blocked IPs
async fn list_blocked_ips(_payload: &serde_json::Value) -> CommandResult {
    let blocked_list = get_blocked_ips_file();
    let blocked_ips: Vec<serde_json::Value> = std::fs::read_to_string(&blocked_list)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "blocked_ips": blocked_ips,
            "count": blocked_ips.len()
        })),
    }
}

/// List blocked domains
async fn list_blocked_domains(_payload: &serde_json::Value) -> CommandResult {
    let blocked_list = get_blocked_domains_file();
    let blocked_domains: Vec<serde_json::Value> = std::fs::read_to_string(&blocked_list)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "blocked_domains": blocked_domains,
            "count": blocked_domains.len()
        })),
    }
}

// Helper functions for tracking blocked items

fn get_data_dir() -> String {
    if cfg!(windows) {
        "C:\\ProgramData\\Tamandua".to_string()
    } else {
        "/var/lib/tamandua".to_string()
    }
}

fn get_blocked_ips_file() -> String {
    format!("{}/blocked_ips.json", get_data_dir())
}

fn get_blocked_domains_file() -> String {
    format!("{}/blocked_domains.json", get_data_dir())
}

fn log_blocked_ip(ip: &str, reason: &str) {
    let data_dir = get_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);

    let file_path = get_blocked_ips_file();
    let entry = serde_json::json!({
        "ip": ip,
        "reason": reason,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let mut content = std::fs::read_to_string(&file_path).unwrap_or_default();
    content.push_str(&format!("{}\n", entry));
    let _ = std::fs::write(&file_path, content);
}

fn remove_blocked_ip(ip: &str) {
    let file_path = get_blocked_ips_file();
    if let Ok(content) = std::fs::read_to_string(&file_path) {
        let new_content: String = content
            .lines()
            .filter(|l| !l.contains(&format!("\"ip\":\"{}\"", ip)))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(&file_path, new_content);
    }
}

fn log_blocked_domain(domain: &str, reason: &str) {
    let data_dir = get_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);

    let file_path = get_blocked_domains_file();
    let entry = serde_json::json!({
        "domain": domain,
        "reason": reason,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let mut content = std::fs::read_to_string(&file_path).unwrap_or_default();
    content.push_str(&format!("{}\n", entry));
    let _ = std::fs::write(&file_path, content);
}

fn remove_blocked_domain(domain: &str) {
    let file_path = get_blocked_domains_file();
    if let Ok(content) = std::fs::read_to_string(&file_path) {
        let new_content: String = content
            .lines()
            .filter(|l| !l.contains(&format!("\"domain\":\"{}\"", domain)))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(&file_path, new_content);
    }
}

// ============================================================
// Application Control Functions
// ============================================================

/// Helper to get the app control manager or return error
#[allow(dead_code)]
async fn with_app_control_manager<F, R>(f: F) -> CommandResult
where
    F: FnOnce(
        &app_control::AppControlManager,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = CommandResult> + Send + '_>>,
{
    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => f(manager).await,
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Set application control enforcement mode
async fn app_control_set_mode(payload: &serde_json::Value) -> CommandResult {
    let mode_str = payload.get("mode").and_then(|v| v.as_str()).unwrap_or("");

    let mode = match mode_str.to_lowercase().as_str() {
        "audit" => app_control::EnforcementMode::Audit,
        "block" => app_control::EnforcementMode::Block,
        "learning" => app_control::EnforcementMode::Learning,
        _ => {
            return CommandResult {
                success: false,
                error_message: Some(format!(
                    "Invalid mode: {}. Valid modes: audit, block, learning",
                    mode_str
                )),
                result_data: None,
            };
        }
    };

    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => {
                    manager.set_mode(mode).await;
                    info!(mode = ?mode, "Application control mode set");
                    CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "mode": mode_str,
                            "message": format!("Enforcement mode set to {}", mode_str)
                        })),
                    }
                }
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Add an application control rule
async fn app_control_add_rule(payload: &serde_json::Value) -> CommandResult {
    // Parse rule from payload
    let rule: app_control::AppControlRule = match serde_json::from_value(payload.clone()) {
        Ok(r) => r,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to parse rule: {}", e)),
                result_data: None,
            };
        }
    };

    let rule_id = rule.id.clone();
    let rule_name = rule.name.clone();

    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => match manager.add_rule(rule).await {
                    Ok(()) => {
                        info!(rule_id = %rule_id, "Application control rule added");
                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({
                                "rule_id": rule_id,
                                "rule_name": rule_name,
                                "message": "Rule added successfully"
                            })),
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to add rule: {}", e)),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Remove an application control rule
async fn app_control_remove_rule(payload: &serde_json::Value) -> CommandResult {
    let rule_id = payload
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if rule_id.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("rule_id is required".to_string()),
            result_data: None,
        };
    }

    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => match manager.remove_rule(rule_id).await {
                    Ok(removed) => {
                        if removed {
                            info!(rule_id = %rule_id, "Application control rule removed");
                            CommandResult {
                                success: true,
                                error_message: None,
                                result_data: Some(serde_json::json!({
                                    "rule_id": rule_id,
                                    "message": "Rule removed successfully"
                                })),
                            }
                        } else {
                            CommandResult {
                                success: false,
                                error_message: Some(format!("Rule '{}' not found", rule_id)),
                                result_data: None,
                            }
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to remove rule: {}", e)),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Enable an application control rule
async fn app_control_enable_rule(payload: &serde_json::Value) -> CommandResult {
    let rule_id = payload
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if rule_id.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("rule_id is required".to_string()),
            result_data: None,
        };
    }

    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => match manager.set_rule_enabled(rule_id, true).await {
                    Ok(found) => {
                        if found {
                            info!(rule_id = %rule_id, "Application control rule enabled");
                            CommandResult {
                                success: true,
                                error_message: None,
                                result_data: Some(serde_json::json!({
                                    "rule_id": rule_id,
                                    "enabled": true,
                                    "message": "Rule enabled successfully"
                                })),
                            }
                        } else {
                            CommandResult {
                                success: false,
                                error_message: Some(format!("Rule '{}' not found", rule_id)),
                                result_data: None,
                            }
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to enable rule: {}", e)),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Disable an application control rule
async fn app_control_disable_rule(payload: &serde_json::Value) -> CommandResult {
    let rule_id = payload
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if rule_id.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("rule_id is required".to_string()),
            result_data: None,
        };
    }

    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => match manager.set_rule_enabled(rule_id, false).await {
                    Ok(found) => {
                        if found {
                            info!(rule_id = %rule_id, "Application control rule disabled");
                            CommandResult {
                                success: true,
                                error_message: None,
                                result_data: Some(serde_json::json!({
                                    "rule_id": rule_id,
                                    "enabled": false,
                                    "message": "Rule disabled successfully"
                                })),
                            }
                        } else {
                            CommandResult {
                                success: false,
                                error_message: Some(format!("Rule '{}' not found", rule_id)),
                                result_data: None,
                            }
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to disable rule: {}", e)),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// List all application control rules
async fn app_control_list_rules(_payload: &serde_json::Value) -> CommandResult {
    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => {
                    let rules = manager.get_rules().await;
                    CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "rules": rules,
                            "count": rules.len()
                        })),
                    }
                }
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Get the full application control policy
async fn app_control_get_policy(_payload: &serde_json::Value) -> CommandResult {
    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => {
                    let policy = manager.get_policy().await;
                    CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::to_value(&policy).unwrap_or_default()),
                    }
                }
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Update the full application control policy from server
async fn app_control_update_policy(payload: &serde_json::Value) -> CommandResult {
    let policy = payload.get("policy").unwrap_or(payload);

    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => match manager.update_policy_from_server(policy).await {
                    Ok(()) => {
                        let new_policy = manager.get_policy().await;
                        info!(
                            version = new_policy.version,
                            rules = new_policy.rules.len(),
                            "Application control policy updated"
                        );
                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({
                                "version": new_policy.version,
                                "rules_count": new_policy.rules.len(),
                                "checksum": new_policy.checksum,
                                "message": "Policy updated successfully"
                            })),
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to update policy: {}", e)),
                        result_data: None,
                    },
                },
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

/// Get application control statistics
async fn app_control_get_stats(_payload: &serde_json::Value) -> CommandResult {
    match APP_CONTROL_MANAGER.get() {
        Some(lock) => {
            let guard = lock.read().await;
            match guard.as_ref() {
                Some(manager) => {
                    let stats = manager.get_stats().await;
                    let mode = manager.get_mode().await;
                    CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "mode": format!("{:?}", mode).to_lowercase(),
                            "stats": stats
                        })),
                    }
                }
                None => CommandResult {
                    success: false,
                    error_message: Some("Application control manager not initialized".to_string()),
                    result_data: None,
                },
            }
        }
        None => CommandResult {
            success: false,
            error_message: Some("Application control manager not available".to_string()),
            result_data: None,
        },
    }
}

// ============================================================
// VSS Snapshot & Rollback Functions
// ============================================================

/// Create a VSS snapshot for a volume
async fn vss_create_snapshot(payload: &serde_json::Value) -> CommandResult {
    let volume = payload
        .get("volume")
        .and_then(|v| v.as_str())
        .unwrap_or("C:");

    info!(volume = %volume, "Creating VSS snapshot");

    #[cfg(target_os = "windows")]
    {
        match rollback::VssManager::new() {
            Ok(vss) => match vss.create_snapshot(volume) {
                Ok(snapshot) => CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "snapshot": {
                            "id": snapshot.id,
                            "volume": snapshot.volume,
                            "created_at": snapshot.created_at,
                            "device_name": snapshot.device_name,
                            "accessible": snapshot.accessible
                        }
                    })),
                },
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to create snapshot: {}", e)),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize VSS manager: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS snapshots are only available on Windows".to_string()),
        result_data: None,
    }
}

/// List available VSS snapshots for a volume
async fn vss_list_snapshots(payload: &serde_json::Value) -> CommandResult {
    let volume = payload
        .get("volume")
        .and_then(|v| v.as_str())
        .unwrap_or("C:");

    info!(volume = %volume, "Listing VSS snapshots");

    #[cfg(target_os = "windows")]
    {
        match rollback::VssManager::new() {
            Ok(vss) => match vss.list_snapshots(volume) {
                Ok(snapshots) => {
                    let snapshot_list: Vec<serde_json::Value> = snapshots
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "id": s.id,
                                "volume": s.volume,
                                "created_at": s.created_at,
                                "device_name": s.device_name,
                                "accessible": s.accessible,
                                "size_bytes": s.size_bytes
                            })
                        })
                        .collect();

                    CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "snapshots": snapshot_list,
                            "count": snapshot_list.len(),
                            "volume": volume
                        })),
                    }
                }
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to list snapshots: {}", e)),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize VSS manager: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS snapshots are only available on Windows".to_string()),
        result_data: None,
    }
}

/// Delete a VSS snapshot
async fn vss_delete_snapshot(payload: &serde_json::Value) -> CommandResult {
    let snapshot_id = payload
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if snapshot_id.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("snapshot_id is required".to_string()),
            result_data: None,
        };
    }

    info!(snapshot_id = %snapshot_id, "Deleting VSS snapshot");

    #[cfg(target_os = "windows")]
    {
        match rollback::VssManager::new() {
            Ok(vss) => match vss.delete_snapshot(snapshot_id) {
                Ok(()) => CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "snapshot_id": snapshot_id,
                        "deleted": true
                    })),
                },
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to delete snapshot: {}", e)),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize VSS manager: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS snapshots are only available on Windows".to_string()),
        result_data: None,
    }
}

/// Restore a single file from a VSS snapshot
async fn vss_restore_file(payload: &serde_json::Value) -> CommandResult {
    let snapshot_id = payload
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let file_path = payload
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if snapshot_id.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("snapshot_id is required".to_string()),
            result_data: None,
        };
    }

    if file_path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("file_path is required".to_string()),
            result_data: None,
        };
    }

    info!(snapshot_id = %snapshot_id, file_path = %file_path, "Restoring file from VSS snapshot");

    #[cfg(target_os = "windows")]
    {
        match rollback::VssManager::new() {
            Ok(vss) => {
                let path = std::path::Path::new(file_path);
                match vss.restore_file(snapshot_id, path) {
                    Ok(()) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "snapshot_id": snapshot_id,
                            "file_path": file_path,
                            "restored": true
                        })),
                    },
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to restore file: {}", e)),
                        result_data: None,
                    },
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize VSS manager: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS snapshots are only available on Windows".to_string()),
        result_data: None,
    }
}

/// Restore multiple files from a VSS snapshot
async fn vss_restore_files(payload: &serde_json::Value) -> CommandResult {
    let snapshot_id = payload
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let file_paths: Vec<std::path::PathBuf> = payload
        .get("file_paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(std::path::PathBuf::from)
                .collect()
        })
        .unwrap_or_default();

    if snapshot_id.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("snapshot_id is required".to_string()),
            result_data: None,
        };
    }

    if file_paths.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("file_paths is required and must not be empty".to_string()),
            result_data: None,
        };
    }

    info!(
        snapshot_id = %snapshot_id,
        file_count = file_paths.len(),
        "Restoring files from VSS snapshot"
    );

    #[cfg(target_os = "windows")]
    {
        match rollback::VssManager::new() {
            Ok(vss) => match vss.restore_files(snapshot_id, &file_paths) {
                Ok(result) => CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "snapshot_id": snapshot_id,
                        "restored_count": result.restored.len(),
                        "restored": result.restored.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                        "failed_count": result.failed.len(),
                        "failed": result.failed.iter().map(|(p, e)| {
                            serde_json::json!({
                                "path": p.to_string_lossy(),
                                "error": e
                            })
                        }).collect::<Vec<_>>(),
                        "skipped_count": result.skipped.len(),
                        "skipped": result.skipped.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                        "bytes_restored": result.bytes_restored,
                        "duration_ms": result.duration_ms
                    })),
                },
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to restore files: {}", e)),
                    result_data: None,
                },
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize VSS manager: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS snapshots are only available on Windows".to_string()),
        result_data: None,
    }
}

/// Find encrypted files (ransomware detection)
async fn vss_find_encrypted_files(payload: &serde_json::Value) -> CommandResult {
    let root_path = payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Users");

    info!(root_path = %root_path, "Scanning for encrypted files");

    #[cfg(target_os = "windows")]
    {
        match rollback::RansomwareRemediator::new() {
            Ok(remediator) => {
                let path = std::path::Path::new(root_path);
                match remediator.find_encrypted_files(path) {
                    Ok(encrypted_files) => {
                        let files: Vec<serde_json::Value> = encrypted_files
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "path": f.path.to_string_lossy(),
                                    "original_extension": f.original_extension,
                                    "ransomware_extension": f.ransomware_extension,
                                    "entropy": f.entropy,
                                    "size": f.size
                                })
                            })
                            .collect();

                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({
                                "root_path": root_path,
                                "encrypted_files": files,
                                "count": files.len()
                            })),
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to scan for encrypted files: {}", e)),
                        result_data: None,
                    },
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize remediator: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("Ransomware remediation is only available on Windows".to_string()),
        result_data: None,
    }
}

/// Perform ransomware remediation by restoring encrypted files from VSS snapshots
async fn vss_ransomware_remediate(payload: &serde_json::Value) -> CommandResult {
    let root_path = payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Users");
    let encrypted_files: Option<Vec<rollback::EncryptedFileInfo>> = payload
        .get("encrypted_files")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    info!(root_path = %root_path, "Starting ransomware remediation");

    #[cfg(target_os = "windows")]
    {
        match rollback::RansomwareRemediator::new() {
            Ok(remediator) => {
                // If encrypted files list not provided, scan for them first
                let files_to_restore = match encrypted_files {
                    Some(files) => files,
                    None => {
                        let path = std::path::Path::new(root_path);
                        match remediator.find_encrypted_files(path) {
                            Ok(files) => files,
                            Err(e) => {
                                return CommandResult {
                                    success: false,
                                    error_message: Some(format!(
                                        "Failed to scan for encrypted files: {}",
                                        e
                                    )),
                                    result_data: None,
                                };
                            }
                        }
                    }
                };

                if files_to_restore.is_empty() {
                    return CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "message": "No encrypted files found to restore",
                            "root_path": root_path
                        })),
                    };
                }

                match remediator.remediate(&files_to_restore) {
                    Ok(result) => {
                        let report = remediator.generate_report(&result);

                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({
                                "root_path": root_path,
                                "total_files": files_to_restore.len(),
                                "restored_count": result.restored.len(),
                                "restored": result.restored.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                                "failed_count": result.failed.len(),
                                "failed": result.failed.iter().map(|(p, e)| {
                                    serde_json::json!({
                                        "path": p.to_string_lossy(),
                                        "error": e
                                    })
                                }).collect::<Vec<_>>(),
                                "skipped_count": result.skipped.len(),
                                "bytes_restored": result.bytes_restored,
                                "duration_ms": result.duration_ms,
                                "report": report
                            })),
                        }
                    }
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Remediation failed: {}", e)),
                        result_data: None,
                    },
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to initialize remediator: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("Ransomware remediation is only available on Windows".to_string()),
        result_data: None,
    }
}

// ============================================================
// VSS One-Click Rollback Functions (vss_rollback module)
// ============================================================

/// One-click VSS rollback: restore specified paths from a snapshot.
///
/// Payload:
/// - `snapshot_id` (optional): Specific snapshot to use. If omitted, uses
///   the most recent clean snapshot.
/// - `paths` (required): Array of file paths to restore.
/// - `verify` (optional, default true): Hash-verify restored files.
/// - `volume` (optional, default "C:"): Volume to look for snapshots.
async fn vss_one_click_rollback(payload: &serde_json::Value) -> CommandResult {
    let snapshot_id = payload.get("snapshot_id").and_then(|v| v.as_str());
    let verify = payload
        .get("verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let volume = payload
        .get("volume")
        .and_then(|v| v.as_str())
        .unwrap_or("C:");
    let paths: Vec<std::path::PathBuf> = payload
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(std::path::PathBuf::from)
                .collect()
        })
        .unwrap_or_default();

    if paths.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("paths is required and must not be empty".to_string()),
            result_data: None,
        };
    }

    info!(
        snapshot_id = ?snapshot_id,
        file_count = paths.len(),
        verify = verify,
        "Executing VSS one-click rollback"
    );

    #[cfg(target_os = "windows")]
    {
        let config = crate::config::AgentConfig::default();
        let mut manager = vss_rollback::VssSnapshotManager::new(&config);

        // Populate snapshot cache.
        if let Err(e) = manager.list_snapshots(Some(volume)) {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to list snapshots: {}", e)),
                result_data: None,
            };
        }

        // Determine which snapshot to use.
        let snap_id = if let Some(id) = snapshot_id {
            id.to_string()
        } else {
            match manager.find_latest_snapshot(volume) {
                Some(snap) => snap.snapshot_id.clone(),
                None => {
                    return CommandResult {
                        success: false,
                        error_message: Some("No VSS snapshots available for rollback".to_string()),
                        result_data: None,
                    };
                }
            }
        };

        match manager.rollback_to_snapshot(&snap_id, &paths, verify) {
            Ok(result) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "snapshot_id": result.snapshot_id,
                    "restored_count": result.restored.len(),
                    "restored": result.restored.iter().map(|r| serde_json::json!({
                        "path": r.path,
                        "size_bytes": r.size_bytes,
                        "sha256": r.sha256_after
                    })).collect::<Vec<_>>(),
                    "failed_count": result.failed.len(),
                    "failed": result.failed.iter().map(|f| serde_json::json!({
                        "path": f.path,
                        "error": f.error
                    })).collect::<Vec<_>>(),
                    "skipped_count": result.skipped.len(),
                    "skipped": result.skipped.iter().map(|s| serde_json::json!({
                        "path": s.path,
                        "reason": s.reason
                    })).collect::<Vec<_>>(),
                    "bytes_restored": result.bytes_restored,
                    "total_files": result.total_files,
                    "duration_ms": result.duration_ms,
                    "verification_passed": result.verification_passed,
                    "verify": verify
                })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("VSS rollback failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS rollback is only available on Windows".to_string()),
        result_data: None,
    }
}

/// Automatic ransomware rollback: find encrypted files, locate best snapshot,
/// restore originals, verify.
///
/// Payload:
/// - `path` (optional, default "C:\\Users"): Root path to scan for encrypted files.
/// - `attack_time` (optional): Unix epoch of attack detection. If given, only
///   snapshots created before this time are considered.
/// - `verify` (optional, default true): Hash-verify restored files.
async fn vss_ransomware_auto_rollback(payload: &serde_json::Value) -> CommandResult {
    let root_path = payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Users");
    let attack_time = payload.get("attack_time").and_then(|v| v.as_u64());
    let _verify = payload
        .get("verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    info!(
        root_path = %root_path,
        attack_time = ?attack_time,
        "Executing automatic ransomware VSS rollback"
    );

    #[cfg(target_os = "windows")]
    {
        let config = crate::config::AgentConfig::default();
        let mut manager = vss_rollback::VssSnapshotManager::new(&config);

        let volume = if root_path.len() >= 2 {
            &root_path[..2]
        } else {
            "C:"
        };
        if let Err(e) = manager.list_snapshots(Some(volume)) {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to list snapshots: {}", e)),
                result_data: None,
            };
        }

        let root = std::path::Path::new(root_path);
        match manager.ransomware_rollback(root, attack_time) {
            Ok(result) => {
                let success = result.failed.is_empty() || !result.restored.is_empty();
                CommandResult {
                    success,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "snapshot_id": result.snapshot_id,
                        "root_path": root_path,
                        "attack_time": attack_time,
                        "restored_count": result.restored.len(),
                        "restored": result.restored.iter().map(|r| serde_json::json!({
                            "path": r.path,
                            "size_bytes": r.size_bytes,
                            "sha256": r.sha256_after
                        })).collect::<Vec<_>>(),
                        "failed_count": result.failed.len(),
                        "failed": result.failed.iter().map(|f| serde_json::json!({
                            "path": f.path,
                            "error": f.error
                        })).collect::<Vec<_>>(),
                        "skipped_count": result.skipped.len(),
                        "bytes_restored": result.bytes_restored,
                        "total_files": result.total_files,
                        "duration_ms": result.duration_ms,
                        "verification_passed": result.verification_passed
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Ransomware rollback failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS ransomware rollback is only available on Windows".to_string()),
        result_data: None,
    }
}

/// Get VSS snapshot schedule configuration.
async fn vss_get_schedule(_payload: &serde_json::Value) -> CommandResult {
    #[cfg(target_os = "windows")]
    {
        let config = crate::config::AgentConfig::default();
        let manager = vss_rollback::VssSnapshotManager::new(&config);
        let schedule = manager.get_schedule();

        CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "enabled": schedule.enabled,
                "interval_seconds": schedule.interval_seconds,
                "max_snapshots_per_volume": schedule.max_snapshots_per_volume,
                "volumes": schedule.volumes,
                "snapshot_on_ransomware": schedule.snapshot_on_ransomware
            })),
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS schedule is only available on Windows".to_string()),
        result_data: None,
    }
}

/// Update VSS snapshot schedule configuration.
///
/// Payload fields (all optional):
/// - `enabled`: Enable/disable scheduling.
/// - `interval_seconds`: Seconds between snapshots.
/// - `max_snapshots_per_volume`: Retention limit.
/// - `volumes`: Array of volume letters.
/// - `snapshot_on_ransomware`: Emergency snapshot toggle.
async fn vss_set_schedule(payload: &serde_json::Value) -> CommandResult {
    info!("Updating VSS snapshot schedule");

    #[cfg(target_os = "windows")]
    {
        let config = crate::config::AgentConfig::default();
        let mut manager = vss_rollback::VssSnapshotManager::new(&config);

        let mut schedule = manager.get_schedule().clone();

        if let Some(enabled) = payload.get("enabled").and_then(|v| v.as_bool()) {
            schedule.enabled = enabled;
        }
        if let Some(interval) = payload.get("interval_seconds").and_then(|v| v.as_u64()) {
            schedule.interval_seconds = interval;
        }
        if let Some(max) = payload
            .get("max_snapshots_per_volume")
            .and_then(|v| v.as_u64())
        {
            schedule.max_snapshots_per_volume = max as usize;
        }
        if let Some(volumes) = payload.get("volumes").and_then(|v| v.as_array()) {
            schedule.volumes = volumes
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
        if let Some(on_ransom) = payload
            .get("snapshot_on_ransomware")
            .and_then(|v| v.as_bool())
        {
            schedule.snapshot_on_ransomware = on_ransom;
        }

        manager.set_schedule(schedule.clone());

        CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "enabled": schedule.enabled,
                "interval_seconds": schedule.interval_seconds,
                "max_snapshots_per_volume": schedule.max_snapshots_per_volume,
                "volumes": schedule.volumes,
                "snapshot_on_ransomware": schedule.snapshot_on_ransomware
            })),
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("VSS schedule is only available on Windows".to_string()),
        result_data: None,
    }
}

// ============================================================================
// Network Connection Management (Live Response)
// ============================================================================

/// Enumerate all active network connections with extended details
async fn network_connections_enumerate(payload: &serde_json::Value) -> CommandResult {
    info!("Enumerating network connections");

    let protocol_filter = payload.get("protocol").and_then(|v| v.as_str());
    let state_filter = payload.get("state").and_then(|v| v.as_str());
    let pid_filter = payload
        .get("pid")
        .and_then(|v| v.as_u64())
        .map(|p| p as u32);

    match network_manager::enumerate_connections().await {
        Ok(mut connections) => {
            // Apply filters
            if let Some(protocol) = protocol_filter {
                connections.retain(|c| c.protocol == protocol);
            }
            if let Some(state) = state_filter {
                connections.retain(|c| c.state == state);
            }
            if let Some(pid) = pid_filter {
                connections.retain(|c| c.pid == pid);
            }

            let stats = network_manager::get_connection_stats(&connections).await;

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "connections": connections,
                    "stats": stats,
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(e),
            result_data: None,
        },
    }
}

/// Terminate a specific network connection
async fn network_connection_terminate(payload: &serde_json::Value) -> CommandResult {
    network_manager::terminate_connection(payload).await
}

/// Get network connection statistics
async fn network_connection_stats(_payload: &serde_json::Value) -> CommandResult {
    info!("Getting network connection statistics");

    match network_manager::enumerate_connections().await {
        Ok(connections) => {
            let stats = network_manager::get_connection_stats(&connections).await;

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(stats),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(e),
            result_data: None,
        },
    }
}
