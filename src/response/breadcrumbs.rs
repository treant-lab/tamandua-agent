//! Breadcrumb (honeyfile/honeytoken) deployment and rotation

use crate::transport::CommandResult;
use base64::Engine as _;
use serde_json;
use tracing::{info, warn};

/// Deploy breadcrumbs to the endpoint
pub async fn deploy_breadcrumbs(payload: &serde_json::Value) -> CommandResult {
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    // Extract deployments array
    let deployments = match payload.get("deployments").and_then(|v| v.as_array()) {
        Some(d) => d,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing 'deployments' array in payload".to_string()),
                result_data: None,
            };
        }
    };

    let mut results = Vec::new();
    let mut success_count = 0;
    let mut failure_count = 0;

    for deployment in deployments {
        let breadcrumb_type = deployment
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let path = deployment
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let content_base64 = deployment
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let canary_token = deployment
            .get("canary_token")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Decode base64 content
        let content = match base64::engine::general_purpose::STANDARD.decode(content_base64) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to decode breadcrumb content: {}", e);
                failure_count += 1;
                results.push(serde_json::json!({
                    "path": path,
                    "status": "failed",
                    "error": format!("Base64 decode error: {}", e)
                }));
                continue;
            }
        };

        // Expand environment variables in path
        let expanded_path = expand_path(path);
        let file_path = Path::new(&expanded_path);

        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                warn!("Failed to create directory {}: {}", parent.display(), e);
                failure_count += 1;
                results.push(serde_json::json!({
                    "path": path,
                    "status": "failed",
                    "error": format!("Directory creation error: {}", e)
                }));
                continue;
            }
        }

        // Write breadcrumb file
        match fs::File::create(file_path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(&content) {
                    warn!("Failed to write breadcrumb to {}: {}", expanded_path, e);
                    failure_count += 1;
                    results.push(serde_json::json!({
                        "path": path,
                        "status": "failed",
                        "error": format!("Write error: {}", e)
                    }));
                    continue;
                }

                // Set realistic file timestamps (backdate by 30-90 days)
                if let Err(e) = set_backdate_timestamp(file_path) {
                    warn!("Failed to set timestamp for {}: {}", expanded_path, e);
                }

                info!(
                    "Deployed breadcrumb: type={}, path={}, token={}",
                    breadcrumb_type, expanded_path, canary_token
                );

                success_count += 1;
                results.push(serde_json::json!({
                    "path": path,
                    "status": "success",
                    "actual_path": expanded_path
                }));
            }
            Err(e) => {
                warn!("Failed to create breadcrumb file {}: {}", expanded_path, e);
                failure_count += 1;
                results.push(serde_json::json!({
                    "path": path,
                    "status": "failed",
                    "error": format!("File creation error: {}", e)
                }));
            }
        }
    }

    CommandResult {
        success: failure_count == 0,
        error_message: if failure_count > 0 {
            Some(format!(
                "{} of {} breadcrumbs failed to deploy",
                failure_count,
                deployments.len()
            ))
        } else {
            None
        },
        result_data: Some(serde_json::json!({
            "deployed": success_count,
            "failed": failure_count,
            "total": deployments.len(),
            "results": results
        })),
    }
}

/// Rotate breadcrumbs (remove old, deploy new)
pub async fn rotate_breadcrumbs(payload: &serde_json::Value) -> CommandResult {
    use std::fs;

    // Extract remove and deploy arrays
    let to_remove = payload.get("remove").and_then(|v| v.as_array());
    let to_deploy = payload.get("deploy").and_then(|v| v.as_array());

    let mut removed_count = 0;
    let mut deployed_count = 0;
    let mut errors = Vec::new();

    // Remove old breadcrumbs
    if let Some(remove_list) = to_remove {
        for item in remove_list {
            let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let expanded_path = expand_path(path);

            if let Err(e) = fs::remove_file(&expanded_path) {
                warn!("Failed to remove old breadcrumb {}: {}", expanded_path, e);
                errors.push(format!("Remove failed ({}): {}", path, e));
            } else {
                info!("Removed old breadcrumb: {}", expanded_path);
                removed_count += 1;
            }
        }
    }

    // Deploy new breadcrumbs
    if let Some(deploy_list) = to_deploy {
        let deploy_payload = serde_json::json!({ "deployments": deploy_list });
        let result = deploy_breadcrumbs(&deploy_payload).await;

        if result.success {
            if let Some(data) = result.result_data {
                deployed_count = data["deployed"].as_u64().unwrap_or(0);
            }
        } else {
            if let Some(err) = result.error_message {
                errors.push(format!("Deployment error: {}", err));
            }
        }
    }

    CommandResult {
        success: errors.is_empty(),
        error_message: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        result_data: Some(serde_json::json!({
            "removed": removed_count,
            "deployed": deployed_count,
            "errors": errors
        })),
    }
}

// Expand environment variables and tildes in file paths
fn expand_path(path: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        let mut expanded = path.to_string();

        // Expand %USERPROFILE%
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            expanded = expanded.replace("%USERPROFILE%", &user_profile);
        }

        // Expand other common variables
        if let Ok(app_data) = std::env::var("APPDATA") {
            expanded = expanded.replace("%APPDATA%", &app_data);
        }
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            expanded = expanded.replace("%LOCALAPPDATA%", &local_app_data);
        }

        expanded
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Expand tilde to home directory
        if path.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return path.replacen("~", &home, 1);
            }
        }
        path.to_string()
    }
}

// Set file modification time to 30-90 days ago to make it look realistic
fn set_backdate_timestamp(path: &std::path::Path) -> std::io::Result<()> {
    use std::time::{Duration, SystemTime};

    // Random backdate between 30 and 90 days
    let days_ago = 30
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % 60) as u64;

    let backdate_duration = Duration::from_secs(days_ago * 24 * 60 * 60);
    let backdate_time = SystemTime::now()
        .checked_sub(backdate_duration)
        .unwrap_or(SystemTime::now());

    // Use filetime crate for cross-platform timestamp setting
    let filetime = filetime::FileTime::from_system_time(backdate_time);
    filetime::set_file_mtime(path, filetime)?;

    Ok(())
}
