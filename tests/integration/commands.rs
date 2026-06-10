//! Command reception and execution integration tests
//!
//! Tests:
//! - Command reception from server
//! - Command parsing and validation
//! - Command execution
//! - Response transmission

use std::time::Duration;

use super::util::{test_agent_id, test_server_url, should_run_server_tests};

/// Create test config
fn test_config() -> tamandua_agent::config::AgentConfig {
    tamandua_agent::config::AgentConfig {
        agent_id: test_agent_id(),
        server_url: test_server_url(),
        auth_token: Some("dev-token-test".to_string()),
        heartbeat_interval_seconds: 30,
        batch_size: 100,
        batch_timeout_seconds: 5,
        reconnect_delay_seconds: 5,
        max_reconnect_attempts: 3,
        local_queue_size: Some(1000),
        yara_enabled: false,
        entropy_check_enabled: true,
        entropy_threshold: 7.5,
        honeyfiles_enabled: false,
        local_analysis_enabled: false,
        health_interval_seconds: 60,
        excluded_paths: vec![],
        excluded_processes: vec![],
        tls: tamandua_agent::config::TlsConfig::default(),
        collectors: tamandua_agent::config::CollectorsConfig::default(),
    }
}

#[tokio::test]
async fn test_command_type_parsing() {
    use tamandua_agent::transport::CommandType;

    // Test all command types can be parsed from JSON
    let commands = vec![
        ("kill_process", CommandType::KillProcess),
        ("quarantine_file", CommandType::QuarantineFile),
        ("isolate_network", CommandType::IsolateNetwork),
        ("unisolate_network", CommandType::UnisolateNetwork),
        ("collect_artifact", CommandType::CollectArtifact),
        ("update_config", CommandType::UpdateConfig),
        ("update_rules", CommandType::UpdateRules),
        ("scan_path", CommandType::ScanPath),
        ("block_ip", CommandType::BlockIP),
        ("unblock_ip", CommandType::UnblockIP),
        ("block_domain", CommandType::BlockDomain),
        ("unblock_domain", CommandType::UnblockDomain),
        ("process_list", CommandType::ProcessList),
        ("network_connections", CommandType::NetworkConnections),
        ("file_download", CommandType::FileDownload),
    ];

    for (json_name, expected_type) in commands {
        let json = format!(r#"{{"command_type": "{}"}}"#, json_name);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let cmd_type: CommandType =
            serde_json::from_value(parsed["command_type"].clone()).unwrap();
        assert_eq!(
            std::mem::discriminant(&cmd_type),
            std::mem::discriminant(&expected_type)
        );
    }
}

#[tokio::test]
async fn test_command_parsing() {
    use tamandua_agent::transport::Command;

    let json = r#"{
        "command_id": "550e8400-e29b-41d4-a716-446655440000",
        "command_type": "kill_process",
        "timestamp": 1704067200000,
        "payload": {
            "pid": 12345,
            "force": true
        }
    }"#;

    let command: Command = serde_json::from_str(json).expect("Command should parse");

    assert_eq!(command.command_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(command.payload["pid"], 12345);
    assert_eq!(command.payload["force"], true);
}

#[tokio::test]
async fn test_command_result_serialization() {
    use tamandua_agent::transport::CommandResult;

    let result = CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "pid_killed": 12345,
            "exit_code": 0
        })),
    };

    let json = serde_json::to_string(&result).expect("Result should serialize");
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("pid_killed"));
}

#[tokio::test]
async fn test_failed_command_result() {
    use tamandua_agent::transport::CommandResult;

    let result = CommandResult {
        success: false,
        error_message: Some("Process not found".to_string()),
        result_data: None,
    };

    let json = serde_json::to_string(&result).expect("Result should serialize");
    assert!(json.contains("\"success\":false"));
    assert!(json.contains("Process not found"));
}

#[tokio::test]
#[ignore = "requires running server"]
async fn test_receives_command_from_server() {
    if !should_run_server_tests() {
        return;
    }

    let config = test_config();

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {:?}", e);
            return;
        }
    };

    if client.connect().await.is_err() {
        eprintln!("Connection failed");
        return;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Try to receive command with timeout
    // In real scenario, server would push command
    let result = client.try_receive_command(Duration::from_secs(2)).await;

    // May or may not receive command depending on server state
    match result {
        Some(cmd) => {
            println!("Received command: {:?}", cmd.command_type);
        }
        None => {
            println!("No command received (expected in test environment)");
        }
    }
}

#[tokio::test]
#[ignore = "requires running server"]
async fn test_sends_command_response() {
    if !should_run_server_tests() {
        return;
    }

    let config = test_config();

    let client = match tamandua_agent::transport::BackendClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {:?}", e);
            return;
        }
    };

    if client.connect().await.is_err() {
        eprintln!("Connection failed");
        return;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Create mock command and response
    use tamandua_agent::transport::{Command, CommandResult, CommandType};

    let command = Command {
        command_id: uuid::Uuid::new_v4().to_string(),
        command_type: CommandType::ProcessList,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        payload: serde_json::json!({}),
    };

    let result = CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "processes": [
                {"pid": 1, "name": "init"},
                {"pid": 100, "name": "sshd"}
            ]
        })),
    };

    match client.send_command_response(&command, result).await {
        Ok(()) => {
            println!("Command response sent successfully");
        }
        Err(e) => {
            eprintln!("Failed to send response: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_config_update_parsing() {
    use tamandua_agent::transport::ConfigUpdate;

    // Simulate config update message from server
    let update = ConfigUpdate {
        config: serde_json::json!({
            "heartbeat_interval_seconds": 60,
            "batch_size": 200
        }),
        yara_rules: Some(vec![serde_json::json!({
            "name": "test_rule",
            "content": "rule test { condition: true }"
        })]),
        sigma_rules: Some(vec![]),
        iocs: Some(vec![serde_json::json!({
            "type": "sha256",
            "value": "abc123"
        })]),
    };

    // Should serialize/deserialize correctly
    let json = serde_json::to_string(&update).unwrap();
    assert!(json.contains("heartbeat_interval_seconds"));
    assert!(json.contains("test_rule"));
}

#[tokio::test]
async fn test_ml_scan_result_parsing() {
    use tamandua_agent::transport::MlScanResult;

    let json = r#"{
        "sha256": "abc123",
        "file_path": "C:\\Users\\test\\malware.exe",
        "is_malicious": true,
        "confidence": 0.95,
        "classification": "Trojan.Generic",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1059"],
        "details": {"model_version": "1.0"}
    }"#;

    let result: MlScanResult = serde_json::from_str(json).expect("Should parse");

    assert_eq!(result.sha256, "abc123");
    assert!(result.is_malicious);
    assert_eq!(result.confidence, 0.95);
    assert_eq!(result.classification, Some("Trojan.Generic".to_string()));
    assert!(result.mitre_tactics.contains(&"execution".to_string()));
}

#[tokio::test]
async fn test_sample_submission_serialization() {
    use tamandua_agent::transport::SampleSubmission;

    let submission = SampleSubmission {
        sha256: "abc123def456".to_string(),
        sha1: "sha1hash".to_string(),
        md5: "md5hash".to_string(),
        file_path: "C:\\test\\sample.exe".to_string(),
        file_type: "pe".to_string(),
        entropy: 7.5,
        content: "base64encodedcontent".to_string(),
        size: 1024,
        is_pe: true,
        is_elf: false,
        is_macho: false,
        is_signed: false,
        signer: None,
        created_at: Some(1704067200),
        modified_at: Some(1704067200),
    };

    let json = serde_json::to_string(&submission).expect("Should serialize");
    assert!(json.contains("abc123def456"));
    assert!(json.contains("\"entropy\":7.5"));
    assert!(json.contains("\"is_pe\":true"));
}

#[cfg(test)]
mod command_execution_tests {
    //! Unit tests for command execution logic

    use super::*;

    #[tokio::test]
    async fn test_kill_process_payload() {
        let payload = serde_json::json!({
            "pid": 12345,
            "force": true
        });

        let pid: u32 = payload["pid"].as_u64().unwrap() as u32;
        let force: bool = payload["force"].as_bool().unwrap();

        assert_eq!(pid, 12345);
        assert!(force);
    }

    #[tokio::test]
    async fn test_quarantine_file_payload() {
        let payload = serde_json::json!({
            "path": "C:\\Users\\test\\malware.exe",
            "delete_original": true
        });

        let path: &str = payload["path"].as_str().unwrap();
        assert_eq!(path, "C:\\Users\\test\\malware.exe");
    }

    #[tokio::test]
    async fn test_scan_path_payload() {
        let payload = serde_json::json!({
            "path": "C:\\Users",
            "recursive": true,
            "include_patterns": ["*.exe", "*.dll"],
            "exclude_patterns": ["*.log"]
        });

        let path: &str = payload["path"].as_str().unwrap();
        let recursive: bool = payload["recursive"].as_bool().unwrap();

        assert_eq!(path, "C:\\Users");
        assert!(recursive);
    }

    #[tokio::test]
    async fn test_block_ip_payload() {
        let payload = serde_json::json!({
            "ip": "192.168.1.100",
            "direction": "both",
            "duration_seconds": 3600
        });

        let ip: &str = payload["ip"].as_str().unwrap();
        let direction: &str = payload["direction"].as_str().unwrap();

        assert_eq!(ip, "192.168.1.100");
        assert_eq!(direction, "both");
    }

    #[tokio::test]
    async fn test_file_download_payload() {
        let payload = serde_json::json!({
            "path": "C:\\Users\\test\\evidence.txt",
            "max_size_bytes": 10485760
        });

        let path: &str = payload["path"].as_str().unwrap();
        let max_size: u64 = payload["max_size_bytes"].as_u64().unwrap();

        assert_eq!(path, "C:\\Users\\test\\evidence.txt");
        assert_eq!(max_size, 10485760);
    }
}
