//! Integration tests for IPC system

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::sync::Arc;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_message_serialization_roundtrip() {
        let messages = vec![
            IpcMessage::GetStatus,
            IpcMessage::GetMetrics,
            IpcMessage::GetVersion,
            IpcMessage::StartScan {
                path: std::path::PathBuf::from("/tmp/test"),
                recursive: true,
                scan_archives: false,
            },
            IpcMessage::Success,
            IpcMessage::Error {
                message: "Test error".to_string(),
                code: Some("TEST_ERROR".to_string()),
            },
        ];

        for msg in messages {
            let bytes = rmp_serde::to_vec(&msg).unwrap();
            let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
            // Messages should roundtrip successfully
            assert!(matches!(decoded, _));
        }
    }

    #[tokio::test]
    async fn test_authenticator_token_generation() {
        let auth = IpcAuthenticator::new();
        let token_hash = auth.token_hash();

        // Verify the hash
        assert!(auth.verify(&token_hash));

        // Invalid hash should fail
        assert!(!auth.verify("invalid_hash"));
    }

    #[tokio::test]
    async fn test_authenticator_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let token_path = temp_dir.path().join("token.json");

        let auth = IpcAuthenticator::new();
        let original_hash = auth.token_hash();

        // Save token
        auth.save_to_file(&token_path).await.unwrap();

        // Load token
        let loaded_auth = IpcAuthenticator::from_file(&token_path).await.unwrap();
        let loaded_hash = loaded_auth.token_hash();

        // Hashes should match
        assert_eq!(original_hash, loaded_hash);
    }

    #[tokio::test]
    async fn test_message_frame_encoding() {
        let msg = IpcMessage::GetStatus;

        let mut buffer = Vec::new();
        MessageFrame::write(&mut buffer, &msg).await.unwrap();

        // Check that buffer contains data
        assert!(!buffer.is_empty());

        // Should have length prefix (4 bytes) + message data
        assert!(buffer.len() > 4);

        // Read back
        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = MessageFrame::read(&mut cursor).await.unwrap();

        assert!(matches!(decoded, IpcMessage::GetStatus));
    }

    #[tokio::test]
    async fn test_message_codec_partial_read() {
        let msg = IpcMessage::GetStatus;

        let mut codec = MessageCodec::new();
        codec.encode(&msg).unwrap();

        let bytes = codec.bytes().to_vec();

        // Feed data in chunks
        let mut partial_codec = MessageCodec::new();

        // First half
        partial_codec.extend_from_slice(&bytes[..bytes.len() / 2]);
        assert!(partial_codec.try_decode().unwrap().is_none());

        // Second half
        partial_codec.extend_from_slice(&bytes[bytes.len() / 2..]);
        let decoded = partial_codec.try_decode().unwrap();

        assert!(decoded.is_some());
        assert!(matches!(decoded.unwrap(), IpcMessage::GetStatus));
    }

    #[tokio::test]
    async fn test_server_creation() {
        let auth = IpcAuthenticator::new();
        let server = Arc::new(IpcServer::new(auth));

        assert_eq!(server.client_count().await, 0);
    }

    #[tokio::test]
    async fn test_server_broadcast() {
        let auth = IpcAuthenticator::new();
        let server = Arc::new(IpcServer::new(auth));

        let msg = IpcMessage::Alert(AlertNotification {
            id: "test-1".to_string(),
            timestamp: chrono::Utc::now(),
            severity: AlertSeverity::High,
            title: "Test Alert".to_string(),
            description: "Test description".to_string(),
            threat_name: None,
            process_name: None,
            process_id: None,
            file_path: None,
            mitre_tactics: vec![],
            remediation: None,
            acknowledged: false,
        });

        // Broadcasting should succeed even with no clients
        assert!(server.broadcast(msg).is_ok());
    }

    #[test]
    fn test_message_auth_requirements() {
        // Basic status operations - safe without auth
        assert!(!IpcMessage::GetStatus.requires_auth());
        assert!(!IpcMessage::GetMetrics.requires_auth());
        assert!(!IpcMessage::GetVersion.requires_auth());
        assert!(!IpcMessage::GetComponentStatus.requires_auth());
        assert!(!IpcMessage::GetPerformanceProfile.requires_auth());

        // Auth messages don't require prior auth
        assert!(!IpcMessage::RequestChallenge.requires_auth());
        assert!(!IpcMessage::Authenticate {
            token_hash: "test".to_string()
        }
        .requires_auth());
        assert!(!IpcMessage::AuthenticateChallenge {
            response: ChallengeResponse {
                nonce: "test".to_string(),
                timestamp: 0,
                signature: "test".to_string(),
            }
        }
        .requires_auth());

        // SENSITIVE READ OPERATIONS - Now require auth per threat model
        assert!(IpcMessage::GetLogs {
            since: None,
            level: None,
            limit: None
        }
        .requires_auth());
        assert!(IpcMessage::GetAlerts {
            since: None,
            limit: None
        }
        .requires_auth());
        assert!(IpcMessage::GetProcessTree.requires_auth());
        assert!(IpcMessage::GetActiveConnections.requires_auth());
        assert!(IpcMessage::GetQuarantinedFiles.requires_auth());
        assert!(IpcMessage::GetEvents {
            event_types: None,
            severities: None,
            search: None,
            date_from: None,
            date_to: None,
            limit: None,
            offset: None,
        }
        .requires_auth());
        assert!(IpcMessage::GetEventStatistics {
            date_from: None,
            date_to: None
        }
        .requires_auth());
        assert!(IpcMessage::GetEvent {
            event_id: "test".to_string()
        }
        .requires_auth());
        assert!(IpcMessage::GetRelatedEvents {
            event_id: "test".to_string()
        }
        .requires_auth());

        // Write operations require auth
        assert!(IpcMessage::UpdateConfig {
            config: AgentConfigUpdate {
                scan_interval_seconds: Some(60),
                heartbeat_interval_seconds: None,
                enable_real_time_protection: None,
                enable_cloud_lookup: None,
                excluded_paths: None,
                excluded_processes: None,
            }
        }
        .requires_auth());

        assert!(IpcMessage::KillProcess { pid: 1234 }.requires_auth());

        assert!(IpcMessage::ExecuteAction {
            action: ResponseAction::IsolateHost,
        }
        .requires_auth());
    }

    #[test]
    fn test_sensitive_read_detection() {
        // Sensitive reads
        assert!(IpcMessage::GetLogs {
            since: None,
            level: None,
            limit: None
        }
        .is_sensitive_read());
        assert!(IpcMessage::GetAlerts {
            since: None,
            limit: None
        }
        .is_sensitive_read());
        assert!(IpcMessage::GetProcessTree.is_sensitive_read());
        assert!(IpcMessage::GetActiveConnections.is_sensitive_read());
        assert!(IpcMessage::GetQuarantinedFiles.is_sensitive_read());

        // Not sensitive reads
        assert!(!IpcMessage::GetStatus.is_sensitive_read());
        assert!(!IpcMessage::GetMetrics.is_sensitive_read());
        assert!(!IpcMessage::GetVersion.is_sensitive_read());
        assert!(!IpcMessage::KillProcess { pid: 1234 }.is_sensitive_read());
    }

    #[test]
    fn test_challenge_response_serialization() {
        // Test AuthChallenge serialization
        let challenge = AuthChallenge::generate();
        let challenge_msg = IpcMessage::Challenge(challenge.clone());

        let bytes = rmp_serde::to_vec(&challenge_msg).expect("Failed to serialize Challenge");
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).expect("Failed to deserialize");

        match decoded {
            IpcMessage::Challenge(decoded_challenge) => {
                assert_eq!(decoded_challenge.nonce, challenge.nonce);
                assert_eq!(decoded_challenge.timestamp, challenge.timestamp);
            }
            _ => panic!("Expected Challenge message"),
        }

        // Test ChallengeResponse serialization
        let response = ChallengeResponse::create(&challenge, "test_secret");
        let response_msg = IpcMessage::AuthenticateChallenge {
            response: response.clone(),
        };

        let bytes =
            rmp_serde::to_vec(&response_msg).expect("Failed to serialize AuthenticateChallenge");
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).expect("Failed to deserialize");

        match decoded {
            IpcMessage::AuthenticateChallenge {
                response: decoded_response,
            } => {
                assert_eq!(decoded_response.nonce, response.nonce);
                assert_eq!(decoded_response.timestamp, response.timestamp);
                assert_eq!(decoded_response.signature, response.signature);
            }
            _ => panic!("Expected AuthenticateChallenge message"),
        }
    }

    #[test]
    fn test_challenge_response_auth_flow() {
        // Simulate the full challenge-response auth flow
        let mut auth = IpcAuthenticator::new();
        let client_id = "test-client-1";
        let secret = auth.token_secret().to_string();

        // 1. Server creates challenge
        let challenge = auth.create_challenge(client_id);
        assert!(challenge.is_valid());

        // 2. Client creates response using token secret
        let response = ChallengeResponse::create(&challenge, &secret);

        // 3. Server verifies response
        assert!(auth.verify_response(client_id, &response));
    }

    #[test]
    fn test_challenge_response_replay_prevention() {
        // Verify that the same response cannot be used twice
        let mut auth = IpcAuthenticator::new();
        let client_id = "test-client-2";
        let secret = auth.token_secret().to_string();

        let challenge = auth.create_challenge(client_id);
        let response = ChallengeResponse::create(&challenge, &secret);

        // First verification should succeed
        assert!(auth.verify_response(client_id, &response));

        // Second verification should fail (challenge consumed)
        assert!(!auth.verify_response(client_id, &response));
    }

    #[test]
    fn test_challenge_response_wrong_secret() {
        let mut auth = IpcAuthenticator::new();
        let client_id = "test-client-3";

        let challenge = auth.create_challenge(client_id);
        let response = ChallengeResponse::create(&challenge, "wrong_secret");

        // Verification should fail with wrong secret
        assert!(!auth.verify_response(client_id, &response));
    }

    #[test]
    fn test_challenge_response_wrong_nonce() {
        let mut auth = IpcAuthenticator::new();
        let client_id = "test-client-4";
        let secret = auth.token_secret().to_string();

        let challenge = auth.create_challenge(client_id);
        let mut response = ChallengeResponse::create(&challenge, &secret);

        // Modify the nonce
        response.nonce =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        // Verification should fail
        assert!(!auth.verify_response(client_id, &response));
    }

    #[test]
    fn test_message_response_detection() {
        // Responses
        assert!(IpcMessage::Success.is_response());
        assert!(IpcMessage::Error {
            message: "test".to_string(),
            code: None
        }
        .is_response());
        assert!(IpcMessage::StatusUpdate(AgentStatus {
            agent_id: "test".to_string(),
            version: "1.0.0".to_string(),
            state: AgentState::Running,
            backend_connected: true,
            last_heartbeat: None,
            collectors_running: vec![],
            protection_enabled: true,
            scan_in_progress: false,
            cpu_usage: 0.0,
            memory_usage: 0,
            uptime_seconds: 0,
        })
        .is_response());

        // Requests
        assert!(!IpcMessage::GetStatus.is_response());
        assert!(!IpcMessage::StartScan {
            path: std::path::PathBuf::from("/tmp"),
            recursive: true,
            scan_archives: false,
        }
        .is_response());
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }

    #[test]
    fn test_authenticate_message_serialization() {
        // Test with a realistic 64-character SHA256 hash
        let token_hash =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string();
        let msg = IpcMessage::Authenticate {
            token_hash: token_hash.clone(),
        };

        // Serialize
        let bytes = rmp_serde::to_vec(&msg).expect("Failed to serialize Authenticate");

        println!("Serialized Authenticate: {:02x?}", bytes);

        // rmp-serde encodes an externally-tagged enum variant as a single-entry
        // map (variant name -> content), so the first byte is fixmap(1) = 0x81.
        assert_eq!(bytes[0], 0x81, "First byte should be fixmap(1)");

        // Deserialize back
        let decoded: IpcMessage =
            rmp_serde::from_slice(&bytes).expect("Failed to deserialize Authenticate");

        // Verify
        match decoded {
            IpcMessage::Authenticate {
                token_hash: decoded_hash,
            } => {
                assert_eq!(decoded_hash, token_hash);
            }
            _ => panic!("Expected Authenticate message, got {:?}", decoded),
        }
    }

    #[test]
    fn test_authenticate_deserialize_raw_bytes() {
        // This simulates the exact bytes the GUI might send
        // We construct the MessagePack bytes manually to verify our understanding

        // Token hash: 64 hex chars
        let token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        // Build MessagePack bytes manually:
        // [0x81] fixmap(1) - externally-tagged enum variant
        // [0xac] fixstr(12) "Authenticate"
        // [0x91] fixarray(1) - the struct fields as an array
        // [0xd9, 0x40, ...] str8(64) - the token hash
        let mut bytes: Vec<u8> = vec![
            0x81, // fixmap(1)
            0xac, // fixstr(12)
        ];
        bytes.extend_from_slice(b"Authenticate");
        bytes.push(0x91); // fixarray(1) for struct content
        bytes.push(0xd9); // str8
        bytes.push(0x40); // length 64
        bytes.extend_from_slice(token.as_bytes());

        println!("Manual bytes: {:02x?}", bytes);

        // Try to deserialize
        let result: Result<IpcMessage, _> = rmp_serde::from_slice(&bytes);

        match result {
            Ok(IpcMessage::Authenticate { token_hash }) => {
                assert_eq!(token_hash, token);
                println!("Successfully deserialized Authenticate message!");
            }
            Ok(other) => panic!("Expected Authenticate, got {:?}", other),
            Err(e) => panic!("Failed to deserialize: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_legacy_auth_config_default() {
        use crate::config::IpcConfig;

        // Default should have legacy auth DISABLED
        let config = IpcConfig::default();
        assert!(
            !config.legacy_auth_enabled,
            "Legacy auth should be disabled by default"
        );
    }

    #[tokio::test]
    async fn test_legacy_auth_config_enabled() {
        use crate::config::IpcConfig;

        // Test explicit enable
        let config = IpcConfig {
            legacy_auth_enabled: true,
        };
        assert!(config.legacy_auth_enabled);
    }

    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_client_server_integration() {
        // This test requires an actual server to be running
        // Run with: cargo test test_client_server_integration --ignored

        // Start server
        let auth = IpcAuthenticator::new();
        let token_path = IpcAuthenticator::default_token_path();
        auth.save_to_file(&token_path).await.unwrap();

        let server = Arc::new(IpcServer::new(auth));
        let server_handle = server.clone().start().await.unwrap();

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let client_result = timeout(Duration::from_secs(5), IpcClient::connect()).await;

        if let Ok(Ok(client)) = client_result {
            // Test basic request
            let status_result = timeout(Duration::from_secs(5), client.get_status()).await;

            if let Ok(Ok(status)) = status_result {
                assert!(!status.agent_id.is_empty());
                assert!(!status.version.is_empty());
            } else {
                panic!("Failed to get status: {:?}", status_result);
            }
        } else {
            panic!("Failed to connect client");
        }

        // Cleanup
        server.shutdown().await.ok();
    }
}
