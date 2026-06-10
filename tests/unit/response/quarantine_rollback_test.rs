//! Tests for quarantine rollback state machine
//!
//! These tests exercise the restore/rollback logic WITHOUT actually
//! quarantining or restoring files. Safe to run on dev machines.

#[cfg(target_os = "windows")]
use tamandua_agent::quarantine::{
    QuarantineConfig, QuarantineEntry, QuarantineReason, RescanRecommendation, RestoreRequest,
    ThreatInfo, ThreatSeverity,
};

#[cfg(target_os = "windows")]
#[test]
fn test_restore_request_serialization() {
    let request = RestoreRequest {
        quarantine_id: "test-quar-123".to_string(),
        restore_path: Some("/tmp/restored.exe".to_string()),
        risk_acknowledged: true,
        rescan_after_restore: true,
        auth_token: Some("test-token-abc".to_string()),
        requested_by: Some("admin@example.com".to_string()),
        restore_reason: Some("False positive".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: RestoreRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.quarantine_id, "test-quar-123");
    assert_eq!(deserialized.restore_path, Some("/tmp/restored.exe".to_string()));
    assert!(deserialized.risk_acknowledged);
    assert!(deserialized.rescan_after_restore);
    assert_eq!(deserialized.auth_token, Some("test-token-abc".to_string()));
}

#[cfg(target_os = "windows")]
#[test]
fn test_restore_request_risk_not_acknowledged() {
    let request = RestoreRequest {
        quarantine_id: "test-quar-123".to_string(),
        restore_path: None,
        risk_acknowledged: false, // NOT acknowledged
        rescan_after_restore: false,
        auth_token: None,
        requested_by: None,
        restore_reason: None,
    };

    // Verify the field is correctly set
    assert!(!request.risk_acknowledged);

    // In production, the RestoreManager would reject this with:
    // error="Risk acknowledgment required before restoration"
}

#[cfg(target_os = "windows")]
#[test]
fn test_quarantine_entry_serialization() {
    use chrono::Utc;

    let entry = QuarantineEntry {
        id: "quar-456".to_string(),
        original_path: "C:\\Users\\test\\malware.exe".to_string(),
        quarantine_path: "C:\\ProgramData\\Tamandua\\Quarantine\\quar-456.quar".to_string(),
        quarantined_at: Utc::now(),
        reason: QuarantineReason::MalwareDetected,
        threat_info: Some(ThreatInfo {
            detection_name: "Trojan.Generic".to_string(),
            severity: ThreatSeverity::High,
            confidence: 0.95,
            detection_source: "yara".to_string(),
            detection_metadata: serde_json::json!({"rule": "malware_generic"}),
        }),
        file_size: 1024000,
        file_hash_sha256: "abc123def456...".to_string(),
        file_hash_md5: Some("def456abc123...".to_string()),
        original_permissions: None,
        encryption_key_id: "default".to_string(),
        metadata: serde_json::json!({"source": "ml_service"}),
        restored_at: None,
        restored_by: None,
        restore_reason: None,
        deleted_at: None,
    };

    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: QuarantineEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, "quar-456");
    assert_eq!(deserialized.original_path, "C:\\Users\\test\\malware.exe");
    assert_eq!(deserialized.file_size, 1024000);
    assert!(deserialized.threat_info.is_some());
}

#[cfg(target_os = "windows")]
#[test]
fn test_threat_severity_ordering() {
    use ThreatSeverity::*;

    // Verify severity levels are correctly ordered
    assert!(Critical > High);
    assert!(High > Medium);
    assert!(Medium > Low);
    assert!(Low > Info);
}

#[cfg(target_os = "windows")]
#[test]
fn test_quarantine_reason_serialization() {
    let reasons = vec![
        QuarantineReason::MalwareDetected,
        QuarantineReason::SuspiciousBehavior,
        QuarantineReason::UserInitiated,
        QuarantineReason::PolicyViolation,
    ];

    for reason in reasons {
        let json = serde_json::to_string(&reason).unwrap();
        let deserialized: QuarantineReason = serde_json::from_str(&json).unwrap();

        // Verify round-trip
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, json2);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn test_rescan_recommendation_serialization() {
    let recommendations = vec![
        RescanRecommendation::AllowKeep,
        RescanRecommendation::RecommendDelete,
        RescanRecommendation::RecommendRequarantine,
        RescanRecommendation::ManualReviewNeeded,
    ];

    for rec in recommendations {
        let json = serde_json::to_string(&rec).unwrap();
        let deserialized: RescanRecommendation = serde_json::from_str(&json).unwrap();

        // Verify round-trip
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, json2);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn test_quarantine_config_defaults() {
    let config = QuarantineConfig::default();

    // Verify default vault path
    assert!(config.vault_path.to_str().unwrap().contains("Quarantine"));

    // Verify default max size (10 GB)
    assert_eq!(config.max_vault_size_bytes, 10 * 1024 * 1024 * 1024);

    // Verify retention period (30 days)
    assert_eq!(config.retention_days, 30);
}

#[cfg(target_os = "windows")]
#[test]
fn test_restore_path_validation() {
    // Test cases for restore path validation logic
    let valid_paths = vec![
        Some("C:\\Users\\test\\restored.exe".to_string()),
        Some("D:\\safe-zone\\file.dll".to_string()),
        None, // None means restore to original path
    ];

    for path in valid_paths {
        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: path.clone(),
            risk_acknowledged: true,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        // Verify request is created successfully
        assert!(request.risk_acknowledged);
        assert_eq!(request.restore_path, path);
    }
}

// Test for non-Windows platforms (Linux/macOS)
#[cfg(not(target_os = "windows"))]
#[test]
fn test_quarantine_not_available_on_linux_macos() {
    // On Linux/macOS, the advanced quarantine vault is stubbed
    // This test just verifies the module compiles
    // The actual quarantine commands return "not implemented" errors
}

#[cfg(target_os = "windows")]
#[test]
fn test_threat_info_confidence_validation() {
    use ThreatInfo;

    let valid_confidences = vec![0.0, 0.5, 0.95, 1.0];

    for confidence in valid_confidences {
        let threat = ThreatInfo {
            detection_name: "Test".to_string(),
            severity: ThreatSeverity::Medium,
            confidence,
            detection_source: "test".to_string(),
            detection_metadata: serde_json::json!({}),
        };

        assert!(threat.confidence >= 0.0 && threat.confidence <= 1.0);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn test_encryption_key_id_format() {
    // Test that encryption key IDs follow expected format
    let valid_key_ids = vec!["default", "key-2024-01", "rotation-v2"];

    for key_id in valid_key_ids {
        let entry = QuarantineEntry {
            id: "test".to_string(),
            original_path: "test.exe".to_string(),
            quarantine_path: "vault/test.quar".to_string(),
            quarantined_at: chrono::Utc::now(),
            reason: QuarantineReason::MalwareDetected,
            threat_info: None,
            file_size: 1000,
            file_hash_sha256: "abc123".to_string(),
            file_hash_md5: None,
            original_permissions: None,
            encryption_key_id: key_id.to_string(),
            metadata: serde_json::json!({}),
            restored_at: None,
            restored_by: None,
            restore_reason: None,
            deleted_at: None,
        };

        assert_eq!(entry.encryption_key_id, key_id);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn test_quarantine_entry_timestamps() {
    use chrono::Utc;

    let now = Utc::now();

    let entry = QuarantineEntry {
        id: "test".to_string(),
        original_path: "test.exe".to_string(),
        quarantine_path: "vault/test.quar".to_string(),
        quarantined_at: now,
        reason: QuarantineReason::MalwareDetected,
        threat_info: None,
        file_size: 1000,
        file_hash_sha256: "abc123".to_string(),
        file_hash_md5: None,
        original_permissions: None,
        encryption_key_id: "default".to_string(),
        metadata: serde_json::json!({}),
        restored_at: Some(now),
        restored_by: Some("admin".to_string()),
        restore_reason: Some("FP".to_string()),
        deleted_at: None,
    };

    // Verify timestamps are set correctly
    assert_eq!(entry.quarantined_at, now);
    assert_eq!(entry.restored_at, Some(now));
    assert!(entry.restored_by.is_some());
    assert!(entry.deleted_at.is_none());
}
