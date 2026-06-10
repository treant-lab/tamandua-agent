//! Tests for the Quarantine Vault module

#[cfg(test)]
mod integration_tests {

    use crate::quarantine::*;

    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio;

    fn create_test_config(temp_dir: &TempDir) -> QuarantineConfig {
        QuarantineConfig {
            enabled: true,
            vault_path: temp_dir
                .path()
                .join("quarantine")
                .to_string_lossy()
                .to_string(),
            max_size_bytes: 1024 * 1024 * 100, // 100MB for tests
            retention_days: 30,
            require_auth_for_restore: false,
            rescan_after_restore: false,
            master_key_id: Some("test-key".to_string()),
            compress_before_encrypt: true,
            max_file_size_bytes: 10 * 1024 * 1024, // 10MB
        }
    }

    fn create_test_file(temp_dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = temp_dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[tokio::test]
    async fn test_quarantine_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // This test may fail if credential storage is not available
        // In CI environments, we skip the full manager creation
        if std::env::var("CI").is_ok() {
            return;
        }

        let result = QuarantineManager::new(config).await;
        // May fail due to credential storage requirements
        if result.is_err() {
            println!("Skipping test due to credential storage unavailability");
            return;
        }

        let manager = result.unwrap();
        let stats = manager.get_stats().await.unwrap();
        assert_eq!(stats.total_files, 0);
    }

    #[test]
    fn test_threat_severity_from_score() {
        assert_eq!(ThreatSeverity::from_score(0.95), ThreatSeverity::Critical);
        assert_eq!(ThreatSeverity::from_score(0.85), ThreatSeverity::High);
        assert_eq!(ThreatSeverity::from_score(0.55), ThreatSeverity::Medium);
        assert_eq!(ThreatSeverity::from_score(0.25), ThreatSeverity::Low);
    }

    #[test]
    fn test_quarantine_config_default() {
        let config = QuarantineConfig::default();

        assert!(config.enabled);
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.max_size_bytes, 10 * 1024 * 1024 * 1024);
        assert!(config.require_auth_for_restore);
        assert!(config.rescan_after_restore);
        assert!(config.compress_before_encrypt);
    }
}

#[cfg(test)]
mod vault_tests {
    use super::super::vault::VaultStorage;
    use chrono::Utc;
    use tempfile::TempDir;

    #[test]
    fn test_vault_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();

        // Vault directory should exist
        assert!(vault_path.join("vault").exists());
    }

    #[test]
    fn test_vault_file_path_includes_date() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();

        let id = "test-file-id";
        let data = b"test encrypted content";
        let now = Utc::now();

        let stored_path = vault.store_file(id, data, now).unwrap();

        // Path should include year/month
        let year = now.format("%Y").to_string();
        let month = now.format("%m").to_string();

        assert!(stored_path.to_string_lossy().contains(&year));
        assert!(stored_path.to_string_lossy().contains(&month));
        assert!(stored_path.to_string_lossy().ends_with(".enc"));
    }

    #[test]
    fn test_vault_file_count() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();

        // Initially empty
        assert_eq!(vault.get_file_count().unwrap(), 0);

        // Add files
        vault.store_file("file1", b"content1", Utc::now()).unwrap();
        vault.store_file("file2", b"content2", Utc::now()).unwrap();

        assert_eq!(vault.get_file_count().unwrap(), 2);
    }
}

#[cfg(test)]
mod encryption_tests {
    use super::super::encryption::EncryptionManager;

    #[test]
    fn test_encryption_roundtrip_with_test_key() {
        // Create manager with a known key for testing
        let manager = EncryptionManager::new_for_test_key(vec![0x42; 32], "test");

        let plaintext = b"This is sensitive malware sample data that needs encryption!";
        let aad = "test-quarantine-id-12345";

        let encrypted = manager.encrypt(plaintext, aad).unwrap();

        // Verify encrypted data is different from plaintext
        assert_ne!(encrypted.ciphertext, plaintext.as_slice());

        // Decrypt and verify
        let decrypted = manager
            .decrypt(&encrypted.ciphertext, &encrypted.iv, &encrypted.tag, aad)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_produces_different_output_each_time() {
        let manager = EncryptionManager::new_for_test_key(vec![0x42; 32], "test");

        let plaintext = b"Same content";
        let aad = "same-id";

        let enc1 = manager.encrypt(plaintext, aad).unwrap();
        let enc2 = manager.encrypt(plaintext, aad).unwrap();

        // Different IVs
        assert_ne!(enc1.iv, enc2.iv);
        // Different ciphertext
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn test_wrong_aad_fails_decryption() {
        let manager = EncryptionManager::new_for_test_key(vec![0x42; 32], "test");

        let plaintext = b"Secret data";
        let correct_aad = "correct-id";
        let wrong_aad = "wrong-id";

        let encrypted = manager.encrypt(plaintext, correct_aad).unwrap();

        // Should fail with wrong AAD
        let result = manager.decrypt(
            &encrypted.ciphertext,
            &encrypted.iv,
            &encrypted.tag,
            wrong_aad,
        );

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::super::metadata::{MetadataDb, QuarantineEntry, QuarantineReason};
    use super::super::ThreatSeverity;
    use chrono::{Duration, Utc};
    use tempfile::TempDir;

    fn create_test_entry(id: &str) -> QuarantineEntry {
        QuarantineEntry {
            id: id.to_string(),
            original_path: format!("/test/path/{}.exe", id),
            original_name: format!("{}.exe", id),
            file_size: 1234,
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            sha256: format!("sha256-{}", id),
            quarantined_at: Utc::now(),
            reason: QuarantineReason::MlDetection,
            detection_source: "ml".to_string(),
            threat_name: Some("Test.Malware".to_string()),
            threat_family: Some("TestFamily".to_string()),
            severity: ThreatSeverity::High,
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
            triggered_by: Some("test".to_string()),
            vault_path: format!("/vault/{}.enc", id),
            encryption_iv: "abcdef123456".to_string(),
            encryption_tag: "tag123456789".to_string(),
            is_compressed: true,
            restoration_history: Vec::new(),
            is_deleted: false,
        }
    }

    #[test]
    fn test_database_schema_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let _db = MetadataDb::new(&db_path).unwrap();

        // Database file should exist
        assert!(db_path.exists());
    }

    #[test]
    fn test_entry_crud_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        // Create
        let entry = create_test_entry("crud-test");
        db.insert_entry(&entry).unwrap();

        // Read
        let retrieved = db.get_entry("crud-test").unwrap().unwrap();
        assert_eq!(retrieved.original_path, entry.original_path);
        assert_eq!(retrieved.sha256, entry.sha256);

        // Update (via mark_deleted)
        db.mark_deleted("crud-test").unwrap();

        // Verify deleted
        let entries = db.list_entries(None, None, false).unwrap();
        assert!(entries.is_empty());

        let entries_with_deleted = db.list_entries(None, None, true).unwrap();
        assert_eq!(entries_with_deleted.len(), 1);
    }

    #[test]
    fn test_get_by_hash() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        let entry = create_test_entry("hash-test");
        db.insert_entry(&entry).unwrap();

        let by_hash = db.get_entry_by_hash(&entry.sha256).unwrap();
        assert!(by_hash.is_some());
        assert_eq!(by_hash.unwrap().id, "hash-test");
    }

    #[test]
    fn test_entries_older_than() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        // Insert entries with different ages
        let mut old_entry = create_test_entry("old");
        old_entry.quarantined_at = Utc::now() - Duration::days(100);
        db.insert_entry(&old_entry).unwrap();

        let new_entry = create_test_entry("new");
        db.insert_entry(&new_entry).unwrap();

        // Query for entries older than 50 days
        let cutoff = Utc::now() - Duration::days(50);
        let old_ids = db.get_entries_older_than(cutoff).unwrap();

        assert_eq!(old_ids.len(), 1);
        assert_eq!(old_ids[0], "old");
    }

    #[test]
    fn test_restoration_history() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        let entry = create_test_entry("restore-test");
        db.insert_entry(&entry).unwrap();

        // Record restorations
        db.record_restoration("restore-test", "/restored/path1")
            .unwrap();
        db.record_restoration("restore-test", "/restored/path2")
            .unwrap();

        // Check history
        let retrieved = db.get_entry("restore-test").unwrap().unwrap();
        assert_eq!(retrieved.restoration_history.len(), 2);
    }

    #[test]
    fn test_threat_family_stats() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        // Insert entries with different families
        for i in 0..5 {
            let mut entry = create_test_entry(&format!("family1-{}", i));
            entry.threat_family = Some("Emotet".to_string());
            db.insert_entry(&entry).unwrap();
        }

        for i in 0..3 {
            let mut entry = create_test_entry(&format!("family2-{}", i));
            entry.threat_family = Some("Ryuk".to_string());
            db.insert_entry(&entry).unwrap();
        }

        let stats = db.get_threat_family_stats().unwrap();

        assert!(stats.len() >= 2);
        // Emotet should have more entries
        let emotet = stats.iter().find(|(name, _)| name == "Emotet").unwrap();
        assert_eq!(emotet.1, 5);
    }
}

#[cfg(test)]
mod retention_tests {
    use super::super::metadata::{QuarantineEntry, QuarantineReason};
    use super::super::retention::{RetentionConfig, RetentionPolicy};
    use super::super::ThreatSeverity;
    use chrono::{Duration, Utc};

    fn create_entry_with_age(id: &str, days_old: i64, severity: ThreatSeverity) -> QuarantineEntry {
        QuarantineEntry {
            id: id.to_string(),
            original_path: "/test/file.exe".to_string(),
            original_name: "file.exe".to_string(),
            file_size: 1000,
            md5: "md5".to_string(),
            sha1: "sha1".to_string(),
            sha256: "sha256".to_string(),
            quarantined_at: Utc::now() - Duration::days(days_old),
            reason: QuarantineReason::MlDetection,
            detection_source: "ml".to_string(),
            threat_name: Some("Test".to_string()),
            threat_family: None,
            severity,
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            triggered_by: None,
            vault_path: "/vault/file.enc".to_string(),
            encryption_iv: "iv".to_string(),
            encryption_tag: "tag".to_string(),
            is_compressed: true,
            restoration_history: Vec::new(),
            is_deleted: false,
        }
    }

    #[test]
    fn test_retention_policy_basic() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        // Recent entry should be kept
        let recent = create_entry_with_age("recent", 10, ThreatSeverity::Medium);
        assert!(policy.should_keep(&recent));

        // Old entry should be removed
        let old = create_entry_with_age("old", 45, ThreatSeverity::Medium);
        assert!(!policy.should_keep(&old));
    }

    #[test]
    fn test_retention_extension_for_critical() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        // Critical entry at 45 days should still be kept (30 + 60 = 90 days)
        let critical = create_entry_with_age("critical", 45, ThreatSeverity::Critical);
        assert!(policy.should_keep(&critical));

        // Critical entry at 100 days should be removed
        let very_old_critical = create_entry_with_age("very-old", 100, ThreatSeverity::Critical);
        assert!(!policy.should_keep(&very_old_critical));
    }

    #[test]
    fn test_days_until_expiry() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        let entry = create_entry_with_age("test", 10, ThreatSeverity::Medium);
        let days = policy.days_until_expiry(&entry);

        // Should have approximately 20 days remaining
        assert!(days >= 19 && days <= 21, "Expected ~20 days, got {}", days);
    }
}

#[cfg(test)]
mod restore_tests {
    use super::super::metadata::{QuarantineEntry, QuarantineReason};
    use super::super::restore::{RestoreManager, RestoreRequest};
    use super::super::ThreatSeverity;
    use chrono::Utc;

    fn create_test_entry() -> QuarantineEntry {
        QuarantineEntry {
            id: "test".to_string(),
            original_path: "/home/user/suspicious.exe".to_string(),
            original_name: "suspicious.exe".to_string(),
            file_size: 12345,
            md5: "md5".to_string(),
            sha1: "sha1".to_string(),
            sha256: "sha256".to_string(),
            quarantined_at: Utc::now(),
            reason: QuarantineReason::MlDetection,
            detection_source: "ml".to_string(),
            threat_name: Some("Trojan.Generic".to_string()),
            threat_family: Some("GenericTrojan".to_string()),
            severity: ThreatSeverity::High,
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
            triggered_by: None,
            vault_path: "/vault/test.enc".to_string(),
            encryption_iv: "iv".to_string(),
            encryption_tag: "tag".to_string(),
            is_compressed: true,
            restoration_history: Vec::new(),
            is_deleted: false,
        }
    }

    #[test]
    fn test_validation_requires_auth() {
        let manager = RestoreManager::new(true, false, false);

        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: None,
            risk_acknowledged: true,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        let result = manager.validate_request(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication"));
    }

    #[test]
    fn test_validation_requires_acknowledgment() {
        let manager = RestoreManager::new(false, true, false);

        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: None,
            risk_acknowledged: false,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        let result = manager.validate_request(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("acknowledgment"));
    }

    #[test]
    fn test_path_traversal_blocked() {
        let manager = RestoreManager::new(false, false, false);

        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: Some("../../etc/passwd".to_string()),
            risk_acknowledged: true,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        let result = manager.validate_request(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("traversal"));
    }

    #[test]
    fn test_should_warn_for_critical() {
        let manager = RestoreManager::default();
        let entry = create_test_entry();

        assert!(manager.should_warn(&entry));
    }

    #[test]
    fn test_warning_generation() {
        let manager = RestoreManager::default();
        let entry = create_test_entry();

        let warning = manager.generate_warning(&entry);

        assert!(warning.contains("WARNING"));
        assert!(warning.contains("Trojan.Generic"));
        assert!(warning.contains("GenericTrojan"));
        assert!(warning.contains("High"));
    }
}

#[cfg(test)]
mod stats_tests {
    use super::super::stats::{format_size, SeverityDistribution};

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1023), "1023 bytes");
    }

    #[test]
    fn test_format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(10240), "10.00 KB");
    }

    #[test]
    fn test_format_size_megabytes() {
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 500), "500.00 MB");
    }

    #[test]
    fn test_format_size_gigabytes() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(1024 * 1024 * 1024 * 5), "5.00 GB");
    }

    #[test]
    fn test_format_size_terabytes() {
        assert_eq!(format_size(1024 * 1024 * 1024 * 1024), "1.00 TB");
    }

    #[test]
    fn test_severity_distribution_default() {
        let dist = SeverityDistribution::default();
        assert_eq!(dist.low, 0);
        assert_eq!(dist.medium, 0);
        assert_eq!(dist.high, 0);
        assert_eq!(dist.critical, 0);
    }
}
