//! Retention Policy for Quarantine Vault
//!
//! Manages automatic cleanup of quarantined files based on:
//! - Age (default: 90 days retention)
//! - Vault size (default: 10GB maximum)
//! - Permanent deletion after retention period
//!
//! Cleanup priorities:
//! 1. Files past retention period are deleted first
//! 2. If vault size still exceeds limit, oldest files are deleted
//! 3. Files with restoration history may have extended retention

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::metadata::MetadataDb;
use super::stats::VaultStats;

/// Retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Retention period in days (default: 90)
    pub retention_days: u32,
    /// Maximum vault size in bytes (default: 10GB)
    pub max_size_bytes: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_size_bytes: 10 * 1024 * 1024 * 1024, // 10GB
        }
    }
}

/// Extended retention configuration for specific scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRetentionRules {
    /// Extra days to keep files with restoration history
    pub restoration_extension_days: u32,
    /// Extra days to keep critical severity files
    pub critical_severity_extension_days: u32,
    /// Extra days to keep files from known malware families
    pub known_family_extension_days: u32,
    /// Minimum files to always keep (regardless of retention)
    pub minimum_file_count: u32,
}

impl Default for ExtendedRetentionRules {
    fn default() -> Self {
        Self {
            restoration_extension_days: 30,
            critical_severity_extension_days: 60,
            known_family_extension_days: 45,
            minimum_file_count: 100,
        }
    }
}

/// Retention policy manager
pub struct RetentionPolicy {
    config: RetentionConfig,
    extended_rules: ExtendedRetentionRules,
}

impl RetentionPolicy {
    /// Create a new retention policy
    pub fn new(config: RetentionConfig) -> Self {
        Self {
            config,
            extended_rules: ExtendedRetentionRules::default(),
        }
    }

    /// Create with extended rules
    pub fn with_extended_rules(
        config: RetentionConfig,
        extended_rules: ExtendedRetentionRules,
    ) -> Self {
        Self {
            config,
            extended_rules,
        }
    }

    /// Get list of entry IDs that should be deleted based on retention policy
    pub fn get_entries_to_delete(
        &self,
        db: &MetadataDb,
        stats: &VaultStats,
    ) -> Result<Vec<String>> {
        let mut to_delete = Vec::new();
        let now = Utc::now();

        // Phase 1: Delete entries past retention period
        let retention_cutoff = now - Duration::days(self.config.retention_days as i64);
        let expired_ids = db.get_entries_older_than(retention_cutoff)?;

        for id in expired_ids {
            // Check for extended retention
            if let Ok(Some(entry)) = db.get_entry(&id) {
                let effective_cutoff = self.calculate_effective_retention(&entry, now);
                if entry.quarantined_at < effective_cutoff {
                    to_delete.push(id);
                }
            }
        }

        info!(
            expired_count = to_delete.len(),
            retention_days = self.config.retention_days,
            "Found expired entries for retention cleanup"
        );

        // Phase 2: Check if we need to delete more for size limit
        let current_size = stats.total_size_bytes;
        if current_size > self.config.max_size_bytes && to_delete.len() < stats.total_files as usize
        {
            let excess_bytes = current_size - self.config.max_size_bytes;
            let additional = self.get_entries_for_size_limit(db, &to_delete, excess_bytes)?;
            to_delete.extend(additional);

            info!(
                current_size_mb = current_size / (1024 * 1024),
                max_size_mb = self.config.max_size_bytes / (1024 * 1024),
                excess_mb = excess_bytes / (1024 * 1024),
                "Vault size exceeds limit, additional cleanup needed"
            );
        }

        // Phase 3: Ensure minimum file count
        let total_files = stats.total_files;
        let remaining_after_delete = total_files.saturating_sub(to_delete.len() as u64);
        if remaining_after_delete < self.extended_rules.minimum_file_count as u64 {
            // Don't delete enough to go below minimum
            let max_to_delete =
                total_files.saturating_sub(self.extended_rules.minimum_file_count as u64);
            to_delete.truncate(max_to_delete as usize);

            debug!(
                minimum_files = self.extended_rules.minimum_file_count,
                "Limiting deletions to maintain minimum file count"
            );
        }

        Ok(to_delete)
    }

    /// Check if an entry should be kept based on retention policy
    pub fn should_keep(&self, entry: &super::metadata::QuarantineEntry) -> bool {
        let now = Utc::now();
        let effective_cutoff = self.calculate_effective_retention(entry, now);
        entry.quarantined_at >= effective_cutoff
    }

    /// Get the effective retention date for an entry (considering extensions)
    pub fn get_effective_retention_date(
        &self,
        entry: &super::metadata::QuarantineEntry,
    ) -> DateTime<Utc> {
        let now = Utc::now();
        self.calculate_effective_retention(entry, now)
    }

    /// Calculate days until entry expires
    pub fn days_until_expiry(&self, entry: &super::metadata::QuarantineEntry) -> i64 {
        let now = Utc::now();
        let effective_cutoff = self.calculate_effective_retention(entry, now);
        let _expiry_date = entry.quarantined_at + (now - effective_cutoff);

        // Days remaining = expiry date - now
        let base_expiry = entry.quarantined_at + Duration::days(self.config.retention_days as i64);
        let extension = self.calculate_extension_days(entry);
        let extended_expiry = base_expiry + Duration::days(extension as i64);

        (extended_expiry - now).num_days()
    }

    /// Calculate effective retention cutoff for an entry
    fn calculate_effective_retention(
        &self,
        entry: &super::metadata::QuarantineEntry,
        now: DateTime<Utc>,
    ) -> DateTime<Utc> {
        let base_days = self.config.retention_days;
        let extension = self.calculate_extension_days(entry);
        let total_days = base_days + extension;

        now - Duration::days(total_days as i64)
    }

    /// Calculate retention extension days for an entry
    fn calculate_extension_days(&self, entry: &super::metadata::QuarantineEntry) -> u32 {
        let mut extension = 0u32;

        // Extension for restoration history
        if !entry.restoration_history.is_empty() {
            extension += self.extended_rules.restoration_extension_days;
        }

        // Extension for critical severity
        if entry.severity == super::ThreatSeverity::Critical {
            extension += self.extended_rules.critical_severity_extension_days;
        }

        // Extension for known malware families
        if entry.threat_family.is_some() {
            extension += self.extended_rules.known_family_extension_days;
        }

        extension
    }

    /// Get additional entries to delete to meet size limit
    fn get_entries_for_size_limit(
        &self,
        db: &MetadataDb,
        already_deleting: &[String],
        excess_bytes: u64,
    ) -> Result<Vec<String>> {
        let mut additional = Vec::new();
        let mut freed_bytes = 0u64;

        // Get all entries sorted by age (oldest first)
        let all_entries = db.list_entries(None, None, false)?;

        for entry in all_entries {
            // Skip if already marked for deletion
            if already_deleting.contains(&entry.id) {
                continue;
            }

            // Skip if has extended retention that hasn't expired
            if self.should_keep(&entry) {
                continue;
            }

            additional.push(entry.id);
            freed_bytes += entry.file_size;

            if freed_bytes >= excess_bytes {
                break;
            }
        }

        // If we still need more space, start deleting regardless of retention
        if freed_bytes < excess_bytes {
            let all_entries = db.list_entries(None, None, false)?;

            for entry in all_entries {
                if already_deleting.contains(&entry.id) || additional.contains(&entry.id) {
                    continue;
                }

                additional.push(entry.id.clone());
                freed_bytes += entry.file_size;

                if freed_bytes >= excess_bytes {
                    break;
                }
            }
        }

        Ok(additional)
    }
}

/// Retention statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionStats {
    /// Number of entries expiring within 7 days
    pub expiring_7_days: u64,
    /// Number of entries expiring within 30 days
    pub expiring_30_days: u64,
    /// Number of entries with extended retention
    pub with_extended_retention: u64,
    /// Average retention days
    pub average_retention_days: f64,
    /// Oldest entry age in days
    pub oldest_entry_age_days: u64,
    /// Percentage of vault used
    pub vault_usage_percent: f64,
}

impl RetentionPolicy {
    /// Calculate retention statistics
    pub fn calculate_stats(&self, db: &MetadataDb, vault_size: u64) -> Result<RetentionStats> {
        let entries = db.list_entries(None, None, false)?;
        let now = Utc::now();

        let mut expiring_7 = 0u64;
        let mut expiring_30 = 0u64;
        let mut with_extension = 0u64;
        let mut total_retention_days = 0i64;
        let mut oldest_age = 0i64;

        for entry in &entries {
            let days_remaining = self.days_until_expiry(entry);
            let age = (now - entry.quarantined_at).num_days();

            if days_remaining <= 7 {
                expiring_7 += 1;
            }
            if days_remaining <= 30 {
                expiring_30 += 1;
            }

            let extension = self.calculate_extension_days(entry);
            if extension > 0 {
                with_extension += 1;
            }

            total_retention_days += self.config.retention_days as i64 + extension as i64;
            if age > oldest_age {
                oldest_age = age;
            }
        }

        let average_retention = if entries.is_empty() {
            self.config.retention_days as f64
        } else {
            total_retention_days as f64 / entries.len() as f64
        };

        let usage_percent = if self.config.max_size_bytes > 0 {
            (vault_size as f64 / self.config.max_size_bytes as f64) * 100.0
        } else {
            0.0
        };

        Ok(RetentionStats {
            expiring_7_days: expiring_7,
            expiring_30_days: expiring_30,
            with_extended_retention: with_extension,
            average_retention_days: average_retention,
            oldest_entry_age_days: oldest_age as u64,
            vault_usage_percent: usage_percent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine::metadata::{QuarantineEntry, QuarantineReason, RestorationRecord};
    use crate::quarantine::ThreatSeverity;

    fn create_test_entry(id: &str, days_ago: i64, severity: ThreatSeverity) -> QuarantineEntry {
        QuarantineEntry {
            id: id.to_string(),
            original_path: "/test/file.exe".to_string(),
            original_name: "file.exe".to_string(),
            file_size: 1000,
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            quarantined_at: Utc::now() - Duration::days(days_ago),
            reason: QuarantineReason::MlDetection,
            detection_source: "ml".to_string(),
            threat_name: Some("Test.Malware".to_string()),
            threat_family: None,
            severity,
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            triggered_by: None,
            vault_path: format!("/vault/{}.enc", id),
            encryption_iv: "abcdef".to_string(),
            encryption_tag: "123456".to_string(),
            is_compressed: true,
            restoration_history: Vec::new(),
            is_deleted: false,
        }
    }

    #[test]
    fn test_basic_retention() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        // Entry from 20 days ago should be kept
        let entry = create_test_entry("test1", 20, ThreatSeverity::Medium);
        assert!(policy.should_keep(&entry));

        // Entry from 40 days ago should be deleted
        let entry = create_test_entry("test2", 40, ThreatSeverity::Medium);
        assert!(!policy.should_keep(&entry));
    }

    #[test]
    fn test_critical_severity_extension() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        // Critical entry from 40 days ago should still be kept (30 + 60 = 90 days)
        let entry = create_test_entry("test1", 40, ThreatSeverity::Critical);
        assert!(policy.should_keep(&entry));

        // Critical entry from 100 days ago should be deleted
        let entry = create_test_entry("test2", 100, ThreatSeverity::Critical);
        assert!(!policy.should_keep(&entry));
    }

    #[test]
    fn test_restoration_extension() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        // Entry with restoration history from 40 days ago should be kept (30 + 30 = 60 days)
        let mut entry = create_test_entry("test1", 40, ThreatSeverity::Medium);
        entry.restoration_history.push(RestorationRecord {
            restored_at: Utc::now() - Duration::days(10),
            restored_path: "/restored/file.exe".to_string(),
            restored_by: Some("admin".to_string()),
        });
        assert!(policy.should_keep(&entry));
    }

    #[test]
    fn test_days_until_expiry() {
        let config = RetentionConfig {
            retention_days: 30,
            max_size_bytes: 1024 * 1024 * 1024,
        };
        let policy = RetentionPolicy::new(config);

        let entry = create_test_entry("test1", 10, ThreatSeverity::Medium);
        let days = policy.days_until_expiry(&entry);

        // Should have about 20 days left (30 - 10)
        assert!(days >= 19 && days <= 21);
    }
}
