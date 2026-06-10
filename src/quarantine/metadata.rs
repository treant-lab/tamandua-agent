//! Metadata Storage for Quarantine Vault
//!
//! Stores quarantine metadata in SQLite database:
//! - Original path, filename, size, hashes (MD5, SHA1, SHA256)
//! - Quarantine timestamp, reason, detection source
//! - Threat name, severity, MITRE ATT&CK tactics/techniques
//! - User who triggered quarantine
//! - Restoration history
//!
//! Database location:
//! - Windows: %ProgramData%\Tamandua\Quarantine\quarantine.db
//! - Linux/macOS: /var/lib/tamandua/quarantine/quarantine.db

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

use super::ThreatSeverity;

/// Reason for quarantine
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Detected by ML model
    MlDetection,
    /// Detected by YARA rules
    YaraMatch,
    /// Detected by Sigma rules
    SigmaMatch,
    /// Detected by IOC match
    IocMatch,
    /// Manual quarantine by user
    ManualAction,
    /// Detected by behavioral analysis
    BehavioralDetection,
    /// Detected by ransomware protection
    RansomwareProtection,
    /// Detected during real-time scanning
    RealtimeScan,
    /// Detected during scheduled scan
    ScheduledScan,
    /// Detected during on-demand scan
    OnDemandScan,
    /// Unknown/other reason
    Other(String),
}

impl QuarantineReason {
    fn to_db_string(&self) -> String {
        match self {
            QuarantineReason::MlDetection => "ml_detection".to_string(),
            QuarantineReason::YaraMatch => "yara_match".to_string(),
            QuarantineReason::SigmaMatch => "sigma_match".to_string(),
            QuarantineReason::IocMatch => "ioc_match".to_string(),
            QuarantineReason::ManualAction => "manual_action".to_string(),
            QuarantineReason::BehavioralDetection => "behavioral_detection".to_string(),
            QuarantineReason::RansomwareProtection => "ransomware_protection".to_string(),
            QuarantineReason::RealtimeScan => "realtime_scan".to_string(),
            QuarantineReason::ScheduledScan => "scheduled_scan".to_string(),
            QuarantineReason::OnDemandScan => "on_demand_scan".to_string(),
            QuarantineReason::Other(s) => format!("other:{}", s),
        }
    }

    fn from_db_string(s: &str) -> Self {
        match s {
            "ml_detection" => QuarantineReason::MlDetection,
            "yara_match" => QuarantineReason::YaraMatch,
            "sigma_match" => QuarantineReason::SigmaMatch,
            "ioc_match" => QuarantineReason::IocMatch,
            "manual_action" => QuarantineReason::ManualAction,
            "behavioral_detection" => QuarantineReason::BehavioralDetection,
            "ransomware_protection" => QuarantineReason::RansomwareProtection,
            "realtime_scan" => QuarantineReason::RealtimeScan,
            "scheduled_scan" => QuarantineReason::ScheduledScan,
            "on_demand_scan" => QuarantineReason::OnDemandScan,
            other => {
                if let Some(suffix) = other.strip_prefix("other:") {
                    QuarantineReason::Other(suffix.to_string())
                } else {
                    QuarantineReason::Other(other.to_string())
                }
            }
        }
    }
}

/// Threat information for quarantined file
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatInfo {
    /// Source of detection (e.g., "yara", "ml", "behavioral")
    pub detection_source: String,
    /// Threat name/classification
    pub threat_name: Option<String>,
    /// Malware family (e.g., "Emotet", "Ryuk")
    pub threat_family: Option<String>,
    /// Threat severity
    pub severity: ThreatSeverity,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: Option<f32>,
}

/// Record of a file restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorationRecord {
    /// Timestamp of restoration
    pub restored_at: DateTime<Utc>,
    /// Path where file was restored
    pub restored_path: String,
    /// User who performed restoration
    pub restored_by: Option<String>,
}

/// Full quarantine entry with all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique quarantine ID (UUID)
    pub id: String,
    /// Original file path
    pub original_path: String,
    /// Original file name
    pub original_name: String,
    /// File size in bytes
    pub file_size: u64,
    /// MD5 hash
    pub md5: String,
    /// SHA1 hash
    pub sha1: String,
    /// SHA256 hash
    pub sha256: String,
    /// When file was quarantined
    pub quarantined_at: DateTime<Utc>,
    /// Reason for quarantine
    pub reason: QuarantineReason,
    /// Detection source
    pub detection_source: String,
    /// Threat name
    pub threat_name: Option<String>,
    /// Threat family
    pub threat_family: Option<String>,
    /// Severity level
    pub severity: ThreatSeverity,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// User who triggered quarantine
    pub triggered_by: Option<String>,
    /// Path to encrypted file in vault
    pub vault_path: String,
    /// Encryption IV (hex encoded)
    pub encryption_iv: String,
    /// Encryption authentication tag (hex encoded)
    pub encryption_tag: String,
    /// Whether file was compressed before encryption
    pub is_compressed: bool,
    /// History of restorations
    pub restoration_history: Vec<RestorationRecord>,
    /// Whether file has been permanently deleted
    pub is_deleted: bool,
}

/// Metadata database manager
///
/// Uses `parking_lot::Mutex` to wrap the SQLite connection, making it thread-safe
/// for use across async tasks. The `rusqlite::Connection` internally uses `RefCell`
/// which is not `Sync`, so we need this wrapper for multi-threaded contexts.
pub struct MetadataDb {
    conn: Mutex<Connection>,
}

impl MetadataDb {
    /// Create or open the metadata database
    pub fn new(db_path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

        // Configure database
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA cache_size = -4000;",
        )?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;

        info!(path = %db_path.display(), "Quarantine metadata database initialized");
        Ok(db)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantine_entries (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                original_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                md5 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                quarantined_at INTEGER NOT NULL,
                reason TEXT NOT NULL,
                detection_source TEXT NOT NULL DEFAULT '',
                threat_name TEXT,
                threat_family TEXT,
                severity TEXT NOT NULL DEFAULT 'medium',
                mitre_tactics TEXT NOT NULL DEFAULT '[]',
                mitre_techniques TEXT NOT NULL DEFAULT '[]',
                triggered_by TEXT,
                vault_path TEXT NOT NULL,
                encryption_iv TEXT NOT NULL,
                encryption_tag TEXT NOT NULL,
                is_compressed INTEGER NOT NULL DEFAULT 0,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS restoration_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_id TEXT NOT NULL REFERENCES quarantine_entries(id) ON DELETE CASCADE,
                restored_at INTEGER NOT NULL,
                restored_path TEXT NOT NULL,
                restored_by TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_quarantine_sha256 ON quarantine_entries(sha256);
            CREATE INDEX IF NOT EXISTS idx_quarantine_quarantined_at ON quarantine_entries(quarantined_at);
            CREATE INDEX IF NOT EXISTS idx_quarantine_severity ON quarantine_entries(severity);
            CREATE INDEX IF NOT EXISTS idx_quarantine_threat_family ON quarantine_entries(threat_family);
            CREATE INDEX IF NOT EXISTS idx_quarantine_is_deleted ON quarantine_entries(is_deleted);
            CREATE INDEX IF NOT EXISTS idx_restoration_quarantine_id ON restoration_history(quarantine_id);"
        ).context("Failed to initialize database schema")?;

        Ok(())
    }

    /// Insert a new quarantine entry
    pub fn insert_entry(&self, entry: &QuarantineEntry) -> Result<()> {
        let timestamp = entry.quarantined_at.timestamp();
        let reason = entry.reason.to_db_string();
        let severity = format!("{:?}", entry.severity).to_lowercase();
        let tactics_json = serde_json::to_string(&entry.mitre_tactics)?;
        let techniques_json = serde_json::to_string(&entry.mitre_techniques)?;

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO quarantine_entries (
                id, original_path, original_name, file_size, md5, sha1, sha256,
                quarantined_at, reason, detection_source, threat_name, threat_family,
                severity, mitre_tactics, mitre_techniques, triggered_by,
                vault_path, encryption_iv, encryption_tag, is_compressed, is_deleted
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
            )",
            params![
                entry.id,
                entry.original_path,
                entry.original_name,
                entry.file_size as i64,
                entry.md5,
                entry.sha1,
                entry.sha256,
                timestamp,
                reason,
                entry.detection_source,
                entry.threat_name,
                entry.threat_family,
                severity,
                tactics_json,
                techniques_json,
                entry.triggered_by,
                entry.vault_path,
                entry.encryption_iv,
                entry.encryption_tag,
                entry.is_compressed as i32,
                entry.is_deleted as i32,
            ],
        ).context("Failed to insert quarantine entry")?;

        debug!(id = %entry.id, "Inserted quarantine entry");
        Ok(())
    }

    /// Get a quarantine entry by ID
    pub fn get_entry(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, original_path, original_name, file_size, md5, sha1, sha256,
                    quarantined_at, reason, detection_source, threat_name, threat_family,
                    severity, mitre_tactics, mitre_techniques, triggered_by,
                    vault_path, encryption_iv, encryption_tag, is_compressed, is_deleted
             FROM quarantine_entries WHERE id = ?1",
        )?;

        let entry = stmt
            .query_row(params![id], |row| Ok(Self::row_to_entry(row)?))
            .optional()
            .context("Failed to query quarantine entry")?;
        drop(stmt);
        drop(conn);

        if let Some(mut entry) = entry {
            // Load restoration history
            entry.restoration_history = self.get_restoration_history(&entry.id)?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Get a quarantine entry by SHA256 hash
    pub fn get_entry_by_hash(&self, sha256: &str) -> Result<Option<QuarantineEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, original_path, original_name, file_size, md5, sha1, sha256,
                    quarantined_at, reason, detection_source, threat_name, threat_family,
                    severity, mitre_tactics, mitre_techniques, triggered_by,
                    vault_path, encryption_iv, encryption_tag, is_compressed, is_deleted
             FROM quarantine_entries WHERE sha256 = ?1 AND is_deleted = 0",
        )?;

        let entry = stmt
            .query_row(params![sha256], |row| Ok(Self::row_to_entry(row)?))
            .optional()
            .context("Failed to query quarantine entry by hash")?;
        drop(stmt);
        drop(conn);

        if let Some(mut entry) = entry {
            entry.restoration_history = self.get_restoration_history(&entry.id)?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// List quarantine entries with pagination
    pub fn list_entries(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
        include_deleted: bool,
    ) -> Result<Vec<QuarantineEntry>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let sql = if include_deleted {
            "SELECT id, original_path, original_name, file_size, md5, sha1, sha256,
                    quarantined_at, reason, detection_source, threat_name, threat_family,
                    severity, mitre_tactics, mitre_techniques, triggered_by,
                    vault_path, encryption_iv, encryption_tag, is_compressed, is_deleted
             FROM quarantine_entries
             ORDER BY quarantined_at DESC
             LIMIT ?1 OFFSET ?2"
        } else {
            "SELECT id, original_path, original_name, file_size, md5, sha1, sha256,
                    quarantined_at, reason, detection_source, threat_name, threat_family,
                    severity, mitre_tactics, mitre_techniques, triggered_by,
                    vault_path, encryption_iv, encryption_tag, is_compressed, is_deleted
             FROM quarantine_entries
             WHERE is_deleted = 0
             ORDER BY quarantined_at DESC
             LIMIT ?1 OFFSET ?2"
        };

        let conn = self.conn.lock();
        let mut stmt = conn.prepare(sql)?;
        let entries = stmt
            .query_map(params![limit, offset], |row| Ok(Self::row_to_entry(row)?))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Get entries older than a certain timestamp
    pub fn get_entries_older_than(&self, timestamp: DateTime<Utc>) -> Result<Vec<String>> {
        let ts = timestamp.timestamp();
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM quarantine_entries WHERE quarantined_at < ?1 AND is_deleted = 0",
        )?;

        let ids: Vec<String> = stmt
            .query_map(params![ts], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(ids)
    }

    /// Get total count of entries
    pub fn get_entry_count(&self, include_deleted: bool) -> Result<u64> {
        let sql = if include_deleted {
            "SELECT COUNT(*) FROM quarantine_entries"
        } else {
            "SELECT COUNT(*) FROM quarantine_entries WHERE is_deleted = 0"
        };

        let conn = self.conn.lock();
        let count: i64 = conn.query_row(sql, [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Get total size of quarantined files
    pub fn get_total_file_size(&self) -> Result<u64> {
        let conn = self.conn.lock();
        let size: i64 = conn.query_row(
            "SELECT COALESCE(SUM(file_size), 0) FROM quarantine_entries WHERE is_deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(size as u64)
    }

    /// Get oldest entry timestamp
    pub fn get_oldest_entry_time(&self) -> Result<Option<DateTime<Utc>>> {
        let conn = self.conn.lock();
        let timestamp: Option<i64> = conn.query_row(
            "SELECT MIN(quarantined_at) FROM quarantine_entries WHERE is_deleted = 0",
            [],
            |row| row.get(0),
        )?;

        Ok(timestamp.map(|ts| Utc.timestamp_opt(ts, 0).unwrap()))
    }

    /// Get newest entry timestamp
    pub fn get_newest_entry_time(&self) -> Result<Option<DateTime<Utc>>> {
        let conn = self.conn.lock();
        let timestamp: Option<i64> = conn.query_row(
            "SELECT MAX(quarantined_at) FROM quarantine_entries WHERE is_deleted = 0",
            [],
            |row| row.get(0),
        )?;

        Ok(timestamp.map(|ts| Utc.timestamp_opt(ts, 0).unwrap()))
    }

    /// Get threat family statistics
    pub fn get_threat_family_stats(&self) -> Result<Vec<(String, u64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(threat_family, 'Unknown'), COUNT(*) as count
             FROM quarantine_entries
             WHERE is_deleted = 0
             GROUP BY threat_family
             ORDER BY count DESC",
        )?;

        let stats: Vec<(String, u64)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(stats)
    }

    /// Get restoration count
    pub fn get_restoration_count(&self) -> Result<u64> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM restoration_history", [], |row| {
            row.get(0)
        })?;
        Ok(count as u64)
    }

    /// Record a file restoration
    pub fn record_restoration(&self, quarantine_id: &str, restored_path: &str) -> Result<()> {
        let now = Utc::now().timestamp();

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO restoration_history (quarantine_id, restored_at, restored_path)
             VALUES (?1, ?2, ?3)",
            params![quarantine_id, now, restored_path],
        )?;

        // Update the entry's updated_at timestamp
        conn.execute(
            "UPDATE quarantine_entries SET updated_at = ?1 WHERE id = ?2",
            params![now, quarantine_id],
        )?;

        debug!(id = %quarantine_id, "Recorded restoration");
        Ok(())
    }

    /// Mark entry as deleted
    pub fn mark_deleted(&self, id: &str) -> Result<()> {
        let now = Utc::now().timestamp();

        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE quarantine_entries SET is_deleted = 1, updated_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;

        if rows == 0 {
            return Err(anyhow!("Entry not found: {}", id));
        }

        debug!(id = %id, "Marked entry as deleted");
        Ok(())
    }

    /// Get restoration history for an entry
    fn get_restoration_history(&self, quarantine_id: &str) -> Result<Vec<RestorationRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT restored_at, restored_path, restored_by
             FROM restoration_history
             WHERE quarantine_id = ?1
             ORDER BY restored_at DESC",
        )?;

        let records: Vec<RestorationRecord> = stmt
            .query_map(params![quarantine_id], |row| {
                let timestamp: i64 = row.get(0)?;
                Ok(RestorationRecord {
                    restored_at: Utc.timestamp_opt(timestamp, 0).unwrap(),
                    restored_path: row.get(1)?,
                    restored_by: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(records)
    }

    /// Convert a database row to a QuarantineEntry
    fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<QuarantineEntry> {
        let timestamp: i64 = row.get(7)?;
        let reason_str: String = row.get(8)?;
        let severity_str: String = row.get(12)?;
        let tactics_json: String = row.get(13)?;
        let techniques_json: String = row.get(14)?;

        let severity = match severity_str.as_str() {
            "low" => ThreatSeverity::Low,
            "high" => ThreatSeverity::High,
            "critical" => ThreatSeverity::Critical,
            _ => ThreatSeverity::Medium,
        };

        let mitre_tactics: Vec<String> = serde_json::from_str(&tactics_json).unwrap_or_default();
        let mitre_techniques: Vec<String> =
            serde_json::from_str(&techniques_json).unwrap_or_default();

        Ok(QuarantineEntry {
            id: row.get(0)?,
            original_path: row.get(1)?,
            original_name: row.get(2)?,
            file_size: row.get::<_, i64>(3)? as u64,
            md5: row.get(4)?,
            sha1: row.get(5)?,
            sha256: row.get(6)?,
            quarantined_at: Utc.timestamp_opt(timestamp, 0).unwrap(),
            reason: QuarantineReason::from_db_string(&reason_str),
            detection_source: row.get(9)?,
            threat_name: row.get(10)?,
            threat_family: row.get(11)?,
            severity,
            mitre_tactics,
            mitre_techniques,
            triggered_by: row.get(15)?,
            vault_path: row.get(16)?,
            encryption_iv: row.get(17)?,
            encryption_tag: row.get(18)?,
            is_compressed: row.get::<_, i32>(19)? != 0,
            is_deleted: row.get::<_, i32>(20)? != 0,
            restoration_history: Vec::new(), // Loaded separately
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_entry() -> QuarantineEntry {
        QuarantineEntry {
            id: "test-id-123".to_string(),
            original_path: "/home/user/malware.exe".to_string(),
            original_name: "malware.exe".to_string(),
            file_size: 12345,
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            quarantined_at: Utc::now(),
            reason: QuarantineReason::MlDetection,
            detection_source: "ml".to_string(),
            threat_name: Some("Trojan.Generic".to_string()),
            threat_family: Some("GenericTrojan".to_string()),
            severity: ThreatSeverity::High,
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
            triggered_by: Some("system".to_string()),
            vault_path: "/vault/2024/01/test-id-123.enc".to_string(),
            encryption_iv: "0123456789ab".to_string(),
            encryption_tag: "0123456789abcdef".to_string(),
            is_compressed: true,
            restoration_history: Vec::new(),
            is_deleted: false,
        }
    }

    #[test]
    fn test_create_database() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let db = MetadataDb::new(&db_path).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_insert_and_get_entry() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        let entry = create_test_entry();
        db.insert_entry(&entry).unwrap();

        let retrieved = db.get_entry(&entry.id).unwrap().unwrap();
        assert_eq!(retrieved.id, entry.id);
        assert_eq!(retrieved.sha256, entry.sha256);
        assert_eq!(retrieved.threat_name, entry.threat_name);
    }

    #[test]
    fn test_list_entries() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        // Insert multiple entries
        for i in 0..5 {
            let mut entry = create_test_entry();
            entry.id = format!("test-id-{}", i);
            db.insert_entry(&entry).unwrap();
        }

        let entries = db.list_entries(Some(3), Some(0), false).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_mark_deleted() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        let entry = create_test_entry();
        db.insert_entry(&entry).unwrap();

        db.mark_deleted(&entry.id).unwrap();

        let entries = db.list_entries(None, None, false).unwrap();
        assert_eq!(entries.len(), 0);

        let entries_with_deleted = db.list_entries(None, None, true).unwrap();
        assert_eq!(entries_with_deleted.len(), 1);
    }

    #[test]
    fn test_record_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = MetadataDb::new(&db_path).unwrap();

        let entry = create_test_entry();
        db.insert_entry(&entry).unwrap();

        db.record_restoration(&entry.id, "/home/user/restored.exe")
            .unwrap();

        let retrieved = db.get_entry(&entry.id).unwrap().unwrap();
        assert_eq!(retrieved.restoration_history.len(), 1);
        assert_eq!(
            retrieved.restoration_history[0].restored_path,
            "/home/user/restored.exe"
        );
    }
}
