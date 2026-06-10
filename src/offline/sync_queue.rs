//! SQLite-backed sync queue for offline detections.
//!
//! Persists detections to disk so they survive agent restarts.
//! Uses bounded capacity with FIFO eviction.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// A detection queued for sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedDetection {
    /// Unique ID for deduplication
    pub id: String,
    /// When the detection occurred
    pub timestamp: DateTime<Utc>,
    /// Agent ID that produced this detection
    pub agent_id: String,
    /// File path or resource identifier
    pub resource: String,
    /// Detection rule name
    pub rule_name: String,
    /// Detection type (YARA, Sigma, ML, etc.)
    pub detection_type: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Full detection payload as JSON
    pub payload: String,
    /// Whether this was produced while offline
    pub offline: bool,
}

impl QueuedDetection {
    /// Create a new queued detection with auto-generated ID.
    pub fn new(
        agent_id: &str,
        resource: &str,
        rule_name: &str,
        detection_type: &str,
        confidence: f32,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            resource: resource.to_string(),
            rule_name: rule_name.to_string(),
            detection_type: detection_type.to_string(),
            confidence,
            payload: serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()),
            offline: true,
        }
    }
}

/// SQLite-backed sync queue.
pub struct SyncQueue {
    conn: Mutex<Connection>,
    max_size: usize,
}

impl SyncQueue {
    /// Create or open the sync queue database.
    pub fn new(db_path: &str, max_size: usize) -> Result<Self> {
        // Handle in-memory database for testing
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory().context("Failed to open in-memory sync queue database")?
        } else {
            let path = Path::new(db_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).context("Failed to create database directory")?;
            }

            Connection::open(db_path).context("Failed to open sync queue database")?
        };

        // Enable WAL mode for better concurrent access
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .ok(); // Ignore errors for in-memory databases

        // Create schema
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS queued_detections (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                payload TEXT NOT NULL,
                offline INTEGER NOT NULL DEFAULT 1,
                integrity_digest TEXT,
                queued_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_queued_timestamp ON queued_detections(timestamp);
            CREATE INDEX IF NOT EXISTS idx_queued_at ON queued_detections(queued_at);
            CREATE TABLE IF NOT EXISTS sync_integrity_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                detected_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )
        .context("Failed to create schema")?;

        ensure_integrity_column(&conn)?;

        info!(path = %db_path, max_size = max_size, "Sync queue database initialized");

        Ok(Self {
            conn: Mutex::new(conn),
            max_size,
        })
    }

    /// Push a detection onto the queue.
    pub fn push(&self, detection: QueuedDetection) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        // Enforce max size by deleting oldest entries
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queued_detections", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        if count as usize >= self.max_size {
            let to_delete = (count as usize - self.max_size + 1) as i64;
            conn.execute(
                "DELETE FROM queued_detections WHERE id IN (
                    SELECT id FROM queued_detections ORDER BY queued_at ASC LIMIT ?
                )",
                params![to_delete],
            )?;
            debug!(deleted = to_delete, "Evicted oldest detections from queue");
        }

        let integrity_digest = integrity_digest(&detection);

        // Insert new detection
        conn.execute(
            r#"
            INSERT OR REPLACE INTO queued_detections
                (id, timestamp, agent_id, resource, rule_name, detection_type, confidence, payload, offline, integrity_digest)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                detection.id,
                detection.timestamp.to_rfc3339(),
                detection.agent_id,
                detection.resource,
                detection.rule_name,
                detection.detection_type,
                detection.confidence,
                detection.payload,
                detection.offline as i32,
                integrity_digest,
            ],
        )?;

        debug!(id = %detection.id, rule = %detection.rule_name, "Queued detection for sync");
        Ok(())
    }

    /// Get the number of queued detections.
    pub fn len(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM queued_detections", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain all detections from the queue.
    pub fn try_drain_all(&self) -> Result<Vec<QueuedDetection>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let mut stmt = match conn.prepare(
            "SELECT id, timestamp, agent_id, resource, rule_name, detection_type, confidence, payload, offline, integrity_digest
             FROM queued_detections ORDER BY timestamp ASC"
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to prepare drain query");
                bail!("Failed to prepare drain query: {e}");
            }
        };

        let rows: Vec<(QueuedDetection, Option<String>)> = stmt
            .query_map([], |row| {
                let detection = QueuedDetection {
                    id: row.get(0)?,
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    agent_id: row.get(2)?,
                    resource: row.get(3)?,
                    rule_name: row.get(4)?,
                    detection_type: row.get(5)?,
                    confidence: row.get(6)?,
                    payload: row.get(7)?,
                    offline: row.get::<_, i32>(8)? != 0,
                };
                Ok((detection, row.get(9)?))
            })
            .context("Failed to read queued detections")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to decode queued detections")?;

        let mut detections = Vec::with_capacity(rows.len());
        for (detection, digest) in rows {
            verify_integrity_or_record(&conn, &detection, digest.as_deref())?;
            detections.push(detection);
        }

        // Delete all after reading
        if !detections.is_empty() {
            if let Err(e) = conn.execute("DELETE FROM queued_detections", []) {
                error!(error = %e, "Failed to clear queue after drain");
            }
            info!(
                count = detections.len(),
                "Drained detections from sync queue"
            );
        }

        Ok(detections)
    }

    /// Drain all detections from the queue.
    pub fn drain_all(&self) -> Vec<QueuedDetection> {
        match self.try_drain_all() {
            Ok(detections) => detections,
            Err(e) => {
                error!(
                    error = %e,
                    event = "offline_sync_integrity_failure",
                    "Refusing to drain offline sync queue"
                );
                vec![]
            }
        }
    }

    /// Drain up to N detections.
    pub fn try_drain_batch(&self, limit: usize) -> Result<Vec<QueuedDetection>> {
        let detections = self.try_read_batch(limit)?;

        // Delete the drained entries
        if !detections.is_empty() {
            let ids: Vec<&str> = detections.iter().map(|d| d.id.as_str()).collect();
            if let Err(e) = self.try_ack_ids(&ids) {
                error!(error = %e, "Failed to delete drained entries");
            }
            debug!(count = detections.len(), "Drained batch from sync queue");
        }

        Ok(detections)
    }

    /// Drain up to N detections.
    pub fn drain_batch(&self, limit: usize) -> Vec<QueuedDetection> {
        match self.try_drain_batch(limit) {
            Ok(detections) => detections,
            Err(e) => {
                error!(
                    error = %e,
                    event = "offline_sync_integrity_failure",
                    "Refusing to drain offline sync queue batch"
                );
                vec![]
            }
        }
    }

    /// Read up to N detections without removing them.
    ///
    /// Use this for ACK-safe replay: send the returned detections first, then
    /// call `try_ack_ids` only after the server has accepted them.
    pub fn try_read_batch(&self, limit: usize) -> Result<Vec<QueuedDetection>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let mut stmt = match conn.prepare(
            "SELECT id, timestamp, agent_id, resource, rule_name, detection_type, confidence, payload, offline, integrity_digest
             FROM queued_detections ORDER BY timestamp ASC LIMIT ?"
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to prepare batch read query");
                bail!("Failed to prepare batch read query: {e}");
            }
        };

        let rows: Vec<(QueuedDetection, Option<String>)> = stmt
            .query_map(params![limit as i64], |row| {
                let detection = QueuedDetection {
                    id: row.get(0)?,
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    agent_id: row.get(2)?,
                    resource: row.get(3)?,
                    rule_name: row.get(4)?,
                    detection_type: row.get(5)?,
                    confidence: row.get(6)?,
                    payload: row.get(7)?,
                    offline: row.get::<_, i32>(8)? != 0,
                };
                Ok((detection, row.get(9)?))
            })
            .context("Failed to read queued detection batch")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to decode queued detection batch")?;

        let mut detections = Vec::with_capacity(rows.len());
        for (detection, digest) in rows {
            verify_integrity_or_record(&conn, &detection, digest.as_deref())?;
            detections.push(detection);
        }

        Ok(detections)
    }

    /// Acknowledge detections that were accepted by the server.
    pub fn try_ack_ids(&self, ids: &[&str]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM queued_detections WHERE id IN ({})",
            placeholders
        );
        let deleted = conn
            .execute(&sql, rusqlite::params_from_iter(ids.iter().copied()))
            .context("Failed to acknowledge queued detections")?;
        debug!(count = deleted, "Acknowledged queued detections");
        Ok(deleted)
    }

    /// Peek at the next N detections without removing them.
    pub fn try_peek(&self, limit: usize) -> Result<Vec<QueuedDetection>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let mut stmt = match conn.prepare(
            "SELECT id, timestamp, agent_id, resource, rule_name, detection_type, confidence, payload, offline, integrity_digest
             FROM queued_detections ORDER BY timestamp ASC LIMIT ?"
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to prepare peek query");
                bail!("Failed to prepare peek query: {e}");
            }
        };

        let rows: Vec<(QueuedDetection, Option<String>)> = stmt
            .query_map(params![limit as i64], |row| {
                let detection = QueuedDetection {
                    id: row.get(0)?,
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    agent_id: row.get(2)?,
                    resource: row.get(3)?,
                    rule_name: row.get(4)?,
                    detection_type: row.get(5)?,
                    confidence: row.get(6)?,
                    payload: row.get(7)?,
                    offline: row.get::<_, i32>(8)? != 0,
                };
                Ok((detection, row.get(9)?))
            })
            .context("Failed to read queued detections")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to decode queued detections")?;

        let mut detections = Vec::with_capacity(rows.len());
        for (detection, digest) in rows {
            verify_integrity_or_record(&conn, &detection, digest.as_deref())?;
            detections.push(detection);
        }
        Ok(detections)
    }

    /// Peek at the next N detections without removing them.
    pub fn peek(&self, limit: usize) -> Vec<QueuedDetection> {
        match self.try_peek(limit) {
            Ok(detections) => detections,
            Err(e) => {
                error!(
                    error = %e,
                    event = "offline_sync_integrity_failure",
                    "Refusing to read offline sync queue"
                );
                vec![]
            }
        }
    }

    /// Get the oldest detection timestamp in the queue.
    pub fn oldest_timestamp(&self) -> Option<DateTime<Utc>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT timestamp FROM queued_detections ORDER BY timestamp ASC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|ts| DateTime::parse_from_rfc3339(&ts).ok())
        .map(|dt| dt.with_timezone(&Utc))
    }

    /// Get queue statistics.
    pub fn stats(&self) -> QueueStats {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queued_detections", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        let by_type: Vec<(String, i64)> = conn
            .prepare(
                "SELECT detection_type, COUNT(*) FROM queued_detections GROUP BY detection_type",
            )
            .ok()
            .map(|mut stmt| {
                stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .ok()
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        QueueStats {
            total_count: count as usize,
            max_size: self.max_size,
            by_type: by_type.into_iter().collect(),
        }
    }
}

fn ensure_integrity_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(queued_detections)")
        .context("Failed to inspect sync queue schema")?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "integrity_digest") {
        conn.execute(
            "ALTER TABLE queued_detections ADD COLUMN integrity_digest TEXT",
            [],
        )
        .context("Failed to add sync queue integrity column")?;
        warn!(
            "Added offline sync integrity column; pre-existing rows have no digest and cannot be tamper-checked"
        );
    }

    Ok(())
}

fn canonical_detection_bytes(detection: &QueuedDetection) -> Vec<u8> {
    serde_json::json!({
        "id": &detection.id,
        "timestamp": detection.timestamp.to_rfc3339(),
        "agent_id": &detection.agent_id,
        "resource": &detection.resource,
        "rule_name": &detection.rule_name,
        "detection_type": &detection.detection_type,
        "confidence": detection.confidence,
        "payload": &detection.payload,
        "offline": detection.offline,
    })
    .to_string()
    .into_bytes()
}

fn integrity_digest(detection: &QueuedDetection) -> String {
    let message = canonical_detection_bytes(detection);

    if let Ok(key) = std::env::var("TAMANDUA_OFFLINE_SYNC_HMAC_KEY") {
        if !key.is_empty() {
            let mut mac =
                HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any size");
            mac.update(&message);
            return format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(message);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn verify_integrity_or_record(
    conn: &Connection,
    detection: &QueuedDetection,
    stored_digest: Option<&str>,
) -> Result<()> {
    let Some(stored_digest) = stored_digest.filter(|digest| !digest.trim().is_empty()) else {
        warn!(
            detection_id = %detection.id,
            event = "offline_sync_integrity_legacy_row",
            "Queued detection has no integrity digest; accepting legacy row"
        );
        return Ok(());
    };

    let expected = integrity_digest(detection);
    if stored_digest == expected {
        return Ok(());
    }

    let reason = format!(
        "offline sync integrity digest mismatch: expected {expected}, stored {stored_digest}"
    );
    let _ = conn.execute(
        "INSERT INTO sync_integrity_events (detection_id, reason) VALUES (?1, ?2)",
        params![&detection.id, reason],
    );
    error!(
        detection_id = %detection.id,
        expected = %expected,
        stored = %stored_digest,
        event = "offline_sync_integrity_failure",
        "Queued detection failed integrity verification"
    );
    bail!(
        "Offline sync queue integrity check failed for detection {}",
        detection.id
    )
}

/// Queue statistics.
#[derive(Debug, Clone)]
pub struct QueueStats {
    pub total_count: usize,
    pub max_size: usize,
    pub by_type: std::collections::HashMap<String, i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detection(id: &str, rule: &str) -> QueuedDetection {
        QueuedDetection {
            id: id.to_string(),
            timestamp: Utc::now(),
            agent_id: "agent-1".to_string(),
            resource: "/tmp/test.exe".to_string(),
            rule_name: rule.to_string(),
            detection_type: "YARA".to_string(),
            confidence: 0.95,
            payload: "{}".to_string(),
            offline: true,
        }
    }

    #[test]
    fn test_queue_push_and_drain() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();

        assert!(queue.is_empty());

        let detection = make_detection("test-1", "MALWARE_Test");

        queue.push(detection).unwrap();
        assert_eq!(queue.len(), 1);

        let drained = queue.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].id, "test-1");
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_max_size() {
        let queue = SyncQueue::new(":memory:", 3).unwrap();

        for i in 0..5 {
            let detection = make_detection(&format!("test-{}", i), "TEST");
            queue.push(detection).unwrap();
        }

        assert_eq!(queue.len(), 3);

        let drained = queue.drain_all();
        assert_eq!(drained.len(), 3);
        // Should have the last 3 (test-2, test-3, test-4)
        assert_eq!(drained[0].id, "test-2");
        assert_eq!(drained[1].id, "test-3");
        assert_eq!(drained[2].id, "test-4");
    }

    #[test]
    fn test_queue_drain_batch() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();

        for i in 0..10 {
            let detection = make_detection(&format!("test-{}", i), "TEST");
            queue.push(detection).unwrap();
        }

        assert_eq!(queue.len(), 10);

        let batch1 = queue.drain_batch(3);
        assert_eq!(batch1.len(), 3);
        assert_eq!(queue.len(), 7);

        let batch2 = queue.drain_batch(5);
        assert_eq!(batch2.len(), 5);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_queue_read_batch_requires_explicit_ack() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();

        for i in 0..5 {
            let detection = make_detection(&format!("test-{}", i), "TEST");
            queue.push(detection).unwrap();
        }

        let batch = queue.try_read_batch(3).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(queue.len(), 5);

        let ids: Vec<&str> = batch
            .iter()
            .map(|detection| detection.id.as_str())
            .collect();
        let deleted = queue.try_ack_ids(&ids).unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_queue_ack_empty_is_noop() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();

        assert_eq!(queue.try_ack_ids(&[]).unwrap(), 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_peek() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();

        for i in 0..5 {
            let detection = make_detection(&format!("test-{}", i), "TEST");
            queue.push(detection).unwrap();
        }

        let peeked = queue.peek(3);
        assert_eq!(peeked.len(), 3);
        // Peek should not remove items
        assert_eq!(queue.len(), 5);
    }

    #[test]
    fn test_queue_stats() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();

        let yara = QueuedDetection {
            id: "y1".to_string(),
            timestamp: Utc::now(),
            agent_id: "agent-1".to_string(),
            resource: "/test".to_string(),
            rule_name: "YARA_Rule".to_string(),
            detection_type: "YARA".to_string(),
            confidence: 0.9,
            payload: "{}".to_string(),
            offline: true,
        };

        let sigma = QueuedDetection {
            id: "s1".to_string(),
            timestamp: Utc::now(),
            agent_id: "agent-1".to_string(),
            resource: "/test".to_string(),
            rule_name: "Sigma_Rule".to_string(),
            detection_type: "Sigma".to_string(),
            confidence: 0.8,
            payload: "{}".to_string(),
            offline: true,
        };

        queue.push(yara).unwrap();
        queue.push(sigma.clone()).unwrap();
        queue
            .push(QueuedDetection {
                id: "s2".to_string(),
                ..sigma
            })
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.by_type.get("YARA"), Some(&1));
        assert_eq!(stats.by_type.get("Sigma"), Some(&2));
    }

    #[test]
    fn test_queued_detection_new() {
        let detection = QueuedDetection::new(
            "agent-123",
            "/path/to/file.exe",
            "MALWARE_Test",
            "YARA",
            0.95,
            serde_json::json!({"key": "value"}),
        );

        assert!(!detection.id.is_empty());
        assert_eq!(detection.agent_id, "agent-123");
        assert_eq!(detection.resource, "/path/to/file.exe");
        assert_eq!(detection.rule_name, "MALWARE_Test");
        assert!(detection.offline);
    }

    #[test]
    fn test_queue_detects_payload_tamper_before_drain() {
        let queue = SyncQueue::new(":memory:", 100).unwrap();
        queue
            .push(make_detection("tamper-1", "MALWARE_Test"))
            .unwrap();

        {
            let conn = queue.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute(
                "UPDATE queued_detections SET payload = ?1 WHERE id = ?2",
                params![r#"{"tampered":true}"#, "tamper-1"],
            )
            .unwrap();
        }

        let result = queue.try_drain_all();
        assert!(result.is_err());
        assert_eq!(queue.len(), 1);

        let conn = queue.conn.lock().unwrap_or_else(|e| e.into_inner());
        let failures: i64 = conn
            .query_row("SELECT COUNT(*) FROM sync_integrity_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(failures, 1);
    }
}
