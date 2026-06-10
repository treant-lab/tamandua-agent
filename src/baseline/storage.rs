//! Baseline storage using SQLite
//!
//! Stores baselines in a local SQLite database with efficient querying
//! and compression support for sync operations.

use super::config::BaselineConfig;
use super::types::*;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

const SCHEMA_VERSION: i32 = 1;

/// Baseline storage manager
#[derive(Clone)]
pub struct BaselineStorage {
    conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
}

impl BaselineStorage {
    /// Create a new baseline storage
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(&db_path).context("Failed to open baseline database")?;

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch("PRAGMA cache_size=-64000;")?; // 64MB cache

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path,
        };

        storage.initialize_schema()?;
        Ok(storage)
    }

    /// Initialize database schema
    fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        // Metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        // Check schema version
        let version: Option<i32> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;

        if version.is_none() {
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION],
            )?;
        }

        // Process baselines table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS process_baselines (
                process_name TEXT PRIMARY KEY,
                avg_memory_mb REAL NOT NULL,
                stddev_memory_mb REAL NOT NULL,
                avg_cpu_percent REAL NOT NULL,
                stddev_cpu_percent REAL NOT NULL,
                network_destinations TEXT NOT NULL,
                file_access TEXT NOT NULL,
                learning_samples INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_process_last_updated
             ON process_baselines(last_updated)",
            [],
        )?;

        // User baselines table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_baselines (
                username TEXT PRIMARY KEY,
                login_hours TEXT NOT NULL,
                workstations TEXT NOT NULL,
                applications TEXT NOT NULL,
                learning_samples INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        // Network baselines table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS network_baselines (
                key TEXT PRIMARY KEY,
                destinations TEXT NOT NULL,
                ports TEXT NOT NULL,
                protocols TEXT NOT NULL,
                learning_samples INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        // File access baselines table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS file_access_baselines (
                process_name TEXT PRIMARY KEY,
                common_paths TEXT NOT NULL,
                common_extensions TEXT NOT NULL,
                learning_samples INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        // Registry baselines table (Windows only)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS registry_baselines (
                process_name TEXT PRIMARY KEY,
                common_keys TEXT NOT NULL,
                learning_samples INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        // Anomaly suppression table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS anomaly_suppression (
                suppression_key TEXT PRIMARY KEY,
                last_seen INTEGER NOT NULL,
                count INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_anomaly_last_seen
             ON anomaly_suppression(last_seen)",
            [],
        )?;

        info!("Baseline database schema initialized");
        Ok(())
    }

    // ========================================================================
    // Process Baselines
    // ========================================================================

    /// Store or update a process baseline
    pub async fn store_process_baseline(&self, baseline: &ProcessBaseline) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let network_json = serde_json::to_string(&baseline.common_network_destinations)?;
        let file_json = serde_json::to_string(&baseline.common_file_access)?;

        conn.execute(
            "INSERT OR REPLACE INTO process_baselines
             (process_name, avg_memory_mb, stddev_memory_mb, avg_cpu_percent,
              stddev_cpu_percent, network_destinations, file_access, learning_samples,
              first_seen, last_updated, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                baseline.process_name,
                baseline.avg_memory_mb,
                baseline.stddev_memory_mb,
                baseline.avg_cpu_percent,
                baseline.stddev_cpu_percent,
                network_json,
                file_json,
                baseline.learning_samples,
                baseline.first_seen,
                baseline.last_updated,
                baseline.version,
            ],
        )?;

        debug!("Stored process baseline: {}", baseline.process_name);
        Ok(())
    }

    /// Get a process baseline by name
    pub async fn get_process_baseline(
        &self,
        process_name: &str,
    ) -> Result<Option<ProcessBaseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let result = conn
            .query_row(
                "SELECT process_name, avg_memory_mb, stddev_memory_mb, avg_cpu_percent,
                    stddev_cpu_percent, network_destinations, file_access, learning_samples,
                    first_seen, last_updated, version
             FROM process_baselines WHERE process_name = ?1",
                params![process_name],
                |row| {
                    let network_json: String = row.get(5)?;
                    let file_json: String = row.get(6)?;

                    Ok(ProcessBaseline {
                        process_name: row.get(0)?,
                        avg_memory_mb: row.get(1)?,
                        stddev_memory_mb: row.get(2)?,
                        avg_cpu_percent: row.get(3)?,
                        stddev_cpu_percent: row.get(4)?,
                        common_network_destinations: serde_json::from_str(&network_json)
                            .unwrap_or_default(),
                        common_file_access: serde_json::from_str(&file_json).unwrap_or_default(),
                        learning_samples: row.get(7)?,
                        first_seen: row.get(8)?,
                        last_updated: row.get(9)?,
                        version: row.get(10)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    /// Get all process baselines
    pub async fn get_all_process_baselines(&self) -> Result<Vec<ProcessBaseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let mut stmt = conn.prepare(
            "SELECT process_name, avg_memory_mb, stddev_memory_mb, avg_cpu_percent,
                    stddev_cpu_percent, network_destinations, file_access, learning_samples,
                    first_seen, last_updated, version
             FROM process_baselines
             ORDER BY last_updated DESC",
        )?;

        let baselines = stmt
            .query_map([], |row| {
                let network_json: String = row.get(5)?;
                let file_json: String = row.get(6)?;

                Ok(ProcessBaseline {
                    process_name: row.get(0)?,
                    avg_memory_mb: row.get(1)?,
                    stddev_memory_mb: row.get(2)?,
                    avg_cpu_percent: row.get(3)?,
                    stddev_cpu_percent: row.get(4)?,
                    common_network_destinations: serde_json::from_str(&network_json)
                        .unwrap_or_default(),
                    common_file_access: serde_json::from_str(&file_json).unwrap_or_default(),
                    learning_samples: row.get(7)?,
                    first_seen: row.get(8)?,
                    last_updated: row.get(9)?,
                    version: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(baselines)
    }

    // ========================================================================
    // User Baselines
    // ========================================================================

    /// Store or update a user baseline
    pub async fn store_user_baseline(&self, baseline: &UserBaseline) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let login_hours_json = serde_json::to_string(&baseline.login_hours)?;
        let workstations_json = serde_json::to_string(&baseline.common_workstations)?;
        let applications_json = serde_json::to_string(&baseline.common_applications)?;

        conn.execute(
            "INSERT OR REPLACE INTO user_baselines
             (username, login_hours, workstations, applications, learning_samples,
              first_seen, last_updated, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                baseline.username,
                login_hours_json,
                workstations_json,
                applications_json,
                baseline.learning_samples,
                baseline.first_seen,
                baseline.last_updated,
                baseline.version,
            ],
        )?;

        debug!("Stored user baseline: {}", baseline.username);
        Ok(())
    }

    /// Get a user baseline by username
    pub async fn get_user_baseline(&self, username: &str) -> Result<Option<UserBaseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let result = conn
            .query_row(
                "SELECT username, login_hours, workstations, applications, learning_samples,
                    first_seen, last_updated, version
             FROM user_baselines WHERE username = ?1",
                params![username],
                |row| {
                    let login_hours_json: String = row.get(1)?;
                    let workstations_json: String = row.get(2)?;
                    let applications_json: String = row.get(3)?;

                    Ok(UserBaseline {
                        username: row.get(0)?,
                        login_hours: serde_json::from_str(&login_hours_json)
                            .unwrap_or_else(|_| vec![0; 24]),
                        common_workstations: serde_json::from_str(&workstations_json)
                            .unwrap_or_default(),
                        common_applications: serde_json::from_str(&applications_json)
                            .unwrap_or_default(),
                        learning_samples: row.get(4)?,
                        first_seen: row.get(5)?,
                        last_updated: row.get(6)?,
                        version: row.get(7)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    // ========================================================================
    // Network Baselines
    // ========================================================================

    /// Store or update a network baseline
    pub async fn store_network_baseline(&self, baseline: &NetworkBaseline) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let destinations_json = serde_json::to_string(&baseline.common_destinations)?;
        let ports_json = serde_json::to_string(&baseline.common_ports)?;
        let protocols_json = serde_json::to_string(&baseline.common_protocols)?;

        conn.execute(
            "INSERT OR REPLACE INTO network_baselines
             (key, destinations, ports, protocols, learning_samples,
              first_seen, last_updated, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                baseline.key,
                destinations_json,
                ports_json,
                protocols_json,
                baseline.learning_samples,
                baseline.first_seen,
                baseline.last_updated,
                baseline.version,
            ],
        )?;

        debug!("Stored network baseline: {}", baseline.key);
        Ok(())
    }

    /// Get a network baseline by key
    pub async fn get_network_baseline(&self, key: &str) -> Result<Option<NetworkBaseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let result = conn
            .query_row(
                "SELECT key, destinations, ports, protocols, learning_samples,
                    first_seen, last_updated, version
             FROM network_baselines WHERE key = ?1",
                params![key],
                |row| {
                    let destinations_json: String = row.get(1)?;
                    let ports_json: String = row.get(2)?;
                    let protocols_json: String = row.get(3)?;

                    Ok(NetworkBaseline {
                        key: row.get(0)?,
                        common_destinations: serde_json::from_str(&destinations_json)
                            .unwrap_or_default(),
                        common_ports: serde_json::from_str(&ports_json).unwrap_or_default(),
                        common_protocols: serde_json::from_str(&protocols_json).unwrap_or_default(),
                        learning_samples: row.get(4)?,
                        first_seen: row.get(5)?,
                        last_updated: row.get(6)?,
                        version: row.get(7)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    // ========================================================================
    // File Access Baselines
    // ========================================================================

    /// Store or update a file access baseline
    pub async fn store_file_access_baseline(&self, baseline: &FileAccessBaseline) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let paths_json = serde_json::to_string(&baseline.common_paths)?;
        let extensions_json = serde_json::to_string(&baseline.common_extensions)?;

        conn.execute(
            "INSERT OR REPLACE INTO file_access_baselines
             (process_name, common_paths, common_extensions, learning_samples,
              first_seen, last_updated, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                baseline.process_name,
                paths_json,
                extensions_json,
                baseline.learning_samples,
                baseline.first_seen,
                baseline.last_updated,
                baseline.version,
            ],
        )?;

        debug!("Stored file access baseline: {}", baseline.process_name);
        Ok(())
    }

    /// Get a file access baseline by process name
    pub async fn get_file_access_baseline(
        &self,
        process_name: &str,
    ) -> Result<Option<FileAccessBaseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let result = conn
            .query_row(
                "SELECT process_name, common_paths, common_extensions, learning_samples,
                    first_seen, last_updated, version
             FROM file_access_baselines WHERE process_name = ?1",
                params![process_name],
                |row| {
                    let paths_json: String = row.get(1)?;
                    let extensions_json: String = row.get(2)?;

                    Ok(FileAccessBaseline {
                        process_name: row.get(0)?,
                        common_paths: serde_json::from_str(&paths_json).unwrap_or_default(),
                        common_extensions: serde_json::from_str(&extensions_json)
                            .unwrap_or_default(),
                        learning_samples: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_updated: row.get(5)?,
                        version: row.get(6)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    // ========================================================================
    // Registry Baselines (Windows only)
    // ========================================================================

    /// Store or update a registry baseline
    #[cfg(target_os = "windows")]
    pub async fn store_registry_baseline(&self, baseline: &RegistryBaseline) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let keys_json = serde_json::to_string(&baseline.common_keys)?;

        conn.execute(
            "INSERT OR REPLACE INTO registry_baselines
             (process_name, common_keys, learning_samples,
              first_seen, last_updated, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                baseline.process_name,
                keys_json,
                baseline.learning_samples,
                baseline.first_seen,
                baseline.last_updated,
                baseline.version,
            ],
        )?;

        debug!("Stored registry baseline: {}", baseline.process_name);
        Ok(())
    }

    /// Get a registry baseline by process name
    #[cfg(target_os = "windows")]
    pub async fn get_registry_baseline(
        &self,
        process_name: &str,
    ) -> Result<Option<RegistryBaseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let result = conn
            .query_row(
                "SELECT process_name, common_keys, learning_samples,
                    first_seen, last_updated, version
             FROM registry_baselines WHERE process_name = ?1",
                params![process_name],
                |row| {
                    let keys_json: String = row.get(1)?;

                    Ok(RegistryBaseline {
                        process_name: row.get(0)?,
                        common_keys: serde_json::from_str(&keys_json).unwrap_or_default(),
                        learning_samples: row.get(2)?,
                        first_seen: row.get(3)?,
                        last_updated: row.get(4)?,
                        version: row.get(5)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    // ========================================================================
    // Anomaly Suppression
    // ========================================================================

    /// Check if an anomaly should be suppressed
    pub async fn should_suppress_anomaly(&self, key: &str, window_seconds: u64) -> Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - window_seconds as i64;

        let count: Option<i64> = conn
            .query_row(
                "SELECT count FROM anomaly_suppression
             WHERE suppression_key = ?1 AND last_seen > ?2",
                params![key, cutoff],
                |row| row.get(0),
            )
            .optional()?;

        Ok(count.is_some())
    }

    /// Record an anomaly for suppression
    pub async fn record_anomaly_suppression(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT OR REPLACE INTO anomaly_suppression (suppression_key, last_seen, count)
             VALUES (?1, ?2, COALESCE((SELECT count + 1 FROM anomaly_suppression WHERE suppression_key = ?1), 1))",
            params![key, now],
        )?;

        Ok(())
    }

    /// Clean up old suppression entries
    pub async fn cleanup_suppression(&self, window_seconds: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = chrono::Utc::now().timestamp() - window_seconds as i64;

        let deleted = conn.execute(
            "DELETE FROM anomaly_suppression WHERE last_seen < ?1",
            params![cutoff],
        )?;

        if deleted > 0 {
            debug!("Cleaned up {} old suppression entries", deleted);
        }

        Ok(())
    }

    // ========================================================================
    // Statistics & Maintenance
    // ========================================================================

    /// Get baseline statistics
    pub async fn get_statistics(&self) -> Result<BaselineStatistics> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let process_count: usize =
            conn.query_row("SELECT COUNT(*) FROM process_baselines", [], |row| {
                row.get(0)
            })?;

        let user_count: usize =
            conn.query_row("SELECT COUNT(*) FROM user_baselines", [], |row| row.get(0))?;

        let network_count: usize =
            conn.query_row("SELECT COUNT(*) FROM network_baselines", [], |row| {
                row.get(0)
            })?;

        let file_count: usize =
            conn.query_row("SELECT COUNT(*) FROM file_access_baselines", [], |row| {
                row.get(0)
            })?;

        let registry_count: usize = conn
            .query_row("SELECT COUNT(*) FROM registry_baselines", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        let total_samples: u64 = conn
            .query_row(
                "SELECT SUM(learning_samples) FROM (
                SELECT learning_samples FROM process_baselines
                UNION ALL
                SELECT learning_samples FROM user_baselines
                UNION ALL
                SELECT learning_samples FROM network_baselines
                UNION ALL
                SELECT learning_samples FROM file_access_baselines
            )",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let oldest: Option<i64> = conn
            .query_row(
                "SELECT MIN(first_seen) FROM (
                SELECT first_seen FROM process_baselines
                UNION ALL
                SELECT first_seen FROM user_baselines
                UNION ALL
                SELECT first_seen FROM network_baselines
                UNION ALL
                SELECT first_seen FROM file_access_baselines
            )",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let newest: Option<i64> = conn
            .query_row(
                "SELECT MAX(last_updated) FROM (
                SELECT last_updated FROM process_baselines
                UNION ALL
                SELECT last_updated FROM user_baselines
                UNION ALL
                SELECT last_updated FROM network_baselines
                UNION ALL
                SELECT last_updated FROM file_access_baselines
            )",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let db_size = std::fs::metadata(&self.db_path)?.len();

        Ok(BaselineStatistics {
            process_baselines: process_count,
            user_baselines: user_count,
            network_baselines: network_count,
            file_access_baselines: file_count,
            registry_baselines: registry_count,
            total_samples,
            oldest_baseline: oldest,
            newest_baseline: newest,
            database_size_bytes: db_size,
        })
    }

    /// Clear all baselines
    pub async fn clear_all(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        conn.execute("DELETE FROM process_baselines", [])?;
        conn.execute("DELETE FROM user_baselines", [])?;
        conn.execute("DELETE FROM network_baselines", [])?;
        conn.execute("DELETE FROM file_access_baselines", [])?;
        conn.execute("DELETE FROM registry_baselines", [])?;
        conn.execute("DELETE FROM anomaly_suppression", [])?;

        conn.execute("VACUUM", [])?;

        info!("Cleared all baselines from database");
        Ok(())
    }

    /// Export baselines for backend sync
    pub async fn export_baselines(&self) -> Result<Vec<u8>> {
        let process_baselines = self.get_all_process_baselines().await?;

        let export_data = serde_json::to_vec(&process_baselines)?;

        // Compress if enabled
        #[cfg(feature = "compression")]
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&export_data)?;
            Ok(encoder.finish()?)
        }

        #[cfg(not(feature = "compression"))]
        Ok(export_data)
    }

    /// Import baselines from backend
    pub async fn import_baselines(&self, data: Vec<u8>) -> Result<()> {
        // Decompress if needed
        #[cfg(feature = "compression")]
        let data = {
            use flate2::read::GzDecoder;
            use std::io::Read;

            let mut decoder = GzDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        };

        let baselines: Vec<ProcessBaseline> = serde_json::from_slice(&data)?;

        for baseline in baselines {
            self.store_process_baseline(&baseline).await?;
        }

        info!("Imported {} baselines from backend", baselines.len());
        Ok(())
    }

    /// Clean up expired baselines
    pub async fn cleanup_expired(&self, ttl_seconds: u64) -> Result<usize> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = chrono::Utc::now().timestamp() - ttl_seconds as i64;

        let mut deleted = 0;

        deleted += conn.execute(
            "DELETE FROM process_baselines WHERE last_updated < ?1",
            params![cutoff],
        )?;

        deleted += conn.execute(
            "DELETE FROM user_baselines WHERE last_updated < ?1",
            params![cutoff],
        )?;

        deleted += conn.execute(
            "DELETE FROM network_baselines WHERE last_updated < ?1",
            params![cutoff],
        )?;

        deleted += conn.execute(
            "DELETE FROM file_access_baselines WHERE last_updated < ?1",
            params![cutoff],
        )?;

        deleted += conn.execute(
            "DELETE FROM registry_baselines WHERE last_updated < ?1",
            params![cutoff],
        )?;

        if deleted > 0 {
            info!("Cleaned up {} expired baselines", deleted);
            conn.execute("VACUUM", [])?;
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let storage = BaselineStorage::new(db_path);
        assert!(storage.is_ok());
    }

    #[tokio::test]
    async fn test_process_baseline_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = BaselineStorage::new(db_path).unwrap();

        let mut baseline = ProcessBaseline::new("chrome.exe".to_string());
        baseline.avg_memory_mb = 500.0;
        baseline.stddev_memory_mb = 50.0;
        baseline.learning_samples = 100;

        storage.store_process_baseline(&baseline).await.unwrap();

        let retrieved = storage.get_process_baseline("chrome.exe").await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.process_name, "chrome.exe");
        assert_eq!(retrieved.avg_memory_mb, 500.0);
        assert_eq!(retrieved.learning_samples, 100);
    }

    #[tokio::test]
    async fn test_statistics() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = BaselineStorage::new(db_path).unwrap();

        let baseline = ProcessBaseline::new("test.exe".to_string());
        storage.store_process_baseline(&baseline).await.unwrap();

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.process_baselines, 1);
    }
}
