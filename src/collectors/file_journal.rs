//! File Modification Journal for Ransomware Rollback
//!
//! Records file modifications (write, rename, delete) with before-snapshots
//! enabling point-in-time rollback of file changes associated with an attack.
//!
//! Storage: Local SQLite database with configurable size limits.
//! Integration: VSS (Volume Shadow Copy) on Windows for full-volume snapshots.
//!
//! Rollback modes:
//! - By storyline: Undo all changes from a specific attack chain
//! - By time range: Undo all changes within a time window
//! - By path: Undo changes to specific files/directories
//!
//! Performance:
//! - Async write channel prevents journal I/O from blocking collectors
//! - SQLite WAL mode enables concurrent read/write
//! - Backups deduplicated by SHA-256 hash (same content stored once)
//! - Configurable size caps with automatic eviction of oldest entries
//!
//! MITRE ATT&CK:
//! - T1486 (Data Encrypted for Impact) - Defense / recovery capability
//! - T1490 (Inhibit System Recovery) - Resilience against this technique

// Ransomware file-rollback journal. VSS-integration fields and rollback
// scaffolding parameters are intentionally kept for platform-specific paths
// that are not yet wired through every code path.
#![allow(dead_code, unused_variables)]

use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Core Types
// ============================================================================

/// File operation types tracked by the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Write,
    Delete,
    Rename,
    PermissionChange,
    Create,
}

impl FileOperation {
    fn as_str(&self) -> &'static str {
        match self {
            FileOperation::Write => "write",
            FileOperation::Delete => "delete",
            FileOperation::Rename => "rename",
            FileOperation::PermissionChange => "permission_change",
            FileOperation::Create => "create",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "write" => Some(FileOperation::Write),
            "delete" => Some(FileOperation::Delete),
            "rename" => Some(FileOperation::Rename),
            "permission_change" => Some(FileOperation::PermissionChange),
            "create" => Some(FileOperation::Create),
            _ => None,
        }
    }
}

/// A single journal entry recording a file modification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub id: i64,
    pub timestamp: u64,
    pub operation: FileOperation,
    pub file_path: String,
    /// New path for rename operations.
    pub new_path: Option<String>,
    /// SHA-256 hash of the file content before modification.
    pub file_hash_before: Option<String>,
    /// File size in bytes before modification.
    pub file_size_before: u64,
    /// Path to the backed-up original content (gzip compressed).
    pub backup_path: Option<String>,
    /// PID of the process that performed the modification.
    pub process_pid: u32,
    /// Name of the process that performed the modification.
    pub process_name: String,
    /// Storyline/attack-chain ID for correlated rollback.
    pub storyline_id: Option<String>,
    /// Whether this entry has been rolled back.
    pub rolled_back: bool,
}

/// Result summary for a rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    /// Number of files successfully restored.
    pub restored_count: u32,
    /// Number of files that failed to restore.
    pub failed_count: u32,
    /// Number of entries skipped (already rolled back, no backup, etc.).
    pub skipped_count: u32,
    /// Details for each restored file.
    pub restored_files: Vec<String>,
    /// Details for each failed file with error description.
    pub failed_files: Vec<(String, String)>,
}

impl RollbackResult {
    fn new() -> Self {
        Self {
            restored_count: 0,
            failed_count: 0,
            skipped_count: 0,
            restored_files: Vec::new(),
            failed_files: Vec::new(),
        }
    }
}

/// Journal statistics for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalStats {
    pub total_entries: u64,
    pub db_size_bytes: u64,
    pub backup_size_bytes: u64,
    pub oldest_entry_timestamp: Option<u64>,
    pub newest_entry_timestamp: Option<u64>,
    pub entries_by_operation: std::collections::HashMap<String, u64>,
}

/// Configuration for the file journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalConfig {
    /// Whether the file journal is enabled.
    pub enabled: bool,
    /// Path to the SQLite database file.
    pub db_path: String,
    /// Maximum database size in megabytes (default: 500 MB).
    pub max_db_size_mb: u64,
    /// Maximum total backup size in megabytes (default: 2048 MB).
    pub max_backup_size_mb: u64,
    /// Path to the directory where file backups are stored.
    pub backup_dir: String,
    /// Retention period in hours (default: 72 hours).
    pub retention_hours: u64,
    /// File extensions to monitor (e.g., "doc", "xls", "pdf").
    pub monitored_extensions: Vec<String>,
    /// Paths to exclude from journaling.
    pub excluded_paths: Vec<String>,
    /// Enable VSS integration on Windows.
    pub vss_enabled: bool,
    /// Interval in hours between automatic VSS snapshot creation.
    pub vss_interval_hours: u64,
}

impl Default for JournalConfig {
    fn default() -> Self {
        let (db_path, backup_dir) = if cfg!(windows) {
            (
                "C:\\ProgramData\\Tamandua\\journal\\file_journal.db".to_string(),
                "C:\\ProgramData\\Tamandua\\journal\\backups".to_string(),
            )
        } else {
            (
                "/var/lib/tamandua/journal/file_journal.db".to_string(),
                "/var/lib/tamandua/journal/backups".to_string(),
            )
        };

        Self {
            enabled: true,
            db_path,
            max_db_size_mb: 500,
            max_backup_size_mb: 2048,
            backup_dir,
            retention_hours: 72,
            monitored_extensions: vec![
                "doc".into(),
                "docx".into(),
                "xls".into(),
                "xlsx".into(),
                "ppt".into(),
                "pptx".into(),
                "pdf".into(),
                "jpg".into(),
                "png".into(),
                "txt".into(),
                "csv".into(),
                "db".into(),
                "sql".into(),
                "bak".into(),
                "rtf".into(),
                "odt".into(),
                "ods".into(),
                "odp".into(),
                "zip".into(),
                "7z".into(),
                "tar".into(),
                "gz".into(),
                "psd".into(),
                "ai".into(),
                "dwg".into(),
                "dxf".into(),
                "mdb".into(),
                "accdb".into(),
                "sqlite".into(),
                "json".into(),
                "xml".into(),
                "yaml".into(),
                "yml".into(),
                "ini".into(),
                "cfg".into(),
                "conf".into(),
                "log".into(),
                "md".into(),
                "html".into(),
                "htm".into(),
                "py".into(),
                "rs".into(),
                "js".into(),
                "ts".into(),
                "java".into(),
                "cpp".into(),
                "c".into(),
                "h".into(),
                "cs".into(),
                "go".into(),
                "rb".into(),
                "php".into(),
            ],
            excluded_paths: default_excluded_paths(),
            vss_enabled: cfg!(windows),
            vss_interval_hours: 4,
        }
    }
}

/// Default paths excluded from journaling (system directories, temp files, etc.).
fn default_excluded_paths() -> Vec<String> {
    if cfg!(windows) {
        vec![
            "C:\\Windows\\".into(),
            "C:\\Program Files\\".into(),
            "C:\\Program Files (x86)\\".into(),
            "C:\\ProgramData\\Tamandua\\".into(),
            "C:\\$Recycle.Bin\\".into(),
        ]
    } else {
        vec![
            "/proc/".into(),
            "/sys/".into(),
            "/dev/".into(),
            "/run/".into(),
            "/tmp/".into(),
            "/usr/".into(),
            "/bin/".into(),
            "/sbin/".into(),
            "/lib/".into(),
            "/lib64/".into(),
            "/boot/".into(),
            "/var/lib/tamandua/".into(),
        ]
    }
}

/// Internal message sent to the async journal writer task.
struct JournalWriteRequest {
    file_path: String,
    new_path: Option<String>,
    operation: FileOperation,
    process_pid: u32,
    process_name: String,
    storyline_id: Option<String>,
}

// ============================================================================
// FileJournal
// ============================================================================

/// File modification journal backed by SQLite with compressed file backups.
///
/// The journal records file modifications and stores before-snapshots of file
/// content, enabling rollback of changes caused by ransomware or other attacks.
///
/// Writes are performed asynchronously via an internal channel to avoid
/// blocking the telemetry collector loop. The SQLite database uses WAL mode
/// for concurrent reader/writer access.
pub struct FileJournal {
    config: JournalConfig,
    /// Channel sender for async write requests.
    write_tx: mpsc::Sender<JournalWriteRequest>,
    /// Flag to signal the writer task to stop.
    running: Arc<AtomicBool>,
    /// Handle to the background writer task.
    _writer_handle: tokio::task::JoinHandle<()>,
    /// VSS manager (Windows only).
    #[cfg(target_os = "windows")]
    vss_manager: Option<Arc<tokio::sync::Mutex<VssManager>>>,
}

impl FileJournal {
    /// Create a new FileJournal instance.
    ///
    /// Opens (or creates) the SQLite database, initializes the schema, and
    /// spawns a background task for async journal writes.
    pub fn new(config: JournalConfig) -> Result<Self> {
        if !config.enabled {
            return Err(anyhow!("File journal is disabled by configuration"));
        }

        // Ensure parent directories exist
        if let Some(parent) = Path::new(&config.db_path).parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create journal database directory")?;
        }
        std::fs::create_dir_all(&config.backup_dir)
            .context("Failed to create journal backup directory")?;

        // Open SQLite database with WAL mode for concurrent access
        let db = Self::open_database(&config.db_path)?;

        // Initialize schema
        Self::init_schema(&db)?;

        info!(
            db_path = %config.db_path,
            backup_dir = %config.backup_dir,
            max_db_mb = config.max_db_size_mb,
            max_backup_mb = config.max_backup_size_mb,
            retention_hours = config.retention_hours,
            "File journal initialized"
        );

        // Create async write channel
        let (write_tx, write_rx) = mpsc::channel::<JournalWriteRequest>(4096);
        let running = Arc::new(AtomicBool::new(true));

        // Initialize VSS manager on Windows
        #[cfg(target_os = "windows")]
        let vss_manager = if config.vss_enabled {
            match VssManager::new() {
                Ok(mgr) => {
                    info!("VSS manager initialized for file journal");
                    Some(Arc::new(tokio::sync::Mutex::new(mgr)))
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize VSS manager, continuing without VSS");
                    None
                }
            }
        } else {
            None
        };

        // Spawn background writer task
        let writer_config = config.clone();
        let writer_running = running.clone();
        let writer_handle = tokio::spawn(async move {
            Self::writer_loop(write_rx, writer_config, writer_running).await;
        });

        Ok(Self {
            config,
            write_tx,
            running,
            _writer_handle: writer_handle,
            #[cfg(target_os = "windows")]
            vss_manager,
        })
    }

    /// Open the SQLite database with WAL mode enabled.
    fn open_database(db_path: &str) -> Result<rusqlite::Connection> {
        let db = rusqlite::Connection::open(db_path).context("Failed to open journal database")?;

        // Enable WAL mode for concurrent read/write
        db.execute_batch("PRAGMA journal_mode = WAL;")?;
        // Reasonable page cache size (default is -2000 which is ~2MB)
        db.execute_batch("PRAGMA cache_size = -8000;")?;
        // Synchronous NORMAL is safe with WAL mode and much faster
        db.execute_batch("PRAGMA synchronous = NORMAL;")?;
        // Temp store in memory for faster temp table operations
        db.execute_batch("PRAGMA temp_store = MEMORY;")?;

        Ok(db)
    }

    /// Initialize the database schema.
    fn init_schema(db: &rusqlite::Connection) -> Result<()> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                operation TEXT NOT NULL,
                file_path TEXT NOT NULL,
                new_path TEXT,
                hash_before TEXT,
                size_before INTEGER DEFAULT 0,
                backup_path TEXT,
                process_pid INTEGER,
                process_name TEXT,
                storyline_id TEXT,
                rolled_back INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_journal_timestamp ON journal(timestamp);
            CREATE INDEX IF NOT EXISTS idx_journal_file_path ON journal(file_path);
            CREATE INDEX IF NOT EXISTS idx_journal_storyline ON journal(storyline_id);
            CREATE INDEX IF NOT EXISTS idx_journal_rolled_back ON journal(rolled_back);
            CREATE INDEX IF NOT EXISTS idx_journal_hash_before ON journal(hash_before);",
        )
        .context("Failed to initialize journal schema")?;

        Ok(())
    }

    /// Record a file modification in the journal (async, non-blocking).
    ///
    /// The actual file backup and database write happen in a background task.
    /// This method returns immediately after enqueueing the request.
    pub async fn record_modification(
        &self,
        file_path: &str,
        operation: FileOperation,
        process_pid: u32,
        process_name: &str,
        storyline_id: Option<&str>,
    ) -> Result<()> {
        // Quick check: is the path eligible for journaling?
        if !self.should_journal(file_path) {
            return Ok(());
        }

        let request = JournalWriteRequest {
            file_path: file_path.to_string(),
            new_path: None,
            operation,
            process_pid,
            process_name: process_name.to_string(),
            storyline_id: storyline_id.map(|s| s.to_string()),
        };

        self.write_tx
            .send(request)
            .await
            .map_err(|_| anyhow!("Journal write channel closed"))?;

        Ok(())
    }

    /// Record a file rename operation (async, non-blocking).
    pub async fn record_rename(
        &self,
        old_path: &str,
        new_path: &str,
        process_pid: u32,
        process_name: &str,
        storyline_id: Option<&str>,
    ) -> Result<()> {
        if !self.should_journal(old_path) && !self.should_journal(new_path) {
            return Ok(());
        }

        let request = JournalWriteRequest {
            file_path: old_path.to_string(),
            new_path: Some(new_path.to_string()),
            operation: FileOperation::Rename,
            process_pid,
            process_name: process_name.to_string(),
            storyline_id: storyline_id.map(|s| s.to_string()),
        };

        self.write_tx
            .send(request)
            .await
            .map_err(|_| anyhow!("Journal write channel closed"))?;

        Ok(())
    }

    /// Check whether a file path should be journaled based on extension and exclusion rules.
    fn should_journal(&self, file_path: &str) -> bool {
        let path = Path::new(file_path);

        // Check excluded paths (case-insensitive on Windows)
        for excluded in &self.config.excluded_paths {
            if cfg!(windows) {
                if file_path
                    .to_lowercase()
                    .starts_with(&excluded.to_lowercase())
                {
                    return false;
                }
            } else if file_path.starts_with(excluded) {
                return false;
            }
        }

        // Check monitored extensions
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            self.config
                .monitored_extensions
                .iter()
                .any(|m| m.to_lowercase() == ext_lower)
        } else {
            // No extension -- do not journal
            false
        }
    }

    /// Background writer loop that processes journal write requests.
    ///
    /// This runs in a dedicated tokio task to avoid blocking the main event loop.
    async fn writer_loop(
        mut rx: mpsc::Receiver<JournalWriteRequest>,
        config: JournalConfig,
        running: Arc<AtomicBool>,
    ) {
        // Open our own database connection for the writer task
        let db = match Self::open_database(&config.db_path) {
            Ok(db) => db,
            Err(e) => {
                error!(error = %e, "Journal writer failed to open database");
                return;
            }
        };

        let mut entries_since_cleanup = 0u64;

        while running.load(Ordering::Relaxed) {
            match rx.recv().await {
                Some(request) => {
                    if let Err(e) = Self::process_write_request(&db, &config, &request) {
                        warn!(
                            error = %e,
                            file_path = %request.file_path,
                            operation = ?request.operation,
                            "Failed to process journal write request"
                        );
                    }

                    entries_since_cleanup += 1;

                    // Run periodic cleanup every 100 entries
                    if entries_since_cleanup >= 100 {
                        entries_since_cleanup = 0;
                        if let Err(e) = Self::cleanup_old_entries(&db, &config) {
                            warn!(error = %e, "Journal cleanup failed");
                        }
                    }
                }
                None => {
                    info!("Journal write channel closed, stopping writer");
                    break;
                }
            }
        }

        info!("Journal writer loop exited");
    }

    /// Process a single write request: back up the file and insert a journal entry.
    fn process_write_request(
        db: &rusqlite::Connection,
        config: &JournalConfig,
        request: &JournalWriteRequest,
    ) -> Result<()> {
        let path = Path::new(&request.file_path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (hash_before, size_before, backup_path) = match request.operation {
            FileOperation::Write | FileOperation::Delete => {
                // Back up the file content before modification
                if path.exists() && path.is_file() {
                    match Self::backup_file(path, &config.backup_dir, config.max_backup_size_mb) {
                        Ok((hash, size, bpath)) => (Some(hash), size, Some(bpath)),
                        Err(e) => {
                            debug!(
                                error = %e,
                                path = %request.file_path,
                                "Failed to back up file, recording entry without backup"
                            );
                            (None, 0, None)
                        }
                    }
                } else {
                    (None, 0, None)
                }
            }
            FileOperation::Rename => {
                // For renames, compute hash of original file at old path
                if path.exists() && path.is_file() {
                    match Self::compute_file_hash(path) {
                        Ok((hash, size)) => (Some(hash), size, None),
                        Err(_) => (None, 0, None),
                    }
                } else {
                    (None, 0, None)
                }
            }
            FileOperation::Create | FileOperation::PermissionChange => {
                // Create: no "before" content exists
                // PermissionChange: content unchanged, no backup needed
                (None, 0, None)
            }
        };

        // Insert journal entry
        db.execute(
            "INSERT INTO journal (timestamp, operation, file_path, new_path, hash_before,
             size_before, backup_path, process_pid, process_name, storyline_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                now as i64,
                request.operation.as_str(),
                request.file_path,
                request.new_path,
                hash_before,
                size_before as i64,
                backup_path.as_ref().map(|p: &String| p.as_str()),
                request.process_pid,
                request.process_name,
                request.storyline_id,
            ],
        )
        .context("Failed to insert journal entry")?;

        debug!(
            file_path = %request.file_path,
            operation = ?request.operation,
            pid = request.process_pid,
            has_backup = backup_path.is_some(),
            "Journal entry recorded"
        );

        Ok(())
    }

    /// Back up a file to the backup directory, compressed with gzip.
    ///
    /// Files are stored by SHA-256 hash for deduplication. If a backup with
    /// the same hash already exists, the file is not stored again.
    ///
    /// Returns (sha256_hex, original_size, backup_file_path).
    fn backup_file(
        source: &Path,
        backup_dir: &str,
        max_backup_mb: u64,
    ) -> Result<(String, u64, String)> {
        // Read the source file
        let content = std::fs::read(source)
            .with_context(|| format!("Failed to read file for backup: {}", source.display()))?;

        let original_size = content.len() as u64;

        // Compute SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash_bytes = hasher.finalize();
        let hash_hex = hex::encode(hash_bytes);

        // Build backup path: backup_dir/<first 2 chars>/<hash>.gz
        let subdir = Path::new(backup_dir).join(&hash_hex[..2]);
        std::fs::create_dir_all(&subdir)?;

        let backup_path = subdir.join(format!("{}.gz", hash_hex));
        let backup_path_str = backup_path.to_string_lossy().to_string();

        // Deduplicate: if backup already exists with same hash, skip writing
        if backup_path.exists() {
            debug!(
                hash = %hash_hex,
                "Backup already exists (deduplicated)"
            );
            return Ok((hash_hex, original_size, backup_path_str));
        }

        // Check total backup size before writing
        let current_backup_size = dir_size_bytes(backup_dir);
        let max_backup_bytes = max_backup_mb * 1024 * 1024;
        if current_backup_size + original_size > max_backup_bytes {
            return Err(anyhow!(
                "Backup size limit exceeded ({} MB / {} MB)",
                current_backup_size / (1024 * 1024),
                max_backup_mb
            ));
        }

        // Compress and write
        let backup_file =
            std::fs::File::create(&backup_path).context("Failed to create backup file")?;
        let mut encoder = GzEncoder::new(backup_file, Compression::fast());
        encoder
            .write_all(&content)
            .context("Failed to write compressed backup")?;
        encoder
            .finish()
            .context("Failed to finalize compressed backup")?;

        debug!(
            hash = %hash_hex,
            original_size = original_size,
            backup_path = %backup_path_str,
            "File backed up successfully"
        );

        Ok((hash_hex, original_size, backup_path_str))
    }

    /// Compute SHA-256 hash and file size without backing up.
    fn compute_file_hash(path: &Path) -> Result<(String, u64)> {
        let content = std::fs::read(path)?;
        let size = content.len() as u64;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash_hex = hex::encode(hasher.finalize());
        Ok((hash_hex, size))
    }

    /// Restore a file from its gzip-compressed backup.
    fn restore_file_from_backup(backup_path: &str, target_path: &str) -> Result<()> {
        let backup_file = std::fs::File::open(backup_path)
            .with_context(|| format!("Failed to open backup: {}", backup_path))?;
        let mut decoder = GzDecoder::new(backup_file);
        let mut content = Vec::new();
        decoder
            .read_to_end(&mut content)
            .context("Failed to decompress backup")?;

        // Ensure parent directory exists
        if let Some(parent) = Path::new(target_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(target_path, &content)
            .with_context(|| format!("Failed to write restored file: {}", target_path))?;

        info!(
            backup = %backup_path,
            target = %target_path,
            size = content.len(),
            "File restored from backup"
        );

        Ok(())
    }

    // ========================================================================
    // Rollback Operations
    // ========================================================================

    /// Roll back all changes associated with a specific storyline (attack chain).
    ///
    /// Entries are processed newest-first so that the most recent change is
    /// undone first, resulting in the correct final state.
    pub fn rollback_by_storyline(&self, storyline_id: &str) -> Result<RollbackResult> {
        let db = Self::open_database(&self.config.db_path)?;
        let mut result = RollbackResult::new();

        let mut stmt = db.prepare(
            "SELECT id, timestamp, operation, file_path, new_path, hash_before,
                    size_before, backup_path, process_pid, process_name, storyline_id, rolled_back
             FROM journal
             WHERE storyline_id = ?1 AND rolled_back = 0
             ORDER BY timestamp DESC",
        )?;

        let entries: Vec<JournalEntry> = stmt
            .query_map(rusqlite::params![storyline_id], |row| {
                Self::row_to_entry(row)
            })?
            .filter_map(|r| r.ok())
            .collect();

        info!(
            storyline_id = %storyline_id,
            entry_count = entries.len(),
            "Starting storyline rollback"
        );

        for entry in &entries {
            match Self::rollback_entry(&db, entry) {
                Ok(true) => {
                    result.restored_count += 1;
                    result.restored_files.push(entry.file_path.clone());
                }
                Ok(false) => {
                    result.skipped_count += 1;
                }
                Err(e) => {
                    result.failed_count += 1;
                    result
                        .failed_files
                        .push((entry.file_path.clone(), e.to_string()));
                }
            }
        }

        info!(
            storyline_id = %storyline_id,
            restored = result.restored_count,
            failed = result.failed_count,
            skipped = result.skipped_count,
            "Storyline rollback complete"
        );

        Ok(result)
    }

    /// Roll back all changes within a time range (Unix timestamps in seconds).
    pub fn rollback_by_timerange(&self, start: u64, end: u64) -> Result<RollbackResult> {
        let db = Self::open_database(&self.config.db_path)?;
        let mut result = RollbackResult::new();

        let mut stmt = db.prepare(
            "SELECT id, timestamp, operation, file_path, new_path, hash_before,
                    size_before, backup_path, process_pid, process_name, storyline_id, rolled_back
             FROM journal
             WHERE timestamp >= ?1 AND timestamp <= ?2 AND rolled_back = 0
             ORDER BY timestamp DESC",
        )?;

        let entries: Vec<JournalEntry> = stmt
            .query_map(rusqlite::params![start as i64, end as i64], |row| {
                Self::row_to_entry(row)
            })?
            .filter_map(|r| r.ok())
            .collect();

        info!(
            start = start,
            end = end,
            entry_count = entries.len(),
            "Starting time-range rollback"
        );

        for entry in &entries {
            match Self::rollback_entry(&db, entry) {
                Ok(true) => {
                    result.restored_count += 1;
                    result.restored_files.push(entry.file_path.clone());
                }
                Ok(false) => {
                    result.skipped_count += 1;
                }
                Err(e) => {
                    result.failed_count += 1;
                    result
                        .failed_files
                        .push((entry.file_path.clone(), e.to_string()));
                }
            }
        }

        info!(
            start = start,
            end = end,
            restored = result.restored_count,
            failed = result.failed_count,
            skipped = result.skipped_count,
            "Time-range rollback complete"
        );

        Ok(result)
    }

    /// Restore a single file to its state before the most recent modification.
    pub fn rollback_file(&self, file_path: &str) -> Result<bool> {
        let db = Self::open_database(&self.config.db_path)?;

        let mut stmt = db.prepare(
            "SELECT id, timestamp, operation, file_path, new_path, hash_before,
                    size_before, backup_path, process_pid, process_name, storyline_id, rolled_back
             FROM journal
             WHERE file_path = ?1 AND rolled_back = 0
             ORDER BY timestamp DESC
             LIMIT 1",
        )?;

        let entry = stmt
            .query_map(rusqlite::params![file_path], |row| Self::row_to_entry(row))?
            .filter_map(|r| r.ok())
            .next();

        match entry {
            Some(entry) => Self::rollback_entry(&db, &entry),
            None => {
                info!(file_path = %file_path, "No un-rolled-back journal entry found for file");
                Ok(false)
            }
        }
    }

    /// Roll back a single journal entry.
    ///
    /// Returns Ok(true) if the file was restored, Ok(false) if skipped.
    fn rollback_entry(db: &rusqlite::Connection, entry: &JournalEntry) -> Result<bool> {
        match entry.operation {
            FileOperation::Write | FileOperation::Delete => {
                // Restore file from backup
                if let Some(ref backup_path) = entry.backup_path {
                    if Path::new(backup_path).exists() {
                        Self::restore_file_from_backup(backup_path, &entry.file_path)?;
                        Self::mark_rolled_back(db, entry.id)?;
                        return Ok(true);
                    } else {
                        warn!(
                            backup_path = %backup_path,
                            file_path = %entry.file_path,
                            "Backup file not found, cannot restore"
                        );
                        return Err(anyhow!("Backup file not found: {}", backup_path));
                    }
                } else {
                    // No backup available
                    debug!(
                        file_path = %entry.file_path,
                        operation = ?entry.operation,
                        "No backup path for entry, skipping"
                    );
                    return Ok(false);
                }
            }
            FileOperation::Rename => {
                // Undo rename: move file back to original path
                if let Some(ref new_path) = entry.new_path {
                    if Path::new(new_path).exists() {
                        // Ensure original parent directory exists
                        if let Some(parent) = Path::new(&entry.file_path).parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::rename(new_path, &entry.file_path).with_context(|| {
                            format!("Failed to rename {} back to {}", new_path, entry.file_path)
                        })?;
                        Self::mark_rolled_back(db, entry.id)?;
                        info!(
                            from = %new_path,
                            to = %entry.file_path,
                            "File rename rolled back"
                        );
                        return Ok(true);
                    } else {
                        return Err(anyhow!("Renamed file no longer exists at: {}", new_path));
                    }
                }
                Ok(false)
            }
            FileOperation::Create => {
                // Undo creation: delete the file
                let path = Path::new(&entry.file_path);
                if path.exists() {
                    std::fs::remove_file(path).with_context(|| {
                        format!("Failed to delete created file: {}", entry.file_path)
                    })?;
                    Self::mark_rolled_back(db, entry.id)?;
                    info!(file_path = %entry.file_path, "Created file removed during rollback");
                    return Ok(true);
                }
                Ok(false)
            }
            FileOperation::PermissionChange => {
                // STUB — PRODUCTION-GAP, not production. Permission-change rollback is
                // a no-op: prior mode/ACL/ownership is not restored. The journal entry
                // is left un-rolled-back (returns false). Missing: capturing the prior
                // permission state and reapplying it (chmod/SetFileSecurity per platform).
                debug!(
                    file_path = %entry.file_path,
                    "Permission rollback not implemented, skipping"
                );
                Ok(false)
            }
        }
    }

    /// Mark a journal entry as rolled back.
    fn mark_rolled_back(db: &rusqlite::Connection, entry_id: i64) -> Result<()> {
        db.execute(
            "UPDATE journal SET rolled_back = 1 WHERE id = ?1",
            rusqlite::params![entry_id],
        )?;
        Ok(())
    }

    /// Map a database row to a JournalEntry.
    fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<JournalEntry> {
        let operation_str: String = row.get(2)?;
        let operation = FileOperation::from_str(&operation_str).unwrap_or(FileOperation::Write);

        Ok(JournalEntry {
            id: row.get(0)?,
            timestamp: row.get::<_, i64>(1)? as u64,
            operation,
            file_path: row.get(3)?,
            new_path: row.get(4)?,
            file_hash_before: row.get(5)?,
            file_size_before: row.get::<_, i64>(6).unwrap_or(0) as u64,
            backup_path: row.get(7)?,
            process_pid: row.get::<_, i32>(8).unwrap_or(0) as u32,
            process_name: row.get(9).unwrap_or_default(),
            storyline_id: row.get(10)?,
            rolled_back: row.get::<_, i32>(11).unwrap_or(0) != 0,
        })
    }

    // ========================================================================
    // Cleanup and Maintenance
    // ========================================================================

    /// Remove old journal entries and orphaned backups.
    fn cleanup_old_entries(db: &rusqlite::Connection, config: &JournalConfig) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(config.retention_hours * 3600);

        // Collect backup paths that will be deleted
        let mut stmt = db.prepare(
            "SELECT backup_path FROM journal
             WHERE timestamp < ?1 AND backup_path IS NOT NULL",
        )?;
        let old_backups: Vec<String> = stmt
            .query_map(rusqlite::params![cutoff as i64], |row| {
                row.get::<_, String>(0)
            })?
            .filter_map(|r| r.ok())
            .collect();

        // Delete old journal entries
        let deleted = db.execute(
            "DELETE FROM journal WHERE timestamp < ?1",
            rusqlite::params![cutoff as i64],
        )?;

        if deleted > 0 {
            info!(
                deleted_entries = deleted,
                cutoff_timestamp = cutoff,
                "Cleaned up old journal entries"
            );
        }

        // Collect all backup paths still referenced in the journal
        let mut stmt =
            db.prepare("SELECT DISTINCT backup_path FROM journal WHERE backup_path IS NOT NULL")?;
        let active_backups: HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();

        // Delete orphaned backup files
        let mut orphans_deleted = 0u64;
        for backup_path in &old_backups {
            if !active_backups.contains(backup_path) {
                if Path::new(backup_path).exists() {
                    if let Err(e) = std::fs::remove_file(backup_path) {
                        debug!(error = %e, path = %backup_path, "Failed to delete orphaned backup");
                    } else {
                        orphans_deleted += 1;
                    }
                }
            }
        }

        if orphans_deleted > 0 {
            info!(
                orphans_deleted = orphans_deleted,
                "Cleaned up orphaned backup files"
            );
        }

        // Enforce max DB size by deleting oldest entries
        Self::enforce_db_size_limit(db, config)?;

        Ok(())
    }

    /// Enforce the maximum database size by deleting the oldest entries.
    fn enforce_db_size_limit(db: &rusqlite::Connection, config: &JournalConfig) -> Result<()> {
        let db_size: i64 = db
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count, pragma_page_size",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let max_bytes = (config.max_db_size_mb * 1024 * 1024) as i64;

        if db_size > max_bytes {
            // Delete oldest 10% of entries to bring size down
            let total_entries: i64 =
                db.query_row("SELECT COUNT(*) FROM journal", [], |row| row.get(0))?;
            let to_delete = (total_entries / 10).max(100);

            db.execute(
                "DELETE FROM journal WHERE id IN (
                    SELECT id FROM journal ORDER BY timestamp ASC LIMIT ?1
                )",
                rusqlite::params![to_delete],
            )?;

            info!(
                db_size_mb = db_size / (1024 * 1024),
                max_mb = config.max_db_size_mb,
                entries_deleted = to_delete,
                "Enforced database size limit"
            );
        }

        Ok(())
    }

    /// Get journal statistics.
    pub fn get_stats(&self) -> Result<JournalStats> {
        let db = Self::open_database(&self.config.db_path)?;

        let total_entries: u64 = db.query_row("SELECT COUNT(*) FROM journal", [], |row| {
            row.get::<_, i64>(0)
        })? as u64;

        let db_size: u64 = db
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count, pragma_page_size",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64;

        let oldest: Option<u64> = db
            .query_row("SELECT MIN(timestamp) FROM journal", [], |row| {
                row.get::<_, Option<i64>>(0)
            })?
            .map(|ts| ts as u64);

        let newest: Option<u64> = db
            .query_row("SELECT MAX(timestamp) FROM journal", [], |row| {
                row.get::<_, Option<i64>>(0)
            })?
            .map(|ts| ts as u64);

        let backup_size = dir_size_bytes(&self.config.backup_dir);

        let mut entries_by_op = std::collections::HashMap::new();
        let mut stmt = db.prepare("SELECT operation, COUNT(*) FROM journal GROUP BY operation")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        for row in rows {
            if let Ok((op, count)) = row {
                entries_by_op.insert(op, count);
            }
        }

        Ok(JournalStats {
            total_entries,
            db_size_bytes: db_size,
            backup_size_bytes: backup_size,
            oldest_entry_timestamp: oldest,
            newest_entry_timestamp: newest,
            entries_by_operation: entries_by_op,
        })
    }

    /// Run a manual cleanup cycle.
    pub fn run_cleanup(&self) -> Result<()> {
        let db = Self::open_database(&self.config.db_path)?;
        Self::cleanup_old_entries(&db, &self.config)
    }

    /// Stop the journal writer task.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("File journal stop requested");
    }
}

// ============================================================================
// VSS Manager (Windows Only)
// ============================================================================

/// Volume Shadow Copy Service manager for Windows.
///
/// Uses `vssadmin` command-line tool for pragmatic VSS operations rather than
/// the complex COM interfaces. This approach is reliable and simpler to maintain.
#[cfg(target_os = "windows")]
pub struct VssManager {
    /// Tracked shadow copies created by this manager.
    shadow_copies: Vec<VssShadowCopy>,
}

/// Information about a VSS shadow copy.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssShadowCopy {
    pub shadow_id: String,
    pub volume: String,
    pub shadow_device: String,
    pub created_at: u64,
}

#[cfg(target_os = "windows")]
impl VssManager {
    /// Create a new VSS manager.
    pub fn new() -> Result<Self> {
        Ok(Self {
            shadow_copies: Vec::new(),
        })
    }

    /// Create a new VSS snapshot for the specified volume.
    ///
    /// Uses `vssadmin create shadow /for=<volume>` and parses the output.
    pub fn create_snapshot(&mut self, volume: &str) -> Result<String> {
        let volume = if volume.ends_with(':') {
            format!("{}\\", volume)
        } else if volume.ends_with(":\\") {
            volume.to_string()
        } else {
            format!("{}:\\", volume)
        };

        info!(volume = %volume, "Creating VSS snapshot");

        let output = std::process::Command::new("vssadmin")
            .args(&["create", "shadow", &format!("/for={}", volume)])
            .output()
            .context("Failed to execute vssadmin")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(anyhow!(
                "vssadmin create shadow failed: {} {}",
                stdout,
                stderr
            ));
        }

        // Parse shadow copy ID from output
        // Example: "Shadow Copy ID: {guid-here}"
        let shadow_id = stdout
            .lines()
            .find(|line| line.contains("Shadow Copy ID:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|id| id.trim().to_string())
            .ok_or_else(|| anyhow!("Could not parse shadow copy ID from vssadmin output"))?;

        // Parse device name
        // Example: "Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy123"
        let shadow_device = stdout
            .lines()
            .find(|line| line.contains("Shadow Copy Volume Name:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|name| name.trim().to_string())
            .unwrap_or_default();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let copy = VssShadowCopy {
            shadow_id: shadow_id.clone(),
            volume: volume.clone(),
            shadow_device,
            created_at: now,
        };

        info!(
            shadow_id = %shadow_id,
            volume = %volume,
            "VSS snapshot created"
        );

        self.shadow_copies.push(copy);
        Ok(shadow_id)
    }

    /// List all tracked shadow copies.
    pub fn list_snapshots(&self) -> &[VssShadowCopy] {
        &self.shadow_copies
    }

    /// Restore a file from a VSS shadow copy.
    ///
    /// The shadow device provides access to the pre-snapshot version of files.
    pub fn restore_file_from_snapshot(&self, snapshot_id: &str, file_path: &str) -> Result<()> {
        let copy = self
            .shadow_copies
            .iter()
            .find(|c| c.shadow_id == snapshot_id)
            .ok_or_else(|| anyhow!("Shadow copy not found: {}", snapshot_id))?;

        if copy.shadow_device.is_empty() {
            return Err(anyhow!("Shadow copy has no device path"));
        }

        // Build the shadow copy path
        // e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\...
        let relative_path = file_path
            .strip_prefix(&copy.volume)
            .or_else(|| file_path.get(3..)) // Strip "C:\" prefix
            .ok_or_else(|| {
                anyhow!(
                    "File path {} does not belong to volume {}",
                    file_path,
                    copy.volume
                )
            })?;

        let shadow_file = format!("{}\\{}", copy.shadow_device, relative_path);

        // Use robocopy for reliable file copy from shadow
        let target_dir = Path::new(file_path)
            .parent()
            .ok_or_else(|| anyhow!("Invalid file path"))?;
        let file_name = Path::new(file_path)
            .file_name()
            .ok_or_else(|| anyhow!("Invalid file name"))?;

        let shadow_dir = Path::new(&shadow_file)
            .parent()
            .ok_or_else(|| anyhow!("Invalid shadow path"))?;

        // Use copy command as a simple approach
        let output = std::process::Command::new("cmd")
            .args(&["/C", "copy", "/Y", &shadow_file, file_path])
            .output()
            .context("Failed to copy file from VSS shadow")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("File copy from shadow failed: {}", stderr));
        }

        info!(
            shadow_id = %snapshot_id,
            file_path = %file_path,
            "File restored from VSS snapshot"
        );

        Ok(())
    }

    /// Delete shadow copies older than the specified age in hours.
    pub fn delete_old_snapshots(&mut self, max_age_hours: u64) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(max_age_hours * 3600);

        let mut deleted = 0usize;
        let mut kept = Vec::new();

        for copy in self.shadow_copies.drain(..) {
            if copy.created_at < cutoff {
                // Delete via vssadmin
                let result = std::process::Command::new("vssadmin")
                    .args(&[
                        "delete",
                        "shadows",
                        &format!("/shadow={}", copy.shadow_id),
                        "/quiet",
                    ])
                    .output();

                match result {
                    Ok(output) if output.status.success() => {
                        info!(shadow_id = %copy.shadow_id, "Deleted old VSS snapshot");
                        deleted += 1;
                    }
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!(
                            shadow_id = %copy.shadow_id,
                            error = %stderr,
                            "Failed to delete VSS snapshot"
                        );
                        kept.push(copy); // Keep in list for retry
                    }
                    Err(e) => {
                        warn!(
                            shadow_id = %copy.shadow_id,
                            error = %e,
                            "Failed to execute vssadmin delete"
                        );
                        kept.push(copy);
                    }
                }
            } else {
                kept.push(copy);
            }
        }

        self.shadow_copies = kept;

        if deleted > 0 {
            info!(deleted = deleted, "Old VSS snapshots cleaned up");
        }

        Ok(deleted)
    }
}

// ============================================================================
// VSS Stubs for non-Windows platforms
// ============================================================================

#[cfg(not(target_os = "windows"))]
pub struct VssManager;

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssShadowCopy {
    pub shadow_id: String,
    pub volume: String,
    pub shadow_device: String,
    pub created_at: u64,
}

#[cfg(not(target_os = "windows"))]
impl VssManager {
    pub fn new() -> Result<Self> {
        Err(anyhow!("VSS is only available on Windows"))
    }

    pub fn create_snapshot(&mut self, _volume: &str) -> Result<String> {
        Err(anyhow!("VSS is only available on Windows"))
    }

    pub fn list_snapshots(&self) -> &[VssShadowCopy] {
        &[]
    }

    pub fn restore_file_from_snapshot(&self, _snapshot_id: &str, _file_path: &str) -> Result<()> {
        Err(anyhow!("VSS is only available on Windows"))
    }

    pub fn delete_old_snapshots(&mut self, _max_age_hours: u64) -> Result<usize> {
        Err(anyhow!("VSS is only available on Windows"))
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Calculate the total size of a directory tree in bytes.
fn dir_size_bytes(path: &str) -> u64 {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| entry.metadata().ok())
        .map(|meta| meta.len())
        .sum()
}
