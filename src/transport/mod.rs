//! Communication with backend server
//!
//! Handles WebSocket connection, message serialization, and command handling.
//!
//! # Sans-IO Architecture
//!
//! The transport layer uses a sans-IO architecture pattern (inspired by Firezone)
//! that separates protocol logic from I/O operations. This provides:
//!
//! - **Deterministic Testing**: Protocol can be tested without real I/O
//! - **Portability**: Same logic works across async runtimes
//! - **Debuggability**: Pure functions that can be inspected and replayed
//! - **Performance**: Zero-copy where possible, no async overhead in protocol logic
//!
//! See `sans_io` module for the core protocol implementation and `event_loop`
//! for the I/O layer that drives it.

#[cfg(test)]
mod tests;

pub mod cert_pinning;
pub mod proxy;
pub mod siem;
pub mod token_manager;

// Sans-IO architecture modules
pub mod codec;
pub mod event_loop;
pub mod sans_io;
pub mod state_machine;

use crate::collectors::TelemetryEvent;
use crate::config::AgentConfig;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use native_tls::{Certificate, Identity, TlsConnector};
use rusqlite::{params, Connection, OptionalExtension};
use rustls::ClientConfig as RustlsClientConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, trace, warn};

use self::cert_pinning::CertPins;
use self::proxy::ProxyConfig;
use self::token_manager::{extract_http_base, TokenManager, TokenManagerConfig};

fn windows_tamandua_data_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        if let Some(path) = std::env::var_os("TAMANDUA_DATA_DIR").map(std::path::PathBuf::from) {
            return path;
        }

        if let Some(path) =
            std::env::var_os("ProgramData").map(|p| std::path::PathBuf::from(p).join("Tamandua"))
        {
            if path.exists() || path.parent().is_some_and(|parent| parent.exists()) {
                return path;
            }
        }

        std::env::var_os("SystemDrive")
            .map(|drive| {
                std::path::PathBuf::from(format!(
                    r"{}\ProgramData\Tamandua",
                    drive.to_string_lossy()
                ))
            })
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData\Tamandua"))
    }

    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/var/lib/tamandua")
    }
}

/// Sample submission for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleSubmission {
    /// SHA256 hash of the file (hex encoded)
    pub sha256: String,
    /// SHA1 hash of the file (hex encoded)
    pub sha1: String,
    /// MD5 hash of the file (hex encoded)
    pub md5: String,
    /// Original file path on the endpoint
    pub file_path: String,
    /// Detected file type (pe, elf, macho, script, unknown)
    pub file_type: String,
    /// Shannon entropy of the file content
    pub entropy: f64,
    /// Base64 encoded gzip-compressed file content
    pub content: String,
    /// File size in bytes (original, uncompressed)
    pub size: u64,
    /// Whether this is a PE (Windows) executable
    pub is_pe: bool,
    /// Whether this is an ELF (Linux) executable
    pub is_elf: bool,
    /// Whether this is a Mach-O (macOS) executable
    pub is_macho: bool,
    /// Whether the file is signed
    pub is_signed: bool,
    /// Signer name if signed
    pub signer: Option<String>,
    /// File creation timestamp (Unix epoch seconds)
    pub created_at: Option<u64>,
    /// File modification timestamp (Unix epoch seconds)
    pub modified_at: Option<u64>,
    /// Whether PII was detected and scrubbed from the sample
    pub pii_scrubbed: bool,
    /// Count of PII items that were redacted
    pub pii_count: usize,
}

/// ML scan result received from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlScanResult {
    /// SHA256 hash of the scanned file
    pub sha256: String,
    /// Original file path
    pub file_path: String,
    /// Whether the file is classified as malicious
    pub is_malicious: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Malware family/classification if detected
    pub classification: Option<String>,
    /// MITRE ATT&CK tactics if applicable
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques if applicable
    pub mitre_techniques: Vec<String>,
    /// Additional details from ML model
    pub details: Option<serde_json::Value>,
}

/// Command received from backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub command_id: String,
    pub command_type: CommandType,
    pub timestamp: u64,
    pub payload: serde_json::Value,
}

/// Command types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandType {
    KillProcess,
    QuarantineFile,
    IsolateNetwork,
    UnisolateNetwork,
    CollectArtifact,
    UpdateConfig,
    UpdateRules,
    ScanPath,
    // Network blocking commands
    // Note: rename_all = "snake_case" turns consecutive capitals (e.g. "IP")
    // into "i_p", producing the wrong wire value (block_i_p). The backend
    // canonical command string is `block_ip`, so rename these explicitly.
    #[serde(rename = "block_ip")]
    BlockIP,
    #[serde(rename = "unblock_ip")]
    UnblockIP,
    BlockDomain,
    UnblockDomain,
    #[serde(rename = "list_blocked_ips")]
    ListBlockedIPs,
    ListBlockedDomains,
    // Application control commands
    AppControlSetMode,
    AppControlAddRule,
    AppControlRemoveRule,
    AppControlEnableRule,
    AppControlDisableRule,
    AppControlListRules,
    AppControlGetPolicy,
    AppControlUpdatePolicy,
    AppControlGetStats,
    // Live Response commands
    ProcessList,
    ProcessDump,
    MemoryScan,
    MemoryStrings,
    FileList,
    FileDownload,
    FileHash,
    FileUpload,
    NetworkConnections,
    NetworkConnectionsEnumerate,
    NetworkConnectionTerminate,
    NetworkConnectionStats,
    DnsCache,
    RegistryQuery,
    ServiceList,
    ScheduledTasks,
    StartupItems,
    ShellExecute,
    // Live Response - Process Manager commands
    ProcessTreeList,
    ProcessKill,
    ProcessSuspend,
    ProcessResume,
    ProcessSetPriority,
    ProcessListHandles,
    ProcessCreateDump,
    // VSS Snapshot & Rollback commands
    CreateSnapshot,
    ListSnapshots,
    DeleteSnapshot,
    RestoreFile,
    RestoreFiles,
    FindEncryptedFiles,
    RansomwareRemediate,
    // VSS one-click rollback
    VssRollback,
    VssRansomwareRollback,
    VssGetSchedule,
    VssSetSchedule,
    // Patch management commands
    ScanPatches,
    InstallPatches,
    RollbackPatches,
    // Deception/Breadcrumb commands
    DeployBreadcrumbs,
    RotateBreadcrumbs,
    // Self-update commands (server-pushed)
    UpdateAvailable,
    ForceUpdate,
    // Advanced memory analysis commands
    DumpMemory,
    ScanMemoryYara,
    AnalyzeSuspiciousRegions,
    AnalyzeMemoryHooks,
    ExtractMemoryStrings,
    FullMemoryAnalysis,
    ScanIndirectSyscalls,
    // FIM commands
    FimGetBaseline,
    FimRestoreFile,
    FimQuarantineFile,
    FimForceBaselineScan,
    FimGetStats,
    FimAddWhitelist,
    FimGetCompliance,
    FimGetChanges,
    // Quarantine vault commands
    QuarantineFileAdvanced,
    QuarantineGetList,
    QuarantineGetStats,
    QuarantineGetDetails,
    QuarantineRestoreFile,
    QuarantineDeleteFile,
    QuarantineExportReport,
    // Model control commands (kill switch)
    IsolateModel,
    ReleaseModel,
    KillModel,
    ListModels,
    // Model quarantine commands
    ModelQuarantine,
    ModelRestore,
    ModelQuarantineList,
    ModelQuarantineDelete,
    // Interactive shell commands (PTY)
    ShellStart,
    ShellInput,
    ShellResize,
    ShellTerminate,
}

/// Command execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub result_data: Option<serde_json::Value>,
}

/// Message types from backend
#[allow(dead_code)] // Variants consumed via serde tag dispatch; reserved for upcoming dispatcher refactor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BackendMessage {
    Command(Command),
    Config {
        config: serde_json::Value,
        yara_rules: Vec<serde_json::Value>,
        sigma_rules: Vec<serde_json::Value>,
        iocs: Vec<serde_json::Value>,
    },
    HeartbeatAck {
        server_time: u64,
        config_updated: bool,
        rules_updated: bool,
    },
    Error {
        message: String,
    },
}

/// Connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

/// Configuration update notification
#[derive(Debug, Clone)]
pub struct ConfigUpdate {
    pub config: serde_json::Value,
    pub yara_rules: Option<Vec<serde_json::Value>>,
    pub sigma_rules: Option<Vec<serde_json::Value>>,
    pub iocs: Option<Vec<serde_json::Value>>,
}

/// Delivery acknowledgment received from the server
#[derive(Debug, Clone)]
pub struct DeliveryAck {
    /// The batch sequence number being acknowledged
    pub seq: u64,
    /// Number of events the server processed in this batch
    pub count: usize,
}

/// Tracks delivery statistics for telemetry batches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryStats {
    /// Total events sent (handed to WebSocket)
    pub events_sent: u64,
    /// Total events acknowledged by server
    pub events_acked: u64,
    /// Total events retried due to missing ACK
    pub events_retried: u64,
    /// Total events permanently dropped after max retries
    pub events_dropped: u64,
    /// Total queued offline events removed only after server ACK
    pub events_confirmed_after_ack: u64,
    /// Total telemetry ACKs whose accepted count did not match the tracked batch
    pub ack_count_mismatches: u64,
    /// Number of batches currently in-flight (sent, awaiting ACK)
    pub in_flight_batches: usize,
}

impl Default for DeliveryStats {
    fn default() -> Self {
        Self {
            events_sent: 0,
            events_acked: 0,
            events_retried: 0,
            events_dropped: 0,
            events_confirmed_after_ack: 0,
            ack_count_mismatches: 0,
            in_flight_batches: 0,
        }
    }
}

/// A batch of events that has been sent but not yet acknowledged
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct InFlightBatch {
    /// Monotonic sequence number for this batch
    seq: u64,
    /// The events in the batch (kept for retry)
    events: Vec<TelemetryEvent>,
    /// When the batch was originally sent
    sent_at: tokio::time::Instant,
    /// How many times this batch has been retried
    retry_count: u32,
}

/// Maximum number of unacknowledged batches before blocking
const MAX_IN_FLIGHT_BATCHES: usize = 100;
/// Maximum number of retries before permanently dropping a batch
const MAX_RETRIES: u32 = 3;
/// Base timeout for ACK (used with exponential backoff: 10s, 20s, 40s)
const ACK_BASE_TIMEOUT_SECS: u64 = 10;

type HmacSha256 = Hmac<Sha256>;

/// Local event queue for offline storage.
///
/// Events are kept in memory for fast draining and mirrored to a SQLite/WAL
/// spool. Each persisted payload is protected with an HMAC derived from the
/// enrolled agent identity, so local edits by other software are detected
/// before sync.
pub struct LocalEventQueue {
    /// Events waiting to be sent
    events: std::collections::VecDeque<TelemetryEvent>,
    /// Maximum queue size before dropping oldest events
    max_size: usize,
    /// Path to SQLite spool database
    persist_path: Option<std::path::PathBuf>,
    /// SQLite spool connection
    db: Option<Mutex<Connection>>,
    /// HMAC key for payload and metadata integrity
    integrity_key: Vec<u8>,
    /// Tamper events generated while opening/verifying the spool
    integrity_events: Vec<TelemetryEvent>,
    /// Counter for dropped events (used for rate-limited logging)
    drop_count: u64,
}

impl LocalEventQueue {
    pub fn new(
        max_size: usize,
        persist_path: Option<std::path::PathBuf>,
        integrity_key: Vec<u8>,
    ) -> Self {
        let mut queue = Self {
            events: std::collections::VecDeque::new(),
            max_size,
            persist_path: persist_path.clone(),
            db: None,
            integrity_key,
            integrity_events: Vec::new(),
            drop_count: 0,
        };

        // Try to load persisted events from disk.
        if let Some(ref path) = persist_path {
            if let Err(e) = queue.open_spool(path) {
                warn!(error = %e, "Failed to open persisted event spool");
                queue.record_integrity_event(
                    "offline_spool_open_failed",
                    format!("Failed to open offline telemetry spool: {e}"),
                    serde_json::json!({"path": path.display().to_string()}),
                );
            } else if let Err(e) = queue.load_from_disk(path) {
                warn!(error = %e, "Failed to load persisted events from SQLite spool");
                queue.record_integrity_event(
                    "offline_spool_load_failed",
                    format!("Failed to load offline telemetry spool: {e}"),
                    serde_json::json!({"path": path.display().to_string()}),
                );
            }
        }
        queue
    }

    pub fn push(&mut self, event: TelemetryEvent) {
        if self.events.len() >= self.max_size {
            // Drop oldest event
            if let Some(dropped) = self.events.pop_front() {
                self.delete_event_from_spool(&dropped.event_id);
            }
            self.drop_count += 1;
            // Rate-limit the warning: log every 1000 drops instead of every single one
            if self.drop_count % 1000 == 1 {
                warn!(
                    total_dropped = self.drop_count,
                    queue_size = self.max_size,
                    "Local event queue full, dropping oldest events (summary every 1000 drops)"
                );
            }
        }
        if let Err(e) = self.insert_event_into_spool(&event) {
            warn!(error = %e, event_id = %event.event_id, "Failed to persist event to SQLite spool");
            self.record_integrity_event(
                "offline_spool_write_failed",
                format!("Failed to persist queued telemetry event: {e}"),
                serde_json::json!({"event_id": event.event_id}),
            );
        }
        self.events.push_back(event);
        if let Err(e) = self.update_pending_count_meta() {
            warn!(error = %e, "Failed to update offline spool integrity metadata");
        }
    }

    /// Enqueue a batch of events with a single spool transaction and one
    /// integrity-metadata update.
    ///
    /// `push` (the single-event path) issues a `SELECT COUNT(*)` plus two
    /// autocommit writes per event, so looping it over an offline batch is
    /// O(N^2) and pins the CPU as the queue fills. This batches eviction,
    /// insertion, and the pending-count update so each offline batch costs a
    /// bounded amount of work.
    pub fn push_batch(&mut self, mut events: Vec<TelemetryEvent>) {
        if events.is_empty() {
            return;
        }

        // Bound the queue to `max_size` up front, dropping the oldest events
        // (existing first, then the oldest of the incoming batch). Evicted
        // spool rows are deleted in one transaction instead of one autocommit
        // per drop, and incoming events trimmed before insert are never spooled.
        let total = self.events.len() + events.len();
        if total > self.max_size {
            let need_drop = total - self.max_size;
            let drop_existing = std::cmp::min(self.events.len(), need_drop);
            if drop_existing > 0 {
                let mut dropped_ids = Vec::with_capacity(drop_existing);
                for _ in 0..drop_existing {
                    if let Some(dropped) = self.events.pop_front() {
                        dropped_ids.push(dropped.event_id);
                    }
                }
                self.delete_event_ids_from_spool(&dropped_ids);
            }
            let drop_incoming = need_drop - drop_existing;
            if drop_incoming > 0 {
                events.drain(0..drop_incoming);
            }
            let dropped = need_drop as u64;
            let before = self.drop_count;
            self.drop_count += dropped;
            // Rate-limit: log when crossing a multiple of 1000 drops.
            if before / 1000 != self.drop_count / 1000 {
                warn!(
                    total_dropped = self.drop_count,
                    queue_size = self.max_size,
                    "Local event queue full, dropping oldest events (summary every 1000 drops)"
                );
            }
        }

        if events.is_empty() {
            return;
        }
        let incoming = events.len();

        // Persist the whole batch in a single transaction, then push into
        // memory and update the integrity metadata once.
        if let Err(e) = self.insert_events_into_spool(&events) {
            warn!(error = %e, count = incoming, "Failed to persist event batch to SQLite spool");
            self.record_integrity_event(
                "offline_spool_write_failed",
                format!("Failed to persist {incoming} queued telemetry event(s): {e}"),
                serde_json::json!({"batch_size": incoming}),
            );
        }
        for event in events {
            self.events.push_back(event);
        }
        if let Err(e) = self.update_pending_count_meta() {
            warn!(error = %e, "Failed to update offline spool integrity metadata");
        }
    }

    pub fn drain_batch(&mut self, max_count: usize) -> Vec<TelemetryEvent> {
        let count = std::cmp::min(max_count, self.events.len());
        let drained: Vec<TelemetryEvent> = self.events.drain(..count).collect();
        if let Some(db) = self.db.as_ref() {
            {
                let conn = db.lock().unwrap();
                for event in &drained {
                    if let Err(e) = conn.execute(
                        "DELETE FROM queued_events WHERE event_id = ?1",
                        params![event.event_id],
                    ) {
                        warn!(error = %e, event_id = %event.event_id, "Failed to delete drained event from SQLite spool");
                    }
                }
            }
            if let Err(e) = self.update_pending_count_meta_ref() {
                warn!(error = %e, "Failed to update offline spool metadata after drain");
            }
        }
        drained
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Persist queue to disk for crash recovery.
    ///
    /// SQLite mode writes through on every push/delete. This method keeps the
    /// old call sites meaningful by checkpointing WAL state and re-validating
    /// metadata.
    pub fn persist_to_disk(&self) -> Result<()> {
        if let Some(db) = self.db.as_ref() {
            let conn = db.lock().unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
            debug!(
                count = self.events.len(),
                "Checkpointed SQLite event queue spool"
            );
        } else if let Some(ref path) = self.persist_path {
            // Legacy fallback only if SQLite could not be opened.
            let data = serde_json::to_vec(&self.events.iter().collect::<Vec<_>>())?;
            std::fs::write(path, data)?;
            debug!(count = self.events.len(), path = %path.display(), "Persisted event queue to legacy disk file");
        }
        Ok(())
    }

    fn load_from_disk(&mut self, path: &std::path::Path) -> Result<()> {
        if self.db.is_some() {
            self.verify_spool_metadata()?;
            let (events, tampered) = self.load_verified_events_from_spool()?;
            self.events = events.into_iter().collect();
            if tampered > 0 {
                self.record_integrity_event(
                    "offline_spool_payload_tamper",
                    format!("{tampered} queued telemetry event(s) failed HMAC verification"),
                    serde_json::json!({"tampered_rows": tampered}),
                );
            }
            if !self.integrity_events.is_empty() {
                for event in std::mem::take(&mut self.integrity_events) {
                    self.events.push_back(event);
                }
            }
            info!(count = self.events.len(), path = %path.display(), "Loaded verified events from SQLite spool");
        } else if path.exists() {
            let data = std::fs::read(path)?;
            let events: Vec<TelemetryEvent> = serde_json::from_slice(&data)?;
            self.events = events.into_iter().collect();
            info!(
                count = self.events.len(),
                "Loaded persisted events from legacy disk file"
            );
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Merge persisted events from disk into the in-memory queue.
    /// Unlike `load_from_disk` (called at construction), this merges into
    /// an already-populated queue without discarding existing events.
    pub fn merge_persisted_events(&mut self) -> Result<usize> {
        if self.db.is_some() {
            self.verify_spool_metadata()?;
            let (events, tampered) = self.load_verified_events_from_spool()?;
            let mut merged = 0usize;

            for event in events {
                if !self
                    .events
                    .iter()
                    .any(|existing| existing.event_id == event.event_id)
                {
                    self.events.push_back(event);
                    merged += 1;
                }
            }

            if tampered > 0 {
                let event = Self::build_integrity_event(
                    "offline_spool_payload_tamper",
                    format!("{tampered} queued telemetry event(s) failed HMAC verification during merge"),
                    serde_json::json!({"tampered_rows": tampered}),
                );
                self.push(event);
            }

            return Ok(merged);
        }

        let path = match self.persist_path {
            Some(ref p) => p.clone(),
            None => return Ok(0),
        };
        if path.exists() {
            let data = std::fs::read(&path)?;
            let events: Vec<TelemetryEvent> = serde_json::from_slice(&data)?;
            let count = events.len();
            if count > 0 {
                info!(
                    count = count,
                    "Merging persisted events from legacy disk file into queue"
                );
                for event in events {
                    self.push(event);
                }
                std::fs::remove_file(&path)?;
            }
            return Ok(count);
        }
        Ok(0)
    }

    /// Remove the persisted queue file from disk (called after successful flush)
    pub fn clear_persisted_file(&self) -> Result<()> {
        if let Some(db) = self.db.as_ref() {
            {
                let conn = db.lock().unwrap();
                conn.execute("DELETE FROM queued_events", [])?;
            }
            self.update_pending_count_meta_ref()?;
            debug!("Cleared SQLite event queue spool");
        } else if let Some(ref path) = self.persist_path {
            if path.exists() {
                std::fs::remove_file(path)?;
                debug!(path = %path.display(), "Cleared persisted event queue file");
            }
        }
        Ok(())
    }

    /// Discard events older than `max_age` and return the number of discarded events.
    /// `max_age` is compared against each event's `timestamp` field (Unix millis).
    pub fn expire_old_events(&mut self, max_age: std::time::Duration) -> usize {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_millis.saturating_sub(max_age.as_millis() as u64);

        let before = self.events.len();
        self.events.retain(|event| event.timestamp >= cutoff);
        let expired = before - self.events.len();

        if expired > 0 {
            if let Some(db) = self.db.as_ref() {
                {
                    let conn = db.lock().unwrap();
                    let _ = conn.execute(
                        "DELETE FROM queued_events WHERE timestamp_ms < ?1",
                        params![cutoff as i64],
                    );
                }
                let _ = self.update_pending_count_meta_ref();
            }
            warn!(
                expired = expired,
                remaining = self.events.len(),
                max_age_hours = max_age.as_secs() / 3600,
                "Discarded expired events from queue"
            );
        }

        expired
    }

    /// Return the front events without removing them (peek for re-queue on failure)
    pub fn peek_batch(&self, max_count: usize) -> Vec<TelemetryEvent> {
        self.events.iter().take(max_count).cloned().collect()
    }

    /// Remove exactly `count` events from the front of the queue.
    /// Used after a batch has been confirmed sent.
    pub fn confirm_sent(&mut self, count: usize) {
        let to_remove = std::cmp::min(count, self.events.len());
        let removed: Vec<TelemetryEvent> = self.events.drain(..to_remove).collect();
        self.delete_events_from_spool(&removed, "sent");
    }

    /// Remove specific events from memory and disk after the server ACKs them.
    pub fn confirm_event_ids(&mut self, event_ids: &[&str]) -> usize {
        if event_ids.is_empty() {
            return 0;
        }

        let ids: std::collections::HashSet<&str> = event_ids.iter().copied().collect();
        let before = self.events.len();
        let mut removed = Vec::new();

        self.events.retain(|event| {
            if ids.contains(event.event_id.as_str()) {
                removed.push(event.clone());
                false
            } else {
                true
            }
        });

        self.delete_events_from_spool(&removed, "acked");
        before - self.events.len()
    }

    fn delete_events_from_spool(&self, events: &[TelemetryEvent], reason: &str) {
        if let Some(db) = self.db.as_ref() {
            {
                let conn = db.lock().unwrap();
                for event in events {
                    if let Err(e) = conn.execute(
                        "DELETE FROM queued_events WHERE event_id = ?1",
                        params![event.event_id],
                    ) {
                        warn!(error = %e, event_id = %event.event_id, reason = reason, "Failed to delete confirmed event from SQLite spool");
                    }
                }
            }
            if let Err(e) = self.update_pending_count_meta_ref() {
                warn!(error = %e, "Failed to update offline spool metadata after confirm");
            }
        }
    }

    fn open_spool(&mut self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS queued_events (
                event_id TEXT PRIMARY KEY,
                timestamp_ms INTEGER NOT NULL,
                payload TEXT NOT NULL,
                payload_hmac TEXT NOT NULL,
                queued_at_ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_queued_events_timestamp
                ON queued_events(timestamp_ms);

            CREATE TABLE IF NOT EXISTS queue_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                value_hmac TEXT NOT NULL
            );
            "#,
        )?;

        self.db = Some(Mutex::new(conn));
        self.ensure_pending_count_meta()?;
        Ok(())
    }

    fn insert_event_into_spool(&self, event: &TelemetryEvent) -> Result<()> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let conn = db.lock().unwrap();

        let payload = serde_json::to_string(event)?;
        let mac = self.hmac_hex(payload.as_bytes());
        let queued_at = current_millis() as i64;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO queued_events
                (event_id, timestamp_ms, payload, payload_hmac, queued_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                event.event_id,
                event.timestamp as i64,
                payload,
                mac,
                queued_at
            ],
        )?;

        Ok(())
    }

    fn delete_event_from_spool(&self, event_id: &str) {
        if let Some(db) = self.db.as_ref() {
            let conn = db.lock().unwrap();
            if let Err(e) = conn.execute(
                "DELETE FROM queued_events WHERE event_id = ?1",
                params![event_id],
            ) {
                warn!(error = %e, event_id = %event_id, "Failed to delete evicted event from SQLite spool");
            }
        }
    }

    /// Persist a batch of events to the spool in a single transaction.
    ///
    /// The per-event path (`insert_event_into_spool` called in a loop) issues
    /// one autocommit transaction per event, so a high offline event rate turns
    /// the spool into a write storm. Wrapping the batch in one transaction with
    /// a single prepared statement collapses that to one fsync per batch while
    /// preserving the per-payload HMAC.
    fn insert_events_into_spool(&self, events: &[TelemetryEvent]) -> Result<()> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let mut conn = db.lock().unwrap();
        let queued_at = current_millis() as i64;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT OR REPLACE INTO queued_events
                    (event_id, timestamp_ms, payload, payload_hmac, queued_at_ms)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
            )?;
            for event in events {
                let payload = serde_json::to_string(event)?;
                let mac = self.hmac_hex(payload.as_bytes());
                stmt.execute(params![
                    event.event_id,
                    event.timestamp as i64,
                    payload,
                    mac,
                    queued_at
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete a batch of evicted events from the spool in a single transaction.
    fn delete_event_ids_from_spool(&self, event_ids: &[String]) {
        if event_ids.is_empty() {
            return;
        }
        let Some(db) = self.db.as_ref() else {
            return;
        };
        let mut conn = db.lock().unwrap();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                warn!(error = %e, "Failed to open transaction to delete evicted events from spool");
                return;
            }
        };
        {
            let mut stmt = match tx.prepare("DELETE FROM queued_events WHERE event_id = ?1") {
                Ok(stmt) => stmt,
                Err(e) => {
                    warn!(error = %e, "Failed to prepare eviction delete for spool");
                    return;
                }
            };
            for event_id in event_ids {
                if let Err(e) = stmt.execute(params![event_id]) {
                    warn!(error = %e, event_id = %event_id, "Failed to delete evicted event from SQLite spool");
                }
            }
        }
        if let Err(e) = tx.commit() {
            warn!(error = %e, "Failed to commit eviction deletes to spool");
        }
    }

    fn load_verified_events_from_spool(&self) -> Result<(Vec<TelemetryEvent>, usize)> {
        let mut events = Vec::new();
        let mut tampered = 0usize;
        let mut tampered_ids = Vec::new();

        {
            let Some(db) = self.db.as_ref() else {
                return Ok((Vec::new(), 0));
            };
            let conn = db.lock().unwrap();

            let mut stmt = conn.prepare(
                "SELECT event_id, payload, payload_hmac FROM queued_events ORDER BY timestamp_ms ASC, queued_at_ms ASC",
            )?;

            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;

            for row in rows {
                let (event_id, payload, expected_mac) = row?;
                if !self.verify_hmac(payload.as_bytes(), &expected_mac) {
                    tampered += 1;
                    tampered_ids.push(event_id);
                    continue;
                }

                match serde_json::from_str::<TelemetryEvent>(&payload) {
                    Ok(event) => events.push(event),
                    Err(e) => {
                        warn!(error = %e, event_id = %event_id, "Queued event payload failed JSON parse");
                        tampered += 1;
                        tampered_ids.push(event_id);
                    }
                }
            }
        }

        if !tampered_ids.is_empty() {
            if let Some(db) = self.db.as_ref() {
                let conn = db.lock().unwrap();
                for event_id in tampered_ids {
                    let _ = conn.execute(
                        "DELETE FROM queued_events WHERE event_id = ?1",
                        params![event_id],
                    );
                }
            }
            let _ = self.update_pending_count_meta_ref();
        }

        Ok((events, tampered))
    }

    fn ensure_pending_count_meta(&self) -> Result<()> {
        let existing: Option<String> = {
            let Some(db) = self.db.as_ref() else {
                return Ok(());
            };
            let conn = db.lock().unwrap();

            conn.query_row(
                "SELECT value FROM queue_meta WHERE key = 'pending_count'",
                [],
                |row| row.get(0),
            )
            .optional()?
        };

        if existing.is_none() {
            self.update_pending_count_meta_ref()?;
        }

        Ok(())
    }

    fn verify_spool_metadata(&mut self) -> Result<()> {
        let (count, meta) = {
            let Some(db) = self.db.as_ref() else {
                return Ok(());
            };
            let conn = db.lock().unwrap();

            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM queued_events", [], |row| row.get(0))?;

            let meta: Option<(String, String)> = conn
                .query_row(
                    "SELECT value, value_hmac FROM queue_meta WHERE key = 'pending_count'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            (count, meta)
        };

        match meta {
            Some((value, value_hmac)) if self.verify_hmac(value.as_bytes(), &value_hmac) => {
                if value.parse::<i64>().ok() != Some(count) {
                    self.record_integrity_event(
                        "offline_spool_metadata_tamper",
                        "Offline telemetry spool pending-count metadata does not match row count",
                        serde_json::json!({"metadata_count": value, "actual_count": count}),
                    );
                    self.update_pending_count_meta_ref()?;
                }
            }
            Some((value, _)) => {
                self.record_integrity_event(
                    "offline_spool_metadata_tamper",
                    "Offline telemetry spool metadata HMAC verification failed",
                    serde_json::json!({"metadata_value": value, "actual_count": count}),
                );
                self.update_pending_count_meta_ref()?;
            }
            None => {
                self.record_integrity_event(
                    "offline_spool_metadata_missing",
                    "Offline telemetry spool metadata was missing",
                    serde_json::json!({"actual_count": count}),
                );
                self.update_pending_count_meta_ref()?;
            }
        }

        Ok(())
    }

    fn update_pending_count_meta(&self) -> Result<()> {
        self.update_pending_count_meta_ref()
    }

    fn update_pending_count_meta_ref(&self) -> Result<()> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let conn = db.lock().unwrap();

        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM queued_events", [], |row| row.get(0))?;
        let value = count.to_string();
        let mac = self.hmac_hex(value.as_bytes());

        conn.execute(
            r#"
            INSERT INTO queue_meta (key, value, value_hmac)
            VALUES ('pending_count', ?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, value_hmac = excluded.value_hmac
            "#,
            params![value, mac],
        )?;

        Ok(())
    }

    fn hmac_hex(&self, data: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.integrity_key).expect("HMAC accepts keys of any size");
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }

    fn verify_hmac(&self, data: &[u8], expected_hex: &str) -> bool {
        let Ok(expected) = hex::decode(expected_hex) else {
            return false;
        };

        let mut mac =
            HmacSha256::new_from_slice(&self.integrity_key).expect("HMAC accepts keys of any size");
        mac.update(data);
        mac.verify_slice(&expected).is_ok()
    }

    fn record_integrity_event(
        &mut self,
        reason: &str,
        description: impl Into<String>,
        details: serde_json::Value,
    ) {
        self.integrity_events
            .push(Self::build_integrity_event(reason, description, details));
    }

    fn build_integrity_event(
        reason: &str,
        description: impl Into<String>,
        details: serde_json::Value,
    ) -> TelemetryEvent {
        let description = description.into();
        let mut metadata = HashMap::new();
        metadata.insert("tamandua_internal".to_string(), "true".to_string());
        metadata.insert(
            "tamper_surface".to_string(),
            "offline_telemetry_spool".to_string(),
        );
        metadata.insert("reason".to_string(), reason.to_string());

        TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: crate::collectors::EventType::SecurityToolTamper,
            timestamp: current_millis(),
            severity: crate::collectors::Severity::High,
            payload: crate::collectors::EventPayload::Generic(serde_json::json!({
                "category": "offline_spool_integrity",
                "reason": reason,
                "description": description,
                "details": details,
            })),
            detections: vec![],
            metadata,
        }
    }
}

fn current_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn derive_queue_integrity_key(config: &AgentConfig) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"tamandua-offline-telemetry-spool-v1");
    hasher.update(config.agent_id.as_bytes());
    if let Some(token) = &config.auth_token {
        hasher.update(token.as_bytes());
    }
    hasher.finalize().to_vec()
}

/// Backend client for WebSocket communication with auto-reconnection
#[derive(Clone)]
pub struct BackendClient {
    config: AgentConfig,
    /// Sender for outgoing messages
    outgoing_tx: mpsc::Sender<Message>,
    /// Receiver for outgoing messages (used by WebSocket sender)
    outgoing_rx: Arc<RwLock<mpsc::Receiver<Message>>>,
    /// Sender for latency-sensitive live response messages.
    priority_outgoing_tx: mpsc::Sender<Message>,
    /// Receiver for latency-sensitive live response messages.
    priority_outgoing_rx: Arc<RwLock<mpsc::Receiver<Message>>>,
    /// Receiver for incoming commands
    command_rx: Arc<RwLock<mpsc::Receiver<Command>>>,
    /// Sender for incoming commands (used by message handler)
    command_tx: mpsc::Sender<Command>,
    /// Sender for config updates
    config_tx: mpsc::Sender<ConfigUpdate>,
    /// Receiver for config updates
    config_rx: Arc<RwLock<mpsc::Receiver<ConfigUpdate>>>,
    /// Sender for ML scan results
    ml_result_tx: mpsc::Sender<MlScanResult>,
    /// Receiver for ML scan results
    ml_result_rx: Arc<RwLock<mpsc::Receiver<MlScanResult>>>,
    /// Sender for delivery acknowledgments (fed by message handler)
    ack_tx: mpsc::Sender<DeliveryAck>,
    /// Receiver for delivery acknowledgments (consumed by ACK processor)
    ack_rx: Arc<RwLock<mpsc::Receiver<DeliveryAck>>>,
    /// Current connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Local event queue for offline operation
    local_queue: Arc<RwLock<LocalEventQueue>>,
    /// In-flight batches awaiting acknowledgment, keyed by sequence number
    in_flight: Arc<RwLock<HashMap<u64, InFlightBatch>>>,
    /// Monotonic sequence counter for telemetry batches
    batch_seq: Arc<AtomicU64>,
    /// Delivery statistics (sent, acked, retried, dropped)
    delivery_stats: Arc<RwLock<DeliveryStats>>,
    /// Last inbound WebSocket activity observed from the backend.
    ///
    /// This intentionally tracks backend responses, not local heartbeat sends.
    /// A half-closed TCP socket can still accept writes briefly while the
    /// reader is gone; liveness must be based on receiving traffic.
    last_heartbeat_at: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Last backend transport error visible to the local GUI.
    last_error: Arc<RwLock<Option<String>>>,
    /// Flag to signal shutdown
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Abort handles for connection-specific tasks (sender, heartbeat, reader)
    /// These are cancelled on reconnect to avoid deadlocks and stale tasks.
    connection_tasks: Arc<RwLock<Vec<tokio::task::AbortHandle>>>,
    /// Notifies when a reconnection completes so collectors can send full refresh
    reconnect_notify: Arc<tokio::sync::Notify>,
    /// CLI profile override - if set, tells server about the forced profile
    #[allow(dead_code)]
    cli_profile_override: Option<crate::config::PerformanceProfile>,
    /// Event triage engine for agent-side filtering (reduces telemetry volume 85-95%)
    triage: Arc<RwLock<crate::event_triage::EventTriage>>,
}

impl BackendClient {
    fn latest_auth_token_for_connect(&self) -> Option<String> {
        let configured = self.config.auth_token.clone();
        let config_path = AgentConfig::default_config_path();

        let Ok(on_disk) = AgentConfig::from_file(&config_path) else {
            return configured;
        };

        if on_disk.agent_id != self.config.agent_id {
            return configured;
        }

        on_disk.auth_token.or(configured)
    }

    async fn refresh_auth_token_from_disk(&self) -> Result<()> {
        let config_path = AgentConfig::default_config_path();
        let on_disk = AgentConfig::from_file(&config_path)
            .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

        if on_disk.agent_id != self.config.agent_id {
            return Err(anyhow::anyhow!(
                "Config agent_id changed on disk; refusing token refresh for reconnect"
            ));
        }

        let token = on_disk
            .auth_token
            .clone()
            .or_else(|| self.config.auth_token.clone())
            .ok_or_else(|| anyhow::anyhow!("No auth token available for refresh"))?;

        let server_url = Self::auth_api_base_url(&on_disk.server_url)
            .or_else(|_| Self::auth_api_base_url(&self.config.server_url))?;

        let recovery_token = crate::installer::token::get_recovery_token()
            .map_err(|error| {
                warn!(
                    error = %error,
                    "Recovery token unavailable; reconnect token refresh cannot re-enroll if JWT refresh fails"
                );
                error
            })
            .ok();

        let manager = TokenManager::new(
            self.config.agent_id.clone(),
            token,
            TokenManagerConfig {
                server_url,
                config_path,
                check_interval_seconds: 300,
                refresh_window_percent: 60,
                max_retries: 3,
                installation_token: recovery_token,
            },
        )?;

        manager.refresh_with_retry().await
    }

    async fn spawn_token_manager(&self) -> Result<()> {
        let config_path = AgentConfig::default_config_path();
        let on_disk = AgentConfig::from_file(&config_path).unwrap_or_else(|_| self.config.clone());

        if on_disk.agent_id != self.config.agent_id {
            warn!(
                configured_agent_id = %self.config.agent_id,
                disk_agent_id = %on_disk.agent_id,
                "Skipping proactive token manager because config agent_id changed on disk"
            );
            return Ok(());
        }

        let Some(token) = on_disk
            .auth_token
            .clone()
            .or_else(|| self.config.auth_token.clone())
        else {
            warn!("Skipping proactive token manager because no auth token is configured");
            return Ok(());
        };

        let server_url = Self::auth_api_base_url(&on_disk.server_url)
            .or_else(|_| Self::auth_api_base_url(&self.config.server_url))?;

        let recovery_token = crate::installer::token::get_recovery_token()
            .map_err(|error| {
                warn!(
                    error = %error,
                    "Recovery token unavailable; proactive token manager cannot re-enroll if JWT refresh fails"
                );
                error
            })
            .ok();

        let manager = Arc::new(TokenManager::new(
            self.config.agent_id.clone(),
            token,
            TokenManagerConfig {
                server_url,
                config_path,
                check_interval_seconds: 300,
                refresh_window_percent: 60,
                max_retries: 3,
                installation_token: recovery_token,
            },
        )?);

        manager.start();
        info!("Proactive token manager started");
        Ok(())
    }

    fn auth_api_base_url(server_url: &str) -> Result<String> {
        if let Ok(override_url) = std::env::var("TAMANDUA_AUTH_API_BASE_URL") {
            let trimmed = override_url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }

        let base = extract_http_base(server_url)?;

        if base == "https://agents.tamandua.treantlab.org:8443"
            || base == "https://agents.tamandua.treantlab.org"
        {
            return Ok("https://tamandua.treantlab.org".to_string());
        }

        Ok(base)
    }

    fn is_auth_rejection(error: &anyhow::Error) -> bool {
        let message = error.to_string();
        message.contains("401")
            || message.contains("403")
            || message.contains("Unauthorized")
            || message.contains("Forbidden")
            || message.contains("credential_")
            || message.contains("token")
    }

    fn missing_enrollment_credentials(&self) -> Option<&'static str> {
        let production_cloud = self
            .config
            .server_url
            .contains("agents.tamandua.treantlab.org");

        if production_cloud && self.config.auth_token.is_none() {
            return Some(
                "Enrollment credentials missing locally: agent auth token is not configured. Re-enroll with a fresh token.",
            );
        }

        if production_cloud
            && (!self.config.tls.enabled
                || self.config.tls.cert_path.is_none()
                || self.config.tls.key_path.is_none()
                || self.config.tls.ca_path.is_none())
        {
            return Some(
                "Enrollment credentials missing locally: mTLS is not fully configured. Re-enroll with a fresh token.",
            );
        }

        None
    }

    pub async fn new(
        config: &AgentConfig,
        cli_profile_override: Option<crate::config::PerformanceProfile>,
    ) -> Result<Self> {
        // Channel for outgoing messages (telemetry, responses)
        let (outgoing_tx, outgoing_rx) = mpsc::channel(100);
        let (priority_outgoing_tx, priority_outgoing_rx) = mpsc::channel(500);

        // Channel for incoming commands from backend
        let (command_tx, command_rx) = mpsc::channel(100);

        // Channel for config updates
        let (config_tx, config_rx) = mpsc::channel(10);

        // Channel for ML scan results
        let (ml_result_tx, ml_result_rx) = mpsc::channel(100);

        // Channel for delivery acknowledgments from server
        let (ack_tx, ack_rx) = mpsc::channel(256);

        // Local event queue for offline operation
        let persist_path = if cfg!(windows) {
            Some(windows_tamandua_data_dir().join("event_queue.sqlite"))
        } else if cfg!(target_os = "macos") {
            Some(std::path::PathBuf::from(
                "/Library/Application Support/Tamandua/event_queue.sqlite",
            ))
        } else {
            Some(std::path::PathBuf::from(
                "/var/lib/tamandua/event_queue.sqlite",
            ))
        };

        // Ensure parent directory exists
        if let Some(ref path) = persist_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let local_queue = LocalEventQueue::new(
            config.local_queue_size.unwrap_or(50_000),
            persist_path,
            derive_queue_integrity_key(config),
        );

        // Initialize event triage with no governor initially
        // (governor will be passed to collectors separately if available)
        let triage = crate::event_triage::EventTriage::new(config.event_triage.clone(), None);

        Ok(Self {
            config: config.clone(),
            outgoing_tx,
            outgoing_rx: Arc::new(RwLock::new(outgoing_rx)),
            priority_outgoing_tx,
            priority_outgoing_rx: Arc::new(RwLock::new(priority_outgoing_rx)),
            command_rx: Arc::new(RwLock::new(command_rx)),
            command_tx,
            config_tx,
            config_rx: Arc::new(RwLock::new(config_rx)),
            ml_result_tx,
            ml_result_rx: Arc::new(RwLock::new(ml_result_rx)),
            ack_tx,
            ack_rx: Arc::new(RwLock::new(ack_rx)),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            local_queue: Arc::new(RwLock::new(local_queue)),
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            batch_seq: Arc::new(AtomicU64::new(1)),
            delivery_stats: Arc::new(RwLock::new(DeliveryStats::default())),
            last_heartbeat_at: Arc::new(RwLock::new(None)),
            last_error: Arc::new(RwLock::new(None)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            connection_tasks: Arc::new(RwLock::new(Vec::new())),
            reconnect_notify: Arc::new(tokio::sync::Notify::new()),
            cli_profile_override,
            triage: Arc::new(RwLock::new(triage)),
        })
    }

    /// Connect to backend with automatic reconnection loop
    /// This method spawns a background task that maintains the connection
    pub async fn connect(&self) -> Result<()> {
        if let Some(reason) = self.missing_enrollment_credentials() {
            warn!(
                reason,
                "Backend connection disabled until enrollment is repaired"
            );
            self.set_last_error(reason.to_string()).await;
            let mut state = self.state.write().await;
            *state = ConnectionState::Disconnected;
            return Ok(());
        }

        self.spawn_token_manager().await?;

        // Initial connection
        if let Err(e) = self.connect_once(0).await {
            warn!(error = %e, "Initial connection failed, will retry in background");
            self.set_last_error(format!("Initial connection failed: {}", e))
                .await;
            // Reset state to Disconnected so the connection monitor can retry.
            // connect_once sets state to Connecting, and without this reset
            // the monitor loop skips reconnection (it excludes Connecting state).
            {
                let mut state = self.state.write().await;
                *state = ConnectionState::Disconnected;
            }
        }

        // Spawn reconnection monitor
        self.spawn_connection_monitor().await;

        // Spawn queue sync task
        self.spawn_queue_sync().await;

        // Spawn ACK processor for delivery acknowledgment handling
        self.spawn_ack_processor().await;

        Ok(())
    }

    /// Spawn a task that monitors connection and reconnects when needed
    async fn spawn_connection_monitor(&self) {
        let client = self.clone();

        tokio::spawn(async move {
            let mut attempt: u32 = 0;
            let mut last_connected = false;

            loop {
                // Check if shutdown was requested
                if client.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    info!("Connection monitor shutting down");
                    break;
                }

                let current_state = client.get_state().await;
                let is_connected = current_state == ConnectionState::Connected;

                if is_connected {
                    let heartbeat_interval =
                        client.config.heartbeat_interval_seconds.clamp(1, 25) as i64;
                    let stale_after = chrono::Duration::seconds((heartbeat_interval * 3).max(30));
                    let last_heartbeat = *client.last_heartbeat_at.read().await;

                    if last_heartbeat
                        .map(|last| Utc::now().signed_duration_since(last) > stale_after)
                        .unwrap_or(true)
                    {
                        warn!(
                            stale_after_seconds = stale_after.num_seconds(),
                            "Connection heartbeat stale, forcing reconnect"
                        );

                        {
                            let mut state = client.state.write().await;
                            *state = ConnectionState::Disconnected;
                        }

                        let mut tasks = client.connection_tasks.write().await;
                        for task in tasks.drain(..) {
                            task.abort();
                        }
                    }
                }

                // Detect disconnect
                if last_connected && !is_connected {
                    warn!("Connection lost, initiating reconnection");
                    attempt = 0;
                }

                last_connected = is_connected;

                // Reconnect if disconnected
                if !is_connected
                    && current_state != ConnectionState::Connecting
                    && current_state != ConnectionState::Reconnecting
                {
                    attempt += 1;
                    let backoff = client.calculate_backoff(attempt);

                    info!(
                        attempt = attempt,
                        backoff_seconds = backoff,
                        "Attempting to reconnect"
                    );

                    match client.connect_once(attempt).await {
                        Ok(()) => {
                            info!("Reconnection successful");
                            client.clear_last_error().await;
                            attempt = 0;

                            // Flush queued events in the background so we don't
                            // block the connection monitor loop.  This loads
                            // persisted events from disk, expires stale entries
                            // (>24h), and drains batches of 100 with 100ms
                            // inter-batch delays.
                            client.spawn_reconnection_flush();
                        }
                        Err(e) => {
                            error!(error = %e, attempt = attempt, "Reconnection failed");

                            if Self::is_auth_rejection(&e) {
                                warn!(
                                    error = %e,
                                    "Backend rejected agent credentials during reconnect; attempting token refresh"
                                );

                                match client.refresh_auth_token_from_disk().await {
                                    Ok(()) => {
                                        info!(
                                            "Agent auth token refreshed after reconnect rejection"
                                        );
                                    }
                                    Err(refresh_error) => {
                                        error!(
                                            error = %refresh_error,
                                            "Agent auth token refresh failed after reconnect rejection; re-enrollment may be required"
                                        );
                                    }
                                }
                            }

                            client
                                .set_last_error(format!(
                                    "Reconnect attempt {} failed: {}",
                                    attempt, e
                                ))
                                .await;

                            // Reset state to Disconnected so the monitor loop
                            // can retry.  connect_with_retry sets the state to
                            // Reconnecting, and without this reset the condition
                            // `current_state != Reconnecting` would be false on
                            // the next iteration, permanently blocking retries.
                            {
                                let mut state = client.state.write().await;
                                *state = ConnectionState::Disconnected;
                            }

                            // Wait before next attempt
                            tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                        }
                    }
                }

                // Check connection health periodically
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    /// Spawn a task that periodically syncs queued events when connected
    async fn spawn_queue_sync(&self) {
        let client = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

            loop {
                interval.tick().await;

                if client.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                if client.is_connected().await {
                    client.sync_queued_events().await;
                }
            }
        });
    }

    /// Spawn the ACK processor task.
    ///
    /// This task runs two concurrent loops:
    /// 1. **ACK receiver**: drains the `ack_rx` channel and removes acknowledged
    ///    batches from the in-flight map, updating delivery stats.
    /// 2. **Timeout scanner**: periodically scans in-flight batches for ones that
    ///    have exceeded their ACK deadline. Timed-out batches are retried with
    ///    exponential backoff (2s, 4s, 8s) up to MAX_RETRIES times, after which
    ///    they are permanently dropped.
    async fn spawn_ack_processor(&self) {
        let client = self.clone();

        tokio::spawn(async move {
            // Scan interval for checking timed-out in-flight batches
            let mut timeout_interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

            loop {
                tokio::select! {
                    // Branch 1: process incoming ACKs
                    ack = async {
                        let mut rx = client.ack_rx.write().await;
                        rx.recv().await
                    } => {
                        match ack {
                            Some(delivery_ack) => {
                                client.process_ack(delivery_ack).await;
                            }
                            None => {
                                // Channel closed (shutdown)
                                debug!("ACK channel closed, stopping ACK processor");
                                break;
                            }
                        }
                    }

                    // Branch 2: scan for timed-out batches
                    _ = timeout_interval.tick() => {
                        if client.shutdown.load(Ordering::Relaxed) {
                            info!("ACK processor shutting down");
                            break;
                        }
                        client.scan_in_flight_timeouts().await;
                    }
                }
            }
        });
    }

    /// Process a single delivery ACK from the server.
    /// Removes the batch from in-flight and updates delivery stats.
    async fn process_ack(&self, ack: DeliveryAck) {
        let mut in_flight = self.in_flight.write().await;

        if let Some(batch) = in_flight.remove(&ack.seq) {
            let latency = batch.sent_at.elapsed();
            let accepted_count = ack.count.min(batch.events.len());
            let acked_ids: Vec<&str> = batch
                .events
                .iter()
                .take(accepted_count)
                .map(|event| event.event_id.as_str())
                .collect();
            let confirmed_from_queue = {
                let mut queue = self.local_queue.write().await;
                queue.confirm_event_ids(&acked_ids)
            };

            debug!(
                seq = ack.seq,
                count = ack.count,
                confirmed_from_queue = confirmed_from_queue,
                latency_ms = latency.as_millis() as u64,
                retries = batch.retry_count,
                "Telemetry batch acknowledged by server"
            );

            let mut stats = self.delivery_stats.write().await;
            stats.events_acked += ack.count as u64;
            stats.events_confirmed_after_ack += confirmed_from_queue as u64;
            if ack.count != batch.events.len() {
                stats.ack_count_mismatches += 1;
                warn!(
                    seq = ack.seq,
                    ack_count = ack.count,
                    batch_events = batch.events.len(),
                    confirmed_from_queue = confirmed_from_queue,
                    "Telemetry ACK count did not match tracked batch"
                );
            }
            stats.in_flight_batches = in_flight.len();
        } else {
            // ACK for an unknown seq -- could be a duplicate or very late ACK
            trace!(
                seq = ack.seq,
                "Received ACK for unknown batch sequence (possible duplicate)"
            );
        }
    }

    /// Scan in-flight batches for timeouts.
    ///
    /// For each batch whose deadline has elapsed:
    /// - If retry_count < MAX_RETRIES: re-send the batch and increment retry_count
    /// - If retry_count >= MAX_RETRIES: permanently drop the batch and log an error
    async fn scan_in_flight_timeouts(&self) {
        let now = tokio::time::Instant::now();
        let mut timed_out: Vec<(u64, InFlightBatch)> = Vec::new();

        // Phase 1: identify timed-out batches (read lock)
        {
            let in_flight = self.in_flight.read().await;
            for (&seq, batch) in in_flight.iter() {
                let deadline_secs = ACK_BASE_TIMEOUT_SECS * 2u64.pow(batch.retry_count);
                let deadline = batch.sent_at + tokio::time::Duration::from_secs(deadline_secs);
                if now >= deadline {
                    timed_out.push((seq, batch.clone()));
                }
            }
        }

        if timed_out.is_empty() {
            return;
        }

        // Phase 2: handle timed-out batches
        for (seq, batch) in timed_out {
            if batch.retry_count >= MAX_RETRIES {
                // Permanently drop -- all retries exhausted
                let remaining = {
                    let mut in_flight = self.in_flight.write().await;
                    in_flight.remove(&seq);
                    in_flight.len()
                };
                let event_count = batch.events.len() as u64;
                error!(
                    seq = seq,
                    events = event_count,
                    retries = batch.retry_count,
                    "Permanently dropping telemetry batch after {} retries -- events lost",
                    MAX_RETRIES
                );

                let mut stats = self.delivery_stats.write().await;
                stats.events_dropped += event_count;
                stats.in_flight_batches = remaining;
            } else {
                // Retry: re-send the batch with a new timestamp
                let retry_num = batch.retry_count + 1;
                let event_count = batch.events.len();
                warn!(
                    seq = seq,
                    events = event_count,
                    retry = retry_num,
                    "Telemetry batch ACK timed out, retrying ({}/{})",
                    retry_num,
                    MAX_RETRIES
                );

                // Update stats
                {
                    let mut stats = self.delivery_stats.write().await;
                    stats.events_retried += event_count as u64;
                }

                // Re-send the batch over the wire
                match self.send_telemetry_wire(&batch.events, seq).await {
                    Ok(()) => {
                        // Update the in-flight entry with new sent_at and incremented retry count
                        let mut in_flight = self.in_flight.write().await;
                        if let Some(entry) = in_flight.get_mut(&seq) {
                            entry.sent_at = tokio::time::Instant::now();
                            entry.retry_count = retry_num;
                        }
                    }
                    Err(e) => {
                        warn!(
                            seq = seq,
                            error = %e,
                            "Failed to re-send timed-out batch, will retry on next scan"
                        );
                        // Leave in in-flight map; it will be scanned again
                        // but bump retry_count so we make progress towards the drop limit
                        let mut in_flight = self.in_flight.write().await;
                        if let Some(entry) = in_flight.get_mut(&seq) {
                            entry.retry_count = retry_num;
                            // Reset timer to give the retry a fresh window
                            entry.sent_at = tokio::time::Instant::now();
                        }
                    }
                }
            }
        }
    }

    fn telemetry_ack_tracking_enabled() -> bool {
        std::env::var("TAMANDUA_TELEMETRY_ACK_TRACKING")
            .map(|value| !(value == "0" || value.eq_ignore_ascii_case("false")))
            .unwrap_or(true)
    }

    /// Sync queued events to backend.
    ///
    /// This is the lightweight version called by the periodic queue-sync task.
    /// It acquires the lock, sends whatever is in memory, and returns.
    async fn sync_queued_events(&self) {
        let queue_len = {
            let queue = self.local_queue.read().await;
            queue.len()
        };

        if queue_len == 0 {
            return;
        }

        info!(count = queue_len, "Periodic sync: flushing queued events");
        self.flush_queue_batched().await;
    }

    /// Full reconnection flush: loads persisted events from disk, expires stale
    /// events, then drains the queue in batches of 100 with a 100ms inter-batch
    /// delay. Spawned as a background task so the main WebSocket message loop
    /// is never blocked.
    fn spawn_reconnection_flush(&self) {
        let client = self.clone();

        tokio::spawn(async move {
            info!("Reconnection flush: starting background queue drain");

            // Step 1: Merge any events persisted to disk back into the in-memory queue
            {
                let mut queue = client.local_queue.write().await;
                match queue.merge_persisted_events() {
                    Ok(merged) if merged > 0 => {
                        info!(
                            merged = merged,
                            "Reconnection flush: merged persisted events from disk"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "Reconnection flush: failed to load persisted events from disk");
                    }
                    _ => {}
                }

                // Step 2: Expire events older than 24 hours
                let max_age = std::time::Duration::from_secs(24 * 60 * 60);
                queue.expire_old_events(max_age);
            }

            // Step 3: Drain and send in batches (lock is released between batches
            // so the main loop can continue to queue new events)
            client.flush_queue_batched().await;
        });
    }

    /// Drain the in-memory queue in batches of 100 events, sending each batch
    /// to the server with a 100ms delay between batches. On failure the unsent
    /// events remain in the queue and the persisted file is updated.
    async fn flush_queue_batched(&self) {
        const BATCH_SIZE: usize = 100;
        let delay = tokio::time::Duration::from_millis(100);
        let mut total_sent: usize = 0;
        let mut batch_num: usize = 0;

        loop {
            if Self::telemetry_ack_tracking_enabled() && !self.in_flight.read().await.is_empty() {
                trace!("Flush: waiting for in-flight telemetry ACK before replaying more queued events");
                break;
            }

            // Peek at the next batch while holding the lock briefly
            let batch = {
                let queue = self.local_queue.read().await;
                if queue.is_empty() {
                    break;
                }
                queue.peek_batch(BATCH_SIZE)
            };

            if batch.is_empty() {
                break;
            }

            let batch_len = batch.len();
            batch_num += 1;

            // Attempt to send (without holding the queue lock)
            match self.send_telemetry_direct_without_triage(&batch).await {
                Ok(()) => {
                    let remaining = if Self::telemetry_ack_tracking_enabled() {
                        let queue = self.local_queue.read().await;
                        queue.len()
                    } else {
                        // Older backends may not emit telemetry ACKs. In that
                        // compatibility mode, a successful write remains the
                        // queue confirmation boundary.
                        let mut queue = self.local_queue.write().await;
                        queue.confirm_sent(batch_len);
                        queue.len()
                    };
                    total_sent += batch_len;

                    trace!(
                        batch = batch_num,
                        sent = batch_len,
                        remaining = remaining,
                        "Flush: batch sent successfully"
                    );

                    if Self::telemetry_ack_tracking_enabled() {
                        trace!(
                            batch = batch_num,
                            pending_ack = batch_len,
                            "Flush: waiting for telemetry ACK before removing queued events"
                        );
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        error = %e,
                        batch = batch_num,
                        unsent = batch_len,
                        "Flush: failed to send batch, stopping flush"
                    );

                    // Persist whatever remains so nothing is lost across restarts
                    let queue = self.local_queue.read().await;
                    if let Err(pe) = queue.persist_to_disk() {
                        error!(error = %pe, "Flush: failed to persist remaining events");
                    }
                    break;
                }
            }

            // Throttle to avoid flooding the server
            tokio::time::sleep(delay).await;

            // Safety: abort if we lost the connection mid-flush
            if !self.is_connected().await {
                warn!("Flush: connection lost during flush, aborting");
                let queue = self.local_queue.read().await;
                if let Err(pe) = queue.persist_to_disk() {
                    error!(error = %pe, "Flush: failed to persist remaining events after disconnect");
                }
                break;
            }
        }

        // If queue is fully drained, clean up the disk file
        {
            let queue = self.local_queue.read().await;
            if queue.is_empty() {
                if let Err(e) = queue.clear_persisted_file() {
                    warn!(error = %e, "Flush: failed to clear persisted queue file");
                }
            }
        }

        if total_sent > 0 {
            info!(
                total_sent = total_sent,
                batches = batch_num,
                "Flush: completed"
            );
        }
    }

    /// Internal connect without spawning monitor
    async fn connect_once(&self, attempt: u32) -> Result<()> {
        self.connect_with_retry(attempt).await
    }

    async fn connect_with_retry(&self, attempt: u32) -> Result<()> {
        let _max_attempts = self.config.max_reconnect_attempts;

        // Abort any existing connection-specific tasks to avoid deadlocks.
        // The old sender task holds a write lock on outgoing_rx — if we don't
        // abort it first, the new sender task will deadlock.
        {
            let mut tasks = self.connection_tasks.write().await;
            if !tasks.is_empty() {
                info!(count = tasks.len(), "Aborting previous connection tasks");
                for handle in tasks.drain(..) {
                    handle.abort();
                }
            }
        }
        // Yield so aborted tasks can clean up and release locks
        tokio::task::yield_now().await;

        // Set state
        {
            let mut state = self.state.write().await;
            *state = if attempt == 0 {
                ConnectionState::Connecting
            } else {
                ConnectionState::Reconnecting
            };
        }

        // Phoenix WebSocket requires /websocket suffix on the socket path
        let base_url = if self.config.server_url.ends_with("/websocket") {
            self.config.server_url.clone()
        } else {
            format!("{}/websocket", self.config.server_url.trim_end_matches('/'))
        };

        info!(
            url = %self.config.server_url,
            attempt = attempt,
            "Connecting to backend"
        );

        let auth_token = self.latest_auth_token_for_connect();
        let mut uri = base_url.parse::<url::Url>()?;
        {
            let mut query = uri.query_pairs_mut();
            query
                // The agent uses Phoenix V1 JSON object frames
                // (%{"topic", "event", "payload", "ref", "join_ref"}).
                // V2 expects array frames and will reject object payloads.
                .append_pair("vsn", "1.0.0")
                .append_pair("agent_id", &self.config.agent_id)
                .append_pair("hostname", &self.config.get_hostname())
                .append_pair("os_type", self.config.get_os_type())
                .append_pair("os_version", &self.config.get_os_version())
                .append_pair("agent_version", env!("CARGO_PKG_VERSION"))
                .append_pair("machine_id", &self.config.get_machine_id_hash())
                .append_pair("token", auth_token.as_deref().unwrap_or("dev-token"));
            if let Some(org_id) = self.config.organization_id.as_deref() {
                query.append_pair("organization_id", org_id);
            }
        }

        // --- Build certificate pins (if configured) ---
        let cert_pins = if !self.config.transport.cert_pins.is_empty() {
            match CertPins::from_base64(
                &self.config.transport.cert_pins,
                self.config.transport.cert_pin_enforce,
            ) {
                Ok(pins) => {
                    info!(
                        pin_count = pins.pin_count(),
                        enforce = pins.is_enforcing(),
                        "Certificate pinning configured"
                    );
                    Some(pins)
                }
                Err(e) => {
                    error!(error = %e, "Failed to parse certificate pins, continuing without pinning");
                    None
                }
            }
        } else {
            None
        };

        // --- Determine if proxy is configured ---
        let proxy_config = if let Some(ref proxy_url) = self.config.transport.proxy_url {
            match ProxyConfig::from_url(proxy_url) {
                Ok(proxy) => {
                    info!(
                        proxy = %proxy_url,
                        "Proxy configured for WebSocket connection"
                    );
                    Some(proxy)
                }
                Err(e) => {
                    error!(error = %e, "Failed to parse proxy URL, connecting directly");
                    None
                }
            }
        } else {
            None
        };

        // --- Establish connection ---
        // When proxy or cert pinning is configured, we need manual control over
        // the TCP and TLS layers. Otherwise, use the simpler connect_async path.
        let is_wss = uri.scheme() == "wss";
        let custom_tls_required = is_wss
            && (self.config.tls.enabled
                || self.config.tls.cert_path.is_some()
                || self.config.tls.key_path.is_some()
                || self.config.tls.ca_path.is_some()
                || self.config.tls.skip_verify);

        let use_manual_connect = proxy_config.is_some() || cert_pins.is_some();

        let (ws_stream, _response) = if use_manual_connect {
            // Manual connection path: TCP -> (proxy tunnel) -> TLS -> cert pin check -> WebSocket
            let host = uri.host_str().unwrap_or("localhost");
            let port = uri.port().unwrap_or(if is_wss { 443 } else { 80 });

            // Step 1: Establish TCP stream (through proxy if configured)
            let tcp_stream = if let Some(ref proxy) = proxy_config {
                proxy.connect(host, port).await?
            } else {
                tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?
            };

            // Step 2: TLS handshake (if wss://)
            if is_wss {
                let tls_connector = Self::build_tls_connector(&self.config)
                    .await?
                    .or_else(|| {
                        native_tls::TlsConnector::builder()
                            .build()
                            .map_err(|e| {
                                anyhow::anyhow!("Failed to build default TLS connector: {}", e)
                            })
                            .ok()
                    })
                    .ok_or_else(|| anyhow::anyhow!("Could not construct default TLS connector"))?;

                let tokio_connector = tokio_native_tls::TlsConnector::from(tls_connector);
                let tls_stream = tokio_connector.connect(host, tcp_stream).await?;

                // Step 3: Certificate pinning verification
                if let Some(ref pins) = cert_pins {
                    // Extract the peer certificate from the TLS session
                    let peer_cert = tls_stream
                        .get_ref()
                        .peer_certificate()
                        .map_err(|e| anyhow::anyhow!("Failed to get peer certificate: {}", e))?;

                    if let Some(cert) = peer_cert {
                        let cert_der = cert.to_der().map_err(|e| {
                            anyhow::anyhow!("Failed to encode peer certificate to DER: {}", e)
                        })?;

                        if !pins.verify_cert_der(&cert_der) {
                            return Err(anyhow::anyhow!(
                                "Certificate pin verification failed: server certificate does not match any pinned hash"
                            ));
                        }
                        info!("Certificate pin verification passed");
                    } else if pins.is_enforcing() {
                        return Err(anyhow::anyhow!(
                            "Certificate pin verification failed: no peer certificate available"
                        ));
                    } else {
                        warn!("No peer certificate available for pin verification (non-enforcing mode, allowing)");
                    }
                }

                // Step 4: WebSocket upgrade over the already-established TLS stream
                let wrapped: tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream> =
                    tokio_tungstenite::MaybeTlsStream::NativeTls(tls_stream);
                tokio_tungstenite::client_async(uri.as_str(), wrapped).await?
            } else {
                // Plain WebSocket (ws://) through proxy
                let wrapped: tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream> =
                    tokio_tungstenite::MaybeTlsStream::Plain(tcp_stream);
                tokio_tungstenite::client_async(uri.as_str(), wrapped).await?
            }
        } else if is_wss && custom_tls_required {
            // Standard TLS path (no proxy, no cert pinning)
            debug!("Connecting with TLS");
            if self.config.tls.skip_verify {
                let connector = Self::build_tls_connector(&self.config).await?;
                let tls_connector = connector
                    .ok_or_else(|| anyhow::anyhow!("Could not construct TLS connector"))?;
                let native_connector = tokio_tungstenite::Connector::NativeTls(tls_connector);
                tokio_tungstenite::connect_async_tls_with_config(
                    uri,
                    None,
                    false,
                    Some(native_connector),
                )
                .await?
            } else if let Some(rustls_config) = Self::build_rustls_connector(&self.config).await? {
                let rustls_connector = tokio_tungstenite::Connector::Rustls(rustls_config);
                tokio_tungstenite::connect_async_tls_with_config(
                    uri,
                    None,
                    false,
                    Some(rustls_connector),
                )
                .await?
            } else {
                tokio_tungstenite::connect_async(uri).await?
            }
        } else {
            debug!("Connecting without custom TLS connector");
            tokio_tungstenite::connect_async(uri).await?
        };

        info!("WebSocket connected, joining Phoenix channel");

        let (mut write, mut read) = ws_stream.split();

        // Send Phoenix channel join message (V1 JSON format - object style)
        // Include agent config so the server can display settings in the UI
        let topic = format!("agent:{}", self.config.agent_id);
        let collector_status =
            crate::collectors::CollectorCapabilityStatus::from_config(&self.config);
        let config_payload = serde_json::json!({
            "config": {
                "performance_profile": self.config.performance_profile,
                "heartbeat_interval_seconds": self.config.heartbeat_interval_seconds,
                "batch_size": self.config.batch_size,
                "batch_timeout_seconds": self.config.batch_timeout_seconds,
                "yara_enabled": self.config.yara_enabled,
                "entropy_check_enabled": self.config.entropy_check_enabled,
                "entropy_threshold": self.config.entropy_threshold,
                "honeyfiles_enabled": self.config.honeyfiles_enabled,
                "local_analysis_enabled": self.config.local_analysis_enabled,
                "health_interval_seconds": self.config.health_interval_seconds,
                "excluded_paths": self.config.excluded_paths,
                "excluded_processes": self.config.excluded_processes,
                "collectors": {
                    "process_enabled": self.config.collectors.process_enabled,
                    "file_enabled": self.config.collectors.file_enabled,
                    "network_enabled": self.config.collectors.network_enabled,
                    "dns_enabled": self.config.collectors.dns_enabled,
                    "injection_enabled": self.config.collectors.injection_enabled,
                    "named_pipes_enabled": self.config.collectors.named_pipes_enabled,
                    "usb_enabled": self.config.collectors.usb_enabled,
                    "ransomware_canary_enabled": self.config.collectors.ransomware_canary_enabled,
                    "driver_blocklist_enabled": self.config.collectors.driver_blocklist_enabled,
                    "memory_enabled": self.config.collectors.memory_enabled,
                    "cloud_enabled": self.config.collectors.cloud_enabled,
                    "exploit_mitigation_enabled": self.config.collectors.exploit_mitigation_enabled,
                    "defense_evasion_enabled": self.config.collectors.defense_evasion_enabled,
                    "persistence_enabled": self.config.collectors.persistence_enabled,
                    "credential_theft_enabled": self.config.collectors.credential_theft_enabled,
                    "health_enabled": self.config.collectors.health_enabled
                },
                "collector_status": collector_status.clone(),
                "collector_capabilities": collector_status.supported_collectors.clone(),
                "enabled_collectors": collector_status.enabled_collectors.clone(),
                "policy_status": collector_status.policy.clone()
            }
        });
        let join_msg = serde_json::json!({
            "topic": topic,
            "event": "phx_join",
            "payload": config_payload,
            "ref": "1",
            "join_ref": "1"
        });
        write.send(Message::Text(join_msg.to_string())).await?;
        debug!(topic = %topic, "Sent phx_join message with config");

        // Wait for join response
        let join_timeout = tokio::time::Duration::from_secs(10);
        let join_result = tokio::time::timeout(join_timeout, async {
            while let Some(result) = read.next().await {
                match result {
                    Ok(Message::Text(text)) => {
                        debug!(msg = %text, "Received message during join");
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            // Phoenix V1 JSON response format: {"topic": "...", "event": "phx_reply", "payload": {...}, "ref": "1"}
                            let event = parsed.get("event").and_then(|e| e.as_str()).unwrap_or("");
                            if event == "phx_reply" {
                                let status = parsed
                                    .get("payload")
                                    .and_then(|p| p.get("status"))
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("");
                                if status == "ok" {
                                    info!("Successfully joined Phoenix channel");
                                    return Ok(());
                                } else {
                                    let reason = parsed
                                        .get("payload")
                                        .and_then(|p| p.get("response"))
                                        .and_then(|r| r.get("reason"))
                                        .and_then(|r| r.as_str())
                                        .unwrap_or("unknown");
                                    return Err(anyhow::anyhow!("Channel join failed: {}", reason));
                                }
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        return Err(anyhow::anyhow!("Connection closed during join"));
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("WebSocket error during join: {}", e));
                    }
                    _ => {}
                }
            }
            Err(anyhow::anyhow!("Stream ended before join response"))
        })
        .await;

        match join_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow::anyhow!("Timeout waiting for channel join response")),
        }

        info!("Connected to backend");
        self.clear_last_error().await;

        {
            let mut state = self.state.write().await;
            *state = ConnectionState::Connected;
        }
        {
            let mut last = self.last_heartbeat_at.write().await;
            *last = Some(Utc::now());
        }

        // Recreate stream from the split parts
        let (write, read) = (write, read);

        // Create channel for this connection's internal messages (heartbeat, etc)
        let (ws_tx, mut ws_rx) = mpsc::channel::<Message>(100);

        // Store ws_tx for sending messages
        let ws_tx_clone = ws_tx.clone();

        // Spawn message sender task that reads from channels:
        // 1. ws_rx: Internal messages (heartbeat, pong)
        // 2. priority_outgoing_rx: Live response / shell messages
        // 3. outgoing_rx: Application messages (telemetry, command responses)
        let mut write = write;
        let outgoing_rx_clone = self.outgoing_rx.clone();
        let priority_outgoing_rx_clone = self.priority_outgoing_rx.clone();
        let sender_state = self.state.clone();
        let heartbeat_interval_seconds = self.config.heartbeat_interval_seconds;
        let heartbeat_agent_id = self.config.agent_id.clone();
        let stale_guard_state = self.state.clone();
        let stale_guard_last_seen = self.last_heartbeat_at.clone();
        let stale_guard_tasks = self.connection_tasks.clone();
        let stale_guard_after = tokio::time::Duration::from_secs(
            (heartbeat_interval_seconds.clamp(1, 25) as u64 * 3).max(30),
        );
        let sender_handle = tokio::spawn(async move {
            let mut outgoing_rx = outgoing_rx_clone.write().await;
            let mut priority_outgoing_rx = priority_outgoing_rx_clone.write().await;
            // The Phoenix endpoint currently closes agent websockets after
            // 60s of inactivity. Use a transport-side upper bound so a stale
            // local config cannot make the connection look idle before the
            // first remote config update is applied.
            let heartbeat_interval_seconds = heartbeat_interval_seconds.clamp(1, 25);
            let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(
                heartbeat_interval_seconds as u64,
            ));
            heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Live-response shell output can produce sizeable bursts; a 5s write
            // timeout was too aggressive and dropped the socket (forcing a
            // reconnect) during long benchmark runs. 10s tolerates slow links and
            // large output bursts while still bounding hung writes.
            let send_timeout = tokio::time::Duration::from_secs(10);
            let mut heartbeat_ref: u64 = 100;
            let heartbeat_topic = format!("agent:{}", heartbeat_agent_id);
            info!(
                interval_seconds = heartbeat_interval_seconds,
                "WebSocket sender task started"
            );

            loop {
                tokio::select! {
                    biased;

                    // Keep the Phoenix transport and the agent channel alive.
                    _ = heartbeat_interval.tick() => {
                        heartbeat_ref += 1;
                        info!(ref_id = heartbeat_ref, "Sending Phoenix transport heartbeat");

                        let phoenix_heartbeat = serde_json::json!({
                            "topic": "phoenix",
                            "event": "heartbeat",
                            "payload": {},
                            "ref": heartbeat_ref.to_string()
                        });
                        match tokio::time::timeout(send_timeout, write.send(Message::Text(phoenix_heartbeat.to_string()))).await {
                            Ok(Ok(())) => {
                                debug!(ref_id = heartbeat_ref, "Phoenix transport heartbeat sent");
                            }
                            Ok(Err(e)) => {
                                error!(error = %e, "Failed to send Phoenix transport heartbeat");
                                break;
                            }
                            Err(_) => {
                                error!("Timed out sending Phoenix transport heartbeat");
                                break;
                            }
                        }

                        heartbeat_ref += 1;

                        let heartbeat = serde_json::json!({
                            "topic": heartbeat_topic,
                            "event": "heartbeat",
                            "payload": {
                                "timestamp": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                            },
                            "ref": heartbeat_ref.to_string(),
                            "join_ref": "1"
                        });
                        match tokio::time::timeout(send_timeout, write.send(Message::Text(heartbeat.to_string()))).await {
                            Ok(Ok(())) => {
                                debug!(ref_id = heartbeat_ref, "Agent channel heartbeat sent");
                            }
                            Ok(Err(e)) => {
                                error!(error = %e, "Failed to send agent heartbeat");
                                break;
                            }
                            Err(_) => {
                                error!("Timed out sending agent heartbeat");
                                break;
                            }
                        }

                        // Do not update last_heartbeat_at here. Stale
                        // detection is based on inbound ACK/message traffic
                        // from the backend, not on successful local writes.
                    }

                    // Receive from internal WebSocket channel (heartbeat, pong)
                    msg = ws_rx.recv() => {
                        match msg {
                            Some(m) => {
                                match tokio::time::timeout(send_timeout, write.send(m)).await {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => {
                                        error!(error = %e, "Failed to send WebSocket message");
                                        break;
                                    }
                                    Err(_) => {
                                        error!("Timed out sending WebSocket message");
                                        break;
                                    }
                                }
                            }
                            None => break,
                        }
                    }

                    // Prioritize live response / shell messages so telemetry
                    // bursts do not make an interactive terminal feel laggy.
                    msg = priority_outgoing_rx.recv() => {
                        match msg {
                            Some(m) => {
                                debug!("Sending priority application message to WebSocket");
                                match tokio::time::timeout(send_timeout, write.send(m)).await {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => {
                                        error!(error = %e, "Failed to send priority application message");
                                        break;
                                    }
                                    Err(_) => {
                                        error!("Timed out sending priority application message");
                                        break;
                                    }
                                }
                            }
                            None => break,
                        }
                    }

                    // Receive from application outgoing channel (telemetry, responses)
                    msg = outgoing_rx.recv() => {
                        match msg {
                            Some(m) => {
                                debug!("Sending application message to WebSocket");
                                match tokio::time::timeout(send_timeout, write.send(m)).await {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => {
                                        error!(error = %e, "Failed to send application message");
                                        break;
                                    }
                                    Err(_) => {
                                        error!("Timed out sending application message");
                                        break;
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            {
                let mut state = sender_state.write().await;
                if *state == ConnectionState::Connected {
                    *state = ConnectionState::Disconnected;
                }
            }
            warn!("WebSocket sender task exiting");
        });

        let stale_guard_handle = tokio::spawn(async move {
            info!(
                stale_after_seconds = stale_guard_after.as_secs(),
                "WebSocket stale guard started"
            );
            loop {
                tokio::time::sleep(stale_guard_after).await;

                if *stale_guard_state.read().await != ConnectionState::Connected {
                    break;
                }

                let last_seen = *stale_guard_last_seen.read().await;
                let stale = last_seen
                    .map(|last| {
                        Utc::now().signed_duration_since(last)
                            > chrono::Duration::from_std(stale_guard_after)
                                .unwrap_or_else(|_| chrono::Duration::seconds(75))
                    })
                    .unwrap_or(true);

                if !stale {
                    continue;
                }

                warn!(
                    stale_after_seconds = stale_guard_after.as_secs(),
                    "Connection heartbeat stale in connection guard, forcing reconnect"
                );

                {
                    let mut state = stale_guard_state.write().await;
                    if *state == ConnectionState::Connected {
                        *state = ConnectionState::Disconnected;
                    }
                }

                let mut tasks = stale_guard_tasks.write().await;
                for task in tasks.drain(..) {
                    task.abort();
                }
                break;
            }
        });

        // Spawn incoming message handler
        let command_tx = self.command_tx.clone();
        let config_tx = self.config_tx.clone();
        let ml_result_tx = self.ml_result_tx.clone();
        let ack_tx = self.ack_tx.clone();
        let state = self.state.clone();
        let reader_state = state.clone();
        let reader_last_seen = self.last_heartbeat_at.clone();
        let mut read = read;

        let reader_handle = tokio::spawn(async move {
            while let Some(result) = read.next().await {
                match result {
                    Ok(Message::Text(text)) => {
                        {
                            let mut last = reader_last_seen.write().await;
                            *last = Some(Utc::now());
                        }
                        if let Err(e) = Self::handle_message(
                            &text,
                            &command_tx,
                            &config_tx,
                            &ml_result_tx,
                            &ack_tx,
                        )
                        .await
                        {
                            warn!(error = %e, "Failed to handle message");
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        {
                            let mut last = reader_last_seen.write().await;
                            *last = Some(Utc::now());
                        }
                        // Decompress if zstd feature is enabled
                        #[cfg(feature = "compression")]
                        {
                            if let Ok(decompressed) = zstd::decode_all(data.as_slice()) {
                                if let Ok(text) = String::from_utf8(decompressed) {
                                    if let Err(e) = Self::handle_message(
                                        &text,
                                        &command_tx,
                                        &config_tx,
                                        &ml_result_tx,
                                        &ack_tx,
                                    )
                                    .await
                                    {
                                        warn!(error = %e, "Failed to handle decompressed message");
                                    }
                                }
                            }
                        }
                        #[cfg(not(feature = "compression"))]
                        {
                            // Without compression, try to parse binary as UTF-8 directly
                            if let Ok(text) = String::from_utf8(data) {
                                if let Err(e) = Self::handle_message(
                                    &text,
                                    &command_tx,
                                    &config_tx,
                                    &ml_result_tx,
                                    &ack_tx,
                                )
                                .await
                                {
                                    warn!(error = %e, "Failed to handle binary message");
                                }
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("Connection closed by server");
                        let terminated = crate::response::pty_bridge::terminate_all_sessions(
                            "Backend connection closed",
                        )
                        .await;
                        if terminated > 0 {
                            info!(
                                count = terminated,
                                "Terminated live response sessions after backend close"
                            );
                        }
                        let mut s = state.write().await;
                        *s = ConnectionState::Disconnected;
                        break;
                    }
                    Ok(Message::Ping(data)) => {
                        {
                            let mut last = reader_last_seen.write().await;
                            *last = Some(Utc::now());
                        }
                        // Respond with pong
                        let _ = ws_tx_clone.send(Message::Pong(data)).await;
                    }
                    Ok(Message::Pong(_)) => {
                        let mut last = reader_last_seen.write().await;
                        *last = Some(Utc::now());
                    }
                    Err(e) => {
                        error!(error = %e, "WebSocket error");
                        let terminated = crate::response::pty_bridge::terminate_all_sessions(
                            "Backend connection lost",
                        )
                        .await;
                        if terminated > 0 {
                            info!(
                                count = terminated,
                                "Terminated live response sessions after backend error"
                            );
                        }
                        let mut s = state.write().await;
                        *s = ConnectionState::Disconnected;
                        break;
                    }
                    _ => {}
                }
            }

            warn!("WebSocket reader task ended");

            let mut s = reader_state.write().await;
            if *s == ConnectionState::Connected {
                *s = ConnectionState::Disconnected;
            }
        });

        // Store abort handles so we can cancel these tasks on reconnect
        {
            let mut tasks = self.connection_tasks.write().await;
            tasks.push(sender_handle.abort_handle());
            tasks.push(stale_guard_handle.abort_handle());
            tasks.push(reader_handle.abort_handle());
        }

        // Notify waiters that reconnection completed (triggers full process refresh)
        if attempt > 0 {
            info!("Reconnection complete, notifying for full refresh");
            self.reconnect_notify.notify_waiters();
        }

        Ok(())
    }

    fn calculate_backoff(&self, attempt: u32) -> u64 {
        let base_delay = self.config.reconnect_delay_seconds as u64;
        let delay = base_delay * 2u64.pow(attempt.min(6)); // Cap at 2^6 = 64x base
        delay.min(60) // Max 60 seconds
    }

    async fn build_tls_connector(config: &AgentConfig) -> Result<Option<TlsConnector>> {
        let has_tls_material = config.tls.cert_path.is_some()
            || config.tls.key_path.is_some()
            || config.tls.ca_path.is_some()
            || config.tls.skip_verify;

        if !config.tls.enabled && !has_tls_material {
            return Ok(None);
        }

        let mut builder = TlsConnector::builder();

        // Handle client certificate for mTLS
        if let (Some(cert_path), Some(key_path)) = (&config.tls.cert_path, &config.tls.key_path) {
            let cert_bytes = tokio::fs::read(cert_path).await?;
            let key_bytes = tokio::fs::read(key_path).await?;

            let identity = if cert_bytes.starts_with(b"-----BEGIN") {
                Identity::from_pkcs8(&cert_bytes, &key_bytes)?
            } else {
                Identity::from_pkcs12(&cert_bytes, "")?
            };

            builder.identity(identity);
            info!("Loaded client certificate for mTLS");
        } else if config.tls.enabled {
            warn!("TLS is enabled but mTLS client cert/key paths are incomplete");
        }

        // Handle custom CA for server verification
        if let Some(ca_path) = &config.tls.ca_path {
            let ca_bytes = tokio::fs::read(ca_path).await?;
            let ca_cert = Certificate::from_pem(&ca_bytes)?;
            builder.add_root_certificate(ca_cert);
            info!("Loaded custom CA certificate");
        }

        // Handle skip_verify (DANGEROUS)
        if config.tls.skip_verify {
            warn!("TLS certificate verification is DISABLED. This is INSECURE and should ONLY be used for development/testing.");
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }

        Ok(Some(builder.build()?))
    }

    async fn build_rustls_connector(
        config: &AgentConfig,
    ) -> Result<Option<Arc<RustlsClientConfig>>> {
        let has_tls_material = config.tls.cert_path.is_some()
            || config.tls.key_path.is_some()
            || config.tls.ca_path.is_some();

        if !config.tls.enabled && !has_tls_material {
            return Ok(None);
        }

        let mut roots = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs()
            .context("Failed to load native root certificates")?;
        let mut native_loaded = 0usize;
        for cert in native_certs {
            if roots.add(cert).is_ok() {
                native_loaded += 1;
            }
        }

        if let Some(ca_path) = &config.tls.ca_path {
            let ca_bytes = tokio::fs::read(ca_path).await?;
            let mut reader = BufReader::new(Cursor::new(ca_bytes));
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("Failed to parse mTLS CA bundle PEM")?;
            let count = certs.len();
            for cert in certs {
                roots
                    .add(cert)
                    .context("Failed to add mTLS CA certificate to trust store")?;
            }
            info!(
                native = native_loaded,
                custom = count,
                "Loaded native and custom CA certificates for Rustls"
            );
        } else {
            info!(
                count = native_loaded,
                "Loaded native root certificates for Rustls"
            );
        }

        let builder = RustlsClientConfig::builder().with_root_certificates(roots);

        let client_config = if let (Some(cert_path), Some(key_path)) =
            (&config.tls.cert_path, &config.tls.key_path)
        {
            let cert_bytes = tokio::fs::read(cert_path).await?;
            let key_bytes = tokio::fs::read(key_path).await?;
            let cert_chain = Self::parse_rustls_cert_chain(&cert_bytes)?;
            let private_key = Self::parse_rustls_private_key(&key_bytes)?;

            info!(
                certs = cert_chain.len(),
                "Loaded client certificate for Rustls mTLS"
            );

            builder
                .with_client_auth_cert(cert_chain, private_key)
                .context("Failed to build Rustls mTLS client config")?
        } else {
            if config.tls.enabled {
                warn!("TLS is enabled but mTLS client cert/key paths are incomplete");
            }
            builder.with_no_client_auth()
        };

        Ok(Some(Arc::new(client_config)))
    }

    fn parse_rustls_cert_chain(cert_bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
        let mut reader = BufReader::new(Cursor::new(cert_bytes));
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to parse mTLS certificate PEM")?;

        if certs.is_empty() {
            anyhow::bail!("mTLS certificate PEM did not contain any certificates");
        }

        Ok(certs)
    }

    fn parse_rustls_private_key(key_bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
        let mut reader = BufReader::new(Cursor::new(key_bytes));
        let key = rustls_pemfile::private_key(&mut reader)
            .context("Failed to parse mTLS private key PEM")?
            .ok_or_else(|| anyhow::anyhow!("mTLS private key PEM block was not found"))?;

        Ok(key)
    }

    async fn handle_message(
        text: &str,
        command_tx: &mpsc::Sender<Command>,
        config_tx: &mpsc::Sender<ConfigUpdate>,
        ml_result_tx: &mpsc::Sender<MlScanResult>,
        ack_tx: &mpsc::Sender<DeliveryAck>,
    ) -> Result<()> {
        debug!(message = %text, "Received message from backend");

        // Try to parse as a backend message
        let parsed: serde_json::Value = serde_json::from_str(text)?;

        // Check message type - support both "type" and "event" fields (Phoenix Channel format)
        let msg_type = parsed
            .get("type")
            .or_else(|| parsed.get("event"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Get payload if present (Phoenix Channel wraps data in "payload")
        let payload = parsed.get("payload").cloned().unwrap_or(parsed.clone());

        match msg_type {
            "command" | "phx_reply" => {
                // For phx_reply, check if status is ok and get response
                if msg_type == "phx_reply" {
                    if payload.get("status").and_then(|v| v.as_str()) == Some("ok") {
                        if let Some(seq) = parsed
                            .get("ref")
                            .and_then(|v| v.as_str())
                            .and_then(|r| r.strip_prefix("telemetry:"))
                            .and_then(|r| r.parse::<u64>().ok())
                        {
                            let count = payload
                                .get("response")
                                .and_then(|r| r.get("received").or_else(|| r.get("count")))
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as usize;

                            let ack = DeliveryAck { seq, count };
                            if let Err(e) = ack_tx.send(ack).await {
                                warn!(error = %e, seq = seq, "Failed to forward telemetry phx_reply ACK to processor");
                            }
                        }
                    }

                    if let Some(response) = payload.get("response") {
                        if response.get("command_id").is_some() {
                            if let Ok(command) = serde_json::from_value::<Command>(response.clone())
                            {
                                info!(
                                    command_id = %command.command_id,
                                    command_type = ?command.command_type,
                                    "Received command from backend (phx_reply)"
                                );
                                command_tx.send(command).await?;
                            }
                        }
                    }
                } else {
                    // Parse command directly from payload
                    if let Ok(command) = serde_json::from_value::<Command>(payload.clone()) {
                        info!(
                            command_id = %command.command_id,
                            command_type = ?command.command_type,
                            "Received command from backend"
                        );
                        command_tx.send(command).await?;
                    }
                }
            }
            "config" | "config_update" => {
                info!("Received configuration update");

                // Extract config and rules from payload
                let config = payload
                    .get("config")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                let yara_rules = payload
                    .get("yara_rules")
                    .and_then(|v| v.as_array())
                    .cloned();
                let sigma_rules = payload
                    .get("sigma_rules")
                    .and_then(|v| v.as_array())
                    .cloned();
                let iocs = payload.get("iocs").and_then(|v| v.as_array()).cloned();

                let update = ConfigUpdate {
                    config,
                    yara_rules,
                    sigma_rules,
                    iocs,
                };

                if let Err(e) = config_tx.send(update).await {
                    error!(error = %e, "Failed to send config update");
                } else {
                    info!("Configuration update queued for processing");
                }
            }
            "rules_update" => {
                info!("Received rules update");

                // Rules update is a subset of config update
                let yara_rules = payload
                    .get("yara_rules")
                    .and_then(|v| v.as_array())
                    .cloned();
                let sigma_rules = payload
                    .get("sigma_rules")
                    .and_then(|v| v.as_array())
                    .cloned();
                let iocs = payload.get("iocs").and_then(|v| v.as_array()).cloned();

                let update = ConfigUpdate {
                    config: serde_json::json!({}),
                    yara_rules,
                    sigma_rules,
                    iocs,
                };

                if let Err(e) = config_tx.send(update).await {
                    error!(error = %e, "Failed to send rules update");
                } else {
                    info!("Rules update queued for processing");
                }
            }
            "fim_policies" => {
                info!("Received FIM policies update");
                if let Err(e) = crate::config::handle_fim_policies_update(&payload).await {
                    error!(error = %e, "Failed to update FIM policies");
                } else {
                    info!("FIM policies update processed successfully");
                }
            }
            "ml_scan_result" | "ml_result" => {
                info!("Received ML scan result");

                // Parse ML scan result
                if let Ok(result) = serde_json::from_value::<MlScanResult>(payload) {
                    info!(
                        sha256 = %result.sha256,
                        is_malicious = result.is_malicious,
                        confidence = result.confidence,
                        classification = ?result.classification,
                        "ML scan result received"
                    );
                    if let Err(e) = ml_result_tx.send(result).await {
                        error!(error = %e, "Failed to send ML scan result");
                    }
                } else {
                    warn!("Failed to parse ML scan result payload");
                }
            }
            "heartbeat_ack" | "heartbeat" | "phx_heartbeat" => {
                debug!("Heartbeat acknowledged");
            }
            "telemetry:ack" | "telemetry_ack" => {
                // Server acknowledges receipt of a telemetry batch
                let seq = payload.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let count = payload.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                debug!(
                    seq = seq,
                    count = count,
                    "Received telemetry ACK from server"
                );

                if seq > 0 {
                    let ack = DeliveryAck { seq, count };
                    if let Err(e) = ack_tx.send(ack).await {
                        warn!(error = %e, seq = seq, "Failed to forward telemetry ACK to processor");
                    }
                }
            }
            "error" | "phx_error" => {
                let message = payload
                    .get("message")
                    .or_else(|| payload.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                error!(message = %message, "Error from backend");
            }
            _ => {
                // Try to parse as command directly (command_id + command_type present)
                if payload.get("command_id").is_some() && payload.get("command_type").is_some() {
                    if let Ok(command) = serde_json::from_value::<Command>(payload) {
                        info!(
                            command_id = %command.command_id,
                            command_type = ?command.command_type,
                            "Received command from backend (direct)"
                        );
                        command_tx.send(command).await?;
                    }
                } else if !msg_type.is_empty() && !msg_type.starts_with("phx_") {
                    debug!(msg_type = %msg_type, "Unknown message type");
                }
            }
        }

        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from backend");

        // Signal shutdown to background tasks
        self.shutdown.store(true, Ordering::Relaxed);

        // Re-queue any in-flight batches back into the local queue so they
        // are persisted to disk and can be retried after restart.
        {
            let mut in_flight = self.in_flight.write().await;
            if !in_flight.is_empty() {
                let mut queue = self.local_queue.write().await;
                let batch_count = in_flight.len();
                let mut event_count = 0usize;
                for (_seq, batch) in in_flight.drain() {
                    event_count += batch.events.len();
                    queue.push_batch(batch.events);
                }
                info!(
                    batches = batch_count,
                    events = event_count,
                    "Re-queued in-flight batches for persistence"
                );
            }
        }

        // Persist any remaining queued events (including re-queued in-flight ones)
        let queue = self.local_queue.read().await;
        if !queue.is_empty() {
            info!(
                count = queue.len(),
                "Persisting queued events before shutdown"
            );
            if let Err(e) = queue.persist_to_disk() {
                error!(error = %e, "Failed to persist event queue during shutdown");
            }
        }

        let mut state = self.state.write().await;
        *state = ConnectionState::Disconnected;
        Ok(())
    }

    /// Get current connection state
    pub async fn get_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == ConnectionState::Connected
    }

    /// Get the reconnect notify handle.
    /// Callers can `notified().await` on this to be woken when a reconnection
    /// completes, then perform a full refresh (e.g. re-enumerate all processes).
    pub fn reconnect_notify(&self) -> Arc<tokio::sync::Notify> {
        self.reconnect_notify.clone()
    }

    /// Try to receive a config update (non-blocking)
    pub async fn try_receive_config_update(&self) -> Option<ConfigUpdate> {
        let mut rx = self.config_rx.write().await;
        rx.try_recv().ok()
    }

    /// Receive next config update from backend
    pub async fn receive_config_update(&self) -> Result<ConfigUpdate> {
        let mut rx = self.config_rx.write().await;
        match rx.recv().await {
            Some(update) => {
                info!("Config update received");
                Ok(update)
            }
            None => Err(anyhow::anyhow!("Config channel closed")),
        }
    }

    /// Send telemetry events to backend, queuing locally if disconnected
    pub async fn send_telemetry(&self, events: &[TelemetryEvent]) -> Result<()> {
        // If not connected, queue events locally for later sync
        if !self.is_connected().await {
            self.queue_events_locally(events).await;
            return Ok(());
        }

        // Connected - try to send with a timeout to detect stale connections.
        // If the outgoing channel is full (sender task dead / connection stale),
        // we don't want to block the main event loop forever.
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            self.send_telemetry_direct(events),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                warn!(error = %e, "Failed to send telemetry, queuing locally");
                // Mark as disconnected so reconnect monitor picks up
                {
                    let mut state = self.state.write().await;
                    *state = ConnectionState::Disconnected;
                }
                self.queue_events_locally(events).await;
                Ok(())
            }
            Err(_timeout) => {
                warn!("Telemetry send timed out (stale connection), queuing locally");
                // Connection is stale — mark disconnected
                {
                    let mut state = self.state.write().await;
                    *state = ConnectionState::Disconnected;
                }
                self.queue_events_locally(events).await;
                Ok(())
            }
        }
    }

    /// Send latency-sensitive telemetry without agent-side triage.
    ///
    /// This is intentionally narrow: benchmark markers and short-lived process
    /// evidence must be delivered exactly once through the ACK-tracked path, not
    /// sampled/deduplicated by local volume controls.
    pub async fn send_telemetry_without_triage(&self, events: &[TelemetryEvent]) -> Result<()> {
        if !self.is_connected().await {
            self.queue_events_locally(events).await;
            return Ok(());
        }

        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            self.send_telemetry_direct_without_triage(events),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                warn!(
                    error = %e,
                    "Failed to send no-triage telemetry, queuing locally"
                );
                {
                    let mut state = self.state.write().await;
                    *state = ConnectionState::Disconnected;
                }
                self.queue_events_locally(events).await;
                Ok(())
            }
            Err(_timeout) => {
                warn!("No-triage telemetry send timed out, queuing locally");
                {
                    let mut state = self.state.write().await;
                    *state = ConnectionState::Disconnected;
                }
                self.queue_events_locally(events).await;
                Ok(())
            }
        }
    }

    /// Queue events into the local offline buffer
    async fn queue_events_locally(&self, events: &[TelemetryEvent]) {
        let mut queue = self.local_queue.write().await;
        let force_persist = events.iter().any(|event| {
            event
                .metadata
                .get("offline_sync")
                .is_some_and(|value| value == "true")
        });
        queue.push_batch(events.to_vec());
        debug!(
            count = events.len(),
            queue_size = queue.len(),
            "Queued events locally"
        );

        // Periodically persist to disk. Offline verdict sync events are already
        // ACKed at the detector once accepted by transport, so force persistence
        // when they fall back to the local queue.
        if force_persist || queue.len() % 100 == 0 {
            if let Err(e) = queue.persist_to_disk() {
                warn!(error = %e, "Failed to persist event queue");
            }
        }
    }

    /// Send telemetry directly without queueing (used for sync).
    ///
    /// Assigns a monotonic sequence number, sends the batch on the wire,
    /// and registers it as in-flight so the ACK processor can track it.
    /// If the in-flight buffer is full (MAX_IN_FLIGHT_BATCHES), falls back
    /// to fire-and-forget to avoid memory leaks.
    async fn send_telemetry_direct(&self, events: &[TelemetryEvent]) -> Result<()> {
        self.send_telemetry_direct_inner(events, true).await
    }

    async fn send_telemetry_direct_without_triage(&self, events: &[TelemetryEvent]) -> Result<()> {
        self.send_telemetry_direct_inner(events, false).await
    }

    async fn send_telemetry_direct_inner(
        &self,
        events: &[TelemetryEvent],
        apply_triage: bool,
    ) -> Result<()> {
        // Apply agent-side event triage to reduce telemetry volume 85-95%
        let filtered_events = if apply_triage {
            let mut triage = self.triage.write().await;
            let filtered = triage.filter_batch(events.to_vec());

            // Emit triage stats periodically
            if triage.should_emit_stats() {
                let stats = triage.stats();
                debug!(
                    received = stats.events_received,
                    passed = stats.events_passed,
                    deduped = stats.events_deduplicated,
                    sampled_out = stats.events_sampled_out,
                    reduction = format!("{:.1}%", stats.reduction_ratio() * 100.0),
                    "triage stats"
                );
                triage.mark_stats_emitted();
            }

            filtered
        } else {
            events.to_vec()
        };

        // If all events were filtered out, return early
        if filtered_events.is_empty() {
            debug!("All events filtered by triage, skipping send");
            return Ok(());
        }

        let seq = self.batch_seq.fetch_add(1, Ordering::Relaxed);

        let track_delivery_acks = Self::telemetry_ack_tracking_enabled();

        // Check whether the in-flight buffer is at capacity. ACK tracking is
        // optional because older/cloud backends may accept telemetry without
        // emitting telemetry ACKs. In that case, retry storms can starve live
        // response control messages on the shared websocket.
        let in_flight_full = if track_delivery_acks {
            let in_flight = self.in_flight.read().await;
            in_flight.len() >= MAX_IN_FLIGHT_BATCHES
        } else {
            false
        };

        if in_flight_full {
            warn!(
                seq = seq,
                in_flight_max = MAX_IN_FLIGHT_BATCHES,
                "In-flight buffer full, sending batch fire-and-forget (no ACK tracking)"
            );
        }

        // Send the batch on the wire
        self.send_telemetry_wire(&filtered_events, seq).await?;

        // Update sent stats
        {
            let mut stats = self.delivery_stats.write().await;
            stats.events_sent += filtered_events.len() as u64;
        }

        // Register in in-flight map for ACK tracking only when explicitly
        // enabled and the buffer has room.
        if track_delivery_acks && !in_flight_full {
            let mut in_flight = self.in_flight.write().await;
            in_flight.insert(
                seq,
                InFlightBatch {
                    seq,
                    events: filtered_events.clone(),
                    sent_at: tokio::time::Instant::now(),
                    retry_count: 0,
                },
            );

            let mut stats = self.delivery_stats.write().await;
            stats.in_flight_batches = in_flight.len();
        }

        debug!(
            seq = seq,
            count = filtered_events.len(),
            "Sent telemetry batch (after triage)"
        );
        Ok(())
    }

    /// Low-level wire send: serializes events into a Phoenix V1 JSON message
    /// and pushes it into the outgoing channel.
    ///
    /// This is separate from `send_telemetry_direct` so it can be reused for
    /// retries without re-registering the in-flight entry.
    async fn send_telemetry_wire(&self, events: &[TelemetryEvent], seq: u64) -> Result<()> {
        let topic = format!("agent:{}", self.config.agent_id);

        // Phoenix V1 JSON format with seq for ACK correlation
        let batch = serde_json::json!({
            "topic": topic,
            "event": "telemetry",
            "payload": {
                "events": events,
                "seq": seq,
                "batch_timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            },
            "ref": format!("telemetry:{}", seq),
            "join_ref": "1"
        });

        let batch_str = batch.to_string();
        let msg = Message::Text(batch_str);

        self.outgoing_tx.send(msg).await?;
        Ok(())
    }

    /// Get the number of events currently queued locally
    pub async fn get_queue_size(&self) -> usize {
        self.local_queue.read().await.len()
    }

    /// Get a snapshot of delivery statistics
    pub async fn get_delivery_stats(&self) -> DeliveryStats {
        self.delivery_stats.read().await.clone()
    }

    /// Get the last heartbeat timestamp queued to the backend WebSocket.
    pub async fn get_last_heartbeat_at(&self) -> Option<DateTime<Utc>> {
        *self.last_heartbeat_at.read().await
    }

    /// Get the last backend transport error observed by the connection loop.
    pub async fn get_last_error(&self) -> Option<String> {
        self.last_error.read().await.clone()
    }

    async fn set_last_error(&self, error: String) {
        let mut last_error = self.last_error.write().await;
        *last_error = Some(error);
    }

    async fn clear_last_error(&self) {
        let mut last_error = self.last_error.write().await;
        *last_error = None;
    }

    /// Receive next command from backend
    ///
    /// Returns Ok(command) when a command is received, or waits for the next one.
    /// Use with timeout for non-blocking behavior.
    pub async fn receive_command(&self) -> Result<Command> {
        let mut rx = self.command_rx.write().await;

        match rx.recv().await {
            Some(command) => {
                info!(
                    command_id = %command.command_id,
                    command_type = ?command.command_type,
                    "Command received"
                );
                Ok(command)
            }
            None => Err(anyhow::anyhow!("Command channel closed")),
        }
    }

    /// Try to receive a command with timeout
    pub async fn try_receive_command(&self, timeout: std::time::Duration) -> Option<Command> {
        tokio::time::timeout(timeout, self.receive_command())
            .await
            .ok()
            .and_then(|r| r.ok())
    }

    pub async fn send_command_response(
        &self,
        command: &Command,
        result: CommandResult,
    ) -> Result<()> {
        static MSG_REF: AtomicU64 = AtomicU64::new(2000);

        let topic = format!("agent:{}", self.config.agent_id);
        let msg_ref = MSG_REF.fetch_add(1, Ordering::Relaxed);

        // Phoenix V1 JSON format: {"topic": "...", "event": "...", "payload": {...}, "ref": "..."}
        let response = serde_json::json!({
            "topic": topic,
            "event": "command_response",
            "payload": {
                "command_id": command.command_id,
                "success": result.success,
                "error_message": result.error_message,
                "result_data": result.result_data,
                "executed_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            },
            "ref": msg_ref.to_string(),
            "join_ref": "1"
        });

        let msg = Message::Text(response.to_string());
        if command.command_id.starts_with("rt_") {
            self.priority_outgoing_tx.send(msg).await?;
        } else {
            self.outgoing_tx.send(msg).await?;
        }

        debug!(
            command_id = %command.command_id,
            success = result.success,
            "Sent command response"
        );

        Ok(())
    }

    pub async fn send_binary_sample(
        &self,
        path: &str,
        sha256: &[u8],
        content: &[u8],
    ) -> Result<()> {
        use base64::Engine;
        static MSG_REF: AtomicU64 = AtomicU64::new(3000);

        let topic = format!("agent:{}", self.config.agent_id);
        let msg_ref = MSG_REF.fetch_add(1, Ordering::Relaxed);

        // Phoenix V1 JSON format: {"topic": "...", "event": "...", "payload": {...}, "ref": "..."}
        let sample = serde_json::json!({
            "topic": topic,
            "event": "binary_sample",
            "payload": {
                "file_path": path,
                "sha256": hex::encode(sha256),
                "content": base64::engine::general_purpose::STANDARD.encode(content),
                "total_size": content.len(),
            },
            "ref": msg_ref.to_string(),
            "join_ref": "1"
        });

        let msg = Message::Text(sample.to_string());
        self.outgoing_tx.send(msg).await?;

        debug!(path = %path, "Sent binary sample for analysis");

        Ok(())
    }

    /// Send a sample submission for ML analysis
    /// Send logs to backend server
    pub async fn send_logs(&self, payload: serde_json::Value) -> Result<()> {
        static MSG_REF: AtomicU64 = AtomicU64::new(5000);

        let topic = format!("agent:{}", self.config.agent_id);
        let msg_ref = MSG_REF.fetch_add(1, Ordering::SeqCst).to_string();

        let message = serde_json::json!({
            "topic": topic,
            "event": "logs",
            "payload": payload,
            "ref": msg_ref
        });

        let msg_text = serde_json::to_string(&message)?;
        let ws_message = Message::Text(msg_text);

        // Send via websocket
        self.outgoing_tx.send(ws_message).await?;

        Ok(())
    }

    /// Send shell output to backend (for PTY streaming)
    ///
    /// This streams terminal output back to the server for interactive shell sessions.
    pub async fn send_shell_output(
        &self,
        _session_id: &str,
        output: &crate::response::pty_bridge::PtyOutput,
    ) -> Result<()> {
        static MSG_REF: AtomicU64 = AtomicU64::new(6000);

        let topic = format!("agent:{}", self.config.agent_id);
        let msg_ref = MSG_REF.fetch_add(1, Ordering::Relaxed);

        let payload = serde_json::to_value(output)?;

        let message = serde_json::json!({
            "topic": topic,
            "event": "shell_output",
            "payload": payload,
            "ref": msg_ref.to_string(),
            "join_ref": "1"
        });

        let msg = Message::Text(message.to_string());
        self.priority_outgoing_tx.send(msg).await?;

        Ok(())
    }

    /// Send shell data output (optimized for frequent small messages)
    pub async fn send_shell_data(&self, session_id: &str, data: &str) -> Result<()> {
        static MSG_REF: AtomicU64 = AtomicU64::new(6000);

        let topic = format!("agent:{}", self.config.agent_id);
        let msg_ref = MSG_REF.fetch_add(1, Ordering::Relaxed);

        let message = serde_json::json!({
            "topic": topic,
            "event": "shell_output",
            "payload": {
                "type": "data",
                "session_id": session_id,
                "data": data
            },
            "ref": msg_ref.to_string(),
            "join_ref": "1"
        });

        let msg = Message::Text(message.to_string());
        self.priority_outgoing_tx.send(msg).await?;

        Ok(())
    }

    pub async fn send_sample_submission(&self, submission: &SampleSubmission) -> Result<()> {
        static MSG_REF: AtomicU64 = AtomicU64::new(4000);

        let topic = format!("agent:{}", self.config.agent_id);
        let msg_ref = MSG_REF.fetch_add(1, Ordering::Relaxed);

        // Phoenix V1 JSON format for sample_submit event
        let sample_msg = serde_json::json!({
            "topic": topic,
            "event": "sample_submit",
            "payload": {
                "sha256": submission.sha256,
                "sha1": submission.sha1,
                "md5": submission.md5,
                "file_path": submission.file_path,
                "file_type": submission.file_type,
                "entropy": submission.entropy,
                "content": submission.content,
                "size": submission.size,
                "is_pe": submission.is_pe,
                "is_elf": submission.is_elf,
                "is_macho": submission.is_macho,
                "is_signed": submission.is_signed,
                "signer": submission.signer,
                "created_at": submission.created_at,
                "modified_at": submission.modified_at,
                "submitted_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            },
            "ref": msg_ref.to_string(),
            "join_ref": "1"
        });

        let msg = Message::Text(sample_msg.to_string());
        self.outgoing_tx.send(msg).await?;

        info!(
            sha256 = %submission.sha256,
            file_type = %submission.file_type,
            size = submission.size,
            "Sent sample for ML analysis"
        );

        Ok(())
    }

    /// Try to receive an ML scan result (non-blocking)
    pub async fn try_receive_ml_result(&self) -> Option<MlScanResult> {
        let mut rx = self.ml_result_rx.write().await;
        rx.try_recv().ok()
    }

    /// Receive next ML scan result from backend
    pub async fn receive_ml_result(&self) -> Result<MlScanResult> {
        let mut rx = self.ml_result_rx.write().await;
        match rx.recv().await {
            Some(result) => {
                info!(
                    sha256 = %result.sha256,
                    is_malicious = result.is_malicious,
                    "ML scan result received"
                );
                Ok(result)
            }
            None => Err(anyhow::anyhow!("ML result channel closed")),
        }
    }
}
