use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use tracing::warn;

use super::TelemetryEvent;

const DEFAULT_MAX_EVENTS: usize = 5_000;

#[derive(Debug, Clone)]
pub struct EventStore {
    path: PathBuf,
    max_events: usize,
}

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub event_types: Option<Vec<String>>,
    pub severities: Option<Vec<String>>,
    pub search: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl EventStore {
    pub fn new_default() -> Result<Self> {
        Self::new(default_event_store_path(), DEFAULT_MAX_EVENTS)
    }

    pub fn new(path: PathBuf, max_events: usize) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create event store dir {}", parent.display())
            })?;
        }

        let store = Self { path, max_events };
        store.with_connection(|conn| init_schema(conn))?;
        Ok(store)
    }

    pub fn insert(&self, event: &TelemetryEvent) -> Result<()> {
        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;
        self.with_connection(|conn| {
            conn.execute(
                r#"
                INSERT OR REPLACE INTO events (
                    id, timestamp, event_type, severity, agent_id, hostname,
                    message, process_name, file_path, remote_ip, event_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    event.id,
                    event.timestamp.to_rfc3339(),
                    event.event_type,
                    event.severity,
                    event.agent_id,
                    event.hostname,
                    event.message,
                    event.process_name,
                    event.file_path,
                    event.remote_ip,
                    event_json,
                ],
            )?;

            prune_events(conn, self.max_events)?;
            Ok(())
        })
    }

    pub fn query(&self, query: EventQuery) -> Result<Vec<TelemetryEvent>> {
        self.with_connection(|conn| {
            // Avoid depending on secondary indexes while reading GUI history. If an
            // index is damaged by a crash, a full table scan can still salvage valid
            // rows instead of making the whole Event History page empty.
            let mut stmt =
                conn.prepare("SELECT event_json FROM events NOT INDEXED ORDER BY timestamp DESC")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

            let mut events = Vec::new();
            let offset = query.offset.unwrap_or(0);
            let limit = query.limit;
            let mut matched = 0usize;

            for row in rows {
                let raw = match row {
                    Ok(raw) => raw,
                    Err(error) => {
                        warn!(error = %error, "Skipping unreadable persisted event row");
                        continue;
                    }
                };
                let event: TelemetryEvent = match serde_json::from_str(&raw) {
                    Ok(event) => event,
                    Err(error) => {
                        warn!(error = %error, "Skipping invalid persisted event JSON");
                        continue;
                    }
                };

                if !matches_query(&event, &query) {
                    continue;
                }

                if matched < offset {
                    matched += 1;
                    continue;
                }

                if limit.map(|limit| events.len() >= limit).unwrap_or(false) {
                    break;
                }

                matched += 1;
                events.push(event);
            }

            Ok(events)
        })
    }

    pub fn get(&self, event_id: &str) -> Result<Option<TelemetryEvent>> {
        self.with_connection(|conn| {
            let raw = conn
                .query_row(
                    "SELECT event_json FROM events WHERE id = ?1",
                    params![event_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;

            raw.map(|value| serde_json::from_str(&value).context("Failed to deserialize event"))
                .transpose()
        })
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<TelemetryEvent>> {
        self.query(EventQuery {
            limit: Some(limit),
            ..EventQuery::default()
        })
    }

    fn with_connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("Failed to open event store {}", self.path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        f(&conn)
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            message TEXT NOT NULL,
            process_name TEXT,
            file_path TEXT,
            remote_ip TEXT,
            event_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        "#,
    )?;
    Ok(())
}

fn prune_events(conn: &Connection, max_events: usize) -> Result<()> {
    conn.execute(
        r#"
        DELETE FROM events
        WHERE id IN (
            SELECT id FROM events
            ORDER BY timestamp DESC
            LIMIT -1 OFFSET ?1
        )
        "#,
        params![max_events as i64],
    )?;
    Ok(())
}

fn matches_query(event: &TelemetryEvent, query: &EventQuery) -> bool {
    if let Some(types) = &query.event_types {
        if !types.is_empty()
            && !types
                .iter()
                .any(|t| event_matches_type_filter(&event.event_type, t))
        {
            return false;
        }
    }

    if let Some(severities) = &query.severities {
        if !severities.is_empty()
            && !severities
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&event.severity))
        {
            return false;
        }
    }

    if let Some(from) = query.date_from {
        if event.timestamp < from {
            return false;
        }
    }

    if let Some(to) = query.date_to {
        if event.timestamp > to {
            return false;
        }
    }

    if let Some(search) = &query.search {
        let term = search.to_lowercase();
        let haystack = format!(
            "{} {} {} {} {} {}",
            event.message,
            event.event_type,
            event.hostname,
            event.process_name.as_deref().unwrap_or_default(),
            event.file_path.as_deref().unwrap_or_default(),
            event.remote_ip.as_deref().unwrap_or_default()
        )
        .to_lowercase();

        if !haystack.contains(&term) {
            return false;
        }
    }

    true
}

fn event_matches_type_filter(event_type: &str, filter: &str) -> bool {
    if event_type == filter {
        return true;
    }

    match filter {
        "process" => event_type.starts_with("process_"),
        "file" => event_type.starts_with("file_"),
        "network" => {
            event_type.starts_with("network_")
                || event_type.starts_with("dns_")
                || matches!(
                    event_type,
                    "connection" | "connection_start" | "connection_end" | "dns_query"
                )
        }
        "registry" => event_type.starts_with("registry_"),
        "alert" => event_type.starts_with("alert_") || event_type.contains("detection"),
        "response" => event_type.starts_with("response_") || event_type.starts_with("remediation_"),
        "system" => {
            event_type.starts_with("system_")
                || event_type.starts_with("security_")
                || event_type.ends_with("_audit")
        }
        _ => false,
    }
}

fn default_event_store_path() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Tamandua")
            .join("event_history.sqlite")
    }

    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/Application Support/Tamandua").join("event_history.sqlite")
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Path::new("/var/lib/tamandua").join("event_history.sqlite")
    }
}
