//! TCC (Transparency, Consent, and Control) database parser
//!
//! Parses macOS TCC.db (SQLite) to extract permission grants/denials for
//! privacy-sensitive resources like camera, microphone, contacts, etc.
//!
//! TCC database locations:
//! - System: /Library/Application Support/com.apple.TCC/TCC.db
//! - User: ~/Library/Application Support/com.apple.TCC/TCC.db
//!
//! Schema (simplified):
//! ```sql
//! CREATE TABLE access (
//!   service TEXT NOT NULL,
//!   client TEXT NOT NULL,
//!   client_type INTEGER NOT NULL,
//!   auth_value INTEGER NOT NULL,
//!   auth_reason INTEGER NOT NULL,
//!   last_modified INTEGER NOT NULL
//! );
//! ```

use rusqlite::{Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, warn};

/// TCC service identifiers (privacy-sensitive resources)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TccService {
    /// Camera access
    Camera,
    /// Microphone access
    Microphone,
    /// Contacts access
    Contacts,
    /// Photos library access
    Photos,
    /// Calendar access
    Calendar,
    /// Reminders access
    Reminders,
    /// Full Disk Access
    FullDiskAccess,
    /// Screen Recording
    ScreenCapture,
    /// Accessibility
    Accessibility,
    /// Location Services
    Location,
    /// Automation (AppleEvents)
    AppleEvents,
    /// SystemPolicyAllFiles (Files and Folders)
    SystemPolicyAllFiles,
    /// File Provider (iCloud Drive)
    FileProvider,
    /// Media Library
    MediaLibrary,
    /// Bluetooth
    Bluetooth,
    /// Unknown/custom service
    Unknown(String),
}

impl From<&str> for TccService {
    fn from(s: &str) -> Self {
        match s {
            "kTCCServiceCamera" => Self::Camera,
            "kTCCServiceMicrophone" => Self::Microphone,
            "kTCCServiceAddressBook" => Self::Contacts,
            "kTCCServicePhotos" => Self::Photos,
            "kTCCServiceCalendar" => Self::Calendar,
            "kTCCServiceReminders" => Self::Reminders,
            "kTCCServiceSystemPolicyAllFiles" => Self::FullDiskAccess,
            "kTCCServiceScreenCapture" => Self::ScreenCapture,
            "kTCCServiceAccessibility" => Self::Accessibility,
            "kTCCServiceLocation" => Self::Location,
            "kTCCServiceAppleEvents" => Self::AppleEvents,
            "kTCCServiceFileProviderDomain" => Self::FileProvider,
            "kTCCServiceMediaLibrary" => Self::MediaLibrary,
            "kTCCServiceBluetooth" => Self::Bluetooth,
            _ => Self::Unknown(s.to_string()),
        }
    }
}

impl TccService {
    /// Convert to string representation
    pub fn as_str(&self) -> &str {
        match self {
            Self::Camera => "kTCCServiceCamera",
            Self::Microphone => "kTCCServiceMicrophone",
            Self::Contacts => "kTCCServiceAddressBook",
            Self::Photos => "kTCCServicePhotos",
            Self::Calendar => "kTCCServiceCalendar",
            Self::Reminders => "kTCCServiceReminders",
            Self::FullDiskAccess => "kTCCServiceSystemPolicyAllFiles",
            Self::ScreenCapture => "kTCCServiceScreenCapture",
            Self::Accessibility => "kTCCServiceAccessibility",
            Self::Location => "kTCCServiceLocation",
            Self::AppleEvents => "kTCCServiceAppleEvents",
            Self::SystemPolicyAllFiles => "kTCCServiceSystemPolicyAllFiles",
            Self::FileProvider => "kTCCServiceFileProviderDomain",
            Self::MediaLibrary => "kTCCServiceMediaLibrary",
            Self::Bluetooth => "kTCCServiceBluetooth",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Human-readable name
    pub fn display_name(&self) -> &str {
        match self {
            Self::Camera => "Camera",
            Self::Microphone => "Microphone",
            Self::Contacts => "Contacts",
            Self::Photos => "Photos",
            Self::Calendar => "Calendar",
            Self::Reminders => "Reminders",
            Self::FullDiskAccess => "Full Disk Access",
            Self::ScreenCapture => "Screen Recording",
            Self::Accessibility => "Accessibility",
            Self::Location => "Location Services",
            Self::AppleEvents => "Automation",
            Self::SystemPolicyAllFiles => "Files and Folders",
            Self::FileProvider => "iCloud Drive",
            Self::MediaLibrary => "Media Library",
            Self::Bluetooth => "Bluetooth",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// TCC authorization value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum TccAuthValue {
    /// Permission denied
    Denied = 0,
    /// Permission allowed
    Allowed = 2,
    /// Unknown state (represents values outside 0/2, which may exist in future macOS versions)
    Unknown = -1,
}

impl From<i32> for TccAuthValue {
    fn from(val: i32) -> Self {
        match val {
            0 => Self::Denied,
            2 => Self::Allowed,
            _ => Self::Unknown,
        }
    }
}

impl TccAuthValue {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Denied => "denied",
            Self::Allowed => "allowed",
            Self::Unknown => "unknown",
        }
    }
}

/// TCC client type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum TccClientType {
    /// Bundle identifier
    BundleId = 0,
    /// Absolute path
    AbsolutePath = 1,
}

impl From<i32> for TccClientType {
    fn from(val: i32) -> Self {
        match val {
            0 => Self::BundleId,
            1 => Self::AbsolutePath,
            _ => Self::BundleId, // Default fallback
        }
    }
}

/// TCC database entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccEntry {
    /// Service (privacy resource)
    pub service: TccService,
    /// Client identifier (bundle ID or path)
    pub client: String,
    /// Client type (bundle ID vs path)
    pub client_type: TccClientType,
    /// Authorization value (allowed/denied)
    pub auth_value: TccAuthValue,
    /// Authorization reason code
    pub auth_reason: i32,
    /// Last modified timestamp (seconds since epoch)
    pub last_modified: i64,
    /// Indirect object identifier (optional, for AppleEvents target)
    pub indirect_object_identifier: Option<String>,
    /// Indirect object code signature (optional)
    pub indirect_object_code_identity: Option<String>,
}

/// Parse the TCC database and return all entries
///
/// ## Arguments
/// * `db_path` - Path to TCC.db file
///
/// ## Returns
/// * `Ok(Vec<TccEntry>)` - Parsed entries
/// * `Err(rusqlite::Error)` - Database read error
pub fn parse_tcc_db<P: AsRef<Path>>(db_path: P) -> SqliteResult<Vec<TccEntry>> {
    let path = db_path.as_ref();
    debug!(path = %path.display(), "Parsing TCC database");

    // Open database in read-only mode with immutable flag to avoid locking issues.
    // TCC.db is owned by root and actively used by the system.
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    // Query the access table
    // Note: Schema may vary across macOS versions. We handle missing columns gracefully.
    let mut stmt = conn.prepare(
        r#"
        SELECT
            service,
            client,
            client_type,
            auth_value,
            auth_reason,
            last_modified,
            indirect_object_identifier,
            indirect_object_code_identity
        FROM access
        ORDER BY last_modified DESC
        "#,
    )?;

    let entries = stmt
        .query_map([], |row| {
            Ok(TccEntry {
                service: TccService::from(row.get::<_, String>(0)?.as_str()),
                client: row.get(1)?,
                client_type: TccClientType::from(row.get::<_, i32>(2)?),
                auth_value: TccAuthValue::from(row.get::<_, i32>(3)?),
                auth_reason: row.get(4)?,
                last_modified: row.get(5)?,
                indirect_object_identifier: row.get(6).ok(),
                indirect_object_code_identity: row.get(7).ok(),
            })
        })?
        .filter_map(|result| match result {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!(error = %e, "Failed to parse TCC entry");
                None
            }
        })
        .collect();

    Ok(entries)
}

/// Get TCC database path for current user
pub fn get_user_tcc_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|home| {
        home.join("Library")
            .join("Application Support")
            .join("com.apple.TCC")
            .join("TCC.db")
    })
}

/// Get system TCC database path
pub fn get_system_tcc_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_conversion() {
        assert_eq!(TccService::from("kTCCServiceCamera"), TccService::Camera);
        assert_eq!(TccService::Camera.as_str(), "kTCCServiceCamera");
        assert_eq!(TccService::Camera.display_name(), "Camera");
    }

    #[test]
    fn test_auth_value_conversion() {
        assert_eq!(TccAuthValue::from(0), TccAuthValue::Denied);
        assert_eq!(TccAuthValue::from(2), TccAuthValue::Allowed);
        assert_eq!(TccAuthValue::from(99), TccAuthValue::Unknown);
    }

    #[test]
    fn parses_modern_tcc_access_database_without_writing_to_source_db() {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(file.path()).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE access (
                    service TEXT NOT NULL,
                    client TEXT NOT NULL,
                    client_type INTEGER NOT NULL,
                    auth_value INTEGER NOT NULL,
                    auth_reason INTEGER NOT NULL,
                    last_modified INTEGER NOT NULL,
                    indirect_object_identifier TEXT,
                    indirect_object_code_identity TEXT
                );

                INSERT INTO access VALUES
                    ('kTCCServiceSystemPolicyAllFiles', 'com.tamandua.agent', 0, 2, 4, 1710000000, NULL, NULL),
                    ('kTCCServiceAppleEvents', '/Applications/Suspicious.app', 1, 0, 2, 1710000100, 'com.apple.Terminal', 'terminal-cs');
                "#,
            )
            .unwrap();
        }

        let entries = parse_tcc_db(file.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].service, TccService::AppleEvents);
        assert_eq!(entries[0].client_type, TccClientType::AbsolutePath);
        assert_eq!(entries[0].auth_value, TccAuthValue::Denied);
        assert_eq!(
            entries[0].indirect_object_identifier.as_deref(),
            Some("com.apple.Terminal")
        );
        assert_eq!(entries[1].service, TccService::FullDiskAccess);
        assert_eq!(entries[1].auth_value, TccAuthValue::Allowed);
    }
}
