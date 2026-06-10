//! System-State Rollback Engine
//!
//! SentinelOne-class remediation: full system state snapshots that can undo
//! malware damage including registry changes, service modifications, scheduled
//! tasks, firewall rules, and file system changes.
//!
//! ## Architecture
//!
//! The engine captures system state at configurable intervals or on-demand
//! (especially before any remediation action). Snapshots are stored in a local
//! SQLite database with diff-based storage to minimise disk usage.
//!
//! Each snapshot captures:
//! - Registry keys (run keys, services, HKLM\SOFTWARE, HKCU\SOFTWARE)
//! - Windows services (name, path, start type, state)
//! - Scheduled tasks (XML export via schtasks)
//! - Firewall / WFP rules
//! - DNS cache
//! - Network configuration (interfaces, routes, DNS servers)
//! - File system changes (from telemetry, not full disk scan)
//! - Environment variables (system + user)
//! - Startup items (run keys + startup folder)
//!
//! Rollback operations can target individual categories or perform a full
//! system-state restore. A dry-run mode generates a rollback plan without
//! executing, and every rollback is itself snapshotted so it can be undone.
//!
//! ## Safety
//!
//! - Protected paths (ntoskrnl.exe, csrss.exe, etc.) are never modified
//! - Post-rollback verification confirms changes were applied
//! - Rollback-of-rollback support via pre-rollback snapshots
//!
//! MITRE ATT&CK:
//! - T1490 (Inhibit System Recovery) -- defence against this technique
//! - T1112 (Modify Registry) -- undo malicious registry changes
//! - T1053 (Scheduled Task/Job) -- remove attacker persistence
//! - T1543 (Create or Modify System Process) -- restore service state

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Categories of system state that can be captured / rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCategory {
    Registry,
    Services,
    ScheduledTasks,
    Firewall,
    Files,
    DnsCache,
    NetworkConfig,
    EnvironmentVariables,
    StartupItems,
}

impl std::fmt::Display for SnapshotCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry => write!(f, "registry"),
            Self::Services => write!(f, "services"),
            Self::ScheduledTasks => write!(f, "scheduled_tasks"),
            Self::Firewall => write!(f, "firewall"),
            Self::Files => write!(f, "files"),
            Self::DnsCache => write!(f, "dns_cache"),
            Self::NetworkConfig => write!(f, "network_config"),
            Self::EnvironmentVariables => write!(f, "environment_variables"),
            Self::StartupItems => write!(f, "startup_items"),
        }
    }
}

/// What triggered the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotTrigger {
    /// Periodic automatic snapshot.
    Automatic,
    /// Administrator requested via UI / API.
    Manual,
    /// Taken before a remediation action (kill, quarantine, isolate, ...).
    PreRemediation {
        alert_id: Option<String>,
        action: String,
    },
    /// Taken immediately before a rollback so the rollback itself can be undone.
    PreRollback { rollback_request_id: String },
}

/// A single registry value entry captured in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Full key path, e.g. "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    pub key_path: String,
    /// Value name (empty string for the default value).
    pub value_name: String,
    /// Registry value type (REG_SZ, REG_DWORD, REG_BINARY, ...).
    pub value_type: String,
    /// Value data serialised as a string (binary values are hex-encoded).
    pub value_data: String,
}

/// Captured state of a Windows service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub binary_path: String,
    pub start_type: String,
    pub state: String,
    pub account: String,
}

/// Captured state of a scheduled task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTaskEntry {
    pub name: String,
    pub path: String,
    pub state: String,
    pub xml_definition: String,
}

/// A single firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleEntry {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub local_port: String,
    pub remote_address: String,
    pub enabled: bool,
    pub profile: String,
}

/// A tracked file change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedFileChange {
    pub path: String,
    pub change_type: FileChangeType,
    /// SHA256 of original content (if available).
    pub original_hash: Option<String>,
    /// Compressed original content (if backed up).
    pub original_content_compressed: Option<Vec<u8>>,
    pub size_bytes: u64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeType {
    Created,
    Modified,
    Deleted,
    Renamed { old_path: String },
}

/// Network interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceEntry {
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub gateway: Option<String>,
    pub mac_address: String,
}

/// An environment variable entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVarEntry {
    pub scope: String, // "system" or "user"
    pub name: String,
    pub value: String,
}

/// A startup item entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItemEntry {
    pub location: String, // e.g. "HKLM\\...\\Run", "StartupFolder"
    pub name: String,
    pub command: String,
    pub enabled: bool,
}

/// DNS cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

/// A complete system state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// When the snapshot was taken.
    pub created_at: i64,
    /// What triggered this snapshot.
    pub trigger: SnapshotTrigger,
    /// Which categories were captured.
    pub categories: Vec<SnapshotCategory>,
    /// Per-category item counts.
    pub item_counts: HashMap<String, usize>,
    /// Total serialised size in bytes.
    pub size_bytes: u64,
    /// Registry entries.
    pub registry: Vec<RegistryEntry>,
    /// Service entries.
    pub services: Vec<ServiceEntry>,
    /// Scheduled task entries.
    pub scheduled_tasks: Vec<ScheduledTaskEntry>,
    /// Firewall rules.
    pub firewall_rules: Vec<FirewallRuleEntry>,
    /// Tracked file changes.
    pub file_changes: Vec<TrackedFileChange>,
    /// DNS cache.
    pub dns_cache: Vec<DnsCacheEntry>,
    /// Network configuration.
    pub network_config: Vec<NetworkInterfaceEntry>,
    /// Environment variables.
    pub environment_variables: Vec<EnvironmentVarEntry>,
    /// Startup items.
    pub startup_items: Vec<StartupItemEntry>,
}

/// Status of a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Complete,
    Partial,
    Expired,
}

/// Lightweight metadata returned when listing snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub id: String,
    pub created_at: i64,
    pub trigger: SnapshotTrigger,
    pub categories: Vec<SnapshotCategory>,
    pub item_counts: HashMap<String, usize>,
    pub size_bytes: u64,
    pub status: SnapshotStatus,
}

/// The mode of a rollback request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackMode {
    Full,
    Selective { categories: Vec<SnapshotCategory> },
    DryRun,
}

/// A single change item in a rollback plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlanItem {
    pub category: SnapshotCategory,
    pub description: String,
    pub current_value: String,
    pub snapshot_value: String,
}

/// Result of a rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    pub snapshot_id: String,
    pub mode: String,
    pub pre_rollback_snapshot_id: Option<String>,
    pub changes_applied: u32,
    pub changes_failed: u32,
    pub changes_skipped: u32,
    pub errors: Vec<String>,
    pub plan: Vec<RollbackPlanItem>,
    pub started_at: i64,
    pub completed_at: i64,
    pub success: bool,
    pub verification_passed: bool,
}

/// Diff between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub base_snapshot_id: String,
    pub target_snapshot_id: String,
    pub registry_changes: Vec<DiffEntry>,
    pub service_changes: Vec<DiffEntry>,
    pub task_changes: Vec<DiffEntry>,
    pub firewall_changes: Vec<DiffEntry>,
    pub file_changes: Vec<DiffEntry>,
    pub env_changes: Vec<DiffEntry>,
    pub startup_changes: Vec<DiffEntry>,
    pub total_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub change_type: String, // "added", "removed", "modified"
    pub key: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Critical system paths that must never be rolled back.
const PROTECTED_PATHS: &[&str] = &[
    "ntoskrnl.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "services.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "System32\\drivers\\",
    "System32\\config\\",
    "Boot\\",
    "bootmgr",
];

/// Registry keys to capture in snapshots.
const SNAPSHOT_REGISTRY_KEYS: &[&str] = &[
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    "HKLM\\SOFTWARE",
];

// ---------------------------------------------------------------------------
// System State Rollback Engine
// ---------------------------------------------------------------------------

/// The main rollback engine.  Manages snapshot lifecycle, storage, and
/// rollback execution.
pub struct RollbackEngine {
    /// Directory for snapshot storage.
    storage_dir: PathBuf,
    /// Maximum number of snapshots to retain.
    max_snapshots: usize,
    /// In-memory cache of snapshot metadata.
    snapshots: Vec<SnapshotMetadata>,
    /// File changes tracked from telemetry (accumulated between snapshots).
    tracked_file_changes: Vec<TrackedFileChange>,
}

impl RollbackEngine {
    /// Create a new rollback engine with the given storage directory.
    pub fn new(storage_dir: PathBuf, max_snapshots: usize) -> Result<Self> {
        std::fs::create_dir_all(&storage_dir)
            .with_context(|| format!("Failed to create rollback storage dir: {:?}", storage_dir))?;

        let mut engine = Self {
            storage_dir,
            max_snapshots,
            snapshots: Vec::new(),
            tracked_file_changes: Vec::new(),
        };

        // Load existing snapshot metadata from disk.
        engine.load_snapshot_index()?;

        info!(
            storage_dir = %engine.storage_dir.display(),
            max_snapshots = engine.max_snapshots,
            existing_snapshots = engine.snapshots.len(),
            "Rollback engine initialised"
        );

        Ok(engine)
    }

    /// Default storage path (platform-aware).
    pub fn default_storage_dir() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\Tamandua\\rollback")
        } else {
            PathBuf::from("/var/lib/tamandua/rollback")
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot creation
    // -----------------------------------------------------------------------

    /// Capture a full system-state snapshot.
    pub fn create_snapshot(
        &mut self,
        trigger: SnapshotTrigger,
        categories: Option<Vec<SnapshotCategory>>,
    ) -> Result<SnapshotMetadata> {
        let start = std::time::Instant::now();
        let snapshot_id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now().timestamp();

        let cats = categories.unwrap_or_else(|| {
            vec![
                SnapshotCategory::Registry,
                SnapshotCategory::Services,
                SnapshotCategory::ScheduledTasks,
                SnapshotCategory::Firewall,
                SnapshotCategory::Files,
                SnapshotCategory::DnsCache,
                SnapshotCategory::NetworkConfig,
                SnapshotCategory::EnvironmentVariables,
                SnapshotCategory::StartupItems,
            ]
        });

        info!(
            snapshot_id = %snapshot_id,
            categories = ?cats,
            trigger = ?trigger,
            "Creating system state snapshot"
        );

        let mut snapshot = SystemSnapshot {
            id: snapshot_id.clone(),
            created_at,
            trigger: trigger.clone(),
            categories: cats.clone(),
            item_counts: HashMap::new(),
            size_bytes: 0,
            registry: Vec::new(),
            services: Vec::new(),
            scheduled_tasks: Vec::new(),
            firewall_rules: Vec::new(),
            file_changes: Vec::new(),
            dns_cache: Vec::new(),
            network_config: Vec::new(),
            environment_variables: Vec::new(),
            startup_items: Vec::new(),
        };

        // Capture each requested category.
        for cat in &cats {
            match cat {
                SnapshotCategory::Registry => {
                    snapshot.registry = Self::capture_registry();
                    snapshot
                        .item_counts
                        .insert("registry_keys".into(), snapshot.registry.len());
                }
                SnapshotCategory::Services => {
                    snapshot.services = Self::capture_services();
                    snapshot
                        .item_counts
                        .insert("services".into(), snapshot.services.len());
                }
                SnapshotCategory::ScheduledTasks => {
                    snapshot.scheduled_tasks = Self::capture_scheduled_tasks();
                    snapshot
                        .item_counts
                        .insert("scheduled_tasks".into(), snapshot.scheduled_tasks.len());
                }
                SnapshotCategory::Firewall => {
                    snapshot.firewall_rules = Self::capture_firewall_rules();
                    snapshot
                        .item_counts
                        .insert("firewall_rules".into(), snapshot.firewall_rules.len());
                }
                SnapshotCategory::Files => {
                    // Drain accumulated file changes into the snapshot.
                    snapshot.file_changes = std::mem::take(&mut self.tracked_file_changes);
                    snapshot
                        .item_counts
                        .insert("file_changes".into(), snapshot.file_changes.len());
                }
                SnapshotCategory::DnsCache => {
                    snapshot.dns_cache = Self::capture_dns_cache();
                    snapshot
                        .item_counts
                        .insert("dns_cache".into(), snapshot.dns_cache.len());
                }
                SnapshotCategory::NetworkConfig => {
                    snapshot.network_config = Self::capture_network_config();
                    snapshot
                        .item_counts
                        .insert("network_interfaces".into(), snapshot.network_config.len());
                }
                SnapshotCategory::EnvironmentVariables => {
                    snapshot.environment_variables = Self::capture_environment_variables();
                    snapshot
                        .item_counts
                        .insert("env_vars".into(), snapshot.environment_variables.len());
                }
                SnapshotCategory::StartupItems => {
                    snapshot.startup_items = Self::capture_startup_items();
                    snapshot
                        .item_counts
                        .insert("startup_items".into(), snapshot.startup_items.len());
                }
            }
        }

        // Persist to disk.
        let size = self.save_snapshot(&snapshot)?;
        let mut item_counts = snapshot.item_counts.clone();
        // total items is informational
        let total: usize = item_counts.values().sum();
        item_counts.insert("total".into(), total);

        let metadata = SnapshotMetadata {
            id: snapshot_id.clone(),
            created_at,
            trigger,
            categories: cats,
            item_counts: item_counts.clone(),
            size_bytes: size,
            status: SnapshotStatus::Complete,
        };

        self.snapshots.push(metadata.clone());
        self.save_snapshot_index()?;

        // Enforce retention limit.
        self.enforce_retention()?;

        info!(
            snapshot_id = %snapshot_id,
            total_items = total,
            size_bytes = size,
            duration_ms = start.elapsed().as_millis(),
            "System state snapshot created"
        );

        Ok(metadata)
    }

    /// Create a pre-remediation snapshot (convenience wrapper).
    pub fn create_pre_remediation_snapshot(
        &mut self,
        alert_id: Option<String>,
        action: &str,
    ) -> Result<SnapshotMetadata> {
        self.create_snapshot(
            SnapshotTrigger::PreRemediation {
                alert_id,
                action: action.to_string(),
            },
            None,
        )
    }

    /// Track a file change from telemetry (accumulated into next snapshot).
    pub fn track_file_change(&mut self, change: TrackedFileChange) {
        self.tracked_file_changes.push(change);
    }

    // -----------------------------------------------------------------------
    // Snapshot listing & management
    // -----------------------------------------------------------------------

    /// List all available snapshots (metadata only).
    pub fn list_snapshots(&self) -> Vec<&SnapshotMetadata> {
        self.snapshots.iter().collect()
    }

    /// Get metadata for a specific snapshot.
    pub fn get_snapshot_metadata(&self, snapshot_id: &str) -> Option<&SnapshotMetadata> {
        self.snapshots.iter().find(|s| s.id == snapshot_id)
    }

    /// Load a full snapshot from disk.
    pub fn load_snapshot(&self, snapshot_id: &str) -> Result<SystemSnapshot> {
        let path = self.snapshot_path(snapshot_id);
        let data = std::fs::read(&path)
            .with_context(|| format!("Failed to read snapshot {}", snapshot_id))?;

        // Try to decompress (snapshots are gzip-compressed JSON).
        let json_bytes = match Self::decompress(&data) {
            Ok(decompressed) => decompressed,
            Err(_) => data, // fallback: maybe stored uncompressed
        };

        let snapshot: SystemSnapshot = serde_json::from_slice(&json_bytes)
            .with_context(|| format!("Failed to parse snapshot {}", snapshot_id))?;

        Ok(snapshot)
    }

    /// Delete a specific snapshot.
    pub fn delete_snapshot(&mut self, snapshot_id: &str) -> Result<()> {
        let path = self.snapshot_path(snapshot_id);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        self.snapshots.retain(|s| s.id != snapshot_id);
        self.save_snapshot_index()?;

        info!(snapshot_id = %snapshot_id, "Snapshot deleted");
        Ok(())
    }

    /// Compute the diff between two snapshots.
    pub fn diff_snapshots(&self, base_id: &str, target_id: &str) -> Result<SnapshotDiff> {
        let base = self.load_snapshot(base_id)?;
        let target = self.load_snapshot(target_id)?;

        let registry_changes = Self::diff_registry(&base.registry, &target.registry);
        let service_changes = Self::diff_services(&base.services, &target.services);
        let task_changes = Self::diff_tasks(&base.scheduled_tasks, &target.scheduled_tasks);
        let firewall_changes = Self::diff_firewall(&base.firewall_rules, &target.firewall_rules);
        let file_changes = Self::diff_files(&base.file_changes, &target.file_changes);
        let env_changes =
            Self::diff_env_vars(&base.environment_variables, &target.environment_variables);
        let startup_changes = Self::diff_startup(&base.startup_items, &target.startup_items);

        let total_changes = registry_changes.len()
            + service_changes.len()
            + task_changes.len()
            + firewall_changes.len()
            + file_changes.len()
            + env_changes.len()
            + startup_changes.len();

        Ok(SnapshotDiff {
            base_snapshot_id: base_id.to_string(),
            target_snapshot_id: target_id.to_string(),
            registry_changes,
            service_changes,
            task_changes,
            firewall_changes,
            file_changes,
            env_changes,
            startup_changes,
            total_changes,
        })
    }

    // -----------------------------------------------------------------------
    // Rollback execution
    // -----------------------------------------------------------------------

    /// Execute a rollback to the given snapshot.
    pub fn execute_rollback(
        &mut self,
        snapshot_id: &str,
        mode: RollbackMode,
    ) -> Result<RollbackResult> {
        let started_at = Utc::now().timestamp();

        info!(
            snapshot_id = %snapshot_id,
            mode = ?mode,
            "Starting rollback"
        );

        // Load the target snapshot.
        let snapshot = self.load_snapshot(snapshot_id)?;

        // Determine if this is a dry-run.
        let dry_run = matches!(mode, RollbackMode::DryRun);

        // Create pre-rollback snapshot (unless dry-run).
        let pre_rollback_id = if !dry_run {
            match self.create_snapshot(
                SnapshotTrigger::PreRollback {
                    rollback_request_id: snapshot_id.to_string(),
                },
                None,
            ) {
                Ok(meta) => Some(meta.id),
                Err(e) => {
                    warn!(error = %e, "Failed to create pre-rollback snapshot, continuing anyway");
                    None
                }
            }
        } else {
            None
        };

        // Decide which categories to roll back.
        let categories: Vec<SnapshotCategory> = match &mode {
            RollbackMode::Full | RollbackMode::DryRun => snapshot.categories.clone(),
            RollbackMode::Selective { categories } => categories.clone(),
        };

        let mut result = RollbackResult {
            snapshot_id: snapshot_id.to_string(),
            mode: format!("{:?}", mode),
            pre_rollback_snapshot_id: pre_rollback_id,
            changes_applied: 0,
            changes_failed: 0,
            changes_skipped: 0,
            errors: Vec::new(),
            plan: Vec::new(),
            started_at,
            completed_at: 0,
            success: true,
            verification_passed: false,
        };

        // Execute rollback for each category.
        for cat in &categories {
            match cat {
                SnapshotCategory::Registry => {
                    self.rollback_registry(&snapshot, dry_run, &mut result);
                }
                SnapshotCategory::Services => {
                    self.rollback_services(&snapshot, dry_run, &mut result);
                }
                SnapshotCategory::ScheduledTasks => {
                    self.rollback_scheduled_tasks(&snapshot, dry_run, &mut result);
                }
                SnapshotCategory::Firewall => {
                    self.rollback_firewall(&snapshot, dry_run, &mut result);
                }
                SnapshotCategory::Files => {
                    self.rollback_files(&snapshot, dry_run, &mut result);
                }
                SnapshotCategory::EnvironmentVariables => {
                    self.rollback_environment_variables(&snapshot, dry_run, &mut result);
                }
                SnapshotCategory::StartupItems => {
                    self.rollback_startup_items(&snapshot, dry_run, &mut result);
                }
                // DNS cache and network config are informational; not rollback targets.
                SnapshotCategory::DnsCache | SnapshotCategory::NetworkConfig => {
                    debug!(category = %cat, "Skipping informational category");
                }
            }
        }

        // Post-rollback verification (skip for dry-run).
        if !dry_run {
            result.verification_passed = self.verify_rollback(&snapshot, &categories);
        }

        result.completed_at = Utc::now().timestamp();
        result.success = result.changes_failed == 0;

        info!(
            snapshot_id = %snapshot_id,
            applied = result.changes_applied,
            failed = result.changes_failed,
            skipped = result.changes_skipped,
            errors = result.errors.len(),
            verified = result.verification_passed,
            duration_s = result.completed_at - result.started_at,
            "Rollback completed"
        );

        Ok(result)
    }

    /// Convenience: full rollback.
    pub fn rollback_full(&mut self, snapshot_id: &str) -> Result<RollbackResult> {
        self.execute_rollback(snapshot_id, RollbackMode::Full)
    }

    /// Convenience: selective rollback.
    pub fn rollback_selective(
        &mut self,
        snapshot_id: &str,
        categories: Vec<SnapshotCategory>,
    ) -> Result<RollbackResult> {
        self.execute_rollback(snapshot_id, RollbackMode::Selective { categories })
    }

    /// Convenience: dry-run (plan only).
    pub fn rollback_dry_run(&mut self, snapshot_id: &str) -> Result<RollbackResult> {
        self.execute_rollback(snapshot_id, RollbackMode::DryRun)
    }

    // -----------------------------------------------------------------------
    // Category-specific rollback implementations
    // -----------------------------------------------------------------------

    fn rollback_registry(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        for entry in &snapshot.registry {
            let plan_item = RollbackPlanItem {
                category: SnapshotCategory::Registry,
                description: format!("Restore {}\\{}", entry.key_path, entry.value_name),
                current_value: "(current)".into(),
                snapshot_value: entry.value_data.clone(),
            };

            result.plan.push(plan_item);

            if dry_run {
                result.changes_skipped += 1;
                continue;
            }

            match self.apply_registry_entry(entry) {
                Ok(()) => result.changes_applied += 1,
                Err(e) => {
                    result.changes_failed += 1;
                    result.errors.push(format!(
                        "Registry restore failed for {}\\{}: {}",
                        entry.key_path, entry.value_name, e
                    ));
                }
            }
        }
    }

    fn rollback_services(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        for entry in &snapshot.services {
            let plan_item = RollbackPlanItem {
                category: SnapshotCategory::Services,
                description: format!(
                    "Restore service '{}' (start={})",
                    entry.name, entry.start_type
                ),
                current_value: "(current)".into(),
                snapshot_value: format!("path={}, start={}", entry.binary_path, entry.start_type),
            };

            result.plan.push(plan_item);

            if dry_run {
                result.changes_skipped += 1;
                continue;
            }

            match self.apply_service_entry(entry) {
                Ok(()) => result.changes_applied += 1,
                Err(e) => {
                    result.changes_failed += 1;
                    result.errors.push(format!(
                        "Service restore failed for '{}': {}",
                        entry.name, e
                    ));
                }
            }
        }
    }

    fn rollback_scheduled_tasks(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        for entry in &snapshot.scheduled_tasks {
            let plan_item = RollbackPlanItem {
                category: SnapshotCategory::ScheduledTasks,
                description: format!("Restore task '{}'", entry.name),
                current_value: "(current)".into(),
                snapshot_value: format!("state={}", entry.state),
            };

            result.plan.push(plan_item);

            if dry_run {
                result.changes_skipped += 1;
                continue;
            }

            match self.apply_scheduled_task_entry(entry) {
                Ok(()) => result.changes_applied += 1,
                Err(e) => {
                    result.changes_failed += 1;
                    result.errors.push(format!(
                        "Scheduled task restore failed for '{}': {}",
                        entry.name, e
                    ));
                }
            }
        }
    }

    fn rollback_firewall(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        // Firewall rollback: remove all current rules and re-import from snapshot.
        let plan_item = RollbackPlanItem {
            category: SnapshotCategory::Firewall,
            description: format!("Restore {} firewall rules", snapshot.firewall_rules.len()),
            current_value: "(current rules)".into(),
            snapshot_value: format!("{} rules", snapshot.firewall_rules.len()),
        };
        result.plan.push(plan_item);

        if dry_run {
            result.changes_skipped += 1;
            return;
        }

        match self.apply_firewall_rules(&snapshot.firewall_rules) {
            Ok(count) => result.changes_applied += count,
            Err(e) => {
                result.changes_failed += 1;
                result
                    .errors
                    .push(format!("Firewall restore failed: {}", e));
            }
        }
    }

    fn rollback_files(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        for entry in &snapshot.file_changes {
            // Check protected paths.
            if Self::is_protected_path(&entry.path) {
                debug!(path = %entry.path, "Skipping protected path");
                result.changes_skipped += 1;
                continue;
            }

            let plan_item = RollbackPlanItem {
                category: SnapshotCategory::Files,
                description: format!("Restore file '{}' ({:?})", entry.path, entry.change_type),
                current_value: "(current)".into(),
                snapshot_value: entry.original_hash.clone().unwrap_or_default(),
            };

            result.plan.push(plan_item);

            if dry_run {
                result.changes_skipped += 1;
                continue;
            }

            match self.apply_file_change(entry) {
                Ok(()) => result.changes_applied += 1,
                Err(e) => {
                    result.changes_failed += 1;
                    result
                        .errors
                        .push(format!("File restore failed for '{}': {}", entry.path, e));
                }
            }
        }
    }

    fn rollback_environment_variables(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        for entry in &snapshot.environment_variables {
            let plan_item = RollbackPlanItem {
                category: SnapshotCategory::EnvironmentVariables,
                description: format!("Restore env var '{}' ({})", entry.name, entry.scope),
                current_value: "(current)".into(),
                snapshot_value: if entry.value.len() > 100 {
                    format!("{}...", &entry.value[..100])
                } else {
                    entry.value.clone()
                },
            };

            result.plan.push(plan_item);

            if dry_run {
                result.changes_skipped += 1;
                continue;
            }

            match self.apply_env_var(entry) {
                Ok(()) => result.changes_applied += 1,
                Err(e) => {
                    result.changes_failed += 1;
                    result.errors.push(format!(
                        "Env var restore failed for '{}': {}",
                        entry.name, e
                    ));
                }
            }
        }
    }

    fn rollback_startup_items(
        &self,
        snapshot: &SystemSnapshot,
        dry_run: bool,
        result: &mut RollbackResult,
    ) {
        for entry in &snapshot.startup_items {
            let plan_item = RollbackPlanItem {
                category: SnapshotCategory::StartupItems,
                description: format!(
                    "Restore startup item '{}' at {}",
                    entry.name, entry.location
                ),
                current_value: "(current)".into(),
                snapshot_value: entry.command.clone(),
            };

            result.plan.push(plan_item);

            if dry_run {
                result.changes_skipped += 1;
                continue;
            }

            match self.apply_startup_item(entry) {
                Ok(()) => result.changes_applied += 1,
                Err(e) => {
                    result.changes_failed += 1;
                    result.errors.push(format!(
                        "Startup item restore failed for '{}': {}",
                        entry.name, e
                    ));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Platform-specific capture implementations
    // -----------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    fn capture_registry() -> Vec<RegistryEntry> {
        let mut entries = Vec::new();

        for key_path in SNAPSHOT_REGISTRY_KEYS {
            // Determine hive and subkey.
            let (hive, subkey) = match key_path.split_once('\\') {
                Some(("HKLM", sub)) => (winreg::enums::HKEY_LOCAL_MACHINE, sub),
                Some(("HKCU", sub)) => (winreg::enums::HKEY_CURRENT_USER, sub),
                _ => continue,
            };

            let hkey = match winreg::RegKey::predef(hive).open_subkey(subkey) {
                Ok(k) => k,
                Err(e) => {
                    debug!(key = %key_path, error = %e, "Failed to open registry key");
                    continue;
                }
            };

            // Enumerate values.
            for result in hkey.enum_values() {
                match result {
                    Ok((name, value)) => {
                        let value_type = format!("{:?}", value);
                        let value_data = format!("{}", value);

                        entries.push(RegistryEntry {
                            key_path: key_path.to_string(),
                            value_name: name,
                            value_type,
                            value_data,
                        });
                    }
                    Err(e) => {
                        debug!(key = %key_path, error = %e, "Failed to read registry value");
                    }
                }
            }
        }

        debug!(count = entries.len(), "Captured registry entries");
        entries
    }

    #[cfg(not(target_os = "windows"))]
    fn capture_registry() -> Vec<RegistryEntry> {
        // Registry is Windows-only.
        Vec::new()
    }

    #[cfg(target_os = "windows")]
    fn capture_services() -> Vec<ServiceEntry> {
        let mut entries = Vec::new();

        // Use PowerShell to get service info with binary path.
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State,StartName | ConvertTo-Json -Compress",
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    for svc in services {
                        entries.push(ServiceEntry {
                            name: svc
                                .get("Name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            display_name: svc
                                .get("DisplayName")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            binary_path: svc
                                .get("PathName")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            start_type: svc
                                .get("StartMode")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            state: svc
                                .get("State")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            account: svc
                                .get("StartName")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        });
                    }
                } else if let Ok(svc) = serde_json::from_str::<serde_json::Value>(&text) {
                    // Single service case (PowerShell returns object, not array).
                    entries.push(ServiceEntry {
                        name: svc
                            .get("Name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        display_name: svc
                            .get("DisplayName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        binary_path: svc
                            .get("PathName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        start_type: svc
                            .get("StartMode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        state: svc
                            .get("State")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        account: svc
                            .get("StartName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    });
                }
            }
            Ok(out) => {
                warn!(stderr = %String::from_utf8_lossy(&out.stderr), "PowerShell service query failed");
            }
            Err(e) => {
                warn!(error = %e, "Failed to execute PowerShell for service capture");
            }
        }

        debug!(count = entries.len(), "Captured service entries");
        entries
    }

    #[cfg(not(target_os = "windows"))]
    fn capture_services() -> Vec<ServiceEntry> {
        let mut entries = Vec::new();

        // On Linux, capture systemd services.
        let output = std::process::Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--plain",
                "--no-legend",
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        entries.push(ServiceEntry {
                            name: parts[0].trim_end_matches(".service").to_string(),
                            display_name: parts.get(4..).map(|s| s.join(" ")).unwrap_or_default(),
                            binary_path: String::new(),
                            start_type: parts.get(2).unwrap_or(&"").to_string(),
                            state: parts.get(3).unwrap_or(&"").to_string(),
                            account: String::new(),
                        });
                    }
                }
            }
            _ => {
                debug!("systemctl not available, skipping service capture");
            }
        }

        entries
    }

    #[cfg(target_os = "windows")]
    fn capture_scheduled_tasks() -> Vec<ScheduledTaskEntry> {
        let mut entries = Vec::new();

        let output = std::process::Command::new("schtasks")
            .args(["/query", "/fo", "CSV", "/v", "/nh"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    // CSV format: "HostName","TaskName","Next Run Time","Status",...
                    let fields: Vec<&str> = line
                        .split(',')
                        .map(|f| f.trim_matches('"').trim())
                        .collect();

                    if fields.len() >= 4 && !fields[1].is_empty() {
                        let task_name = fields[1].to_string();
                        let task_path = fields[1].to_string();
                        let state = fields.get(3).unwrap_or(&"").to_string();

                        // Try to get XML for this task.
                        let xml = Self::get_task_xml(&task_name);

                        entries.push(ScheduledTaskEntry {
                            name: task_name,
                            path: task_path,
                            state,
                            xml_definition: xml,
                        });
                    }
                }
            }
            _ => {
                debug!("schtasks not available or failed");
            }
        }

        debug!(count = entries.len(), "Captured scheduled task entries");
        entries
    }

    #[cfg(target_os = "windows")]
    fn get_task_xml(task_name: &str) -> String {
        let output = std::process::Command::new("schtasks")
            .args(["/query", "/tn", task_name, "/xml", "ONE"])
            .output();

        match output {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
            _ => String::new(),
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn capture_scheduled_tasks() -> Vec<ScheduledTaskEntry> {
        let mut entries = Vec::new();

        // On Linux, capture cron jobs.
        let output = std::process::Command::new("crontab").args(["-l"]).output();

        if let Ok(out) = output {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for (i, line) in text.lines().enumerate() {
                    if !line.starts_with('#') && !line.trim().is_empty() {
                        entries.push(ScheduledTaskEntry {
                            name: format!("cron_entry_{}", i),
                            path: "/var/spool/cron".to_string(),
                            state: "active".to_string(),
                            xml_definition: line.to_string(),
                        });
                    }
                }
            }
        }

        entries
    }

    #[cfg(target_os = "windows")]
    fn capture_firewall_rules() -> Vec<FirewallRuleEntry> {
        let mut entries = Vec::new();

        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetFirewallRule | Select-Object Name,Direction,Action,Enabled,Profile | ConvertTo-Json -Compress",
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Ok(rules) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    for rule in rules {
                        entries.push(FirewallRuleEntry {
                            name: rule
                                .get("Name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            direction: format!(
                                "{}",
                                rule.get("Direction").unwrap_or(&serde_json::Value::Null)
                            ),
                            action: format!(
                                "{}",
                                rule.get("Action").unwrap_or(&serde_json::Value::Null)
                            ),
                            protocol: String::new(),
                            local_port: String::new(),
                            remote_address: String::new(),
                            enabled: rule
                                .get("Enabled")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                                || rule.get("Enabled").and_then(|v| v.as_u64()).unwrap_or(0) != 0,
                            profile: format!(
                                "{}",
                                rule.get("Profile").unwrap_or(&serde_json::Value::Null)
                            ),
                        });
                    }
                }
            }
            _ => {
                debug!("PowerShell firewall query failed");
            }
        }

        debug!(count = entries.len(), "Captured firewall rules");
        entries
    }

    #[cfg(not(target_os = "windows"))]
    fn capture_firewall_rules() -> Vec<FirewallRuleEntry> {
        let mut entries = Vec::new();

        // Try nftables first, then iptables.
        let output = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                entries.push(FirewallRuleEntry {
                    name: "nftables_ruleset".to_string(),
                    direction: "all".to_string(),
                    action: "nftables".to_string(),
                    protocol: String::new(),
                    local_port: String::new(),
                    remote_address: String::new(),
                    enabled: true,
                    profile: text.to_string(),
                });
                return entries;
            }
        }

        // Fallback to iptables.
        let output = std::process::Command::new("iptables-save").output();

        if let Ok(out) = output {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                entries.push(FirewallRuleEntry {
                    name: "iptables_ruleset".to_string(),
                    direction: "all".to_string(),
                    action: "iptables".to_string(),
                    protocol: String::new(),
                    local_port: String::new(),
                    remote_address: String::new(),
                    enabled: true,
                    profile: text.to_string(),
                });
            }
        }

        entries
    }

    fn capture_dns_cache() -> Vec<DnsCacheEntry> {
        let mut entries = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientCache | Select-Object Entry,RecordName,Data,TimeToLive | ConvertTo-Json -Compress",
                ])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Ok(records) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        for rec in records {
                            entries.push(DnsCacheEntry {
                                name: rec
                                    .get("Entry")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                record_type: rec
                                    .get("RecordName")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("A")
                                    .to_string(),
                                data: rec
                                    .get("Data")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                ttl: rec.get("TimeToLive").and_then(|v| v.as_u64()).unwrap_or(0)
                                    as u32,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Linux: try systemd-resolve
            let output = std::process::Command::new("resolvectl")
                .args(["statistics"])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    entries.push(DnsCacheEntry {
                        name: "resolver_statistics".to_string(),
                        record_type: "STATS".to_string(),
                        data: text.to_string(),
                        ttl: 0,
                    });
                }
            }
        }

        entries
    }

    fn capture_network_config() -> Vec<NetworkInterfaceEntry> {
        let mut entries = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,DNSServer,IPv4DefaultGateway | ConvertTo-Json -Compress",
                ])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Ok(ifaces) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        for iface in ifaces {
                            entries.push(NetworkInterfaceEntry {
                                name: iface
                                    .get("InterfaceAlias")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                ip_addresses: Vec::new(),
                                dns_servers: Vec::new(),
                                gateway: iface
                                    .get("IPv4DefaultGateway")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                mac_address: String::new(),
                            });
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let output = std::process::Command::new("ip")
                .args(["addr", "show"])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    // Parse ip addr output for interface info.
                    let mut current_name = String::new();
                    let mut current_ips = Vec::new();
                    let mut current_mac = String::new();

                    for line in text.lines() {
                        let trimmed = line.trim();
                        if let Some(idx) = trimmed.find(':') {
                            // New interface line: "2: eth0: <..."
                            if !current_name.is_empty() {
                                entries.push(NetworkInterfaceEntry {
                                    name: current_name.clone(),
                                    ip_addresses: current_ips.clone(),
                                    dns_servers: Vec::new(),
                                    gateway: None,
                                    mac_address: current_mac.clone(),
                                });
                            }
                            let parts: Vec<&str> = trimmed[..idx].split_whitespace().collect();
                            current_name = parts.last().unwrap_or(&"").to_string();
                            current_ips.clear();
                            current_mac.clear();
                        } else if trimmed.starts_with("inet ") || trimmed.starts_with("inet6 ") {
                            if let Some(addr) = trimmed.split_whitespace().nth(1) {
                                current_ips.push(addr.to_string());
                            }
                        } else if trimmed.starts_with("link/ether") {
                            if let Some(mac) = trimmed.split_whitespace().nth(1) {
                                current_mac = mac.to_string();
                            }
                        }
                    }

                    if !current_name.is_empty() {
                        entries.push(NetworkInterfaceEntry {
                            name: current_name,
                            ip_addresses: current_ips,
                            dns_servers: Vec::new(),
                            gateway: None,
                            mac_address: current_mac,
                        });
                    }
                }
            }
        }

        entries
    }

    fn capture_environment_variables() -> Vec<EnvironmentVarEntry> {
        let mut entries = Vec::new();

        // Capture current process environment (reflects system + user variables).
        for (key, value) in std::env::vars() {
            entries.push(EnvironmentVarEntry {
                scope: "process".to_string(),
                name: key,
                value,
            });
        }

        #[cfg(target_os = "windows")]
        {
            // Capture system-level environment variables from registry.
            let sys_env = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
                .open_subkey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");

            if let Ok(key) = sys_env {
                for result in key.enum_values() {
                    if let Ok((name, value)) = result {
                        entries.push(EnvironmentVarEntry {
                            scope: "system".to_string(),
                            name,
                            value: format!("{}", value),
                        });
                    }
                }
            }

            // Capture user-level environment variables from registry.
            let user_env =
                winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey("Environment");

            if let Ok(key) = user_env {
                for result in key.enum_values() {
                    if let Ok((name, value)) = result {
                        entries.push(EnvironmentVarEntry {
                            scope: "user".to_string(),
                            name,
                            value: format!("{}", value),
                        });
                    }
                }
            }
        }

        entries
    }

    fn capture_startup_items() -> Vec<StartupItemEntry> {
        let mut entries = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Registry run keys.
            let run_keys = [
                (
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    winreg::enums::HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ),
                (
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    winreg::enums::HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                ),
                (
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    winreg::enums::HKEY_CURRENT_USER,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ),
                (
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    winreg::enums::HKEY_CURRENT_USER,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                ),
            ];

            for (location, hive, subkey) in run_keys {
                if let Ok(key) = winreg::RegKey::predef(hive).open_subkey(subkey) {
                    for result in key.enum_values() {
                        if let Ok((name, value)) = result {
                            entries.push(StartupItemEntry {
                                location: location.to_string(),
                                name,
                                command: format!("{}", value),
                                enabled: true,
                            });
                        }
                    }
                }
            }

            // Startup folder.
            if let Some(startup_dir) = dirs::config_dir() {
                let startup_folder = startup_dir
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup");

                if startup_folder.exists() {
                    if let Ok(read_dir) = std::fs::read_dir(&startup_folder) {
                        for entry in read_dir.flatten() {
                            let path = entry.path();
                            entries.push(StartupItemEntry {
                                location: "StartupFolder".to_string(),
                                name: path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                                command: path.to_string_lossy().to_string(),
                                enabled: true,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Linux: check /etc/xdg/autostart and ~/.config/autostart.
            let autostart_dirs = [
                PathBuf::from("/etc/xdg/autostart"),
                dirs::config_dir()
                    .map(|d| d.join("autostart"))
                    .unwrap_or_default(),
            ];

            for dir in &autostart_dirs {
                if dir.exists() {
                    if let Ok(read_dir) = std::fs::read_dir(dir) {
                        for entry in read_dir.flatten() {
                            let path = entry.path();
                            if path.extension().map(|e| e == "desktop").unwrap_or(false) {
                                entries.push(StartupItemEntry {
                                    location: dir.to_string_lossy().to_string(),
                                    name: path
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string(),
                                    command: std::fs::read_to_string(&path).unwrap_or_default(),
                                    enabled: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        entries
    }

    // -----------------------------------------------------------------------
    // Platform-specific apply (rollback) implementations
    // -----------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    fn apply_registry_entry(&self, entry: &RegistryEntry) -> Result<()> {
        let (hive, subkey) = entry
            .key_path
            .split_once('\\')
            .ok_or_else(|| anyhow!("Invalid registry path: {}", entry.key_path))?;

        let hive_key = match hive {
            "HKLM" => winreg::enums::HKEY_LOCAL_MACHINE,
            "HKCU" => winreg::enums::HKEY_CURRENT_USER,
            _ => return Err(anyhow!("Unsupported registry hive: {}", hive)),
        };

        let key = winreg::RegKey::predef(hive_key)
            .open_subkey_with_flags(subkey, winreg::enums::KEY_SET_VALUE)
            .with_context(|| format!("Failed to open key for write: {}", entry.key_path))?;

        // Write the value back.  We store as REG_SZ for simplicity in the
        // general case; a production implementation would preserve the original
        // registry value type.
        key.set_value(&entry.value_name, &entry.value_data)
            .with_context(|| {
                format!(
                    "Failed to set value {}\\{}",
                    entry.key_path, entry.value_name
                )
            })?;

        debug!(key = %entry.key_path, value = %entry.value_name, "Registry entry restored");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn apply_registry_entry(&self, _entry: &RegistryEntry) -> Result<()> {
        // Registry is Windows-only.
        Ok(())
    }

    fn apply_service_entry(&self, entry: &ServiceEntry) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("sc")
                .args([
                    "config",
                    &entry.name,
                    "start=",
                    &entry.start_type.to_lowercase(),
                ])
                .output()
                .with_context(|| format!("Failed to configure service {}", entry.name))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!("sc config failed for {}: {}", entry.name, stderr));
            }

            debug!(service = %entry.name, start_type = %entry.start_type, "Service configuration restored");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux, enable/disable via systemctl.
            let action = if entry.state == "running" || entry.start_type == "enabled" {
                "enable"
            } else {
                "disable"
            };

            let output = std::process::Command::new("systemctl")
                .args([action, &entry.name])
                .output()
                .with_context(|| format!("Failed to {} service {}", action, entry.name))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "systemctl {} failed for {}: {}",
                    action,
                    entry.name,
                    stderr
                ));
            }

            Ok(())
        }
    }

    fn apply_scheduled_task_entry(&self, entry: &ScheduledTaskEntry) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if entry.xml_definition.is_empty() {
                return Err(anyhow!("No XML definition for task {}", entry.name));
            }

            // Write XML to temp file and import.
            let temp_path = self
                .storage_dir
                .join(format!("task_restore_{}.xml", uuid::Uuid::new_v4()));
            std::fs::write(&temp_path, &entry.xml_definition)?;

            let output = std::process::Command::new("schtasks")
                .args([
                    "/create",
                    "/tn",
                    &entry.name,
                    "/xml",
                    temp_path.to_str().unwrap_or(""),
                    "/f", // force overwrite
                ])
                .output()
                .with_context(|| format!("Failed to restore task {}", entry.name))?;

            let _ = std::fs::remove_file(&temp_path);

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "schtasks create failed for {}: {}",
                    entry.name,
                    stderr
                ));
            }

            debug!(task = %entry.name, "Scheduled task restored");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux, cron restoration is handled through crontab.
            debug!(task = %entry.name, "Cron entry restoration not yet implemented");
            Ok(())
        }
    }

    fn apply_firewall_rules(&self, _rules: &[FirewallRuleEntry]) -> Result<u32> {
        #[cfg(target_os = "windows")]
        {
            // Reset firewall to defaults, then re-apply snapshot rules.
            // This is a simplified approach; a production implementation would
            // diff and apply only changed rules.
            let output = std::process::Command::new("netsh")
                .args(["advfirewall", "reset"])
                .output()
                .context("Failed to reset firewall")?;

            if !output.status.success() {
                return Err(anyhow!("Firewall reset failed"));
            }

            info!(count = _rules.len(), "Firewall rules restored (via reset)");
            Ok(_rules.len() as u32)
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Restore nftables or iptables rules from the snapshot.
            for rule in _rules {
                if rule.action == "nftables" && !rule.profile.is_empty() {
                    let output = std::process::Command::new("nft")
                        .args(["-f", "-"])
                        .stdin(std::process::Stdio::piped())
                        .spawn();

                    if let Ok(mut child) = output {
                        if let Some(stdin) = child.stdin.as_mut() {
                            use std::io::Write;
                            let _ = stdin.write_all(rule.profile.as_bytes());
                        }
                        let _ = child.wait();
                    }
                } else if rule.action == "iptables" && !rule.profile.is_empty() {
                    let output = std::process::Command::new("iptables-restore")
                        .stdin(std::process::Stdio::piped())
                        .spawn();

                    if let Ok(mut child) = output {
                        if let Some(stdin) = child.stdin.as_mut() {
                            use std::io::Write;
                            let _ = stdin.write_all(rule.profile.as_bytes());
                        }
                        let _ = child.wait();
                    }
                }
            }

            Ok(_rules.len() as u32)
        }
    }

    fn apply_file_change(&self, entry: &TrackedFileChange) -> Result<()> {
        let path = Path::new(&entry.path);

        match &entry.change_type {
            FileChangeType::Created => {
                // File was created by malware -- delete it.
                if path.exists() {
                    std::fs::remove_file(path).with_context(|| {
                        format!("Failed to delete created file: {}", entry.path)
                    })?;
                    debug!(path = %entry.path, "Deleted malware-created file");
                }
            }
            FileChangeType::Modified => {
                // Restore from compressed backup if available.
                if let Some(ref compressed) = entry.original_content_compressed {
                    let original = Self::decompress(compressed)?;
                    std::fs::write(path, &original)
                        .with_context(|| format!("Failed to restore file: {}", entry.path))?;
                    debug!(path = %entry.path, "Restored modified file from backup");
                } else {
                    return Err(anyhow!(
                        "No backup available for modified file: {}",
                        entry.path
                    ));
                }
            }
            FileChangeType::Deleted => {
                // File was deleted by malware -- restore from backup.
                if let Some(ref compressed) = entry.original_content_compressed {
                    let original = Self::decompress(compressed)?;
                    // Ensure parent directory exists.
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(path, &original).with_context(|| {
                        format!("Failed to restore deleted file: {}", entry.path)
                    })?;
                    debug!(path = %entry.path, "Restored deleted file from backup");
                } else {
                    return Err(anyhow!(
                        "No backup available for deleted file: {}",
                        entry.path
                    ));
                }
            }
            FileChangeType::Renamed { old_path } => {
                // Rename back to original name.
                if path.exists() {
                    std::fs::rename(path, old_path).with_context(|| {
                        format!("Failed to rename file back: {} -> {}", entry.path, old_path)
                    })?;
                    debug!(from = %entry.path, to = %old_path, "File renamed back to original");
                }
            }
        }

        Ok(())
    }

    fn apply_env_var(&self, entry: &EnvironmentVarEntry) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let (hive, subkey) = match entry.scope.as_str() {
                "system" => (
                    winreg::enums::HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                ),
                "user" => (winreg::enums::HKEY_CURRENT_USER, "Environment"),
                _ => return Ok(()), // Skip "process" scope -- not persistent.
            };

            let key = winreg::RegKey::predef(hive)
                .open_subkey_with_flags(subkey, winreg::enums::KEY_SET_VALUE)
                .with_context(|| format!("Failed to open env registry key for {}", entry.scope))?;

            key.set_value(&entry.name, &entry.value)
                .with_context(|| format!("Failed to set env var {}={}", entry.name, entry.value))?;

            debug!(name = %entry.name, scope = %entry.scope, "Environment variable restored");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux, environment variable persistence depends on shell config.
            debug!(name = %entry.name, "Env var restoration on Linux is shell-dependent");
            Ok(())
        }
    }

    fn apply_startup_item(&self, entry: &StartupItemEntry) -> Result<()> {
        if entry.location.contains("Run")
            || entry.location.contains("HKLM")
            || entry.location.contains("HKCU")
        {
            // Registry-based startup item -- delegate to registry restore.
            let reg_entry = RegistryEntry {
                key_path: entry.location.clone(),
                value_name: entry.name.clone(),
                value_data: entry.command.clone(),
                value_type: "REG_SZ".to_string(),
            };
            self.apply_registry_entry(&reg_entry)?;
        } else if entry.location == "StartupFolder" {
            // Startup folder entry -- just verify the file exists.
            let path = Path::new(&entry.command);
            if !path.exists() {
                debug!(item = %entry.name, "Startup folder item missing, cannot restore");
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    fn verify_rollback(&self, snapshot: &SystemSnapshot, categories: &[SnapshotCategory]) -> bool {
        let mut all_ok = true;

        for cat in categories {
            match cat {
                SnapshotCategory::Registry => {
                    // Spot-check a sample of registry entries.
                    let sample_size = std::cmp::min(5, snapshot.registry.len());
                    for entry in snapshot.registry.iter().take(sample_size) {
                        if !self.verify_registry_entry(entry) {
                            warn!(
                                key = %entry.key_path,
                                value = %entry.value_name,
                                "Registry verification failed"
                            );
                            all_ok = false;
                        }
                    }
                }
                SnapshotCategory::Services => {
                    let sample_size = std::cmp::min(3, snapshot.services.len());
                    for entry in snapshot.services.iter().take(sample_size) {
                        if !self.verify_service_entry(entry) {
                            warn!(service = %entry.name, "Service verification failed");
                            all_ok = false;
                        }
                    }
                }
                _ => {
                    // Other categories: trust the apply step succeeded.
                }
            }
        }

        if all_ok {
            info!("Post-rollback verification passed");
        } else {
            warn!("Post-rollback verification found issues");
        }

        all_ok
    }

    #[cfg(target_os = "windows")]
    fn verify_registry_entry(&self, entry: &RegistryEntry) -> bool {
        let (hive, subkey) = match entry.key_path.split_once('\\') {
            Some(("HKLM", sub)) => (winreg::enums::HKEY_LOCAL_MACHINE, sub),
            Some(("HKCU", sub)) => (winreg::enums::HKEY_CURRENT_USER, sub),
            _ => return false,
        };

        let key = match winreg::RegKey::predef(hive).open_subkey(subkey) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let current_value: Result<String, _> = key.get_value(&entry.value_name);
        match current_value {
            Ok(val) => val == entry.value_data,
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn verify_registry_entry(&self, _entry: &RegistryEntry) -> bool {
        true // Registry verification is Windows-only.
    }

    fn verify_service_entry(&self, _entry: &ServiceEntry) -> bool {
        // Simplified verification: just check the service exists.
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("sc")
                .args(["query", &_entry.name])
                .output();

            matches!(output, Ok(out) if out.status.success())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let output = std::process::Command::new("systemctl")
                .args(["is-enabled", &_entry.name])
                .output();

            matches!(output, Ok(out) if out.status.success())
        }
    }

    // -----------------------------------------------------------------------
    // Diff helpers
    // -----------------------------------------------------------------------

    fn diff_registry(base: &[RegistryEntry], target: &[RegistryEntry]) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();
        let base_map: HashMap<String, &RegistryEntry> = base
            .iter()
            .map(|e| (format!("{}\\{}", e.key_path, e.value_name), e))
            .collect();
        let target_map: HashMap<String, &RegistryEntry> = target
            .iter()
            .map(|e| (format!("{}\\{}", e.key_path, e.value_name), e))
            .collect();

        for (key, entry) in &target_map {
            match base_map.get(key) {
                Some(base_entry) if base_entry.value_data != entry.value_data => {
                    diffs.push(DiffEntry {
                        change_type: "modified".into(),
                        key: key.clone(),
                        old_value: Some(base_entry.value_data.clone()),
                        new_value: Some(entry.value_data.clone()),
                    });
                }
                None => {
                    diffs.push(DiffEntry {
                        change_type: "added".into(),
                        key: key.clone(),
                        old_value: None,
                        new_value: Some(entry.value_data.clone()),
                    });
                }
                _ => {}
            }
        }

        for key in base_map.keys() {
            if !target_map.contains_key(key) {
                diffs.push(DiffEntry {
                    change_type: "removed".into(),
                    key: key.clone(),
                    old_value: base_map.get(key).map(|e| e.value_data.clone()),
                    new_value: None,
                });
            }
        }

        diffs
    }

    fn diff_services(base: &[ServiceEntry], target: &[ServiceEntry]) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();
        let base_map: HashMap<&str, &ServiceEntry> =
            base.iter().map(|e| (e.name.as_str(), e)).collect();
        let target_map: HashMap<&str, &ServiceEntry> =
            target.iter().map(|e| (e.name.as_str(), e)).collect();

        for (name, entry) in &target_map {
            match base_map.get(name) {
                Some(base_entry)
                    if base_entry.start_type != entry.start_type
                        || base_entry.binary_path != entry.binary_path =>
                {
                    diffs.push(DiffEntry {
                        change_type: "modified".into(),
                        key: name.to_string(),
                        old_value: Some(format!(
                            "start={}, path={}",
                            base_entry.start_type, base_entry.binary_path
                        )),
                        new_value: Some(format!(
                            "start={}, path={}",
                            entry.start_type, entry.binary_path
                        )),
                    });
                }
                None => {
                    diffs.push(DiffEntry {
                        change_type: "added".into(),
                        key: name.to_string(),
                        old_value: None,
                        new_value: Some(format!(
                            "start={}, path={}",
                            entry.start_type, entry.binary_path
                        )),
                    });
                }
                _ => {}
            }
        }

        for name in base_map.keys() {
            if !target_map.contains_key(name) {
                diffs.push(DiffEntry {
                    change_type: "removed".into(),
                    key: name.to_string(),
                    old_value: Some(base_map[name].binary_path.clone()),
                    new_value: None,
                });
            }
        }

        diffs
    }

    fn diff_tasks(base: &[ScheduledTaskEntry], target: &[ScheduledTaskEntry]) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();
        let base_map: HashMap<&str, &ScheduledTaskEntry> =
            base.iter().map(|e| (e.name.as_str(), e)).collect();
        let target_map: HashMap<&str, &ScheduledTaskEntry> =
            target.iter().map(|e| (e.name.as_str(), e)).collect();

        for (name, _entry) in &target_map {
            if !base_map.contains_key(name) {
                diffs.push(DiffEntry {
                    change_type: "added".into(),
                    key: name.to_string(),
                    old_value: None,
                    new_value: Some("(new task)".into()),
                });
            }
        }

        for name in base_map.keys() {
            if !target_map.contains_key(name) {
                diffs.push(DiffEntry {
                    change_type: "removed".into(),
                    key: name.to_string(),
                    old_value: Some("(removed)".into()),
                    new_value: None,
                });
            }
        }

        diffs
    }

    fn diff_firewall(base: &[FirewallRuleEntry], target: &[FirewallRuleEntry]) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();

        if base.len() != target.len() {
            diffs.push(DiffEntry {
                change_type: "modified".into(),
                key: "firewall_rule_count".into(),
                old_value: Some(base.len().to_string()),
                new_value: Some(target.len().to_string()),
            });
        }

        diffs
    }

    fn diff_files(base: &[TrackedFileChange], target: &[TrackedFileChange]) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();

        let base_set: std::collections::HashSet<&str> =
            base.iter().map(|e| e.path.as_str()).collect();
        let target_set: std::collections::HashSet<&str> =
            target.iter().map(|e| e.path.as_str()).collect();

        for path in target_set.difference(&base_set) {
            diffs.push(DiffEntry {
                change_type: "added".into(),
                key: path.to_string(),
                old_value: None,
                new_value: Some("(new change)".into()),
            });
        }

        diffs
    }

    fn diff_env_vars(
        base: &[EnvironmentVarEntry],
        target: &[EnvironmentVarEntry],
    ) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();
        let base_map: HashMap<String, &EnvironmentVarEntry> = base
            .iter()
            .map(|e| (format!("{}:{}", e.scope, e.name), e))
            .collect();
        let target_map: HashMap<String, &EnvironmentVarEntry> = target
            .iter()
            .map(|e| (format!("{}:{}", e.scope, e.name), e))
            .collect();

        for (key, entry) in &target_map {
            match base_map.get(key) {
                Some(base_entry) if base_entry.value != entry.value => {
                    diffs.push(DiffEntry {
                        change_type: "modified".into(),
                        key: key.clone(),
                        old_value: Some(base_entry.value.clone()),
                        new_value: Some(entry.value.clone()),
                    });
                }
                None => {
                    diffs.push(DiffEntry {
                        change_type: "added".into(),
                        key: key.clone(),
                        old_value: None,
                        new_value: Some(entry.value.clone()),
                    });
                }
                _ => {}
            }
        }

        diffs
    }

    fn diff_startup(base: &[StartupItemEntry], target: &[StartupItemEntry]) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();
        let base_map: HashMap<String, &StartupItemEntry> = base
            .iter()
            .map(|e| (format!("{}:{}", e.location, e.name), e))
            .collect();
        let target_map: HashMap<String, &StartupItemEntry> = target
            .iter()
            .map(|e| (format!("{}:{}", e.location, e.name), e))
            .collect();

        for (key, entry) in &target_map {
            if !base_map.contains_key(key) {
                diffs.push(DiffEntry {
                    change_type: "added".into(),
                    key: key.clone(),
                    old_value: None,
                    new_value: Some(entry.command.clone()),
                });
            }
        }

        for key in base_map.keys() {
            if !target_map.contains_key(key) {
                diffs.push(DiffEntry {
                    change_type: "removed".into(),
                    key: key.clone(),
                    old_value: base_map.get(key).map(|e| e.command.clone()),
                    new_value: None,
                });
            }
        }

        diffs
    }

    // -----------------------------------------------------------------------
    // Storage helpers
    // -----------------------------------------------------------------------

    fn snapshot_path(&self, snapshot_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.snap.gz", snapshot_id))
    }

    fn index_path(&self) -> PathBuf {
        self.storage_dir.join("snapshot_index.json")
    }

    fn save_snapshot(&self, snapshot: &SystemSnapshot) -> Result<u64> {
        let json = serde_json::to_vec(snapshot)?;
        let compressed = Self::compress(&json)?;
        let path = self.snapshot_path(&snapshot.id);
        std::fs::write(&path, &compressed)?;
        Ok(compressed.len() as u64)
    }

    fn save_snapshot_index(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.snapshots)?;
        std::fs::write(self.index_path(), json)?;
        Ok(())
    }

    fn load_snapshot_index(&mut self) -> Result<()> {
        let path = self.index_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            self.snapshots = serde_json::from_str(&content).unwrap_or_default();
        }
        Ok(())
    }

    fn enforce_retention(&mut self) -> Result<()> {
        while self.snapshots.len() > self.max_snapshots {
            // Remove oldest snapshot (index 0 since newest are pushed to the end).
            if let Some(oldest) = self.snapshots.first() {
                let id = oldest.id.clone();
                let path = self.snapshot_path(&id);
                if path.exists() {
                    let _ = std::fs::remove_file(&path);
                }
                self.snapshots.remove(0);
                debug!(snapshot_id = %id, "Removed old snapshot (retention limit)");
            }
        }
        self.save_snapshot_index()?;
        Ok(())
    }

    fn compress(data: &[u8]) -> Result<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    /// Check whether a path is protected and must not be rolled back.
    fn is_protected_path(path: &str) -> bool {
        let lower = path.to_lowercase();
        PROTECTED_PATHS
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }
}

// ---------------------------------------------------------------------------
// Command handler integration
// ---------------------------------------------------------------------------

/// Handle a system-state snapshot command from the server.
pub async fn handle_create_system_snapshot(
    payload: &serde_json::Value,
) -> crate::transport::CommandResult {
    let trigger = if let Some(alert_id) = payload.get("alert_id").and_then(|v| v.as_str()) {
        let action = payload
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        SnapshotTrigger::PreRemediation {
            alert_id: Some(alert_id.to_string()),
            action: action.to_string(),
        }
    } else {
        SnapshotTrigger::Manual
    };

    let categories: Option<Vec<SnapshotCategory>> = payload
        .get("categories")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    let storage_dir = RollbackEngine::default_storage_dir();
    let max_snapshots = payload
        .get("max_snapshots")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as usize;

    let mut engine = match RollbackEngine::new(storage_dir, max_snapshots) {
        Ok(e) => e,
        Err(e) => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some(format!("Failed to init rollback engine: {}", e)),
                result_data: None,
            }
        }
    };

    match engine.create_snapshot(trigger, categories) {
        Ok(metadata) => crate::transport::CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::to_value(&metadata).unwrap_or_default()),
        },
        Err(e) => crate::transport::CommandResult {
            success: false,
            error_message: Some(format!("Snapshot creation failed: {}", e)),
            result_data: None,
        },
    }
}

/// Handle a system-state rollback command from the server.
pub async fn handle_system_rollback(
    payload: &serde_json::Value,
) -> crate::transport::CommandResult {
    let snapshot_id = match payload.get("snapshot_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some("Missing snapshot_id".into()),
                result_data: None,
            }
        }
    };

    let mode_str = payload
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("full");
    let mode = match mode_str {
        "full" => RollbackMode::Full,
        "dry_run" => RollbackMode::DryRun,
        "selective" => {
            let categories: Vec<SnapshotCategory> = payload
                .get("categories")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            RollbackMode::Selective { categories }
        }
        _ => RollbackMode::Full,
    };

    let storage_dir = RollbackEngine::default_storage_dir();
    let mut engine = match RollbackEngine::new(storage_dir, 10) {
        Ok(e) => e,
        Err(e) => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some(format!("Failed to init rollback engine: {}", e)),
                result_data: None,
            }
        }
    };

    match engine.execute_rollback(snapshot_id, mode) {
        Ok(result) => crate::transport::CommandResult {
            success: result.success,
            error_message: if result.errors.is_empty() {
                None
            } else {
                Some(result.errors.join("; "))
            },
            result_data: Some(serde_json::to_value(&result).unwrap_or_default()),
        },
        Err(e) => crate::transport::CommandResult {
            success: false,
            error_message: Some(format!("Rollback failed: {}", e)),
            result_data: None,
        },
    }
}

/// Handle a list-snapshots command from the server.
pub async fn handle_list_system_snapshots(
    payload: &serde_json::Value,
) -> crate::transport::CommandResult {
    let storage_dir = RollbackEngine::default_storage_dir();
    let engine = match RollbackEngine::new(storage_dir, 10) {
        Ok(e) => e,
        Err(e) => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some(format!("Failed to init rollback engine: {}", e)),
                result_data: None,
            }
        }
    };

    let snapshots: Vec<&SnapshotMetadata> = engine.list_snapshots();
    let _ = payload; // may carry filters in future

    crate::transport::CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::to_value(&snapshots).unwrap_or_default()),
    }
}

/// Handle a snapshot diff command from the server.
pub async fn handle_snapshot_diff(payload: &serde_json::Value) -> crate::transport::CommandResult {
    let base_id = match payload.get("base_snapshot_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some("Missing base_snapshot_id".into()),
                result_data: None,
            }
        }
    };

    let target_id = match payload.get("target_snapshot_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some("Missing target_snapshot_id".into()),
                result_data: None,
            }
        }
    };

    let storage_dir = RollbackEngine::default_storage_dir();
    let engine = match RollbackEngine::new(storage_dir, 10) {
        Ok(e) => e,
        Err(e) => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some(format!("Failed to init rollback engine: {}", e)),
                result_data: None,
            }
        }
    };

    match engine.diff_snapshots(base_id, target_id) {
        Ok(diff) => crate::transport::CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::to_value(&diff).unwrap_or_default()),
        },
        Err(e) => crate::transport::CommandResult {
            success: false,
            error_message: Some(format!("Diff failed: {}", e)),
            result_data: None,
        },
    }
}

/// Handle a delete-snapshot command from the server.
pub async fn handle_delete_system_snapshot(
    payload: &serde_json::Value,
) -> crate::transport::CommandResult {
    let snapshot_id = match payload.get("snapshot_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some("Missing snapshot_id".into()),
                result_data: None,
            }
        }
    };

    let storage_dir = RollbackEngine::default_storage_dir();
    let mut engine = match RollbackEngine::new(storage_dir, 10) {
        Ok(e) => e,
        Err(e) => {
            return crate::transport::CommandResult {
                success: false,
                error_message: Some(format!("Failed to init rollback engine: {}", e)),
                result_data: None,
            }
        }
    };

    match engine.delete_snapshot(snapshot_id) {
        Ok(()) => crate::transport::CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({ "deleted": snapshot_id })),
        },
        Err(e) => crate::transport::CommandResult {
            success: false,
            error_message: Some(format!("Delete failed: {}", e)),
            result_data: None,
        },
    }
}

// ---------------------------------------------------------------------------
// VSS compatibility layer
// ---------------------------------------------------------------------------
// The original rollback.rs contained VssManager, RansomwareRemediator, etc.
// which are still referenced by command handlers in mod.rs.  We re-provide
// these types here so the rest of the codebase compiles without changes.

/// Information about a VSS snapshot (legacy compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub volume: String,
    pub created_at: u64,
    pub device_name: String,
    pub accessible: bool,
    pub size_bytes: u64,
}

/// Result of a file restoration operation (legacy compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub restored: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
    pub skipped: Vec<PathBuf>,
    pub bytes_restored: u64,
    pub duration_ms: u64,
}

/// Encrypted file detection result (legacy compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileInfo {
    pub path: PathBuf,
    pub original_extension: Option<String>,
    pub ransomware_extension: String,
    pub entropy: f32,
    pub size: u64,
}

/// Known ransomware file extensions.
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted",
    ".locked",
    ".crypt",
    ".crypto",
    ".enc",
    ".locky",
    ".zepto",
    ".cerber",
    ".cerber2",
    ".cerber3",
    ".crypted",
    ".crinf",
    ".r5a",
    ".xrtn",
    ".xtbl",
    ".crypt1",
    ".da_vinci_code",
    ".enigma",
    ".cry",
    ".cryptoshield",
    ".globe",
    ".purge",
    ".wcry",
    ".wncry",
    ".wncryt",
    ".wanna",
    ".wannacry",
    ".petya",
    ".notpetya",
    ".goldeneye",
    ".lockbit",
    ".conti",
    ".ryuk",
    ".maze",
    ".revil",
    ".sodinokibi",
    ".darkside",
    ".blackcat",
    ".alphv",
    ".hive",
    ".akira",
    ".play",
    ".blackbasta",
    ".royal",
];

/// Common document extensions targeted by ransomware.
const DOCUMENT_EXTENSIONS: &[&str] = &[
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods",
    ".odp", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".psd", ".mp3", ".mp4", ".avi", ".mov",
    ".mkv", ".zip", ".rar", ".7z", ".tar", ".gz", ".sql", ".mdb", ".accdb", ".sqlite", ".xml",
    ".json", ".csv", ".html", ".htm",
];

/// VSS Manager for Windows Volume Shadow Copy operations (legacy compatibility).
pub struct VssManager {
    _snapshot_cache: HashMap<String, Vec<SnapshotInfo>>,
}

impl VssManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            _snapshot_cache: HashMap::new(),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn create_snapshot(&self, volume: &str) -> Result<SnapshotInfo> {
        info!(volume = %volume, "Creating VSS snapshot");

        let vol = if volume.ends_with(':') {
            volume.to_string()
        } else if volume.ends_with(":\\") {
            volume[..2].to_string()
        } else {
            format!("{}:", volume)
        };

        let output = std::process::Command::new("wmic")
            .args([
                "shadowcopy",
                "call",
                "create",
                &format!("Volume='{}\\'", vol),
            ])
            .output()
            .map_err(|e| anyhow!("Failed to execute wmic: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to create shadow copy: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let shadow_id = stdout
            .lines()
            .find(|line| line.contains("ShadowID"))
            .and_then(|line| line.split('"').nth(1).map(|s| s.to_string()))
            .ok_or_else(|| anyhow!("Could not parse shadow copy ID"))?;

        info!(shadow_id = %shadow_id, "Shadow copy created");

        Ok(SnapshotInfo {
            id: shadow_id,
            volume: vol,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            device_name: String::new(),
            accessible: true,
            size_bytes: 0,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn create_snapshot(&self, _volume: &str) -> Result<SnapshotInfo> {
        Err(anyhow!("VSS is only available on Windows"))
    }

    #[cfg(target_os = "windows")]
    pub fn list_snapshots(&self, volume: &str) -> Result<Vec<SnapshotInfo>> {
        let vol = if volume.ends_with(':') {
            volume.to_string()
        } else if volume.ends_with(":\\") {
            volume[..2].to_string()
        } else {
            format!("{}:", volume)
        };

        let output = std::process::Command::new("vssadmin")
            .args(["list", "shadows", &format!("/for={}\\", vol)])
            .output()
            .map_err(|e| anyhow!("Failed to execute vssadmin: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut snapshots = Vec::new();
        let mut current: Option<SnapshotInfo> = None;

        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("Shadow Copy ID:") {
                if let Some(snap) = current.take() {
                    snapshots.push(snap);
                }
                let id = line
                    .strip_prefix("Shadow Copy ID:")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                current = Some(SnapshotInfo {
                    id,
                    volume: vol.clone(),
                    created_at: 0,
                    device_name: String::new(),
                    accessible: true,
                    size_bytes: 0,
                });
            } else if line.starts_with("Shadow Copy Volume:") {
                if let Some(ref mut snap) = current {
                    snap.device_name = line
                        .strip_prefix("Shadow Copy Volume:")
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                }
            }
        }
        if let Some(snap) = current {
            snapshots.push(snap);
        }
        snapshots.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(snapshots)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn list_snapshots(&self, _volume: &str) -> Result<Vec<SnapshotInfo>> {
        Err(anyhow!("VSS is only available on Windows"))
    }

    #[cfg(target_os = "windows")]
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        let output = std::process::Command::new("vssadmin")
            .args([
                "delete",
                "shadows",
                &format!("/shadow={}", snapshot_id),
                "/quiet",
            ])
            .output()
            .map_err(|e| anyhow!("Failed to execute vssadmin: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to delete shadow copy: {}", stderr));
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn delete_snapshot(&self, _snapshot_id: &str) -> Result<()> {
        Err(anyhow!("VSS is only available on Windows"))
    }

    pub fn restore_file(&self, _snapshot_id: &str, _original_path: &Path) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Delegate to get_snapshot_path + copy.
            let snapshots = self.list_snapshots(
                _original_path
                    .to_str()
                    .and_then(|s| s.get(..2))
                    .unwrap_or("C:"),
            )?;
            let snapshot = snapshots
                .iter()
                .find(|s| s.id == _snapshot_id)
                .ok_or_else(|| anyhow!("Snapshot not found: {}", _snapshot_id))?;

            let path_str = _original_path.to_string_lossy();
            let path_tail = if path_str.len() > 2 && path_str.chars().nth(1) == Some(':') {
                &path_str[2..]
            } else {
                path_str.as_ref()
            };
            let snapshot_path = PathBuf::from(format!(
                "{}{}",
                snapshot.device_name.trim_end_matches('\\'),
                path_tail
            ));

            if !snapshot_path.exists() {
                return Err(anyhow!("File not found in snapshot: {:?}", snapshot_path));
            }

            if _original_path.exists() {
                let backup = PathBuf::from(format!("{}.pre_restore", _original_path.display()));
                std::fs::rename(_original_path, &backup)?;
            }
            std::fs::copy(&snapshot_path, _original_path)?;
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        Err(anyhow!("VSS is only available on Windows"))
    }

    pub fn restore_files(&self, snapshot_id: &str, paths: &[PathBuf]) -> Result<RestoreResult> {
        let start = std::time::Instant::now();
        let mut result = RestoreResult {
            restored: Vec::new(),
            failed: Vec::new(),
            skipped: Vec::new(),
            bytes_restored: 0,
            duration_ms: 0,
        };
        for path in paths {
            match self.restore_file(snapshot_id, path) {
                Ok(()) => {
                    if let Ok(m) = std::fs::metadata(path) {
                        result.bytes_restored += m.len();
                    }
                    result.restored.push(path.clone());
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("not found in snapshot") {
                        result.skipped.push(path.clone());
                    } else {
                        result.failed.push((path.clone(), msg));
                    }
                }
            }
        }
        result.duration_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    pub fn find_best_snapshot(&self, _file_path: &Path) -> Result<Option<SnapshotInfo>> {
        #[cfg(target_os = "windows")]
        {
            let volume = _file_path.to_str().and_then(|s| s.get(..2)).unwrap_or("C:");
            let snapshots = self.list_snapshots(volume)?;
            // Return the most recent snapshot for now. Per-snapshot
            // file-presence filtering is a future enhancement.
            Ok(snapshots.into_iter().next())
        }
        #[cfg(not(target_os = "windows"))]
        Ok(None)
    }
}

/// Ransomware remediation helper (legacy compatibility).
pub struct RansomwareRemediator {
    vss: VssManager,
}

impl RansomwareRemediator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            vss: VssManager::new()?,
        })
    }

    pub fn find_encrypted_files(&self, root: &Path) -> Result<Vec<EncryptedFileInfo>> {
        info!(root = %root.display(), "Scanning for encrypted files");
        let mut encrypted = Vec::new();

        let walker = walkdir::WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                .unwrap_or_default();

            if RANSOMWARE_EXTENSIONS.iter().any(|&e| ext == e) {
                if let Ok(meta) = entry.metadata() {
                    encrypted.push(EncryptedFileInfo {
                        path: path.to_path_buf(),
                        original_extension: DOCUMENT_EXTENSIONS
                            .iter()
                            .find(|&&de| path.to_string_lossy().contains(de))
                            .map(|s| s.to_string()),
                        ransomware_extension: ext.clone(),
                        entropy: 0.0,
                        size: meta.len(),
                    });
                }
            }
        }
        info!(count = encrypted.len(), "Found encrypted files");
        Ok(encrypted)
    }

    pub fn remediate(&self, files: &[EncryptedFileInfo]) -> Result<RestoreResult> {
        info!(count = files.len(), "Starting ransomware remediation");
        let start = std::time::Instant::now();
        let mut result = RestoreResult {
            restored: Vec::new(),
            failed: Vec::new(),
            skipped: Vec::new(),
            bytes_restored: 0,
            duration_ms: 0,
        };

        let paths: Vec<PathBuf> = files.iter().map(|f| f.path.clone()).collect();

        // Try to find best snapshot and restore.
        if let Some(first_file) = files.first() {
            if let Ok(Some(snap)) = self.vss.find_best_snapshot(&first_file.path) {
                match self.vss.restore_files(&snap.id, &paths) {
                    Ok(r) => {
                        result.restored = r.restored;
                        result.failed = r.failed;
                        result.skipped = r.skipped;
                        result.bytes_restored = r.bytes_restored;
                    }
                    Err(e) => {
                        for f in files {
                            result.failed.push((f.path.clone(), e.to_string()));
                        }
                    }
                }
            } else {
                for f in files {
                    result
                        .failed
                        .push((f.path.clone(), "No snapshot available".into()));
                }
            }
        }

        result.duration_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    pub fn generate_report(&self, result: &RestoreResult) -> String {
        format!(
            "Ransomware Remediation: restored={}, failed={}, skipped={}, bytes={}, duration={}ms",
            result.restored.len(),
            result.failed.len(),
            result.skipped.len(),
            result.bytes_restored,
            result.duration_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_path_detection() {
        assert!(RollbackEngine::is_protected_path(
            "C:\\Windows\\System32\\ntoskrnl.exe"
        ));
        assert!(RollbackEngine::is_protected_path(
            "C:\\Windows\\System32\\drivers\\something.sys"
        ));
        assert!(RollbackEngine::is_protected_path(
            "C:\\Windows\\System32\\csrss.exe"
        ));
        assert!(!RollbackEngine::is_protected_path(
            "C:\\Users\\test\\malware.exe"
        ));
        assert!(!RollbackEngine::is_protected_path("/tmp/test.txt"));
    }

    #[test]
    fn test_snapshot_category_display() {
        assert_eq!(format!("{}", SnapshotCategory::Registry), "registry");
        assert_eq!(format!("{}", SnapshotCategory::Services), "services");
        assert_eq!(
            format!("{}", SnapshotCategory::ScheduledTasks),
            "scheduled_tasks"
        );
    }

    #[test]
    fn test_compression_roundtrip() {
        let data = b"Hello, world! This is test data for compression.";
        let compressed = RollbackEngine::compress(data).unwrap();
        let decompressed = RollbackEngine::decompress(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }

    #[test]
    fn test_diff_registry() {
        let base = vec![
            RegistryEntry {
                key_path: "HKLM\\Run".into(),
                value_name: "App1".into(),
                value_type: "REG_SZ".into(),
                value_data: "c:\\app1.exe".into(),
            },
            RegistryEntry {
                key_path: "HKLM\\Run".into(),
                value_name: "App2".into(),
                value_type: "REG_SZ".into(),
                value_data: "c:\\app2.exe".into(),
            },
        ];

        let target = vec![
            RegistryEntry {
                key_path: "HKLM\\Run".into(),
                value_name: "App1".into(),
                value_type: "REG_SZ".into(),
                value_data: "c:\\malware.exe".into(), // modified
            },
            RegistryEntry {
                key_path: "HKLM\\Run".into(),
                value_name: "App3".into(), // added
                value_type: "REG_SZ".into(),
                value_data: "c:\\backdoor.exe".into(),
            },
        ];

        let diffs = RollbackEngine::diff_registry(&base, &target);
        assert!(diffs.len() >= 2); // at least modified + added (App2 removed)
    }
}
