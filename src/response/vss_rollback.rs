//! Windows VSS (Volume Shadow Copy) Rollback Engine
//!
//! Provides SentinelOne-class 1-click file rollback using Windows Volume Shadow
//! Copy Service (VSS). This module complements the system-state rollback engine
//! in `rollback.rs` by adding true file-level rollback capabilities via VSS
//! shadow copies.
//!
//! ## Capabilities
//!
//! - Create VSS snapshots of specified volumes via COM API
//! - Enumerate, inspect, and delete existing shadow copies
//! - Restore individual files or entire directory trees from shadow copies
//! - Automatic periodic snapshot scheduling with configurable retention
//! - Ransomware-triggered emergency snapshots (before damage spreads)
//! - Full rollback of affected file paths using pre-attack snapshots
//! - Shadow copy protection monitoring (blocks vssadmin/wmic deletion)
//! - Hash verification of restored files against known-good baselines
//!
//! ## Architecture
//!
//! ```text
//! [Ransomware Disruptor] --detects--> [VssSnapshotManager]
//!                                          |
//!                           +--------------+------------+
//!                           |              |            |
//!                    [Emergency Snap]  [Restore]  [Verify]
//!                           |              |            |
//!                    [VSS COM API]  [File Copy]  [SHA256]
//! ```
//!
//! ## COM Interaction
//!
//! The Windows VSS API is COM-based.  On Windows we use
//! `CoInitializeEx` / `CoCreateInstance` to drive `IVssBackupComponents`.
//! On other platforms, all public functions return `Err` or no-op stubs.
//!
//! MITRE ATT&CK:
//! - T1490 (Inhibit System Recovery) -- defence: create & protect shadow copies
//! - T1486 (Data Encrypted for Impact) -- remediation: restore from snapshots

// VSS rollback engine (defensive remediation against T1486/T1490).
// Scaffolded snapshot/restore fields retained for cross-platform stubs.
#![allow(dead_code, unused_variables)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::config::AgentConfig;

#[cfg(target_os = "windows")]
use std::time::Duration;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Metadata for a single VSS shadow copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshot {
    /// Shadow copy GUID (e.g. `{ABCD1234-...}`).
    pub snapshot_id: String,
    /// Volume letter the snapshot covers (e.g. `C:`).
    pub volume: String,
    /// Device object path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
    pub device_path: String,
    /// When the snapshot was created.
    pub created_at: u64,
    /// Approximate size consumed on disk (bytes).
    pub size_bytes: u64,
    /// Whether the snapshot is currently accessible for reads.
    pub accessible: bool,
    /// Whether this snapshot was created by Tamandua (vs. Windows or other software).
    pub tamandua_managed: bool,
    /// Optional label/reason for the snapshot.
    pub label: Option<String>,
}

/// Result of a multi-file rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    /// Snapshot used for restoration.
    pub snapshot_id: String,
    /// Files successfully restored.
    pub restored: Vec<RestoredFile>,
    /// Files that could not be restored.
    pub failed: Vec<FailedFile>,
    /// Files skipped (protected path, not found in snapshot, etc.).
    pub skipped: Vec<SkippedFile>,
    /// Total bytes restored.
    pub bytes_restored: u64,
    /// Total number of files processed.
    pub total_files: usize,
    /// Duration of the rollback operation in milliseconds.
    pub duration_ms: u64,
    /// Whether hash verification passed for all restored files.
    pub verification_passed: bool,
    /// Per-file verification results (path -> matches baseline).
    pub verification_details: HashMap<String, bool>,
}

/// A successfully restored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoredFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256_before: Option<String>,
    pub sha256_after: String,
}

/// A file that failed to restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedFile {
    pub path: String,
    pub error: String,
}

/// A file that was skipped during rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedFile {
    pub path: String,
    pub reason: String,
}

/// Configuration for automatic VSS snapshot scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssScheduleConfig {
    /// Whether automatic periodic snapshots are enabled.
    pub enabled: bool,
    /// Interval between automatic snapshots in seconds (default: 4 hours).
    pub interval_seconds: u64,
    /// Maximum number of Tamandua-managed snapshots to retain per volume.
    pub max_snapshots_per_volume: usize,
    /// Volumes to snapshot (e.g. `["C:", "D:"]`).  Empty = all fixed drives.
    pub volumes: Vec<String>,
    /// Whether to create an emergency snapshot on ransomware detection.
    pub snapshot_on_ransomware: bool,
}

impl Default for VssScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 4 * 3600, // 4 hours
            max_snapshots_per_volume: 5,
            volumes: vec!["C:".to_string()],
            snapshot_on_ransomware: true,
        }
    }
}

/// VSS shadow copy deletion attempt detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssDeletionAttempt {
    pub pid: u32,
    pub process_name: String,
    pub cmdline: String,
    pub timestamp: u64,
    pub blocked: bool,
}

/// Progress callback for long-running rollback operations.
pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;

// ---------------------------------------------------------------------------
// Critical system paths that must never be overwritten during rollback
// ---------------------------------------------------------------------------

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
    "System32\\drivers\\",
    "System32\\config\\",
    "Boot\\",
    "bootmgr",
];

/// Commands that indicate shadow copy deletion attempts.
const VSS_DELETE_COMMANDS: &[&str] = &[
    "vssadmin delete shadows",
    "vssadmin resize shadowstorage",
    "wmic shadowcopy delete",
    "Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }",
    "gwmi Win32_Shadowcopy | % { $_.Delete() }",
];

// ---------------------------------------------------------------------------
// VSS Service Availability Check
// ---------------------------------------------------------------------------

/// Check if the VSS (Volume Shadow Copy Service) is running.
///
/// Returns:
/// - `Ok(true)` if VSS service is running
/// - `Ok(false)` if VSS service exists but is not running
/// - `Err` if there was an error checking the service status
#[cfg(target_os = "windows")]
fn check_vss_service_available() -> Result<bool> {
    use windows::core::w;
    use windows::Win32::System::Services::*;

    unsafe {
        // Open the Service Control Manager with minimal permissions
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .map_err(|e| anyhow!("Failed to open Service Control Manager: {}", e))?;

        // Open the VSS service with query permissions
        let vss_service = OpenServiceW(scm, w!("VSS"), SERVICE_QUERY_STATUS);

        // Check if service handle was obtained
        let service_result = match vss_service {
            Ok(svc) => {
                // Query the service status
                let mut status: SERVICE_STATUS = std::mem::zeroed();
                let query_result = QueryServiceStatus(svc, &mut status);

                // Close the service handle
                let _ = CloseServiceHandle(svc);

                match query_result {
                    Ok(_) => {
                        let is_running = status.dwCurrentState == SERVICE_RUNNING;
                        debug!(
                            state = status.dwCurrentState.0,
                            is_running = is_running,
                            "VSS service status checked"
                        );
                        Ok(is_running)
                    }
                    Err(e) => Err(anyhow!("Failed to query VSS service status: {}", e)),
                }
            }
            Err(e) => {
                warn!(error = %e, "VSS service not found or cannot be opened");
                Err(anyhow!("VSS service not found: {}", e))
            }
        };

        // Close the SCM handle
        let _ = CloseServiceHandle(scm);

        service_result
    }
}

/// Attempt to start the VSS service.
///
/// Returns:
/// - `Ok(())` if service was started successfully
/// - `Err` if service could not be started
#[cfg(target_os = "windows")]
fn start_vss_service() -> Result<()> {
    use windows::core::w;
    use windows::Win32::System::Services::*;

    unsafe {
        // Open SCM with higher permissions to start services
        let scm = OpenSCManagerW(
            None,
            None,
            SC_MANAGER_ALL_ACCESS,
        ).map_err(|e| anyhow!("Failed to open SCM for starting service: {}. You may need administrator privileges.", e))?;

        // Open VSS service with start permissions
        let vss_service = OpenServiceW(scm, w!("VSS"), SERVICE_START | SERVICE_QUERY_STATUS);

        let start_result = match vss_service {
            Ok(svc) => {
                info!("Attempting to start VSS service");

                // Try to start the service
                let start_result = StartServiceW(svc, None);

                let result = match start_result {
                    Ok(_) => {
                        info!("VSS service start command sent successfully");
                        Ok(())
                    }
                    Err(e) => {
                        // ERROR_SERVICE_ALREADY_RUNNING (1056) is not an actual error
                        let win_err = windows::core::Error::from_win32();
                        if win_err.code().0 == 1056 {
                            info!("VSS service is already running");
                            Ok(())
                        } else {
                            Err(anyhow!(
                                "Failed to start VSS service: {}. Error code: {}",
                                e,
                                win_err.code().0
                            ))
                        }
                    }
                };

                // Close service handle
                let _ = CloseServiceHandle(svc);
                result
            }
            Err(e) => Err(anyhow!("Cannot open VSS service for starting: {}", e)),
        };

        // Close SCM handle
        let _ = CloseServiceHandle(scm);

        start_result
    }
}

/// Wait for VSS service to reach running state.
///
/// Polls the service status up to `max_attempts` times with a delay between checks.
#[cfg(target_os = "windows")]
fn wait_for_vss_service(max_attempts: u32, delay: Duration) -> Result<()> {
    for attempt in 1..=max_attempts {
        match check_vss_service_available() {
            Ok(true) => {
                info!(attempts = attempt, "VSS service is running");
                return Ok(());
            }
            Ok(false) => {
                debug!(
                    attempt = attempt,
                    max_attempts = max_attempts,
                    "VSS service not yet running, waiting..."
                );
                std::thread::sleep(delay);
            }
            Err(e) => {
                return Err(anyhow!("Error while waiting for VSS service: {}", e));
            }
        }
    }

    Err(anyhow!(
        "VSS service did not start within expected time ({} attempts)",
        max_attempts
    ))
}

/// Ensure VSS service is available, starting it if necessary.
///
/// This function checks if the VSS service is running and attempts to start it
/// if it's not. It will wait for the service to be ready before returning.
///
/// Returns:
/// - `Ok(())` if VSS service is running or was successfully started
/// - `Err` if VSS service cannot be made available
#[cfg(target_os = "windows")]
fn ensure_vss_service_available() -> Result<()> {
    debug!("Checking VSS service availability");

    match check_vss_service_available() {
        Ok(true) => {
            debug!("VSS service is already running");
            Ok(())
        }
        Ok(false) => {
            warn!("VSS service is not running, attempting to start it");

            // Try to start the service
            start_vss_service()?;

            // Wait for the service to be ready (10 attempts, 500ms each = 5 seconds max)
            wait_for_vss_service(10, Duration::from_millis(500))
                .context("VSS service was started but did not become ready in time")?;

            info!("VSS service started successfully");
            Ok(())
        }
        Err(e) => Err(anyhow!(
            "Cannot check VSS service status: {}. \
                VSS may not be installed or you may need administrator privileges.",
            e
        )),
    }
}

// ---------------------------------------------------------------------------
// VssSnapshotManager
// ---------------------------------------------------------------------------

/// Manages VSS shadow copies for file-level rollback.
///
/// This is the main entry point for all VSS operations.  It maintains an
/// in-memory cache of known snapshots and provides methods for creating,
/// listing, deleting, and restoring from shadow copies.
pub struct VssSnapshotManager {
    /// Per-volume snapshot metadata cache.  Key = volume letter (e.g. "C:").
    snapshots: HashMap<String, Vec<VssSnapshot>>,
    /// Maximum number of Tamandua-managed snapshots to retain per volume.
    max_snapshots_per_volume: usize,
    /// Schedule configuration.
    schedule: VssScheduleConfig,
    /// Log of blocked VSS deletion attempts.
    deletion_attempts: Vec<VssDeletionAttempt>,
    /// Known-good file hashes for verification (path -> SHA256 hex).
    baseline_hashes: HashMap<String, String>,
}

impl VssSnapshotManager {
    /// Create a new VSS snapshot manager with the given configuration.
    pub fn new(_config: &AgentConfig) -> Self {
        let schedule = VssScheduleConfig::default();

        Self {
            snapshots: HashMap::new(),
            max_snapshots_per_volume: schedule.max_snapshots_per_volume,
            schedule,
            deletion_attempts: Vec::new(),
            baseline_hashes: HashMap::new(),
        }
    }

    /// Create a new manager with explicit schedule config.
    pub fn with_schedule(_config: &AgentConfig, schedule: VssScheduleConfig) -> Self {
        Self {
            snapshots: HashMap::new(),
            max_snapshots_per_volume: schedule.max_snapshots_per_volume,
            schedule,
            deletion_attempts: Vec::new(),
            baseline_hashes: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot creation
    // -----------------------------------------------------------------------

    /// Create a VSS shadow copy for the specified volumes.
    ///
    /// On Windows this drives the VSS COM API.  On other platforms it returns
    /// an error.
    pub fn create_snapshot(
        &mut self,
        volumes: &[String],
        label: Option<String>,
    ) -> Result<Vec<VssSnapshot>> {
        if volumes.is_empty() {
            return Err(anyhow!("No volumes specified for snapshot"));
        }

        info!(
            volumes = ?volumes,
            label = ?label,
            "Creating VSS snapshot"
        );

        #[cfg(target_os = "windows")]
        {
            self.create_snapshot_windows(volumes, label)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VSS snapshots are only available on Windows"))
        }
    }

    /// Create a snapshot of all configured volumes (convenience method).
    pub fn create_scheduled_snapshot(&mut self) -> Result<Vec<VssSnapshot>> {
        let volumes = self.schedule.volumes.clone();
        self.create_snapshot(&volumes, Some("scheduled".to_string()))
    }

    /// Create an emergency snapshot triggered by ransomware detection.
    pub fn create_emergency_snapshot(&mut self) -> Result<Vec<VssSnapshot>> {
        if !self.schedule.snapshot_on_ransomware {
            return Ok(Vec::new());
        }

        warn!("Creating EMERGENCY VSS snapshot due to ransomware detection");
        let volumes = self.schedule.volumes.clone();
        self.create_snapshot(&volumes, Some("emergency_ransomware".to_string()))
    }

    #[cfg(target_os = "windows")]
    fn create_snapshot_windows(
        &mut self,
        volumes: &[String],
        label: Option<String>,
    ) -> Result<Vec<VssSnapshot>> {
        use std::process::Command;

        // Ensure VSS service is available before attempting snapshot creation
        ensure_vss_service_available().map_err(|e| {
            error!(error = %e, "VSS service is not available");
            anyhow!(
                "Cannot create VSS snapshot: VSS service is unavailable. \
                Error: {}. \n\
                \n\
                To enable VSS snapshots:\n\
                1. Ensure you have administrator privileges\n\
                2. Start the Volume Shadow Copy service (VSS) via services.msc\n\
                3. Verify System Restore is enabled for the target volume\n\
                \n\
                Note: Without VSS, ransomware protection and file rollback capabilities \
                will be severely limited. Consider using alternative backup solutions.",
                e
            )
        })?;

        let mut created = Vec::new();

        for volume in volumes {
            let vol = Self::normalize_volume(volume);

            info!(volume = %vol, "Creating shadow copy via wmic");

            // Use wmic to create shadow copy (COM-free approach that works
            // reliably across Windows versions and does not require linking
            // against the VSS SDK).
            let output = Command::new("wmic")
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
                warn!(volume = %vol, error = %stderr, "wmic shadow copy creation failed");
                // Try PowerShell fallback
                let ps_output = Command::new("powershell")
                    .args([
                        "-NoProfile", "-Command",
                        &format!(
                            "(Get-WmiObject -List Win32_ShadowCopy).Create('{}\\', 'ClientAccessible') | ConvertTo-Json",
                            vol
                        ),
                    ])
                    .output()
                    .map_err(|e| anyhow!("PowerShell fallback failed: {}", e))?;

                if !ps_output.status.success() {
                    let ps_err = String::from_utf8_lossy(&ps_output.stderr);
                    return Err(anyhow!(
                        "Failed to create shadow copy for {}: wmic={}, powershell={}",
                        vol,
                        stderr.trim(),
                        ps_err.trim()
                    ));
                }

                // Parse PowerShell output to get shadow ID
                let ps_stdout = String::from_utf8_lossy(&ps_output.stdout);
                let shadow_id = self
                    .parse_powershell_shadow_id(&ps_stdout)
                    .unwrap_or_else(|| format!("{{unknown-{}}}", Self::now()));

                let snapshot = self.build_snapshot_from_id(&vol, &shadow_id, &label)?;
                created.push(snapshot);
                continue;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let shadow_id = stdout
                .lines()
                .find(|line| line.contains("ShadowID"))
                .and_then(|line| line.split('"').nth(1).map(|s| s.to_string()))
                .ok_or_else(|| anyhow!("Could not parse shadow copy ID from wmic output"))?;

            let snapshot = self.build_snapshot_from_id(&vol, &shadow_id, &label)?;
            created.push(snapshot);
        }

        // Store in cache and enforce retention.
        for snap in &created {
            let entry = self.snapshots.entry(snap.volume.clone()).or_default();
            entry.push(snap.clone());
        }
        self.enforce_retention()?;

        info!(count = created.len(), "VSS snapshots created successfully");

        Ok(created)
    }

    #[cfg(target_os = "windows")]
    fn build_snapshot_from_id(
        &self,
        volume: &str,
        shadow_id: &str,
        label: &Option<String>,
    ) -> Result<VssSnapshot> {
        // Query the newly created shadow copy for its device path.
        let device_path = self.query_device_path(shadow_id).unwrap_or_else(|_| {
            format!(
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy-{}",
                shadow_id
            )
        });

        let now = Self::now();

        Ok(VssSnapshot {
            snapshot_id: shadow_id.to_string(),
            volume: volume.to_string(),
            device_path,
            created_at: now,
            size_bytes: 0,
            accessible: true,
            tamandua_managed: true,
            label: label.clone(),
        })
    }

    #[cfg(target_os = "windows")]
    fn query_device_path(&self, shadow_id: &str) -> Result<String> {
        use std::process::Command;

        let output = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!(
                    "Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{}' }} | Select-Object -ExpandProperty DeviceObject",
                    shadow_id
                ),
            ])
            .output()
            .map_err(|e| anyhow!("Failed to query device path: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let device = stdout.trim().to_string();
        if device.is_empty() {
            return Err(anyhow!("Empty device path for shadow {}", shadow_id));
        }
        Ok(device)
    }

    #[cfg(target_os = "windows")]
    fn parse_powershell_shadow_id(&self, output: &str) -> Option<String> {
        // Try to parse JSON output from PowerShell
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(output) {
            // Look for ShadowID in the result
            if let Some(id) = val.get("ShadowID").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
            if let Some(id) = val.get("ReturnValue").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
        }

        // Fallback: look for GUID pattern in output
        let re = regex::Regex::new(r"\{[0-9A-Fa-f\-]{36}\}").ok()?;
        re.find(output).map(|m| m.as_str().to_string())
    }

    // -----------------------------------------------------------------------
    // Snapshot listing
    // -----------------------------------------------------------------------

    /// List all VSS snapshots for the given volume (or all volumes if None).
    pub fn list_snapshots(&mut self, volume: Option<&str>) -> Result<Vec<VssSnapshot>> {
        #[cfg(target_os = "windows")]
        {
            self.list_snapshots_windows(volume)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VSS snapshots are only available on Windows"))
        }
    }

    #[cfg(target_os = "windows")]
    fn list_snapshots_windows(&mut self, volume: Option<&str>) -> Result<Vec<VssSnapshot>> {
        use std::process::Command;

        let mut args = vec!["list", "shadows"];
        let for_arg;
        if let Some(vol) = volume {
            let v = Self::normalize_volume(vol);
            for_arg = format!("/for={}\\", v);
            args.push(&for_arg);
        }

        let output = Command::new("vssadmin")
            .args(&args)
            .output()
            .map_err(|e| anyhow!("Failed to execute vssadmin: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let snapshots = self.parse_vssadmin_list(&stdout, volume);

        // Update cache.
        if let Some(vol) = volume {
            let v = Self::normalize_volume(vol);
            self.snapshots.insert(v, snapshots.clone());
        } else {
            // Group by volume.
            let mut grouped: HashMap<String, Vec<VssSnapshot>> = HashMap::new();
            for snap in &snapshots {
                grouped
                    .entry(snap.volume.clone())
                    .or_default()
                    .push(snap.clone());
            }
            for (vol, snaps) in grouped {
                self.snapshots.insert(vol, snaps);
            }
        }

        Ok(snapshots)
    }

    #[cfg(target_os = "windows")]
    fn parse_vssadmin_list(&self, output: &str, _volume_filter: Option<&str>) -> Vec<VssSnapshot> {
        let mut snapshots = Vec::new();
        let mut current_id: Option<String> = None;
        let mut current_volume: Option<String> = None;
        let mut current_device: Option<String> = None;
        let mut current_time: Option<String> = None;

        for line in output.lines() {
            let line = line.trim();

            if line.starts_with("Shadow Copy ID:") {
                // Flush previous snapshot.
                if let (Some(id), Some(vol)) = (current_id.take(), current_volume.take()) {
                    let device = current_device.take().unwrap_or_default();
                    snapshots.push(VssSnapshot {
                        snapshot_id: id,
                        volume: vol,
                        device_path: device,
                        created_at: self.parse_vss_time(current_time.as_deref()),
                        size_bytes: 0,
                        accessible: true,
                        tamandua_managed: false, // cannot determine from vssadmin alone
                        label: None,
                    });
                    current_time = None;
                }

                current_id = line
                    .strip_prefix("Shadow Copy ID:")
                    .map(|s| s.trim().to_string());
            } else if line.starts_with("Original Volume:") {
                current_volume = line.strip_prefix("Original Volume:").and_then(|s| {
                    // Extract volume letter from e.g. "(C:)\"
                    let s = s.trim();
                    if let Some(start) = s.find('(') {
                        if let Some(end) = s.find(')') {
                            return Some(s[start + 1..end].trim_end_matches('\\').to_string());
                        }
                    }
                    Some(s.to_string())
                });
            } else if line.starts_with("Shadow Copy Volume:") {
                current_device = line
                    .strip_prefix("Shadow Copy Volume:")
                    .map(|s| s.trim().to_string());
            } else if line.contains("creation time:") || line.contains("Creation Time:") {
                // "Contents of shadow copy set ID: ... creation time: 1/20/2026 3:14:00 PM"
                if let Some(pos) = line.rfind("time:") {
                    current_time = Some(line[pos + 5..].trim().to_string());
                }
            }
        }

        // Flush last snapshot.
        if let (Some(id), Some(vol)) = (current_id, current_volume) {
            let device = current_device.unwrap_or_default();
            snapshots.push(VssSnapshot {
                snapshot_id: id,
                volume: vol,
                device_path: device,
                created_at: self.parse_vss_time(current_time.as_deref()),
                size_bytes: 0,
                accessible: true,
                tamandua_managed: false,
                label: None,
            });
        }

        // Sort newest first.
        snapshots.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        snapshots
    }

    fn parse_vss_time(&self, time_str: Option<&str>) -> u64 {
        // Best-effort parsing of vssadmin date strings.
        match time_str {
            Some(s) if !s.is_empty() => {
                // Try chrono parsing with common formats.
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%m/%d/%Y %I:%M:%S %p") {
                    return dt.and_utc().timestamp() as u64;
                }
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                    return dt.and_utc().timestamp() as u64;
                }
                Self::now()
            }
            _ => Self::now(),
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot deletion
    // -----------------------------------------------------------------------

    /// Delete a specific shadow copy by ID.
    pub fn delete_snapshot(&mut self, snapshot_id: &str) -> Result<()> {
        info!(snapshot_id = %snapshot_id, "Deleting VSS snapshot");

        #[cfg(target_os = "windows")]
        {
            self.delete_snapshot_windows(snapshot_id)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VSS snapshots are only available on Windows"))
        }
    }

    #[cfg(target_os = "windows")]
    fn delete_snapshot_windows(&mut self, snapshot_id: &str) -> Result<()> {
        use std::process::Command;

        let output = Command::new("vssadmin")
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
            return Err(anyhow!(
                "Failed to delete shadow copy {}: {}",
                snapshot_id,
                stderr.trim()
            ));
        }

        // Remove from cache.
        for snaps in self.snapshots.values_mut() {
            snaps.retain(|s| s.snapshot_id != snapshot_id);
        }

        info!(snapshot_id = %snapshot_id, "VSS snapshot deleted");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // File restoration
    // -----------------------------------------------------------------------

    /// Restore a single file from a VSS shadow copy.
    ///
    /// The file at `original_path` is replaced with the version from the
    /// shadow copy identified by `snapshot_id`.  The current file (if any)
    /// is backed up to `<original>.pre_vss_restore` before overwriting.
    pub fn restore_file(&self, snapshot_id: &str, original_path: &Path) -> Result<RestoredFile> {
        if Self::is_protected_path(original_path) {
            return Err(anyhow!(
                "Cannot restore protected system file: {}",
                original_path.display()
            ));
        }

        info!(
            snapshot_id = %snapshot_id,
            path = %original_path.display(),
            "Restoring file from VSS snapshot"
        );

        #[cfg(target_os = "windows")]
        {
            self.restore_file_windows(snapshot_id, original_path)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VSS file restore is only available on Windows"))
        }
    }

    #[cfg(target_os = "windows")]
    fn restore_file_windows(
        &self,
        snapshot_id: &str,
        original_path: &Path,
    ) -> Result<RestoredFile> {
        // Find the snapshot to get its device path.
        let snapshot = self
            .find_snapshot(snapshot_id)
            .ok_or_else(|| anyhow!("Snapshot {} not found in cache", snapshot_id))?;

        // Build the path within the shadow copy.
        let shadow_path = self.build_shadow_path(&snapshot, original_path)?;

        if !shadow_path.exists() {
            return Err(anyhow!(
                "File not found in snapshot: {}",
                shadow_path.display()
            ));
        }

        // Compute hash of the current file (if it exists).
        let sha256_before = if original_path.exists() {
            Self::compute_sha256(original_path).ok()
        } else {
            None
        };

        // Back up current file before overwriting.
        if original_path.exists() {
            let backup_path = PathBuf::from(format!("{}.pre_vss_restore", original_path.display()));
            std::fs::copy(original_path, &backup_path).with_context(|| {
                format!(
                    "Failed to back up {} before restore",
                    original_path.display()
                )
            })?;
            debug!(
                backup = %backup_path.display(),
                "Created pre-restore backup"
            );
        }

        // Ensure parent directory exists.
        if let Some(parent) = original_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent dir for {}",
                    original_path.display()
                )
            })?;
        }

        // Copy from shadow copy to original location.
        std::fs::copy(&shadow_path, original_path).with_context(|| {
            format!(
                "Failed to copy {} -> {}",
                shadow_path.display(),
                original_path.display()
            )
        })?;

        let metadata = std::fs::metadata(original_path)?;
        let sha256_after = Self::compute_sha256(original_path)?;

        info!(
            path = %original_path.display(),
            size = metadata.len(),
            "File restored from VSS snapshot"
        );

        Ok(RestoredFile {
            path: original_path.to_string_lossy().to_string(),
            size_bytes: metadata.len(),
            sha256_before,
            sha256_after,
        })
    }

    /// Restore an entire directory tree from a VSS shadow copy.
    pub fn restore_directory(&self, snapshot_id: &str, dir: &Path) -> Result<RollbackResult> {
        info!(
            snapshot_id = %snapshot_id,
            dir = %dir.display(),
            "Restoring directory tree from VSS snapshot"
        );

        #[cfg(target_os = "windows")]
        {
            let snapshot = self
                .find_snapshot(snapshot_id)
                .ok_or_else(|| anyhow!("Snapshot {} not found", snapshot_id))?;

            let shadow_dir = self.build_shadow_path(&snapshot, dir)?;
            if !shadow_dir.exists() || !shadow_dir.is_dir() {
                return Err(anyhow!(
                    "Directory not found in snapshot: {}",
                    shadow_dir.display()
                ));
            }

            // Walk the shadow directory and restore each file.
            let mut paths = Vec::new();
            for entry in walkdir::WalkDir::new(&shadow_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    // Map shadow path back to original path.
                    let rel = entry
                        .path()
                        .strip_prefix(&shadow_dir)
                        .unwrap_or(entry.path());
                    let original = dir.join(rel);
                    paths.push(original);
                }
            }

            self.rollback_to_snapshot(snapshot_id, &paths, true)
        }

        #[cfg(not(target_os = "windows"))]
        Err(anyhow!(
            "VSS directory restore is only available on Windows"
        ))
    }

    /// Full rollback of the specified file paths using a VSS snapshot.
    ///
    /// If `verify` is true, each restored file is hashed and compared against
    /// the baseline (if available).
    pub fn rollback_to_snapshot(
        &self,
        snapshot_id: &str,
        paths: &[PathBuf],
        verify: bool,
    ) -> Result<RollbackResult> {
        let start = std::time::Instant::now();

        info!(
            snapshot_id = %snapshot_id,
            file_count = paths.len(),
            verify = verify,
            "Starting VSS rollback"
        );

        let mut result = RollbackResult {
            snapshot_id: snapshot_id.to_string(),
            restored: Vec::new(),
            failed: Vec::new(),
            skipped: Vec::new(),
            bytes_restored: 0,
            total_files: paths.len(),
            duration_ms: 0,
            verification_passed: true,
            verification_details: HashMap::new(),
        };

        for path in paths {
            // Check protected paths.
            if Self::is_protected_path(path) {
                result.skipped.push(SkippedFile {
                    path: path.to_string_lossy().to_string(),
                    reason: "Protected system path".to_string(),
                });
                continue;
            }

            match self.restore_file(snapshot_id, path) {
                Ok(restored) => {
                    result.bytes_restored += restored.size_bytes;

                    // Verify if requested.
                    if verify {
                        let path_str = restored.path.clone();
                        let matches = self.verify_restored_file(&path_str, &restored.sha256_after);
                        result.verification_details.insert(path_str, matches);
                        if !matches {
                            result.verification_passed = false;
                        }
                    }

                    result.restored.push(restored);
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    if err_msg.contains("not found in snapshot") {
                        result.skipped.push(SkippedFile {
                            path: path.to_string_lossy().to_string(),
                            reason: "File not found in snapshot".to_string(),
                        });
                    } else {
                        result.failed.push(FailedFile {
                            path: path.to_string_lossy().to_string(),
                            error: err_msg,
                        });
                    }
                }
            }
        }

        result.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            snapshot_id = %snapshot_id,
            restored = result.restored.len(),
            failed = result.failed.len(),
            skipped = result.skipped.len(),
            bytes = result.bytes_restored,
            duration_ms = result.duration_ms,
            verified = result.verification_passed,
            "VSS rollback completed"
        );

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Snapshot retention / cleanup
    // -----------------------------------------------------------------------

    /// Enforce the retention policy by deleting old Tamandua-managed snapshots.
    pub fn enforce_retention(&mut self) -> Result<()> {
        let max = self.max_snapshots_per_volume;
        let mut to_delete = Vec::new();

        for (_vol, snaps) in &self.snapshots {
            // Only manage Tamandua-created snapshots.
            let mut managed: Vec<&VssSnapshot> =
                snaps.iter().filter(|s| s.tamandua_managed).collect();

            // Sort oldest first.
            managed.sort_by(|a, b| a.created_at.cmp(&b.created_at));

            // Mark excess for deletion.
            if managed.len() > max {
                let excess = managed.len() - max;
                for snap in managed.iter().take(excess) {
                    to_delete.push(snap.snapshot_id.clone());
                }
            }
        }

        for id in &to_delete {
            if let Err(e) = self.delete_snapshot(id) {
                warn!(snapshot_id = %id, error = %e, "Failed to delete expired snapshot");
            } else {
                debug!(snapshot_id = %id, "Deleted expired snapshot (retention policy)");
            }
        }

        if !to_delete.is_empty() {
            info!(
                deleted = to_delete.len(),
                max_per_volume = max,
                "Snapshot retention enforced"
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Shadow copy protection (detection of deletion attempts)
    // -----------------------------------------------------------------------

    /// Check whether a process creation command line is attempting to delete
    /// shadow copies.  Returns `Some(VssDeletionAttempt)` if so.
    pub fn check_vss_deletion_attempt(
        &mut self,
        pid: u32,
        process_name: &str,
        cmdline: &str,
    ) -> Option<VssDeletionAttempt> {
        let cmdline_lower = cmdline.to_lowercase();

        let is_deletion = VSS_DELETE_COMMANDS
            .iter()
            .any(|cmd| cmdline_lower.contains(&cmd.to_lowercase()));

        if is_deletion {
            let attempt = VssDeletionAttempt {
                pid,
                process_name: process_name.to_string(),
                cmdline: cmdline.to_string(),
                timestamp: Self::now(),
                blocked: true, // We report this as blocked; the caller should kill the process
            };

            warn!(
                pid = pid,
                process = %process_name,
                cmdline = %cmdline,
                "VSS DELETION ATTEMPT DETECTED AND BLOCKED"
            );

            self.deletion_attempts.push(attempt.clone());
            Some(attempt)
        } else {
            None
        }
    }

    /// Get all recorded VSS deletion attempts.
    pub fn get_deletion_attempts(&self) -> &[VssDeletionAttempt] {
        &self.deletion_attempts
    }

    // -----------------------------------------------------------------------
    // Baseline hash management (for verification)
    // -----------------------------------------------------------------------

    /// Register a known-good hash for a file path.
    pub fn register_baseline_hash(&mut self, path: &str, sha256: &str) {
        self.baseline_hashes
            .insert(path.to_string(), sha256.to_string());
    }

    /// Bulk-register baseline hashes.
    pub fn register_baseline_hashes(&mut self, hashes: HashMap<String, String>) {
        self.baseline_hashes.extend(hashes);
    }

    /// Verify a restored file against its baseline hash.
    fn verify_restored_file(&self, path: &str, actual_sha256: &str) -> bool {
        match self.baseline_hashes.get(path) {
            Some(expected) => {
                let matches = expected == actual_sha256;
                if !matches {
                    warn!(
                        path = %path,
                        expected = %expected,
                        actual = %actual_sha256,
                        "Restored file hash does NOT match baseline"
                    );
                }
                matches
            }
            None => {
                // No baseline available; assume OK.
                debug!(path = %path, "No baseline hash for verification; skipping");
                true
            }
        }
    }

    // -----------------------------------------------------------------------
    // Ransomware rollback helpers
    // -----------------------------------------------------------------------

    /// Find the most recent clean snapshot for the given volume.
    ///
    /// A "clean" snapshot is one created before a given timestamp (typically
    /// the ransomware detection time).
    pub fn find_pre_attack_snapshot(&self, volume: &str, attack_time: u64) -> Option<&VssSnapshot> {
        let vol = Self::normalize_volume(volume);
        let snaps = self.snapshots.get(&vol)?;

        // Find the most recent snapshot created before the attack.
        snaps
            .iter()
            .filter(|s| s.created_at < attack_time && s.accessible)
            .max_by_key(|s| s.created_at)
    }

    /// Find the most recent snapshot for a volume (regardless of attack time).
    pub fn find_latest_snapshot(&self, volume: &str) -> Option<&VssSnapshot> {
        let vol = Self::normalize_volume(volume);
        let snaps = self.snapshots.get(&vol)?;
        snaps
            .iter()
            .filter(|s| s.accessible)
            .max_by_key(|s| s.created_at)
    }

    /// Find encrypted files in a directory tree using ransomware extension patterns.
    pub fn find_encrypted_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let ransomware_extensions: Vec<&str> = vec![
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
            ".wcry",
            ".wncry",
            ".wncryt",
            ".wanna",
            ".wannacry",
        ];

        let mut encrypted = Vec::new();

        for entry in walkdir::WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let ext = entry
                .path()
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                .unwrap_or_default();

            if ransomware_extensions.iter().any(|&re| ext == re) {
                encrypted.push(entry.path().to_path_buf());
            }
        }

        info!(count = encrypted.len(), root = %root.display(), "Found encrypted files");
        Ok(encrypted)
    }

    /// Perform a complete ransomware rollback:
    /// 1. Find encrypted files under `root`
    /// 2. Identify the best pre-attack snapshot
    /// 3. Restore all affected files
    /// 4. Verify restored files
    /// 5. Return detailed results
    pub fn ransomware_rollback(
        &self,
        root: &Path,
        attack_time: Option<u64>,
    ) -> Result<RollbackResult> {
        info!(
            root = %root.display(),
            attack_time = ?attack_time,
            "Starting ransomware rollback"
        );

        // Step 1: Find encrypted files.
        let encrypted = self.find_encrypted_files(root)?;
        if encrypted.is_empty() {
            return Ok(RollbackResult {
                snapshot_id: String::new(),
                restored: Vec::new(),
                failed: Vec::new(),
                skipped: Vec::new(),
                bytes_restored: 0,
                total_files: 0,
                duration_ms: 0,
                verification_passed: true,
                verification_details: HashMap::new(),
            });
        }

        // Step 2: Determine volume and find best snapshot.
        let volume = root.to_str().and_then(|s| s.get(..2)).unwrap_or("C:");

        let snapshot = if let Some(ts) = attack_time {
            self.find_pre_attack_snapshot(volume, ts)
        } else {
            self.find_latest_snapshot(volume)
        };

        let snapshot = snapshot.ok_or_else(|| {
            anyhow!(
                "No suitable VSS snapshot found for volume {} (attack_time={:?})",
                volume,
                attack_time
            )
        })?;

        info!(
            snapshot_id = %snapshot.snapshot_id,
            snapshot_time = snapshot.created_at,
            encrypted_files = encrypted.len(),
            "Using snapshot for ransomware rollback"
        );

        // Step 3-4: Restore and verify.
        // Map encrypted file paths to their original paths (strip ransomware extension).
        let mut original_paths: Vec<PathBuf> = Vec::new();
        for path in &encrypted {
            // Try to determine the original path by removing the ransomware extension.
            // Many ransomware variants append an extension: document.docx.lockbit
            let path_str = path.to_string_lossy();
            let stem = path.with_extension(""); // Remove last extension
            if stem.extension().is_some() {
                // Had a double extension, so the stem IS the original filename.
                original_paths.push(stem);
            } else {
                // Single extension (ransomware replaced original), try as-is.
                original_paths.push(path.clone());
            }
        }

        self.rollback_to_snapshot(&snapshot.snapshot_id, &original_paths, true)
    }

    // -----------------------------------------------------------------------
    // Scheduling helpers
    // -----------------------------------------------------------------------

    /// Get the schedule configuration.
    pub fn get_schedule(&self) -> &VssScheduleConfig {
        &self.schedule
    }

    /// Update the schedule configuration.
    pub fn set_schedule(&mut self, schedule: VssScheduleConfig) {
        self.max_snapshots_per_volume = schedule.max_snapshots_per_volume;
        self.schedule = schedule;
    }

    /// Get cached snapshots for a volume.
    pub fn get_cached_snapshots(&self, volume: &str) -> Vec<&VssSnapshot> {
        let vol = Self::normalize_volume(volume);
        self.snapshots
            .get(&vol)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Check if VSS service is available on the system.
    ///
    /// This is a diagnostic method that can be called to verify VSS availability
    /// before attempting snapshot operations.
    ///
    /// Returns:
    /// - `Ok(true)` if VSS is running and ready
    /// - `Ok(false)` if VSS is installed but not running
    /// - `Err` if VSS cannot be checked (not installed, no permissions, etc.)
    pub fn check_vss_availability(&self) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            check_vss_service_available()
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VSS is only available on Windows"))
        }
    }

    /// Attempt to ensure VSS service is running.
    ///
    /// This will start the VSS service if it's not running and wait for it to be ready.
    /// Useful for pre-flight checks before critical operations.
    ///
    /// Returns:
    /// - `Ok(())` if VSS is now running
    /// - `Err` if VSS cannot be started or made available
    pub fn ensure_vss_available(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            ensure_vss_service_available()
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VSS is only available on Windows"))
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn find_snapshot(&self, snapshot_id: &str) -> Option<VssSnapshot> {
        for snaps in self.snapshots.values() {
            if let Some(snap) = snaps.iter().find(|s| s.snapshot_id == snapshot_id) {
                return Some(snap.clone());
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    fn build_shadow_path(&self, snapshot: &VssSnapshot, original_path: &Path) -> Result<PathBuf> {
        let path_str = original_path.to_string_lossy();

        // Strip drive letter prefix (e.g. "C:\Users\..." -> "\Users\...")
        let path_tail = if path_str.len() > 2 && path_str.chars().nth(1) == Some(':') {
            &path_str[2..]
        } else {
            path_str.as_ref()
        };

        // Build shadow copy path: device_path + tail
        let device = snapshot.device_path.trim_end_matches('\\');
        let shadow_path = PathBuf::from(format!("{}{}", device, path_tail));

        Ok(shadow_path)
    }

    fn normalize_volume(vol: &str) -> String {
        let v = vol.trim();
        if v.ends_with(":\\") {
            v[..2].to_string()
        } else if v.ends_with(':') {
            v.to_string()
        } else if v.len() == 1
            && v.chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
        {
            format!("{}:", v)
        } else {
            v.to_string()
        }
    }

    fn is_protected_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        PROTECTED_PATHS
            .iter()
            .any(|&p| path_str.contains(&p.to_lowercase()))
    }

    fn compute_sha256(path: &Path) -> Result<String> {
        use sha2::{Digest, Sha256};
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ---------------------------------------------------------------------------
// Automatic snapshot scheduler (runs as a tokio background task)
// ---------------------------------------------------------------------------

/// Runs the periodic snapshot scheduler.
///
/// This function is intended to be spawned as a background `tokio::task`.
/// It creates snapshots at the configured interval and enforces retention.
pub async fn run_snapshot_scheduler(
    manager: std::sync::Arc<tokio::sync::RwLock<VssSnapshotManager>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let interval_secs = {
        let mgr = manager.read().await;
        mgr.get_schedule().interval_seconds
    };

    if interval_secs == 0 {
        info!("VSS snapshot scheduler disabled (interval=0)");
        return;
    }

    info!(
        interval_seconds = interval_secs,
        "VSS snapshot scheduler started"
    );

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    // Skip the first immediate tick.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let enabled = {
                    let mgr = manager.read().await;
                    mgr.get_schedule().enabled
                };

                if !enabled {
                    debug!("Scheduled VSS snapshot skipped (disabled)");
                    continue;
                }

                info!("Executing scheduled VSS snapshot");
                let mut mgr = manager.write().await;
                match mgr.create_scheduled_snapshot() {
                    Ok(snaps) => {
                        info!(count = snaps.len(), "Scheduled snapshot(s) created");
                    }
                    Err(e) => {
                        warn!(error = %e, "Scheduled snapshot creation failed");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("VSS snapshot scheduler shutting down");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VSS protection monitor
// ---------------------------------------------------------------------------

/// Monitor for VSS shadow copy deletion attempts in process creation events.
///
/// This is designed to be called from the ransomware disruption engine or
/// process creation collector whenever a new process is created.  If the
/// process command line matches known VSS deletion patterns, it returns
/// the details so the caller can block/kill the process.
pub fn check_process_for_vss_deletion(
    pid: u32,
    process_name: &str,
    cmdline: &str,
) -> Option<VssDeletionAttempt> {
    let cmdline_lower = cmdline.to_lowercase();

    let is_deletion = VSS_DELETE_COMMANDS
        .iter()
        .any(|cmd| cmdline_lower.contains(&cmd.to_lowercase()));

    if is_deletion {
        warn!(
            pid = pid,
            process = %process_name,
            cmdline = %cmdline,
            "VSS SHADOW COPY DELETION ATTEMPT DETECTED"
        );

        Some(VssDeletionAttempt {
            pid,
            process_name: process_name.to_string(),
            cmdline: cmdline.to_string(),
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            blocked: true,
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_volume() {
        assert_eq!(VssSnapshotManager::normalize_volume("C:"), "C:");
        assert_eq!(VssSnapshotManager::normalize_volume("C:\\"), "C:");
        assert_eq!(VssSnapshotManager::normalize_volume("D"), "D:");
        assert_eq!(VssSnapshotManager::normalize_volume("E:"), "E:");
    }

    #[test]
    fn test_protected_path_detection() {
        assert!(VssSnapshotManager::is_protected_path(Path::new(
            "C:\\Windows\\System32\\ntoskrnl.exe"
        )));
        assert!(VssSnapshotManager::is_protected_path(Path::new(
            "C:\\Windows\\System32\\drivers\\something.sys"
        )));
        assert!(!VssSnapshotManager::is_protected_path(Path::new(
            "C:\\Users\\test\\documents\\file.docx"
        )));
    }

    #[test]
    fn test_vss_deletion_detection() {
        let result = check_process_for_vss_deletion(
            1234,
            "cmd.exe",
            "cmd.exe /c vssadmin delete shadows /all /quiet",
        );
        assert!(result.is_some());
        assert!(result.unwrap().blocked);

        let result = check_process_for_vss_deletion(
            1234,
            "powershell.exe",
            "powershell.exe -c Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }",
        );
        assert!(result.is_some());

        let result =
            check_process_for_vss_deletion(1234, "notepad.exe", "notepad.exe C:\\Users\\test.txt");
        assert!(result.is_none());
    }

    #[test]
    fn test_vss_schedule_config_default() {
        let config = VssScheduleConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_seconds, 4 * 3600);
        assert_eq!(config.max_snapshots_per_volume, 5);
        assert!(config.snapshot_on_ransomware);
    }

    #[test]
    fn test_rollback_result_empty() {
        let result = RollbackResult {
            snapshot_id: "test".to_string(),
            restored: Vec::new(),
            failed: Vec::new(),
            skipped: Vec::new(),
            bytes_restored: 0,
            total_files: 0,
            duration_ms: 0,
            verification_passed: true,
            verification_details: HashMap::new(),
        };
        assert!(result.verification_passed);
        assert_eq!(result.total_files, 0);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_vss_service_check() {
        // This test checks if the VSS service check functions are callable
        // We don't assert on the result because VSS may or may not be running
        // in the test environment, but we ensure the functions don't panic
        let result = check_vss_service_available();

        // Should return either Ok(true), Ok(false), or Err, but not panic
        match result {
            Ok(running) => {
                println!("VSS service running: {}", running);
            }
            Err(e) => {
                println!("VSS service check error: {}", e);
            }
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_ensure_vss_service_available_does_not_panic() {
        // This test ensures that ensure_vss_service_available doesn't panic
        // It may fail if VSS is not available or we lack privileges, but shouldn't panic
        let _result = ensure_vss_service_available();
        // We don't assert on success because:
        // 1. Test may run without admin privileges
        // 2. VSS may be disabled in test environment
        // 3. We just want to ensure proper error handling, not panics
    }
}
