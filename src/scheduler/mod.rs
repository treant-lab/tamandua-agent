//! Scheduled Scans Module
//!
//! Provides cross-platform scheduled scan functionality with:
//! - Windows Task Scheduler integration
//! - Linux cron/systemd timer integration
//! - macOS launchd integration

mod executor;
mod schedule;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub use executor::ScheduleExecutor;
pub use schedule::{
    CpuPriority, DetectionAction, ScanOptions, Schedule, ScheduleConfig, ScheduleFrequency,
    ScheduleId, ScheduleRun, ScheduleRunStatus, ScheduleStatus,
};

use crate::config::AgentConfig;
use anyhow::Result;
use chrono::{DateTime, NaiveTime, Utc, Weekday};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Scheduler manager for handling scheduled scans
pub struct Scheduler {
    /// All configured schedules
    schedules: Arc<RwLock<HashMap<ScheduleId, Schedule>>>,
    /// Schedule execution history
    history: Arc<RwLock<HashMap<ScheduleId, Vec<ScheduleRun>>>>,
    /// Currently running schedules
    running: Arc<RwLock<HashMap<ScheduleId, RunningSchedule>>>,
    /// Channel to trigger immediate scan execution
    trigger_tx: mpsc::Sender<ScheduleId>,
    /// Executor for running scans
    executor: Arc<ScheduleExecutor>,
    /// Storage path for schedules
    storage_path: PathBuf,
}

/// Information about a currently running schedule
pub struct RunningSchedule {
    pub schedule_id: ScheduleId,
    pub started_at: DateTime<Utc>,
    pub files_scanned: u64,
    pub total_files: u64,
    pub threats_found: u32,
    pub current_path: String,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(storage_path: PathBuf) -> Self {
        Self::with_executor(storage_path, Arc::new(ScheduleExecutor::new()))
    }

    /// Create a new scheduler with agent-configured scanning engines.
    pub fn new_with_config(storage_path: PathBuf, config: &AgentConfig) -> Self {
        Self::with_executor(
            storage_path,
            Arc::new(ScheduleExecutor::from_config(config)),
        )
    }

    fn with_executor(storage_path: PathBuf, executor: Arc<ScheduleExecutor>) -> Self {
        let (trigger_tx, _trigger_rx) = mpsc::channel(32);

        let scheduler = Self {
            schedules: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(HashMap::new())),
            trigger_tx,
            executor,
            storage_path,
        };

        // Load existing schedules
        if let Err(e) = scheduler.load_schedules() {
            warn!("Failed to load schedules: {}", e);
        }

        scheduler
    }

    /// Start the scheduler background task
    pub async fn start(&self) -> Result<()> {
        info!("Starting schedule manager");

        let schedules = self.schedules.clone();
        let history = self.history.clone();
        let running = self.running.clone();
        let executor = self.executor.clone();

        // Spawn the schedule checker task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                interval.tick().await;

                // Check for schedules that should run
                let now = Utc::now();
                let schedules_to_run: Vec<Schedule> = {
                    let scheds = schedules.read();
                    scheds
                        .values()
                        .filter(|s| s.enabled && s.should_run_now(&now))
                        .cloned()
                        .collect()
                };

                for schedule in schedules_to_run {
                    // Check if already running
                    {
                        let running_guard = running.read();
                        if running_guard.contains_key(&schedule.id) {
                            debug!("Schedule {} already running, skipping", schedule.id);
                            continue;
                        }
                    }

                    // Check battery condition
                    if schedule.config.options.skip_if_on_battery && is_on_battery() {
                        debug!("Skipping schedule {} - system on battery", schedule.id);
                        continue;
                    }

                    // Start the scan
                    info!("Executing scheduled scan: {}", schedule.name);
                    let schedule_clone = schedule.clone();
                    let executor_clone = executor.clone();
                    let running_clone = running.clone();
                    let history_clone = history.clone();

                    tokio::spawn(async move {
                        let result = executor_clone
                            .execute_schedule(&schedule_clone, running_clone.clone())
                            .await;

                        // Record result in history
                        let run = ScheduleRun {
                            id: Uuid::new_v4(),
                            schedule_id: schedule_clone.id,
                            started_at: Utc::now(),
                            completed_at: Some(Utc::now()),
                            status: if result.is_ok() {
                                ScheduleRunStatus::Completed
                            } else {
                                ScheduleRunStatus::Failed
                            },
                            files_scanned: result.as_ref().map(|r| r.files_scanned).unwrap_or(0),
                            threats_found: result.as_ref().map(|r| r.threats_found).unwrap_or(0),
                            error_message: result.as_ref().err().map(|e| e.to_string()),
                        };

                        {
                            let mut hist = history_clone.write();
                            hist.entry(schedule_clone.id)
                                .or_insert_with(Vec::new)
                                .push(run);
                        }

                        // Remove from running
                        {
                            let mut running_guard = running_clone.write();
                            running_guard.remove(&schedule_clone.id);
                        }
                    });

                    // Update last run time
                    {
                        let mut scheds = schedules.write();
                        if let Some(s) = scheds.get_mut(&schedule.id) {
                            s.last_run = Some(now);
                            s.update_next_run();
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Get all schedules
    pub fn get_schedules(&self) -> Vec<Schedule> {
        let schedules = self.schedules.read();
        schedules.values().cloned().collect()
    }

    /// Get a specific schedule
    pub fn get_schedule(&self, id: ScheduleId) -> Option<Schedule> {
        let schedules = self.schedules.read();
        schedules.get(&id).cloned()
    }

    /// Create a new schedule
    pub fn create_schedule(&self, config: ScheduleConfig) -> Result<Schedule> {
        let schedule = Schedule::new(config);
        let id = schedule.id;

        {
            let mut schedules = self.schedules.write();
            schedules.insert(id, schedule.clone());
        }

        self.save_schedules()?;
        self.register_system_schedule(&schedule)?;

        info!("Created schedule: {} ({})", schedule.name, id);
        Ok(schedule)
    }

    /// Update an existing schedule
    pub fn update_schedule(&self, id: ScheduleId, config: ScheduleConfig) -> Result<Schedule> {
        let mut schedule = {
            let schedules = self.schedules.read();
            schedules
                .get(&id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Schedule not found: {}", id))?
        };

        // Unregister old system schedule
        self.unregister_system_schedule(&schedule)?;

        // Update schedule
        schedule.name = config.name.clone();
        schedule.config = config;
        schedule.updated_at = Utc::now();
        schedule.update_next_run();

        {
            let mut schedules = self.schedules.write();
            schedules.insert(id, schedule.clone());
        }

        self.save_schedules()?;
        self.register_system_schedule(&schedule)?;

        info!("Updated schedule: {} ({})", schedule.name, id);
        Ok(schedule)
    }

    /// Delete a schedule
    pub fn delete_schedule(&self, id: ScheduleId) -> Result<()> {
        let schedule = {
            let mut schedules = self.schedules.write();
            schedules
                .remove(&id)
                .ok_or_else(|| anyhow::anyhow!("Schedule not found: {}", id))?
        };

        self.unregister_system_schedule(&schedule)?;
        self.save_schedules()?;

        info!("Deleted schedule: {} ({})", schedule.name, id);
        Ok(())
    }

    /// Enable or disable a schedule
    pub fn set_schedule_enabled(&self, id: ScheduleId, enabled: bool) -> Result<()> {
        let mut schedules = self.schedules.write();
        let schedule = schedules
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("Schedule not found: {}", id))?;

        schedule.enabled = enabled;
        schedule.updated_at = Utc::now();

        drop(schedules);
        self.save_schedules()?;

        info!(
            "Schedule {} {} ({})",
            if enabled { "enabled" } else { "disabled" },
            id,
            enabled
        );
        Ok(())
    }

    /// Run a schedule immediately
    pub async fn run_now(&self, id: ScheduleId) -> Result<()> {
        let schedule = {
            let schedules = self.schedules.read();
            schedules
                .get(&id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Schedule not found: {}", id))?
        };

        // Check if already running
        {
            let running = self.running.read();
            if running.contains_key(&id) {
                return Err(anyhow::anyhow!("Schedule is already running"));
            }
        }

        info!("Running schedule now: {} ({})", schedule.name, id);

        let executor = self.executor.clone();
        let running = self.running.clone();
        let history = self.history.clone();

        tokio::spawn(async move {
            let result = executor.execute_schedule(&schedule, running.clone()).await;

            // Record result
            let run = ScheduleRun {
                id: Uuid::new_v4(),
                schedule_id: schedule.id,
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
                status: if result.is_ok() {
                    ScheduleRunStatus::Completed
                } else {
                    ScheduleRunStatus::Failed
                },
                files_scanned: result.as_ref().map(|r| r.files_scanned).unwrap_or(0),
                threats_found: result.as_ref().map(|r| r.threats_found).unwrap_or(0),
                error_message: result.as_ref().err().map(|e| e.to_string()),
            };

            {
                let mut hist = history.write();
                hist.entry(schedule.id).or_insert_with(Vec::new).push(run);
            }

            // Remove from running
            {
                let mut running_guard = running.write();
                running_guard.remove(&schedule.id);
            }
        });

        Ok(())
    }

    /// Get schedule run history
    pub fn get_history(&self, id: ScheduleId, limit: Option<usize>) -> Vec<ScheduleRun> {
        let history = self.history.read();
        let runs = history.get(&id).map(|r| r.as_slice()).unwrap_or(&[]);

        let limit = limit.unwrap_or(100);
        runs.iter().rev().take(limit).cloned().collect()
    }

    /// Get running status for a schedule
    pub fn get_running_status(&self, id: ScheduleId) -> Option<RunningSchedule> {
        let running = self.running.read();
        running.get(&id).map(|r| RunningSchedule {
            schedule_id: r.schedule_id,
            started_at: r.started_at,
            files_scanned: r.files_scanned,
            total_files: r.total_files,
            threats_found: r.threats_found,
            current_path: r.current_path.clone(),
        })
    }

    /// Cancel a running schedule
    pub fn cancel_schedule(&self, id: ScheduleId) -> Result<()> {
        self.executor.cancel(id)
    }

    /// Load schedules from storage
    fn load_schedules(&self) -> Result<()> {
        let path = self.storage_path.join("schedules.json");

        if !path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&path)?;
        let schedules: Vec<Schedule> = serde_json::from_str(&content)?;

        let mut scheds = self.schedules.write();
        for schedule in schedules {
            scheds.insert(schedule.id, schedule);
        }

        info!("Loaded {} schedules", scheds.len());
        Ok(())
    }

    /// Save schedules to storage
    fn save_schedules(&self) -> Result<()> {
        let schedules = self.schedules.read();
        let schedules_vec: Vec<&Schedule> = schedules.values().collect();

        std::fs::create_dir_all(&self.storage_path)?;
        let path = self.storage_path.join("schedules.json");
        let content = serde_json::to_string_pretty(&schedules_vec)?;
        std::fs::write(&path, content)?;

        Ok(())
    }

    /// Register schedule with system scheduler
    fn register_system_schedule(&self, schedule: &Schedule) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            windows::register_task(schedule)?;
        }

        #[cfg(target_os = "linux")]
        {
            linux::register_systemd_timer(schedule)?;
        }

        #[cfg(target_os = "macos")]
        {
            macos::register_launchd(schedule)?;
        }

        Ok(())
    }

    /// Unregister schedule from system scheduler
    fn unregister_system_schedule(&self, schedule: &Schedule) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            windows::unregister_task(schedule)?;
        }

        #[cfg(target_os = "linux")]
        {
            linux::unregister_systemd_timer(schedule)?;
        }

        #[cfg(target_os = "macos")]
        {
            macos::unregister_launchd(schedule)?;
        }

        Ok(())
    }
}

/// Check if system is running on battery power
fn is_on_battery() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::is_on_battery()
    }

    #[cfg(target_os = "linux")]
    {
        linux::is_on_battery()
    }

    #[cfg(target_os = "macos")]
    {
        macos::is_on_battery()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Create a daily quick scan preset
pub fn daily_quick_scan_preset() -> ScheduleConfig {
    ScheduleConfig {
        name: "Daily Quick Scan".to_string(),
        scan_type: schedule::ScheduleScanType::Quick,
        frequency: ScheduleFrequency::Daily {
            time: NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
        },
        paths: vec![],
        options: ScanOptions::default(),
        detection_action: DetectionAction::Alert,
    }
}

/// Create a weekly full scan preset
pub fn weekly_full_scan_preset() -> ScheduleConfig {
    ScheduleConfig {
        name: "Weekly Full Scan".to_string(),
        scan_type: schedule::ScheduleScanType::Full,
        frequency: ScheduleFrequency::Weekly {
            days: vec![Weekday::Sun],
            time: NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
        },
        paths: vec![],
        options: ScanOptions {
            scan_archives: true,
            follow_symlinks: false,
            cpu_priority: CpuPriority::Low,
            skip_if_on_battery: true,
            wake_to_scan: false,
        },
        detection_action: DetectionAction::Quarantine,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daily_quick_scan_preset() {
        let config = daily_quick_scan_preset();
        assert_eq!(config.name, "Daily Quick Scan");
        assert!(matches!(
            config.scan_type,
            schedule::ScheduleScanType::Quick
        ));
    }

    #[test]
    fn test_weekly_full_scan_preset() {
        let config = weekly_full_scan_preset();
        assert_eq!(config.name, "Weekly Full Scan");
        assert!(matches!(config.scan_type, schedule::ScheduleScanType::Full));
    }
}
