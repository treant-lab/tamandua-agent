//! Schedule types and configuration

use chrono::{DateTime, Datelike, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Unique identifier for a schedule
pub type ScheduleId = Uuid;

/// A scheduled scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    /// Unique identifier
    pub id: ScheduleId,
    /// Display name
    pub name: String,
    /// Schedule configuration
    pub config: ScheduleConfig,
    /// Whether the schedule is enabled
    pub enabled: bool,
    /// Next scheduled run time
    pub next_run: Option<DateTime<Utc>>,
    /// Last run time
    pub last_run: Option<DateTime<Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl Schedule {
    /// Create a new schedule from configuration
    pub fn new(config: ScheduleConfig) -> Self {
        let mut schedule = Self {
            id: Uuid::new_v4(),
            name: config.name.clone(),
            config,
            enabled: true,
            next_run: None,
            last_run: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        schedule.update_next_run();
        schedule
    }

    /// Check if the schedule should run now
    pub fn should_run_now(&self, now: &DateTime<Utc>) -> bool {
        if let Some(next_run) = self.next_run {
            next_run <= *now
        } else {
            false
        }
    }

    /// Update the next run time based on frequency
    pub fn update_next_run(&mut self) {
        self.next_run = self.config.frequency.next_occurrence(Utc::now());
    }
}

/// Schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Display name
    pub name: String,
    /// Type of scan to perform
    pub scan_type: ScheduleScanType,
    /// How often to run
    pub frequency: ScheduleFrequency,
    /// Paths to scan (for custom scans)
    pub paths: Vec<PathBuf>,
    /// Scan options
    pub options: ScanOptions,
    /// Action to take on detection
    pub detection_action: DetectionAction,
}

/// Type of scheduled scan
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleScanType {
    /// Quick scan of common threat locations
    Quick,
    /// Full system scan
    Full,
    /// Custom scan of specified paths
    Custom,
}

/// Schedule frequency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduleFrequency {
    /// Run once at a specific time
    Once { datetime: DateTime<Utc> },
    /// Run daily at a specific time
    Daily { time: NaiveTime },
    /// Run on specific days of the week
    Weekly { days: Vec<Weekday>, time: NaiveTime },
    /// Run on specific day of the month
    Monthly { day: u32, time: NaiveTime },
    /// Custom cron expression
    Cron { expression: String },
}

impl ScheduleFrequency {
    /// Calculate the next occurrence from the given time
    pub fn next_occurrence(&self, from: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            ScheduleFrequency::Once { datetime } => {
                if *datetime > from {
                    Some(*datetime)
                } else {
                    None
                }
            }
            ScheduleFrequency::Daily { time } => {
                let today = from.date_naive();
                let scheduled = today.and_time(*time);
                let scheduled_utc = DateTime::from_naive_utc_and_offset(scheduled, Utc);

                if scheduled_utc > from {
                    Some(scheduled_utc)
                } else {
                    // Schedule for tomorrow
                    let tomorrow = today.succ_opt()?;
                    Some(DateTime::from_naive_utc_and_offset(
                        tomorrow.and_time(*time),
                        Utc,
                    ))
                }
            }
            ScheduleFrequency::Weekly { days, time } => {
                if days.is_empty() {
                    return None;
                }

                let today = from.date_naive();

                // Find next matching day
                for i in 0..=7 {
                    let check_date = today + chrono::Duration::days(i);
                    let check_weekday = check_date.weekday();

                    if days.contains(&check_weekday) {
                        let scheduled = check_date.and_time(*time);
                        let scheduled_utc = DateTime::from_naive_utc_and_offset(scheduled, Utc);

                        if scheduled_utc > from {
                            return Some(scheduled_utc);
                        }
                    }
                }

                None
            }
            ScheduleFrequency::Monthly { day, time } => {
                let today = from.date_naive();
                let mut check_month = today.month();
                let mut check_year = today.year();

                for _ in 0..13 {
                    if let Some(check_date) = chrono::NaiveDate::from_ymd_opt(
                        check_year,
                        check_month,
                        (*day).min(days_in_month(check_year, check_month)),
                    ) {
                        let scheduled = check_date.and_time(*time);
                        let scheduled_utc = DateTime::from_naive_utc_and_offset(scheduled, Utc);

                        if scheduled_utc > from {
                            return Some(scheduled_utc);
                        }
                    }

                    // Move to next month
                    check_month += 1;
                    if check_month > 12 {
                        check_month = 1;
                        check_year += 1;
                    }
                }

                None
            }
            ScheduleFrequency::Cron { expression } => {
                // Simple cron parsing - for complex expressions, consider using cron crate
                parse_cron_next(expression, from)
            }
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            ScheduleFrequency::Once { datetime } => {
                format!("Once at {}", datetime.format("%Y-%m-%d %H:%M"))
            }
            ScheduleFrequency::Daily { time } => {
                format!("Daily at {}", time.format("%H:%M"))
            }
            ScheduleFrequency::Weekly { days, time } => {
                let day_names: Vec<&str> = days
                    .iter()
                    .map(|d| match d {
                        Weekday::Mon => "Monday",
                        Weekday::Tue => "Tuesday",
                        Weekday::Wed => "Wednesday",
                        Weekday::Thu => "Thursday",
                        Weekday::Fri => "Friday",
                        Weekday::Sat => "Saturday",
                        Weekday::Sun => "Sunday",
                    })
                    .collect();
                format!("Every {} at {}", day_names.join(", "), time.format("%H:%M"))
            }
            ScheduleFrequency::Monthly { day, time } => {
                format!("Monthly on day {} at {}", day, time.format("%H:%M"))
            }
            ScheduleFrequency::Cron { expression } => {
                format!("Cron: {}", expression)
            }
        }
    }
}

/// Calculate days in a month
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

/// Simple cron expression parser (minute hour day month weekday)
fn parse_cron_next(expression: &str, from: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let parts: Vec<&str> = expression.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }

    // Parse minute and hour for simple cases
    let minute = parse_cron_field(parts[0], 0..60)?;
    let hour = parse_cron_field(parts[1], 0..24)?;

    let today = from.date_naive();

    // Try next 366 days
    for i in 0..366 {
        let check_date = today + chrono::Duration::days(i);

        // Check day of month
        if parts[2] != "*" {
            if let Ok(day) = parts[2].parse::<u32>() {
                if check_date.day() != day {
                    continue;
                }
            }
        }

        // Check month
        if parts[3] != "*" {
            if let Ok(month) = parts[3].parse::<u32>() {
                if check_date.month() != month {
                    continue;
                }
            }
        }

        // Check weekday
        if parts[4] != "*" {
            if let Ok(weekday) = parts[4].parse::<u32>() {
                let check_weekday = check_date.weekday().num_days_from_sunday();
                if check_weekday != weekday {
                    continue;
                }
            }
        }

        // Found a matching day, use the time
        if let Some(time) = NaiveTime::from_hms_opt(hour as u32, minute as u32, 0) {
            let scheduled = check_date.and_time(time);
            let scheduled_utc = DateTime::from_naive_utc_and_offset(scheduled, Utc);

            if scheduled_utc > from {
                return Some(scheduled_utc);
            }
        }
    }

    None
}

/// Parse a cron field value
fn parse_cron_field(field: &str, range: std::ops::Range<i32>) -> Option<i32> {
    if field == "*" {
        return Some(range.start);
    }

    if let Ok(val) = field.parse::<i32>() {
        if range.contains(&val) {
            return Some(val);
        }
    }

    None
}

/// Scan options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Scan inside archive files
    pub scan_archives: bool,
    /// Follow symbolic links
    pub follow_symlinks: bool,
    /// CPU priority for scanning
    pub cpu_priority: CpuPriority,
    /// Skip scan if running on battery
    pub skip_if_on_battery: bool,
    /// Wake system from sleep to perform scan
    pub wake_to_scan: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_archives: true,
            follow_symlinks: false,
            cpu_priority: CpuPriority::Normal,
            skip_if_on_battery: false,
            wake_to_scan: false,
        }
    }
}

/// CPU priority levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CpuPriority {
    Low,
    Normal,
    High,
}

impl CpuPriority {
    /// Get the niceness value for this priority
    pub fn nice_value(&self) -> i32 {
        match self {
            CpuPriority::Low => 19,
            CpuPriority::Normal => 0,
            CpuPriority::High => -10,
        }
    }
}

/// Action to take when a threat is detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionAction {
    /// Only send an alert
    Alert,
    /// Automatically quarantine the file
    Quarantine,
    /// Execute a custom response action
    Custom {
        action_name: String,
        params: serde_json::Value,
    },
}

/// Current status of a schedule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    /// Schedule is enabled and waiting
    Enabled,
    /// Schedule is disabled
    Disabled,
    /// Schedule is currently running
    Running,
    /// Schedule completed successfully
    Completed,
    /// Schedule failed
    Failed,
}

/// Record of a schedule run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRun {
    /// Unique run ID
    pub id: Uuid,
    /// Schedule that was run
    pub schedule_id: ScheduleId,
    /// When the run started
    pub started_at: DateTime<Utc>,
    /// When the run completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Run status
    pub status: ScheduleRunStatus,
    /// Number of files scanned
    pub files_scanned: u64,
    /// Number of threats found
    pub threats_found: u32,
    /// Error message if failed
    pub error_message: Option<String>,
}

impl ScheduleRun {
    /// Get duration of the run
    pub fn duration(&self) -> Option<chrono::Duration> {
        self.completed_at.map(|end| end - self.started_at)
    }
}

/// Status of a schedule run
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_daily_next_occurrence() {
        let freq = ScheduleFrequency::Daily {
            time: NaiveTime::from_hms_opt(10, 0, 0).unwrap(),
        };

        let from = chrono::DateTime::parse_from_rfc3339("2024-01-15T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let next = freq.next_occurrence(from);
        assert!(next.is_some());

        let next = next.unwrap();
        assert_eq!(next.hour(), 10);
        assert_eq!(next.minute(), 0);
    }

    #[test]
    fn test_weekly_next_occurrence() {
        let freq = ScheduleFrequency::Weekly {
            days: vec![Weekday::Mon, Weekday::Wed, Weekday::Fri],
            time: NaiveTime::from_hms_opt(14, 30, 0).unwrap(),
        };

        let next = freq.next_occurrence(Utc::now());
        assert!(next.is_some());
    }

    #[test]
    fn test_monthly_next_occurrence() {
        let freq = ScheduleFrequency::Monthly {
            day: 15,
            time: NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
        };

        let next = freq.next_occurrence(Utc::now());
        assert!(next.is_some());
    }

    #[test]
    fn test_schedule_creation() {
        let config = ScheduleConfig {
            name: "Test Schedule".to_string(),
            scan_type: ScheduleScanType::Quick,
            frequency: ScheduleFrequency::Daily {
                time: NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
            },
            paths: vec![],
            options: ScanOptions::default(),
            detection_action: DetectionAction::Alert,
        };

        let schedule = Schedule::new(config);
        assert!(schedule.enabled);
        assert!(schedule.next_run.is_some());
    }
}
