//! macOS launchd integration

use super::schedule::{Schedule, ScheduleFrequency};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

/// Check if the system is running on battery
pub fn is_on_battery() -> bool {
    // Use pmset to check power source
    let output = Command::new("pmset")
        .args(["-g", "batt"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Look for "Battery Power" in output
            stdout.contains("Battery Power")
        }
        _ => false,
    }
}

/// Register a launchd plist for the schedule
pub fn register_launchd(schedule: &Schedule) -> Result<()> {
    let label = format!("com.tamandua.scan.{}", schedule.id);
    let exe_path = std::env::current_exe()?;

    // Create LaunchAgents directory
    let launch_agents_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?
        .join("Library/LaunchAgents");
    fs::create_dir_all(&launch_agents_dir)?;

    // Build plist content
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--run-schedule</string>
        <string>{}</string>
    </array>

    {}

    <key>RunAtLoad</key>
    <false/>

    <key>Nice</key>
    <integer>{}</integer>

    <key>ProcessType</key>
    <string>Background</string>

    <key>LowPriorityIO</key>
    <{}/>

    <key>StandardOutPath</key>
    <string>/tmp/tamandua-scan-{}.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/tamandua-scan-{}.err</string>
</dict>
</plist>
"#,
        label,
        exe_path.display(),
        schedule.id,
        format_launchd_calendar(&schedule.config.frequency),
        schedule.config.options.cpu_priority.nice_value(),
        if schedule.config.options.cpu_priority == super::schedule::CpuPriority::Low { "true" } else { "false" },
        schedule.id,
        schedule.id
    );

    let plist_path = launch_agents_dir.join(format!("{}.plist", label));
    fs::write(&plist_path, plist_content)?;
    debug!("Created launchd plist: {:?}", plist_path);

    // Unload if already loaded
    let _ = Command::new("launchctl")
        .args(["unload", plist_path.to_str().unwrap_or_default()])
        .output();

    // Load the plist
    let output = Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap_or_default()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to load launchd plist: {}", stderr);
        return Err(anyhow::anyhow!("launchctl load failed: {}", stderr));
    }

    info!("Created launchd job: {}", label);
    Ok(())
}

/// Unregister a launchd plist
pub fn unregister_launchd(schedule: &Schedule) -> Result<()> {
    let label = format!("com.tamandua.scan.{}", schedule.id);

    let launch_agents_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?
        .join("Library/LaunchAgents");

    let plist_path = launch_agents_dir.join(format!("{}.plist", label));

    // Unload the plist
    if plist_path.exists() {
        let _ = Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap_or_default()])
            .output();

        fs::remove_file(&plist_path)?;
    }

    info!("Removed launchd job: {}", label);
    Ok(())
}

/// Format StartCalendarInterval for launchd
fn format_launchd_calendar(frequency: &ScheduleFrequency) -> String {
    match frequency {
        ScheduleFrequency::Once { datetime } => {
            format!(
                r#"<key>StartCalendarInterval</key>
    <dict>
        <key>Month</key>
        <integer>{}</integer>
        <key>Day</key>
        <integer>{}</integer>
        <key>Hour</key>
        <integer>{}</integer>
        <key>Minute</key>
        <integer>{}</integer>
    </dict>"#,
                datetime.format("%m").to_string().parse::<u32>().unwrap_or(1),
                datetime.format("%d").to_string().parse::<u32>().unwrap_or(1),
                datetime.format("%H").to_string().parse::<u32>().unwrap_or(0),
                datetime.format("%M").to_string().parse::<u32>().unwrap_or(0)
            )
        }
        ScheduleFrequency::Daily { time } => {
            format!(
                r#"<key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>{}</integer>
        <key>Minute</key>
        <integer>{}</integer>
    </dict>"#,
                time.hour(),
                time.minute()
            )
        }
        ScheduleFrequency::Weekly { days, time } => {
            if days.is_empty() {
                return format_launchd_calendar(&ScheduleFrequency::Daily { time: *time });
            }

            // launchd uses Weekday: 0 = Sunday, 1 = Monday, etc.
            let intervals: Vec<String> = days.iter()
                .map(|d| {
                    let weekday = match d {
                        chrono::Weekday::Sun => 0,
                        chrono::Weekday::Mon => 1,
                        chrono::Weekday::Tue => 2,
                        chrono::Weekday::Wed => 3,
                        chrono::Weekday::Thu => 4,
                        chrono::Weekday::Fri => 5,
                        chrono::Weekday::Sat => 6,
                    };
                    format!(
                        r#"<dict>
            <key>Weekday</key>
            <integer>{}</integer>
            <key>Hour</key>
            <integer>{}</integer>
            <key>Minute</key>
            <integer>{}</integer>
        </dict>"#,
                        weekday,
                        time.hour(),
                        time.minute()
                    )
                })
                .collect();

            format!(
                r#"<key>StartCalendarInterval</key>
    <array>
        {}
    </array>"#,
                intervals.join("\n        ")
            )
        }
        ScheduleFrequency::Monthly { day, time } => {
            format!(
                r#"<key>StartCalendarInterval</key>
    <dict>
        <key>Day</key>
        <integer>{}</integer>
        <key>Hour</key>
        <integer>{}</integer>
        <key>Minute</key>
        <integer>{}</integer>
    </dict>"#,
                day,
                time.hour(),
                time.minute()
            )
        }
        ScheduleFrequency::Cron { expression } => {
            // Parse cron and convert to launchd format
            let parts: Vec<&str> = expression.split_whitespace().collect();
            if parts.len() >= 2 {
                let minute = parts[0].parse::<u32>().unwrap_or(0);
                let hour = parts[1].parse::<u32>().unwrap_or(0);

                return format!(
                    r#"<key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>{}</integer>
        <key>Minute</key>
        <integer>{}</integer>
    </dict>"#,
                    hour, minute
                );
            }

            // Default to daily at midnight
            r#"<key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>0</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>"#.to_string()
        }
    }
}

/// Get status of a launchd job
pub fn get_job_status(schedule: &Schedule) -> Result<JobStatus> {
    let label = format!("com.tamandua.scan.{}", schedule.id);

    let output = Command::new("launchctl")
        .args(["list", &label])
        .output()?;

    if !output.status.success() {
        return Ok(JobStatus::NotLoaded);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse launchctl list output
    if let Some(line) = stdout.lines().find(|l| l.contains(&label)) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pid) = parts[0].parse::<i32>() {
                if pid > 0 {
                    return Ok(JobStatus::Running(pid));
                }
            }
        }
    }

    Ok(JobStatus::Loaded)
}

/// Status of a launchd job
#[derive(Debug, PartialEq)]
pub enum JobStatus {
    NotLoaded,
    Loaded,
    Running(i32),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveTime;

    #[test]
    fn test_format_launchd_daily() {
        let freq = ScheduleFrequency::Daily {
            time: NaiveTime::from_hms_opt(14, 30, 0).unwrap(),
        };
        let plist = format_launchd_calendar(&freq);
        assert!(plist.contains("<key>Hour</key>"));
        assert!(plist.contains("<integer>14</integer>"));
        assert!(plist.contains("<key>Minute</key>"));
        assert!(plist.contains("<integer>30</integer>"));
    }

    #[test]
    fn test_format_launchd_weekly() {
        let freq = ScheduleFrequency::Weekly {
            days: vec![chrono::Weekday::Mon],
            time: NaiveTime::from_hms_opt(9, 0, 0).unwrap(),
        };
        let plist = format_launchd_calendar(&freq);
        assert!(plist.contains("<key>Weekday</key>"));
        assert!(plist.contains("<integer>1</integer>")); // Monday
    }

    #[test]
    fn test_is_on_battery() {
        // Just ensure it doesn't panic
        let _ = is_on_battery();
    }
}
