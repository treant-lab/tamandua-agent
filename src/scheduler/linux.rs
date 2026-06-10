//! Linux systemd timer and cron integration

use super::schedule::{Schedule, ScheduleFrequency};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

/// Check if the system is running on battery
pub fn is_on_battery() -> bool {
    // Check /sys/class/power_supply for battery status
    let power_supply_path = PathBuf::from("/sys/class/power_supply");

    if let Ok(entries) = fs::read_dir(&power_supply_path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Check AC adapter status
            if name.starts_with("AC") || name.starts_with("ACAD") {
                let online_path = path.join("online");
                if let Ok(content) = fs::read_to_string(&online_path) {
                    if content.trim() == "0" {
                        return true; // AC is offline, on battery
                    }
                }
            }

            // Check battery status
            if name.starts_with("BAT") {
                let status_path = path.join("status");
                if let Ok(content) = fs::read_to_string(&status_path) {
                    let status = content.trim().to_lowercase();
                    if status == "discharging" {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Register a systemd timer for the schedule
pub fn register_systemd_timer(schedule: &Schedule) -> Result<()> {
    let unit_name = format!("tamandua-scan-{}", schedule.id);
    let exe_path = std::env::current_exe()?;

    // Create systemd user directory
    let systemd_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("systemd/user");
    fs::create_dir_all(&systemd_dir)?;

    // Create service unit
    let service_content = format!(
        r#"[Unit]
Description=Tamandua Scheduled Scan: {}
After=network.target

[Service]
Type=oneshot
ExecStart={} --run-schedule {}
Nice={}
"#,
        schedule.name,
        exe_path.display(),
        schedule.id,
        schedule.config.options.cpu_priority.nice_value()
    );

    let service_path = systemd_dir.join(format!("{}.service", unit_name));
    fs::write(&service_path, service_content)?;
    debug!("Created service unit: {:?}", service_path);

    // Create timer unit
    let timer_content = format!(
        r#"[Unit]
Description=Timer for Tamandua Scheduled Scan: {}

[Timer]
{}
Persistent=true
{}

[Install]
WantedBy=timers.target
"#,
        schedule.name,
        format_systemd_oncalendar(&schedule.config.frequency),
        if schedule.config.options.wake_to_scan { "WakeSystem=true" } else { "" }
    );

    let timer_path = systemd_dir.join(format!("{}.timer", unit_name));
    fs::write(&timer_path, timer_content)?;
    debug!("Created timer unit: {:?}", timer_path);

    // Reload systemd and enable timer
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    let output = Command::new("systemctl")
        .args(["--user", "enable", "--now", &format!("{}.timer", unit_name)])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to enable systemd timer: {}", stderr);

        // Fall back to cron
        return register_cron(schedule);
    }

    info!("Created systemd timer: {}", unit_name);
    Ok(())
}

/// Unregister a systemd timer
pub fn unregister_systemd_timer(schedule: &Schedule) -> Result<()> {
    let unit_name = format!("tamandua-scan-{}", schedule.id);

    // Stop and disable timer
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &format!("{}.timer", unit_name)])
        .output();

    let _ = Command::new("systemctl")
        .args(["--user", "disable", &format!("{}.timer", unit_name)])
        .output();

    // Remove unit files
    let systemd_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("systemd/user");

    let service_path = systemd_dir.join(format!("{}.service", unit_name));
    let timer_path = systemd_dir.join(format!("{}.timer", unit_name));

    let _ = fs::remove_file(&service_path);
    let _ = fs::remove_file(&timer_path);

    // Reload systemd
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    // Also remove cron entry if exists
    let _ = unregister_cron(schedule);

    info!("Removed systemd timer: {}", unit_name);
    Ok(())
}

/// Format OnCalendar directive for systemd timer
fn format_systemd_oncalendar(frequency: &ScheduleFrequency) -> String {
    match frequency {
        ScheduleFrequency::Once { datetime } => {
            format!("OnCalendar={}", datetime.format("%Y-%m-%d %H:%M:%S"))
        }
        ScheduleFrequency::Daily { time } => {
            format!("OnCalendar=*-*-* {}", time.format("%H:%M:%S"))
        }
        ScheduleFrequency::Weekly { days, time } => {
            let day_str: String = days.iter()
                .map(|d| match d {
                    chrono::Weekday::Mon => "Mon",
                    chrono::Weekday::Tue => "Tue",
                    chrono::Weekday::Wed => "Wed",
                    chrono::Weekday::Thu => "Thu",
                    chrono::Weekday::Fri => "Fri",
                    chrono::Weekday::Sat => "Sat",
                    chrono::Weekday::Sun => "Sun",
                })
                .collect::<Vec<_>>()
                .join(",");

            format!("OnCalendar={} {}", day_str, time.format("%H:%M:%S"))
        }
        ScheduleFrequency::Monthly { day, time } => {
            format!("OnCalendar=*-*-{} {}", day, time.format("%H:%M:%S"))
        }
        ScheduleFrequency::Cron { expression } => {
            // Convert cron to systemd calendar format
            convert_cron_to_oncalendar(expression)
        }
    }
}

/// Convert cron expression to systemd OnCalendar format
fn convert_cron_to_oncalendar(cron: &str) -> String {
    let parts: Vec<&str> = cron.split_whitespace().collect();
    if parts.len() != 5 {
        return "OnCalendar=daily".to_string();
    }

    let minute = parts[0];
    let hour = parts[1];
    let day = if parts[2] == "*" { "*" } else { parts[2] };
    let month = if parts[3] == "*" { "*" } else { parts[3] };
    let weekday = if parts[4] == "*" { "" } else {
        match parts[4] {
            "0" | "7" => "Sun ",
            "1" => "Mon ",
            "2" => "Tue ",
            "3" => "Wed ",
            "4" => "Thu ",
            "5" => "Fri ",
            "6" => "Sat ",
            _ => "",
        }
    };

    format!(
        "OnCalendar={}{}-{}-{} {:0>2}:{:0>2}:00",
        weekday, "*", month, day, hour, minute
    )
}

/// Register a cron job as fallback
fn register_cron(schedule: &Schedule) -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let cron_entry = format!(
        "{} {} --run-schedule {} # tamandua-{}",
        format_cron_schedule(&schedule.config.frequency),
        exe_path.display(),
        schedule.id,
        schedule.id
    );

    // Read current crontab
    let output = Command::new("crontab")
        .arg("-l")
        .output();

    let current_crontab = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => String::new(),
    };

    // Remove any existing entry for this schedule
    let filtered: Vec<&str> = current_crontab
        .lines()
        .filter(|l| !l.contains(&format!("tamandua-{}", schedule.id)))
        .collect();

    // Add new entry
    let mut new_crontab = filtered.join("\n");
    if !new_crontab.is_empty() && !new_crontab.ends_with('\n') {
        new_crontab.push('\n');
    }
    new_crontab.push_str(&cron_entry);
    new_crontab.push('\n');

    // Write new crontab
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(new_crontab.as_bytes())?;
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to update crontab"));
    }

    info!("Created cron entry for schedule: {}", schedule.id);
    Ok(())
}

/// Unregister a cron job
fn unregister_cron(schedule: &Schedule) -> Result<()> {
    // Read current crontab
    let output = Command::new("crontab")
        .arg("-l")
        .output()?;

    if !output.status.success() {
        return Ok(());
    }

    let current_crontab = String::from_utf8_lossy(&output.stdout);

    // Remove entry for this schedule
    let filtered: Vec<&str> = current_crontab
        .lines()
        .filter(|l| !l.contains(&format!("tamandua-{}", schedule.id)))
        .collect();

    let new_crontab = filtered.join("\n") + "\n";

    // Write new crontab
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(new_crontab.as_bytes())?;
    }

    let _ = child.wait();
    Ok(())
}

/// Format cron schedule expression
fn format_cron_schedule(frequency: &ScheduleFrequency) -> String {
    match frequency {
        ScheduleFrequency::Once { datetime } => {
            format!(
                "{} {} {} {} *",
                datetime.format("%M"),
                datetime.format("%H"),
                datetime.format("%d"),
                datetime.format("%m")
            )
        }
        ScheduleFrequency::Daily { time } => {
            format!("{} {} * * *", time.format("%M"), time.format("%H"))
        }
        ScheduleFrequency::Weekly { days, time } => {
            let day_nums: String = days.iter()
                .map(|d| match d {
                    chrono::Weekday::Sun => "0",
                    chrono::Weekday::Mon => "1",
                    chrono::Weekday::Tue => "2",
                    chrono::Weekday::Wed => "3",
                    chrono::Weekday::Thu => "4",
                    chrono::Weekday::Fri => "5",
                    chrono::Weekday::Sat => "6",
                })
                .collect::<Vec<_>>()
                .join(",");

            format!(
                "{} {} * * {}",
                time.format("%M"),
                time.format("%H"),
                day_nums
            )
        }
        ScheduleFrequency::Monthly { day, time } => {
            format!("{} {} {} * *", time.format("%M"), time.format("%H"), day)
        }
        ScheduleFrequency::Cron { expression } => expression.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveTime;

    #[test]
    fn test_format_cron_daily() {
        let freq = ScheduleFrequency::Daily {
            time: NaiveTime::from_hms_opt(14, 30, 0).unwrap(),
        };
        let cron = format_cron_schedule(&freq);
        assert_eq!(cron, "30 14 * * *");
    }

    #[test]
    fn test_format_cron_weekly() {
        let freq = ScheduleFrequency::Weekly {
            days: vec![chrono::Weekday::Mon, chrono::Weekday::Wed, chrono::Weekday::Fri],
            time: NaiveTime::from_hms_opt(9, 0, 0).unwrap(),
        };
        let cron = format_cron_schedule(&freq);
        assert_eq!(cron, "00 09 * * 1,3,5");
    }

    #[test]
    fn test_is_on_battery() {
        // Just ensure it doesn't panic
        let _ = is_on_battery();
    }
}
