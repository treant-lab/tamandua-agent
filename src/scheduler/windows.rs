//! Windows Task Scheduler integration

use super::schedule::{Schedule, ScheduleFrequency};
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info, warn};

/// Check if the system is running on battery
pub fn is_on_battery() -> bool {
    use windows::Win32::System::Power::GetSystemPowerStatus;
    use windows::Win32::System::Power::SYSTEM_POWER_STATUS;

    unsafe {
        let mut status = SYSTEM_POWER_STATUS::default();
        if GetSystemPowerStatus(&mut status).is_ok() {
            // ACLineStatus: 0 = Offline (on battery), 1 = Online (plugged in)
            status.ACLineStatus == 0
        } else {
            false
        }
    }
}

/// Register a scheduled task with Windows Task Scheduler
pub fn register_task(schedule: &Schedule) -> Result<()> {
    let task_name = format!("TamanduaScan_{}", schedule.id);
    let exe_path = std::env::current_exe()?;

    // Build the schtasks command
    let mut args = vec![
        "/Create".to_string(),
        "/TN".to_string(),
        task_name.clone(),
        "/TR".to_string(),
        format!("\"{}\" --run-schedule {}", exe_path.display(), schedule.id),
        "/F".to_string(), // Force overwrite
    ];

    // Add schedule trigger based on frequency
    match &schedule.config.frequency {
        ScheduleFrequency::Once { datetime } => {
            args.push("/SC".to_string());
            args.push("ONCE".to_string());
            args.push("/ST".to_string());
            args.push(datetime.format("%H:%M").to_string());
            args.push("/SD".to_string());
            args.push(datetime.format("%m/%d/%Y").to_string());
        }
        ScheduleFrequency::Daily { time } => {
            args.push("/SC".to_string());
            args.push("DAILY".to_string());
            args.push("/ST".to_string());
            args.push(time.format("%H:%M").to_string());
        }
        ScheduleFrequency::Weekly { days, time } => {
            args.push("/SC".to_string());
            args.push("WEEKLY".to_string());
            args.push("/ST".to_string());
            args.push(time.format("%H:%M").to_string());

            if !days.is_empty() {
                let day_str: String = days
                    .iter()
                    .map(|d| match d {
                        chrono::Weekday::Mon => "MON",
                        chrono::Weekday::Tue => "TUE",
                        chrono::Weekday::Wed => "WED",
                        chrono::Weekday::Thu => "THU",
                        chrono::Weekday::Fri => "FRI",
                        chrono::Weekday::Sat => "SAT",
                        chrono::Weekday::Sun => "SUN",
                    })
                    .collect::<Vec<_>>()
                    .join(",");

                args.push("/D".to_string());
                args.push(day_str);
            }
        }
        ScheduleFrequency::Monthly { day, time } => {
            args.push("/SC".to_string());
            args.push("MONTHLY".to_string());
            args.push("/ST".to_string());
            args.push(time.format("%H:%M").to_string());
            args.push("/D".to_string());
            args.push(day.to_string());
        }
        ScheduleFrequency::Cron { expression } => {
            // Parse cron expression and use closest schtasks equivalent
            // For simplicity, use daily schedule with the cron time
            let parts: Vec<&str> = expression.split_whitespace().collect();
            if parts.len() >= 2 {
                let minute = parts[0].parse::<u32>().unwrap_or(0);
                let hour = parts[1].parse::<u32>().unwrap_or(0);
                args.push("/SC".to_string());
                args.push("DAILY".to_string());
                args.push("/ST".to_string());
                args.push(format!("{:02}:{:02}", hour, minute));
            }
        }
    }

    // Add run level
    args.push("/RL".to_string());
    args.push("HIGHEST".to_string());

    // Add battery settings
    if !schedule.config.options.skip_if_on_battery {
        args.push("/NP".to_string()); // No battery policy
    }

    // Execute schtasks
    debug!("Creating scheduled task: schtasks {}", args.join(" "));

    let output = Command::new("schtasks").args(&args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to create scheduled task: {}", stderr);
        return Err(anyhow::anyhow!("schtasks failed: {}", stderr));
    }

    info!("Created Windows scheduled task: {}", task_name);
    Ok(())
}

/// Unregister a scheduled task from Windows Task Scheduler
pub fn unregister_task(schedule: &Schedule) -> Result<()> {
    let task_name = format!("TamanduaScan_{}", schedule.id);

    let output = Command::new("schtasks")
        .args(["/Delete", "/TN", &task_name, "/F"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore if task doesn't exist
        if !stderr.contains("does not exist") {
            warn!("Failed to delete scheduled task: {}", stderr);
        }
    } else {
        info!("Deleted Windows scheduled task: {}", task_name);
    }

    Ok(())
}

/// Get the status of a scheduled task
pub fn get_task_status(schedule: &Schedule) -> Result<TaskStatus> {
    let task_name = format!("TamanduaScan_{}", schedule.id);

    let output = Command::new("schtasks")
        .args(["/Query", "/TN", &task_name, "/FO", "LIST", "/V"])
        .output()?;

    if !output.status.success() {
        return Ok(TaskStatus::NotFound);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("Running") {
        Ok(TaskStatus::Running)
    } else if stdout.contains("Ready") {
        Ok(TaskStatus::Ready)
    } else if stdout.contains("Disabled") {
        Ok(TaskStatus::Disabled)
    } else {
        Ok(TaskStatus::Unknown)
    }
}

/// Wake the system for a scheduled task
pub fn enable_wake_timer(schedule: &Schedule) -> Result<()> {
    if !schedule.config.options.wake_to_scan {
        return Ok(());
    }

    let task_name = format!("TamanduaScan_{}", schedule.id);

    // Use powershell to modify task settings for wake timer
    let script = format!(
        r#"
        $task = Get-ScheduledTask -TaskName "{}"
        $settings = $task.Settings
        $settings.WakeToRun = $true
        Set-ScheduledTask -TaskName "{}" -Settings $settings
        "#,
        task_name, task_name
    );

    let output = Command::new("powershell")
        .args(["-Command", &script])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to enable wake timer: {}", stderr);
    } else {
        info!("Enabled wake timer for task: {}", task_name);
    }

    Ok(())
}

/// Status of a Windows scheduled task
#[derive(Debug, PartialEq)]
pub enum TaskStatus {
    Ready,
    Running,
    Disabled,
    NotFound,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_on_battery() {
        // Just ensure it doesn't panic
        let _ = is_on_battery();
    }
}
