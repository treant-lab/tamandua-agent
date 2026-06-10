//! Desktop notifications for alerts

use anyhow::{Context, Result};
use tracing::{debug, warn};

use crate::ipc::{AlertNotification, AlertSeverity};

/// Show a desktop notification for an alert
pub fn show_alert_notification(alert: &AlertNotification) -> Result<()> {
    let title = format!("[{}] {}", severity_to_emoji(&alert.severity), alert.title);
    let body = &alert.description;

    #[cfg(target_os = "linux")]
    {
        use notify_rust::{Notification, Timeout, Urgency};

        let urgency = match alert.severity {
            AlertSeverity::Info => Urgency::Low,
            AlertSeverity::Low => Urgency::Low,
            AlertSeverity::Medium => Urgency::Normal,
            AlertSeverity::High => Urgency::Critical,
            AlertSeverity::Critical => Urgency::Critical,
        };

        Notification::new()
            .summary(&title)
            .body(body)
            .urgency(urgency)
            .timeout(Timeout::Milliseconds(10000))
            .show()
            .context("Failed to show notification")?;

        debug!("Showed notification for alert: {}", alert.id);
    }

    #[cfg(target_os = "windows")]
    {
        // Windows notifications via tray-icon are handled separately
        // Log the notification for now
        debug!("Alert notification (Windows): {} - {}", title, body);
    }

    #[cfg(target_os = "macos")]
    {
        // macOS notifications can use osascript or UNUserNotificationCenter
        debug!("Alert notification (macOS): {} - {}", title, body);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        warn!("Desktop notifications not supported on this platform");
    }

    Ok(())
}

/// Convert severity to emoji indicator
fn severity_to_emoji(severity: &AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Info => "ℹ️",
        AlertSeverity::Low => "⚠️",
        AlertSeverity::Medium => "⚠️",
        AlertSeverity::High => "🔴",
        AlertSeverity::Critical => "🚨",
    }
}

/// Show a generic notification
#[allow(dead_code)]
pub fn show_notification(title: &str, body: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use notify_rust::{Notification, Timeout};

        Notification::new()
            .summary(title)
            .body(body)
            .timeout(Timeout::Milliseconds(5000))
            .show()
            .context("Failed to show notification")?;
    }

    #[cfg(target_os = "windows")]
    {
        debug!("Notification (Windows): {} - {}", title, body);
    }

    #[cfg(target_os = "macos")]
    {
        debug!("Notification (macOS): {} - {}", title, body);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    #[ignore] // Requires desktop environment
    fn test_show_notification() {
        let alert = AlertNotification {
            id: "test-1".to_string(),
            timestamp: Utc::now(),
            severity: AlertSeverity::High,
            title: "Test Alert".to_string(),
            description: "This is a test alert notification.".to_string(),
            threat_name: Some("TestThreat".to_string()),
            process_name: None,
            process_id: None,
            file_path: None,
            mitre_tactics: vec![],
            remediation: None,
            acknowledged: false,
        };

        let result = show_alert_notification(&alert);
        assert!(result.is_ok());
    }
}
