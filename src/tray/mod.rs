//! System Tray Application (unprivileged)
//!
//! Provides user interface for the Tamandua EDR agent:
//! - System tray icon with status indicator
//! - Context menu for common actions
//! - Desktop notifications for alerts
//! - Communication with service via IPC

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use tray_icon::menu::Menu;

mod icon;
mod menu;
mod notifications;

use crate::ipc::{AgentStatus, AlertNotification, AlertSeverity, IpcClient, IpcMessage};

/// System tray application state
pub struct TrayApp {
    ipc_client: Arc<IpcClient>,
    status: Arc<RwLock<Option<AgentStatus>>>,
    notifications_enabled: Arc<RwLock<bool>>,
}

impl TrayApp {
    /// Create a new tray application
    pub async fn new() -> Result<Self> {
        info!("Initializing system tray application");

        // Connect to service
        let ipc_client = IpcClient::connect()
            .await
            .context("Failed to connect to agent service. Is the service running?")?;

        Ok(Self {
            ipc_client: Arc::new(ipc_client),
            status: Arc::new(RwLock::new(None)),
            notifications_enabled: Arc::new(RwLock::new(true)),
        })
    }

    /// Run the tray application
    pub async fn run(self) -> Result<()> {
        info!("Starting system tray application");

        // Start periodic status updates
        let status_updater = self.start_status_updater();

        // Start notification listener
        let notification_listener = self.start_notification_listener();

        // Build and run tray icon (this blocks)
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        self.run_tray_icon().await?;

        // Wait for tasks to complete (shouldn't happen unless shutting down)
        tokio::select! {
            _ = status_updater => {
                warn!("Status updater exited");
            }
            _ = notification_listener => {
                warn!("Notification listener exited");
            }
        }

        Ok(())
    }

    /// Build and run the system tray icon
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    async fn run_tray_icon(&self) -> Result<()> {
        use tray_icon::{
            menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
            TrayIconBuilder, TrayIconEvent,
        };

        // Load icon
        let icon = icon::load_icon()?;

        // Build menu
        let menu = self.build_menu()?;

        // Create tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Tamandua EDR Agent")
            .with_icon(icon)
            .build()
            .context("Failed to create tray icon")?;

        info!("System tray icon created");

        // Handle menu events
        let menu_channel = MenuEvent::receiver();
        let tray_channel = TrayIconEvent::receiver();

        loop {
            tokio::select! {
                Ok(event) = tokio::task::spawn_blocking({
                    let menu_rx = menu_channel.clone();
                    move || menu_rx.recv()
                }) => {
                    if let Ok(event) = event {
                        if let Err(e) = self.handle_menu_event(event).await {
                            error!("Error handling menu event: {}", e);
                        }
                    }
                }

                Ok(event) = tokio::task::spawn_blocking({
                    let tray_rx = tray_channel.clone();
                    move || tray_rx.recv()
                }) => {
                    if let Ok(_event) = event {
                        debug!("Tray icon event received");
                    }
                }

                // Update icon based on status changes
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                    if let Err(e) = self.update_tray_icon(&tray_icon).await {
                        warn!("Failed to update tray icon: {}", e);
                    }
                }
            }
        }
    }

    /// Build the context menu
    fn build_menu(&self) -> Result<Menu> {
        use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};

        let menu = Menu::new();

        // Status
        let status_item = MenuItem::new("Status: Connecting...", false, None);
        menu.append(&status_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Actions
        let scan_item = MenuItem::new("Run Scan...", true, None);
        menu.append(&scan_item)?;

        let view_alerts_item = MenuItem::new("View Alerts", true, None);
        menu.append(&view_alerts_item)?;

        let view_logs_item = MenuItem::new("View Logs", true, None);
        menu.append(&view_logs_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Settings
        let settings_item = MenuItem::new("Settings...", true, None);
        menu.append(&settings_item)?;

        let about_item = MenuItem::new("About", true, None);
        menu.append(&about_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Exit
        let exit_item = MenuItem::new("Exit", true, None);
        menu.append(&exit_item)?;

        Ok(menu)
    }

    /// Handle menu events
    async fn handle_menu_event(&self, event: tray_icon::menu::MenuEvent) -> Result<()> {
        debug!("Menu event: {:?}", event.id);

        let id_str = event.id.0;

        match id_str.as_ref() {
            "scan" => {
                self.show_scan_dialog().await?;
            }
            "view_alerts" => {
                self.show_alerts_window().await?;
            }
            "view_logs" => {
                self.show_logs_window().await?;
            }
            "settings" => {
                self.show_settings_window().await?;
            }
            "about" => {
                self.show_about_dialog().await?;
            }
            "exit" => {
                info!("Exiting tray application");
                std::process::exit(0);
            }
            _ => {
                debug!("Unknown menu item: {}", id_str);
            }
        }

        Ok(())
    }

    /// Update tray icon based on current status
    async fn update_tray_icon(&self, _tray_icon: &tray_icon::TrayIcon) -> Result<()> {
        // TODO: Change icon based on agent state
        // - Green: Running, connected
        // - Yellow: Degraded or disconnected
        // - Red: Error or stopped
        Ok(())
    }

    /// Start periodic status updates
    fn start_status_updater(&self) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(&self.ipc_client);
        let status = Arc::clone(&self.status);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

            loop {
                interval.tick().await;

                match client.get_status().await {
                    Ok(new_status) => {
                        debug!("Status update: {:?}", new_status);
                        *status.write().await = Some(new_status);
                    }
                    Err(e) => {
                        warn!("Failed to get status: {}", e);
                        *status.write().await = None;
                    }
                }
            }
        })
    }

    /// Start listening for notifications from service
    fn start_notification_listener(&self) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(&self.ipc_client);
        let notifications_enabled = Arc::clone(&self.notifications_enabled);

        tokio::spawn(async move {
            let listener = Arc::clone(&client);
            let _handle = listener.start_notification_listener();

            // Subscribe to notifications
            let mut notification_rx = client.subscribe_notifications().await;

            while let Some(message) = notification_rx.recv().await {
                if let IpcMessage::Alert(alert) = message {
                    let enabled = *notifications_enabled.read().await;
                    if enabled {
                        if let Err(e) = Self::show_notification_static(&alert).await {
                            error!("Failed to show notification: {}", e);
                        }
                    }
                }
            }
        })
    }

    /// Show a desktop notification for an alert
    async fn show_notification_static(alert: &AlertNotification) -> Result<()> {
        notifications::show_alert_notification(alert).context("Failed to show desktop notification")
    }

    /// Show scan dialog
    async fn show_scan_dialog(&self) -> Result<()> {
        // TODO: Implement file picker and start scan
        info!("Show scan dialog");
        Ok(())
    }

    /// Show alerts window
    async fn show_alerts_window(&self) -> Result<()> {
        let alerts = self.ipc_client.get_alerts(None, Some(100)).await?;
        info!("Retrieved {} alerts", alerts.len());

        // TODO: Display in GUI window
        for alert in &alerts {
            println!(
                "[{}] {} - {}",
                alert.severity_str(),
                alert.title,
                alert.description
            );
        }

        Ok(())
    }

    /// Show logs window
    async fn show_logs_window(&self) -> Result<()> {
        let logs = self.ipc_client.get_logs(None, None, Some(100)).await?;
        info!("Retrieved {} log entries", logs.len());

        // TODO: Display in GUI window
        for log in &logs {
            println!("[{}] {}: {}", log.timestamp, log.level, log.message);
        }

        Ok(())
    }

    /// Show settings window
    async fn show_settings_window(&self) -> Result<()> {
        info!("Show settings window");
        // TODO: Implement settings UI
        Ok(())
    }

    /// Show about dialog
    async fn show_about_dialog(&self) -> Result<()> {
        let version = self.ipc_client.get_version().await?;

        let about_text = format!(
            "Tamandua EDR Agent\nVersion: {}\nBuild: {}\nCommit: {}",
            version.version, version.build_date, version.commit_hash
        );

        info!("About: {}", about_text);

        // TODO: Show in native dialog
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            use native_dialog::{MessageDialog, MessageType};
            MessageDialog::new()
                .set_type(MessageType::Info)
                .set_title("About Tamandua EDR")
                .set_text(&about_text)
                .show_alert()
                .ok();
        }

        Ok(())
    }
}

// Extension trait for AlertNotification
trait AlertExt {
    fn severity_str(&self) -> &str;
}

impl AlertExt for AlertNotification {
    fn severity_str(&self) -> &str {
        match self.severity {
            AlertSeverity::Info => "INFO",
            AlertSeverity::Low => "LOW",
            AlertSeverity::Medium => "MEDIUM",
            AlertSeverity::High => "HIGH",
            AlertSeverity::Critical => "CRITICAL",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires running service
    async fn test_tray_app_creation() {
        let app = TrayApp::new().await;
        assert!(app.is_ok());
    }
}
