//! Systemd integration for Linux
//!
//! Provides systemd service management, socket activation, and watchdog support.

#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

use super::{ServiceConfig, StartType};

/// Systemd service manager
pub struct SystemdManager {
    system_mode: bool,
}

impl SystemdManager {
    pub fn new(system_mode: bool) -> Self {
        Self { system_mode }
    }

    /// Install systemd service unit
    pub async fn install(&self, config: &ServiceConfig) -> Result<()> {
        info!("Installing systemd service: {}", config.name);

        let unit_content = self.generate_unit_file(config)?;
        let unit_path = self.get_unit_path(&config.name);

        // Ensure directory exists
        if let Some(parent) = unit_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write unit file
        fs::write(&unit_path, unit_content)
            .await
            .with_context(|| format!("Failed to write unit file: {}", unit_path.display()))?;

        info!("Created systemd unit at {}", unit_path.display());

        // Reload systemd
        self.reload_systemd().await?;

        // Enable service
        if matches!(config.start_type, StartType::Auto | StartType::AutoDelayed) {
            self.enable_service(&config.name).await?;
        }

        Ok(())
    }

    /// Uninstall systemd service
    pub async fn uninstall(&self, service_name: &str) -> Result<()> {
        info!("Uninstalling systemd service: {}", service_name);

        // Stop service
        self.stop_service(service_name).await.ok();

        // Disable service
        self.disable_service(service_name).await.ok();

        // Remove unit file
        let unit_path = self.get_unit_path(service_name);
        if unit_path.exists() {
            fs::remove_file(&unit_path).await?;
            info!("Removed unit file: {}", unit_path.display());
        }

        // Reload systemd
        self.reload_systemd().await?;

        Ok(())
    }

    /// Start service
    pub async fn start_service(&self, service_name: &str) -> Result<()> {
        info!("Starting systemd service: {}", service_name);

        let output = tokio::process::Command::new("systemctl")
            .arg("start")
            .arg(service_name)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to start service: {}", stderr);
        }

        Ok(())
    }

    /// Stop service
    pub async fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Stopping systemd service: {}", service_name);

        let output = tokio::process::Command::new("systemctl")
            .arg("stop")
            .arg(service_name)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to stop service: {}", stderr);
        }

        Ok(())
    }

    /// Enable service (start on boot)
    async fn enable_service(&self, service_name: &str) -> Result<()> {
        debug!("Enabling systemd service: {}", service_name);

        let output = tokio::process::Command::new("systemctl")
            .arg("enable")
            .arg(service_name)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to enable service: {}", stderr);
        }

        Ok(())
    }

    /// Disable service
    async fn disable_service(&self, service_name: &str) -> Result<()> {
        debug!("Disabling systemd service: {}", service_name);

        let output = tokio::process::Command::new("systemctl")
            .arg("disable")
            .arg(service_name)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to disable service: {}", stderr);
        }

        Ok(())
    }

    /// Reload systemd configuration
    async fn reload_systemd(&self) -> Result<()> {
        debug!("Reloading systemd daemon");

        let output = tokio::process::Command::new("systemctl")
            .arg("daemon-reload")
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to reload systemd: {}", stderr);
        }

        Ok(())
    }

    /// Check if service is running
    pub async fn is_running(&self, service_name: &str) -> Result<bool> {
        let output = tokio::process::Command::new("systemctl")
            .arg("is-active")
            .arg(service_name)
            .output()
            .await?;

        Ok(output.status.success())
    }

    /// Get unit file path
    fn get_unit_path(&self, service_name: &str) -> PathBuf {
        if self.system_mode {
            PathBuf::from(format!("/etc/systemd/system/{}.service", service_name))
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(format!(
                "{}/.config/systemd/user/{}.service",
                home, service_name
            ))
        }
    }

    /// Generate systemd unit file content
    fn generate_unit_file(&self, config: &ServiceConfig) -> Result<String> {
        let exec_path = config.executable_path.to_string_lossy();
        let args = config.arguments.join(" ");
        let exec_start = if args.is_empty() {
            exec_path.to_string()
        } else {
            format!("{} {}", exec_path, args)
        };

        let working_dir = config
            .working_dir
            .as_ref()
            .map(|p| format!("WorkingDirectory={}", p.display()))
            .unwrap_or_default();

        let unit = format!(
            r#"[Unit]
Description={}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=notify
ExecStart={}
{}
Restart=always
RestartSec=5
User=root

# Security hardening
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_RAW CAP_SYS_ADMIN
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=false
ReadWritePaths=/var/lib/tamandua /var/run/tamandua /var/log/tamandua

# Watchdog support
WatchdogSec=30s

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
"#,
            config.description, exec_start, working_dir
        );

        Ok(unit)
    }
}

/// Notify systemd of service status
pub async fn notify_ready() -> Result<()> {
    if std::env::var("NOTIFY_SOCKET").is_ok() {
        debug!("Notifying systemd: service ready");

        let output = tokio::process::Command::new("systemd-notify")
            .arg("--ready")
            .output()
            .await?;

        if !output.status.success() {
            warn!("Failed to notify systemd");
        }
    }

    Ok(())
}

/// Send watchdog keepalive to systemd
pub async fn notify_watchdog() -> Result<()> {
    if std::env::var("WATCHDOG_USEC").is_ok() {
        let output = tokio::process::Command::new("systemd-notify")
            .arg("WATCHDOG=1")
            .output()
            .await?;

        if !output.status.success() {
            warn!("Failed to send watchdog keepalive");
        }
    }

    Ok(())
}

/// Start watchdog task
pub fn start_watchdog_task() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        // Get watchdog interval from environment
        let interval = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|us| us / 2) // Notify at half the interval
            .unwrap_or(15_000_000); // Default: 15 seconds

        let duration = tokio::time::Duration::from_micros(interval);
        let mut interval = tokio::time::interval(duration);

        loop {
            interval.tick().await;
            if let Err(e) = notify_watchdog().await {
                warn!("Watchdog notification failed: {}", e);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_file_generation() {
        let manager = SystemdManager::new(true);
        let config = ServiceConfig::default();

        let unit = manager.generate_unit_file(&config);
        assert!(unit.is_ok());

        let content = unit.unwrap();
        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Service]"));
        assert!(content.contains("[Install]"));
        assert!(content.contains("Type=notify"));
    }

    #[test]
    fn test_unit_path() {
        let manager = SystemdManager::new(true);
        let path = manager.get_unit_path("tamandua-agent");
        assert_eq!(
            path,
            PathBuf::from("/etc/systemd/system/tamandua-agent.service")
        );
    }
}
