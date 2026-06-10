//! IPC client implementation
//!
//! Runs in the unprivileged GUI and connects to the service.

// IPC client. Notification/response channels are scaffolded for upcoming
// streaming-update paths.
#![allow(dead_code, unused_variables)]

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::{IpcMessage, MessageFrame};

#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

#[cfg(unix)]
use tokio::net::UnixStream;

/// IPC client for GUI-to-service communication
pub struct IpcClient {
    #[cfg(windows)]
    stream: Arc<tokio::sync::Mutex<tokio::net::windows::named_pipe::NamedPipeClient>>,

    #[cfg(unix)]
    stream: Arc<tokio::sync::Mutex<UnixStream>>,

    response_rx: Arc<RwLock<Option<mpsc::Receiver<IpcMessage>>>>,
    notification_tx: mpsc::Sender<IpcMessage>,
}

impl IpcClient {
    /// Connect to the IPC server
    pub async fn connect() -> Result<Self> {
        #[cfg(windows)]
        let stream = Self::connect_windows().await?;

        #[cfg(unix)]
        let stream = Self::connect_unix().await?;

        let (notification_tx, _notification_rx) = mpsc::channel(100);

        Ok(Self {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            response_rx: Arc::new(RwLock::new(None)),
            notification_tx,
        })
    }

    /// Connect to Windows named pipe
    #[cfg(windows)]
    async fn connect_windows() -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use super::PIPE_NAME;
        use std::time::Duration;

        debug!("Connecting to IPC server at {}", PIPE_NAME);

        // Retry connection with exponential backoff
        let mut retries = 0;
        let max_retries = 5;

        loop {
            match ClientOptions::new().open(PIPE_NAME) {
                Ok(client) => {
                    info!("Connected to IPC server");
                    return Ok(client);
                }
                Err(e) if retries < max_retries => {
                    let delay = Duration::from_millis(100 * (1 << retries));
                    warn!(
                        "Failed to connect to IPC server (attempt {}/{}): {}. Retrying in {:?}...",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    retries += 1;
                }
                Err(e) => {
                    bail!(
                        "Failed to connect to IPC server after {} attempts: {}",
                        max_retries,
                        e
                    );
                }
            }
        }
    }

    /// Connect to Unix domain socket
    #[cfg(unix)]
    async fn connect_unix() -> Result<UnixStream> {
        use super::SOCKET_PATH;
        use std::time::Duration;

        debug!("Connecting to IPC server at {}", SOCKET_PATH);

        let mut retries = 0;
        let max_retries = 5;

        loop {
            match UnixStream::connect(SOCKET_PATH).await {
                Ok(stream) => {
                    info!("Connected to IPC server");
                    return Ok(stream);
                }
                Err(e) if retries < max_retries => {
                    let delay = Duration::from_millis(100 * (1 << retries));
                    warn!(
                        "Failed to connect to IPC server (attempt {}/{}): {}. Retrying in {:?}...",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    retries += 1;
                }
                Err(e) => {
                    bail!(
                        "Failed to connect to IPC server after {} attempts: {}",
                        max_retries,
                        e
                    );
                }
            }
        }
    }

    /// Send a message and wait for response
    pub async fn request(&self, message: IpcMessage) -> Result<IpcMessage> {
        let mut stream = self.stream.lock().await;

        // Send request
        MessageFrame::write(&mut *stream, &message)
            .await
            .context("Failed to send IPC request")?;

        // Read response
        let response = MessageFrame::read(&mut *stream)
            .await
            .context("Failed to read IPC response")?;

        Ok(response)
    }

    /// Send a message without waiting for response (fire-and-forget)
    pub async fn send(&self, message: IpcMessage) -> Result<()> {
        let mut stream = self.stream.lock().await;
        MessageFrame::write(&mut *stream, &message)
            .await
            .context("Failed to send IPC message")?;
        Ok(())
    }

    /// Start listening for server notifications
    pub fn start_notification_listener(self: Arc<Self>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            loop {
                let message = {
                    let mut stream = self.stream.lock().await;
                    match MessageFrame::read(&mut *stream).await {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("Failed to read notification: {}", e);
                            break;
                        }
                    }
                };

                // Handle server-initiated messages
                if message.is_response() {
                    if let Err(e) = self.notification_tx.send(message).await {
                        warn!("Failed to forward notification: {}", e);
                    }
                } else {
                    warn!("Received unexpected request from server: {:?}", message);
                }
            }

            Ok(())
        })
    }

    /// Subscribe to server notifications
    pub async fn subscribe_notifications(&self) -> mpsc::Receiver<IpcMessage> {
        let (tx, rx) = mpsc::channel(100);

        // Clone the notification_tx to forward messages
        let notification_tx = self.notification_tx.clone();

        tokio::spawn(async move {
            // This is a simplified implementation
            // In production, use a proper pub/sub mechanism
        });

        rx
    }

    // ==================== Convenience methods ====================

    /// Get agent status
    pub async fn get_status(&self) -> Result<super::AgentStatus> {
        let response = self.request(IpcMessage::GetStatus).await?;
        match response {
            IpcMessage::StatusUpdate(status) => Ok(status),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get agent metrics
    pub async fn get_metrics(&self) -> Result<super::AgentMetrics> {
        let response = self.request(IpcMessage::GetMetrics).await?;
        match response {
            IpcMessage::MetricsUpdate(metrics) => Ok(metrics),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get alerts
    pub async fn get_alerts(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<super::AlertNotification>> {
        let response = self.request(IpcMessage::GetAlerts { since, limit }).await?;
        match response {
            IpcMessage::Alerts(alerts) => Ok(alerts),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get logs
    pub async fn get_logs(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        level: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<super::LogEntry>> {
        let response = self
            .request(IpcMessage::GetLogs {
                since,
                level,
                limit,
            })
            .await?;
        match response {
            IpcMessage::LogEntries(logs) => Ok(logs),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Start scan
    pub async fn start_scan(
        &self,
        path: std::path::PathBuf,
        recursive: bool,
        scan_archives: bool,
    ) -> Result<()> {
        let response = self
            .request(IpcMessage::StartScan {
                path,
                recursive,
                scan_archives,
            })
            .await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get version info
    pub async fn get_version(&self) -> Result<super::VersionInfo> {
        let response = self.request(IpcMessage::GetVersion).await?;
        match response {
            IpcMessage::VersionInfo(info) => Ok(info),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Update configuration
    pub async fn update_config(&self, config: super::AgentConfigUpdate) -> Result<()> {
        let response = self.request(IpcMessage::UpdateConfig { config }).await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Kill process
    pub async fn kill_process(&self, pid: u32) -> Result<()> {
        let response = self.request(IpcMessage::KillProcess { pid }).await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get quarantined files
    pub async fn get_quarantined_files(&self) -> Result<Vec<super::QuarantineEntry>> {
        let response = self.request(IpcMessage::GetQuarantinedFiles).await?;
        match response {
            IpcMessage::QuarantinedFiles(files) => Ok(files),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Test backend connection
    pub async fn test_backend_connection(&self) -> Result<(bool, Option<u64>)> {
        let response = self.request(IpcMessage::TestBackendConnection).await?;
        match response {
            IpcMessage::BackendTestResult {
                connected,
                latency_ms,
                ..
            } => Ok((connected, latency_ms)),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require the IPC server to be running
    // In production, use integration tests with a test server

    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_client_connection() {
        let client = IpcClient::connect().await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_status() {
        let client = IpcClient::connect().await.unwrap();
        let status = client.get_status().await;
        assert!(status.is_ok());
    }
}
