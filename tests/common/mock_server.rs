//! Mock WebSocket server for testing agent-server communication
//!
//! Provides a lightweight mock server that simulates Phoenix channels
//! for testing without requiring a full Elixir backend.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

/// Mock Phoenix channel message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PhoenixMessage {
    pub topic: String,
    pub event: String,
    pub payload: serde_json::Value,
    pub r#ref: Option<String>,
    pub join_ref: Option<String>,
}

/// Mock server configuration
#[derive(Debug, Clone)]
pub struct MockServerConfig {
    /// Auto-respond to heartbeats
    pub auto_heartbeat: bool,
    /// Auto-acknowledge telemetry
    pub auto_ack_telemetry: bool,
    /// Send config on join
    pub send_config_on_join: bool,
    /// Simulate network delays (milliseconds)
    pub network_delay_ms: u64,
}

impl Default for MockServerConfig {
    fn default() -> Self {
        Self {
            auto_heartbeat: true,
            auto_ack_telemetry: true,
            send_config_on_join: false,
            network_delay_ms: 0,
        }
    }
}

/// Mock WebSocket server for testing
pub struct MockServer {
    /// Server address
    addr: SocketAddr,
    /// Server configuration
    config: MockServerConfig,
    /// Received messages
    received: Arc<RwLock<Vec<PhoenixMessage>>>,
    /// Commands to send to clients
    commands_tx: mpsc::Sender<PhoenixMessage>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl MockServer {
    /// Create a new mock server
    pub async fn new(config: MockServerConfig) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let received = Arc::new(RwLock::new(Vec::new()));
        let (commands_tx, commands_rx) = mpsc::channel(100);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let server_config = config.clone();
        let server_received = received.clone();

        // Spawn server task
        tokio::spawn(async move {
            Self::run_server(
                listener,
                server_config,
                server_received,
                commands_rx,
                shutdown_rx,
            )
            .await;
        });

        info!(addr = %addr, "Mock server started");

        Ok(Self {
            addr,
            config,
            received,
            commands_tx,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Get server address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get WebSocket URL
    pub fn url(&self) -> String {
        format!("ws://{}/socket/agent/websocket", self.addr)
    }

    /// Send a command to connected clients
    pub async fn send_command(&self, command: PhoenixMessage) -> Result<()> {
        self.commands_tx.send(command).await?;
        Ok(())
    }

    /// Get all received messages
    pub async fn received_messages(&self) -> Vec<PhoenixMessage> {
        self.received.read().await.clone()
    }

    /// Get messages of a specific event type
    pub async fn get_messages(&self, event: &str) -> Vec<PhoenixMessage> {
        self.received
            .read()
            .await
            .iter()
            .filter(|msg| msg.event == event)
            .cloned()
            .collect()
    }

    /// Wait for a specific number of messages
    pub async fn wait_for_messages(&self, event: &str, count: usize, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        loop {
            let messages = self.get_messages(event).await;
            if messages.len() >= count {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Clear received messages
    pub async fn clear_messages(&self) {
        self.received.write().await.clear();
    }

    /// Shutdown the server
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    async fn run_server(
        listener: TcpListener,
        config: MockServerConfig,
        received: Arc<RwLock<Vec<PhoenixMessage>>>,
        mut commands_rx: mpsc::Receiver<PhoenixMessage>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            debug!(client = %addr, "Client connected");

                            let config = config.clone();
                            let received = received.clone();
                            let mut commands_rx = commands_rx.resubscribe();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_client(
                                    stream,
                                    config,
                                    received,
                                    &mut commands_rx,
                                )
                                .await
                                {
                                    warn!(error = %e, "Client handler error");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Server shutting down");
                    break;
                }
            }
        }
    }

    async fn handle_client(
        stream: tokio::net::TcpStream,
        config: MockServerConfig,
        received: Arc<RwLock<Vec<PhoenixMessage>>>,
        commands_rx: &mut mpsc::Receiver<PhoenixMessage>,
    ) -> Result<()> {
        let ws_stream = accept_async(stream).await?;
        let (mut write, mut read) = ws_stream.split();

        // Track joined channels
        let mut joined_channels: HashMap<String, String> = HashMap::new();

        loop {
            tokio::select! {
                msg_result = read.next() => {
                    match msg_result {
                        Some(Ok(Message::Text(text))) => {
                            // Simulate network delay
                            if config.network_delay_ms > 0 {
                                tokio::time::sleep(
                                    std::time::Duration::from_millis(config.network_delay_ms)
                                ).await;
                            }

                            if let Ok(msg) = serde_json::from_str::<PhoenixMessage>(&text) {
                                debug!(event = %msg.event, topic = %msg.topic, "Received message");

                                // Store message
                                received.write().await.push(msg.clone());

                                // Handle special messages
                                match msg.event.as_str() {
                                    "phx_join" => {
                                        // Send join reply
                                        let join_ref = msg.r#ref.clone().unwrap_or_default();
                                        joined_channels.insert(msg.topic.clone(), join_ref.clone());

                                        let reply = json!({
                                            "topic": msg.topic,
                                            "event": "phx_reply",
                                            "payload": {
                                                "status": "ok",
                                                "response": {}
                                            },
                                            "ref": msg.r#ref,
                                            "join_ref": join_ref
                                        });

                                        write.send(Message::Text(reply.to_string())).await?;

                                        // Send config if enabled
                                        if config.send_config_on_join {
                                            let config_msg = json!({
                                                "topic": msg.topic,
                                                "event": "config_update",
                                                "payload": {
                                                    "config": {
                                                        "batch_size": 50,
                                                        "heartbeat_interval_seconds": 30
                                                    },
                                                    "yara_rules": [],
                                                    "sigma_rules": [],
                                                    "iocs": []
                                                },
                                                "ref": null,
                                                "join_ref": join_ref
                                            });

                                            write.send(Message::Text(config_msg.to_string())).await?;
                                        }
                                    }
                                    "heartbeat" => {
                                        if config.auto_heartbeat {
                                            let ack = json!({
                                                "topic": msg.topic,
                                                "event": "heartbeat_ack",
                                                "payload": {
                                                    "server_time": std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_millis() as u64
                                                },
                                                "ref": msg.r#ref,
                                                "join_ref": msg.join_ref
                                            });

                                            write.send(Message::Text(ack.to_string())).await?;
                                        }
                                    }
                                    "telemetry" => {
                                        if config.auto_ack_telemetry {
                                            // Extract seq and event count
                                            let seq = msg.payload.get("seq")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0);
                                            let events = msg.payload.get("events")
                                                .and_then(|v| v.as_array())
                                                .map(|arr| arr.len())
                                                .unwrap_or(0);

                                            let ack = json!({
                                                "topic": msg.topic,
                                                "event": "telemetry:ack",
                                                "payload": {
                                                    "seq": seq,
                                                    "count": events
                                                },
                                                "ref": null,
                                                "join_ref": msg.join_ref
                                            });

                                            write.send(Message::Text(ack.to_string())).await?;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            debug!("Client closed connection");
                            break;
                        }
                        Some(Ok(Message::Ping(data))) => {
                            write.send(Message::Pong(data)).await?;
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "WebSocket error");
                            break;
                        }
                        None => {
                            debug!("Client disconnected");
                            break;
                        }
                        _ => {}
                    }
                }
                cmd = commands_rx.recv() => {
                    if let Some(command) = cmd {
                        let msg = serde_json::to_string(&command)?;
                        write.send(Message::Text(msg)).await?;
                    }
                }
            }
        }

        Ok(())
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_starts() {
        let server = MockServer::new(MockServerConfig::default()).await.unwrap();
        assert!(server.addr().port() > 0);
    }

    #[tokio::test]
    async fn test_mock_server_accepts_connections() {
        let server = MockServer::new(MockServerConfig::default()).await.unwrap();

        // Try to connect
        let url = server.url();
        let result = tokio_tungstenite::connect_async(&url).await;

        assert!(result.is_ok());
    }
}
