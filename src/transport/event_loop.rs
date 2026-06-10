//! Event Loop - I/O Layer for Sans-IO Protocol
//!
//! This module provides the Tokio-based event loop that drives the sans-IO
//! protocol implementation. It handles:
//!
//! - WebSocket I/O (sending and receiving)
//! - Timer management
//! - Backpressure and flow control
//! - Connection lifecycle
//!
//! The event loop is the only part of the transport layer that performs actual I/O.
//! All protocol logic is handled by the sans-IO core (`AgentProtocol`).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │              Application                        │
//! │    (Collectors, Response Handlers)              │
//! └─────────────┬─────────────────────┬─────────────┘
//!               │                     │
//!               │ events              │ telemetry
//!               v                     v
//! ┌─────────────────────────────────────────────────┐
//! │           EventLoop (I/O Layer)                 │
//! │                                                 │
//! │  ┌──────────────────────────────────────────┐  │
//! │  │     Sans-IO Protocol (AgentProtocol)     │  │
//! │  │                                          │  │
//! │  │  • State machine                        │  │
//! │  │  • Message codec                        │  │
//! │  │  • Timeout tracking                     │  │
//! │  └──────────────────────────────────────────┘  │
//! │                                                 │
//! │  ┌──────────────┐    ┌─────────────────────┐  │
//! │  │   Timers     │    │   WebSocket I/O     │  │
//! │  │  (Tokio)     │    │   (tungstenite)     │  │
//! │  └──────────────┘    └─────────────────────┘  │
//! └─────────────────────────────────────────────────┘
//! ```

use crate::collectors::TelemetryEvent;
use crate::config::AgentConfig;
use crate::transport::sans_io::{
    AgentProtocol, DisconnectReason, ProtocolConfig, ProtocolEvent, TransmitDestination,
};
use crate::transport::{Command, CommandResult};
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, trace, warn};

/// Event loop configuration
#[derive(Debug, Clone)]
pub struct EventLoopConfig {
    /// WebSocket URL
    pub server_url: String,

    /// Agent configuration
    pub agent_config: AgentConfig,

    /// Protocol configuration
    pub protocol_config: ProtocolConfig,

    /// Channel buffer sizes
    pub channel_buffer_size: usize,

    /// Reconnect on error
    pub auto_reconnect: bool,

    /// Connection timeout
    pub connection_timeout: Duration,

    /// Read timeout
    pub read_timeout: Duration,

    /// Write timeout
    pub write_timeout: Duration,
}

impl Default for EventLoopConfig {
    fn default() -> Self {
        Self {
            server_url: "ws://localhost:4000/socket/agent".to_string(),
            agent_config: AgentConfig::default(),
            protocol_config: ProtocolConfig::default(),
            channel_buffer_size: 1000,
            auto_reconnect: true,
            connection_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(10),
        }
    }
}

/// Event loop handle for external communication
#[derive(Clone)]
pub struct EventLoopHandle {
    /// Send telemetry events
    telemetry_tx: mpsc::Sender<TelemetryEvent>,

    /// Send command responses
    response_tx: mpsc::Sender<(String, CommandResult)>,

    /// Receive commands
    command_rx: Arc<RwLock<mpsc::Receiver<Command>>>,

    /// Receive protocol events
    event_rx: Arc<RwLock<mpsc::Receiver<ProtocolEvent>>>,

    /// Shutdown signal
    shutdown_tx: mpsc::Sender<()>,
}

impl EventLoopHandle {
    /// Send a telemetry event
    pub async fn send_telemetry(&self, event: TelemetryEvent) -> Result<()> {
        self.telemetry_tx
            .send(event)
            .await
            .map_err(|_| anyhow::anyhow!("Event loop closed"))?;
        Ok(())
    }

    /// Send a command response
    pub async fn send_command_response(
        &self,
        command_id: String,
        result: CommandResult,
    ) -> Result<()> {
        self.response_tx
            .send((command_id, result))
            .await
            .map_err(|_| anyhow::anyhow!("Event loop closed"))?;
        Ok(())
    }

    /// Receive next command
    pub async fn receive_command(&self) -> Option<Command> {
        let mut rx = self.command_rx.write().await;
        rx.recv().await
    }

    /// Receive next protocol event
    pub async fn receive_event(&self) -> Option<ProtocolEvent> {
        let mut rx = self.event_rx.write().await;
        rx.recv().await
    }

    /// Try to receive a command without blocking
    pub async fn try_receive_command(&self) -> Option<Command> {
        let mut rx = self.command_rx.write().await;
        rx.try_recv().ok()
    }

    /// Try to receive a protocol event without blocking
    pub async fn try_receive_event(&self) -> Option<ProtocolEvent> {
        let mut rx = self.event_rx.write().await;
        rx.try_recv().ok()
    }

    /// Shutdown the event loop
    pub async fn shutdown(&self) -> Result<()> {
        self.shutdown_tx
            .send(())
            .await
            .map_err(|_| anyhow::anyhow!("Event loop already shut down"))?;
        Ok(())
    }
}

/// Event loop for driving the sans-IO protocol
pub struct EventLoop {
    /// Configuration
    config: EventLoopConfig,

    /// Protocol state machine
    protocol: AgentProtocol,

    /// Channels for communication
    telemetry_rx: mpsc::Receiver<TelemetryEvent>,
    response_rx: mpsc::Receiver<(String, CommandResult)>,
    command_tx: mpsc::Sender<Command>,
    event_tx: mpsc::Sender<ProtocolEvent>,
    shutdown_rx: mpsc::Receiver<()>,
}

impl EventLoop {
    /// Create a new event loop
    pub fn new(config: EventLoopConfig) -> (Self, EventLoopHandle) {
        let (telemetry_tx, telemetry_rx) = mpsc::channel(config.channel_buffer_size);
        let (response_tx, response_rx) = mpsc::channel(config.channel_buffer_size);
        let (command_tx, command_rx) = mpsc::channel(config.channel_buffer_size);
        let (event_tx, event_rx) = mpsc::channel(config.channel_buffer_size);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let protocol = AgentProtocol::new(config.protocol_config.clone());

        let event_loop = Self {
            config: config.clone(),
            protocol,
            telemetry_rx,
            response_rx,
            command_tx,
            event_tx,
            shutdown_rx,
        };

        let handle = EventLoopHandle {
            telemetry_tx,
            response_tx,
            command_rx: Arc::new(RwLock::new(command_rx)),
            event_rx: Arc::new(RwLock::new(event_rx)),
            shutdown_tx,
        };

        (event_loop, handle)
    }

    /// Run the event loop
    pub async fn run(mut self) -> Result<()> {
        info!("Starting event loop");

        loop {
            // Try to connect
            match self.connect_and_run().await {
                Ok(()) => {
                    info!("Event loop completed successfully");
                    break;
                }
                Err(e) => {
                    error!("Event loop error: {}", e);

                    if !self.config.auto_reconnect {
                        return Err(e);
                    }

                    // Calculate reconnect delay
                    let delay = Duration::from_secs(5);
                    warn!("Reconnecting in {:?}", delay);
                    sleep(delay).await;
                }
            }
        }

        Ok(())
    }

    async fn connect_and_run(&mut self) -> Result<()> {
        info!("Connecting to {}", self.config.server_url);

        // Connect with timeout
        let ws_stream = timeout(
            self.config.connection_timeout,
            connect_async(&self.config.server_url),
        )
        .await??
        .0;

        info!("WebSocket connected");

        let now = Instant::now();
        self.protocol.handle_connected(now);

        // Split stream
        let (mut write, mut read) = ws_stream.split();

        // Process initial events (Connected event)
        self.process_protocol_events().await?;

        // Main event loop
        let mut timer_interval = interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                // Shutdown signal
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown requested");
                    self.protocol.handle_disconnected(DisconnectReason::Clean, Instant::now());
                    break;
                }

                // Timer tick
                _ = timer_interval.tick() => {
                    let now = Instant::now();

                    // Check for timeouts
                    if let Some(deadline) = self.protocol.poll_timeout() {
                        if now >= deadline {
                            self.protocol.handle_timeout(now);
                        }
                    }

                    // Process events
                    self.process_protocol_events().await?;

                    // Process transmits
                    self.process_transmits(&mut write).await?;
                }

                // Incoming telemetry
                Some(event) = self.telemetry_rx.recv() => {
                    let now = Instant::now();
                    if let Err(e) = self.protocol.send_telemetry(event, now) {
                        warn!("Failed to queue telemetry: {}", e);
                    }
                }

                // Command response
                Some((command_id, result)) = self.response_rx.recv() => {
                    let now = Instant::now();
                    if let Err(e) = self.protocol.send_command_response(command_id, result, now) {
                        warn!("Failed to send command response: {}", e);
                    }
                }

                // WebSocket messages
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            let now = Instant::now();
                            if let Err(e) = self.protocol.handle_input(&data, now) {
                                error!("Failed to handle input: {}", e);
                                self.protocol.handle_disconnected(
                                    DisconnectReason::ProtocolError(e.to_string()),
                                    now
                                );
                                break;
                            }
                        }

                        Some(Ok(Message::Text(text))) => {
                            // Handle text as binary (UTF-8 encoded)
                            let now = Instant::now();
                            if let Err(e) = self.protocol.handle_input(text.as_bytes(), now) {
                                error!("Failed to handle input: {}", e);
                                self.protocol.handle_disconnected(
                                    DisconnectReason::ProtocolError(e.to_string()),
                                    now
                                );
                                break;
                            }
                        }

                        Some(Ok(Message::Close(_))) => {
                            info!("Server closed connection");
                            self.protocol.handle_disconnected(
                                DisconnectReason::ServerClosed,
                                Instant::now()
                            );
                            break;
                        }

                        Some(Ok(Message::Ping(data))) => {
                            // Respond with pong
                            if let Err(e) = write.send(Message::Pong(data)).await {
                                error!("Failed to send pong: {}", e);
                                break;
                            }
                        }

                        Some(Err(e)) => {
                            error!("WebSocket error: {}", e);
                            self.protocol.handle_disconnected(
                                DisconnectReason::NetworkError(e.to_string()),
                                Instant::now()
                            );
                            break;
                        }

                        None => {
                            info!("WebSocket stream ended");
                            self.protocol.handle_disconnected(
                                DisconnectReason::ServerClosed,
                                Instant::now()
                            );
                            break;
                        }

                        _ => {}
                    }

                    // Process events after handling input
                    self.process_protocol_events().await?;
                }
            }
        }

        // Final cleanup
        self.process_protocol_events().await?;

        Ok(())
    }

    async fn process_protocol_events(&mut self) -> Result<()> {
        while let Some(event) = self.protocol.poll_event() {
            match &event {
                ProtocolEvent::Connected => {
                    debug!("Protocol connected");
                    self.event_tx.send(event.clone()).await?;
                }

                ProtocolEvent::Disconnected { reason } => {
                    debug!("Protocol disconnected: {:?}", reason);
                    self.event_tx.send(event.clone()).await?;
                }

                ProtocolEvent::CommandReceived(command) => {
                    debug!("Command received: {}", command.command_id);
                    self.command_tx.send(command.clone()).await?;
                }

                ProtocolEvent::HeartbeatRequired => {
                    trace!("Sending heartbeat");
                    let now = Instant::now();
                    self.protocol.send_heartbeat(now)?;
                }

                other => {
                    // Forward to application
                    self.event_tx.send(other.clone()).await?;
                }
            }
        }

        Ok(())
    }

    async fn process_transmits<S>(&mut self, write: &mut S) -> Result<()>
    where
        S: SinkExt<Message> + Unpin,
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        while let Some(transmit) = self.protocol.poll_transmit() {
            match transmit.destination {
                TransmitDestination::Server => {
                    trace!(size = transmit.payload.len(), "Sending to server");

                    // Send with timeout
                    match timeout(
                        self.config.write_timeout,
                        write.send(Message::Binary(transmit.payload)),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            error!("Failed to send message: {}", e);
                            return Err(e.into());
                        }
                        Err(_) => {
                            error!("Write timeout");
                            return Err(anyhow::anyhow!("Write timeout"));
                        }
                    }
                }

                TransmitDestination::Driver => {
                    // Send to kernel driver (not implemented)
                    warn!("Driver destination not implemented");
                }

                TransmitDestination::LocalProcess(pid) => {
                    // Send to local process via IPC (not implemented)
                    warn!("Local process destination not implemented: {}", pid);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_loop_creation() {
        let config = EventLoopConfig::default();
        let (_event_loop, handle) = EventLoop::new(config);

        // Should be able to shutdown
        assert!(handle.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_handle_channels() {
        let config = EventLoopConfig::default();
        let (_event_loop, handle) = EventLoop::new(config);

        // Should be able to send telemetry
        let event = TelemetryEvent {
            event_id: "test".to_string(),
            event_type: crate::collectors::EventType::ProcessCreate,
            timestamp: 0,
            severity: crate::collectors::Severity::Info,
            payload: crate::collectors::EventPayload::Process(crate::collectors::ProcessEvent {
                pid: 1234,
                ppid: 1,
                name: "test".to_string(),
                path: "/bin/test".to_string(),
                cmdline: "test".to_string(),
                user: "user".to_string(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
            detections: vec![],
            metadata: Default::default(),
        };

        assert!(handle.send_telemetry(event).await.is_ok());
    }
}
