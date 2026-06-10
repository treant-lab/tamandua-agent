# Tamandua Agent Transport Layer

This directory contains the transport layer implementation for the Tamandua EDR Agent, which handles communication with the backend server.

## Architecture

The transport layer uses a **Sans-IO architecture** that separates protocol logic from I/O operations.

```
├── sans_io.rs          # Core protocol state machine (pure, no I/O)
├── state_machine.rs    # State transitions with validation
├── codec.rs            # Message encoding/decoding
├── event_loop.rs       # Tokio-based I/O layer
├── cert_pinning.rs     # Certificate pinning for security
├── proxy.rs            # Proxy support
├── siem.rs             # SIEM integration
├── token_manager.rs    # Authentication token management
└── tests/              # Comprehensive test suite
    ├── mod.rs
    └── sans_io_tests.rs
```

## Quick Start

### Using the Event Loop (Recommended)

```rust
use tamandua_agent::transport::event_loop::{EventLoop, EventLoopConfig};

let config = EventLoopConfig::default();
let (event_loop, handle) = EventLoop::new(config);

// Spawn event loop
tokio::spawn(event_loop.run());

// Send telemetry
handle.send_telemetry(event).await?;

// Receive commands
let command = handle.receive_command().await;
```

### Using the Protocol Directly (Testing/Advanced)

```rust
use tamandua_agent::transport::sans_io::{AgentProtocol, ProtocolConfig};

let mut protocol = AgentProtocol::new(ProtocolConfig::default());

// Connect
protocol.handle_connected(Instant::now());

// Send telemetry
protocol.send_telemetry(event, Instant::now())?;

// Poll for transmits
while let Some(tx) = protocol.poll_transmit() {
    // Send tx.payload to network
}

// Poll for events
while let Some(event) = protocol.poll_event() {
    // Handle event
}
```

## Key Features

### 1. Sans-IO Architecture
- Protocol logic separated from I/O
- Deterministic testing with controlled time
- Portable across async runtimes

### 2. Reliable Delivery
- Automatic batching (configurable size/timeout)
- ACK tracking with retry logic
- Exponential backoff for retries
- Queue persistence for offline operation

### 3. Backpressure Handling
- Automatic detection when in-flight limit reached
- Signals to slow down event generation
- Prevents memory exhaustion

### 4. Connection Management
- Automatic reconnection with exponential backoff
- Heartbeat mechanism for keepalive
- Timeout detection and recovery

### 5. Message Encoding
- JSON (default)
- MessagePack (efficient binary)
- Protocol Buffers (planned)
- Optional zstd compression

## Protocol Events

The protocol emits events that the application handles:

```rust
pub enum ProtocolEvent {
    Connected,
    Disconnected { reason: DisconnectReason },
    CommandReceived(Command),
    ConfigUpdated(AgentConfig),
    RulesUpdated(RulesUpdate),
    HeartbeatRequired,
    ReconnectRequired { delay: Duration },
    TelemetryAcknowledged { sequence: u64, count: usize },
    MlScanResult(MlScanResult),
    BackpressureApplied { queue_size: usize },
    BackpressureReleased,
}
```

## Configuration

### Protocol Config

```rust
let config = ProtocolConfig {
    agent_id: "my-agent".to_string(),
    heartbeat_interval: Duration::from_secs(30),
    heartbeat_timeout: Duration::from_secs(120),
    batch_size: 100,
    batch_timeout: Duration::from_secs(5),
    ack_timeout: Duration::from_secs(10),
    max_retries: 3,
    reconnect_delay_base: Duration::from_secs(1),
    reconnect_delay_max: Duration::from_secs(60),
    max_reconnect_attempts: 0, // Infinite
};
```

### Event Loop Config

```rust
let config = EventLoopConfig {
    server_url: "wss://server.example.com/agent".to_string(),
    agent_config: load_config()?,
    protocol_config: ProtocolConfig::default(),
    channel_buffer_size: 1000,
    auto_reconnect: true,
    connection_timeout: Duration::from_secs(30),
    read_timeout: Duration::from_secs(60),
    write_timeout: Duration::from_secs(10),
};
```

## Testing

### Run Tests

```bash
# All transport tests
cargo test -p tamandua-agent transport

# Sans-IO tests only
cargo test -p tamandua-agent sans_io_tests

# State machine tests
cargo test -p tamandua-agent state_machine

# Codec tests
cargo test -p tamandua-agent codec
```

### Test with Controlled Time

```rust
#[test]
fn test_timeout() {
    let mut protocol = AgentProtocol::new(config);
    let mut time = TimeController::new();

    protocol.handle_connected(time.now());

    // Advance time
    time.advance(Duration::from_secs(120));
    protocol.handle_timeout(time.now());

    // Verify behavior
    assert!(!protocol.state().is_connected());
}
```

### Test with Network Simulation

```rust
#[test]
fn test_packet_loss() {
    let mut net = NetworkSimulator::new()
        .with_packet_loss(0.1);

    // Simulate packet loss
    if !net.should_drop_packet() {
        protocol.handle_input(data, now)?;
    }

    // Verify retry behavior
    assert!(protocol.stats().events_retried > 0);
}
```

## Monitoring

### Get Statistics

```rust
let stats = protocol.stats();

println!("Sent: {}", stats.events_sent);
println!("Acked: {}", stats.events_acked);
println!("Retried: {}", stats.events_retried);
println!("Dropped: {}", stats.events_dropped);
println!("In-flight: {}", stats.in_flight_batches);
println!("Queued: {}", stats.queue_size);
```

### Health Check

```rust
fn is_healthy(protocol: &AgentProtocol) -> bool {
    let stats = protocol.stats();

    protocol.state().is_connected() &&
    stats.events_dropped == 0 &&
    stats.queue_size < 5000 &&
    stats.in_flight_batches < 50
}
```

## Wire Format

Messages use a length-prefixed frame format:

```
+--------+--------+------------------+
| Length | Format |     Payload      |
| 4 bytes| 1 byte |   N bytes        |
+--------+--------+------------------+
```

- **Length**: u32 big-endian (frame size excluding length field)
- **Format**: u8 (0=JSON, 1=MessagePack, 2=Protobuf)
  - Bit 7: Compression flag (1=compressed)
  - Bits 0-6: Format ID
- **Payload**: Encoded message data

## Performance

| Metric | Value |
|--------|-------|
| Memory overhead | ~15 MB (max) |
| CPU overhead | < 1% |
| Encoding latency | ~100 μs per batch |
| Decoding latency | ~50 μs per message |
| State transition | ~1 μs |

## Security Features

### Certificate Pinning
```rust
let pins = CertPins::from_base64(&pin_hashes, true)?;
// Automatic verification during TLS handshake
```

### Proxy Support
```rust
let proxy = ProxyConfig::from_url("http://proxy:8080")?;
// Automatic tunneling
```

### Token Management
```rust
let token_mgr = TokenManager::new(token, refresh_url);
// Automatic token refresh
```

## Troubleshooting

### Events Not Sending

```rust
// Check connection
if !protocol.state().is_connected() {
    warn!("Not connected");
}

// Check queue
if protocol.stats().queue_size > 5000 {
    warn!("Queue full");
}
```

### High Drop Rate

```rust
let stats = protocol.stats();
let drop_rate = stats.events_dropped as f64 / stats.events_sent as f64;

if drop_rate > 0.01 {
    error!("High drop rate: {:.2}%", drop_rate * 100.0);
}
```

### Connection Timeout

```rust
// Increase timeout
let mut config = ProtocolConfig::default();
config.heartbeat_timeout = Duration::from_secs(180);
```

## Documentation

- [SANS_IO_ARCHITECTURE.md](../../../../docs/apps/tamandua_agent/SANS_IO_ARCHITECTURE.md) - Detailed architecture
- [SANS_IO_QUICKSTART.md](../../../../docs/apps/tamandua_agent/SANS_IO_QUICKSTART.md) - Quick start guide
- [SANS_IO_IMPLEMENTATION_SUMMARY.md](../../../../docs/apps/tamandua_agent/SANS_IO_IMPLEMENTATION_SUMMARY.md) - Implementation details

## References

- [Firezone Sans-IO Blog](https://www.firezone.dev/blog/sans-io)
- [Sans-IO Design Pattern](https://sans-io.readthedocs.io/)
- [RFC 6455 - WebSocket Protocol](https://tools.ietf.org/html/rfc6455)

---

For questions or contributions, see the main Tamandua repository.
