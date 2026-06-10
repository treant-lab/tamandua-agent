# Tamandua Agent Test Suite

Comprehensive test suite for the Tamandua EDR Agent with 80%+ code coverage target.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── collectors/         # Collector tests (process, file, network, etc.)
│   ├── response/           # Response action tests
│   ├── transport/          # WebSocket communication tests
│   ├── config/             # Configuration management tests
│   └── analyzers/          # Analysis engine tests (YARA, entropy, etc.)
├── integration/            # End-to-end integration tests
│   ├── server_connection.rs
│   ├── telemetry.rs
│   ├── commands.rs
│   └── collectors.rs
├── common/                 # Shared test utilities
│   ├── mock_server.rs     # Mock Phoenix WebSocket server
│   ├── test_data.rs       # Test data generators
│   └── helpers.rs         # Test helper functions
└── README.md              # This file

benches/                    # Performance benchmarks
├── collectors.rs          # Collector performance benchmarks
├── event_processing.rs    # Event processing benchmarks
└── network_performance.rs # Network throughput benchmarks
```

## Running Tests

### All Tests

```bash
# Run all tests (unit + integration)
cargo test

# Run with output
cargo test -- --nocapture

# Run with specific log level
RUST_LOG=debug cargo test -- --nocapture
```

### Unit Tests Only

```bash
# All unit tests
cargo test --lib

# Specific module
cargo test --lib collectors::process

# Specific test
cargo test --lib test_enumerate_processes
```

### Integration Tests

```bash
# All integration tests
cargo test --test integration

# Specific integration test file
cargo test --test integration::server_connection

# With mock server
cargo test --test integration -- --nocapture
```

### Platform-Specific Tests

```bash
# Windows-only tests
cargo test --lib collectors::registry
cargo test --lib collectors::etw

# Linux-only tests
cargo test --lib collectors::ebpf

# macOS-only tests
cargo test --lib collectors::endpoint_security
```

### Tests Requiring Elevated Privileges

```bash
# Windows (Administrator)
cargo test --lib -- --ignored

# Linux/macOS (root)
sudo -E cargo test --lib -- --ignored
```

### Tests Requiring Running Server

```bash
# Set server URL environment variable
export TAMANDUA_TEST_SERVER=ws://localhost:4000/socket/agent
cargo test --test integration -- --ignored

# Or
RUN_INTEGRATION_TESTS=1 cargo test --test integration -- --ignored
```

## Benchmarks

```bash
# Run all benchmarks
cargo bench

# Specific benchmark
cargo bench collectors

# Generate HTML report
cargo bench --bench collectors -- --save-baseline main

# Compare with baseline
cargo bench --bench collectors -- --baseline main
```

## Test Categories

### Unit Tests

#### Collectors (tests/unit/collectors/)

- **process.rs** - Process collector tests
  - Process enumeration
  - PID tracking
  - Parent-child relationships
  - Process metrics (CPU, memory)
  - Code signing verification
  - Elevation detection
  - Environment variable capture

- **file.rs** - File collector tests
  - File monitoring (create, modify, delete, rename)
  - SHA256 hashing
  - Entropy calculation
  - File type detection
  - Path filtering

- **network.rs** - Network collector tests
  - Connection enumeration
  - TCP/UDP protocol detection
  - Connection state tracking
  - Byte counting
  - IP address validation

- **dns.rs** - DNS collector tests
  - DNS query capture
  - Response parsing
  - Query type detection
  - Domain filtering

- **registry.rs** (Windows) - Registry collector tests
  - Registry monitoring
  - Value type detection
  - Key path parsing

- **etw.rs** (Windows) - ETW collector tests
  - ETW provider subscription
  - Event parsing
  - Event filtering

- **ebpf.rs** (Linux) - eBPF collector tests
  - eBPF program loading
  - Event capture
  - Ring buffer handling

- **endpoint_security.rs** (macOS) - Endpoint Security tests
  - ES client initialization
  - Event subscription
  - Event filtering

#### Response Actions (tests/unit/response/)

- **kill_process.rs** - Process termination tests
  - PID validation
  - Graceful vs forceful termination
  - Permission checks
  - Process existence verification

- **quarantine.rs** - File quarantine tests
  - File isolation
  - Quarantine directory creation
  - File restoration
  - Permission preservation

- **network_isolation.rs** - Network isolation tests
  - Windows WFP isolation
  - Linux iptables/nftables isolation
  - macOS PF isolation
  - Isolation status tracking

- **live_response.rs** - Live response tests
  - Process listing
  - Memory dumping
  - File collection
  - Registry queries
  - Network connections

- **vss_rollback.rs** (Windows) - VSS rollback tests
  - Snapshot creation
  - File restoration
  - Ransomware remediation
  - Snapshot scheduling

### Integration Tests (tests/integration/)

- **server_connection.rs** - Server connection tests
  - WebSocket connection
  - Phoenix channel join
  - Heartbeat handling
  - Reconnection logic
  - TLS/mTLS

- **telemetry.rs** - Telemetry flow tests
  - Event batching
  - Compression
  - Delivery acknowledgment
  - Retry logic
  - Offline queueing

- **commands.rs** - Command execution tests
  - Command reception
  - Response generation
  - Error handling
  - Timeout handling

- **collectors.rs** - Collector integration tests
  - Multi-collector operation
  - Event correlation
  - Performance under load

### Performance Benchmarks (benches/)

- **collectors.rs** - Collector performance
  - Process enumeration speed
  - Network connection enumeration
  - Event serialization throughput
  - Batch processing performance

- **event_processing.rs** - Event processing performance
  - YARA scanning throughput
  - Entropy calculation speed
  - Hash calculation speed
  - Detection engine performance

- **network_performance.rs** - Network performance
  - WebSocket throughput
  - Compression efficiency
  - Batching efficiency

## Test Coverage

### Current Coverage Target: 80%+

```bash
# Install tarpaulin for coverage
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage

# View coverage
open coverage/index.html
```

### Coverage by Module

| Module | Target | Current | Status |
|--------|--------|---------|--------|
| collectors/process | 85% | TBD | ⏳ |
| collectors/file | 80% | TBD | ⏳ |
| collectors/network | 80% | TBD | ⏳ |
| collectors/dns | 75% | TBD | ⏳ |
| collectors/registry | 75% | TBD | ⏳ |
| response/kill | 90% | TBD | ⏳ |
| response/quarantine | 85% | TBD | ⏳ |
| response/isolation | 80% | TBD | ⏳ |
| transport | 85% | TBD | ⏳ |
| config | 90% | TBD | ⏳ |
| analyzers | 75% | TBD | ⏳ |

## Test Utilities

### Mock Server (tests/common/mock_server.rs)

The mock WebSocket server simulates Phoenix channels for testing without a backend:

```rust
use tamandua_agent::tests::common::MockServer;

#[tokio::test]
async fn test_with_mock_server() {
    let mut config = MockServerConfig::default();
    config.auto_ack_telemetry = true;

    let server = MockServer::new(config).await.unwrap();

    // Use server.url() for agent connection
    // ...
}
```

### Test Data Generators (tests/common/test_data.rs)

Generate realistic test data:

```rust
use tamandua_agent::tests::common::test_data::*;

// Generate 100 process events
let events = generate_process_events(100);

// Generate malicious event for detection testing
let malicious = create_malicious_process_event();
```

### Helper Functions (tests/common/helpers.rs)

Common test utilities:

```rust
use tamandua_agent::tests::common::helpers::*;

// Retry until success
retry_until(|| async { /* ... */ }, Duration::from_secs(5), Duration::from_millis(100)).await;

// Wait for condition
wait_for_condition(|| some_condition(), Duration::from_secs(5)).await;

// Calculate entropy
let entropy = calculate_entropy(&data);
```

## Error Injection Tests

Test error handling and resilience:

```rust
#[tokio::test]
async fn test_network_failure_recovery() {
    // Simulate network failure
    // Verify offline queueing
    // Verify automatic reconnection
    // Verify event replay
}

#[tokio::test]
async fn test_disk_full_handling() {
    // Simulate disk full condition
    // Verify graceful degradation
    // Verify event dropping with logging
}
```

## Concurrency Tests

Test thread safety and concurrent operation:

```rust
#[tokio::test]
async fn test_multiple_collectors_concurrent() {
    // Start all collectors simultaneously
    // Verify no data races
    // Verify event correlation
}
```

## Security Tests

Test security features:

```rust
#[test]
fn test_path_traversal_prevention() {
    // Attempt path traversal in file operations
    // Verify rejection
}

#[test]
fn test_command_injection_prevention() {
    // Attempt command injection in shell actions
    // Verify sanitization
}
```

## Property-Based Testing

Using proptest for generative testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_entropy_bounds(data: Vec<u8>) {
        let entropy = calculate_entropy(&data);
        prop_assert!(entropy >= 0.0 && entropy <= 8.0);
    }
}
```

## CI Integration

### GitHub Actions

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo test --all-features
      - run: cargo bench --no-run
```

## Test Best Practices

1. **Isolation** - Each test should be independent
2. **Cleanup** - Always cleanup resources (files, processes, etc.)
3. **Determinism** - Tests should be deterministic (no race conditions)
4. **Speed** - Unit tests should be fast (<100ms each)
5. **Coverage** - Aim for 80%+ code coverage
6. **Documentation** - Document complex test scenarios
7. **Assertions** - Use descriptive assertion messages
8. **Mocking** - Mock external dependencies (network, filesystem, etc.)

## Troubleshooting

### Test Failures

**Permission Denied**
```bash
# Run with elevated privileges
sudo cargo test -- --ignored
```

**Timeout Errors**
```bash
# Increase timeout
cargo test -- --test-threads=1
```

**Flaky Tests**
```bash
# Run multiple times to identify flaky tests
for i in {1..10}; do cargo test test_name; done
```

### Platform-Specific Issues

**Windows**
- Ensure Windows SDK is installed
- Run as Administrator for elevated tests
- Disable Windows Defender for performance tests

**Linux**
- Install libpcap-dev for DNS capture tests
- Load eBPF-capable kernel for eBPF tests
- Install libbpf for eBPF tests

**macOS**
- Sign the test binary for Endpoint Security tests
- Grant Full Disk Access for file monitoring tests
- Disable SIP for some kernel-level tests

## Contributing

When adding new features:

1. Write unit tests first (TDD)
2. Achieve 80%+ coverage for new code
3. Add integration tests for user-facing features
4. Update this README with new test information
5. Run full test suite before submitting PR

## References

- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Criterion.rs Benchmarking](https://bheisler.github.io/criterion.rs/book/)
- [Tokio Testing](https://tokio.rs/tokio/topics/testing)
- [Property-Based Testing](https://altsysrq.github.io/proptest-book/intro.html)
