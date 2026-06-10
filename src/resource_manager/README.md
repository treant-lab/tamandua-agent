# Resource Manager Module

Per-collector resource budgeting and enforcement for the Tamandua EDR agent.

## Purpose

Prevent individual collectors from monopolizing system resources by enforcing fine-grained CPU, memory, disk I/O, and event rate budgets on a per-collector basis.

## Quick Start

### 1. Enable in Config

```toml
# agent.toml
[resource_manager]
enabled = true
monitor_interval_secs = 2

[resource_manager.default_budget]
cpu_percent_max = 5.0
memory_mb_max = 50
event_rate_per_sec_max = 100
```

### 2. Register Collector

```rust
use tamandua_agent::resource_manager::{
    CollectorRegistration, ResourceManager, CollectorPriority,
};

// In your collector's initialization code:
let throttle_handle = resource_manager.register(CollectorRegistration {
    name: "my_collector".to_string(),
    pid: None,
    priority: CollectorPriority::Normal,
});
```

### 3. Check Throttle State

```rust
// In your collector's main loop:
loop {
    // Check if we should throttle
    if let Some(delay) = throttle_handle.should_throttle() {
        tokio::time::sleep(delay).await;
    }

    // Check if we're paused
    if throttle_handle.is_paused() {
        throttle_handle.wait_for_resume().await;
    }

    // Do work...
    collect_events().await;

    tokio::time::sleep(interval).await;
}
```

## Module Structure

```
resource_manager/
├── mod.rs                  # ResourceManager and configuration
├── budget.rs              # Budget definitions and enforcement logic
├── monitor.rs             # Real-time usage tracking
├── throttler.rs           # Throttling and backpressure
├── integration_example.rs # Example collector integration
└── README.md              # This file
```

## Components

### ResourceManager (`mod.rs`)

Central coordinator that:
- Registers collectors and creates monitors/throttlers
- Periodically samples resource usage
- Enforces budgets and triggers throttling/pausing
- Publishes usage snapshots for health reporting
- Handles priority-based resource reallocation

**Key API:**
```rust
let (manager, snapshot_rx) = ResourceManager::new(config);
let handle = manager.register(registration);
let snapshots = manager.get_all_snapshots();
manager.unregister("collector_name");
```

### CollectorBudget (`budget.rs`)

Defines resource limits and enforcement thresholds:
- `cpu_percent_max`: Maximum CPU usage (0-100%)
- `memory_mb_max`: Maximum memory in MB
- `disk_io_bytes_per_sec_max`: Maximum I/O rate
- `event_rate_per_sec_max`: Maximum event emission rate
- `soft_threshold_percent`: Throttle when this % of budget exceeded
- `hard_threshold_percent`: Pause when this % of budget exceeded

**Key API:**
```rust
let budget = CollectorBudget::new(config, priority);
budget.apply_multiplier(0.5); // Scale down all limits
let action = budget.check_budget(&snapshot);
```

### CollectorMonitor (`monitor.rs`)

Tracks real-time resource usage:
- CPU usage (smoothed over 10 samples)
- Memory usage (process RSS)
- Disk I/O rate (bytes/sec)
- Event emission rate (events/sec)

**Key API:**
```rust
let monitor = CollectorMonitor::new(name, pid);
monitor.record_event();
monitor.record_disk_io(bytes);
monitor.update_memory(bytes);
let snapshot = monitor.snapshot();
```

### CollectorThrottler (`throttler.rs`)

Applies backpressure when budgets are exceeded:
- **Throttle**: Add delay before each operation
- **Pause**: Stop completely for a duration
- **Resume**: Automatically resume after pause expires

**Key API:**
```rust
let throttler = CollectorThrottler::new(name);
throttler.apply_action(action);
let delay = throttler.should_throttle();
let paused = throttler.is_paused();
throttler.wait_for_resume().await;
let stats = throttler.stats();
```

## Priority Levels

| Priority   | Behavior                                       | Examples                          |
|------------|------------------------------------------------|-----------------------------------|
| Critical   | Never paused, only throttled if 2x over budget | process, network, file            |
| High       | Higher resource allocation, throttled normally | injection, memory, defense_evasion|
| Normal     | Standard allocation                            | dns, registry, usb                |
| Low        | First to be throttled when resources scarce    | clipboard, firmware, software_inventory |

## Budget Enforcement

### Soft Threshold (Default: 80%)

When usage exceeds `soft_threshold_percent` of budget:
1. Throttler applies a delay (default 100ms)
2. Collector continues running but slower
3. Logged every 10th occurrence

### Hard Threshold (Default: 100%)

When usage exceeds `hard_threshold_percent` of budget:
1. Collector is paused completely
2. Default pause duration: 1 second
3. Automatically resumes after timeout
4. Logged immediately with WARNING level

### Dynamic Adjustment

When system CPU >80% (configurable):
- All budgets are scaled by 0.5 (cut in half)
- Prevents agent from overwhelming system under load
- Automatically returns to normal when system CPU drops

### Priority Reallocation

When high-priority collectors exceed budgets:
- Low-priority collectors are throttled to free resources
- `priority_reclaim_percent` controls how much to reclaim (default 30%)
- Ensures critical detection capabilities stay active

## Usage Patterns

### Pattern 1: Lightweight Collector

For collectors with minimal resource needs (clipboard, health):

```toml
[resource_manager.collector_budgets.clipboard]
cpu_percent_max = 1.0
memory_mb_max = 10
event_rate_per_sec_max = 5
```

### Pattern 2: CPU-Intensive Collector

For collectors doing heavy analysis (memory, DPI):

```toml
[resource_manager.collector_budgets.memory]
cpu_percent_max = 12.0
memory_mb_max = 150
soft_threshold_percent = 75.0
hard_threshold_percent = 90.0
```

### Pattern 3: High-Volume Collector

For collectors emitting many events (ETW, eBPF):

```toml
[resource_manager.collector_budgets.etw]
cpu_percent_max = 10.0
memory_mb_max = 150
event_rate_per_sec_max = 500
```

### Pattern 4: I/O-Intensive Collector

For collectors reading/writing files (FIM, DLP):

```toml
[resource_manager.collector_budgets.fim]
cpu_percent_max = 6.0
memory_mb_max = 100
disk_io_bytes_per_sec_max = 20971520  # 20 MB/s
event_rate_per_sec_max = 150
```

## Integration Checklist

When adding resource budgets to a collector:

- [ ] Register with ResourceManager on startup
- [ ] Store throttle handle
- [ ] Check `should_throttle()` before expensive operations
- [ ] Check `is_paused()` and call `wait_for_resume()` if paused
- [ ] Unregister on collector shutdown
- [ ] Add budget config to `resource_budgets_example.toml`
- [ ] Set appropriate priority level
- [ ] Test with aggressive budgets to verify throttling works

## Testing

### Unit Tests

```bash
cargo test --package tamandua-agent --lib resource_manager
```

### Integration Tests

```bash
cargo test --package tamandua-agent --test resource_manager_test
```

### Manual Testing

1. Set very low budgets:
   ```toml
   [resource_manager.collector_budgets.test]
   cpu_percent_max = 0.5
   ```

2. Run agent with debug logging:
   ```bash
   RUST_LOG=debug cargo run
   ```

3. Verify throttling/pausing in logs:
   ```
   [WARN] Collector 'test' throttled: cpu=0.6%, budget=0.5%
   [WARN] Collector 'test' PAUSED: cpu=1.2%, budget=0.5%
   ```

## Performance

Resource manager overhead:
- **CPU**: <0.1% (monitoring runs every 2 seconds)
- **Memory**: ~100 KB per registered collector
- **Latency**: Throttle checks are atomic reads (~10 ns)

## Debugging

### Enable Debug Logs

```bash
RUST_LOG=tamandua_agent::resource_manager=debug cargo run
```

### View Throttle Stats

```rust
let stats = throttle_handle.stats();
println!("Throttles: {}, Pauses: {}", stats.throttle_count, stats.pause_count);
```

### Disable Temporarily

```toml
[resource_manager]
enabled = false
```

## Common Issues

### Collector Frequently Paused

**Cause**: Budget too low for collector's workload.

**Solution**: Increase budget or reduce collector scope.

### High CPU Despite Budgets

**Cause**: Collectors not integrated with throttler.

**Solution**: Verify all collectors check `should_throttle()` and `is_paused()`.

### Missed Events

**Cause**: Collector paused during critical event window.

**Solution**: Increase budget or set higher priority.

## See Also

- [Full Documentation](../../../../docs/RESOURCE_BUDGETS.md)
- [Example Config](../../../../config/resource_budgets_example.toml)
- [Integration Example](./integration_example.rs)
- [Global Resource Governor](../resource_governor.rs)
