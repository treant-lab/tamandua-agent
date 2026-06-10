# eBPF LSM Quick Start Guide

Status: lab/partial until runtime proof is collected on the target Linux host. A successful build is not enough;
the agent must also load the BPF object, attach programs, and receive events.

## 5-Minute Setup

### 1. Check Prerequisites

```bash
# Minimum kernel version
uname -r  # Should be >= 4.15

# Check if you can run eBPF
sudo bpftool prog list  # If this works, you're good

# Check runtime prerequisites used by health reporting
test -e /sys/kernel/btf/vmlinux && echo BTF_OK
test -d /sys/fs/bpf && echo BPF_FS_OK
test -e /opt/tamandua/bpf/tamandua-ebpf.o && echo BPF_OBJECT_OK
```

### 2. Build BPF Programs

```bash
cd apps/tamandua_agent/bpf
make all
```

### 3. Run Example

```rust
use tamandua_agent::collectors::ebpf::lsm::LsmHookManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load and attach with automatic fallback
    let mut manager = LsmHookManager::load()?;
    manager.attach()?;

    println!("LSM hooks attached using: {:?}", manager.strategy());

    // Read events
    let mut ring_buf = manager.event_ring_buffer()?;
    loop {
        if let Ok(events) = ring_buf.read() {
            println!("Received {} events", events.len());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
```

### 4. Run as Root

```bash
sudo cargo run --example ebpf_monitor
```

## Kernel Version Detection

```rust
use tamandua_agent::collectors::ebpf::KernelVersion;

let version = KernelVersion::current()?;
println!("Kernel: {}.{}.{}", version.major, version.minor, version.patch);

if version.supports_lsm_bpf() {
    println!("Native LSM BPF may be available; confirm /sys/kernel/security/lsm contains bpf");
} else if version.supports_kprobes() {
    println!("Will use kprobe fallback if symbols and privileges are available");
} else {
    println!("Kernel too old");
}
```

## Event Types

```rust
use tamandua_ebpf_common::{EventType, get_event_type};

match get_event_type(&event_data) {
    Some(EventType::LsmFileOpen) => {
        let event: FileEvent = unsafe { std::ptr::read(event_data.as_ptr() as *const _) };
        println!("File opened: {:?}", event.path);
    }
    Some(EventType::LsmSocketConnect) => {
        let event: SocketEvent = unsafe { std::ptr::read(event_data.as_ptr() as *const _) };
        println!("Connection to {}:{}", event.addr, event.port);
    }
    _ => {}
}
```

## Configuration

```rust
use tamandua_ebpf_common::EbpfConfig;

let config = EbpfConfig {
    enabled: 1,
    file_enabled: 1,        // Monitor file operations
    network_enabled: 1,     // Monitor network
    security_enabled: 1,    // Monitor security events
    filter_low_pids: 1,     // Skip kernel threads
    ..Default::default()
};

manager.set_config(config)?;
```

## Monitoring Sensitive Files

```rust
// Add files to monitor for unauthorized access
manager.add_sensitive_file("/etc/shadow", 1)?;
manager.add_sensitive_file("/etc/passwd", 0)?;
manager.add_sensitive_file("/root/.ssh/id_rsa", 2)?;
```

## Statistics

```rust
let stats = manager.get_stats()?;
println!("Generated: {}", stats.events_generated);
println!("Dropped: {}", stats.events_dropped_full);
println!("Rate limited: {}", stats.events_rate_limited);
```

## Common Issues

### "Permission denied"
```bash
sudo cargo run
# OR
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+eip ./target/release/tamandua-agent
```

### "BTF not available"
```bash
# Use the provided vmlinux.h stub
cd bpf
make all  # Will use stub if BTF unavailable
```

### "Failed to attach kprobe"
```bash
# Check which functions are available
grep security_file_open /proc/kallsyms
```

### Too many events
```rust
// Increase rate limiting
config.filter_uid = 1000;  // Only monitor specific user
config.filter_low_pids = 1; // Skip kernel threads
```

## Testing

```bash
# Unit tests
cargo test --lib collectors::ebpf

# Integration tests (requires root)
sudo cargo test --features ebpf -- --ignored --test-threads=1
```

## Debug Output

```bash
# Enable debug logging
RUST_LOG=debug cargo run

# View BPF program logs (requires bpftool)
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Hook Coverage by Kernel

| Kernel | Strategy | Hooks Available |
|--------|----------|----------------|
| >= 5.7 | LSM BPF | All 8 hooks |
| >= 5.4 | Kprobes | 7 hooks (no XDP) |
| >= 4.17 | Tracepoints | 3 hooks |
| >= 4.15 | Raw Tracepoints | 1 hook |

## Performance Tips

1. **Reduce event rate**: Enable `filter_low_pids` and `filter_uid`
2. **Increase ring buffer**: Modify `BPF_MAP_TYPE_RINGBUF` size in BPF code
3. **Batch reads**: Read multiple events per poll instead of one-by-one
4. **Use high-priority buffer**: Critical events go to separate ring buffer

## Next Steps

- Read full documentation: `src/collectors/ebpf/README.md`
- View implementation details: `docs/EBPF_LSM_IMPLEMENTATION.md`
- Check examples: `examples/ebpf_monitor.rs`
- Join development: See `CONTRIBUTING.md`
