# eBPF LSM Hooks with Fallback Strategy

> **Status: ARCHIVED / LEGACY (aspirational design).**
>
> The `EbpfCollectorManager` and `LsmHookManager` types documented here are the
> original libbpf-style design for Tamandua's eBPF subsystem. They are **not**
> the live collector path. The wired, production collector is
> `EbpfLinuxCollector` in `apps/tamandua_agent/src/collectors/ebpf_linux.rs`
> (aya-based, implements `next_event()` and is started from `main.rs`).
>
> This document is retained for historical reference and as the design contract
> for the libbpf path that lives behind `feature = "ebpf"`. New work should
> target `ebpf_linux.rs`. `EbpfCollectorManager` is marked `#[deprecated]` in
> `mod.rs` and will be removed once the aya-based migration is fully verified
> on Linux.

This module implements Linux Security Module (LSM) BPF hooks with automatic fallback support for older kernels.
It remains a lab/partial capability until a target host proves the full runtime path: BPF object present,
BTF available, privileges granted, programs attached, and events observed.

## Overview

Tamandua's eBPF LSM implementation is intended to provide kernel-level visibility into security events with
minimal performance overhead. The system reports prerequisite and health state separately from configured
intent so the agent can say `inactive` or `degraded` instead of implying that eBPF is collecting when load or
attach failed.

## Runtime Status Model

- `active`: the BPF object loaded, at least one program attached, and the ring-buffer reader is running.
- `degraded`: the host appears capable, but load/attach failed or runtime proof is missing.
- `unavailable`: required kernel/runtime prerequisites are missing.

Prerequisite reporting includes kernel feature gates, `/sys/kernel/btf/vmlinux`, `/sys/fs/bpf`, root/CAP_BPF,
LSM `bpf` enablement, tracing filesystem availability, and the expected BPF object path.

## Kernel Support Matrix

| Kernel Version | Strategy | Expected Coverage | Features |
|----------------|----------|----------|----------|
| >= 5.7 | **BPF_LSM** | best | Native LSM hooks when BPF LSM is enabled |
| >= 5.4 | **Kprobes** | good | Hook LSM functions where symbols are available |
| >= 4.17 | **Tracepoints** | 60% | Stable kernel tracepoints |
| >= 4.15 | **Raw Tracepoints** | 20% | Minimal coverage (process exec only) |
| < 4.15 | **Unsupported** | 0% | Kernel too old for eBPF |

## Supported Hook Points

### Full Support (All Strategies)

- **bprm_check_security**: Process execution authorization
  - Detects process launches
  - Captures executable path and arguments
  - Monitors setuid/setgid execution

### LSM + Kprobe Support

- **file_open**: File access monitoring
- **file_permission**: Permission checks for sensitive files
- **socket_connect**: Outbound network connections
- **socket_bind**: Listen sockets and port binding
- **task_kill**: Signal authorization (process termination)
- **ptrace_access_check**: Debugging/injection detection
- **mmap_file**: Memory mapping with PROT_EXEC (code injection)

### Limited Support (Tracepoint Fallback)

- **file_open**: Via `lsm/file_open` tracepoint (if available)
- **task_kill**: Via `signal/signal_generate` tracepoint

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Space (Rust)                        │
├─────────────────────────────────────────────────────────────┤
│  LsmHookManager                                             │
│    ├─ KernelVersion::current()                             │
│    ├─ AttachStrategy::for_kernel()                         │
│    └─ FallbackStrategy::attach_all()                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   Kernel Space (eBPF)                       │
├─────────────────────────────────────────────────────────────┤
│  Try: BPF_LSM (kernel >= 5.7)                              │
│    ├─ lsm/file_open                                        │
│    ├─ lsm/socket_connect                                   │
│    └─ lsm/task_kill                                        │
│                                                             │
│  Fallback: Kprobes (kernel >= 5.4)                        │
│    ├─ security_file_open                                   │
│    ├─ security_socket_connect                              │
│    └─ security_task_kill                                   │
│                                                             │
│  Fallback: Tracepoints (kernel >= 4.17)                   │
│    ├─ sched/sched_process_exec                             │
│    └─ signal/signal_generate                               │
│                                                             │
│  Fallback: Raw Tracepoints (kernel >= 4.15)               │
│    └─ sched_process_exec                                   │
└─────────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install -y \
    clang llvm \
    linux-headers-$(uname -r) \
    bpftool

# RHEL/CentOS
sudo yum install -y \
    clang llvm \
    kernel-devel-$(uname -r) \
    bpftool

# Arch Linux
sudo pacman -S clang llvm linux-headers bpf
```

### Compile BPF Programs

```bash
cd apps/tamandua_agent/bpf
make all
```

This generates:
- `build/lsm_hooks.o` - BPF bytecode for LSM hooks

### Runtime Prerequisite Check

```bash
uname -r
test -e /sys/kernel/btf/vmlinux && echo BTF_OK
test -d /sys/fs/bpf && echo BPF_FS_OK
cat /sys/kernel/security/lsm 2>/dev/null | grep -qw bpf && echo BPF_LSM_OK
sudo bpftool prog list >/dev/null && echo PRIVILEGES_OK
test -e /opt/tamandua/bpf/tamandua-ebpf.o && echo BPF_OBJECT_OK
```

If any required check fails, report eBPF as `partial` or `unavailable` and rely on auditd/userspace collectors
instead of claiming production eBPF coverage.

### Generate vmlinux.h (Optional)

For maximum portability across kernel versions:

```bash
cd apps/tamandua_agent/bpf
make vmlinux
```

This requires kernel CONFIG_DEBUG_INFO_BTF=y (available in most modern distributions).

### Install BPF Programs

```bash
cd apps/tamandua_agent/bpf
sudo make install
```

Installs to `/opt/tamandua/bpf/`

## Usage

### Basic Usage

```rust
use tamandua_agent::collectors::ebpf::lsm::LsmHookManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load BPF programs with automatic fallback
    let mut manager = LsmHookManager::load()?;

    println!("Kernel: {}.{}.{}",
        manager.kernel_version().major,
        manager.kernel_version().minor,
        manager.kernel_version().patch
    );
    println!("Strategy: {:?}", manager.strategy());

    // Attach hooks
    manager.attach()?;

    // Read events
    let mut ring_buf = manager.event_ring_buffer()?;

    loop {
        if let Ok(events) = ring_buf.read() {
            for event_data in events {
                // Process event
                handle_event(event_data)?;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
```

### Configuration

```rust
use tamandua_ebpf_common::EbpfConfig;

let config = EbpfConfig {
    enabled: 1,
    process_enabled: 1,
    file_enabled: 1,
    network_enabled: 1,
    security_enabled: 1,
    container_enabled: 1,
    lsm_enabled: 1,
    xdp_enabled: 0,
    filter_uid: 0,          // 0 = monitor all UIDs
    containers_only: 0,     // 0 = monitor host and containers
    sensitive_files_enabled: 1,
    filter_low_pids: 1,     // Skip kernel threads
    _pad: [0; 1],
};

manager.set_config(config)?;
```

### Monitoring Sensitive Files

```rust
// Add sensitive files to monitor
manager.add_sensitive_file("/etc/shadow", 1)?;
manager.add_sensitive_file("/etc/passwd", 0)?;
manager.add_sensitive_file("/root/.ssh/id_rsa", 2)?;
manager.add_sensitive_file("/etc/sudoers", 1)?;
```

### Statistics

```rust
let stats = manager.get_stats()?;

println!("Events generated: {}", stats.events_generated);
println!("Events dropped: {}", stats.events_dropped_full);
println!("Events rate limited: {}", stats.events_rate_limited);
println!("Map lookup failures: {}", stats.map_lookup_failures);
println!("Probe read failures: {}", stats.probe_read_failures);
```

## Testing

### Unit Tests

```bash
cargo test --package tamandua-agent --lib collectors::ebpf
```

### Integration Tests (Requires Root)

```bash
# Run all integration tests
sudo -E cargo test --package tamandua-agent --features ebpf -- --ignored --test-threads=1

# Run specific test
sudo -E cargo test --package tamandua-agent --features ebpf test_lsm_hook_manager_events -- --ignored
```

### Manual Testing

```bash
# Load and attach hooks
sudo cargo run --example ebpf_monitor

# In another terminal, generate events
ls /etc
cat /etc/passwd
ping -c 1 8.8.8.8
```

## Troubleshooting

### Error: "Failed to load BPF program"

**Cause**: Missing CAP_BPF or CAP_SYS_ADMIN capability

**Solution**: Run as root or with capabilities:
```bash
sudo cargo run
# OR
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+eip ./target/release/tamandua-agent
```

### Error: "BTF not available"

**Cause**: Kernel not built with CONFIG_DEBUG_INFO_BTF=y

**Solution**: Use the provided vmlinux.h stub or upgrade kernel

### Error: "Kprobe not found: security_file_open"

**Cause**: Kernel function not exported

**Solution**: Fallback will automatically try alternative functions. Check `/proc/kallsyms`:
```bash
grep security_file_open /proc/kallsyms
```

### Error: "Ring buffer full"

**Cause**: Event rate exceeds ring buffer capacity

**Solution**: Increase ring buffer size or add rate limiting:
```rust
// Reduce event rate
config.filter_low_pids = 1;  // Skip kernel threads
config.filter_uid = 1000;     // Only monitor specific UID
```

## Performance

### Overhead

These are planning targets, not production guarantees until measured on the target kernel and workload.

| Strategy | CPU Overhead Target | Memory |
|----------|-------------|--------|
| BPF_LSM | < 1% | ~4MB ring buffer |
| Kprobe | < 2% | ~4MB ring buffer |
| Tracepoint | < 1% | ~4MB ring buffer |

### Event Rates

Typical production workload (1000 processes/sec):
- Events generated: ~10,000/sec
- Events dropped: < 0.1%
- Rate limited: ~5%

### Tuning

```rust
// Adjust rate limits per PID
// Default: 100 exec, 1000 file ops, 500 network ops per second

// Reduce ring buffer backpressure
// Increase ring buffer size in BPF program:
// #define RINGBUF_SIZE (8 * 1024 * 1024)  // 8MB
```

## Security Considerations

1. **Privilege Requirements**: Requires CAP_BPF + CAP_PERFMON (kernel >= 5.8) or CAP_SYS_ADMIN
2. **Kernel Verification**: All BPF programs are verified by kernel before loading
3. **Resource Limits**: Ring buffers are capped at 4MB to prevent memory exhaustion
4. **Rate Limiting**: Per-PID rate limits prevent DoS attacks
5. **Fail-Open**: LSM hooks return 0 (allow) on error to prevent system disruption

## References

- [BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [Aya BPF Framework](https://aya-rs.dev/)

## License

Apache-2.0
