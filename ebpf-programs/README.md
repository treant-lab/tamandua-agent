# Tamandua eBPF Programs - Production Deployment Guide

## Overview

This directory contains production-hardened eBPF programs for the Tamandua EDR agent. The programs provide comprehensive kernel-level monitoring with minimal overhead.

## Features

### Monitoring Capabilities

| Category | Events | Hook Type |
|----------|--------|-----------|
| **Process** | exec, exit, fork, clone | Tracepoint, BTF Tracepoint |
| **File** | open, read, write, unlink, rename, mmap | Kprobe, LSM |
| **Network** | connect, accept, bind, TCP state | Kprobe, Tracepoint |
| **Security** | privilege escalation, capabilities, ptrace | Kprobe, LSM |
| **Container** | namespace change, cgroup migrate, escape detection | Kprobe |
| **Evasion** | memfd_create, anonymous exec, process_vm_writev | Raw Tracepoint |

### Production Hardening

- **BTF/CO-RE**: Compile once, run on kernels 5.4-6.x without recompilation
- **Ring Buffer**: BPF_MAP_TYPE_RINGBUF with priority queues for critical events
- **Rate Limiting**: Per-PID rate limiting to prevent event storms
- **Graceful Degradation**: Falls back gracefully if features unavailable
- **Memory Safety**: All array accesses bounds-checked for verifier
- **Stack Optimization**: Functions stay under 512-byte stack limit

## Kernel Compatibility

| Kernel Version | Support Level | Features |
|----------------|---------------|----------|
| 5.4 LTS | Full | Tracepoints, Kprobes, Ring Buffer |
| 5.10 LTS | Full | + BTF CO-RE, fentry/fexit |
| 5.15 LTS | Full | + Enhanced LSM hooks |
| 6.1 LTS | Full | + All features |
| 6.x | Full | Latest features |

### Required Kernel Config

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_TRACING=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_BPF_LSM=y (optional, for LSM hooks)
```

## Building

### Prerequisites

```bash
# Install Rust nightly
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker
cargo install bpf-linker
```

### Build Commands

```bash
# Development build
cargo +nightly build --target bpfel-unknown-none -Z build-std=core

# Release build (optimized)
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

# With BTF generation
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release --features btf
```

### Build Artifacts

The compiled eBPF program will be at:
```
target/bpfel-unknown-none/release/tamandua-ebpf
```

## Deployment

### Installation

```bash
# Copy eBPF program to agent directory
sudo mkdir -p /opt/tamandua/ebpf
sudo cp target/bpfel-unknown-none/release/tamandua-ebpf /opt/tamandua/ebpf/

# Set permissions
sudo chmod 644 /opt/tamandua/ebpf/tamandua-ebpf
```

### Capability Requirements

The agent requires one of:
- Running as root, OR
- CAP_BPF + CAP_PERFMON capabilities

```bash
# Option 1: Run as root (not recommended for production)
sudo /opt/tamandua/bin/tamandua-agent

# Option 2: Set capabilities (recommended)
sudo setcap cap_bpf,cap_perfmon+ep /opt/tamandua/bin/tamandua-agent
```

### Systemd Service

```ini
[Unit]
Description=Tamandua EDR Agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/tamandua/bin/tamandua-agent
Restart=always
RestartSec=5
User=tamandua
Group=tamandua
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
```

## Configuration

### Runtime Configuration

The eBPF programs can be configured via the CONFIG map. Set from userspace:

```rust
// In Rust loader
let mut config: Array<_, EbpfConfig> = Array::try_from(bpf.map_mut("CONFIG")?)?;
config.set(0, EbpfConfig {
    enabled: 1,
    process_enabled: 1,
    file_enabled: 1,
    network_enabled: 1,
    security_enabled: 1,
    container_enabled: 1,
    lsm_enabled: 0,  // Enable only if kernel supports BPF LSM
    xdp_enabled: 0,
    filter_uid: 0,    // 0 = monitor all users
    containers_only: 0,
    sensitive_files_enabled: 1,
    filter_low_pids: 1,
    _pad: [0; 1],
}, 0)?;
```

### Sensitive File Monitoring

Add paths to monitor:

```rust
let mut sensitive: HashMap<_, [u8; 256], u32> = HashMap::try_from(bpf.map_mut("SENSITIVE_FILES")?)?;

// Add /etc/shadow
let mut path = [0u8; 256];
path[..11].copy_from_slice(b"/etc/shadow");
sensitive.insert(path, SENSITIVITY_SHADOW, 0)?;
```

### Process Allowlist

Reduce noise by skipping known-good processes:

```rust
let mut allowlist: HashMap<_, [u8; 64], u8> = HashMap::try_from(bpf.map_mut("PROCESS_ALLOWLIST")?)?;

let mut comm = [0u8; 64];
comm[..10].copy_from_slice(b"systemd-jo");  // systemd-journald
allowlist.insert(comm, 1, 0)?;
```

## Maps Reference

| Map Name | Type | Key | Value | Purpose |
|----------|------|-----|-------|---------|
| EVENTS | RingBuf | - | Events | Main event stream (4MB) |
| EVENTS_PRIORITY | RingBuf | - | Events | High-priority events (1MB) |
| CONFIG | Array | u32 | EbpfConfig | Runtime configuration |
| ACTIVE_PIDS | LruHashMap | u32 | u64 | Track exec'd PIDs |
| PROCESS_CREDS | LruHashMap | u32 | (u32, u64) | UID/caps per PID |
| SENSITIVE_FILES | HashMap | [u8; 256] | u32 | Sensitive paths |
| FD_PATHS | LruHashMap | (u32, i32) | [u8; 256] | FD to path mapping |
| STATS | PerCpuArray | u32 | EbpfStats | Per-CPU counters |
| RATE_LIMIT | LruHashMap | u32 | RateLimitEntry | Rate limiting state |

## LSM Hooks

LSM hooks require a kernel compiled with `CONFIG_BPF_LSM=y` and `bpf` in the LSM list.

Check if LSM is available:
```bash
cat /sys/kernel/security/lsm
# Should include "bpf" in the list
```

Enable BPF LSM at boot:
```bash
# Add to /etc/default/grub
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,bpf"
```

## Troubleshooting

### eBPF Program Won't Load

1. **Check kernel version**: Must be 5.4+
   ```bash
   uname -r
   ```

2. **Check BTF availability**:
   ```bash
   ls -la /sys/kernel/btf/vmlinux
   ```

3. **Check capabilities**:
   ```bash
   capsh --print | grep cap_bpf
   ```

4. **Check locked memory limit**:
   ```bash
   ulimit -l
   # Should be unlimited or > 128MB
   ```

5. **Enable BPF JIT** (performance):
   ```bash
   echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable
   ```

### High Event Volume

1. Enable rate limiting in config
2. Add noisy processes to allowlist
3. Disable unnecessary monitoring categories
4. Increase ring buffer size if events are being dropped

### Ring Buffer Full

Monitor the STATS map for `events_dropped_full`:

```rust
let stats: PerCpuArray<_, EbpfStats> = PerCpuArray::try_from(bpf.map("STATS")?)?;
for cpu in 0..num_cpus {
    let s = stats.get(&0, cpu)?;
    println!("CPU {}: dropped={}", cpu, s.events_dropped_full);
}
```

### LSM Hooks Not Working

1. Verify kernel config: `CONFIG_BPF_LSM=y`
2. Check LSM list: `cat /sys/kernel/security/lsm`
3. Add `lsm=...,bpf` to boot params
4. Reboot required after changing LSM config

## Performance Tuning

### Ring Buffer Sizing

```
Events/sec    Recommended Size
< 10,000      2MB (default)
10,000-50,000 4MB
50,000-100,000 8MB
> 100,000     16MB + priority buffer
```

### Rate Limits

Default limits per PID per second:
- Process exec: 100
- File events: 1000
- Network events: 500
- Security events: no limit

Adjust in code or via config map.

## Testing

### Unit Tests

```bash
cd apps/tamandua_agent/ebpf-programs
cargo +nightly test --target x86_64-unknown-linux-gnu
```

### Integration Tests

```bash
# Run with test harness
cd apps/tamandua_agent
cargo test --features ebpf-integration
```

### Stress Testing

```bash
# Generate high event volume
stress-ng --fork 100 --timeout 60s &
./tamandua-agent --benchmark

# Check for drops
grep "events_dropped" /var/log/tamandua/agent.log
```

## Security Considerations

1. **Capability Minimization**: Only grant required capabilities
2. **Namespace Isolation**: Consider running agent in host namespace only
3. **Audit Logging**: All eBPF program loads are logged by kernel
4. **Program Pinning**: Consider pinning programs to prevent unloading
5. **Map Permissions**: Restrict map access to agent process only

## Version History

| Version | Changes |
|---------|---------|
| 0.1.0 | Initial release with basic monitoring |
| 0.2.0 | Added LSM hooks, container awareness |
| 0.3.0 | Production hardening, rate limiting |
| 0.4.0 | BTF/CO-RE support, priority queues |
