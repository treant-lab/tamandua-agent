# Tamandua Agent Linux Package Builder

This directory contains scripts and configuration for building DEB and RPM packages of the Tamandua EDR agent.

## Quick Start

```bash
# Build both DEB and RPM packages
./build.sh

# Build specific package type
./build.sh --deb-only
./build.sh --rpm-only

# Build with specific version
./build.sh --version 1.2.0

# Build for ARM64
./build.sh --arch arm64
```

## Prerequisites

### For DEB packages (Debian/Ubuntu)
```bash
sudo apt-get install dpkg-dev fakeroot lintian
```

### For RPM packages (RHEL/Fedora/CentOS)
```bash
# On Debian/Ubuntu:
sudo apt-get install rpm

# On RHEL/Fedora:
sudo dnf install rpm-build
```

### Rust Toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu  # For ARM64 builds
```

## Directory Structure

```
linux/
├── build.sh                 # Main build script
├── docker-build.sh          # Docker-based build (cross-platform)
├── ci-build.sh              # CI/CD build script
├── Makefile                 # Make targets for common tasks
├── tamandua-agent.service   # Systemd unit file
├── agent.toml.production    # Production config template
├── debian/                  # DEB package files
│   ├── control              # Package metadata
│   ├── conffiles            # Config files to preserve
│   ├── postinst             # Post-installation script
│   ├── prerm                # Pre-removal script
│   ├── postrm               # Post-removal script
│   ├── copyright            # License information
│   └── changelog            # Package changelog
└── rpm/
    └── tamandua-agent.spec  # RPM spec file
```

## Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `--version VERSION` | Package version | From Cargo.toml |
| `--arch ARCH` | Target architecture (amd64, arm64) | amd64 |
| `--target TARGET` | Rust target triple | Auto-detected |
| `--deb-only` | Build only DEB package | Build both |
| `--rpm-only` | Build only RPM package | Build both |
| `--skip-build` | Use existing binary | Build fresh |
| `--features FEATURES` | Cargo features | compression |
| `--output DIR` | Output directory | ./dist |
| `--clean` | Clean before building | No clean |

## Using Make

```bash
# Build all packages
make all

# Build specific package
make deb
make rpm

# Build with custom version
make all VERSION=1.2.0

# Build in Docker (cross-platform)
make docker-all

# Test package installation
make test-deb
make test-rpm

# Clean build artifacts
make clean
```

## Docker-Based Builds

For consistent builds across platforms, use the Docker-based builder:

```bash
# Build all packages in Docker
./docker-build.sh

# Build specific type
./docker-build.sh --deb-only
./docker-build.sh --rpm-only
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Build Linux Packages

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-action@stable

      - name: Build packages
        run: |
          cd apps/tamandua_agent/installer/linux
          ./ci-build.sh all

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: linux-packages
          path: apps/tamandua_agent/installer/linux/dist/
```

### GitLab CI

```yaml
build:linux:
  image: rust:1.75-bookworm
  script:
    - apt-get update && apt-get install -y dpkg-dev rpm
    - cd apps/tamandua_agent/installer/linux
    - ./ci-build.sh all
  artifacts:
    paths:
      - apps/tamandua_agent/installer/linux/dist/
```

## Package Installation

### DEB (Debian/Ubuntu)

```bash
# Install
sudo dpkg -i tamandua-agent_1.0.0_amd64.deb
sudo apt-get install -f  # Install dependencies

# Configure
sudo vi /etc/tamandua/agent.toml

# Start service
sudo systemctl start tamandua-agent
sudo systemctl enable tamandua-agent
```

### RPM (RHEL/Fedora/CentOS)

```bash
# Install
sudo rpm -i tamandua-agent-1.0.0-1.x86_64.rpm
# or
sudo dnf install tamandua-agent-1.0.0-1.x86_64.rpm

# Configure
sudo vi /etc/tamandua/agent.toml

# Start service
sudo systemctl start tamandua-agent
sudo systemctl enable tamandua-agent
```

## Package Contents

After installation:

| Path | Description |
|------|-------------|
| `/usr/bin/tamandua-agent` | Agent binary |
| `/etc/tamandua/agent.toml` | Configuration file |
| `/usr/lib/systemd/system/tamandua-agent.service` | Systemd service |
| `/var/lib/tamandua/` | Agent data directory |
| `/var/log/tamandua/` | Log directory (journald is primary) |

## Security Features

- Runs as dedicated `tamandua` user (not root)
- Linux capabilities for required permissions:
  - `CAP_NET_ADMIN` - Network monitoring
  - `CAP_NET_RAW` - Raw packet capture
  - `CAP_SYS_PTRACE` - Process inspection
  - `CAP_DAC_READ_SEARCH` - File access
  - `CAP_BPF` - eBPF programs
  - `CAP_PERFMON` - Performance monitoring
- Systemd security hardening (ProtectSystem, PrivateTmp, etc.)
- Config file permissions: 640 (root:tamandua)

## Troubleshooting

### Service won't start

```bash
# Check status
systemctl status tamandua-agent

# View logs
journalctl -u tamandua-agent -f

# Check config syntax
tamandua-agent --config /etc/tamandua/agent.toml --check
```

### Connection issues

```bash
# Test server connectivity
curl -v https://your-server.com/api/health

# Check agent logs for connection errors
journalctl -u tamandua-agent | grep -i "connection\|error"
```

### Permission denied

```bash
# Verify capabilities are set
getcap /usr/bin/tamandua-agent

# Re-set capabilities if needed
sudo setcap 'cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search,cap_bpf,cap_perfmon,cap_sys_resource+eip' /usr/bin/tamandua-agent
```

## Uninstallation

### DEB
```bash
# Remove (keep config)
sudo apt-get remove tamandua-agent

# Purge (remove everything)
sudo apt-get purge tamandua-agent
```

### RPM
```bash
# Remove
sudo rpm -e tamandua-agent
# or
sudo dnf remove tamandua-agent

# Manual cleanup
sudo rm -rf /etc/tamandua /var/lib/tamandua /var/log/tamandua
sudo userdel tamandua
sudo groupdel tamandua
```

## License

Apache License 2.0 - See LICENSE file for details.
