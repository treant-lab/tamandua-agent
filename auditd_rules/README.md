# Tamandua EDR Audit Rules

This directory contains Linux audit rules intended to provide Linux auditd visibility similar to selected
Windows ETW providers. Treat this as partial coverage until rules are loaded, audit backlog is healthy, and
events are observed with `ausearch`.

## Files

- **tamandua.rules** - Comprehensive audit rule set for production use

## Quick Start

```bash
# Install auditd
sudo apt-get install auditd  # Debian/Ubuntu
sudo yum install audit       # RHEL/CentOS

# Deploy rules
sudo cp tamandua.rules /etc/audit/rules.d/
sudo augenrules --load

# Verify
sudo auditctl -l | grep tamandua
sudo auditctl -s
```

## Health and Prerequisites

The agent reports auditd readiness without changing service state. Required checks are:

- `auditd` is active.
- `auditctl -s` can query audit status.
- The agent can open the audit stream, requiring root or `CAP_AUDIT_READ`.
- If auto-deploy is enabled, the rules directory is writable and `augenrules` is available.

If these fail, the Linux collector should be reported as `degraded` or `unavailable` instead of silently
claiming auditd coverage.

## Rule Categories

1. **Process Monitoring** - execve, fork, clone, ptrace
2. **File Operations** - open, create, delete, rename, chmod
3. **Network Operations** - socket, connect, bind, accept
4. **Authentication** - login, sudo, su, ssh
5. **Privileged Operations** - kernel modules, capabilities, LD_PRELOAD
6. **Persistence** - cron, systemd, init scripts, SSH keys
7. **Credential Access** - /etc/shadow, SSH keys, browser credentials

## ETW Provider Equivalents

| Windows ETW Provider | Linux Audit Rules |
|---------------------|-------------------|
| Microsoft-Windows-Security-Auditing | Authentication rules |
| Microsoft-Windows-Sysmon | Process, File, Network rules |
| Microsoft-Windows-PowerShell | Script execution monitoring |
| Microsoft-Windows-WMI-Activity | Process monitoring |
| Microsoft-Windows-Kernel-File | File operation rules |
| Microsoft-Windows-Kernel-Network | Network operation rules |
| Microsoft-Windows-Kernel-Process | Process creation rules |

## Performance Modes

### Balanced (Default)
- Buffer: 4096 events
- Rate limit: 500 events/sec
- CPU overhead: 5-10%

### Aggressive
- Buffer: 8192 events
- Rate limit: None
- CPU overhead: 10-20%

### Lightweight
- Buffer: 1024 events
- Rate limit: 100 events/sec
- CPU overhead: 2-5%

## Testing

```bash
# Test process monitoring
ls /tmp
sudo ausearch -k tamandua_process_create -i | tail

# Test file monitoring
touch /tmp/test.txt
sudo ausearch -k tamandua_file_create -i | tail

# Test network monitoring
curl https://example.com
sudo ausearch -k tamandua_network_connect -i | tail
```

## Documentation

See the Linux collector source under `src/collectors/linux/` for the current implementation details.
