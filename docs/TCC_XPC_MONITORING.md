# macOS TCC and XPC Monitoring

## Overview

This document describes the macOS TCC (Transparency, Consent, and Control) and XPC service monitoring implementation for Tamandua EDR.

## Architecture

### TCC Monitor (`tcc_monitor.rs`)

Monitors the macOS TCC database for privacy permission changes and detects:
- Unauthorized camera/microphone access
- Suspicious Full Disk Access grants
- Privacy permission abuse
- TCC database tampering

**Detection Strategy:**
1. Poll TCC.db for changes (user and system databases)
2. Detect new entries or modifications (last_modified timestamp)
3. Correlate permission grants with process creation events
4. Alert on high-risk permissions (FullDiskAccess, ScreenCapture, Accessibility)

**TCC Database Locations:**
- User: `~/Library/Application Support/com.apple.TCC/TCC.db`
- System: `/Library/Application Support/com.apple.TCC/TCC.db` (requires FDA or root)

### XPC Monitor (`xpc_monitor.rs`)

Monitors XPC (Inter-Process Communication) services for:
- New XPC service registrations
- XPC connections between processes
- Suspicious privilege escalation via XPC
- Unauthorized XPC service creation

**Detection Strategy:**
1. Enumerate active XPC services via `launchctl list`
2. Monitor launchd plist directories for new service files
3. Detect XPC connections by correlating process command-line arguments
4. Alert on XPC services created outside standard directories
5. Flag privilege escalation (user → root XPC connections)

**Monitored Directories:**
- `/Library/LaunchDaemons` (system daemons, run as root)
- `/Library/LaunchAgents` (system agents, run per-user)
- `~/Library/LaunchAgents` (user agents)
- `.app/Contents/XPCServices` (application XPC services)

## Implementation Details

### File Structure

```
apps/tamandua_agent/src/collectors/
├── macos/
│   ├── mod.rs                   # Module exports
│   ├── tcc_parser.rs            # TCC.db SQLite parsing
│   ├── xpc_introspection.rs     # XPC service enumeration
│   └── system_apis.rs           # macOS system API wrappers
├── tcc_monitor.rs               # TCC monitoring collector
└── xpc_monitor.rs               # XPC monitoring collector
```

### TCC Parser (`macos/tcc_parser.rs`)

**Key Types:**
- `TccService`: Enum of privacy services (Camera, Microphone, FullDiskAccess, etc.)
- `TccAuthValue`: Permission status (Allowed, Denied, Unknown)
- `TccEntry`: Parsed TCC database entry
- `parse_tcc_db()`: SQLite parser for TCC.db

**Supported Services:**
- Camera (`kTCCServiceCamera`)
- Microphone (`kTCCServiceMicrophone`)
- Contacts (`kTCCServiceAddressBook`)
- Photos (`kTCCServicePhotos`)
- Calendar (`kTCCServiceCalendar`)
- Reminders (`kTCCServiceReminders`)
- Full Disk Access (`kTCCServiceSystemPolicyAllFiles`)
- Screen Recording (`kTCCServiceScreenCapture`)
- Accessibility (`kTCCServiceAccessibility`)
- Location Services (`kTCCServiceLocation`)
- Automation (`kTCCServiceAppleEvents`)
- Files and Folders (`kTCCServiceSystemPolicyAllFiles`)
- iCloud Drive (`kTCCServiceFileProviderDomain`)
- Media Library (`kTCCServiceMediaLibrary`)
- Bluetooth (`kTCCServiceBluetooth`)

### XPC Introspection (`macos/xpc_introspection.rs`)

**Key Types:**
- `XpcService`: XPC service metadata (label, PID, type)
- `XpcServiceType`: Service classification (SystemDaemon, SystemAgent, UserAgent, ApplicationService)
- `XpcConnection`: Logical XPC connection between processes
- `enumerate_xpc_services()`: Parse `launchctl list` output
- `scan_launchd_plists()`: Filesystem scan for plist files

**Service Classification:**
- System daemons: `/Library/LaunchDaemons/*.plist`, run as root
- System agents: `/Library/LaunchAgents/*.plist`, run per-user
- User agents: `~/Library/LaunchAgents/*.plist`, user-specific
- Application services: `.app/Contents/XPCServices/*.xpc`

### System APIs (`macos/system_apis.rs`)

**Functions:**
- `get_process_codesign_info(pid)`: Extract code signature via `codesign` command
- `get_process_audit_token(pid)`: Get audit token (AUID, EUID, PID, etc.)
- `has_full_disk_access()`: Test Full Disk Access permission

## Configuration

Add to `agent.toml`:

```toml
# TCC monitor interval (seconds)
tcc_monitor_interval_seconds = 30

# XPC monitor interval (seconds)
xpc_monitor_interval_seconds = 60
```

## Events Generated

### TCC Change Event

```json
{
  "event_type": "tcc_change",
  "severity": "high",
  "payload": {
    "service": "kTCCServiceSystemPolicyAllFiles",
    "service_display": "Full Disk Access",
    "client": "com.malware.backdoor",
    "client_type": "bundle_id",
    "auth_value": "allowed",
    "previous_auth_value": null,
    "auth_reason": 3,
    "last_modified": 1640000100,
    "change_type": "new",
    "is_high_risk": true,
    "risk_explanation": "Full Disk Access allows reading all user files including protected data"
  }
}
```

### XPC Service Event

```json
{
  "event_type": "xpc_service",
  "severity": "high",
  "payload": {
    "event_type": "new_service",
    "service_label": "com.malware.backdoor.daemon",
    "service_type": "system_daemon",
    "pid": 1234,
    "executable_path": "/Library/PrivilegedHelperTools/malware",
    "plist_path": "/Library/LaunchDaemons/com.malware.backdoor.daemon.plist",
    "is_suspicious": true,
    "suspicion_reason": "Third-party system daemon, Suspicious keyword: backdoor",
    "risk_score": 0.9
  }
}
```

## MITRE ATT&CK Coverage

### TCC Monitoring
- **T1562**: Impair Defenses - Defense Evasion
  - Detects unauthorized Full Disk Access grants
  - Monitors Screen Recording permission abuse
  - Tracks Accessibility permission escalation

### XPC Monitoring
- **T1543.001**: Create or Modify System Process - Launch Daemon
  - Detects new system daemon registrations
  - Monitors `/Library/LaunchDaemons` for changes
- **T1543.004**: Create or Modify System Process - Launch Agent
  - Detects new launch agent registrations
  - Monitors `/Library/LaunchAgents` for changes
- **T1574.011**: Hijack Execution Flow - XPC Service Hijacking
  - Detects suspicious XPC service creation
  - Flags third-party system daemons

## Risk Assessment

### TCC Permissions

High-risk permissions (risk score ≥ 0.7):
- Full Disk Access
- Screen Recording
- Accessibility
- Camera
- Microphone

### XPC Services

Risk scoring factors:
- **Service type** (0.0 - 0.4):
  - SystemDaemon (not from Apple): +0.4
  - SystemAgent (not from Apple): +0.3
  - UserAgent: +0.1
  - ApplicationService: +0.1
- **Suspicious keywords** (+0.5):
  - backdoor, rootkit, keylog, inject, hidden
- **Unknown service type** (+0.2)

**Thresholds:**
- Risk ≥ 0.7: High severity
- Risk ≥ 0.4: Medium severity
- Risk < 0.4: Low severity

## Performance Impact

### TCC Monitor
- **Polling interval**: 30 seconds (configurable)
- **CPU impact**: < 0.1% (SQLite reads are fast)
- **Memory**: < 5 MB (state tracking for ~1000 entries)
- **Disk I/O**: Minimal (read-only SQLite queries)

### XPC Monitor
- **Polling interval**: 60 seconds (configurable)
- **CPU impact**: < 0.5% (launchctl parsing + filesystem scan)
- **Memory**: < 10 MB (service tracking for ~500 services)
- **Disk I/O**: Minimal (directory scans)

**Combined impact**: < 1% CPU, < 15 MB memory

## Testing

### Unit Tests

```bash
# Run TCC/XPC tests (macOS only)
cargo test --test tcc_xpc_tests

# Run specific test
cargo test test_parse_tcc_db
```

### Mock TCC Database

The test suite creates a temporary SQLite database with sample entries:
- Zoom (Camera + Microphone): Allowed
- Malware (Full Disk Access): Allowed
- Suspicious app (Screen Recording): Allowed
- Untrusted binary (Accessibility): Denied

### Integration Testing

```bash
# Create test TCC entry (requires TCC reset capability)
tccutil reset Camera com.test.app

# Grant permission
tccutil grant Camera com.test.app

# Verify event generation
tail -f /var/log/tamandua-agent.log | grep tcc_change
```

## Security Considerations

### TCC Database Access

- **User TCC.db**: Always readable by the owning user
- **System TCC.db**: Requires Full Disk Access or root privileges
- Parser uses read-only SQLite mode to avoid locking issues
- No writes to TCC.db (monitoring only)

### XPC Service Enumeration

- `launchctl list` requires no special permissions
- Plist directory scans require read access (standard user permissions)
- Service details via `launchctl print` may require elevated access

### Privacy Implications

- TCC monitoring reveals installed applications and their permissions
- XPC enumeration exposes system service architecture
- All data is transmitted securely to backend (TLS + optional mTLS)
- No TCC permission bypasses (monitoring only)

## Troubleshooting

### TCC Monitor

**Issue**: "Failed to parse user TCC database"
- **Cause**: TCC.db is locked by another process
- **Solution**: Wait for lock to release (automatic retry)

**Issue**: "Failed to scan system TCC database (expected without FDA)"
- **Cause**: Agent lacks Full Disk Access permission
- **Solution**: Grant FDA to Tamandua agent (macOS System Preferences)

### XPC Monitor

**Issue**: "Failed to enumerate XPC services"
- **Cause**: `launchctl` not in PATH or permission denied
- **Solution**: Verify agent runs in proper user context

**Issue**: "Failed to scan launchd plists"
- **Cause**: Directory permission issues
- **Solution**: Verify agent has read access to `/Library/Launch*`

## Future Enhancements

1. **Real-time TCC monitoring**
   - Use FSEvents API to watch TCC.db for changes
   - Reduce polling latency from 30s to <1s

2. **XPC connection tracking**
   - Hook XPC message passing via Endpoint Security
   - Capture actual XPC method calls and arguments
   - Detect privilege escalation in real-time

3. **Endpoint Security integration**
   - Use ES_EVENT_TYPE_AUTH_EXEC for TCC permission checks
   - Use ES_EVENT_TYPE_NOTIFY_XPC_CONNECT for XPC connections
   - Enable blocking of unauthorized XPC calls

4. **TCC permission correlation**
   - Link TCC grants to process creation events
   - Tag process events with TCC authorization status
   - Build permission timeline per application

5. **Automated remediation**
   - Revoke suspicious TCC permissions
   - Unload malicious XPC services
   - Quarantine unauthorized launchd plists

## References

- [Apple TCC Database Schema](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [macOS TCC Internals](https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/)
- [XPC Services Programming Guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [launchd plist format](https://www.launchd.info/)
- [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
