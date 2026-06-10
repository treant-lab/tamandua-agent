# Configuration Rollback System

The Tamandua agent includes a comprehensive configuration rollback system that ensures safe config updates with automatic recovery.

## Features

### 1. Configuration Validation

Before applying any config changes, the system validates:

- **TOML Syntax**: Ensures the file is valid TOML
- **Collector Names**: Verifies all enabled collectors exist
- **Port Numbers & Intervals**: Validates ranges and types
- **Paths**: Checks file/directory paths are accessible
- **YARA Rules**: Compiles YARA rules to ensure validity (if enabled)
- **Sigma Rules**: Parses Sigma rules for syntax errors (if enabled)

#### Validation Levels

- **Errors**: Critical issues that prevent config from being applied
- **Warnings**: Issues that may cause problems but won't block config

#### Example

```bash
# Validate a config file without applying it
tamandua-agent config-validate /path/to/agent.toml
```

### 2. Automatic Backup

Every config change triggers an automatic backup:

- Stores last **10 versions** with timestamps
- Each backup includes **SHA256 checksum** for integrity verification
- Metadata tracks source, timestamp, and who triggered the change
- Backup directory: `~/.tamandua/config/backups/` (Linux/macOS) or `C:\ProgramData\Tamandua\config\backups\` (Windows)

#### Backup Metadata

Each backup stores:
- Version number (incrementing)
- Timestamp (UTC)
- SHA256 checksum
- Description (optional)
- Source (server-push, manual-edit, rollback, etc.)
- Triggered by (user/system)

### 3. Health Check System

After applying a config update, the agent runs a health check:

- **30-second delay** before starting check
- **2-minute timeout** for health verification
- **Monitors**:
  - Connection to backend server
  - Collector panics
  - Memory usage (threshold: 1 GB)
  - CPU usage (threshold: 80%)

#### Health Check Triggers

The health check passes when:
- Agent successfully connects to backend within timeout
- No collector panics detected
- Resource usage within acceptable limits

#### Rollback Triggers

Automatic rollback occurs if:
- Agent cannot connect to server within 30 seconds
- Any collector panics during initialization
- Memory exceeds 1 GB
- CPU usage exceeds 80% sustained
- Health check times out (2 minutes)

### 4. Automatic Rollback

If health check fails, the system automatically:

1. Logs the failure reason
2. Restores the previous config version
3. Reloads the old configuration
4. Alerts the backend about the rollback
5. Records the rollback in telemetry

#### Disabling Auto-Rollback

```rust
let mut manager = ConfigManager::new(&config_path)?;
manager.set_auto_rollback(false); // Disable automatic rollback
```

### 5. Manual Rollback

Administrators can manually rollback configs using CLI commands.

## CLI Commands

### List Available Backups

```bash
tamandua-agent config-list

# Output:
# Available config backups:
#
# Version  Timestamp                 Source        Triggered By         Description
# ----------------------------------------------------------------------------------------------------
# 1        2026-02-20 10:30:45      server-push   admin@company.com    Pre-update from server
# 2        2026-02-20 11:15:22      manual-edit   sysadmin             Manual configuration
# 3        2026-02-20 12:00:00      rollback      system               Pre-rollback to v1
```

### Restore a Specific Version

```bash
# Rollback to version 2
tamandua-agent config-rollback 2

# Output:
# Rolling back config to version 2...
# Config successfully rolled back to version 2
# Restart the agent for changes to take effect.
```

### Show Diff Between Versions

```bash
# Diff between version 1 and version 2
tamandua-agent config-diff 1 2

# Diff between version 1 and current config
tamandua-agent config-diff 1

# Output:
# Diff between version 1 and version 2:
#
# - server_url = "wss://old-server:4000"
# + server_url = "wss://new-server:4000"
# - heartbeat_interval_seconds = 30
# + heartbeat_interval_seconds = 60
```

### Verify Backup Integrity

```bash
tamandua-agent config-verify

# Output:
# Verifying config backup integrity...
#
# Version 1: OK
# Version 2: OK
# Version 3: FAILED
#
# Some backups failed verification. Consider creating new backups.
```

### Validate Configuration

```bash
tamandua-agent config-validate /etc/tamandua/agent.toml

# Output:
# Validating configuration file: /etc/tamandua/agent.toml
#
# TOML syntax: OK
# Config validation: OK
#
# Warnings (2):
#
#   WARNING: heartbeat_interval_seconds: Heartbeat interval > 1 hour may cause connection timeouts
#   WARNING: tls.skip_verify: TLS verification disabled - DANGEROUS for production
#
# Configuration is valid!
```

## Programmatic Usage

### Using ConfigManager

```rust
use tamandua_agent::config::manager::ConfigManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Create manager
    let mut manager = ConfigManager::new("/etc/tamandua/agent.toml")?;

    // Apply new config from file
    let result = manager.apply_config_file(
        &PathBuf::from("/tmp/new_config.toml"),
        "admin-update",
        Some("admin@company.com".to_string())
    ).await?;

    if result.success {
        println!("Config applied successfully");
    } else {
        println!("Config update failed");
        if result.rolled_back {
            println!("Automatically rolled back to version {}",
                     result.backup_version.unwrap());
        }
    }

    Ok(())
}
```

### Direct Rollback Operations

```rust
use tamandua_agent::config::rollback::ConfigRollback;

fn main() -> Result<()> {
    let rollback = ConfigRollback::new("/etc/tamandua/agent.toml")?;

    // List backups
    let backups = rollback.list_backups()?;
    for backup in backups {
        println!("Version {}: {} ({})",
                 backup.version,
                 backup.timestamp,
                 backup.source);
    }

    // Restore version 3
    rollback.restore_version(3)?;

    // Verify all backups
    let results = rollback.verify_backups()?;
    for (version, valid) in results {
        println!("Version {}: {}", version, if valid { "OK" } else { "FAILED" });
    }

    Ok(())
}
```

### Custom Health Check Configuration

```rust
use tamandua_agent::config::{
    manager::ConfigManager,
    health_check::HealthCheckConfig,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let health_config = HealthCheckConfig {
        delay: Duration::from_secs(60),           // Wait 1 minute before checking
        timeout: Duration::from_secs(180),        // 3-minute timeout
        memory_threshold_mb: 2048,                // 2 GB memory limit
        cpu_threshold_percent: 50.0,              // 50% CPU limit
    };

    let manager = ConfigManager::with_health_config(
        "/etc/tamandua/agent.toml",
        health_config
    )?;

    Ok(())
}
```

## Configuration Update Flow

```
┌─────────────────────┐
│ Config Update       │
│ Received            │
└──────┬──────────────┘
       │
       v
┌──────────────────────┐
│ Validate TOML        │
│ Syntax               │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ Validate Config      │
│ Values               │
└──────┬───────────────┘
       │
       ├─── Validation Failed ──> Reject Update
       │
       v
┌──────────────────────┐
│ Create Backup        │
│ (v1 -> v2)           │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ Apply New Config     │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ Start Health Check   │
│ (30s delay)          │
└──────┬───────────────┘
       │
       ├─── Check Connection
       ├─── Check Collectors
       └─── Check Resources
       │
       v
┌──────────────────────┐
│ Health Check Result  │
└──────┬───────────────┘
       │
       ├─── PASS ──> Success!
       │
       └─── FAIL ──> ┌─────────────────┐
                      │ Automatic       │
                      │ Rollback to v1  │
                      └─────────────────┘
```

## Best Practices

### 1. Test Config Changes in Staging

Always validate and test config changes in a staging environment before pushing to production:

```bash
# Validate before applying
tamandua-agent config-validate /tmp/new_config.toml

# Test in non-production environment first
```

### 2. Monitor Health Checks

Set up alerts for automatic rollbacks:

```elixir
# In Elixir backend
def handle_telemetry_event(%{event_type: "config_rollback"} = event) do
  alert = %Alert{
    severity: :high,
    title: "Agent Config Auto-Rollback",
    description: "Agent #{event.agent_id} rolled back config due to: #{event.reason}",
    agent_id: event.agent_id
  }

  Alerts.create_alert(alert)
end
```

### 3. Regular Backup Verification

Schedule periodic backup integrity checks:

```bash
# Weekly cron job
0 2 * * 0 tamandua-agent config-verify >> /var/log/tamandua/backup-verify.log
```

### 4. Document Config Changes

Always provide descriptive backup descriptions:

```rust
manager.apply_config_file(
    &new_config,
    "performance-tuning",
    Some("admin@company.com - Reduced CPU usage to 10%".to_string())
).await?;
```

### 5. Keep Rollback History

The system automatically maintains 10 versions. For longer history:

- Back up the backup directory to external storage
- Use version control (git) for config files
- Export metadata to a database

## Troubleshooting

### Backup Directory Not Found

```bash
# Create backup directory manually
sudo mkdir -p /var/lib/tamandua/config/backups
sudo chown tamandua:tamandua /var/lib/tamandua/config/backups
```

### Checksum Mismatch

If backups fail verification:

```bash
# List backups to find corrupted versions
tamandua-agent config-list

# Remove corrupted backup manually
rm /var/lib/tamandua/config/backups/config_v0003.toml

# Create fresh backup
# (will happen automatically on next config change)
```

### Health Check Always Failing

If auto-rollback keeps triggering:

1. Check network connectivity to backend
2. Review collector logs for panics
3. Verify resource limits aren't too low
4. Temporarily disable auto-rollback and investigate

```rust
manager.set_auto_rollback(false);
```

### Cannot Restore Old Version

If restore fails with "backup not found":

```bash
# Verify backup exists
ls -la /var/lib/tamandua/config/backups/

# Check metadata
cat /var/lib/tamandua/config/backups/metadata.json
```

## Integration with Backend

### Server-Side Config Push

When pushing config from the backend, include metadata:

```elixir
# Phoenix backend
def push_config_update(agent_id, new_config) do
  payload = %{
    type: "config_update",
    config: new_config,
    metadata: %{
      source: "server-push",
      triggered_by: "#{current_user.email}",
      description: "Global policy update - enable DLP scanning"
    }
  }

  AgentChannel.push(agent_id, payload)
end
```

### Rollback Alerts

The agent sends alerts to the backend when rollback occurs:

```json
{
  "event_type": "config_rollback",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-20T12:30:45Z",
  "backup_version": 5,
  "health_failure_reason": "connection_timeout",
  "details": "Failed to connect to backend within 30 seconds"
}
```

### Backend Dashboard

Display config history and rollback events in the admin dashboard:

- Timeline of config changes
- Rollback frequency metrics
- Failed health check reasons
- Version diff viewer

## Performance Considerations

- **Backup Creation**: < 50ms (copy + checksum calculation)
- **Validation**: < 100ms for typical config
- **Health Check**: 30s-2min (configurable)
- **Rollback**: < 200ms (restore + reload)
- **Storage**: ~10-50 KB per backup (depending on config size)

## Security

- Backups stored in protected directory (root/system access only)
- SHA256 checksums prevent tampering
- Metadata tracks all changes for audit trail
- No sensitive data (tokens, passwords) in backup metadata

## Future Enhancements

- [ ] Encrypted backups for sensitive configurations
- [ ] Remote backup storage (S3, Azure Blob)
- [ ] Configurable backup retention policies
- [ ] Diff viewer in web UI
- [ ] A/B testing for config changes (gradual rollout)
- [ ] Scheduled config changes with automatic rollback
