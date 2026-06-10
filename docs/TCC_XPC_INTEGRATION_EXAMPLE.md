# TCC/XPC Monitor Integration Example

This document shows how to integrate the TCC and XPC monitors into the main agent collector loop.

## Integration into main.rs

```rust
use tamandua_agent::collectors::{tcc_monitor::TccMonitor, xpc_monitor::XpcMonitor};
use tamandua_agent::config::AgentConfig;

async fn start_collectors(config: &AgentConfig, backend_client: Arc<BackendClient>) {
    // ... other collector initialization ...

    // macOS-specific collectors
    #[cfg(target_os = "macos")]
    {
        // Start TCC monitor
        if config.tcc_monitor_interval_seconds.is_some() {
            let mut tcc_monitor = TccMonitor::new(config);
            let backend = backend_client.clone();

            tokio::spawn(async move {
                info!("Starting TCC monitor");
                while let Some(event) = tcc_monitor.next_event().await {
                    if let Err(e) = backend.send_telemetry(&[event]).await {
                        warn!(error = %e, "Failed to send TCC event");
                    }
                }
            });
        }

        // Start XPC monitor
        if config.xpc_monitor_interval_seconds.is_some() {
            let mut xpc_monitor = XpcMonitor::new(config);
            let backend = backend_client.clone();

            tokio::spawn(async move {
                info!("Starting XPC monitor");
                while let Some(event) = xpc_monitor.next_event().await {
                    if let Err(e) = backend.send_telemetry(&[event]).await {
                        warn!(error = %e, "Failed to send XPC event");
                    }
                }
            });
        }
    }

    // ... other collectors ...
}
```

## Configuration Example

### agent.toml

```toml
# Agent configuration
agent_id = "macos-mbp-001"
server_url = "wss://tamandua.example.com/socket/agent"

# macOS TCC monitoring (default: 30 seconds)
tcc_monitor_interval_seconds = 30

# macOS XPC service monitoring (default: 60 seconds)
xpc_monitor_interval_seconds = 60

# Performance profile affects sub-collectors
performance_profile = "balanced"

# Enable Full Disk Access required for system TCC.db
# Grant via: System Preferences > Security & Privacy > Privacy > Full Disk Access
```

### Performance Profile Impact

**Aggressive Profile:**
- TCC interval: 15 seconds
- XPC interval: 30 seconds
- Full service detail extraction enabled

**Balanced Profile (default):**
- TCC interval: 30 seconds
- XPC interval: 60 seconds
- Standard detail extraction

**Lightweight Profile:**
- TCC interval: 60 seconds
- XPC interval: 120 seconds
- Minimal detail extraction

## Event Pipeline

```
┌─────────────────┐
│   TCC.db Poll   │
│  (30s interval) │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Parse Entries  │
│ (SQLite query)  │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Detect Changes  │
│ (diff vs cache) │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Risk Assessment│
│  (0.0 - 1.0)   │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Create Event   │
│ (TelemetryEvent)│
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Backend Client  │
│  (WebSocket)   │
└─────────────────┘
```

## Backend Event Processing

### Elixir Backend Handler

```elixir
# lib/tamandua_server/telemetry/tcc_handler.ex

defmodule TamanduaServer.Telemetry.TccHandler do
  @moduledoc """
  Handles TCC permission change events from macOS agents.
  """

  alias TamanduaServer.Alerts

  def handle_tcc_event(event, agent_id) do
    %{
      "service" => service,
      "client" => client,
      "auth_value" => auth_value,
      "is_high_risk" => is_high_risk
    } = event.payload

    # Create alert for high-risk permissions
    if is_high_risk and auth_value == "allowed" do
      Alerts.create_alert(%{
        agent_id: agent_id,
        severity: "high",
        title: "High-Risk TCC Permission Granted",
        description: "#{client} granted #{service} permission",
        mitre_tactics: ["TA0005"], # Defense Evasion
        mitre_techniques: ["T1562"], # Impair Defenses
        metadata: event.payload
      })
    end

    # Store in telemetry database
    insert_tcc_event(event, agent_id)
  end
end
```

### XPC Event Handler

```elixir
# lib/tamandua_server/telemetry/xpc_handler.ex

defmodule TamanduaServer.Telemetry.XpcHandler do
  @moduledoc """
  Handles XPC service events from macOS agents.
  """

  alias TamanduaServer.Alerts

  def handle_xpc_event(event, agent_id) do
    %{
      "service_label" => label,
      "service_type" => type,
      "is_suspicious" => suspicious,
      "risk_score" => risk_score
    } = event.payload

    # Create alert for suspicious services
    if suspicious and risk_score >= 0.7 do
      Alerts.create_alert(%{
        agent_id: agent_id,
        severity: "high",
        title: "Suspicious XPC Service Detected",
        description: "New #{type} registered: #{label}",
        mitre_tactics: ["TA0003"], # Persistence
        mitre_techniques: ["T1543.001"], # Launch Daemon
        metadata: event.payload
      })
    end

    # Store in telemetry database
    insert_xpc_event(event, agent_id)
  end
end
```

## Dashboard Integration

### TCC Permission Timeline

```jsx
// dashboard/components/TccTimeline.tsx

export function TccTimeline({ agentId }) {
  const { data } = useQuery(['tcc-events', agentId], () =>
    fetchTccEvents(agentId)
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>TCC Permission Changes</CardTitle>
      </CardHeader>
      <CardContent>
        <Timeline>
          {data?.events.map(event => (
            <TimelineItem key={event.id}>
              <Badge variant={event.is_high_risk ? "destructive" : "secondary"}>
                {event.service_display}
              </Badge>
              <span>{event.client}</span>
              <span className={event.auth_value === 'allowed' ? 'text-green' : 'text-red'}>
                {event.auth_value}
              </span>
              <span>{formatTimestamp(event.last_modified)}</span>
            </TimelineItem>
          ))}
        </Timeline>
      </CardContent>
    </Card>
  );
}
```

### XPC Service Registry

```jsx
// dashboard/components/XpcRegistry.tsx

export function XpcRegistry({ agentId }) {
  const { data } = useQuery(['xpc-services', agentId], () =>
    fetchXpcServices(agentId)
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>XPC Services</CardTitle>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={[
            { header: 'Label', accessor: 'service_label' },
            { header: 'Type', accessor: 'service_type' },
            { header: 'PID', accessor: 'pid' },
            { header: 'Risk', accessor: row => (
              <Badge variant={row.risk_score >= 0.7 ? 'destructive' : 'secondary'}>
                {(row.risk_score * 100).toFixed(0)}%
              </Badge>
            )}
          ]}
          data={data?.services || []}
        />
      </CardContent>
    </Card>
  );
}
```

## Sigma Rules

### High-Risk TCC Permission

```yaml
# rules/sigma/macos/tcc_high_risk_permission.yml

title: High-Risk TCC Permission Granted
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: experimental
description: Detects when a high-risk TCC permission is granted to an application
author: Tamandua Security Team
date: 2026-02-20
tags:
  - attack.defense_evasion
  - attack.t1562
logsource:
  product: tamandua
  category: tcc
detection:
  selection:
    event_type: tcc_change
    service:
      - kTCCServiceSystemPolicyAllFiles  # Full Disk Access
      - kTCCServiceScreenCapture         # Screen Recording
      - kTCCServiceAccessibility         # Accessibility
    auth_value: allowed
  condition: selection
falsepositives:
  - Legitimate applications requiring elevated permissions
level: high
```

### Suspicious XPC Service

```yaml
# rules/sigma/macos/xpc_suspicious_service.yml

title: Suspicious XPC Service Registration
id: b2c3d4e5-f6a7-8901-2345-678901bcdefg
status: experimental
description: Detects registration of third-party system daemons or suspicious XPC services
author: Tamandua Security Team
date: 2026-02-20
tags:
  - attack.persistence
  - attack.t1543.001
logsource:
  product: tamandua
  category: xpc
detection:
  selection:
    event_type: xpc_service
    service_type: system_daemon
    is_suspicious: true
  condition: selection
falsepositives:
  - Legitimate third-party security software
  - Enterprise management agents
level: high
```

## Testing Commands

### Manual TCC Testing

```bash
# Reset camera permission for test app
tccutil reset Camera com.test.app

# Grant camera permission
tccutil grant Camera com.test.app

# Check agent logs
tail -f /var/log/tamandua/agent.log | grep tcc_change
```

### Manual XPC Testing

```bash
# List active XPC services
launchctl list

# Load a test launchd plist
sudo launchctl load /Library/LaunchDaemons/com.test.daemon.plist

# Check agent logs
tail -f /var/log/tamandua/agent.log | grep xpc_service
```

### Integration Test

```bash
# Run full integration test suite
cargo test --test integration_tests --features macos

# Run specific test
cargo test test_tcc_monitor_integration --features macos
```

## Deployment Checklist

- [ ] Grant Full Disk Access to Tamandua agent (System Preferences)
- [ ] Verify TCC.db is readable (`sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access LIMIT 1"`)
- [ ] Verify launchctl access (`launchctl list | head`)
- [ ] Configure polling intervals in agent.toml
- [ ] Enable TCC/XPC monitors in collector config
- [ ] Deploy Sigma rules to backend
- [ ] Configure alert routing for high-risk events
- [ ] Test event pipeline end-to-end
- [ ] Monitor performance impact (<1% CPU expected)
- [ ] Review dashboard widgets for TCC/XPC events
