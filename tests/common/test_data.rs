//! Test data generators for various event types

use tamandua_agent::collectors::*;

/// Generate test process events
pub fn generate_process_events(count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|i| {
            TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid: 1000 + i as u32,
                    ppid: 1,
                    name: format!("test_{}.exe", i),
                    path: format!("C:\\Windows\\test_{}.exe", i),
                    cmdline: format!("test_{}.exe --arg", i),
                    user: "SYSTEM".to_string(),
                    sha256: vec![i as u8; 32],
                    entropy: 5.0 + (i as f32 * 0.1),
                    is_elevated: i % 2 == 0,
                    parent_name: Some("parent.exe".to_string()),
                    parent_path: Some("C:\\Windows\\parent.exe".to_string()),
                    is_signed: i % 3 == 0,
                    signer: if i % 3 == 0 {
                        Some("Microsoft Corporation".to_string())
                    } else {
                        None
                    },
                    start_time: 1000000 + i as u64,
                    cpu_usage: (i as f32 * 0.5) % 100.0,
                    memory_bytes: (i as u64 + 1) * 1024 * 1024,
                    company_name: Some("Test Company".to_string()),
                    file_description: Some("Test Application".to_string()),
                    product_name: Some("Test Product".to_string()),
                    file_version: Some("1.0.0".to_string()),
                    environment: None,
                }),
            )
        })
        .collect()
}

/// Generate test file events
pub fn generate_file_events(count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|i| {
            TelemetryEvent::new(
                EventType::FileCreate,
                Severity::Info,
                EventPayload::File(FileEvent {
                    path: format!("C:\\Temp\\test_{}.txt", i),
                    old_path: None,
                    operation: "create".to_string(),
                    pid: 1234,
                    process_name: "notepad.exe".to_string(),
                    sha256: vec![i as u8; 32],
                    size: (i as u64 + 1) * 1024,
                    entropy: 4.0 + (i as f32 * 0.05),
                    file_type: "text/plain".to_string(),
                }),
            )
        })
        .collect()
}

/// Generate test network events
pub fn generate_network_events(count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|i| {
            TelemetryEvent::new(
                EventType::NetworkConnect,
                Severity::Info,
                EventPayload::Network(NetworkEvent {
                    pid: 1234,
                    process_name: "chrome.exe".to_string(),
                    local_ip: "192.168.1.100".to_string(),
                    local_port: 50000 + i as u16,
                    remote_ip: format!("8.8.{}.{}", (i / 256) % 256, i % 256),
                    remote_port: 443,
                    protocol: "tcp".to_string(),
                    direction: "outbound".to_string(),
                    state: Some("ESTABLISHED".to_string()),
                    bytes_sent: i as u64 * 100,
                    bytes_received: i as u64 * 200,
                    ..Default::default()
                }),
            )
        })
        .collect()
}

/// Generate test DNS events
pub fn generate_dns_events(count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|i| {
            TelemetryEvent::new(
                EventType::DnsQuery,
                Severity::Info,
                EventPayload::Dns(DnsEvent {
                    pid: 1234,
                    process_name: "chrome.exe".to_string(),
                    query: format!("example{}.com", i),
                    query_type: "A".to_string(),
                    responses: vec![format!("192.0.2.{}", i % 256)],
                }),
            )
        })
        .collect()
}

/// Generate test registry events (Windows)
#[cfg(target_os = "windows")]
pub fn generate_registry_events(count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|i| {
            TelemetryEvent::new(
                EventType::RegistrySetValue,
                Severity::Info,
                EventPayload::Registry(RegistryEvent {
                    key_path: format!("HKLM\\Software\\Test\\Key{}", i),
                    value_name: Some(format!("Value{}", i)),
                    value_data: Some(format!("Data{}", i)),
                    operation: "set_value".to_string(),
                    pid: 1234,
                    process_name: "regedit.exe".to_string(),
                }),
            )
        })
        .collect()
}

/// Create a malicious process event for detection testing
pub fn create_malicious_process_event() -> TelemetryEvent {
    TelemetryEvent::new(
        EventType::ProcessCreate,
        Severity::High,
        EventPayload::Process(ProcessEvent {
            pid: 6666,
            ppid: 1,
            name: "mimikatz.exe".to_string(),
            path: "C:\\Temp\\mimikatz.exe".to_string(),
            cmdline: "mimikatz.exe sekurlsa::logonpasswords".to_string(),
            user: "SYSTEM".to_string(),
            sha256: vec![0xAB; 32],
            entropy: 7.8,
            is_elevated: true,
            parent_name: Some("cmd.exe".to_string()),
            parent_path: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
            is_signed: false,
            signer: None,
            start_time: 1000000,
            cpu_usage: 25.0,
            memory_bytes: 10 * 1024 * 1024,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        }),
    )
}

/// Create a ransomware-like file event
pub fn create_ransomware_file_event() -> TelemetryEvent {
    TelemetryEvent::new(
        EventType::FileCreate,
        Severity::Critical,
        EventPayload::File(FileEvent {
            path: "C:\\Users\\test\\Documents\\important.txt.encrypted".to_string(),
            old_path: Some("C:\\Users\\test\\Documents\\important.txt".to_string()),
            operation: "rename".to_string(),
            pid: 5555,
            process_name: "ransomware.exe".to_string(),
            sha256: vec![0xFF; 32],
            size: 1024,
            entropy: 7.95,
            file_type: "application/octet-stream".to_string(),
        }),
    )
}

/// Create a suspicious network connection
pub fn create_c2_network_event() -> TelemetryEvent {
    TelemetryEvent::new(
        EventType::NetworkConnect,
        Severity::High,
        EventPayload::Network(NetworkEvent {
            pid: 4444,
            process_name: "backdoor.exe".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_port: 49152,
            remote_ip: "185.220.101.1".to_string(), // Known malicious IP range
            remote_port: 8080,
            protocol: "tcp".to_string(),
            direction: "outbound".to_string(),
            state: Some("ESTABLISHED".to_string()),
            bytes_sent: 1024,
            bytes_received: 2048,
            ..Default::default()
        }),
    )
}

/// Generate a batch of mixed events
pub fn generate_mixed_events(count: usize) -> Vec<TelemetryEvent> {
    let mut events = Vec::new();

    for i in 0..count {
        match i % 4 {
            0 => events.extend(generate_process_events(1)),
            1 => events.extend(generate_file_events(1)),
            2 => events.extend(generate_network_events(1)),
            3 => events.extend(generate_dns_events(1)),
            _ => unreachable!(),
        }
    }

    events
}

/// Create test configuration
pub fn create_test_config() -> tamandua_agent::config::AgentConfig {
    tamandua_agent::config::AgentConfig {
        agent_id: uuid::Uuid::new_v4().to_string(),
        server_url: "ws://localhost:4000/socket/agent".to_string(),
        auth_token: Some("test-token".to_string()),
        heartbeat_interval_seconds: 30,
        batch_size: 100,
        batch_timeout_seconds: 5,
        reconnect_delay_seconds: 5,
        max_reconnect_attempts: 3,
        local_queue_size: Some(1000),
        yara_enabled: false,
        entropy_check_enabled: true,
        entropy_threshold: 7.5,
        honeyfiles_enabled: false,
        local_analysis_enabled: false,
        health_interval_seconds: 60,
        excluded_paths: vec![],
        excluded_processes: vec![],
        tls: tamandua_agent::config::TlsConfig::default(),
        collectors: tamandua_agent::config::CollectorsConfig::default(),
        transport: tamandua_agent::config::TransportConfig::default(),
        event_triage: tamandua_agent::config::TriageConfig::default(),
    }
}
