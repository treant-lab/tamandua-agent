//! Unit tests for telemetry collectors
//!
//! Tests cover all collector types across all platforms:
//! - Process collector (Windows, Linux, macOS)
//! - File collector (all platforms)
//! - Network collector
//! - DNS collector
//! - Registry collector (Windows only)
//! - ETW collector (Windows only)
//! - eBPF collector (Linux only)
//! - Endpoint Security collector (macOS only)

mod process;
mod file;
mod network;
mod dns;

#[cfg(target_os = "windows")]
mod registry;

#[cfg(target_os = "windows")]
mod etw;

#[cfg(target_os = "linux")]
mod ebpf;

#[cfg(target_os = "macos")]
mod endpoint_security;

mod memory;
mod injection;
mod persistence;
mod defense_evasion;

use tamandua_agent::collectors::*;

/// Test that TelemetryEvent can be created and serialized
#[test]
fn test_telemetry_event_creation() {
    let event = TelemetryEvent::new(
        EventType::ProcessCreate,
        Severity::Info,
        EventPayload::Process(ProcessEvent {
            pid: 1234,
            ppid: 1,
            name: "test.exe".to_string(),
            path: "C:\\Windows\\test.exe".to_string(),
            cmdline: "test.exe --arg".to_string(),
            user: "SYSTEM".to_string(),
            sha256: vec![0u8; 32],
            entropy: 5.5,
            is_elevated: false,
            parent_name: Some("parent.exe".to_string()),
            parent_path: Some("C:\\Windows\\parent.exe".to_string()),
            is_signed: false,
            signer: None,
            start_time: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        }),
    );

    assert_eq!(event.event_type, EventType::ProcessCreate);
    assert_eq!(event.severity, Severity::Info);
    assert!(!event.event_id.is_empty());
}

/// Test event serialization to JSON
#[test]
fn test_event_serialization() {
    let event = TelemetryEvent::new(
        EventType::FileCreate,
        Severity::Info,
        EventPayload::File(FileEvent {
            path: "C:\\Temp\\test.txt".to_string(),
            old_path: None,
            operation: "create".to_string(),
            pid: 1234,
            process_name: "notepad.exe".to_string(),
            sha256: vec![0u8; 32],
            size: 1024,
            entropy: 5.0,
            file_type: "text/plain".to_string(),
        }),
    );

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("file_create"));
    assert!(json.contains("test.txt"));
}

/// Test event deserialization from JSON
#[test]
fn test_event_deserialization() {
    let json = r#"{
        "event_id": "test-123",
        "event_type": "process_create",
        "timestamp": 1000000,
        "severity": "high",
        "payload": {
            "pid": 1234,
            "ppid": 1,
            "name": "test.exe",
            "path": "C:\\Windows\\test.exe",
            "cmdline": "test.exe",
            "user": "SYSTEM",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "entropy": 5.5,
            "is_elevated": false,
            "parent_name": null,
            "parent_path": null,
            "is_signed": false,
            "signer": null,
            "start_time": 0,
            "cpu_usage": 0.0,
            "memory_bytes": 0
        },
        "detections": []
    }"#;

    let event: TelemetryEvent = serde_json::from_str(json).unwrap();
    assert_eq!(event.event_id, "test-123");
    assert_eq!(event.event_type, EventType::ProcessCreate);
}

/// Test adding detections to events
#[test]
fn test_event_detections() {
    let mut event = TelemetryEvent::new(
        EventType::ProcessCreate,
        Severity::High,
        EventPayload::Process(ProcessEvent {
            pid: 1234,
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
            start_time: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        }),
    );

    event.add_detection(Detection {
        detection_type: DetectionType::Behavioral,
        rule_name: "Mimikatz Execution".to_string(),
        confidence: 0.95,
        description: "Detected Mimikatz credential dumping tool".to_string(),
        mitre_tactics: vec!["TA0006".to_string()],
        mitre_techniques: vec!["T1003".to_string()],
    });

    assert_eq!(event.detections.len(), 1);
    assert_eq!(event.detections[0].rule_name, "Mimikatz Execution");
}

/// Test severity levels ordering
#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}
