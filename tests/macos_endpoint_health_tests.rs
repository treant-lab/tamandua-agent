//! macOS Endpoint Security/System Extension health contract tests.

use std::collections::HashMap;
use tamandua_agent::collectors::health::DriverHealthEvent;

#[test]
fn endpoint_health_payload_preserves_macos_driver_fields() {
    let event = DriverHealthEvent {
        supported: true,
        loaded: true,
        connected: false,
        state: "loaded_no_telemetry".to_string(),
        platform: Some("macos".to_string()),
        provider: Some("endpoint_security_sysext".to_string()),
        service_name: Some("com.tamandua.agent.filemonitor".to_string()),
        entitlement_status: Some("framework_available".to_string()),
        lab_level: 0,
        feature_level: "endpoint_security".to_string(),
        writable_read_index: false,
        protocol_version: 1,
        buffer_size: 0,
        write_index: 0,
        read_index: 0,
        sequence_number: 0,
        flags: 0,
        events_consumed: 0,
        events_converted: 0,
        events_skipped: 0,
        events_malformed: 0,
        channel_drops: 0,
        raw_event_type_counts: HashMap::new(),
        converted_event_type_counts: HashMap::new(),
        skipped_event_type_counts: HashMap::new(),
        kernel_events_written: 0,
        kernel_events_dropped: 0,
        reconnect_attempts: 0,
        consecutive_failures: 1,
        last_event_at: None,
        last_error: Some("System Extension Mach service is not currently reachable".to_string()),
    };

    let json = serde_json::to_value(&event).expect("driver health should serialize");

    assert_eq!(json["platform"], "macos");
    assert_eq!(json["provider"], "endpoint_security_sysext");
    assert_eq!(json["service_name"], "com.tamandua.agent.filemonitor");
    assert_eq!(json["entitlement_status"], "framework_available");
    assert_eq!(json["state"], "loaded_no_telemetry");
}

#[cfg(target_os = "macos")]
#[test]
fn endpoint_collectors_are_enabled_by_default_on_macos() {
    use tamandua_agent::collectors::status::{CollectorCapabilityStatus, CollectorState};
    use tamandua_agent::config::AgentConfig;

    let config = AgentConfig::default();
    let status = CollectorCapabilityStatus::from_config(&config);

    let endpoint_security = status
        .collectors
        .iter()
        .find(|collector| collector.name == "endpoint_security")
        .expect("endpoint_security collector status should be present");
    assert!(endpoint_security.supported);
    assert!(endpoint_security.enabled);
    assert_eq!(endpoint_security.state, CollectorState::Enabled);

    let sysext_bridge = status
        .collectors
        .iter()
        .find(|collector| collector.name == "sysext_bridge")
        .expect("sysext_bridge collector status should be present");
    assert!(sysext_bridge.supported);
    assert!(sysext_bridge.enabled);
    assert_eq!(sysext_bridge.state, CollectorState::Enabled);
}
