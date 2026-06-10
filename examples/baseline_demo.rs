//! Baseline Learning Demo
//!
//! Demonstrates the baseline learning and anomaly detection system.
//!
//! Run with: cargo run --example baseline_demo

use std::collections::HashMap;
use tamandua_agent::baseline::{BaselineConfig, BaselineEngine};
use tamandua_agent::collectors::{
    EventPayload, EventType, FileEvent, NetworkEvent, ProcessEvent, Severity, TelemetryEvent,
};
use tempfile::TempDir;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("baseline_demo=info,tamandua_agent=debug")
        .init();

    println!("=== Tamandua Baseline Learning Demo ===\n");

    // Create temporary database
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("demo.db");

    // Configure baseline engine
    let mut config = BaselineConfig::default();
    config.min_samples = 10; // Lower for demo
    config.learning_period_days = 7;
    config.z_score_threshold = 3.0;

    println!("Configuration:");
    println!("  Learning Period: {} days", config.learning_period_days);
    println!("  Min Samples: {}", config.min_samples);
    println!("  Z-Score Threshold: {}\n", config.z_score_threshold);

    // Create and start engine
    let mut engine = BaselineEngine::new(db_path, config)?;
    engine.start().await?;

    println!("=== Phase 1: Learning Normal Behavior ===\n");

    // Simulate normal Chrome behavior
    println!("Learning normal Chrome behavior...");
    for i in 0..15 {
        let event = create_process_event("chrome", 500.0 + (i as f64 * 2.0), 15.0);
        engine.learn_event(&event).await?;

        if i % 5 == 0 {
            println!("  Learned {} samples", i + 1);
        }
    }

    // Simulate normal network behavior
    println!("\nLearning normal network behavior...");
    for i in 0..15 {
        let event = create_network_event("chrome", "8.8.8.8", 443);
        engine.learn_event(&event).await?;

        if i % 5 == 0 {
            println!("  Learned {} samples", i + 1);
        }
    }

    // Get statistics
    let stats = engine.get_statistics().await?;
    println!("\nBaseline Statistics:");
    println!("  Process Baselines: {}", stats.process_baselines);
    println!("  Network Baselines: {}", stats.network_baselines);
    println!("  Total Samples: {}", stats.total_samples);

    println!("\n=== Phase 2: Anomaly Detection ===\n");

    // Test normal behavior (should not trigger anomaly)
    println!("Testing normal Chrome behavior (510 MB)...");
    let normal_event = create_process_event("chrome", 510.0, 15.0);
    let anomalies = engine.detect_anomalies(&normal_event).await?;

    if anomalies.is_empty() {
        println!("  ✓ No anomalies detected (as expected)\n");
    } else {
        println!("  ✗ Unexpected anomaly detected!\n");
    }

    // Test anomalous memory usage
    println!("Testing anomalous Chrome behavior (1000 MB)...");
    let anomalous_event = create_process_event("chrome", 1000.0, 15.0);
    let anomalies = engine.detect_anomalies(&anomalous_event).await?;

    if !anomalies.is_empty() {
        println!("  ✓ Anomaly detected!");
        for anomaly in &anomalies {
            println!("\n  Anomaly Details:");
            println!("    Type: {}", anomaly.anomaly_type);
            println!("    Score: {:.1}", anomaly.score);
            println!("    Z-Score: {:.2}", anomaly.z_score);
            println!("    Expected: {:.1} MB", anomaly.expected);
            println!("    Observed: {:.1} MB", anomaly.observed);
            println!("    Description: {}", anomaly.description);
        }
    } else {
        println!("  ✗ No anomaly detected (unexpected)");
    }

    // Test unknown network destination
    println!("\n\nTesting unknown network destination (1.2.3.4:8080)...");
    let unknown_network = create_network_event("chrome", "1.2.3.4", 8080);
    let anomalies = engine.detect_anomalies(&unknown_network).await?;

    if !anomalies.is_empty() {
        println!("  ✓ Anomaly detected!");
        for anomaly in &anomalies {
            println!("\n  Anomaly Details:");
            println!("    Type: {}", anomaly.anomaly_type);
            println!("    Score: {:.1}", anomaly.score);
            println!("    Description: {}", anomaly.description);
        }
    } else {
        println!("  ✗ No anomaly detected (may be expected during learning)");
    }

    println!("\n=== Demo Complete ===\n");

    Ok(())
}

fn create_process_event(name: &str, memory_mb: f64, cpu_percent: f64) -> TelemetryEvent {
    let mut metadata = HashMap::new();
    metadata.insert("memory_mb".to_string(), serde_json::json!(memory_mb));
    metadata.insert("cpu_percent".to_string(), serde_json::json!(cpu_percent));

    TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: EventType::ProcessStart,
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
        severity: Severity::Info,
        payload: EventPayload::Process(ProcessEvent {
            pid: 1234,
            ppid: 1,
            name: name.to_string(),
            path: format!("C:\\Program Files\\{}\\{}.exe", name, name),
            cmdline: format!("{}.exe", name),
            user: "demo_user".to_string(),
            sha256: vec![0u8; 32],
            entropy: 7.5,
            is_elevated: false,
            parent_name: Some("explorer.exe".to_string()),
            parent_path: Some("C:\\Windows\\explorer.exe".to_string()),
            is_signed: true,
            signer: Some("Demo Corp".to_string()),
            metadata: Some(metadata.clone()),
        }),
        detections: vec![],
        metadata: Some(metadata),
    }
}

fn create_network_event(process_name: &str, dest: &str, port: u16) -> TelemetryEvent {
    TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: EventType::NetworkConnection,
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
        severity: Severity::Info,
        payload: EventPayload::Network(NetworkEvent {
            pid: 1234,
            process_name: process_name.to_string(),
            process_path: format!("C:\\Program Files\\{}\\{}.exe", process_name, process_name),
            local_addr: "192.168.1.100".to_string(),
            local_port: 54321,
            remote_addr: dest.to_string(),
            remote_port: port,
            protocol: "TCP".to_string(),
            direction: "outbound".to_string(),
            bytes_sent: 1024,
            bytes_received: 2048,
            metadata: None,
        }),
        detections: vec![],
        metadata: None,
    }
}
