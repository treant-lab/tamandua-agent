//! Benchmarks for telemetry collectors
//!
//! Measures performance of various collectors to ensure they meet
//! performance requirements (<5% CPU overhead target).
//!
//! Run with: cargo bench --bench collectors

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;
use tamandua_agent::collectors::*;

fn benchmark_process_enumeration(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_enumeration");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("enumerate_processes", |b| {
        b.iter(|| {
            let processes = tamandua_agent::collectors::process::enumerate_processes();
            black_box(processes);
        });
    });

    group.bench_function("enumerate_with_metadata", |b| {
        b.iter(|| {
            let processes =
                tamandua_agent::collectors::process::enumerate_processes_with_metadata();
            black_box(processes);
        });
    });

    group.finish();
}

fn benchmark_network_enumeration(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_enumeration");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("enumerate_network_connections", |b| {
        b.iter(|| {
            let connections = tamandua_agent::collectors::network::enumerate_network_connections();
            black_box(connections);
        });
    });

    group.bench_function("enumerate_with_filtering", |b| {
        b.iter(|| {
            let connections =
                tamandua_agent::collectors::network::enumerate_network_connections_filtered();
            black_box(connections);
        });
    });

    group.finish();
}

fn benchmark_file_monitoring(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_monitoring");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("enumerate_recent_files", |b| {
        b.iter(|| {
            let files = tamandua_agent::collectors::file::enumerate_recent_files();
            black_box(files);
        });
    });

    group.finish();
}

fn benchmark_event_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_serialization");

    // Process event
    let process_event = TelemetryEvent::new(
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

    group.bench_function("process_event", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&process_event).unwrap();
            black_box(json);
        });
    });

    // Network event
    let network_event = TelemetryEvent::new(
        EventType::NetworkConnect,
        Severity::Info,
        EventPayload::Network(NetworkEvent {
            pid: 1234,
            process_name: "chrome.exe".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_port: 50000,
            remote_ip: "8.8.8.8".to_string(),
            remote_port: 443,
            protocol: "tcp".to_string(),
            direction: "outbound".to_string(),
            bytes_sent: 0,
            bytes_received: 0,
        }),
    );

    group.bench_function("network_event", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&network_event).unwrap();
            black_box(json);
        });
    });

    group.finish();
}

fn benchmark_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing");

    for size in [10, 50, 100, 500].iter() {
        let events: Vec<TelemetryEvent> = (0..*size)
            .map(|i| {
                TelemetryEvent::new(
                    EventType::ProcessCreate,
                    Severity::Info,
                    EventPayload::Process(ProcessEvent {
                        pid: 1000 + i,
                        ppid: 1,
                        name: format!("test_{}.exe", i),
                        path: format!("C:\\Windows\\test_{}.exe", i),
                        cmdline: "test".to_string(),
                        user: "SYSTEM".to_string(),
                        sha256: vec![0u8; 32],
                        entropy: 5.5,
                        is_elevated: false,
                        parent_name: None,
                        parent_path: None,
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
                )
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &events, |b, events| {
            b.iter(|| {
                let json = serde_json::to_string(&events).unwrap();
                black_box(json);
            });
        });
    }

    group.finish();
}

fn benchmark_sha256_calculation(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    let mut group = c.benchmark_group("hash_calculation");
    group.measurement_time(Duration::from_secs(15));

    for size in [1024, 10240, 102400, 1048576, 10485760].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = Sha256::new();
                hasher.update(data);
                let result = hasher.finalize();
                black_box(result);
            });
        });
    }

    group.finish();
}

fn benchmark_entropy_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_calculation");
    group.measurement_time(Duration::from_secs(15));

    for size in [1024, 10240, 102400, 1048576].iter() {
        // High entropy data
        let random_data: Vec<u8> = (0..=255).cycle().take(*size).collect();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("high_entropy", size),
            &random_data,
            |b, data| {
                b.iter(|| {
                    let entropy = tamandua_agent::analyzers::calculate_entropy(data);
                    black_box(entropy);
                });
            },
        );

        // Low entropy data
        let repetitive_data = vec![0xAB; *size];
        group.bench_with_input(
            BenchmarkId::new("low_entropy", size),
            &repetitive_data,
            |b, data| {
                b.iter(|| {
                    let entropy = tamandua_agent::analyzers::calculate_entropy(data);
                    black_box(entropy);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark YARA rule scanning
#[cfg(feature = "yara")]
fn benchmark_yara_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("yara_scanning");
    group.measurement_time(Duration::from_secs(20));

    let test_rules = r#"
        rule SuspiciousString {
            strings:
                $s1 = "malware" nocase
                $s2 = "suspicious" nocase
            condition:
                any of them
        }
    "#;

    for size in [1024, 10240, 102400, 1048576].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("scan", size), &data, |b, data| {
            b.iter(|| {
                // Scan would be performed here
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark concurrent collector performance
fn benchmark_concurrent_collection(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_collection");
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("parallel_collectors", |b| {
        b.iter(|| {
            use std::thread;
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    thread::spawn(|| {
                        let processes = tamandua_agent::collectors::process::enumerate_processes();
                        black_box(processes);
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });

    group.finish();
}

/// Benchmark end-to-end event pipeline
fn benchmark_event_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_pipeline");
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("collect_serialize_send", |b| {
        b.iter(|| {
            // Collect event
            let processes = tamandua_agent::collectors::process::enumerate_processes();

            // Create telemetry event
            let events: Vec<TelemetryEvent> = processes
                .into_iter()
                .take(10)
                .map(|p| {
                    TelemetryEvent::new(
                        EventType::ProcessCreate,
                        Severity::Info,
                        EventPayload::Process(p),
                    )
                })
                .collect();

            // Serialize
            let json = serde_json::to_string(&events).unwrap();
            black_box(json);
        });
    });

    group.finish();
}

#[cfg(not(feature = "yara"))]
criterion_group!(
    benches,
    benchmark_process_enumeration,
    benchmark_network_enumeration,
    benchmark_file_monitoring,
    benchmark_event_serialization,
    benchmark_batch_processing,
    benchmark_sha256_calculation,
    benchmark_entropy_calculation,
    benchmark_concurrent_collection,
    benchmark_event_pipeline,
);

#[cfg(feature = "yara")]
criterion_group!(
    benches,
    benchmark_process_enumeration,
    benchmark_network_enumeration,
    benchmark_file_monitoring,
    benchmark_event_serialization,
    benchmark_batch_processing,
    benchmark_sha256_calculation,
    benchmark_entropy_calculation,
    benchmark_yara_scanning,
    benchmark_concurrent_collection,
    benchmark_event_pipeline,
);

criterion_main!(benches);
