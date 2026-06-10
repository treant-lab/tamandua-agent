//! Performance Optimization Benchmarks
//!
//! Benchmark suite for performance optimizations:
//! - Lock-free queues vs. Mutex-based queues
//! - Memory pooling vs. direct allocation
//! - SIMD hash calculation vs. standard
//! - CPU affinity impact

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tamandua_agent::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};
use tamandua_agent::performance::*;
use tempfile::NamedTempFile;

// Helper: Create test event
fn create_test_event(id: usize) -> TelemetryEvent {
    TelemetryEvent::new(
        EventType::ProcessCreate,
        Severity::Info,
        EventPayload::Process(ProcessEvent {
            pid: id as u32,
            ppid: 1,
            name: format!("test-{}.exe", id),
            path: format!("/tmp/test-{}.exe", id),
            cmdline: format!("test-{}.exe --arg", id),
            user: "root".to_string(),
            sha256: vec![0u8; 32],
            entropy: 4.5,
            is_elevated: false,
            parent_name: Some("init".to_string()),
            parent_path: Some("/sbin/init".to_string()),
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
}

// Benchmark: Lock-free queue vs Mutex queue
fn bench_queue_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue_throughput");

    for size in [1000, 10000, 100000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        // Lock-free queue
        group.bench_with_input(BenchmarkId::new("lockfree", size), size, |b, &size| {
            b.iter(|| {
                let queue = lockfree_queue::create_telemetry_queue(size);
                for i in 0..size {
                    let _ = queue.push(create_test_event(i));
                }
                let mut count = 0;
                while queue.pop().is_some() {
                    count += 1;
                }
                black_box(count);
            });
        });

        // Mutex-based queue (baseline)
        group.bench_with_input(BenchmarkId::new("mutex", size), size, |b, &size| {
            b.iter(|| {
                let queue = Arc::new(Mutex::new(Vec::with_capacity(size)));
                for i in 0..size {
                    queue.lock().unwrap().push(create_test_event(i));
                }
                let mut count = 0;
                while !queue.lock().unwrap().is_empty() {
                    queue.lock().unwrap().pop();
                    count += 1;
                }
                black_box(count);
            });
        });
    }

    group.finish();
}

// Benchmark: Concurrent queue access
fn bench_queue_concurrent(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue_concurrent");

    let num_threads = 4;
    let items_per_thread = 10000;

    // Lock-free queue
    group.bench_function("lockfree_4threads", |b| {
        b.iter(|| {
            let queue = lockfree_queue::create_telemetry_queue(items_per_thread * num_threads);
            let queue_clone = queue.clone();

            // Producer threads
            let mut producers = Vec::new();
            for _ in 0..num_threads {
                let q = queue.clone();
                producers.push(thread::spawn(move || {
                    for i in 0..items_per_thread {
                        let _ = q.push(create_test_event(i));
                    }
                }));
            }

            // Consumer thread
            let consumer = thread::spawn(move || {
                let mut count = 0;
                while count < items_per_thread * num_threads {
                    if queue_clone.pop().is_some() {
                        count += 1;
                    }
                }
                count
            });

            for p in producers {
                p.join().unwrap();
            }
            let count = consumer.join().unwrap();
            black_box(count);
        });
    });

    // Mutex-based queue
    group.bench_function("mutex_4threads", |b| {
        b.iter(|| {
            let queue = Arc::new(Mutex::new(Vec::with_capacity(
                items_per_thread * num_threads,
            )));
            let queue_clone = Arc::clone(&queue);

            // Producer threads
            let mut producers = Vec::new();
            for _ in 0..num_threads {
                let q = Arc::clone(&queue);
                producers.push(thread::spawn(move || {
                    for i in 0..items_per_thread {
                        q.lock().unwrap().push(create_test_event(i));
                    }
                }));
            }

            // Consumer thread
            let consumer = thread::spawn(move || {
                let mut count = 0;
                while count < items_per_thread * num_threads {
                    if !queue_clone.lock().unwrap().is_empty() {
                        queue_clone.lock().unwrap().pop();
                        count += 1;
                    }
                }
                count
            });

            for p in producers {
                p.join().unwrap();
            }
            let count = consumer.join().unwrap();
            black_box(count);
        });
    });

    group.finish();
}

// Benchmark: Memory pool vs direct allocation
fn bench_memory_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_pool");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        // With memory pool
        group.bench_with_input(BenchmarkId::new("pooled", size), size, |b, &size| {
            let pool = BufferPool::new(1000, 4096);
            b.iter(|| {
                for _ in 0..size {
                    let mut buf = pool.acquire();
                    buf.extend_from_slice(&[0u8; 1024]);
                    black_box(&buf);
                }
            });
        });

        // Direct allocation
        group.bench_with_input(BenchmarkId::new("direct", size), size, |b, &size| {
            b.iter(|| {
                for _ in 0..size {
                    let mut buf = Vec::with_capacity(4096);
                    buf.extend_from_slice(&[0u8; 1024]);
                    black_box(&buf);
                }
            });
        });
    }

    group.finish();
}

// Benchmark: SIMD hash calculation
fn bench_simd_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_hash");

    for size in [1024, 65536, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let data = vec![0x42u8; *size];

        // SHA256
        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, data| {
            let hasher = SimdHasher::new();
            b.iter(|| {
                let hash = hasher.sha256(black_box(data));
                black_box(hash);
            });
        });

        // MD5
        group.bench_with_input(BenchmarkId::new("md5", size), &data, |b, data| {
            let hasher = SimdHasher::new();
            b.iter(|| {
                let hash = hasher.md5(black_box(data));
                black_box(hash);
            });
        });
    }

    group.finish();
}

// Benchmark: Entropy calculation
fn bench_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy");

    for size in [1024, 65536, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        // High entropy data
        let high_entropy: Vec<u8> = (0..=255).cycle().take(*size).collect();

        // Low entropy data
        let low_entropy = vec![0x42u8; *size];

        let hasher = SimdHasher::new();

        group.bench_with_input(
            BenchmarkId::new("high_entropy", size),
            &high_entropy,
            |b, data| {
                b.iter(|| {
                    let entropy = hasher.entropy(black_box(data));
                    black_box(entropy);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("low_entropy", size),
            &low_entropy,
            |b, data| {
                b.iter(|| {
                    let entropy = hasher.entropy(black_box(data));
                    black_box(entropy);
                });
            },
        );
    }

    group.finish();
}

// Benchmark: File hashing
fn bench_file_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_hash");

    for size in [1024, 65536, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        // Create temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = vec![0x42u8; *size];
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        group.bench_with_input(
            BenchmarkId::new("hash_file", size),
            temp_file.path(),
            |b, path| {
                let hasher = SimdHasher::new();
                b.iter(|| {
                    let hashes = hasher.hash_file(black_box(path)).unwrap();
                    black_box(hashes);
                });
            },
        );
    }

    group.finish();
}

// Benchmark: Performance metrics overhead
fn bench_metrics_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_overhead");

    let metrics = PerformanceMetrics::new();

    group.bench_function("record_allocation", |b| {
        b.iter(|| {
            metrics.record_allocation(black_box(1024));
        });
    });

    group.bench_function("record_event_enqueued", |b| {
        b.iter(|| {
            metrics.record_event_enqueued();
        });
    });

    group.bench_function("record_collector_cpu_time", |b| {
        b.iter(|| {
            metrics.record_collector_cpu_time(black_box("process"), Duration::from_micros(100));
        });
    });

    group.bench_function("snapshot", |b| {
        b.iter(|| {
            let snapshot = metrics.snapshot();
            black_box(snapshot);
        });
    });

    group.finish();
}

// Benchmark: Event pool
fn bench_event_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_pool");

    let pool = EventPool::new(1000);

    group.bench_function("acquire_return", |b| {
        b.iter(|| {
            let event = pool.acquire();
            black_box(&event);
        });
    });

    group.bench_function("acquire_modify_return", |b| {
        b.iter(|| {
            let mut event = pool.acquire();
            event.event_id = black_box("test-id".to_string());
            event.timestamp = black_box(123456);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_queue_throughput,
    bench_queue_concurrent,
    bench_memory_pool,
    bench_simd_hash,
    bench_entropy,
    bench_file_hash,
    bench_metrics_overhead,
    bench_event_pool,
);

criterion_main!(benches);
