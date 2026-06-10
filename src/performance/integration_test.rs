//! Integration tests for performance optimizations

#[cfg(test)]
mod tests {
    use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};
    use crate::performance::*;
    use std::io::Write;
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::NamedTempFile;

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

    #[test]
    fn test_full_stack_integration() {
        // Initialize performance system
        let config = PerformanceConfig::default();
        assert!(initialize(&config).is_ok());
        assert!(is_enabled());

        // Create telemetry queue
        let queue = lockfree_queue::create_telemetry_queue(1000);

        // Create buffer pool
        let buffer_pool = BufferPool::new(100, 4096);

        // Create metrics
        let metrics = PerformanceMetrics::new();

        // Simulate event production and consumption
        for i in 0..100 {
            let event = create_test_event(i);
            metrics.record_event_enqueued();
            assert!(queue.push(event).is_ok());
        }

        let mut consumed = 0;
        while let Some(_event) = queue.pop() {
            metrics.record_event_dequeued();
            consumed += 1;
        }

        assert_eq!(consumed, 100);

        // Check metrics
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.events_enqueued, 100);
        assert_eq!(snapshot.events_dequeued, 100);
        assert_eq!(snapshot.events_dropped, 0);
    }

    #[test]
    fn test_concurrent_producers_consumers() {
        let queue = lockfree_queue::create_telemetry_queue(10000);
        let metrics = PerformanceMetrics::new();

        let num_producers = 4;
        let num_consumers = 2;
        let items_per_producer = 1000;

        // Start producers
        let mut producers = Vec::new();
        for _ in 0..num_producers {
            let q = queue.clone();
            let m = metrics.clone();
            producers.push(thread::spawn(move || {
                for i in 0..items_per_producer {
                    let event = create_test_event(i);
                    if q.push(event).is_ok() {
                        m.record_event_enqueued();
                    } else {
                        m.record_event_dropped();
                    }
                }
            }));
        }

        // Start consumers
        let mut consumers = Vec::new();
        for _ in 0..num_consumers {
            let q = queue.clone();
            let m = metrics.clone();
            consumers.push(thread::spawn(move || {
                let mut count = 0;
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(5) {
                    if q.pop().is_some() {
                        m.record_event_dequeued();
                        count += 1;
                    }
                }
                count
            }));
        }

        // Wait for producers
        for p in producers {
            p.join().unwrap();
        }

        // Wait for consumers
        thread::sleep(Duration::from_millis(100));
        let mut total_consumed = 0;
        for c in consumers {
            total_consumed += c.join().unwrap();
        }

        let snapshot = metrics.snapshot();
        println!(
            "Produced: {}, Consumed: {}, Dropped: {}",
            snapshot.events_enqueued, snapshot.events_dequeued, snapshot.events_dropped
        );

        assert!(total_consumed > 0);
        assert_eq!(snapshot.events_dequeued as usize, total_consumed);
    }

    #[test]
    fn test_cpu_affinity_integration() {
        let mut affinity = CpuAffinity::new(false);
        affinity.set_mapping(CollectorType::Process, vec![0]);

        // Apply affinity (may fail on some systems, that's OK)
        let result = affinity.apply(CollectorType::Process);
        println!("CPU affinity result: {:?}", result);

        // Test NUMA topology detection
        let topology = CpuAffinity::detect_numa_topology();
        println!("NUMA topology: {:?}", topology);
        assert!(topology.is_ok());
    }

    #[test]
    fn test_memory_pool_integration() {
        let buffer_pool = BufferPool::new(100, 4096);
        let event_pool = EventPool::new(100);

        // Test buffer pool
        {
            let mut buf = buffer_pool.acquire();
            buf.extend_from_slice(b"test data");
            assert_eq!(&buf[..], b"test data");
        }

        // Buffer returned to pool
        let stats = buffer_pool.stats();
        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.deallocations, 1);
        assert!(stats.hit_rate() >= 0.0);

        // Test event pool
        {
            let mut event = event_pool.acquire();
            event.event_id = "test-123".to_string();
            assert_eq!(event.event_id, "test-123");
        }

        let stats = event_pool.stats();
        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.deallocations, 1);
    }

    #[test]
    fn test_simd_hash_integration() {
        let hasher = SimdHasher::new();

        // Test data hashing
        let data = b"hello world";
        let sha256 = hasher.sha256(data);
        let md5 = hasher.md5(data);
        let entropy = hasher.entropy(data);

        assert_eq!(sha256.len(), 32);
        assert_eq!(md5.len(), 16);
        assert!(entropy > 0.0);

        // Test file hashing
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test file content").unwrap();
        temp_file.flush().unwrap();

        let result = hasher.hash_file(temp_file.path()).unwrap();
        assert_eq!(result.sha256.len(), 32);
        assert_eq!(result.md5.len(), 16);
        assert!(result.entropy > 0.0);
        assert_eq!(result.size, 17);
    }

    #[test]
    fn test_metrics_integration() {
        let metrics = PerformanceMetrics::new();

        // Record various operations
        metrics.record_allocation(1024);
        metrics.record_allocation(2048);
        metrics.record_deallocation(512);

        metrics.record_event_enqueued();
        metrics.record_event_enqueued();
        metrics.record_event_dequeued();

        metrics.record_collector_cpu_time("process", Duration::from_millis(10));
        metrics.record_collector_cpu_time("network", Duration::from_millis(5));

        metrics.record_lock_acquisition(false, Duration::from_micros(10));
        metrics.record_lock_acquisition(true, Duration::from_millis(2));

        // Get snapshot
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_allocations, 2);
        assert_eq!(snapshot.total_deallocations, 1);
        assert_eq!(snapshot.events_enqueued, 2);
        assert_eq!(snapshot.events_dequeued, 1);
        assert!(snapshot.process_cpu_time_ms >= 10);
        assert!(snapshot.network_cpu_time_ms >= 5);
        assert_eq!(snapshot.lock_acquisitions, 2);
        assert_eq!(snapshot.lock_contentions, 1);

        // Test metrics calculations
        assert!(snapshot.allocation_rate() >= 0.0);
        assert!(snapshot.event_throughput() >= 0.0);
        assert_eq!(snapshot.event_drop_rate(), 0.0);
        assert_eq!(snapshot.lock_contention_rate(), 50.0);

        // Test formatting
        let formatted = snapshot.format();
        assert!(formatted.contains("Performance Metrics"));
    }

    #[test]
    fn test_performance_under_load() {
        let queue = lockfree_queue::create_telemetry_queue(10000);
        let buffer_pool = BufferPool::new(1000, 4096);
        let metrics = PerformanceMetrics::new();

        let start = Instant::now();
        let num_operations = 10000;

        for i in 0..num_operations {
            // Simulate event creation with pooled buffer
            let mut buf = buffer_pool.acquire();
            buf.extend_from_slice(format!("event-{}", i).as_bytes());

            // Create and enqueue event
            let event = create_test_event(i);
            metrics.record_allocation(std::mem::size_of_val(&event));

            if queue.push(event).is_ok() {
                metrics.record_event_enqueued();
            } else {
                metrics.record_event_dropped();
            }

            // Simulate processing
            if let Some(_event) = queue.pop() {
                metrics.record_event_dequeued();
            }
        }

        let elapsed = start.elapsed();
        let throughput = num_operations as f64 / elapsed.as_secs_f64();

        println!("Performance under load:");
        println!("  Operations: {}", num_operations);
        println!("  Duration: {:?}", elapsed);
        println!("  Throughput: {:.2} ops/s", throughput);

        let snapshot = metrics.snapshot();
        println!("{}", snapshot.format());

        // Verify no drops under normal load
        assert_eq!(snapshot.events_dropped, 0);
    }

    #[test]
    fn test_allocator_detection() {
        let allocator = allocator::allocator_name();
        println!("Current allocator: {}", allocator);
        assert!(allocator == "jemalloc" || allocator == "system");

        let is_jemalloc = allocator::is_jemalloc_enabled();
        println!("Jemalloc enabled: {}", is_jemalloc);
    }

    #[test]
    fn test_configuration_roundtrip() {
        let config = PerformanceConfig::default();

        assert!(config.use_cpu_affinity);
        assert!(config.use_jemalloc);
        assert!(config.use_lockfree_queues);
        assert!(config.use_simd);
        assert_eq!(config.event_pool_size, 1024);
        assert_eq!(config.buffer_pool_size, 512);
        assert_eq!(config.telemetry_queue_capacity, 10000);

        // Serialize to TOML
        let toml_str = toml::to_string(&config).unwrap();
        println!("Config TOML:\n{}", toml_str);

        // Deserialize
        let config2: PerformanceConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.event_pool_size, config2.event_pool_size);
    }
}
