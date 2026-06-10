//! Example: Performance-Optimized Collector
//!
//! This example demonstrates how to integrate performance optimizations
//! into a telemetry collector.

#[cfg(test)]
mod example {
    use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};
    use crate::performance::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::task::JoinHandle;

    /// Performance-optimized collector context
    pub struct OptimizedCollectorContext {
        /// Lock-free telemetry queue
        pub telemetry_queue: TelemetryQueue,
        /// Buffer pool for I/O operations
        pub buffer_pool: BufferPool,
        /// Event pool for pre-allocated events
        pub event_pool: EventPool,
        /// SIMD hasher
        pub hasher: SimdHasher,
        /// Performance metrics
        pub metrics: PerformanceMetrics,
        /// CPU affinity manager
        pub cpu_affinity: Arc<CpuAffinity>,
    }

    impl OptimizedCollectorContext {
        pub fn new(config: &PerformanceConfig) -> Self {
            let mut cpu_affinity = CpuAffinity::new(true);

            // Setup NUMA-aware CPU affinity
            if let Ok(mappings) = CpuAffinity::create_numa_aware_mappings() {
                for (collector, cores) in mappings {
                    cpu_affinity.set_mapping(collector, cores);
                }
            }

            Self {
                telemetry_queue: lockfree_queue::create_telemetry_queue(
                    config.telemetry_queue_capacity,
                ),
                buffer_pool: BufferPool::new(
                    config.buffer_pool_size,
                    64 * 1024, // 64KB buffers
                ),
                event_pool: EventPool::new(config.event_pool_size),
                hasher: SimdHasher::new(),
                metrics: PerformanceMetrics::new(),
                cpu_affinity: Arc::new(cpu_affinity),
            }
        }

        /// Submit an event to the telemetry queue
        pub fn submit_event(&self, event: TelemetryEvent) -> Result<(), TelemetryEvent> {
            self.metrics.record_event_enqueued();

            match self.telemetry_queue.push(event) {
                Ok(()) => Ok(()),
                Err(event) => {
                    self.metrics.record_event_dropped();
                    Err(event)
                }
            }
        }

        /// Get performance statistics
        pub fn get_stats(&self) -> metrics::MetricsSnapshot {
            self.metrics.snapshot()
        }
    }

    /// Example: Process collector with performance optimizations
    pub struct OptimizedProcessCollector {
        context: Arc<OptimizedCollectorContext>,
        collector_type: CollectorType,
    }

    impl OptimizedProcessCollector {
        pub fn new(context: Arc<OptimizedCollectorContext>) -> Self {
            Self {
                context,
                collector_type: CollectorType::Process,
            }
        }

        /// Start the collector with CPU affinity
        pub async fn start(self) -> JoinHandle<()> {
            tokio::spawn(async move {
                // Apply CPU affinity
                if let Err(e) = self.context.cpu_affinity.apply(self.collector_type) {
                    tracing::warn!("Failed to set CPU affinity: {}", e);
                }

                tracing::info!("Process collector started on dedicated core");

                self.collect_loop().await;
            })
        }

        /// Collection loop with performance optimizations
        async fn collect_loop(&self) {
            let mut interval = tokio::time::interval(Duration::from_millis(100));

            loop {
                interval.tick().await;

                // Measure CPU time for this collection cycle
                let _timing_guard = metrics::TimingGuard::new(&self.context.metrics, "process");

                // Collect events
                if let Err(e) = self.collect_events().await {
                    tracing::error!("Collection error: {}", e);
                }
            }
        }

        /// Collect process events with optimized I/O
        async fn collect_events(&self) -> anyhow::Result<()> {
            // Use buffer pool for reading process data
            let mut buf = self.context.buffer_pool.acquire();

            // Simulate reading process information
            // In reality, this would read from /proc, WMI, etc.
            buf.extend_from_slice(b"process data");

            // Create event (could use event pool for base structure)
            let event = TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid: 1234,
                    ppid: 1,
                    name: "test.exe".to_string(),
                    path: "/tmp/test.exe".to_string(),
                    cmdline: "test.exe --arg".to_string(),
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
            );

            // Record allocation
            self.context
                .metrics
                .record_allocation(std::mem::size_of_val(&event));

            // Submit to lock-free queue
            if let Err(e) = self.context.submit_event(event) {
                tracing::warn!("Failed to enqueue event, queue full");
                return Err(anyhow::anyhow!("Queue full"));
            }

            Ok(())
        }
    }

    /// Example: File collector with SIMD hash calculation
    pub struct OptimizedFileCollector {
        context: Arc<OptimizedCollectorContext>,
        collector_type: CollectorType,
    }

    impl OptimizedFileCollector {
        pub fn new(context: Arc<OptimizedCollectorContext>) -> Self {
            Self {
                context,
                collector_type: CollectorType::File,
            }
        }

        /// Hash a file using SIMD acceleration
        pub async fn hash_file(
            &self,
            path: &std::path::Path,
        ) -> anyhow::Result<simd_hash::FileHashes> {
            let _timing_guard = metrics::TimingGuard::new(&self.context.metrics, "file");

            // Use SIMD-accelerated hashing
            let hashes = self.context.hasher.hash_file(path)?;

            tracing::debug!(
                "Hashed file {} ({} bytes, entropy={:.2})",
                path.display(),
                hashes.size,
                hashes.entropy
            );

            Ok(hashes)
        }
    }

    /// Example: Event consumer with lock-free queue
    pub struct OptimizedEventConsumer {
        context: Arc<OptimizedCollectorContext>,
    }

    impl OptimizedEventConsumer {
        pub fn new(context: Arc<OptimizedCollectorContext>) -> Self {
            Self { context }
        }

        /// Start consuming events from the lock-free queue
        pub async fn start(self) -> JoinHandle<()> {
            tokio::spawn(async move {
                tracing::info!("Event consumer started");
                self.consume_loop().await;
            })
        }

        /// Consumption loop
        async fn consume_loop(&self) {
            let mut batch = Vec::with_capacity(100);
            let mut interval = tokio::time::interval(Duration::from_millis(10));

            loop {
                interval.tick().await;

                // Drain events from lock-free queue
                while let Some(event) = self.context.telemetry_queue.pop() {
                    self.context.metrics.record_event_dequeued();
                    batch.push(event);

                    if batch.len() >= 100 {
                        break;
                    }
                }

                if !batch.is_empty() {
                    self.process_batch(&batch).await;
                    batch.clear();
                }
            }
        }

        /// Process a batch of events
        async fn process_batch(&self, events: &[TelemetryEvent]) {
            tracing::debug!("Processing batch of {} events", events.len());

            // Process events (send to backend, analyze, etc.)
            for event in events {
                // Simulate processing
                let _ = event;
            }
        }
    }

    #[tokio::test]
    async fn test_optimized_collector_integration() {
        let config = PerformanceConfig::default();
        initialize(&config).unwrap();

        // Create shared context
        let context = Arc::new(OptimizedCollectorContext::new(&config));

        // Start collectors
        let process_collector = OptimizedProcessCollector::new(Arc::clone(&context));
        let _process_handle = process_collector.start().await;

        // Start consumer
        let consumer = OptimizedEventConsumer::new(Arc::clone(&context));
        let _consumer_handle = consumer.start().await;

        // Let them run for a bit
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Check statistics
        let stats = context.get_stats();
        tracing::info!("{}", stats.format());

        assert!(stats.events_enqueued > 0);
        assert!(stats.events_dequeued > 0);
    }

    #[tokio::test]
    async fn test_file_collector_with_simd() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let config = PerformanceConfig::default();
        let context = Arc::new(OptimizedCollectorContext::new(&config));

        let file_collector = OptimizedFileCollector::new(context);

        // Create test file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"test file content for SIMD hashing")
            .unwrap();
        temp_file.flush().unwrap();

        // Hash file
        let hashes = file_collector.hash_file(temp_file.path()).await.unwrap();

        assert_eq!(hashes.sha256.len(), 32);
        assert_eq!(hashes.md5.len(), 16);
        assert!(hashes.entropy > 0.0);
        assert_eq!(hashes.size, 35);
    }

    #[test]
    fn test_performance_impact_comparison() {
        use std::sync::Mutex;

        let iterations = 10000;

        // Baseline: Mutex-based queue
        let mutex_queue = Arc::new(Mutex::new(Vec::with_capacity(iterations)));
        let start = Instant::now();
        for i in 0..iterations {
            mutex_queue.lock().unwrap().push(i);
        }
        let mutex_duration = start.elapsed();

        // Optimized: Lock-free queue
        let lockfree_queue = lockfree_queue::LockFreeQueue::new(iterations);
        let start = Instant::now();
        for i in 0..iterations {
            let _ = lockfree_queue.push(i);
        }
        let lockfree_duration = start.elapsed();

        println!("Performance comparison ({} operations):", iterations);
        println!("  Mutex queue:     {:?}", mutex_duration);
        println!("  Lock-free queue: {:?}", lockfree_duration);
        println!(
            "  Speedup:         {:.2}x",
            mutex_duration.as_secs_f64() / lockfree_duration.as_secs_f64()
        );

        // Lock-free should be faster or similar
        assert!(lockfree_duration <= mutex_duration * 2);
    }
}
