//! Lock-Free Queue Implementation
//!
//! High-performance lock-free queue using crossbeam for telemetry events.
//! Provides better throughput than Mutex-based queues with reduced contention.

use crate::collectors::TelemetryEvent;
use anyhow::Result;
use crossbeam_queue::{ArrayQueue, SegQueue};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Lock-free bounded queue
pub struct LockFreeQueue<T> {
    queue: Arc<ArrayQueue<T>>,
    enqueued: Arc<AtomicUsize>,
    dequeued: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl<T> LockFreeQueue<T> {
    /// Create a new lock-free queue with the specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Arc::new(ArrayQueue::new(capacity)),
            enqueued: Arc::new(AtomicUsize::new(0)),
            dequeued: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Push an item to the queue
    /// Returns Ok(()) if successful, Err(item) if queue is full
    pub fn push(&self, item: T) -> Result<(), T> {
        match self.queue.push(item) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(item) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Err(item)
            }
        }
    }

    /// Try to push an item, dropping it if the queue is full
    pub fn try_push(&self, item: T) -> bool {
        self.push(item).is_ok()
    }

    /// Pop an item from the queue
    pub fn pop(&self) -> Option<T> {
        self.queue.pop().map(|item| {
            self.dequeued.fetch_add(1, Ordering::Relaxed);
            item
        })
    }

    /// Get current queue length
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    /// Get queue capacity
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    /// Get statistics
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dequeued: self.dequeued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            current_len: self.len(),
            capacity: self.capacity(),
        }
    }
}

impl<T> Clone for LockFreeQueue<T> {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            enqueued: Arc::clone(&self.enqueued),
            dequeued: Arc::clone(&self.dequeued),
            dropped: Arc::clone(&self.dropped),
        }
    }
}

/// Lock-free unbounded queue (using SegQueue)
pub struct UnboundedLockFreeQueue<T> {
    queue: Arc<SegQueue<T>>,
    enqueued: Arc<AtomicUsize>,
    dequeued: Arc<AtomicUsize>,
}

impl<T> UnboundedLockFreeQueue<T> {
    /// Create a new unbounded lock-free queue
    pub fn new() -> Self {
        Self {
            queue: Arc::new(SegQueue::new()),
            enqueued: Arc::new(AtomicUsize::new(0)),
            dequeued: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Push an item to the queue (never fails)
    pub fn push(&self, item: T) {
        self.queue.push(item);
        self.enqueued.fetch_add(1, Ordering::Relaxed);
    }

    /// Pop an item from the queue
    pub fn pop(&self) -> Option<T> {
        self.queue.pop().map(|item| {
            self.dequeued.fetch_add(1, Ordering::Relaxed);
            item
        })
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get approximate queue length
    pub fn len(&self) -> usize {
        self.enqueued
            .load(Ordering::Relaxed)
            .saturating_sub(self.dequeued.load(Ordering::Relaxed))
    }

    /// Get statistics
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dequeued: self.dequeued.load(Ordering::Relaxed),
            dropped: 0,
            current_len: self.len(),
            capacity: usize::MAX,
        }
    }
}

impl<T> Clone for UnboundedLockFreeQueue<T> {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            enqueued: Arc::clone(&self.enqueued),
            dequeued: Arc::clone(&self.dequeued),
        }
    }
}

impl<T> Default for UnboundedLockFreeQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Queue statistics
#[derive(Debug, Clone, Copy)]
pub struct QueueStats {
    pub enqueued: usize,
    pub dequeued: usize,
    pub dropped: usize,
    pub current_len: usize,
    pub capacity: usize,
}

impl QueueStats {
    /// Calculate queue utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.capacity == usize::MAX {
            0.0 // Unbounded queue
        } else if self.capacity == 0 {
            0.0
        } else {
            (self.current_len as f64 / self.capacity as f64) * 100.0
        }
    }

    /// Calculate drop rate percentage
    pub fn drop_rate(&self) -> f64 {
        if self.enqueued == 0 {
            0.0
        } else {
            (self.dropped as f64 / self.enqueued as f64) * 100.0
        }
    }
}

/// Specialized telemetry event queue
pub type TelemetryQueue = LockFreeQueue<TelemetryEvent>;

/// Create a telemetry queue with default capacity
pub fn create_telemetry_queue(capacity: usize) -> TelemetryQueue {
    TelemetryQueue::new(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity};

    fn create_test_event() -> TelemetryEvent {
        TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid: 1234,
                ppid: 1,
                name: "test.exe".to_string(),
                path: "/tmp/test.exe".to_string(),
                cmdline: "test.exe --test".to_string(),
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
    fn test_bounded_queue() {
        let queue = LockFreeQueue::new(10);
        assert_eq!(queue.capacity(), 10);
        assert!(queue.is_empty());
        assert!(!queue.is_full());

        // Push items
        for i in 0..10 {
            assert!(queue.push(i).is_ok());
        }

        assert!(queue.is_full());
        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 10);

        // Try to push when full
        assert!(queue.push(99).is_err());

        // Pop items
        for i in 0..10 {
            assert_eq!(queue.pop(), Some(i));
        }

        assert!(queue.is_empty());
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_unbounded_queue() {
        let queue = UnboundedLockFreeQueue::new();
        assert!(queue.is_empty());

        // Push many items
        for i in 0..1000 {
            queue.push(i);
        }

        assert_eq!(queue.len(), 1000);

        // Pop all items
        for i in 0..1000 {
            assert_eq!(queue.pop(), Some(i));
        }

        assert!(queue.is_empty());
    }

    #[test]
    fn test_telemetry_queue() {
        let queue = create_telemetry_queue(100);
        let event = create_test_event();

        assert!(queue.try_push(event.clone()));
        assert_eq!(queue.len(), 1);

        let popped = queue.pop().unwrap();
        assert_eq!(popped.event_type, EventType::ProcessCreate);
    }

    #[test]
    fn test_queue_stats() {
        let queue = LockFreeQueue::new(10);

        for i in 0..5 {
            let _ = queue.push(i);
        }

        for _ in 0..3 {
            let _ = queue.pop();
        }

        // Try to overfill
        for i in 0..20 {
            let _ = queue.push(i);
        }

        let stats = queue.stats();
        assert!(stats.enqueued > 0);
        assert_eq!(stats.dequeued, 3);
        assert!(stats.dropped > 0);
        assert!(stats.utilization() > 0.0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let queue = LockFreeQueue::new(1000);
        let queue_clone = queue.clone();

        // Producer thread
        let producer = thread::spawn(move || {
            for i in 0..500 {
                let _ = queue_clone.push(i);
            }
        });

        // Consumer thread
        let consumer = thread::spawn(move || {
            let mut count = 0;
            while count < 500 {
                if queue.pop().is_some() {
                    count += 1;
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }
}
