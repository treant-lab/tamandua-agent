//! Memory Pooling
//!
//! Object pooling for frequently allocated structures to reduce allocation churn.
//! Provides pools for TelemetryEvent and I/O buffers.

use crate::collectors::{EventPayload, EventType, Severity, TelemetryEvent};
use bytes::{Bytes, BytesMut};
use crossbeam_queue::ArrayQueue;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Pool statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub allocations: usize,
    pub deallocations: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub current_size: usize,
    pub capacity: usize,
}

impl PoolStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }
}

/// Generic object pool
pub struct ObjectPool<T, F>
where
    F: Fn() -> T,
{
    pool: Arc<ArrayQueue<T>>,
    factory: F,
    allocations: Arc<AtomicUsize>,
    deallocations: Arc<AtomicUsize>,
    cache_hits: Arc<AtomicUsize>,
    cache_misses: Arc<AtomicUsize>,
}

impl<T, F> ObjectPool<T, F>
where
    F: Fn() -> T,
{
    /// Create a new object pool
    pub fn new(capacity: usize, factory: F) -> Self {
        let pool = ArrayQueue::new(capacity);

        // Pre-populate the pool
        for _ in 0..capacity.min(16) {
            let _ = pool.push(factory());
        }

        Self {
            pool: Arc::new(pool),
            factory,
            allocations: Arc::new(AtomicUsize::new(0)),
            deallocations: Arc::new(AtomicUsize::new(0)),
            cache_hits: Arc::new(AtomicUsize::new(0)),
            cache_misses: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Acquire an object from the pool
    pub fn acquire(&self) -> PooledObject<T, F> {
        let obj = if let Some(obj) = self.pool.pop() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            obj
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            (self.factory)()
        };

        self.allocations.fetch_add(1, Ordering::Relaxed);

        PooledObject {
            obj: Some(obj),
            pool: self.pool.clone(),
            deallocations: self.deallocations.clone(),
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            allocations: self.allocations.load(Ordering::Relaxed),
            deallocations: self.deallocations.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            current_size: self.pool.len(),
            capacity: self.pool.capacity(),
        }
    }
}

impl<T, F> Clone for ObjectPool<T, F>
where
    F: Fn() -> T + Clone,
{
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            factory: self.factory.clone(),
            allocations: Arc::clone(&self.allocations),
            deallocations: Arc::clone(&self.deallocations),
            cache_hits: Arc::clone(&self.cache_hits),
            cache_misses: Arc::clone(&self.cache_misses),
        }
    }
}

/// Pooled object that returns to pool on drop
pub struct PooledObject<T, F>
where
    F: Fn() -> T,
{
    obj: Option<T>,
    pool: Arc<ArrayQueue<T>>,
    deallocations: Arc<AtomicUsize>,
}

impl<T, F> PooledObject<T, F>
where
    F: Fn() -> T,
{
    /// Get a reference to the pooled object
    pub fn get(&self) -> &T {
        self.obj.as_ref().unwrap()
    }

    /// Get a mutable reference to the pooled object
    pub fn get_mut(&mut self) -> &mut T {
        self.obj.as_mut().unwrap()
    }

    /// Take the object out of the pool (won't be returned)
    pub fn take(mut self) -> T {
        self.obj.take().unwrap()
    }
}

impl<T, F> std::ops::Deref for PooledObject<T, F>
where
    F: Fn() -> T,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T, F> std::ops::DerefMut for PooledObject<T, F>
where
    F: Fn() -> T,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

impl<T, F> Drop for PooledObject<T, F>
where
    F: Fn() -> T,
{
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            self.deallocations.fetch_add(1, Ordering::Relaxed);
            let _ = self.pool.push(obj); // Ignore if pool is full
        }
    }
}

/// Buffer pool for I/O operations
pub struct BufferPool {
    pool: ObjectPool<BytesMut, fn() -> BytesMut>,
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let factory = move || BytesMut::with_capacity(buffer_size);
        Self {
            pool: ObjectPool::new(capacity, factory),
            buffer_size,
        }
    }

    /// Acquire a buffer from the pool
    pub fn acquire(&self) -> PooledObject<BytesMut, fn() -> BytesMut> {
        let mut buf = self.pool.acquire();
        buf.clear(); // Clear the buffer before reuse
        buf.reserve(self.buffer_size);
        buf
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.pool.stats()
    }
}

impl Clone for BufferPool {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            buffer_size: self.buffer_size,
        }
    }
}

/// Event pool for TelemetryEvent (placeholder events)
pub struct EventPool {
    pool: ObjectPool<TelemetryEvent, fn() -> TelemetryEvent>,
}

impl EventPool {
    /// Create a new event pool
    pub fn new(capacity: usize) -> Self {
        let factory = || {
            // Create a minimal placeholder event
            TelemetryEvent {
                event_id: String::new(),
                event_type: EventType::ProcessCreate,
                timestamp: 0,
                severity: Severity::Info,
                payload: EventPayload::Custom(serde_json::Value::Null),
                detections: Vec::new(),
                metadata: std::collections::HashMap::new(),
            }
        };

        Self {
            pool: ObjectPool::new(capacity, factory),
        }
    }

    /// Acquire an event from the pool
    pub fn acquire(&self) -> PooledObject<TelemetryEvent, fn() -> TelemetryEvent> {
        self.pool.acquire()
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.pool.stats()
    }
}

impl Clone for EventPool {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

/// Zero-copy bytes wrapper
pub struct ZeroCopyBytes {
    inner: Bytes,
}

impl ZeroCopyBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: Bytes::from(data),
        }
    }

    pub fn from_bytes(bytes: Bytes) -> Self {
        Self { inner: bytes }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clone_bytes(&self) -> Bytes {
        self.inner.clone()
    }
}

impl std::ops::Deref for ZeroCopyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Clone for ZeroCopyBytes {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_pool() {
        let pool = ObjectPool::new(10, || vec![0u8; 1024]);

        // Acquire and return objects
        {
            let obj1 = pool.acquire();
            assert_eq!(obj1.len(), 1024);
            let obj2 = pool.acquire();
            assert_eq!(obj2.len(), 1024);
        }

        // Check stats
        let stats = pool.stats();
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.deallocations, 2);
        assert!(stats.current_size > 0);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(10, 4096);

        {
            let mut buf = pool.acquire();
            buf.extend_from_slice(b"test data");
            assert_eq!(&buf[..], b"test data");
        }

        // Acquire again, should be cleared
        {
            let buf = pool.acquire();
            assert_eq!(buf.len(), 0);
        }

        let stats = pool.stats();
        assert!(stats.cache_hits > 0 || stats.cache_misses > 0);
    }

    #[test]
    fn test_event_pool() {
        let pool = EventPool::new(10);

        {
            let mut event = pool.acquire();
            event.event_id = "test-id".to_string();
            event.timestamp = 123456;
        }

        let stats = pool.stats();
        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.deallocations, 1);
    }

    #[test]
    fn test_zero_copy_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let zcb = ZeroCopyBytes::new(data);

        assert_eq!(zcb.len(), 5);
        assert!(!zcb.is_empty());
        assert_eq!(zcb.as_slice(), &[1, 2, 3, 4, 5]);

        let cloned = zcb.clone();
        assert_eq!(cloned.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_pool_stats() {
        let pool = ObjectPool::new(5, || 42);

        // Cause cache miss
        let obj1 = pool.acquire();
        drop(obj1);

        // Cause cache hit
        let obj2 = pool.acquire();
        drop(obj2);

        let stats = pool.stats();
        assert!(stats.hit_rate() > 0.0);
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.deallocations, 2);
    }

    #[test]
    fn test_concurrent_pool_access() {
        use std::thread;

        let pool = ObjectPool::new(100, || vec![0u8; 1024]);
        let pool_clone = pool.clone();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let p = pool_clone.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        let obj = p.acquire();
                        assert_eq!(obj.len(), 1024);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = pool.stats();
        assert_eq!(stats.allocations, 1000);
        assert_eq!(stats.deallocations, 1000);
    }
}
