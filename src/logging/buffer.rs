//! Circular buffer for log entries
//!
//! Provides a bounded, thread-safe buffer for log entries with
//! efficient insertion and batch draining.

use super::forwarder::LogEntry;
use std::collections::VecDeque;
use tokio::sync::RwLock;

/// Circular buffer for log entries
pub struct LogBuffer {
    buffer: RwLock<VecDeque<LogEntry>>,
    max_size: usize,
    dropped_count: RwLock<usize>,
}

impl LogBuffer {
    /// Create a new log buffer with maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: RwLock::new(VecDeque::with_capacity(max_size)),
            max_size,
            dropped_count: RwLock::new(0),
        }
    }

    /// Push a log entry to the buffer
    pub async fn push(&self, entry: LogEntry) {
        let mut buffer = self.buffer.write().await;

        if buffer.len() >= self.max_size {
            // Drop oldest entry
            buffer.pop_front();
            let mut dropped = self.dropped_count.write().await;
            *dropped += 1;
        }

        buffer.push_back(entry);
    }

    /// Drain up to `count` entries from the buffer
    pub async fn drain(&self, count: usize) -> Vec<LogEntry> {
        let mut buffer = self.buffer.write().await;
        let drain_count = count.min(buffer.len());

        buffer.drain(..drain_count).collect()
    }

    /// Get current buffer size
    pub async fn len(&self) -> usize {
        self.buffer.read().await.len()
    }

    /// Check if buffer is empty
    pub async fn is_empty(&self) -> bool {
        self.buffer.read().await.is_empty()
    }

    /// Get number of dropped entries
    pub async fn dropped_count(&self) -> usize {
        *self.dropped_count.read().await
    }

    /// Clear the buffer
    pub async fn clear(&self) {
        let mut buffer = self.buffer.write().await;
        buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_log(message: &str) -> LogEntry {
        LogEntry {
            timestamp: 1234567890,
            level: "info".to_string(),
            component: "test".to_string(),
            message: message.to_string(),
            fields: None,
            file: None,
            line: None,
            thread: None,
        }
    }

    #[tokio::test]
    async fn test_buffer_push_and_drain() {
        let buffer = LogBuffer::new(100);

        buffer.push(create_test_log("log 1")).await;
        buffer.push(create_test_log("log 2")).await;
        buffer.push(create_test_log("log 3")).await;

        assert_eq!(buffer.len().await, 3);

        let logs = buffer.drain(2).await;
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].message, "log 1");
        assert_eq!(logs[1].message, "log 2");

        assert_eq!(buffer.len().await, 1);
    }

    #[tokio::test]
    async fn test_buffer_overflow() {
        let buffer = LogBuffer::new(3);

        buffer.push(create_test_log("log 1")).await;
        buffer.push(create_test_log("log 2")).await;
        buffer.push(create_test_log("log 3")).await;
        buffer.push(create_test_log("log 4")).await; // Should drop log 1

        assert_eq!(buffer.len().await, 3);
        assert_eq!(buffer.dropped_count().await, 1);

        let logs = buffer.drain(10).await;
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].message, "log 2"); // log 1 was dropped
    }
}
