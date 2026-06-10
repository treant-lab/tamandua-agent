#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LogBuffer, LogEntry, LogForwarder, LogForwarderConfig};

    #[tokio::test]
    async fn test_log_buffer_basic() {
        let buffer = LogBuffer::new(100);

        let log = LogEntry {
            timestamp: 1234567890,
            level: "info".to_string(),
            component: "test".to_string(),
            message: "Test message".to_string(),
            fields: None,
            file: None,
            line: None,
            thread: None,
        };

        buffer.push(log.clone()).await;
        assert_eq!(buffer.len().await, 1);

        let logs = buffer.drain(10).await;
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "Test message");
        assert_eq!(buffer.len().await, 0);
    }

    #[tokio::test]
    async fn test_log_buffer_overflow() {
        let buffer = LogBuffer::new(3);

        for i in 0..5 {
            let log = LogEntry {
                timestamp: 1234567890 + i,
                level: "info".to_string(),
                component: "test".to_string(),
                message: format!("Message {}", i),
                fields: None,
                file: None,
                line: None,
                thread: None,
            };
            buffer.push(log).await;
        }

        assert_eq!(buffer.len().await, 3);
        assert_eq!(buffer.dropped_count().await, 2);

        let logs = buffer.drain(10).await;
        assert_eq!(logs.len(), 3);
        // First two messages should be dropped, so we should have 2, 3, 4
        assert_eq!(logs[0].message, "Message 2");
        assert_eq!(logs[1].message, "Message 3");
        assert_eq!(logs[2].message, "Message 4");
    }

    #[tokio::test]
    async fn test_log_buffer_partial_drain() {
        let buffer = LogBuffer::new(100);

        for i in 0..10 {
            let log = LogEntry {
                timestamp: 1234567890 + i,
                level: "info".to_string(),
                component: "test".to_string(),
                message: format!("Message {}", i),
                fields: None,
                file: None,
                line: None,
                thread: None,
            };
            buffer.push(log).await;
        }

        assert_eq!(buffer.len().await, 10);

        // Drain 5 logs
        let logs = buffer.drain(5).await;
        assert_eq!(logs.len(), 5);
        assert_eq!(buffer.len().await, 5);

        // Drain remaining
        let logs = buffer.drain(10).await;
        assert_eq!(logs.len(), 5);
        assert_eq!(buffer.len().await, 0);
    }

    #[test]
    fn test_log_forwarder_config_default() {
        let config = LogForwarderConfig::default();
        assert!(config.enabled);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.batch_timeout_secs, 5);
        assert_eq!(config.max_buffer_size, 10_000);
    }

    #[test]
    fn test_extract_component() {
        use crate::logging::forwarder::extract_component;

        assert_eq!(
            extract_component("tamandua_agent::collectors::process"),
            "collectors"
        );
        assert_eq!(
            extract_component("tamandua_agent::transport::websocket"),
            "transport"
        );
        assert_eq!(
            extract_component("tamandua_agent::response"),
            "response"
        );
        assert_eq!(extract_component("other::module"), "module");
        assert_eq!(extract_component("single"), "single");
    }

    #[tokio::test]
    async fn test_log_forwarder_creation() {
        let config = LogForwarderConfig::default();
        let (forwarder, _rx) = LogForwarder::new(config);

        assert_eq!(forwarder.buffer_size().await, 0);
    }

    #[tokio::test]
    async fn test_log_forwarder_buffering() {
        let config = LogForwarderConfig::default();
        let (forwarder, mut rx) = LogForwarder::new(config);

        let log = LogEntry {
            timestamp: 1234567890,
            level: "info".to_string(),
            component: "test".to_string(),
            message: "Test log".to_string(),
            fields: None,
            file: None,
            line: None,
            thread: None,
        };

        // Send log through channel
        forwarder.tx.send(log.clone()).unwrap();

        // Should be able to receive it
        let received = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            rx.recv()
        ).await;

        assert!(received.is_ok());
        let received_log = received.unwrap().unwrap();
        assert_eq!(received_log.message, "Test log");
    }

    #[test]
    fn test_log_level_parsing() {
        use crate::logging::parser::LogLevel;

        assert_eq!(LogLevel::from_str("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("invalid"), None);
    }

    #[test]
    fn test_log_level_ordering() {
        use crate::logging::parser::LogLevel;

        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }

    #[test]
    fn test_structured_log_filtering() {
        use crate::logging::parser::{LogFilter, LogLevel, StructuredLog};
        use std::collections::HashMap;

        let log = StructuredLog {
            timestamp: 1234567890,
            level: LogLevel::Info,
            component: "collectors".to_string(),
            message: "Process started: test.exe".to_string(),
            fields: HashMap::new(),
        };

        // Level filter
        let filter = LogFilter::new().with_level(LogLevel::Debug);
        assert!(log.matches_filter(&filter));

        let filter = LogFilter::new().with_level(LogLevel::Warn);
        assert!(!log.matches_filter(&filter));

        // Component filter
        let filter = LogFilter::new().with_component("collectors".to_string());
        assert!(log.matches_filter(&filter));

        let filter = LogFilter::new().with_component("transport".to_string());
        assert!(!log.matches_filter(&filter));

        // Keyword filter
        let filter = LogFilter::new().with_keyword("Process".to_string());
        assert!(log.matches_filter(&filter));

        let filter = LogFilter::new().with_keyword("Network".to_string());
        assert!(!log.matches_filter(&filter));
    }

    #[test]
    fn test_structured_log_regex_filter() {
        use crate::logging::parser::{LogFilter, LogLevel, StructuredLog};
        use std::collections::HashMap;

        let log = StructuredLog {
            timestamp: 1234567890,
            level: LogLevel::Error,
            component: "transport".to_string(),
            message: "Connection timeout after 30s".to_string(),
            fields: HashMap::new(),
        };

        // Regex matching
        let filter = LogFilter::new()
            .with_regex(r"timeout.*\d+s")
            .unwrap();
        assert!(log.matches_filter(&filter));

        let filter = LogFilter::new()
            .with_regex(r"success")
            .unwrap();
        assert!(!log.matches_filter(&filter));
    }

    #[test]
    fn test_structured_log_time_range_filter() {
        use crate::logging::parser::{LogFilter, LogLevel, StructuredLog};
        use std::collections::HashMap;

        let log = StructuredLog {
            timestamp: 1000,
            level: LogLevel::Info,
            component: "test".to_string(),
            message: "Test".to_string(),
            fields: HashMap::new(),
        };

        // Within range
        let filter = LogFilter::new().with_time_range(900, 1100);
        assert!(log.matches_filter(&filter));

        // Before range
        let filter = LogFilter::new().with_time_range(1100, 1200);
        assert!(!log.matches_filter(&filter));

        // After range
        let filter = LogFilter::new().with_time_range(800, 900);
        assert!(!log.matches_filter(&filter));
    }
}
