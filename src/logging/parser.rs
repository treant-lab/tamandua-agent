//! Log parsing and structured log utilities

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Parse log level from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLog {
    pub timestamp: u64,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
    pub fields: HashMap<String, serde_json::Value>,
}

impl StructuredLog {
    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Check if log matches filter
    pub fn matches_filter(&self, filter: &LogFilter) -> bool {
        // Check level
        if let Some(min_level) = filter.min_level {
            if self.level < min_level {
                return false;
            }
        }

        // Check component
        if !filter.components.is_empty() && !filter.components.contains(&self.component) {
            return false;
        }

        // Check keyword
        if let Some(keyword) = &filter.keyword {
            if !self.message.contains(keyword) {
                return false;
            }
        }

        // Check regex
        if let Some(regex) = &filter.regex {
            if !regex.is_match(&self.message) {
                return false;
            }
        }

        // Check time range
        if let Some(start) = filter.time_start {
            if self.timestamp < start {
                return false;
            }
        }

        if let Some(end) = filter.time_end {
            if self.timestamp > end {
                return false;
            }
        }

        true
    }
}

/// Log filter for searching and filtering logs
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub min_level: Option<LogLevel>,
    pub components: Vec<String>,
    pub keyword: Option<String>,
    pub regex: Option<regex::Regex>,
    pub time_start: Option<u64>,
    pub time_end: Option<u64>,
}

impl LogFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum log level
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.min_level = Some(level);
        self
    }

    /// Add component filter
    pub fn with_component(mut self, component: String) -> Self {
        self.components.push(component);
        self
    }

    /// Set keyword filter
    pub fn with_keyword(mut self, keyword: String) -> Self {
        self.keyword = Some(keyword);
        self
    }

    /// Set regex filter
    pub fn with_regex(mut self, pattern: &str) -> Result<Self, regex::Error> {
        self.regex = Some(regex::Regex::new(pattern)?);
        Ok(self)
    }

    /// Set time range
    pub fn with_time_range(mut self, start: u64, end: u64) -> Self {
        self.time_start = Some(start);
        self.time_end = Some(end);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(LogLevel::from_str("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("invalid"), None);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }

    #[test]
    fn test_filter_matching() {
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

        let filter = LogFilter::new().with_keyword("File".to_string());
        assert!(!log.matches_filter(&filter));
    }
}
