//! Configuration validation framework for Tamandua agent.
//!
//! Validates agent configuration before applying updates to prevent:
//! - Invalid TOML syntax
//! - Unknown collector names
//! - Out-of-range port numbers, intervals, paths
//! - YARA compilation failures
//! - Sigma parsing errors
//!
//! Returns detailed validation errors with field paths for troubleshooting.

use anyhow::{Context, Result};
use std::path::Path;
use tracing::debug;

use super::AgentConfig;

/// Validation error with field path for precise troubleshooting
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Field path (e.g., "collectors.process_enabled", "collector_tuning.dns_poll_interval_ms")
    pub field: String,
    /// Error message
    pub message: String,
}

impl ValidationError {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Validation result containing all errors found
#[derive(Debug, Default)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn error(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationError::new(field, message));
    }

    pub fn warning(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(ValidationError::new(field, message));
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate TOML file syntax and structure
    pub fn validate_toml_file(path: &Path) -> Result<AgentConfig> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::validate_toml_string(&content)
    }

    /// Validate TOML string syntax and structure
    pub fn validate_toml_string(content: &str) -> Result<AgentConfig> {
        // Parse TOML syntax
        let config: AgentConfig =
            toml::from_str(content).context("Invalid TOML syntax or structure")?;

        Ok(config)
    }

    /// Comprehensive validation of agent configuration
    pub fn validate_config(config: &AgentConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Validate basic fields
        Self::validate_basic_fields(config, &mut result);

        // Validate network settings
        Self::validate_network_settings(config, &mut result);

        // Validate collector configuration
        Self::validate_collectors(config, &mut result);

        // Validate collector tuning
        Self::validate_tuning(config, &mut result);

        // Validate paths
        Self::validate_paths(config, &mut result);

        // Validate performance profile consistency
        Self::validate_performance_profile(config, &mut result);

        result
    }

    fn validate_basic_fields(config: &AgentConfig, result: &mut ValidationResult) {
        // Validate agent_id
        if config.agent_id.is_empty() {
            result.error("agent_id", "Agent ID cannot be empty");
        }

        // Validate server_url
        if config.server_url.is_empty() {
            result.error("server_url", "Server URL cannot be empty");
        } else if !config.server_url.starts_with("ws://")
            && !config.server_url.starts_with("wss://")
        {
            result.error("server_url", "Server URL must start with ws:// or wss://");
        }

        // Validate intervals
        if config.heartbeat_interval_seconds == 0 {
            result.error(
                "heartbeat_interval_seconds",
                "Heartbeat interval must be > 0",
            );
        }

        if config.heartbeat_interval_seconds > 3600 {
            result.warning(
                "heartbeat_interval_seconds",
                "Heartbeat interval > 1 hour may cause connection timeouts",
            );
        }

        if config.batch_timeout_seconds == 0 {
            result.error("batch_timeout_seconds", "Batch timeout must be > 0");
        }

        if config.batch_size == 0 {
            result.error("batch_size", "Batch size must be > 0");
        }

        if config.batch_size > 10000 {
            result.warning("batch_size", "Batch size > 10000 may cause memory issues");
        }

        // Validate thresholds
        if config.entropy_threshold < 0.0 || config.entropy_threshold > 8.0 {
            result.error(
                "entropy_threshold",
                "Entropy threshold must be between 0.0 and 8.0",
            );
        }

        if config.max_cpu_percent < 0.0 || config.max_cpu_percent > 100.0 {
            result.error(
                "max_cpu_percent",
                "CPU percent must be between 0.0 and 100.0",
            );
        }

        if config.sub_loop_interval_multiplier < 0.1 || config.sub_loop_interval_multiplier > 100.0
        {
            result.error(
                "sub_loop_interval_multiplier",
                "Interval multiplier must be between 0.1 and 100.0",
            );
        }
    }

    fn validate_network_settings(config: &AgentConfig, result: &mut ValidationResult) {
        if config.connection_timeout_seconds == 0 {
            result.error(
                "connection_timeout_seconds",
                "Connection timeout must be > 0",
            );
        }

        if config.reconnect_delay_seconds == 0 {
            result.error("reconnect_delay_seconds", "Reconnect delay must be > 0");
        }

        if config.reconnect_delay_seconds > 300 {
            result.warning(
                "reconnect_delay_seconds",
                "Reconnect delay > 5 minutes may cause long outages",
            );
        }

        // Validate TLS config
        if config.tls.enabled {
            if config.tls.cert_path.is_none() {
                result.error(
                    "tls.cert_path",
                    "Certificate path required when TLS is enabled",
                );
            }
            if config.tls.key_path.is_none() {
                result.error("tls.key_path", "Key path required when TLS is enabled");
            }

            if config.tls.skip_verify {
                result.warning(
                    "tls.skip_verify",
                    "TLS verification disabled - DANGEROUS for production",
                );
            }
        }

        // Validate backup servers
        for (i, server) in config.transport.backup_servers.iter().enumerate() {
            if !server.starts_with("ws://") && !server.starts_with("wss://") {
                result.error(
                    format!("transport.backup_servers[{}]", i),
                    "Backup server URL must start with ws:// or wss://",
                );
            }
        }

        // Validate cert pins
        if config.transport.cert_pin_enforce && config.transport.cert_pins.is_empty() {
            result.warning(
                "transport.cert_pin_enforce",
                "Certificate pinning enabled but no pins configured",
            );
        }
    }

    fn validate_collectors(config: &AgentConfig, result: &mut ValidationResult) {
        // Warn if all collectors are disabled
        let core_collectors = config.collectors.process_enabled
            || config.collectors.file_enabled
            || config.collectors.network_enabled
            || config.collectors.dns_enabled;

        if !core_collectors {
            result.warning(
                "collectors",
                "All core collectors are disabled - no telemetry will be collected",
            );
        }

        // Platform-specific validation
        #[cfg(target_os = "windows")]
        {
            if config.collectors.etw_enabled {
                // Validate ETW collector config
                if config.collectors.etw.ring_buffer_size == 0 {
                    result.error(
                        "collectors.etw.ring_buffer_size",
                        "ETW ring buffer size must be > 0",
                    );
                }

                if config.collectors.etw.ring_buffer_size > 10_000_000 {
                    result.warning(
                        "collectors.etw.ring_buffer_size",
                        "ETW ring buffer > 10M may cause memory issues",
                    );
                }

                if config.collectors.etw.provider_rate_limit == 0 {
                    result.warning(
                        "collectors.etw.provider_rate_limit",
                        "ETW rate limit of 0 may cause event flooding",
                    );
                }

                if config.collectors.etw.health_check_interval_secs == 0 {
                    result.error(
                        "collectors.etw.health_check_interval_secs",
                        "ETW health check interval must be > 0",
                    );
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Warn about Windows-only collectors on non-Windows platforms
            #[cfg(target_os = "linux")]
            {
                if !cfg!(target_os = "windows") {
                    // This would be checked at runtime, but we're in compile-time cfg block
                }
            }
        }
    }

    fn validate_tuning(config: &AgentConfig, result: &mut ValidationResult) {
        let tuning = &config.collector_tuning;

        if tuning.memory_scan_interval_secs == 0 {
            result.error(
                "collector_tuning.memory_scan_interval_secs",
                "Memory scan interval must be > 0",
            );
        }

        if tuning.memory_scan_interval_secs < 10 {
            result.warning(
                "collector_tuning.memory_scan_interval_secs",
                "Memory scan interval < 10s may cause high CPU usage",
            );
        }

        if tuning.dns_poll_interval_ms == 0 {
            result.error(
                "collector_tuning.dns_poll_interval_ms",
                "DNS poll interval must be > 0",
            );
        }

        if tuning.dns_poll_interval_ms < 100 {
            result.warning(
                "collector_tuning.dns_poll_interval_ms",
                "DNS poll interval < 100ms may cause high CPU usage",
            );
        }

        if tuning.network_poll_interval_ms == 0 {
            result.error(
                "collector_tuning.network_poll_interval_ms",
                "Network poll interval must be > 0",
            );
        }

        if tuning.process_scan_interval_secs == 0 {
            result.error(
                "collector_tuning.process_scan_interval_secs",
                "Process scan interval must be > 0",
            );
        }

        if tuning.registry_poll_interval_secs == 0 {
            result.error(
                "collector_tuning.registry_poll_interval_secs",
                "Registry poll interval must be > 0",
            );
        }

        if tuning.cpu_throttle_threshold < 0.0 || tuning.cpu_throttle_threshold > 100.0 {
            result.error(
                "collector_tuning.cpu_throttle_threshold",
                "CPU threshold must be between 0.0 and 100.0",
            );
        }

        if tuning.memory_entropy_threshold < 0.0 || tuning.memory_entropy_threshold > 8.0 {
            result.error(
                "collector_tuning.memory_entropy_threshold",
                "Entropy threshold must be between 0.0 and 8.0",
            );
        }
    }

    fn validate_paths(config: &AgentConfig, result: &mut ValidationResult) {
        // Validate TLS paths if enabled
        if config.tls.enabled {
            if let Some(ref cert_path) = config.tls.cert_path {
                if !Path::new(cert_path).exists() {
                    result.warning(
                        "tls.cert_path",
                        format!("Certificate file does not exist: {}", cert_path),
                    );
                }
            }

            if let Some(ref key_path) = config.tls.key_path {
                if !Path::new(key_path).exists() {
                    result.warning(
                        "tls.key_path",
                        format!("Key file does not exist: {}", key_path),
                    );
                }
            }

            if let Some(ref ca_path) = config.tls.ca_path {
                if !Path::new(ca_path).exists() {
                    result.warning(
                        "tls.ca_path",
                        format!("CA file does not exist: {}", ca_path),
                    );
                }
            }
        }

        // Validate ML model paths
        if config.ml_scanning_enabled {
            if let Some(ref model_path) = config.ml_model_path {
                if !model_path.is_empty() && !Path::new(model_path).exists() {
                    result.warning(
                        "ml_model_path",
                        format!("ML model file does not exist: {}", model_path),
                    );
                }
            }
        }

        // Validate offline detection paths
        if config.offline_detection.enabled {
            if !config.offline_detection.onnx_model_path.is_empty() {
                let path = Path::new(&config.offline_detection.onnx_model_path);
                if !path.exists() {
                    result.warning(
                        "offline_detection.onnx_model_path",
                        format!(
                            "ONNX model file does not exist: {}",
                            config.offline_detection.onnx_model_path
                        ),
                    );
                }
            }
        }

        // Validate excluded paths format
        for (i, path) in config.excluded_paths.iter().enumerate() {
            if path.is_empty() {
                result.warning(format!("excluded_paths[{}]", i), "Empty excluded path");
            }
        }

        // Validate honeyfile paths
        if config.honeyfiles_enabled {
            for (i, path) in config.honeyfile_paths.iter().enumerate() {
                if path.is_empty() {
                    result.warning(format!("honeyfile_paths[{}]", i), "Empty honeyfile path");
                }
            }
        }
    }

    fn validate_performance_profile(config: &AgentConfig, result: &mut ValidationResult) {
        use super::PerformanceProfile;

        match config.performance_profile {
            PerformanceProfile::Lightweight => {
                if config.max_cpu_percent > 10.0 {
                    result.warning(
                        "max_cpu_percent",
                        "Lightweight profile typically uses max_cpu_percent <= 10%",
                    );
                }
            }
            PerformanceProfile::Balanced => {
                if config.max_cpu_percent > 20.0 {
                    result.warning(
                        "max_cpu_percent",
                        "Balanced profile typically uses max_cpu_percent <= 20%",
                    );
                }
            }
            PerformanceProfile::Aggressive => {
                // Aggressive profile can use more CPU
            }
        }
    }

    /// Validate YARA rules compilation
    #[cfg(feature = "yara")]
    pub fn validate_yara_rules(rules_dir: &Path) -> Result<ValidationResult> {
        use std::fs;

        let mut result = ValidationResult::new();

        if !rules_dir.exists() {
            result.error(
                "yara_rules",
                format!(
                    "YARA rules directory does not exist: {}",
                    rules_dir.display()
                ),
            );
            return Ok(result);
        }

        debug!(path = %rules_dir.display(), "Validating YARA rules");

        let mut rule_count = 0;

        // Recursively find all .yar and .yara files
        for entry in walkdir::WalkDir::new(rules_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "yar" || ext == "yara" {
                    rule_count += 1;

                    // Try to compile the rule
                    match fs::read_to_string(path) {
                        Ok(content) => match yara::Compiler::new() {
                            Ok(mut compiler) => {
                                if let Err(e) = compiler.add_rules_str(&content) {
                                    result.error(
                                        format!("yara:{}", path.display()),
                                        format!("YARA compilation failed: {}", e),
                                    );
                                }
                            }
                            Err(e) => {
                                result.error(
                                    "yara",
                                    format!("Failed to create YARA compiler: {}", e),
                                );
                            }
                        },
                        Err(e) => {
                            result.error(
                                format!("yara:{}", path.display()),
                                format!("Failed to read rule file: {}", e),
                            );
                        }
                    }
                }
            }
        }

        if rule_count == 0 {
            result.warning("yara_rules", "No YARA rule files found in directory");
        } else {
            debug!(count = rule_count, "YARA rules validated");
        }

        Ok(result)
    }

    #[cfg(not(feature = "yara"))]
    pub fn validate_yara_rules(_rules_dir: &Path) -> Result<ValidationResult> {
        let mut result = ValidationResult::new();
        result.warning(
            "yara",
            "YARA feature not enabled - skipping rule validation",
        );
        Ok(result)
    }

    /// Validate Sigma rules parsing
    pub fn validate_sigma_rules(rules_dir: &Path) -> Result<ValidationResult> {
        let mut result = ValidationResult::new();

        if !rules_dir.exists() {
            result.error(
                "sigma_rules",
                format!(
                    "Sigma rules directory does not exist: {}",
                    rules_dir.display()
                ),
            );
            return Ok(result);
        }

        debug!(path = %rules_dir.display(), "Validating Sigma rules");

        let mut rule_count = 0;

        // Recursively find all .yml and .yaml files
        for entry in walkdir::WalkDir::new(rules_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "yml" || ext == "yaml" {
                    rule_count += 1;

                    // Try to parse as Sigma rule (basic YAML validation)
                    match std::fs::read_to_string(path) {
                        Ok(content) => {
                            // Basic YAML validation - we'd need a proper Sigma parser here
                            // For now, just check it's valid YAML
                            if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                                result.error(
                                    format!("sigma:{}", path.display()),
                                    format!("Invalid YAML: {}", e),
                                );
                            }
                        }
                        Err(e) => {
                            result.error(
                                format!("sigma:{}", path.display()),
                                format!("Failed to read rule file: {}", e),
                            );
                        }
                    }
                }
            }
        }

        if rule_count == 0 {
            result.warning("sigma_rules", "No Sigma rule files found in directory");
        } else {
            debug!(count = rule_count, "Sigma rules validated");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_basic_config() {
        let config = AgentConfig::default();
        let result = ConfigValidator::validate_config(&config);
        assert!(result.is_valid(), "Default config should be valid");
    }

    #[test]
    fn test_validate_empty_agent_id() {
        let mut config = AgentConfig::default();
        config.agent_id = String::new();
        let result = ConfigValidator::validate_config(&config);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.field == "agent_id"));
    }

    #[test]
    fn test_validate_invalid_server_url() {
        let mut config = AgentConfig::default();
        config.server_url = "http://invalid".to_string();
        let result = ConfigValidator::validate_config(&config);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.field == "server_url"));
    }

    #[test]
    fn test_validate_entropy_threshold() {
        let mut config = AgentConfig::default();
        config.entropy_threshold = 10.0; // Invalid: > 8.0
        let result = ConfigValidator::validate_config(&config);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.field == "entropy_threshold"));
    }

    #[test]
    fn test_validate_cpu_percent() {
        let mut config = AgentConfig::default();
        config.max_cpu_percent = 150.0; // Invalid: > 100.0
        let result = ConfigValidator::validate_config(&config);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.field == "max_cpu_percent"));
    }

    #[test]
    fn test_validate_intervals() {
        let mut config = AgentConfig::default();
        config.heartbeat_interval_seconds = 0; // Invalid
        let result = ConfigValidator::validate_config(&config);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "heartbeat_interval_seconds"));
    }

    #[test]
    fn test_toml_validation() {
        let valid_toml = r#"
            agent_id = "test-agent"
            server_url = "wss://localhost:4000"
            heartbeat_interval_seconds = 30
            batch_size = 100
            batch_timeout_seconds = 5
        "#;

        let result = ConfigValidator::validate_toml_string(valid_toml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_toml() {
        let invalid_toml = r#"
            agent_id = "test
            this is not valid toml
        "#;

        let result = ConfigValidator::validate_toml_string(invalid_toml);
        assert!(result.is_err());
    }
}
