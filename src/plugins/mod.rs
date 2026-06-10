//! WASM-based Plugin System for Tamandua EDR
//!
//! This module provides a secure, sandboxed plugin runtime that allows third-party
//! extensions to run safely within the agent. Plugins are compiled to WebAssembly
//! and executed in a restricted environment with resource limits and capability-based
//! security.
//!
//! # Plugin Types
//!
//! - **Collectors**: Gather custom telemetry data
//! - **Analyzers**: Analyze events with custom logic
//! - **Response Actions**: Execute custom remediation steps
//!
//! # Security
//!
//! - WASM sandbox execution (no direct system access)
//! - Resource limits (CPU, memory, disk I/O)
//! - Capability-based filesystem access
//! - Plugin signature verification (Ed25519)
//! - Network access control (allowlist/denylist)
//!
//! # Example
//!
//! ```no_run
//! use tamandua_agent::plugins::{PluginManager, PluginConfig};
//!
//! let mut manager = PluginManager::new().await?;
//! let config = PluginConfig::from_file("plugins/custom_collector.toml")?;
//! manager.load_plugin(config).await?;
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub mod api;
pub mod loader;
pub mod monitor;
pub mod runtime;
pub mod sandbox;

use runtime::PluginRuntime;
use sandbox::SandboxConfig;

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique plugin identifier
    pub id: String,
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin author
    pub author: String,
    /// Plugin description
    pub description: String,
    /// Plugin type
    pub plugin_type: PluginType,
    /// Required API version
    pub api_version: String,
    /// Plugin dependencies
    pub dependencies: Vec<String>,
    /// Plugin capabilities (required permissions)
    pub capabilities: Vec<Capability>,
}

/// Plugin type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginType {
    /// Custom telemetry collector
    Collector,
    /// Event analyzer
    Analyzer,
    /// Response action
    Response,
}

/// Plugin capability (permission)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read filesystem access
    FilesystemRead,
    /// Write filesystem access
    FilesystemWrite,
    /// Network access (with optional allowlist)
    Network(Option<Vec<String>>),
    /// Process information access
    ProcessInfo,
    /// System information access
    SystemInfo,
    /// Send events to backend
    SendEvents,
    /// Execute response actions
    ExecuteActions,
    /// Access to YARA scan results
    YaraResults,
    /// Access to ML inference results
    MlResults,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin metadata
    pub metadata: PluginMetadata,
    /// Path to WASM module
    pub wasm_path: PathBuf,
    /// Path to signature file (Ed25519)
    pub signature_path: PathBuf,
    /// Public key for signature verification
    pub public_key: String,
    /// Sandbox configuration
    pub sandbox: SandboxConfig,
    /// Plugin-specific configuration
    pub config: HashMap<String, serde_json::Value>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Auto-start on agent startup
    pub autostart: bool,
    /// Enabled status
    pub enabled: bool,
}

impl PluginConfig {
    /// Load plugin configuration from TOML file
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read plugin config: {:?}", path))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse plugin config: {:?}", path))
    }

    /// Validate plugin configuration
    pub fn validate(&self) -> Result<()> {
        // Check WASM file exists
        if !self.wasm_path.exists() {
            anyhow::bail!("WASM module not found: {:?}", self.wasm_path);
        }

        // Check signature file exists
        if !self.signature_path.exists() {
            anyhow::bail!("Signature file not found: {:?}", self.signature_path);
        }

        // Validate public key format
        if self.public_key.is_empty() {
            anyhow::bail!("Public key is empty");
        }

        // Validate API version compatibility
        if !is_api_version_compatible(&self.metadata.api_version) {
            anyhow::bail!(
                "Incompatible API version: {} (expected: {})",
                self.metadata.api_version,
                CURRENT_API_VERSION
            );
        }

        Ok(())
    }
}

/// Current plugin API version
pub const CURRENT_API_VERSION: &str = "1.0.0";

/// Check if API version is compatible
fn is_api_version_compatible(version: &str) -> bool {
    // Simple semantic versioning check (major version must match)
    let current_major = CURRENT_API_VERSION.split('.').next().unwrap_or("0");
    let plugin_major = version.split('.').next().unwrap_or("0");
    current_major == plugin_major
}

/// Plugin instance state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginState {
    /// Plugin is loading
    Loading,
    /// Plugin is running
    Running,
    /// Plugin is stopped
    Stopped,
    /// Plugin has crashed
    Crashed,
    /// Plugin is being unloaded
    Unloading,
}

/// Plugin instance
pub struct PluginInstance {
    /// Plugin configuration
    pub config: PluginConfig,
    /// Plugin runtime
    pub runtime: PluginRuntime,
    /// Current state
    pub state: PluginState,
    /// Plugin metrics
    pub metrics: PluginMetrics,
}

/// Plugin metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginMetrics {
    /// Total events collected (for collectors)
    pub events_collected: u64,
    /// Total events analyzed (for analyzers)
    pub events_analyzed: u64,
    /// Total actions executed (for response plugins)
    pub actions_executed: u64,
    /// Total errors
    pub errors: u64,
    /// CPU time used (microseconds)
    pub cpu_time_us: u64,
    /// Memory used (bytes)
    pub memory_bytes: u64,
    /// Disk I/O (bytes)
    pub disk_io_bytes: u64,
    /// Network I/O (bytes)
    pub network_io_bytes: u64,
    /// Last execution time (microseconds)
    pub last_execution_us: u64,
}

/// Plugin manager
pub struct PluginManager {
    /// Loaded plugins
    plugins: Arc<RwLock<HashMap<String, PluginInstance>>>,
    /// Plugin monitor
    monitor: monitor::PluginMonitor,
}

impl PluginManager {
    /// Create new plugin manager
    pub async fn new() -> Result<Self> {
        let monitor = monitor::PluginMonitor::new();

        Ok(Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            monitor,
        })
    }

    /// Load plugin from configuration
    pub async fn load_plugin(&mut self, config: PluginConfig) -> Result<()> {
        info!(
            plugin_id = %config.metadata.id,
            plugin_name = %config.metadata.name,
            plugin_type = ?config.metadata.plugin_type,
            "Loading plugin"
        );

        // Validate configuration
        config.validate()?;

        // Verify signature
        loader::verify_signature(
            &config.wasm_path,
            &config.signature_path,
            &config.public_key,
        )
        .context("Plugin signature verification failed")?;

        // Create runtime
        let runtime = PluginRuntime::new(&config)
            .await
            .context("Failed to create plugin runtime")?;

        // Create plugin instance
        let instance = PluginInstance {
            config: config.clone(),
            runtime,
            state: PluginState::Loading,
            metrics: PluginMetrics::default(),
        };

        // Store plugin
        let mut plugins = self.plugins.write().await;
        plugins.insert(config.metadata.id.clone(), instance);

        // Start monitoring
        self.monitor.start_monitoring(&config.metadata.id);

        info!(plugin_id = %config.metadata.id, "Plugin loaded successfully");

        Ok(())
    }

    /// Unload plugin
    pub async fn unload_plugin(&mut self, plugin_id: &str) -> Result<()> {
        info!(plugin_id = %plugin_id, "Unloading plugin");

        let mut plugins = self.plugins.write().await;
        if let Some(mut instance) = plugins.remove(plugin_id) {
            instance.state = PluginState::Unloading;

            // Shutdown runtime
            instance.runtime.shutdown().await?;

            // Stop monitoring
            self.monitor.stop_monitoring(plugin_id);

            info!(plugin_id = %plugin_id, "Plugin unloaded successfully");
        } else {
            warn!(plugin_id = %plugin_id, "Plugin not found");
        }

        Ok(())
    }

    /// Start plugin
    pub async fn start_plugin(&mut self, plugin_id: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        if let Some(instance) = plugins.get_mut(plugin_id) {
            instance.runtime.start().await?;
            instance.state = PluginState::Running;
            info!(plugin_id = %plugin_id, "Plugin started");
            Ok(())
        } else {
            anyhow::bail!("Plugin not found: {}", plugin_id)
        }
    }

    /// Stop plugin
    pub async fn stop_plugin(&mut self, plugin_id: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        if let Some(instance) = plugins.get_mut(plugin_id) {
            instance.runtime.stop().await?;
            instance.state = PluginState::Stopped;
            info!(plugin_id = %plugin_id, "Plugin stopped");
            Ok(())
        } else {
            anyhow::bail!("Plugin not found: {}", plugin_id)
        }
    }

    /// Get plugin state
    pub async fn get_plugin_state(&self, plugin_id: &str) -> Option<PluginState> {
        let plugins = self.plugins.read().await;
        plugins.get(plugin_id).map(|p| p.state)
    }

    /// Get plugin metrics
    pub async fn get_plugin_metrics(&self, plugin_id: &str) -> Option<PluginMetrics> {
        let plugins = self.plugins.read().await;
        plugins.get(plugin_id).map(|p| p.metrics.clone())
    }

    /// List all plugins
    pub async fn list_plugins(&self) -> Vec<PluginMetadata> {
        let plugins = self.plugins.read().await;
        plugins
            .values()
            .map(|p| p.config.metadata.clone())
            .collect()
    }

    /// Reload plugin (hot-reload)
    pub async fn reload_plugin(&mut self, plugin_id: &str) -> Result<()> {
        info!(plugin_id = %plugin_id, "Reloading plugin");

        // Get current config
        let config = {
            let plugins = self.plugins.read().await;
            plugins
                .get(plugin_id)
                .map(|p| p.config.clone())
                .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", plugin_id))?
        };

        // Unload and reload
        self.unload_plugin(plugin_id).await?;
        self.load_plugin(config).await?;
        self.start_plugin(plugin_id).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_version_compatibility() {
        assert!(is_api_version_compatible("1.0.0"));
        assert!(is_api_version_compatible("1.1.0"));
        assert!(is_api_version_compatible("1.9.9"));
        assert!(!is_api_version_compatible("2.0.0"));
        assert!(!is_api_version_compatible("0.9.0"));
    }
}
