//! WASM Plugin Runtime using Wasmtime
//!
//! This module provides the WASM runtime for executing plugins in a sandboxed environment.

#![cfg(feature = "plugins")]

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use wasmtime::*;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};

use super::api::{AnalysisResult, PluginEvent, ResponseAction, ResponseResult};
use super::sandbox::{ResourceTracker, SandboxConfig};
use super::{PluginConfig, PluginType};

/// Plugin runtime state
pub struct PluginRuntime {
    /// WASM engine
    engine: Engine,

    /// WASM module
    module: Module,

    /// Runtime linker
    linker: Arc<RwLock<Linker<RuntimeState>>>,

    /// Plugin configuration
    config: PluginConfig,

    /// Resource tracker
    resource_tracker: Arc<RwLock<ResourceTracker>>,
}

/// Runtime state (passed to host functions)
pub struct RuntimeState {
    /// WASI context
    wasi: WasiCtx,

    /// Plugin configuration
    config: PluginConfig,

    /// Resource tracker
    resource_tracker: Arc<RwLock<ResourceTracker>>,

    /// Host API implementation
    host_api: Arc<dyn super::api::PluginHostApi + Send + Sync>,
}

impl PluginRuntime {
    /// Create new plugin runtime
    pub async fn new(config: &PluginConfig) -> Result<Self> {
        info!(plugin_id = %config.metadata.id, "Creating plugin runtime");

        // Create WASM engine with resource limits
        let mut wasm_config = Config::new();
        wasm_config.async_support(true);

        // Memory limits
        wasm_config.max_wasm_stack(1024 * 1024); // 1MB stack

        // Fuel for execution limits (CPU time tracking)
        wasm_config.consume_fuel(true);

        let engine = Engine::new(&wasm_config)?;

        // Load WASM module
        let module = Module::from_file(&engine, &config.wasm_path)
            .with_context(|| format!("Failed to load WASM module: {:?}", config.wasm_path))?;

        // Create linker
        let mut linker = Linker::new(&engine);

        // Add WASI if enabled
        if config.sandbox.enable_wasi {
            wasmtime_wasi::add_to_linker(&mut linker, |state: &mut RuntimeState| &mut state.wasi)?;
        }

        // Create resource tracker
        let resource_tracker = Arc::new(RwLock::new(ResourceTracker::new()));

        // Register host functions
        Self::register_host_functions(&mut linker, &resource_tracker)?;

        Ok(Self {
            engine,
            module,
            linker: Arc::new(RwLock::new(linker)),
            config: config.clone(),
            resource_tracker,
        })
    }

    /// Register host functions that plugins can call
    fn register_host_functions(
        linker: &mut Linker<RuntimeState>,
        resource_tracker: &Arc<RwLock<ResourceTracker>>,
    ) -> Result<()> {
        // Log function
        linker.func_wrap(
            "env",
            "host_log",
            |mut caller: Caller<'_, RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32| {
                let level_str = match level {
                    0 => "TRACE",
                    1 => "DEBUG",
                    2 => "INFO",
                    3 => "WARN",
                    4 => "ERROR",
                    _ => "UNKNOWN",
                };

                // Read message from WASM memory
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| anyhow::anyhow!("Failed to get memory"))?;

                let data = memory.data(&caller);
                let msg_start = msg_ptr as usize;
                let msg_end = msg_start + msg_len as usize;

                if msg_end > data.len() {
                    return Err(anyhow::anyhow!("Invalid memory access"));
                }

                let msg = std::str::from_utf8(&data[msg_start..msg_end])?;

                match level {
                    0 => tracing::trace!("[PLUGIN] {}", msg),
                    1 => tracing::debug!("[PLUGIN] {}", msg),
                    2 => tracing::info!("[PLUGIN] {}", msg),
                    3 => tracing::warn!("[PLUGIN] {}", msg),
                    4 => tracing::error!("[PLUGIN] {}", msg),
                    _ => tracing::info!("[PLUGIN] {}", msg),
                }

                Ok(())
            },
        )?;

        // Send event function
        linker.func_wrap(
            "env",
            "host_send_event",
            |caller: Caller<'_, RuntimeState>, event_ptr: i32, event_len: i32| -> Result<i32> {
                // Read event from WASM memory
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| anyhow::anyhow!("Failed to get memory"))?;

                let data = memory.data(&caller);
                let event_start = event_ptr as usize;
                let event_end = event_start + event_len as usize;

                if event_end > data.len() {
                    return Ok(-1); // Error
                }

                let event_json = &data[event_start..event_end];
                let event: PluginEvent = serde_json::from_slice(event_json)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize event: {}", e))?;

                // Call host API
                let state = caller.data();
                state.host_api.send_event(event)?;

                Ok(0) // Success
            },
        )?;

        // Get process info function
        linker.func_wrap(
            "env",
            "host_get_process_info",
            |mut caller: Caller<'_, RuntimeState>, pid: u32, out_ptr: i32| -> Result<i32> {
                let state = caller.data();

                match state.host_api.get_process_info(pid)? {
                    Some(info) => {
                        // Serialize to JSON
                        let json = serde_json::to_vec(&info)?;

                        // Write to WASM memory
                        let memory = caller
                            .get_export("memory")
                            .and_then(|e| e.into_memory())
                            .ok_or_else(|| anyhow::anyhow!("Failed to get memory"))?;

                        let data = memory.data_mut(&mut caller);
                        let start = out_ptr as usize;
                        let end = start + json.len();

                        if end > data.len() {
                            return Ok(-1);
                        }

                        data[start..end].copy_from_slice(&json);
                        Ok(json.len() as i32)
                    }
                    None => Ok(0), // Not found
                }
            },
        )?;

        // Kill process function
        linker.func_wrap(
            "env",
            "host_kill_process",
            |caller: Caller<'_, RuntimeState>, pid: u32, force: i32| -> Result<i32> {
                let state = caller.data();

                match state.host_api.kill_process(pid, force != 0)? {
                    true => Ok(1),  // Success
                    false => Ok(0), // Failed
                }
            },
        )?;

        // Quarantine file function
        linker.func_wrap(
            "env",
            "host_quarantine_file",
            |mut caller: Caller<'_, RuntimeState>,
             path_ptr: i32,
             path_len: i32,
             out_ptr: i32|
             -> Result<i32> {
                // Read path from WASM memory
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| anyhow::anyhow!("Failed to get memory"))?;

                let data = memory.data(&caller);
                let path_start = path_ptr as usize;
                let path_end = path_start + path_len as usize;

                if path_end > data.len() {
                    return Ok(-1);
                }

                let path = std::str::from_utf8(&data[path_start..path_end])?;

                let state = caller.data();
                let quarantine_id = state.host_api.quarantine_file(path)?;

                // Write quarantine ID back to WASM memory
                let id_bytes = quarantine_id.as_bytes();
                let data_mut = memory.data_mut(&mut caller);
                let out_start = out_ptr as usize;
                let out_end = out_start + id_bytes.len();

                if out_end > data_mut.len() {
                    return Ok(-1);
                }

                data_mut[out_start..out_end].copy_from_slice(id_bytes);
                Ok(id_bytes.len() as i32)
            },
        )?;

        Ok(())
    }

    /// Start the plugin
    pub async fn start(&mut self) -> Result<()> {
        info!(plugin_id = %self.config.metadata.id, "Starting plugin");

        // Create store with runtime state
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_args()?
            .build();

        let host_api = Arc::new(HostApiImpl::new(self.config.clone()));

        let state = RuntimeState {
            wasi,
            config: self.config.clone(),
            resource_tracker: Arc::clone(&self.resource_tracker),
            host_api,
        };

        let mut store = Store::new(&self.engine, state);

        // Set fuel limit for execution time control
        store.add_fuel(10_000_000)?; // Generous initial fuel

        // Instantiate module
        let linker = self.linker.read().await;
        let instance = linker.instantiate_async(&mut store, &self.module).await?;

        // Call init function
        let init_func = instance
            .get_typed_func::<(), ()>(&mut store, "plugin_init")
            .context("Plugin must export 'plugin_init' function")?;

        init_func
            .call_async(&mut store, ())
            .await
            .context("Plugin initialization failed")?;

        info!(plugin_id = %self.config.metadata.id, "Plugin started successfully");

        Ok(())
    }

    /// Stop the plugin
    pub async fn stop(&mut self) -> Result<()> {
        info!(plugin_id = %self.config.metadata.id, "Stopping plugin");

        // Reset resource tracker
        let mut tracker = self.resource_tracker.write().await;
        tracker.reset();

        Ok(())
    }

    /// Shutdown the plugin
    pub async fn shutdown(&mut self) -> Result<()> {
        info!(plugin_id = %self.config.metadata.id, "Shutting down plugin");
        self.stop().await
    }

    /// Execute collector plugin
    pub async fn collect(&mut self) -> Result<Vec<PluginEvent>> {
        // Create store
        let wasi = WasiCtxBuilder::new().build();
        let host_api = Arc::new(HostApiImpl::new(self.config.clone()));

        let state = RuntimeState {
            wasi,
            config: self.config.clone(),
            resource_tracker: Arc::clone(&self.resource_tracker),
            host_api,
        };

        let mut store = Store::new(&self.engine, state);
        store.add_fuel(1_000_000)?;

        // Instantiate
        let linker = self.linker.read().await;
        let instance = linker.instantiate_async(&mut store, &self.module).await?;

        // Call collect function
        let collect_func = instance.get_typed_func::<(), i32>(&mut store, "plugin_collect")?;

        let result_ptr = collect_func.call_async(&mut store, ()).await?;

        // STUB — not production; plugin_collect's return pointer is ignored and no
        // events are decoded from WASM linear memory. Always yields zero events.
        let events = vec![]; // TODO: Parse from WASM memory

        Ok(events)
    }
}

/// Host API implementation
struct HostApiImpl {
    config: PluginConfig,
}

impl HostApiImpl {
    fn new(config: PluginConfig) -> Self {
        Self { config }
    }
}

impl super::api::PluginHostApi for HostApiImpl {
    fn log(&self, level: super::api::LogLevel, message: &str) -> Result<()> {
        match level {
            super::api::LogLevel::Trace => tracing::trace!("[PLUGIN] {}", message),
            super::api::LogLevel::Debug => tracing::debug!("[PLUGIN] {}", message),
            super::api::LogLevel::Info => tracing::info!("[PLUGIN] {}", message),
            super::api::LogLevel::Warn => tracing::warn!("[PLUGIN] {}", message),
            super::api::LogLevel::Error => tracing::error!("[PLUGIN] {}", message),
        }
        Ok(())
    }

    // STUB — DESIGN-DORMANT: the WASM plugin runtime host API is not production.
    // Every method below is an inert no-op returning empty/false/default values.
    // The WASM plugin subsystem (wasmtime sandbox + plugin ABI) is not yet shipped;
    // these host functions must be wired to real transport/sysinfo/detection/response
    // backends before any plugin is allowed to call them. Do not treat returns as authoritative.
    fn send_event(&self, event: PluginEvent) -> Result<()> {
        info!("Plugin event: {:?}", event);
        // STUB — not production; event is logged only, never forwarded to backend transport.
        Ok(())
    }

    fn get_process_info(&self, pid: u32) -> Result<Option<super::api::ProcessInfo>> {
        // STUB — not production; always returns None (sysinfo lookup not implemented).
        Ok(None)
    }

    fn get_file_info(&self, path: &str) -> Result<Option<super::api::FileInfo>> {
        // STUB — not production; always returns None (file metadata gathering not implemented).
        Ok(None)
    }

    fn list_network_connections(&self) -> Result<Vec<super::api::NetworkConnection>> {
        // STUB — not production; always returns empty (connection enumeration not implemented).
        Ok(vec![])
    }

    fn read_file(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>> {
        // STUB — not production; always returns empty (sandbox-validated read not implemented).
        Ok(vec![])
    }

    fn hash_file(&self, path: &str, algorithm: super::api::HashAlgorithm) -> Result<String> {
        // STUB — not production; always returns empty string (hashing not implemented).
        Ok(String::new())
    }

    fn yara_scan_file(&self, path: &str) -> Result<Vec<String>> {
        // STUB — not production; always returns no matches (YARA engine not wired in).
        Ok(vec![])
    }

    fn ml_classify_file(&self, path: &str) -> Result<(super::api::Verdict, f64)> {
        // STUB — not production; always returns Unknown/0.0 (ML inference not wired in).
        Ok((super::api::Verdict::Unknown, 0.0))
    }

    fn kill_process(&self, pid: u32, force: bool) -> Result<bool> {
        // STUB — not production; always returns false, no process is killed (response not wired in).
        Ok(false)
    }

    fn quarantine_file(&self, path: &str) -> Result<String> {
        // STUB — not production; always returns empty string, no file is quarantined.
        Ok(String::new())
    }

    fn get_config(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .config
            .config
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from))
    }

    fn get_env(&self, key: &str) -> Result<Option<String>> {
        Ok(self.config.env.get(key).cloned())
    }

    fn http_request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<super::api::HttpResponse> {
        // STUB — not production; no request is sent. Returns a fabricated 200/empty
        // response. Network sandbox validation and an actual HTTP client are not implemented.
        Ok(super::api::HttpResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: vec![],
        })
    }
}
