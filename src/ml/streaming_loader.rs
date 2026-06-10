//! Streaming Model Loader for Incremental Inference
//!
//! This module implements the core streaming model loading infrastructure that
//! enables memory-efficient, on-demand loading of model weights for ML inference.
//!
//! ## Architecture
//!
//! Instead of loading the entire ONNX model into memory at startup (typically
//! 100-500MB for Malware-SMELL), we:
//!
//! 1. **Chunk the model offline** into layer-wise files (see `model_chunker.rs`)
//! 2. **Load chunks on-demand** during inference using memory-mapped files
//! 3. **Cache hot chunks** in an LRU cache to avoid repeated disk I/O
//! 4. **Evict cold chunks** to stay within memory budget
//!
//! ## Execution Graph
//!
//! The loader maintains a dependency graph of layer chunks. During inference:
//! 1. Parse the input to determine required layers
//! 2. Topologically sort layer dependencies
//! 3. Load layers in order, checking cache first
//! 4. Execute each layer as weights become available
//! 5. Evict intermediate layers no longer needed
//!
//! ## Performance Targets
//!
//! - **Cold start** (cache empty): 70% faster than full model load
//! - **Warm start** (cache full): 95% faster than full model load
//! - **Inference latency**: <10% overhead vs. full model in-memory
//! - **Memory usage**: 50% reduction vs. full model in-memory

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

use super::layer_cache::{CacheStats, LayerCache};
use super::model_chunker::{ChunkManifest, ModelChunk};

#[cfg(feature = "onnx")]
use ort::{session::Session, value::Value};

/// Configuration for streaming model loader.
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Path to the chunked model directory (contains manifest.json and .chunk files).
    pub model_dir: PathBuf,
    /// Maximum memory for layer cache (default: 128MB).
    pub cache_size_bytes: usize,
    /// Whether to enable compression for cached layers.
    pub compress_cache: bool,
    /// Number of intra-op threads for ONNX Runtime.
    pub intra_threads: usize,
}

impl StreamingConfig {
    /// Create default config for a given model directory.
    pub fn new(model_dir: impl Into<PathBuf>) -> Self {
        Self {
            model_dir: model_dir.into(),
            cache_size_bytes: 128 * 1024 * 1024, // 128MB
            compress_cache: true,
            intra_threads: 2,
        }
    }
}

/// Metadata for a single layer (re-exported from model_chunker for convenience).
pub use super::model_chunker::LayerMetadata;

/// Statistics for streaming loader performance.
#[derive(Debug, Clone, Default)]
pub struct StreamingStats {
    /// Total number of chunks loaded from disk.
    pub chunks_loaded: u64,
    /// Total bytes read from disk.
    pub bytes_loaded: u64,
    /// Total time spent loading chunks (milliseconds).
    pub load_time_ms: u64,
    /// Total number of inferences performed.
    pub inferences: u64,
    /// Total inference time (milliseconds).
    pub inference_time_ms: u64,
}

/// Streaming model loader with incremental weight loading.
pub struct StreamingModelLoader {
    /// Configuration.
    config: StreamingConfig,
    /// Chunk manifest.
    pub(crate) manifest: ChunkManifest,
    /// Layer cache (LRU).
    cache: LayerCache,
    /// Dependency graph: layer_id -> list of dependencies.
    dependencies: HashMap<String, Vec<String>>,
    /// Statistics.
    stats: StreamingStats,
    /// ONNX session (optional, for integration with ort).
    #[cfg(feature = "onnx")]
    session: Option<Session>,
    /// Placeholder when ONNX feature not enabled.
    #[cfg(not(feature = "onnx"))]
    _session: (),
}

impl StreamingModelLoader {
    /// Create a new streaming loader from a chunked model directory.
    ///
    /// The directory must contain:
    /// - `manifest.json` - Model manifest
    /// - `*.chunk` files - Layer weight chunks
    pub fn new(config: StreamingConfig) -> Result<Self> {
        let manifest_path = config.model_dir.join("manifest.json");
        let manifest =
            ChunkManifest::load(&manifest_path).context("Failed to load chunk manifest")?;

        // Build dependency graph.
        let mut dependencies = HashMap::new();
        for chunk in &manifest.chunks {
            let chunk_path = config.model_dir.join(&chunk.file_name);
            let model_chunk = ModelChunk::read_from_file(&chunk_path)
                .with_context(|| format!("Failed to load chunk: {}", chunk.file_name))?;
            dependencies.insert(
                model_chunk.metadata.layer_id.clone(),
                model_chunk.metadata.dependencies.clone(),
            );
        }

        let cache = LayerCache::new(config.cache_size_bytes);

        info!(
            model_dir = %config.model_dir.display(),
            num_layers = manifest.num_layers,
            cache_size_mb = config.cache_size_bytes / (1024 * 1024),
            "Initialized streaming model loader"
        );

        Ok(Self {
            config,
            manifest,
            cache,
            dependencies,
            stats: StreamingStats::default(),
            #[cfg(feature = "onnx")]
            session: None,
            #[cfg(not(feature = "onnx"))]
            _session: (),
        })
    }

    /// Initialize ONNX Runtime session (when `onnx` feature is enabled).
    ///
    /// This creates a minimal session that can be used for inference with
    /// incrementally loaded weights. Note that true incremental loading of
    /// ONNX models requires custom runtime integration; this is a simplified
    /// demonstration.
    #[cfg(feature = "onnx")]
    pub fn init_onnx_session(&mut self) -> Result<()> {
        // In a full implementation, we would:
        // 1. Create a custom ONNX session that supports dynamic weight loading
        // 2. Hook into the ORT execution graph to load weights on-demand
        // 3. Integrate with the layer cache
        //
        // For now, this is a placeholder demonstrating the API.
        warn!("ONNX session initialization not yet fully implemented for streaming loader");
        Ok(())
    }

    /// Load a specific layer's weights.
    ///
    /// Checks cache first; if not found, loads from disk and caches.
    pub fn load_layer(&mut self, layer_id: &str) -> Result<Vec<f32>> {
        // Check cache first.
        if let Some(cached_data) = self.cache.get(layer_id) {
            debug!(layer_id = %layer_id, "Layer cache hit");
            // Deserialize f32 from bytes.
            return self.deserialize_weights(&cached_data);
        }

        // Cache miss - load from disk.
        debug!(layer_id = %layer_id, "Layer cache miss, loading from disk");
        let load_start = Instant::now();

        let chunk_meta = self
            .manifest
            .get_chunk(layer_id)
            .ok_or_else(|| anyhow::anyhow!("Layer not found in manifest: {}", layer_id))?;

        let chunk_path = self.config.model_dir.join(&chunk_meta.file_name);
        let chunk = ModelChunk::read_from_file(&chunk_path)
            .with_context(|| format!("Failed to load chunk: {}", chunk_meta.file_name))?;

        let weights = chunk
            .get_weights()
            .context("Failed to extract weights from chunk")?;

        // Serialize back to bytes for caching.
        let weight_bytes = self.serialize_weights(&weights);

        // Cache the raw bytes (optionally compressed).
        self.cache
            .insert(
                layer_id.to_string(),
                weight_bytes,
                self.config.compress_cache,
            )
            .context("Failed to insert layer into cache")?;

        // Update stats.
        let load_time = load_start.elapsed();
        self.stats.chunks_loaded += 1;
        self.stats.bytes_loaded += chunk.data.len() as u64;
        self.stats.load_time_ms += load_time.as_millis() as u64;

        debug!(
            layer_id = %layer_id,
            bytes = chunk.data.len(),
            load_ms = load_time.as_millis(),
            "Loaded layer from disk"
        );

        Ok(weights)
    }

    /// Preload a set of layers (for warm-up).
    ///
    /// Useful for loading critical layers (e.g., early conv layers) at startup
    /// to minimize cold-start latency.
    pub fn preload_layers(&mut self, layer_ids: &[String]) -> Result<()> {
        info!(count = layer_ids.len(), "Preloading layers");
        for layer_id in layer_ids {
            self.load_layer(layer_id)?;
        }
        Ok(())
    }

    /// Load all layers required for inference, respecting dependencies.
    ///
    /// Returns the layers in topological order (dependencies first).
    pub fn load_inference_graph(&mut self, required_layers: &[String]) -> Result<Vec<String>> {
        let sorted = self.topological_sort(required_layers)?;
        info!(
            required = required_layers.len(),
            total = sorted.len(),
            "Computed inference graph"
        );

        // Load each layer in dependency order.
        for layer_id in &sorted {
            self.load_layer(layer_id)?;
        }

        Ok(sorted)
    }

    /// Topologically sort layers based on dependencies.
    fn topological_sort(&self, required: &[String]) -> Result<Vec<String>> {
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        let mut visiting = HashSet::new();

        for layer_id in required {
            if !visited.contains(layer_id) {
                self.dfs_topo(layer_id, &mut visited, &mut visiting, &mut stack)?;
            }
        }

        // DFS post-order push already yields dependencies before dependents,
        // so no reversal is needed.
        Ok(stack)
    }

    /// DFS helper for topological sort.
    fn dfs_topo(
        &self,
        layer_id: &str,
        visited: &mut HashSet<String>,
        visiting: &mut HashSet<String>,
        stack: &mut Vec<String>,
    ) -> Result<()> {
        if visiting.contains(layer_id) {
            anyhow::bail!("Circular dependency detected: {}", layer_id);
        }

        if visited.contains(layer_id) {
            return Ok(());
        }

        visiting.insert(layer_id.to_string());

        if let Some(deps) = self.dependencies.get(layer_id) {
            for dep in deps {
                self.dfs_topo(dep, visited, visiting, stack)?;
            }
        }

        visiting.remove(layer_id);
        visited.insert(layer_id.to_string());
        stack.push(layer_id.to_string());

        Ok(())
    }

    /// Run inference on input data (simplified demonstration).
    ///
    /// In a full implementation, this would:
    /// 1. Parse the input to determine required layers
    /// 2. Load layers in topological order
    /// 3. Execute the inference graph layer-by-layer
    /// 4. Return the final output
    ///
    /// For now, this is a placeholder showing the API.
    pub fn run_inference(&mut self, _input: &[u8]) -> Result<Vec<f32>> {
        let start = Instant::now();
        self.stats.inferences += 1;

        // Example: Load all layers (in production, we'd only load required ones).
        let all_layers: Vec<String> = self
            .manifest
            .chunks
            .iter()
            .map(|c| c.layer_id.clone())
            .collect();

        let _sorted_layers = self.load_inference_graph(&all_layers)?;

        // Placeholder inference result.
        let output = vec![0.0f32; self.manifest.output_shape.iter().product()];

        let inference_time = start.elapsed();
        self.stats.inference_time_ms += inference_time.as_millis() as u64;

        debug!(
            inference_ms = inference_time.as_millis(),
            "Completed inference"
        );

        Ok(output)
    }

    /// Get current cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Get streaming loader statistics.
    pub fn stats(&self) -> &StreamingStats {
        &self.stats
    }

    /// Log performance statistics.
    pub fn log_stats(&self) {
        info!(
            chunks_loaded = self.stats.chunks_loaded,
            bytes_loaded_mb = self.stats.bytes_loaded / (1024 * 1024),
            load_time_ms = self.stats.load_time_ms,
            inferences = self.stats.inferences,
            inference_time_ms = self.stats.inference_time_ms,
            avg_inference_ms = if self.stats.inferences > 0 {
                self.stats.inference_time_ms / self.stats.inferences
            } else {
                0
            },
            "Streaming loader statistics"
        );
        self.cache.log_stats();
    }

    /// Clear the layer cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    // Helper methods for weight serialization.

    fn serialize_weights(&self, weights: &[f32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(weights.len() * 4);
        for &w in weights {
            data.extend_from_slice(&w.to_le_bytes());
        }
        data
    }

    fn deserialize_weights(&self, data: &[u8]) -> Result<Vec<f32>> {
        if data.len() % 4 != 0 {
            anyhow::bail!("Invalid weight data size: {} bytes", data.len());
        }
        let mut weights = Vec::with_capacity(data.len() / 4);
        for chunk in data.chunks_exact(4) {
            let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
            weights.push(f32::from_le_bytes(bytes));
        }
        Ok(weights)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::model_chunker::{ChunkManifest, ChunkMetadata, LayerMetadata, ModelChunk};
    use tempfile::TempDir;

    fn create_test_model(dir: &Path) -> Result<()> {
        // Create a simple 2-layer model.
        let manifest = ChunkManifest {
            model_name: "test_model".to_string(),
            model_version: "1.0.0".to_string(),
            input_shape: vec![1, 3, 64, 64],
            output_shape: vec![1, 8],
            num_layers: 2,
            chunks: vec![
                ChunkMetadata {
                    layer_id: "layer_0".to_string(),
                    file_name: "layer_0.chunk".to_string(),
                    file_size: 0,
                    checksum: "".to_string(),
                },
                ChunkMetadata {
                    layer_id: "layer_1".to_string(),
                    file_name: "layer_1.chunk".to_string(),
                    file_size: 0,
                    checksum: "".to_string(),
                },
            ],
        };
        manifest.save(&dir.join("manifest.json"))?;

        // Create chunk files.
        for (i, chunk_meta) in manifest.chunks.iter().enumerate() {
            let layer_meta = LayerMetadata {
                layer_id: chunk_meta.layer_id.clone(),
                layer_type: "Linear".to_string(),
                weight_shape: vec![128, 128],
                weight_count: 128 * 128,
                weight_bytes: 128 * 128 * 4,
                compressed: false,
                dependencies: if i == 0 {
                    vec![]
                } else {
                    vec!["layer_0".to_string()]
                },
            };
            let weights: Vec<f32> = (0..128 * 128)
                .map(|j| (i * 10000 + j) as f32 * 0.001)
                .collect();
            let chunk = ModelChunk::new(layer_meta, weights);
            chunk.write_to_file(&dir.join(&chunk_meta.file_name))?;
        }

        Ok(())
    }

    #[test]
    fn test_streaming_loader_init() {
        let temp_dir = TempDir::new().unwrap();
        create_test_model(temp_dir.path()).unwrap();

        let config = StreamingConfig::new(temp_dir.path());
        let loader = StreamingModelLoader::new(config).unwrap();

        assert_eq!(loader.manifest.num_layers, 2);
        assert_eq!(loader.dependencies.len(), 2);
    }

    #[test]
    fn test_load_layer() {
        let temp_dir = TempDir::new().unwrap();
        create_test_model(temp_dir.path()).unwrap();

        let config = StreamingConfig::new(temp_dir.path());
        let mut loader = StreamingModelLoader::new(config).unwrap();

        // Load layer_0.
        let weights = loader.load_layer("layer_0").unwrap();
        assert_eq!(weights.len(), 128 * 128);

        // Load again - should be cached.
        let weights2 = loader.load_layer("layer_0").unwrap();
        assert_eq!(weights, weights2);

        // Cache stats.
        let cache_stats = loader.cache_stats();
        assert_eq!(cache_stats.hits, 1);
        assert_eq!(cache_stats.misses, 1);
    }

    #[test]
    fn test_topological_sort() {
        let temp_dir = TempDir::new().unwrap();
        create_test_model(temp_dir.path()).unwrap();

        let config = StreamingConfig::new(temp_dir.path());
        let loader = StreamingModelLoader::new(config).unwrap();

        // layer_1 depends on layer_0.
        let sorted = loader
            .topological_sort(&["layer_1".to_string(), "layer_0".to_string()])
            .unwrap();

        // layer_0 should come before layer_1.
        assert_eq!(sorted[0], "layer_0");
        assert_eq!(sorted[1], "layer_1");
    }
}
