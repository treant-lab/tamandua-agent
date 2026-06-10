//! LRU Layer Cache for Incremental Model Loading
//!
//! Implements a least-recently-used cache for model layer weights. This allows
//! frequently-accessed layers (e.g., early convolutional layers in CNNs) to
//! remain in memory while evicting rarely-used layers (e.g., late classifier
//! layers that might only run once per sample).
//!
//! ## Design
//!
//! - **Key**: Layer identifier (string: "vgg19_encoder_layer_0")
//! - **Value**: Raw weight bytes (compressed or raw f32 arrays)
//! - **Eviction**: LRU policy with configurable max memory budget
//! - **Thread Safety**: Mutex-protected for multi-threaded inference
//!
//! ## Memory Budget
//!
//! The cache enforces a maximum memory budget (default: 128MB). When inserting
//! a new layer would exceed the budget, the least-recently-used layer is evicted.
//!
//! ## Compression
//!
//! Layers can be stored in compressed form (zstd) to reduce memory footprint.
//! Decompression is performed on-demand during cache hits.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Compression format for cached layer data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    /// No compression (raw bytes).
    None,
    /// Zstd compression (requires `compression` feature).
    #[cfg(feature = "compression")]
    Zstd,
}

/// A cached layer entry with metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Layer identifier (e.g., "vgg19_encoder_layer_0").
    layer_id: String,
    /// Raw or compressed weight bytes.
    data: Vec<u8>,
    /// Size of data in bytes (uncompressed).
    uncompressed_size: usize,
    /// Compression format.
    compression: CompressionFormat,
    /// Timestamp of last access (for LRU eviction).
    last_access: std::time::Instant,
}

impl CacheEntry {
    /// Get uncompressed data, decompressing if necessary.
    fn get_data(&self) -> Result<Vec<u8>> {
        match self.compression {
            CompressionFormat::None => Ok(self.data.clone()),
            #[cfg(feature = "compression")]
            CompressionFormat::Zstd => {
                use std::io::Read;
                let mut decoder =
                    zstd::Decoder::new(&self.data[..]).context("Failed to create zstd decoder")?;
                let mut decompressed = Vec::with_capacity(self.uncompressed_size);
                decoder
                    .read_to_end(&mut decompressed)
                    .context("Failed to decompress layer data")?;
                Ok(decompressed)
            }
        }
    }

    /// Get memory usage of this entry (compressed size + overhead).
    fn memory_usage(&self) -> usize {
        self.data.len() + std::mem::size_of::<CacheEntry>()
    }
}

/// Statistics for cache performance monitoring.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total number of cache hits.
    pub hits: u64,
    /// Total number of cache misses.
    pub misses: u64,
    /// Total number of evictions.
    pub evictions: u64,
    /// Current number of cached layers.
    pub cached_layers: usize,
    /// Current memory usage in bytes.
    pub memory_bytes: usize,
    /// Maximum memory budget in bytes.
    pub max_memory_bytes: usize,
}

impl CacheStats {
    /// Calculate cache hit ratio (0.0 - 1.0).
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Inner state of the layer cache (mutex-protected).
struct CacheState {
    /// Map from layer_id to cache entry.
    entries: HashMap<String, CacheEntry>,
    /// LRU queue (layer_id in order of last access, oldest first).
    lru_queue: Vec<String>,
    /// Current total memory usage.
    current_memory: usize,
    /// Maximum memory budget.
    max_memory: usize,
    /// Statistics.
    stats: CacheStats,
}

impl CacheState {
    fn new(max_memory: usize) -> Self {
        Self {
            entries: HashMap::new(),
            lru_queue: Vec::new(),
            current_memory: 0,
            max_memory,
            stats: CacheStats {
                max_memory_bytes: max_memory,
                ..Default::default()
            },
        }
    }

    /// Update LRU queue when a layer is accessed.
    fn touch(&mut self, layer_id: &str) {
        // Remove from current position and push to end (most recent).
        if let Some(pos) = self.lru_queue.iter().position(|id| id == layer_id) {
            self.lru_queue.remove(pos);
        }
        self.lru_queue.push(layer_id.to_string());
    }

    /// Evict the least-recently-used layer.
    fn evict_lru(&mut self) -> Option<String> {
        if self.lru_queue.is_empty() {
            return None;
        }

        let layer_id = self.lru_queue.remove(0);
        if let Some(entry) = self.entries.remove(&layer_id) {
            self.current_memory = self.current_memory.saturating_sub(entry.memory_usage());
            self.stats.evictions += 1;
            debug!(
                layer_id = %layer_id,
                freed_bytes = entry.memory_usage(),
                "Evicted layer from cache"
            );
            Some(layer_id)
        } else {
            None
        }
    }

    /// Insert a new layer into the cache, evicting as needed.
    fn insert(
        &mut self,
        layer_id: String,
        data: Vec<u8>,
        uncompressed_size: usize,
        compression: CompressionFormat,
    ) {
        let entry = CacheEntry {
            layer_id: layer_id.clone(),
            data,
            uncompressed_size,
            compression,
            last_access: std::time::Instant::now(),
        };

        let entry_size = entry.memory_usage();

        // Evict until we have space.
        while self.current_memory + entry_size > self.max_memory && !self.entries.is_empty() {
            self.evict_lru();
        }

        // Insert new entry.
        self.entries.insert(layer_id.clone(), entry);
        self.touch(&layer_id);
        self.current_memory += entry_size;

        // Update stats.
        self.stats.cached_layers = self.entries.len();
        self.stats.memory_bytes = self.current_memory;
    }

    /// Get a layer from cache.
    fn get(&mut self, layer_id: &str) -> Option<Vec<u8>> {
        if self.entries.contains_key(layer_id) {
            // Clone entry to avoid borrow checker issues
            let entry = self.entries.get(layer_id)?.clone();
            self.touch(layer_id);
            self.stats.hits += 1;
            match entry.get_data() {
                Ok(data) => Some(data),
                Err(e) => {
                    warn!(
                        layer_id = %layer_id,
                        error = %e,
                        "Failed to decompress cached layer"
                    );
                    None
                }
            }
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Clear all entries.
    fn clear(&mut self) {
        self.entries.clear();
        self.lru_queue.clear();
        self.current_memory = 0;
        self.stats.cached_layers = 0;
        self.stats.memory_bytes = 0;
    }
}

/// LRU cache for model layer weights.
///
/// Thread-safe, supports optional compression, and enforces a memory budget.
pub struct LayerCache {
    state: Arc<Mutex<CacheState>>,
}

impl LayerCache {
    /// Create a new layer cache with the given memory budget (in bytes).
    ///
    /// Default budget: 128MB (suitable for edge deployments).
    pub fn new(max_memory_bytes: usize) -> Self {
        info!(
            max_memory_mb = max_memory_bytes / (1024 * 1024),
            "Initializing layer cache"
        );
        Self {
            state: Arc::new(Mutex::new(CacheState::new(max_memory_bytes))),
        }
    }

    /// Create a cache with default 128MB budget.
    pub fn default() -> Self {
        Self::new(128 * 1024 * 1024)
    }

    /// Get a layer from the cache.
    ///
    /// Returns `Some(data)` on cache hit, `None` on miss.
    pub fn get(&self, layer_id: &str) -> Option<Vec<u8>> {
        let mut state = self.state.lock();
        state.get(layer_id)
    }

    /// Insert a layer into the cache.
    ///
    /// If the layer would exceed the memory budget, the least-recently-used
    /// layer is evicted. Optionally compresses data before caching.
    pub fn insert(&self, layer_id: String, data: Vec<u8>, compress: bool) -> Result<()> {
        let uncompressed_size = data.len();
        let (final_data, compression) = if compress {
            #[cfg(feature = "compression")]
            {
                let compressed =
                    zstd::encode_all(&data[..], 3).context("Failed to compress layer data")?;
                let ratio = compressed.len() as f64 / data.len() as f64;
                debug!(
                    layer_id = %layer_id,
                    original_bytes = data.len(),
                    compressed_bytes = compressed.len(),
                    ratio = format!("{:.2}", ratio),
                    "Compressed layer for cache"
                );
                (compressed, CompressionFormat::Zstd)
            }
            #[cfg(not(feature = "compression"))]
            {
                warn!("Compression requested but 'compression' feature not enabled");
                (data, CompressionFormat::None)
            }
        } else {
            (data, CompressionFormat::None)
        };

        let mut state = self.state.lock();
        state.insert(layer_id, final_data, uncompressed_size, compression);
        Ok(())
    }

    /// Clear all cached layers.
    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.clear();
        info!("Layer cache cleared");
    }

    /// Get current cache statistics.
    pub fn stats(&self) -> CacheStats {
        let state = self.state.lock();
        state.stats.clone()
    }

    /// Log current cache statistics.
    pub fn log_stats(&self) {
        let stats = self.stats();
        info!(
            hits = stats.hits,
            misses = stats.misses,
            hit_ratio = format!("{:.2}%", stats.hit_ratio() * 100.0),
            evictions = stats.evictions,
            cached_layers = stats.cached_layers,
            memory_mb = stats.memory_bytes / (1024 * 1024),
            max_memory_mb = stats.max_memory_bytes / (1024 * 1024),
            "Layer cache statistics"
        );
    }
}

impl Clone for LayerCache {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic() {
        let cache = LayerCache::new(1024 * 1024); // 1MB

        // Insert a layer.
        let data = vec![0u8; 1024]; // 1KB
        cache
            .insert("layer_0".to_string(), data.clone(), false)
            .unwrap();

        // Cache hit.
        let retrieved = cache.get("layer_0");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);

        // Cache miss.
        assert!(cache.get("layer_nonexistent").is_none());

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_lru_eviction() {
        // Budget sized to hold exactly 2 entries (1024 bytes data +
        // size_of::<CacheEntry>() overhead each) but not 3.
        let cache = LayerCache::new(1024 * 2 + std::mem::size_of::<CacheEntry>() * 2 + 64);

        // Insert 3 layers of 1KB each (exceeds budget).
        cache
            .insert("layer_0".to_string(), vec![0u8; 1024], false)
            .unwrap();
        cache
            .insert("layer_1".to_string(), vec![1u8; 1024], false)
            .unwrap();
        cache
            .insert("layer_2".to_string(), vec![2u8; 1024], false)
            .unwrap();

        // layer_0 should be evicted (least recently used).
        assert!(cache.get("layer_0").is_none());
        assert!(cache.get("layer_1").is_some());
        assert!(cache.get("layer_2").is_some());

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_cache_clear() {
        let cache = LayerCache::new(1024 * 1024);
        cache
            .insert("layer_0".to_string(), vec![0u8; 1024], false)
            .unwrap();
        cache
            .insert("layer_1".to_string(), vec![1u8; 1024], false)
            .unwrap();

        cache.clear();

        assert!(cache.get("layer_0").is_none());
        assert!(cache.get("layer_1").is_none());

        let stats = cache.stats();
        assert_eq!(stats.cached_layers, 0);
        assert_eq!(stats.memory_bytes, 0);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_cache_compression() {
        let cache = LayerCache::new(1024 * 1024);

        // Insert compressible data (all zeros compress well).
        let data = vec![0u8; 10_000];
        cache
            .insert("layer_comp".to_string(), data.clone(), true)
            .unwrap();

        // Retrieve and verify data is correct.
        let retrieved = cache.get("layer_comp");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);

        // Check that compressed size is smaller.
        let stats = cache.stats();
        // Compressed size should be much less than 10KB.
        assert!(stats.memory_bytes < 1000);
    }
}
