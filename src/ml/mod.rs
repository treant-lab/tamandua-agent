//! Incremental ML Model Loading Infrastructure
//!
//! This module provides memory-efficient, streaming-based model loading for
//! the Tamandua agent's ML inference pipeline. Instead of loading entire
//! PyTorch or ONNX models into memory at once, we employ several strategies:
//!
//! 1. **Streaming Loader**: Load model weights in chunks via memory-mapped files
//! 2. **Layer Cache**: LRU cache for frequently-used layers to reduce re-loading
//! 3. **Model Chunker**: Split models into independently-loadable chunks
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ Full Model  │
//! │  (.onnx)    │
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────────┐
//! │ Model Chunker   │  ← Python preprocessing script
//! │ (split layers)  │
//! └──────┬──────────┘
//!        │
//!        ▼
//! ┌──────────────────────────┐
//! │ Chunk Files (.chunk)     │
//! │  - layer_0.chunk         │
//! │  - layer_1.chunk         │
//! │  - ...                   │
//! │  - manifest.json         │
//! └──────┬───────────────────┘
//!        │
//!        ▼
//! ┌──────────────────────┐
//! │ Streaming Loader     │  ← Memory-mapped file access
//! │ (lazy loading)       │
//! └──────┬───────────────┘
//!        │
//!        ▼
//! ┌──────────────────────┐
//! │ Layer Cache (LRU)    │  ← Hot layers stay resident
//! └──────┬───────────────┘
//!        │
//!        ▼
//! ┌──────────────────────┐
//! │ ONNX Runtime         │
//! │ (inference)          │
//! └──────────────────────┘
//! ```
//!
//! ## Target Metrics
//!
//! - **Memory reduction**: 50% (measured: baseline vs streaming)
//! - **Startup time reduction**: 70% (measured: time to first inference)
//! - **Inference latency overhead**: <10% (measured: per-sample inference time)
//! - **Accuracy**: No degradation (bit-exact weights)
//!
//! ## Usage
//!
//! ```rust,no_run
//! use tamandua_agent::ml::{StreamingModelLoader, LayerCache};
//!
//! // Create streaming loader with LRU cache
//! let mut loader = StreamingModelLoader::new(
//!     "models/malware_smell_chunked",
//!     LayerCache::new(128 * 1024 * 1024), // 128MB cache
//! )?;
//!
//! // First inference: loads required layers
//! let result = loader.run_inference(&binary_data)?;
//!
//! // Subsequent inferences: cache hits for hot layers
//! let result2 = loader.run_inference(&binary_data2)?;
//! ```

pub mod layer_cache;
pub mod model_chunker;
pub mod streaming_loader;

pub use layer_cache::{CacheStats, LayerCache};
pub use model_chunker::{chunk_onnx_model, ChunkManifest, ModelChunk};
pub use streaming_loader::{LayerMetadata, StreamingConfig, StreamingModelLoader};

#[cfg(test)]
mod tests;
