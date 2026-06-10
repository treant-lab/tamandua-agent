# Incremental Model Loading for Tamandua Agent

This module implements memory-efficient, streaming-based ML model loading for the Tamandua EDR agent. Instead of loading entire ONNX or PyTorch models into memory at startup (typically 100-500MB), we employ incremental loading strategies to achieve significant reductions in both memory footprint and startup time.

## Architecture

### Components

1. **Model Chunker** (`model_chunker.rs`)
   - Splits models into layer-wise chunk files
   - Each chunk contains: header, metadata, weights, checksum
   - Supports both ONNX and PyTorch models (via Python preprocessing)

2. **Layer Cache** (`layer_cache.rs`)
   - LRU cache for frequently-used layer weights
   - Configurable memory budget (default: 128MB)
   - Optional zstd compression for cached data
   - Thread-safe for concurrent inference

3. **Streaming Loader** (`streaming_loader.rs`)
   - On-demand layer loading with dependency resolution
   - Memory-mapped file access for large layers
   - Topological sorting of layer dependencies
   - Integration with ONNX Runtime

### Data Flow

```
┌─────────────────┐
│ Full ONNX Model │
│   (500MB)       │
└────────┬────────┘
         │
         │ [Offline: Python script]
         ▼
┌─────────────────────────────┐
│ Chunked Model Directory     │
│  ├── manifest.json          │
│  ├── layer_000_Conv2d.chunk │
│  ├── layer_001_Conv2d.chunk │
│  └── ...                    │
└────────┬────────────────────┘
         │
         │ [Runtime: Rust agent]
         ▼
┌─────────────────────────┐
│ Streaming Loader        │
│  - Loads layers on-demand│
│  - Checks cache first   │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Layer Cache (LRU, 128MB)│
│  - Hot layers resident  │
│  - Cold layers evicted  │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ ONNX Runtime Inference  │
└─────────────────────────┘
```

## Usage

### 1. Chunk the Model (Offline)

Use the Python script to split a trained model into chunks:

```bash
cd apps/tamandua_ml
python scripts/chunk_model.py \
  --input models/malware_smell.onnx \
  --output models/malware_smell_chunked/ \
  --compress
```

This creates:
- `manifest.json` - Model metadata and chunk index
- `layer_*.chunk` - Individual layer weight files

### 2. Load Model Incrementally (Runtime)

In your Rust agent code:

```rust
use tamandua_agent::ml::{StreamingModelLoader, StreamingConfig};

// Initialize streaming loader
let config = StreamingConfig::new("models/malware_smell_chunked");
let mut loader = StreamingModelLoader::new(config)?;

// First inference: loads required layers
let result = loader.run_inference(&binary_data)?;

// Subsequent inferences: cache hits for hot layers
let result2 = loader.run_inference(&binary_data2)?;

// Check performance stats
loader.log_stats();
```

### 3. Integration with Existing ML Engine

To integrate with the existing `OnnxInferenceEngine`:

```rust
use tamandua_agent::analyzers::OnnxInferenceEngine;
use tamandua_agent::ml::StreamingModelLoader;

// Option 1: Use streaming loader directly
let mut streaming_loader = StreamingModelLoader::new(config)?;
let prediction = streaming_loader.run_inference(binary)?;

// Option 2: Preload hot layers for ONNX engine
let mut streaming_loader = StreamingModelLoader::new(config)?;
streaming_loader.preload_layers(&["conv1_1", "conv1_2", "conv2_1"])?;
// Then use standard ONNX engine...
```

## Performance Targets

Based on the Malware-SMELL model architecture:

| Metric | Baseline (Full Load) | Target (Streaming) | Measured |
|--------|---------------------|-------------------|----------|
| Memory Usage | ~500MB | <250MB (50%) | TBD |
| Startup Time | ~2000ms | <600ms (70%) | TBD |
| Inference Latency | 50ms | <55ms (<10% overhead) | TBD |
| Model Accuracy | 95.3% | 95.3% (no degradation) | TBD |

### Benchmarking

Run the included benchmark suite:

```bash
cd apps/tamandua_agent
cargo bench --bench ml_streaming

# Or run specific benchmarks:
cargo bench --bench ml_streaming -- cold_start
cargo bench --bench ml_streaming -- warm_inference
cargo bench --bench ml_streaming -- cache_hit_ratio
```

## Chunk File Format

Each `.chunk` file has the following structure:

```
┌──────────────────────────┐
│ Magic: "TAMC" (4 bytes)  │
├──────────────────────────┤
│ Version: u32             │
├──────────────────────────┤
│ Metadata Length: u32     │
├──────────────────────────┤
│ Metadata (JSON)          │
│  {                       │
│    "layer_id": "...",    │
│    "layer_type": "...",  │
│    "weight_shape": [...],│
│    "compressed": bool,   │
│    "dependencies": [...] │
│  }                       │
├──────────────────────────┤
│ Data Length: u64         │
├──────────────────────────┤
│ Weight Data (f32 bytes)  │
│  [optionally compressed] │
├──────────────────────────┤
│ SHA256 Checksum (32B)    │
└──────────────────────────┘
```

## Configuration

### Cache Size

Adjust cache size based on deployment constraints:

```rust
// Edge device with 512MB RAM
let config = StreamingConfig {
    cache_size_bytes: 64 * 1024 * 1024, // 64MB
    ..Default::default()
};

// Server with abundant RAM
let config = StreamingConfig {
    cache_size_bytes: 512 * 1024 * 1024, // 512MB
    ..Default::default()
};
```

### Compression

Enable compression to reduce memory at the cost of CPU:

```rust
let config = StreamingConfig {
    compress_cache: true, // Requires 'compression' feature
    ..Default::default()
};
```

### Preloading

Preload critical layers to minimize cold-start latency:

```rust
loader.preload_layers(&[
    "vgg19_features_0".to_string(),
    "vgg19_features_2".to_string(),
    "vgg19_features_5".to_string(),
])?;
```

## Testing

Run the test suite:

```bash
# All ML tests
cargo test --lib ml

# Specific test modules
cargo test --lib ml::layer_cache
cargo test --lib ml::streaming_loader

# With compression feature
cargo test --lib ml --features compression

# Integration tests with mock models
cargo test --test ml_integration
```

## Limitations and Future Work

### Current Limitations

1. **Full ONNX Integration**: The current implementation demonstrates the chunking and caching infrastructure but doesn't yet fully integrate with ONNX Runtime's execution graph. Full integration requires custom ORT operators or a custom inference runtime.

2. **Static Dependency Graph**: Layer dependencies are computed offline and stored in the manifest. Dynamic computation graphs (e.g., with conditional branches) are not yet supported.

3. **Single-Threaded Inference**: To simplify cache management, inference is currently single-threaded. Multi-threaded inference with proper cache locking is planned.

### Future Enhancements

1. **Dynamic Layer Unloading**: Automatically unload layers that haven't been accessed recently to reclaim memory during inference.

2. **Quantization Support**: Add support for INT8/INT4 quantized weights to further reduce memory.

3. **GPU Integration**: Extend streaming to GPU memory management for CUDA/ROCm inference.

4. **Model Versioning**: Support hot-swapping model chunks without restarting the agent.

5. **Adaptive Caching**: Use ML to predict which layers will be needed next and preload them.

## References

- ONNX Runtime: https://onnxruntime.ai/
- Malware-SMELL Paper: [citation needed]
- LRU Cache Algorithm: https://en.wikipedia.org/wiki/Cache_replacement_policies#LRU
- Memory-Mapped Files: https://en.wikipedia.org/wiki/Memory-mapped_file
