//! Tests for incremental model loading infrastructure

use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a mock chunked model for testing.
fn create_mock_model(dir: &std::path::Path) -> anyhow::Result<()> {
    use model_chunker::{ChunkManifest, ChunkMetadata, LayerMetadata, ModelChunk};

    // Create manifest
    let manifest = ChunkManifest {
        model_name: "mock_vgg19".to_string(),
        model_version: "1.0.0-test".to_string(),
        input_shape: vec![1, 3, 64, 64],
        output_shape: vec![1, 8],
        num_layers: 3,
        chunks: vec![
            ChunkMetadata {
                layer_id: "conv1".to_string(),
                file_name: "conv1.chunk".to_string(),
                file_size: 0,
                checksum: String::new(),
            },
            ChunkMetadata {
                layer_id: "conv2".to_string(),
                file_name: "conv2.chunk".to_string(),
                file_size: 0,
                checksum: String::new(),
            },
            ChunkMetadata {
                layer_id: "fc".to_string(),
                file_name: "fc.chunk".to_string(),
                file_size: 0,
                checksum: String::new(),
            },
        ],
    };
    manifest.save(&dir.join("manifest.json"))?;

    // Create chunks
    // Conv1: 64 filters, 3 channels, 3x3 kernel = 64*3*3*3 = 1728 weights
    let conv1_meta = LayerMetadata {
        layer_id: "conv1".to_string(),
        layer_type: "Conv2d".to_string(),
        weight_shape: vec![64, 3, 3, 3],
        weight_count: 1728,
        weight_bytes: 1728 * 4,
        compressed: false,
        dependencies: vec![],
    };
    let conv1_weights: Vec<f32> = (0..1728).map(|i| i as f32 * 0.001).collect();
    let conv1_chunk = ModelChunk::new(conv1_meta, conv1_weights);
    conv1_chunk.write_to_file(&dir.join("conv1.chunk"))?;

    // Conv2: depends on conv1, 128 filters, 64 channels, 3x3 kernel
    let conv2_meta = LayerMetadata {
        layer_id: "conv2".to_string(),
        layer_type: "Conv2d".to_string(),
        weight_shape: vec![128, 64, 3, 3],
        weight_count: 128 * 64 * 3 * 3,
        weight_bytes: 128 * 64 * 3 * 3 * 4,
        compressed: false,
        dependencies: vec!["conv1".to_string()],
    };
    let conv2_weights: Vec<f32> = (0..conv2_meta.weight_count)
        .map(|i| i as f32 * 0.001)
        .collect();
    let conv2_chunk = ModelChunk::new(conv2_meta, conv2_weights);
    conv2_chunk.write_to_file(&dir.join("conv2.chunk"))?;

    // FC: depends on conv2, 512 x 8 weights
    let fc_meta = LayerMetadata {
        layer_id: "fc".to_string(),
        layer_type: "Linear".to_string(),
        weight_shape: vec![8, 512],
        weight_count: 8 * 512,
        weight_bytes: 8 * 512 * 4,
        compressed: false,
        dependencies: vec!["conv2".to_string()],
    };
    let fc_weights: Vec<f32> = (0..fc_meta.weight_count)
        .map(|i| i as f32 * 0.001)
        .collect();
    let fc_chunk = ModelChunk::new(fc_meta, fc_weights);
    fc_chunk.write_to_file(&dir.join("fc.chunk"))?;

    Ok(())
}

#[test]
fn test_layer_cache_basic_operations() {
    use layer_cache::LayerCache;

    let cache = LayerCache::new(1024 * 1024); // 1MB

    // Insert a layer
    let layer_data = vec![0u8; 1024];
    cache
        .insert("test_layer".to_string(), layer_data.clone(), false)
        .unwrap();

    // Retrieve it
    let retrieved = cache.get("test_layer");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), layer_data);

    // Miss
    assert!(cache.get("nonexistent").is_none());

    // Stats
    let stats = cache.stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
}

#[test]
fn test_layer_cache_eviction() {
    use layer_cache::LayerCache;

    // Use 16KB data so per-entry overhead (CacheEntry struct ~80 bytes) is
    // negligible relative to the data, and the budget cleanly fits 3 entries.
    let entry_data_size = 16 * 1024;
    let cache = LayerCache::new(entry_data_size * 3 + 1024); // ~48KB + slack

    // Insert 4 layers (will trigger eviction)
    for i in 0..4 {
        let layer_id = format!("layer_{}", i);
        let data = vec![i as u8; entry_data_size];
        cache.insert(layer_id, data, false).unwrap();
    }

    // First layer should be evicted (LRU)
    assert!(cache.get("layer_0").is_none());
    assert!(cache.get("layer_1").is_some());
    assert!(cache.get("layer_2").is_some());
    assert!(cache.get("layer_3").is_some());

    let stats = cache.stats();
    assert!(stats.evictions > 0);
}

#[test]
fn test_model_chunk_roundtrip() {
    use model_chunker::{LayerMetadata, ModelChunk};

    let temp_dir = TempDir::new().unwrap();
    let chunk_path = temp_dir.path().join("test.chunk");

    // Create chunk
    let metadata = LayerMetadata {
        layer_id: "test_conv".to_string(),
        layer_type: "Conv2d".to_string(),
        weight_shape: vec![64, 3, 3, 3],
        weight_count: 1728,
        weight_bytes: 1728 * 4,
        compressed: false,
        dependencies: vec![],
    };
    let weights: Vec<f32> = (0..1728).map(|i| i as f32 * 0.01).collect();
    let chunk = ModelChunk::new(metadata.clone(), weights.clone());

    // Write
    chunk.write_to_file(&chunk_path).unwrap();

    // Read back
    let loaded = ModelChunk::read_from_file(&chunk_path).unwrap();

    // Verify metadata
    assert_eq!(loaded.metadata.layer_id, metadata.layer_id);
    assert_eq!(loaded.metadata.weight_count, metadata.weight_count);

    // Verify weights
    let loaded_weights = loaded.get_weights().unwrap();
    assert_eq!(loaded_weights.len(), weights.len());
    for (a, b) in loaded_weights.iter().zip(weights.iter()) {
        assert!((a - b).abs() < 1e-5);
    }
}

#[test]
fn test_streaming_loader_initialization() {
    let temp_dir = TempDir::new().unwrap();
    create_mock_model(temp_dir.path()).unwrap();

    let config = streaming_loader::StreamingConfig::new(temp_dir.path());
    let loader = streaming_loader::StreamingModelLoader::new(config).unwrap();

    assert_eq!(loader.manifest.num_layers, 3);
    assert_eq!(loader.manifest.model_name, "mock_vgg19");
}

#[test]
fn test_streaming_loader_load_layer() {
    let temp_dir = TempDir::new().unwrap();
    create_mock_model(temp_dir.path()).unwrap();

    let config = streaming_loader::StreamingConfig::new(temp_dir.path());
    let mut loader = streaming_loader::StreamingModelLoader::new(config).unwrap();

    // Load conv1
    let weights = loader.load_layer("conv1").unwrap();
    assert_eq!(weights.len(), 1728);

    // Load again - should hit cache
    let weights2 = loader.load_layer("conv1").unwrap();
    assert_eq!(weights, weights2);

    let stats = loader.cache_stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
}

#[test]
fn test_streaming_loader_dependency_graph() {
    let temp_dir = TempDir::new().unwrap();
    create_mock_model(temp_dir.path()).unwrap();

    let config = streaming_loader::StreamingConfig::new(temp_dir.path());
    let mut loader = streaming_loader::StreamingModelLoader::new(config).unwrap();

    // Load inference graph for fc (which depends on conv2, which depends on conv1)
    let sorted = loader.load_inference_graph(&["fc".to_string()]).unwrap();

    // Should load in order: conv1 -> conv2 -> fc
    assert_eq!(sorted.len(), 3);
    assert_eq!(sorted[0], "conv1");
    assert_eq!(sorted[1], "conv2");
    assert_eq!(sorted[2], "fc");

    // All layers should be cached now
    let stats = loader.cache_stats();
    assert_eq!(stats.cached_layers, 3);
}

#[test]
fn test_memory_reduction_target() {
    // This test validates that chunked loading reduces memory compared to
    // loading the full model at once.
    let temp_dir = TempDir::new().unwrap();
    create_mock_model(temp_dir.path()).unwrap();

    // Measure memory for full model (all chunks loaded)
    let config_full = streaming_loader::StreamingConfig {
        cache_size_bytes: 10 * 1024 * 1024, // 10MB (large enough to hold everything)
        ..streaming_loader::StreamingConfig::new(temp_dir.path())
    };
    let mut loader_full = streaming_loader::StreamingModelLoader::new(config_full).unwrap();
    loader_full
        .load_inference_graph(&["conv1".to_string(), "conv2".to_string(), "fc".to_string()])
        .unwrap();
    let full_memory = loader_full.cache_stats().memory_bytes;

    // Measure memory for streaming (small cache, only keeps hot layers)
    let config_streaming = streaming_loader::StreamingConfig {
        cache_size_bytes: full_memory / 2, // 50% of full model size
        ..streaming_loader::StreamingConfig::new(temp_dir.path())
    };
    let mut loader_streaming =
        streaming_loader::StreamingModelLoader::new(config_streaming).unwrap();

    // Load multiple times to trigger evictions
    for _ in 0..5 {
        loader_streaming.load_layer("conv1").unwrap();
        loader_streaming.load_layer("conv2").unwrap();
        loader_streaming.load_layer("fc").unwrap();
    }

    let streaming_memory = loader_streaming.cache_stats().memory_bytes;

    // Streaming should use ≤50% of full model memory
    assert!(
        streaming_memory <= full_memory / 2,
        "Streaming memory ({} bytes) should be ≤50% of full memory ({} bytes)",
        streaming_memory,
        full_memory
    );

    println!(
        "Memory reduction: {:.1}% (full: {} bytes, streaming: {} bytes)",
        (1.0 - streaming_memory as f64 / full_memory as f64) * 100.0,
        full_memory,
        streaming_memory
    );
}

#[cfg(feature = "compression")]
#[test]
fn test_compression_reduces_memory() {
    use layer_cache::LayerCache;

    let cache = LayerCache::new(10 * 1024 * 1024);

    // Create highly compressible data (all zeros)
    let uncompressed_data = vec![0u8; 100_000];

    // Insert without compression
    cache
        .insert(
            "layer_uncompressed".to_string(),
            uncompressed_data.clone(),
            false,
        )
        .unwrap();
    let uncompressed_size = cache.stats().memory_bytes;

    cache.clear();

    // Insert with compression
    cache
        .insert("layer_compressed".to_string(), uncompressed_data, true)
        .unwrap();
    let compressed_size = cache.stats().memory_bytes;

    // Compressed should be much smaller
    assert!(
        compressed_size < uncompressed_size / 10,
        "Compressed size ({}) should be <10% of uncompressed ({})",
        compressed_size,
        uncompressed_size
    );

    println!(
        "Compression ratio: {:.1}x (uncompressed: {} bytes, compressed: {} bytes)",
        uncompressed_size as f64 / compressed_size as f64,
        uncompressed_size,
        compressed_size
    );
}
