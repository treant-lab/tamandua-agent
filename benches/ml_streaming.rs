//! Benchmarks for incremental ML model loading
//!
//! Measures:
//! - Cold start time (cache empty)
//! - Warm inference time (cache full)
//! - Memory usage
//! - Cache hit ratio
//!
//! Run with:
//!   cargo bench --bench ml_streaming

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

// Note: These benchmarks require the ml module to be compiled.
// If ml module is not available, these tests will be skipped.

#[cfg(all(test, feature = "ml"))]
use tamandua_agent::ml::{
    layer_cache::LayerCache,
    model_chunker::{ChunkManifest, ChunkMetadata, LayerMetadata, ModelChunk},
    streaming_loader::{StreamingConfig, StreamingModelLoader},
};

/// Create a realistic mock VGG-19 style model for benchmarking.
#[cfg(all(test, feature = "ml"))]
fn create_benchmark_model(dir: &std::path::Path) -> anyhow::Result<()> {
    use tamandua_agent::ml::model_chunker::{
        ChunkManifest, ChunkMetadata, LayerMetadata, ModelChunk,
    };

    // VGG-19 architecture (simplified):
    // - Block 1: 2 conv layers (64 filters)
    // - Block 2: 2 conv layers (128 filters)
    // - Block 3: 4 conv layers (256 filters)
    // - Block 4: 4 conv layers (512 filters)
    // - Block 5: 4 conv layers (512 filters)
    // - FC layers: 3 layers

    let mut chunks = Vec::new();

    // Block 1: Conv 64, 3x3x3 (3 input channels, RGB)
    for i in 0..2 {
        let layer_id = format!("block1_conv{}", i + 1);
        let metadata = LayerMetadata {
            layer_id: layer_id.clone(),
            layer_type: "Conv2d".to_string(),
            weight_shape: vec![64, 3, 3, 3],
            weight_count: 64 * 3 * 3 * 3,
            weight_bytes: 64 * 3 * 3 * 3 * 4,
            compressed: false,
            dependencies: if i == 0 {
                vec![]
            } else {
                vec![format!("block1_conv{}", i)]
            },
        };
        let weights: Vec<f32> = (0..metadata.weight_count)
            .map(|j| (i * 10000 + j) as f32 * 0.001)
            .collect();
        let chunk = ModelChunk::new(metadata, weights);
        let chunk_filename = format!("{}.chunk", layer_id);
        chunk.write_to_file(&dir.join(&chunk_filename))?;
        chunks.push(ChunkMetadata {
            layer_id,
            file_name: chunk_filename,
            file_size: 0,
            checksum: String::new(),
        });
    }

    // Block 2: Conv 128, 3x3x64
    for i in 0..2 {
        let layer_id = format!("block2_conv{}", i + 1);
        let metadata = LayerMetadata {
            layer_id: layer_id.clone(),
            layer_type: "Conv2d".to_string(),
            weight_shape: vec![128, 64, 3, 3],
            weight_count: 128 * 64 * 3 * 3,
            weight_bytes: 128 * 64 * 3 * 3 * 4,
            compressed: false,
            dependencies: if i == 0 {
                vec!["block1_conv2".to_string()]
            } else {
                vec![format!("block2_conv{}", i)]
            },
        };
        let weights: Vec<f32> = (0..metadata.weight_count)
            .map(|j| (i * 10000 + j) as f32 * 0.001)
            .collect();
        let chunk = ModelChunk::new(metadata, weights);
        let chunk_filename = format!("{}.chunk", layer_id);
        chunk.write_to_file(&dir.join(&chunk_filename))?;
        chunks.push(ChunkMetadata {
            layer_id,
            file_name: chunk_filename,
            file_size: 0,
            checksum: String::new(),
        });
    }

    // FC layers
    for i in 0..3 {
        let layer_id = format!("fc{}", i + 1);
        let (in_features, out_features) = match i {
            0 => (512 * 7 * 7, 4096), // Flattened
            1 => (4096, 4096),
            2 => (4096, 8), // 8 classes
            _ => unreachable!(),
        };
        let metadata = LayerMetadata {
            layer_id: layer_id.clone(),
            layer_type: "Linear".to_string(),
            weight_shape: vec![out_features, in_features],
            weight_count: out_features * in_features,
            weight_bytes: out_features * in_features * 4,
            compressed: false,
            dependencies: if i == 0 {
                vec!["block2_conv2".to_string()]
            } else {
                vec![format!("fc{}", i)]
            },
        };
        let weights: Vec<f32> = (0..metadata.weight_count)
            .map(|j| (i * 10000 + j) as f32 * 0.001)
            .collect();
        let chunk = ModelChunk::new(metadata, weights);
        let chunk_filename = format!("{}.chunk", layer_id);
        chunk.write_to_file(&dir.join(&chunk_filename))?;
        chunks.push(ChunkMetadata {
            layer_id,
            file_name: chunk_filename,
            file_size: 0,
            checksum: String::new(),
        });
    }

    // Create manifest
    let manifest = ChunkManifest {
        model_name: "benchmark_vgg19".to_string(),
        model_version: "1.0.0".to_string(),
        input_shape: vec![1, 3, 64, 64],
        output_shape: vec![1, 8],
        num_layers: chunks.len(),
        chunks,
    };
    manifest.save(&dir.join("manifest.json"))?;

    Ok(())
}

#[cfg(all(test, feature = "ml"))]
fn bench_layer_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer_cache");

    // Benchmark cache insert
    group.bench_function("insert_1kb", |b| {
        let cache = LayerCache::new(10 * 1024 * 1024); // 10MB
        let data = vec![0u8; 1024];
        let mut counter = 0;
        b.iter(|| {
            cache
                .insert(format!("layer_{}", counter), data.clone(), false)
                .unwrap();
            counter += 1;
        });
    });

    // Benchmark cache hit
    group.bench_function("get_hit", |b| {
        let cache = LayerCache::new(10 * 1024 * 1024);
        let data = vec![0u8; 1024];
        cache.insert("test_layer".to_string(), data, false).unwrap();
        b.iter(|| {
            black_box(cache.get("test_layer"));
        });
    });

    // Benchmark cache miss
    group.bench_function("get_miss", |b| {
        let cache = LayerCache::new(10 * 1024 * 1024);
        b.iter(|| {
            black_box(cache.get("nonexistent"));
        });
    });

    group.finish();
}

#[cfg(all(test, feature = "ml"))]
fn bench_streaming_loader_cold_start(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    create_benchmark_model(temp_dir.path()).unwrap();

    c.bench_function("streaming_loader_cold_start", |b| {
        b.iter(|| {
            let config = StreamingConfig::new(temp_dir.path());
            let loader = StreamingModelLoader::new(config).unwrap();
            black_box(loader);
        });
    });
}

#[cfg(all(test, feature = "ml"))]
fn bench_streaming_loader_layer_loading(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    create_benchmark_model(temp_dir.path()).unwrap();

    let mut group = c.benchmark_group("layer_loading");

    // Benchmark loading a single layer (cold cache)
    group.bench_function("load_layer_cold", |b| {
        let config = StreamingConfig::new(temp_dir.path());
        let mut loader = StreamingModelLoader::new(config).unwrap();
        b.iter(|| {
            loader.clear_cache();
            loader.load_layer("block1_conv1").unwrap();
        });
    });

    // Benchmark loading a single layer (warm cache)
    group.bench_function("load_layer_warm", |b| {
        let config = StreamingConfig::new(temp_dir.path());
        let mut loader = StreamingModelLoader::new(config).unwrap();
        // Warm up cache
        loader.load_layer("block1_conv1").unwrap();
        b.iter(|| {
            loader.load_layer("block1_conv1").unwrap();
        });
    });

    // Benchmark loading full inference graph
    group.bench_function("load_inference_graph", |b| {
        let config = StreamingConfig::new(temp_dir.path());
        let mut loader = StreamingModelLoader::new(config).unwrap();
        b.iter(|| {
            loader.clear_cache();
            loader.load_inference_graph(&["fc3".to_string()]).unwrap();
        });
    });

    group.finish();
}

#[cfg(all(test, feature = "ml"))]
fn bench_cache_size_impact(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    create_benchmark_model(temp_dir.path()).unwrap();

    let mut group = c.benchmark_group("cache_size_impact");

    for cache_size_mb in [16, 32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", cache_size_mb)),
            &cache_size_mb,
            |b, &size_mb| {
                let config = StreamingConfig {
                    cache_size_bytes: size_mb * 1024 * 1024,
                    ..StreamingConfig::new(temp_dir.path())
                };
                let mut loader = StreamingModelLoader::new(config).unwrap();

                b.iter(|| {
                    // Simulate inference workload: load multiple layers repeatedly
                    for _ in 0..10 {
                        loader.load_layer("block1_conv1").unwrap();
                        loader.load_layer("block2_conv1").unwrap();
                        loader.load_layer("fc1").unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

#[cfg(all(test, feature = "ml"))]
fn bench_compression_overhead(c: &mut Criterion) {
    #[cfg(feature = "compression")]
    {
        let mut group = c.benchmark_group("compression");

        let cache = LayerCache::new(50 * 1024 * 1024);
        let data = vec![0u8; 100_000]; // 100KB of compressible data

        group.bench_function("insert_uncompressed", |b| {
            let mut counter = 0;
            b.iter(|| {
                cache
                    .insert(format!("layer_{}", counter), data.clone(), false)
                    .unwrap();
                counter += 1;
            });
        });

        group.bench_function("insert_compressed", |b| {
            let mut counter = 0;
            b.iter(|| {
                cache
                    .insert(format!("layer_{}", counter), data.clone(), true)
                    .unwrap();
                counter += 1;
            });
        });

        // Warm up cache with compressed data
        cache.insert("test_layer".to_string(), data, true).unwrap();

        group.bench_function("get_compressed", |b| {
            b.iter(|| {
                black_box(cache.get("test_layer"));
            });
        });

        group.finish();
    }
}

// Conditional compilation: only build benchmarks if ml feature is enabled
#[cfg(all(test, feature = "ml"))]
criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets =
        bench_layer_cache_operations,
        bench_streaming_loader_cold_start,
        bench_streaming_loader_layer_loading,
        bench_cache_size_impact,
        bench_compression_overhead
}

#[cfg(all(test, feature = "ml"))]
criterion_main!(benches);

#[cfg(not(all(test, feature = "ml")))]
fn main() {
    eprintln!("ml_streaming benchmarks require the 'ml' feature to be enabled");
    eprintln!("Run with: cargo bench --bench ml_streaming --features ml");
}
