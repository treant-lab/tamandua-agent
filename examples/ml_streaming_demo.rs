//! Incremental ML Model Loading Demo
//!
//! This example demonstrates the incremental model loading system for
//! memory-efficient ML inference in the Tamandua agent.
//!
//! Run with:
//!   cargo run --example ml_streaming_demo --features ml

use anyhow::Result;
use std::path::PathBuf;
use std::time::Instant;

#[cfg(feature = "ml")]
use tamandua_agent::ml::{
    layer_cache::LayerCache,
    model_chunker::{ChunkManifest, ChunkMetadata, LayerMetadata, ModelChunk},
    streaming_loader::{StreamingConfig, StreamingModelLoader},
};

#[cfg(feature = "ml")]
fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,tamandua_agent=debug")
        .init();

    println!("=== Tamandua ML Incremental Loading Demo ===\n");

    // Step 1: Create a mock model for demonstration
    let temp_dir = tempfile::TempDir::new()?;
    println!("📁 Creating mock model in: {}", temp_dir.path().display());
    create_demo_model(temp_dir.path())?;
    println!("   ✓ Model created with 5 layers\n");

    // Step 2: Demonstrate layer cache
    println!("🗄️  Layer Cache Demo");
    demo_layer_cache()?;
    println!();

    // Step 3: Demonstrate streaming loader - cold start
    println!("❄️  Streaming Loader - Cold Start");
    demo_cold_start(temp_dir.path())?;
    println!();

    // Step 4: Demonstrate streaming loader - warm cache
    println!("🔥 Streaming Loader - Warm Cache");
    demo_warm_inference(temp_dir.path())?;
    println!();

    // Step 5: Demonstrate memory efficiency
    println!("💾 Memory Efficiency Comparison");
    demo_memory_efficiency(temp_dir.path())?;
    println!();

    println!("=== Demo Complete ===");

    Ok(())
}

#[cfg(feature = "ml")]
fn create_demo_model(dir: &std::path::Path) -> Result<()> {
    // Create a simple 5-layer model
    let chunks = vec![
        ("input_conv", "Conv2d", vec![32, 3, 3, 3], vec![]),
        (
            "hidden_conv1",
            "Conv2d",
            vec![64, 32, 3, 3],
            vec!["input_conv".to_string()],
        ),
        (
            "hidden_conv2",
            "Conv2d",
            vec![128, 64, 3, 3],
            vec!["hidden_conv1".to_string()],
        ),
        (
            "fc1",
            "Linear",
            vec![256, 128 * 8 * 8],
            vec!["hidden_conv2".to_string()],
        ),
        ("fc2", "Linear", vec![8, 256], vec!["fc1".to_string()]),
    ];

    let mut chunk_metas = Vec::new();

    for (layer_id, layer_type, weight_shape, dependencies) in chunks {
        let weight_count: usize = weight_shape.iter().product();
        let metadata = LayerMetadata {
            layer_id: layer_id.to_string(),
            layer_type: layer_type.to_string(),
            weight_shape: weight_shape.clone(),
            weight_count,
            weight_bytes: weight_count * 4,
            compressed: false,
            dependencies,
        };

        let weights: Vec<f32> = (0..weight_count)
            .map(|i| (i as f32 * 0.001) % 1.0)
            .collect();

        let chunk = ModelChunk::new(metadata, weights);
        let chunk_filename = format!("{}.chunk", layer_id);
        chunk.write_to_file(&dir.join(&chunk_filename))?;

        chunk_metas.push(ChunkMetadata {
            layer_id: layer_id.to_string(),
            file_name: chunk_filename,
            file_size: 0,
            checksum: String::new(),
        });
    }

    let manifest = ChunkManifest {
        model_name: "demo_model".to_string(),
        model_version: "1.0.0".to_string(),
        input_shape: vec![1, 3, 32, 32],
        output_shape: vec![1, 8],
        num_layers: chunk_metas.len(),
        chunks: chunk_metas,
    };

    manifest.save(&dir.join("manifest.json"))?;

    Ok(())
}

#[cfg(feature = "ml")]
fn demo_layer_cache() -> Result<()> {
    let cache = LayerCache::new(1024 * 1024); // 1MB cache

    println!("   Creating cache with 1MB budget");

    // Insert some layers
    for i in 0..5 {
        let layer_data = vec![i as u8; 100_000]; // 100KB each
        cache.insert(format!("demo_layer_{}", i), layer_data, false)?;
    }

    println!("   Inserted 5 layers (100KB each)");

    // Test cache hits
    let mut hits = 0;
    let mut misses = 0;
    for i in 0..7 {
        if cache.get(&format!("demo_layer_{}", i)).is_some() {
            hits += 1;
        } else {
            misses += 1;
        }
    }

    println!("   Cache hits: {}, misses: {}", hits, misses);

    let stats = cache.stats();
    println!("   Hit ratio: {:.1}%", stats.hit_ratio() * 100.0);
    println!(
        "   Memory usage: {:.2} MB / {:.2} MB",
        stats.memory_bytes as f64 / (1024.0 * 1024.0),
        stats.max_memory_bytes as f64 / (1024.0 * 1024.0)
    );

    Ok(())
}

#[cfg(feature = "ml")]
fn demo_cold_start(model_dir: &std::path::Path) -> Result<()> {
    let start = Instant::now();

    let config = StreamingConfig::new(model_dir);
    let mut loader = StreamingModelLoader::new(config)?;

    let init_time = start.elapsed();
    println!("   Initialization: {:?}", init_time);

    // Load full inference graph (all layers)
    let load_start = Instant::now();
    loader.load_inference_graph(&["fc2".to_string()])?;
    let load_time = load_start.elapsed();

    println!("   Graph loading: {:?}", load_time);
    println!("   Total cold start: {:?}", init_time + load_time);

    loader.log_stats();

    Ok(())
}

#[cfg(feature = "ml")]
fn demo_warm_inference(model_dir: &std::path::Path) -> Result<()> {
    let config = StreamingConfig::new(model_dir);
    let mut loader = StreamingModelLoader::new(config)?;

    // Warm up cache
    loader.load_inference_graph(&["fc2".to_string()])?;

    println!("   Running 10 warm inferences...");

    let mut total_time = std::time::Duration::ZERO;
    for i in 0..10 {
        let start = Instant::now();
        loader.load_layer("input_conv")?;
        loader.load_layer("hidden_conv1")?;
        loader.load_layer("fc2")?;
        let inference_time = start.elapsed();
        total_time += inference_time;

        if i == 0 || i == 9 {
            println!("   Inference {}: {:?}", i + 1, inference_time);
        }
    }

    println!("   Average warm inference: {:?}", total_time / 10);

    let cache_stats = loader.cache_stats();
    println!(
        "   Cache hit ratio: {:.1}%",
        cache_stats.hit_ratio() * 100.0
    );

    Ok(())
}

#[cfg(feature = "ml")]
fn demo_memory_efficiency(model_dir: &std::path::Path) -> Result<()> {
    // Scenario 1: Full model in memory (large cache)
    println!("   Scenario 1: Full model (large cache)");
    let config_full = StreamingConfig {
        cache_size_bytes: 100 * 1024 * 1024, // 100MB
        ..StreamingConfig::new(model_dir)
    };
    let mut loader_full = StreamingModelLoader::new(config_full)?;
    loader_full.load_inference_graph(&["fc2".to_string()])?;
    let full_memory = loader_full.cache_stats().memory_bytes;
    println!(
        "      Memory used: {:.2} MB",
        full_memory as f64 / (1024.0 * 1024.0)
    );

    // Scenario 2: Streaming with small cache
    println!("   Scenario 2: Streaming (small cache)");
    let config_streaming = StreamingConfig {
        cache_size_bytes: full_memory / 2, // 50% of full
        ..StreamingConfig::new(model_dir)
    };
    let mut loader_streaming = StreamingModelLoader::new(config_streaming)?;
    // Simulate inference pattern
    for _ in 0..5 {
        loader_streaming.load_layer("input_conv")?;
        loader_streaming.load_layer("fc2")?;
    }
    let streaming_memory = loader_streaming.cache_stats().memory_bytes;
    println!(
        "      Memory used: {:.2} MB",
        streaming_memory as f64 / (1024.0 * 1024.0)
    );

    // Calculate reduction
    let reduction = (1.0 - streaming_memory as f64 / full_memory as f64) * 100.0;
    println!("   Memory reduction: {:.1}%", reduction);

    // Check target
    if reduction >= 40.0 {
        println!("   ✓ Target achieved (≥40% reduction)");
    } else {
        println!("   ⚠ Target not met (<40% reduction)");
    }

    Ok(())
}

#[cfg(not(feature = "ml"))]
fn main() {
    eprintln!("This example requires the 'ml' feature to be enabled.");
    eprintln!("Run with: cargo run --example ml_streaming_demo --features ml");
    std::process::exit(1);
}
