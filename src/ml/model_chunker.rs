//! Model Chunking for Incremental Loading
//!
//! This module provides utilities for splitting ONNX models into independently-
//! loadable chunks. Each chunk corresponds to a layer or group of layers and
//! can be loaded on-demand during inference.
//!
//! ## Chunk Format
//!
//! Each chunk file (`.chunk`) contains:
//! - **Header**: Magic bytes, version, layer metadata
//! - **Weights**: Raw f32 tensor data (optionally compressed)
//! - **Checksum**: SHA256 hash for integrity verification
//!
//! ## Manifest
//!
//! A `manifest.json` file describes the complete model structure:
//! - Model metadata (input/output shapes, layer count)
//! - Chunk list (file names, sizes, checksums)
//! - Dependency graph (which layers depend on which chunks)
//!
//! ## Usage
//!
//! Chunking is performed offline by a Python preprocessing script that loads
//! the full ONNX model, splits it into layers, and writes chunk files:
//!
//! ```bash
//! python scripts/chunk_model.py \
//!   --input models/malware_smell.onnx \
//!   --output models/malware_smell_chunked/
//! ```
//!
//! The Rust agent then uses [`StreamingModelLoader`] to load chunks on-demand.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Magic bytes at the start of each chunk file ("TAMC" = Tamandua Model Chunk).
const CHUNK_MAGIC: &[u8; 4] = b"TAMC";

/// Current chunk format version.
const CHUNK_VERSION: u32 = 1;

/// Metadata for a single layer chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerMetadata {
    /// Layer identifier (e.g., "vgg19_features_0").
    pub layer_id: String,
    /// Layer type (Conv2d, Linear, BatchNorm, etc.).
    pub layer_type: String,
    /// Shape of the weight tensor (e.g., [64, 3, 3, 3] for conv).
    pub weight_shape: Vec<usize>,
    /// Total number of f32 elements.
    pub weight_count: usize,
    /// Byte size of raw weights (uncompressed).
    pub weight_bytes: usize,
    /// Whether this chunk is compressed.
    pub compressed: bool,
    /// Dependencies (layer IDs that must be loaded before this one).
    pub dependencies: Vec<String>,
}

/// A model chunk containing weights for one or more layers.
#[derive(Debug, Clone)]
pub struct ModelChunk {
    /// Metadata for the layer(s) in this chunk.
    pub metadata: LayerMetadata,
    /// Raw weight data (f32 bytes, possibly compressed).
    pub data: Vec<u8>,
    /// SHA256 checksum of the data.
    pub checksum: Vec<u8>,
}

impl ModelChunk {
    /// Create a new chunk from raw f32 weights.
    pub fn new(metadata: LayerMetadata, weights: Vec<f32>) -> Self {
        let data = Self::serialize_weights(&weights);
        let checksum = Self::compute_checksum(&data);
        Self {
            metadata,
            data,
            checksum,
        }
    }

    /// Serialize f32 weights to bytes (little-endian).
    fn serialize_weights(weights: &[f32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(weights.len() * 4);
        for &w in weights {
            data.extend_from_slice(&w.to_le_bytes());
        }
        data
    }

    /// Deserialize bytes to f32 weights (little-endian).
    fn deserialize_weights(data: &[u8]) -> Result<Vec<f32>> {
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

    /// Compute SHA256 checksum of data.
    fn compute_checksum(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Verify checksum matches expected.
    pub fn verify_checksum(&self) -> bool {
        Self::compute_checksum(&self.data) == self.checksum
    }

    /// Write chunk to a file.
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create chunk file: {}", path.display()))?;
        let mut writer = BufWriter::new(file);

        // Write header.
        writer.write_all(CHUNK_MAGIC)?;
        writer.write_all(&CHUNK_VERSION.to_le_bytes())?;

        // Write metadata (JSON, length-prefixed).
        let metadata_json =
            serde_json::to_vec(&self.metadata).context("Failed to serialize metadata")?;
        writer.write_all(&(metadata_json.len() as u32).to_le_bytes())?;
        writer.write_all(&metadata_json)?;

        // Write data (length-prefixed).
        writer.write_all(&(self.data.len() as u64).to_le_bytes())?;
        writer.write_all(&self.data)?;

        // Write checksum.
        writer.write_all(&self.checksum)?;

        writer.flush()?;
        debug!(
            path = %path.display(),
            layer_id = %self.metadata.layer_id,
            bytes = self.data.len(),
            "Wrote model chunk"
        );
        Ok(())
    }

    /// Read chunk from a file.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open chunk file: {}", path.display()))?;
        let mut reader = BufReader::new(file);

        // Read and verify magic.
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != CHUNK_MAGIC {
            anyhow::bail!("Invalid chunk file: bad magic bytes");
        }

        // Read version.
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = u32::from_le_bytes(version_bytes);
        if version != CHUNK_VERSION {
            anyhow::bail!("Unsupported chunk version: {}", version);
        }

        // Read metadata.
        let mut meta_len_bytes = [0u8; 4];
        reader.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;
        let mut meta_json = vec![0u8; meta_len];
        reader.read_exact(&mut meta_json)?;
        let metadata: LayerMetadata =
            serde_json::from_slice(&meta_json).context("Failed to deserialize metadata")?;

        // Read data.
        let mut data_len_bytes = [0u8; 8];
        reader.read_exact(&mut data_len_bytes)?;
        let data_len = u64::from_le_bytes(data_len_bytes) as usize;
        let mut data = vec![0u8; data_len];
        reader.read_exact(&mut data)?;

        // Read checksum.
        let mut checksum = vec![0u8; 32]; // SHA256 = 32 bytes
        reader.read_exact(&mut checksum)?;

        let chunk = Self {
            metadata,
            data,
            checksum,
        };

        // Verify checksum.
        if !chunk.verify_checksum() {
            anyhow::bail!(
                "Chunk checksum mismatch for layer {}",
                chunk.metadata.layer_id
            );
        }

        debug!(
            path = %path.display(),
            layer_id = %chunk.metadata.layer_id,
            bytes = chunk.data.len(),
            "Read model chunk"
        );
        Ok(chunk)
    }

    /// Get weights as f32 vector (decompresses if necessary).
    pub fn get_weights(&self) -> Result<Vec<f32>> {
        let data = if self.metadata.compressed {
            #[cfg(feature = "compression")]
            {
                use std::io::Read as _;
                let mut decoder =
                    zstd::Decoder::new(&self.data[..]).context("Failed to create zstd decoder")?;
                let mut decompressed = Vec::new();
                decoder
                    .read_to_end(&mut decompressed)
                    .context("Failed to decompress weights")?;
                decompressed
            }
            #[cfg(not(feature = "compression"))]
            {
                anyhow::bail!("Chunk is compressed but 'compression' feature not enabled");
            }
        } else {
            self.data.clone()
        };

        Self::deserialize_weights(&data)
    }
}

/// Manifest describing the complete chunked model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifest {
    /// Model name.
    pub model_name: String,
    /// Model version.
    pub model_version: String,
    /// Input shape (e.g., [1, 3, 64, 64]).
    pub input_shape: Vec<usize>,
    /// Output shape (e.g., [1, 8] for 8 classes).
    pub output_shape: Vec<usize>,
    /// Total number of layers.
    pub num_layers: usize,
    /// Chunk metadata for each layer.
    pub chunks: Vec<ChunkMetadata>,
}

/// Metadata for a single chunk file in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMetadata {
    /// Layer identifier.
    pub layer_id: String,
    /// Chunk file name (relative to manifest directory).
    pub file_name: String,
    /// File size in bytes.
    pub file_size: usize,
    /// SHA256 checksum of the chunk file.
    pub checksum: String,
}

impl ChunkManifest {
    /// Load manifest from JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open manifest: {}", path.display()))?;
        let reader = BufReader::new(file);
        let manifest: ChunkManifest =
            serde_json::from_reader(reader).context("Failed to parse manifest JSON")?;
        info!(
            model = %manifest.model_name,
            version = %manifest.model_version,
            num_layers = manifest.num_layers,
            "Loaded chunk manifest"
        );
        Ok(manifest)
    }

    /// Save manifest to JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create manifest: {}", path.display()))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self).context("Failed to write manifest JSON")?;
        info!(
            path = %path.display(),
            model = %self.model_name,
            "Saved chunk manifest"
        );
        Ok(())
    }

    /// Get chunk metadata by layer ID.
    pub fn get_chunk(&self, layer_id: &str) -> Option<&ChunkMetadata> {
        self.chunks.iter().find(|c| c.layer_id == layer_id)
    }
}

/// Split an ONNX model into chunks (stub for Rust - actual implementation in Python).
///
/// This is a placeholder for the Python chunking script. In production, the
/// Python script (`scripts/chunk_model.py`) performs the actual chunking:
///
/// 1. Load ONNX model with `onnx.load()`
/// 2. Extract layer weights from the model graph
/// 3. Create a `ModelChunk` for each layer
/// 4. Write chunks to disk with [`ModelChunk::write_to_file`]
/// 5. Generate and save [`ChunkManifest`]
///
/// This Rust function exists for documentation and type checking purposes.
pub fn chunk_onnx_model(
    _model_path: &Path,
    _output_dir: &Path,
    _compress: bool,
) -> Result<ChunkManifest> {
    anyhow::bail!("Model chunking must be performed using Python script: scripts/chunk_model.py");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_chunk_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let chunk_path = temp_dir.path().join("test_layer.chunk");

        // Create a chunk.
        let metadata = LayerMetadata {
            layer_id: "test_layer_0".to_string(),
            layer_type: "Linear".to_string(),
            weight_shape: vec![128, 256],
            weight_count: 128 * 256,
            weight_bytes: 128 * 256 * 4,
            compressed: false,
            dependencies: vec![],
        };
        let weights: Vec<f32> = (0..128 * 256).map(|i| i as f32 * 0.001).collect();
        let chunk = ModelChunk::new(metadata.clone(), weights.clone());

        // Write to file.
        chunk.write_to_file(&chunk_path).unwrap();

        // Read back.
        let loaded_chunk = ModelChunk::read_from_file(&chunk_path).unwrap();

        // Verify metadata.
        assert_eq!(loaded_chunk.metadata.layer_id, metadata.layer_id);
        assert_eq!(loaded_chunk.metadata.weight_count, metadata.weight_count);

        // Verify weights.
        let loaded_weights = loaded_chunk.get_weights().unwrap();
        assert_eq!(loaded_weights.len(), weights.len());
        for (a, b) in loaded_weights.iter().zip(weights.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn test_manifest_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

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
                    file_size: 1024,
                    checksum: "abc123".to_string(),
                },
                ChunkMetadata {
                    layer_id: "layer_1".to_string(),
                    file_name: "layer_1.chunk".to_string(),
                    file_size: 2048,
                    checksum: "def456".to_string(),
                },
            ],
        };

        // Save to file.
        manifest.save(&manifest_path).unwrap();

        // Load back.
        let loaded = ChunkManifest::load(&manifest_path).unwrap();

        // Verify.
        assert_eq!(loaded.model_name, manifest.model_name);
        assert_eq!(loaded.num_layers, manifest.num_layers);
        assert_eq!(loaded.chunks.len(), manifest.chunks.len());
    }
}
