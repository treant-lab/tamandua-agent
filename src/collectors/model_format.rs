//! Model Format Detection via Magic Bytes and Metadata Extraction
//!
//! This module provides runtime detection of AI/ML model formats by analyzing
//! file headers and magic byte sequences. Unlike the extension-based ModelType
//! in model_scanner.rs, this module validates actual file contents for security.
//!
//! Supported formats:
//! - **GGUF**: llama.cpp quantized models (magic: 0x46554747 "GGUF")
//! - **SafeTensors**: HuggingFace safe format (JSON header with "__metadata__")
//! - **PyTorch**: ZIP archives containing data.pkl (magic: PK\x03\x04)
//! - **ONNX**: Protocol buffer format (magic: 0x08)
//! - **TensorFlow**: SavedModel format (directory structure)
//!
//! Key insight: File extensions can be changed (malware evasion), but magic bytes
//! are definitive for format identification.

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use tracing::debug;

// ============================================================================
// Model Format Enum
// ============================================================================

/// Runtime-detected model format based on magic byte validation.
///
/// This enum represents the actual file format detected by reading headers,
/// not just file extension. Use this for security-sensitive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFormat {
    /// GGUF format (llama.cpp v2+) - magic: 0x46554747
    Gguf,
    /// SafeTensors format (HuggingFace) - JSON header with "__metadata__"
    Safetensors,
    /// PyTorch format (.pt/.pth) - ZIP archive (PK\x03\x04)
    Pytorch,
    /// ONNX format - Protobuf (starts with 0x08)
    Onnx,
    /// TensorFlow SavedModel - directory with saved_model.pb
    Tensorflow,
    /// Unknown or unrecognized format
    Unknown,
}

impl std::fmt::Display for ModelFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelFormat::Gguf => write!(f, "GGUF"),
            ModelFormat::Safetensors => write!(f, "SafeTensors"),
            ModelFormat::Pytorch => write!(f, "PyTorch"),
            ModelFormat::Onnx => write!(f, "ONNX"),
            ModelFormat::Tensorflow => write!(f, "TensorFlow"),
            ModelFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

// ============================================================================
// Model Metadata
// ============================================================================

/// Extracted metadata from model files.
///
/// Contains architecture, parameter count, and quantization information
/// extracted from file headers (GGUF metadata, SafeTensors JSON, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Detected format via magic bytes
    pub format: ModelFormat,
    /// Model architecture (llama, mistral, gpt2, bert, phi, etc.)
    pub architecture: Option<String>,
    /// Parameter count as human-readable string (7B, 13B, 70B, etc.)
    pub parameters: Option<String>,
    /// Quantization type (Q4_K_M, Q8_0, FP16, BF16, etc.)
    pub quantization: Option<String>,
    /// GGUF version (for GGUF files)
    pub gguf_version: Option<u32>,
    /// Number of tensors (for GGUF files)
    pub tensor_count: Option<u64>,
}

impl Default for ModelFormat {
    fn default() -> Self {
        ModelFormat::Unknown
    }
}

// ============================================================================
// Magic Byte Constants
// ============================================================================

/// GGUF magic bytes: "GGUF" = 0x46554747 (little-endian)
const GGUF_MAGIC_LE: u32 = 0x46554747;

/// GGUF magic bytes (big-endian variant): 0x47475546
const GGUF_MAGIC_BE: u32 = 0x47475546;

/// ZIP magic bytes (PK\x03\x04) for PyTorch .pt files
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// ONNX protobuf typically starts with field tag 0x08 (varint field 1)
const ONNX_PROTO_MAGIC: u8 = 0x08;

/// SafeTensors header size limit (10MB max to prevent DoS)
const SAFETENSORS_MAX_HEADER_SIZE: u64 = 10_000_000;

// ============================================================================
// GGUF Value Types (for metadata parsing)
// ============================================================================

/// GGUF metadata value types as defined in the GGUF spec
#[allow(dead_code)]
#[repr(u32)]
enum GgufMetadataValueType {
    Uint8 = 0,
    Int8 = 1,
    Uint16 = 2,
    Int16 = 3,
    Uint32 = 4,
    Int32 = 5,
    Float32 = 6,
    Bool = 7,
    String = 8,
    Array = 9,
    Uint64 = 10,
    Int64 = 11,
    Float64 = 12,
}

// ============================================================================
// Format Detection
// ============================================================================

/// Detect model format by reading magic bytes from file header.
///
/// # Arguments
/// * `path` - Path to the model file
///
/// # Returns
/// * `Ok(ModelFormat)` - Detected format
/// * `Err(io::Error)` - If file cannot be read
///
/// # Example
/// ```ignore
/// let format = detect_model_format(Path::new("model.gguf"))?;
/// assert_eq!(format, ModelFormat::Gguf);
/// ```
pub fn detect_model_format(path: &Path) -> Result<ModelFormat, io::Error> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 16];

    // Read first 16 bytes for magic byte detection
    let bytes_read = file.read(&mut header)?;
    if bytes_read < 3 {
        debug!(path = %path.display(), "File too small for format detection");
        return Ok(ModelFormat::Unknown);
    }

    // Check GGUF magic: bytes "GGUF" at offset 0
    // GGUF uses little-endian, so bytes are: 0x47 0x47 0x55 0x46
    if &header[0..4] == b"GGUF" {
        debug!(path = %path.display(), "Detected GGUF format (magic bytes)");
        return Ok(ModelFormat::Gguf);
    }

    // Alternative GGUF check using u32 (handles endianness)
    let magic_u32 = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic_u32 == GGUF_MAGIC_LE || magic_u32 == GGUF_MAGIC_BE {
        debug!(path = %path.display(), magic = magic_u32, "Detected GGUF format (u32 magic)");
        return Ok(ModelFormat::Gguf);
    }

    // Check ZIP magic for PyTorch (PK\x03\x04)
    if header[0..4] == ZIP_MAGIC {
        // PyTorch .pt files are ZIP archives containing data.pkl
        // We could verify by checking for data.pkl inside, but ZIP magic is strong enough
        debug!(path = %path.display(), "Detected PyTorch format (ZIP magic)");
        return Ok(ModelFormat::Pytorch);
    }

    // Check SafeTensors: starts with 8-byte header size, then JSON with "__metadata__"
    file.seek(SeekFrom::Start(0))?;
    if let Ok(format) = detect_safetensors(&mut file) {
        if format == ModelFormat::Safetensors {
            debug!(path = %path.display(), "Detected SafeTensors format");
            return Ok(ModelFormat::Safetensors);
        }
    }

    // Check ONNX: protobuf format, typically starts with 0x08 (field 1, varint)
    // This is a weak check - ONNX detection is best done with extension confirmation
    if header[0] == ONNX_PROTO_MAGIC {
        // Additional check: ONNX files often have 0x08 0x00 0x12 pattern
        if bytes_read >= 3 && header[2] == 0x12 {
            debug!(path = %path.display(), "Detected ONNX format (protobuf magic)");
            return Ok(ModelFormat::Onnx);
        }
        // Single 0x08 is too weak, check extension as confirmation
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("onnx") {
                debug!(path = %path.display(), "Detected ONNX format (magic + extension)");
                return Ok(ModelFormat::Onnx);
            }
        }
    }

    // Check TensorFlow SavedModel (directory with saved_model.pb)
    if path.is_dir() {
        let saved_model_pb = path.join("saved_model.pb");
        if saved_model_pb.exists() {
            debug!(path = %path.display(), "Detected TensorFlow SavedModel format");
            return Ok(ModelFormat::Tensorflow);
        }
    }

    debug!(path = %path.display(), "Unknown model format");
    Ok(ModelFormat::Unknown)
}

/// Detect SafeTensors format by reading JSON header.
fn detect_safetensors(file: &mut File) -> Result<ModelFormat, io::Error> {
    // SafeTensors format: 8-byte header size (LE u64) + JSON header + tensor data
    let mut size_buf = [0u8; 8];
    file.read_exact(&mut size_buf)?;
    let header_size = u64::from_le_bytes(size_buf);

    // Sanity check: header should be reasonable size
    if header_size == 0 || header_size > SAFETENSORS_MAX_HEADER_SIZE {
        return Ok(ModelFormat::Unknown);
    }

    // Read enough of the header to check for "__metadata__" or tensor names
    let read_size = std::cmp::min(header_size as usize, 1024);
    let mut header_preview = vec![0u8; read_size];
    file.read_exact(&mut header_preview)?;

    // Check if it looks like JSON with tensor metadata
    let header_str = String::from_utf8_lossy(&header_preview);
    if header_str.contains("__metadata__") || header_str.contains("\"dtype\"") {
        return Ok(ModelFormat::Safetensors);
    }

    Ok(ModelFormat::Unknown)
}

// ============================================================================
// GGUF Metadata Extraction
// ============================================================================

/// Extract metadata from a GGUF file header.
///
/// Parses the GGUF header to extract:
/// - Architecture (general.architecture)
/// - Parameter count (general.parameter_count)
/// - Quantization type (general.file_type)
///
/// # Arguments
/// * `path` - Path to the GGUF file
///
/// # Returns
/// * `Ok(ModelMetadata)` - Extracted metadata
/// * `Err(io::Error)` - If file cannot be read or is invalid GGUF
pub fn extract_gguf_metadata(path: &Path) -> Result<ModelMetadata, io::Error> {
    let mut file = File::open(path)?;
    let mut metadata = ModelMetadata {
        format: ModelFormat::Gguf,
        ..Default::default()
    };

    // Read and validate GGUF header (24 bytes)
    // Header: magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8)
    let magic = file.read_u32::<LittleEndian>()?;
    if magic != GGUF_MAGIC_LE && magic != GGUF_MAGIC_BE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid GGUF magic: 0x{:08X}, expected 0x{:08X}",
                magic, GGUF_MAGIC_LE
            ),
        ));
    }

    let version = file.read_u32::<LittleEndian>()?;
    metadata.gguf_version = Some(version);

    // Version 1-3 are supported (version 3 is current)
    if version < 1 || version > 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported GGUF version: {}", version),
        ));
    }

    let tensor_count = file.read_u64::<LittleEndian>()?;
    metadata.tensor_count = Some(tensor_count);

    let metadata_kv_count = file.read_u64::<LittleEndian>()?;

    // Sanity check: prevent DoS from malicious files
    if metadata_kv_count > 10000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Suspiciously high metadata count: {}", metadata_kv_count),
        ));
    }

    debug!(
        version = version,
        tensor_count = tensor_count,
        metadata_kv_count = metadata_kv_count,
        "Parsing GGUF metadata"
    );

    // Parse metadata key-value pairs
    for _ in 0..metadata_kv_count {
        match parse_gguf_kv_pair(&mut file, &mut metadata) {
            Ok(_) => {}
            Err(e) => {
                // Log but continue - some keys may be unsupported
                debug!(error = %e, "Failed to parse GGUF metadata key");
                break;
            }
        }
    }

    Ok(metadata)
}

/// Parse a single GGUF metadata key-value pair.
fn parse_gguf_kv_pair(file: &mut File, metadata: &mut ModelMetadata) -> Result<(), io::Error> {
    // Read key length and key string
    let key_len = file.read_u64::<LittleEndian>()? as usize;
    if key_len > 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Key too long"));
    }

    let mut key_buf = vec![0u8; key_len];
    file.read_exact(&mut key_buf)?;
    let key = String::from_utf8_lossy(&key_buf).to_string();

    // Read value type
    let value_type = file.read_u32::<LittleEndian>()?;

    // Process known keys, skip unknown
    match key.as_str() {
        "general.architecture" => {
            if value_type == GgufMetadataValueType::String as u32 {
                let val_len = file.read_u64::<LittleEndian>()? as usize;
                if val_len <= 256 {
                    let mut val_buf = vec![0u8; val_len];
                    file.read_exact(&mut val_buf)?;
                    metadata.architecture = Some(String::from_utf8_lossy(&val_buf).to_string());
                } else {
                    skip_gguf_value(file, value_type, Some(val_len as u64))?;
                }
            } else {
                skip_gguf_value(file, value_type, None)?;
            }
        }
        "general.parameter_count" => {
            // Usually stored as UINT64
            if value_type == GgufMetadataValueType::Uint64 as u32 {
                let param_count = file.read_u64::<LittleEndian>()?;
                metadata.parameters = Some(format_parameter_count(param_count));
            } else {
                skip_gguf_value(file, value_type, None)?;
            }
        }
        "general.file_type" => {
            // UINT32 mapping to quantization type
            if value_type == GgufMetadataValueType::Uint32 as u32 {
                let file_type = file.read_u32::<LittleEndian>()?;
                metadata.quantization = Some(quantization_from_file_type(file_type));
            } else {
                skip_gguf_value(file, value_type, None)?;
            }
        }
        _ => {
            // Skip unknown keys
            skip_gguf_value(file, value_type, None)?;
        }
    }

    Ok(())
}

/// Skip a GGUF metadata value based on its type.
fn skip_gguf_value(
    file: &mut File,
    value_type: u32,
    string_len: Option<u64>,
) -> Result<(), io::Error> {
    let skip_bytes: u64 = match value_type {
        0 => 1, // UINT8
        1 => 1, // INT8
        2 => 2, // UINT16
        3 => 2, // INT16
        4 => 4, // UINT32
        5 => 4, // INT32
        6 => 4, // FLOAT32
        7 => 1, // BOOL
        8 => {
            // STRING: length(u64) + data
            let len = string_len.unwrap_or_else(|| {
                let mut buf = [0u8; 8];
                file.read_exact(&mut buf).unwrap_or(());
                u64::from_le_bytes(buf)
            });
            len
        }
        9 => {
            // ARRAY: type(u32) + count(u64) + elements
            // Too complex to skip generically, just return error
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Array skip not implemented",
            ));
        }
        10 => 8, // UINT64
        11 => 8, // INT64
        12 => 8, // FLOAT64
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown value type",
            ));
        }
    };

    file.seek(SeekFrom::Current(skip_bytes as i64))?;
    Ok(())
}

/// Format parameter count as human-readable string (7B, 13B, 70B).
fn format_parameter_count(count: u64) -> String {
    if count >= 1_000_000_000 {
        format!("{}B", count / 1_000_000_000)
    } else if count >= 1_000_000 {
        format!("{}M", count / 1_000_000)
    } else if count >= 1_000 {
        format!("{}K", count / 1_000)
    } else {
        format!("{}", count)
    }
}

/// Map GGUF file_type to quantization name.
fn quantization_from_file_type(file_type: u32) -> String {
    match file_type {
        0 => "F32".to_string(),
        1 => "F16".to_string(),
        2 => "Q4_0".to_string(),
        3 => "Q4_1".to_string(),
        6 => "Q5_0".to_string(),
        7 => "Q8_0".to_string(),
        8 => "Q5_1".to_string(),
        10 => "Q2_K".to_string(),
        11 => "Q3_K_S".to_string(),
        12 => "Q3_K_M".to_string(),
        13 => "Q3_K_L".to_string(),
        14 => "Q4_K_S".to_string(),
        15 => "Q4_K_M".to_string(),
        16 => "Q5_K_S".to_string(),
        17 => "Q5_K_M".to_string(),
        18 => "Q6_K".to_string(),
        19 => "IQ2_XXS".to_string(),
        20 => "IQ2_XS".to_string(),
        21 => "IQ3_XXS".to_string(),
        22 => "IQ1_S".to_string(),
        23 => "IQ4_NL".to_string(),
        24 => "IQ3_S".to_string(),
        25 => "IQ2_S".to_string(),
        26 => "IQ4_XS".to_string(),
        _ => format!("UNKNOWN({})", file_type),
    }
}

// ============================================================================
// SafeTensors Metadata Extraction
// ============================================================================

/// Extract metadata from a SafeTensors file header.
///
/// Parses the JSON header to extract:
/// - Model type from "__metadata__.model_type"
/// - Total params from "__metadata__.total_params"
/// - Data type from "__metadata__.dtype"
///
/// # Arguments
/// * `path` - Path to the SafeTensors file
///
/// # Returns
/// * `Ok(ModelMetadata)` - Extracted metadata
/// * `Err(io::Error)` - If file cannot be read or is invalid SafeTensors
pub fn extract_safetensors_metadata(path: &Path) -> Result<ModelMetadata, io::Error> {
    let mut file = File::open(path)?;
    let mut metadata = ModelMetadata {
        format: ModelFormat::Safetensors,
        ..Default::default()
    };

    // Read 8-byte header size
    let mut size_buf = [0u8; 8];
    file.read_exact(&mut size_buf)?;
    let header_size = u64::from_le_bytes(size_buf) as usize;

    // Sanity check
    if header_size == 0 || header_size > SAFETENSORS_MAX_HEADER_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SafeTensors header size: {}", header_size),
        ));
    }

    // Read JSON header
    let mut header_buf = vec![0u8; header_size];
    file.read_exact(&mut header_buf)?;

    // Parse JSON
    let header: serde_json::Value = serde_json::from_slice(&header_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e)))?;

    // Extract metadata from "__metadata__" key
    if let Some(meta_obj) = header.get("__metadata__").and_then(|m| m.as_object()) {
        // Architecture/model type
        if let Some(model_type) = meta_obj.get("model_type").and_then(|v| v.as_str()) {
            metadata.architecture = Some(model_type.to_string());
        }

        // Parameter count
        if let Some(total_params) = meta_obj.get("total_params").and_then(|v| v.as_u64()) {
            metadata.parameters = Some(format_parameter_count(total_params));
        } else if let Some(total_params_str) = meta_obj.get("total_params").and_then(|v| v.as_str())
        {
            // Sometimes stored as string
            if let Ok(count) = total_params_str.parse::<u64>() {
                metadata.parameters = Some(format_parameter_count(count));
            }
        }

        // Data type / quantization
        if let Some(dtype) = meta_obj.get("dtype").and_then(|v| v.as_str()) {
            metadata.quantization = Some(dtype.to_string());
        } else if let Some(dtype) = meta_obj.get("torch_dtype").and_then(|v| v.as_str()) {
            metadata.quantization = Some(dtype.to_string());
        }
    }

    // If no __metadata__, try to infer from tensor names
    if metadata.architecture.is_none() {
        // Look for common tensor patterns to identify architecture
        let header_str = serde_json::to_string(&header).unwrap_or_default();
        if header_str.contains("model.layers") || header_str.contains("model.embed_tokens") {
            // Likely a transformer model
            metadata.architecture = Some("transformer".to_string());
        }
    }

    debug!(
        architecture = ?metadata.architecture,
        parameters = ?metadata.parameters,
        quantization = ?metadata.quantization,
        "Extracted SafeTensors metadata"
    );

    Ok(metadata)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ========================================================================
    // Format Detection Tests
    // ========================================================================

    #[test]
    fn test_detect_gguf_format() {
        // Create a file with GGUF magic bytes
        let mut file = NamedTempFile::new().unwrap();
        // GGUF magic: "GGUF" = 0x47 0x47 0x55 0x46
        file.write_all(b"GGUF").unwrap();
        // Version
        file.write_all(&3u32.to_le_bytes()).unwrap();
        // Tensor count
        file.write_all(&100u64.to_le_bytes()).unwrap();
        // Metadata count
        file.write_all(&10u64.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let format = detect_model_format(file.path()).unwrap();
        assert_eq!(format, ModelFormat::Gguf);
    }

    #[test]
    fn test_detect_pytorch_format() {
        // Create a file with ZIP magic bytes (PyTorch .pt files are ZIP archives)
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&ZIP_MAGIC).unwrap();
        file.write_all(b"fake zip content").unwrap();
        file.flush().unwrap();

        let format = detect_model_format(file.path()).unwrap();
        assert_eq!(format, ModelFormat::Pytorch);
    }

    #[test]
    fn test_detect_safetensors_format() {
        // Create a file with SafeTensors format
        let mut file = NamedTempFile::new().unwrap();

        // JSON header with __metadata__
        let header = r#"{"__metadata__":{"model_type":"llama"},"layer.weight":{"dtype":"F16","shape":[4096,4096],"data_offsets":[0,33554432]}}"#;
        let header_bytes = header.as_bytes();

        // Write header size (8 bytes, LE)
        file.write_all(&(header_bytes.len() as u64).to_le_bytes())
            .unwrap();
        // Write header
        file.write_all(header_bytes).unwrap();
        file.flush().unwrap();

        let format = detect_model_format(file.path()).unwrap();
        assert_eq!(format, ModelFormat::Safetensors);
    }

    #[test]
    fn test_detect_onnx_format_with_extension() {
        // Create a file with ONNX-like magic and .onnx extension
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("model.onnx");

        let mut file = File::create(&file_path).unwrap();
        // ONNX protobuf starts with 0x08 (field 1, varint)
        file.write_all(&[0x08, 0x00, 0x12]).unwrap();
        file.flush().unwrap();

        let format = detect_model_format(&file_path).unwrap();
        assert_eq!(format, ModelFormat::Onnx);
    }

    #[test]
    fn test_detect_unknown_format() {
        // Create a file with random bytes
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"random content that is not a model")
            .unwrap();
        file.flush().unwrap();

        let format = detect_model_format(file.path()).unwrap();
        assert_eq!(format, ModelFormat::Unknown);
    }

    #[test]
    fn test_detect_empty_file() {
        // Create an empty file
        let file = NamedTempFile::new().unwrap();

        let format = detect_model_format(file.path()).unwrap();
        assert_eq!(format, ModelFormat::Unknown);
    }

    // ========================================================================
    // GGUF Metadata Tests
    // ========================================================================

    #[test]
    fn test_gguf_magic_constant() {
        // Verify the GGUF magic constant
        assert_eq!(GGUF_MAGIC_LE, 0x46554747);

        // "GGUF" as bytes
        let gguf_bytes = b"GGUF";
        let magic =
            u32::from_le_bytes([gguf_bytes[0], gguf_bytes[1], gguf_bytes[2], gguf_bytes[3]]);
        assert_eq!(magic, GGUF_MAGIC_LE);
    }

    #[test]
    fn test_gguf_metadata_invalid_magic() {
        // Create a file with invalid magic
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"NOTG").unwrap();
        file.write_all(&3u32.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let result = extract_gguf_metadata(file.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid GGUF magic"));
    }

    #[test]
    fn test_gguf_metadata_basic() {
        // Create a minimal valid GGUF file (header only, no metadata)
        let mut file = NamedTempFile::new().unwrap();

        // Magic
        file.write_all(b"GGUF").unwrap();
        // Version 3
        file.write_all(&3u32.to_le_bytes()).unwrap();
        // Tensor count
        file.write_all(&100u64.to_le_bytes()).unwrap();
        // Metadata count = 0
        file.write_all(&0u64.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let metadata = extract_gguf_metadata(file.path()).unwrap();
        assert_eq!(metadata.format, ModelFormat::Gguf);
        assert_eq!(metadata.gguf_version, Some(3));
        assert_eq!(metadata.tensor_count, Some(100));
    }

    // ========================================================================
    // SafeTensors Metadata Tests
    // ========================================================================

    #[test]
    fn test_safetensors_metadata_with_metadata() {
        // Create a SafeTensors file with __metadata__
        let mut file = NamedTempFile::new().unwrap();

        let header = r#"{"__metadata__":{"model_type":"llama","total_params":"7000000000","dtype":"bfloat16"},"layer.weight":{"dtype":"BF16","shape":[4096,4096],"data_offsets":[0,33554432]}}"#;
        let header_bytes = header.as_bytes();

        file.write_all(&(header_bytes.len() as u64).to_le_bytes())
            .unwrap();
        file.write_all(header_bytes).unwrap();
        file.flush().unwrap();

        let metadata = extract_safetensors_metadata(file.path()).unwrap();
        assert_eq!(metadata.format, ModelFormat::Safetensors);
        assert_eq!(metadata.architecture, Some("llama".to_string()));
        assert_eq!(metadata.parameters, Some("7B".to_string()));
        assert_eq!(metadata.quantization, Some("bfloat16".to_string()));
    }

    #[test]
    fn test_safetensors_metadata_without_metadata() {
        // Create a SafeTensors file without __metadata__
        let mut file = NamedTempFile::new().unwrap();

        let header = r#"{"model.layers.0.weight":{"dtype":"F16","shape":[4096,4096],"data_offsets":[0,33554432]}}"#;
        let header_bytes = header.as_bytes();

        file.write_all(&(header_bytes.len() as u64).to_le_bytes())
            .unwrap();
        file.write_all(header_bytes).unwrap();
        file.flush().unwrap();

        let metadata = extract_safetensors_metadata(file.path()).unwrap();
        assert_eq!(metadata.format, ModelFormat::Safetensors);
        // Should infer transformer from tensor names
        assert_eq!(metadata.architecture, Some("transformer".to_string()));
    }

    #[test]
    fn test_safetensors_invalid_header_size() {
        // Create a file with invalid header size
        let mut file = NamedTempFile::new().unwrap();

        // Header size > max (10MB)
        file.write_all(&(20_000_000u64).to_le_bytes()).unwrap();
        file.flush().unwrap();

        let result = extract_safetensors_metadata(file.path());
        assert!(result.is_err());
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_format_parameter_count() {
        assert_eq!(format_parameter_count(7_000_000_000), "7B");
        assert_eq!(format_parameter_count(13_000_000_000), "13B");
        assert_eq!(format_parameter_count(70_000_000_000), "70B");
        assert_eq!(format_parameter_count(350_000_000), "350M");
        assert_eq!(format_parameter_count(1_500_000), "1M");
        assert_eq!(format_parameter_count(125_000), "125K");
        assert_eq!(format_parameter_count(500), "500");
    }

    #[test]
    fn test_quantization_from_file_type() {
        assert_eq!(quantization_from_file_type(0), "F32");
        assert_eq!(quantization_from_file_type(1), "F16");
        assert_eq!(quantization_from_file_type(2), "Q4_0");
        assert_eq!(quantization_from_file_type(7), "Q8_0");
        assert_eq!(quantization_from_file_type(15), "Q4_K_M");
        assert_eq!(quantization_from_file_type(17), "Q5_K_M");
        assert_eq!(quantization_from_file_type(18), "Q6_K");
        assert_eq!(quantization_from_file_type(999), "UNKNOWN(999)");
    }

    #[test]
    fn test_model_format_display() {
        assert_eq!(format!("{}", ModelFormat::Gguf), "GGUF");
        assert_eq!(format!("{}", ModelFormat::Safetensors), "SafeTensors");
        assert_eq!(format!("{}", ModelFormat::Pytorch), "PyTorch");
        assert_eq!(format!("{}", ModelFormat::Onnx), "ONNX");
        assert_eq!(format!("{}", ModelFormat::Tensorflow), "TensorFlow");
        assert_eq!(format!("{}", ModelFormat::Unknown), "Unknown");
    }

    #[test]
    fn test_model_format_serialization() {
        let format = ModelFormat::Gguf;
        let json = serde_json::to_string(&format).unwrap();
        assert_eq!(json, "\"gguf\"");

        let deserialized: ModelFormat = serde_json::from_str("\"safetensors\"").unwrap();
        assert_eq!(deserialized, ModelFormat::Safetensors);
    }

    #[test]
    fn test_model_metadata_serialization() {
        let metadata = ModelMetadata {
            format: ModelFormat::Gguf,
            architecture: Some("llama".to_string()),
            parameters: Some("7B".to_string()),
            quantization: Some("Q4_K_M".to_string()),
            gguf_version: Some(3),
            tensor_count: Some(291),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"format\":\"gguf\""));
        assert!(json.contains("\"architecture\":\"llama\""));
        assert!(json.contains("\"parameters\":\"7B\""));

        let deserialized: ModelMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.format, ModelFormat::Gguf);
        assert_eq!(deserialized.architecture, Some("llama".to_string()));
    }

    // ========================================================================
    // ZIP Magic Tests (for PyTorch)
    // ========================================================================

    #[test]
    fn test_zip_magic_constant() {
        // PK\x03\x04 is the ZIP local file header signature
        assert_eq!(ZIP_MAGIC, [0x50, 0x4B, 0x03, 0x04]);
        assert_eq!(&ZIP_MAGIC[0..2], b"PK");
    }
}
