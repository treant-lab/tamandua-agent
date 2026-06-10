//! Integration tests for ModelScanner module
//!
//! These tests verify the model scanner functionality including:
//! - Model type detection
//! - SHA-256 file hashing
//! - SQLite cache operations
//! - API endpoint routing

use std::path::Path;
use tempfile::TempDir;

// Import from the library
use tamandua_agent::collectors::model_scanner::{
    hash_file, CachedScanResult, ModelScanner, ModelType, ScanCache, ScanResult, ScanStatus, Threat,
};

// ============================================================================
// ModelType Tests
// ============================================================================

#[test]
fn test_model_type_pickle_extensions() {
    // All pickle-related extensions
    assert_eq!(
        ModelType::from_path(Path::new("model.pkl")),
        ModelType::Pickle
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.pt")),
        ModelType::Pickle
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.pth")),
        ModelType::Pickle
    );

    // Case insensitive
    assert_eq!(
        ModelType::from_path(Path::new("model.PKL")),
        ModelType::Pickle
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.PT")),
        ModelType::Pickle
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.PTH")),
        ModelType::Pickle
    );
}

#[test]
fn test_model_type_gguf_extensions() {
    assert_eq!(
        ModelType::from_path(Path::new("llama.gguf")),
        ModelType::Gguf
    );
    assert_eq!(
        ModelType::from_path(Path::new("llama.ggml")),
        ModelType::Gguf
    );
    assert_eq!(
        ModelType::from_path(Path::new("MODEL.GGUF")),
        ModelType::Gguf
    );
}

#[test]
fn test_model_type_safetensors() {
    assert_eq!(
        ModelType::from_path(Path::new("model.safetensors")),
        ModelType::Safetensors
    );
    assert_eq!(
        ModelType::from_path(Path::new("weights.SAFETENSORS")),
        ModelType::Safetensors
    );
}

#[test]
fn test_model_type_other_formats() {
    assert_eq!(
        ModelType::from_path(Path::new("model.onnx")),
        ModelType::Onnx
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.bin")),
        ModelType::Binary
    );
}

#[test]
fn test_model_type_unknown() {
    assert_eq!(
        ModelType::from_path(Path::new("model.txt")),
        ModelType::Unknown
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.json")),
        ModelType::Unknown
    );
    assert_eq!(
        ModelType::from_path(Path::new("model.h5")),
        ModelType::Unknown
    );
    assert_eq!(ModelType::from_path(Path::new("model")), ModelType::Unknown);
    assert_eq!(ModelType::from_path(Path::new("")), ModelType::Unknown);
}

#[test]
fn test_model_type_endpoints() {
    assert_eq!(
        ModelType::Pickle.endpoint(),
        Some("/ai-security/scan-pickle")
    );
    assert_eq!(ModelType::Gguf.endpoint(), Some("/ai-security/scan-gguf"));
    assert_eq!(
        ModelType::Safetensors.endpoint(),
        Some("/ai-security/scan-safetensors")
    );
    assert_eq!(ModelType::Onnx.endpoint(), Some("/ai-security/scan-onnx"));
    assert_eq!(
        ModelType::Binary.endpoint(),
        Some("/ai-security/scan-binary")
    );
    assert_eq!(ModelType::Unknown.endpoint(), None);
}

#[test]
fn test_model_type_is_supported() {
    assert!(ModelType::Pickle.is_supported());
    assert!(ModelType::Gguf.is_supported());
    assert!(ModelType::Safetensors.is_supported());
    assert!(ModelType::Onnx.is_supported());
    assert!(ModelType::Binary.is_supported());
    assert!(!ModelType::Unknown.is_supported());
}

// ============================================================================
// ScanResult Tests
// ============================================================================

#[test]
fn test_scan_result_safe() {
    let json = r#"{
        "safe": true,
        "threats": [],
        "risk_score": 0.0,
        "scan_time_ms": 50.5,
        "file_name": "safe_model.pkl"
    }"#;

    let result: ScanResult = serde_json::from_str(json).unwrap();
    assert!(result.safe);
    assert!(result.threats.is_empty());
    assert_eq!(result.risk_score, 0.0);
    assert_eq!(result.file_name, "safe_model.pkl");
}

#[test]
fn test_scan_result_unsafe() {
    let json = r#"{
        "safe": false,
        "threats": [
            {
                "type": "pickle_injection",
                "description": "Malicious __reduce__ detected",
                "confidence": 0.98,
                "technique_id": "T1059.006"
            },
            {
                "type": "code_execution",
                "description": "os.system call found",
                "confidence": 0.85,
                "technique_id": "T1059"
            }
        ],
        "risk_score": 0.95,
        "scan_time_ms": 123.4,
        "file_name": "malicious.pkl"
    }"#;

    let result: ScanResult = serde_json::from_str(json).unwrap();
    assert!(!result.safe);
    assert_eq!(result.threats.len(), 2);
    assert_eq!(result.risk_score, 0.95);

    // Check first threat
    assert_eq!(result.threats[0].threat_type, "pickle_injection");
    assert_eq!(result.threats[0].confidence, 0.98);
    assert_eq!(result.threats[0].technique_id, "T1059.006");
}

#[test]
fn test_scan_result_valid_alias() {
    // Some API responses use "valid" instead of "safe"
    let json = r#"{
        "valid": true,
        "threats": [],
        "risk_score": 0.0,
        "scan_time_ms": 100.0
    }"#;

    let result: ScanResult = serde_json::from_str(json).unwrap();
    assert!(result.safe); // Should correctly alias to "safe"
}

#[test]
fn test_scan_result_with_metadata() {
    let json = r#"{
        "safe": true,
        "threats": [],
        "risk_score": 0.1,
        "scan_time_ms": 200.0,
        "file_name": "model.gguf",
        "model_type": "gguf",
        "metadata": {
            "version": "1.0",
            "layers": 32
        }
    }"#;

    let result: ScanResult = serde_json::from_str(json).unwrap();
    assert!(result.metadata.is_some());
    assert_eq!(result.model_type, Some("gguf".to_string()));
}

// ============================================================================
// Threat Tests
// ============================================================================

#[test]
fn test_threat_deserialization_full() {
    let json = r#"{
        "type": "arbitrary_code_execution",
        "description": "Detected dangerous pickle opcode REDUCE",
        "confidence": 0.99,
        "technique_id": "T1059.006",
        "severity": "critical",
        "location": "offset:0x1234"
    }"#;

    let threat: Threat = serde_json::from_str(json).unwrap();
    assert_eq!(threat.threat_type, "arbitrary_code_execution");
    assert_eq!(threat.confidence, 0.99);
    assert_eq!(threat.severity, Some("critical".to_string()));
    assert_eq!(threat.location, Some("offset:0x1234".to_string()));
}

#[test]
fn test_threat_deserialization_minimal() {
    let json = r#"{
        "type": "suspicious_pattern",
        "description": "Unknown function call detected",
        "confidence": 0.5
    }"#;

    let threat: Threat = serde_json::from_str(json).unwrap();
    assert_eq!(threat.threat_type, "suspicious_pattern");
    assert_eq!(threat.technique_id, ""); // Default empty string
    assert!(threat.severity.is_none());
    assert!(threat.location.is_none());
}

// ============================================================================
// ScanStatus Tests
// ============================================================================

#[test]
fn test_scan_status_serialization() {
    assert_eq!(
        serde_json::to_string(&ScanStatus::Pending).unwrap(),
        r#""pending""#
    );
    assert_eq!(
        serde_json::to_string(&ScanStatus::Scanning).unwrap(),
        r#""scanning""#
    );
    assert_eq!(
        serde_json::to_string(&ScanStatus::Completed).unwrap(),
        r#""completed""#
    );
    assert_eq!(
        serde_json::to_string(&ScanStatus::Failed).unwrap(),
        r#""failed""#
    );
    assert_eq!(
        serde_json::to_string(&ScanStatus::Cached).unwrap(),
        r#""cached""#
    );
}

#[test]
fn test_scan_status_deserialization() {
    let pending: ScanStatus = serde_json::from_str(r#""pending""#).unwrap();
    assert_eq!(pending, ScanStatus::Pending);

    let cached: ScanStatus = serde_json::from_str(r#""cached""#).unwrap();
    assert_eq!(cached, ScanStatus::Cached);
}

// ============================================================================
// ScanCache Tests
// ============================================================================

#[tokio::test]
async fn test_cache_new_creates_database() {
    let temp_dir = TempDir::new().unwrap();
    let cache_path = temp_dir.path().to_path_buf();

    let cache = ScanCache::new(cache_path.clone());
    assert!(cache.is_ok());

    // Database file should exist
    let db_path = cache_path.join("model_scan_cache.db");
    assert!(db_path.exists());
}

#[tokio::test]
async fn test_cache_get_missing() {
    let temp_dir = TempDir::new().unwrap();
    let cache = ScanCache::new(temp_dir.path().to_path_buf()).unwrap();

    // Get should return None for missing hash
    let result = cache.get("nonexistent_hash_12345").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_cache_put_and_get() {
    let temp_dir = TempDir::new().unwrap();
    let cache = ScanCache::new(temp_dir.path().to_path_buf()).unwrap();

    let hash = "abc123def456789";
    let path = "/models/test.pkl";
    let scan_result = ScanResult {
        safe: true,
        threats: vec![],
        risk_score: 0.0,
        scan_time_ms: 100.0,
        file_name: "test.pkl".to_string(),
        model_type: Some("pickle".to_string()),
        metadata: None,
    };

    // Put the result
    cache.put(hash, path, &scan_result).await.unwrap();

    // Get should return the cached result
    let cached = cache.get(hash).await;
    assert!(cached.is_some());

    let cached = cached.unwrap();
    assert_eq!(cached.sha256, hash);
    assert_eq!(cached.file_path, path);
    assert!(cached.result.safe);
    assert_eq!(cached.result.risk_score, 0.0);
}

#[tokio::test]
async fn test_cache_update_existing() {
    let temp_dir = TempDir::new().unwrap();
    let cache = ScanCache::new(temp_dir.path().to_path_buf()).unwrap();

    let hash = "update_test_hash";
    let path = "/models/test.pkl";

    // First result
    let result1 = ScanResult {
        safe: true,
        threats: vec![],
        risk_score: 0.0,
        scan_time_ms: 100.0,
        file_name: "test.pkl".to_string(),
        model_type: None,
        metadata: None,
    };

    cache.put(hash, path, &result1).await.unwrap();

    // Update with new result
    let result2 = ScanResult {
        safe: false,
        threats: vec![Threat {
            threat_type: "test".to_string(),
            description: "Test threat".to_string(),
            confidence: 0.5,
            technique_id: "T1234".to_string(),
            severity: None,
            location: None,
        }],
        risk_score: 0.5,
        scan_time_ms: 200.0,
        file_name: "test.pkl".to_string(),
        model_type: None,
        metadata: None,
    };

    cache.put(hash, path, &result2).await.unwrap();

    // Should get the updated result
    let cached = cache.get(hash).await.unwrap();
    assert!(!cached.result.safe);
    assert_eq!(cached.result.risk_score, 0.5);
    assert_eq!(cached.result.threats.len(), 1);
}

// ============================================================================
// hash_file Tests
// ============================================================================

#[tokio::test]
async fn test_hash_file_known_content() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");

    // Write known content
    std::fs::write(&test_file, b"Hello, World!").unwrap();

    let hash = hash_file(&test_file).await.unwrap();

    // SHA-256 of "Hello, World!"
    assert_eq!(
        hash,
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    );
}

#[tokio::test]
async fn test_hash_file_empty() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("empty.txt");

    std::fs::write(&test_file, b"").unwrap();

    let hash = hash_file(&test_file).await.unwrap();

    // SHA-256 of empty string
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[tokio::test]
async fn test_hash_file_binary_content() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("binary.bin");

    // Binary content with nulls and high bytes
    let content: Vec<u8> = (0..256).map(|i| i as u8).collect();
    std::fs::write(&test_file, &content).unwrap();

    let hash = hash_file(&test_file).await.unwrap();

    // Should be a valid 64-char hex string
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_hash_file_large() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("large.bin");

    // Create file larger than buffer size (64KB chunks)
    let content = vec![0xABu8; 100 * 1024]; // 100KB
    std::fs::write(&test_file, &content).unwrap();

    let hash = hash_file(&test_file).await.unwrap();

    // Should produce valid hash
    assert_eq!(hash.len(), 64);
}

#[tokio::test]
async fn test_hash_file_nonexistent() {
    let result = hash_file(Path::new("/nonexistent/path/file.bin")).await;
    assert!(result.is_err());
}

// ============================================================================
// ModelScanner Tests
// ============================================================================

#[tokio::test]
async fn test_scanner_creation() {
    let temp_dir = TempDir::new().unwrap();

    let scanner = ModelScanner::new(
        "http://localhost:8000".to_string(),
        "test-api-key".to_string(),
        temp_dir.path().to_path_buf(),
    );

    assert!(scanner.is_ok());
}

#[test]
fn test_scanner_is_supported_type() {
    // Supported types
    assert!(ModelScanner::is_supported_type(Path::new("model.pkl")));
    assert!(ModelScanner::is_supported_type(Path::new("model.pt")));
    assert!(ModelScanner::is_supported_type(Path::new("model.pth")));
    assert!(ModelScanner::is_supported_type(Path::new("model.gguf")));
    assert!(ModelScanner::is_supported_type(Path::new(
        "model.safetensors"
    )));
    assert!(ModelScanner::is_supported_type(Path::new("model.onnx")));
    assert!(ModelScanner::is_supported_type(Path::new("model.bin")));

    // Unsupported types
    assert!(!ModelScanner::is_supported_type(Path::new("model.txt")));
    assert!(!ModelScanner::is_supported_type(Path::new("model.json")));
    assert!(!ModelScanner::is_supported_type(Path::new("README.md")));
}

#[test]
fn test_scanner_get_model_type() {
    assert_eq!(
        ModelScanner::get_model_type(Path::new("model.pkl")),
        ModelType::Pickle
    );
    assert_eq!(
        ModelScanner::get_model_type(Path::new("model.gguf")),
        ModelType::Gguf
    );
    assert_eq!(
        ModelScanner::get_model_type(Path::new("model.txt")),
        ModelType::Unknown
    );
}

// ============================================================================
// CachedScanResult Tests
// ============================================================================

#[test]
fn test_cached_scan_result_serialization() {
    let cached = CachedScanResult {
        sha256: "abc123".to_string(),
        file_path: "/path/to/model.pkl".to_string(),
        result: ScanResult {
            safe: true,
            threats: vec![],
            risk_score: 0.0,
            scan_time_ms: 50.0,
            file_name: "model.pkl".to_string(),
            model_type: None,
            metadata: None,
        },
        scanned_at: 1234567890,
    };

    let json = serde_json::to_string(&cached).unwrap();
    assert!(json.contains("abc123"));
    assert!(json.contains("model.pkl"));

    // Round-trip
    let deserialized: CachedScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.sha256, "abc123");
    assert_eq!(deserialized.scanned_at, 1234567890);
}
