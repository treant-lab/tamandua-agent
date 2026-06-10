//! Model Scanner - HTTP client for ML service API calls with SQLite cache
//!
//! This module provides security scanning capabilities for AI/ML model files by
//! communicating with the ML service API and caching results locally.

use anyhow::{Context, Result};
use reqwest::Client;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

/// Maximum concurrent scans allowed
const MAX_CONCURRENT_SCANS: usize = 5;

/// Cache TTL in seconds (24 hours)
const CACHE_TTL_SECONDS: i64 = 86400;

/// HTTP client timeout in seconds (5 minutes for large files)
const HTTP_TIMEOUT_SECONDS: u64 = 300;

/// Model file type classification based on extension
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelType {
    /// Python pickle files (.pkl, .pt, .pth)
    Pickle,
    /// GGUF format files (.gguf)
    Gguf,
    /// Safetensors format files (.safetensors)
    Safetensors,
    /// ONNX format files (.onnx)
    Onnx,
    /// Binary format files (.bin)
    Binary,
    /// Unknown file type
    Unknown,
}

impl ModelType {
    /// Determine model type from file path extension
    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
        {
            Some(ext) => match ext.as_str() {
                "pkl" | "pt" | "pth" => Self::Pickle,
                "gguf" | "ggml" => Self::Gguf,
                "safetensors" => Self::Safetensors,
                "onnx" => Self::Onnx,
                "bin" => Self::Binary,
                _ => Self::Unknown,
            },
            None => Self::Unknown,
        }
    }

    /// Get the API endpoint path for this model type
    pub fn endpoint(&self) -> Option<&'static str> {
        match self {
            Self::Pickle => Some("/ai-security/scan-pickle"),
            Self::Gguf => Some("/ai-security/scan-gguf"),
            Self::Safetensors => Some("/ai-security/scan-safetensors"),
            Self::Onnx => Some("/ai-security/scan-onnx"),
            Self::Binary => Some("/ai-security/scan-binary"),
            Self::Unknown => None,
        }
    }

    /// Check if this model type is supported for scanning
    pub fn is_supported(&self) -> bool {
        self.endpoint().is_some()
    }
}

/// Scan result from ML service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Whether the model is safe (no threats detected)
    #[serde(alias = "valid")]
    pub safe: bool,

    /// List of detected threats
    #[serde(default)]
    pub threats: Vec<Threat>,

    /// Overall risk score (0.0 - 1.0)
    pub risk_score: f64,

    /// Scan duration in milliseconds
    pub scan_time_ms: f64,

    /// Original file name
    #[serde(default)]
    pub file_name: String,

    /// Model type detected
    #[serde(default)]
    pub model_type: Option<String>,

    /// Additional scan metadata
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Threat detected in a model file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Threat type classification
    #[serde(rename = "type")]
    pub threat_type: String,

    /// Human-readable threat description
    pub description: String,

    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,

    /// MITRE ATT&CK technique ID (e.g., "T1059")
    #[serde(default)]
    pub technique_id: String,

    /// Severity level
    #[serde(default)]
    pub severity: Option<String>,

    /// Location within the file (if applicable)
    #[serde(default)]
    pub location: Option<String>,
}

/// Scan status for tracking scan progress
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Scan is pending (queued)
    Pending,
    /// Scan is in progress
    Scanning,
    /// Scan completed successfully
    Completed,
    /// Scan failed with an error
    Failed,
    /// Result was retrieved from cache
    Cached,
}

/// Cached scan result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScanResult {
    /// SHA-256 hash of the scanned file
    pub sha256: String,

    /// Original file path
    pub file_path: String,

    /// The scan result
    pub result: ScanResult,

    /// Unix timestamp when the scan was performed
    pub scanned_at: i64,
}

/// SQLite-based scan result cache
pub struct ScanCache {
    /// Path to the SQLite database
    db_path: PathBuf,
}

impl ScanCache {
    /// Create a new scan cache in the specified directory
    ///
    /// Creates the cache directory if it doesn't exist and initializes
    /// the SQLite database with the required schema.
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        // Ensure cache directory exists
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;

        let db_path = cache_dir.join("model_scan_cache.db");

        // Initialize database schema
        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open cache database: {:?}", db_path))?;

        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS scan_cache (
                sha256 TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                scan_result TEXT NOT NULL,
                risk_score REAL NOT NULL,
                scanned_at INTEGER NOT NULL
            )
            "#,
            [],
        )
        .context("Failed to create scan_cache table")?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_cache(scanned_at)",
            [],
        )
        .context("Failed to create scanned_at index")?;

        Ok(Self { db_path })
    }

    /// Get a cached scan result by SHA-256 hash
    ///
    /// Returns None if the entry doesn't exist or has expired (>24 hours old).
    pub async fn get(&self, sha256: &str) -> Option<CachedScanResult> {
        let db_path = self.db_path.clone();
        let sha256 = sha256.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).ok()?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;

            let mut stmt = conn
                .prepare(
                    r#"
                    SELECT sha256, file_path, scan_result, scanned_at
                    FROM scan_cache
                    WHERE sha256 = ? AND scanned_at + ? > ?
                    "#,
                )
                .ok()?;

            let result = stmt
                .query_row(rusqlite::params![sha256, CACHE_TTL_SECONDS, now], |row| {
                    let sha256: String = row.get(0)?;
                    let file_path: String = row.get(1)?;
                    let scan_result_json: String = row.get(2)?;
                    let scanned_at: i64 = row.get(3)?;

                    let result: ScanResult =
                        serde_json::from_str(&scan_result_json).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                2,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;

                    Ok(CachedScanResult {
                        sha256,
                        file_path,
                        result,
                        scanned_at,
                    })
                })
                .ok();

            result
        })
        .await
        .ok()
        .flatten()
    }

    /// Store a scan result in the cache
    pub async fn put(&self, sha256: &str, file_path: &str, result: &ScanResult) -> Result<()> {
        let db_path = self.db_path.clone();
        let sha256 = sha256.to_string();
        let file_path = file_path.to_string();
        let result_json =
            serde_json::to_string(result).context("Failed to serialize scan result")?;
        let risk_score = result.risk_score;

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open cache database: {:?}", db_path))?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("Failed to get current time")?
                .as_secs() as i64;

            conn.execute(
                r#"
                INSERT OR REPLACE INTO scan_cache (sha256, file_path, scan_result, risk_score, scanned_at)
                VALUES (?, ?, ?, ?, ?)
                "#,
                rusqlite::params![sha256, file_path, result_json, risk_score, now],
            )
            .context("Failed to insert scan result into cache")?;

            Ok(())
        })
        .await
        .context("Cache put task panicked")?
    }

    /// Remove expired entries from the cache
    pub async fn cleanup_expired(&self) -> Result<u64> {
        let db_path = self.db_path.clone();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open cache database: {:?}", db_path))?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("Failed to get current time")?
                .as_secs() as i64;

            let cutoff = now - CACHE_TTL_SECONDS;

            let deleted = conn
                .execute(
                    "DELETE FROM scan_cache WHERE scanned_at < ?",
                    rusqlite::params![cutoff],
                )
                .context("Failed to delete expired entries")?;

            Ok(deleted as u64)
        })
        .await
        .context("Cache cleanup task panicked")?
    }
}

/// Compute SHA-256 hash of a file asynchronously
///
/// Reads the file in 64KB chunks to handle large files efficiently.
pub async fn hash_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open file for hashing: {:?}", path))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks

    loop {
        let n = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("Failed to read file for hashing: {:?}", path))?;

        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Model scanner with HTTP client and caching
pub struct ModelScanner {
    /// HTTP client for API requests
    client: Client,

    /// Base URL of the ML service
    base_url: String,

    /// API key for authentication
    api_key: String,

    /// Semaphore to limit concurrent scans
    semaphore: Arc<Semaphore>,

    /// Local scan result cache
    cache: ScanCache,
}

impl ModelScanner {
    /// Create a new ModelScanner with the specified configuration
    pub fn new(base_url: String, api_key: String, cache_dir: PathBuf) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECONDS))
            .build()
            .context("Failed to create HTTP client")?;

        let cache = ScanCache::new(cache_dir)?;

        Ok(Self {
            client,
            base_url,
            api_key,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
            cache,
        })
    }

    /// Create a ModelScanner from environment variables
    ///
    /// Uses:
    /// - `TAMANDUA_ML_SERVICE_URL` (default: "http://localhost:8000")
    /// - `TAMANDUA_ML_API_KEY` (default: "")
    pub fn from_env(cache_dir: PathBuf) -> Result<Self> {
        let base_url = std::env::var("TAMANDUA_ML_SERVICE_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());
        let api_key = std::env::var("TAMANDUA_ML_API_KEY").unwrap_or_default();

        Self::new(base_url, api_key, cache_dir)
    }

    /// Scan a model file for security threats
    ///
    /// Returns:
    /// - `Ok(Some(result))` if the scan succeeded
    /// - `Ok(None)` if the file type is not supported
    /// - `Err(_)` if the scan failed
    pub async fn scan_model(&self, path: &Path) -> Result<Option<ScanResult>> {
        // 1. Determine model type and endpoint
        let model_type = ModelType::from_path(path);
        let endpoint = match model_type.endpoint() {
            Some(e) => e,
            None => {
                tracing::debug!(path = %path.display(), "Unsupported model file type");
                return Ok(None);
            }
        };

        // 2. Hash the file
        let hash = hash_file(path)
            .await
            .with_context(|| format!("Failed to hash file: {:?}", path))?;

        // 3. Check cache
        if let Some(cached) = self.cache.get(&hash).await {
            tracing::debug!(
                path = %path.display(),
                hash = %hash,
                "Using cached scan result"
            );
            return Ok(Some(cached.result));
        }

        // 4. Acquire semaphore permit (limits to 5 concurrent scans)
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("Semaphore error: {}", e))?;

        // 5. Stream file upload using tokio-util
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("Failed to open file for upload: {:?}", path))?;

        let stream = tokio_util::codec::FramedRead::new(file, tokio_util::codec::BytesCodec::new());
        let file_body = reqwest::Body::wrap_stream(stream);

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("model")
            .to_string();

        let part = reqwest::multipart::Part::stream(file_body)
            .file_name(file_name.clone())
            .mime_str("application/octet-stream")
            .context("Failed to set MIME type for upload part")?;

        let form = reqwest::multipart::Form::new().part("file", part);

        // 6. Send request
        let url = format!("{}{}", self.base_url, endpoint);
        tracing::info!(
            path = %path.display(),
            endpoint = %endpoint,
            hash = %hash,
            "Scanning model file"
        );

        let mut request = self.client.post(&url).multipart(form);

        if !self.api_key.is_empty() {
            request = request.header("X-API-Key", &self.api_key);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to send scan request to ML service at {}", url))?;

        // 7. Handle response
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Scan failed: {} - {}", status, body));
        }

        let mut result: ScanResult = response
            .json()
            .await
            .context("Failed to parse scan response")?;

        // Set file_name if not provided by server
        if result.file_name.is_empty() {
            result.file_name = file_name;
        }

        // 8. Cache the result
        self.cache
            .put(&hash, path.to_string_lossy().as_ref(), &result)
            .await
            .context("Failed to cache scan result")?;

        tracing::info!(
            path = %path.display(),
            safe = result.safe,
            risk_score = result.risk_score,
            threats = result.threats.len(),
            scan_time_ms = result.scan_time_ms,
            "Model scan complete"
        );

        Ok(Some(result))
    }

    /// Check if a file is a supported model type
    pub fn is_supported_type(path: &Path) -> bool {
        ModelType::from_path(path).is_supported()
    }

    /// Get the model type for a file
    pub fn get_model_type(path: &Path) -> ModelType {
        ModelType::from_path(path)
    }

    /// Clean up expired cache entries
    pub async fn cleanup_cache(&self) -> Result<u64> {
        self.cache.cleanup_expired().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_model_type_from_path() {
        // Pickle variants
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

        // GGUF variants
        assert_eq!(
            ModelType::from_path(Path::new("model.gguf")),
            ModelType::Gguf
        );
        assert_eq!(
            ModelType::from_path(Path::new("model.ggml")),
            ModelType::Gguf
        );

        // Safetensors
        assert_eq!(
            ModelType::from_path(Path::new("model.safetensors")),
            ModelType::Safetensors
        );

        // ONNX
        assert_eq!(
            ModelType::from_path(Path::new("model.onnx")),
            ModelType::Onnx
        );

        // Binary
        assert_eq!(
            ModelType::from_path(Path::new("model.bin")),
            ModelType::Binary
        );

        // Unknown types
        assert_eq!(
            ModelType::from_path(Path::new("model.txt")),
            ModelType::Unknown
        );
        assert_eq!(
            ModelType::from_path(Path::new("model.json")),
            ModelType::Unknown
        );
        assert_eq!(ModelType::from_path(Path::new("model")), ModelType::Unknown);

        // Case insensitivity
        assert_eq!(
            ModelType::from_path(Path::new("model.PKL")),
            ModelType::Pickle
        );
        assert_eq!(
            ModelType::from_path(Path::new("model.SAFETENSORS")),
            ModelType::Safetensors
        );
    }

    #[test]
    fn test_model_type_endpoint() {
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

    #[test]
    fn test_scan_result_deserialization() {
        let json = r#"{
            "safe": true,
            "threats": [],
            "risk_score": 0.0,
            "scan_time_ms": 123.45,
            "file_name": "test.pkl"
        }"#;

        let result: ScanResult = serde_json::from_str(json).unwrap();
        assert!(result.safe);
        assert!(result.threats.is_empty());
        assert_eq!(result.risk_score, 0.0);
        assert_eq!(result.scan_time_ms, 123.45);
        assert_eq!(result.file_name, "test.pkl");
    }

    #[test]
    fn test_scan_result_with_threats() {
        let json = r#"{
            "safe": false,
            "threats": [
                {
                    "type": "pickle_injection",
                    "description": "Malicious __reduce__ call detected",
                    "confidence": 0.95,
                    "technique_id": "T1059"
                }
            ],
            "risk_score": 0.9,
            "scan_time_ms": 456.78,
            "file_name": "malicious.pkl"
        }"#;

        let result: ScanResult = serde_json::from_str(json).unwrap();
        assert!(!result.safe);
        assert_eq!(result.threats.len(), 1);
        assert_eq!(result.threats[0].threat_type, "pickle_injection");
        assert_eq!(result.threats[0].confidence, 0.95);
        assert_eq!(result.threats[0].technique_id, "T1059");
        assert_eq!(result.risk_score, 0.9);
    }

    #[test]
    fn test_scan_result_with_valid_alias() {
        // Some endpoints return "valid" instead of "safe"
        let json = r#"{
            "valid": true,
            "threats": [],
            "risk_score": 0.0,
            "scan_time_ms": 100.0
        }"#;

        let result: ScanResult = serde_json::from_str(json).unwrap();
        assert!(result.safe);
    }

    #[test]
    fn test_threat_deserialization() {
        let json = r#"{
            "type": "code_execution",
            "description": "Arbitrary code execution detected",
            "confidence": 0.99,
            "technique_id": "T1203",
            "severity": "critical",
            "location": "layer.0.weight"
        }"#;

        let threat: Threat = serde_json::from_str(json).unwrap();
        assert_eq!(threat.threat_type, "code_execution");
        assert_eq!(threat.description, "Arbitrary code execution detected");
        assert_eq!(threat.confidence, 0.99);
        assert_eq!(threat.technique_id, "T1203");
        assert_eq!(threat.severity, Some("critical".to_string()));
        assert_eq!(threat.location, Some("layer.0.weight".to_string()));
    }

    #[tokio::test]
    async fn test_scan_cache_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let cache = ScanCache::new(temp_dir.path().to_path_buf()).unwrap();

        let test_hash = "abc123def456";
        let test_path = "/path/to/model.pkl";
        let test_result = ScanResult {
            safe: true,
            threats: vec![],
            risk_score: 0.0,
            scan_time_ms: 100.0,
            file_name: "model.pkl".to_string(),
            model_type: Some("pickle".to_string()),
            metadata: None,
        };

        // Initially, cache should be empty
        let cached = cache.get(test_hash).await;
        assert!(cached.is_none());

        // Put a result in the cache
        cache.put(test_hash, test_path, &test_result).await.unwrap();

        // Now we should be able to retrieve it
        let cached = cache.get(test_hash).await;
        assert!(cached.is_some());

        let cached = cached.unwrap();
        assert_eq!(cached.sha256, test_hash);
        assert_eq!(cached.file_path, test_path);
        assert_eq!(cached.result.safe, true);
        assert_eq!(cached.result.risk_score, 0.0);
    }

    #[tokio::test]
    async fn test_scan_cache_missing_hash() {
        let temp_dir = TempDir::new().unwrap();
        let cache = ScanCache::new(temp_dir.path().to_path_buf()).unwrap();

        // Query for a hash that doesn't exist
        let cached = cache.get("nonexistent_hash").await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_hash_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        // Create a test file with known content
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

        // Create an empty file
        std::fs::write(&test_file, b"").unwrap();

        let hash = hash_file(&test_file).await.unwrap();

        // SHA-256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn test_hash_file_large() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("large.bin");

        // Create a file larger than the buffer size (64KB)
        let data = vec![0u8; 100 * 1024]; // 100KB
        std::fs::write(&test_file, &data).unwrap();

        // Should not panic and should produce a valid hash
        let hash = hash_file(&test_file).await.unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters
    }

    #[test]
    fn test_model_scanner_is_supported_type() {
        assert!(ModelScanner::is_supported_type(Path::new("model.pkl")));
        assert!(ModelScanner::is_supported_type(Path::new(
            "model.safetensors"
        )));
        assert!(ModelScanner::is_supported_type(Path::new("model.gguf")));
        assert!(!ModelScanner::is_supported_type(Path::new("model.txt")));
        assert!(!ModelScanner::is_supported_type(Path::new("README.md")));
    }

    #[test]
    fn test_scan_status_serialization() {
        let pending = ScanStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, r#""pending""#);

        let cached: ScanStatus = serde_json::from_str(r#""cached""#).unwrap();
        assert_eq!(cached, ScanStatus::Cached);
    }

    #[tokio::test]
    async fn test_model_scanner_creation() {
        let temp_dir = TempDir::new().unwrap();

        // Should successfully create a scanner
        let scanner = ModelScanner::new(
            "http://localhost:8000".to_string(),
            "test-api-key".to_string(),
            temp_dir.path().to_path_buf(),
        );

        assert!(scanner.is_ok());
    }
}
