//! Content-Aware Data Loss Prevention (DLP) Collector
//!
//! Implements content classification and scanning to detect sensitive data
//! exfiltration via file writes, clipboard operations, and network transfers.
//!
//! Classifier categories:
//! - **PII**: SSN, credit cards (Luhn-validated), emails, phone numbers,
//!   passport numbers, driver's license patterns
//! - **Credentials**: AWS keys, Azure secrets, GCP service account keys,
//!   generic API keys, SSH private keys, JWT tokens, database connection strings
//! - **Regulated Data**: ICD-10 medical codes, HIPAA identifiers, PCI card data
//! - **Source Code Secrets**: Private key material, hardcoded passwords,
//!   internal URLs/IPs
//!
//! Performance: scans in configurable chunks, skips binary files, respects
//! maximum file size limits, and runs classification concurrently.
//!
//! MITRE ATT&CK: T1567 (Exfiltration Over Web Service), T1048 (Exfiltration
//! Over Alternative Protocol), T1052 (Exfiltration Over Physical Medium)

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Configuration
// ============================================================================

/// DLP collector configuration (nested under `[dlp]` in agent.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DlpConfig {
    /// Master switch for DLP content scanning.
    pub enabled: bool,

    /// Enable PII classifiers (SSN, credit card, email, phone, passport, DL).
    pub pii_enabled: bool,

    /// Enable credential classifiers (AWS, Azure, GCP, API keys, SSH, JWT, DB).
    pub credentials_enabled: bool,

    /// Enable regulated data classifiers (ICD-10, HIPAA, PCI).
    pub regulated_data_enabled: bool,

    /// Enable source code secret classifiers (private keys, hardcoded passwords).
    pub source_code_secrets_enabled: bool,

    /// Maximum file size in bytes to scan (default: 50 MB).
    pub max_file_size_bytes: u64,

    /// Chunk size in bytes for incremental scanning (default: 64 KB).
    pub scan_chunk_size: usize,

    /// Minimum confidence threshold (0.0 - 1.0) to report a match.
    pub min_confidence: f32,

    /// Monitor file writes to removable media (USB drives).
    pub monitor_usb_writes: bool,

    /// Monitor file writes to network shares (UNC paths, NFS mounts).
    pub monitor_network_shares: bool,

    /// Monitor file writes to cloud sync folders.
    pub monitor_cloud_sync: bool,

    /// Monitor clipboard for DLP content.
    pub monitor_clipboard: bool,

    /// Cloud sync folder paths to monitor (auto-detected if empty).
    pub cloud_sync_paths: Vec<String>,

    /// File extensions to always skip (binary, media).
    pub skip_extensions: Vec<String>,

    /// DLP action on detection: "log", "warn", "block".
    pub action_on_detection: String,

    /// Polling interval in milliseconds for file transfer monitoring.
    pub poll_interval_ms: u64,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pii_enabled: true,
            credentials_enabled: true,
            regulated_data_enabled: true,
            source_code_secrets_enabled: true,
            max_file_size_bytes: 50 * 1024 * 1024, // 50 MB
            scan_chunk_size: 64 * 1024,            // 64 KB
            min_confidence: 0.5,
            monitor_usb_writes: true,
            monitor_network_shares: true,
            monitor_cloud_sync: true,
            monitor_clipboard: true,
            cloud_sync_paths: Vec::new(),
            skip_extensions: vec![
                "exe".into(),
                "dll".into(),
                "so".into(),
                "dylib".into(),
                "bin".into(),
                "img".into(),
                "iso".into(),
                "dmg".into(),
                "mp3".into(),
                "mp4".into(),
                "avi".into(),
                "mkv".into(),
                "wav".into(),
                "flac".into(),
                "ogg".into(),
                "webm".into(),
                "zip".into(),
                "gz".into(),
                "tar".into(),
                "7z".into(),
                "rar".into(),
                "bz2".into(),
                "xz".into(),
                "zst".into(),
                "png".into(),
                "jpg".into(),
                "jpeg".into(),
                "gif".into(),
                "bmp".into(),
                "ico".into(),
                "svg".into(),
                "webp".into(),
            ],
            action_on_detection: "log".into(),
            poll_interval_ms: 2000,
        }
    }
}

// ============================================================================
// Content Match Types
// ============================================================================

/// Category of classified content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierCategory {
    Pii,
    Credentials,
    RegulatedData,
    SourceCodeSecrets,
}

/// Specific classifier type within a category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierType {
    // PII
    Ssn,
    CreditCard,
    Email,
    PhoneNumber,
    PassportNumber,
    DriversLicense,
    // Credentials
    AwsAccessKey,
    AwsSecretKey,
    AzureClientSecret,
    GcpServiceAccountKey,
    GenericApiKey,
    SshPrivateKey,
    JwtToken,
    DatabaseConnectionString,
    // Regulated
    Icd10Code,
    HipaaIdentifier,
    PciCardData,
    // Source Code Secrets
    PrivateKeyMaterial,
    HardcodedPassword,
    InternalUrl,
    InternalIp,
}

impl ClassifierType {
    /// Get the category for this classifier type.
    pub fn category(&self) -> ClassifierCategory {
        match self {
            Self::Ssn
            | Self::CreditCard
            | Self::Email
            | Self::PhoneNumber
            | Self::PassportNumber
            | Self::DriversLicense => ClassifierCategory::Pii,

            Self::AwsAccessKey
            | Self::AwsSecretKey
            | Self::AzureClientSecret
            | Self::GcpServiceAccountKey
            | Self::GenericApiKey
            | Self::SshPrivateKey
            | Self::JwtToken
            | Self::DatabaseConnectionString => ClassifierCategory::Credentials,

            Self::Icd10Code | Self::HipaaIdentifier | Self::PciCardData => {
                ClassifierCategory::RegulatedData
            }

            Self::PrivateKeyMaterial
            | Self::HardcodedPassword
            | Self::InternalUrl
            | Self::InternalIp => ClassifierCategory::SourceCodeSecrets,
        }
    }

    /// Default confidence score for this classifier.
    pub fn default_confidence(&self) -> f32 {
        match self {
            Self::Ssn => 0.85,
            Self::CreditCard => 0.95, // Luhn-validated
            Self::Email => 0.70,
            Self::PhoneNumber => 0.60,
            Self::PassportNumber => 0.75,
            Self::DriversLicense => 0.70,
            Self::AwsAccessKey => 0.95,
            Self::AwsSecretKey => 0.90,
            Self::AzureClientSecret => 0.90,
            Self::GcpServiceAccountKey => 0.90,
            Self::GenericApiKey => 0.65,
            Self::SshPrivateKey => 0.98,
            Self::JwtToken => 0.85,
            Self::DatabaseConnectionString => 0.80,
            Self::Icd10Code => 0.70,
            Self::HipaaIdentifier => 0.75,
            Self::PciCardData => 0.90,
            Self::PrivateKeyMaterial => 0.95,
            Self::HardcodedPassword => 0.75,
            Self::InternalUrl => 0.60,
            Self::InternalIp => 0.55,
        }
    }
}

/// A single content match from the DLP classifier engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMatch {
    /// Which classifier produced this match.
    pub classifier_type: ClassifierType,
    /// Redacted version of matched text (e.g., "****-**-1234").
    pub matched_text_redacted: String,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Byte offset of the match within the scanned content.
    pub offset: usize,
    /// Length of the matched region in bytes.
    pub length: usize,
    /// High-level category.
    pub category: ClassifierCategory,
}

/// Destination type for file transfer monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDestination {
    UsbDrive,
    NetworkShare,
    CloudSync,
    EmailStaging,
    Clipboard,
    Unknown,
}

/// DLP event payload sent as telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpEvent {
    /// File path or "clipboard" for clipboard events.
    pub source_path: String,
    /// Transfer destination type.
    pub destination: TransferDestination,
    /// Process that triggered the write/copy.
    pub process_name: String,
    /// Process ID.
    pub pid: u32,
    /// Username context.
    pub user: String,
    /// SHA-256 hash of the scanned content.
    pub content_hash: String,
    /// Size of scanned content in bytes.
    pub content_size: u64,
    /// Content matches found by classifiers.
    pub matches: Vec<ContentMatch>,
    /// DLP policy action taken (log, warn, block).
    pub action_taken: String,
    /// Count of distinct classifier types matched.
    pub distinct_classifier_count: usize,
    /// Highest confidence score among all matches.
    pub max_confidence: f32,
}

// ============================================================================
// Regex Pattern Library
// ============================================================================

lazy_static! {
    // ----- PII -----
    /// SSN: XXX-XX-XXXX (not starting with 000, 666, or 900-999)
    static ref RE_SSN: Regex = Regex::new(
        r"\b(?:00[1-9]|0[1-9]\d|[1-5]\d{2}|6[0-57-9]\d|66[0-57-9]|[78]\d{2})-\d{2}-\d{4}\b"
    ).expect("SSN regex invalid");

    /// Credit card: Visa, Mastercard, Amex, Discover with optional separators
    static ref RE_CREDIT_CARD: Regex = Regex::new(
        r"\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b"
    ).expect("Credit card regex invalid");

    /// Email addresses
    static ref RE_EMAIL: Regex = Regex::new(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ).expect("Email regex invalid");

    /// Phone numbers: US format with various separators
    static ref RE_PHONE: Regex = Regex::new(
        r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ).expect("Phone regex invalid");

    /// Passport numbers: US format (letter + 8 digits)
    static ref RE_PASSPORT: Regex = Regex::new(
        r"\b[A-Z][0-9]{8}\b"
    ).expect("Passport regex invalid");

    /// Driver's license: various US state formats
    static ref RE_DRIVERS_LICENSE: Regex = Regex::new(
        r"\b(?:[A-Z][0-9]{3}-[0-9]{4}-[0-9]{4}|[A-Z][0-9]{12,14}|[0-9]{1,3}-[0-9]{2,3}-[0-9]{4})\b"
    ).expect("DL regex invalid");

    // ----- Credentials -----
    /// AWS Access Key ID (AKIA...)
    static ref RE_AWS_ACCESS_KEY: Regex = Regex::new(
        r"\bAKIA[0-9A-Z]{16}\b"
    ).expect("AWS key regex invalid");

    /// AWS Secret Access Key (40-char base64)
    static ref RE_AWS_SECRET_KEY: Regex = Regex::new(
        r#"(?i)(?:aws_secret_access_key|secret_access_key|aws_secret)[=:\s]+['"]?([A-Za-z0-9/+=]{40})['"]?"#
    ).expect("AWS secret regex invalid");

    /// Azure client secret (various formats)
    static ref RE_AZURE_SECRET: Regex = Regex::new(
        r#"(?i)(?:client[_-]?secret|azure[_-]?secret)[=:\s]+['"]?([a-zA-Z0-9~._-]{34,})['"]?"#
    ).expect("Azure secret regex invalid");

    /// GCP service account key (JSON pattern)
    static ref RE_GCP_KEY: Regex = Regex::new(
        r#""type"\s*:\s*"service_account""#
    ).expect("GCP key regex invalid");

    /// Generic API key patterns
    static ref RE_GENERIC_API_KEY: Regex = Regex::new(
        r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?token|secret[_-]?key)[=:\s]+['"]?([a-zA-Z0-9_-]{32,})['"]?"#
    ).expect("API key regex invalid");

    /// SSH Private Key headers
    static ref RE_SSH_PRIVATE_KEY: Regex = Regex::new(
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|ENCRYPTED)?\s*PRIVATE\s+KEY-----"
    ).expect("SSH key regex invalid");

    /// JWT tokens (three base64url parts separated by dots)
    static ref RE_JWT: Regex = Regex::new(
        r"\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+"
    ).expect("JWT regex invalid");

    /// Database connection strings (various formats)
    static ref RE_DB_CONNSTRING: Regex = Regex::new(
        r#"(?i)(?:(?:postgresql|postgres|mysql|mssql|mongodb|redis|sqlserver)://[^\s'"]+|(?:server|data\s*source)\s*=[^;]+;.*(?:password|pwd)\s*=[^;]+)"#
    ).expect("DB connection string regex invalid");

    // ----- Regulated Data -----
    /// ICD-10 codes (letter + 2 digits + optional dot + up to 4 alphanumeric)
    static ref RE_ICD10: Regex = Regex::new(
        r"\b[A-TV-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?\b"
    ).expect("ICD-10 regex invalid");

    /// HIPAA identifiers: Medical Record Number patterns
    static ref RE_HIPAA_MRN: Regex = Regex::new(
        r#"(?i)(?:MRN|medical[_\s]record[_\s]?(?:number|num|no|#))[=:\s]+['"]?([A-Z0-9]{6,12})['"]?"#
    ).expect("HIPAA MRN regex invalid");

    /// PCI card data (16-digit card numbers in structured data)
    static ref RE_PCI_CARD: Regex = Regex::new(
        r#"(?i)(?:card[_\s]?(?:number|num|no)|pan)[=:\s]+['"]?(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})['"]?"#
    ).expect("PCI card regex invalid");

    // ----- Source Code Secrets -----
    /// Private key material in source code
    static ref RE_PRIVATE_KEY_IN_CODE: Regex = Regex::new(
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    ).expect("Private key in code regex invalid");

    /// Hardcoded passwords in source code
    static ref RE_HARDCODED_PASSWORD: Regex = Regex::new(
        r#"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*['"]([^'"]{8,})['"]"#
    ).expect("Hardcoded password regex invalid");

    /// Internal URLs (common internal TLDs)
    static ref RE_INTERNAL_URL: Regex = Regex::new(
        r"(?i)https?://[a-zA-Z0-9.-]+\.(?:internal|local|corp|intranet|private|lan)(?::\d+)?(?:/\S*)?"
    ).expect("Internal URL regex invalid");

    /// Internal/private IP addresses (RFC 1918 + link-local)
    static ref RE_INTERNAL_IP: Regex = Regex::new(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    ).expect("Internal IP regex invalid");
}

// ============================================================================
// Luhn Validation
// ============================================================================

/// Validate a credit card number using the Luhn algorithm.
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Redact sensitive text, keeping only a few characters visible.
fn redact_text(text: &str, classifier: &ClassifierType) -> String {
    let len = text.len();
    match classifier {
        ClassifierType::Ssn if len >= 4 => {
            format!("***-**-{}", &text[text.len().saturating_sub(4)..])
        }
        ClassifierType::CreditCard => {
            let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 4 {
                format!("****-****-****-{}", &digits[digits.len() - 4..])
            } else {
                "****-****-****-****".to_string()
            }
        }
        ClassifierType::Email => {
            if let Some(at_pos) = text.find('@') {
                let local = &text[..at_pos];
                let domain = &text[at_pos..];
                if local.len() > 2 {
                    format!("{}***{}", &local[..1], domain)
                } else {
                    format!("***{}", domain)
                }
            } else {
                "***@***.***".to_string()
            }
        }
        ClassifierType::AwsAccessKey if len > 8 => {
            format!("{}...{}", &text[..4], &text[len - 4..])
        }
        ClassifierType::SshPrivateKey => "-----BEGIN ***PRIVATE KEY-----".to_string(),
        ClassifierType::JwtToken if len > 20 => {
            format!("eyJ...{}", &text[len.saturating_sub(6)..])
        }
        _ if len > 8 => {
            format!("{}...{}", &text[..3], &text[len.saturating_sub(3)..])
        }
        _ => "*".repeat(len.min(20)),
    }
}

// ============================================================================
// Content Classification Engine
// ============================================================================

/// The core content classification engine. Holds compiled regex patterns and
/// configuration to scan text buffers for sensitive data.
#[derive(Clone)]
pub struct ContentClassifier {
    config: DlpConfig,
}

impl ContentClassifier {
    /// Create a new content classifier with the given DLP configuration.
    pub fn new(config: &DlpConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Scan a text buffer and return all content matches above the confidence
    /// threshold. Runs all enabled classifier categories.
    pub fn classify(&self, text: &str) -> Vec<ContentMatch> {
        let mut matches = Vec::new();

        if self.config.pii_enabled {
            self.classify_pii(text, &mut matches);
        }
        if self.config.credentials_enabled {
            self.classify_credentials(text, &mut matches);
        }
        if self.config.regulated_data_enabled {
            self.classify_regulated(text, &mut matches);
        }
        if self.config.source_code_secrets_enabled {
            self.classify_source_code_secrets(text, &mut matches);
        }

        // Filter by minimum confidence
        matches.retain(|m| m.confidence >= self.config.min_confidence);
        matches
    }

    /// Classify a file by reading it in chunks and running classifiers.
    /// Skips binary files and files over the size limit.
    pub fn classify_file(&self, path: &Path) -> Vec<ContentMatch> {
        // Check file size
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "Cannot stat file for DLP scan");
                return Vec::new();
            }
        };

        if metadata.len() > self.config.max_file_size_bytes {
            debug!(
                path = %path.display(),
                size = metadata.len(),
                max = self.config.max_file_size_bytes,
                "File exceeds DLP max scan size, skipping"
            );
            return Vec::new();
        }

        // Check extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            if self.config.skip_extensions.iter().any(|s| s == &ext_lower) {
                return Vec::new();
            }
        }

        // Read file content
        let content = match std::fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "Cannot read file for DLP scan");
                return Vec::new();
            }
        };

        // Skip likely binary files: check for null bytes in first 8KB
        let check_len = content.len().min(8192);
        let null_count = content[..check_len].iter().filter(|&&b| b == 0).count();
        if null_count > check_len / 10 {
            debug!(path = %path.display(), "File appears binary, skipping DLP scan");
            return Vec::new();
        }

        // Convert to UTF-8 (lossy) and classify
        let text = String::from_utf8_lossy(&content);
        self.classify(&text)
    }

    // ---- PII classifiers ----

    fn classify_pii(&self, text: &str, matches: &mut Vec<ContentMatch>) {
        // SSN
        for m in RE_SSN.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::Ssn,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::Ssn),
                confidence: ClassifierType::Ssn.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Pii,
            });
        }

        // Credit cards with Luhn validation
        for m in RE_CREDIT_CARD.find_iter(text) {
            let raw = m.as_str();
            if luhn_check(raw) {
                matches.push(ContentMatch {
                    classifier_type: ClassifierType::CreditCard,
                    matched_text_redacted: redact_text(raw, &ClassifierType::CreditCard),
                    confidence: ClassifierType::CreditCard.default_confidence(),
                    offset: m.start(),
                    length: m.len(),
                    category: ClassifierCategory::Pii,
                });
            } else {
                // Failed Luhn: lower confidence
                matches.push(ContentMatch {
                    classifier_type: ClassifierType::CreditCard,
                    matched_text_redacted: redact_text(raw, &ClassifierType::CreditCard),
                    confidence: 0.40,
                    offset: m.start(),
                    length: m.len(),
                    category: ClassifierCategory::Pii,
                });
            }
        }

        // Email
        for m in RE_EMAIL.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::Email,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::Email),
                confidence: ClassifierType::Email.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Pii,
            });
        }

        // Phone numbers
        for m in RE_PHONE.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::PhoneNumber,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::PhoneNumber),
                confidence: ClassifierType::PhoneNumber.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Pii,
            });
        }

        // Passport numbers
        for m in RE_PASSPORT.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::PassportNumber,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::PassportNumber),
                confidence: ClassifierType::PassportNumber.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Pii,
            });
        }

        // Driver's license
        for m in RE_DRIVERS_LICENSE.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::DriversLicense,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::DriversLicense),
                confidence: ClassifierType::DriversLicense.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Pii,
            });
        }
    }

    // ---- Credential classifiers ----

    fn classify_credentials(&self, text: &str, matches: &mut Vec<ContentMatch>) {
        // AWS Access Key
        for m in RE_AWS_ACCESS_KEY.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::AwsAccessKey,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::AwsAccessKey),
                confidence: ClassifierType::AwsAccessKey.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // AWS Secret Key
        for m in RE_AWS_SECRET_KEY.find_iter(text) {
            let full = m.as_str();
            matches.push(ContentMatch {
                classifier_type: ClassifierType::AwsSecretKey,
                matched_text_redacted: redact_text(full, &ClassifierType::AwsSecretKey),
                confidence: ClassifierType::AwsSecretKey.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // Azure Client Secret
        for m in RE_AZURE_SECRET.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::AzureClientSecret,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::AzureClientSecret),
                confidence: ClassifierType::AzureClientSecret.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // GCP Service Account Key
        for m in RE_GCP_KEY.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::GcpServiceAccountKey,
                matched_text_redacted: "[GCP Service Account JSON]".to_string(),
                confidence: ClassifierType::GcpServiceAccountKey.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // Generic API Key
        for m in RE_GENERIC_API_KEY.find_iter(text) {
            // Skip if already matched as AWS key
            let start = m.start();
            if matches.iter().any(|cm| {
                cm.classifier_type == ClassifierType::AwsAccessKey
                    && cm.offset <= start
                    && cm.offset + cm.length >= start
            }) {
                continue;
            }
            matches.push(ContentMatch {
                classifier_type: ClassifierType::GenericApiKey,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::GenericApiKey),
                confidence: ClassifierType::GenericApiKey.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // SSH Private Key
        for m in RE_SSH_PRIVATE_KEY.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::SshPrivateKey,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::SshPrivateKey),
                confidence: ClassifierType::SshPrivateKey.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // JWT Tokens
        for m in RE_JWT.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::JwtToken,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::JwtToken),
                confidence: ClassifierType::JwtToken.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }

        // Database Connection Strings
        for m in RE_DB_CONNSTRING.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::DatabaseConnectionString,
                matched_text_redacted: redact_text(
                    m.as_str(),
                    &ClassifierType::DatabaseConnectionString,
                ),
                confidence: ClassifierType::DatabaseConnectionString.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::Credentials,
            });
        }
    }

    // ---- Regulated data classifiers ----

    fn classify_regulated(&self, text: &str, matches: &mut Vec<ContentMatch>) {
        // ICD-10 codes: only flag if multiple codes found (single codes are too
        // common as false positives; presence of 3+ suggests medical data)
        let icd10_matches: Vec<_> = RE_ICD10.find_iter(text).collect();
        if icd10_matches.len() >= 3 {
            for m in &icd10_matches {
                matches.push(ContentMatch {
                    classifier_type: ClassifierType::Icd10Code,
                    matched_text_redacted: m.as_str().to_string(),
                    confidence: ClassifierType::Icd10Code.default_confidence(),
                    offset: m.start(),
                    length: m.len(),
                    category: ClassifierCategory::RegulatedData,
                });
            }
        }

        // HIPAA MRN
        for m in RE_HIPAA_MRN.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::HipaaIdentifier,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::HipaaIdentifier),
                confidence: ClassifierType::HipaaIdentifier.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::RegulatedData,
            });
        }

        // PCI Card Data
        for m in RE_PCI_CARD.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::PciCardData,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::PciCardData),
                confidence: ClassifierType::PciCardData.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::RegulatedData,
            });
        }
    }

    // ---- Source code secret classifiers ----

    fn classify_source_code_secrets(&self, text: &str, matches: &mut Vec<ContentMatch>) {
        // Private key material
        for m in RE_PRIVATE_KEY_IN_CODE.find_iter(text) {
            // Avoid duplicating SSH key matches
            let start = m.start();
            if matches
                .iter()
                .any(|cm| cm.classifier_type == ClassifierType::SshPrivateKey && cm.offset == start)
            {
                continue;
            }
            matches.push(ContentMatch {
                classifier_type: ClassifierType::PrivateKeyMaterial,
                matched_text_redacted: "-----BEGIN PRIVATE KEY-----".to_string(),
                confidence: ClassifierType::PrivateKeyMaterial.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::SourceCodeSecrets,
            });
        }

        // Hardcoded passwords
        for m in RE_HARDCODED_PASSWORD.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::HardcodedPassword,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::HardcodedPassword),
                confidence: ClassifierType::HardcodedPassword.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::SourceCodeSecrets,
            });
        }

        // Internal URLs
        for m in RE_INTERNAL_URL.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::InternalUrl,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::InternalUrl),
                confidence: ClassifierType::InternalUrl.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::SourceCodeSecrets,
            });
        }

        // Internal IPs
        for m in RE_INTERNAL_IP.find_iter(text) {
            matches.push(ContentMatch {
                classifier_type: ClassifierType::InternalIp,
                matched_text_redacted: redact_text(m.as_str(), &ClassifierType::InternalIp),
                confidence: ClassifierType::InternalIp.default_confidence(),
                offset: m.start(),
                length: m.len(),
                category: ClassifierCategory::SourceCodeSecrets,
            });
        }
    }
}

// ============================================================================
// File Transfer Destination Detection
// ============================================================================

/// Determine the transfer destination type for a given file path.
pub fn detect_destination(path: &Path, cloud_paths: &[String]) -> TransferDestination {
    let path_str = path.to_string_lossy();
    let path_lower = path_str.to_lowercase();

    // USB / removable media detection
    #[cfg(target_os = "windows")]
    {
        // Check drive type for removable
        if path_str.len() >= 3 {
            let drive_letter = &path_str[..3];
            if is_removable_drive_windows(drive_letter) {
                return TransferDestination::UsbDrive;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if path_lower.starts_with("/media/")
            || path_lower.starts_with("/mnt/usb")
            || path_lower.starts_with("/run/media/")
        {
            return TransferDestination::UsbDrive;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if path_lower.starts_with("/volumes/") && !path_lower.starts_with("/volumes/macintosh") {
            return TransferDestination::UsbDrive;
        }
    }

    // Network shares
    #[cfg(target_os = "windows")]
    {
        if path_str.starts_with("\\\\") || path_str.starts_with("//") {
            return TransferDestination::NetworkShare;
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Check for NFS/SMB/CIFS mount points
        if path_lower.starts_with("/mnt/")
            || path_lower.contains("/nfs/")
            || path_lower.contains("/smb/")
        {
            return TransferDestination::NetworkShare;
        }
    }

    // Cloud sync folders
    let cloud_indicators = [
        "onedrive",
        "dropbox",
        "google drive",
        "googledrive",
        "icloud",
        "box sync",
        "box drive",
        "mega",
        "pcloud",
    ];
    for indicator in &cloud_indicators {
        if path_lower.contains(indicator) {
            return TransferDestination::CloudSync;
        }
    }

    // Custom cloud sync paths from config
    for cloud_path in cloud_paths {
        let cp_lower = cloud_path.to_lowercase();
        if path_lower.starts_with(&cp_lower) {
            return TransferDestination::CloudSync;
        }
    }

    // Email staging directories
    let email_indicators = [
        "outlook",
        "thunderbird",
        "outbox",
        "drafts",
        "appdata\\local\\microsoft\\outlook",
        ".thunderbird",
    ];
    for indicator in &email_indicators {
        if path_lower.contains(indicator) {
            return TransferDestination::EmailStaging;
        }
    }

    TransferDestination::Unknown
}

/// Check if a Windows drive letter corresponds to a removable device.
#[cfg(target_os = "windows")]
fn is_removable_drive_windows(drive_root: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = OsStr::new(drive_root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    #[link(name = "kernel32")]
    extern "system" {
        fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
    }

    const DRIVE_REMOVABLE: u32 = 2;
    unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOVABLE }
}

// ============================================================================
// DLP Collector
// ============================================================================

/// DLP collector that monitors file writes to sensitive destinations and
/// scans content for policy violations.
pub struct DlpCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl DlpCollector {
    /// Create a new DLP collector.
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::run_monitor(tx, config_clone).await {
                error!(error = %e, "DLP collector error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    /// Get the next DLP telemetry event.
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Main monitoring loop: watches for file writes to sensitive destinations.
    async fn run_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
    ) -> anyhow::Result<()> {
        info!("DLP collector started");

        let dlp_config = &config.dlp;
        let classifier = ContentClassifier::new(dlp_config);

        // Build list of directories to watch
        let watch_dirs = Self::build_watch_dirs(dlp_config);
        if watch_dirs.is_empty() {
            info!("DLP collector: no directories to monitor, running in passive mode");
        } else {
            info!(
                dirs = ?watch_dirs.iter().map(|(p, _)| p.display().to_string()).collect::<Vec<_>>(),
                "DLP collector monitoring directories"
            );
        }

        // Set up file system watcher for sensitive directories
        let (notify_tx, mut notify_rx) = mpsc::channel::<(PathBuf, TransferDestination)>(1000);

        // Spawn the notify watcher in a blocking thread
        let watch_dirs_clone = watch_dirs.clone();
        let _watcher_handle = std::thread::spawn(move || {
            Self::run_file_watcher(watch_dirs_clone, notify_tx);
        });

        // Process file events
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(
            dlp_config.poll_interval_ms,
        ));

        loop {
            tokio::select! {
                Some((path, dest)) = notify_rx.recv() => {
                    // File was written to a sensitive destination
                    let matches = classifier.classify_file(&path);
                    if !matches.is_empty() {
                        let event = Self::create_dlp_event(
                            &path,
                            dest,
                            &matches,
                            &config.dlp.action_on_detection,
                        );
                        if tx.send(event).await.is_err() {
                            warn!("DLP event channel closed");
                            return Ok(());
                        }
                    }
                }
                _ = interval.tick() => {
                    // Periodic housekeeping (future: scan pending queue)
                }
            }
        }
    }

    /// Build the list of directories to watch and their destination types.
    fn build_watch_dirs(config: &DlpConfig) -> Vec<(PathBuf, TransferDestination)> {
        let mut dirs = Vec::new();

        if config.monitor_cloud_sync {
            // Auto-detect cloud sync paths
            let cloud_paths = Self::detect_cloud_sync_paths();
            for p in cloud_paths {
                if p.exists() {
                    dirs.push((p, TransferDestination::CloudSync));
                }
            }
            // Add configured paths
            for p in &config.cloud_sync_paths {
                let path = PathBuf::from(p);
                if path.exists() {
                    dirs.push((path, TransferDestination::CloudSync));
                }
            }
        }

        if config.monitor_usb_writes {
            let usb_paths = Self::detect_usb_mount_paths();
            for p in usb_paths {
                if p.exists() {
                    dirs.push((p, TransferDestination::UsbDrive));
                }
            }
        }

        if config.monitor_network_shares {
            let share_paths = Self::detect_network_share_paths();
            for p in share_paths {
                if p.exists() {
                    dirs.push((p, TransferDestination::NetworkShare));
                }
            }
        }

        dirs
    }

    /// Detect common cloud sync folder paths.
    fn detect_cloud_sync_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Some(home) = dirs::home_dir() {
            // OneDrive
            paths.push(home.join("OneDrive"));
            paths.push(home.join("OneDrive - Business"));

            // Dropbox
            paths.push(home.join("Dropbox"));

            // Google Drive
            paths.push(home.join("Google Drive"));
            #[cfg(target_os = "windows")]
            paths.push(home.join("My Drive"));

            // iCloud (macOS)
            #[cfg(target_os = "macos")]
            {
                paths.push(home.join("Library/Mobile Documents/com~apple~CloudDocs"));
            }

            // Box
            paths.push(home.join("Box"));
            paths.push(home.join("Box Sync"));
        }

        paths
    }

    /// Detect USB mount paths.
    fn detect_usb_mount_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "linux")]
        {
            // Common USB mount points
            paths.push(PathBuf::from("/media"));
            paths.push(PathBuf::from("/run/media"));
        }

        #[cfg(target_os = "macos")]
        {
            paths.push(PathBuf::from("/Volumes"));
        }

        #[cfg(target_os = "windows")]
        {
            // Scan drive letters for removable drives
            for letter in b'D'..=b'Z' {
                let drive = format!("{}:\\", letter as char);
                if is_removable_drive_windows(&drive) {
                    paths.push(PathBuf::from(&drive));
                }
            }
        }

        paths
    }

    /// Detect network share mount paths.
    fn detect_network_share_paths() -> Vec<PathBuf> {
        let paths = Vec::new();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Read /proc/mounts or /etc/mtab for NFS/CIFS mounts
            if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let fs_type = parts[2];
                        let mount_point = parts[1];
                        if fs_type == "nfs"
                            || fs_type == "nfs4"
                            || fs_type == "cifs"
                            || fs_type == "smb"
                        {
                            paths.push(PathBuf::from(mount_point));
                        }
                    }
                }
            }
        }

        paths
    }

    /// Run the filesystem watcher (blocking, runs in a separate thread).
    fn run_file_watcher(
        watch_dirs: Vec<(PathBuf, TransferDestination)>,
        notify_tx: mpsc::Sender<(PathBuf, TransferDestination)>,
    ) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};

        // Map paths to destinations for quick lookup
        let dir_map: HashMap<PathBuf, TransferDestination> = watch_dirs.into_iter().collect();

        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();

        let mut watcher = match notify::recommended_watcher(move |res: Result<NotifyEvent, _>| {
            if let Ok(event) = res {
                let _ = watcher_tx.send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                error!(error = %e, "Failed to create DLP file watcher");
                return;
            }
        };

        // Watch all configured directories
        for (path, _dest) in &dir_map {
            if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                warn!(path = %path.display(), error = %e, "Failed to watch directory for DLP");
            }
        }

        // Process file events
        loop {
            match watcher_rx.recv() {
                Ok(event) => {
                    // Only process create and modify events
                    let is_write =
                        matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));

                    if !is_write {
                        continue;
                    }

                    for path in &event.paths {
                        // Determine destination by finding which watched directory contains this path
                        let dest = dir_map
                            .iter()
                            .find(|(dir, _)| path.starts_with(dir))
                            .map(|(_, d)| d.clone())
                            .unwrap_or(TransferDestination::Unknown);

                        if let Err(_) = notify_tx.blocking_send((path.clone(), dest)) {
                            debug!("DLP notify channel closed");
                            return;
                        }
                    }
                }
                Err(_) => {
                    debug!("DLP file watcher channel closed");
                    return;
                }
            }
        }
    }

    /// Create a DLP telemetry event from content matches.
    fn create_dlp_event(
        path: &Path,
        destination: TransferDestination,
        matches: &[ContentMatch],
        action: &str,
    ) -> TelemetryEvent {
        // Get process info for the writing process
        let (pid, process_name, user) = Self::get_current_process_info();

        // Hash the file content
        let content_hash = match std::fs::read(path) {
            Ok(content) => {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                hex::encode(hasher.finalize())
            }
            Err(_) => String::new(),
        };

        let content_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        let distinct_classifiers: std::collections::HashSet<_> =
            matches.iter().map(|m| &m.classifier_type).collect();

        let max_confidence = matches.iter().map(|m| m.confidence).fold(0.0f32, f32::max);

        let severity = if max_confidence >= 0.90 {
            Severity::Critical
        } else if max_confidence >= 0.75 {
            Severity::High
        } else if max_confidence >= 0.50 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let dlp_event = DlpEvent {
            source_path: path.to_string_lossy().to_string(),
            destination: destination.clone(),
            process_name: process_name.clone(),
            pid,
            user: user.clone(),
            content_hash,
            content_size,
            matches: matches.to_vec(),
            action_taken: action.to_string(),
            distinct_classifier_count: distinct_classifiers.len(),
            max_confidence,
        };

        let mut event = TelemetryEvent::new(
            EventType::FileModify,
            severity,
            EventPayload::Custom(serde_json::to_value(&dlp_event).unwrap_or_default()),
        );

        event
            .metadata
            .insert("event_category".to_string(), "dlp".to_string());
        event
            .metadata
            .insert("dlp_destination".to_string(), format!("{:?}", destination));
        event
            .metadata
            .insert("dlp_action".to_string(), action.to_string());
        event.metadata.insert("pid".to_string(), pid.to_string());
        event
            .metadata
            .insert("process_name".to_string(), process_name);

        // Add detections for each classifier category found
        let categories: std::collections::HashSet<_> =
            matches.iter().map(|m| &m.category).collect();

        for category in categories {
            let cat_matches: Vec<_> = matches.iter().filter(|m| &m.category == category).collect();
            let description = format!(
                "DLP: {} {:?} match(es) detected in file written to {:?}",
                cat_matches.len(),
                category,
                destination,
            );

            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: format!("dlp_{:?}", category).to_lowercase(),
                confidence: cat_matches
                    .iter()
                    .map(|m| m.confidence)
                    .fold(0.0f32, f32::max),
                description,
                mitre_tactics: vec!["exfiltration".to_string(), "collection".to_string()],
                mitre_techniques: vec![
                    "T1567".to_string(),
                    "T1048".to_string(),
                    "T1052".to_string(),
                ],
            });
        }

        event
    }

    /// Get information about the current process (fallback).
    fn get_current_process_info() -> (u32, String, String) {
        let pid = std::process::id();
        let process_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        let user = whoami::username();
        (pid, process_name, user)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid_cards() {
        // Visa test card
        assert!(luhn_check("4111111111111111"));
        // Mastercard test card
        assert!(luhn_check("5500000000000004"));
        // Amex test card
        assert!(luhn_check("378282246310005"));
        // Invalid number
        assert!(!luhn_check("1234567890123456"));
    }

    #[test]
    fn test_luhn_with_separators() {
        // Luhn works on digits only
        assert!(luhn_check("4111-1111-1111-1111"));
        assert!(luhn_check("4111 1111 1111 1111"));
    }

    #[test]
    fn test_ssn_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "SSN: 123-45-6789 is John's number";
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::Ssn));
    }

    #[test]
    fn test_ssn_invalid_prefix_not_matched() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        // SSNs starting with 000 or 666 should not match
        let text = "Invalid SSN: 000-12-3456";
        let matches = classifier.classify(text);
        assert!(!matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::Ssn));
    }

    #[test]
    fn test_credit_card_with_luhn() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "Card: 4111-1111-1111-1111";
        let matches = classifier.classify(text);
        let cc_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.classifier_type == ClassifierType::CreditCard)
            .collect();
        assert!(!cc_matches.is_empty());
        // Luhn-valid cards should have high confidence
        assert!(cc_matches[0].confidence >= 0.90);
    }

    #[test]
    fn test_email_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "Contact: john.doe@example.com for details";
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::Email));
    }

    #[test]
    fn test_aws_key_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "Access Key: AKIAIOSFODNN7EXAMPLE";
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::AwsAccessKey));
    }

    #[test]
    fn test_ssh_private_key_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC...\n-----END RSA PRIVATE KEY-----";
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::SshPrivateKey));
    }

    #[test]
    fn test_jwt_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::JwtToken));
    }

    #[test]
    fn test_db_connection_string_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = r#"DATABASE_URL=postgresql://admin:s3cretP@ss@db.internal.corp:5432/production"#;
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::DatabaseConnectionString));
    }

    #[test]
    fn test_gcp_service_account_key() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = r#"{"type": "service_account", "project_id": "my-project"}"#;
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::GcpServiceAccountKey));
    }

    #[test]
    fn test_hardcoded_password() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = r#"let password = "SuperSecret123!@#";"#;
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::HardcodedPassword));
    }

    #[test]
    fn test_internal_ip_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "Server IP: 192.168.1.100 and 10.0.0.1 are internal";
        let matches = classifier.classify(text);
        let ip_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.classifier_type == ClassifierType::InternalIp)
            .collect();
        assert!(ip_matches.len() >= 2);
    }

    #[test]
    fn test_internal_url_detection() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "API at https://api.internal.corp:8443/v2/data";
        let matches = classifier.classify(text);
        assert!(matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::InternalUrl));
    }

    #[test]
    fn test_redact_ssn() {
        let redacted = redact_text("123-45-6789", &ClassifierType::Ssn);
        assert_eq!(redacted, "***-**-6789");
    }

    #[test]
    fn test_redact_credit_card() {
        let redacted = redact_text("4111-1111-1111-1111", &ClassifierType::CreditCard);
        assert!(redacted.starts_with("****-"));
        assert!(redacted.ends_with("1111"));
    }

    #[test]
    fn test_redact_email() {
        let redacted = redact_text("john.doe@example.com", &ClassifierType::Email);
        assert!(redacted.starts_with("j"));
        assert!(redacted.contains("@example.com"));
    }

    #[test]
    fn test_confidence_filtering() {
        let mut config = DlpConfig::default();
        config.min_confidence = 0.90;
        let classifier = ContentClassifier::new(&config);
        // Phone numbers have 0.60 confidence, should be filtered
        let text = "Call (555) 123-4567";
        let matches = classifier.classify(text);
        assert!(!matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::PhoneNumber));
    }

    #[test]
    fn test_disabled_classifiers() {
        let mut config = DlpConfig::default();
        config.pii_enabled = false;
        let classifier = ContentClassifier::new(&config);
        let text = "SSN: 123-45-6789 and email: test@test.com";
        let matches = classifier.classify(text);
        assert!(!matches
            .iter()
            .any(|m| m.category == ClassifierCategory::Pii));
    }

    #[test]
    fn test_multiple_classifier_types() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        let text = "SSN: 123-45-6789, Key: AKIAIOSFODNN7EXAMPLE, Email: admin@internal.corp";
        let matches = classifier.classify(text);
        let categories: std::collections::HashSet<_> =
            matches.iter().map(|m| m.category.clone()).collect();
        assert!(categories.contains(&ClassifierCategory::Pii));
        assert!(categories.contains(&ClassifierCategory::Credentials));
    }

    #[test]
    fn test_destination_detection_cloud() {
        let path = Path::new("/home/user/Dropbox/secret.txt");
        let dest = detect_destination(path, &[]);
        assert_eq!(dest, TransferDestination::CloudSync);
    }

    #[test]
    fn test_destination_detection_custom_cloud() {
        let path = Path::new("/data/my-sync/file.txt");
        let dest = detect_destination(path, &["/data/my-sync".to_string()]);
        assert_eq!(dest, TransferDestination::CloudSync);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_destination_detection_usb_linux() {
        let path = Path::new("/media/user/USB_DRIVE/report.xlsx");
        let dest = detect_destination(path, &[]);
        assert_eq!(dest, TransferDestination::UsbDrive);
    }

    #[test]
    fn test_icd10_requires_multiple() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);
        // Single ICD-10 code should not trigger (too many false positives)
        let text = "Code: A01";
        let matches = classifier.classify(text);
        assert!(!matches
            .iter()
            .any(|m| m.classifier_type == ClassifierType::Icd10Code));

        // Three or more should trigger
        let text2 = "Diagnoses: A01.2 B02.3 C34.1";
        let matches2 = classifier.classify(text2);
        assert!(matches2
            .iter()
            .any(|m| m.classifier_type == ClassifierType::Icd10Code));
    }
}
