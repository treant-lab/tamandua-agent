//! Sample submission for ML analysis
//!
//! Determines which files should be sent to the server for ML scanning
//! and handles the upload with rate limiting.

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Rate limit: max samples per minute
const MAX_SAMPLES_PER_MINUTE: usize = 10;
/// Max file size to upload (10MB)
const MAX_SAMPLE_SIZE: u64 = 10 * 1024 * 1024;
/// Maximum recent hashes to track (to avoid memory bloat)
const MAX_TRACKED_HASHES: usize = 10000;

/// File extensions that should be scanned by ML
pub const SCANNABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "bat", "cmd", "ps1", "vbs", "js", "msi", "jar", "py", "elf",
    "so", "dylib", "app", "bin",
];

/// Paths to skip (system files, known good)
pub const SKIP_PATHS: &[&str] = &[
    // Windows
    "\\Windows\\WinSxS\\",
    "\\Windows\\System32\\DriverStore\\",
    "\\Windows\\assembly\\",
    "\\Windows\\Microsoft.NET\\",
    // Linux
    "/usr/lib/",
    "/usr/share/",
    "/lib/modules/",
    "/lib/firmware/",
    // macOS
    "/System/Library/",
    "/Library/Apple/",
];

/// Type of PII detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiType {
    Email,
    Ssn,
    CreditCard,
    ApiKey,
    PrivateIpv4,
    WindowsUserPath,
    AwsKey,
    PrivateKey,
}

impl PiiType {
    /// Get the redaction string for this PII type
    fn redaction_string(&self) -> &'static str {
        match self {
            PiiType::Email => "[REDACTED-EMAIL]",
            PiiType::Ssn => "[REDACTED-SSN]",
            PiiType::CreditCard => "[REDACTED-CARD]",
            PiiType::ApiKey => "[REDACTED-KEY]",
            PiiType::PrivateIpv4 => "[REDACTED-IP]",
            PiiType::WindowsUserPath => "C:\\Users\\[REDACTED]",
            PiiType::AwsKey => "[REDACTED-AWS-KEY]",
            PiiType::PrivateKey => "[REDACTED-PRIVATE-KEY]",
        }
    }

    /// Get the name of this PII type for logging
    fn name(&self) -> &'static str {
        match self {
            PiiType::Email => "email",
            PiiType::Ssn => "ssn",
            PiiType::CreditCard => "credit_card",
            PiiType::ApiKey => "api_key",
            PiiType::PrivateIpv4 => "private_ipv4",
            PiiType::WindowsUserPath => "windows_user_path",
            PiiType::AwsKey => "aws_key",
            PiiType::PrivateKey => "private_key",
        }
    }
}

/// Information about a detected PII match
#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub pii_type: PiiType,
    pub offset: usize,
    pub length: usize,
}

/// PII scrubber for sanitizing sample data before ML submission
pub struct PiiScrubber {
    email_regex: Regex,
    ssn_regex: Regex,
    credit_card_regex: Regex,
    api_key_regex: Regex,
    private_ipv4_regex: Regex,
    windows_user_path_regex: Regex,
    aws_key_regex: Regex,
    private_key_regex: Regex,
}

impl PiiScrubber {
    /// Create a new PII scrubber with compiled regex patterns
    pub fn new() -> Self {
        Self {
            // Email addresses
            email_regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),

            // Social Security Numbers (XXX-XX-XXXX)
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),

            // Credit card numbers (with optional spaces/hyphens)
            credit_card_regex: Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(),

            // API keys/tokens (case-insensitive)
            api_key_regex: Regex::new(
                r#"(?i)(api[_-]?key|token|secret)[=:\s]['"]?[a-zA-Z0-9_-]{16,}['"]?"#,
            )
            .unwrap(),

            // Private IPv4 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
            private_ipv4_regex: Regex::new(
                r"\b(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
            )
            .unwrap(),

            // Windows user paths
            windows_user_path_regex: Regex::new(r"(?i)C:\\Users\\[^\\]+").unwrap(),

            // AWS access keys
            aws_key_regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),

            // Private keys
            private_key_regex: Regex::new(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----").unwrap(),
        }
    }

    /// Scan data for PII and return all matches found
    pub fn check_for_pii(&self, data: &[u8]) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        // Convert to string for regex matching (lossy conversion for binary data)
        let text = String::from_utf8_lossy(data);

        // Check each pattern type
        for mat in self.email_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Email,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.ssn_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Ssn,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.credit_card_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::CreditCard,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.api_key_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::ApiKey,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.private_ipv4_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::PrivateIpv4,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.windows_user_path_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::WindowsUserPath,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.aws_key_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::AwsKey,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        for mat in self.private_key_regex.find_iter(&text) {
            matches.push(PiiMatch {
                pii_type: PiiType::PrivateKey,
                offset: mat.start(),
                length: mat.len(),
            });
        }

        matches
    }

    /// Scan data for PII and redact all matches
    pub fn scan_and_redact(&self, data: &[u8]) -> Result<Vec<u8>> {
        // For binary data that contains strings, we need to be careful
        // We'll convert to string (lossy), apply redactions, then convert back
        let text = String::from_utf8_lossy(data);
        let mut redacted = text.to_string();

        // Apply redactions in reverse order of offset to preserve positions
        // We need to collect all replacements first, then apply them
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();

        // Collect all matches
        for mat in self.email_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::Email.redaction_string().to_string(),
            ));
        }

        for mat in self.ssn_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::Ssn.redaction_string().to_string(),
            ));
        }

        for mat in self.credit_card_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::CreditCard.redaction_string().to_string(),
            ));
        }

        for mat in self.api_key_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::ApiKey.redaction_string().to_string(),
            ));
        }

        for mat in self.private_ipv4_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::PrivateIpv4.redaction_string().to_string(),
            ));
        }

        for mat in self.windows_user_path_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::WindowsUserPath.redaction_string().to_string(),
            ));
        }

        for mat in self.aws_key_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::AwsKey.redaction_string().to_string(),
            ));
        }

        for mat in self.private_key_regex.find_iter(&text) {
            replacements.push((
                mat.start(),
                mat.end(),
                PiiType::PrivateKey.redaction_string().to_string(),
            ));
        }

        // Sort by offset in descending order to apply from end to start
        replacements.sort_by(|a, b| b.0.cmp(&a.0));

        // Apply replacements
        for (start, end, replacement) in replacements {
            redacted.replace_range(start..end, &replacement);
        }

        // Convert back to bytes
        Ok(redacted.into_bytes())
    }
}

impl Default for PiiScrubber {
    fn default() -> Self {
        Self::new()
    }
}

/// Sample submitter for ML analysis
pub struct SampleSubmitter {
    /// Recently submitted hashes (avoid duplicates)
    submitted_hashes: Mutex<HashSet<String>>,
    /// Submission timestamps for rate limiting
    submission_times: Mutex<Vec<Instant>>,
}

impl SampleSubmitter {
    /// Create a new sample submitter
    pub fn new() -> Self {
        Self {
            submitted_hashes: Mutex::new(HashSet::new()),
            submission_times: Mutex::new(Vec::new()),
        }
    }

    /// Check if file should be submitted for ML scan
    pub fn should_submit(&self, path: &Path, sha256: &str, file_size: u64) -> bool {
        // Check file size
        if file_size > MAX_SAMPLE_SIZE {
            debug!(
                path = %path.display(),
                size = file_size,
                max = MAX_SAMPLE_SIZE,
                "File too large for ML submission"
            );
            return false;
        }

        if file_size == 0 {
            return false;
        }

        // Check extension
        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if !SCANNABLE_EXTENSIONS.contains(&extension.as_str()) {
            debug!(
                path = %path.display(),
                extension = %extension,
                "Extension not scannable by ML"
            );
            return false;
        }

        // Check skip paths
        let path_str = path.to_string_lossy();
        for skip in SKIP_PATHS {
            if path_str.contains(skip) {
                debug!(
                    path = %path.display(),
                    skip_pattern = %skip,
                    "Path in skip list"
                );
                return false;
            }
        }

        // Check if already submitted
        {
            let submitted = match self.submitted_hashes.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("Submitted hashes lock poisoned during check, recovering");
                    poisoned.into_inner()
                }
            };
            if submitted.contains(sha256) {
                debug!(
                    sha256 = %sha256,
                    "Sample already submitted"
                );
                return false;
            }
        }

        // Check rate limit
        if !self.check_rate_limit() {
            debug!("Rate limit exceeded for sample submission");
            return false;
        }

        true
    }

    /// Prepare sample for submission
    pub fn prepare_sample(&self, path: &Path) -> Result<SamplePayload> {
        // Read file content
        let content = std::fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        // Compute hashes (before PII scrubbing)
        let sha256 = hex::encode(Sha256::digest(&content));
        let sha1 = hex::encode(Sha1::digest(&content));
        let md5 = hex::encode(md5::compute(&content).0);

        // Get file metadata
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get metadata: {}", path.display()))?;
        let file_size = metadata.len();

        // Get timestamps
        let created_at = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        // Detect file type
        let file_type = Self::detect_file_type(&content, path);

        // Calculate entropy
        let entropy = crate::analyzers::calculate_entropy(&content) as f64;

        // Check signature (platform-specific)
        let (is_signed, signer) = Self::check_signature(path);

        // PII detection and scrubbing
        let scrubber = PiiScrubber::new();
        let pii_matches = scrubber.check_for_pii(&content);
        let pii_count = pii_matches.len();
        let pii_scrubbed = pii_count > 0;

        // Log PII findings
        if pii_scrubbed {
            // Count by type for detailed logging
            let mut pii_by_type: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for m in &pii_matches {
                *pii_by_type.entry(m.pii_type.name()).or_insert(0) += 1;
            }

            warn!(
                path = %path.display(),
                sha256 = %sha256,
                pii_count = pii_count,
                pii_types = ?pii_by_type,
                "PII detected in sample, will redact before submission"
            );
        }

        // Redact PII from content before compression
        let final_content = if pii_scrubbed {
            scrubber
                .scan_and_redact(&content)
                .context("Failed to redact PII from sample")?
        } else {
            content.clone()
        };

        // Gzip compress the scrubbed content
        let compressed = Self::compress_content(&final_content)?;

        info!(
            path = %path.display(),
            sha256 = %sha256,
            file_type = %file_type,
            original_size = content.len(),
            compressed_size = compressed.len(),
            entropy = entropy,
            pii_scrubbed = pii_scrubbed,
            pii_count = pii_count,
            "Sample prepared for submission"
        );

        Ok(SamplePayload {
            sha256,
            sha1,
            md5,
            file_size,
            file_type,
            content: compressed,
            metadata: SampleMetadata {
                path: path.to_string_lossy().to_string(),
                created_at,
                modified_at,
                is_signed,
                signer,
                entropy,
                pii_scrubbed,
                pii_count,
            },
        })
    }

    /// Mark sample as submitted
    pub fn mark_submitted(&self, sha256: &str) {
        let mut submitted = match self.submitted_hashes.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Submitted hashes lock poisoned during mark_submitted, recovering");
                poisoned.into_inner()
            }
        };

        // Trim if too large (LRU-style: just clear half)
        if submitted.len() >= MAX_TRACKED_HASHES {
            let to_remove: Vec<_> = submitted
                .iter()
                .take(MAX_TRACKED_HASHES / 2)
                .cloned()
                .collect();
            for hash in to_remove {
                submitted.remove(&hash);
            }
        }

        submitted.insert(sha256.to_string());

        // Record submission time for rate limiting
        let mut times = match self.submission_times.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Submission times lock poisoned during mark_submitted, recovering");
                poisoned.into_inner()
            }
        };
        times.push(Instant::now());
    }

    /// Check rate limit
    fn check_rate_limit(&self) -> bool {
        let mut times = match self.submission_times.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Submission times lock poisoned during rate limit check, recovering");
                poisoned.into_inner()
            }
        };

        // Remove old entries (older than 1 minute)
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        times.retain(|t| *t > cutoff);

        // Check if under limit
        times.len() < MAX_SAMPLES_PER_MINUTE
    }

    /// Compress content with gzip
    fn compress_content(data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(data)
            .context("Failed to write to gzip encoder")?;
        encoder.finish().context("Failed to finish gzip encoding")
    }

    /// Detect file type from magic bytes and extension
    fn detect_file_type(content: &[u8], path: &Path) -> String {
        // Check magic bytes first
        if content.len() >= 4 {
            // PE (Windows executable)
            if content[0] == 0x4D && content[1] == 0x5A {
                // MZ header
                return "pe".to_string();
            }

            // ELF (Linux executable)
            if content[0] == 0x7F && content[1] == 0x45 && content[2] == 0x4C && content[3] == 0x46
            {
                return "elf".to_string();
            }

            // Mach-O (macOS executable)
            // 32-bit: 0xFEEDFACE, 64-bit: 0xFEEDFACF
            // Fat/Universal: 0xCAFEBABE
            if (content[0] == 0xFE && content[1] == 0xED && content[2] == 0xFA)
                || (content[0] == 0xCA
                    && content[1] == 0xFE
                    && content[2] == 0xBA
                    && content[3] == 0xBE)
                || (content[0] == 0xCF
                    && content[1] == 0xFA
                    && content[2] == 0xED
                    && content[3] == 0xFE)
            {
                return "macho".to_string();
            }

            // Java JAR (ZIP with specific content)
            if content[0] == 0x50 && content[1] == 0x4B {
                // PK (ZIP)
                // Could be JAR, check extension
                let ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if ext == "jar" {
                    return "jar".to_string();
                }
                return "archive".to_string();
            }

            // MSI (Windows Installer)
            if content[0] == 0xD0 && content[1] == 0xCF && content[2] == 0x11 && content[3] == 0xE0
            {
                return "msi".to_string();
            }
        }

        // Fall back to extension
        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        match extension.as_str() {
            "exe" | "dll" | "sys" | "scr" | "com" => "pe".to_string(),
            "so" | "elf" => "elf".to_string(),
            "dylib" | "app" => "macho".to_string(),
            "bat" | "cmd" | "ps1" | "vbs" | "js" | "py" => "script".to_string(),
            "jar" => "jar".to_string(),
            "msi" => "msi".to_string(),
            _ => "unknown".to_string(),
        }
    }

    /// Check if file is signed
    #[cfg(target_os = "windows")]
    fn check_signature(path: &Path) -> (bool, Option<String>) {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
            WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };

        let path_wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut file_info = WINTRUST_FILE_INFO::default();
            file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
            file_info.pcwszFilePath = PCWSTR(path_wide.as_ptr());

            let mut trust_data = WINTRUST_DATA::default();
            trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
            trust_data.dwUIChoice = WTD_UI_NONE;
            trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
            trust_data.dwUnionChoice = WTD_CHOICE_FILE;
            trust_data.Anonymous.pFile = &mut file_info as *mut _;
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

            // Use HWND_INVALID (0) for silent verification
            let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let result = WinVerifyTrust(
                HWND::default(),
                &mut action_id as *mut _,
                &mut trust_data as *mut _ as *mut _,
            );

            if result == 0 {
                // Signed - try to get signer info
                // Note: Full signer extraction requires more complex code
                (true, None)
            } else {
                (false, None)
            }
        }
    }

    /// Check if file is signed (Linux - check for ELF signature section)
    #[cfg(target_os = "linux")]
    fn check_signature(path: &Path) -> (bool, Option<String>) {
        // On Linux, we could check for:
        // 1. GPG signatures
        // 2. ELF .note.GNU-stack or other signature sections
        // For now, return false as Linux doesn't have universal code signing
        let _ = path;
        (false, None)
    }

    /// Check if file is signed (macOS - use codesign)
    #[cfg(target_os = "macos")]
    fn check_signature(path: &Path) -> (bool, Option<String>) {
        use std::process::Command;

        let output = Command::new("codesign")
            .args(["-v", "--verbose=2"])
            .arg(path)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    // Parse stderr for signer info
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    let signer = stderr
                        .lines()
                        .find(|l| l.contains("Authority="))
                        .map(|l| l.replace("Authority=", "").trim().to_string());
                    (true, signer)
                } else {
                    (false, None)
                }
            }
            Err(_) => (false, None),
        }
    }

    /// Check if file is signed (fallback for other platforms)
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    fn check_signature(path: &Path) -> (bool, Option<String>) {
        let _ = path;
        (false, None)
    }

    /// Get count of submitted samples
    pub fn get_submitted_count(&self) -> usize {
        match self.submitted_hashes.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => {
                warn!("Submitted hashes lock poisoned during count, recovering");
                poisoned.into_inner().len()
            }
        }
    }

    /// Clear submitted hashes (useful for testing)
    pub fn clear_submitted(&self) {
        match self.submitted_hashes.lock() {
            Ok(mut guard) => guard.clear(),
            Err(poisoned) => {
                warn!("Submitted hashes lock poisoned during clear, recovering");
                poisoned.into_inner().clear()
            }
        }
        match self.submission_times.lock() {
            Ok(mut guard) => guard.clear(),
            Err(poisoned) => {
                warn!("Submission times lock poisoned during clear, recovering");
                poisoned.into_inner().clear()
            }
        }
    }
}

impl Default for SampleSubmitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Payload for sample submission
#[derive(Debug, Clone)]
pub struct SamplePayload {
    /// SHA256 hash of the file (hex encoded)
    pub sha256: String,
    /// SHA1 hash of the file (hex encoded)
    pub sha1: String,
    /// MD5 hash of the file (hex encoded)
    pub md5: String,
    /// File size in bytes
    pub file_size: u64,
    /// Detected file type (pe, elf, macho, script, unknown)
    pub file_type: String,
    /// Gzip-compressed file content
    pub content: Vec<u8>,
    /// Additional metadata
    pub metadata: SampleMetadata,
}

impl SamplePayload {
    /// Get base64-encoded compressed content for transmission
    pub fn content_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.content)
    }
}

/// Metadata about the sample
#[derive(Debug, Clone)]
pub struct SampleMetadata {
    /// Original file path
    pub path: String,
    /// File creation timestamp (Unix epoch seconds)
    pub created_at: Option<u64>,
    /// File modification timestamp (Unix epoch seconds)
    pub modified_at: Option<u64>,
    /// Whether the file is signed
    pub is_signed: bool,
    /// Signer name if signed
    pub signer: Option<String>,
    /// Shannon entropy of file content
    pub entropy: f64,
    /// Whether PII was scrubbed from the sample
    pub pii_scrubbed: bool,
    /// Count of PII items found and redacted
    pub pii_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_should_submit_checks_extension() {
        let submitter = SampleSubmitter::new();

        // Create a temp file with .exe extension
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"MZ test content").unwrap();
        let path = file.path().with_extension("exe");
        std::fs::rename(file.path(), &path).unwrap();

        // Should submit .exe files
        assert!(submitter.should_submit(&path, "abc123", 1000));

        // Clean up
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_should_submit_checks_size() {
        let submitter = SampleSubmitter::new();
        let path = Path::new("/test/file.exe");

        // File too large
        assert!(!submitter.should_submit(path, "abc123", MAX_SAMPLE_SIZE + 1));

        // Empty file
        assert!(!submitter.should_submit(path, "abc123", 0));
    }

    #[test]
    fn test_should_submit_checks_duplicates() {
        let submitter = SampleSubmitter::new();
        let path = Path::new("/test/file.exe");
        let hash = "deadbeef1234";

        // First submission should be allowed
        assert!(submitter.should_submit(path, hash, 1000));

        // Mark as submitted
        submitter.mark_submitted(hash);

        // Second submission should be rejected
        assert!(!submitter.should_submit(path, hash, 1000));
    }

    #[test]
    fn test_rate_limiting() {
        let submitter = SampleSubmitter::new();
        let path = Path::new("/test/file.exe");

        // Submit up to the limit
        for i in 0..MAX_SAMPLES_PER_MINUTE {
            let hash = format!("hash{}", i);
            assert!(submitter.should_submit(path, &hash, 1000));
            submitter.mark_submitted(&hash);
        }

        // Next submission should be rate limited
        assert!(!submitter.should_submit(path, "hash_new", 1000));
    }

    #[test]
    fn test_detect_file_type() {
        // PE file
        let pe_content = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header
        assert_eq!(
            SampleSubmitter::detect_file_type(&pe_content, Path::new("test.exe")),
            "pe"
        );

        // ELF file
        let elf_content = vec![0x7F, 0x45, 0x4C, 0x46]; // ELF magic
        assert_eq!(
            SampleSubmitter::detect_file_type(&elf_content, Path::new("test")),
            "elf"
        );

        // Script by extension
        let script_content = b"#!/bin/bash\necho hello";
        assert_eq!(
            SampleSubmitter::detect_file_type(script_content, Path::new("test.ps1")),
            "script"
        );
    }

    #[test]
    fn test_pii_scrubber_detects_email() {
        let scrubber = PiiScrubber::new();
        let data = b"Contact: john.doe@example.com for support";
        let matches = scrubber.check_for_pii(data);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Email);
    }

    #[test]
    fn test_pii_scrubber_detects_ssn() {
        let scrubber = PiiScrubber::new();
        let data = b"SSN: 123-45-6789";
        let matches = scrubber.check_for_pii(data);

        assert!(matches.iter().any(|m| m.pii_type == PiiType::Ssn));
    }

    #[test]
    fn test_pii_scrubber_detects_credit_card() {
        let scrubber = PiiScrubber::new();
        let data = b"Card: 4532-1234-5678-9010";
        let matches = scrubber.check_for_pii(data);

        assert!(matches.iter().any(|m| m.pii_type == PiiType::CreditCard));
    }

    #[test]
    fn test_pii_scrubber_detects_api_key() {
        let scrubber = PiiScrubber::new();
        let data = b"api_key=abcdef1234567890abcdef1234567890";
        let matches = scrubber.check_for_pii(data);

        assert!(matches.iter().any(|m| m.pii_type == PiiType::ApiKey));
    }

    #[test]
    fn test_pii_scrubber_detects_private_ip() {
        let scrubber = PiiScrubber::new();
        let data = b"Server: 192.168.1.100";
        let matches = scrubber.check_for_pii(data);

        assert!(matches.iter().any(|m| m.pii_type == PiiType::PrivateIpv4));
    }

    #[test]
    fn test_pii_scrubber_detects_windows_user_path() {
        let scrubber = PiiScrubber::new();
        let data = b"Path: C:\\Users\\JohnDoe\\Documents";
        let matches = scrubber.check_for_pii(data);

        assert!(matches
            .iter()
            .any(|m| m.pii_type == PiiType::WindowsUserPath));
    }

    #[test]
    fn test_pii_scrubber_detects_aws_key() {
        let scrubber = PiiScrubber::new();
        let data = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE";
        let matches = scrubber.check_for_pii(data);

        assert!(matches.iter().any(|m| m.pii_type == PiiType::AwsKey));
    }

    #[test]
    fn test_pii_scrubber_detects_private_key() {
        let scrubber = PiiScrubber::new();
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAKBgQ...";
        let matches = scrubber.check_for_pii(data);

        assert!(matches.iter().any(|m| m.pii_type == PiiType::PrivateKey));
    }

    #[test]
    fn test_pii_scrubber_redacts_email() {
        let scrubber = PiiScrubber::new();
        let data = b"Contact: john.doe@example.com for support";
        let redacted = scrubber.scan_and_redact(data).unwrap();
        let redacted_str = String::from_utf8_lossy(&redacted);

        assert!(redacted_str.contains("[REDACTED-EMAIL]"));
        assert!(!redacted_str.contains("john.doe@example.com"));
    }

    #[test]
    fn test_pii_scrubber_redacts_multiple_pii() {
        let scrubber = PiiScrubber::new();
        let data = b"Email: test@example.com, SSN: 123-45-6789, IP: 192.168.1.1";
        let redacted = scrubber.scan_and_redact(data).unwrap();
        let redacted_str = String::from_utf8_lossy(&redacted);

        assert!(redacted_str.contains("[REDACTED-EMAIL]"));
        assert!(redacted_str.contains("[REDACTED-SSN]"));
        assert!(redacted_str.contains("[REDACTED-IP]"));
        assert!(!redacted_str.contains("test@example.com"));
        assert!(!redacted_str.contains("123-45-6789"));
        assert!(!redacted_str.contains("192.168.1.1"));
    }

    #[test]
    fn test_pii_scrubber_no_false_positives() {
        let scrubber = PiiScrubber::new();
        let data = b"This is clean data with no PII";
        let matches = scrubber.check_for_pii(data);

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_prepare_sample_includes_pii_metadata() {
        let submitter = SampleSubmitter::new();

        // Create a temp file with PII
        let mut file = NamedTempFile::new().unwrap();
        let content = b"Test content with email: test@example.com";
        file.write_all(content).unwrap();
        let path = file.path().with_extension("exe");
        std::fs::rename(file.path(), &path).unwrap();

        // Prepare the sample
        let payload = submitter.prepare_sample(&path).unwrap();

        // Should have detected and scrubbed PII
        assert!(payload.metadata.pii_scrubbed);
        assert!(payload.metadata.pii_count > 0);

        // Clean up
        std::fs::remove_file(&path).ok();
    }
}
