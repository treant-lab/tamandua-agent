//! Credential configuration and validation for the Tamandua agent.
//!
//! This module provides:
//! - Centralized credential path management
//! - Startup validation for weak/default credentials
//! - Credential rotation status tracking
//! - Certificate expiry checking
//!
//! ## Credential Inventory
//!
//! | Credential        | Config Field     | File Path                          | Purpose                |
//! |-------------------|------------------|-----------------------------------|------------------------|
//! | Auth Token        | auth_token       | (in-memory / config)               | Server authentication  |
//! | TLS Certificate   | tls.cert_path    | Platform-specific                  | mTLS client cert       |
//! | TLS Private Key   | tls.key_path     | Platform-specific                  | mTLS client key        |
//! | CA Certificate    | tls.ca_path      | Platform-specific                  | Server CA verification |

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};

#[cfg(target_os = "windows")]
fn windows_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("TAMANDUA_DATA_DIR").map(PathBuf::from) {
        return path;
    }

    if let Some(path) = std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join("Tamandua")) {
        if path.exists() || path.parent().is_some_and(|parent| parent.exists()) {
            return path;
        }
    }

    std::env::var_os("SystemDrive")
        .map(|drive| PathBuf::from(format!(r"{}\ProgramData\Tamandua", drive.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Tamandua"))
}

/// Known weak secrets that should trigger warnings
const KNOWN_WEAK_SECRETS: &[&str] = &[
    "secret",
    "changeme",
    "development",
    "test123",
    "password",
    "admin",
    "letmein",
    "12345678",
    "qwerty",
    "abc123",
    "tamandua",
    "default",
    "example",
    "mysecret",
    "supersecret",
    "token",
];

/// Minimum acceptable token length
const MIN_TOKEN_LENGTH: usize = 32;

/// Days before certificate expiry to start warning
#[allow(dead_code)]
const CERT_EXPIRY_WARNING_DAYS: u64 = 30;

/// A credential warning with details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialWarning {
    /// The credential name
    pub credential: String,
    /// Warning severity
    pub severity: WarningSeverity,
    /// Warning message
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    /// Non-critical warning
    Warning,
    /// Critical - should not be used in production
    Critical,
}

/// Credential configuration paths and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// Path to the authentication token file (optional, token can be in config)
    pub token_path: Option<PathBuf>,

    /// Path to the TLS client certificate
    pub cert_path: Option<PathBuf>,

    /// Path to the TLS private key
    pub key_path: Option<PathBuf>,

    /// Path to the CA certificate for server verification
    pub ca_path: Option<PathBuf>,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            token_path: None,
            cert_path: None,
            key_path: None,
            ca_path: None,
        }
    }
}

impl CredentialConfig {
    /// Create a new credential config with platform-specific default paths
    pub fn with_platform_defaults() -> Self {
        Self {
            token_path: Some(Self::default_token_path()),
            cert_path: Some(Self::default_cert_path()),
            key_path: Some(Self::default_key_path()),
            ca_path: Some(Self::default_ca_path()),
        }
    }

    /// Default path for authentication token
    pub fn default_token_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        return windows_data_dir().join("credentials").join("auth_token");

        #[cfg(target_os = "linux")]
        return PathBuf::from("/var/lib/tamandua/credentials/auth_token");

        #[cfg(target_os = "macos")]
        return PathBuf::from("/Library/Application Support/Tamandua/credentials/auth_token");

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return PathBuf::from("./credentials/auth_token");
    }

    /// Default path for TLS client certificate
    pub fn default_cert_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        return windows_data_dir().join("certs").join("client.crt");

        #[cfg(target_os = "linux")]
        return PathBuf::from("/var/lib/tamandua/certs/client.crt");

        #[cfg(target_os = "macos")]
        return PathBuf::from("/Library/Application Support/Tamandua/certs/client.crt");

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return PathBuf::from("./certs/client.crt");
    }

    /// Default path for TLS private key
    pub fn default_key_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        return windows_data_dir().join("certs").join("client.key");

        #[cfg(target_os = "linux")]
        return PathBuf::from("/var/lib/tamandua/certs/client.key");

        #[cfg(target_os = "macos")]
        return PathBuf::from("/Library/Application Support/Tamandua/certs/client.key");

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return PathBuf::from("./certs/client.key");
    }

    /// Default path for CA certificate
    pub fn default_ca_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        return windows_data_dir().join("certs").join("ca.crt");

        #[cfg(target_os = "linux")]
        return PathBuf::from("/var/lib/tamandua/certs/ca.crt");

        #[cfg(target_os = "macos")]
        return PathBuf::from("/Library/Application Support/Tamandua/certs/ca.crt");

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return PathBuf::from("./certs/ca.crt");
    }

    /// Validate all credentials and return warnings
    pub fn validate(&self, auth_token: Option<&str>, tls_enabled: bool) -> Vec<CredentialWarning> {
        let mut warnings = Vec::new();

        // Validate auth token
        warnings.extend(self.validate_auth_token(auth_token));

        // Validate TLS credentials if enabled
        if tls_enabled {
            warnings.extend(self.validate_tls_credentials());
        }

        warnings
    }

    /// Check if any credentials need rotation
    pub fn rotation_needed(&self, auth_token: Option<&str>, tls_enabled: bool) -> bool {
        let warnings = self.validate(auth_token, tls_enabled);
        warnings
            .iter()
            .any(|w| w.severity == WarningSeverity::Critical)
    }

    fn validate_auth_token(&self, auth_token: Option<&str>) -> Vec<CredentialWarning> {
        let mut warnings = Vec::new();

        match auth_token {
            None => {
                warnings.push(CredentialWarning {
                    credential: "auth_token".to_string(),
                    severity: WarningSeverity::Critical,
                    message: "Authentication token is not configured".to_string(),
                });
            }
            Some(token) if token.is_empty() => {
                warnings.push(CredentialWarning {
                    credential: "auth_token".to_string(),
                    severity: WarningSeverity::Critical,
                    message: "Authentication token is empty".to_string(),
                });
            }
            // Check for weak/default values before the length heuristic: a weak
            // secret is a Critical finding regardless of length, and a short weak
            // token (e.g. "password123") must not be downgraded to a Warning.
            Some(token) if is_weak_secret(token) => {
                warnings.push(CredentialWarning {
                    credential: "auth_token".to_string(),
                    severity: WarningSeverity::Critical,
                    message: "Authentication token appears to be a weak/default value".to_string(),
                });
            }
            Some(token) if token.len() < MIN_TOKEN_LENGTH => {
                warnings.push(CredentialWarning {
                    credential: "auth_token".to_string(),
                    severity: WarningSeverity::Warning,
                    message: format!(
                        "Authentication token is shorter than recommended ({} chars minimum)",
                        MIN_TOKEN_LENGTH
                    ),
                });
            }
            Some(_) => {
                // Token looks okay
            }
        }

        warnings
    }

    fn validate_tls_credentials(&self) -> Vec<CredentialWarning> {
        let mut warnings = Vec::new();

        // Check certificate file
        if let Some(ref cert_path) = self.cert_path {
            if !cert_path.exists() {
                warnings.push(CredentialWarning {
                    credential: "tls.cert_path".to_string(),
                    severity: WarningSeverity::Critical,
                    message: format!("Certificate file does not exist: {}", cert_path.display()),
                });
            } else {
                // Check certificate expiry
                if let Some(warning) = check_certificate_expiry(cert_path) {
                    warnings.push(warning);
                }
            }
        } else {
            warnings.push(CredentialWarning {
                credential: "tls.cert_path".to_string(),
                severity: WarningSeverity::Critical,
                message: "TLS is enabled but cert_path is not configured".to_string(),
            });
        }

        // Check private key file
        if let Some(ref key_path) = self.key_path {
            if !key_path.exists() {
                warnings.push(CredentialWarning {
                    credential: "tls.key_path".to_string(),
                    severity: WarningSeverity::Critical,
                    message: format!("Private key file does not exist: {}", key_path.display()),
                });
            } else {
                // Check key file permissions (Linux/macOS only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(metadata) = std::fs::metadata(key_path) {
                        let mode = metadata.mode();
                        if mode & 0o077 != 0 {
                            warnings.push(CredentialWarning {
                                credential: "tls.key_path".to_string(),
                                severity: WarningSeverity::Warning,
                                message: format!(
                                    "Private key file has insecure permissions (mode: {:o}). Should be 0600.",
                                    mode & 0o777
                                ),
                            });
                        }
                    }
                }
            }
        } else {
            warnings.push(CredentialWarning {
                credential: "tls.key_path".to_string(),
                severity: WarningSeverity::Critical,
                message: "TLS is enabled but key_path is not configured".to_string(),
            });
        }

        // Check CA certificate
        if let Some(ref ca_path) = self.ca_path {
            if !ca_path.exists() {
                warnings.push(CredentialWarning {
                    credential: "tls.ca_path".to_string(),
                    severity: WarningSeverity::Warning,
                    message: format!("CA certificate file does not exist: {}", ca_path.display()),
                });
            }
        }

        warnings
    }
}

/// Check if a secret appears to be weak/default
fn is_weak_secret(secret: &str) -> bool {
    let lower = secret.to_lowercase();

    // Check against known weak patterns
    for weak in KNOWN_WEAK_SECRETS {
        if lower.contains(weak) {
            return true;
        }
    }

    // Check if it's all the same character
    if let Some(first) = secret.chars().next() {
        if secret.chars().all(|c| c == first) {
            return true;
        }
    }

    // Check if it's a sequential pattern
    if secret.len() >= 4 && is_sequential(secret) {
        return true;
    }

    false
}

/// Check if a string is a sequential pattern (like "abcd" or "1234")
fn is_sequential(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 4 {
        return false;
    }

    let mut ascending = true;
    let mut descending = true;

    for i in 1..chars.len() {
        let diff = chars[i] as i32 - chars[i - 1] as i32;
        if diff != 1 {
            ascending = false;
        }
        if diff != -1 {
            descending = false;
        }
    }

    ascending || descending
}

/// Check certificate expiry and return a warning if it's expiring soon
fn check_certificate_expiry(cert_path: &Path) -> Option<CredentialWarning> {
    // Read the certificate file
    let _cert_pem = match std::fs::read_to_string(cert_path) {
        Ok(content) => content,
        Err(e) => {
            warn!(path = %cert_path.display(), error = %e, "Failed to read certificate file");
            return None;
        }
    };

    // Parse the certificate to extract expiry date
    // This is a simplified check - we look for the notAfter field in the PEM
    // For a production implementation, use a proper X.509 parsing library

    // Try using openssl command if available
    #[cfg(unix)]
    {
        use std::process::Command;

        let output = Command::new("openssl")
            .args(["x509", "-enddate", "-noout", "-in"])
            .arg(cert_path)
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(expiry_str) = stdout.strip_prefix("notAfter=") {
                    // Parse the date and check if it's within warning threshold
                    // OpenSSL date format: "Jan  1 00:00:00 2026 GMT"
                    debug!(cert = %cert_path.display(), expiry = %expiry_str.trim(), "Certificate expiry date");

                    // For now, just check if it contains a year in the past or current year
                    let current_year = chrono::Utc::now().year();
                    if expiry_str.contains(&(current_year - 1).to_string()) {
                        return Some(CredentialWarning {
                            credential: format!("tls.cert:{}", cert_path.display()),
                            severity: WarningSeverity::Critical,
                            message: "Certificate has expired".to_string(),
                        });
                    }
                }
            }
        }
    }

    // On Windows, use certutil or just check file modification time as a rough heuristic
    #[cfg(target_os = "windows")]
    {
        // For Windows, we could use certutil -dump
        // For now, just check if the cert file is very old
        if let Ok(metadata) = std::fs::metadata(cert_path) {
            if let Ok(modified) = metadata.modified() {
                let age = SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                // If the cert file hasn't been modified in over 2 years, warn
                if age > Duration::from_secs(2 * 365 * 24 * 60 * 60) {
                    return Some(CredentialWarning {
                        credential: format!("tls.cert:{}", cert_path.display()),
                        severity: WarningSeverity::Warning,
                        message: "Certificate file is over 2 years old - verify it hasn't expired"
                            .to_string(),
                    });
                }
            }
        }
    }

    None
}

/// Credential rotation status for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatus {
    /// Overall health
    pub health: RotationHealth,
    /// List of credentials and their status
    pub credentials: Vec<CredentialStatus>,
    /// Recommendations for rotation
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationHealth {
    Healthy,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub name: String,
    pub configured: bool,
    pub needs_rotation: bool,
    pub reason: Option<String>,
}

/// Get the full rotation status for all credentials
pub fn get_rotation_status(
    credential_config: &CredentialConfig,
    auth_token: Option<&str>,
    tls_enabled: bool,
) -> RotationStatus {
    let warnings = credential_config.validate(auth_token, tls_enabled);

    let mut credentials = Vec::new();
    let mut recommendations = Vec::new();

    // Auth token status
    let auth_warnings: Vec<_> = warnings
        .iter()
        .filter(|w| w.credential == "auth_token")
        .collect();

    credentials.push(CredentialStatus {
        name: "Authentication Token".to_string(),
        configured: auth_token.is_some() && !auth_token.unwrap_or("").is_empty(),
        needs_rotation: auth_warnings
            .iter()
            .any(|w| w.severity == WarningSeverity::Critical),
        reason: auth_warnings.first().map(|w| w.message.clone()),
    });

    if auth_warnings
        .iter()
        .any(|w| w.severity == WarningSeverity::Critical)
    {
        recommendations.push("Rotate authentication token immediately".to_string());
    }

    // TLS certificate status
    if tls_enabled {
        let cert_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| w.credential.starts_with("tls.cert"))
            .collect();

        credentials.push(CredentialStatus {
            name: "TLS Certificate".to_string(),
            configured: credential_config
                .cert_path
                .as_ref()
                .map(|p| p.exists())
                .unwrap_or(false),
            needs_rotation: cert_warnings
                .iter()
                .any(|w| w.severity == WarningSeverity::Critical),
            reason: cert_warnings.first().map(|w| w.message.clone()),
        });

        if cert_warnings
            .iter()
            .any(|w| w.severity == WarningSeverity::Critical)
        {
            recommendations.push("Renew TLS certificate".to_string());
        }

        // TLS key status
        let key_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| w.credential.starts_with("tls.key"))
            .collect();

        credentials.push(CredentialStatus {
            name: "TLS Private Key".to_string(),
            configured: credential_config
                .key_path
                .as_ref()
                .map(|p| p.exists())
                .unwrap_or(false),
            needs_rotation: key_warnings
                .iter()
                .any(|w| w.severity == WarningSeverity::Critical),
            reason: key_warnings.first().map(|w| w.message.clone()),
        });
    }

    // Determine overall health
    let health = if warnings
        .iter()
        .any(|w| w.severity == WarningSeverity::Critical)
    {
        RotationHealth::Critical
    } else if !warnings.is_empty() {
        RotationHealth::Warning
    } else {
        RotationHealth::Healthy
    };

    RotationStatus {
        health,
        credentials,
        recommendations,
    }
}

/// Validate credentials and log warnings on startup
pub fn validate_and_log(
    credential_config: &CredentialConfig,
    auth_token: Option<&str>,
    tls_enabled: bool,
) {
    let warnings = credential_config.validate(auth_token, tls_enabled);

    if warnings.is_empty() {
        info!("All credential validations passed");
        return;
    }

    let critical_count = warnings
        .iter()
        .filter(|w| w.severity == WarningSeverity::Critical)
        .count();
    let warning_count = warnings.len() - critical_count;

    if critical_count > 0 {
        error!(
            critical = critical_count,
            warnings = warning_count,
            "Credential validation found critical issues"
        );
    } else {
        warn!(warnings = warning_count, "Credential validation warnings");
    }

    for warning in &warnings {
        match warning.severity {
            WarningSeverity::Critical => {
                error!(
                    credential = %warning.credential,
                    "CRITICAL: {}",
                    warning.message
                );
            }
            WarningSeverity::Warning => {
                warn!(
                    credential = %warning.credential,
                    "{}",
                    warning.message
                );
            }
        }
    }

    if critical_count > 0 {
        error!("See docs/security/CREDENTIAL_ROTATION.md for rotation procedures");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_secret_detection() {
        assert!(is_weak_secret("password"));
        assert!(is_weak_secret("changeme"));
        assert!(is_weak_secret("my-secret-token"));
        assert!(is_weak_secret("admin123"));
        assert!(is_weak_secret("aaaaaaa"));
        assert!(is_weak_secret("abcdefgh"));
        assert!(is_weak_secret("12345678"));

        assert!(!is_weak_secret("xK9mN2pQ7rS4tU"));
        assert!(!is_weak_secret("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn test_sequential_detection() {
        assert!(is_sequential("abcd"));
        assert!(is_sequential("1234"));
        assert!(is_sequential("dcba"));

        assert!(!is_sequential("abdc"));
        assert!(!is_sequential("1324"));
        assert!(!is_sequential("xyz"));
    }

    #[test]
    fn test_validate_empty_token() {
        let config = CredentialConfig::default();
        let warnings = config.validate(None, false);
        assert!(warnings
            .iter()
            .any(|w| w.credential == "auth_token" && w.severity == WarningSeverity::Critical));
    }

    #[test]
    fn test_validate_weak_token() {
        let config = CredentialConfig::default();
        let warnings = config.validate(Some("password123"), false);
        assert!(warnings
            .iter()
            .any(|w| w.credential == "auth_token" && w.severity == WarningSeverity::Critical));
    }

    #[test]
    fn test_validate_good_token() {
        let config = CredentialConfig::default();
        let good_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let warnings = config.validate(Some(good_token), false);
        assert!(warnings.is_empty() || !warnings.iter().any(|w| w.credential == "auth_token"));
    }
}
