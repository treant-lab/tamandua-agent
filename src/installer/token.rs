//! Installation token validation and secure storage.
//!
//! - Validates installation tokens against the backend via HTTPS
//! - Hashes tokens with Argon2id for local uninstall protection
//! - Stores/retrieves hashed tokens from protected OS storage
//! - Stores a protected recovery token for unattended re-enrollment
//! - CSR-based enrollment where private key never leaves the agent

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::pki::csr::CsrGenerator;
use crate::pki::CertPaths;

/// Response from the backend enrollment validation endpoint.
#[derive(Debug, Deserialize)]
pub struct ValidationResponse {
    pub valid: bool,
    pub org_id: Option<String>,
    pub error: Option<String>,
}

/// Response from the backend enrollment exchange endpoint.
#[derive(Debug, Deserialize)]
pub struct EnrollmentResponse {
    pub agent_id: String,
    pub jwt: String,
    pub org_id: String,
    pub config: Option<EnrollmentConfig>,
}

/// Optional configuration from the enrollment response.
#[derive(Debug, Deserialize)]
pub struct EnrollmentConfig {
    pub collection_interval_ms: Option<u64>,
    pub enabled_collectors: Option<Vec<String>>,
}

/// Response from the CSR-based enrollment endpoint.
#[derive(Debug, Deserialize)]
pub struct CsrEnrollmentResponse {
    pub agent_id: String,
    pub jwt: String,
    pub org_id: String,
    pub certificate: String, // Base64-encoded certificate PEM
    pub ca_bundle: String,   // Base64-encoded CA bundle PEM
    #[serde(default)]
    pub config: Option<EnrollmentConfig>,
}

/// Request body for CSR-based enrollment.
#[derive(Debug, Serialize)]
struct CsrEnrollmentRequest {
    token: String,
    csr: String, // Base64-encoded CSR PEM
    agent_info: AgentInfoPublic,
}

/// Public version of AgentInfo for serialization in requests.
#[derive(Debug, Serialize, Clone)]
pub struct AgentInfoPublic {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub agent_version: String,
    pub machine_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

impl AgentInfoPublic {
    /// Collect system information for enrollment.
    pub fn collect() -> Self {
        let info = os_info::get();
        Self {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            os: std::env::consts::OS.to_string(),
            os_version: format!("{}", info.version()),
            arch: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            machine_id: AgentConfig::default().get_machine_id_hash(),
            agent_id: None,
        }
    }

    /// Set the agent_id (used when it's pre-generated).
    pub fn with_agent_id(mut self, agent_id: String) -> Self {
        self.agent_id = Some(agent_id);
        self
    }
}

/// Information about the enrolling agent sent to the backend.
#[derive(Debug, Serialize)]
struct AgentInfo {
    hostname: String,
    os: String,
    os_version: String,
    arch: String,
    agent_version: String,
}

impl AgentInfo {
    fn collect() -> Self {
        let info = os_info::get();
        Self {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            os: std::env::consts::OS.to_string(),
            os_version: format!("{}", info.version()),
            arch: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Validate an installation token against the backend.
///
/// Makes an HTTPS POST to `/api/v1/enrollment/validate` with the token.
/// Returns the validation response containing org_id if valid.
pub async fn validate_token(server_url: &str, token: &str) -> Result<ValidationResponse> {
    let base_url = extract_http_base(server_url)?;
    let url = format!("{}/api/v1/enrollment/validate", base_url);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg!(debug_assertions)) // Allow self-signed in dev
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(25))
        .build()
        .context("Failed to create HTTP client")?;

    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .with_context(|| format!("Failed to connect to backend at {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("Token validation failed (HTTP {}): {}", status, body);
    }

    let validation: ValidationResponse = resp
        .json()
        .await
        .context("Failed to parse validation response")?;

    if !validation.valid {
        bail!(
            "Invalid installation token: {}",
            validation
                .error
                .as_deref()
                .unwrap_or("token rejected by server")
        );
    }

    info!("Installation token validated successfully");
    Ok(validation)
}

/// Exchange an installation token for a JWT and agent credentials.
///
/// Makes an HTTPS POST to `/api/v1/enrollment/exchange` with the token
/// and agent system information. Returns the enrollment response.
pub async fn exchange_token(server_url: &str, token: &str) -> Result<EnrollmentResponse> {
    let base_url = extract_http_base(server_url)?;
    let url = format!("{}/api/v1/enrollment/exchange", base_url);

    let agent_info = AgentInfo::collect();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg!(debug_assertions))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(25))
        .build()
        .context("Failed to create HTTP client")?;

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "token": token,
            "agent_info": agent_info,
        }))
        .send()
        .await
        .with_context(|| format!("Failed to connect to backend at {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("Token exchange failed (HTTP {}): {}", status, body);
    }

    let enrollment: EnrollmentResponse = resp
        .json()
        .await
        .context("Failed to parse enrollment response")?;

    info!(
        agent_id = %enrollment.agent_id,
        org_id = %enrollment.org_id,
        "Token exchanged for agent credentials"
    );

    Ok(enrollment)
}

/// Enroll agent using CSR-based flow (private key never leaves agent).
///
/// This is the secure enrollment flow where:
/// 1. Agent generates RSA keypair locally
/// 2. Private key is saved to disk immediately (before network call)
/// 3. CSR is sent to server
/// 4. Server signs CSR and returns certificate
/// 5. Agent saves certificate and CA bundle
///
/// # Arguments
///
/// * `server_url` - The base server URL (can be ws/wss or http/https)
/// * `token` - Installation token for authorization
/// * `agent_id` - Optional pre-generated agent ID (if None, server generates one)
///
/// # Returns
///
/// The enrollment response containing certificate, JWT, and configuration.
pub async fn enroll_with_csr(
    server_url: &str,
    token: &str,
    agent_id: Option<&str>,
) -> Result<CsrEnrollmentResponse> {
    let base_url = extract_http_base(server_url)?;

    // Collect agent info
    let agent_info = AgentInfoPublic::collect();
    let hostname = agent_info.hostname.clone();

    // Generate agent_id if not provided
    let agent_id = agent_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    info!(
        agent_id = %agent_id,
        hostname = %hostname,
        "Starting CSR-based enrollment"
    );

    // Step 1: Generate keypair and CSR
    let csr_gen = CsrGenerator::new().context("Failed to generate keypair")?;

    let csr_pem = csr_gen
        .generate_csr(&agent_id, &hostname)
        .context("Failed to generate CSR")?;

    // Step 2: Save private key to a temporary path before the network call.
    // Never overwrite an existing enrolled key unless the server actually
    // accepts the CSR and returns a matching certificate.
    let paths = CertPaths::default_paths();
    let key_tmp_path = paths.key_path.with_extension("key.enrolling");
    csr_gen
        .save_private_key(&key_tmp_path)
        .with_context(|| format!("Failed to save temporary private key to {:?}", key_tmp_path))?;
    info!("Temporary private key saved to {:?}", key_tmp_path);

    // Step 3: Send CSR to server
    let url = format!("{}/api/v1/enrollment/csr", base_url);

    let request = CsrEnrollmentRequest {
        token: token.to_string(),
        csr: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &csr_pem),
        agent_info: agent_info.with_agent_id(agent_id.clone()),
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg!(debug_assertions))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(150))
        .build()
        .context("Failed to create HTTP client")?;

    let resp = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .with_context(|| format!("Failed to connect to CSR enrollment endpoint at {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let _ = std::fs::remove_file(&key_tmp_path);
        bail!("CSR enrollment failed (HTTP {}): {}", status, body);
    }

    let enrollment: CsrEnrollmentResponse = resp
        .json()
        .await
        .context("Failed to parse CSR enrollment response")?;

    // Step 4: Save certificate and CA bundle
    let cert_pem = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &enrollment.certificate,
    )
    .context("Failed to decode certificate from base64")?;
    let ca_bundle_pem = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &enrollment.ca_bundle,
    )
    .context("Failed to decode CA bundle from base64")?;

    // Ensure directory exists
    if let Some(parent) = paths.cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&paths.cert_path, &cert_pem)
        .with_context(|| format!("Failed to save certificate to {:?}", paths.cert_path))?;
    std::fs::write(&paths.ca_bundle_path, &ca_bundle_pem)
        .with_context(|| format!("Failed to save CA bundle to {:?}", paths.ca_bundle_path))?;
    std::fs::rename(&key_tmp_path, &paths.key_path).with_context(|| {
        format!(
            "Failed to activate private key {:?} -> {:?}",
            key_tmp_path, paths.key_path
        )
    })?;

    info!(
        agent_id = %enrollment.agent_id,
        org_id = %enrollment.org_id,
        cert_path = ?paths.cert_path,
        "CSR enrollment completed successfully"
    );

    Ok(enrollment)
}

/// Hash a token using Argon2id for secure local storage.
pub fn hash_token(token: &str) -> Result<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash token: {}", e))?;

    Ok(hash.to_string())
}

/// Verify a token against a stored Argon2id hash.
pub fn verify_token_hash(token: &str, stored_hash: &str) -> Result<bool> {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let parsed_hash = PasswordHash::new(stored_hash)
        .map_err(|e| anyhow!("Failed to parse stored hash: {}", e))?;

    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Store the hashed installation token in the Windows registry.
#[cfg(target_os = "windows")]
pub fn store_token_hash(hash: &str) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(r"SOFTWARE\Tamandua")
        .context("Failed to create Tamandua registry key")?;

    key.set_value("InstallToken", &hash)
        .context("Failed to store token hash in registry")?;

    info!("Installation token hash stored in registry");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn store_token_hash(hash: &str) -> Result<()> {
    // On Linux/macOS, store in a protected file
    let path = "/etc/tamandua/.install_token";
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, hash)?;

    // Restrict permissions to root only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("Installation token hash stored");
    Ok(())
}

/// Retrieve the stored token hash from the registry.
#[cfg(target_os = "windows")]
pub fn get_stored_token_hash() -> Result<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey(r"SOFTWARE\Tamandua")
        .context("Tamandua registry key not found - is the agent installed?")?;

    let hash: String = key
        .get_value("InstallToken")
        .context("InstallToken not found in registry")?;

    Ok(hash)
}

#[cfg(not(target_os = "windows"))]
pub fn get_stored_token_hash() -> Result<String> {
    let path = "/etc/tamandua/.install_token";
    std::fs::read_to_string(path)
        .context("Installation token hash not found - is the agent installed?")
}

/// Remove the stored token hash (during uninstall).
#[cfg(target_os = "windows")]
pub fn remove_token_hash() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // Delete the entire Tamandua key
    match hklm.delete_subkey_all(r"SOFTWARE\Tamandua") {
        Ok(_) => info!("Tamandua registry key removed"),
        Err(e) => warn!(error = %e, "Failed to remove Tamandua registry key"),
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn remove_token_hash() -> Result<()> {
    let path = "/etc/tamandua/.install_token";
    match std::fs::remove_file(path) {
        Ok(_) => info!("Installation token hash removed"),
        Err(e) => warn!(error = %e, "Failed to remove token hash file"),
    }
    Ok(())
}

/// Store the installation token for unattended re-enrollment recovery.
///
/// This token must be protected as a secret. It is only used after normal JWT
/// refresh fails and the agent needs to recover from an expired/rejected token.
#[cfg(target_os = "windows")]
pub fn store_recovery_token(token: &str) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(r"SOFTWARE\Tamandua")
        .context("Failed to create Tamandua registry key")?;

    key.set_value("RecoveryToken", &token)
        .context("Failed to store recovery token in registry")?;

    info!("Recovery token stored in protected registry metadata");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn store_recovery_token(token: &str) -> Result<()> {
    let path = "/etc/tamandua/.recovery_token";
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("Recovery token stored in protected metadata");
    Ok(())
}

/// Retrieve the protected recovery token.
#[cfg(target_os = "windows")]
pub fn get_recovery_token() -> Result<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey(r"SOFTWARE\Tamandua")
        .context("Tamandua registry key not found - is the agent installed?")?;

    let token: String = key
        .get_value("RecoveryToken")
        .context("RecoveryToken not found in registry")?;

    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("Recovery token is empty");
    }

    Ok(token)
}

#[cfg(not(target_os = "windows"))]
pub fn get_recovery_token() -> Result<String> {
    let path = "/etc/tamandua/.recovery_token";
    let token = std::fs::read_to_string(path)
        .context("Recovery token not found - is unattended re-enrollment configured?")?
        .trim()
        .to_string();

    if token.is_empty() {
        bail!("Recovery token is empty");
    }

    Ok(token)
}

/// Remove the stored recovery token.
#[cfg(target_os = "windows")]
pub fn remove_recovery_token() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey_with_flags(r"SOFTWARE\Tamandua", KEY_SET_VALUE) {
        Ok(key) => match key.delete_value("RecoveryToken") {
            Ok(_) => info!("Recovery token removed"),
            Err(e) => warn!(error = %e, "Failed to remove recovery token"),
        },
        Err(e) => warn!(error = %e, "Failed to open Tamandua registry key"),
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn remove_recovery_token() -> Result<()> {
    let path = "/etc/tamandua/.recovery_token";
    match std::fs::remove_file(path) {
        Ok(_) => info!("Recovery token removed"),
        Err(e) => warn!(error = %e, "Failed to remove recovery token file"),
    }
    Ok(())
}

/// Convert a WebSocket URL to an HTTPS base URL for REST API calls.
///
/// `wss://edr.company.com/socket/agent` -> `https://edr.company.com`
/// `ws://localhost:4000/socket/agent` -> `http://localhost:4000`
fn extract_http_base(server_url: &str) -> Result<String> {
    let url = url::Url::parse(server_url)
        .with_context(|| format!("Invalid server URL: {}", server_url))?;

    let scheme = match url.scheme() {
        "wss" | "https" => "https",
        "ws" | "http" => "http",
        other => bail!("Unsupported URL scheme: {}", other),
    };

    let host = url.host_str().ok_or_else(|| anyhow!("No host in URL"))?;

    match url.port() {
        Some(port) => Ok(format!("{}://{}:{}", scheme, host, port)),
        None => Ok(format!("{}://{}", scheme, host)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_http_base() {
        assert_eq!(
            extract_http_base("wss://edr.company.com/socket/agent").unwrap(),
            "https://edr.company.com"
        );
        assert_eq!(
            extract_http_base("ws://localhost:4000/socket/agent").unwrap(),
            "http://localhost:4000"
        );
        assert_eq!(
            extract_http_base("wss://edr.company.com:8443/socket/agent").unwrap(),
            "https://edr.company.com:8443"
        );
    }

    #[test]
    fn test_hash_and_verify() {
        let token = "test-token-12345";
        let hash = hash_token(token).unwrap();
        assert!(verify_token_hash(token, &hash).unwrap());
        assert!(!verify_token_hash("wrong-token", &hash).unwrap());
    }
}
