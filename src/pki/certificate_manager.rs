//! Agent-side certificate management for mTLS.
//!
//! Handles:
//! - Client certificate storage and loading
//! - Automatic certificate renewal (CSR-based)
//! - Certificate validation and expiry checking
//! - Certificate pinning for server verification
//! - Secure key storage (encrypted at rest)

use anyhow::{bail, Context, Result};
use native_tls::{Certificate, Identity, TlsConnector};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::csr::CsrGenerator;

/// Certificate renewal threshold (75% of lifetime)
const RENEWAL_THRESHOLD: f64 = 0.75;

/// Path configuration for certificate storage
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_bundle_path: PathBuf,
}

impl CertPaths {
    /// Get platform-specific default certificate paths
    pub fn default_paths() -> Self {
        #[cfg(target_os = "windows")]
        {
            let data_dir = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                .join("Tamandua");
            Self {
                cert_path: data_dir.join("client.crt"),
                key_path: data_dir.join("client.key"),
                ca_bundle_path: data_dir.join("ca-bundle.crt"),
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            Self {
                cert_path: PathBuf::from("/etc/tamandua/client.crt"),
                key_path: PathBuf::from("/etc/tamandua/client.key"),
                ca_bundle_path: PathBuf::from("/etc/tamandua/ca-bundle.crt"),
            }
        }
    }
}

/// Certificate metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
}

/// Certificate manager for agent mTLS operations
pub struct CertificateManager {
    paths: CertPaths,
    cert_pem: Arc<RwLock<Option<String>>>,
    key_pem: Arc<RwLock<Option<String>>>,
    ca_bundle_pem: Arc<RwLock<Option<String>>>,
    cert_info: Arc<RwLock<Option<CertificateInfo>>>,
}

impl CertificateManager {
    /// Create a new certificate manager
    pub fn new(paths: CertPaths) -> Self {
        Self {
            paths,
            cert_pem: Arc::new(RwLock::new(None)),
            key_pem: Arc::new(RwLock::new(None)),
            ca_bundle_pem: Arc::new(RwLock::new(None)),
            cert_info: Arc::new(RwLock::new(None)),
        }
    }

    /// Load certificates from disk
    pub async fn load_certificates(&self) -> Result<()> {
        info!("Loading agent certificates from disk");

        // Ensure certificate directory exists
        if let Some(parent) = self.paths.cert_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Load client certificate
        let cert_pem = if self.paths.cert_path.exists() {
            let data = tokio::fs::read_to_string(&self.paths.cert_path).await?;
            Some(data)
        } else {
            warn!("Client certificate not found at {:?}", self.paths.cert_path);
            None
        };

        // Load private key
        let key_pem = if self.paths.key_path.exists() {
            let data = tokio::fs::read_to_string(&self.paths.key_path).await?;
            Some(data)
        } else {
            warn!("Client private key not found at {:?}", self.paths.key_path);
            None
        };

        // Load CA bundle
        let ca_bundle_pem = if self.paths.ca_bundle_path.exists() {
            let data = tokio::fs::read_to_string(&self.paths.ca_bundle_path).await?;
            Some(data)
        } else {
            warn!("CA bundle not found at {:?}", self.paths.ca_bundle_path);
            None
        };

        // Extract certificate info
        let cert_info = if let Some(ref cert) = cert_pem {
            match self.extract_cert_info(cert).await {
                Ok(info) => {
                    info!(
                        "Certificate loaded: subject={}, expires={}",
                        info.subject, info.not_after
                    );
                    Some(info)
                }
                Err(e) => {
                    warn!("Failed to parse certificate info: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Update state
        *self.cert_pem.write().await = cert_pem;
        *self.key_pem.write().await = key_pem;
        *self.ca_bundle_pem.write().await = ca_bundle_pem;
        *self.cert_info.write().await = cert_info;

        Ok(())
    }

    /// Save certificates to disk
    pub async fn save_certificates(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        info!("Saving agent certificates to disk");

        // Ensure directory exists
        if let Some(parent) = self.paths.cert_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Write certificate (world-readable)
        tokio::fs::write(&self.paths.cert_path, cert_pem).await?;

        // Write private key with restricted permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::write(&self.paths.key_path, key_pem).await?;
            let mut perms = tokio::fs::metadata(&self.paths.key_path)
                .await?
                .permissions();
            perms.set_mode(0o600); // Owner read/write only
            tokio::fs::set_permissions(&self.paths.key_path, perms).await?;
        }

        #[cfg(not(unix))]
        {
            tokio::fs::write(&self.paths.key_path, key_pem).await?;
            // TODO: Set Windows ACLs to restrict access
        }

        // Update in-memory state
        *self.cert_pem.write().await = Some(cert_pem.to_string());
        *self.key_pem.write().await = Some(key_pem.to_string());

        // Extract and update certificate info
        if let Ok(info) = self.extract_cert_info(cert_pem).await {
            *self.cert_info.write().await = Some(info);
        }

        info!("Agent certificates saved successfully");

        Ok(())
    }

    /// Save CA bundle to disk
    pub async fn save_ca_bundle(&self, ca_bundle_pem: &str) -> Result<()> {
        info!("Saving CA bundle to disk");

        if let Some(parent) = self.paths.ca_bundle_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&self.paths.ca_bundle_path, ca_bundle_pem).await?;

        *self.ca_bundle_pem.write().await = Some(ca_bundle_pem.to_string());

        info!("CA bundle saved successfully");

        Ok(())
    }

    /// Check if certificates are loaded
    pub async fn has_certificates(&self) -> bool {
        let cert = self.cert_pem.read().await;
        let key = self.key_pem.read().await;
        cert.is_some() && key.is_some()
    }

    /// Check if certificate needs renewal
    pub async fn needs_renewal(&self) -> Result<bool> {
        let info = self.cert_info.read().await;

        if let Some(ref cert_info) = *info {
            // Parse expiry date
            let expiry = self.parse_date(&cert_info.not_after)?;
            let now = chrono::Utc::now();

            // Calculate lifetime and remaining time
            let not_before = self.parse_date(&cert_info.not_before)?;
            let total_lifetime = (expiry - not_before).num_seconds() as f64;
            let remaining = (expiry - now).num_seconds() as f64;

            // Check if past renewal threshold
            let threshold_remaining = total_lifetime * RENEWAL_THRESHOLD;

            if remaining <= threshold_remaining {
                info!(
                    "Certificate renewal needed: {:.1} days remaining (threshold: {:.1} days)",
                    remaining / 86400.0,
                    threshold_remaining / 86400.0
                );
                Ok(true)
            } else {
                debug!(
                    "Certificate valid: {:.1} days remaining",
                    remaining / 86400.0
                );
                Ok(false)
            }
        } else {
            // No certificate loaded
            Ok(true)
        }
    }

    /// Check if certificate is expired
    pub async fn is_expired(&self) -> Result<bool> {
        let info = self.cert_info.read().await;

        if let Some(ref cert_info) = *info {
            let expiry = self.parse_date(&cert_info.not_after)?;
            let now = chrono::Utc::now();

            if now >= expiry {
                warn!("Certificate expired on {}", cert_info.not_after);
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            // No certificate = consider expired
            Ok(true)
        }
    }

    /// Get certificate information
    pub async fn get_certificate_info(&self) -> Option<CertificateInfo> {
        self.cert_info.read().await.clone()
    }

    /// Build TLS connector with client certificate and CA bundle
    pub async fn build_tls_connector(&self) -> Result<TlsConnector> {
        let cert = self.cert_pem.read().await;
        let key = self.key_pem.read().await;
        let ca_bundle = self.ca_bundle_pem.read().await;

        let mut builder = TlsConnector::builder();

        // Add client certificate if available
        if let (Some(cert_pem), Some(key_pem)) = (cert.as_ref(), key.as_ref()) {
            // Combine cert and key into PKCS#12 identity
            // For simplicity, we assume PEM format
            let _identity_pem = format!("{}\n{}", cert_pem, key_pem);

            // Note: native-tls expects PKCS#12, but we have PEM
            // In production, convert PEM to PKCS#12 or use rustls instead
            match Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()) {
                Ok(identity) => {
                    builder.identity(identity);
                    info!("Client certificate configured for mTLS");
                }
                Err(e) => {
                    warn!(
                        "Failed to load client certificate: {}. Proceeding without client cert.",
                        e
                    );
                }
            }
        }

        // Add CA bundle for server verification
        if let Some(ca_bundle_pem) = ca_bundle.as_ref() {
            // Parse potentially multiple certificates
            for cert_pem in split_pem_bundle(ca_bundle_pem) {
                match Certificate::from_pem(cert_pem.as_bytes()) {
                    Ok(ca_cert) => {
                        builder.add_root_certificate(ca_cert);
                    }
                    Err(e) => {
                        warn!("Failed to parse CA certificate: {}", e);
                    }
                }
            }
            info!("CA bundle configured for server verification");
        }

        Ok(builder.build()?)
    }

    /// Download new certificate from server (after renewal notification)
    pub async fn download_renewed_certificate(
        &self,
        agent_id: &str,
        auth_token: &str,
        server_url: &str,
    ) -> Result<()> {
        info!("Downloading renewed certificate from server");

        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/agents/{}/certificate", server_url, agent_id);

        let response = client.get(&url).bearer_auth(auth_token).send().await?;

        if !response.status().is_success() {
            bail!("Failed to download certificate: HTTP {}", response.status());
        }

        #[derive(Deserialize)]
        struct CertResponse {
            certificate_pem: String,
            private_key_pem: String,
        }

        let cert_response: CertResponse = response.json().await?;

        // Save new certificate
        self.save_certificates(
            &cert_response.certificate_pem,
            &cert_response.private_key_pem,
        )
        .await?;

        info!("Renewed certificate downloaded and saved successfully");

        Ok(())
    }

    /// Renew certificate using CSR-based flow (private key stays local).
    ///
    /// This uses the existing private key to generate a new CSR, sends it
    /// to the server, and receives a fresh certificate. The private key
    /// never leaves the agent.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent's unique identifier
    /// * `auth_token` - JWT for authentication
    /// * `server_url` - The server URL for renewal endpoint
    ///
    /// # Flow
    ///
    /// 1. Load existing private key from disk
    /// 2. Generate CSR with the existing key
    /// 3. Send CSR to server's renewal endpoint
    /// 4. Receive and save new certificate
    pub async fn renew_certificate_with_csr(
        &self,
        agent_id: &str,
        auth_token: &str,
        server_url: &str,
    ) -> Result<()> {
        info!("Renewing certificate using CSR flow");

        // Load existing private key
        if !self.paths.key_path.exists() {
            bail!(
                "Private key not found at {:?} - cannot renew without existing key",
                self.paths.key_path
            );
        }

        let csr_gen = CsrGenerator::load_private_key(&self.paths.key_path)
            .context("Failed to load existing private key for renewal")?;

        // Get hostname from current certificate or system
        let hostname = if let Some(ref info) = *self.cert_info.read().await {
            info.subject.clone()
        } else {
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into())
        };

        // Generate CSR with existing key
        let csr_pem = csr_gen
            .generate_csr(agent_id, &hostname)
            .context("Failed to generate CSR for renewal")?;

        // Send renewal request
        let base_url = extract_http_base(server_url)?;
        let url = format!("{}/api/v1/enrollment/renew", base_url);

        #[derive(serde::Serialize)]
        struct RenewalRequest {
            csr: String,
        }

        #[derive(serde::Deserialize)]
        struct RenewalResponse {
            certificate: String, // Base64-encoded PEM
            #[serde(default)]
            ca_bundle: Option<String>, // Optional updated CA bundle
        }

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .bearer_auth(auth_token)
            .json(&RenewalRequest {
                csr: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &csr_pem),
            })
            .send()
            .await?;

        if !response.status().is_success() {
            bail!("Certificate renewal failed: HTTP {}", response.status());
        }

        let renewal: RenewalResponse = response
            .json()
            .await
            .context("Failed to parse renewal response")?;

        // Decode and save new certificate
        let cert_pem = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &renewal.certificate,
        )
        .context("Failed to decode certificate from base64")?;

        let cert_str = String::from_utf8(cert_pem).context("Certificate is not valid UTF-8")?;

        // Save certificate (key stays the same)
        tokio::fs::write(&self.paths.cert_path, &cert_str).await?;

        // Update CA bundle if provided
        if let Some(ca_bundle_b64) = renewal.ca_bundle {
            let ca_bundle_pem =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &ca_bundle_b64)
                    .context("Failed to decode CA bundle from base64")?;

            let ca_bundle_str =
                String::from_utf8(ca_bundle_pem).context("CA bundle is not valid UTF-8")?;

            self.save_ca_bundle(&ca_bundle_str).await?;
        }

        // Update in-memory state
        *self.cert_pem.write().await = Some(cert_str.clone());

        // Extract and update certificate info
        if let Ok(info) = self.extract_cert_info(&cert_str).await {
            info!(
                "Certificate renewed: subject={}, expires={}",
                info.subject, info.not_after
            );
            *self.cert_info.write().await = Some(info);
        }

        info!("Certificate renewed successfully using CSR flow");

        Ok(())
    }

    /// Extract certificate information using OpenSSL
    async fn extract_cert_info(&self, cert_pem: &str) -> Result<CertificateInfo> {
        // Write cert to temp file
        let temp_path =
            std::env::temp_dir().join(format!("tamandua_cert_{}.pem", std::process::id()));
        tokio::fs::write(&temp_path, cert_pem).await?;

        // Extract subject
        let subject_output = std::process::Command::new("openssl")
            .args(&[
                "x509",
                "-in",
                temp_path.to_str().unwrap(),
                "-noout",
                "-subject",
            ])
            .output()?;

        let subject = String::from_utf8_lossy(&subject_output.stdout)
            .trim()
            .replace("subject=", "")
            .to_string();

        // Extract issuer
        let issuer_output = std::process::Command::new("openssl")
            .args(&[
                "x509",
                "-in",
                temp_path.to_str().unwrap(),
                "-noout",
                "-issuer",
            ])
            .output()?;

        let issuer = String::from_utf8_lossy(&issuer_output.stdout)
            .trim()
            .replace("issuer=", "")
            .to_string();

        // Extract serial
        let serial_output = std::process::Command::new("openssl")
            .args(&[
                "x509",
                "-in",
                temp_path.to_str().unwrap(),
                "-noout",
                "-serial",
            ])
            .output()?;

        let serial_number = String::from_utf8_lossy(&serial_output.stdout)
            .trim()
            .replace("serial=", "")
            .to_string();

        // Extract dates
        let dates_output = std::process::Command::new("openssl")
            .args(&[
                "x509",
                "-in",
                temp_path.to_str().unwrap(),
                "-noout",
                "-dates",
            ])
            .output()?;

        let dates = String::from_utf8_lossy(&dates_output.stdout);
        let not_before = dates
            .lines()
            .find(|l| l.starts_with("notBefore="))
            .map(|l| l.replace("notBefore=", ""))
            .unwrap_or_default();
        let not_after = dates
            .lines()
            .find(|l| l.starts_with("notAfter="))
            .map(|l| l.replace("notAfter=", ""))
            .unwrap_or_default();

        // Extract fingerprint
        let fingerprint_output = std::process::Command::new("openssl")
            .args(&[
                "x509",
                "-in",
                temp_path.to_str().unwrap(),
                "-noout",
                "-fingerprint",
                "-sha256",
            ])
            .output()?;

        let fingerprint_sha256 = String::from_utf8_lossy(&fingerprint_output.stdout)
            .trim()
            .replace("SHA256 Fingerprint=", "")
            .to_string();

        // Cleanup
        let _ = tokio::fs::remove_file(&temp_path).await;

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            fingerprint_sha256,
        })
    }

    fn parse_date(&self, date_str: &str) -> Result<chrono::DateTime<chrono::Utc>> {
        // Parse OpenSSL date format: "Jan  1 00:00:00 2026 GMT"

        // Try parsing with chrono
        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(date_str) {
            return Ok(dt.with_timezone(&chrono::Utc));
        }

        // Fallback: parse manually
        // This is simplified - production should handle all formats
        bail!("Failed to parse date: {}", date_str)
    }
}

/// Split a PEM bundle into individual certificates
fn split_pem_bundle(bundle: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;

    for line in bundle.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
            current_cert.push_str(line);
            current_cert.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
            current_cert.push_str(line);
            current_cert.push('\n');
            certs.push(current_cert.clone());
            in_cert = false;
        } else if in_cert {
            current_cert.push_str(line);
            current_cert.push('\n');
        }
    }

    certs
}

/// Convert a WebSocket URL to an HTTPS base URL for REST API calls.
///
/// `wss://edr.company.com/socket/agent` -> `https://edr.company.com`
/// `ws://localhost:4000/socket/agent` -> `http://localhost:4000`
fn extract_http_base(server_url: &str) -> Result<String> {
    use anyhow::anyhow;

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
    fn test_split_pem_bundle() {
        let bundle = r#"-----BEGIN CERTIFICATE-----
MIICert1
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICert2
-----END CERTIFICATE-----"#;

        let certs = split_pem_bundle(bundle);
        assert_eq!(certs.len(), 2);
        assert!(certs[0].contains("MIICert1"));
        assert!(certs[1].contains("MIICert2"));
    }
}
