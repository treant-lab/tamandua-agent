//! CSR (Certificate Signing Request) generation for agent enrollment.
//!
//! This module handles local keypair generation and CSR creation for the
//! secure CSR-based enrollment flow where the private key never leaves the agent.
//!
//! ## Security Properties
//!
//! - Private key is generated locally using ECDSA P-256
//! - Private key is saved to disk immediately, before any network calls
//! - CSR is signed with the private key, proving possession
//! - Server only receives the CSR (public key + subject), never the private key

use anyhow::{bail, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::Path;
use tracing::{debug, info};

/// Agent certificate key algorithm.
///
/// rcgen can sign CSRs with RSA keys but cannot generate RSA keypairs on all
/// targets. ECDSA P-256 is supported cross-platform and is appropriate for
/// client-authentication certificates.
const AGENT_KEY_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// CSR Generator for creating certificate signing requests.
///
/// Handles local keypair generation and CSR creation for the enrollment flow.
/// The private key is generated once and can be reused for certificate renewals.
pub struct CsrGenerator {
    key_pair: KeyPair,
}

impl CsrGenerator {
    /// Generate a new ECDSA P-256 keypair.
    ///
    /// The private key is generated using a secure random number generator.
    ///
    /// # Returns
    ///
    /// A new `CsrGenerator` containing the generated keypair.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tamandua_agent::pki::csr::CsrGenerator;
    ///
    /// let generator = CsrGenerator::new()?;
    /// let csr = generator.generate_csr("agent-123", "workstation.local")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new() -> Result<Self> {
        info!("Generating new ECDSA P-256 keypair");

        let key_pair = KeyPair::generate_for(AGENT_KEY_ALGORITHM)
            .context("Failed to generate ECDSA P-256 keypair")?;

        debug!("ECDSA P-256 keypair generated successfully");
        Ok(Self { key_pair })
    }

    /// Create a CsrGenerator from an existing private key PEM.
    ///
    /// Used for certificate renewal, where we want to reuse the existing keypair.
    ///
    /// # Arguments
    ///
    /// * `key_pem` - PEM-encoded private key
    pub fn from_pem(key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(key_pem).context("Failed to parse private key PEM")?;
        Ok(Self { key_pair })
    }

    /// Load an existing private key from PEM file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PEM-encoded private key file
    pub fn load_private_key(path: &Path) -> Result<Self> {
        info!("Loading private key from {:?}", path);
        let key_pem = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read private key from {:?}", path))?;
        Self::from_pem(&key_pem)
    }

    /// Generate a CSR with the agent_id as Common Name.
    ///
    /// The CSR includes:
    /// - Subject CN (Common Name) = agent_id
    /// - Subject O (Organization) = "Tamandua EDR"
    /// - SAN (Subject Alternative Name) with the hostname
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The unique agent identifier (used as CN)
    /// * `hostname` - The agent's hostname (added as SAN)
    ///
    /// # Returns
    ///
    /// The CSR in PEM format as bytes.
    pub fn generate_csr(&self, agent_id: &str, hostname: &str) -> Result<Vec<u8>> {
        info!(
            "Generating CSR for agent_id={}, hostname={}",
            agent_id, hostname
        );

        // Build distinguished name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, agent_id);
        distinguished_name.push(DnType::OrganizationName, "Tamandua EDR");

        // Build certificate parameters for CSR
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;

        // Add Subject Alternative Names
        params.subject_alt_names = vec![SanType::DnsName(
            hostname.try_into().context("Invalid hostname for SAN")?,
        )];

        // Generate the CSR
        let csr = params
            .serialize_request(&self.key_pair)
            .context("Failed to generate CSR")?;

        let csr_pem = csr.pem().context("Failed to encode CSR as PEM")?;

        debug!("CSR generated successfully ({} bytes)", csr_pem.len());

        Ok(csr_pem.into_bytes())
    }

    /// Save the private key to a file with restricted permissions.
    ///
    /// On Unix systems, the file is created with mode 0600 (owner read/write only).
    /// On Windows, standard file permissions are used (ACL-based restriction TODO).
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the private key should be saved
    ///
    /// # Security
    ///
    /// The private key is saved BEFORE any network calls to ensure it's not lost
    /// if enrollment fails partway through.
    pub fn save_private_key(&self, path: &Path) -> Result<()> {
        info!("Saving private key to {:?}", path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        let key_pem = self.key_pair.serialize_pem();

        // Write key file
        std::fs::write(path, &key_pem)
            .with_context(|| format!("Failed to write private key to {:?}", path))?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600); // Owner read/write only
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("Failed to set permissions on {:?}", path))?;
        }

        // TODO: On Windows, set ACLs to restrict access to SYSTEM and Administrators
        #[cfg(windows)]
        {
            debug!("Windows ACL restriction not yet implemented for private key");
        }

        info!("Private key saved successfully");
        Ok(())
    }

    /// Export private key as PEM string.
    ///
    /// Used for storing the key in memory or passing to TLS libraries.
    pub fn private_key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Get the public key in PEM format.
    pub fn public_key_pem(&self) -> String {
        self.key_pair.public_key_pem()
    }
}

/// Extract the Common Name (CN) from a CSR PEM.
///
/// This is used by the server to verify the agent_id in the CSR matches
/// the expected value.
///
/// Note: This is a simple parser that looks for the CN in the CSR subject.
/// For production use, consider using a proper ASN.1 parser.
pub fn extract_cn_from_csr(csr_pem: &[u8]) -> Result<String> {
    // rcgen doesn't have a CSR parser, so we'll parse it manually
    // The CSR subject is encoded in the PEM, but extracting it requires
    // ASN.1 parsing. For now, we'll rely on the server to do this properly.
    //
    // In the agent, we generate the CSR with a known agent_id, so we don't
    // need to parse it back. This function is mainly for server-side validation.
    //
    // A simple approach: look for CN in the decoded DER using basic pattern matching
    // This is a placeholder - the server should use proper X.509 parsing.

    let pem_str = std::str::from_utf8(csr_pem).context("CSR is not valid UTF-8")?;

    if !pem_str.contains("CERTIFICATE REQUEST") {
        bail!("Not a valid CSR PEM");
    }

    // For now, return an error indicating the server should parse this
    bail!("CN extraction should be done server-side with proper X.509 parsing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_keypair() {
        let generator = CsrGenerator::new().unwrap();
        let pem = generator.private_key_pem();
        assert!(pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_generate_csr() {
        let generator = CsrGenerator::new().unwrap();
        let csr = generator
            .generate_csr("test-agent-id", "test-host.local")
            .unwrap();

        // Verify it's valid PEM
        let csr_str = std::str::from_utf8(&csr).unwrap();
        assert!(csr_str.contains("CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_save_and_load_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        // Generate and save
        let generator = CsrGenerator::new().unwrap();
        let pem1 = generator.private_key_pem();
        generator.save_private_key(&key_path).unwrap();

        // Load
        let loaded = CsrGenerator::load_private_key(&key_path).unwrap();
        let pem2 = loaded.private_key_pem();

        // Keys should be identical
        assert_eq!(pem1, pem2);
    }

    #[test]
    fn test_from_pem() {
        let generator = CsrGenerator::new().unwrap();
        let pem = generator.private_key_pem();

        // Should be able to recreate from PEM
        let loaded = CsrGenerator::from_pem(&pem).unwrap();
        assert_eq!(pem, loaded.private_key_pem());
    }

    #[test]
    fn test_public_key_export() {
        let generator = CsrGenerator::new().unwrap();
        let pub_pem = generator.public_key_pem();

        assert!(pub_pem.contains("PUBLIC KEY"));
    }
}
