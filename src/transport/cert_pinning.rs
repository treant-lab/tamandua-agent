//! Certificate pinning for TLS connections to the Tamandua server.
//!
//! Prevents MITM attacks by validating the server's public key hash
//! against a set of pinned SHA-256 digests. Supports pin rotation by
//! allowing multiple pins; any single match is considered valid.
//!
//! When `enforce` is true, a pin mismatch terminates the TLS handshake.
//! When `enforce` is false (report-only mode), mismatches are logged via
//! `tracing::warn` but the connection proceeds. This allows gradual
//! rollout of pinning in production.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use tracing::warn;

/// A set of SHA-256 public key pins for certificate pinning.
///
/// Each pin is the SHA-256 hash of the DER-encoded SubjectPublicKeyInfo (SPKI)
/// of the server's leaf certificate. In practice, we hash the entire leaf
/// certificate DER for simplicity and consistency with HPKP-style pinning.
#[derive(Clone, Debug)]
pub struct CertPins {
    /// SHA-256 hashes of pinned certificates (DER-encoded)
    pins: Vec<[u8; 32]>,
    /// Whether to enforce pinning (false = report only)
    enforce: bool,
}

impl CertPins {
    /// Create from a list of base64-encoded SHA-256 hashes.
    ///
    /// Each string should be a standard base64 encoding of exactly 32 bytes
    /// (a SHA-256 digest). Returns an error if any hash decodes to a length
    /// other than 32 bytes.
    pub fn from_base64(hashes: &[String], enforce: bool) -> Result<Self> {
        let mut pins = Vec::with_capacity(hashes.len());
        for h in hashes {
            // Strip optional "sha256//" prefix (HPKP format)
            let hash_str = h.strip_prefix("sha256//").unwrap_or(h);
            let decoded = BASE64.decode(hash_str.as_bytes())?;
            if decoded.len() != 32 {
                bail!(
                    "Certificate pin hash must be 32 bytes (SHA-256), got {}",
                    decoded.len()
                );
            }
            let mut pin = [0u8; 32];
            pin.copy_from_slice(&decoded);
            pins.push(pin);
        }
        Ok(Self { pins, enforce })
    }

    /// Return the number of configured pins.
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// Return whether pinning is in enforcement mode.
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }

    /// Check if a certificate's DER encoding matches any pinned hash.
    ///
    /// Computes SHA-256 over the provided DER bytes and compares against all
    /// configured pins. Returns `true` if:
    /// - No pins are configured (pinning is effectively disabled), or
    /// - At least one pin matches the computed hash, or
    /// - Enforcement is disabled (`enforce = false`) -- the mismatch is logged
    ///   but the connection is allowed.
    ///
    /// Returns `false` only when enforcement is enabled and no pin matches.
    pub fn verify_cert_der(&self, cert_der: &[u8]) -> bool {
        if self.pins.is_empty() {
            // No pins configured -- pinning is disabled, allow everything
            return true;
        }

        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();
        let hash_bytes: [u8; 32] = hash.into();

        for pin in &self.pins {
            if &hash_bytes == pin {
                tracing::debug!(
                    pin_hash = %BASE64.encode(hash_bytes),
                    "Certificate pin verification succeeded"
                );
                return true;
            }
        }

        // No pin matched
        warn!(
            expected_pins = self.pins.len(),
            actual_hash = %BASE64.encode(hash_bytes),
            enforce = self.enforce,
            "Certificate pin verification FAILED - server certificate does not match any pinned hash"
        );

        // If not enforcing, allow but warn
        !self.enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pins_allows_everything() {
        let pins = CertPins::from_base64(&[], true).unwrap();
        assert!(pins.verify_cert_der(b"any certificate data"));
    }

    #[test]
    fn test_matching_pin_succeeds() {
        // Compute SHA-256 of test data and encode as base64
        let test_cert = b"test certificate DER data";
        let mut hasher = Sha256::new();
        hasher.update(test_cert);
        let hash = hasher.finalize();
        let pin_b64 = BASE64.encode(hash);

        let pins = CertPins::from_base64(&[pin_b64], true).unwrap();
        assert!(pins.verify_cert_der(test_cert));
    }

    #[test]
    fn test_non_matching_pin_fails_when_enforced() {
        let fake_pin = BASE64.encode([0u8; 32]);
        let pins = CertPins::from_base64(&[fake_pin], true).unwrap();
        assert!(!pins.verify_cert_der(b"actual certificate data"));
    }

    #[test]
    fn test_non_matching_pin_warns_when_not_enforced() {
        let fake_pin = BASE64.encode([0u8; 32]);
        let pins = CertPins::from_base64(&[fake_pin], false).unwrap();
        // Should return true (allow) even though pin doesn't match
        assert!(pins.verify_cert_der(b"actual certificate data"));
    }

    #[test]
    fn test_multiple_pins_any_match() {
        let test_cert = b"test certificate DER data";
        let mut hasher = Sha256::new();
        hasher.update(test_cert);
        let hash = hasher.finalize();
        let correct_pin = BASE64.encode(hash);
        let wrong_pin = BASE64.encode([0u8; 32]);

        let pins = CertPins::from_base64(&[wrong_pin, correct_pin], true).unwrap();
        assert!(pins.verify_cert_der(test_cert));
    }

    #[test]
    fn test_invalid_pin_length_rejected() {
        let bad_pin = BASE64.encode([0u8; 16]); // 16 bytes, not 32
        let result = CertPins::from_base64(&[bad_pin], true);
        assert!(result.is_err());
    }

    #[test]
    fn test_hpkp_prefix_stripped() {
        let test_cert = b"test certificate DER data";
        let mut hasher = Sha256::new();
        hasher.update(test_cert);
        let hash = hasher.finalize();
        let pin_with_prefix = format!("sha256//{}", BASE64.encode(hash));

        let pins = CertPins::from_base64(&[pin_with_prefix], true).unwrap();
        assert!(pins.verify_cert_der(test_cert));
    }
}
