//! Configuration signing and verification using Ed25519.
//!
//! Ensures that configuration updates received from the server have not been
//! tampered with in transit. The server signs config payloads with its private
//! key and the agent verifies using the pinned public key.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

/// Configuration signature envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    /// Base64-encoded config payload (JSON)
    pub payload: String,
    /// Base64-encoded Ed25519 signature of the payload bytes
    pub signature: String,
    /// Key ID for key rotation support
    pub key_id: String,
}

/// Config signature verifier with pinned public keys.
pub struct ConfigVerifier {
    /// Map of key_id -> VerifyingKey
    keys: Vec<(String, VerifyingKey)>,
    /// Whether to enforce verification (false = warn-only mode)
    enforce: bool,
}

impl ConfigVerifier {
    /// Create a new verifier from base64-encoded public keys.
    ///
    /// `keys` is a list of (key_id, base64_public_key) pairs.
    /// Multiple keys support rotation: any matching key_id with valid signature passes.
    pub fn new(keys: &[(String, String)], enforce: bool) -> Result<Self> {
        let mut parsed_keys = Vec::with_capacity(keys.len());

        for (key_id, b64_key) in keys {
            let key_bytes = BASE64
                .decode(b64_key.as_bytes())
                .context("Invalid base64 in public key")?;

            if key_bytes.len() != PUBLIC_KEY_LENGTH {
                bail!(
                    "Public key '{}' has wrong length: expected {}, got {}",
                    key_id,
                    PUBLIC_KEY_LENGTH,
                    key_bytes.len()
                );
            }

            let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
            key_array.copy_from_slice(&key_bytes);

            let verifying_key =
                VerifyingKey::from_bytes(&key_array).context("Invalid Ed25519 public key")?;

            parsed_keys.push((key_id.clone(), verifying_key));
        }

        Ok(Self {
            keys: parsed_keys,
            enforce,
        })
    }

    /// Verify a signed config envelope and return the payload if valid.
    pub fn verify(&self, signed: &SignedConfig) -> Result<String> {
        if self.keys.is_empty() {
            if self.enforce {
                bail!("No signing keys configured but verification is enforced");
            }
            tracing::warn!("No config signing keys configured - accepting unsigned config");
            return Ok(signed.payload.clone());
        }

        // Find the key matching key_id
        let key = self.keys.iter().find(|(id, _)| id == &signed.key_id);

        let (key_id, verifying_key) = match key {
            Some(k) => k,
            None => {
                let msg = format!(
                    "Config signed with unknown key_id '{}'. Known keys: {:?}",
                    signed.key_id,
                    self.keys.iter().map(|(id, _)| id).collect::<Vec<_>>()
                );
                if self.enforce {
                    bail!("{}", msg);
                }
                tracing::warn!("{}", msg);
                return Ok(signed.payload.clone());
            }
        };

        // Decode signature
        let sig_bytes = BASE64
            .decode(signed.signature.as_bytes())
            .context("Invalid base64 in signature")?;

        if sig_bytes.len() != SIGNATURE_LENGTH {
            bail!(
                "Signature has wrong length: expected {}, got {}",
                SIGNATURE_LENGTH,
                sig_bytes.len()
            );
        }

        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .context("Signature byte conversion failed")?,
        );

        // Verify signature over the raw payload bytes
        let payload_bytes = signed.payload.as_bytes();

        match verifying_key.verify(payload_bytes, &signature) {
            Ok(()) => {
                tracing::debug!(key_id = %key_id, "Config signature verified successfully");
                Ok(signed.payload.clone())
            }
            Err(e) => {
                let msg = format!(
                    "Config signature verification FAILED (key_id='{}'): {}",
                    key_id, e
                );
                if self.enforce {
                    bail!("{}", msg);
                }
                tracing::warn!("{}", msg);
                Ok(signed.payload.clone())
            }
        }
    }

    /// Check if any keys are configured.
    pub fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_b64 = BASE64.encode(signing_key.verifying_key().as_bytes());
        (signing_key, public_key_b64)
    }

    #[test]
    fn test_valid_signature() {
        let (signing_key, pub_b64) = create_test_keypair();

        let verifier = ConfigVerifier::new(&[("test-key".to_string(), pub_b64)], true).unwrap();

        let payload = r#"{"collector_interval": 5}"#;
        let signature = signing_key.sign(payload.as_bytes());

        let signed = SignedConfig {
            payload: payload.to_string(),
            signature: BASE64.encode(signature.to_bytes()),
            key_id: "test-key".to_string(),
        };

        let result = verifier.verify(&signed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_invalid_signature() {
        let (_signing_key, pub_b64) = create_test_keypair();
        let (other_key, _) = create_test_keypair();

        let verifier = ConfigVerifier::new(&[("test-key".to_string(), pub_b64)], true).unwrap();

        let payload = "test payload";
        let bad_signature = other_key.sign(payload.as_bytes());

        let signed = SignedConfig {
            payload: payload.to_string(),
            signature: BASE64.encode(bad_signature.to_bytes()),
            key_id: "test-key".to_string(),
        };

        let result = verifier.verify(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_key_id_enforce_mode() {
        let (_signing_key, pub_b64) = create_test_keypair();

        let verifier = ConfigVerifier::new(
            &[("key-1".to_string(), pub_b64)],
            true, // enforce
        )
        .unwrap();

        let signed = SignedConfig {
            payload: "test".to_string(),
            signature: BASE64.encode([0u8; 64]),
            key_id: "unknown-key".to_string(),
        };

        // Should fail in enforce mode
        let result = verifier.verify(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_key_id_warn_mode() {
        let (_signing_key, pub_b64) = create_test_keypair();

        let verifier = ConfigVerifier::new(
            &[("key-1".to_string(), pub_b64)],
            false, // warn only
        )
        .unwrap();

        let signed = SignedConfig {
            payload: "test".to_string(),
            signature: BASE64.encode([0u8; 64]),
            key_id: "unknown-key".to_string(),
        };

        // Should succeed in warn mode
        let result = verifier.verify(&signed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_keys_warn_mode() {
        let verifier = ConfigVerifier::new(&[], false).unwrap();

        let signed = SignedConfig {
            payload: "anything".to_string(),
            signature: BASE64.encode([0u8; 64]),
            key_id: "any".to_string(),
        };

        let result = verifier.verify(&signed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "anything");
    }

    #[test]
    fn test_no_keys_enforce_mode() {
        let verifier = ConfigVerifier::new(&[], true).unwrap();

        let signed = SignedConfig {
            payload: "anything".to_string(),
            signature: BASE64.encode([0u8; 64]),
            key_id: "any".to_string(),
        };

        let result = verifier.verify(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_keys_rotation() {
        let (key1, pub1_b64) = create_test_keypair();
        let (key2, pub2_b64) = create_test_keypair();

        let verifier = ConfigVerifier::new(
            &[
                ("key-v1".to_string(), pub1_b64),
                ("key-v2".to_string(), pub2_b64),
            ],
            true,
        )
        .unwrap();

        // Sign with key2
        let payload = r#"{"version": 2}"#;
        let signature = key2.sign(payload.as_bytes());

        let signed = SignedConfig {
            payload: payload.to_string(),
            signature: BASE64.encode(signature.to_bytes()),
            key_id: "key-v2".to_string(),
        };

        let result = verifier.verify(&signed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload);

        // Sign with key1
        let sig1 = key1.sign(payload.as_bytes());
        let signed1 = SignedConfig {
            payload: payload.to_string(),
            signature: BASE64.encode(sig1.to_bytes()),
            key_id: "key-v1".to_string(),
        };

        let result1 = verifier.verify(&signed1);
        assert!(result1.is_ok());
    }

    #[test]
    fn test_tampered_payload() {
        let (signing_key, pub_b64) = create_test_keypair();

        let verifier = ConfigVerifier::new(&[("test-key".to_string(), pub_b64)], true).unwrap();

        let original_payload = r#"{"setting": "safe_value"}"#;
        let signature = signing_key.sign(original_payload.as_bytes());

        // Tamper with the payload after signing
        let signed = SignedConfig {
            payload: r#"{"setting": "malicious_value"}"#.to_string(),
            signature: BASE64.encode(signature.to_bytes()),
            key_id: "test-key".to_string(),
        };

        let result = verifier.verify(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base64_key() {
        let result = ConfigVerifier::new(
            &[("bad-key".to_string(), "not-valid-base64!!!".to_string())],
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_length() {
        let short_key = BASE64.encode(&[0u8; 16]); // 16 bytes, not 32
        let result = ConfigVerifier::new(&[("short-key".to_string(), short_key)], true);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_keys() {
        let (_, pub_b64) = create_test_keypair();

        let empty_verifier = ConfigVerifier::new(&[], true).unwrap();
        assert!(!empty_verifier.has_keys());

        let verifier = ConfigVerifier::new(&[("k".to_string(), pub_b64)], true).unwrap();
        assert!(verifier.has_keys());
    }
}
