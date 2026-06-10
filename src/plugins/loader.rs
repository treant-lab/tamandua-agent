//! Plugin Loader and Signature Verification
//!
//! This module handles loading plugins from disk and verifying their Ed25519 signatures.

use anyhow::{Context, Result};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use std::path::Path;
use tracing::{debug, info};

/// Verify plugin signature
pub fn verify_signature(
    wasm_path: &Path,
    signature_path: &Path,
    public_key_hex: &str,
) -> Result<()> {
    info!(
        wasm_path = ?wasm_path,
        signature_path = ?signature_path,
        "Verifying plugin signature"
    );

    // Read WASM module
    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("Failed to read WASM module: {:?}", wasm_path))?;

    // Read signature
    let signature_bytes = std::fs::read(signature_path)
        .with_context(|| format!("Failed to read signature: {:?}", signature_path))?;

    if signature_bytes.len() != 64 {
        anyhow::bail!(
            "Invalid signature length: {} (expected 64)",
            signature_bytes.len()
        );
    }

    let signature = Signature::from_bytes(&signature_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;

    // Parse public key
    let public_key_bytes =
        hex::decode(public_key_hex).context("Failed to decode public key hex")?;

    if public_key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid public key length: {} (expected 32)",
            public_key_bytes.len()
        );
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&public_key_bytes);

    let public_key = PublicKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key format: {}", e))?;

    // Verify signature
    public_key
        .verify(&wasm_bytes, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    info!("Plugin signature verified successfully");

    Ok(())
}

/// Sign plugin (for plugin developers)
#[cfg(test)]
pub fn sign_plugin(wasm_path: &Path, secret_key_hex: &str) -> Result<Vec<u8>> {
    use ed25519_dalek::SecretKey;
    use ed25519_dalek::Signer;

    // Read WASM module
    let wasm_bytes = std::fs::read(wasm_path)?;

    // Parse secret key
    let secret_key_bytes = hex::decode(secret_key_hex)?;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_key_bytes);

    let secret_key = SecretKey::from_bytes(&key_bytes)?;
    let public_key = PublicKey::from(&secret_key);
    let keypair = ed25519_dalek::Keypair {
        secret: secret_key,
        public: public_key,
    };

    // Sign
    let signature = keypair.sign(&wasm_bytes);

    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_signature_verification() {
        // Generate keypair
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        // Create dummy WASM file
        let mut wasm_file = NamedTempFile::new().unwrap();
        wasm_file.write_all(b"\0asm\x01\x00\x00\x00").unwrap();

        // Sign
        let signature =
            sign_plugin(wasm_file.path(), &hex::encode(keypair.secret.to_bytes())).unwrap();

        // Write signature
        let mut sig_file = NamedTempFile::new().unwrap();
        sig_file.write_all(&signature).unwrap();

        // Verify
        let result = verify_signature(
            wasm_file.path(),
            sig_file.path(),
            &hex::encode(keypair.public.to_bytes()),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_key() {
        // Generate two keypairs
        let mut csprng = OsRng {};
        let keypair1: Keypair = Keypair::generate(&mut csprng);
        let keypair2: Keypair = Keypair::generate(&mut csprng);

        // Create dummy WASM file
        let mut wasm_file = NamedTempFile::new().unwrap();
        wasm_file.write_all(b"\0asm\x01\x00\x00\x00").unwrap();

        // Sign with keypair1
        let signature =
            sign_plugin(wasm_file.path(), &hex::encode(keypair1.secret.to_bytes())).unwrap();

        // Write signature
        let mut sig_file = NamedTempFile::new().unwrap();
        sig_file.write_all(&signature).unwrap();

        // Verify with keypair2 (should fail)
        let result = verify_signature(
            wasm_file.path(),
            sig_file.path(),
            &hex::encode(keypair2.public.to_bytes()),
        );

        assert!(result.is_err());
    }
}
