//! Ed25519 signature verification for update manifests and binaries.
//!
//! The server signs each [`UpdateManifest`] with an Ed25519 private key.
//! The agent embeds the corresponding public key at compile time and uses
//! it to verify manifest authenticity before downloading or installing
//! any update binary.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::{debug, error, info, warn};

/// Default Ed25519 public key for update verification (base64-encoded).
///
/// This is a placeholder development key. In production builds, this
/// should be replaced with the real release-signing public key via
/// the `TAMANDUA_UPDATE_PUBLIC_KEY` environment variable at build time.
const DEFAULT_PUBLIC_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

pub fn placeholder_key_allowed() -> bool {
    cfg!(debug_assertions)
        || matches!(
            std::env::var("TAMANDUA_ALLOW_INSECURE_UPDATE_KEY").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE")
        )
}

/// Return the configured update signing key, or the compiled-in default when
/// config is empty.
pub fn effective_public_key(configured_key: Option<&str>) -> &str {
    configured_key
        .filter(|k| !k.trim().is_empty())
        .unwrap_or(DEFAULT_PUBLIC_KEY_B64)
}

/// Ensure update signing is backed by a real key before starting updater loops.
///
/// Debug/dev builds may opt into the placeholder for local testing, but
/// release/prod builds fail closed until a real release-signing key is present.
pub fn ensure_non_placeholder_key(configured_key: Option<&str>) -> Result<()> {
    let effective_key = effective_public_key(configured_key);

    if is_placeholder_key(effective_key) && !placeholder_key_allowed() {
        bail!(
            "update signing public key is not configured; refusing to start updater with placeholder key"
        );
    }

    Ok(())
}

/// Check whether the given base64-encoded public key is the all-zeros
/// placeholder. This means no real signing key has been configured.
pub fn is_placeholder_key(key_b64: &str) -> bool {
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(key_b64.trim()) {
        Ok(bytes) => bytes.iter().all(|&b| b == 0),
        Err(_) => false,
    }
}

/// Log a startup diagnostic about the update signing key configuration.
///
/// Should be called once during agent initialization. Emits an ERROR
/// if no production key is configured (the placeholder all-zeros key
/// provides zero security).
pub fn warn_if_placeholder_key(configured_key: Option<&str>) {
    let effective_key = effective_public_key(configured_key);

    if is_placeholder_key(effective_key) {
        if placeholder_key_allowed() {
            error!(
                "UPDATE SIGNING KEY IS THE DEVELOPMENT PLACEHOLDER (all zeros). \
                 Updates will NOT be cryptographically verified. This is only allowed \
                 in debug/dev or with TAMANDUA_ALLOW_INSECURE_UPDATE_KEY=1. \
                 Set `updater.signing_public_key` in agent config or build with \
                 TAMANDUA_UPDATE_PUBLIC_KEY to embed the production key."
            );
        } else {
            error!(
                "FATAL UPDATE SIGNING CONFIGURATION: placeholder all-zero public key \
                 is configured in a release/prod build. Update verification will fail \
                 closed until a real Ed25519 public key is configured."
            );
        }
    } else {
        info!("Update signing key configured (non-placeholder)");
    }
}

/// Verify an Ed25519 signature over the given message bytes.
///
/// `public_key_b64` is the base64-encoded 32-byte Ed25519 public key.
/// `signature_b64` is the base64-encoded 64-byte Ed25519 signature.
/// `message` is the raw bytes that were signed.
pub fn verify_signature(public_key_b64: &str, signature_b64: &str, message: &[u8]) -> Result<()> {
    use base64::Engine;

    // Decode public key
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .context("Failed to decode public key from base64")?;

    if pk_bytes.len() != 32 {
        bail!(
            "Invalid public key length: expected 32 bytes, got {}",
            pk_bytes.len()
        );
    }

    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key byte conversion failed"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).context("Invalid Ed25519 public key")?;

    // Decode signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .context("Failed to decode signature from base64")?;

    if sig_bytes.len() != 64 {
        bail!(
            "Invalid signature length: expected 64 bytes, got {}",
            sig_bytes.len()
        );
    }

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature byte conversion failed"))?;
    let signature = Signature::from_bytes(&sig_array);

    // Verify
    verifying_key
        .verify(message, &signature)
        .context("Ed25519 signature verification failed")?;

    debug!("Ed25519 signature verified successfully");
    Ok(())
}

/// Verify an update manifest's signature using the configured (or default)
/// public key.
///
/// The manifest JSON (without the `signature` field) is the signed message.
/// This function reconstructs the canonical JSON, then verifies the
/// Ed25519 signature.
pub fn verify_manifest_signature(
    manifest_json_without_sig: &str,
    signature_b64: &str,
    configured_public_key: Option<&str>,
) -> Result<()> {
    let public_key = configured_public_key.unwrap_or(DEFAULT_PUBLIC_KEY_B64);

    if is_placeholder_key(public_key) {
        if placeholder_key_allowed() {
            warn!(
                "Verifying update manifest with PLACEHOLDER key; this is insecure \
                 and is only allowed for debug/dev builds"
            );
        } else {
            bail!(
                "Refusing to verify update manifest with placeholder update signing key in release/prod build"
            );
        }
    }

    info!("Verifying update manifest signature");
    verify_signature(
        public_key,
        signature_b64,
        manifest_json_without_sig.as_bytes(),
    )
    .context("Update manifest signature verification failed")?;

    info!("Update manifest signature is valid");
    Ok(())
}

/// Compute the SHA-256 hash of a file and return it as a lowercase hex string.
pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024]; // 64 KB buffer

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Verify that a file's SHA-256 hash matches the expected value.
pub fn verify_file_hash(path: &std::path::Path, expected_sha256: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    let expected = expected_sha256.to_lowercase();

    if actual != expected {
        bail!(
            "SHA-256 hash mismatch for {}: expected {}, got {}",
            path.display(),
            expected,
            actual
        );
    }

    info!(
        path = %path.display(),
        hash = %actual,
        "File hash verified successfully"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash_consistency() {
        // Create a temp file and hash it twice -- results should match
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_binary.bin");
        std::fs::write(&file_path, b"Hello, Tamandua!").unwrap();

        let hash1 = sha256_file(&file_path).unwrap();
        let hash2 = sha256_file(&file_path).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn test_verify_file_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.bin");
        std::fs::write(&file_path, b"content").unwrap();

        let result = verify_file_hash(
            &file_path,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_is_placeholder_key_detects_all_zeros() {
        assert!(is_placeholder_key(DEFAULT_PUBLIC_KEY_B64));
        assert!(is_placeholder_key(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ));
    }

    #[test]
    fn test_is_placeholder_key_rejects_real_key() {
        // A non-zero 32-byte key (first byte = 0x01)
        assert!(!is_placeholder_key(
            "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="
        ));
    }

    #[test]
    fn test_is_placeholder_key_handles_invalid_base64() {
        assert!(!is_placeholder_key("not-valid-base64!!!"));
    }
}
