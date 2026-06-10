//! IPC authentication mechanism
//!
//! Authenticates GUI clients connecting to the service.
//! Uses a shared secret stored in a protected location with challenge-response protocol.
//!
//! ## Security Model
//!
//! 1. The service generates a random secret token at startup and stores it in a protected file.
//! 2. Windows: Token file has restrictive ACLs (SYSTEM + Administrators only).
//! 3. Unix: Token file has 0600 permissions (owner only).
//! 4. Authentication uses nonce-based challenge-response to prevent replay attacks:
//!    - Server sends a random challenge nonce + timestamp
//!    - Client computes HMAC-SHA256(challenge || timestamp, token_secret)
//!    - Server validates the HMAC and timestamp freshness (< 30 seconds)

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tracing::{debug, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Challenge validity window in seconds
const CHALLENGE_VALIDITY_SECONDS: u64 = 30;

/// Authentication token for IPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcToken {
    pub secret: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl IpcToken {
    /// Generate a new random token
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let secret: String = (0..32)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect();

        Self {
            secret,
            created_at: chrono::Utc::now(),
        }
    }

    /// Hash the token for verification (legacy method for backwards compatibility)
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.secret.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Challenge sent from server to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Random nonce (32 bytes, hex-encoded)
    pub nonce: String,
    /// Unix timestamp when challenge was created
    pub timestamp: u64,
}

impl AuthChallenge {
    /// Generate a new challenge
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce: String = (0..32)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self { nonce, timestamp }
    }

    /// Check if this challenge is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Challenge must be recent (within validity window)
        now.saturating_sub(self.timestamp) < CHALLENGE_VALIDITY_SECONDS
    }

    /// Compute the expected response for this challenge given a secret
    pub fn compute_response(&self, secret: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");

        // HMAC(nonce || timestamp, secret)
        mac.update(self.nonce.as_bytes());
        mac.update(&self.timestamp.to_le_bytes());

        hex::encode(mac.finalize().into_bytes())
    }
}

/// Response from client to server challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The nonce from the challenge (echoed back)
    pub nonce: String,
    /// The timestamp from the challenge (echoed back)
    pub timestamp: u64,
    /// HMAC-SHA256(nonce || timestamp, token_secret), hex-encoded
    pub signature: String,
}

impl ChallengeResponse {
    /// Create a response to a challenge using the token secret
    pub fn create(challenge: &AuthChallenge, secret: &str) -> Self {
        let signature = challenge.compute_response(secret);

        Self {
            nonce: challenge.nonce.clone(),
            timestamp: challenge.timestamp,
            signature,
        }
    }
}

/// IPC authenticator state for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Initial state - awaiting authentication
    Unauthenticated,
    /// Challenge sent, awaiting response
    ChallengeSent,
    /// Successfully authenticated
    Authenticated,
}

/// IPC authenticator
pub struct IpcAuthenticator {
    token: IpcToken,
    /// Current pending challenge for each connection (keyed by connection ID)
    pending_challenges: std::collections::HashMap<String, AuthChallenge>,
}

impl IpcAuthenticator {
    /// Create a new authenticator with a generated token
    pub fn new() -> Self {
        Self {
            token: IpcToken::generate(),
            pending_challenges: std::collections::HashMap::new(),
        }
    }

    /// Load authenticator from token file
    pub async fn from_file(path: &PathBuf) -> Result<Self> {
        let data = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read token file: {}", path.display()))?;

        let token: IpcToken = serde_json::from_str(&data).context("Failed to parse token file")?;

        // Existing installs may have older root-only permissions. Re-apply the
        // current platform ACL on startup so GUI recovery works after upgrade.
        super::acl::set_token_file_acl(path.as_path())?;

        debug!("Loaded IPC token from {}", path.display());

        Ok(Self {
            token,
            pending_challenges: std::collections::HashMap::new(),
        })
    }

    /// Save token to file with proper ACLs
    pub async fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let data =
            serde_json::to_string_pretty(&self.token).context("Failed to serialize token")?;

        fs::write(path, data)
            .await
            .with_context(|| format!("Failed to write token file: {}", path.display()))?;

        // Apply platform-specific ACLs
        super::acl::set_token_file_acl(path.as_path())?;

        info!(
            "Saved IPC token to {} with restrictive ACLs",
            path.display()
        );

        Ok(())
    }

    /// Verify a token hash (legacy method for backwards compatibility)
    pub fn verify(&self, provided_hash: &str) -> bool {
        let expected_hash = self.token.hash();

        // Constant-time comparison to prevent timing attacks
        constant_time_compare(provided_hash.as_bytes(), expected_hash.as_bytes())
    }

    /// Generate a new challenge for a connection
    pub fn create_challenge(&mut self, connection_id: &str) -> AuthChallenge {
        let challenge = AuthChallenge::generate();
        self.pending_challenges
            .insert(connection_id.to_string(), challenge.clone());

        debug!(
            "Created auth challenge for connection {}: nonce={}",
            connection_id, challenge.nonce
        );

        challenge
    }

    /// Verify a challenge response
    pub fn verify_response(&mut self, connection_id: &str, response: &ChallengeResponse) -> bool {
        // Get the pending challenge
        let challenge = match self.pending_challenges.remove(connection_id) {
            Some(c) => c,
            None => {
                warn!(
                    "No pending challenge for connection {}, rejecting",
                    connection_id
                );
                return false;
            }
        };

        // Verify nonce matches
        if response.nonce != challenge.nonce {
            warn!(
                "Challenge nonce mismatch for connection {}: expected {}, got {}",
                connection_id, challenge.nonce, response.nonce
            );
            return false;
        }

        // Verify timestamp matches
        if response.timestamp != challenge.timestamp {
            warn!(
                "Challenge timestamp mismatch for connection {}",
                connection_id
            );
            return false;
        }

        // Verify challenge is still valid (not expired)
        if !challenge.is_valid() {
            warn!(
                "Challenge expired for connection {} (timestamp: {})",
                connection_id, challenge.timestamp
            );
            return false;
        }

        // Compute expected signature
        let expected_signature = challenge.compute_response(&self.token.secret);

        // Constant-time comparison
        if !constant_time_compare(response.signature.as_bytes(), expected_signature.as_bytes()) {
            warn!(
                "Invalid signature for connection {} (replay attack or wrong token?)",
                connection_id
            );
            return false;
        }

        info!(
            "Successfully authenticated connection {} via challenge-response",
            connection_id
        );
        true
    }

    /// Remove a pending challenge (e.g., on disconnect)
    pub fn cancel_challenge(&mut self, connection_id: &str) {
        self.pending_challenges.remove(connection_id);
    }

    /// Get the token hash for client use (legacy)
    pub fn token_hash(&self) -> String {
        self.token.hash()
    }

    /// Get the raw token secret (for challenge-response auth)
    pub fn token_secret(&self) -> &str {
        &self.token.secret
    }

    /// Get the raw token (for initial client setup only)
    pub fn raw_token(&self) -> &str {
        &self.token.secret
    }

    /// Get default token file path
    pub fn default_token_path() -> PathBuf {
        #[cfg(windows)]
        {
            std::env::var_os("TAMANDUA_DATA_DIR")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join("Tamandua"))
                })
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Tamandua"))
                .join("ipc_token.json")
        }

        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/ipc_token.json")
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            PathBuf::from("/var/lib/tamandua/ipc_token.json")
        }
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

impl Default for IpcAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let token = IpcToken::generate();
        assert_eq!(token.secret.len(), 64); // 32 bytes in hex
    }

    #[test]
    fn test_token_verification() {
        let auth = IpcAuthenticator::new();
        let hash = auth.token_hash();

        assert!(auth.verify(&hash));
        assert!(!auth.verify("invalid_hash"));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hi"));
    }

    #[test]
    fn test_challenge_generation() {
        let challenge = AuthChallenge::generate();
        assert_eq!(challenge.nonce.len(), 64); // 32 bytes in hex
        assert!(challenge.timestamp > 0);
        assert!(challenge.is_valid());
    }

    #[test]
    fn test_challenge_response() {
        let secret = "test_secret_12345";
        let challenge = AuthChallenge::generate();
        let response = ChallengeResponse::create(&challenge, secret);

        // Verify signature is correct
        let expected = challenge.compute_response(secret);
        assert_eq!(response.signature, expected);
        assert_eq!(response.nonce, challenge.nonce);
        assert_eq!(response.timestamp, challenge.timestamp);
    }

    #[test]
    fn test_challenge_verification() {
        let mut auth = IpcAuthenticator::new();
        let conn_id = "test-conn-1";

        // Create challenge
        let challenge = auth.create_challenge(conn_id);

        // Create valid response
        let response = ChallengeResponse::create(&challenge, auth.token_secret());

        // Should verify successfully
        assert!(auth.verify_response(conn_id, &response));
    }

    #[test]
    fn test_challenge_wrong_secret() {
        let mut auth = IpcAuthenticator::new();
        let conn_id = "test-conn-2";

        // Create challenge
        let challenge = auth.create_challenge(conn_id);

        // Create response with wrong secret
        let response = ChallengeResponse::create(&challenge, "wrong_secret");

        // Should fail verification
        assert!(!auth.verify_response(conn_id, &response));
    }

    #[test]
    fn test_challenge_replay_prevention() {
        let mut auth = IpcAuthenticator::new();
        let conn_id = "test-conn-3";

        // Create challenge
        let challenge = auth.create_challenge(conn_id);

        // Create valid response
        let response = ChallengeResponse::create(&challenge, auth.token_secret());

        // First verification should succeed
        assert!(auth.verify_response(conn_id, &response));

        // Second verification should fail (challenge consumed)
        assert!(!auth.verify_response(conn_id, &response));
    }

    #[test]
    fn test_challenge_nonce_mismatch() {
        let mut auth = IpcAuthenticator::new();
        let conn_id = "test-conn-4";

        // Create challenge
        let challenge = auth.create_challenge(conn_id);

        // Create response with modified nonce
        let mut response = ChallengeResponse::create(&challenge, auth.token_secret());
        response.nonce =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        // Should fail verification
        assert!(!auth.verify_response(conn_id, &response));
    }

    #[tokio::test]
    async fn test_token_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let token_path = temp_dir.path().join("token.json");

        let auth = IpcAuthenticator::new();
        let original_hash = auth.token_hash();

        auth.save_to_file(&token_path).await.unwrap();

        let loaded_auth = IpcAuthenticator::from_file(&token_path).await.unwrap();
        let loaded_hash = loaded_auth.token_hash();

        assert_eq!(original_hash, loaded_hash);
    }
}
