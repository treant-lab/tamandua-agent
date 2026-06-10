//! Deception 2.0 - Advanced Honey Tokens
//!
//! Creates and monitors deceptive artifacts that trigger alerts when accessed:
//! - Fake credentials (AWS keys, SSH keys, database passwords)
//! - Fake configuration files
//! - Fake browser cookies/sessions
//! - Fake cryptocurrency wallets
//! - Fake internal documents
//! - Process canaries (fake sensitive processes)
//!
//! UNIQUE FEATURE: Goes beyond simple honeyfiles to include:
//! - Dynamic token generation
//! - Token diversity (different types for different attack scenarios)
//! - Breadcrumb trails (tokens that lead attackers to other tokens)
//! - Token telemetry (how/when/where accessed)
//!
//! MITRE ATT&CK Detection:
//! - T1552 (Unsecured Credentials)
//! - T1555 (Credentials from Password Stores)
//! - T1539 (Steal Web Session Cookie)

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, HoneyfileEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::info;

/// Types of honey tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoneyTokenType {
    /// Fake AWS credentials
    AwsCredentials,
    /// Fake SSH private key
    SshKey,
    /// Fake database credentials
    DatabaseCredentials,
    /// Fake API keys
    ApiKey,
    /// Fake browser cookies
    BrowserCookie,
    /// Fake cryptocurrency wallet
    CryptoWallet,
    /// Fake internal document
    InternalDocument,
    /// Fake configuration file
    ConfigFile,
    /// Fake password file
    PasswordFile,
    /// Fake Kubernetes config
    KubeConfig,
    /// Fake environment file
    EnvFile,
    /// Process canary (fake sensitive process)
    ProcessCanary,
}

impl HoneyTokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwsCredentials => "aws_credentials",
            Self::SshKey => "ssh_key",
            Self::DatabaseCredentials => "database_credentials",
            Self::ApiKey => "api_key",
            Self::BrowserCookie => "browser_cookie",
            Self::CryptoWallet => "crypto_wallet",
            Self::InternalDocument => "internal_document",
            Self::ConfigFile => "config_file",
            Self::PasswordFile => "password_file",
            Self::KubeConfig => "kube_config",
            Self::EnvFile => "env_file",
            Self::ProcessCanary => "process_canary",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::AwsCredentials | Self::ApiKey => "T1552.001",
            Self::SshKey => "T1552.004",
            Self::DatabaseCredentials | Self::PasswordFile => "T1552",
            Self::BrowserCookie => "T1539",
            Self::CryptoWallet => "T1555",
            Self::KubeConfig => "T1552.001",
            Self::EnvFile | Self::ConfigFile => "T1552.001",
            _ => "T1552",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::AwsCredentials | Self::SshKey | Self::CryptoWallet => Severity::Critical,
            Self::DatabaseCredentials | Self::ApiKey | Self::KubeConfig => Severity::High,
            Self::BrowserCookie | Self::PasswordFile | Self::EnvFile => Severity::High,
            _ => Severity::Medium,
        }
    }
}

/// A deployed honey token
#[derive(Debug, Clone)]
pub struct HoneyToken {
    /// Token ID
    pub id: String,
    /// Token type
    pub token_type: HoneyTokenType,
    /// File path where deployed
    pub path: PathBuf,
    /// Token content
    pub content: String,
    /// Unique marker for tracking
    pub marker: String,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Number of times accessed
    pub access_count: u32,
    /// Last access timestamp
    pub last_access: Option<u64>,
    /// Description
    pub description: String,
}

/// Honey token generator
pub struct HoneyTokenGenerator {
    /// Random seed for token generation
    seed: u64,
}

impl HoneyTokenGenerator {
    pub fn new() -> Self {
        Self {
            seed: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Generate a unique marker
    fn generate_marker(&mut self) -> String {
        self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        format!("TAMANDUA-{:016x}", self.seed)
    }

    /// Generate fake AWS credentials
    pub fn generate_aws_credentials(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"[default]
aws_access_key_id = AKIA{}
aws_secret_access_key = {}
# DO NOT SHARE - Internal Use Only
# Marker: {}
"#,
            self.random_string(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
            self.random_string(
                40,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
            marker
        );
        (content, marker)
    }

    /// Generate fake SSH private key
    pub fn generate_ssh_key(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
{}
{}
{}
-----END OPENSSH PRIVATE KEY-----
# Marker: {}"#,
            self.random_string(
                70,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
            self.random_string(
                70,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
            self.random_string(
                70,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
            marker
        );
        (content, marker)
    }

    /// Generate fake database credentials
    pub fn generate_database_credentials(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"# Database Configuration - CONFIDENTIAL
# Production Database Credentials
# Marker: {}

DB_HOST=prod-db-master.internal.company.com
DB_PORT=5432
DB_NAME=production_app
DB_USER=admin_{}
DB_PASSWORD={}
DB_SSL=require

# Replica for read operations
DB_REPLICA_HOST=prod-db-replica.internal.company.com
"#,
            marker,
            self.random_string(8, "abcdefghijklmnopqrstuvwxyz"),
            self.random_string(
                32,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
            )
        );
        (content, marker)
    }

    /// Generate fake API key
    pub fn generate_api_key(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"{{
  "api_keys": {{
    "production": {{
      "key": "sk-{}",
      "secret": "{}",
      "created": "2024-01-15T10:30:00Z",
      "permissions": ["read", "write", "admin"]
    }},
    "_marker": "{}"
  }}
}}"#,
            self.random_string(
                48,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
            self.random_string(
                64,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
            marker
        );
        (content, marker)
    }

    /// Generate fake cryptocurrency wallet
    pub fn generate_crypto_wallet(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"{{
  "version": 3,
  "id": "{}",
  "address": "0x{}",
  "crypto": {{
    "cipher": "aes-128-ctr",
    "ciphertext": "{}",
    "cipherparams": {{
      "iv": "{}"
    }},
    "kdf": "scrypt",
    "kdfparams": {{
      "dklen": 32,
      "n": 262144,
      "p": 1,
      "r": 8,
      "salt": "{}"
    }},
    "mac": "{}"
  }},
  "_marker": "{}"
}}"#,
            uuid::Uuid::new_v4(),
            self.random_string(40, "0123456789abcdef"),
            self.random_string(64, "0123456789abcdef"),
            self.random_string(32, "0123456789abcdef"),
            self.random_string(64, "0123456789abcdef"),
            self.random_string(64, "0123456789abcdef"),
            marker
        );
        (content, marker)
    }

    /// Generate fake Kubernetes config
    pub fn generate_kube_config(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: {}
    server: https://k8s-prod.internal.company.com:6443
  name: production-cluster
contexts:
- context:
    cluster: production-cluster
    user: admin
  name: production
current-context: production
users:
- name: admin
  user:
    token: {}
# Marker: {}"#,
            self.random_string(
                100,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
            self.random_string(
                100,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            ),
            marker
        );
        (content, marker)
    }

    /// Generate fake .env file
    pub fn generate_env_file(&mut self) -> (String, String) {
        let marker = self.generate_marker();
        let content = format!(
            r#"# Production Environment Variables
# DO NOT COMMIT TO VERSION CONTROL
# Marker: {}

NODE_ENV=production
SECRET_KEY={}
JWT_SECRET={}
ENCRYPTION_KEY={}

# Third-party API Keys
STRIPE_SECRET_KEY=sk_live_{}
SENDGRID_API_KEY=SG.{}
TWILIO_AUTH_TOKEN={}

# Database
DATABASE_URL=postgres://admin:{}@prod-db.internal:5432/production

# AWS
AWS_ACCESS_KEY_ID=AKIA{}
AWS_SECRET_ACCESS_KEY={}
"#,
            marker,
            self.random_string(
                64,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
            self.random_string(
                64,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
            self.random_string(32, "0123456789abcdef"),
            self.random_string(
                24,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
            self.random_string(
                50,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            ),
            self.random_string(32, "0123456789abcdef"),
            self.random_string(
                24,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%"
            ),
            self.random_string(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
            self.random_string(
                40,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            )
        );
        (content, marker)
    }

    fn random_string(&mut self, len: usize, charset: &str) -> String {
        let chars: Vec<char> = charset.chars().collect();
        let mut result = String::with_capacity(len);

        for _ in 0..len {
            self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = (self.seed as usize) % chars.len();
            result.push(chars[idx]);
        }

        result
    }
}

/// Honey token manager
pub struct HoneyTokenManager {
    config: AgentConfig,
    generator: HoneyTokenGenerator,
    tokens: HashMap<String, HoneyToken>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl HoneyTokenManager {
    /// Create a new honey token manager
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(100);

        Self {
            config: config.clone(),
            generator: HoneyTokenGenerator::new(),
            tokens: HashMap::new(),
            event_tx: tx,
            event_rx: rx,
        }
    }

    /// Deploy honey tokens across the system
    pub async fn deploy_all(&mut self) -> Result<Vec<PathBuf>> {
        let mut deployed = Vec::new();

        // Get deployment directories
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));

        // Deploy AWS credentials
        let aws_path = home_dir.join(".aws").join("credentials.bak");
        if let Ok(path) = self
            .deploy_token(HoneyTokenType::AwsCredentials, &aws_path)
            .await
        {
            deployed.push(path);
        }

        // Deploy SSH key
        let ssh_path = home_dir.join(".ssh").join("id_rsa_backup");
        if let Ok(path) = self.deploy_token(HoneyTokenType::SshKey, &ssh_path).await {
            deployed.push(path);
        }

        // Deploy database config
        let db_path = home_dir.join(".config").join("database.conf");
        if let Ok(path) = self
            .deploy_token(HoneyTokenType::DatabaseCredentials, &db_path)
            .await
        {
            deployed.push(path);
        }

        // Deploy .env file
        let env_path = home_dir.join("projects").join(".env.production");
        if let Ok(path) = self.deploy_token(HoneyTokenType::EnvFile, &env_path).await {
            deployed.push(path);
        }

        // Deploy crypto wallet
        let wallet_path = home_dir
            .join(".ethereum")
            .join("keystore")
            .join("backup-wallet.json");
        if let Ok(path) = self
            .deploy_token(HoneyTokenType::CryptoWallet, &wallet_path)
            .await
        {
            deployed.push(path);
        }

        // Deploy kube config
        let kube_path = home_dir.join(".kube").join("config.backup");
        if let Ok(path) = self
            .deploy_token(HoneyTokenType::KubeConfig, &kube_path)
            .await
        {
            deployed.push(path);
        }

        info!(count = deployed.len(), "Deployed honey tokens");
        Ok(deployed)
    }

    /// Deploy a single honey token
    pub async fn deploy_token(
        &mut self,
        token_type: HoneyTokenType,
        path: &PathBuf,
    ) -> Result<PathBuf> {
        // Create parent directory
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Generate content
        let (content, marker) = match token_type {
            HoneyTokenType::AwsCredentials => self.generator.generate_aws_credentials(),
            HoneyTokenType::SshKey => self.generator.generate_ssh_key(),
            HoneyTokenType::DatabaseCredentials => self.generator.generate_database_credentials(),
            HoneyTokenType::ApiKey => self.generator.generate_api_key(),
            HoneyTokenType::CryptoWallet => self.generator.generate_crypto_wallet(),
            HoneyTokenType::KubeConfig => self.generator.generate_kube_config(),
            HoneyTokenType::EnvFile => self.generator.generate_env_file(),
            _ => return Err(anyhow::anyhow!("Unsupported token type")),
        };

        // Write file
        tokio::fs::write(path, &content).await?;

        // Create token record
        let token = HoneyToken {
            id: uuid::Uuid::new_v4().to_string(),
            token_type,
            path: path.clone(),
            content: content.clone(),
            marker: marker.clone(),
            deployed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            access_count: 0,
            last_access: None,
            description: format!("{:?} honey token at {:?}", token_type, path),
        };

        self.tokens.insert(marker, token);

        info!(
            token_type = ?token_type,
            path = %path.display(),
            "Deployed honey token"
        );

        Ok(path.clone())
    }

    /// Check if a path is a honey token
    pub fn is_honey_token(&self, path: &str) -> Option<&HoneyToken> {
        self.tokens
            .values()
            .find(|t| t.path.to_string_lossy() == path)
    }

    /// Check if content contains a honey token marker
    pub fn check_content_for_markers(&self, content: &str) -> Option<&HoneyToken> {
        for (marker, token) in &self.tokens {
            if content.contains(marker) {
                return Some(token);
            }
        }
        None
    }

    /// Record token access
    pub async fn record_access(&mut self, marker: &str, accessor_pid: u32, accessor_name: &str) {
        // First update the token and clone what we need for the alert
        let token_clone = if let Some(token) = self.tokens.get_mut(marker) {
            token.access_count += 1;
            token.last_access = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            );
            Some(token.clone())
        } else {
            None
        };

        // Now create and send the alert using the cloned data
        if let Some(token) = token_clone {
            let event = self.create_access_alert(&token, accessor_pid, accessor_name);
            let _ = self.event_tx.send(event).await;
        }
    }

    fn create_access_alert(
        &self,
        token: &HoneyToken,
        accessor_pid: u32,
        accessor_name: &str,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::HoneyfileAccess,
            token.token_type.severity(),
            EventPayload::Honeyfile(HoneyfileEvent {
                path: token.path.to_string_lossy().to_string(),
                operation: "access".to_string(),
                pid: accessor_pid,
                process_name: accessor_name.to_string(),
                process_path: String::new(),
                process_sha256: Vec::new(),
            }),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Honeyfile,
            rule_name: format!("HoneyToken_{}", token.token_type.as_str()),
            confidence: 0.99,
            description: format!(
                "DECEPTION TRIGGERED: {} accessed {} (type: {:?})",
                accessor_name,
                token.path.display(),
                token.token_type
            ),
            mitre_tactics: vec!["Credential Access".to_string(), "Discovery".to_string()],
            mitre_techniques: vec![token.token_type.mitre_technique().to_string()],
        });

        event
            .metadata
            .insert("token_id".to_string(), token.id.clone());
        event.metadata.insert(
            "token_type".to_string(),
            token.token_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("access_count".to_string(), token.access_count.to_string());
        event
            .metadata
            .insert("marker".to_string(), token.marker.clone());

        event
    }

    /// Get all deployed tokens
    pub fn get_tokens(&self) -> &HashMap<String, HoneyToken> {
        &self.tokens
    }

    /// Get next alert event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}
