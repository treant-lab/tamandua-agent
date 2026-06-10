//! Deception Technology Module - Enterprise Deception Platform
//!
//! Provides comprehensive deception capabilities comparable to
//! SentinelOne Singularity Hologram (formerly Attivo) or Illusive Networks.
//!
//! Features:
//! - Honeyfiles: Document, credential, config, database decoys
//! - Honey Tokens: Trackable fake credentials that alert on use
//! - Decoy Services: Fake SSH, RDP, HTTP, SMB honeypots
//! - Breadcrumbs: Distributed decoy artifacts across endpoints
//! - Cloud Deception: Fake AWS/Azure/GCP credentials
//! - Browser Deception: Fake saved passwords and cookies
//!
//! MITRE ATT&CK Coverage:
//! - T1552 (Unsecured Credentials)
//! - T1555 (Credentials from Password Stores)
//! - T1539 (Steal Web Session Cookie)
//! - T1021 (Remote Services)
//! - T1486 (Data Encrypted for Impact)

pub mod honeytokens;
pub mod services;
pub mod templates;

use crate::collectors::file::FileCollector;
use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, HoneyfileEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ============================================================================
// Deception Categories and Types
// ============================================================================

/// Deception category for grouping decoy types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeceptionCategory {
    /// Credential-based deception (passwords, keys, tokens)
    Credentials,
    /// Document-based deception (financial, HR, legal docs)
    Documents,
    /// Infrastructure deception (configs, database, network)
    Infrastructure,
    /// Cloud deception (AWS, Azure, GCP credentials)
    Cloud,
    /// Browser deception (saved passwords, cookies, sessions)
    Browser,
    /// Network services (SSH, RDP, SMB, HTTP honeypots)
    NetworkServices,
}

/// Honeyfile types for different attack detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HoneyfileType {
    /// Document files (ransomware bait)
    Document,
    /// Credential files (credential theft bait)
    Credential,
    /// Configuration files (lateral movement bait)
    Config,
    /// Database files (data exfiltration bait)
    Database,
    /// Source code files (IP theft bait)
    SourceCode,
    /// SSH private key
    SshKey,
    /// API token/key file
    ApiToken,
    /// Cloud credentials (AWS, Azure, GCP)
    CloudCredential,
    /// Browser saved passwords
    BrowserPassword,
    /// Browser cookies/sessions
    BrowserSession,
    /// Windows registry credentials
    RegistryCredential,
    /// Kubernetes config
    KubeConfig,
    /// Environment variables file
    EnvFile,
    /// SQLite database with decoy data
    SqliteDatabase,
    /// Network share mapping
    NetworkShare,
    /// Crypto wallet/keys
    CryptoWallet,
    /// VPN configuration
    VpnConfig,
    /// OAuth/JWT tokens
    OAuthToken,
}

impl HoneyfileType {
    /// Get file extension for this honeypot type
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Document => "docx",
            Self::Credential => "txt",
            Self::Config => "conf",
            Self::Database => "sql",
            Self::SourceCode => "py",
            Self::SshKey => "pem",
            Self::ApiToken => "json",
            Self::CloudCredential => "json",
            Self::BrowserPassword => "sqlite",
            Self::BrowserSession => "sqlite",
            Self::RegistryCredential => "reg",
            Self::KubeConfig => "yaml",
            Self::EnvFile => "env",
            Self::SqliteDatabase => "db",
            Self::NetworkShare => "lnk",
            Self::CryptoWallet => "dat",
            Self::VpnConfig => "ovpn",
            Self::OAuthToken => "json",
        }
    }

    /// Get filename prefix for this honeypot type
    pub fn filename_prefix(&self) -> &'static str {
        match self {
            Self::Document => "Financial_Report_2024",
            Self::Credential => "passwords",
            Self::Config => "vpn_config",
            Self::Database => "customer_backup",
            Self::SourceCode => "api_keys",
            Self::SshKey => "id_rsa_backup",
            Self::ApiToken => "api_credentials",
            Self::CloudCredential => "aws_credentials",
            Self::BrowserPassword => "logins",
            Self::BrowserSession => "cookies",
            Self::RegistryCredential => "cached_creds",
            Self::KubeConfig => "kubeconfig",
            Self::EnvFile => ".env.production",
            Self::SqliteDatabase => "users",
            Self::NetworkShare => "\\\\fileserver\\finance",
            Self::CryptoWallet => "wallet",
            Self::VpnConfig => "corporate_vpn",
            Self::OAuthToken => "oauth_tokens",
        }
    }

    /// Get MITRE ATT&CK techniques associated with this honeypot type
    pub fn mitre_techniques(&self) -> Vec<String> {
        match self {
            Self::Document => vec!["T1486".to_string(), "T1005".to_string()],
            Self::Credential => vec!["T1552.001".to_string(), "T1003".to_string()],
            Self::Config => vec!["T1021".to_string(), "T1570".to_string()],
            Self::Database => vec!["T1005".to_string(), "T1039".to_string()],
            Self::SourceCode => vec!["T1213".to_string(), "T1005".to_string()],
            Self::SshKey => vec!["T1552.004".to_string(), "T1021.004".to_string()],
            Self::ApiToken => vec!["T1552.001".to_string(), "T1550.001".to_string()],
            Self::CloudCredential => vec!["T1552.001".to_string(), "T1078.004".to_string()],
            Self::BrowserPassword => vec!["T1555.003".to_string(), "T1539".to_string()],
            Self::BrowserSession => vec!["T1539".to_string(), "T1550.004".to_string()],
            Self::RegistryCredential => vec!["T1552.002".to_string(), "T1003.002".to_string()],
            Self::KubeConfig => vec!["T1552.001".to_string(), "T1613".to_string()],
            Self::EnvFile => vec!["T1552.001".to_string()],
            Self::SqliteDatabase => vec!["T1005".to_string(), "T1555".to_string()],
            Self::NetworkShare => vec!["T1021.002".to_string(), "T1135".to_string()],
            Self::CryptoWallet => vec!["T1496".to_string(), "T1552.001".to_string()],
            Self::VpnConfig => vec!["T1133".to_string(), "T1552.001".to_string()],
            Self::OAuthToken => vec!["T1550.001".to_string(), "T1528".to_string()],
        }
    }

    /// Get MITRE tactics associated with this honeypot type
    pub fn mitre_tactics(&self) -> Vec<String> {
        match self {
            Self::Document => vec!["impact".to_string(), "collection".to_string()],
            Self::Credential
            | Self::SshKey
            | Self::ApiToken
            | Self::CloudCredential
            | Self::BrowserPassword
            | Self::RegistryCredential
            | Self::EnvFile
            | Self::OAuthToken
            | Self::VpnConfig => {
                vec![
                    "credential-access".to_string(),
                    "initial-access".to_string(),
                ]
            }
            Self::Config | Self::KubeConfig => {
                vec!["lateral-movement".to_string(), "discovery".to_string()]
            }
            Self::Database | Self::SourceCode | Self::SqliteDatabase => {
                vec!["collection".to_string(), "exfiltration".to_string()]
            }
            Self::BrowserSession => {
                vec!["credential-access".to_string(), "persistence".to_string()]
            }
            Self::NetworkShare => vec!["lateral-movement".to_string(), "discovery".to_string()],
            Self::CryptoWallet => vec!["impact".to_string(), "collection".to_string()],
        }
    }

    /// Get severity for detecting access to this honeypot type
    pub fn severity(&self) -> Severity {
        match self {
            Self::SshKey | Self::CloudCredential | Self::CryptoWallet | Self::OAuthToken => {
                Severity::Critical
            }
            Self::Credential
            | Self::ApiToken
            | Self::BrowserPassword
            | Self::RegistryCredential
            | Self::KubeConfig
            | Self::EnvFile
            | Self::VpnConfig => Severity::High,
            Self::Document
            | Self::Config
            | Self::Database
            | Self::SqliteDatabase
            | Self::NetworkShare => Severity::High,
            Self::BrowserSession | Self::SourceCode => Severity::Medium,
        }
    }

    /// Get the deception category for this honeypot type
    pub fn category(&self) -> DeceptionCategory {
        match self {
            Self::Credential | Self::SshKey | Self::ApiToken | Self::OAuthToken => {
                DeceptionCategory::Credentials
            }
            Self::Document | Self::SourceCode => DeceptionCategory::Documents,
            Self::Config
            | Self::Database
            | Self::KubeConfig
            | Self::EnvFile
            | Self::SqliteDatabase
            | Self::NetworkShare
            | Self::VpnConfig => DeceptionCategory::Infrastructure,
            Self::CloudCredential => DeceptionCategory::Cloud,
            Self::BrowserPassword | Self::BrowserSession | Self::RegistryCredential => {
                DeceptionCategory::Browser
            }
            Self::CryptoWallet => DeceptionCategory::Credentials,
        }
    }

    /// Get deployment path suggestions for this honeypot type
    pub fn deployment_paths(&self) -> Vec<&'static str> {
        match self {
            Self::SshKey => vec![".ssh", ".gnupg"],
            Self::CloudCredential => vec![".aws", ".azure", ".config/gcloud"],
            Self::KubeConfig => vec![".kube"],
            Self::BrowserPassword | Self::BrowserSession => {
                #[cfg(target_os = "windows")]
                {
                    vec![
                        r"AppData\Local\Google\Chrome\User Data\Default",
                        r"AppData\Local\Microsoft\Edge\User Data\Default",
                        r"AppData\Roaming\Mozilla\Firefox\Profiles",
                    ]
                }
                #[cfg(target_os = "macos")]
                {
                    vec![
                        "Library/Application Support/Google/Chrome/Default",
                        "Library/Application Support/Firefox/Profiles",
                        "Library/Safari",
                    ]
                }
                #[cfg(target_os = "linux")]
                {
                    vec![
                        ".config/google-chrome/Default",
                        ".mozilla/firefox",
                        ".config/chromium/Default",
                    ]
                }
                #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
                {
                    vec![]
                }
            }
            Self::VpnConfig => vec![".openvpn", ".config/vpn", "VPN"],
            Self::CryptoWallet => vec![".ethereum", ".bitcoin", ".config/solana", "Wallets"],
            Self::EnvFile => vec!["projects", "src", "app", "code"],
            _ => vec!["Documents", "Desktop", "Downloads"],
        }
    }
}

/// Honeyfile metadata
#[derive(Debug, Clone)]
pub struct Honeyfile {
    pub path: PathBuf,
    pub file_type: HoneyfileType,
    pub created_at: u64,
    pub canary_token: Option<String>,
}

/// Deception engine for honeyfile management
pub struct DeceptionEngine {
    config: AgentConfig,
    honeyfiles: HashMap<PathBuf, Honeyfile>,
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl DeceptionEngine {
    /// Create a new deception engine
    pub fn new(config: &AgentConfig, event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        Self {
            config: config.clone(),
            honeyfiles: HashMap::new(),
            event_tx,
        }
    }

    /// Initialize honeyfiles in monitored directories
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing deception engine");

        // Clone paths to avoid borrow issues
        let paths: Vec<String> = self.config.honeyfile_paths.clone();

        // Create honeyfiles in configured paths
        for base_path in paths {
            if let Err(e) = self.deploy_honeyfiles(&base_path).await {
                warn!(path = %base_path, error = %e, "Failed to deploy honeyfiles");
            }
        }

        // Start monitoring
        self.start_monitoring().await?;

        info!(count = self.honeyfiles.len(), "Honeyfiles deployed");
        Ok(())
    }

    async fn deploy_honeyfiles(&mut self, base_path: &str) -> Result<()> {
        let base = Path::new(base_path);

        if !base.exists() {
            std::fs::create_dir_all(base)?;
        }

        // Deploy different honeyfile types
        let types = vec![
            HoneyfileType::Document,
            HoneyfileType::Credential,
            HoneyfileType::Config,
        ];

        for file_type in types {
            let filename = format!(
                "{}_{}.{}",
                file_type.filename_prefix(),
                self.generate_realistic_suffix(),
                file_type.extension()
            );

            let path = base.join(&filename);

            if !path.exists() {
                let content = self.generate_honeyfile_content(&file_type);
                std::fs::write(&path, content)?;

                // Set file times to look legitimate
                self.set_realistic_timestamps(&path)?;

                // Hide from normal directory listings on Windows
                #[cfg(target_os = "windows")]
                self.set_hidden_attribute(&path)?;
            }

            let honeyfile = Honeyfile {
                path: path.clone(),
                file_type,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                canary_token: None,
            };

            self.honeyfiles.insert(path, honeyfile);
        }

        Ok(())
    }

    fn generate_realistic_suffix(&self) -> String {
        // Generate a suffix that looks like a real backup or version
        let suffixes = ["Q4", "final", "backup", "v2", "2024"];
        let idx = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize
            % suffixes.len();
        suffixes[idx].to_string()
    }

    fn generate_honeyfile_content(&self, file_type: &HoneyfileType) -> Vec<u8> {
        let canary_id = Uuid::new_v4().to_string();

        match file_type {
            HoneyfileType::Document => {
                let content = format!(
                    r#"PK   Financial Report Q4 2024

CONFIDENTIAL - Internal Use Only
Canary: TAMANDUA-{}

Revenue Summary:
- Total Revenue: $12,453,890.00
- Operating Expenses: $8,234,567.00
- Net Profit: $4,219,323.00

Key Accounts:
- Enterprise Client A: $2,340,000
- Government Contract B: $1,890,000
- Healthcare Division: $3,450,000

Banking Details (Wire Transfer):
Bank: First National Corp
Account: 4532-8876-2341
Routing: 021000089

Contact: CFO Office - finance@internal.corp
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::Credential => {
                let content = format!(
                    r#"# VPN Credentials - DO NOT SHARE
# Last updated: 2024-01-15
# Canary: TAMANDUA-{}

[Production VPN]
server = vpn.internal.corp.local
username = admin_backup
password = Tr0ub4dor&3
certificate = /etc/vpn/admin.pem

[Development VPN]
server = vpn-dev.internal.corp.local
username = devops_user
password = P@ssw0rd123!
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::Config => {
                let content = format!(
                    r#"# Internal Service Configuration
# Environment: Production
# Canary: TAMANDUA-{}

[database]
host = db-prod-master.internal
port = 5432
username = app_user
password = SuperS3cret!DB

[redis]
host = redis-prod.internal
port = 6379
auth = redis_auth_token_12345

[api]
key = sk_live_abcdef123456789
secret = shh_very_secret_key
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::Database => {
                let content = format!(
                    r#"-- Customer Database Backup
-- Generated: 2024-01-10
-- Canary: TAMANDUA-{}

CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255),
    credit_card VARCHAR(19),
    ssn VARCHAR(11)
);

INSERT INTO customers VALUES
(1, 'John Doe', 'john@example.com', '4111-1111-1111-1111', '123-45-6789'),
(2, 'Jane Smith', 'jane@example.com', '5500-0000-0000-0004', '987-65-4321');
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::SourceCode => {
                let content = format!(
                    r#"#!/usr/bin/env python3
# API Integration Module
# WARNING: Contains production credentials
# Canary: TAMANDUA-{}

API_KEY = "sk_live_production_key_12345"
API_SECRET = "secret_key_do_not_commit"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_customer_data(customer_id):
    # Production API endpoint
    endpoint = "https://api.internal.corp/v2/customers"
    headers = {{"Authorization": f"Bearer {{API_KEY}}"}}
    # ...
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::SshKey => {
                let content = format!(
                    r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA0Z3qX2BTLS4e5tqPN8EX4vMZq7VVb2QaOTTBx6W2KzG8RI2f5Xpk
m0QF9qI7KQHVVK8gOxQ7bBw0VZnKVGZMaU5cpRYNz7L0WBJC2Z1aHBxNLBxqXVdNLB
nK8WP2p3sOFz8Z7VpL4x2Z6L0n3WFdRqB3Q5UVXYZ4YZ7VL3QTAMANDUA-{}
-----END OPENSSH PRIVATE KEY-----
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::ApiToken => {
                let content = format!(
                    r#"{{
  "api_keys": {{
    "production": {{
      "key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
      "secret": "whsec_{}",
      "created": "2024-01-15T10:30:00Z",
      "permissions": ["read", "write", "admin"]
    }},
    "stripe": {{
      "publishable_key": "pk_live_TYooMQauvdEDq54NiTphI7jx",
      "secret_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    }},
    "sendgrid": {{
      "api_key": "SG.{}.TAMANDUA_CANARY"
    }},
    "_canary": "TAMANDUA-{}"
  }}
}}"#,
                    canary_id, canary_id, canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::CloudCredential => {
                let content = format!(
                    r#"[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIA{}
aws_secret_access_key = {}TAMANDUA{}
region = us-west-2

# Azure Service Principal
[azure]
client_id = 12345678-1234-1234-1234-123456789abc
client_secret = azureClientSecret{}
tenant_id = 87654321-4321-4321-4321-cba987654321

# GCP Service Account Key (reference)
# See: ~/.config/gcloud/application_default_credentials.json

# Canary Token: TAMANDUA-{}
"#,
                    &canary_id[..8],
                    &canary_id[..16],
                    &canary_id[16..24],
                    &canary_id[..8],
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::BrowserPassword => {
                // Fake SQLite database header with password data
                let content = format!(
                    r#"SQLite format 3
-- Browser Password Database (Chrome/Firefox format simulation)
-- Canary: TAMANDUA-{}

CREATE TABLE logins (
    origin_url TEXT NOT NULL,
    username_value TEXT,
    password_value BLOB,
    date_created INTEGER,
    times_used INTEGER
);

INSERT INTO logins VALUES
('https://mail.google.com/', 'admin@company.com', X'5472307562346430723a33', 13301234567890000, 150),
('https://github.com/', 'devops-admin', X'5375706572536563726574313233', 13302345678900000, 89),
('https://aws.amazon.com/', 'root-account', X'41575330776E6572526F6F74', 13303456789000000, 45),
('https://portal.azure.com/', 'azure-admin@company.onmicrosoft.com', X'417A7572654031323334', 13304567890000000, 67);
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::BrowserSession => {
                let content = format!(
                    r#"SQLite format 3
-- Browser Cookie/Session Database
-- Canary: TAMANDUA-{}

CREATE TABLE cookies (
    host_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER,
    is_secure INTEGER,
    is_httponly INTEGER
);

INSERT INTO cookies VALUES
('.google.com', 'SID', 'TAMANDUA_SESSION_{}', '/', 13400000000000000, 1, 1),
('.github.com', 'logged_in', 'yes', '/', 13400000000000000, 1, 1),
('.github.com', 'dotcom_user', 'enterprise-admin', '/', 13400000000000000, 1, 0),
('.microsoft.com', 'ESTSAUTH', 'azure_session_token_{}', '/', 13400000000000000, 1, 1);
"#,
                    canary_id,
                    &canary_id[..8],
                    &canary_id[..8]
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::RegistryCredential => {
                let content = format!(
                    r#"Windows Registry Editor Version 5.00
; Cached Credentials Export
; Canary: TAMANDUA-{}

[HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DefaultPassword]
"CurrVal"=hex:54,41,4d,41,4e,44,55,41,2d,{}

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"DefaultUserName"="DOMAIN\\Administrator"
"DefaultPassword"="Adm1nP@ssw0rd!123"
"AutoAdminLogon"="1"

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676]
"Password"=hex:50,40,73,73,77,30,72,64,21
"#,
                    canary_id,
                    &canary_id[..8]
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::KubeConfig => {
                let content = format!(
                    r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM...TAMANDUA{}
    server: https://k8s-prod.internal.company.com:6443
  name: production-cluster
- cluster:
    server: https://k8s-staging.internal.company.com:6443
  name: staging-cluster
contexts:
- context:
    cluster: production-cluster
    user: admin
    namespace: default
  name: production
- context:
    cluster: staging-cluster
    user: developer
    namespace: development
  name: staging
current-context: production
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IlRBTUFORFVBLXt9In0.TAMANDUA-{}-{}
- name: developer
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==
"#,
                    &canary_id[..8],
                    canary_id,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::EnvFile => {
                let content = format!(
                    r#"# Production Environment Variables
# DO NOT COMMIT TO VERSION CONTROL
# Canary: TAMANDUA-{}

NODE_ENV=production
SECRET_KEY={}
JWT_SECRET=jwt_secret_{}

# Database
DATABASE_URL=postgres://admin:SuperS3cr3t!@prod-db.internal:5432/production
REDIS_URL=redis://:redis_password_123@redis-prod.internal:6379/0

# Third-party API Keys
STRIPE_SECRET_KEY=sk_live_{}
SENDGRID_API_KEY=SG.{}.TAMANDUA
TWILIO_AUTH_TOKEN={}

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# OAuth
GITHUB_CLIENT_SECRET=github_secret_{}
GOOGLE_CLIENT_SECRET=GOCSPX-{}
"#,
                    canary_id,
                    &canary_id[..32],
                    &canary_id[..16],
                    &canary_id[..24],
                    &canary_id[..20],
                    &canary_id[..16],
                    &canary_id[..16],
                    &canary_id[..12]
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::SqliteDatabase => {
                // Generate a minimal SQLite database header with fake data
                let content = format!(
                    r#"SQLite format 3
-- Production User Database Backup
-- Generated: 2024-01-15
-- Canary: TAMANDUA-{}

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    role TEXT DEFAULT 'user',
    api_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users VALUES
(1, 'admin@company.com', '$2b$12$TAMANDUA{}...hash', 'System Administrator', 'superadmin', 'api_key_admin_{}', '2023-01-01 00:00:00'),
(2, 'cfo@company.com', '$2b$12$CFO_PASSWORD_HASH', 'Chief Financial Officer', 'executive', 'api_key_cfo_123', '2023-02-15 10:30:00'),
(3, 'devops@company.com', '$2b$12$DEVOPS_HASH', 'DevOps Lead', 'admin', 'api_key_devops_456', '2023-03-20 14:45:00');

CREATE TABLE credit_cards (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    card_number TEXT,
    expiry TEXT,
    cvv TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO credit_cards VALUES
(1, 1, '4111111111111111', '12/26', '123'),
(2, 2, '5500000000000004', '03/27', '456');
"#,
                    canary_id,
                    &canary_id[..8],
                    &canary_id[..12]
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::NetworkShare => {
                // Windows shortcut (.lnk) content simulation
                let content = format!(
                    r#"[InternetShortcut]
URL=file://fileserver.internal.corp/finance/confidential
IconFile=\\fileserver.internal.corp\icons\folder.ico
IconIndex=0

[Shell]
Command=2

; Network Share: \\fileserver\finance
; Credentials: domain\finance_admin / F1n@nce!2024
; Canary: TAMANDUA-{}
"#,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::CryptoWallet => {
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
  "_canary": "TAMANDUA-{}",
  "_note": "Bitcoin Recovery Phrase: abandon ability able about above absent absorb abstract absurd abuse access"
}}"#,
                    Uuid::new_v4(),
                    &canary_id[..40],
                    &canary_id,
                    &canary_id[..32],
                    &canary_id,
                    &canary_id,
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::VpnConfig => {
                let content = format!(
                    r#"client
dev tun
proto udp
remote vpn.internal.corp 1194
resolv-retry infinite
nobind
persist-key
persist-tun

# Authentication
auth-user-pass
# Saved credentials:
# Username: vpn_admin
# Password: VPN@dmin!2024

<ca>
-----BEGIN CERTIFICATE-----
MIIDkTAMANDUA{}CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIID{}TAMANDUA_CANARY_{}
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA{}TAMANDUA
-----END RSA PRIVATE KEY-----
</key>

# Canary: TAMANDUA-{}
"#,
                    &canary_id[..20],
                    &canary_id[..16],
                    &canary_id[..8],
                    &canary_id[..32],
                    canary_id
                );
                content.as_bytes().to_vec()
            }
            HoneyfileType::OAuthToken => {
                let content = format!(
                    r#"{{
  "tokens": {{
    "google": {{
      "access_token": "ya29.{}",
      "refresh_token": "1//{}",
      "token_uri": "https://oauth2.googleapis.com/token",
      "client_id": "123456789-abc.apps.googleusercontent.com",
      "client_secret": "GOCSPX-{}"
    }},
    "microsoft": {{
      "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.{}",
      "refresh_token": "M.R3_{}",
      "tenant_id": "87654321-4321-4321-4321-cba987654321"
    }},
    "github": {{
      "access_token": "ghp_{}",
      "scope": "repo,admin:org,admin:enterprise"
    }},
    "slack": {{
      "bot_token": "xoxb-{}",
      "user_token": "xoxp-{}"
    }}
  }},
  "_canary": "TAMANDUA-{}"
}}"#,
                    &canary_id[..40],
                    &canary_id[..32],
                    &canary_id[..16],
                    &canary_id[..24],
                    &canary_id[..20],
                    &canary_id[..40],
                    &canary_id[..24],
                    &canary_id[..24],
                    canary_id
                );
                content.as_bytes().to_vec()
            }
        }
    }

    fn set_realistic_timestamps(&self, path: &Path) -> Result<()> {
        // Set modification time to a few weeks ago
        let weeks_ago = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(60 * 60 * 24 * 14))
            .unwrap_or(std::time::SystemTime::now());

        #[cfg(unix)]
        {
            #[allow(unused_imports)]
            use std::os::unix::fs::MetadataExt;
            let secs = weeks_ago
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            // Use filetime crate in production
            let _ = secs; // Placeholder
        }

        Ok(())
    }

    #[cfg(windows)]
    fn set_hidden_attribute(&self, path: &Path) -> Result<()> {
        // Don't actually hide - we want them discoverable by attackers
        // but not cluttering normal user views
        // attrib +h would hide them
        Ok(())
    }

    async fn start_monitoring(&self) -> Result<()> {
        let honeyfile_paths: Vec<PathBuf> = self.honeyfiles.keys().cloned().collect();
        let event_tx = self.event_tx.clone();
        let honeyfiles = self.honeyfiles.clone();

        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();

            let mut watcher =
                match notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
                    if let Ok(event) = res {
                        let _ = tx.send(event);
                    }
                }) {
                    Ok(w) => w,
                    Err(e) => {
                        error!(error = %e, "Failed to create honeyfile watcher");
                        return;
                    }
                };

            // Watch each honeyfile
            for path in &honeyfile_paths {
                if let Some(parent) = path.parent() {
                    if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
                        warn!(path = %parent.display(), error = %e, "Failed to watch honeyfile directory");
                    }
                }
            }

            // Process events
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "Failed to create tokio runtime for honeyfile watcher");
                    return;
                }
            };

            for event in rx {
                for path in &event.paths {
                    if let Some(honeyfile) = honeyfiles.get(path) {
                        let telemetry_event = Self::create_alert(&event, honeyfile);
                        if rt.block_on(event_tx.send(telemetry_event)).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    fn create_alert(notify_event: &NotifyEvent, honeyfile: &Honeyfile) -> TelemetryEvent {
        let operation = match &notify_event.kind {
            EventKind::Access(_) => "read",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "delete",
            EventKind::Create(_) => "create",
            _ => "unknown",
        };

        let description = match operation {
            "read" => "Honeyfile read access detected - potential reconnaissance or data theft",
            "modify" => "Honeyfile modified - potential ransomware encryption",
            "delete" => "Honeyfile deleted - potential ransomware or evidence destruction",
            _ => "Honeyfile access detected",
        };

        let severity = match operation {
            "modify" | "delete" => Severity::Critical,
            "read" => Severity::High,
            _ => Severity::Medium,
        };

        // Correlate with the process that accessed the honeyfile
        let (pid, process_name, process_path) = FileCollector::find_process_for_file(
            &honeyfile.path,
        )
        .unwrap_or((0, String::new(), String::new()));

        let mut event = TelemetryEvent::new(
            EventType::HoneyfileAccess,
            severity,
            EventPayload::Honeyfile(HoneyfileEvent {
                path: honeyfile.path.to_string_lossy().to_string(),
                operation: operation.to_string(),
                pid,
                process_name,
                process_path,
                process_sha256: Vec::new(),
            }),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Honeyfile,
            rule_name: format!("honeyfile_{}", operation),
            confidence: 1.0,
            description: description.to_string(),
            mitre_tactics: vec!["impact".to_string(), "collection".to_string()],
            mitre_techniques: honeyfile.file_type.mitre_techniques(),
        });

        event
    }

    /// Get list of active honeyfiles
    pub fn list_honeyfiles(&self) -> Vec<&Honeyfile> {
        self.honeyfiles.values().collect()
    }

    /// Remove all honeyfiles (cleanup)
    pub fn cleanup(&mut self) -> Result<()> {
        for (path, _) in self.honeyfiles.drain() {
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

/// Canary token for tracking document exfiltration
pub struct CanaryToken {
    pub token_id: String,
    pub callback_url: String,
    pub created_at: u64,
}

impl CanaryToken {
    /// Generate a new canary token
    pub fn new(backend_url: &str) -> Self {
        let token_id = uuid::Uuid::new_v4().to_string();
        let callback_url = format!("{}/api/canary/{}", backend_url, token_id);

        Self {
            token_id,
            callback_url,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Generate HTML canary (image beacon)
    pub fn html_beacon(&self) -> String {
        format!(
            r#"<img src="{}" width="1" height="1" style="display:none" />"#,
            self.callback_url
        )
    }

    /// Generate Word document canary (external reference)
    pub fn docx_reference(&self) -> String {
        format!(
            r#"<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{}" TargetMode="External"/>"#,
            self.callback_url
        )
    }
}
