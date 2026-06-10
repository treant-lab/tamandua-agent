//! JWT Token lifecycle management with automatic rotation.
//!
//! Handles:
//! - Token expiration monitoring
//! - Automatic refresh before expiration (at 60% of TTL)
//! - Retry logic with exponential backoff
//! - Fallback to re-enrollment if refresh fails
//! - Persistence of new tokens to config
//!
//! ## Architecture
//!
//! The token manager runs as a background task that:
//! 1. Periodically checks token expiration (every 5 minutes)
//! 2. Refreshes token when it reaches 60% of its TTL
//! 3. Retries failed refreshes with exponential backoff (5s, 10s, 20s)
//! 4. Falls back to re-enrollment if all retries fail
//! 5. Persists new tokens to the agent config file
//!
//! ## Security
//!
//! - Tokens are refreshed in-place (no manual intervention required)
//! - Old tokens are immediately invalidated server-side on refresh
//! - Failed refresh attempts are logged for audit
//! - Re-enrollment requires valid installation token

// JWT token lifecycle. Scaffolded telemetry fields retained for future
// audit/alerting paths.
#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use super::windows_tamandua_data_dir;

/// Token refresh request sent to backend
#[derive(Debug, Serialize)]
struct RefreshRequest {}

/// Token refresh response from backend
#[derive(Debug, Deserialize)]
struct RefreshResponse {
    token: String,
    expires_at: String,
    generation: i64,
    refresh_count: i64,
    #[serde(default)]
    message: String,
}

/// Token status response from backend
#[derive(Debug, Deserialize)]
struct TokenStatusResponse {
    valid: bool,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    generation: i64,
    #[serde(default)]
    expires_at: String,
    #[serde(default)]
    refresh_eligible: bool,
    #[serde(default)]
    time_to_expiry_seconds: i64,
    #[serde(default)]
    percent_elapsed: f64,
}

/// Token manager configuration
#[derive(Debug, Clone)]
pub struct TokenManagerConfig {
    /// Server base URL (e.g., https://edr.company.com)
    pub server_url: String,
    /// Path to agent config file for persisting new tokens
    pub config_path: PathBuf,
    /// Check interval in seconds (default: 300 = 5 minutes)
    pub check_interval_seconds: u64,
    /// Refresh window percentage (default: 60 = refresh at 60% of TTL)
    pub refresh_window_percent: u8,
    /// Maximum refresh retries before fallback to re-enrollment
    pub max_retries: u32,
    /// Installation token for re-enrollment fallback
    pub installation_token: Option<String>,
}

impl Default for TokenManagerConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            config_path: PathBuf::new(),
            check_interval_seconds: 300, // 5 minutes
            refresh_window_percent: 60,
            max_retries: 3,
            installation_token: None,
        }
    }
}

/// Token manager state
pub struct TokenManager {
    config: TokenManagerConfig,
    current_token: Arc<RwLock<String>>,
    agent_id: String,
    http_client: reqwest::Client,
    shutdown: Arc<tokio::sync::Notify>,
}

impl TokenManager {
    /// Create a new token manager
    pub fn new(
        agent_id: String,
        initial_token: String,
        mut config: TokenManagerConfig,
    ) -> Result<Self> {
        if !config.server_url.is_empty() {
            config.server_url = extract_http_base(&config.server_url)?;
        }

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(cfg!(debug_assertions))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            config,
            current_token: Arc::new(RwLock::new(initial_token)),
            agent_id,
            http_client,
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Start the token manager background task
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();

        tokio::spawn(async move {
            info!("Token manager started for agent {}", manager.agent_id);
            manager.run().await;
            info!("Token manager stopped for agent {}", manager.agent_id);
        })
    }

    /// Stop the token manager
    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }

    /// Get the current token
    pub async fn get_token(&self) -> String {
        self.current_token.read().await.clone()
    }

    /// Update the current token (called after successful refresh)
    async fn update_token(&self, new_token: String) -> Result<()> {
        // Update in-memory token
        {
            let mut token = self.current_token.write().await;
            *token = new_token.clone();
        }

        // Persist to config file
        self.persist_token(&new_token).await?;

        info!("Token updated successfully for agent {}", self.agent_id);
        Ok(())
    }

    /// Main run loop
    async fn run(&self) {
        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.check_interval_seconds));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.check_and_refresh().await {
                        error!("Token check/refresh failed: {}", e);
                    }
                }

                _ = self.shutdown.notified() => {
                    info!("Token manager shutdown requested");
                    break;
                }
            }
        }
    }

    /// Check token expiration and refresh if needed
    async fn check_and_refresh(&self) -> Result<()> {
        // Get token status from backend
        let status = match self.get_token_status().await {
            Ok(status) => status,
            Err(error) if Self::is_refreshable_status_error(&error) => {
                warn!(
                    error = %error,
                    "Token status check was rejected; attempting auth refresh"
                );
                return self.refresh_with_retry().await;
            }
            Err(error) if Self::is_transient_status_error(&error) => {
                warn!(
                    error = %error,
                    "Token status check temporarily unavailable; keeping current token"
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        if !status.valid {
            warn!(
                "Token is invalid for agent {}. Attempting refresh...",
                self.agent_id
            );
            return self.refresh_with_retry().await;
        }

        if status.refresh_eligible {
            info!(
                "Token is {:.1}% through its lifetime, initiating refresh (agent: {})",
                status.percent_elapsed, self.agent_id
            );
            return self.refresh_with_retry().await;
        }

        debug!(
            "Token is valid. {:.1}% through lifetime, {} seconds to expiry (agent: {})",
            status.percent_elapsed, status.time_to_expiry_seconds, self.agent_id
        );

        Ok(())
    }

    fn is_refreshable_status_error(error: &anyhow::Error) -> bool {
        let message = error.to_string();
        message.contains("401")
            || message.contains("403")
            || message.contains("Unauthorized")
            || message.contains("Forbidden")
            || message.contains("token_expired")
            || message.contains("credential_expired")
            || message.contains("invalid_token")
    }

    fn is_transient_status_error(error: &anyhow::Error) -> bool {
        let message = error.to_string();
        message.contains("500")
            || message.contains("502")
            || message.contains("503")
            || message.contains("504")
            || message.contains("database_error")
            || message.contains("internal_server_error")
            || message.contains("Failed to connect")
            || message.contains("operation timed out")
            || message.contains("request timed out")
            || message.contains("deadline has elapsed")
    }

    /// Get token status from backend
    async fn get_token_status(&self) -> Result<TokenStatusResponse> {
        let url = format!("{}/api/v1/agents/auth/status", self.config.server_url);
        let token = self.get_token().await;

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("Failed to connect to backend")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Token status check failed (HTTP {}): {}",
                status,
                body
            ));
        }

        response
            .json::<TokenStatusResponse>()
            .await
            .context("Failed to parse token status response")
    }

    /// Refresh token with retry logic
    pub async fn refresh_with_retry(&self) -> Result<()> {
        let mut attempt = 0;

        while attempt < self.config.max_retries {
            attempt += 1;

            match self.refresh_token().await {
                Ok(new_token) => {
                    info!(
                        "Token refreshed successfully on attempt {}/{} (agent: {})",
                        attempt, self.config.max_retries, self.agent_id
                    );
                    return self.update_token(new_token).await;
                }
                Err(e) => {
                    error!(
                        "Token refresh failed on attempt {}/{} (agent: {}): {}",
                        attempt, self.config.max_retries, self.agent_id, e
                    );

                    if attempt < self.config.max_retries {
                        // Exponential backoff: 5s, 10s, 20s
                        let delay_secs = 5 * (1 << (attempt - 1));
                        warn!(
                            "Retrying token refresh in {} seconds... (agent: {})",
                            delay_secs, self.agent_id
                        );
                        sleep(Duration::from_secs(delay_secs)).await;
                    }
                }
            }
        }

        // All retries failed - attempt re-enrollment if installation token is available
        error!(
            "All token refresh attempts failed for agent {}. Falling back to re-enrollment...",
            self.agent_id
        );

        if let Some(ref install_token) = self.config.installation_token {
            self.re_enroll(install_token).await
        } else {
            Err(anyhow!(
                "Token refresh failed and no installation token available for re-enrollment"
            ))
        }
    }

    /// Refresh the token by calling the backend refresh endpoint
    async fn refresh_token(&self) -> Result<String> {
        let url = format!("{}/api/v1/agents/auth/refresh", self.config.server_url);
        let token = self.get_token().await;

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&RefreshRequest {})
            .send()
            .await
            .context("Failed to connect to backend")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed (HTTP {}): {}", status, body));
        }

        let refresh_response = response
            .json::<RefreshResponse>()
            .await
            .context("Failed to parse refresh response")?;

        info!(
            "Token refreshed: generation {}, refresh count {}, expires at {} (agent: {})",
            refresh_response.generation,
            refresh_response.refresh_count,
            refresh_response.expires_at,
            self.agent_id
        );

        Ok(refresh_response.token)
    }

    /// Re-enroll the agent using installation token and CSR-based mTLS issuance.
    async fn re_enroll(&self, installation_token: &str) -> Result<()> {
        use crate::installer::token::{enroll_with_csr, CsrEnrollmentResponse};

        warn!(
            "Re-enrolling agent {} with installation token...",
            self.agent_id
        );

        let enrollment: CsrEnrollmentResponse = enroll_with_csr(
            &self.config.server_url,
            installation_token,
            Some(&self.agent_id),
        )
        .await
        .context("CSR re-enrollment failed")?;

        info!(
            "CSR re-enrollment successful. Agent ID: {}, org_id: {}",
            enrollment.agent_id, enrollment.org_id
        );

        if enrollment.agent_id != self.agent_id {
            warn!(
                old_agent_id = %self.agent_id,
                new_agent_id = %enrollment.agent_id,
                "Backend returned a different agent_id during re-enrollment; persisted config will use the backend value"
            );
        }

        let cert_paths = default_cert_paths();
        self.update_enrollment(&enrollment, &cert_paths).await?;

        Ok(())
    }

    /// Update in-memory token and persist full enrollment state.
    async fn update_enrollment(
        &self,
        enrollment: &crate::installer::token::CsrEnrollmentResponse,
        cert_paths: &DefaultCertPaths,
    ) -> Result<()> {
        {
            let mut token = self.current_token.write().await;
            *token = enrollment.jwt.clone();
        }

        self.persist_enrollment(enrollment, cert_paths).await?;

        info!(
            "Enrollment updated successfully for agent {}",
            enrollment.agent_id
        );
        Ok(())
    }

    /// Persist the new token to the agent config file
    async fn persist_token(&self, new_token: &str) -> Result<()> {
        use crate::config::AgentConfig;

        // Read current config
        let config_str = tokio::fs::read_to_string(&self.config.config_path)
            .await
            .context("Failed to read agent config")?;

        let mut config: AgentConfig =
            toml::from_str(&config_str).context("Failed to parse agent config")?;

        // Update token
        config.auth_token = Some(new_token.to_string());

        // Write back to file
        let new_config_str =
            toml::to_string_pretty(&config).context("Failed to serialize config")?;

        tokio::fs::write(&self.config.config_path, new_config_str)
            .await
            .context("Failed to write agent config")?;

        info!(
            "Persisted new token to config file: {}",
            self.config.config_path.display()
        );

        Ok(())
    }

    /// Persist agent identity, JWT, org and mTLS paths after CSR re-enrollment.
    async fn persist_enrollment(
        &self,
        enrollment: &crate::installer::token::CsrEnrollmentResponse,
        cert_paths: &DefaultCertPaths,
    ) -> Result<()> {
        use crate::config::AgentConfig;

        let config_str = tokio::fs::read_to_string(&self.config.config_path)
            .await
            .context("Failed to read agent config")?;

        let mut config: AgentConfig =
            toml::from_str(&config_str).context("Failed to parse agent config")?;

        config.agent_id = enrollment.agent_id.clone();
        config.organization_id = Some(enrollment.org_id.clone());
        config.auth_token = Some(enrollment.jwt.clone());
        config.tls.enabled = true;
        config.tls.cert_path = Some(cert_paths.cert_path.display().to_string());
        config.tls.key_path = Some(cert_paths.key_path.display().to_string());
        config.tls.ca_path = Some(cert_paths.ca_bundle_path.display().to_string());
        config.tls.skip_verify = false;

        let new_config_str =
            toml::to_string_pretty(&config).context("Failed to serialize config")?;

        tokio::fs::write(&self.config.config_path, new_config_str)
            .await
            .context("Failed to write agent config")?;

        info!(
            "Persisted re-enrollment to config file: {}",
            self.config.config_path.display()
        );

        Ok(())
    }
}

struct DefaultCertPaths {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    ca_bundle_path: std::path::PathBuf,
}

fn default_cert_paths() -> DefaultCertPaths {
    #[cfg(target_os = "windows")]
    {
        let data_dir = windows_tamandua_data_dir();
        return DefaultCertPaths {
            cert_path: data_dir.join("client.crt"),
            key_path: data_dir.join("client.key"),
            ca_bundle_path: data_dir.join("ca-bundle.crt"),
        };
    }

    #[cfg(not(target_os = "windows"))]
    {
        DefaultCertPaths {
            cert_path: std::path::PathBuf::from("/etc/tamandua/client.crt"),
            key_path: std::path::PathBuf::from("/etc/tamandua/client.key"),
            ca_bundle_path: std::path::PathBuf::from("/etc/tamandua/ca-bundle.crt"),
        }
    }
}

/// Helper function to extract HTTP base URL from WebSocket URL
pub fn extract_http_base(server_url: &str) -> Result<String> {
    let url = url::Url::parse(server_url)
        .with_context(|| format!("Invalid server URL: {}", server_url))?;

    let scheme = match url.scheme() {
        "wss" | "https" => "https",
        "ws" | "http" => "http",
        other => return Err(anyhow!("Unsupported URL scheme: {}", other)),
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
    fn token_manager_constructor_normalizes_websocket_url_for_auth_api() {
        let manager = TokenManager::new(
            "agent-1".to_string(),
            "token".to_string(),
            TokenManagerConfig {
                server_url: "wss://edr.company.com:8443/socket/agent".to_string(),
                config_path: PathBuf::from("agent.toml"),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(manager.config.server_url, "https://edr.company.com:8443");
    }
}
