//! Threat Intelligence Integration
//!
//! Comprehensive threat intelligence module providing:
//! - Multiple IOC feed support (MISP, AlienVault OTX, Abuse.ch, VirusTotal, Shodan)
//! - Extended IOC types (hashes, IPs, domains, URLs, JA3/JARM, etc.)
//! - Real-time enrichment with caching
//! - Threat scoring with confidence weighting and age decay
//! - Custom IOC list management
//! - MITRE ATT&CK enrichment
//! - Local SQLite cache with TTL

use crate::collectors::{Detection, DetectionType, EventPayload, Severity, TelemetryEvent};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

// ============================================================================
// IOC Types
// ============================================================================

/// Extended IOC (Indicator of Compromise) types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    // Network indicators
    IPv4,
    IPv6,
    Domain,
    Url,
    Email,

    // File hashes
    Md5,
    Sha1,
    Sha256,
    Ssdeep,
    Imphash,

    // TLS/SSL indicators
    Ja3,
    Ja3s,
    Jarm,
    SslCertHash,
    SslCertSerial,
    SslCertSubject,

    // Windows-specific
    RegistryKey,
    RegistryValue,
    MutexName,
    NamedPipe,
    ServiceName,
    ScheduledTask,
    WmiSubscription,

    // Process/file indicators
    FileName,
    FilePath,
    ProcessName,
    CommandLine,
    UserAgent,

    // YARA/Sigma rules (stored as IOCs)
    YaraRule,
    SigmaRule,

    // Miscellaneous
    BitcoinAddress,
    CveId,
    MitreAttackId,
    Custom,
}

impl IocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IPv4 => "ipv4",
            Self::IPv6 => "ipv6",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Ssdeep => "ssdeep",
            Self::Imphash => "imphash",
            Self::Ja3 => "ja3",
            Self::Ja3s => "ja3s",
            Self::Jarm => "jarm",
            Self::SslCertHash => "ssl_cert_hash",
            Self::SslCertSerial => "ssl_cert_serial",
            Self::SslCertSubject => "ssl_cert_subject",
            Self::RegistryKey => "registry_key",
            Self::RegistryValue => "registry_value",
            Self::MutexName => "mutex",
            Self::NamedPipe => "named_pipe",
            Self::ServiceName => "service_name",
            Self::ScheduledTask => "scheduled_task",
            Self::WmiSubscription => "wmi_subscription",
            Self::FileName => "filename",
            Self::FilePath => "filepath",
            Self::ProcessName => "process_name",
            Self::CommandLine => "command_line",
            Self::UserAgent => "user_agent",
            Self::YaraRule => "yara_rule",
            Self::SigmaRule => "sigma_rule",
            Self::BitcoinAddress => "bitcoin_address",
            Self::CveId => "cve_id",
            Self::MitreAttackId => "mitre_attack_id",
            Self::Custom => "custom",
        }
    }

    /// Parse IOC type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ipv4" | "ip" | "ipv4-addr" | "ip-dst" | "ip-src" => Some(Self::IPv4),
            "ipv6" | "ipv6-addr" => Some(Self::IPv6),
            "domain" | "domain-name" | "hostname" => Some(Self::Domain),
            "url" | "uri" | "link" => Some(Self::Url),
            "email" | "email-addr" | "email-src" | "email-dst" => Some(Self::Email),
            "md5" | "hash-md5" | "hash_md5" => Some(Self::Md5),
            "sha1" | "hash-sha1" | "hash_sha1" => Some(Self::Sha1),
            "sha256" | "hash-sha256" | "hash_sha256" => Some(Self::Sha256),
            "ssdeep" => Some(Self::Ssdeep),
            "imphash" => Some(Self::Imphash),
            "ja3" | "ja3-fingerprint" => Some(Self::Ja3),
            "ja3s" | "ja3s-fingerprint" => Some(Self::Ja3s),
            "jarm" | "jarm-fingerprint" => Some(Self::Jarm),
            "ssl-cert-hash" | "x509-certificate-sha256" => Some(Self::SslCertHash),
            "ssl-cert-serial" | "x509-certificate-serial" => Some(Self::SslCertSerial),
            "ssl-cert-subject" => Some(Self::SslCertSubject),
            "registry-key" | "regkey" | "windows-registry-key" => Some(Self::RegistryKey),
            "registry-value" | "regvalue" => Some(Self::RegistryValue),
            "mutex" | "mutex-name" | "windows-mutex" => Some(Self::MutexName),
            "named-pipe" | "pipe" | "windows-pipe" => Some(Self::NamedPipe),
            "service" | "service-name" | "windows-service" => Some(Self::ServiceName),
            "scheduled-task" | "task" => Some(Self::ScheduledTask),
            "wmi-subscription" | "wmi" => Some(Self::WmiSubscription),
            "filename" | "file-name" => Some(Self::FileName),
            "filepath" | "file-path" => Some(Self::FilePath),
            "process-name" | "process" => Some(Self::ProcessName),
            "command-line" | "cmdline" => Some(Self::CommandLine),
            "user-agent" | "http-user-agent" => Some(Self::UserAgent),
            "yara" | "yara-rule" => Some(Self::YaraRule),
            "sigma" | "sigma-rule" => Some(Self::SigmaRule),
            "bitcoin" | "btc" | "bitcoin-address" => Some(Self::BitcoinAddress),
            "cve" | "cve-id" | "vulnerability" => Some(Self::CveId),
            "mitre" | "mitre-attack" | "attack-pattern" => Some(Self::MitreAttackId),
            _ => None,
        }
    }
}

// ============================================================================
// IOC Entry
// ============================================================================

/// Single IOC entry with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// IOC type
    pub ioc_type: IocType,
    /// IOC value (normalized/lowercase for comparison)
    pub value: String,
    /// Original value (preserving case)
    pub original_value: String,
    /// Source feed/provider
    pub source: String,
    /// Source-specific ID
    pub source_id: Option<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Severity level
    pub severity: Severity,
    /// Human-readable description
    pub description: Option<String>,
    /// Tags/labels
    pub tags: Vec<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_techniques: Vec<String>,
    /// MITRE ATT&CK tactic IDs
    pub mitre_tactics: Vec<String>,
    /// Associated threat actor/campaign
    pub threat_actor: Option<String>,
    /// Associated campaign
    pub campaign: Option<String>,
    /// Related malware families
    pub malware_families: Vec<String>,
    /// First seen timestamp (Unix epoch seconds)
    pub first_seen: Option<u64>,
    /// Last seen timestamp (Unix epoch seconds)
    pub last_seen: Option<u64>,
    /// Expiration timestamp (Unix epoch seconds)
    pub expiration: Option<u64>,
    /// When this IOC was added to local cache
    pub cached_at: u64,
    /// False positive count from feedback
    pub false_positive_count: u32,
    /// True positive count from feedback
    pub true_positive_count: u32,
    /// Related IOCs (e.g., hash -> IPs)
    pub related_iocs: Vec<RelatedIoc>,
    /// Kill chain stage
    pub kill_chain_phase: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Related IOC reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedIoc {
    pub ioc_type: IocType,
    pub value: String,
    pub relationship: String, // e.g., "communicates-with", "drops", "downloads"
}

impl Ioc {
    /// Create a new IOC with defaults
    pub fn new(ioc_type: IocType, value: String, source: String) -> Self {
        let normalized = Self::normalize_value(&ioc_type, &value);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ioc_type,
            value: normalized,
            original_value: value,
            source,
            source_id: None,
            confidence: 0.5,
            severity: Severity::Medium,
            description: None,
            tags: Vec::new(),
            mitre_techniques: Vec::new(),
            mitre_tactics: Vec::new(),
            threat_actor: None,
            campaign: None,
            malware_families: Vec::new(),
            first_seen: Some(now),
            last_seen: Some(now),
            expiration: None,
            cached_at: now,
            false_positive_count: 0,
            true_positive_count: 0,
            related_iocs: Vec::new(),
            kill_chain_phase: None,
            metadata: HashMap::new(),
        }
    }

    /// Normalize IOC value for consistent comparison
    fn normalize_value(ioc_type: &IocType, value: &str) -> String {
        match ioc_type {
            // Lowercase for case-insensitive types
            IocType::Domain | IocType::Email | IocType::Url | IocType::FileName => {
                value.to_lowercase().trim().to_string()
            }
            // Lowercase hex hashes
            IocType::Md5
            | IocType::Sha1
            | IocType::Sha256
            | IocType::Ja3
            | IocType::Ja3s
            | IocType::Jarm
            | IocType::SslCertHash
            | IocType::Imphash => value.to_lowercase().trim().to_string(),
            // Registry keys - normalize separators
            IocType::RegistryKey | IocType::RegistryValue => {
                value.replace('/', "\\").to_uppercase().trim().to_string()
            }
            // Keep original for others
            _ => value.trim().to_string(),
        }
    }

    /// Check if IOC is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = self.expiration {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now > expiration
        } else {
            false
        }
    }

    /// Calculate age-adjusted confidence
    pub fn age_adjusted_confidence(&self) -> f32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Use last_seen or cached_at as reference
        let age_ref = self.last_seen.unwrap_or(self.cached_at);
        let age_days = (now.saturating_sub(age_ref)) as f32 / 86400.0;

        // Decay factor: confidence decreases by 10% every 30 days
        let decay = (-age_days / 300.0).exp();

        // Factor in feedback
        let feedback_factor = if self.true_positive_count + self.false_positive_count > 0 {
            let tp = self.true_positive_count as f32;
            let fp = self.false_positive_count as f32;
            tp / (tp + fp)
        } else {
            1.0
        };

        (self.confidence * decay * feedback_factor).clamp(0.0, 1.0)
    }
}

// ============================================================================
// Threat Score
// ============================================================================

/// Combined threat score from multiple sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    /// Overall score (0.0 - 100.0)
    pub score: f32,
    /// Individual source scores
    pub source_scores: HashMap<String, f32>,
    /// Confidence in the score
    pub confidence: f32,
    /// Contributing IOCs
    pub contributing_iocs: Vec<Ioc>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Recommendation
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Unknown,
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatScore {
    /// Calculate combined score from multiple IOC matches
    pub fn calculate(iocs: &[Ioc]) -> Self {
        if iocs.is_empty() {
            return Self {
                score: 0.0,
                source_scores: HashMap::new(),
                confidence: 0.0,
                contributing_iocs: Vec::new(),
                risk_level: RiskLevel::Unknown,
                recommendation: "No threat intelligence data available".to_string(),
            };
        }

        let mut source_scores: HashMap<String, Vec<f32>> = HashMap::new();

        // Group scores by source
        for ioc in iocs {
            let score = ioc.age_adjusted_confidence() * 100.0;
            source_scores
                .entry(ioc.source.clone())
                .or_default()
                .push(score);
        }

        // Average scores per source
        let avg_source_scores: HashMap<String, f32> = source_scores
            .iter()
            .map(|(source, scores)| {
                let avg = scores.iter().sum::<f32>() / scores.len() as f32;
                (source.clone(), avg)
            })
            .collect();

        // Weighted average (more sources = higher confidence)
        let source_weights: HashMap<&str, f32> = [
            ("VirusTotal", 1.2),
            ("MISP", 1.1),
            ("AlienVaultOTX", 1.0),
            ("AbuseCH", 1.0),
            ("Shodan", 0.9),
            ("Custom", 0.8),
            ("builtin", 0.5),
        ]
        .into_iter()
        .collect();

        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;

        for (source, score) in &avg_source_scores {
            let weight = source_weights.get(source.as_str()).copied().unwrap_or(0.7);
            weighted_sum += score * weight;
            weight_total += weight;
        }

        let overall_score = if weight_total > 0.0 {
            weighted_sum / weight_total
        } else {
            0.0
        };

        // Confidence based on source diversity
        let source_count = avg_source_scores.len();
        let confidence = match source_count {
            0 => 0.0,
            1 => 0.5,
            2 => 0.7,
            3 => 0.85,
            _ => 0.95,
        };

        // Determine risk level
        let risk_level = match overall_score as u32 {
            0..=10 => RiskLevel::Clean,
            11..=30 => RiskLevel::Low,
            31..=60 => RiskLevel::Medium,
            61..=85 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        let recommendation = match risk_level {
            RiskLevel::Unknown => "Insufficient data for assessment".to_string(),
            RiskLevel::Clean => "No action required".to_string(),
            RiskLevel::Low => "Monitor for additional suspicious activity".to_string(),
            RiskLevel::Medium => "Investigate and consider blocking".to_string(),
            RiskLevel::High => "Block immediately and investigate".to_string(),
            RiskLevel::Critical => {
                "Critical threat - isolate affected systems immediately".to_string()
            }
        };

        Self {
            score: overall_score,
            source_scores: avg_source_scores,
            confidence,
            contributing_iocs: iocs.to_vec(),
            risk_level,
            recommendation,
        }
    }
}

// ============================================================================
// Feed Providers
// ============================================================================

/// Feed provider trait
#[async_trait::async_trait]
pub trait FeedProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;

    /// Check if provider is configured
    fn is_configured(&self) -> bool;

    /// Lookup a single IOC
    async fn lookup(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>>;

    /// Batch lookup multiple IOCs
    async fn batch_lookup(&self, queries: &[(IocType, String)]) -> Result<Vec<Ioc>> {
        let mut results = Vec::new();
        for (ioc_type, value) in queries {
            match self.lookup(*ioc_type, value).await {
                Ok(iocs) => results.extend(iocs),
                Err(e) => debug!("Lookup failed for {} {}: {}", ioc_type.as_str(), value, e),
            }
        }
        Ok(results)
    }

    /// Download full feed
    async fn download_feed(&self) -> Result<Vec<Ioc>>;

    /// Get rate limit info
    fn rate_limit(&self) -> RateLimitInfo;
}

/// Rate limit information
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub requests_per_minute: u32,
    pub requests_per_day: u32,
    pub current_minute_count: u32,
    pub current_day_count: u32,
}

// ============================================================================
// MISP Provider
// ============================================================================

/// MISP (Malware Information Sharing Platform) integration
pub struct MispProvider {
    base_url: String,
    api_key: String,
    client: reqwest::Client,
    #[allow(dead_code)]
    verify_ssl: bool,
}

impl MispProvider {
    pub fn new(base_url: String, api_key: String, verify_ssl: bool) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            client,
            verify_ssl,
        })
    }
}

#[async_trait::async_trait]
impl FeedProvider for MispProvider {
    fn name(&self) -> &str {
        "MISP"
    }

    fn is_configured(&self) -> bool {
        !self.api_key.is_empty() && !self.base_url.is_empty()
    }

    async fn lookup(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        let search_type = match ioc_type {
            IocType::IPv4 | IocType::IPv6 => "ip-dst",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Email => "email-dst",
            _ => return Ok(Vec::new()),
        };

        let url = format!("{}/attributes/restSearch", self.base_url);

        let body = serde_json::json!({
            "returnFormat": "json",
            "type": search_type,
            "value": value,
            "limit": 100
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("MISP API request failed")?;

        if !response.status().is_success() {
            anyhow::bail!("MISP API error: {}", response.status());
        }

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        if let Some(attributes) = data
            .get("response")
            .and_then(|r| r.get("Attribute"))
            .and_then(|a| a.as_array())
        {
            for attr in attributes {
                if let Some(ioc) = Self::parse_misp_attribute(attr) {
                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }

    async fn download_feed(&self) -> Result<Vec<Ioc>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        let url = format!("{}/events/restSearch", self.base_url);

        // Get events from last 7 days
        let body = serde_json::json!({
            "returnFormat": "json",
            "last": "7d",
            "limit": 1000,
            "includeEventTags": true,
            "includeContext": true
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .context("MISP feed download failed")?;

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        if let Some(events) = data.get("response").and_then(|r| r.as_array()) {
            for event in events {
                if let Some(event_obj) = event.get("Event") {
                    if let Some(attributes) = event_obj.get("Attribute").and_then(|a| a.as_array())
                    {
                        for attr in attributes {
                            if let Some(mut ioc) = Self::parse_misp_attribute(attr) {
                                // Add event-level metadata
                                if let Some(info) = event_obj.get("info").and_then(|i| i.as_str()) {
                                    ioc.description = Some(info.to_string());
                                }
                                iocs.push(ioc);
                            }
                        }
                    }
                }
            }
        }

        info!("Downloaded {} IOCs from MISP", iocs.len());
        Ok(iocs)
    }

    fn rate_limit(&self) -> RateLimitInfo {
        RateLimitInfo {
            requests_per_minute: 60,
            requests_per_day: 10000,
            current_minute_count: 0,
            current_day_count: 0,
        }
    }
}

impl MispProvider {
    fn parse_misp_attribute(attr: &serde_json::Value) -> Option<Ioc> {
        let attr_type = attr.get("type")?.as_str()?;
        let value = attr.get("value")?.as_str()?;

        let ioc_type = IocType::from_str(attr_type)?;

        let mut ioc = Ioc::new(ioc_type, value.to_string(), "MISP".to_string());

        ioc.source_id = attr
            .get("id")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string());

        if let Some(comment) = attr.get("comment").and_then(|c| c.as_str()) {
            ioc.description = Some(comment.to_string());
        }

        // Parse timestamp
        if let Some(ts) = attr.get("timestamp").and_then(|t| t.as_str()) {
            if let Ok(ts_int) = ts.parse::<u64>() {
                ioc.first_seen = Some(ts_int);
                ioc.last_seen = Some(ts_int);
            }
        }

        // Parse category for tags
        if let Some(category) = attr.get("category").and_then(|c| c.as_str()) {
            ioc.tags.push(format!("misp-category:{}", category));
        }

        Some(ioc)
    }
}

// ============================================================================
// AlienVault OTX Provider
// ============================================================================

/// AlienVault Open Threat Exchange integration
pub struct AlienVaultOtxProvider {
    api_key: String,
    client: reqwest::Client,
}

impl AlienVaultOtxProvider {
    pub fn new(api_key: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client for AlienVault OTX provider")?;

        Ok(Self { api_key, client })
    }
}

#[async_trait::async_trait]
impl FeedProvider for AlienVaultOtxProvider {
    fn name(&self) -> &str {
        "AlienVaultOTX"
    }

    fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    async fn lookup(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        let (section, indicator_type) = match ioc_type {
            IocType::IPv4 => ("IPv4", "general"),
            IocType::IPv6 => ("IPv6", "general"),
            IocType::Domain => ("domain", "general"),
            IocType::Url => ("url", "general"),
            IocType::Md5 => ("file", "general"),
            IocType::Sha1 => ("file", "general"),
            IocType::Sha256 => ("file", "general"),
            _ => return Ok(Vec::new()),
        };

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/{}/{}/{}",
            section, value, indicator_type
        );

        let response = self
            .client
            .get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .context("OTX API request failed")?;

        if response.status() == 404 {
            // Not found = clean
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            anyhow::bail!("OTX API error: {}", response.status());
        }

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        // Check pulse count (indicates malicious)
        let pulse_count = data
            .get("pulse_info")
            .and_then(|p| p.get("count"))
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        if pulse_count > 0 {
            let mut ioc = Ioc::new(ioc_type, value.to_string(), "AlienVaultOTX".to_string());

            // Confidence based on pulse count
            ioc.confidence = match pulse_count {
                1..=3 => 0.4,
                4..=10 => 0.6,
                11..=50 => 0.8,
                _ => 0.95,
            };

            ioc.severity = match pulse_count {
                1..=3 => Severity::Low,
                4..=10 => Severity::Medium,
                11..=50 => Severity::High,
                _ => Severity::Critical,
            };

            ioc.description = Some(format!("Found in {} OTX pulses", pulse_count));

            // Extract tags from pulses
            if let Some(pulses) = data
                .get("pulse_info")
                .and_then(|p| p.get("pulses"))
                .and_then(|p| p.as_array())
            {
                for pulse in pulses.iter().take(10) {
                    if let Some(tags) = pulse.get("tags").and_then(|t| t.as_array()) {
                        for tag in tags {
                            if let Some(tag_str) = tag.as_str() {
                                if !ioc.tags.contains(&tag_str.to_string()) {
                                    ioc.tags.push(tag_str.to_string());
                                }
                            }
                        }
                    }

                    // Extract malware families
                    if let Some(families) = pulse.get("malware_families").and_then(|m| m.as_array())
                    {
                        for family in families {
                            if let Some(family_str) = family.as_str() {
                                if !ioc.malware_families.contains(&family_str.to_string()) {
                                    ioc.malware_families.push(family_str.to_string());
                                }
                            }
                        }
                    }

                    // Extract attack IDs
                    if let Some(attack_ids) = pulse.get("attack_ids").and_then(|a| a.as_array()) {
                        for attack in attack_ids {
                            if let Some(attack_id) = attack.get("id").and_then(|i| i.as_str()) {
                                if !ioc.mitre_techniques.contains(&attack_id.to_string()) {
                                    ioc.mitre_techniques.push(attack_id.to_string());
                                }
                            }
                        }
                    }
                }
            }

            iocs.push(ioc);
        }

        Ok(iocs)
    }

    async fn download_feed(&self) -> Result<Vec<Ioc>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        // Get subscribed pulses from last 7 days
        let url = "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=7d&limit=50";

        let response = self
            .client
            .get(url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .context("OTX feed download failed")?;

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        if let Some(pulses) = data.get("results").and_then(|r| r.as_array()) {
            for pulse in pulses {
                if let Some(indicators) = pulse.get("indicators").and_then(|i| i.as_array()) {
                    for indicator in indicators {
                        if let Some(ioc) = Self::parse_otx_indicator(indicator, pulse) {
                            iocs.push(ioc);
                        }
                    }
                }
            }
        }

        info!("Downloaded {} IOCs from AlienVault OTX", iocs.len());
        Ok(iocs)
    }

    fn rate_limit(&self) -> RateLimitInfo {
        RateLimitInfo {
            requests_per_minute: 30,
            requests_per_day: 10000,
            current_minute_count: 0,
            current_day_count: 0,
        }
    }
}

impl AlienVaultOtxProvider {
    fn parse_otx_indicator(
        indicator: &serde_json::Value,
        pulse: &serde_json::Value,
    ) -> Option<Ioc> {
        let ind_type = indicator.get("type")?.as_str()?;
        let value = indicator.get("indicator")?.as_str()?;

        let ioc_type = IocType::from_str(ind_type)?;

        let mut ioc = Ioc::new(ioc_type, value.to_string(), "AlienVaultOTX".to_string());

        // Add pulse info
        if let Some(name) = pulse.get("name").and_then(|n| n.as_str()) {
            ioc.description = Some(name.to_string());
        }

        if let Some(tags) = pulse.get("tags").and_then(|t| t.as_array()) {
            for tag in tags {
                if let Some(tag_str) = tag.as_str() {
                    ioc.tags.push(tag_str.to_string());
                }
            }
        }

        ioc.confidence = 0.6;
        ioc.severity = Severity::Medium;

        Some(ioc)
    }
}

// ============================================================================
// Abuse.ch Provider (URLhaus, MalwareBazaar, ThreatFox)
// ============================================================================

/// Abuse.ch feeds integration
pub struct AbusechProvider {
    client: reqwest::Client,
}

impl AbusechProvider {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Failed to build HTTP client for Abuse.ch provider")?;

        Ok(Self { client })
    }
}

impl Default for AbusechProvider {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            client: reqwest::Client::new(),
        })
    }
}

#[async_trait::async_trait]
impl FeedProvider for AbusechProvider {
    fn name(&self) -> &str {
        "AbuseCH"
    }

    fn is_configured(&self) -> bool {
        true // No API key required
    }

    async fn lookup(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>> {
        match ioc_type {
            IocType::Url | IocType::Domain => self.lookup_urlhaus(value).await,
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                self.lookup_malwarebazaar(ioc_type, value).await
            }
            IocType::IPv4 => self.lookup_threatfox_ip(value).await,
            _ => Ok(Vec::new()),
        }
    }

    async fn download_feed(&self) -> Result<Vec<Ioc>> {
        let mut all_iocs = Vec::new();

        // Download URLhaus recent URLs
        match self.download_urlhaus_recent().await {
            Ok(iocs) => all_iocs.extend(iocs),
            Err(e) => warn!("URLhaus download failed: {}", e),
        }

        // Download recent malware samples
        match self.download_malwarebazaar_recent().await {
            Ok(iocs) => all_iocs.extend(iocs),
            Err(e) => warn!("MalwareBazaar download failed: {}", e),
        }

        // Download ThreatFox IOCs
        match self.download_threatfox_recent().await {
            Ok(iocs) => all_iocs.extend(iocs),
            Err(e) => warn!("ThreatFox download failed: {}", e),
        }

        info!("Downloaded {} IOCs from Abuse.ch feeds", all_iocs.len());
        Ok(all_iocs)
    }

    fn rate_limit(&self) -> RateLimitInfo {
        RateLimitInfo {
            requests_per_minute: 60,
            requests_per_day: 100000,
            current_minute_count: 0,
            current_day_count: 0,
        }
    }
}

impl AbusechProvider {
    async fn lookup_urlhaus(&self, value: &str) -> Result<Vec<Ioc>> {
        let url = "https://urlhaus-api.abuse.ch/v1/url/";

        let response = self.client.post(url).form(&[("url", value)]).send().await?;

        let data: serde_json::Value = response.json().await?;

        if data.get("query_status").and_then(|s| s.as_str()) != Some("ok") {
            return Ok(Vec::new());
        }

        let mut iocs = Vec::new();

        if let Some(urls) = data.get("urls").and_then(|u| u.as_array()) {
            for url_entry in urls {
                let mut ioc = Ioc::new(
                    IocType::Url,
                    value.to_string(),
                    "AbuseCH-URLhaus".to_string(),
                );

                if let Some(threat) = url_entry.get("threat").and_then(|t| t.as_str()) {
                    ioc.tags.push(threat.to_string());
                }

                if let Some(status) = url_entry.get("url_status").and_then(|s| s.as_str()) {
                    if status == "online" {
                        ioc.confidence = 0.9;
                        ioc.severity = Severity::High;
                    } else {
                        ioc.confidence = 0.6;
                        ioc.severity = Severity::Medium;
                    }
                }

                iocs.push(ioc);
            }
        }

        Ok(iocs)
    }

    async fn lookup_malwarebazaar(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>> {
        let url = "https://mb-api.abuse.ch/api/v1/";

        let hash_type = match ioc_type {
            IocType::Md5 => "md5_hash",
            IocType::Sha1 => "sha1_hash",
            IocType::Sha256 => "sha256_hash",
            _ => return Ok(Vec::new()),
        };

        let response = self
            .client
            .post(url)
            .form(&[("query", "get_info"), (hash_type, value)])
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;

        if data.get("query_status").and_then(|s| s.as_str()) != Some("ok") {
            return Ok(Vec::new());
        }

        let mut iocs = Vec::new();

        if let Some(samples) = data.get("data").and_then(|d| d.as_array()) {
            for sample in samples {
                let sha256 = sample
                    .get("sha256_hash")
                    .and_then(|s| s.as_str())
                    .unwrap_or(value);

                let mut ioc = Ioc::new(
                    IocType::Sha256,
                    sha256.to_string(),
                    "AbuseCH-MalwareBazaar".to_string(),
                );

                if let Some(family) = sample.get("signature").and_then(|s| s.as_str()) {
                    ioc.malware_families.push(family.to_string());
                    ioc.description = Some(format!("Malware: {}", family));
                }

                if let Some(file_type) = sample.get("file_type").and_then(|f| f.as_str()) {
                    ioc.tags.push(format!("file-type:{}", file_type));
                }

                if let Some(tags) = sample.get("tags").and_then(|t| t.as_array()) {
                    for tag in tags {
                        if let Some(tag_str) = tag.as_str() {
                            ioc.tags.push(tag_str.to_string());
                        }
                    }
                }

                ioc.confidence = 0.95;
                ioc.severity = Severity::Critical;

                iocs.push(ioc);
            }
        }

        Ok(iocs)
    }

    async fn lookup_threatfox_ip(&self, ip: &str) -> Result<Vec<Ioc>> {
        let url = "https://threatfox-api.abuse.ch/api/v1/";

        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "query": "search_ioc",
                "search_term": ip
            }))
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;

        if data.get("query_status").and_then(|s| s.as_str()) != Some("ok") {
            return Ok(Vec::new());
        }

        let mut iocs = Vec::new();

        if let Some(entries) = data.get("data").and_then(|d| d.as_array()) {
            for entry in entries {
                let mut ioc = Ioc::new(
                    IocType::IPv4,
                    ip.to_string(),
                    "AbuseCH-ThreatFox".to_string(),
                );

                if let Some(malware) = entry.get("malware_printable").and_then(|m| m.as_str()) {
                    ioc.malware_families.push(malware.to_string());
                }

                if let Some(threat_type) = entry.get("threat_type").and_then(|t| t.as_str()) {
                    ioc.tags.push(threat_type.to_string());
                }

                if let Some(confidence) = entry.get("confidence_level").and_then(|c| c.as_i64()) {
                    ioc.confidence = (confidence as f32 / 100.0).clamp(0.0, 1.0);
                }

                ioc.severity = Severity::High;

                iocs.push(ioc);
            }
        }

        Ok(iocs)
    }

    async fn download_urlhaus_recent(&self) -> Result<Vec<Ioc>> {
        let url = "https://urlhaus-api.abuse.ch/v1/urls/recent/";

        let response = self.client.get(url).send().await?;
        let data: serde_json::Value = response.json().await?;

        let mut iocs = Vec::new();

        if let Some(urls) = data.get("urls").and_then(|u| u.as_array()) {
            for url_entry in urls.iter().take(1000) {
                if let Some(url_value) = url_entry.get("url").and_then(|u| u.as_str()) {
                    let mut ioc = Ioc::new(
                        IocType::Url,
                        url_value.to_string(),
                        "AbuseCH-URLhaus".to_string(),
                    );

                    if let Some(threat) = url_entry.get("threat").and_then(|t| t.as_str()) {
                        ioc.tags.push(threat.to_string());
                    }

                    ioc.confidence = 0.85;
                    ioc.severity = Severity::High;

                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }

    async fn download_malwarebazaar_recent(&self) -> Result<Vec<Ioc>> {
        let url = "https://mb-api.abuse.ch/api/v1/";

        let response = self
            .client
            .post(url)
            .form(&[("query", "get_recent"), ("selector", "100")])
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        if let Some(samples) = data.get("data").and_then(|d| d.as_array()) {
            for sample in samples {
                if let Some(sha256) = sample.get("sha256_hash").and_then(|s| s.as_str()) {
                    let mut ioc = Ioc::new(
                        IocType::Sha256,
                        sha256.to_string(),
                        "AbuseCH-MalwareBazaar".to_string(),
                    );

                    if let Some(family) = sample.get("signature").and_then(|s| s.as_str()) {
                        ioc.malware_families.push(family.to_string());
                    }

                    ioc.confidence = 0.95;
                    ioc.severity = Severity::Critical;

                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }

    async fn download_threatfox_recent(&self) -> Result<Vec<Ioc>> {
        let url = "https://threatfox-api.abuse.ch/api/v1/";

        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "query": "get_iocs",
                "days": 7
            }))
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        if let Some(entries) = data.get("data").and_then(|d| d.as_array()) {
            for entry in entries.iter().take(1000) {
                if let Some(ioc_value) = entry.get("ioc").and_then(|i| i.as_str()) {
                    let ioc_type_str = entry.get("ioc_type").and_then(|t| t.as_str()).unwrap_or("");

                    let ioc_type = match ioc_type_str {
                        "ip:port" | "ip" => IocType::IPv4,
                        "domain" => IocType::Domain,
                        "url" => IocType::Url,
                        _ => continue,
                    };

                    // Clean up ip:port format
                    let clean_value = if ioc_type_str == "ip:port" {
                        ioc_value.split(':').next().unwrap_or(ioc_value).to_string()
                    } else {
                        ioc_value.to_string()
                    };

                    let mut ioc = Ioc::new(ioc_type, clean_value, "AbuseCH-ThreatFox".to_string());

                    if let Some(malware) = entry.get("malware_printable").and_then(|m| m.as_str()) {
                        ioc.malware_families.push(malware.to_string());
                    }

                    ioc.confidence = 0.8;
                    ioc.severity = Severity::High;

                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }
}

// ============================================================================
// VirusTotal Provider
// ============================================================================

/// VirusTotal integration with caching
pub struct VirusTotalProvider {
    api_key: String,
    client: reqwest::Client,
}

impl VirusTotalProvider {
    pub fn new(api_key: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client for VirusTotal provider")?;

        Ok(Self { api_key, client })
    }
}

#[async_trait::async_trait]
impl FeedProvider for VirusTotalProvider {
    fn name(&self) -> &str {
        "VirusTotal"
    }

    fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    async fn lookup(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        let endpoint = match ioc_type {
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => format!("files/{}", value),
            IocType::IPv4 | IocType::IPv6 => format!("ip_addresses/{}", value),
            IocType::Domain => format!("domains/{}", value),
            IocType::Url => {
                // URL needs to be base64 encoded
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    value,
                );
                format!("urls/{}", encoded)
            }
            _ => return Ok(Vec::new()),
        };

        let url = format!("https://www.virustotal.com/api/v3/{}", endpoint);

        let response = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .context("VirusTotal API request failed")?;

        if response.status() == 404 {
            return Ok(Vec::new()); // Not found = clean
        }

        if !response.status().is_success() {
            anyhow::bail!("VirusTotal API error: {}", response.status());
        }

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        if let Some(attributes) = data.get("data").and_then(|d| d.get("attributes")) {
            let (malicious, suspicious, total) = match ioc_type {
                IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                    let stats = attributes.get("last_analysis_stats");
                    (
                        stats
                            .and_then(|s| s.get("malicious"))
                            .and_then(|m| m.as_u64())
                            .unwrap_or(0),
                        stats
                            .and_then(|s| s.get("suspicious"))
                            .and_then(|s| s.as_u64())
                            .unwrap_or(0),
                        stats
                            .and_then(|s| {
                                Some(
                                    s.get("malicious")?.as_u64()?
                                        + s.get("undetected")?.as_u64()?
                                        + s.get("suspicious")?.as_u64()?
                                        + s.get("harmless")?.as_u64()?,
                                )
                            })
                            .unwrap_or(70),
                    )
                }
                _ => {
                    let stats = attributes.get("last_analysis_stats");
                    (
                        stats
                            .and_then(|s| s.get("malicious"))
                            .and_then(|m| m.as_u64())
                            .unwrap_or(0),
                        stats
                            .and_then(|s| s.get("suspicious"))
                            .and_then(|s| s.as_u64())
                            .unwrap_or(0),
                        70,
                    )
                }
            };

            if malicious > 0 || suspicious > 0 {
                let mut ioc = Ioc::new(ioc_type, value.to_string(), "VirusTotal".to_string());

                let detection_rate = (malicious + suspicious) as f32 / total as f32;
                ioc.confidence = detection_rate.clamp(0.0, 1.0);

                ioc.severity = match malicious {
                    0 => Severity::Low,
                    1..=3 => Severity::Medium,
                    4..=10 => Severity::High,
                    _ => Severity::Critical,
                };

                ioc.description = Some(format!(
                    "VirusTotal: {}/{} engines detected as malicious",
                    malicious, total
                ));

                // Extract threat names
                if let Some(names) = attributes
                    .get("popular_threat_classification")
                    .and_then(|p| p.get("suggested_threat_label"))
                    .and_then(|l| l.as_str())
                {
                    ioc.malware_families.push(names.to_string());
                }

                // Extract tags
                if let Some(tags) = attributes.get("tags").and_then(|t| t.as_array()) {
                    for tag in tags {
                        if let Some(tag_str) = tag.as_str() {
                            ioc.tags.push(tag_str.to_string());
                        }
                    }
                }

                iocs.push(ioc);
            }
        }

        Ok(iocs)
    }

    async fn download_feed(&self) -> Result<Vec<Ioc>> {
        // VirusTotal doesn't provide bulk feed download in the free tier
        // This would require VT Enterprise
        Ok(Vec::new())
    }

    fn rate_limit(&self) -> RateLimitInfo {
        RateLimitInfo {
            requests_per_minute: 4, // Free tier: 4 requests/minute
            requests_per_day: 500,  // Free tier: 500 requests/day
            current_minute_count: 0,
            current_day_count: 0,
        }
    }
}

// ============================================================================
// Shodan Provider
// ============================================================================

/// Shodan integration for IP reputation
pub struct ShodanProvider {
    api_key: String,
    client: reqwest::Client,
}

impl ShodanProvider {
    pub fn new(api_key: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client for Shodan provider")?;

        Ok(Self { api_key, client })
    }
}

#[async_trait::async_trait]
impl FeedProvider for ShodanProvider {
    fn name(&self) -> &str {
        "Shodan"
    }

    fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    async fn lookup(&self, ioc_type: IocType, value: &str) -> Result<Vec<Ioc>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        // Shodan is primarily for IP lookups
        if ioc_type != IocType::IPv4 && ioc_type != IocType::IPv6 {
            return Ok(Vec::new());
        }

        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            value, self.api_key
        );

        let response = self.client.get(&url).send().await?;

        if response.status() == 404 {
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            anyhow::bail!("Shodan API error: {}", response.status());
        }

        let data: serde_json::Value = response.json().await?;
        let mut iocs = Vec::new();

        // Check for suspicious indicators
        let mut risk_score: f32 = 0.0;
        let mut tags = Vec::new();

        // Check for known malicious tags
        if let Some(shodan_tags) = data.get("tags").and_then(|t| t.as_array()) {
            for tag in shodan_tags {
                if let Some(tag_str) = tag.as_str() {
                    tags.push(tag_str.to_string());

                    // Known malicious tags
                    if matches!(
                        tag_str,
                        "c2" | "botnet" | "malware" | "vpn" | "tor" | "proxy"
                    ) {
                        risk_score += 0.3;
                    }
                }
            }
        }

        // Check for vulnerable services
        if let Some(vulns) = data.get("vulns").and_then(|v| v.as_array()) {
            if !vulns.is_empty() {
                risk_score += 0.2;
                for vuln in vulns {
                    if let Some(cve) = vuln.as_str() {
                        tags.push(format!("vuln:{}", cve));
                    }
                }
            }
        }

        // Check for suspicious ports
        if let Some(ports) = data.get("ports").and_then(|p| p.as_array()) {
            for port in ports {
                if let Some(port_num) = port.as_u64() {
                    // Known C2/suspicious ports
                    if matches!(port_num, 4444 | 5555 | 6666 | 8080 | 8888 | 1337 | 31337) {
                        risk_score += 0.1;
                        tags.push(format!("suspicious-port:{}", port_num));
                    }
                }
            }
        }

        if risk_score > 0.0 {
            let mut ioc = Ioc::new(ioc_type, value.to_string(), "Shodan".to_string());

            ioc.confidence = risk_score.clamp(0.0, 1.0);
            ioc.tags = tags;

            ioc.severity = if risk_score > 0.7 {
                Severity::High
            } else if risk_score > 0.4 {
                Severity::Medium
            } else {
                Severity::Low
            };

            // Add enrichment data
            if let Some(org) = data.get("org").and_then(|o| o.as_str()) {
                ioc.metadata.insert("org".to_string(), org.to_string());
            }

            if let Some(asn) = data.get("asn").and_then(|a| a.as_str()) {
                ioc.metadata.insert("asn".to_string(), asn.to_string());
            }

            if let Some(country) = data.get("country_code").and_then(|c| c.as_str()) {
                ioc.metadata
                    .insert("country".to_string(), country.to_string());
            }

            iocs.push(ioc);
        }

        Ok(iocs)
    }

    async fn download_feed(&self) -> Result<Vec<Ioc>> {
        // Shodan doesn't provide IOC feeds
        Ok(Vec::new())
    }

    fn rate_limit(&self) -> RateLimitInfo {
        RateLimitInfo {
            requests_per_minute: 1, // Free tier is very limited
            requests_per_day: 100,
            current_minute_count: 0,
            current_day_count: 0,
        }
    }
}

// ============================================================================
// Local Cache
// ============================================================================

/// Cache entry with TTL
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    iocs: Vec<Ioc>,
    cached_at: u64,
    ttl_seconds: u64,
    is_negative: bool, // True if lookup returned no results (negative caching)
}

/// Local SQLite-backed cache for IOC lookups
pub struct ThreatIntelCache {
    /// In-memory cache for fast access
    memory_cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// SQLite database path
    db_path: PathBuf,
    /// Default TTL for positive results
    positive_ttl: Duration,
    /// Default TTL for negative results (known good)
    negative_ttl: Duration,
    /// Maximum memory cache size
    max_memory_entries: usize,
}

impl ThreatIntelCache {
    /// Create a new cache
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            db_path,
            positive_ttl: Duration::from_secs(3600), // 1 hour
            negative_ttl: Duration::from_secs(86400), // 24 hours
            max_memory_entries: 100000,
        }
    }

    /// Initialize the SQLite database
    pub async fn init(&self) -> Result<()> {
        // Note: In production, use rusqlite or sqlx
        // For now, we'll use in-memory only
        info!("Initialized threat intel cache at {:?}", self.db_path);
        Ok(())
    }

    /// Generate cache key
    fn cache_key(ioc_type: IocType, value: &str) -> String {
        format!("{}:{}", ioc_type.as_str(), value.to_lowercase())
    }

    /// Get from cache
    pub async fn get(&self, ioc_type: IocType, value: &str) -> Option<Vec<Ioc>> {
        let key = Self::cache_key(ioc_type, value);
        let cache = self.memory_cache.read().await;

        if let Some(entry) = cache.get(&key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Check TTL
            if now < entry.cached_at + entry.ttl_seconds {
                if entry.is_negative {
                    return Some(Vec::new()); // Return empty for negative cache hit
                }
                return Some(entry.iocs.clone());
            }
        }

        None
    }

    /// Store in cache
    pub async fn set(&self, ioc_type: IocType, value: &str, iocs: Vec<Ioc>) {
        let key = Self::cache_key(ioc_type, value);
        let is_negative = iocs.is_empty();

        let entry = CacheEntry {
            iocs,
            cached_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ttl_seconds: if is_negative {
                self.negative_ttl.as_secs()
            } else {
                self.positive_ttl.as_secs()
            },
            is_negative,
        };

        let mut cache = self.memory_cache.write().await;

        // Evict if over limit
        if cache.len() >= self.max_memory_entries {
            // Simple LRU-ish eviction: remove oldest entries
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            cache.retain(|_, v| now < v.cached_at + v.ttl_seconds);
        }

        cache.insert(key, entry);
    }

    /// Clear expired entries
    pub async fn cleanup(&self) {
        let mut cache = self.memory_cache.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        cache.retain(|_, v| now < v.cached_at + v.ttl_seconds);
        debug!("Cache cleanup complete, {} entries remaining", cache.len());
    }

    /// Get cache statistics
    pub async fn stats(&self) -> (usize, usize, usize) {
        let cache = self.memory_cache.read().await;
        let total = cache.len();
        let positive = cache.values().filter(|e| !e.is_negative).count();
        let negative = cache.values().filter(|e| e.is_negative).count();
        (total, positive, negative)
    }
}

// ============================================================================
// MITRE ATT&CK Enrichment
// ============================================================================

/// MITRE ATT&CK technique information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactic: String,
    pub platforms: Vec<String>,
    pub detection: String,
    pub data_sources: Vec<String>,
}

/// MITRE ATT&CK enrichment database
pub struct MitreEnrichment {
    techniques: HashMap<String, MitreTechnique>,
    tactic_techniques: HashMap<String, Vec<String>>,
}

impl MitreEnrichment {
    pub fn new() -> Self {
        let mut enrichment = Self {
            techniques: HashMap::new(),
            tactic_techniques: HashMap::new(),
        };
        enrichment.load_builtin_techniques();
        enrichment
    }

    /// Load built-in technique definitions
    fn load_builtin_techniques(&mut self) {
        // Common techniques used in IOC mapping
        let techniques = vec![
            MitreTechnique {
                id: "T1071".to_string(),
                name: "Application Layer Protocol".to_string(),
                description: "Adversaries may communicate using application layer protocols to avoid detection".to_string(),
                tactic: "Command and Control".to_string(),
                platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                detection: "Monitor for anomalous network connections".to_string(),
                data_sources: vec!["Network Traffic".to_string()],
            },
            MitreTechnique {
                id: "T1059".to_string(),
                name: "Command and Scripting Interpreter".to_string(),
                description: "Adversaries may abuse command and script interpreters to execute commands".to_string(),
                tactic: "Execution".to_string(),
                platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                detection: "Monitor command-line arguments".to_string(),
                data_sources: vec!["Process".to_string(), "Command".to_string()],
            },
            MitreTechnique {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                description: "Adversaries may inject code into processes to evade defenses".to_string(),
                tactic: "Defense Evasion".to_string(),
                platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                detection: "Monitor for API calls associated with process injection".to_string(),
                data_sources: vec!["Process".to_string(), "Module".to_string()],
            },
            MitreTechnique {
                id: "T1486".to_string(),
                name: "Data Encrypted for Impact".to_string(),
                description: "Adversaries may encrypt data to interrupt availability (ransomware)".to_string(),
                tactic: "Impact".to_string(),
                platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                detection: "Monitor for rapid file modification".to_string(),
                data_sources: vec!["File".to_string()],
            },
            MitreTechnique {
                id: "T1566".to_string(),
                name: "Phishing".to_string(),
                description: "Adversaries may send phishing messages to gain access".to_string(),
                tactic: "Initial Access".to_string(),
                platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                detection: "Monitor for suspicious email attachments and links".to_string(),
                data_sources: vec!["Application Log".to_string(), "Network Traffic".to_string()],
            },
        ];

        for tech in techniques {
            let tactic = tech.tactic.clone();
            self.tactic_techniques
                .entry(tactic)
                .or_default()
                .push(tech.id.clone());
            self.techniques.insert(tech.id.clone(), tech);
        }
    }

    /// Get technique by ID
    pub fn get_technique(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.get(id)
    }

    /// Get techniques for a tactic
    pub fn get_tactic_techniques(&self, tactic: &str) -> Vec<&MitreTechnique> {
        self.tactic_techniques
            .get(tactic)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.techniques.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Enrich IOC with MITRE techniques
    pub fn enrich_ioc(&self, ioc: &mut Ioc) {
        // Map IOC types to common techniques
        let technique_ids: Vec<&str> = match ioc.ioc_type {
            IocType::IPv4 | IocType::IPv6 | IocType::Domain | IocType::Url => {
                vec!["T1071", "T1102"]
            }
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                vec!["T1204", "T1059"]
            }
            IocType::RegistryKey | IocType::RegistryValue => {
                vec!["T1547", "T1112"]
            }
            IocType::NamedPipe | IocType::MutexName => {
                vec!["T1055"]
            }
            _ => vec![],
        };

        for id in technique_ids {
            if !ioc.mitre_techniques.contains(&id.to_string()) {
                ioc.mitre_techniques.push(id.to_string());
            }
        }

        // Map based on tags/malware families
        for family in &ioc.malware_families {
            let family_lower = family.to_lowercase();
            if family_lower.contains("ransom") {
                if !ioc.mitre_techniques.contains(&"T1486".to_string()) {
                    ioc.mitre_techniques.push("T1486".to_string());
                }
            }
            if family_lower.contains("loader") || family_lower.contains("dropper") {
                if !ioc.mitre_techniques.contains(&"T1105".to_string()) {
                    ioc.mitre_techniques.push("T1105".to_string());
                }
            }
        }
    }
}

impl Default for MitreEnrichment {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Rate limiter for API calls
pub struct RateLimiter {
    /// Semaphore for concurrent request limiting
    semaphore: Arc<Semaphore>,
    /// Per-provider minute counters
    minute_counts: Arc<RwLock<HashMap<String, (u64, u32)>>>,
    /// Per-provider day counters
    day_counts: Arc<RwLock<HashMap<String, (u64, u32)>>>,
}

impl RateLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            minute_counts: Arc::new(RwLock::new(HashMap::new())),
            day_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if request is allowed for provider
    pub async fn check(&self, provider: &str, limits: &RateLimitInfo) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let current_minute = now / 60;
        let current_day = now / 86400;

        // Check minute limit
        {
            let mut counts = self.minute_counts.write().await;
            let entry = counts
                .entry(provider.to_string())
                .or_insert((current_minute, 0));

            if entry.0 != current_minute {
                *entry = (current_minute, 0);
            }

            if entry.1 >= limits.requests_per_minute {
                return false;
            }
            entry.1 += 1;
        }

        // Check day limit
        {
            let mut counts = self.day_counts.write().await;
            let entry = counts
                .entry(provider.to_string())
                .or_insert((current_day, 0));

            if entry.0 != current_day {
                *entry = (current_day, 0);
            }

            if entry.1 >= limits.requests_per_day {
                return false;
            }
            entry.1 += 1;
        }

        true
    }

    /// Acquire a permit for concurrent request
    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("rate limiter semaphore should never be closed")
    }
}

// ============================================================================
// Threat Intelligence Database (Main Interface)
// ============================================================================

/// Main threat intelligence database
pub struct ThreatIntelDb {
    /// IP addresses (IPv4 and IPv6)
    ips: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// Domain names
    domains: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// URLs
    urls: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// File hashes (all types)
    hashes: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// TLS fingerprints (JA3, JA3S, JARM)
    tls_fingerprints: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// Windows artifacts (registry, mutex, pipes)
    windows_artifacts: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// Other IOCs
    other: Arc<RwLock<HashMap<String, Vec<Ioc>>>>,
    /// Statistics
    stats: Arc<RwLock<ThreatIntelStats>>,
    /// Cache
    cache: Arc<ThreatIntelCache>,
    /// Feed providers
    providers: Arc<RwLock<Vec<Box<dyn FeedProvider>>>>,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// MITRE enrichment
    mitre_enrichment: Arc<MitreEnrichment>,
}

#[derive(Debug, Default)]
struct ThreatIntelStats {
    total_iocs: usize,
    ip_count: usize,
    domain_count: usize,
    hash_count: usize,
    url_count: usize,
    tls_count: usize,
    windows_count: usize,
    matches_found: u64,
    lookups_performed: u64,
    cache_hits: u64,
    cache_misses: u64,
    last_update: u64,
    last_feed_refresh: u64,
}

impl ThreatIntelDb {
    /// Create a new threat intelligence database
    pub fn new(cache_path: PathBuf) -> Self {
        Self {
            ips: Arc::new(RwLock::new(HashMap::new())),
            domains: Arc::new(RwLock::new(HashMap::new())),
            urls: Arc::new(RwLock::new(HashMap::new())),
            hashes: Arc::new(RwLock::new(HashMap::new())),
            tls_fingerprints: Arc::new(RwLock::new(HashMap::new())),
            windows_artifacts: Arc::new(RwLock::new(HashMap::new())),
            other: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ThreatIntelStats::default())),
            cache: Arc::new(ThreatIntelCache::new(cache_path)),
            providers: Arc::new(RwLock::new(Vec::new())),
            rate_limiter: Arc::new(RateLimiter::new(10)),
            mitre_enrichment: Arc::new(MitreEnrichment::new()),
        }
    }

    /// Initialize the database
    pub async fn init(&self) -> Result<()> {
        self.cache.init().await?;
        info!("Threat intelligence database initialized");
        Ok(())
    }

    /// Add a feed provider
    pub async fn add_provider(&self, provider: Box<dyn FeedProvider>) {
        let mut providers = self.providers.write().await;
        info!("Added threat intel provider: {}", provider.name());
        providers.push(provider);
    }

    /// Add an IOC to the database
    pub async fn add_ioc(&self, mut ioc: Ioc) {
        // Enrich with MITRE
        self.mitre_enrichment.enrich_ioc(&mut ioc);

        let value = ioc.value.clone();

        match ioc.ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                let mut ips = self.ips.write().await;
                ips.entry(value).or_default().push(ioc);
                self.stats.write().await.ip_count = ips.len();
            }
            IocType::Domain => {
                let mut domains = self.domains.write().await;
                domains.entry(value).or_default().push(ioc);
                self.stats.write().await.domain_count = domains.len();
            }
            IocType::Url => {
                let mut urls = self.urls.write().await;
                urls.entry(value).or_default().push(ioc);
                self.stats.write().await.url_count = urls.len();
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Ssdeep | IocType::Imphash => {
                let mut hashes = self.hashes.write().await;
                hashes.entry(value).or_default().push(ioc);
                self.stats.write().await.hash_count = hashes.len();
            }
            IocType::Ja3 | IocType::Ja3s | IocType::Jarm | IocType::SslCertHash => {
                let mut tls = self.tls_fingerprints.write().await;
                tls.entry(value).or_default().push(ioc);
                self.stats.write().await.tls_count = tls.len();
            }
            IocType::RegistryKey
            | IocType::RegistryValue
            | IocType::MutexName
            | IocType::NamedPipe
            | IocType::ServiceName => {
                let mut windows = self.windows_artifacts.write().await;
                windows.entry(value).or_default().push(ioc);
                self.stats.write().await.windows_count = windows.len();
            }
            _ => {
                let mut other = self.other.write().await;
                other.entry(value).or_default().push(ioc);
            }
        }

        let mut stats = self.stats.write().await;
        stats.total_iocs += 1;
        stats.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Add multiple IOCs to the database efficiently (batch processing)
    pub async fn add_iocs(&self, iocs: Vec<Ioc>) {
        if iocs.is_empty() {
            return;
        }

        // Pre-categorize to minimize lock contention
        let mut batch_ips = HashMap::new();
        let mut batch_domains = HashMap::new();
        let mut batch_urls = HashMap::new();
        let mut batch_hashes = HashMap::new();
        let mut batch_tls = HashMap::new();
        let mut batch_windows = HashMap::new();
        let mut batch_other = HashMap::new();

        let count = iocs.len();

        for mut ioc in iocs {
            // Enrich with MITRE
            self.mitre_enrichment.enrich_ioc(&mut ioc);
            let value = ioc.value.clone();

            match ioc.ioc_type {
                IocType::IPv4 | IocType::IPv6 => {
                    batch_ips.entry(value).or_insert_with(Vec::new).push(ioc);
                }
                IocType::Domain => {
                    batch_domains
                        .entry(value)
                        .or_insert_with(Vec::new)
                        .push(ioc);
                }
                IocType::Url => {
                    batch_urls.entry(value).or_insert_with(Vec::new).push(ioc);
                }
                IocType::Md5
                | IocType::Sha1
                | IocType::Sha256
                | IocType::Ssdeep
                | IocType::Imphash => {
                    batch_hashes.entry(value).or_insert_with(Vec::new).push(ioc);
                }
                IocType::Ja3 | IocType::Ja3s | IocType::Jarm | IocType::SslCertHash => {
                    batch_tls.entry(value).or_insert_with(Vec::new).push(ioc);
                }
                IocType::RegistryKey
                | IocType::RegistryValue
                | IocType::MutexName
                | IocType::NamedPipe
                | IocType::ServiceName => {
                    batch_windows
                        .entry(value)
                        .or_insert_with(Vec::new)
                        .push(ioc);
                }
                _ => {
                    batch_other.entry(value).or_insert_with(Vec::new).push(ioc);
                }
            }
        }

        // Apply batches with single lock per category
        if !batch_ips.is_empty() {
            let mut lock = self.ips.write().await;
            for (k, v) in batch_ips {
                lock.entry(k).or_default().extend(v);
            }
        }
        if !batch_domains.is_empty() {
            let mut lock = self.domains.write().await;
            for (k, v) in batch_domains {
                lock.entry(k).or_default().extend(v);
            }
        }
        if !batch_urls.is_empty() {
            let mut lock = self.urls.write().await;
            for (k, v) in batch_urls {
                lock.entry(k).or_default().extend(v);
            }
        }
        if !batch_hashes.is_empty() {
            let mut lock = self.hashes.write().await;
            for (k, v) in batch_hashes {
                lock.entry(k).or_default().extend(v);
            }
        }
        if !batch_tls.is_empty() {
            let mut lock = self.tls_fingerprints.write().await;
            for (k, v) in batch_tls {
                lock.entry(k).or_default().extend(v);
            }
        }
        if !batch_windows.is_empty() {
            let mut lock = self.windows_artifacts.write().await;
            for (k, v) in batch_windows {
                lock.entry(k).or_default().extend(v);
            }
        }
        if !batch_other.is_empty() {
            let mut lock = self.other.write().await;
            for (k, v) in batch_other {
                lock.entry(k).or_default().extend(v);
            }
        }

        // Update stats once
        let mut stats = self.stats.write().await;
        stats.total_iocs += count;
        stats.ip_count = self.ips.read().await.len();
        stats.domain_count = self.domains.read().await.len();
        stats.url_count = self.urls.read().await.len();
        stats.hash_count = self.hashes.read().await.len();
        stats.tls_count = self.tls_fingerprints.read().await.len();
        stats.windows_count = self.windows_artifacts.read().await.len();
        stats.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Check an IOC against local database and remote providers
    pub async fn check(&self, ioc_type: IocType, value: &str) -> Vec<Ioc> {
        let normalized = Ioc::normalize_value(&ioc_type, value);
        let mut results = Vec::new();

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.lookups_performed += 1;
        }

        // Check cache first
        if let Some(cached) = self.cache.get(ioc_type, &normalized).await {
            let mut stats = self.stats.write().await;
            stats.cache_hits += 1;
            if !cached.is_empty() {
                stats.matches_found += cached.len() as u64;
            }
            return cached;
        }

        {
            let mut stats = self.stats.write().await;
            stats.cache_misses += 1;
        }

        // Check local database
        let local_results = self.check_local(ioc_type, &normalized).await;
        results.extend(local_results);

        // Check remote providers if configured
        let provider_results = self.check_providers(ioc_type, &normalized).await;
        results.extend(provider_results);

        // Update cache
        self.cache.set(ioc_type, &normalized, results.clone()).await;

        // Update match stats
        if !results.is_empty() {
            let mut stats = self.stats.write().await;
            stats.matches_found += results.len() as u64;
        }

        results
    }

    /// Check local database only
    async fn check_local(&self, ioc_type: IocType, value: &str) -> Vec<Ioc> {
        match ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                let ips = self.ips.read().await;
                ips.get(value).cloned().unwrap_or_default()
            }
            IocType::Domain => {
                let domains = self.domains.read().await;

                // Direct match
                if let Some(iocs) = domains.get(value) {
                    return iocs.clone();
                }

                // Subdomain matching
                let parts: Vec<&str> = value.split('.').collect();
                for i in 1..parts.len().saturating_sub(1) {
                    let parent = parts[i..].join(".");
                    if let Some(iocs) = domains.get(&parent) {
                        return iocs.clone();
                    }
                }

                Vec::new()
            }
            IocType::Url => {
                let urls = self.urls.read().await;
                urls.get(value).cloned().unwrap_or_default()
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Ssdeep | IocType::Imphash => {
                let hashes = self.hashes.read().await;
                hashes.get(value).cloned().unwrap_or_default()
            }
            IocType::Ja3 | IocType::Ja3s | IocType::Jarm | IocType::SslCertHash => {
                let tls = self.tls_fingerprints.read().await;
                tls.get(value).cloned().unwrap_or_default()
            }
            IocType::RegistryKey
            | IocType::RegistryValue
            | IocType::MutexName
            | IocType::NamedPipe
            | IocType::ServiceName => {
                let windows = self.windows_artifacts.read().await;
                windows.get(value).cloned().unwrap_or_default()
            }
            _ => {
                let other = self.other.read().await;
                other.get(value).cloned().unwrap_or_default()
            }
        }
    }

    /// Check remote providers
    async fn check_providers(&self, ioc_type: IocType, value: &str) -> Vec<Ioc> {
        let providers = self.providers.read().await;
        let mut results = Vec::new();

        for provider in providers.iter() {
            if !provider.is_configured() {
                continue;
            }

            // Check rate limit
            if !self
                .rate_limiter
                .check(provider.name(), &provider.rate_limit())
                .await
            {
                debug!("Rate limited for provider: {}", provider.name());
                continue;
            }

            match provider.lookup(ioc_type, value).await {
                Ok(iocs) => {
                    results.extend(iocs);
                }
                Err(e) => {
                    warn!("Provider {} lookup failed: {}", provider.name(), e);
                }
            }
        }

        results
    }

    /// Refresh feeds from all providers
    pub async fn refresh_feeds(&self) -> Result<usize> {
        let providers = self.providers.read().await;
        let mut total_iocs = 0;

        for provider in providers.iter() {
            if !provider.is_configured() {
                continue;
            }

            info!("Refreshing feed from: {}", provider.name());

            match provider.download_feed().await {
                Ok(iocs) => {
                    let count = iocs.len();
                    self.add_iocs(iocs).await;
                    total_iocs += count;
                    info!("Loaded {} IOCs from {}", count, provider.name());
                }
                Err(e) => {
                    error!("Failed to refresh feed from {}: {}", provider.name(), e);
                }
            }
        }

        let mut stats = self.stats.write().await;
        stats.last_feed_refresh = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        info!("Feed refresh complete: {} total IOCs loaded", total_iocs);
        Ok(total_iocs)
    }

    /// Load IOCs from JSON file/string
    pub async fn load_from_json(&self, json_data: &str) -> Result<usize> {
        let iocs: Vec<serde_json::Value> = serde_json::from_str(json_data)?;
        let mut parsed_iocs = Vec::new();

        for ioc_value in iocs {
            if let Some(ioc) = Self::parse_ioc_json(&ioc_value) {
                parsed_iocs.push(ioc);
            }
        }

        let count = parsed_iocs.len();
        self.add_iocs(parsed_iocs).await;

        info!(count = count, "Loaded IOCs from JSON");
        Ok(count)
    }

    /// Parse IOC from JSON value
    pub(crate) fn parse_ioc_json(value: &serde_json::Value) -> Option<Ioc> {
        let ioc_type_str = value.get("type")?.as_str()?;
        let ioc_value = value.get("value")?.as_str()?;

        let ioc_type = IocType::from_str(ioc_type_str)?;

        let mut ioc = Ioc::new(
            ioc_type,
            ioc_value.to_string(),
            value
                .get("source")
                .and_then(|s| s.as_str())
                .unwrap_or("Custom")
                .to_string(),
        );

        if let Some(confidence) = value.get("confidence").and_then(|c| c.as_f64()) {
            ioc.confidence = (confidence as f32).clamp(0.0, 1.0);
        }

        if let Some(severity) = value.get("severity").and_then(|s| s.as_str()) {
            ioc.severity = match severity.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };
        }

        if let Some(desc) = value.get("description").and_then(|d| d.as_str()) {
            ioc.description = Some(desc.to_string());
        }

        if let Some(tags) = value.get("tags").and_then(|t| t.as_array()) {
            ioc.tags = tags
                .iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect();
        }

        if let Some(techniques) = value.get("mitre_techniques").and_then(|t| t.as_array()) {
            ioc.mitre_techniques = techniques
                .iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect();
        }

        if let Some(first) = value.get("first_seen").and_then(|f| f.as_u64()) {
            ioc.first_seen = Some(first);
        }

        if let Some(last) = value.get("last_seen").and_then(|l| l.as_u64()) {
            ioc.last_seen = Some(last);
        }

        if let Some(exp) = value.get("expiration").and_then(|e| e.as_u64()) {
            ioc.expiration = Some(exp);
        }

        Some(ioc)
    }

    /// Load IOCs from STIX 2.x format
    pub async fn load_from_stix(&self, stix_data: &str) -> Result<usize> {
        let stix: serde_json::Value = serde_json::from_str(stix_data)?;
        let mut count = 0;

        // Check STIX version
        let spec_version = stix
            .get("spec_version")
            .and_then(|v| v.as_str())
            .unwrap_or("2.0");

        if let Some(objects) = stix.get("objects").and_then(|o| o.as_array()) {
            for obj in objects {
                let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

                match obj_type {
                    "indicator" => {
                        if let Some(ioc) = Self::parse_stix_indicator(obj) {
                            self.add_ioc(ioc).await;
                            count += 1;
                        }
                    }
                    "malware" | "threat-actor" | "campaign" => {
                        // Could be used for enrichment
                        debug!("Skipping STIX object type: {}", obj_type);
                    }
                    _ => {}
                }
            }
        }

        info!(
            count = count,
            version = spec_version,
            "Loaded IOCs from STIX"
        );
        Ok(count)
    }

    /// Parse STIX 2.x indicator
    fn parse_stix_indicator(obj: &serde_json::Value) -> Option<Ioc> {
        let pattern = obj.get("pattern")?.as_str()?;

        // Parse STIX pattern (simplified)
        let (ioc_type, value) = Self::parse_stix_pattern(pattern)?;

        let mut ioc = Ioc::new(ioc_type, value, "STIX".to_string());

        // Extract metadata
        if let Some(name) = obj.get("name").and_then(|n| n.as_str()) {
            ioc.description = Some(name.to_string());
        }

        if let Some(confidence) = obj.get("confidence").and_then(|c| c.as_i64()) {
            ioc.confidence = (confidence as f32 / 100.0).clamp(0.0, 1.0);
        }

        // Extract kill chain phases
        if let Some(phases) = obj.get("kill_chain_phases").and_then(|k| k.as_array()) {
            for phase in phases {
                if let Some(name) = phase.get("phase_name").and_then(|n| n.as_str()) {
                    ioc.kill_chain_phase = Some(name.to_string());
                    break;
                }
            }
        }

        // Extract labels as tags
        if let Some(labels) = obj.get("labels").and_then(|l| l.as_array()) {
            for label in labels {
                if let Some(label_str) = label.as_str() {
                    ioc.tags.push(label_str.to_string());
                }
            }
        }

        // Parse timestamps
        if let Some(created) = obj.get("created").and_then(|c| c.as_str()) {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(created) {
                ioc.first_seen = Some(ts.timestamp() as u64);
            }
        }

        if let Some(modified) = obj.get("modified").and_then(|m| m.as_str()) {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(modified) {
                ioc.last_seen = Some(ts.timestamp() as u64);
            }
        }

        if let Some(valid_until) = obj.get("valid_until").and_then(|v| v.as_str()) {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(valid_until) {
                ioc.expiration = Some(ts.timestamp() as u64);
            }
        }

        Some(ioc)
    }

    /// Parse STIX 2.x pattern string
    fn parse_stix_pattern(pattern: &str) -> Option<(IocType, String)> {
        // STIX 2.x patterns like:
        // [ipv4-addr:value = '1.2.3.4']
        // [domain-name:value = 'evil.com']
        // [file:hashes.'SHA-256' = 'abc123']

        let extract_value = |p: &str| -> Option<String> {
            // The value is the last single-quoted token (after `=`), since the
            // object-path itself may be quoted, e.g. file:hashes.'SHA-256'.
            let end = p.rfind('\'')?;
            let start = p[..end].rfind('\'')?;
            Some(p[start + 1..end].to_string())
        };

        if pattern.contains("ipv4-addr:value") {
            return Some((IocType::IPv4, extract_value(pattern)?));
        }
        if pattern.contains("ipv6-addr:value") {
            return Some((IocType::IPv6, extract_value(pattern)?));
        }
        if pattern.contains("domain-name:value") {
            return Some((IocType::Domain, extract_value(pattern)?));
        }
        if pattern.contains("url:value") {
            return Some((IocType::Url, extract_value(pattern)?));
        }
        if pattern.contains("email-addr:value") {
            return Some((IocType::Email, extract_value(pattern)?));
        }
        if pattern.contains("SHA-256") || pattern.contains("sha256") {
            return Some((IocType::Sha256, extract_value(pattern)?));
        }
        if pattern.contains("SHA-1") || pattern.contains("sha1") {
            return Some((IocType::Sha1, extract_value(pattern)?));
        }
        if pattern.contains("MD5") || pattern.contains("md5") {
            return Some((IocType::Md5, extract_value(pattern)?));
        }
        if pattern.contains("windows-registry-key:key") {
            return Some((IocType::RegistryKey, extract_value(pattern)?));
        }
        if pattern.contains("mutex:name") {
            return Some((IocType::MutexName, extract_value(pattern)?));
        }

        None
    }

    /// Get database statistics
    pub async fn get_stats(
        &self,
    ) -> (
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        u64,
        u64,
        u64,
        u64,
    ) {
        let stats = self.stats.read().await;
        (
            stats.total_iocs,
            stats.ip_count,
            stats.domain_count,
            stats.hash_count,
            stats.url_count,
            stats.tls_count,
            stats.windows_count,
            stats.matches_found,
            stats.lookups_performed,
            stats.cache_hits,
            stats.cache_misses,
        )
    }

    /// Clear all IOCs
    pub async fn clear(&self) {
        self.ips.write().await.clear();
        self.domains.write().await.clear();
        self.urls.write().await.clear();
        self.hashes.write().await.clear();
        self.tls_fingerprints.write().await.clear();
        self.windows_artifacts.write().await.clear();
        self.other.write().await.clear();

        let mut stats = self.stats.write().await;
        *stats = ThreatIntelStats::default();
    }

    /// Record false positive feedback
    pub async fn record_false_positive(&self, ioc_type: IocType, value: &str) {
        let normalized = Ioc::normalize_value(&ioc_type, value);

        // Update IOC in the appropriate storage
        let update_iocs = |iocs: &mut Vec<Ioc>| {
            for ioc in iocs {
                ioc.false_positive_count += 1;
            }
        };

        match ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                let mut ips = self.ips.write().await;
                if let Some(iocs) = ips.get_mut(&normalized) {
                    update_iocs(iocs);
                }
            }
            IocType::Domain => {
                let mut domains = self.domains.write().await;
                if let Some(iocs) = domains.get_mut(&normalized) {
                    update_iocs(iocs);
                }
            }
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                let mut hashes = self.hashes.write().await;
                if let Some(iocs) = hashes.get_mut(&normalized) {
                    update_iocs(iocs);
                }
            }
            _ => {}
        }
    }

    /// Record true positive feedback
    pub async fn record_true_positive(&self, ioc_type: IocType, value: &str) {
        let normalized = Ioc::normalize_value(&ioc_type, value);

        let update_iocs = |iocs: &mut Vec<Ioc>| {
            for ioc in iocs {
                ioc.true_positive_count += 1;
            }
        };

        match ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                let mut ips = self.ips.write().await;
                if let Some(iocs) = ips.get_mut(&normalized) {
                    update_iocs(iocs);
                }
            }
            IocType::Domain => {
                let mut domains = self.domains.write().await;
                if let Some(iocs) = domains.get_mut(&normalized) {
                    update_iocs(iocs);
                }
            }
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                let mut hashes = self.hashes.write().await;
                if let Some(iocs) = hashes.get_mut(&normalized) {
                    update_iocs(iocs);
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// Threat Intelligence Analyzer
// ============================================================================

/// Main analyzer interface for event processing
pub struct ThreatIntelAnalyzer {
    db: Arc<ThreatIntelDb>,
}

impl ThreatIntelAnalyzer {
    /// Create a new threat intel analyzer
    pub fn new(cache_path: PathBuf) -> Self {
        Self {
            db: Arc::new(ThreatIntelDb::new(cache_path)),
        }
    }

    /// Create with default cache path
    pub fn with_defaults() -> Self {
        let cache_path = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("tamandua")
            .join("threat_intel.db");

        Self::new(cache_path)
    }

    /// Get database reference
    pub fn get_db(&self) -> Arc<ThreatIntelDb> {
        self.db.clone()
    }

    /// Initialize with providers
    pub async fn init(&self, config: ThreatIntelConfig) -> Result<()> {
        self.db.init().await?;

        // Add configured providers
        if let Some(misp_config) = config.misp {
            if misp_config.enabled {
                let provider = MispProvider::new(
                    misp_config.url,
                    misp_config.api_key,
                    misp_config.verify_ssl,
                )?;
                self.db.add_provider(Box::new(provider)).await;
            }
        }

        if let Some(otx_config) = config.alienvault_otx {
            if otx_config.enabled {
                match AlienVaultOtxProvider::new(otx_config.api_key) {
                    Ok(provider) => self.db.add_provider(Box::new(provider)).await,
                    Err(e) => warn!("Failed to initialize AlienVault OTX provider: {}", e),
                }
            }
        }

        if config.abusech.map(|c| c.enabled).unwrap_or(true) {
            match AbusechProvider::new() {
                Ok(provider) => self.db.add_provider(Box::new(provider)).await,
                Err(e) => warn!("Failed to initialize Abuse.ch provider: {}", e),
            }
        }

        if let Some(vt_config) = config.virustotal {
            if vt_config.enabled {
                match VirusTotalProvider::new(vt_config.api_key) {
                    Ok(provider) => self.db.add_provider(Box::new(provider)).await,
                    Err(e) => warn!("Failed to initialize VirusTotal provider: {}", e),
                }
            }
        }

        if let Some(shodan_config) = config.shodan {
            if shodan_config.enabled {
                match ShodanProvider::new(shodan_config.api_key) {
                    Ok(provider) => self.db.add_provider(Box::new(provider)).await,
                    Err(e) => warn!("Failed to initialize Shodan provider: {}", e),
                }
            }
        }

        // Refresh feeds
        if config.auto_refresh {
            self.db.refresh_feeds().await?;
        }

        Ok(())
    }

    /// Analyze an event for threat indicators
    pub async fn analyze_event(&self, event: &TelemetryEvent) -> Vec<Detection> {
        let mut detections = Vec::new();

        match &event.payload {
            EventPayload::Network(net_event) => {
                // Check remote IP
                let iocs = self.db.check(IocType::IPv4, &net_event.remote_ip).await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &net_event.remote_ip));
                }
            }
            EventPayload::Dns(dns_event) => {
                // Check queried domain
                let iocs = self.db.check(IocType::Domain, &dns_event.query).await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &dns_event.query));
                }

                // Check resolved IPs
                for response in &dns_event.responses {
                    let iocs = self.db.check(IocType::IPv4, response).await;
                    for ioc in iocs {
                        detections.push(self.create_detection(&ioc, response));
                    }
                }
            }
            EventPayload::File(file_event) => {
                // Check file hash
                let hash_hex = hex::encode(&file_event.sha256);
                let iocs = self.db.check(IocType::Sha256, &hash_hex).await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &hash_hex));
                }

                // Check file path patterns
                let iocs = self.db.check(IocType::FilePath, &file_event.path).await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &file_event.path));
                }
            }
            EventPayload::Process(proc_event) => {
                // Check process hash
                let hash_hex = hex::encode(&proc_event.sha256);
                let iocs = self.db.check(IocType::Sha256, &hash_hex).await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &hash_hex));
                }

                // Check process name
                let iocs = self.db.check(IocType::ProcessName, &proc_event.name).await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &proc_event.name));
                }
            }
            EventPayload::Registry(reg_event) => {
                // Check registry key
                let iocs = self
                    .db
                    .check(IocType::RegistryKey, &reg_event.key_path)
                    .await;
                for ioc in iocs {
                    detections.push(self.create_detection(&ioc, &reg_event.key_path));
                }
            }
            _ => {}
        }

        detections
    }

    /// Batch analyze multiple values
    pub async fn batch_check(&self, queries: &[(IocType, String)]) -> Vec<(String, ThreatScore)> {
        let mut results = Vec::new();

        for (ioc_type, value) in queries {
            let iocs = self.db.check(*ioc_type, value).await;
            let score = ThreatScore::calculate(&iocs);
            results.push((value.clone(), score));
        }

        results
    }

    fn create_detection(&self, ioc: &Ioc, matched_value: &str) -> Detection {
        let adjusted_confidence = ioc.age_adjusted_confidence();

        Detection {
            detection_type: DetectionType::ThreatIntel,
            rule_name: format!("ThreatIntel_{}", ioc.ioc_type.as_str()),
            confidence: adjusted_confidence,
            description: format!(
                "Threat Intelligence match: {} = {} (Source: {}, Confidence: {:.0}%){}",
                ioc.ioc_type.as_str(),
                matched_value,
                ioc.source,
                adjusted_confidence * 100.0,
                ioc.description
                    .as_ref()
                    .map(|d| format!(" - {}", d))
                    .unwrap_or_default()
            ),
            mitre_tactics: ioc.mitre_tactics.clone(),
            mitre_techniques: ioc.mitre_techniques.clone(),
        }
    }

    /// Load feeds and built-in IOCs
    pub async fn load_feeds(&self) -> Result<()> {
        // Load built-in IOCs
        for ioc in get_builtin_iocs() {
            self.db.add_ioc(ioc).await;
        }

        // Refresh from providers
        self.db.refresh_feeds().await?;

        Ok(())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Threat intelligence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// MISP configuration
    pub misp: Option<MispConfig>,
    /// AlienVault OTX configuration
    pub alienvault_otx: Option<OtxConfig>,
    /// Abuse.ch configuration
    pub abusech: Option<AbusechConfig>,
    /// VirusTotal configuration
    pub virustotal: Option<VirusTotalConfig>,
    /// Shodan configuration
    pub shodan: Option<ShodanConfig>,
    /// Auto-refresh feeds on startup
    #[serde(default)]
    pub auto_refresh: bool,
    /// Feed refresh interval in seconds
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
    /// Cache path
    pub cache_path: Option<String>,
}

fn default_refresh_interval() -> u64 {
    3600 // 1 hour
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispConfig {
    pub enabled: bool,
    pub url: String,
    pub api_key: String,
    #[serde(default = "default_true")]
    pub verify_ssl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxConfig {
    pub enabled: bool,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbusechConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalConfig {
    pub enabled: bool,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanConfig {
    pub enabled: bool,
    pub api_key: String,
}

fn default_true() -> bool {
    true
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            misp: None,
            alienvault_otx: None,
            abusech: Some(AbusechConfig { enabled: true }),
            virustotal: None,
            shodan: None,
            auto_refresh: true,
            refresh_interval: 3600,
            cache_path: None,
        }
    }
}

// ============================================================================
// Built-in IOCs
// ============================================================================

/// Get built-in IOCs for basic protection
pub fn get_builtin_iocs() -> Vec<Ioc> {
    vec![
        // Tor hidden services
        Ioc {
            ioc_type: IocType::Domain,
            value: "*.onion".to_string(),
            original_value: "*.onion".to_string(),
            source: "builtin".to_string(),
            source_id: None,
            confidence: 0.7,
            severity: Severity::Medium,
            description: Some("Tor hidden service domain".to_string()),
            tags: vec!["tor".to_string(), "anonymization".to_string()],
            mitre_techniques: vec!["T1090.003".to_string()],
            mitre_tactics: vec!["command-and-control".to_string()],
            threat_actor: None,
            campaign: None,
            malware_families: Vec::new(),
            first_seen: None,
            last_seen: None,
            expiration: None,
            cached_at: 0,
            false_positive_count: 0,
            true_positive_count: 0,
            related_iocs: Vec::new(),
            kill_chain_phase: Some("command-and-control".to_string()),
            metadata: HashMap::new(),
        },
        // Cobalt Strike default JA3
        Ioc {
            ioc_type: IocType::Ja3,
            value: "72a589da586844d7f0818ce684948eea".to_string(),
            original_value: "72a589da586844d7f0818ce684948eea".to_string(),
            source: "builtin".to_string(),
            source_id: None,
            confidence: 0.85,
            severity: Severity::High,
            description: Some("Cobalt Strike default JA3 fingerprint".to_string()),
            tags: vec!["cobalt-strike".to_string(), "c2".to_string()],
            mitre_techniques: vec!["T1071.001".to_string()],
            mitre_tactics: vec!["command-and-control".to_string()],
            threat_actor: None,
            campaign: None,
            malware_families: vec!["CobaltStrike".to_string()],
            first_seen: None,
            last_seen: None,
            expiration: None,
            cached_at: 0,
            false_positive_count: 0,
            true_positive_count: 0,
            related_iocs: Vec::new(),
            kill_chain_phase: Some("command-and-control".to_string()),
            metadata: HashMap::new(),
        },
    ]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_type_parsing() {
        assert_eq!(IocType::from_str("ipv4"), Some(IocType::IPv4));
        assert_eq!(IocType::from_str("domain-name"), Some(IocType::Domain));
        assert_eq!(IocType::from_str("sha256"), Some(IocType::Sha256));
        assert_eq!(IocType::from_str("ja3"), Some(IocType::Ja3));
        assert_eq!(IocType::from_str("named-pipe"), Some(IocType::NamedPipe));
        assert_eq!(IocType::from_str("unknown-type"), None);
    }

    #[test]
    fn test_ioc_normalization() {
        assert_eq!(
            Ioc::normalize_value(&IocType::Domain, "EXAMPLE.COM"),
            "example.com"
        );
        assert_eq!(Ioc::normalize_value(&IocType::Sha256, "ABC123"), "abc123");
        assert_eq!(
            Ioc::normalize_value(&IocType::RegistryKey, "hklm/software/test"),
            "HKLM\\SOFTWARE\\TEST"
        );
    }

    #[test]
    fn test_age_adjusted_confidence() {
        let mut ioc = Ioc::new(IocType::IPv4, "1.2.3.4".to_string(), "test".to_string());
        ioc.confidence = 0.8;

        // Fresh IOC should have near-original confidence
        let adjusted = ioc.age_adjusted_confidence();
        assert!(adjusted > 0.7);

        // With false positives, confidence should decrease
        ioc.false_positive_count = 5;
        ioc.true_positive_count = 0;
        let adjusted_with_fp = ioc.age_adjusted_confidence();
        assert!(adjusted_with_fp < adjusted);
    }

    #[test]
    fn test_threat_score_calculation() {
        let iocs = vec![
            {
                let mut ioc = Ioc::new(
                    IocType::IPv4,
                    "1.2.3.4".to_string(),
                    "VirusTotal".to_string(),
                );
                ioc.confidence = 0.9;
                ioc
            },
            {
                let mut ioc = Ioc::new(IocType::IPv4, "1.2.3.4".to_string(), "MISP".to_string());
                ioc.confidence = 0.8;
                ioc
            },
        ];

        let score = ThreatScore::calculate(&iocs);

        assert!(score.score > 50.0);
        assert!(score.confidence > 0.5);
        assert_eq!(score.source_scores.len(), 2);
        assert!(matches!(
            score.risk_level,
            RiskLevel::High | RiskLevel::Critical
        ));
    }

    #[tokio::test]
    async fn test_threat_intel_db() {
        let db = ThreatIntelDb::new(PathBuf::from("/tmp/test_cache.db"));

        let ioc = Ioc::new(IocType::IPv4, "192.168.1.1".to_string(), "test".to_string());
        db.add_ioc(ioc).await;

        let results = db.check(IocType::IPv4, "192.168.1.1").await;
        assert_eq!(results.len(), 1);

        let results = db.check(IocType::IPv4, "10.0.0.1").await;
        assert!(results.is_empty());
    }

    #[test]
    fn test_stix_pattern_parsing() {
        let patterns = vec![
            ("[ipv4-addr:value = '1.2.3.4']", IocType::IPv4, "1.2.3.4"),
            (
                "[domain-name:value = 'evil.com']",
                IocType::Domain,
                "evil.com",
            ),
            (
                "[file:hashes.'SHA-256' = 'abc123']",
                IocType::Sha256,
                "abc123",
            ),
        ];

        for (pattern, expected_type, expected_value) in patterns {
            let result = ThreatIntelDb::parse_stix_pattern(pattern);
            assert!(result.is_some(), "Failed to parse: {}", pattern);
            let (ioc_type, value) = result.unwrap();
            assert_eq!(ioc_type, expected_type);
            assert_eq!(value, expected_value);
        }
    }
}
