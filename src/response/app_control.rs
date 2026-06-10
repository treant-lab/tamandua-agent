//! Application Whitelisting and Control Module
//!
//! Provides comprehensive application control capabilities:
//! - Whitelist/Blacklist management by hash, path, certificate, or publisher
//! - Multiple enforcement modes (Audit, Block, Learning)
//! - Platform-specific enforcement (Windows WDAC, Linux AppArmor/SELinux)
//! - Remote policy updates from server
//! - Default policies for trusted binaries
//!
//! MITRE ATT&CK:
//! - T1204 (User Execution) - Prevention
//! - T1059 (Command and Scripting Interpreter) - Prevention
//! - T1218 (Signed Binary Proxy Execution) - Detection

// Application whitelisting. AppArmor helpers and scaffolded fields retained.
#![allow(dead_code, unused_variables)]

#[cfg(all(target_os = "linux", feature = "linux-app-control"))]
pub mod app_control_linux;
#[cfg(all(target_os = "linux", feature = "linux-app-control"))]
#[path = "app_control/apparmor.rs"]
pub mod apparmor;
#[cfg(all(target_os = "linux", feature = "linux-app-control"))]
#[path = "app_control/selinux.rs"]
pub mod selinux;

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

/// Enforcement mode for application control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Log only, do not block
    Audit,
    /// Actively block unauthorized applications
    Block,
    /// Automatically add executed applications to whitelist
    Learning,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        EnforcementMode::Audit
    }
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
}

/// Rule match type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMatchType {
    /// Match by SHA256 hash
    Hash,
    /// Match by file path (supports wildcards)
    Path,
    /// Match by certificate/code signing
    Certificate,
    /// Match by software publisher
    Publisher,
}

/// Application control rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppControlRule {
    /// Unique rule identifier
    pub id: String,
    /// Rule name/description
    pub name: String,
    /// Match type
    pub match_type: RuleMatchType,
    /// Match value (hash, path pattern, certificate CN, or publisher name)
    pub match_value: String,
    /// Action to take
    pub action: RuleAction,
    /// Rule priority (higher = more important)
    pub priority: u32,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Optional comment/reason
    pub comment: Option<String>,
    /// Timestamp when rule was created
    pub created_at: u64,
    /// Timestamp when rule was last modified
    pub modified_at: u64,
    /// Source of the rule (local, server, learning)
    pub source: RuleSource,
}

/// Source of a rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    /// Manually created locally
    Local,
    /// Pushed from server
    Server,
    /// Auto-created during learning mode
    Learning,
    /// Built-in default rule
    Default,
}

/// Application control policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppControlPolicy {
    /// Policy version
    pub version: u32,
    /// Enforcement mode
    pub mode: EnforcementMode,
    /// List of rules
    pub rules: Vec<AppControlRule>,
    /// Default action when no rule matches
    pub default_action: RuleAction,
    /// Policy last updated timestamp
    pub last_updated: u64,
    /// Policy checksum for sync
    pub checksum: String,
}

impl Default for AppControlPolicy {
    fn default() -> Self {
        let now = Self::current_timestamp();
        Self {
            version: 1,
            mode: EnforcementMode::Audit,
            rules: Self::default_rules(),
            default_action: RuleAction::Allow,
            last_updated: now,
            checksum: String::new(),
        }
    }
}

impl AppControlPolicy {
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Generate default rules for trusted sources
    fn default_rules() -> Vec<AppControlRule> {
        let now = Self::current_timestamp();
        let mut rules = Vec::new();

        // Windows: Allow Microsoft-signed binaries
        #[cfg(target_os = "windows")]
        {
            rules.push(AppControlRule {
                id: "default_microsoft_signed".to_string(),
                name: "Allow Microsoft-signed binaries".to_string(),
                match_type: RuleMatchType::Publisher,
                match_value: "Microsoft".to_string(),
                action: RuleAction::Allow,
                priority: 1000,
                enabled: true,
                comment: Some("Default rule: Allow all Microsoft-signed binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_windows_system".to_string(),
                name: "Allow Windows system binaries".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "C:\\Windows\\System32\\*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow Windows System32 binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_windows_syswow64".to_string(),
                name: "Allow Windows SysWOW64 binaries".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "C:\\Windows\\SysWOW64\\*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow Windows SysWOW64 binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_program_files".to_string(),
                name: "Allow Program Files".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "C:\\Program Files\\*".to_string(),
                action: RuleAction::Allow,
                priority: 800,
                enabled: true,
                comment: Some("Default rule: Allow Program Files installations".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_program_files_x86".to_string(),
                name: "Allow Program Files (x86)".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "C:\\Program Files (x86)\\*".to_string(),
                action: RuleAction::Allow,
                priority: 800,
                enabled: true,
                comment: Some("Default rule: Allow Program Files (x86) installations".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            // Block by default: Temp, Downloads, AppData
            rules.push(AppControlRule {
                id: "default_block_temp".to_string(),
                name: "Block Temp folder execution".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "*\\Temp\\*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from Temp folders".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_block_downloads".to_string(),
                name: "Block Downloads folder execution".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "*\\Downloads\\*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from Downloads folder".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_block_appdata_local_temp".to_string(),
                name: "Block AppData\\Local\\Temp execution".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "*\\AppData\\Local\\Temp\\*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some(
                    "Default rule: Block execution from AppData\\Local\\Temp".to_string(),
                ),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });
        }

        // macOS: Allow Apple-signed binaries
        #[cfg(target_os = "macos")]
        {
            rules.push(AppControlRule {
                id: "default_apple_signed".to_string(),
                name: "Allow Apple-signed binaries".to_string(),
                match_type: RuleMatchType::Publisher,
                match_value: "Apple".to_string(),
                action: RuleAction::Allow,
                priority: 1000,
                enabled: true,
                comment: Some("Default rule: Allow all Apple-signed binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_system_apps".to_string(),
                name: "Allow System Applications".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/System/Applications/*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow macOS system applications".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_applications".to_string(),
                name: "Allow Applications folder".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/Applications/*".to_string(),
                action: RuleAction::Allow,
                priority: 800,
                enabled: true,
                comment: Some("Default rule: Allow Applications folder".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_usr_bin".to_string(),
                name: "Allow /usr/bin".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/usr/bin/*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow /usr/bin binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            // Block: Downloads and tmp
            rules.push(AppControlRule {
                id: "default_block_downloads".to_string(),
                name: "Block Downloads folder".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "*/Downloads/*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from Downloads".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_block_tmp".to_string(),
                name: "Block /tmp folder".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/tmp/*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from /tmp".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });
        }

        // Linux: Allow system binaries
        #[cfg(target_os = "linux")]
        {
            rules.push(AppControlRule {
                id: "default_usr_bin".to_string(),
                name: "Allow /usr/bin".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/usr/bin/*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow /usr/bin binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_usr_sbin".to_string(),
                name: "Allow /usr/sbin".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/usr/sbin/*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow /usr/sbin binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_bin".to_string(),
                name: "Allow /bin".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/bin/*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow /bin binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_sbin".to_string(),
                name: "Allow /sbin".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/sbin/*".to_string(),
                action: RuleAction::Allow,
                priority: 900,
                enabled: true,
                comment: Some("Default rule: Allow /sbin binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_usr_local_bin".to_string(),
                name: "Allow /usr/local/bin".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/usr/local/bin/*".to_string(),
                action: RuleAction::Allow,
                priority: 800,
                enabled: true,
                comment: Some("Default rule: Allow /usr/local/bin binaries".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_opt".to_string(),
                name: "Allow /opt applications".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/opt/*".to_string(),
                action: RuleAction::Allow,
                priority: 700,
                enabled: true,
                comment: Some("Default rule: Allow /opt applications".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            // Block: /tmp, /var/tmp, /dev/shm
            rules.push(AppControlRule {
                id: "default_block_tmp".to_string(),
                name: "Block /tmp folder".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/tmp/*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from /tmp".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_block_var_tmp".to_string(),
                name: "Block /var/tmp folder".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/var/tmp/*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from /var/tmp".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });

            rules.push(AppControlRule {
                id: "default_block_dev_shm".to_string(),
                name: "Block /dev/shm folder".to_string(),
                match_type: RuleMatchType::Path,
                match_value: "/dev/shm/*".to_string(),
                action: RuleAction::Block,
                priority: 500,
                enabled: true,
                comment: Some("Default rule: Block execution from /dev/shm".to_string()),
                created_at: now,
                modified_at: now,
                source: RuleSource::Default,
            });
        }

        rules
    }

    /// Calculate policy checksum
    pub fn calculate_checksum(&self) -> String {
        let data = serde_json::to_string(&self.rules).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Update checksum
    pub fn update_checksum(&mut self) {
        self.checksum = self.calculate_checksum();
    }
}

/// Execution decision result
#[derive(Debug, Clone)]
pub struct ExecutionDecision {
    /// Whether execution is allowed
    pub allowed: bool,
    /// Matched rule (if any)
    pub matched_rule: Option<AppControlRule>,
    /// Reason for decision
    pub reason: String,
    /// Whether this was a default decision (no rule matched)
    pub is_default: bool,
}

/// Blocked execution event for telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedExecution {
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub sha256: String,
    pub signer: Option<String>,
    pub publisher: Option<String>,
    pub matched_rule_id: Option<String>,
    pub matched_rule_name: Option<String>,
    pub reason: String,
    pub action_taken: String,
}

/// Application Control Manager
pub struct AppControlManager {
    /// Current policy
    policy: Arc<RwLock<AppControlPolicy>>,
    /// Hash cache for performance
    hash_cache: Arc<RwLock<HashMap<String, String>>>,
    /// Signer cache
    signer_cache: Arc<RwLock<HashMap<String, (bool, Option<String>)>>>,
    /// Learned applications (in learning mode)
    learned_apps: Arc<RwLock<HashSet<String>>>,
    /// Event sender for blocked execution alerts
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Event receiver
    event_rx: Arc<RwLock<mpsc::Receiver<TelemetryEvent>>>,
    /// Statistics
    stats: Arc<RwLock<AppControlStats>>,
    /// Configuration
    config: AgentConfig,
}

/// Statistics for application control
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppControlStats {
    pub total_evaluated: u64,
    pub allowed_by_rule: u64,
    pub blocked_by_rule: u64,
    pub allowed_by_default: u64,
    pub blocked_by_default: u64,
    pub learned_applications: u64,
    pub last_block_timestamp: Option<u64>,
    pub last_allow_timestamp: Option<u64>,
}

impl AppControlManager {
    /// Create a new application control manager
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        Self {
            policy: Arc::new(RwLock::new(AppControlPolicy::default())),
            hash_cache: Arc::new(RwLock::new(HashMap::new())),
            signer_cache: Arc::new(RwLock::new(HashMap::new())),
            learned_apps: Arc::new(RwLock::new(HashSet::new())),
            event_tx: tx,
            event_rx: Arc::new(RwLock::new(rx)),
            stats: Arc::new(RwLock::new(AppControlStats::default())),
            config: config.clone(),
        }
    }

    /// Initialize the application control manager
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing application control manager");

        // Load policy from file if exists
        if let Err(e) = self.load_policy_from_file().await {
            debug!("No existing policy file found, using defaults: {}", e);
        }

        // Check for platform-specific enforcement capabilities
        self.check_enforcement_capabilities().await;

        info!(
            mode = ?self.get_mode().await,
            rules = self.policy.read().await.rules.len(),
            "Application control initialized"
        );

        Ok(())
    }

    /// Check platform enforcement capabilities
    async fn check_enforcement_capabilities(&self) {
        #[cfg(target_os = "windows")]
        {
            // Check for WDAC availability
            if Self::check_wdac_available() {
                info!("Windows Defender Application Control (WDAC) is available");
            } else {
                debug!("WDAC not available, using process termination fallback");
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check for AppArmor availability
            if Self::check_apparmor_available() {
                info!("AppArmor is available");
            } else {
                debug!("AppArmor not available, using process termination fallback");
            }
        }
    }

    /// Check if WDAC is available (Windows)
    #[cfg(target_os = "windows")]
    fn check_wdac_available() -> bool {
        use std::process::Command;

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty CodeIntegrityPolicyEnforcementStatus",
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
                // 0 = Off, 1 = Audit mode, 2 = Enforced
                status == "1" || status == "2"
            }
            _ => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn check_wdac_available() -> bool {
        false
    }

    /// Check if AppArmor is available (Linux)
    #[cfg(target_os = "linux")]
    fn check_apparmor_available() -> bool {
        std::path::Path::new("/sys/kernel/security/apparmor").exists()
    }

    #[cfg(not(target_os = "linux"))]
    fn check_apparmor_available() -> bool {
        false
    }

    /// Get current enforcement mode
    pub async fn get_mode(&self) -> EnforcementMode {
        self.policy.read().await.mode
    }

    /// Set enforcement mode
    pub async fn set_mode(&self, mode: EnforcementMode) {
        let mut policy = self.policy.write().await;
        policy.mode = mode;
        policy.last_updated = AppControlPolicy::current_timestamp();
        policy.update_checksum();

        info!(mode = ?mode, "Enforcement mode changed");

        // Save policy
        drop(policy);
        if let Err(e) = self.save_policy_to_file().await {
            tracing::error!(error = %e, "Failed to persist app-control policy after mode change; on-disk policy is stale");
        }
    }

    /// Evaluate a process for execution permission
    pub async fn evaluate_process(&self, process_event: &ProcessEvent) -> ExecutionDecision {
        let mut stats = self.stats.write().await;
        stats.total_evaluated += 1;
        drop(stats);

        let policy = self.policy.read().await;
        let path = &process_event.path;
        let sha256 = if process_event.sha256.is_empty() {
            self.calculate_hash(path).await.unwrap_or_default()
        } else {
            hex::encode(&process_event.sha256)
        };
        let signer = process_event.signer.clone();

        // Sort rules by priority (descending)
        let mut rules: Vec<_> = policy.rules.iter().filter(|r| r.enabled).collect();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Check each rule
        for rule in rules {
            if self.matches_rule(rule, path, &sha256, &signer).await {
                let allowed = rule.action == RuleAction::Allow;
                let decision = ExecutionDecision {
                    allowed,
                    matched_rule: Some(rule.clone()),
                    reason: format!(
                        "Matched rule '{}' ({})",
                        rule.name,
                        if allowed { "allow" } else { "block" }
                    ),
                    is_default: false,
                };

                // Update stats
                let mut stats = self.stats.write().await;
                if allowed {
                    stats.allowed_by_rule += 1;
                    stats.last_allow_timestamp = Some(AppControlPolicy::current_timestamp());
                } else {
                    stats.blocked_by_rule += 1;
                    stats.last_block_timestamp = Some(AppControlPolicy::current_timestamp());
                }

                return decision;
            }
        }

        // No rule matched - apply default action
        let allowed = policy.default_action == RuleAction::Allow;
        let decision = ExecutionDecision {
            allowed,
            matched_rule: None,
            reason: format!(
                "No matching rule, default action: {}",
                if allowed { "allow" } else { "block" }
            ),
            is_default: true,
        };

        // Update stats
        let mut stats = self.stats.write().await;
        if allowed {
            stats.allowed_by_default += 1;
            stats.last_allow_timestamp = Some(AppControlPolicy::current_timestamp());
        } else {
            stats.blocked_by_default += 1;
            stats.last_block_timestamp = Some(AppControlPolicy::current_timestamp());
        }

        // In learning mode, auto-add to whitelist
        if policy.mode == EnforcementMode::Learning && !path.is_empty() {
            drop(policy);
            drop(stats);
            self.learn_application(process_event).await;
        }

        decision
    }

    /// Check if a rule matches the process
    async fn matches_rule(
        &self,
        rule: &AppControlRule,
        path: &str,
        sha256: &str,
        signer: &Option<String>,
    ) -> bool {
        match rule.match_type {
            RuleMatchType::Hash => {
                !sha256.is_empty() && sha256.to_lowercase() == rule.match_value.to_lowercase()
            }
            RuleMatchType::Path => self.matches_path_pattern(path, &rule.match_value),
            RuleMatchType::Certificate | RuleMatchType::Publisher => {
                if let Some(s) = signer {
                    s.to_lowercase().contains(&rule.match_value.to_lowercase())
                } else {
                    false
                }
            }
        }
    }

    /// Check if path matches a pattern (supports wildcards)
    fn matches_path_pattern(&self, path: &str, pattern: &str) -> bool {
        // Normalize path separators so patterns written with either '\' or '/'
        // match paths using the opposite separator (cross-platform rules).
        let path_lower = path.to_lowercase().replace('\\', "/");
        let pattern_lower = pattern.to_lowercase().replace('\\', "/");

        // Handle different wildcard patterns
        if pattern_lower == "*" {
            return true;
        }

        // Convert to a simple glob pattern
        let parts: Vec<&str> = pattern_lower.split('*').collect();

        if parts.len() == 1 {
            // No wildcard - exact match
            return path_lower == pattern_lower;
        }

        // Start pattern (e.g., "C:\Windows\*")
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];

            if prefix.is_empty() && suffix.is_empty() {
                return true; // Just "*"
            }

            if prefix.is_empty() {
                // Pattern like "*\Temp\*" or "*.exe"
                return path_lower.ends_with(suffix) || path_lower.contains(suffix);
            }

            if suffix.is_empty() {
                // Pattern like "C:\Windows\*"
                return path_lower.starts_with(prefix);
            }

            // Pattern like "C:\*\System32"
            return path_lower.starts_with(prefix) && path_lower.ends_with(suffix);
        }

        // Complex pattern with multiple wildcards
        let mut current_pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if let Some(pos) = path_lower[current_pos..].find(part) {
                if i == 0 && pos != 0 {
                    // First part must match at the beginning
                    return false;
                }
                current_pos += pos + part.len();
            } else {
                return false;
            }
        }

        true
    }

    /// Calculate SHA256 hash of a file
    async fn calculate_hash(&self, path: &str) -> Option<String> {
        // Check cache first
        {
            let cache = self.hash_cache.read().await;
            if let Some(hash) = cache.get(path) {
                return Some(hash.clone());
            }
        }

        // Calculate hash
        let path_owned = path.to_string();
        let hash = tokio::task::spawn_blocking(move || {
            if let Ok(content) = std::fs::read(&path_owned) {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                Some(hex::encode(hasher.finalize()))
            } else {
                None
            }
        })
        .await
        .ok()
        .flatten();

        // Cache the result
        if let Some(ref h) = hash {
            let mut cache = self.hash_cache.write().await;
            cache.insert(path.to_string(), h.clone());
        }

        hash
    }

    /// Learn an application (add to whitelist in learning mode)
    async fn learn_application(&self, process_event: &ProcessEvent) {
        let path = &process_event.path;

        // Check if already learned
        {
            let learned = self.learned_apps.read().await;
            if learned.contains(path) {
                return;
            }
        }

        let sha256 = if process_event.sha256.is_empty() {
            self.calculate_hash(path).await.unwrap_or_default()
        } else {
            hex::encode(&process_event.sha256)
        };

        let now = AppControlPolicy::current_timestamp();
        let rule_id = format!("learned_{}", now);

        let rule = AppControlRule {
            id: rule_id,
            name: format!("Learned: {}", process_event.name),
            match_type: if !sha256.is_empty() {
                RuleMatchType::Hash
            } else {
                RuleMatchType::Path
            },
            match_value: if !sha256.is_empty() {
                sha256
            } else {
                path.to_string()
            },
            action: RuleAction::Allow,
            priority: 100,
            enabled: true,
            comment: Some(format!(
                "Auto-learned from execution of {} at {}",
                path, now
            )),
            created_at: now,
            modified_at: now,
            source: RuleSource::Learning,
        };

        // Add rule
        {
            let mut policy = self.policy.write().await;
            policy.rules.push(rule.clone());
            policy.last_updated = now;
            policy.update_checksum();
        }

        // Mark as learned
        {
            let mut learned = self.learned_apps.write().await;
            learned.insert(path.to_string());
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.learned_applications += 1;
        }

        info!(
            path = %path,
            rule_id = %rule.id,
            "Application learned and whitelisted"
        );

        // Save policy
        if let Err(e) = self.save_policy_to_file().await {
            tracing::error!(error = %e, "Failed to persist app-control policy after learning application; whitelist entry will be lost on restart");
        }
    }

    /// Process a telemetry event and enforce policy
    pub async fn process_event(&self, event: &TelemetryEvent) -> Option<TelemetryEvent> {
        if event.event_type != EventType::ProcessCreate {
            return None;
        }

        if let EventPayload::Process(proc_event) = &event.payload {
            let policy = self.policy.read().await;
            let mode = policy.mode;
            drop(policy);

            let decision = self.evaluate_process(proc_event).await;

            // Log decision
            debug!(
                pid = proc_event.pid,
                path = %proc_event.path,
                allowed = decision.allowed,
                reason = %decision.reason,
                "Application control decision"
            );

            // Take action based on mode and decision
            if !decision.allowed {
                match mode {
                    EnforcementMode::Audit => {
                        // Just generate an alert
                        return Some(
                            self.create_blocked_event(proc_event, &decision, false)
                                .await,
                        );
                    }
                    EnforcementMode::Block => {
                        // Actually block/kill the process
                        self.enforce_block(proc_event.pid).await;
                        return Some(self.create_blocked_event(proc_event, &decision, true).await);
                    }
                    EnforcementMode::Learning => {
                        // In learning mode, we don't block - this shouldn't happen
                        // since learned apps are auto-whitelisted
                    }
                }
            }
        }

        None
    }

    /// Enforce a block by terminating the process
    async fn enforce_block(&self, pid: u32) {
        info!(pid = pid, "Enforcing application block");

        #[cfg(target_os = "windows")]
        {
            // Try WDAC first if available, then fall back to process termination
            if !Self::block_via_wdac(pid) {
                Self::terminate_process(pid);
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Try AppArmor profile if available, then fall back to process termination
            if !Self::block_via_apparmor(pid) {
                Self::terminate_process(pid);
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS doesn't have WDAC/AppArmor, use termination
            Self::terminate_process(pid);
        }
    }

    /// Block via WDAC (Windows)
    #[cfg(target_os = "windows")]
    fn block_via_wdac(_pid: u32) -> bool {
        // WDAC policies are typically applied at the system level
        // Runtime blocking would require integration with WDAC supplemental policies
        // For now, we return false to fall back to process termination
        false
    }

    #[cfg(not(target_os = "windows"))]
    fn block_via_wdac(_pid: u32) -> bool {
        false
    }

    /// Block via AppArmor (Linux)
    #[cfg(target_os = "linux")]
    fn block_via_apparmor(_pid: u32) -> bool {
        // AppArmor profiles are typically applied at process startup
        // Runtime profile changes would require aa-exec or similar
        // For now, we return false to fall back to process termination
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn block_via_apparmor(_pid: u32) -> bool {
        false
    }

    /// Terminate a process
    fn terminate_process(pid: u32) {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    let _ = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);
                }
            }
        }

        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }
    }

    /// Create a blocked execution telemetry event
    async fn create_blocked_event(
        &self,
        proc_event: &ProcessEvent,
        decision: &ExecutionDecision,
        was_blocked: bool,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::High,
            EventPayload::Process(proc_event.clone()),
        );

        let rule_name = decision
            .matched_rule
            .as_ref()
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "default_policy".to_string());

        let rule_id = decision
            .matched_rule
            .as_ref()
            .map(|r| r.id.clone())
            .unwrap_or_default();

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("AppControl_{}", rule_name),
            confidence: 1.0,
            description: format!(
                "Application {} {} - {}",
                proc_event.name,
                if was_blocked {
                    "BLOCKED"
                } else {
                    "DETECTED (audit mode)"
                },
                decision.reason
            ),
            mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
            mitre_techniques: vec!["T1204".to_string(), "T1059".to_string()],
        });

        event.metadata.insert(
            "app_control_action".to_string(),
            if was_blocked { "blocked" } else { "audit" }.to_string(),
        );
        event
            .metadata
            .insert("matched_rule_id".to_string(), rule_id);
        event
            .metadata
            .insert("matched_rule_name".to_string(), rule_name);
        event
            .metadata
            .insert("reason".to_string(), decision.reason.clone());

        // Log blocked execution
        let blocked = BlockedExecution {
            timestamp: event.timestamp,
            pid: proc_event.pid,
            process_name: proc_event.name.clone(),
            process_path: proc_event.path.clone(),
            sha256: hex::encode(&proc_event.sha256),
            signer: proc_event.signer.clone(),
            publisher: None,
            matched_rule_id: decision.matched_rule.as_ref().map(|r| r.id.clone()),
            matched_rule_name: decision.matched_rule.as_ref().map(|r| r.name.clone()),
            reason: decision.reason.clone(),
            action_taken: if was_blocked {
                "terminated".to_string()
            } else {
                "logged".to_string()
            },
        };

        self.log_blocked_execution(&blocked).await;

        event
    }

    /// Log blocked execution to file
    async fn log_blocked_execution(&self, blocked: &BlockedExecution) {
        let log_path = Self::get_blocked_log_path();

        if let Some(parent) = Path::new(&log_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let entry = serde_json::to_string(blocked).unwrap_or_default();
        let mut content = std::fs::read_to_string(&log_path).unwrap_or_default();
        content.push_str(&entry);
        content.push('\n');

        let _ = std::fs::write(&log_path, content);
    }

    /// Get path for blocked execution log
    fn get_blocked_log_path() -> String {
        if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\blocked_executions.log".to_string()
        } else {
            "/var/lib/tamandua/blocked_executions.log".to_string()
        }
    }

    /// Get path for policy file
    fn get_policy_path() -> String {
        if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\app_control_policy.json".to_string()
        } else {
            "/var/lib/tamandua/app_control_policy.json".to_string()
        }
    }

    /// Load policy from file
    async fn load_policy_from_file(&self) -> Result<()> {
        let path = Self::get_policy_path();
        let content = tokio::fs::read_to_string(&path).await?;
        let loaded_policy: AppControlPolicy = serde_json::from_str(&content)?;

        let mut policy = self.policy.write().await;
        *policy = loaded_policy;

        info!(
            path = %path,
            version = policy.version,
            rules = policy.rules.len(),
            "Policy loaded from file"
        );

        Ok(())
    }

    /// Save policy to file
    pub async fn save_policy_to_file(&self) -> Result<()> {
        let path = Self::get_policy_path();

        if let Some(parent) = Path::new(&path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let policy = self.policy.read().await;
        let content = serde_json::to_string_pretty(&*policy)?;
        tokio::fs::write(&path, content).await?;

        debug!(path = %path, "Policy saved to file");

        Ok(())
    }

    /// Update policy from server
    pub async fn update_policy_from_server(&self, policy_json: &serde_json::Value) -> Result<()> {
        let new_policy: AppControlPolicy = serde_json::from_value(policy_json.clone())?;

        let mut policy = self.policy.write().await;

        // Check if update is newer
        if new_policy.version <= policy.version && new_policy.checksum == policy.checksum {
            debug!("Policy already up to date");
            return Ok(());
        }

        info!(
            old_version = policy.version,
            new_version = new_policy.version,
            rules = new_policy.rules.len(),
            "Updating policy from server"
        );

        *policy = new_policy;
        policy.update_checksum();

        drop(policy);

        // Save to file
        self.save_policy_to_file().await?;

        Ok(())
    }

    /// Add a rule to the policy
    pub async fn add_rule(&self, rule: AppControlRule) -> Result<()> {
        let mut policy = self.policy.write().await;

        // Check for duplicate ID
        if policy.rules.iter().any(|r| r.id == rule.id) {
            return Err(anyhow::anyhow!("Rule with ID '{}' already exists", rule.id));
        }

        info!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            match_type = ?rule.match_type,
            action = ?rule.action,
            "Adding application control rule"
        );

        policy.rules.push(rule);
        policy.last_updated = AppControlPolicy::current_timestamp();
        policy.update_checksum();

        drop(policy);
        self.save_policy_to_file().await?;

        Ok(())
    }

    /// Remove a rule from the policy
    pub async fn remove_rule(&self, rule_id: &str) -> Result<bool> {
        let mut policy = self.policy.write().await;
        let initial_len = policy.rules.len();

        policy.rules.retain(|r| r.id != rule_id);

        let removed = policy.rules.len() < initial_len;

        if removed {
            policy.last_updated = AppControlPolicy::current_timestamp();
            policy.update_checksum();

            info!(rule_id = %rule_id, "Removed application control rule");

            drop(policy);
            self.save_policy_to_file().await?;
        }

        Ok(removed)
    }

    /// Enable or disable a rule
    pub async fn set_rule_enabled(&self, rule_id: &str, enabled: bool) -> Result<bool> {
        let mut policy = self.policy.write().await;

        if let Some(rule) = policy.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            rule.modified_at = AppControlPolicy::current_timestamp();
            policy.last_updated = AppControlPolicy::current_timestamp();
            policy.update_checksum();

            info!(
                rule_id = %rule_id,
                enabled = enabled,
                "Updated rule enabled status"
            );

            drop(policy);
            self.save_policy_to_file().await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get all rules
    pub async fn get_rules(&self) -> Vec<AppControlRule> {
        self.policy.read().await.rules.clone()
    }

    /// Get policy
    pub async fn get_policy(&self) -> AppControlPolicy {
        self.policy.read().await.clone()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> AppControlStats {
        self.stats.read().await.clone()
    }

    /// Create a rule to allow by hash
    pub fn create_hash_allow_rule(
        id: &str,
        name: &str,
        sha256: &str,
        comment: Option<&str>,
    ) -> AppControlRule {
        let now = AppControlPolicy::current_timestamp();
        AppControlRule {
            id: id.to_string(),
            name: name.to_string(),
            match_type: RuleMatchType::Hash,
            match_value: sha256.to_lowercase(),
            action: RuleAction::Allow,
            priority: 500,
            enabled: true,
            comment: comment.map(String::from),
            created_at: now,
            modified_at: now,
            source: RuleSource::Local,
        }
    }

    /// Create a rule to block by hash
    pub fn create_hash_block_rule(
        id: &str,
        name: &str,
        sha256: &str,
        comment: Option<&str>,
    ) -> AppControlRule {
        let now = AppControlPolicy::current_timestamp();
        AppControlRule {
            id: id.to_string(),
            name: name.to_string(),
            match_type: RuleMatchType::Hash,
            match_value: sha256.to_lowercase(),
            action: RuleAction::Block,
            priority: 600,
            enabled: true,
            comment: comment.map(String::from),
            created_at: now,
            modified_at: now,
            source: RuleSource::Local,
        }
    }

    /// Create a rule to allow by path pattern
    pub fn create_path_allow_rule(
        id: &str,
        name: &str,
        path_pattern: &str,
        comment: Option<&str>,
    ) -> AppControlRule {
        let now = AppControlPolicy::current_timestamp();
        AppControlRule {
            id: id.to_string(),
            name: name.to_string(),
            match_type: RuleMatchType::Path,
            match_value: path_pattern.to_string(),
            action: RuleAction::Allow,
            priority: 400,
            enabled: true,
            comment: comment.map(String::from),
            created_at: now,
            modified_at: now,
            source: RuleSource::Local,
        }
    }

    /// Create a rule to block by path pattern
    pub fn create_path_block_rule(
        id: &str,
        name: &str,
        path_pattern: &str,
        comment: Option<&str>,
    ) -> AppControlRule {
        let now = AppControlPolicy::current_timestamp();
        AppControlRule {
            id: id.to_string(),
            name: name.to_string(),
            match_type: RuleMatchType::Path,
            match_value: path_pattern.to_string(),
            action: RuleAction::Block,
            priority: 450,
            enabled: true,
            comment: comment.map(String::from),
            created_at: now,
            modified_at: now,
            source: RuleSource::Local,
        }
    }

    /// Create a rule to allow by certificate/signer
    pub fn create_certificate_allow_rule(
        id: &str,
        name: &str,
        signer_cn: &str,
        comment: Option<&str>,
    ) -> AppControlRule {
        let now = AppControlPolicy::current_timestamp();
        AppControlRule {
            id: id.to_string(),
            name: name.to_string(),
            match_type: RuleMatchType::Certificate,
            match_value: signer_cn.to_string(),
            action: RuleAction::Allow,
            priority: 700,
            enabled: true,
            comment: comment.map(String::from),
            created_at: now,
            modified_at: now,
            source: RuleSource::Local,
        }
    }

    /// Create a rule to allow by publisher
    pub fn create_publisher_allow_rule(
        id: &str,
        name: &str,
        publisher: &str,
        comment: Option<&str>,
    ) -> AppControlRule {
        let now = AppControlPolicy::current_timestamp();
        AppControlRule {
            id: id.to_string(),
            name: name.to_string(),
            match_type: RuleMatchType::Publisher,
            match_value: publisher.to_string(),
            action: RuleAction::Allow,
            priority: 700,
            enabled: true,
            comment: comment.map(String::from),
            created_at: now,
            modified_at: now,
            source: RuleSource::Local,
        }
    }

    /// Get next alert event
    pub async fn next_event(&self) -> Option<TelemetryEvent> {
        let mut rx = self.event_rx.write().await;
        rx.recv().await
    }

    /// Clear hash and signer caches
    pub async fn clear_caches(&self) {
        self.hash_cache.write().await.clear();
        self.signer_cache.write().await.clear();
        debug!("Application control caches cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_pattern_matching() {
        let config = AgentConfig::default();
        let manager = AppControlManager::new(&config);

        // Test exact match
        assert!(manager.matches_path_pattern("/usr/bin/ls", "/usr/bin/ls"));
        assert!(!manager.matches_path_pattern("/usr/bin/ls", "/usr/bin/cat"));

        // Test wildcard at end
        assert!(manager.matches_path_pattern("/usr/bin/ls", "/usr/bin/*"));
        assert!(manager.matches_path_pattern("/usr/bin/cat", "/usr/bin/*"));
        assert!(!manager.matches_path_pattern("/usr/sbin/ls", "/usr/bin/*"));

        // Test wildcard at start
        assert!(manager.matches_path_pattern("/home/user/Downloads/malware.exe", "*\\Downloads\\*"));
        assert!(
            manager.matches_path_pattern("C:\\Users\\test\\Downloads\\file.exe", "*\\Downloads\\*")
        );

        // Test wildcard in middle
        assert!(
            manager.matches_path_pattern("C:\\Windows\\System32\\cmd.exe", "C:\\*\\System32\\*")
        );
    }

    #[test]
    fn test_default_rules_created() {
        let rules = AppControlPolicy::default_rules();
        assert!(!rules.is_empty());

        // Check that rules have unique IDs
        let mut ids: HashSet<String> = HashSet::new();
        for rule in &rules {
            assert!(
                ids.insert(rule.id.clone()),
                "Duplicate rule ID: {}",
                rule.id
            );
        }
    }

    #[test]
    fn test_policy_checksum() {
        let mut policy = AppControlPolicy::default();
        let checksum1 = policy.calculate_checksum();

        policy.rules.push(AppControlRule {
            id: "test_rule".to_string(),
            name: "Test".to_string(),
            match_type: RuleMatchType::Hash,
            match_value: "abc123".to_string(),
            action: RuleAction::Block,
            priority: 100,
            enabled: true,
            comment: None,
            created_at: 0,
            modified_at: 0,
            source: RuleSource::Local,
        });

        let checksum2 = policy.calculate_checksum();
        assert_ne!(checksum1, checksum2);
    }
}
