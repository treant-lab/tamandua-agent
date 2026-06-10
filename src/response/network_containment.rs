//! Network Containment Module
//!
//! Provides enterprise-grade network isolation and containment features:
//! - Full device quarantine with status tracking
//! - Break-glass emergency access mechanism
//! - Staged reintegration from isolation
//! - Isolation event reporting
//! - Per-application network rules

// Network containment. Scaffolded break-glass/state-persistence retained.
#![allow(dead_code, unused_variables)]

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Containment state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentState {
    /// Whether the device is currently contained/isolated
    pub is_contained: bool,

    /// When containment started
    pub started_at: Option<u64>,

    /// Who initiated the containment
    pub initiated_by: Option<String>,

    /// Reason for containment
    pub reason: Option<String>,

    /// Alert ID that triggered containment
    pub alert_id: Option<String>,

    /// Allowed IPs during containment (server, etc.)
    pub allowed_ips: Vec<String>,

    /// Break-glass code for emergency access
    pub break_glass_code: Option<String>,

    /// Break-glass expiry timestamp
    pub break_glass_expiry: Option<u64>,

    /// Whether break-glass is currently active
    pub break_glass_active: bool,

    /// Containment level (full, partial)
    pub level: ContainmentLevel,

    /// Application-specific network rules
    pub app_rules: Vec<AppNetworkRule>,

    /// Number of containment events
    pub event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainmentLevel {
    /// Block all network except allowed IPs
    Full,
    /// Block only outbound, allow inbound
    OutboundOnly,
    /// Block only certain applications
    AppSpecific,
    /// No containment
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppNetworkRule {
    /// Application executable path or name
    pub app_path: String,

    /// Action to take (allow/block)
    pub action: NetworkAction,

    /// Direction (inbound/outbound/both)
    pub direction: NetworkDirection,

    /// Specific IPs to allow/block (optional)
    pub remote_ips: Option<Vec<String>>,

    /// Specific ports to allow/block (optional)
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentEvent {
    pub timestamp: u64,
    pub event_type: ContainmentEventType,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainmentEventType {
    Activated,
    Deactivated,
    BreakGlassUsed,
    BreakGlassExpired,
    BlockedConnection,
    AllowedConnection,
    RuleAdded,
    RuleRemoved,
}

/// Network Containment Manager
pub struct NetworkContainmentManager {
    state: Arc<RwLock<ContainmentState>>,
    events: Arc<RwLock<Vec<ContainmentEvent>>>,
    state_file_path: String,
}

impl NetworkContainmentManager {
    pub fn new() -> Self {
        let state_file_path = if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\containment_state.json".to_string()
        } else {
            "/var/lib/tamandua/containment_state.json".to_string()
        };

        Self {
            state: Arc::new(RwLock::new(ContainmentState::default())),
            events: Arc::new(RwLock::new(Vec::new())),
            state_file_path,
        }
    }

    /// Initialize the containment manager, loading saved state
    pub async fn initialize(&self) -> anyhow::Result<()> {
        // Load saved state if exists
        if let Ok(content) = std::fs::read_to_string(&self.state_file_path) {
            if let Ok(saved_state) = serde_json::from_str::<ContainmentState>(&content) {
                let mut state = self.state.write().await;
                *state = saved_state;

                // Check if break-glass has expired
                if state.break_glass_active {
                    if let Some(expiry) = state.break_glass_expiry {
                        let now = current_timestamp();
                        if now > expiry {
                            info!("Break-glass access expired, re-applying containment");
                            state.break_glass_active = false;
                            state.break_glass_code = None;
                            state.break_glass_expiry = None;
                        }
                    }
                }

                // Re-apply containment rules if still active
                if state.is_contained && !state.break_glass_active {
                    drop(state);
                    self.apply_containment_rules().await?;
                }

                info!("Containment manager initialized from saved state");
            }
        }

        Ok(())
    }

    /// Activate network containment
    pub async fn activate_containment(
        &self,
        allowed_ips: Vec<String>,
        reason: String,
        initiated_by: String,
        alert_id: Option<String>,
        level: ContainmentLevel,
    ) -> anyhow::Result<()> {
        info!(
            reason = %reason,
            initiated_by = %initiated_by,
            level = ?level,
            "Activating network containment"
        );

        // Update state
        {
            let mut state = self.state.write().await;
            state.is_contained = true;
            state.started_at = Some(current_timestamp());
            state.initiated_by = Some(initiated_by.clone());
            state.reason = Some(reason.clone());
            state.alert_id = alert_id.clone();
            state.allowed_ips = allowed_ips.clone();
            state.level = level.clone();
            state.event_count += 1;
        }

        // Apply firewall rules
        self.apply_containment_rules().await?;

        // Log event
        self.log_event(
            ContainmentEventType::Activated,
            serde_json::json!({
                "reason": reason,
                "initiated_by": initiated_by,
                "alert_id": alert_id,
                "allowed_ips": allowed_ips,
                "level": format!("{:?}", level)
            }),
        )
        .await;

        // Save state
        self.save_state().await?;

        Ok(())
    }

    /// Deactivate network containment (staged reintegration)
    pub async fn deactivate_containment(
        &self,
        initiated_by: String,
        staged: bool,
    ) -> anyhow::Result<()> {
        info!(
            initiated_by = %initiated_by,
            staged = staged,
            "Deactivating network containment"
        );

        if staged {
            // Staged reintegration: gradually remove restrictions
            self.staged_reintegration().await?;
        } else {
            // Immediate removal
            self.remove_containment_rules().await?;
        }

        // Update state
        {
            let mut state = self.state.write().await;
            state.is_contained = false;
            state.break_glass_active = false;
            state.break_glass_code = None;
            state.break_glass_expiry = None;
            state.event_count += 1;
        }

        // Log event
        self.log_event(
            ContainmentEventType::Deactivated,
            serde_json::json!({
                "initiated_by": initiated_by,
                "staged": staged
            }),
        )
        .await;

        // Save state
        self.save_state().await?;

        Ok(())
    }

    /// Generate and activate break-glass emergency access
    pub async fn activate_break_glass(&self, duration_minutes: u64) -> anyhow::Result<String> {
        let code = generate_break_glass_code();
        let expiry = current_timestamp() + (duration_minutes * 60);

        info!(
            duration = duration_minutes,
            "Activating break-glass emergency access"
        );

        // Temporarily remove containment
        self.remove_containment_rules().await?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.break_glass_code = Some(code.clone());
            state.break_glass_expiry = Some(expiry);
            state.break_glass_active = true;
            state.event_count += 1;
        }

        // Log event
        self.log_event(
            ContainmentEventType::BreakGlassUsed,
            serde_json::json!({
                "duration_minutes": duration_minutes,
                "expiry": expiry
            }),
        )
        .await;

        // Save state
        self.save_state().await?;

        // Schedule re-activation after expiry
        let state_clone = Arc::clone(&self.state);
        let this = self.clone_for_timer();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(duration_minutes * 60)).await;

            let state = state_clone.read().await;
            if state.break_glass_active && state.is_contained {
                drop(state);
                if let Err(e) = this.expire_break_glass().await {
                    error!("Failed to expire break-glass: {}", e);
                }
            }
        });

        Ok(code)
    }

    /// Verify break-glass code
    pub async fn verify_break_glass_code(&self, code: &str) -> bool {
        let state = self.state.read().await;

        if let Some(stored_code) = &state.break_glass_code {
            if stored_code == code {
                if let Some(expiry) = state.break_glass_expiry {
                    return current_timestamp() <= expiry;
                }
            }
        }

        false
    }

    /// Get current containment status
    pub async fn get_status(&self) -> ContainmentState {
        self.state.read().await.clone()
    }

    /// Get containment events
    pub async fn get_events(&self, limit: usize) -> Vec<ContainmentEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Add application-specific network rule
    pub async fn add_app_rule(&self, rule: AppNetworkRule) -> anyhow::Result<()> {
        info!(app = %rule.app_path, action = ?rule.action, "Adding app network rule");

        // Add to state
        {
            let mut state = self.state.write().await;
            state.app_rules.push(rule.clone());
        }

        // Apply the rule
        self.apply_app_rule(&rule).await?;

        // Log event
        self.log_event(
            ContainmentEventType::RuleAdded,
            serde_json::json!({
                "app_path": rule.app_path,
                "action": format!("{:?}", rule.action),
                "direction": format!("{:?}", rule.direction)
            }),
        )
        .await;

        // Save state
        self.save_state().await?;

        Ok(())
    }

    /// Remove application-specific network rule
    pub async fn remove_app_rule(&self, app_path: &str) -> anyhow::Result<bool> {
        let mut state = self.state.write().await;
        let initial_len = state.app_rules.len();
        state.app_rules.retain(|r| r.app_path != app_path);

        if state.app_rules.len() < initial_len {
            drop(state);

            // Remove the firewall rule
            self.remove_app_firewall_rule(app_path).await?;

            // Log event
            self.log_event(
                ContainmentEventType::RuleRemoved,
                serde_json::json!({
                    "app_path": app_path
                }),
            )
            .await;

            // Save state
            self.save_state().await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    // =========================================================================
    // Private Methods
    // =========================================================================

    async fn apply_containment_rules(&self) -> anyhow::Result<()> {
        let state = self.state.read().await;

        match state.level {
            ContainmentLevel::Full => self.apply_full_containment(&state.allowed_ips).await?,
            ContainmentLevel::OutboundOnly => {
                self.apply_outbound_containment(&state.allowed_ips).await?
            }
            ContainmentLevel::AppSpecific => {
                for rule in &state.app_rules {
                    self.apply_app_rule(rule).await?;
                }
            }
            ContainmentLevel::None => {}
        }

        Ok(())
    }

    async fn apply_full_containment(&self, allowed_ips: &[String]) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let rule_prefix = "TamanduaContainment";

            // Delete existing containment rules
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}*", rule_prefix),
                ])
                .output();

            // Block all outbound
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}_BlockOut", rule_prefix),
                    "dir=out",
                    "action=block",
                    "enable=yes",
                ])
                .output()?;

            // Block all inbound
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}_BlockIn", rule_prefix),
                    "dir=in",
                    "action=block",
                    "enable=yes",
                ])
                .output()?;

            // Allow loopback
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}_AllowLoopback", rule_prefix),
                    "dir=out",
                    "action=allow",
                    "remoteip=127.0.0.1,::1",
                    "enable=yes",
                ])
                .output()?;

            // Allow specific IPs (both directions)
            for (i, ip) in allowed_ips.iter().enumerate() {
                let _ = std::process::Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={}_AllowOut_{}", rule_prefix, i),
                        "dir=out",
                        "action=allow",
                        &format!("remoteip={}", ip),
                        "enable=yes",
                    ])
                    .output()?;

                let _ = std::process::Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={}_AllowIn_{}", rule_prefix, i),
                        "dir=in",
                        "action=allow",
                        &format!("remoteip={}", ip),
                        "enable=yes",
                    ])
                    .output()?;
            }

            info!("Full containment applied via Windows Firewall");
        }

        #[cfg(target_os = "linux")]
        {
            // Flush OUTPUT chain
            let _ = std::process::Command::new("iptables")
                .args(["-F", "OUTPUT"])
                .output()?;

            let _ = std::process::Command::new("iptables")
                .args(["-F", "INPUT"])
                .output()?;

            // Allow loopback
            let _ = std::process::Command::new("iptables")
                .args(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
                .output()?;

            let _ = std::process::Command::new("iptables")
                .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
                .output()?;

            // Allow established connections
            let _ = std::process::Command::new("iptables")
                .args([
                    "-A",
                    "OUTPUT",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ])
                .output()?;

            let _ = std::process::Command::new("iptables")
                .args([
                    "-A",
                    "INPUT",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ])
                .output()?;

            // Allow specific IPs
            for ip in allowed_ips {
                let _ = std::process::Command::new("iptables")
                    .args(["-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])
                    .output()?;

                let _ = std::process::Command::new("iptables")
                    .args(["-A", "INPUT", "-s", ip, "-j", "ACCEPT"])
                    .output()?;
            }

            // Drop everything else
            let _ = std::process::Command::new("iptables")
                .args(["-A", "OUTPUT", "-j", "DROP"])
                .output()?;

            let _ = std::process::Command::new("iptables")
                .args(["-A", "INPUT", "-j", "DROP"])
                .output()?;

            info!("Full containment applied via iptables");
        }

        #[cfg(target_os = "macos")]
        {
            let pf_rules = format!(
                r#"# Tamandua Full Containment
block all
pass on lo0 all
{}
"#,
                allowed_ips
                    .iter()
                    .flat_map(|ip| vec![
                        format!("pass out to {}", ip),
                        format!("pass in from {}", ip)
                    ])
                    .collect::<Vec<_>>()
                    .join("\n")
            );

            std::fs::write("/tmp/tamandua_containment.conf", &pf_rules)?;

            let _ = std::process::Command::new("pfctl")
                .args(["-f", "/tmp/tamandua_containment.conf", "-e"])
                .output()?;

            info!("Full containment applied via pf");
        }

        Ok(())
    }

    async fn apply_outbound_containment(&self, allowed_ips: &[String]) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let rule_prefix = "TamanduaContainment";

            // Delete existing containment rules
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}*", rule_prefix),
                ])
                .output();

            // Block outbound only
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}_BlockOut", rule_prefix),
                    "dir=out",
                    "action=block",
                    "enable=yes",
                ])
                .output()?;

            // Allow loopback
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}_AllowLoopback", rule_prefix),
                    "dir=out",
                    "action=allow",
                    "remoteip=127.0.0.1,::1",
                    "enable=yes",
                ])
                .output()?;

            // Allow specific IPs outbound
            for (i, ip) in allowed_ips.iter().enumerate() {
                let _ = std::process::Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={}_AllowOut_{}", rule_prefix, i),
                        "dir=out",
                        "action=allow",
                        &format!("remoteip={}", ip),
                        "enable=yes",
                    ])
                    .output()?;
            }

            info!("Outbound containment applied via Windows Firewall");
        }

        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("iptables")
                .args(["-F", "OUTPUT"])
                .output()?;

            let _ = std::process::Command::new("iptables")
                .args(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
                .output()?;

            let _ = std::process::Command::new("iptables")
                .args([
                    "-A",
                    "OUTPUT",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ])
                .output()?;

            for ip in allowed_ips {
                let _ = std::process::Command::new("iptables")
                    .args(["-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])
                    .output()?;
            }

            let _ = std::process::Command::new("iptables")
                .args(["-A", "OUTPUT", "-j", "DROP"])
                .output()?;

            info!("Outbound containment applied via iptables");
        }

        Ok(())
    }

    async fn remove_containment_rules(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let rule_prefix = "TamanduaContainment";
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}*", rule_prefix),
                ])
                .output();

            info!("Containment rules removed via Windows Firewall");
        }

        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("iptables")
                .args(["-F", "OUTPUT"])
                .output();

            let _ = std::process::Command::new("iptables")
                .args(["-F", "INPUT"])
                .output();

            let _ = std::process::Command::new("iptables")
                .args(["-P", "OUTPUT", "ACCEPT"])
                .output();

            let _ = std::process::Command::new("iptables")
                .args(["-P", "INPUT", "ACCEPT"])
                .output();

            info!("Containment rules removed via iptables");
        }

        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("pfctl").args(["-d"]).output();

            let _ = std::fs::remove_file("/tmp/tamandua_containment.conf");

            info!("Containment rules removed via pf");
        }

        Ok(())
    }

    async fn staged_reintegration(&self) -> anyhow::Result<()> {
        info!("Starting staged reintegration");

        // Stage 1: Allow DNS and essential services
        info!("Stage 1: Allowing DNS and essential services");
        // Add DNS (53) to allowed
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=TamanduaContainment_Stage1_DNS",
                    "dir=out",
                    "action=allow",
                    "protocol=UDP",
                    "remoteport=53",
                    "enable=yes",
                ])
                .output();
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        // Stage 2: Allow HTTPS
        info!("Stage 2: Allowing HTTPS");
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=TamanduaContainment_Stage2_HTTPS",
                    "dir=out",
                    "action=allow",
                    "protocol=TCP",
                    "remoteport=443",
                    "enable=yes",
                ])
                .output();
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        // Stage 3: Remove all containment
        info!("Stage 3: Full reintegration");
        self.remove_containment_rules().await?;

        info!("Staged reintegration complete");
        Ok(())
    }

    async fn apply_app_rule(&self, rule: &AppNetworkRule) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let action = match rule.action {
                NetworkAction::Allow => "allow",
                NetworkAction::Block => "block",
            };

            let directions: Vec<&str> = match rule.direction {
                NetworkDirection::Inbound => vec!["in"],
                NetworkDirection::Outbound => vec!["out"],
                NetworkDirection::Both => vec!["in", "out"],
            };

            for dir in directions {
                let rule_name = format!(
                    "TamanduaAppRule_{}_{}_{}",
                    rule.app_path.replace("\\", "_").replace(":", ""),
                    action,
                    dir
                );

                let mut args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "add".to_string(),
                    "rule".to_string(),
                    format!("name={}", rule_name),
                    format!("dir={}", dir),
                    format!("action={}", action),
                    format!("program={}", rule.app_path),
                    "enable=yes".to_string(),
                ];

                if let Some(ref ips) = rule.remote_ips {
                    args.push(format!("remoteip={}", ips.join(",")));
                }

                if let Some(ref ports) = rule.ports {
                    let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                    args.push(format!("remoteport={}", ports_str.join(",")));
                }

                let _ = std::process::Command::new("netsh").args(&args).output()?;
            }

            info!(app = %rule.app_path, "App-specific network rule applied");
        }

        Ok(())
    }

    async fn remove_app_firewall_rule(&self, app_path: &str) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let rule_pattern = format!(
                "TamanduaAppRule_{}*",
                app_path.replace("\\", "_").replace(":", "")
            );

            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", rule_pattern),
                ])
                .output();

            info!(app = %app_path, "App-specific network rule removed");
        }

        Ok(())
    }

    async fn expire_break_glass(&self) -> anyhow::Result<()> {
        info!("Break-glass access expired, re-applying containment");

        {
            let mut state = self.state.write().await;
            state.break_glass_active = false;
            state.break_glass_code = None;
            state.break_glass_expiry = None;
        }

        // Re-apply containment
        self.apply_containment_rules().await?;

        // Log event
        self.log_event(
            ContainmentEventType::BreakGlassExpired,
            serde_json::json!({}),
        )
        .await;

        // Save state
        self.save_state().await?;

        Ok(())
    }

    async fn log_event(&self, event_type: ContainmentEventType, details: serde_json::Value) {
        let event = ContainmentEvent {
            timestamp: current_timestamp(),
            event_type,
            details,
        };

        let mut events = self.events.write().await;
        events.push(event);

        // Keep only last 1000 events
        if events.len() > 1000 {
            events.remove(0);
        }
    }

    async fn save_state(&self) -> anyhow::Result<()> {
        let state = self.state.read().await;

        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(&self.state_file_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&*state)?;
        std::fs::write(&self.state_file_path, content)?;

        debug!("Containment state saved");
        Ok(())
    }

    fn clone_for_timer(&self) -> NetworkContainmentManagerHandle {
        NetworkContainmentManagerHandle {
            state: Arc::clone(&self.state),
            events: Arc::clone(&self.events),
            state_file_path: self.state_file_path.clone(),
        }
    }
}

/// Handle for timer callbacks
struct NetworkContainmentManagerHandle {
    state: Arc<RwLock<ContainmentState>>,
    events: Arc<RwLock<Vec<ContainmentEvent>>>,
    state_file_path: String,
}

impl NetworkContainmentManagerHandle {
    async fn expire_break_glass(&self) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.break_glass_active = false;
            state.break_glass_code = None;
            state.break_glass_expiry = None;
        }

        // Note: Can't re-apply containment rules from handle easily
        // The main manager should handle this

        Ok(())
    }
}

impl Default for ContainmentState {
    fn default() -> Self {
        Self {
            is_contained: false,
            started_at: None,
            initiated_by: None,
            reason: None,
            alert_id: None,
            allowed_ips: Vec::new(),
            break_glass_code: None,
            break_glass_expiry: None,
            break_glass_active: false,
            level: ContainmentLevel::None,
            app_rules: Vec::new(),
            event_count: 0,
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_break_glass_code() -> String {
    // Use timestamp and process ID for unique code generation
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let hash1 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    (now + 1).hash(&mut hasher);
    let hash2 = hasher.finish();

    format!("{:08X}-{:08X}", (hash1 as u32), (hash2 as u32))
}
