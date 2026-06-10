//! Linux Application Control Enforcement
//!
//! This module provides Linux-specific application control using:
//! - AppArmor (Ubuntu/Debian)
//! - SELinux (RHEL/CentOS/Fedora/Rocky)
//!
//! Provides a unified interface for both LSM (Linux Security Module) backends.
//!
//! MITRE ATT&CK Coverage:
//! - T1204 (User Execution) - Prevention via mandatory access control
//! - T1059 (Command and Scripting Interpreter) - Restriction of interpreter execution
//! - T1543 (Create or Modify System Process) - Service/daemon control

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, warn};

use crate::response::app_control::{apparmor, selinux};

/// Linux Security Module backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LsmBackend {
    AppArmor,
    SELinux,
    None,
}

impl std::fmt::Display for LsmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsmBackend::AppArmor => write!(f, "apparmor"),
            LsmBackend::SELinux => write!(f, "selinux"),
            LsmBackend::None => write!(f, "none"),
        }
    }
}

/// Enforcement mode for LSM profiles/policies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// Log violations but don't enforce (AppArmor: complain, SELinux: permissive)
    Audit,
    /// Actively enforce restrictions (AppArmor: enforce, SELinux: enforcing)
    Enforce,
    /// Disable enforcement entirely
    Disable,
}

impl std::fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforcementMode::Audit => write!(f, "audit"),
            EnforcementMode::Enforce => write!(f, "enforce"),
            EnforcementMode::Disable => write!(f, "disable"),
        }
    }
}

/// Application control rule for Linux
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxAppRule {
    /// Rule ID
    pub id: String,
    /// Application path (executable)
    pub path: String,
    /// SHA256 hash of the binary (optional, for additional verification)
    pub hash: Option<String>,
    /// Whether to allow or block
    pub allow: bool,
    /// Profile/policy name
    pub profile_name: String,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Created timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
}

/// Unified Linux application control interface
pub struct LinuxAppControl {
    /// Detected LSM backend
    backend: LsmBackend,
    /// Active enforcement mode
    mode: EnforcementMode,
    /// AppArmor backend (if available)
    apparmor: Option<apparmor::AppArmorBackend>,
    /// SELinux backend (if available)
    selinux: Option<selinux::SELinuxBackend>,
    /// Active rules
    rules: HashMap<String, LinuxAppRule>,
    /// Statistics
    stats: AppControlStats,
}

/// Application control statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppControlStats {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub disabled_rules: usize,
    pub profiles_loaded: usize,
    pub enforcement_actions: u64,
    pub audit_events: u64,
    pub last_enforcement: Option<u64>,
}

impl LinuxAppControl {
    /// Create a new Linux application control manager
    pub fn new() -> Result<Self> {
        info!("Initializing Linux application control");

        // Detect available LSM backend
        let backend = Self::detect_lsm()?;
        info!("Detected LSM backend: {}", backend);

        let (apparmor, selinux) = match backend {
            LsmBackend::AppArmor => {
                let aa = apparmor::AppArmorBackend::new()
                    .context("Failed to initialize AppArmor backend")?;
                (Some(aa), None)
            }
            LsmBackend::SELinux => {
                let se = selinux::SELinuxBackend::new()
                    .context("Failed to initialize SELinux backend")?;
                (None, Some(se))
            }
            LsmBackend::None => {
                warn!("No LSM backend available - application control will be limited");
                (None, None)
            }
        };

        Ok(Self {
            backend,
            mode: EnforcementMode::Audit,
            apparmor,
            selinux,
            rules: HashMap::new(),
            stats: AppControlStats::default(),
        })
    }

    /// Detect which LSM is active on the system
    fn detect_lsm() -> Result<LsmBackend> {
        // Check for AppArmor
        if Path::new("/sys/kernel/security/apparmor").exists() {
            // Verify it's actually enabled
            if let Ok(enabled) = fs::read_to_string("/sys/module/apparmor/parameters/enabled") {
                if enabled.trim() == "Y" {
                    return Ok(LsmBackend::AppArmor);
                }
            }
        }

        // Check for SELinux
        if Path::new("/sys/fs/selinux").exists() || Path::new("/selinux").exists() {
            if let Ok(output) = Command::new("getenforce").output() {
                let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if status == "Enforcing" || status == "Permissive" {
                    return Ok(LsmBackend::SELinux);
                }
            }
        }

        warn!("No LSM backend detected - application control will be unavailable");
        Ok(LsmBackend::None)
    }

    /// Get the active backend
    pub fn backend(&self) -> LsmBackend {
        self.backend
    }

    /// Get current enforcement mode
    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Set enforcement mode
    pub fn set_mode(&mut self, mode: EnforcementMode) -> Result<()> {
        match self.backend {
            LsmBackend::AppArmor => {
                if let Some(ref mut aa) = self.apparmor {
                    aa.set_global_mode(mode)?;
                }
            }
            LsmBackend::SELinux => {
                if let Some(ref mut se) = self.selinux {
                    se.set_global_mode(mode)?;
                }
            }
            LsmBackend::None => {
                return Err(anyhow::anyhow!("No LSM backend available"));
            }
        }

        self.mode = mode;
        info!("Enforcement mode changed to: {}", mode);
        Ok(())
    }

    /// Allow an application by path
    pub fn allow_application(&mut self, path: &str, hash: Option<String>) -> Result<String> {
        let rule_id = format!("allow_{}", uuid::Uuid::new_v4());
        let profile_name = Self::path_to_profile_name(path);

        match self.backend {
            LsmBackend::AppArmor => {
                if let Some(ref mut aa) = self.apparmor {
                    aa.create_allow_profile(&profile_name, path)?;
                    aa.load_profile(&profile_name)?;
                }
            }
            LsmBackend::SELinux => {
                if let Some(ref mut se) = self.selinux {
                    se.create_allow_policy(&profile_name, path)?;
                    se.load_policy(&profile_name)?;
                }
            }
            LsmBackend::None => {
                return Err(anyhow::anyhow!("No LSM backend available"));
            }
        }

        let rule = LinuxAppRule {
            id: rule_id.clone(),
            path: path.to_string(),
            hash,
            allow: true,
            profile_name: profile_name.clone(),
            enabled: true,
            created_at: Self::current_timestamp(),
            modified_at: Self::current_timestamp(),
        };

        self.rules.insert(rule_id.clone(), rule);
        self.update_stats();

        info!(path = %path, profile = %profile_name, "Application whitelisted");
        Ok(rule_id)
    }

    /// Block an application by path
    pub fn block_application(&mut self, path: &str, hash: Option<String>) -> Result<String> {
        let rule_id = format!("block_{}", uuid::Uuid::new_v4());
        let profile_name = Self::path_to_profile_name(path);

        match self.backend {
            LsmBackend::AppArmor => {
                if let Some(ref mut aa) = self.apparmor {
                    aa.create_deny_profile(&profile_name, path)?;
                    aa.load_profile(&profile_name)?;
                }
            }
            LsmBackend::SELinux => {
                if let Some(ref mut se) = self.selinux {
                    se.create_deny_policy(&profile_name, path)?;
                    se.load_policy(&profile_name)?;
                }
            }
            LsmBackend::None => {
                return Err(anyhow::anyhow!("No LSM backend available"));
            }
        }

        let rule = LinuxAppRule {
            id: rule_id.clone(),
            path: path.to_string(),
            hash,
            allow: false,
            profile_name: profile_name.clone(),
            enabled: true,
            created_at: Self::current_timestamp(),
            modified_at: Self::current_timestamp(),
        };

        self.rules.insert(rule_id.clone(), rule);
        self.update_stats();

        info!(path = %path, profile = %profile_name, "Application blacklisted");
        Ok(rule_id)
    }

    /// Remove a rule
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<bool> {
        if let Some(rule) = self.rules.remove(rule_id) {
            match self.backend {
                LsmBackend::AppArmor => {
                    if let Some(ref mut aa) = self.apparmor {
                        aa.unload_profile(&rule.profile_name)?;
                        aa.delete_profile(&rule.profile_name)?;
                    }
                }
                LsmBackend::SELinux => {
                    if let Some(ref mut se) = self.selinux {
                        se.remove_policy(&rule.profile_name)?;
                    }
                }
                LsmBackend::None => {}
            }

            self.update_stats();
            info!(rule_id = %rule_id, "Rule removed");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Enable a rule
    pub fn enable_rule(&mut self, rule_id: &str) -> Result<bool> {
        if let Some(rule) = self.rules.get_mut(rule_id) {
            if !rule.enabled {
                match self.backend {
                    LsmBackend::AppArmor => {
                        if let Some(ref mut aa) = self.apparmor {
                            aa.load_profile(&rule.profile_name)?;
                        }
                    }
                    LsmBackend::SELinux => {
                        if let Some(ref mut se) = self.selinux {
                            se.enable_policy(&rule.profile_name)?;
                        }
                    }
                    LsmBackend::None => {}
                }

                rule.enabled = true;
                rule.modified_at = Self::current_timestamp();
                self.update_stats();

                info!(rule_id = %rule_id, "Rule enabled");
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, rule_id: &str) -> Result<bool> {
        if let Some(rule) = self.rules.get_mut(rule_id) {
            if rule.enabled {
                match self.backend {
                    LsmBackend::AppArmor => {
                        if let Some(ref mut aa) = self.apparmor {
                            aa.unload_profile(&rule.profile_name)?;
                        }
                    }
                    LsmBackend::SELinux => {
                        if let Some(ref mut se) = self.selinux {
                            se.disable_policy(&rule.profile_name)?;
                        }
                    }
                    LsmBackend::None => {}
                }

                rule.enabled = false;
                rule.modified_at = Self::current_timestamp();
                self.update_stats();

                info!(rule_id = %rule_id, "Rule disabled");
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// List all rules
    pub fn list_rules(&self) -> Vec<&LinuxAppRule> {
        self.rules.values().collect()
    }

    /// Get enforcement status
    pub fn get_status(&self) -> serde_json::Value {
        let loaded_profiles = match self.backend {
            LsmBackend::AppArmor => self
                .apparmor
                .as_ref()
                .and_then(|aa| aa.list_loaded_profiles().ok())
                .map(|p| p.len())
                .unwrap_or(0),
            LsmBackend::SELinux => self
                .selinux
                .as_ref()
                .and_then(|se| se.list_loaded_policies().ok())
                .map(|p| p.len())
                .unwrap_or(0),
            LsmBackend::None => 0,
        };

        serde_json::json!({
            "backend": self.backend.to_string(),
            "mode": self.mode.to_string(),
            "total_rules": self.stats.total_rules,
            "enabled_rules": self.stats.enabled_rules,
            "disabled_rules": self.stats.disabled_rules,
            "profiles_loaded": loaded_profiles,
            "enforcement_actions": self.stats.enforcement_actions,
            "audit_events": self.stats.audit_events,
            "last_enforcement": self.stats.last_enforcement,
        })
    }

    /// Get statistics
    pub fn get_stats(&self) -> &AppControlStats {
        &self.stats
    }

    /// Query audit log for blocked/allowed executions
    pub fn query_audit_log(&self, since: Option<u64>) -> Result<Vec<serde_json::Value>> {
        match self.backend {
            LsmBackend::AppArmor => {
                if let Some(ref aa) = self.apparmor {
                    aa.query_audit_log(since)
                } else {
                    Ok(Vec::new())
                }
            }
            LsmBackend::SELinux => {
                if let Some(ref se) = self.selinux {
                    se.query_audit_log(since)
                } else {
                    Ok(Vec::new())
                }
            }
            LsmBackend::None => Ok(Vec::new()),
        }
    }

    /// Convert file path to profile/policy name
    fn path_to_profile_name(path: &str) -> String {
        // Sanitize path for use as profile name
        let sanitized = path.replace('/', "_").replace(' ', "_").replace('.', "_");

        format!("tamandua_{}", sanitized)
    }

    /// Update statistics
    fn update_stats(&mut self) {
        self.stats.total_rules = self.rules.len();
        self.stats.enabled_rules = self.rules.values().filter(|r| r.enabled).count();
        self.stats.disabled_rules = self.stats.total_rules - self.stats.enabled_rules;
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for LinuxAppControl {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            error!("Failed to initialize LinuxAppControl: {}", e);
            Self {
                backend: LsmBackend::None,
                mode: EnforcementMode::Audit,
                apparmor: None,
                selinux: None,
                rules: HashMap::new(),
                stats: AppControlStats::default(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsm_detection() {
        let backend = LinuxAppControl::detect_lsm();
        assert!(backend.is_ok());
    }

    #[test]
    fn test_path_to_profile_name() {
        let name = LinuxAppControl::path_to_profile_name("/usr/bin/suspicious");
        assert_eq!(name, "tamandua__usr_bin_suspicious");
    }
}
