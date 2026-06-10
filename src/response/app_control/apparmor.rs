//! AppArmor Backend for Application Control
//!
//! This module provides AppArmor integration for application whitelisting/blacklisting
//! on Ubuntu, Debian, and other AppArmor-enabled distributions.
//!
//! AppArmor uses profile-based mandatory access control (MAC) where each application
//! can have a profile that defines what resources it can access.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

use super::EnforcementMode;

/// AppArmor profile directory
const APPARMOR_PROFILE_DIR: &str = "/etc/apparmor.d";
/// Tamandua-specific profile directory
const TAMANDUA_PROFILE_DIR: &str = "/etc/apparmor.d/tamandua";
/// AppArmor cache directory
const APPARMOR_CACHE_DIR: &str = "/var/cache/apparmor";

/// AppArmor backend for application control
pub struct AppArmorBackend {
    /// Whether AppArmor is available and enabled
    enabled: bool,
    /// Current global mode
    mode: EnforcementMode,
}

impl AppArmorBackend {
    /// Create a new AppArmor backend
    pub fn new() -> Result<Self> {
        let enabled = Self::check_apparmor_available()?;

        if !enabled {
            warn!("AppArmor is not available or not enabled");
        }

        // Ensure Tamandua profile directory exists
        if enabled {
            fs::create_dir_all(TAMANDUA_PROFILE_DIR)
                .context("Failed to create Tamandua profile directory")?;
        }

        Ok(Self {
            enabled,
            mode: EnforcementMode::Audit,
        })
    }

    /// Check if AppArmor is available and enabled
    fn check_apparmor_available() -> Result<bool> {
        // Check if AppArmor is loaded in the kernel
        if !Path::new("/sys/kernel/security/apparmor").exists() {
            return Ok(false);
        }

        // Check if AppArmor is enabled
        let enabled = fs::read_to_string("/sys/module/apparmor/parameters/enabled")
            .context("Failed to read AppArmor enabled status")?;

        if enabled.trim() != "Y" {
            return Ok(false);
        }

        // Check if apparmor_parser is available
        Command::new("which")
            .arg("apparmor_parser")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
            .then_some(true)
            .ok_or_else(|| anyhow::anyhow!("apparmor_parser not found"))
    }

    /// Set global enforcement mode
    pub fn set_global_mode(&mut self, mode: EnforcementMode) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("AppArmor is not enabled"));
        }

        // Note: AppArmor doesn't have a global mode - each profile has its own mode
        // We track this for future profile creation
        self.mode = mode;
        info!("AppArmor global mode set to: {}", mode);
        Ok(())
    }

    /// Create an allow profile for an application
    pub fn create_allow_profile(&self, profile_name: &str, binary_path: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("AppArmor is not enabled"));
        }

        let profile_content = self.generate_allow_profile(binary_path)?;
        let profile_path = self.get_profile_path(profile_name);

        fs::write(&profile_path, profile_content).context("Failed to write AppArmor profile")?;

        info!(profile = %profile_name, path = %binary_path, "Created AppArmor allow profile");
        Ok(())
    }

    /// Create a deny profile for an application
    pub fn create_deny_profile(&self, profile_name: &str, binary_path: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("AppArmor is not enabled"));
        }

        let profile_content = self.generate_deny_profile(binary_path)?;
        let profile_path = self.get_profile_path(profile_name);

        fs::write(&profile_path, profile_content).context("Failed to write AppArmor profile")?;

        info!(profile = %profile_name, path = %binary_path, "Created AppArmor deny profile");
        Ok(())
    }

    /// Load/reload a profile
    pub fn load_profile(&self, profile_name: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("AppArmor is not enabled"));
        }

        let profile_path = self.get_profile_path(profile_name);

        if !profile_path.exists() {
            return Err(anyhow::anyhow!("Profile does not exist: {}", profile_name));
        }

        // Use apparmor_parser to load the profile
        let output = Command::new("apparmor_parser")
            .arg("-r") // Replace/reload
            .arg("--write-cache") // Write to cache for faster loading
            .arg(&profile_path)
            .output()
            .context("Failed to execute apparmor_parser")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to load profile: {}", stderr));
        }

        info!(profile = %profile_name, "Loaded AppArmor profile");
        Ok(())
    }

    /// Unload a profile
    pub fn unload_profile(&self, profile_name: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("AppArmor is not enabled"));
        }

        let profile_path = self.get_profile_path(profile_name);

        // Use apparmor_parser to remove the profile
        let output = Command::new("apparmor_parser")
            .arg("-R") // Remove
            .arg(&profile_path)
            .output()
            .context("Failed to execute apparmor_parser")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to unload profile (may not be loaded): {}", stderr);
        }

        info!(profile = %profile_name, "Unloaded AppArmor profile");
        Ok(())
    }

    /// Delete a profile file
    pub fn delete_profile(&self, profile_name: &str) -> Result<()> {
        let profile_path = self.get_profile_path(profile_name);

        if profile_path.exists() {
            fs::remove_file(&profile_path).context("Failed to delete profile file")?;
        }

        // Also remove from cache
        self.clear_profile_cache(profile_name)?;

        info!(profile = %profile_name, "Deleted AppArmor profile");
        Ok(())
    }

    /// Set profile mode (enforce/complain)
    pub fn set_profile_mode(&self, profile_name: &str, mode: EnforcementMode) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("AppArmor is not enabled"));
        }

        let profile_path = self.get_profile_path(profile_name);

        if !profile_path.exists() {
            return Err(anyhow::anyhow!("Profile does not exist: {}", profile_name));
        }

        let command = match mode {
            EnforcementMode::Enforce => "aa-enforce",
            EnforcementMode::Audit => "aa-complain",
            EnforcementMode::Disable => {
                // Disable by unloading
                return self.unload_profile(profile_name);
            }
        };

        let output = Command::new(command)
            .arg(&profile_path)
            .output()
            .context("Failed to set profile mode")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to set profile mode: {}", stderr));
        }

        info!(profile = %profile_name, mode = %mode, "Set AppArmor profile mode");
        Ok(())
    }

    /// List loaded profiles
    pub fn list_loaded_profiles(&self) -> Result<Vec<String>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let output = Command::new("aa-status")
            .arg("--profiled")
            .output()
            .context("Failed to execute aa-status")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let profiles: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("tamandua_"))
            .map(|line| line.trim().to_string())
            .collect();

        Ok(profiles)
    }

    /// Query audit log for AppArmor events
    pub fn query_audit_log(&self, since: Option<u64>) -> Result<Vec<serde_json::Value>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // AppArmor logs to syslog/journalctl
        // Query journalctl for AppArmor DENIED messages
        let mut cmd = Command::new("journalctl");
        cmd.arg("-k") // Kernel messages
            .arg("--output=json")
            .arg("--no-pager");

        if let Some(ts) = since {
            cmd.arg(format!("--since=@{}", ts));
        } else {
            cmd.arg("--since=1 hour ago");
        }

        let output = cmd.output().context("Failed to execute journalctl")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        let lines = String::from_utf8_lossy(&output.stdout);

        for line in lines.lines() {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(message) = entry.get("MESSAGE").and_then(|m| m.as_str()) {
                    if message.contains("apparmor=\"DENIED\"")
                        || message.contains("apparmor=\"ALLOWED\"")
                    {
                        events.push(entry);
                    }
                }
            }
        }

        Ok(events)
    }

    /// Generate an allow profile
    fn generate_allow_profile(&self, binary_path: &str) -> Result<String> {
        let mode_flag = match self.mode {
            EnforcementMode::Enforce => "enforce",
            EnforcementMode::Audit => "complain",
            EnforcementMode::Disable => "complain",
        };

        // Basic permissive profile that allows normal operation
        let profile = format!(
            r#"# Tamandua EDR - Allow Profile for {}
# Generated by Tamandua Agent

{} flags=({}) {{
  #include <abstractions/base>

  # Allow execution
  {} rix,

  # Allow basic operations
  /etc/ld.so.cache r,
  /etc/ld.so.preload r,
  /lib/** mr,
  /usr/lib/** mr,

  # Allow common file operations
  /tmp/** rw,
  /var/tmp/** rw,
  owner /home/*/** rw,

  # Allow network access
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,

  # Allow capability drops (common for privilege separation)
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,

  # Deny sensitive locations
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny /root/.ssh/** rw,
}}
"#,
            binary_path, binary_path, mode_flag, binary_path
        );

        Ok(profile)
    }

    /// Generate a deny profile
    fn generate_deny_profile(&self, binary_path: &str) -> Result<String> {
        // Strict profile that blocks everything
        let profile = format!(
            r#"# Tamandua EDR - Deny Profile for {}
# Generated by Tamandua Agent

{} flags=(enforce) {{
  # Deny everything - no includes, no permissions
  # This will prevent the binary from executing

  deny /** rwx,
  deny /lib/** m,
  deny /usr/lib/** m,
}}
"#,
            binary_path, binary_path
        );

        Ok(profile)
    }

    /// Get the full path for a profile
    fn get_profile_path(&self, profile_name: &str) -> PathBuf {
        Path::new(TAMANDUA_PROFILE_DIR).join(profile_name)
    }

    /// Clear cached profile
    fn clear_profile_cache(&self, profile_name: &str) -> Result<()> {
        // AppArmor caches profiles for performance
        let cache_path = Path::new(APPARMOR_CACHE_DIR).join(profile_name);

        if cache_path.exists() {
            fs::remove_file(&cache_path).ok();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apparmor_detection() {
        let result = AppArmorBackend::check_apparmor_available();
        // This will succeed or fail depending on the system
        println!("AppArmor available: {:?}", result);
    }

    #[test]
    fn test_profile_generation() {
        let backend = AppArmorBackend {
            enabled: true,
            mode: EnforcementMode::Enforce,
        };

        let allow_profile = backend.generate_allow_profile("/usr/bin/test").unwrap();
        assert!(allow_profile.contains("/usr/bin/test"));
        assert!(allow_profile.contains("flags=(enforce)"));

        let deny_profile = backend.generate_deny_profile("/usr/bin/malware").unwrap();
        assert!(deny_profile.contains("/usr/bin/malware"));
        assert!(deny_profile.contains("deny /** rwx"));
    }
}
