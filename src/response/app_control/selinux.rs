//! SELinux Backend for Application Control
//!
//! This module provides SELinux integration for application whitelisting/blacklisting
//! on RHEL, CentOS, Fedora, Rocky Linux, and other SELinux-enabled distributions.
//!
//! SELinux uses policy-based mandatory access control (MAC) where each process runs
//! in a security context (domain) and policies define what resources can be accessed.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

use super::EnforcementMode;

/// SELinux policy module directory
const SELINUX_MODULE_DIR: &str = "/etc/selinux/tamandua";
/// Compiled policy modules directory
const SELINUX_COMPILED_DIR: &str = "/var/lib/selinux/tamandua";

/// SELinux backend for application control
pub struct SELinuxBackend {
    /// Whether SELinux is available and enabled
    enabled: bool,
    /// Current enforcement mode
    mode: EnforcementMode,
}

impl SELinuxBackend {
    /// Create a new SELinux backend
    pub fn new() -> Result<Self> {
        let enabled = Self::check_selinux_available()?;

        if !enabled {
            warn!("SELinux is not available or not enabled");
        }

        // Ensure module directories exist
        if enabled {
            fs::create_dir_all(SELINUX_MODULE_DIR)
                .context("Failed to create SELinux module directory")?;
            fs::create_dir_all(SELINUX_COMPILED_DIR)
                .context("Failed to create SELinux compiled directory")?;
        }

        Ok(Self {
            enabled,
            mode: EnforcementMode::Audit,
        })
    }

    /// Check if SELinux is available and enabled
    fn check_selinux_available() -> Result<bool> {
        // Check if SELinux filesystem is mounted
        if !Path::new("/sys/fs/selinux").exists() && !Path::new("/selinux").exists() {
            return Ok(false);
        }

        // Check current SELinux status
        let output = Command::new("getenforce")
            .output()
            .context("Failed to execute getenforce")?;

        if !output.status.success() {
            return Ok(false);
        }

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // SELinux is available if it's in Enforcing or Permissive mode
        Ok(status == "Enforcing" || status == "Permissive")
    }

    /// Set global enforcement mode
    pub fn set_global_mode(&mut self, mode: EnforcementMode) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("SELinux is not enabled"));
        }

        // Note: We can set SELinux to permissive/enforcing globally,
        // but this is dangerous. Instead, we track this for new policies.
        self.mode = mode;

        // Optionally set SELinux global mode (commented out for safety)
        /*
        let selinux_mode = match mode {
            EnforcementMode::Enforce => "1",
            EnforcementMode::Audit | EnforcementMode::Disable => "0",
        };

        Command::new("setenforce")
            .arg(selinux_mode)
            .output()
            .context("Failed to set SELinux enforcement mode")?;
        */

        info!("SELinux global mode set to: {}", mode);
        Ok(())
    }

    /// Create an allow policy for an application
    pub fn create_allow_policy(&self, policy_name: &str, binary_path: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("SELinux is not enabled"));
        }

        let (te_content, fc_content) = self.generate_allow_policy(policy_name, binary_path)?;

        let te_path = self.get_te_path(policy_name);
        let fc_path = self.get_fc_path(policy_name);

        fs::write(&te_path, te_content).context("Failed to write .te file")?;
        fs::write(&fc_path, fc_content).context("Failed to write .fc file")?;

        // Compile the policy
        self.compile_policy(policy_name)?;

        info!(policy = %policy_name, path = %binary_path, "Created SELinux allow policy");
        Ok(())
    }

    /// Create a deny policy for an application
    pub fn create_deny_policy(&self, policy_name: &str, binary_path: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("SELinux is not enabled"));
        }

        let (te_content, fc_content) = self.generate_deny_policy(policy_name, binary_path)?;

        let te_path = self.get_te_path(policy_name);
        let fc_path = self.get_fc_path(policy_name);

        fs::write(&te_path, te_content).context("Failed to write .te file")?;
        fs::write(&fc_path, fc_content).context("Failed to write .fc file")?;

        // Compile the policy
        self.compile_policy(policy_name)?;

        info!(policy = %policy_name, path = %binary_path, "Created SELinux deny policy");
        Ok(())
    }

    /// Load a policy module
    pub fn load_policy(&self, policy_name: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("SELinux is not enabled"));
        }

        let pp_path = self.get_pp_path(policy_name);

        if !pp_path.exists() {
            return Err(anyhow::anyhow!(
                "Compiled policy does not exist: {}",
                policy_name
            ));
        }

        // Install the policy module
        let output = Command::new("semodule")
            .arg("-i") // Install
            .arg(&pp_path)
            .output()
            .context("Failed to execute semodule")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to load policy: {}", stderr));
        }

        // Apply file contexts
        self.apply_file_contexts(policy_name)?;

        info!(policy = %policy_name, "Loaded SELinux policy");
        Ok(())
    }

    /// Remove a policy module
    pub fn remove_policy(&self, policy_name: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("SELinux is not enabled"));
        }

        // Remove the policy module
        let output = Command::new("semodule")
            .arg("-r") // Remove
            .arg(policy_name)
            .output()
            .context("Failed to execute semodule")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to remove policy (may not be loaded): {}", stderr);
        }

        // Delete policy files
        let te_path = self.get_te_path(policy_name);
        let fc_path = self.get_fc_path(policy_name);
        let pp_path = self.get_pp_path(policy_name);

        for path in [te_path, fc_path, pp_path] {
            if path.exists() {
                fs::remove_file(&path).ok();
            }
        }

        info!(policy = %policy_name, "Removed SELinux policy");
        Ok(())
    }

    /// Enable a policy (same as load for SELinux)
    pub fn enable_policy(&self, policy_name: &str) -> Result<()> {
        self.load_policy(policy_name)
    }

    /// Disable a policy
    pub fn disable_policy(&self, policy_name: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow::anyhow!("SELinux is not enabled"));
        }

        // Disable the policy module
        let output = Command::new("semodule")
            .arg("-d") // Disable
            .arg(policy_name)
            .output()
            .context("Failed to execute semodule")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to disable policy: {}", stderr));
        }

        info!(policy = %policy_name, "Disabled SELinux policy");
        Ok(())
    }

    /// List loaded policies
    pub fn list_loaded_policies(&self) -> Result<Vec<String>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let output = Command::new("semodule")
            .arg("-l") // List modules
            .output()
            .context("Failed to execute semodule")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let policies: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("tamandua_"))
            .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
            .collect();

        Ok(policies)
    }

    /// Query audit log for SELinux events
    pub fn query_audit_log(&self, since: Option<u64>) -> Result<Vec<serde_json::Value>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // SELinux logs to /var/log/audit/audit.log
        // Use ausearch to query AVC (Access Vector Cache) denials
        let mut cmd = Command::new("ausearch");
        cmd.arg("-m") // Message type
            .arg("avc")
            .arg("--format")
            .arg("json");

        if let Some(ts) = since {
            cmd.arg("--start").arg(format!("{}", ts));
        } else {
            cmd.arg("--start").arg("recent");
        }

        let output = cmd.output();

        // ausearch may not be available or may fail
        let output = match output {
            Ok(o) => o,
            Err(_) => return Ok(Vec::new()),
        };

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        let lines = String::from_utf8_lossy(&output.stdout);

        for line in lines.lines() {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                events.push(entry);
            }
        }

        Ok(events)
    }

    /// Compile a policy module
    fn compile_policy(&self, policy_name: &str) -> Result<()> {
        let te_path = self.get_te_path(policy_name);
        let pp_path = self.get_pp_path(policy_name);

        // Use checkmodule to compile .te to .mod
        let mod_path = self.get_mod_path(policy_name);

        let output = Command::new("checkmodule")
            .arg("-M") // MLS/MCS support
            .arg("-m") // Create module
            .arg("-o")
            .arg(&mod_path)
            .arg(&te_path)
            .output()
            .context("Failed to execute checkmodule")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to compile module: {}", stderr));
        }

        // Use semodule_package to create .pp from .mod and .fc
        let fc_path = self.get_fc_path(policy_name);

        let output = Command::new("semodule_package")
            .arg("-o")
            .arg(&pp_path)
            .arg("-m")
            .arg(&mod_path)
            .arg("-f")
            .arg(&fc_path)
            .output()
            .context("Failed to execute semodule_package")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to package module: {}", stderr));
        }

        // Clean up .mod file
        fs::remove_file(mod_path).ok();

        debug!(policy = %policy_name, "Compiled SELinux policy");
        Ok(())
    }

    /// Apply file contexts from policy
    fn apply_file_contexts(&self, policy_name: &str) -> Result<()> {
        let fc_path = self.get_fc_path(policy_name);

        if !fc_path.exists() {
            return Ok(());
        }

        // Read file contexts and apply them
        let content = fs::read_to_string(&fc_path)?;

        for line in content.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let file_path = parts[0];
                let context = parts.last().unwrap();

                // Use chcon to set the context
                Command::new("chcon")
                    .arg("-t")
                    .arg(context)
                    .arg(file_path)
                    .output()
                    .ok();
            }
        }

        Ok(())
    }

    /// Generate an allow policy
    fn generate_allow_policy(
        &self,
        policy_name: &str,
        binary_path: &str,
    ) -> Result<(String, String)> {
        // .te file (Type Enforcement)
        let te = format!(
            r#"policy_module({}, 1.0.0)

# Tamandua EDR - Allow Policy for {}
# Generated by Tamandua Agent

# Define the domain for this application
type {}_t;
type {}_exec_t;
init_daemon_domain({}_t, {}_exec_t)

# Allow domain transition
domain_auto_trans(init_t, {}_exec_t, {}_t)

# Allow basic operations
files_read_etc_files({}_t)
libs_use_ld_so({}_t)
libs_use_shared_libs({}_t)

# Allow network access
corenet_tcp_sendrecv_generic_if({}_t)
corenet_udp_sendrecv_generic_if({}_t)
corenet_tcp_sendrecv_all_nodes({}_t)
corenet_udp_sendrecv_all_nodes({}_t)

# Allow file operations in common directories
files_read_usr_files({}_t)
files_rw_generic_tmp_files({}_t)

# Allow logging
logging_send_syslog_msg({}_t)

# Permissive mode for this domain (audit but don't block)
# permissive {}_t;
"#,
            policy_name,
            binary_path,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
        );

        // .fc file (File Context)
        let fc = format!(
            r#"# Tamandua EDR - File Context for {}
{}    --    gen_context(system_u:object_r:{}_exec_t,s0)
"#,
            binary_path, binary_path, policy_name
        );

        Ok((te, fc))
    }

    /// Generate a deny policy
    fn generate_deny_policy(
        &self,
        policy_name: &str,
        binary_path: &str,
    ) -> Result<(String, String)> {
        // .te file (Type Enforcement) - highly restrictive
        let te = format!(
            r#"policy_module({}, 1.0.0)

# Tamandua EDR - Deny Policy for {}
# Generated by Tamandua Agent

# Define the domain for this application
type {}_t;
type {}_exec_t;
init_daemon_domain({}_t, {}_exec_t)

# Allow domain transition
domain_auto_trans(init_t, {}_exec_t, {}_t)

# Deny almost everything - minimal permissions
# This will cause the application to fail when it tries to do anything

# Only allow bare minimum to prevent kernel panic
kernel_read_system_state({}_t)
"#,
            policy_name,
            binary_path,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
            policy_name,
        );

        // .fc file (File Context)
        let fc = format!(
            r#"# Tamandua EDR - File Context for {}
{}    --    gen_context(system_u:object_r:{}_exec_t,s0)
"#,
            binary_path, binary_path, policy_name
        );

        Ok((te, fc))
    }

    /// Get .te file path
    fn get_te_path(&self, policy_name: &str) -> PathBuf {
        Path::new(SELINUX_MODULE_DIR).join(format!("{}.te", policy_name))
    }

    /// Get .fc file path
    fn get_fc_path(&self, policy_name: &str) -> PathBuf {
        Path::new(SELINUX_MODULE_DIR).join(format!("{}.fc", policy_name))
    }

    /// Get .mod file path
    fn get_mod_path(&self, policy_name: &str) -> PathBuf {
        Path::new(SELINUX_COMPILED_DIR).join(format!("{}.mod", policy_name))
    }

    /// Get .pp file path
    fn get_pp_path(&self, policy_name: &str) -> PathBuf {
        Path::new(SELINUX_COMPILED_DIR).join(format!("{}.pp", policy_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selinux_detection() {
        let result = SELinuxBackend::check_selinux_available();
        // This will succeed or fail depending on the system
        println!("SELinux available: {:?}", result);
    }

    #[test]
    fn test_policy_generation() {
        let backend = SELinuxBackend {
            enabled: true,
            mode: EnforcementMode::Enforce,
        };

        let (te, fc) = backend
            .generate_allow_policy("test_allow", "/usr/bin/test")
            .unwrap();
        assert!(te.contains("policy_module(test_allow"));
        assert!(fc.contains("/usr/bin/test"));

        let (te, fc) = backend
            .generate_deny_policy("test_deny", "/usr/bin/malware")
            .unwrap();
        assert!(te.contains("policy_module(test_deny"));
        assert!(fc.contains("/usr/bin/malware"));
    }
}
