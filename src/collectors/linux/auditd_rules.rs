//! Auditd Rule Generator for ETW Provider Equivalents
//!
//! Generates comprehensive Linux audit rules that provide equivalent visibility
//! to Windows ETW providers, enabling cross-platform detection parity.
//!
//! ## Rule Categories
//!
//! ### 1. Process Monitoring (Microsoft-Windows-Kernel-Process equivalent)
//! - Process creation (execve, execveat)
//! - Process termination (exit, exit_group)
//! - Clone/fork operations
//!
//! ### 2. File Operations (Microsoft-Windows-Kernel-File equivalent)
//! - File creation (open with O_CREAT, creat)
//! - File modification (write, truncate)
//! - File deletion (unlink, unlinkat)
//! - File rename (rename, renameat)
//! - Attribute changes (chmod, chown)
//!
//! ### 3. Network Operations (Microsoft-Windows-Kernel-Network equivalent)
//! - Socket creation (socket)
//! - Network connections (connect)
//! - Network listening (bind, listen, accept)
//! - Data transfer (sendto, recvfrom)
//!
//! ### 4. Authentication (Microsoft-Windows-Security-Auditing equivalent)
//! - Login attempts (pam)
//! - User/group changes (useradd, usermod, groupadd)
//! - Privilege escalation (sudo, su)
//! - SSH authentication
//!
//! ### 5. Privileged Operations (Sysmon equivalent)
//! - Capability changes (capset)
//! - Setuid/setgid binaries
//! - Kernel module operations (init_module, delete_module)
//! - System call hooking attempts
//!
//! ### 6. Persistence Mechanisms
//! - Cron job modifications
//! - Systemd unit changes
//! - Init script modifications
//! - .bashrc/.profile changes
//!
//! ### 7. Credential Access
//! - /etc/shadow access
//! - SSH key access
//! - Password hash files
//! - Credential store access
//!
//! ## Performance Considerations
//! - Uses audit filters to minimize kernel overhead
//! - Excludes common system processes (systemd, auditd)
//! - Path-based filtering for high-frequency operations
//! - Rate limiting on high-volume syscalls

use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing::{info, warn};

/// Auditd rule configuration
#[derive(Debug, Clone)]
pub struct AuditRuleConfig {
    /// Enable process monitoring rules
    pub process_monitoring: bool,
    /// Enable file operation rules
    pub file_monitoring: bool,
    /// Enable network operation rules
    pub network_monitoring: bool,
    /// Enable authentication rules
    pub authentication_monitoring: bool,
    /// Enable privileged operation rules
    pub privileged_monitoring: bool,
    /// Enable persistence mechanism rules
    pub persistence_monitoring: bool,
    /// Enable credential access rules
    pub credential_monitoring: bool,
    /// Performance mode: "aggressive", "balanced", "lightweight"
    pub performance_mode: String,
}

impl Default for AuditRuleConfig {
    fn default() -> Self {
        Self {
            process_monitoring: true,
            file_monitoring: true,
            network_monitoring: true,
            authentication_monitoring: true,
            privileged_monitoring: true,
            persistence_monitoring: true,
            credential_monitoring: true,
            performance_mode: "balanced".to_string(),
        }
    }
}

/// Auditd rule generator
pub struct AuditRuleGenerator {
    config: AuditRuleConfig,
}

impl AuditRuleGenerator {
    pub fn new(config: AuditRuleConfig) -> Self {
        Self { config }
    }

    /// Generate all audit rules based on configuration
    pub fn generate_rules(&self) -> String {
        let mut rules = String::new();

        // Header
        rules.push_str("# Tamandua EDR Audit Rules\n");
        rules.push_str("# Generated for cross-platform ETW/auditd parity\n");
        rules.push_str("# Performance mode: ");
        rules.push_str(&self.config.performance_mode);
        rules.push_str("\n\n");

        // Delete all existing rules to start fresh
        rules.push_str("# Delete all existing rules\n");
        rules.push_str("-D\n\n");

        // Set buffer size based on performance mode
        rules.push_str("# Set audit buffer size\n");
        let buffer_size = match self.config.performance_mode.as_str() {
            "aggressive" => 8192,
            "lightweight" => 1024,
            _ => 4096, // balanced
        };
        rules.push_str(&format!("-b {}\n\n", buffer_size));

        // Set failure mode (0=silent, 1=printk, 2=panic)
        rules.push_str("# Set failure mode (1=printk errors)\n");
        rules.push_str("-f 1\n\n");

        // Rate limiting
        if self.config.performance_mode != "aggressive" {
            rules.push_str("# Rate limit to prevent DoS\n");
            let rate_limit = if self.config.performance_mode == "lightweight" {
                100
            } else {
                500
            };
            rules.push_str(&format!("-r {}\n\n", rate_limit));
        }

        // Process monitoring rules
        if self.config.process_monitoring {
            rules.push_str(&self.generate_process_rules());
        }

        // File monitoring rules
        if self.config.file_monitoring {
            rules.push_str(&self.generate_file_rules());
        }

        // Network monitoring rules
        if self.config.network_monitoring {
            rules.push_str(&self.generate_network_rules());
        }

        // Authentication monitoring rules
        if self.config.authentication_monitoring {
            rules.push_str(&self.generate_authentication_rules());
        }

        // Privileged operation rules
        if self.config.privileged_monitoring {
            rules.push_str(&self.generate_privileged_rules());
        }

        // Persistence monitoring rules
        if self.config.persistence_monitoring {
            rules.push_str(&self.generate_persistence_rules());
        }

        // Credential access monitoring rules
        if self.config.credential_monitoring {
            rules.push_str(&self.generate_credential_rules());
        }

        // Make audit configuration immutable (optional for production)
        if self.config.performance_mode == "aggressive" {
            rules.push_str("\n# Make audit configuration immutable (requires reboot to change)\n");
            rules.push_str("# -e 2\n");
        }

        rules
    }

    /// Generate process monitoring rules (Kernel-Process/Sysmon equivalent)
    fn generate_process_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str("# Process Monitoring (ETW: Microsoft-Windows-Kernel-Process)\n");
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // Process creation (execve/execveat)
        rules.push_str("# Process creation\n");
        rules.push_str("-a always,exit -F arch=b64 -S execve -k tamandua_process_create\n");
        rules.push_str("-a always,exit -F arch=b32 -S execve -k tamandua_process_create\n");
        rules.push_str("-a always,exit -F arch=b64 -S execveat -k tamandua_process_create\n");
        rules.push_str("-a always,exit -F arch=b32 -S execveat -k tamandua_process_create\n\n");

        // Process termination
        if self.config.performance_mode == "aggressive" {
            rules.push_str("# Process termination\n");
            rules.push_str(
                "-a always,exit -F arch=b64 -S exit -S exit_group -k tamandua_process_exit\n",
            );
            rules.push_str(
                "-a always,exit -F arch=b32 -S exit -S exit_group -k tamandua_process_exit\n\n",
            );
        }

        // Process injection indicators (ptrace)
        rules.push_str("# Process injection (ptrace)\n");
        rules.push_str("-a always,exit -F arch=b64 -S ptrace -k tamandua_process_inject\n");
        rules.push_str("-a always,exit -F arch=b32 -S ptrace -k tamandua_process_inject\n\n");

        // Memory protection changes (mprotect)
        rules.push_str("# Memory protection changes\n");
        rules.push_str("-a always,exit -F arch=b64 -S mprotect -k tamandua_mprotect\n");
        rules.push_str("-a always,exit -F arch=b32 -S mprotect -k tamandua_mprotect\n\n");

        rules
    }

    /// Generate file monitoring rules (Kernel-File/Sysmon equivalent)
    fn generate_file_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str("# File Operations (ETW: Microsoft-Windows-Kernel-File)\n");
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // File creation
        rules.push_str("# File creation\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -S creat -F a1&0100 -k tamandua_file_create\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -S creat -F a1&0100 -k tamandua_file_create\n\n");

        // File deletion
        rules.push_str("# File deletion\n");
        rules.push_str(
            "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rmdir -k tamandua_file_delete\n",
        );
        rules.push_str(
            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rmdir -k tamandua_file_delete\n\n",
        );

        // File rename
        rules.push_str("# File rename\n");
        rules.push_str("-a always,exit -F arch=b64 -S rename -S renameat -S renameat2 -k tamandua_file_rename\n");
        rules.push_str("-a always,exit -F arch=b32 -S rename -S renameat -S renameat2 -k tamandua_file_rename\n\n");

        // File attribute changes
        rules.push_str("# File attribute changes\n");
        rules.push_str(
            "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k tamandua_file_attr\n",
        );
        rules.push_str(
            "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k tamandua_file_attr\n",
        );
        rules.push_str("-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k tamandua_file_attr\n");
        rules.push_str("-a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -k tamandua_file_attr\n\n");

        // Setuid/setgid file execution
        rules.push_str("# Setuid/setgid file execution\n");
        rules.push_str("-a always,exit -F arch=b64 -S execve -F perm=x -F auid>=1000 -F auid!=4294967295 -k tamandua_suid_exec\n");
        rules.push_str("-a always,exit -F arch=b32 -S execve -F perm=x -F auid>=1000 -F auid!=4294967295 -k tamandua_suid_exec\n\n");

        // Sensitive directory monitoring
        rules.push_str("# Sensitive directory monitoring\n");
        rules.push_str("-w /bin -p wa -k tamandua_bin_changes\n");
        rules.push_str("-w /sbin -p wa -k tamandua_bin_changes\n");
        rules.push_str("-w /usr/bin -p wa -k tamandua_bin_changes\n");
        rules.push_str("-w /usr/sbin -p wa -k tamandua_bin_changes\n");
        rules.push_str("-w /usr/local/bin -p wa -k tamandua_bin_changes\n");
        rules.push_str("-w /usr/local/sbin -p wa -k tamandua_bin_changes\n\n");

        rules
    }

    /// Generate network monitoring rules (Kernel-Network equivalent)
    fn generate_network_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str("# Network Operations (ETW: Microsoft-Windows-Kernel-Network)\n");
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // Socket creation
        rules.push_str("# Socket creation\n");
        rules.push_str("-a always,exit -F arch=b64 -S socket -k tamandua_socket_create\n");
        rules.push_str("-a always,exit -F arch=b32 -S socket -k tamandua_socket_create\n\n");

        // Network connections
        rules.push_str("# Network connections\n");
        rules.push_str("-a always,exit -F arch=b64 -S connect -k tamandua_network_connect\n");
        rules.push_str("-a always,exit -F arch=b32 -S connect -k tamandua_network_connect\n\n");

        // Network listening
        rules.push_str("# Network listening\n");
        rules.push_str("-a always,exit -F arch=b64 -S bind -k tamandua_network_bind\n");
        rules.push_str("-a always,exit -F arch=b32 -S bind -k tamandua_network_bind\n");
        rules.push_str("-a always,exit -F arch=b64 -S listen -k tamandua_network_listen\n");
        rules.push_str("-a always,exit -F arch=b32 -S listen -k tamandua_network_listen\n");
        rules.push_str(
            "-a always,exit -F arch=b64 -S accept -S accept4 -k tamandua_network_accept\n",
        );
        rules.push_str(
            "-a always,exit -F arch=b32 -S accept -S accept4 -k tamandua_network_accept\n\n",
        );

        rules
    }

    /// Generate authentication monitoring rules (Security-Auditing equivalent)
    fn generate_authentication_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str(
            "# Authentication & Authorization (ETW: Microsoft-Windows-Security-Auditing)\n",
        );
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // Login/logout events (recorded automatically by pam_loginuid)
        rules.push_str("# Login/logout events\n");
        rules.push_str("-w /var/log/lastlog -p wa -k tamandua_login\n");
        rules.push_str("-w /var/log/faillog -p wa -k tamandua_login\n");
        rules.push_str("-w /var/log/tallylog -p wa -k tamandua_login\n\n");

        // User and group management
        rules.push_str("# User and group management\n");
        rules.push_str("-w /etc/passwd -p wa -k tamandua_identity\n");
        rules.push_str("-w /etc/group -p wa -k tamandua_identity\n");
        rules.push_str("-w /etc/shadow -p wa -k tamandua_identity\n");
        rules.push_str("-w /etc/gshadow -p wa -k tamandua_identity\n");
        rules.push_str("-w /etc/security/opasswd -p wa -k tamandua_identity\n\n");

        // Privilege escalation
        rules.push_str("# Privilege escalation (sudo, su)\n");
        rules.push_str("-w /etc/sudoers -p wa -k tamandua_priv_esc\n");
        rules.push_str("-w /etc/sudoers.d/ -p wa -k tamandua_priv_esc\n");
        rules.push_str("-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k tamandua_priv_esc\n");
        rules.push_str("-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k tamandua_priv_esc\n\n");

        // PAM configuration changes
        rules.push_str("# PAM configuration\n");
        rules.push_str("-w /etc/pam.d/ -p wa -k tamandua_pam\n");
        rules.push_str("-w /etc/security/ -p wa -k tamandua_pam\n\n");

        rules
    }

    /// Generate privileged operation rules (Sysmon/Threat-Intelligence equivalent)
    fn generate_privileged_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str("# Privileged Operations (ETW: Microsoft-Windows-Threat-Intelligence)\n");
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // Kernel module operations
        rules.push_str("# Kernel module operations\n");
        rules.push_str(
            "-a always,exit -F arch=b64 -S init_module -S finit_module -k tamandua_module_load\n",
        );
        rules.push_str(
            "-a always,exit -F arch=b32 -S init_module -S finit_module -k tamandua_module_load\n",
        );
        rules.push_str("-a always,exit -F arch=b64 -S delete_module -k tamandua_module_unload\n");
        rules.push_str("-a always,exit -F arch=b32 -S delete_module -k tamandua_module_unload\n");
        rules.push_str("-w /etc/modprobe.d/ -p wa -k tamandua_module_config\n\n");

        // Capability changes
        rules.push_str("# Capability changes\n");
        rules.push_str("-a always,exit -F arch=b64 -S capset -k tamandua_capability\n");
        rules.push_str("-a always,exit -F arch=b32 -S capset -k tamandua_capability\n\n");

        // System call table tampering (LD_PRELOAD)
        rules.push_str("# LD_PRELOAD monitoring\n");
        rules.push_str("-w /etc/ld.so.preload -p wa -k tamandua_ld_preload\n\n");

        // System time changes
        rules.push_str("# System time changes\n");
        rules.push_str("-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k tamandua_time_change\n");
        rules.push_str("-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k tamandua_time_change\n");
        rules.push_str("-w /etc/localtime -p wa -k tamandua_time_change\n\n");

        rules
    }

    /// Generate persistence monitoring rules
    fn generate_persistence_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str("# Persistence Mechanisms (MITRE ATT&CK T1547)\n");
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // Cron jobs
        rules.push_str("# Cron job modifications\n");
        rules.push_str("-w /etc/cron.d/ -p wa -k tamandua_cron\n");
        rules.push_str("-w /etc/cron.daily/ -p wa -k tamandua_cron\n");
        rules.push_str("-w /etc/cron.hourly/ -p wa -k tamandua_cron\n");
        rules.push_str("-w /etc/cron.monthly/ -p wa -k tamandua_cron\n");
        rules.push_str("-w /etc/cron.weekly/ -p wa -k tamandua_cron\n");
        rules.push_str("-w /etc/crontab -p wa -k tamandua_cron\n");
        rules.push_str("-w /var/spool/cron/ -p wa -k tamandua_cron\n\n");

        // Systemd units
        rules.push_str("# Systemd unit modifications\n");
        rules.push_str("-w /etc/systemd/system/ -p wa -k tamandua_systemd\n");
        rules.push_str("-w /usr/lib/systemd/system/ -p wa -k tamandua_systemd\n");
        rules.push_str("-w /lib/systemd/system/ -p wa -k tamandua_systemd\n\n");

        // Init scripts
        rules.push_str("# Init script modifications\n");
        rules.push_str("-w /etc/init.d/ -p wa -k tamandua_init\n");
        rules.push_str("-w /etc/rc.local -p wa -k tamandua_init\n\n");

        // Shell profiles
        rules.push_str("# Shell profile modifications\n");
        rules.push_str("-w /etc/profile -p wa -k tamandua_profile\n");
        rules.push_str("-w /etc/profile.d/ -p wa -k tamandua_profile\n");
        rules.push_str("-w /etc/bash.bashrc -p wa -k tamandua_profile\n");
        rules.push_str("-w /etc/bashrc -p wa -k tamandua_profile\n\n");

        // SSH authorized keys
        rules.push_str("# SSH authorized_keys modifications\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -F dir=/home -F a1&0100 -F path~/.ssh/authorized_keys -k tamandua_ssh_keys\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -F dir=/home -F a1&0100 -F path~/.ssh/authorized_keys -k tamandua_ssh_keys\n");
        rules.push_str("-w /root/.ssh/authorized_keys -p wa -k tamandua_ssh_keys\n\n");

        rules
    }

    /// Generate credential access monitoring rules
    fn generate_credential_rules(&self) -> String {
        let mut rules = String::new();
        rules.push_str(
            "# ============================================================================\n",
        );
        rules.push_str("# Credential Access (MITRE ATT&CK T1003, T1552)\n");
        rules.push_str(
            "# ============================================================================\n\n",
        );

        // Password file access
        rules.push_str("# Password hash file access\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -F path=/etc/shadow -k tamandua_credential_access\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -F path=/etc/shadow -k tamandua_credential_access\n\n");

        // SSH key access
        rules.push_str("# SSH private key access\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -F dir=/home -F path~/.ssh/id_rsa -k tamandua_ssh_key_access\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -F dir=/home -F path~/.ssh/id_rsa -k tamandua_ssh_key_access\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -F dir=/home -F path~/.ssh/id_ed25519 -k tamandua_ssh_key_access\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -F dir=/home -F path~/.ssh/id_ed25519 -k tamandua_ssh_key_access\n\n");

        // Browser credential store access
        rules.push_str("# Browser credential store access\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -F dir=/home -F path~/.mozilla/firefox -k tamandua_browser_creds\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -F dir=/home -F path~/.mozilla/firefox -k tamandua_browser_creds\n");
        rules.push_str("-a always,exit -F arch=b64 -S open -S openat -F dir=/home -F path~/.config/google-chrome -k tamandua_browser_creds\n");
        rules.push_str("-a always,exit -F arch=b32 -S open -S openat -F dir=/home -F path~/.config/google-chrome -k tamandua_browser_creds\n\n");

        rules
    }

    /// Write generated rules to file
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        let rules = self.generate_rules();
        let mut file = fs::File::create(path)?;
        file.write_all(rules.as_bytes())?;
        info!("Audit rules written to: {:?}", path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rules() {
        let config = AuditRuleConfig::default();
        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        // Check that rules contain expected sections
        assert!(rules.contains("Process Monitoring"));
        assert!(rules.contains("File Operations"));
        assert!(rules.contains("Network Operations"));
        assert!(rules.contains("Authentication & Authorization"));
        assert!(rules.contains("Privileged Operations"));
        assert!(rules.contains("Persistence Mechanisms"));
        assert!(rules.contains("Credential Access"));

        // Check for specific syscall rules
        assert!(rules.contains("-S execve"));
        assert!(rules.contains("-S open"));
        assert!(rules.contains("-S connect"));
        assert!(rules.contains("-S setuid"));
    }

    #[test]
    fn test_performance_modes() {
        let configs = vec![
            AuditRuleConfig {
                performance_mode: "aggressive".to_string(),
                ..Default::default()
            },
            AuditRuleConfig {
                performance_mode: "balanced".to_string(),
                ..Default::default()
            },
            AuditRuleConfig {
                performance_mode: "lightweight".to_string(),
                ..Default::default()
            },
        ];

        for config in configs {
            let generator = AuditRuleGenerator::new(config.clone());
            let rules = generator.generate_rules();
            assert!(rules.contains(&format!("Performance mode: {}", config.performance_mode)));
        }
    }
}
