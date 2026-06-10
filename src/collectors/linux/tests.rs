//! Tests for Linux auditd integration

#[cfg(test)]
mod event_normalizer_tests {
    use super::super::event_normalizer::*;
    use std::collections::HashMap;

    #[test]
    fn test_audit_record_from_fields_process() {
        let mut fields = HashMap::new();
        fields.insert("type".to_string(), "SYSCALL".to_string());
        fields.insert("time".to_string(), "1234567890.123".to_string());
        fields.insert("syscall".to_string(), "execve".to_string());
        fields.insert("pid".to_string(), "1234".to_string());
        fields.insert("ppid".to_string(), "1000".to_string());
        fields.insert("uid".to_string(), "1000".to_string());
        fields.insert("euid".to_string(), "0".to_string());
        fields.insert("comm".to_string(), "bash".to_string());
        fields.insert("exe".to_string(), "/bin/bash".to_string());
        fields.insert("success".to_string(), "yes".to_string());
        fields.insert("a0".to_string(), "2f62696e2f6c73".to_string()); // /bin/ls
        fields.insert("a1".to_string(), "2d6c".to_string()); // -l

        let record = AuditRecord::from_fields(fields).unwrap();

        assert_eq!(record.record_type, "SYSCALL");
        assert_eq!(record.syscall, Some("execve".to_string()));
        assert_eq!(record.pid, Some(1234));
        assert_eq!(record.ppid, Some(1000));
        assert_eq!(record.uid, Some(1000));
        assert_eq!(record.euid, Some(0));
        assert_eq!(record.comm, Some("bash".to_string()));
        assert_eq!(record.exe, Some("/bin/bash".to_string()));
        assert_eq!(record.success, Some(true));
        assert_eq!(record.args, vec!["/bin/ls", "-l"]);
    }

    #[test]
    fn test_audit_record_from_fields_file() {
        let mut fields = HashMap::new();
        fields.insert("type".to_string(), "SYSCALL".to_string());
        fields.insert("time".to_string(), "1234567890.456".to_string());
        fields.insert("syscall".to_string(), "open".to_string());
        fields.insert("pid".to_string(), "5678".to_string());
        fields.insert("uid".to_string(), "1000".to_string());
        fields.insert("comm".to_string(), "vim".to_string());
        fields.insert("exe".to_string(), "/usr/bin/vim".to_string());
        fields.insert("name".to_string(), "/tmp/test.txt".to_string());
        fields.insert("inode".to_string(), "123456".to_string());

        let record = AuditRecord::from_fields(fields).unwrap();

        assert_eq!(record.syscall, Some("open".to_string()));
        assert_eq!(record.pid, Some(5678));
        assert_eq!(record.path, Some("/tmp/test.txt".to_string()));
        assert_eq!(record.inode, Some(123456));
    }

    #[test]
    fn test_event_normalizer_process_create() {
        let mut normalizer = EventNormalizer::new();

        let mut fields = HashMap::new();
        fields.insert("type".to_string(), "SYSCALL".to_string());
        fields.insert("time".to_string(), "1234567890.123".to_string());
        fields.insert("syscall".to_string(), "execve".to_string());
        fields.insert("pid".to_string(), "1234".to_string());
        fields.insert("ppid".to_string(), "1000".to_string());
        fields.insert("uid".to_string(), "1000".to_string());
        fields.insert("euid".to_string(), "0".to_string());
        fields.insert("comm".to_string(), "sudo".to_string());
        fields.insert("exe".to_string(), "/usr/bin/sudo".to_string());
        fields.insert("a0".to_string(), "2f7573722f62696e2f7375646f".to_string()); // /usr/bin/sudo
        fields.insert("a1".to_string(), "6c73".to_string()); // ls

        let record = AuditRecord::from_fields(fields).unwrap();
        let event = normalizer.normalize(record).unwrap();

        assert!(event.is_some());
        let event = event.unwrap();

        use super::super::super::EventType;
        assert_eq!(event.event_type, EventType::ProcessCreate);

        if let super::super::super::EventPayload::Process(proc_event) = event.payload {
            assert_eq!(proc_event.pid, 1234);
            assert_eq!(proc_event.ppid, 1000);
            assert_eq!(proc_event.name, "sudo");
            assert_eq!(proc_event.path, "/usr/bin/sudo");
            assert_eq!(proc_event.is_elevated, true); // euid == 0
        } else {
            panic!("Expected Process payload");
        }
    }

    #[test]
    fn test_event_normalizer_file_delete() {
        let mut normalizer = EventNormalizer::new();

        let mut fields = HashMap::new();
        fields.insert("type".to_string(), "SYSCALL".to_string());
        fields.insert("time".to_string(), "1234567890.789".to_string());
        fields.insert("syscall".to_string(), "unlink".to_string());
        fields.insert("pid".to_string(), "9999".to_string());
        fields.insert("uid".to_string(), "1000".to_string());
        fields.insert("comm".to_string(), "rm".to_string());
        fields.insert("exe".to_string(), "/bin/rm".to_string());
        fields.insert("name".to_string(), "/tmp/malicious.sh".to_string());

        let record = AuditRecord::from_fields(fields).unwrap();
        let event = normalizer.normalize(record).unwrap();

        assert!(event.is_some());
        let event = event.unwrap();

        use super::super::super::EventType;
        assert_eq!(event.event_type, EventType::FileDelete);

        if let super::super::super::EventPayload::File(file_event) = event.payload {
            assert_eq!(file_event.path, "/tmp/malicious.sh");
            assert_eq!(file_event.operation, "delete");
            assert_eq!(file_event.pid, 9999);
            assert_eq!(file_event.process_name, "rm");
        } else {
            panic!("Expected File payload");
        }
    }

    #[test]
    fn test_parse_sockaddr_ipv4() {
        // AF_INET (2), port 443 (0x01BB), IP 93.184.216.34
        let saddr = "020001BB5DB8D8220000000000000000";
        let (ip, port) = parse_sockaddr(Some(saddr)).unwrap();
        assert_eq!(ip, "93.184.216.34");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_sockaddr_localhost() {
        // AF_INET (2), port 8080 (0x1F90), IP 127.0.0.1
        let saddr = "02001F907F0000010000000000000000";
        let (ip, port) = parse_sockaddr(Some(saddr)).unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_decode_hex_string() {
        assert_eq!(decode_hex_string("48656c6c6f"), "Hello");
        assert_eq!(decode_hex_string("576f726c6421"), "World!");
        assert_eq!(decode_hex_string("2f62696e2f6c73"), "/bin/ls");
        assert_eq!(
            decode_hex_string("2f7573722f62696e2f707974686f6e"),
            "/usr/bin/python"
        );
    }

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal("0644"), Some(0o644));
        assert_eq!(parse_octal("644"), Some(0o644));
        assert_eq!(parse_octal("0o755"), Some(0o755));
        assert_eq!(parse_octal("755"), Some(0o755));
        assert_eq!(parse_octal("0600"), Some(0o600));
    }

    #[test]
    fn test_extract_args() {
        let mut fields = HashMap::new();
        fields.insert("a0".to_string(), "2f62696e2f6c73".to_string()); // /bin/ls
        fields.insert("a1".to_string(), "2d6c61".to_string()); // -la
        fields.insert("a2".to_string(), "2f746d70".to_string()); // /tmp
        fields.insert("a3".to_string(), "2d68".to_string()); // -h

        let args = extract_args(&fields);
        assert_eq!(args, vec!["/bin/ls", "-la", "/tmp", "-h"]);
    }

    #[test]
    fn test_resolve_username() {
        // Test with root UID
        let username = resolve_username(0);
        assert!(username == "root" || username == "0");

        // Test with non-existent UID
        let username = resolve_username(99999);
        assert!(username.contains("99999"));
    }
}

#[cfg(test)]
mod auditd_rules_tests {
    use super::super::auditd_rules::*;

    #[test]
    fn test_audit_rule_config_default() {
        let config = AuditRuleConfig::default();
        assert!(config.process_monitoring);
        assert!(config.file_monitoring);
        assert!(config.network_monitoring);
        assert!(config.authentication_monitoring);
        assert!(config.privileged_monitoring);
        assert!(config.persistence_monitoring);
        assert!(config.credential_monitoring);
        assert_eq!(config.performance_mode, "balanced");
    }

    #[test]
    fn test_generate_rules_balanced() {
        let config = AuditRuleConfig {
            performance_mode: "balanced".to_string(),
            ..Default::default()
        };

        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        // Check header
        assert!(rules.contains("Tamandua EDR Audit Rules"));
        assert!(rules.contains("Performance mode: balanced"));

        // Check initialization
        assert!(rules.contains("-D")); // Delete all rules
        assert!(rules.contains("-b 4096")); // Buffer size
        assert!(rules.contains("-f 1")); // Failure mode
        assert!(rules.contains("-r 500")); // Rate limit

        // Check section headers
        assert!(rules.contains("Process Monitoring"));
        assert!(rules.contains("File Operations"));
        assert!(rules.contains("Network Operations"));
        assert!(rules.contains("Authentication & Authorization"));
        assert!(rules.contains("Privileged Operations"));
        assert!(rules.contains("Persistence Mechanisms"));
        assert!(rules.contains("Credential Access"));

        // Check specific rules
        assert!(rules.contains("-S execve -k tamandua_process_create"));
        assert!(rules.contains("-S open -S openat -S creat"));
        assert!(rules.contains("-S connect -k tamandua_network_connect"));
        assert!(rules.contains("-w /etc/passwd -p wa -k tamandua_identity"));
        assert!(rules.contains("-w /etc/shadow"));
        assert!(rules.contains("-w /etc/sudoers"));
    }

    #[test]
    fn test_generate_rules_aggressive() {
        let config = AuditRuleConfig {
            performance_mode: "aggressive".to_string(),
            ..Default::default()
        };

        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        assert!(rules.contains("Performance mode: aggressive"));
        assert!(rules.contains("-b 8192")); // Larger buffer
        assert!(!rules.contains("-r ")); // No rate limit in aggressive mode
        assert!(rules.contains("-S exit -S exit_group")); // Process termination
    }

    #[test]
    fn test_generate_rules_lightweight() {
        let config = AuditRuleConfig {
            performance_mode: "lightweight".to_string(),
            ..Default::default()
        };

        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        assert!(rules.contains("Performance mode: lightweight"));
        assert!(rules.contains("-b 1024")); // Smaller buffer
        assert!(rules.contains("-r 100")); // Aggressive rate limit
    }

    #[test]
    fn test_generate_rules_selective() {
        let config = AuditRuleConfig {
            process_monitoring: true,
            file_monitoring: false,
            network_monitoring: true,
            authentication_monitoring: false,
            privileged_monitoring: false,
            persistence_monitoring: false,
            credential_monitoring: false,
            performance_mode: "balanced".to_string(),
        };

        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        // Should include enabled sections
        assert!(rules.contains("Process Monitoring"));
        assert!(rules.contains("Network Operations"));
        assert!(rules.contains("-S execve"));
        assert!(rules.contains("-S connect"));

        // Should not include disabled sections
        assert!(!rules.contains("File Operations"));
        assert!(!rules.contains("Authentication & Authorization"));
        assert!(!rules.contains("Privileged Operations"));
        assert!(!rules.contains("Persistence Mechanisms"));
        assert!(!rules.contains("Credential Access"));
    }

    #[test]
    fn test_rule_syntax_validity() {
        let config = AuditRuleConfig::default();
        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        // Check that all rule lines start with valid audit syntax
        for line in rules.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Valid audit rule prefixes
            assert!(
                trimmed.starts_with("-D")
                    || trimmed.starts_with("-b")
                    || trimmed.starts_with("-f")
                    || trimmed.starts_with("-r")
                    || trimmed.starts_with("-a")
                    || trimmed.starts_with("-w")
                    || trimmed.starts_with("-e"),
                "Invalid rule syntax: {}",
                trimmed
            );
        }
    }

    #[test]
    fn test_etw_provider_coverage() {
        let config = AuditRuleConfig::default();
        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        // Verify ETW provider equivalents are documented
        let etw_providers = vec![
            "Microsoft-Windows-Security-Auditing",
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-PowerShell",
            "Microsoft-Windows-WMI-Activity",
            "Microsoft-Windows-Kernel-File",
            "Microsoft-Windows-Kernel-Network",
            "Microsoft-Windows-Kernel-Process",
        ];

        for provider in etw_providers {
            assert!(
                rules.contains(provider) || rules.contains(&provider.replace("-", " ")),
                "Missing ETW provider equivalent: {}",
                provider
            );
        }
    }

    #[test]
    fn test_mitre_attack_coverage() {
        let config = AuditRuleConfig::default();
        let generator = AuditRuleGenerator::new(config);
        let rules = generator.generate_rules();

        // Verify MITRE ATT&CK techniques are covered
        let mitre_techniques = vec!["T1547", "T1003", "T1552"];

        for technique in mitre_techniques {
            assert!(
                rules.contains(technique),
                "Missing MITRE ATT&CK technique: {}",
                technique
            );
        }
    }
}

#[cfg(test)]
mod auditd_collector_tests {
    use super::super::auditd_collector::*;

    #[test]
    fn test_auditd_collector_config_default() {
        let config = AuditdCollectorConfig::default();
        assert!(config.auto_deploy_rules);
        assert!(config.health_monitoring);
        assert_eq!(config.health_check_interval_secs, 60);
        assert_eq!(config.buffer_size, 1000);
    }

    #[test]
    fn test_auditd_collector_config_from_agent_aggressive() {
        use crate::config::{AgentConfig, PerformanceProfile};

        let mut agent_config = AgentConfig::default();
        agent_config.performance_profile = Some(PerformanceProfile::Aggressive);

        let config = AuditdCollectorConfig::from_agent_config(&agent_config);

        assert_eq!(config.rule_config.performance_mode, "aggressive");
        assert_eq!(config.buffer_size, 5000);
    }

    #[test]
    fn test_auditd_collector_config_from_agent_lightweight() {
        use crate::config::{AgentConfig, PerformanceProfile};

        let mut agent_config = AgentConfig::default();
        agent_config.performance_profile = Some(PerformanceProfile::Lightweight);

        let config = AuditdCollectorConfig::from_agent_config(&agent_config);

        assert_eq!(config.rule_config.performance_mode, "lightweight");
        assert_eq!(config.buffer_size, 500);
    }

    #[test]
    fn test_collector_stats_default() {
        let stats = CollectorStats::default();
        assert_eq!(stats.events_received, 0);
        assert_eq!(stats.events_normalized, 0);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.parse_errors, 0);
        assert!(stats.last_event_time.is_none());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_end_to_end_normalization() {
        use super::super::event_normalizer::*;

        let mut normalizer = EventNormalizer::new();

        // Simulate a process creation event with multiple records
        let mut syscall_fields = HashMap::new();
        syscall_fields.insert("type".to_string(), "SYSCALL".to_string());
        syscall_fields.insert("time".to_string(), "1234567890.123".to_string());
        syscall_fields.insert("syscall".to_string(), "execve".to_string());
        syscall_fields.insert("pid".to_string(), "12345".to_string());
        syscall_fields.insert("ppid".to_string(), "1000".to_string());
        syscall_fields.insert("uid".to_string(), "1000".to_string());
        syscall_fields.insert("euid".to_string(), "1000".to_string());
        syscall_fields.insert("comm".to_string(), "curl".to_string());
        syscall_fields.insert("exe".to_string(), "/usr/bin/curl".to_string());
        syscall_fields.insert("a0".to_string(), "6375726c".to_string()); // curl
        syscall_fields.insert(
            "a1".to_string(),
            "68747470733a2f2f6578616d706c652e636f6d".to_string(),
        ); // https://example.com

        let record = AuditRecord::from_fields(syscall_fields).unwrap();
        let event = normalizer.normalize(record).unwrap();

        assert!(event.is_some());
        let event = event.unwrap();

        use super::super::super::{EventPayload, EventType};
        assert_eq!(event.event_type, EventType::ProcessCreate);

        if let EventPayload::Process(proc_event) = event.payload {
            assert_eq!(proc_event.pid, 12345);
            assert_eq!(proc_event.name, "curl");
            assert!(proc_event.cmdline.contains("curl"));
            assert!(proc_event.cmdline.contains("example.com"));
        } else {
            panic!("Expected Process payload");
        }
    }
}
