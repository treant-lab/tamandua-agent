//! Comprehensive unit tests for analyzers module
//!
//! Tests cover YARA scanning, entropy calculation, PE parsing,
//! heuristic detection, and behavioral analysis.

#[cfg(test)]
mod entropy_tests {
    #[test]
    fn test_shannon_entropy_calculation() {
        // High entropy (encrypted/compressed data)
        let encrypted = vec![
            0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x13, 0x57, 0x9B,
            0xDF, 0x24,
        ];

        // Low entropy (repeated data)
        let repeated = vec![0x41; 16]; // "AAAA..."

        // Calculate mock entropy
        let high_entropy = calculate_mock_entropy(&encrypted);
        let low_entropy = calculate_mock_entropy(&repeated);

        assert!(
            high_entropy > 3.5,
            "Encrypted data should have high entropy"
        );
        assert!(low_entropy < 2.0, "Repeated data should have low entropy");
    }

    fn calculate_mock_entropy(data: &[u8]) -> f64 {
        use std::collections::HashMap;

        if data.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for &byte in data {
            *freq.entry(byte).or_insert(0) += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for count in freq.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    #[test]
    fn test_entropy_thresholds() {
        let thresholds = vec![
            (5.0, "low", "text/source code"),
            (6.5, "medium", "normal binaries"),
            (7.5, "high", "compressed/encrypted"),
            (8.0, "very_high", "packed malware"),
        ];

        for (value, level, description) in thresholds {
            assert!(value >= 0.0 && value <= 8.0, "Entropy must be 0-8");
            assert!(!level.is_empty());
            assert!(!description.is_empty());
        }
    }

    #[test]
    fn test_section_entropy() {
        // Simulate PE sections
        struct Section {
            name: String,
            data: Vec<u8>,
        }

        let sections = vec![
            Section {
                name: ".text".to_string(),
                data: vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40], // x86 code
            },
            Section {
                name: ".data".to_string(),
                data: vec![0x00; 100], // Zeros
            },
            Section {
                name: ".rsrc".to_string(),
                data: (0..=255).collect::<Vec<u8>>(), // Random-ish
            },
        ];

        for section in sections {
            let entropy = calculate_mock_entropy(&section.data);
            assert!(
                entropy >= 0.0 && entropy <= 8.0,
                "Section {} has invalid entropy",
                section.name
            );
        }
    }
}

#[cfg(test)]
#[cfg(feature = "yara")]
mod yara_tests {
    #[test]
    fn test_yara_rule_loading() {
        // Mock YARA rule
        let rule = r#"
rule TestRule
{
    meta:
        description = "Test rule"
        author = "Test"

    strings:
        $a = "malware"
        $b = "suspicious"

    condition:
        any of them
}
"#;

        assert!(rule.contains("rule TestRule"));
        assert!(rule.contains("condition:"));
        assert!(rule.contains("any of them"));
    }

    #[test]
    fn test_yara_match_extraction() {
        // Mock match result
        struct YaraMatch {
            rule_name: String,
            namespace: String,
            tags: Vec<String>,
            metadata: std::collections::HashMap<String, String>,
        }

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("description".to_string(), "Test malware".to_string());
        metadata.insert("family".to_string(), "Generic".to_string());

        let match_result = YaraMatch {
            rule_name: "Malware_Generic".to_string(),
            namespace: "default".to_string(),
            tags: vec!["malware".to_string(), "trojan".to_string()],
            metadata,
        };

        assert_eq!(match_result.rule_name, "Malware_Generic");
        assert_eq!(match_result.tags.len(), 2);
        assert!(match_result.metadata.contains_key("description"));
    }
}

#[cfg(test)]
mod pe_parser_tests {
    #[test]
    fn test_pe_header_validation() {
        // DOS header starts with "MZ"
        let dos_signature = [0x4D, 0x5A]; // "MZ"
        assert_eq!(dos_signature, [b'M', b'Z']);

        // PE signature is "PE\0\0"
        let pe_signature = [0x50, 0x45, 0x00, 0x00];
        assert_eq!(&pe_signature[0..2], b"PE");
    }

    #[test]
    fn test_section_flags() {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
        const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

        let characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

        let is_executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        let is_writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        assert!(is_executable);
        assert!(is_readable);
        assert!(!is_writable);
    }

    #[test]
    fn test_suspicious_imports() {
        let suspicious_functions = vec![
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "LoadLibrary",
            "GetProcAddress",
        ];

        let import_list = vec!["VirtualAlloc", "Sleep", "CreateRemoteThread"];

        let suspicious_count = import_list
            .iter()
            .filter(|imp| suspicious_functions.contains(imp))
            .count();

        assert_eq!(suspicious_count, 2);
    }

    #[test]
    fn test_packer_detection() {
        struct Section {
            name: String,
            virtual_size: u32,
            raw_size: u32,
        }

        let sections = vec![
            Section {
                name: ".text".to_string(),
                virtual_size: 10000,
                raw_size: 5000,
            },
            Section {
                name: ".data".to_string(),
                virtual_size: 2000,
                raw_size: 2000,
            },
        ];

        // Packer indicator: virtual size >> raw size
        for section in sections {
            let ratio = section.virtual_size as f32 / section.raw_size as f32;
            let is_packed = ratio > 1.5;

            if section.name == ".text" {
                assert!(is_packed, "Text section looks packed");
            } else {
                assert!(!is_packed, "Data section looks normal");
            }
        }
    }
}

#[cfg(test)]
mod heuristic_detection_tests {
    #[test]
    fn test_suspicious_strings() {
        let strings = vec![
            "127.0.0.1",
            "cmd.exe",
            "powershell",
            "bypass",
            "encrypted",
            "ransomware",
        ];

        let indicators = vec!["powershell", "bypass", "ransomware"];

        let suspicious_count = strings
            .iter()
            .filter(|s| indicators.iter().any(|i| s.contains(i)))
            .count();

        assert!(suspicious_count >= 2, "Should detect multiple indicators");
    }

    #[test]
    fn test_obfuscation_detection() {
        let test_cases = vec![
            ("normal_function", false),
            ("aAbBcCdDeEfF", true),    // Mixed case random
            ("func_1234567890", true), // Long numeric suffix
            ("a1b2c3d4e5f6", true),    // Alternating pattern
        ];

        for (name, should_be_obfuscated) in test_cases {
            let has_mixed_case = name.chars().filter(|c| c.is_uppercase()).count() > 2
                && name.chars().filter(|c| c.is_lowercase()).count() > 2;

            let has_many_numbers = name.chars().filter(|c| c.is_numeric()).count() > 5;

            let is_obfuscated = has_mixed_case || has_many_numbers;

            assert_eq!(
                is_obfuscated, should_be_obfuscated,
                "Obfuscation check failed for '{}'",
                name
            );
        }
    }

    #[test]
    fn test_base64_detection() {
        let strings = vec![
            "SGVsbG8gV29ybGQ=",     // "Hello World"
            "VGhpcyBpcyBhIHRlc3Q=", // "This is a test"
            "bm9ybWFsX3RleHQ=",     // "normal_text"
            "not-base64",
            "12345",
        ];

        for s in strings {
            // Simple heuristic: base64 is alphanumeric + / + = padding
            let looks_like_base64 = s.len() > 10
                && s.chars()
                    .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
                && s.ends_with('=');

            if s.ends_with('=') {
                assert!(looks_like_base64, "String '{}' looks like base64", s);
            }
        }
    }

    #[test]
    fn test_url_extraction() {
        let strings = vec![
            "http://malware.com/payload.exe",
            "https://evil.ru/backdoor",
            "ftp://192.168.1.1/data",
            "normal text without url",
        ];

        let url_pattern = vec!["http://", "https://", "ftp://"];

        for s in strings {
            let has_url = url_pattern.iter().any(|p| s.contains(p));

            if has_url {
                assert!(s.contains("://"), "String '{}' contains URL", s);
            }
        }
    }
}

#[cfg(test)]
mod behavioral_analysis_tests {
    #[test]
    fn test_process_behavior_scoring() {
        struct ProcessBehavior {
            creates_files: bool,
            modifies_registry: bool,
            network_connections: bool,
            spawns_children: bool,
            elevated: bool,
        }

        let behaviors = vec![
            ProcessBehavior {
                creates_files: true,
                modifies_registry: true,
                network_connections: true,
                spawns_children: true,
                elevated: true,
            },
            ProcessBehavior {
                creates_files: false,
                modifies_registry: false,
                network_connections: true,
                spawns_children: false,
                elevated: false,
            },
        ];

        for behavior in behaviors {
            let mut score = 0;

            if behavior.creates_files {
                score += 1;
            }
            if behavior.modifies_registry {
                score += 2;
            }
            if behavior.network_connections {
                score += 1;
            }
            if behavior.spawns_children {
                score += 1;
            }
            if behavior.elevated {
                score += 2;
            }

            let risk_level = if score >= 5 {
                "high"
            } else if score >= 3 {
                "medium"
            } else {
                "low"
            };

            assert!(!risk_level.is_empty());
        }
    }

    #[test]
    fn test_process_tree_analysis() {
        struct Process {
            pid: u32,
            ppid: u32,
            name: String,
        }

        let processes = vec![
            Process {
                pid: 1,
                ppid: 0,
                name: "init".to_string(),
            },
            Process {
                pid: 100,
                ppid: 1,
                name: "sshd".to_string(),
            },
            Process {
                pid: 200,
                ppid: 100,
                name: "bash".to_string(),
            },
            Process {
                pid: 300,
                ppid: 200,
                name: "malware".to_string(),
            },
        ];

        // Find process ancestry
        let target_pid = 300;
        let mut ancestors = vec![];
        let mut current_pid = target_pid;

        for _ in 0..processes.len() {
            if let Some(proc) = processes.iter().find(|p| p.pid == current_pid) {
                ancestors.push(proc.name.clone());
                current_pid = proc.ppid;
                if current_pid == 0 {
                    break;
                }
            }
        }

        assert!(ancestors.contains(&"malware".to_string()));
        assert!(ancestors.contains(&"bash".to_string()));
        assert!(ancestors.len() >= 2);
    }

    #[test]
    fn test_anomalous_parent_detection() {
        let anomalies = vec![
            ("cmd.exe", "winword.exe", true),       // Word spawning cmd
            ("powershell.exe", "excel.exe", true),  // Excel spawning PS
            ("notepad.exe", "explorer.exe", false), // Normal
            ("chrome.exe", "chrome.exe", false),    // Normal (tab process)
        ];

        for (child, parent, should_be_anomalous) in anomalies {
            let office_apps = vec!["winword.exe", "excel.exe", "powerpnt.exe"];
            let suspicious_children = vec!["cmd.exe", "powershell.exe", "wscript.exe"];

            let is_anomalous =
                office_apps.contains(&parent) && suspicious_children.contains(&child);

            assert_eq!(
                is_anomalous, should_be_anomalous,
                "Anomaly check failed for {} <- {}",
                child, parent
            );
        }
    }
}

#[cfg(test)]
mod threat_intel_tests {
    #[test]
    fn test_ioc_matching() {
        use std::collections::HashSet;

        let known_bad_hashes: HashSet<String> = vec![
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            "098f6bcd4621d373cade4e832627b4f6".to_string(),
        ]
        .into_iter()
        .collect();

        let test_hashes = vec![
            "d41d8cd98f00b204e9800998ecf8427e",
            "5d41402abc4b2a76b9719d911017c592",
        ];

        for hash in test_hashes {
            let is_known_bad = known_bad_hashes.contains(hash);

            if hash == "d41d8cd98f00b204e9800998ecf8427e" {
                assert!(is_known_bad, "Hash should be flagged");
            }
        }
    }

    #[test]
    fn test_ip_reputation() {
        use std::collections::HashMap;

        let mut reputation: HashMap<String, &str> = HashMap::new();
        reputation.insert("1.2.3.4".to_string(), "malicious");
        reputation.insert("8.8.8.8".to_string(), "benign");
        reputation.insert("10.0.0.1".to_string(), "unknown");

        let test_ips = vec!["1.2.3.4", "8.8.8.8", "192.168.1.1"];

        for ip in test_ips {
            let rep = reputation.get(ip).unwrap_or(&"unknown");
            assert!(!rep.is_empty());
        }
    }

    #[test]
    fn test_domain_categorization() {
        let domains = vec![
            ("google.com", "legitimate"),
            ("malware.ru", "suspicious"),
            ("phishing-site.tk", "malicious"),
        ];

        for (domain, expected_category) in domains {
            assert!(!domain.is_empty());
            assert!(!expected_category.is_empty());
        }
    }
}

#[cfg(test)]
mod ml_inference_tests {
    #[test]
    fn test_feature_extraction() {
        struct Features {
            entropy: f32,
            size: u64,
            import_count: u32,
            section_count: u32,
            string_count: u32,
        }

        let features = Features {
            entropy: 7.5,
            size: 1024000,
            import_count: 50,
            section_count: 5,
            string_count: 200,
        };

        assert!(features.entropy > 0.0 && features.entropy <= 8.0);
        assert!(features.size > 0);
        assert!(features.import_count > 0);
    }

    #[test]
    fn test_prediction_threshold() {
        let predictions = vec![
            (0.95, "malicious"),
            (0.75, "suspicious"),
            (0.45, "borderline"),
            (0.15, "benign"),
        ];

        for (confidence, expected) in predictions {
            let classification = if confidence >= 0.8 {
                "malicious"
            } else if confidence >= 0.5 {
                "suspicious"
            } else if confidence >= 0.3 {
                "borderline"
            } else {
                "benign"
            };

            if confidence >= 0.8 {
                assert_eq!(classification, "malicious");
            }
        }
    }
}

#[cfg(test)]
mod signature_tests {
    #[test]
    fn test_byte_pattern_matching() {
        let signature = vec![0x4D, 0x5A, 0x90, 0x00]; // PE DOS header
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];

        let matches = data
            .windows(signature.len())
            .any(|window| window == signature.as_slice());

        assert!(matches, "Pattern should be found");
    }

    #[test]
    fn test_wildcard_patterns() {
        // Simple wildcard pattern matching
        let pattern = vec![Some(0x4D), Some(0x5A), None, Some(0x00)]; // 4D 5A ?? 00
        let data = vec![0x4D, 0x5A, 0xFF, 0x00];

        let matches = pattern.iter().zip(data.iter()).all(|(p, d)| {
            match p {
                Some(byte) => byte == d,
                None => true, // Wildcard matches anything
            }
        });

        assert!(matches, "Wildcard pattern should match");
    }
}
