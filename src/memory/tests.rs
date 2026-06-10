//! Memory analysis tests

#[cfg(test)]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn test_memory_region_type_serialization() {
        let region = MemoryRegion {
            base_address: 0x10000000,
            size: 4096,
            protection: 0x20,
            memory_type: MemoryRegionType::Private,
            module_name: None,
            module_path: None,
            is_executable: true,
            is_writable: false,
            is_readable: true,
            is_private: true,
        };

        let json = serde_json::to_string(&region).unwrap();
        let deserialized: MemoryRegion = serde_json::from_str(&json).unwrap();

        assert_eq!(region.base_address, deserialized.base_address);
        assert_eq!(region.size, deserialized.size);
        assert_eq!(region.memory_type, deserialized.memory_type);
    }

    #[test]
    fn test_suspicion_reason_mitre_mapping() {
        assert_eq!(SuspicionReason::RwxMemory.mitre_technique(), "T1055");
        assert_eq!(SuspicionReason::InjectedDll.mitre_technique(), "T1055.001");
        assert_eq!(
            SuspicionReason::HollowedSection.mitre_technique(),
            "T1055.012"
        );
        assert_eq!(
            SuspicionReason::NonImageExecutable.mitre_technique(),
            "T1620"
        );
    }

    #[test]
    fn test_dump_type_serialization() {
        let options = DumpOptions {
            dump_type: DumpType::RwxRegions,
            compress: true,
            upload: false,
            output_path: Some("/tmp/dump.bin".to_string()),
        };

        let json = serde_json::to_string(&options).unwrap();
        let deserialized: DumpOptions = serde_json::from_str(&json).unwrap();

        assert_eq!(options.dump_type, deserialized.dump_type);
        assert_eq!(options.compress, deserialized.compress);
    }

    #[test]
    fn test_string_type_classification() {
        assert_eq!(StringType::Url.as_str(), "url");
        assert_eq!(StringType::IpAddress.as_str(), "ip_address");
        assert_eq!(StringType::FilePath.as_str(), "file_path");
    }

    #[cfg(feature = "yara")]
    #[tokio::test]
    async fn test_yara_match_serialization() {
        let yara_match = MemoryYaraMatch {
            rule_name: "CobaltStrike_Beacon".to_string(),
            tags: vec!["malware".to_string(), "c2".to_string()],
            metadata: serde_json::json!({"severity": "high"}),
            offset: 0x10000,
            length: 256,
            region: MemoryRegion {
                base_address: 0x10000000,
                size: 4096,
                protection: 0x20,
                memory_type: MemoryRegionType::Private,
                module_name: None,
                module_path: None,
                is_executable: true,
                is_writable: false,
                is_readable: true,
                is_private: true,
            },
        };

        let json = serde_json::to_string(&yara_match).unwrap();
        let deserialized: MemoryYaraMatch = serde_json::from_str(&json).unwrap();

        assert_eq!(yara_match.rule_name, deserialized.rule_name);
        assert_eq!(yara_match.offset, deserialized.offset);
        assert_eq!(yara_match.tags, deserialized.tags);
    }

    #[test]
    fn test_memory_analysis_report_structure() {
        let report = MemoryAnalysisReport {
            pid: 1234,
            process_name: "test.exe".to_string(),
            process_path: Some("C:\\test.exe".to_string()),
            timestamp: 1234567890,
            regions_scanned: 100,
            suspicious_regions: Vec::new(),
            yara_matches: Vec::new(),
            iat_hooks: Vec::new(),
            inline_hooks: Vec::new(),
            strings: Vec::new(),
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: MemoryAnalysisReport = serde_json::from_str(&json).unwrap();

        assert_eq!(report.pid, deserialized.pid);
        assert_eq!(report.process_name, deserialized.process_name);
        assert_eq!(report.regions_scanned, deserialized.regions_scanned);
    }

    #[test]
    fn test_suspicious_region_confidence() {
        let region = MemoryRegion {
            base_address: 0x10000000,
            size: 4096,
            protection: 0x40, // RWX
            memory_type: MemoryRegionType::Private,
            module_name: None,
            module_path: None,
            is_executable: true,
            is_writable: true,
            is_readable: true,
            is_private: true,
        };

        let suspicious = SuspiciousRegion {
            pid: 1234,
            process_name: "test.exe".to_string(),
            region,
            reasons: vec![
                SuspicionReason::RwxMemory,
                SuspicionReason::ExecutablePrivate,
            ],
            confidence: 0.85,
            details: "RWX private memory".to_string(),
        };

        assert!(suspicious.confidence > 0.8);
        assert!(suspicious.reasons.contains(&SuspicionReason::RwxMemory));
    }
}
