//! Detection constants for ETW tampering and NTDLL monitoring
//!
//! Centralizes magic numbers, MITRE IDs, and configuration defaults.

// MITRE ATT&CK Technique IDs
pub const MITRE_NTDLL_TAMPERING: &str = "T1562.006";
pub const MITRE_DEFENSE_EVASION: &str = "T1562.001";
pub const MITRE_PROCESS_INJECTION: &str = "T1055";

// Confidence score defaults
pub const CONFIDENCE_NTDLL_INTEGRITY: f64 = 0.95;
pub const CONFIDENCE_FRESH_MAPPING: f64 = 0.90;
pub const CONFIDENCE_DIRECT_SYSCALL: f64 = 0.85;
pub const CONFIDENCE_LIBC_INTEGRITY: f64 = 0.85;

// Module names
pub const NTDLL_MODULE_NAME: &str = "ntdll.dll";
pub const NTDLL_TEXT_SECTION: &str = "ntdll.dll!.text";

// Timing defaults (milliseconds)
pub const INTEGRITY_SCAN_INTERVAL_MS: f64 = 5000.0;
pub const MAPPING_DETECTOR_INTERVAL_MS: f64 = 3000.0;
pub const SYSCALL_SCANNER_INTERVAL_MS: f64 = 10000.0;

// Operation tracking
pub const OPERATION_MAX_AGE_SECS: u64 = 30;
pub const CLEANUP_INTERVAL_SECS: u64 = 30;

// Memory limits
pub const MAX_MODULES: usize = 1024;
pub const PE_HEADER_READ_SIZE: usize = 0x1000;
pub const MAX_TEXT_SECTION_SIZE: usize = 1024 * 1024;
pub const MAX_REGION_SCAN_SIZE: usize = 64 * 1024;
pub const EXPORT_RVA_THRESHOLD: u64 = 256;

// Syscall instruction patterns
pub const SYSCALL_PATTERN: &[u8] = &[0x0F, 0x05];
pub const SYSENTER_PATTERN: &[u8] = &[0x0F, 0x34];
pub const INT2E_PATTERN: &[u8] = &[0xCD, 0x2E];

// Whitelisted security processes (should be configurable)
pub const SECURITY_PROCESS_WHITELIST: &[&str] = &[
    "msmpeng.exe",
    "mssense.exe",
    "csfalconservice.exe",
    "carbonblack.exe",
    "sentinel.exe",
    "tamandua-agent.exe",
];
