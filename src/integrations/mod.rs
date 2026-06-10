//! Windows Security Integrations
//!
//! This module provides integration with Windows security subsystems:
//! - Windows Defender integration (threat events, exclusion coordination)
//! - Windows Security Center (WSC) registration
//! - AMSI provider registration (receive script content)
//!
//! These integrations allow Tamandua EDR to:
//! 1. Leverage Defender's cloud reputation without duplicating scans
//! 2. Appear in Windows Security app as a registered security solution
//! 3. Receive proactive notification of script executions via AMSI

#[cfg(target_os = "windows")]
pub mod defender;

#[cfg(target_os = "windows")]
pub mod wsc;

#[cfg(target_os = "windows")]
pub mod amsi_provider;

// Re-export main types for convenience
#[cfg(target_os = "windows")]
pub use defender::{DefenderConfig, DefenderIntegration, DefenderThreatEvent};

#[cfg(target_os = "windows")]
pub use wsc::{SecurityCenterRegistration, SecurityCenterStatus, WscProductType};

#[cfg(target_os = "windows")]
pub use amsi_provider::{AmsiProvider, AmsiProviderConfig};

// Linux/macOS equivalents
#[cfg(target_os = "linux")]
pub mod clamav;

#[cfg(target_os = "macos")]
pub mod xprotect;

// Stub types for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub mod defender {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default)]
    pub struct DefenderConfig;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DefenderThreatEvent {
        pub placeholder: String,
    }

    pub struct DefenderIntegration;

    impl DefenderIntegration {
        pub fn new(_config: DefenderConfig) -> Result<Self, String> {
            Err("Windows Defender integration only available on Windows".to_string())
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub mod wsc {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WscProductType {
        Antivirus,
        Firewall,
        AntiSpyware,
    }

    #[derive(Debug, Clone, Default)]
    pub struct SecurityCenterStatus;

    pub struct SecurityCenterRegistration;

    impl SecurityCenterRegistration {
        pub fn register(_product_type: WscProductType, _name: &str) -> Result<Self, String> {
            Err("Windows Security Center only available on Windows".to_string())
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub mod amsi_provider {
    #[derive(Debug, Clone, Default)]
    pub struct AmsiProviderConfig;

    pub struct AmsiProvider;

    impl AmsiProvider {
        pub fn new(_config: AmsiProviderConfig) -> Result<Self, String> {
            Err("AMSI provider only available on Windows".to_string())
        }
    }
}
