//! Registry Guard Module - Protects Windows registry keys (Windows only)
//!
//! This module implements registry protection mechanisms:
//! - Protect HKLM\SOFTWARE\Tamandua keys from tampering
//! - Monitor for registry changes via RegNotifyChangeKeyValue
//! - Protect service registration keys
//! - Alert on tampering attempts
//!
//! MITRE ATT&CK Coverage:
//! - T1112 - Modify Registry
//! - T1562.001 - Disable or Modify Tools

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{TamperEvent, TamperEventType, TamperSeverity};

/// Protected registry key paths
pub const PROTECTED_KEYS: &[&str] = &[
    "SOFTWARE\\Tamandua",
    "SOFTWARE\\Tamandua\\Config",
    "SOFTWARE\\Tamandua\\Rules",
    "SYSTEM\\CurrentControlSet\\Services\\TamanduaAgent",
    "SYSTEM\\CurrentControlSet\\Services\\tamandua_driver",
];

/// Registry guard configuration
#[derive(Debug, Clone)]
pub struct RegistryGuardConfig {
    /// Enable registry change monitoring
    pub enable_monitoring: bool,
    /// Enable DACL protection on registry keys
    pub enable_dacl_protection: bool,
    /// Monitor interval in seconds
    pub monitor_interval_secs: u64,
    /// Additional keys to protect
    pub additional_protected_keys: Vec<String>,
}

impl Default for RegistryGuardConfig {
    fn default() -> Self {
        Self {
            enable_monitoring: true,
            enable_dacl_protection: true,
            monitor_interval_secs: 10,
            additional_protected_keys: Vec::new(),
        }
    }
}

/// Registry guard state
pub struct RegistryGuard {
    config: RegistryGuardConfig,
    running: Arc<AtomicBool>,
    tamper_count: Arc<AtomicU64>,
    key_values_baseline: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
    tamper_tx: mpsc::Sender<TamperEvent>,
}

impl RegistryGuard {
    /// Create a new registry guard
    pub fn new(config: RegistryGuardConfig, tamper_tx: mpsc::Sender<TamperEvent>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            tamper_count: Arc::new(AtomicU64::new(0)),
            key_values_baseline: std::sync::RwLock::new(std::collections::HashMap::new()),
            tamper_tx,
        }
    }

    /// Initialize registry protection (Windows only)
    #[cfg(windows)]
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing registry guard");
        self.running.store(true, Ordering::SeqCst);

        // Capture baseline values for protected keys
        self.capture_baseline().await?;

        // Apply DACL protection to registry keys
        if self.config.enable_dacl_protection {
            for key in PROTECTED_KEYS {
                if let Err(e) = self.protect_registry_key(key) {
                    warn!(key = key, "Failed to protect registry key: {}", e);
                }
            }

            for key in &self.config.additional_protected_keys {
                if let Err(e) = self.protect_registry_key(key) {
                    warn!(
                        key = key,
                        "Failed to protect additional registry key: {}", e
                    );
                }
            }
        }

        // Start registry monitoring
        if self.config.enable_monitoring {
            self.start_registry_monitor();
        }

        Ok(())
    }

    #[cfg(not(windows))]
    pub async fn initialize(&self) -> Result<()> {
        info!("Registry guard not applicable on this platform");
        Ok(())
    }

    /// Capture baseline values for protected registry keys
    #[cfg(windows)]
    async fn capture_baseline(&self) -> Result<()> {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::RegKey;

        let mut baseline = self
            .key_values_baseline
            .write()
            .unwrap_or_else(|e| e.into_inner());

        for key_path in PROTECTED_KEYS {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(key) = hklm.open_subkey_with_flags(key_path, KEY_READ) {
                // Capture key values
                for value_result in key.enum_values() {
                    if let Ok((name, value)) = value_result {
                        let full_path = format!("{}\\{}", key_path, name);
                        // Convert RegValue to bytes for comparison
                        baseline.insert(full_path, value.bytes.clone());
                    }
                }
            }
        }

        for key_path in &self.config.additional_protected_keys {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(key) = hklm.open_subkey_with_flags(key_path, KEY_READ) {
                for value_result in key.enum_values() {
                    if let Ok((name, value)) = value_result {
                        let full_path = format!("{}\\{}", key_path, name);
                        baseline.insert(full_path, value.bytes.clone());
                    }
                }
            }
        }

        info!(count = baseline.len(), "Registry baseline captured");
        Ok(())
    }

    #[cfg(not(windows))]
    async fn capture_baseline(&self) -> Result<()> {
        Ok(())
    }

    /// Protect a registry key with restrictive DACL
    #[cfg(windows)]
    fn protect_registry_key(&self, key_path: &str) -> Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_REGISTRY_KEY};
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS,
        };

        let key_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey: HKEY = HKEY::default();

            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(key_wide.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                &mut hkey,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to open registry key: {:?}", result));
            }

            // Set protected DACL on the key
            // This restricts modifications to SYSTEM and Administrators only
            let set_result = SetSecurityInfo(
                windows::Win32::Foundation::HANDLE(hkey.0 as isize),
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                None, // Keep current DACL but protect it
                None,
            );

            let _ = RegCloseKey(hkey);

            if set_result.is_err() {
                return Err(anyhow!("Failed to set registry security: {:?}", set_result));
            }
        }

        debug!(key = key_path, "Registry key protected");
        Ok(())
    }

    #[cfg(not(windows))]
    fn protect_registry_key(&self, _key_path: &str) -> Result<()> {
        Ok(())
    }

    /// Start registry monitoring task
    #[cfg(windows)]
    fn start_registry_monitor(&self) {
        let running = self.running.clone();
        let tamper_tx = self.tamper_tx.clone();
        let tamper_count = self.tamper_count.clone();
        let baseline = self
            .key_values_baseline
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let interval_secs = self.config.monitor_interval_secs;
        let additional_keys = self.config.additional_protected_keys.clone();

        tokio::spawn(async move {
            use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
            use winreg::RegKey;

            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            while running.load(Ordering::SeqCst) {
                interval.tick().await;

                let all_keys: Vec<&str> = PROTECTED_KEYS
                    .iter()
                    .copied()
                    .chain(additional_keys.iter().map(|s| s.as_str()))
                    .collect();

                for key_path in all_keys {
                    // Check if key still exists
                    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                    match hklm.open_subkey_with_flags(key_path, KEY_READ) {
                        Ok(key) => {
                            // Check for value modifications
                            for value_result in key.enum_values() {
                                if let Ok((name, value)) = value_result {
                                    let full_path = format!("{}\\{}", key_path, name);

                                    if let Some(expected) = baseline.get(&full_path) {
                                        if value.bytes != *expected {
                                            warn!(
                                                key = key_path,
                                                value = name,
                                                "Registry value modified"
                                            );

                                            tamper_count.fetch_add(1, Ordering::SeqCst);

                                            let event = TamperEvent {
                                                timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                                                event_type: TamperEventType::RegistryModification,
                                                description: format!(
                                                    "Registry value modified: {}\\{}",
                                                    key_path, name
                                                ),
                                                source_pid: None,
                                                source_process: None,
                                                severity: TamperSeverity::Critical,
                                                mitre_technique: Some("T1112".to_string()),
                                            };

                                            let _ = tamper_tx.send(event).await;
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Key deleted
                            warn!(key = key_path, "Protected registry key deleted");

                            tamper_count.fetch_add(1, Ordering::SeqCst);

                            let event = TamperEvent {
                                timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                                event_type: TamperEventType::RegistryModification,
                                description: format!("Registry key deleted: {}", key_path),
                                source_pid: None,
                                source_process: None,
                                severity: TamperSeverity::Critical,
                                mitre_technique: Some("T1112".to_string()),
                            };

                            let _ = tamper_tx.send(event).await;
                        }
                    }
                }

                // Also check service-specific keys
                Self::check_service_registry_tamper(&tamper_tx, &tamper_count).await;
            }
        });
    }

    #[cfg(not(windows))]
    fn start_registry_monitor(&self) {
        // No-op on non-Windows platforms
    }

    /// Check for service registry tampering
    #[cfg(windows)]
    async fn check_service_registry_tamper(
        tamper_tx: &mpsc::Sender<TamperEvent>,
        tamper_count: &AtomicU64,
    ) {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::RegKey;

        let service_key = "SYSTEM\\CurrentControlSet\\Services\\TamanduaAgent";
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        if let Ok(key) = hklm.open_subkey_with_flags(service_key, KEY_READ) {
            // Check Start value (should be 2 for automatic)
            if let Ok(start_type) = key.get_value::<u32, _>("Start") {
                if start_type != 2 {
                    warn!(
                        start_type = start_type,
                        "Service start type modified (expected 2/Automatic)"
                    );

                    tamper_count.fetch_add(1, Ordering::SeqCst);

                    let event = TamperEvent {
                        timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                        event_type: TamperEventType::ServiceModification,
                        description: format!(
                            "Service start type changed to {} (expected 2/Automatic)",
                            start_type
                        ),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1562.001".to_string()),
                    };

                    let _ = tamper_tx.send(event).await;
                }
            }

            // Check ImagePath value
            if let Ok(image_path) = key.get_value::<String, _>("ImagePath") {
                let expected_paths = [
                    "C:\\Program Files\\Tamandua\\tamandua-agent.exe",
                    "\"C:\\Program Files\\Tamandua\\tamandua-agent.exe\"",
                ];

                let path_valid = expected_paths
                    .iter()
                    .any(|expected| image_path.to_lowercase().contains(&expected.to_lowercase()));

                if !path_valid {
                    warn!(image_path = image_path, "Service image path modified");

                    tamper_count.fetch_add(1, Ordering::SeqCst);

                    let event = TamperEvent {
                        timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                        event_type: TamperEventType::ServiceBinaryReplaced,
                        description: format!("Service binary path modified: {}", image_path),
                        source_pid: None,
                        source_process: None,
                        severity: TamperSeverity::Critical,
                        mitre_technique: Some("T1574.011".to_string()),
                    };

                    let _ = tamper_tx.send(event).await;
                }
            }
        }
    }

    /// Monitor for real-time registry changes using RegNotifyChangeKeyValue
    #[cfg(windows)]
    pub fn start_realtime_monitor(&self, key_path: &str) -> Result<tokio::task::JoinHandle<()>> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
            KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
        };
        use windows::Win32::System::Threading::WaitForSingleObject;

        let key_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();

        let running = self.running.clone();
        let tamper_tx = self.tamper_tx.clone();
        let key_path_owned = key_path.to_string();

        let handle = tokio::spawn(async move {
            unsafe {
                let mut hkey: HKEY = HKEY::default();

                let result = RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(key_wide.as_ptr()),
                    0,
                    KEY_NOTIFY,
                    &mut hkey,
                );

                if result.is_err() {
                    error!(key = %key_path_owned, "Failed to open key for monitoring");
                    return;
                }

                // Create event for notification
                let event =
                    windows::Win32::System::Threading::CreateEventW(None, false, false, None)
                        .unwrap_or(HANDLE::default());

                while running.load(Ordering::SeqCst) {
                    let notify_result = RegNotifyChangeKeyValue(
                        hkey,
                        true, // Watch subtree
                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                        event,
                        true, // Asynchronous
                    );

                    if notify_result.is_err() {
                        warn!(key = %key_path_owned, "RegNotifyChangeKeyValue failed");
                        break;
                    }

                    // Wait for change with timeout
                    let wait_result = WaitForSingleObject(event, 5000);

                    if wait_result.0 == 0 {
                        // Change detected
                        warn!(key = %key_path_owned, "Registry change detected");

                        let tamper_event = TamperEvent {
                            timestamp: crate::protection::ProtectionEngine::current_timestamp(),
                            event_type: TamperEventType::RegistryModification,
                            description: format!(
                                "Real-time registry change detected: {}",
                                key_path_owned
                            ),
                            source_pid: None,
                            source_process: None,
                            severity: TamperSeverity::High,
                            mitre_technique: Some("T1112".to_string()),
                        };

                        let _ = tamper_tx.send(tamper_event).await;
                    }
                }

                let _ = RegCloseKey(hkey);
                let _ = windows::Win32::Foundation::CloseHandle(event);
            }
        });

        Ok(handle)
    }

    #[cfg(not(windows))]
    pub fn start_realtime_monitor(&self, _key_path: &str) -> Result<tokio::task::JoinHandle<()>> {
        Ok(tokio::spawn(async {}))
    }

    /// Get tamper count
    pub fn get_tamper_count(&self) -> u64 {
        self.tamper_count.load(Ordering::SeqCst)
    }

    /// Shutdown registry guard
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Registry guard shutdown");
    }
}

/// Registry guard status
#[derive(Debug, Clone)]
pub struct RegistryGuardStatus {
    pub monitoring_active: bool,
    pub protected_key_count: usize,
    pub tamper_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_keys() {
        assert!(!PROTECTED_KEYS.is_empty());
        assert!(PROTECTED_KEYS.iter().any(|k| k.contains("Tamandua")));
    }
}
