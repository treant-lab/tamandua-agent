//! Clipboard monitoring collector
//!
//! Monitors clipboard activity to detect clipboard-based attacks and data theft:
//! - Clipboard access monitoring (track processes accessing clipboard)
//! - Sensitive data detection (crypto wallets, credit cards, API keys)
//! - Clipboard hijacking detection (address swapping, URL replacement)
//! - Data exfiltration patterns (large copies, rapid access)
//!
//! MITRE ATT&CK: T1115 - Clipboard Data
//!
//! Windows: SetClipboardViewer / AddClipboardFormatListener, clipboard chain monitoring
//! Linux: X11 selections (PRIMARY, CLIPBOARD) via xclip/xsel or direct X11
//! macOS: NSPasteboard monitoring

// Clipboard hijack/exfil detector. `GetClipboardSequenceNumber` keeps the
// Win32 API casing per the FFI signature.
#![allow(dead_code, unused_variables, non_snake_case)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

lazy_static! {
    // Bitcoin: Legacy (1...), P2SH (3...), Bech32 (bc1...)
    static ref RE_BTC_ADDRESS: Regex = Regex::new(
        r"(?i)\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b"
    ).expect("BTC address regex is invalid");
    // Ethereum: 0x followed by 40 hex chars
    static ref RE_ETH_ADDRESS: Regex = Regex::new(
        r"(?i)\b0x[a-fA-F0-9]{40}\b"
    ).expect("ETH address regex is invalid");
    // Credit cards: Visa, Mastercard, Amex, Discover (with optional separators)
    static ref RE_CREDIT_CARD: Regex = Regex::new(
        r"\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b"
    ).expect("Credit card regex is invalid");
    // Generic API keys (32+ alphanumeric chars)
    static ref RE_API_KEY: Regex = Regex::new(
        r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)[=:\s]+['"]?([a-zA-Z0-9_-]{32,})['"]?"#
    ).expect("API key regex is invalid");
    // PEM private keys
    static ref RE_PRIVATE_KEY: Regex = Regex::new(
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    ).expect("Private key regex is invalid");
    // Password patterns
    static ref RE_PASSWORD_PATTERN: Regex = Regex::new(
        r#"(?i)(?:password|passwd|pwd|secret)[=:\s]+['"]?([^\s'"]{4,})['"]?"#
    ).expect("Password pattern regex is invalid");
    // AWS access key ID
    static ref RE_AWS_KEY: Regex = Regex::new(
        r"(?i)AKIA[0-9A-Z]{16}"
    ).expect("AWS key regex is invalid");
    // GitHub personal access token
    static ref RE_GITHUB_TOKEN: Regex = Regex::new(
        r#"(?i)ghp_[a-zA-Z0-9]{36}|github[_-]?token[=:\s]+['"]?([a-zA-Z0-9_-]{35,})['"]?"#
    ).expect("GitHub token regex is invalid");
    // SSH private keys
    static ref RE_SSH_KEY: Regex = Regex::new(
        r"-----BEGIN\s+(?:OPENSSH|DSA|EC|ENCRYPTED)?\s*PRIVATE\s+KEY-----"
    ).expect("SSH key regex is invalid");
    // JWT tokens
    static ref RE_JWT_TOKEN: Regex = Regex::new(
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
    ).expect("JWT token regex is invalid");
    // URLs with credentials
    static ref RE_URL_WITH_CREDS: Regex = Regex::new(
        r"(?i)https?://[^:@\s]+:[^@\s]+@[^\s]+"
    ).expect("URL with credentials regex is invalid");
}

/// Clipboard event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEvent {
    /// Process ID that accessed clipboard
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Type of clipboard access (read, write, clear)
    pub access_type: String,
    /// Data format (text, image, file, etc.)
    pub data_format: String,
    /// Size of clipboard data in bytes
    pub data_size: u64,
    /// Hash of clipboard content (for change detection)
    pub content_hash: String,
    /// Detected sensitive data types
    pub sensitive_data_types: Vec<String>,
    /// Whether hijacking was detected
    pub hijacking_detected: bool,
    /// Original value if hijacking detected
    pub original_value: Option<String>,
    /// Replaced value if hijacking detected
    pub replaced_value: Option<String>,
    /// Rapid access count (for clipbanker detection)
    pub rapid_access_count: u32,
}

/// Sensitive data patterns for detection
#[derive(Debug, Clone)]
pub struct SensitiveDataPatterns {
    /// Bitcoin addresses (legacy, segwit, bech32)
    btc_address: Regex,
    /// Ethereum addresses
    eth_address: Regex,
    /// Credit card numbers (Visa, Mastercard, Amex, etc.)
    credit_card: Regex,
    /// API keys / tokens (generic patterns)
    api_key: Regex,
    /// Private keys (PEM format)
    private_key: Regex,
    /// Password patterns (password=, pwd=, etc.)
    password_pattern: Regex,
    /// AWS access keys
    aws_key: Regex,
    /// GitHub tokens
    github_token: Regex,
    /// SSH private keys
    ssh_key: Regex,
    /// JWT tokens
    jwt_token: Regex,
    /// URLs with credentials
    url_with_creds: Regex,
}

impl Default for SensitiveDataPatterns {
    fn default() -> Self {
        Self {
            btc_address: RE_BTC_ADDRESS.clone(),
            eth_address: RE_ETH_ADDRESS.clone(),
            credit_card: RE_CREDIT_CARD.clone(),
            api_key: RE_API_KEY.clone(),
            private_key: RE_PRIVATE_KEY.clone(),
            password_pattern: RE_PASSWORD_PATTERN.clone(),
            aws_key: RE_AWS_KEY.clone(),
            github_token: RE_GITHUB_TOKEN.clone(),
            ssh_key: RE_SSH_KEY.clone(),
            jwt_token: RE_JWT_TOKEN.clone(),
            url_with_creds: RE_URL_WITH_CREDS.clone(),
        }
    }
}

impl SensitiveDataPatterns {
    /// Check clipboard content for sensitive data
    pub fn detect_sensitive_data(&self, content: &str) -> Vec<String> {
        let mut detected = Vec::new();

        if self.btc_address.is_match(content) {
            detected.push("bitcoin_address".to_string());
        }
        if self.eth_address.is_match(content) {
            detected.push("ethereum_address".to_string());
        }
        if self.credit_card.is_match(content) {
            detected.push("credit_card".to_string());
        }
        if self.api_key.is_match(content) {
            detected.push("api_key".to_string());
        }
        if self.private_key.is_match(content) {
            detected.push("private_key".to_string());
        }
        if self.password_pattern.is_match(content) {
            detected.push("password".to_string());
        }
        if self.aws_key.is_match(content) {
            detected.push("aws_access_key".to_string());
        }
        if self.github_token.is_match(content) {
            detected.push("github_token".to_string());
        }
        if self.ssh_key.is_match(content) {
            detected.push("ssh_private_key".to_string());
        }
        if self.jwt_token.is_match(content) {
            detected.push("jwt_token".to_string());
        }
        if self.url_with_creds.is_match(content) {
            detected.push("url_with_credentials".to_string());
        }

        detected
    }

    /// Extract crypto addresses from content for hijacking detection
    pub fn extract_crypto_addresses(&self, content: &str) -> Vec<(String, String)> {
        let mut addresses = Vec::new();

        for cap in self.btc_address.captures_iter(content) {
            if let Some(addr) = cap.get(1).or(cap.get(0)) {
                addresses.push(("bitcoin".to_string(), addr.as_str().to_string()));
            }
        }

        for cap in self.eth_address.captures_iter(content) {
            if let Some(addr) = cap.get(0) {
                addresses.push(("ethereum".to_string(), addr.as_str().to_string()));
            }
        }

        addresses
    }
}

/// Clipboard access tracking for rapid access detection
#[derive(Debug, Clone)]
struct ClipboardAccessTracker {
    /// Recent access times by PID
    access_history: HashMap<u32, VecDeque<Instant>>,
    /// Time window for rapid access detection (e.g., 5 seconds)
    window_duration: Duration,
    /// Threshold for rapid access (e.g., 10 accesses in window)
    rapid_threshold: u32,
}

impl ClipboardAccessTracker {
    fn new(window_seconds: u64, threshold: u32) -> Self {
        Self {
            access_history: HashMap::new(),
            window_duration: Duration::from_secs(window_seconds),
            rapid_threshold: threshold,
        }
    }

    /// Record an access and return the count within the window
    fn record_access(&mut self, pid: u32) -> u32 {
        let now = Instant::now();
        let history = self.access_history.entry(pid).or_insert_with(VecDeque::new);

        // Remove old entries
        while let Some(front) = history.front() {
            if now.duration_since(*front) > self.window_duration {
                history.pop_front();
            } else {
                break;
            }
        }

        // Add new entry
        history.push_back(now);

        history.len() as u32
    }

    /// Check if access pattern is suspicious (rapid access)
    fn is_rapid_access(&self, count: u32) -> bool {
        count >= self.rapid_threshold
    }

    /// Cleanup old tracking data
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.access_history.retain(|_, history| {
            if let Some(last) = history.back() {
                now.duration_since(*last) < self.window_duration * 2
            } else {
                false
            }
        });
    }
}

/// Clipboard hijacking detector
#[derive(Debug, Clone)]
struct HijackingDetector {
    /// Last known crypto addresses in clipboard
    last_crypto_addresses: Vec<(String, String)>,
    /// Last content hash
    last_content_hash: String,
    /// Patterns for detection
    patterns: SensitiveDataPatterns,
}

impl HijackingDetector {
    fn new() -> Self {
        Self {
            last_crypto_addresses: Vec::new(),
            last_content_hash: String::new(),
            patterns: SensitiveDataPatterns::default(),
        }
    }

    /// Check for hijacking when clipboard content changes
    /// Returns (is_hijacked, original_value, new_value)
    fn check_hijacking(
        &mut self,
        new_content: &str,
        new_hash: &str,
    ) -> (bool, Option<String>, Option<String>) {
        // If content hasn't changed, no hijacking
        if new_hash == self.last_content_hash {
            return (false, None, None);
        }

        // Extract new crypto addresses
        let new_addresses = self.patterns.extract_crypto_addresses(new_content);

        // Check if we had crypto addresses before and they were replaced
        if !self.last_crypto_addresses.is_empty() && !new_addresses.is_empty() {
            // Check if same type of address but different value (hijacking pattern)
            for (old_type, old_addr) in &self.last_crypto_addresses {
                for (new_type, new_addr) in &new_addresses {
                    if old_type == new_type && old_addr != new_addr {
                        // Same crypto type but different address - likely hijacking
                        let result = (true, Some(old_addr.clone()), Some(new_addr.clone()));

                        // Update state
                        self.last_crypto_addresses = new_addresses;
                        self.last_content_hash = new_hash.to_string();

                        return result;
                    }
                }
            }
        }

        // Update state
        self.last_crypto_addresses = new_addresses;
        self.last_content_hash = new_hash.to_string();

        (false, None, None)
    }
}

/// Clipboard collector
pub struct ClipboardCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl ClipboardCollector {
    /// Create a new clipboard collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::monitor_clipboard(tx, config_clone).await {
                error!(error = %e, "Clipboard collector error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    async fn monitor_clipboard(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
    ) -> anyhow::Result<()> {
        info!("Clipboard collector started");

        #[cfg(target_os = "windows")]
        return Self::monitor_clipboard_windows(tx, _config).await;

        #[cfg(target_os = "linux")]
        return Self::monitor_clipboard_linux(tx, _config).await;

        #[cfg(target_os = "macos")]
        return Self::monitor_clipboard_macos(tx, _config).await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            // STUB — PLATFORM-INCOMPLETE, not production. Implemented for Windows/Linux/macOS;
            // on any other target the collector warns once and produces no clipboard events.
            warn!("Clipboard monitoring not implemented for this platform");
            Ok(())
        }
    }

    /// Calculate hash of content for change detection
    fn hash_content(content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8]) // Use first 8 bytes for shorter hash
    }

    /// Create clipboard event
    fn create_clipboard_event(
        pid: u32,
        process_name: String,
        process_path: String,
        access_type: &str,
        data_format: &str,
        content: &str,
        sensitive_types: Vec<String>,
        hijacking: (bool, Option<String>, Option<String>),
        rapid_count: u32,
    ) -> TelemetryEvent {
        let content_hash = Self::hash_content(content);
        let data_size = content.len() as u64;

        // Determine severity based on findings
        let severity = if hijacking.0 {
            Severity::Critical
        } else if !sensitive_types.is_empty() {
            Severity::High
        } else if rapid_count > 5 {
            Severity::Medium
        } else if data_size > 1024 * 1024 {
            // > 1MB
            Severity::Medium
        } else {
            Severity::Low
        };

        let payload = ClipboardEvent {
            pid,
            process_name: process_name.clone(),
            process_path: process_path.clone(),
            access_type: access_type.to_string(),
            data_format: data_format.to_string(),
            data_size,
            content_hash,
            sensitive_data_types: sensitive_types.clone(),
            hijacking_detected: hijacking.0,
            original_value: hijacking.1.clone(),
            replaced_value: hijacking.2.clone(),
            rapid_access_count: rapid_count,
        };

        let mut event = TelemetryEvent::new(
            EventType::ClipboardAccess,
            severity,
            EventPayload::Custom(serde_json::to_value(&payload).unwrap_or_default()),
        );

        // Add metadata
        event
            .metadata
            .insert("event_category".to_string(), "clipboard".to_string());
        event.metadata.insert("pid".to_string(), pid.to_string());
        event
            .metadata
            .insert("process_name".to_string(), process_name.clone());

        // Add detections based on findings
        if hijacking.0 {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "clipboard_hijacking".to_string(),
                confidence: 0.95,
                description: format!(
                    "Clipboard hijacking detected: crypto address replaced from {} to {}",
                    hijacking.1.as_deref().unwrap_or("unknown"),
                    hijacking.2.as_deref().unwrap_or("unknown")
                ),
                mitre_tactics: vec!["collection".to_string(), "credential-access".to_string()],
                mitre_techniques: vec!["T1115".to_string()],
            });
        }

        if !sensitive_types.is_empty() {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "sensitive_clipboard_data".to_string(),
                confidence: 0.8,
                description: format!(
                    "Sensitive data detected in clipboard: {}",
                    sensitive_types.join(", ")
                ),
                mitre_tactics: vec!["collection".to_string()],
                mitre_techniques: vec!["T1115".to_string()],
            });
        }

        if rapid_count > 10 {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "clipbanker_behavior".to_string(),
                confidence: 0.7,
                description: format!(
                    "Rapid clipboard access detected: {} accesses in short window by {}",
                    rapid_count, process_name
                ),
                mitre_tactics: vec!["collection".to_string()],
                mitre_techniques: vec!["T1115".to_string()],
            });
        }

        if data_size > 1024 * 1024 {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "large_clipboard_data".to_string(),
                confidence: 0.5,
                description: format!(
                    "Large data ({} bytes) copied to clipboard - potential data exfiltration",
                    data_size
                ),
                mitre_tactics: vec!["exfiltration".to_string()],
                mitre_techniques: vec!["T1115".to_string()],
            });
        }

        event
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn monitor_clipboard_windows(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
    ) -> anyhow::Result<()> {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Windows clipboard collector");

        let patterns = SensitiveDataPatterns::default();
        let access_tracker = Arc::new(Mutex::new(ClipboardAccessTracker::new(5, 10)));
        let hijacking_detector = Arc::new(Mutex::new(HijackingDetector::new()));

        let mut last_sequence: u32 = 0;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            // Get current clipboard sequence number
            let current_sequence = Self::GetClipboardSequenceNumber();

            if current_sequence != last_sequence && last_sequence != 0 {
                // Clipboard changed
                debug!(
                    old_seq = last_sequence,
                    new_seq = current_sequence,
                    "Clipboard content changed"
                );

                // Try to get clipboard content
                if let Some((content, format)) = Self::get_clipboard_content_windows().await {
                    // Get the process that owns the clipboard
                    let (pid, process_name, process_path) =
                        Self::get_clipboard_owner_windows().await;

                    // Check for sensitive data
                    let sensitive_types = patterns.detect_sensitive_data(&content);

                    // Check for hijacking
                    let content_hash = Self::hash_content(&content);
                    let hijacking = {
                        let mut detector = hijacking_detector.lock().await;
                        detector.check_hijacking(&content, &content_hash)
                    };

                    // Track access
                    let rapid_count = {
                        let mut tracker = access_tracker.lock().await;
                        tracker.record_access(pid)
                    };

                    // Create event
                    let event = Self::create_clipboard_event(
                        pid,
                        process_name,
                        process_path,
                        "write",
                        &format,
                        &content,
                        sensitive_types,
                        hijacking,
                        rapid_count,
                    );

                    if tx.send(event).await.is_err() {
                        warn!("Clipboard event channel closed");
                        return Ok(());
                    }
                }
            }

            last_sequence = current_sequence;

            // Periodic cleanup
            if last_sequence % 100 == 0 {
                let mut tracker = access_tracker.lock().await;
                tracker.cleanup();
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn get_clipboard_content_windows() -> Option<(String, String)> {
        use windows::Win32::Foundation::{HANDLE, HWND};
        use windows::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
        };
        use windows::Win32::System::Memory::GlobalLock;
        use windows::Win32::System::Memory::GlobalUnlock;
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        // SAFETY: OpenClipboard and associated clipboard APIs must be called in sequence:
        // 1. OpenClipboard acquires exclusive access to the clipboard
        // 2. GetClipboardData and IsClipboardFormatAvailable operate on open clipboard
        // 3. CloseClipboard releases the lock (in the finally equivalent at scope end)
        // We ensure this by wrapping all clipboard operations in a single unsafe block
        // and calling CloseClipboard at the end. Windows guarantees these FFI calls are
        // thread-safe for the calling thread. The returned handle is valid only while
        // clipboard is open, which we maintain by keeping the scope tight.
        // Ref: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openclipboard
        unsafe {
            // Try to open clipboard
            if OpenClipboard(HWND::default()).is_err() {
                return None;
            }

            let result = if IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok() {
                if let Ok(handle) = GetClipboardData(CF_UNICODETEXT.0 as u32) {
                    let ptr = GlobalLock(std::mem::transmute::<
                        HANDLE,
                        windows::Win32::Foundation::HGLOBAL,
                    >(handle));
                    if !ptr.is_null() {
                        // Read UTF-16 string
                        let mut len = 0usize;
                        let wide_ptr = ptr as *const u16;
                        while *wide_ptr.add(len) != 0 && len < 1024 * 1024 {
                            len += 1;
                        }

                        let slice = std::slice::from_raw_parts(wide_ptr, len);
                        let content = String::from_utf16_lossy(slice);

                        let _ = GlobalUnlock(std::mem::transmute::<
                            HANDLE,
                            windows::Win32::Foundation::HGLOBAL,
                        >(handle));
                        Some((content, "text/unicode".to_string()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                // Could check for other formats (CF_TEXT, CF_HDROP for files, etc.)
                None
            };

            let _ = CloseClipboard();
            result
        }
    }

    #[cfg(target_os = "windows")]
    async fn get_clipboard_owner_windows() -> (u32, String, String) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::DataExchange::GetClipboardOwner;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };
        use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

        // SAFETY: GetClipboardOwner returns the HWND of the window that owns the clipboard.
        // This is always safe to call and returns NULL if clipboard is not owned by any window.
        // GetWindowThreadProcessId extracts the process ID from a valid HWND.
        // The returned HWND is valid for the lifetime of the owning window, and we immediately
        // extract the PID, which is immutable. No data races possible since we're only reading.
        // Ref: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboardowner
        unsafe {
            let hwnd = GetClipboardOwner();
            if hwnd.0 as isize == 0 {
                return (0, "unknown".to_string(), String::new());
            }

            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));

            if pid == 0 {
                return (0, "unknown".to_string(), String::new());
            }

            let handle = match OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return (pid, format!("pid:{}", pid), String::new()),
            };

            let mut name_buf = [0u16; 512];
            let len = GetModuleFileNameExW(handle, None, &mut name_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                let path = String::from_utf16_lossy(&name_buf[..len as usize]);
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("pid:{}", pid));
                (pid, name, path)
            } else {
                (pid, format!("pid:{}", pid), String::new())
            }
        }
    }

    // Windows-specific clipboard API
    #[cfg(target_os = "windows")]
    fn GetClipboardSequenceNumber() -> u32 {
        // This is a C API function
        #[link(name = "user32")]
        extern "system" {
            fn GetClipboardSequenceNumber() -> u32;
        }
        // SAFETY: GetClipboardSequenceNumber is a simple synchronous FFI call that returns
        // the current clipboard change count. It takes no parameters and is pure, so calling it
        // multiple times is safe. Returns a u32 monotonically increasing value whenever clipboard
        // contents change. No data races possible since Windows maintains this atomically.
        // Ref: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboardsequencenumber
        unsafe { GetClipboardSequenceNumber() }
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn monitor_clipboard_linux(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
    ) -> anyhow::Result<()> {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Linux clipboard collector");

        let patterns = SensitiveDataPatterns::default();
        let access_tracker = Arc::new(Mutex::new(ClipboardAccessTracker::new(5, 10)));
        let hijacking_detector = Arc::new(Mutex::new(HijackingDetector::new()));

        let mut last_hash = String::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        // Detect display server
        let display_server = Self::detect_display_server_linux();
        info!(display = %display_server, "Detected display server");

        loop {
            interval.tick().await;

            // Get clipboard content based on display server
            let content = match display_server.as_str() {
                "wayland" => Self::get_clipboard_wayland().await,
                "x11" => Self::get_clipboard_x11().await,
                _ => None,
            };

            if let Some((content, format)) = content {
                let current_hash = Self::hash_content(&content);

                if current_hash != last_hash {
                    debug!(
                        old_hash = %last_hash,
                        new_hash = %current_hash,
                        "Clipboard content changed"
                    );

                    // Try to find the process that accessed clipboard
                    let (pid, process_name, process_path) =
                        Self::find_clipboard_accessor_linux().await;

                    // Check for sensitive data
                    let sensitive_types = patterns.detect_sensitive_data(&content);

                    // Check for hijacking
                    let hijacking = {
                        let mut detector = hijacking_detector.lock().await;
                        detector.check_hijacking(&content, &current_hash)
                    };

                    // Track access
                    let rapid_count = {
                        let mut tracker = access_tracker.lock().await;
                        tracker.record_access(pid)
                    };

                    // Create event
                    let event = Self::create_clipboard_event(
                        pid,
                        process_name,
                        process_path,
                        "write",
                        &format,
                        &content,
                        sensitive_types,
                        hijacking,
                        rapid_count,
                    );

                    if tx.send(event).await.is_err() {
                        warn!("Clipboard event channel closed");
                        return Ok(());
                    }

                    last_hash = current_hash;
                }
            }

            // Periodic cleanup
            static mut COUNTER: u32 = 0;
            // SAFETY: This unsafe block accesses a thread-local static counter in Windows
            // clipboard monitoring loop. The counter is used only for triggering periodic cleanup
            // (every 100 iterations). Even if incremented by multiple concurrent iterations, the
            // worst case is a few extra cleanups, which is safe. The counter is never read for
            // correctness, only for triggering cleanup. The actual cleanup (access_tracker) is
            // protected by mutex. This is a performance counter, not a correctness counter.
            unsafe {
                COUNTER += 1;
                if COUNTER % 100 == 0 {
                    let mut tracker = access_tracker.lock().await;
                    tracker.cleanup();
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_display_server_linux() -> String {
        // Check for Wayland
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            return "wayland".to_string();
        }

        // Check for X11
        if std::env::var("DISPLAY").is_ok() {
            return "x11".to_string();
        }

        // Check XDG_SESSION_TYPE
        if let Ok(session_type) = std::env::var("XDG_SESSION_TYPE") {
            return session_type.to_lowercase();
        }

        "unknown".to_string()
    }

    #[cfg(target_os = "linux")]
    async fn get_clipboard_x11() -> Option<(String, String)> {
        use std::process::Command;

        // Try xclip first
        let output = Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                return Some((
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    "text/plain".to_string(),
                ));
            }
        }

        // Try xsel as fallback
        let output = Command::new("xsel")
            .args(["--clipboard", "--output"])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                return Some((
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    "text/plain".to_string(),
                ));
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    async fn get_clipboard_wayland() -> Option<(String, String)> {
        use std::process::Command;

        // Try wl-paste
        let output = Command::new("wl-paste").args(["--no-newline"]).output();

        if let Ok(out) = output {
            if out.status.success() {
                return Some((
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    "text/plain".to_string(),
                ));
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    async fn find_clipboard_accessor_linux() -> (u32, String, String) {
        use std::fs;

        // Look for processes with clipboard-related connections
        // This is a heuristic approach since Linux doesn't have direct clipboard ownership

        // Check for processes with X11 connections (using lsof on clipboard sockets)
        let xsel_processes = ["xclip", "xsel", "wl-copy", "wl-paste", "xdotool"];

        // Scan /proc for recent processes that might have accessed clipboard
        if let Ok(proc_dir) = fs::read_dir("/proc") {
            for entry in proc_dir.filter_map(|e| e.ok()) {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let comm_path = format!("/proc/{}/comm", pid);
                    if let Ok(comm) = fs::read_to_string(&comm_path) {
                        let name = comm.trim();
                        // Check if this is a clipboard utility or recently active process
                        if xsel_processes.iter().any(|p| name.contains(p)) {
                            let exe_path = format!("/proc/{}/exe", pid);
                            let path = fs::read_link(&exe_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            return (pid, name.to_string(), path);
                        }
                    }
                }
            }
        }

        // Fallback: return unknown
        (0, "unknown".to_string(), String::new())
    }

    // ==================== macOS Implementation ====================
    #[cfg(target_os = "macos")]
    async fn monitor_clipboard_macos(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
    ) -> anyhow::Result<()> {
        use std::process::Command;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting macOS clipboard collector");

        let patterns = SensitiveDataPatterns::default();
        let access_tracker = Arc::new(Mutex::new(ClipboardAccessTracker::new(5, 10)));
        let hijacking_detector = Arc::new(Mutex::new(HijackingDetector::new()));

        let mut last_change_count: i64 = -1;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            // Get pasteboard change count using pbpaste approach or AppleScript
            let current_change_count = Self::get_pasteboard_change_count_macos().await;

            if current_change_count != last_change_count && last_change_count != -1 {
                debug!(
                    old_count = last_change_count,
                    new_count = current_change_count,
                    "Pasteboard content changed"
                );

                // Get clipboard content
                if let Some((content, format)) = Self::get_clipboard_content_macos().await {
                    // Try to find the frontmost app
                    let (pid, process_name, process_path) = Self::get_frontmost_app_macos().await;

                    // Check for sensitive data
                    let sensitive_types = patterns.detect_sensitive_data(&content);

                    // Check for hijacking
                    let content_hash = Self::hash_content(&content);
                    let hijacking = {
                        let mut detector = hijacking_detector.lock().await;
                        detector.check_hijacking(&content, &content_hash)
                    };

                    // Track access
                    let rapid_count = {
                        let mut tracker = access_tracker.lock().await;
                        tracker.record_access(pid)
                    };

                    // Create event
                    let event = Self::create_clipboard_event(
                        pid,
                        process_name,
                        process_path,
                        "write",
                        &format,
                        &content,
                        sensitive_types,
                        hijacking,
                        rapid_count,
                    );

                    if tx.send(event).await.is_err() {
                        warn!("Clipboard event channel closed");
                        return Ok(());
                    }
                }
            }

            last_change_count = current_change_count;

            // Periodic cleanup
            static mut COUNTER: u32 = 0;
            // SAFETY: This unsafe block accesses a thread-local static counter in Linux
            // clipboard monitoring loop. The counter is used only for triggering periodic cleanup
            // (every 100 iterations). Even if incremented by multiple concurrent iterations, the
            // worst case is a few extra cleanups, which is safe. The counter is never read for
            // correctness, only for triggering cleanup. The actual cleanup (access_tracker) is
            // protected by mutex. This is a performance counter, not a correctness counter.
            unsafe {
                COUNTER += 1;
                if COUNTER % 100 == 0 {
                    let mut tracker = access_tracker.lock().await;
                    tracker.cleanup();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn get_pasteboard_change_count_macos() -> i64 {
        use std::process::Command;

        // Use osascript to get change count
        let output = Command::new("osascript")
            .args([
                "-e",
                "tell application \"System Events\" to return (the clipboard info)",
            ])
            .output();

        // Fallback: just check if content changed via hash
        // The change count approach requires native API access
        // For now, use a simple counter based on content changes
        static mut COUNTER: i64 = 0;

        if let Ok(out) = output {
            if out.status.success() {
                // SAFETY: macOS pasteboard change counter. The static mutable COUNTER tracks
                // how many times the pasteboard has been accessed/changed via osascript.
                // It's a simple i64 counter with no synchronization because: (1) it's only
                // accessed from a single async task, (2) it's only for tracking change count
                // which is inherently racy anyway (we might miss fast changes), and (3)
                // even if multiple threads access it, an i64 increment is usually atomic on modern
                // platforms. This is a best-effort change detector for macOS.
                unsafe {
                    COUNTER += 1;
                    return COUNTER;
                }
            }
        }

        // SAFETY: Same as above - reading the change counter which is unsynchronized but
        // acceptable for this best-effort change detection implementation.
        unsafe { COUNTER }
    }

    #[cfg(target_os = "macos")]
    async fn get_clipboard_content_macos() -> Option<(String, String)> {
        use std::process::Command;

        // Use pbpaste to get clipboard content
        let output = Command::new("pbpaste").output();

        if let Ok(out) = output {
            if out.status.success() {
                return Some((
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    "text/plain".to_string(),
                ));
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    async fn get_frontmost_app_macos() -> (u32, String, String) {
        use std::process::Command;

        // Use osascript to get frontmost application
        let output = Command::new("osascript")
            .args([
                "-e",
                "tell application \"System Events\" to get name of first process whose frontmost is true",
            ])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let name = String::from_utf8_lossy(&out.stdout).trim().to_string();

                // Try to get PID using pgrep
                let pid_output = Command::new("pgrep").args(["-x", &name]).output();

                let pid = pid_output
                    .ok()
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .trim()
                            .lines()
                            .next()
                            .and_then(|s| s.parse().ok())
                    })
                    .unwrap_or(0);

                // Get process path
                let path_output = Command::new("ps")
                    .args(["-p", &pid.to_string(), "-o", "comm="])
                    .output();

                let path = path_output
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();

                return (pid, name, path);
            }
        }

        (0, "unknown".to_string(), String::new())
    }
}

// Add ClipboardAccess to EventType enum - this needs to be done in mod.rs
// For now, we use Custom payload

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_data_detection() {
        let patterns = SensitiveDataPatterns::default();

        // Test Bitcoin address detection
        let btc_content = "Send payment to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let detected = patterns.detect_sensitive_data(btc_content);
        assert!(detected.contains(&"bitcoin_address".to_string()));

        // Test Ethereum address detection
        let eth_content = "ETH address: 0x742d35Cc6634C0532925a3b844Bc9e7595f1Db38";
        let detected = patterns.detect_sensitive_data(eth_content);
        assert!(detected.contains(&"ethereum_address".to_string()));

        // Test credit card detection
        let cc_content = "Card: 4111-1111-1111-1111";
        let detected = patterns.detect_sensitive_data(cc_content);
        assert!(detected.contains(&"credit_card".to_string()));

        // Test API key detection
        let api_content = "api_key=sk_live_1234567890abcdefghijklmnopqrstuvwxyz";
        let detected = patterns.detect_sensitive_data(api_content);
        assert!(detected.contains(&"api_key".to_string()));

        // Test AWS key detection
        let aws_content = "Access Key: AKIAIOSFODNN7EXAMPLE";
        let detected = patterns.detect_sensitive_data(aws_content);
        assert!(detected.contains(&"aws_access_key".to_string()));

        // Test private key detection
        let pem_content = "-----BEGIN PRIVATE KEY-----\nMIIE...";
        let detected = patterns.detect_sensitive_data(pem_content);
        assert!(detected.contains(&"private_key".to_string()));

        // Test JWT detection
        let jwt_content =
            "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let detected = patterns.detect_sensitive_data(jwt_content);
        assert!(detected.contains(&"jwt_token".to_string()));
    }

    #[test]
    fn test_crypto_address_extraction() {
        let patterns = SensitiveDataPatterns::default();

        let content =
            "BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f1Db38";
        let addresses = patterns.extract_crypto_addresses(content);

        assert!(addresses.iter().any(|(t, _)| t == "bitcoin"));
        assert!(addresses.iter().any(|(t, _)| t == "ethereum"));
    }

    #[test]
    fn test_rapid_access_tracker() {
        let mut tracker = ClipboardAccessTracker::new(5, 5);

        // Simulate rapid access
        for _ in 0..6 {
            tracker.record_access(1234);
        }

        let count = tracker.record_access(1234);
        assert!(tracker.is_rapid_access(count));
    }

    #[test]
    fn test_hijacking_detection() {
        let mut detector = HijackingDetector::new();

        // First clipboard content with BTC address
        let content1 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let hash1 = ClipboardCollector::hash_content(content1);
        let (hijacked, _, _) = detector.check_hijacking(content1, &hash1);
        assert!(!hijacked);

        // Second clipboard content with different BTC address (hijacking)
        let content2 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let hash2 = ClipboardCollector::hash_content(content2);
        let (hijacked, original, replaced) = detector.check_hijacking(content2, &hash2);
        assert!(hijacked);
        assert!(original.is_some());
        assert!(replaced.is_some());
    }

    #[test]
    fn test_content_hash() {
        let content = "test content";
        let hash = ClipboardCollector::hash_content(content);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 16); // 8 bytes = 16 hex chars

        // Same content should produce same hash
        let hash2 = ClipboardCollector::hash_content(content);
        assert_eq!(hash, hash2);

        // Different content should produce different hash
        let hash3 = ClipboardCollector::hash_content("different content");
        assert_ne!(hash, hash3);
    }
}
