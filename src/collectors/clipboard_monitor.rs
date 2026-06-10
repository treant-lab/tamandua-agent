//! DLP-Aware Clipboard Monitor
//!
//! Extends the base clipboard collector with content-aware DLP scanning.
//! Monitors clipboard content changes and runs the DLP classification engine
//! to detect sensitive data being copied to the clipboard.
//!
//! This collector integrates the DLP content classifier from `dlp.rs` with
//! clipboard monitoring to detect:
//! - PII (SSN, credit cards, etc.) copied to clipboard
//! - Credentials (AWS keys, SSH keys, JWT tokens) in clipboard
//! - Regulated data (HIPAA, PCI) in clipboard
//! - Source code secrets (private keys, passwords) in clipboard
//!
//! Emits `DlpClipboard` events with content hash, classifications, and source process.
//!
//! MITRE ATT&CK: T1115 (Clipboard Data), T1567 (Exfiltration Over Web Service)

use super::dlp::{ContentClassifier, ContentMatch};
use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Clipboard DLP Event
// ============================================================================

/// DLP clipboard event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpClipboardEvent {
    /// SHA-256 hash of the clipboard content.
    pub content_hash: String,
    /// Size of clipboard content in bytes.
    pub content_size: u64,
    /// DLP classifications found in clipboard content.
    pub classifications: Vec<ContentMatch>,
    /// Process that set the clipboard content.
    pub source_process: String,
    /// Source process ID.
    pub source_pid: u32,
    /// Source process path.
    pub source_process_path: String,
    /// Username.
    pub user: String,
    /// Distinct classifier types matched.
    pub distinct_classifier_count: usize,
    /// Highest confidence score.
    pub max_confidence: f32,
    /// Categories of sensitive data found.
    pub categories_found: Vec<String>,
    /// DLP action taken.
    pub action_taken: String,
}

// ============================================================================
// Clipboard DLP Collector
// ============================================================================

/// DLP-aware clipboard monitor. Monitors clipboard changes and scans content
/// through the DLP classification engine.
pub struct ClipboardDlpCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl ClipboardDlpCollector {
    /// Create a new clipboard DLP collector.
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::run_monitor(tx, config_clone).await {
                error!(error = %e, "Clipboard DLP collector error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    /// Get the next DLP clipboard event.
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Main clipboard monitoring loop with DLP scanning.
    async fn run_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
    ) -> anyhow::Result<()> {
        info!("Clipboard DLP collector started");

        let classifier = ContentClassifier::new(&config.dlp);
        let mut last_content_hash = String::new();
        let mut interval = tokio::time::interval(Duration::from_millis(750));
        let mut scan_count: u64 = 0;

        loop {
            interval.tick().await;

            // Get clipboard content (platform-specific)
            let content = Self::get_clipboard_text().await;

            if let Some(text) = content {
                // Skip empty or very short content
                if text.len() < 5 {
                    continue;
                }

                // Check if content changed
                let hash = Self::hash_content(&text);
                if hash == last_content_hash {
                    continue;
                }
                last_content_hash = hash.clone();
                scan_count += 1;

                // Run DLP classifiers on clipboard content
                let matches = classifier.classify(&text);

                if !matches.is_empty() {
                    let (pid, process_name, process_path) =
                        Self::get_clipboard_source_process().await;
                    let user = whoami::username();

                    let distinct_types: std::collections::HashSet<_> =
                        matches.iter().map(|m| &m.classifier_type).collect();
                    let categories: std::collections::HashSet<_> = matches
                        .iter()
                        .map(|m| format!("{:?}", m.category))
                        .collect();
                    let max_confidence =
                        matches.iter().map(|m| m.confidence).fold(0.0f32, f32::max);

                    info!(
                        matches = matches.len(),
                        classifiers = distinct_types.len(),
                        max_confidence = max_confidence,
                        source_process = %process_name,
                        "DLP: sensitive data detected in clipboard"
                    );

                    let dlp_clipboard = DlpClipboardEvent {
                        content_hash: hash,
                        content_size: text.len() as u64,
                        classifications: matches.clone(),
                        source_process: process_name.clone(),
                        source_pid: pid,
                        source_process_path: process_path,
                        user,
                        distinct_classifier_count: distinct_types.len(),
                        max_confidence,
                        categories_found: categories.into_iter().collect(),
                        action_taken: config.dlp.action_on_detection.clone(),
                    };

                    let event = Self::create_event(dlp_clipboard, &matches);

                    if tx.send(event).await.is_err() {
                        warn!("Clipboard DLP event channel closed");
                        return Ok(());
                    }
                }

                // Periodic log
                if scan_count % 1000 == 0 {
                    debug!(scan_count, "Clipboard DLP collector health check");
                }
            }
        }
    }

    /// Hash clipboard content for change detection.
    fn hash_content(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }

    /// Create a telemetry event from a DLP clipboard detection.
    fn create_event(dlp_clipboard: DlpClipboardEvent, matches: &[ContentMatch]) -> TelemetryEvent {
        let severity = if dlp_clipboard.max_confidence >= 0.90 {
            Severity::Critical
        } else if dlp_clipboard.max_confidence >= 0.75 {
            Severity::High
        } else if dlp_clipboard.max_confidence >= 0.50 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut event = TelemetryEvent::new(
            EventType::ClipboardAccess,
            severity,
            EventPayload::Custom(serde_json::to_value(&dlp_clipboard).unwrap_or_default()),
        );

        event
            .metadata
            .insert("event_category".to_string(), "dlp_clipboard".to_string());
        event
            .metadata
            .insert("pid".to_string(), dlp_clipboard.source_pid.to_string());
        event.metadata.insert(
            "process_name".to_string(),
            dlp_clipboard.source_process.clone(),
        );
        event
            .metadata
            .insert("dlp_action".to_string(), dlp_clipboard.action_taken.clone());

        // Add detections per category
        let categories: std::collections::HashSet<_> =
            matches.iter().map(|m| &m.category).collect();

        for category in categories {
            let cat_matches: Vec<_> = matches.iter().filter(|m| &m.category == category).collect();
            let classifier_types: Vec<_> = cat_matches
                .iter()
                .map(|m| format!("{:?}", m.classifier_type))
                .collect();

            event.add_detection(Detection {
                detection_type: DetectionType::ClipboardCapture,
                rule_name: format!("dlp_clipboard_{:?}", category).to_lowercase(),
                confidence: cat_matches
                    .iter()
                    .map(|m| m.confidence)
                    .fold(0.0f32, f32::max),
                description: format!(
                    "DLP: {:?} data detected in clipboard from process {} (types: {})",
                    category,
                    dlp_clipboard.source_process,
                    classifier_types.join(", "),
                ),
                mitre_tactics: vec!["collection".to_string(), "exfiltration".to_string()],
                mitre_techniques: vec!["T1115".to_string()],
            });
        }

        event
    }

    // ========================================================================
    // Platform-Specific Clipboard Access
    // ========================================================================

    /// Get clipboard text content (platform-specific).
    async fn get_clipboard_text() -> Option<String> {
        #[cfg(target_os = "windows")]
        return Self::get_clipboard_windows().await;

        #[cfg(target_os = "linux")]
        return Self::get_clipboard_linux().await;

        #[cfg(target_os = "macos")]
        return Self::get_clipboard_macos().await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }

    /// Windows clipboard access via Win32 API.
    #[cfg(target_os = "windows")]
    async fn get_clipboard_windows() -> Option<String> {
        use windows::Win32::Foundation::{HANDLE, HWND};
        use windows::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
        };
        use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        // Use a static sequence counter to avoid re-scanning unchanged clipboard
        static LAST_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

        #[link(name = "user32")]
        extern "system" {
            fn GetClipboardSequenceNumber() -> u32;
        }

        let current_seq = unsafe { GetClipboardSequenceNumber() };
        let prev_seq = LAST_SEQ.swap(current_seq, std::sync::atomic::Ordering::Relaxed);
        if current_seq == prev_seq {
            return None;
        }

        unsafe {
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
                        let mut len = 0usize;
                        let wide_ptr = ptr as *const u16;
                        // Limit to 1MB of text
                        while *wide_ptr.add(len) != 0 && len < 512 * 1024 {
                            len += 1;
                        }
                        let slice = std::slice::from_raw_parts(wide_ptr, len);
                        let content = String::from_utf16_lossy(slice);
                        let _ = GlobalUnlock(std::mem::transmute::<
                            HANDLE,
                            windows::Win32::Foundation::HGLOBAL,
                        >(handle));
                        Some(content)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let _ = CloseClipboard();
            result
        }
    }

    /// Linux clipboard access via xclip/xsel/wl-paste.
    #[cfg(target_os = "linux")]
    async fn get_clipboard_linux() -> Option<String> {
        use std::process::Command;

        // Try wl-paste first (Wayland)
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            if let Ok(out) = Command::new("wl-paste").args(["--no-newline"]).output() {
                if out.status.success() {
                    let content = String::from_utf8_lossy(&out.stdout).to_string();
                    if !content.is_empty() {
                        return Some(content);
                    }
                }
            }
        }

        // Try xclip (X11)
        if let Ok(out) = Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output()
        {
            if out.status.success() {
                let content = String::from_utf8_lossy(&out.stdout).to_string();
                if !content.is_empty() {
                    return Some(content);
                }
            }
        }

        // Try xsel as fallback
        if let Ok(out) = Command::new("xsel")
            .args(["--clipboard", "--output"])
            .output()
        {
            if out.status.success() {
                let content = String::from_utf8_lossy(&out.stdout).to_string();
                if !content.is_empty() {
                    return Some(content);
                }
            }
        }

        None
    }

    /// macOS clipboard access via pbpaste.
    #[cfg(target_os = "macos")]
    async fn get_clipboard_macos() -> Option<String> {
        use std::process::Command;

        if let Ok(out) = Command::new("pbpaste").output() {
            if out.status.success() {
                let content = String::from_utf8_lossy(&out.stdout).to_string();
                if !content.is_empty() {
                    return Some(content);
                }
            }
        }

        None
    }

    // ========================================================================
    // Platform-Specific Process Information
    // ========================================================================

    /// Get the process that last set the clipboard content.
    async fn get_clipboard_source_process() -> (u32, String, String) {
        #[cfg(target_os = "windows")]
        return Self::get_clipboard_owner_windows().await;

        #[cfg(target_os = "linux")]
        return Self::get_clipboard_owner_linux().await;

        #[cfg(target_os = "macos")]
        return Self::get_clipboard_owner_macos().await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            (0, "unknown".to_string(), String::new())
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

    #[cfg(target_os = "linux")]
    async fn get_clipboard_owner_linux() -> (u32, String, String) {
        // On Linux there is no direct clipboard ownership API.
        // Use heuristic: find the focused X11 window owner.
        use std::process::Command;

        if let Ok(out) = Command::new("xdotool")
            .args(["getactivewindow", "getwindowpid"])
            .output()
        {
            if out.status.success() {
                if let Ok(pid) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>() {
                    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                        .unwrap_or_else(|_| "unknown".to_string());
                    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    return (pid, comm.trim().to_string(), exe);
                }
            }
        }

        (0, "unknown".to_string(), String::new())
    }

    #[cfg(target_os = "macos")]
    async fn get_clipboard_owner_macos() -> (u32, String, String) {
        use std::process::Command;

        if let Ok(out) = Command::new("osascript")
            .args([
                "-e",
                "tell application \"System Events\" to get name of first process whose frontmost is true",
            ])
            .output()
        {
            if out.status.success() {
                let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let pid_out = Command::new("pgrep")
                    .args(["-x", &name])
                    .output();
                let pid = pid_out
                    .ok()
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .trim()
                            .lines()
                            .next()
                            .and_then(|s| s.parse().ok())
                    })
                    .unwrap_or(0u32);
                return (pid, name, String::new());
            }
        }

        (0, "unknown".to_string(), String::new())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::dlp::{ContentClassifier, DlpConfig};
    use super::*;

    #[test]
    fn test_clipboard_hash() {
        let hash1 = ClipboardDlpCollector::hash_content("test content");
        let hash2 = ClipboardDlpCollector::hash_content("test content");
        assert_eq!(hash1, hash2);

        let hash3 = ClipboardDlpCollector::hash_content("different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_create_event_severity() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);

        // High confidence match (AWS key = 0.95)
        let text = "AKIAIOSFODNN7EXAMPLE";
        let matches = classifier.classify(text);
        assert!(!matches.is_empty());

        let dlp_clipboard = DlpClipboardEvent {
            content_hash: "abc123".to_string(),
            content_size: text.len() as u64,
            classifications: matches.clone(),
            source_process: "notepad.exe".to_string(),
            source_pid: 1234,
            source_process_path: "C:\\Windows\\notepad.exe".to_string(),
            user: "testuser".to_string(),
            distinct_classifier_count: 1,
            max_confidence: 0.95,
            categories_found: vec!["Credentials".to_string()],
            action_taken: "log".to_string(),
        };

        let event = ClipboardDlpCollector::create_event(dlp_clipboard, &matches);
        assert_eq!(event.severity, Severity::Critical);
        assert!(event.metadata.get("event_category").unwrap() == "dlp_clipboard");
    }

    #[test]
    fn test_create_event_detections() {
        let config = DlpConfig::default();
        let classifier = ContentClassifier::new(&config);

        let text = "SSN: 123-45-6789 Key: AKIAIOSFODNN7EXAMPLE";
        let matches = classifier.classify(text);

        let dlp_clipboard = DlpClipboardEvent {
            content_hash: "abc123".to_string(),
            content_size: text.len() as u64,
            classifications: matches.clone(),
            source_process: "chrome.exe".to_string(),
            source_pid: 5678,
            source_process_path: "C:\\chrome.exe".to_string(),
            user: "testuser".to_string(),
            distinct_classifier_count: 2,
            max_confidence: 0.95,
            categories_found: vec!["Pii".to_string(), "Credentials".to_string()],
            action_taken: "log".to_string(),
        };

        let event = ClipboardDlpCollector::create_event(dlp_clipboard, &matches);
        // Should have detections for both PII and Credentials categories
        assert!(event.detections.len() >= 2);
    }
}
