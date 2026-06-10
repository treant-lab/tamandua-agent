//! Memory string extraction
//!
//! Extract ASCII/Unicode strings from process memory with pattern matching

use super::{ExtractedString, MemoryRegion, StringType};
use anyhow::Result;
use regex::Regex;
use tracing::info;

/// Extract strings from memory regions
pub async fn extract_strings(
    pid: u32,
    regions: Vec<MemoryRegion>,
    min_length: usize,
) -> Result<Vec<ExtractedString>> {
    let mut strings = Vec::new();

    // Compile regex patterns once
    let url_regex = Regex::new(r#"https?://[^\s<>"]+|ftp://[^\s<>"]+"#).unwrap();
    let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let path_regex =
        Regex::new(r#"[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#).unwrap();
    let registry_regex = Regex::new(r"(?i)HKEY_[A-Z_]+\\[^\r\n]+").unwrap();
    let base64_regex = Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap();

    for region in regions {
        // Skip very large regions (> 10MB) for performance
        if region.size > 10 * 1024 * 1024 {
            continue;
        }

        // Read region
        let data = match read_memory_region(pid, &region).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Extract ASCII strings
        let ascii_strings = extract_ascii_strings(&data, min_length);
        for (offset, content) in ascii_strings {
            let string_type = classify_string(
                &content,
                &url_regex,
                &ip_regex,
                &path_regex,
                &registry_regex,
                &base64_regex,
            );
            let relevance = calculate_relevance(&content, string_type);

            strings.push(ExtractedString {
                content,
                string_type,
                address: region.base_address + offset as u64,
                region: region.clone(),
                relevance,
            });
        }

        // Extract Unicode strings
        let unicode_strings = extract_unicode_strings(&data, min_length);
        for (offset, content) in unicode_strings {
            let string_type = classify_string(
                &content,
                &url_regex,
                &ip_regex,
                &path_regex,
                &registry_regex,
                &base64_regex,
            );
            let relevance = calculate_relevance(&content, string_type);

            strings.push(ExtractedString {
                content,
                string_type,
                address: region.base_address + offset as u64,
                region: region.clone(),
                relevance,
            });
        }
    }

    info!(
        pid = pid,
        strings = strings.len(),
        "String extraction completed"
    );

    Ok(strings)
}

/// Extract ASCII strings from memory
fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= min_length {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push((start_offset, s));
                }
            }
            current_string.clear();
        }
    }

    // Don't forget the last string if buffer ends with printable chars
    if current_string.len() >= min_length {
        if let Ok(s) = String::from_utf8(current_string) {
            strings.push((start_offset, s));
        }
    }

    strings
}

/// Extract Unicode (UTF-16LE) strings from memory
fn extract_unicode_strings(data: &[u8], min_length: usize) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        if is_printable_unicode(word) {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(word);
        } else {
            if current_string.len() >= min_length {
                let s = String::from_utf16_lossy(&current_string);
                strings.push((start_offset, s));
            }
            current_string.clear();
        }

        i += 2;
    }

    // Last string
    if current_string.len() >= min_length {
        let s = String::from_utf16_lossy(&current_string);
        strings.push((start_offset, s));
    }

    strings
}

/// Check if byte is printable ASCII
fn is_printable_ascii(byte: u8) -> bool {
    (32..=126).contains(&byte) || byte == b'\t' || byte == b'\r' || byte == b'\n'
}

/// Check if Unicode code point is printable
fn is_printable_unicode(word: u16) -> bool {
    matches!(word, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

/// Classify string type
fn classify_string(
    content: &str,
    url_regex: &Regex,
    ip_regex: &Regex,
    path_regex: &Regex,
    registry_regex: &Regex,
    base64_regex: &Regex,
) -> StringType {
    // Check URL first (most specific)
    if url_regex.is_match(content) {
        return StringType::Url;
    }

    // Check IP address
    if ip_regex.is_match(content) {
        return StringType::IpAddress;
    }

    // Check file path
    if path_regex.is_match(content) {
        return StringType::FilePath;
    }

    // Check registry key
    if registry_regex.is_match(content) {
        return StringType::RegistryKey;
    }

    // Check Base64 (must be long enough to avoid false positives)
    if content.len() >= 20 && base64_regex.is_match(content) {
        return StringType::Base64;
    }

    // Check if Unicode
    if content.chars().any(|c| c as u32 > 127) {
        return StringType::Unicode;
    }

    StringType::Ascii
}

/// Calculate string relevance score
fn calculate_relevance(content: &str, string_type: StringType) -> f32 {
    let mut score = 0.0f32;

    // Base score by type
    score += match string_type {
        StringType::Url => 0.9,
        StringType::IpAddress => 0.8,
        StringType::FilePath => 0.7,
        StringType::RegistryKey => 0.7,
        StringType::Base64 => 0.6,
        StringType::Unicode => 0.4,
        StringType::Ascii => 0.3,
    };

    // Length bonus (longer strings are more interesting, up to a point)
    let length_score = (content.len() as f32 / 100.0).min(0.3);
    score += length_score;

    // Content-based scoring
    let lower = content.to_lowercase();

    // Suspicious keywords
    let suspicious_keywords = [
        "password",
        "pwd",
        "pass",
        "token",
        "key",
        "secret",
        "api",
        "credential",
        "auth",
        "admin",
        "root",
        "cmd",
        "powershell",
        "exec",
        "shell",
        "inject",
        "exploit",
        "payload",
        "beacon",
        "malware",
        "ransomware",
        "backdoor",
        "trojan",
        "virus",
    ];

    for keyword in &suspicious_keywords {
        if lower.contains(keyword) {
            score += 0.2;
            break;
        }
    }

    // Command-line indicators
    if lower.contains("-exec") || lower.contains("/c ") || lower.contains("cmd.exe") {
        score += 0.15;
    }

    // Obfuscation indicators
    if content.chars().filter(|&c| c == '^' || c == '%').count() > 3 {
        score += 0.1;
    }

    // Cap at 1.0
    score.min(1.0)
}

/// Read memory region from process
async fn read_memory_region(pid: u32, region: &MemoryRegion) -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| anyhow::anyhow!("Failed to open process: {}", e))?;

            let _guard = scopeguard::guard(handle, |h| {
                let _ = CloseHandle(h);
            });

            let mut buffer = vec![0u8; region.size as usize];
            let mut bytes_read = 0usize;

            ReadProcessMemory(
                handle,
                region.base_address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                Some(&mut bytes_read),
            )
            .map_err(|e| anyhow::anyhow!("ReadProcessMemory failed: {}", e))?;

            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = File::open(&mem_path)
            .map_err(|e| anyhow::anyhow!("Failed to open {}: {}", mem_path, e))?;

        mem_file
            .seek(SeekFrom::Start(region.base_address))
            .map_err(|e| anyhow::anyhow!("Failed to seek: {}", e))?;

        let mut buffer = vec![0u8; region.size as usize];
        mem_file
            .read_exact(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))?;

        Ok(buffer)
    }

    #[cfg(target_os = "macos")]
    {
        use mach2::kern_return::KERN_SUCCESS;
        use mach2::port::mach_port_t;
        use mach2::traps::task_for_pid;
        use mach2::vm::mach_vm_read;
        use mach2::vm_types::vm_offset_t;

        unsafe {
            let mut task: mach_port_t = 0;
            let kr = task_for_pid(mach2::traps::mach_task_self(), pid as i32, &mut task);

            if kr != KERN_SUCCESS {
                return Err(anyhow::anyhow!("task_for_pid failed: {}", kr));
            }

            let mut data_ptr: vm_offset_t = 0;
            let mut data_count: u32 = 0;

            let kr = mach_vm_read(
                task,
                region.base_address,
                region.size,
                &mut data_ptr,
                &mut data_count,
            );

            if kr != KERN_SUCCESS {
                return Err(anyhow::anyhow!("mach_vm_read failed: {}", kr));
            }

            let buffer =
                std::slice::from_raw_parts(data_ptr as *const u8, data_count as usize).to_vec();

            // Free the memory
            mach2::vm::mach_vm_deallocate(
                mach2::traps::mach_task_self(),
                data_ptr as u64,
                data_count as u64,
            );

            Ok(buffer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"Hello\x00World\x00Test String\x00\xff\xfe";
        let strings = extract_ascii_strings(data, 4);

        // "Hello", "World" and "Test String" are all >= 4 printable chars.
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].1, "Hello");
        assert_eq!(strings[1].1, "World");
        assert_eq!(strings[2].1, "Test String");
    }

    #[test]
    fn test_classify_string() {
        let url_regex = Regex::new(r#"https?://[^\s<>"]+"#).unwrap();
        let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        let path_regex =
            Regex::new(r#"[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#).unwrap();
        let registry_regex = Regex::new(r"(?i)HKEY_[A-Z_]+\\[^\r\n]+").unwrap();
        let base64_regex = Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap();

        assert_eq!(
            classify_string(
                "https://example.com/malware",
                &url_regex,
                &ip_regex,
                &path_regex,
                &registry_regex,
                &base64_regex
            ),
            StringType::Url
        );

        assert_eq!(
            classify_string(
                "192.168.1.1",
                &url_regex,
                &ip_regex,
                &path_regex,
                &registry_regex,
                &base64_regex
            ),
            StringType::IpAddress
        );

        assert_eq!(
            classify_string(
                "C:\\Windows\\System32\\malware.exe",
                &url_regex,
                &ip_regex,
                &path_regex,
                &registry_regex,
                &base64_regex
            ),
            StringType::FilePath
        );
    }

    #[test]
    fn test_relevance_scoring() {
        let url_regex = Regex::new(r#"https?://[^\s<>"]+"#).unwrap();
        let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        let path_regex =
            Regex::new(r#"[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#).unwrap();
        let registry_regex = Regex::new(r"(?i)HKEY_[A-Z_]+\\[^\r\n]+").unwrap();
        let base64_regex = Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap();

        let url_type = classify_string(
            "https://evil.com",
            &url_regex,
            &ip_regex,
            &path_regex,
            &registry_regex,
            &base64_regex,
        );
        let score = calculate_relevance("https://evil.com/backdoor", url_type);
        assert!(score > 0.9);

        let password_score = calculate_relevance("password=secret123", StringType::Ascii);
        assert!(password_score > 0.5);
    }
}
