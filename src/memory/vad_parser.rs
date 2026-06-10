//! VAD (Virtual Address Descriptor) Tree Analysis - Windows Only
//!
//! Analyzes the VAD tree for suspicious memory allocations:
//! - RWX regions
//! - Large private allocations
//! - Suspicious VAD attributes
//! - Memory not associated with modules

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// VAD entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VadEntry {
    /// Starting virtual address
    pub start_vpn: u64,
    /// Ending virtual address
    pub end_vpn: u64,
    /// VAD type
    pub vad_type: VadType,
    /// Protection flags
    pub protection: u32,
    /// Commit charge (pages)
    pub commit_charge: u64,
    /// Memory mapped file path (if any)
    pub file_path: Option<String>,
    /// Is suspicious
    pub is_suspicious: bool,
    /// Suspicion reason
    pub suspicion_reason: Option<String>,
}

/// VAD type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VadType {
    /// VAD for private memory (VirtualAlloc)
    Private,
    /// VAD for mapped file
    Mapped,
    /// VAD for image (DLL/EXE)
    Image,
    /// Unknown type
    Unknown,
}

/// Parse VAD tree for a process
pub fn parse_vad_tree(pid: u32) -> Result<Vec<VadEntry>> {
    // VAD tree parsing requires kernel-mode access or WinDbg extensions
    // For a production implementation, you would use:
    // 1. Windows Driver Kit (WDK) kernel driver to read PEB->Ldr
    // 2. NtQueryVirtualMemory with MemoryBasicInformation
    // 3. WinDbg extension or kernel debugger

    // This is a placeholder that uses VirtualQueryEx (already done in dump.rs)
    // For true VAD enumeration, a kernel driver is required

    let mut vad_entries = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use super::dump::windows::get_memory_regions_windows;

        // Use existing memory region enumeration as a proxy for VAD analysis
        let regions =
            tokio::runtime::Handle::current().block_on(get_memory_regions_windows(pid))?;

        for region in regions {
            let vad_type = match region.memory_type {
                super::MemoryRegionType::Image => VadType::Image,
                super::MemoryRegionType::Mapped => VadType::Mapped,
                super::MemoryRegionType::Private => VadType::Private,
                _ => VadType::Unknown,
            };

            // Check for suspicious attributes
            let (is_suspicious, suspicion_reason) = analyze_vad_suspicion(&region);

            vad_entries.push(VadEntry {
                start_vpn: region.base_address,
                end_vpn: region.base_address + region.size,
                vad_type,
                protection: region.protection,
                commit_charge: region.size / 4096, // Assume page size 4KB
                file_path: region.module_path,
                is_suspicious,
                suspicion_reason,
            });
        }
    }

    info!(
        pid = pid,
        vads = vad_entries.len(),
        suspicious = vad_entries.iter().filter(|v| v.is_suspicious).count(),
        "VAD tree analysis completed"
    );

    Ok(vad_entries)
}

/// Analyze VAD entry for suspicious attributes
fn analyze_vad_suspicion(region: &super::MemoryRegion) -> (bool, Option<String>) {
    let mut reasons = Vec::new();

    // RWX memory
    if region.is_writable && region.is_executable {
        reasons.push("RWX protection");
    }

    // Large private allocation (> 10MB)
    if region.is_private && region.size > 10 * 1024 * 1024 {
        reasons.push("Large private allocation");
    }

    // Executable private memory
    if region.is_executable && region.is_private {
        reasons.push("Executable private memory");
    }

    // Unmapped executable region
    if region.is_executable && region.module_path.is_none() {
        reasons.push("Unmapped executable region");
    }

    let is_suspicious = !reasons.is_empty();
    let suspicion_reason = if is_suspicious {
        Some(reasons.join(", "))
    } else {
        None
    };

    (is_suspicious, suspicion_reason)
}

/// Get VAD statistics
pub fn get_vad_statistics(vad_entries: &[VadEntry]) -> VadStatistics {
    let total_vads = vad_entries.len();
    let private_vads = vad_entries
        .iter()
        .filter(|v| v.vad_type == VadType::Private)
        .count();
    let mapped_vads = vad_entries
        .iter()
        .filter(|v| v.vad_type == VadType::Mapped)
        .count();
    let image_vads = vad_entries
        .iter()
        .filter(|v| v.vad_type == VadType::Image)
        .count();
    let suspicious_vads = vad_entries.iter().filter(|v| v.is_suspicious).count();

    let total_commit: u64 = vad_entries.iter().map(|v| v.commit_charge).sum();

    VadStatistics {
        total_vads,
        private_vads,
        mapped_vads,
        image_vads,
        suspicious_vads,
        total_commit_pages: total_commit,
    }
}

/// VAD statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VadStatistics {
    pub total_vads: usize,
    pub private_vads: usize,
    pub mapped_vads: usize,
    pub image_vads: usize,
    pub suspicious_vads: usize,
    pub total_commit_pages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vad_suspicion_analysis() {
        let region = super::super::MemoryRegion {
            base_address: 0x10000000,
            size: 4096,
            protection: 0x40, // PAGE_EXECUTE_READWRITE
            memory_type: super::super::MemoryRegionType::Private,
            module_name: None,
            module_path: None,
            is_executable: true,
            is_writable: true,
            is_readable: true,
            is_private: true,
        };

        let (is_suspicious, reason) = analyze_vad_suspicion(&region);
        assert!(is_suspicious);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("RWX"));
    }
}
