//! Suspicious memory region detection
//!
//! Detects suspicious memory patterns:
//! - RWX regions (writable + executable)
//! - Injected DLLs
//! - Hollowed sections
//! - Unusual memory protections
//! - Non-image executable memory

use super::{MemoryRegion, MemoryRegionType, SuspicionReason, SuspiciousRegion};
use anyhow::Result;
use tracing::{debug, info};

/// Detect suspicious memory regions in a process
pub async fn detect_suspicious_regions(pid: u32) -> Result<Vec<SuspiciousRegion>> {
    let regions = super::get_memory_regions(pid).await?;
    let mut suspicious = Vec::new();

    // Get process name
    let process_name = get_process_name(pid)
        .await
        .unwrap_or_else(|| format!("pid_{}", pid));

    for region in regions {
        let mut reasons = Vec::new();
        let mut confidence = 0.0f32;

        // Check for RWX memory (writable + executable)
        if region.is_writable && region.is_executable {
            reasons.push(SuspicionReason::RwxMemory);
            confidence += 0.8;
        }

        // Check for executable private memory (not backed by file)
        if region.is_executable
            && region.is_private
            && region.memory_type == MemoryRegionType::Private
        {
            reasons.push(SuspicionReason::ExecutablePrivate);
            confidence += 0.7;
        }

        // Check for non-image executable memory
        if region.is_executable
            && region.memory_type != MemoryRegionType::Image
            && region.module_name.is_none()
        {
            reasons.push(SuspicionReason::NonImageExecutable);
            confidence += 0.6;
        }

        // Check for potential PE in private memory
        if region.is_private && region.size > 0x1000 {
            if let Ok(has_pe) = check_pe_header(pid, &region).await {
                if has_pe {
                    reasons.push(SuspicionReason::PeInPrivateMemory);
                    confidence += 0.9;
                }
            }
        }

        // Check for high entropy in executable regions
        if region.is_executable {
            if let Ok(entropy) = calculate_region_entropy(pid, &region).await {
                if entropy > 7.0 {
                    reasons.push(SuspicionReason::HighEntropy);
                    confidence += 0.5;
                }
            }
        }

        // If any reasons were found, add to suspicious list
        if !reasons.is_empty() {
            confidence = confidence.min(1.0);

            let details = format!(
                "Memory region at 0x{:X} (size: {} KB) - {}",
                region.base_address,
                region.size / 1024,
                reasons
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            suspicious.push(SuspiciousRegion {
                pid,
                process_name: process_name.clone(),
                region,
                reasons,
                confidence,
                details,
            });
        }
    }

    info!(
        pid = pid,
        suspicious = suspicious.len(),
        "Suspicious region detection completed"
    );

    Ok(suspicious)
}

/// Get process name by PID
async fn get_process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                let mut name_buf = vec![0u16; 512];
                let len = GetModuleBaseNameW(handle, None, &mut name_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return Some(String::from_utf16_lossy(&name_buf[..len as usize]));
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;

        let comm_path = format!("/proc/{}/comm", pid);
        fs::read_to_string(&comm_path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;

        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
        None
    }
}

/// Check if memory region contains PE header
async fn check_pe_header(pid: u32, region: &MemoryRegion) -> Result<bool> {
    // Read first 0x100 bytes to check for MZ/PE signature
    let header_data = read_memory_bytes(pid, region.base_address, 0x100).await?;

    // Check for MZ signature
    if header_data.len() >= 2 && header_data[0] == 0x4D && header_data[1] == 0x5A {
        // Check for PE signature at e_lfanew offset
        if header_data.len() >= 0x40 {
            let pe_offset = u32::from_le_bytes([
                header_data[0x3C],
                header_data[0x3D],
                header_data[0x3E],
                header_data[0x3F],
            ]) as usize;

            if pe_offset < header_data.len() - 4 {
                let pe_sig = &header_data[pe_offset..pe_offset + 4];
                if pe_sig == b"PE\0\0" {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

/// Calculate Shannon entropy of a memory region
async fn calculate_region_entropy(pid: u32, region: &MemoryRegion) -> Result<f64> {
    // Sample up to 64KB for entropy calculation
    let sample_size = region.size.min(65536) as usize;
    let data = read_memory_bytes(pid, region.base_address, sample_size).await?;

    // Calculate byte frequency
    let mut frequency = [0u32; 256];
    for &byte in &data {
        frequency[byte as usize] += 1;
    }

    // Calculate entropy
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    Ok(entropy)
}

/// Read memory bytes from process
async fn read_memory_bytes(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
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

            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0usize;

            ReadProcessMemory(
                handle,
                address as *const _,
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
            .seek(SeekFrom::Start(address))
            .map_err(|e| anyhow::anyhow!("Failed to seek: {}", e))?;

        let mut buffer = vec![0u8; size];
        let bytes_read = mem_file.read(&mut buffer).unwrap_or(0);
        buffer.truncate(bytes_read);

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

            let kr = mach_vm_read(task, address, size as u64, &mut data_ptr, &mut data_count);

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

/// Detect injected DLLs (Windows only)
#[cfg(target_os = "windows")]
pub async fn detect_injected_dlls(pid: u32) -> Result<Vec<SuspiciousRegion>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, K32GetModuleInformation, MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut suspicious = Vec::new();

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| anyhow::anyhow!("Failed to open process: {}", e))?;

        let _guard = scopeguard::guard(handle, |h| {
            let _ = CloseHandle(h);
        });

        let mut modules: Vec<windows::Win32::Foundation::HMODULE> =
            vec![windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut cb_needed = 0u32;

        if EnumProcessModules(
            handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
            &mut cb_needed,
        )
        .is_ok()
        {
            let count =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

            for i in 0..count.min(modules.len()) {
                if modules[i].is_invalid() {
                    continue;
                }

                let mut info: MODULEINFO = std::mem::zeroed();
                if K32GetModuleInformation(
                    handle,
                    modules[i],
                    &mut info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .as_bool()
                {
                    let mut name_buf = vec![0u16; 512];
                    let len = GetModuleFileNameExW(handle, modules[i], &mut name_buf);

                    if len > 0 {
                        let path = String::from_utf16_lossy(&name_buf[..len as usize]);

                        // Check for suspicious DLL paths
                        let is_suspicious = path.contains("AppData\\Local\\Temp")
                            || path.contains("\\Users\\Public\\")
                            || !std::path::Path::new(&path).exists();

                        if is_suspicious {
                            let region = MemoryRegion {
                                base_address: info.lpBaseOfDll as u64,
                                size: info.SizeOfImage as u64,
                                protection: 0x20, // PAGE_EXECUTE_READ
                                memory_type: MemoryRegionType::Image,
                                module_name: Some(
                                    std::path::Path::new(&path)
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_default(),
                                ),
                                module_path: Some(path.clone()),
                                is_executable: true,
                                is_writable: false,
                                is_readable: true,
                                is_private: false,
                            };

                            suspicious.push(SuspiciousRegion {
                                pid,
                                process_name: get_process_name(pid).await.unwrap_or_default(),
                                region,
                                reasons: vec![SuspicionReason::InjectedDll],
                                confidence: 0.8,
                                details: format!("Suspicious DLL loaded from: {}", path),
                            });
                        }
                    }
                }
            }
        }
    }

    debug!(
        pid = pid,
        injected = suspicious.len(),
        "Injected DLL detection completed"
    );
    Ok(suspicious)
}

#[cfg(not(target_os = "windows"))]
pub async fn detect_injected_dlls(_pid: u32) -> Result<Vec<SuspiciousRegion>> {
    Ok(Vec::new())
}
