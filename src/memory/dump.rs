//! Memory dump acquisition
//!
//! Platform-specific memory dump implementations:
//! - Windows: MiniDumpWriteDump + ReadProcessMemory
//! - Linux: /proc/[pid]/mem
//! - macOS: mach_vm_read

use super::{DumpOptions, DumpType, MemoryRegion, MemoryRegionType};
use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;
    use ::windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
    use ::windows::Win32::System::Diagnostics::Debug::{
        MiniDumpWithFullMemory, MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWriteDump,
        MINIDUMP_TYPE,
    };
    use ::windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use ::windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, K32GetModuleInformation, MODULEINFO,
    };
    use ::windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// Get memory regions for a Windows process
    pub async fn get_memory_regions_windows(pid: u32) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| anyhow!("Failed to open process {}: {}", pid, e))?;

            let _guard = scopeguard::guard(handle, |h| {
                let _ = CloseHandle(h);
            });

            // Get loaded modules for module name resolution
            let mut modules: Vec<HMODULE> = vec![HMODULE::default(); 1024];
            let mut cb_needed = 0u32;

            let module_map = if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
            )
            .is_ok()
            {
                let count = (cb_needed as usize) / std::mem::size_of::<HMODULE>();
                let mut map = std::collections::HashMap::new();

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
                            let base_addr = info.lpBaseOfDll as u64;
                            let size = info.SizeOfImage as u64;
                            map.insert((base_addr, base_addr + size), path);
                        }
                    }
                }
                map
            } else {
                std::collections::HashMap::new()
            };

            // Enumerate memory regions
            let mut address: u64 = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            while address < 0x7FFF_FFFF_FFFF {
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // Only include committed memory
                if mbi.State == MEM_COMMIT {
                    let base_address = mbi.BaseAddress as u64;
                    let size = mbi.RegionSize as u64;
                    let protection = mbi.Protect.0;

                    // Determine memory type
                    let memory_type = match mbi.Type {
                        MEM_IMAGE => MemoryRegionType::Image,
                        MEM_MAPPED => MemoryRegionType::Mapped,
                        MEM_PRIVATE => MemoryRegionType::Private,
                        _ => MemoryRegionType::Unknown,
                    };

                    // Check if executable
                    let is_executable = is_executable_protection(mbi.Protect);
                    let is_writable = is_writable_protection(mbi.Protect);
                    let is_readable = is_readable_protection(mbi.Protect);
                    let is_private = mbi.Type == MEM_PRIVATE;

                    // Find module name
                    let (module_name, module_path) = module_map
                        .iter()
                        .find(|((start, end), _)| base_address >= *start && base_address < *end)
                        .map(|(_, path)| {
                            let name = std::path::Path::new(path)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string());
                            (name, Some(path.clone()))
                        })
                        .unwrap_or((None, None));

                    regions.push(MemoryRegion {
                        base_address,
                        size,
                        protection,
                        memory_type,
                        module_name,
                        module_path,
                        is_executable,
                        is_writable,
                        is_readable,
                        is_private,
                    });
                }

                address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
            }
        }

        debug!(
            pid = pid,
            regions = regions.len(),
            "Enumerated memory regions"
        );
        Ok(regions)
    }

    fn is_executable_protection(protect: PAGE_PROTECTION_FLAGS) -> bool {
        let p = protect.0;
        p == PAGE_EXECUTE.0
            || p == PAGE_EXECUTE_READ.0
            || p == PAGE_EXECUTE_READWRITE.0
            || p == PAGE_EXECUTE_WRITECOPY.0
    }

    fn is_writable_protection(protect: PAGE_PROTECTION_FLAGS) -> bool {
        let p = protect.0;
        p == PAGE_READWRITE.0
            || p == PAGE_WRITECOPY.0
            || p == PAGE_EXECUTE_READWRITE.0
            || p == PAGE_EXECUTE_WRITECOPY.0
    }

    fn is_readable_protection(protect: PAGE_PROTECTION_FLAGS) -> bool {
        protect.0 != PAGE_NOACCESS.0
    }

    /// Dump process memory on Windows
    pub async fn dump_process_memory_windows(
        pid: u32,
        regions: Vec<MemoryRegion>,
        options: &DumpOptions,
    ) -> Result<Vec<u8>> {
        match options.dump_type {
            DumpType::Full => dump_full_memory_windows(pid).await,
            _ => dump_selective_memory_windows(pid, regions, options).await,
        }
    }

    /// Full memory dump using MiniDumpWriteDump
    async fn dump_full_memory_windows(pid: u32) -> Result<Vec<u8>> {
        use std::fs::File;
        use std::io::Read;
        use std::os::windows::io::AsRawHandle;

        let temp_path = std::env::temp_dir().join(format!("tamandua_dump_{}.dmp", pid));

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| anyhow!("Failed to open process {}: {}", pid, e))?;

            let _guard = scopeguard::guard(handle, |h| {
                let _ = CloseHandle(h);
            });

            let file = File::create(&temp_path)
                .map_err(|e| anyhow!("Failed to create dump file: {}", e))?;

            let file_handle = HANDLE(file.as_raw_handle() as isize);

            let dump_type = MINIDUMP_TYPE(
                MiniDumpWithFullMemory.0 | MiniDumpWithHandleData.0 | MiniDumpWithThreadInfo.0,
            );

            MiniDumpWriteDump(handle, pid, file_handle, dump_type, None, None, None)
                .map_err(|e| anyhow!("MiniDumpWriteDump failed: {}", e))?;

            drop(file);

            // Read dump file
            let mut dump_file =
                File::open(&temp_path).map_err(|e| anyhow!("Failed to open dump file: {}", e))?;
            let mut buffer = Vec::new();
            dump_file
                .read_to_end(&mut buffer)
                .map_err(|e| anyhow!("Failed to read dump file: {}", e))?;

            // Clean up temp file
            let _ = std::fs::remove_file(&temp_path);

            info!(pid = pid, size = buffer.len(), "Full memory dump completed");
            Ok(buffer)
        }
    }

    /// Selective memory dump (specific regions)
    async fn dump_selective_memory_windows(
        pid: u32,
        regions: Vec<MemoryRegion>,
        options: &DumpOptions,
    ) -> Result<Vec<u8>> {
        use ::windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let mut dump_data = Vec::new();

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| anyhow!("Failed to open process {}: {}", pid, e))?;

            let _guard = scopeguard::guard(handle, |h| {
                let _ = CloseHandle(h);
            });

            for region in regions {
                // Filter based on dump type
                let should_dump = match options.dump_type {
                    DumpType::RwxRegions => region.is_executable && region.is_writable,
                    DumpType::PrivateExecutable => region.is_private && region.is_executable,
                    DumpType::Suspicious => {
                        // Will be filtered by caller
                        true
                    }
                    DumpType::Full => true,
                };

                if !should_dump {
                    continue;
                }

                // Read region
                let mut buffer = vec![0u8; region.size as usize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    handle,
                    region.base_address as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len(),
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    // Write region header (address, size)
                    dump_data.extend_from_slice(&region.base_address.to_le_bytes());
                    dump_data.extend_from_slice(&(bytes_read as u64).to_le_bytes());
                    dump_data.extend_from_slice(&buffer);

                    debug!(
                        address = format!("0x{:X}", region.base_address),
                        size = bytes_read,
                        "Dumped memory region"
                    );
                } else {
                    warn!(
                        address = format!("0x{:X}", region.base_address),
                        "Failed to read memory region"
                    );
                }
            }
        }

        info!(
            pid = pid,
            size = dump_data.len(),
            "Selective memory dump completed"
        );
        Ok(dump_data)
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

    /// Get memory regions for a Linux process
    pub async fn get_memory_regions_linux(pid: u32) -> Result<Vec<MemoryRegion>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let file =
            File::open(&maps_path).map_err(|e| anyhow!("Failed to open {}: {}", maps_path, e))?;

        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 2 {
                continue;
            }

            // Parse address range
            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() != 2 {
                continue;
            }

            let base_address = u64::from_str_radix(addr_parts[0], 16)?;
            let end_address = u64::from_str_radix(addr_parts[1], 16)?;
            let size = end_address - base_address;

            // Parse permissions
            let perms = parts[1];
            let is_readable = perms.starts_with('r');
            let is_writable = perms.chars().nth(1) == Some('w');
            let is_executable = perms.chars().nth(2) == Some('x');
            let is_private = perms.chars().nth(3) == Some('p');

            // Parse module path (if present)
            let (module_name, module_path, memory_type) = if parts.len() >= 6 {
                let path = parts[5];
                let name = std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string());

                let mem_type = if path.starts_with('/') {
                    if path.ends_with(".so") || path.contains(".so.") {
                        MemoryRegionType::Image
                    } else {
                        MemoryRegionType::Mapped
                    }
                } else if path == "[heap]" {
                    MemoryRegionType::Heap
                } else if path == "[stack]" {
                    MemoryRegionType::Stack
                } else {
                    MemoryRegionType::Private
                };

                (name, Some(path.to_string()), mem_type)
            } else {
                (None, None, MemoryRegionType::Private)
            };

            // Encode protection flags (Linux-style)
            let mut protection = 0u32;
            if is_readable {
                protection |= 0x01;
            }
            if is_writable {
                protection |= 0x02;
            }
            if is_executable {
                protection |= 0x04;
            }

            regions.push(MemoryRegion {
                base_address,
                size,
                protection,
                memory_type,
                module_name,
                module_path,
                is_executable,
                is_writable,
                is_readable,
                is_private,
            });
        }

        debug!(
            pid = pid,
            regions = regions.len(),
            "Enumerated memory regions"
        );
        Ok(regions)
    }

    /// Dump process memory on Linux
    pub async fn dump_process_memory_linux(
        pid: u32,
        regions: Vec<MemoryRegion>,
        options: &DumpOptions,
    ) -> Result<Vec<u8>> {
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file =
            File::open(&mem_path).map_err(|e| anyhow!("Failed to open {}: {}", mem_path, e))?;

        let mut dump_data = Vec::new();

        for region in regions {
            // Filter based on dump type
            let should_dump = match options.dump_type {
                DumpType::Full => true,
                DumpType::RwxRegions => region.is_executable && region.is_writable,
                DumpType::PrivateExecutable => region.is_private && region.is_executable,
                DumpType::Suspicious => true, // Filtered by caller
            };

            if !should_dump {
                continue;
            }

            // Seek to region base address
            if mem_file.seek(SeekFrom::Start(region.base_address)).is_err() {
                warn!(
                    address = format!("0x{:X}", region.base_address),
                    "Failed to seek to memory region"
                );
                continue;
            }

            // Read region
            let mut buffer = vec![0u8; region.size as usize];
            match mem_file.read_exact(&mut buffer) {
                Ok(_) => {
                    // Write region header
                    dump_data.extend_from_slice(&region.base_address.to_le_bytes());
                    dump_data.extend_from_slice(&region.size.to_le_bytes());
                    dump_data.extend_from_slice(&buffer);

                    debug!(
                        address = format!("0x{:X}", region.base_address),
                        size = region.size,
                        "Dumped memory region"
                    );
                }
                Err(e) => {
                    warn!(
                        address = format!("0x{:X}", region.base_address),
                        error = %e,
                        "Failed to read memory region"
                    );
                }
            }
        }

        info!(pid = pid, size = dump_data.len(), "Memory dump completed");
        Ok(dump_data)
    }
}

#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::port::mach_port_t;
    use mach2::traps::task_for_pid;
    use mach2::vm::{mach_vm_read, mach_vm_region_recurse};
    use mach2::vm_inherit::VM_INHERIT_SHARE;
    use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
    use mach2::vm_region::{
        vm_region_basic_info_64, vm_region_submap_info_64, VM_REGION_BASIC_INFO_64,
    };
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t, vm_offset_t};

    /// Get memory regions for a macOS process
    pub async fn get_memory_regions_macos(pid: u32) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();

        unsafe {
            let mut task: mach_port_t = 0;
            let kr = task_for_pid(mach2::traps::mach_task_self(), pid as i32, &mut task);

            if kr != KERN_SUCCESS {
                return Err(anyhow!("task_for_pid failed for pid {}: {}", pid, kr));
            }

            let mut address: mach_vm_address_t = 0;
            let mut size: mach_vm_size_t = 0;
            let mut depth = 0u32;
            let mut info: vm_region_submap_info_64 = std::mem::zeroed();
            let mut info_count = (std::mem::size_of::<vm_region_submap_info_64>()
                / std::mem::size_of::<i32>()) as u32;

            while mach_vm_region_recurse(
                task,
                &mut address,
                &mut size,
                &mut depth,
                &mut info as *mut _ as *mut i32,
                &mut info_count,
            ) == KERN_SUCCESS
            {
                let is_readable = (info.protection & VM_PROT_READ) != 0;
                let is_writable = (info.protection & VM_PROT_WRITE) != 0;
                let is_executable = (info.protection & VM_PROT_EXECUTE) != 0;
                let is_private = info.share_mode != VM_INHERIT_SHARE as u8;

                let memory_type = if info.share_mode == VM_INHERIT_SHARE as u8 {
                    MemoryRegionType::Mapped
                } else {
                    MemoryRegionType::Private
                };

                let mut protection = 0u32;
                if is_readable {
                    protection |= 0x01;
                }
                if is_writable {
                    protection |= 0x02;
                }
                if is_executable {
                    protection |= 0x04;
                }

                regions.push(MemoryRegion {
                    base_address: address,
                    size,
                    protection,
                    memory_type,
                    module_name: None,
                    module_path: None,
                    is_executable,
                    is_writable,
                    is_readable,
                    is_private,
                });

                address += size;
                info_count = (std::mem::size_of::<vm_region_submap_info_64>()
                    / std::mem::size_of::<i32>()) as u32;
            }
        }

        debug!(
            pid = pid,
            regions = regions.len(),
            "Enumerated memory regions"
        );
        Ok(regions)
    }

    /// Dump process memory on macOS
    pub async fn dump_process_memory_macos(
        pid: u32,
        regions: Vec<MemoryRegion>,
        options: &DumpOptions,
    ) -> Result<Vec<u8>> {
        let mut dump_data = Vec::new();

        unsafe {
            let mut task: mach_port_t = 0;
            let kr = task_for_pid(mach2::traps::mach_task_self(), pid as i32, &mut task);

            if kr != KERN_SUCCESS {
                return Err(anyhow!("task_for_pid failed for pid {}: {}", pid, kr));
            }

            for region in regions {
                // Filter based on dump type
                let should_dump = match options.dump_type {
                    DumpType::Full => true,
                    DumpType::RwxRegions => region.is_executable && region.is_writable,
                    DumpType::PrivateExecutable => region.is_private && region.is_executable,
                    DumpType::Suspicious => true,
                };

                if !should_dump {
                    continue;
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

                if kr == KERN_SUCCESS {
                    let buffer =
                        std::slice::from_raw_parts(data_ptr as *const u8, data_count as usize);

                    // Write region header
                    dump_data.extend_from_slice(&region.base_address.to_le_bytes());
                    dump_data.extend_from_slice(&region.size.to_le_bytes());
                    dump_data.extend_from_slice(buffer);

                    debug!(
                        address = format!("0x{:X}", region.base_address),
                        size = data_count,
                        "Dumped memory region"
                    );

                    // Free the memory
                    mach2::vm::mach_vm_deallocate(
                        mach2::traps::mach_task_self(),
                        data_ptr as u64,
                        data_count as u64,
                    );
                } else {
                    warn!(
                        address = format!("0x{:X}", region.base_address),
                        "Failed to read memory region: {}", kr
                    );
                }
            }
        }

        info!(pid = pid, size = dump_data.len(), "Memory dump completed");
        Ok(dump_data)
    }
}

/// Compress memory dump with zstd
#[cfg(feature = "compression")]
pub fn compress_dump(data: Vec<u8>) -> Result<Vec<u8>> {
    use std::io::Write;

    let mut encoder = zstd::Encoder::new(Vec::new(), 3)?;
    encoder.write_all(&data)?;
    let compressed = encoder.finish()?;

    info!(
        original = data.len(),
        compressed = compressed.len(),
        ratio = format!(
            "{:.1}%",
            (compressed.len() as f64 / data.len() as f64) * 100.0
        ),
        "Compressed memory dump"
    );

    Ok(compressed)
}

#[cfg(not(feature = "compression"))]
pub fn compress_dump(data: Vec<u8>) -> Result<Vec<u8>> {
    Ok(data)
}
