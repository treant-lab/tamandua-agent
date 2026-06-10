//! Advanced Evasion Detection Module
//!
//! Detects modern evasion techniques used by sophisticated malware:
//! - Module Stomping: Legitimate DLLs with modified code sections
//! - Direct Syscalls: Bypassing ntdll.dll hooks via direct syscall instructions
//! - Syscall Hooking: Inline hooks in ntdll functions
//! - IAT Hooking: Import Address Table modifications
//! - Early Bird Injection: APC injection before thread execution
//! - Phantom DLL Hollowing: DLL loaded from disk then hollowed
//!
//! MITRE ATT&CK:
//! - T1055 (Process Injection)
//! - T1562.001 (Disable or Modify Tools)
//! - T1620 (Reflective Code Loading)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

/// Evasion technique detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionDetection {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Type of evasion detected
    pub technique: EvasionTechnique,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Severity level
    pub severity: EvasionSeverity,
    /// Detailed evidence
    pub evidence: Vec<String>,
    /// Memory address involved
    pub address: Option<u64>,
    /// Module name (if applicable)
    pub module_name: Option<String>,
    /// MITRE ATT&CK technique ID
    pub mitre_id: &'static str,
}

/// Types of evasion techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvasionTechnique {
    /// Legitimate DLL with modified .text section
    ModuleStomping,
    /// Direct syscall instruction (bypassing ntdll)
    DirectSyscall,
    /// Inline hook in ntdll function
    SyscallHook,
    /// IAT entry pointing outside module
    IatHook,
    /// APC queued to thread before it runs
    EarlyBird,
    /// DLL loaded then hollowed
    PhantomDllHollowing,
    /// ntdll remapped from disk (unhooking)
    NtdllUnhooking,
    /// Syscall number mismatch (syscall stub tampering)
    SyscallNumberMismatch,
    /// Heaven's Gate (32-bit to 64-bit transition)
    HeavensGate,
    /// Exception-based control flow (VEH/SEH abuse)
    ExceptionBasedFlow,
    /// Stack spoofing / call stack masking
    StackSpoofing,
    /// Stack pivot (RSP pointing to non-stack memory)
    StackPivot,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvasionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl EvasionTechnique {
    pub fn mitre_id(&self) -> &'static str {
        match self {
            Self::ModuleStomping => "T1055.001",
            Self::DirectSyscall => "T1562.001",
            Self::SyscallHook => "T1562.001",
            Self::IatHook => "T1574.001",
            Self::EarlyBird => "T1055.004",
            Self::PhantomDllHollowing => "T1055.012",
            Self::NtdllUnhooking => "T1562.001",
            Self::SyscallNumberMismatch => "T1562.001",
            Self::HeavensGate => "T1055",
            Self::ExceptionBasedFlow => "T1055",
            Self::StackSpoofing => "T1562.001",
            Self::StackPivot => "T1055",
        }
    }

    pub fn severity(&self) -> EvasionSeverity {
        match self {
            Self::ModuleStomping => EvasionSeverity::Critical,
            Self::DirectSyscall => EvasionSeverity::High,
            Self::SyscallHook => EvasionSeverity::Critical,
            Self::IatHook => EvasionSeverity::High,
            Self::EarlyBird => EvasionSeverity::Critical,
            Self::PhantomDllHollowing => EvasionSeverity::Critical,
            Self::NtdllUnhooking => EvasionSeverity::High,
            Self::SyscallNumberMismatch => EvasionSeverity::High,
            Self::HeavensGate => EvasionSeverity::High,
            Self::ExceptionBasedFlow => EvasionSeverity::Medium,
            Self::StackSpoofing => EvasionSeverity::Critical,
            Self::StackPivot => EvasionSeverity::Critical,
        }
    }
}

// =============================================================================
// MODULE STOMPING DETECTION
// =============================================================================

/// Detects module stomping by comparing loaded DLL .text section with on-disk version
#[cfg(target_os = "windows")]
pub async fn detect_module_stomping(pid: u32) -> Result<Vec<EvasionDetection>> {
    use windows::Win32::Foundation::{CloseHandle, HMODULE};

    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
        MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut detections = Vec::new();
    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

        // Get list of loaded modules
        let mut modules: Vec<HMODULE> = vec![HMODULE::default(); 1024];
        let mut cb_needed = 0u32;

        if EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
        .is_ok()
        {
            let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();

            for i in 0..module_count {
                let module = modules[i];
                if module.is_invalid() {
                    continue;
                }

                // Get module info
                let mut mod_info = MODULEINFO::default();
                if GetModuleInformation(
                    handle,
                    module,
                    &mut mod_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .is_err()
                {
                    continue;
                }

                // Get module path
                let mut path_buf = vec![0u16; 512];
                let len = GetModuleFileNameExW(handle, module, &mut path_buf);
                if len == 0 {
                    continue;
                }

                let module_path = String::from_utf16_lossy(&path_buf[..len as usize]);

                // Skip if not a system DLL (focus on critical DLLs)
                let module_name_lower = module_path.to_lowercase();
                let is_critical = module_name_lower.contains("ntdll.dll")
                    || module_name_lower.contains("kernel32.dll")
                    || module_name_lower.contains("kernelbase.dll")
                    || module_name_lower.contains("advapi32.dll")
                    || module_name_lower.contains("user32.dll")
                    || module_name_lower.contains("msvcrt.dll");

                if !is_critical {
                    continue;
                }

                // Compare in-memory .text section with on-disk version
                if let Some(detection) = compare_module_text_section(
                    handle,
                    module.0 as u64,
                    &module_path,
                    pid,
                    &process_name,
                )
                .await
                {
                    detections.push(detection);
                }
            }
        }

        CloseHandle(handle)?;
    }

    Ok(detections)
}

#[cfg(target_os = "windows")]
async fn compare_module_text_section(
    process_handle: windows::Win32::Foundation::HANDLE,
    module_base: u64,
    module_path: &str,
    pid: u32,
    process_name: &str,
) -> Option<EvasionDetection> {
    use std::fs::File;
    use std::io::Read;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    // Read on-disk PE
    let mut file = File::open(module_path).ok()?;
    let mut disk_data = Vec::new();
    file.read_to_end(&mut disk_data).ok()?;

    // Parse PE header to find .text section
    let dos_header = unsafe { &*(disk_data.as_ptr() as *const DosHeader) };
    if dos_header.e_magic != 0x5A4D {
        return None;
    }

    let pe_offset = dos_header.e_lfanew as usize;
    if pe_offset + 4 > disk_data.len() {
        return None;
    }

    // Find .text section
    let pe_sig = u32::from_le_bytes(disk_data[pe_offset..pe_offset + 4].try_into().ok()?);
    if pe_sig != 0x00004550 {
        // "PE\0\0"
        return None;
    }

    let coff_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes(
        disk_data[coff_offset + 2..coff_offset + 4]
            .try_into()
            .ok()?,
    );
    let optional_header_size = u16::from_le_bytes(
        disk_data[coff_offset + 16..coff_offset + 18]
            .try_into()
            .ok()?,
    ) as usize;

    let sections_offset = coff_offset + 20 + optional_header_size;

    for i in 0..num_sections as usize {
        let section_offset = sections_offset + i * 40;
        if section_offset + 40 > disk_data.len() {
            break;
        }

        let section_name = &disk_data[section_offset..section_offset + 8];
        let section_name_str = std::str::from_utf8(section_name)
            .unwrap_or("")
            .trim_end_matches('\0');

        if section_name_str != ".text" {
            continue;
        }

        let virtual_size = u32::from_le_bytes(
            disk_data[section_offset + 8..section_offset + 12]
                .try_into()
                .ok()?,
        ) as usize;
        let virtual_addr = u32::from_le_bytes(
            disk_data[section_offset + 12..section_offset + 16]
                .try_into()
                .ok()?,
        ) as u64;
        let raw_size = u32::from_le_bytes(
            disk_data[section_offset + 16..section_offset + 20]
                .try_into()
                .ok()?,
        ) as usize;
        let raw_offset = u32::from_le_bytes(
            disk_data[section_offset + 20..section_offset + 24]
                .try_into()
                .ok()?,
        ) as usize;

        // Read .text section from disk
        let compare_size = virtual_size.min(raw_size).min(4096); // Compare first 4KB
        if raw_offset + compare_size > disk_data.len() {
            break;
        }
        let disk_text = &disk_data[raw_offset..raw_offset + compare_size];

        // Read .text section from memory
        let mut mem_text = vec![0u8; compare_size];
        let text_addr = module_base + virtual_addr;
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                process_handle,
                text_addr as *const std::ffi::c_void,
                mem_text.as_mut_ptr() as *mut std::ffi::c_void,
                compare_size,
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }
        }

        // Compare sections
        let mut diff_count = 0;
        let mut diff_offsets = Vec::new();

        for (offset, (disk_byte, mem_byte)) in disk_text.iter().zip(mem_text.iter()).enumerate() {
            if disk_byte != mem_byte {
                diff_count += 1;
                if diff_offsets.len() < 10 {
                    diff_offsets.push(format!(
                        "0x{:X}: disk=0x{:02X} mem=0x{:02X}",
                        offset, disk_byte, mem_byte
                    ));
                }
            }
        }

        // If significant differences found, it's module stomping
        if diff_count > 16 {
            let module_name = std::path::Path::new(module_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            let mut evidence = vec![
                format!("Module: {}", module_path),
                format!("Text section modified: {} bytes differ", diff_count),
                format!("Compared {} bytes of .text section", compare_size),
            ];
            evidence.extend(diff_offsets);

            return Some(EvasionDetection {
                pid,
                process_name: process_name.to_string(),
                technique: EvasionTechnique::ModuleStomping,
                confidence: (diff_count as f32 / compare_size as f32).min(1.0),
                severity: EvasionSeverity::Critical,
                evidence,
                address: Some(text_addr),
                module_name: Some(module_name),
                mitre_id: "T1055.001",
            });
        }

        break;
    }

    None
}

// DOS Header structure (minimal)
#[repr(C, packed)]
struct DosHeader {
    e_magic: u16,
    _padding: [u8; 58],
    e_lfanew: i32,
}

// =============================================================================
// DIRECT SYSCALL DETECTION
// =============================================================================

/// Detects direct syscall instructions in executable memory regions
/// Direct syscalls bypass ntdll hooks by calling syscall/sysenter directly
#[cfg(target_os = "windows")]
pub async fn detect_direct_syscalls(pid: u32) -> Result<Vec<EvasionDetection>> {
    use super::MemoryRegionType;

    let mut detections = Vec::new();
    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));
    let regions = super::get_memory_regions(pid).await?;

    for region in regions {
        // Only check executable private memory (not backed by DLLs)
        if !region.is_executable || region.memory_type != MemoryRegionType::Private {
            continue;
        }

        // Skip small regions
        if region.size < 64 {
            continue;
        }

        // Read memory and scan for syscall patterns
        if let Ok(data) =
            read_memory_region_safe(pid, region.base_address, region.size.min(65536) as usize).await
        {
            let syscall_locations = find_syscall_patterns(&data, region.base_address);

            if !syscall_locations.is_empty() {
                let mut evidence = vec![
                    format!(
                        "Region: 0x{:X} - 0x{:X}",
                        region.base_address,
                        region.base_address + region.size
                    ),
                    format!("Found {} syscall instruction(s)", syscall_locations.len()),
                    "Direct syscalls bypass EDR hooks in ntdll.dll".to_string(),
                ];

                for (addr, pattern) in syscall_locations.iter().take(5) {
                    evidence.push(format!("Syscall at 0x{:X}: {}", addr, pattern));
                }

                detections.push(EvasionDetection {
                    pid,
                    process_name: process_name.clone(),
                    technique: EvasionTechnique::DirectSyscall,
                    confidence: 0.9,
                    severity: EvasionSeverity::High,
                    evidence,
                    address: Some(syscall_locations[0].0),
                    module_name: None,
                    mitre_id: "T1562.001",
                });
            }
        }
    }

    Ok(detections)
}

/// Find syscall/sysenter patterns in memory
fn find_syscall_patterns(data: &[u8], base_address: u64) -> Vec<(u64, String)> {
    let mut results = Vec::new();

    // Syscall patterns:
    // 0F 05          - syscall (x64)
    // 0F 34          - sysenter (x86)
    // CD 2E          - int 0x2E (legacy syscall)

    for i in 0..data.len().saturating_sub(2) {
        let addr = base_address + i as u64;

        // syscall (x64)
        if data[i] == 0x0F && data[i + 1] == 0x05 {
            // Check context - look for mov eax, <syscall_number> pattern before
            let has_mov_eax =
                i >= 5 && (data[i - 5] == 0xB8 || (data[i - 2] == 0x89 && data[i - 1] == 0xC8));
            if has_mov_eax || is_in_suspicious_context(data, i) {
                results.push((addr, "syscall (0F 05)".to_string()));
            }
        }

        // sysenter (x86)
        if data[i] == 0x0F && data[i + 1] == 0x34 {
            results.push((addr, "sysenter (0F 34)".to_string()));
        }

        // int 0x2E (legacy)
        if data[i] == 0xCD && data[i + 1] == 0x2E {
            results.push((addr, "int 0x2E (CD 2E)".to_string()));
        }
    }

    results
}

/// Check if syscall is in suspicious context (not just random bytes)
fn is_in_suspicious_context(data: &[u8], syscall_offset: usize) -> bool {
    // Look for typical syscall stub patterns:
    // mov r10, rcx (49 89 CA) - common before syscall
    // mov eax, imm32 (B8 xx xx xx xx) - syscall number
    // ret (C3) after syscall

    let start = syscall_offset.saturating_sub(20);
    let end = (syscall_offset + 10).min(data.len());
    let context = &data[start..end];

    // mov r10, rcx
    let has_mov_r10_rcx = context
        .windows(3)
        .any(|w| w == [0x49, 0x89, 0xCA] || w == [0x4C, 0x8B, 0xD1]);

    // mov eax, imm32
    let has_mov_eax = context.iter().any(|&b| b == 0xB8);

    // ret after syscall
    let rel_offset = syscall_offset - start;
    let has_ret_after = context
        .get(rel_offset + 2..rel_offset + 5)
        .map_or(false, |slice| slice.contains(&0xC3));

    has_mov_r10_rcx || (has_mov_eax && has_ret_after)
}

// =============================================================================
// SYSCALL HOOK DETECTION
// =============================================================================

/// Detects inline hooks in ntdll.dll functions
#[cfg(target_os = "windows")]
pub async fn detect_syscall_hooks(pid: u32) -> Result<Vec<EvasionDetection>> {
    use windows::Win32::Foundation::{CloseHandle, HMODULE};

    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut detections = Vec::new();
    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));

    // Critical functions to check for hooks
    let critical_functions = [
        ("NtAllocateVirtualMemory", vec![0x4C, 0x8B, 0xD1, 0xB8]), // mov r10, rcx; mov eax, <num>
        ("NtWriteVirtualMemory", vec![0x4C, 0x8B, 0xD1, 0xB8]),
        ("NtCreateThreadEx", vec![0x4C, 0x8B, 0xD1, 0xB8]),
        ("NtProtectVirtualMemory", vec![0x4C, 0x8B, 0xD1, 0xB8]),
        ("NtMapViewOfSection", vec![0x4C, 0x8B, 0xD1, 0xB8]),
        ("NtQueueApcThread", vec![0x4C, 0x8B, 0xD1, 0xB8]),
        ("NtSetContextThread", vec![0x4C, 0x8B, 0xD1, 0xB8]),
    ];

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

        // Find ntdll.dll base address
        let mut modules: Vec<HMODULE> = vec![HMODULE::default(); 256];
        let mut cb_needed = 0u32;

        if EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
        .is_ok()
        {
            let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();

            for i in 0..module_count {
                let module = modules[i];
                if module.is_invalid() {
                    continue;
                }

                let mut path_buf = vec![0u16; 512];
                let len = GetModuleFileNameExW(handle, module, &mut path_buf);
                if len == 0 {
                    continue;
                }

                let module_path = String::from_utf16_lossy(&path_buf[..len as usize]);

                if !module_path.to_lowercase().contains("ntdll.dll") {
                    continue;
                }

                // Check each critical function
                for (func_name, expected_prologue) in &critical_functions {
                    if let Some(detection) = check_function_hook(
                        handle,
                        module.0 as u64,
                        &module_path,
                        func_name,
                        expected_prologue,
                        pid,
                        &process_name,
                    )
                    .await
                    {
                        detections.push(detection);
                    }
                }

                break;
            }
        }

        CloseHandle(handle)?;
    }

    Ok(detections)
}

#[cfg(target_os = "windows")]
async fn check_function_hook(
    process_handle: windows::Win32::Foundation::HANDLE,
    module_base: u64,
    _module_path: &str,
    func_name: &str,
    expected_prologue: &[u8],
    pid: u32,
    process_name: &str,
) -> Option<EvasionDetection> {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    // Get function address from ntdll in current process (reference)
    let ntdll_name: Vec<u16> = OsStr::new("ntdll.dll")
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let local_ntdll = GetModuleHandleW(windows::core::PCWSTR(ntdll_name.as_ptr())).ok()?;
        let func_name_cstr = std::ffi::CString::new(func_name).ok()?;
        let local_func_addr =
            GetProcAddress(local_ntdll, PCSTR(func_name_cstr.as_ptr() as *const u8))?;

        // Calculate RVA
        let local_ntdll_base = local_ntdll.0 as u64;
        let func_rva = local_func_addr as u64 - local_ntdll_base;

        // Read function bytes from target process
        let target_func_addr = module_base + func_rva;
        let mut func_bytes = vec![0u8; 16];
        let mut bytes_read = 0usize;

        if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process_handle,
            target_func_addr as *const std::ffi::c_void,
            func_bytes.as_mut_ptr() as *mut std::ffi::c_void,
            func_bytes.len(),
            Some(&mut bytes_read),
        )
        .is_err()
        {
            return None;
        }

        // Check for hooks
        // Common hook patterns:
        // E9 xx xx xx xx - JMP rel32 (5 bytes)
        // FF 25 xx xx xx xx - JMP [rip+disp32] (6 bytes)
        // 48 B8 xx xx xx xx xx xx xx xx - MOV RAX, imm64 (10 bytes) + FF E0 - JMP RAX (2 bytes)

        let is_jmp_rel32 = func_bytes[0] == 0xE9;
        let is_jmp_indirect = func_bytes[0] == 0xFF && func_bytes[1] == 0x25;
        let is_mov_rax_jmp = func_bytes[0] == 0x48 && func_bytes[1] == 0xB8;

        if is_jmp_rel32 || is_jmp_indirect || is_mov_rax_jmp {
            let hook_type = if is_jmp_rel32 {
                "JMP rel32 hook"
            } else if is_jmp_indirect {
                "JMP [rip+disp] hook"
            } else {
                "MOV RAX + JMP RAX hook"
            };

            let evidence = vec![
                format!("Function: {}", func_name),
                format!("Address: 0x{:X}", target_func_addr),
                format!("Hook type: {}", hook_type),
                format!("Bytes: {:02X?}", &func_bytes[..8]),
                format!("Expected prologue: {:02X?}", expected_prologue),
            ];

            return Some(EvasionDetection {
                pid,
                process_name: process_name.to_string(),
                technique: EvasionTechnique::SyscallHook,
                confidence: 0.95,
                severity: EvasionSeverity::Critical,
                evidence,
                address: Some(target_func_addr),
                module_name: Some("ntdll.dll".to_string()),
                mitre_id: "T1562.001",
            });
        }
    }

    None
}

// =============================================================================
// EARLY BIRD INJECTION DETECTION
// =============================================================================

/// Detects Early Bird injection (APC queued to thread before execution)
#[cfg(target_os = "windows")]
pub async fn detect_early_bird(pid: u32) -> Result<Vec<EvasionDetection>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        OpenThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    };

    let mut detections = Vec::new();
    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));

    unsafe {
        // Enumerate threads
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == pid {
                    // Check thread state and context
                    if let Ok(thread_handle) = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        false,
                        thread_entry.th32ThreadID,
                    ) {
                        // Check if thread is in suspended/alertable state with queued APCs
                        // This is a heuristic - real detection would need kernel support

                        // Check thread context for suspicious instruction pointer
                        let mut context = CONTEXT::default();

                        // Set context flags based on architecture
                        #[cfg(target_arch = "x86_64")]
                        {
                            context.ContextFlags = CONTEXT_ALL_AMD64;
                        }
                        #[cfg(target_arch = "x86")]
                        {
                            context.ContextFlags = CONTEXT_ALL_X86;
                        }

                        if GetThreadContext(thread_handle, &mut context).is_ok() {
                            // Get instruction pointer based on architecture
                            #[cfg(target_arch = "x86_64")]
                            let ip = context.Rip;
                            #[cfg(target_arch = "x86")]
                            let ip = context.Eip as u64;

                            // Heuristic: IP in non-image memory is suspicious for new threads
                            if let Ok(is_suspicious) = is_rip_in_suspicious_memory(pid, ip).await {
                                if is_suspicious {
                                    let evidence = vec![
                                        format!("Thread ID: {}", thread_entry.th32ThreadID),
                                        format!("IP: 0x{:X}", ip),
                                        "Thread context points to non-image memory".to_string(),
                                        "Possible Early Bird or APC injection".to_string(),
                                    ];

                                    detections.push(EvasionDetection {
                                        pid,
                                        process_name: process_name.clone(),
                                        technique: EvasionTechnique::EarlyBird,
                                        confidence: 0.7,
                                        severity: EvasionSeverity::Critical,
                                        evidence,
                                        address: Some(ip),
                                        module_name: None,
                                        mitre_id: "T1055.004",
                                    });
                                }
                            }
                        }

                        CloseHandle(thread_handle)?;
                    }
                }

                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot)?;
    }

    Ok(detections)
}

#[cfg(target_os = "windows")]
async fn is_rip_in_suspicious_memory(pid: u32, rip: u64) -> Result<bool> {
    use super::MemoryRegionType;

    let regions = super::get_memory_regions(pid).await?;

    for region in regions {
        if rip >= region.base_address && rip < region.base_address + region.size {
            // Suspicious if in private executable memory
            if region.memory_type == MemoryRegionType::Private && region.is_executable {
                return Ok(true);
            }
            return Ok(false);
        }
    }

    // RIP not in any known region is also suspicious
    Ok(true)
}

// =============================================================================
// HEAVEN'S GATE DETECTION
// =============================================================================

/// Detects Heaven's Gate (WoW64 32-bit to 64-bit transition abuse)
#[cfg(target_os = "windows")]
pub async fn detect_heavens_gate(pid: u32) -> Result<Vec<EvasionDetection>> {
    let mut detections = Vec::new();
    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));

    // Check if process is WoW64
    if !is_wow64_process(pid).await? {
        return Ok(detections);
    }

    // Look for Heaven's Gate patterns in memory
    let regions = super::get_memory_regions(pid).await?;

    for region in regions {
        if !region.is_executable {
            continue;
        }

        if let Ok(data) =
            read_memory_region_safe(pid, region.base_address, region.size.min(65536) as usize).await
        {
            // Heaven's Gate pattern: far call/jmp to 64-bit segment
            // EA xx xx xx xx 33 00 - JMP FAR 0x33:addr (switch to 64-bit)
            // 9A xx xx xx xx 33 00 - CALL FAR 0x33:addr

            for i in 0..data.len().saturating_sub(7) {
                if (data[i] == 0xEA || data[i] == 0x9A)
                    && data[i + 5] == 0x33
                    && data[i + 6] == 0x00
                {
                    let evidence = vec![
                        format!("Address: 0x{:X}", region.base_address + i as u64),
                        format!("Pattern: {:02X?}", &data[i..i + 7]),
                        "Far JMP/CALL to 64-bit segment (0x33)".to_string(),
                        "Heaven's Gate technique for EDR bypass".to_string(),
                    ];

                    detections.push(EvasionDetection {
                        pid,
                        process_name: process_name.clone(),
                        technique: EvasionTechnique::HeavensGate,
                        confidence: 0.9,
                        severity: EvasionSeverity::High,
                        evidence,
                        address: Some(region.base_address + i as u64),
                        module_name: None,
                        mitre_id: "T1055",
                    });

                    break; // One detection per region is enough
                }
            }
        }
    }

    Ok(detections)
}

#[cfg(target_os = "windows")]
async fn is_wow64_process(pid: u32) -> Result<bool> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;
        let mut is_wow64 = windows::Win32::Foundation::BOOL(0);
        IsWow64Process(handle, &mut is_wow64)?;
        CloseHandle(handle)?;
        Ok(is_wow64.as_bool())
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn get_process_name(pid: u32) -> Option<String> {
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
                CloseHandle(handle).ok();

                if len > 0 {
                    return Some(String::from_utf16_lossy(&name_buf[..len as usize]));
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
async fn read_memory_region_safe(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    let mut buffer = vec![0u8; size];

    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, false, pid)?;
        let mut bytes_read = 0usize;

        let result = ReadProcessMemory(
            handle,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            size,
            Some(&mut bytes_read),
        );

        CloseHandle(handle)?;

        if result.is_err() {
            return Err(anyhow!("Failed to read process memory"));
        }

        buffer.truncate(bytes_read);
    }

    Ok(buffer)
}

// =============================================================================
// LINUX STUBS
// =============================================================================

#[cfg(not(target_os = "windows"))]
pub async fn detect_module_stomping(_pid: u32) -> Result<Vec<EvasionDetection>> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "windows"))]
pub async fn detect_direct_syscalls(_pid: u32) -> Result<Vec<EvasionDetection>> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "windows"))]
pub async fn detect_syscall_hooks(_pid: u32) -> Result<Vec<EvasionDetection>> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "windows"))]
pub async fn detect_early_bird(_pid: u32) -> Result<Vec<EvasionDetection>> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "windows"))]
pub async fn detect_heavens_gate(_pid: u32) -> Result<Vec<EvasionDetection>> {
    Ok(Vec::new())
}

// =============================================================================
// UNIFIED SCANNER
// =============================================================================

/// Run all evasion detection checks on a process
pub async fn scan_process_for_evasion(pid: u32) -> Result<Vec<EvasionDetection>> {
    let mut all_detections = Vec::new();

    // Run all detectors
    if let Ok(mut detections) = detect_module_stomping(pid).await {
        all_detections.append(&mut detections);
    }

    if let Ok(mut detections) = detect_direct_syscalls(pid).await {
        all_detections.append(&mut detections);
    }

    if let Ok(mut detections) = detect_syscall_hooks(pid).await {
        all_detections.append(&mut detections);
    }

    if let Ok(mut detections) = detect_early_bird(pid).await {
        all_detections.append(&mut detections);
    }

    if let Ok(mut detections) = detect_heavens_gate(pid).await {
        all_detections.append(&mut detections);
    }

    // Stack spoofing detection
    // Note: Stack spoofing detection uses its own result type (StackSpoofingDetection)
    // for richer information. Use super::stack_spoofing_detector::scan_process_for_stack_spoofing()
    // directly for full stack spoofing analysis with detailed frame information.
    // Here we provide a simplified integration that converts to EvasionDetection.
    if let Ok(stack_detections) = detect_stack_spoofing_simple(pid).await {
        all_detections.extend(stack_detections);
    }

    // Phantom DLL hollowing detection
    // Note: Phantom DLL detection uses its own result type (PhantomDllEvent)
    // for richer module-level information. Use crate::collectors::phantom_dll::scan_process_for_phantom_dlls()
    // directly for full phantom DLL analysis with module details.
    if let Ok(phantom_detections) = detect_phantom_dll_simple(pid).await {
        all_detections.extend(phantom_detections);
    }

    info!(
        pid = pid,
        detections = all_detections.len(),
        "Evasion scan completed"
    );

    Ok(all_detections)
}

/// Simplified stack spoofing detection that returns EvasionDetection
/// For full detailed stack analysis, use stack_spoofing_detector::scan_process_for_stack_spoofing()
pub async fn detect_stack_spoofing_simple(pid: u32) -> Result<Vec<EvasionDetection>> {
    use super::stack_spoofing_detector::{
        scan_process_for_stack_spoofing, SpoofingSeverity, StackSpoofingTechnique,
    };

    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));
    let mut detections = Vec::new();

    if let Ok(stack_results) = scan_process_for_stack_spoofing(pid).await {
        for result in stack_results {
            // Map stack spoofing technique to evasion technique
            let technique = match result.technique {
                StackSpoofingTechnique::StackPivot => EvasionTechnique::StackPivot,
                _ => EvasionTechnique::StackSpoofing,
            };

            // Map severity
            let severity = match result.severity {
                SpoofingSeverity::Low => EvasionSeverity::Low,
                SpoofingSeverity::Medium => EvasionSeverity::Medium,
                SpoofingSeverity::High => EvasionSeverity::High,
                SpoofingSeverity::Critical => EvasionSeverity::Critical,
            };

            detections.push(EvasionDetection {
                pid,
                process_name: process_name.clone(),
                technique,
                confidence: result.confidence,
                severity,
                evidence: result.evidence,
                address: Some(result.stack_pointer),
                module_name: None,
                mitre_id: result.mitre_id,
            });
        }
    }

    Ok(detections)
}

/// Simplified phantom DLL hollowing detection that returns EvasionDetection
/// For full detailed module analysis, use collectors::phantom_dll::scan_process_for_phantom_dlls()
pub async fn detect_phantom_dll_simple(pid: u32) -> Result<Vec<EvasionDetection>> {
    use crate::collectors::phantom_dll::{scan_process_for_phantom_dlls, PhantomIndicator};

    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));
    let mut detections = Vec::new();

    if let Ok(phantom_results) = scan_process_for_phantom_dlls(pid).await {
        for result in phantom_results {
            // Map phantom DLL indicator to severity
            let severity = match result.indicator {
                PhantomIndicator::FileDeletedAfterLoad
                | PhantomIndicator::TempPathDeleted
                | PhantomIndicator::SectionFromDeletedFile
                | PhantomIndicator::MultipleIndicators => EvasionSeverity::Critical,
                PhantomIndicator::ModuleFileNotFound => EvasionSeverity::High,
                PhantomIndicator::InvalidModulePath | PhantomIndicator::NetworkPathInaccessible => {
                    EvasionSeverity::Medium
                }
            };

            // Confidence based on indicator type
            let confidence = result.confidence;

            detections.push(EvasionDetection {
                pid,
                process_name: process_name.clone(),
                technique: EvasionTechnique::PhantomDllHollowing,
                confidence,
                severity,
                evidence: result.evidence.clone(),
                address: Some(result.module_base),
                module_name: Some(result.module_name.clone()),
                mitre_id: "T1055.012",
            });
        }
    }

    Ok(detections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_pattern_detection() {
        // Test syscall pattern (0F 05)
        let data = vec![
            0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ];
        let patterns = find_syscall_patterns(&data, 0x1000);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].0, 0x1008);
    }

    #[test]
    fn test_evasion_technique_mitre_mapping() {
        assert_eq!(EvasionTechnique::ModuleStomping.mitre_id(), "T1055.001");
        assert_eq!(EvasionTechnique::DirectSyscall.mitre_id(), "T1562.001");
        assert_eq!(EvasionTechnique::EarlyBird.mitre_id(), "T1055.004");
        assert_eq!(EvasionTechnique::StackSpoofing.mitre_id(), "T1562.001");
        assert_eq!(EvasionTechnique::StackPivot.mitre_id(), "T1055");
    }

    #[test]
    fn test_stack_spoofing_severity() {
        assert_eq!(
            EvasionTechnique::StackSpoofing.severity(),
            EvasionSeverity::Critical
        );
        assert_eq!(
            EvasionTechnique::StackPivot.severity(),
            EvasionSeverity::Critical
        );
    }

    #[test]
    fn test_phantom_dll_mitre_mapping() {
        assert_eq!(
            EvasionTechnique::PhantomDllHollowing.mitre_id(),
            "T1055.012"
        );
        assert_eq!(
            EvasionTechnique::PhantomDllHollowing.severity(),
            EvasionSeverity::Critical
        );
    }
}
