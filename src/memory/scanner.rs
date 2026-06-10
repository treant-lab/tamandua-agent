//! YARA memory scanner
//!
//! Scans process memory with YARA rules to detect malware patterns

use super::{MemoryRegion, MemoryYaraMatch};
use anyhow::{anyhow, Result};

#[cfg(feature = "yara")]
pub async fn scan_memory_yara(
    pid: u32,
    regions: Vec<MemoryRegion>,
    rules_path: &str,
) -> Result<Vec<MemoryYaraMatch>> {
    use yara::Compiler;

    // Load YARA rules
    let mut compiler =
        Compiler::new().map_err(|e| anyhow!("Failed to create YARA compiler: {:?}", e))?;

    // Load rules from directory or file
    let rules_file = if rules_path.is_empty() {
        // Default YARA rules location
        if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\rules\\yara\\memory.yar"
        } else {
            "/var/lib/tamandua/rules/yara/memory.yar"
        }
    } else {
        rules_path
    };

    if std::path::Path::new(rules_file).exists() {
        compiler = compiler
            .add_rules_file(rules_file)
            .map_err(|e| anyhow!("Failed to add YARA rules from {}: {:?}", rules_file, e))?;
    } else {
        // Add default in-memory rules for common malware patterns
        compiler = add_default_memory_rules(compiler)?;
    }

    let rules = compiler
        .compile_rules()
        .map_err(|e| anyhow!("Failed to compile YARA rules: {:?}", e))?;

    let mut matches = Vec::new();

    // Scan each memory region
    for region in regions {
        // Skip non-executable regions for performance
        if !region.is_executable && region.memory_type != super::MemoryRegionType::Private {
            continue;
        }

        // Read memory region
        let memory_data = read_memory_region(pid, &region).await?;

        // Scan with YARA
        match rules.scan_mem(&memory_data, 30) {
            Ok(scan_results) => {
                for rule in scan_results {
                    let rule_name = rule.identifier.clone();
                    let tags: Vec<String> = rule.tags.iter().map(|t| t.to_string()).collect();

                    // Extract metadata
                    let mut metadata = serde_json::Map::new();
                    for (key, value) in rule.metadatas.iter() {
                        let val_str = format!("{:?}", value);
                        metadata.insert(key.clone(), serde_json::Value::String(val_str));
                    }

                    // Get match strings and offsets
                    for string in rule.strings.iter() {
                        for m in string.matches.iter() {
                            matches.push(MemoryYaraMatch {
                                rule_name: rule_name.clone(),
                                tags: tags.clone(),
                                metadata: serde_json::Value::Object(metadata.clone()),
                                offset: region.base_address + m.offset,
                                length: m.length,
                                region: region.clone(),
                            });
                        }
                    }

                    info!(
                        rule = %rule_name,
                        region = format!("0x{:X}", region.base_address),
                        "YARA match in memory"
                    );
                }
            }
            Err(e) => {
                warn!(
                    region = format!("0x{:X}", region.base_address),
                    error = ?e,
                    "YARA scan failed for memory region"
                );
            }
        }
    }

    info!(
        pid = pid,
        matches = matches.len(),
        "Memory YARA scan completed"
    );
    Ok(matches)
}

#[cfg(feature = "yara")]
fn add_default_memory_rules(mut compiler: yara::Compiler) -> Result<yara::Compiler> {
    // Cobalt Strike beacon patterns
    let cs_beacon_rule = r#"
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon in memory"
        severity = "high"
        mitre = "T1071.001"
    strings:
        $mz = { 4D 5A }
        $beacon1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%s"
        $beacon2 = "%02d/%02d/%02d %02d:%02d:%02d"
        $beacon3 = "127.0.0.1"
        $stager = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
    condition:
        $mz at 0 and 2 of ($beacon*, $stager)
}
"#;

    // Reflective DLL loading
    let reflective_dll_rule = r#"
rule Reflective_DLL_Loading {
    meta:
        description = "Detects reflective DLL loading in memory"
        severity = "high"
        mitre = "T1620"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $reflective1 = "ReflectiveLoader"
        $reflective2 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 14 }
        $reflective3 = { 55 89 E5 83 EC ?? 53 56 57 }
    condition:
        $mz at 0 and $pe and any of ($reflective*)
}
"#;

    // Process hollowing indicators
    let hollowing_rule = r#"
rule Process_Hollowing_Indicators {
    meta:
        description = "Detects process hollowing in memory"
        severity = "critical"
        mitre = "T1055.012"
    strings:
        $mz = { 4D 5A }
        $hollow1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 60 }
        $hollow2 = "NtUnmapViewOfSection"
        $hollow3 = "ZwUnmapViewOfSection"
        $hollow4 = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 8B FA }
    condition:
        $mz at 0 and 2 of ($hollow*)
}
"#;

    // Metasploit payloads
    let metasploit_rule = r#"
rule Metasploit_Payload {
    meta:
        description = "Detects Metasploit payload in memory"
        severity = "high"
        mitre = "T1059"
    strings:
        $msf1 = "Metasploit"
        $msf2 = "meterpreter"
        $msf3 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $msf4 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 }
        $msf5 = "core_loadlib"
        $msf6 = "stdapi_"
    condition:
        2 of them
}
"#;

    // Shellcode patterns
    let shellcode_rule = r#"
rule Shellcode_Pattern {
    meta:
        description = "Detects common shellcode patterns"
        severity = "medium"
        mitre = "T1059"
    strings:
        $shell1 = { EB ?? 5? 8? ?? ?? 31 ?? 88 ?? ?? 89 ?? ?? 8D ?? ?? }
        $shell2 = { 31 C0 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 E1 }
        $shell3 = { 6A ?? 58 99 B2 ?? CD 80 }
        $shell4 = { 48 31 FF 57 57 5E 5A 48 BF }
    condition:
        any of them
}
"#;

    compiler = compiler
        .add_rules_str(cs_beacon_rule)
        .map_err(|e| anyhow!("Failed to add Cobalt Strike rule: {:?}", e))?;

    compiler = compiler
        .add_rules_str(reflective_dll_rule)
        .map_err(|e| anyhow!("Failed to add reflective DLL rule: {:?}", e))?;

    compiler = compiler
        .add_rules_str(hollowing_rule)
        .map_err(|e| anyhow!("Failed to add hollowing rule: {:?}", e))?;

    compiler = compiler
        .add_rules_str(metasploit_rule)
        .map_err(|e| anyhow!("Failed to add Metasploit rule: {:?}", e))?;

    compiler = compiler
        .add_rules_str(shellcode_rule)
        .map_err(|e| anyhow!("Failed to add shellcode rule: {:?}", e))?;

    Ok(compiler)
}

#[cfg(not(feature = "yara"))]
pub async fn scan_memory_yara(
    _pid: u32,
    _regions: Vec<MemoryRegion>,
    _rules_path: &str,
) -> Result<Vec<MemoryYaraMatch>> {
    Err(anyhow!("YARA feature not enabled"))
}

/// Read memory region from process
#[allow(dead_code)]
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
                .map_err(|e| anyhow!("Failed to open process {}: {}", pid, e))?;

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
            .map_err(|e| anyhow!("ReadProcessMemory failed: {}", e))?;

            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file =
            File::open(&mem_path).map_err(|e| anyhow!("Failed to open {}: {}", mem_path, e))?;

        mem_file
            .seek(SeekFrom::Start(region.base_address))
            .map_err(|e| anyhow!("Failed to seek: {}", e))?;

        let mut buffer = vec![0u8; region.size as usize];
        mem_file
            .read_exact(&mut buffer)
            .map_err(|e| anyhow!("Failed to read memory: {}", e))?;

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
                return Err(anyhow!("task_for_pid failed: {}", kr));
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
                return Err(anyhow!("mach_vm_read failed: {}", kr));
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
