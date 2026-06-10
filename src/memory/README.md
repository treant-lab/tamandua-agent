# Advanced Memory Analysis Module

Comprehensive memory forensics capabilities for the Tamandua EDR agent.

## Features

### 1. Memory Dump Acquisition
- **Full Process Dump**: Complete memory dump using platform-specific APIs
  - Windows: `MiniDumpWriteDump`
  - Linux: `/proc/[pid]/mem`
  - macOS: `mach_vm_read`
- **Selective Dumps**:
  - RWX regions only (writable + executable)
  - Private executable regions
  - Suspicious regions only
- **Compression**: zstd compression for bandwidth efficiency
- **Streaming Upload**: Direct upload to backend server

### 2. YARA Memory Scanning
- Load YARA rules from file or use built-in rules
- Scan process memory regions for malware patterns
- Built-in detection for:
  - Cobalt Strike beacons
  - Reflective DLL loading
  - Process hollowing indicators
  - Metasploit payloads
  - Common shellcode patterns
- Match metadata extraction and reporting

### 3. Suspicious Region Detection
- **RWX Memory**: Detects writable + executable regions (common injection technique)
- **Executable Private Memory**: Regions not backed by files
- **Injected DLLs**: LoadLibrary calls from suspicious locations
- **Hollowed Sections**: Entry point mismatches
- **Non-Image Executable**: Executable memory outside loaded modules
- **PE in Private Memory**: PE headers found in private allocations
- **High Entropy**: Packed or encrypted code detection

### 4. VAD Tree Analysis (Windows)
- Virtual Address Descriptor tree enumeration
- Detect private memory allocations
- Identify mapped files vs anonymous memory
- Suspicious VAD attribute detection
- Memory commit charge analysis

### 5. Import/Export Table Analysis
- **IAT Hook Detection**: Compare Import Address Table with expected values
- **Inline Hook Detection**: Detect jmp/call redirects at function entry points
- Critical function monitoring:
  - `ntdll.dll`: NtCreateFile, NtReadFile, NtWriteFile
  - `kernel32.dll`: CreateProcess, VirtualAllocEx
  - `user32.dll`: SetWindowsHookEx

### 6. Memory String Extraction
- Extract ASCII and Unicode strings
- Pattern matching for:
  - URLs (http://, https://, ftp://)
  - IP addresses
  - File paths
  - Registry keys
  - Base64-encoded data
- Relevance scoring based on:
  - String type
  - Suspicious keywords (password, token, malware, etc.)
  - Command-line indicators
  - Obfuscation patterns

## Usage

### Response Actions

#### 1. Dump Memory
```json
{
  "command_type": "dump_memory",
  "payload": {
    "pid": 1234,
    "dump_type": "suspicious",  // full, rwx, private_executable, suspicious
    "compress": true,
    "upload": true
  }
}
```

#### 2. YARA Scan
```json
{
  "command_type": "scan_memory_yara",
  "payload": {
    "pid": 1234,
    "rules_path": "/path/to/rules.yar"  // optional, uses defaults if empty
  }
}
```

#### 3. Analyze Suspicious Regions
```json
{
  "command_type": "analyze_suspicious_regions",
  "payload": {
    "pid": 1234
  }
}
```

#### 4. Analyze Memory Hooks
```json
{
  "command_type": "analyze_memory_hooks",
  "payload": {
    "pid": 1234
  }
}
```

#### 5. Extract Strings
```json
{
  "command_type": "extract_memory_strings",
  "payload": {
    "pid": 1234,
    "min_length": 4,
    "max_strings": 100
  }
}
```

#### 6. Full Memory Analysis
```json
{
  "command_type": "full_memory_analysis",
  "payload": {
    "pid": 1234,
    "process_name": "suspicious.exe"
  }
}
```

## API

### Core Functions

```rust
// Get memory regions for a process
pub async fn get_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>>

// Dump process memory
pub async fn dump_process_memory(
    pid: u32,
    regions: Vec<MemoryRegion>,
    options: &DumpOptions,
) -> Result<Vec<u8>>

// Scan memory with YARA (requires 'yara' feature)
pub async fn scan_memory_yara(
    pid: u32,
    regions: Vec<MemoryRegion>,
    rules_path: &str,
) -> Result<Vec<MemoryYaraMatch>>

// Detect suspicious regions
pub async fn detect_suspicious_regions(pid: u32) -> Result<Vec<SuspiciousRegion>>

// Analyze hooks
pub async fn analyze_hooks(pid: u32) -> Result<(Vec<IatHook>, Vec<InlineHook>)>

// Extract strings
pub async fn extract_strings(
    pid: u32,
    regions: Vec<MemoryRegion>,
    min_length: usize,
) -> Result<Vec<ExtractedString>>

// Full analysis
pub async fn analyze_memory(pid: u32, process_name: String) -> Result<MemoryAnalysisReport>
```

## Data Structures

### MemoryRegion
```rust
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: u64,
    pub protection: u32,
    pub memory_type: MemoryRegionType,
    pub module_name: Option<String>,
    pub module_path: Option<String>,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
    pub is_private: bool,
}
```

### SuspiciousRegion
```rust
pub struct SuspiciousRegion {
    pub pid: u32,
    pub process_name: String,
    pub region: MemoryRegion,
    pub reasons: Vec<SuspicionReason>,
    pub confidence: f32,
    pub details: String,
}
```

### MemoryAnalysisReport
```rust
pub struct MemoryAnalysisReport {
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub timestamp: u64,
    pub regions_scanned: usize,
    pub suspicious_regions: Vec<SuspiciousRegion>,
    pub yara_matches: Vec<MemoryYaraMatch>,
    pub iat_hooks: Vec<IatHook>,
    pub inline_hooks: Vec<InlineHook>,
    pub strings: Vec<ExtractedString>,
}
```

## Performance Considerations

1. **Region Filtering**: Skip non-executable regions for YARA scanning
2. **Size Limits**: Skip regions > 10MB for string extraction
3. **Sampling**: Use 64KB samples for entropy calculation
4. **Rate Limiting**: Max 1 full dump per minute per process
5. **Background Processing**: Long-running scans run at low priority

## Platform Support

### Windows
- Full memory dump via MiniDumpWriteDump
- VirtualQueryEx for region enumeration
- ReadProcessMemory for selective dumps
- VAD tree analysis (limited without kernel driver)
- PE parsing for IAT/EAT analysis

### Linux
- `/proc/[pid]/maps` for region enumeration
- `/proc/[pid]/mem` for memory reading
- ELF parsing for GOT/PLT analysis (future)
- Auditd integration for memory events

### macOS
- `task_for_pid` for process access
- `mach_vm_read` for memory reading
- `mach_vm_region_recurse` for region enumeration
- Mach-O parsing for symbol analysis (future)

## MITRE ATT&CK Coverage

- **T1055**: Process Injection
- **T1055.001**: Dynamic-link Library Injection
- **T1055.012**: Process Hollowing
- **T1620**: Reflective Code Loading
- **T1574.011**: DLL Side-Loading
- **T1027**: Obfuscated Files or Information
- **T1106**: Native API
- **T1071.001**: Application Layer Protocol (C2 beacons)

## Testing

Run tests with:
```bash
cargo test --features yara memory::tests
```

## Future Enhancements

1. **Kernel Driver Integration**: True VAD tree access on Windows
2. **Symbol Resolution**: Better hook detection with symbol information
3. **ELF/Mach-O Parsing**: Full support for Linux/macOS hook detection
4. **ML-Based Detection**: Anomaly detection for memory patterns
5. **Automatic Remediation**: Kill process, quarantine, or restore on detection
6. **Memory Diffing**: Compare memory snapshots over time
7. **Heap Analysis**: Detailed heap walking and allocation tracking
