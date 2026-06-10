# Memory Analysis Examples

## Command Examples

### 1. Quick Suspicious Region Check
Fastest way to check for obvious injection techniques:

```bash
# From backend CLI
tamandua-cli memory analyze-suspicious --pid 1234

# Response
{
  "pid": 1234,
  "suspicious_regions": [
    {
      "pid": 1234,
      "process_name": "notepad.exe",
      "region": {
        "base_address": "0x10000000",
        "size": 4096,
        "protection": 64,
        "memory_type": "private",
        "is_executable": true,
        "is_writable": true
      },
      "reasons": ["rwx_memory", "executable_private"],
      "confidence": 0.85,
      "details": "RWX private memory at 0x10000000"
    }
  ],
  "count": 1
}
```

### 2. Full Memory Dump (Production Use)
Dump only suspicious regions to minimize data transfer:

```bash
tamandua-cli memory dump --pid 1234 --type suspicious --compress

# Response
{
  "pid": 1234,
  "dump_type": "suspicious",
  "dump_size": 245760,  # compressed size
  "regions_dumped": 3,
  "compressed": true,
  "uploaded": true
}
```

### 3. YARA Scan for Known Malware
Scan memory with custom YARA rules:

```bash
tamandua-cli memory yara-scan --pid 1234 --rules /opt/yara/malware.yar

# Response
{
  "pid": 1234,
  "matches": [
    {
      "rule_name": "CobaltStrike_Beacon",
      "tags": ["malware", "c2"],
      "metadata": {
        "description": "Detects Cobalt Strike beacon in memory",
        "severity": "high"
      },
      "offset": "0x10000ABC",
      "length": 256,
      "region": {
        "base_address": "0x10000000",
        "size": 65536,
        "memory_type": "private"
      }
    }
  ],
  "match_count": 1
}
```

### 4. Hook Detection
Find API hooks (common rootkit/malware technique):

```bash
tamandua-cli memory analyze-hooks --pid 1234

# Response
{
  "pid": 1234,
  "iat_hooks": [
    {
      "module": "ntdll.dll",
      "function": "NtCreateFile",
      "expected_address": "0x7FFE12340000",
      "actual_address": "0x12340000",
      "hook_target": "unknown.dll"
    }
  ],
  "inline_hooks": [
    {
      "module": "kernel32.dll",
      "function": "CreateProcessW",
      "address": "0x7FFE00010000",
      "bytes": [0xE9, 0x12, 0x34, 0x56, 0x78],
      "disassembly": "jmp 0x12345678",
      "target_address": "0x12345678"
    }
  ],
  "iat_hook_count": 1,
  "inline_hook_count": 1
}
```

### 5. String Extraction
Extract suspicious strings from memory:

```bash
tamandua-cli memory strings --pid 1234 --min-length 6 --max 50

# Response
{
  "pid": 1234,
  "strings": [
    {
      "content": "http://malicious-c2.com/beacon",
      "string_type": "url",
      "address": "0x10000100",
      "region": {
        "base_address": "0x10000000",
        "memory_type": "private"
      },
      "relevance": 0.95
    },
    {
      "content": "password=admin123",
      "string_type": "ascii",
      "address": "0x10000200",
      "relevance": 0.85
    },
    {
      "content": "192.168.1.100",
      "string_type": "ip_address",
      "address": "0x10000300",
      "relevance": 0.80
    }
  ],
  "count": 50
}
```

### 6. Full Memory Analysis
Comprehensive analysis (may take several minutes):

```bash
tamandua-cli memory analyze --pid 1234 --process notepad.exe

# Response
{
  "report": {
    "pid": 1234,
    "process_name": "notepad.exe",
    "timestamp": 1677734400,
    "regions_scanned": 127,
    "suspicious_regions": [...],
    "yara_matches": [...],
    "iat_hooks": [...],
    "inline_hooks": [...],
    "strings": [...]
  },
  "summary": {
    "regions_scanned": 127,
    "suspicious_regions": 3,
    "yara_matches": 1,
    "iat_hooks": 1,
    "inline_hooks": 2,
    "top_strings": 50
  }
}
```

## Automation Examples

### 1. Scheduled Memory Scan
Scan high-risk processes every hour:

```yaml
# config/memory_scan_schedule.yaml
scheduled_scans:
  - name: "Browser Memory Scan"
    processes: ["chrome.exe", "firefox.exe", "msedge.exe"]
    scan_type: "suspicious_regions"
    interval: "1h"

  - name: "System Process Monitor"
    processes: ["svchost.exe", "lsass.exe"]
    scan_type: "full"
    interval: "6h"
```

### 2. Alert-Triggered Analysis
Automatically analyze memory when suspicious behavior detected:

```json
{
  "alert_rules": [
    {
      "name": "Injection Detected",
      "trigger": "process_injection_event",
      "actions": [
        {
          "type": "memory_analysis",
          "dump_type": "suspicious",
          "yara_scan": true,
          "quarantine_on_match": true
        }
      ]
    }
  ]
}
```

### 3. Hunt for Specific Indicators
Search all processes for specific patterns:

```python
# Python script using Tamandua API
import tamandua_client as tc

client = tc.Client("https://tamandua-server:4000")

# Hunt for Cobalt Strike in all processes
processes = client.processes.list()

for proc in processes:
    try:
        results = client.memory.yara_scan(
            pid=proc.pid,
            rules="cobalt_strike_beacon.yar"
        )

        if results.matches:
            print(f"[!] Cobalt Strike detected in {proc.name} (PID: {proc.pid})")

            # Dump and quarantine
            client.memory.dump(proc.pid, type="full", upload=True)
            client.response.kill_process(proc.pid)

    except Exception as e:
        print(f"[!] Failed to scan {proc.name}: {e}")
```

## Real-World Detection Scenarios

### Scenario 1: Process Hollowing Detection
```bash
# Detect hollowed process
tamandua-cli memory analyze-suspicious --pid 2468

# Output shows:
# - Suspicious region: PE header in private memory
# - Reason: hollowed_section
# - Confidence: 0.9
# - Details: Entry point mismatch, SizeOfImage mismatch

# Follow-up with full dump
tamandua-cli memory dump --pid 2468 --type full --upload

# Kill the process
tamandua-cli response kill-process --pid 2468 --force
```

### Scenario 2: DLL Injection Detection
```bash
# Check for injected DLLs
tamandua-cli memory analyze-suspicious --pid 3142

# Output shows:
# - Suspicious region: Injected DLL
# - Module: evil.dll
# - Path: C:\Users\Public\Temp\evil.dll
# - Confidence: 0.8

# Dump the DLL region
tamandua-cli memory dump --pid 3142 --type suspicious

# Submit to sandbox
tamandua-cli sandbox submit --file evil.dll --source memory --pid 3142
```

### Scenario 3: Reflective Loading Detection
```bash
# YARA scan detects reflective DLL
tamandua-cli memory yara-scan --pid 1856

# Match: Reflective_DLL_Loading
# Region: Private memory at 0x20000000

# Extract strings for IOCs
tamandua-cli memory strings --pid 1856 --min-length 8

# Found:
# - http://attacker-c2.com/payload
# - "ReflectiveLoader"
# - "NtQueryVirtualMemory"

# Full analysis and isolation
tamandua-cli memory analyze --pid 1856
tamandua-cli response isolate-network --pid 1856
```

## Performance Benchmarks

### Memory Dump Times
- **Suspicious regions only**: 1-3 seconds (typical 3-5 regions, ~100KB)
- **RWX regions**: 2-5 seconds (typical 10-15 regions, ~500KB)
- **Private executable**: 3-10 seconds (typical 20-30 regions, ~2MB)
- **Full dump**: 10-60 seconds (depends on process size, 100MB-2GB)

### YARA Scan Times
- **Executable regions only**: 5-15 seconds (typical 50MB scanned)
- **All regions**: 30-120 seconds (typical 500MB scanned)
- **With compression**: +20% overhead

### String Extraction
- **64KB sample per region**: 0.5-2 seconds per region
- **Typical process (100 regions)**: 30-60 seconds
- **Filtered by relevance**: Returns top 100 strings in 1-2 seconds

## Best Practices

1. **Start with suspicious regions**: Fastest, catches 90% of injections
2. **Use YARA for known threats**: Leverage existing threat intel
3. **Full dumps only when needed**: High overhead, use for forensics
4. **Automate response**: Kill process + dump + upload for confirmed threats
5. **Rate limit scans**: Max 1 full scan per process per hour
6. **Monitor performance**: Memory analysis is CPU-intensive
7. **Archive dumps**: Keep for 90 days minimum for forensic analysis
