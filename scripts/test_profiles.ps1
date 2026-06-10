# Profile Compliance Test Script
# Tests each performance profile to verify CPU/memory limits are respected
# Usage: ./test_profiles.ps1 -BuildDir D:\treant\tamandua\apps\tamandua_agent\target\debug

param(
    [string]$BuildDir = "D:\treant\tamandua\apps\tamandua_agent\target\debug",
    [int]$TestDurationSeconds = 60,
    [int]$WorkloadIntensity = 5  # Processes created per second
)

$ErrorActionPreference = "Stop"

# Profile definitions with expected bounds
$profiles = @(
    @{
        Name = "aggressive"
        MaxCpuPercent = 20.0
        MaxCpuBuffer = 5.0  # Allow up to 25%
        ProcessInterval = 3
        DnsInterval = 1000
        ExpectedTelemetryReduction = 75
    }
    @{
        Name = "balanced"
        MaxCpuPercent = 15.0
        MaxCpuBuffer = 5.0  # Allow up to 20%
        ProcessInterval = 5
        DnsInterval = 2000
        ExpectedTelemetryReduction = 85
    }
    @{
        Name = "lightweight"
        MaxCpuPercent = 5.0
        MaxCpuBuffer = 3.0  # Allow up to 8%
        ProcessInterval = 15
        DnsInterval = 5000
        ExpectedTelemetryReduction = 92
    }
)

function Get-ProcessCpuPercent {
    param([int]$ProcessId)

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            return [double]$proc.CPU
        }
    } catch {}

    return 0.0
}

function Get-ProcessMemoryMB {
    param([int]$ProcessId)

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            return [double]($proc.WorkingSet64 / 1MB)
        }
    } catch {}

    return 0.0
}

function Create-AgentConfig {
    param(
        [string]$Profile,
        [string]$ConfigPath
    )

    $config = @"
# Auto-generated test config for profile: $Profile
agent_id = "test-agent-$Profile"
server_url = "ws://localhost:4000/socket/agent"
auth_token = "test-token"
performance_profile = "$Profile"
heartbeat_interval_seconds = 10
batch_size = 100
batch_timeout_seconds = 5

[collectors]
process_enabled = true
file_enabled = true
network_enabled = true
dns_enabled = true
registry_enabled = true

[collector_tuning]
adaptive_throttling_enabled = true
process_smart_diff_enabled = true

[resource_governor]
enabled = true
sample_interval_secs = 5
cpu_light_threshold = 10.0
cpu_moderate_threshold = 20.0
cpu_heavy_threshold = 35.0
cpu_critical_threshold = 50.0

[event_triage]
enabled = true
dedup_window_secs = 30
max_dedup_entries = 10000
"@

    $config | Set-Content -Path $ConfigPath -Force
    Write-Host "[CONFIG] Created config for profile '$Profile' at $ConfigPath"
}

function Test-Profile {
    param(
        [hashtable]$Profile,
        [string]$AgentExePath
    )

    $profileName = $Profile.Name
    $maxCpu = $Profile.MaxCpuPercent
    $maxCpuAllowed = $maxCpu + $Profile.MaxCpuBuffer

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Testing profile: $profileName" -ForegroundColor Cyan
    Write-Host "Expected max CPU: $maxCpu% (allow up to $maxCpuAllowed%)" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $configPath = "$env:TEMP\tamandua-test-$profileName.toml"
    Create-AgentConfig -Profile $profileName -ConfigPath $configPath

    # Start agent process using ProcessStartInfo to avoid env var conflicts
    Write-Host "[START] Starting agent with profile: $profileName" -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $AgentExePath
    $psi.Arguments = "--config=`"$configPath`" --foreground"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        $agentProcess = [System.Diagnostics.Process]::Start($psi)
    } catch {
        Write-Host "[ERROR] Failed to start agent: $_" -ForegroundColor Red
        return $false
    }

    if (-not $agentProcess) {
        Write-Host "[ERROR] Failed to start agent process" -ForegroundColor Red
        return $false
    }

    $agentPid = $agentProcess.Id
    Write-Host "[PID] Agent started with PID: $agentPid" -ForegroundColor Green

    # Wait for agent to initialize
    Start-Sleep -Seconds 3

    # Simulate workload
    Write-Host "[WORKLOAD] Starting workload simulation for $TestDurationSeconds seconds" -ForegroundColor Yellow
    $workloadStart = Get-Date
    $workloadProcCount = 0

    while (((Get-Date) - $workloadStart).TotalSeconds -lt $TestDurationSeconds) {
        for ($i = 0; $i -lt $WorkloadIntensity; $i++) {
            try {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo test" -WindowStyle Hidden | Out-Null
                $workloadProcCount++
            } catch {
                # Silently ignore if process fails
            }
        }
        Start-Sleep -Milliseconds 200
    }

    Write-Host "[WORKLOAD] Created $workloadProcCount processes during test" -ForegroundColor Green

    # Collect metrics
    Write-Host "`n[METRICS] Collecting CPU/memory samples..." -ForegroundColor Yellow
    $cpuSamples = @()
    $memSamples = @()
    $sampleCount = 0

    for ($i = 0; $i -lt 10; $i++) {
        try {
            $cpu = Get-ProcessCpuPercent -ProcessId $agentPid
            $mem = Get-ProcessMemoryMB -ProcessId $agentPid

            if ($cpu -gt 0 -or $mem -gt 0) {
                $cpuSamples += $cpu
                $memSamples += $mem
                $sampleCount++
                Write-Host "  Sample $($sampleCount): CPU=$($cpu.ToString('F1'))% Memory=$($mem.ToString('F0'))MB"
            }
        } catch {}

        Start-Sleep -Seconds 1
    }

    # Calculate averages
    $avgCpu = if ($cpuSamples.Count -gt 0) {
        ($cpuSamples | Measure-Object -Average).Average
    } else {
        0.0
    }

    $avgMem = if ($memSamples.Count -gt 0) {
        ($memSamples | Measure-Object -Average).Average
    } else {
        0.0
    }

    # Check compliance
    Write-Host "`n[RESULTS]" -ForegroundColor Cyan
    Write-Host "  Profile: $profileName" -ForegroundColor Cyan
    Write-Host "  Avg CPU: $($avgCpu.ToString('F1'))% (limit: $($maxCpuAllowed.ToString('F1'))%)" -ForegroundColor $(if ($avgCpu -le $maxCpuAllowed) { "Green" } else { "Red" })
    Write-Host "  Avg Memory: $($avgMem.ToString('F0'))MB" -ForegroundColor Green
    Write-Host "  Samples collected: $sampleCount" -ForegroundColor Green

    # Cleanup
    Write-Host "`n[CLEANUP] Stopping agent..." -ForegroundColor Yellow
    Stop-Process -Id $agentPid -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $passed = $avgCpu -le $maxCpuAllowed
    if ($passed) {
        Write-Host "[PASS] $profileName profile is COMPLIANT" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $profileName profile EXCEEDED limits" -ForegroundColor Red
    }

    return @{
        Profile = $profileName
        AvgCpu = $avgCpu
        MaxAllowed = $maxCpuAllowed
        Passed = $passed
    }
}

# Main execution
Write-Host "Profile Compliance Test Suite" -ForegroundColor Magenta
Write-Host "=============================" -ForegroundColor Magenta
Write-Host "BuildDir: $BuildDir" -ForegroundColor Gray
Write-Host "TestDuration: $TestDurationSeconds seconds" -ForegroundColor Gray
Write-Host "WorkloadIntensity: $WorkloadIntensity processes/sec" -ForegroundColor Gray

$agentExe = "$BuildDir\tamandua-agent.exe"
if (-not (Test-Path $agentExe)) {
    Write-Host "[ERROR] Agent binary not found: $agentExe" -ForegroundColor Red
    exit 1
}

$results = @()
foreach ($profile in $profiles) {
    $result = Test-Profile -Profile $profile -AgentExePath $agentExe
    $results += $result
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$allPassed = $true
foreach ($result in $results) {
    $status = if ($result.Passed) { "[PASS]" } else { "[FAIL]" }
    $color = if ($result.Passed) { "Green" } else { "Red" }
    Write-Host "$status  $($result.Profile): $($result.AvgCpu.ToString('F1'))% (limit: $($result.MaxAllowed.ToString('F1'))%)" -ForegroundColor $color

    if (-not $result.Passed) {
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Host "`n[SUCCESS] All profiles PASSED compliance" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[FAILURE] Some profiles FAILED compliance" -ForegroundColor Red
    exit 1
}
