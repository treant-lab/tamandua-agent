# Comprehensive Profile Validation with Admin Elevation
# Validates resource usage, collector activity, and telemetry output

param(
    [string]$BuildDir = "D:\treant\tamandua\apps\tamandua_agent\target\release",
    [int]$TestDurationSeconds = 50,
    [int]$WorkloadIntensity = 8
)

$ErrorActionPreference = "Stop"

# Check if running as admin, if not, re-launch with admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -BuildDir `"$BuildDir`" -TestDurationSeconds $TestDurationSeconds -WorkloadIntensity $WorkloadIntensity"

    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs -Wait
    exit
}

Write-Host "================================" -ForegroundColor Green
Write-Host "RUNNING WITH ADMINISTRATOR PRIVILEGES" -ForegroundColor Green
Write-Host "================================`n" -ForegroundColor Green

# Profile specifications
$profiles = @(
    @{
        Name = "aggressive"
        MaxCpuPercent = 20.0
        ExpectedProcessInterval = 3
        ExpectedDnsInterval = 1000
        ExpectedNetworkInterval = 2000
        ExpectedMinCollectors = 8
        MustInclude = @("process", "file", "dns", "network", "registry", "etw", "usb", "health")
        MustExclude = @("injection", "memory", "network_dpi", "credential_theft", "lateral_movement")
    }
    @{
        Name = "balanced"
        MaxCpuPercent = 15.0
        ExpectedProcessInterval = 5
        ExpectedDnsInterval = 2000
        ExpectedNetworkInterval = 3000
        ExpectedMinCollectors = 7
        MustInclude = @("process", "file", "dns", "network", "registry", "usb", "health")
        MustExclude = @("injection", "memory", "network_dpi", "etw", "amsi", "wmi", "credential_theft")
    }
    @{
        Name = "lightweight"
        MaxCpuPercent = 5.0
        ExpectedProcessInterval = 15
        ExpectedDnsInterval = 5000
        ExpectedNetworkInterval = 10000
        ExpectedMinCollectors = 6
        MustInclude = @("process", "file", "dns", "network", "usb", "health")
        MustExclude = @("injection", "memory", "network_dpi", "etw", "amsi", "wmi", "credential_theft", "persistence", "fim", "dlp")
    }
)

function Create-ProfileConfig {
    param([string]$Profile, [string]$ConfigPath)

    $config = @"
agent_id = "validate-$Profile"
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
process_smart_diff_enabled = false
adaptive_throttling_enabled = true

[resource_governor]
enabled = true
sample_interval_secs = 5
cpu_light_threshold = 10.0
cpu_moderate_threshold = 20.0
cpu_heavy_threshold = 35.0
cpu_critical_threshold = 50.0
"@
    $config | Set-Content -Path $ConfigPath -Force
}

function Analyze-AgentOutput {
    param([string]$Output, [hashtable]$Profile)

    $result = @{
        ActiveCollectors = @()
        DisabledCollectors = @()
        GovernorEnabled = $false
        GovernorAwareCollectors = @()
        EventsDetected = 0
        Warnings = @()
    }

    # Find active collectors
    $lines = $output -split "`n"
    foreach ($line in $lines) {
        if ($line -match "Collector initialized" -and $line -match 'collector="([^"]+)"') {
            $name = $matches[1]
            $result.ActiveCollectors += $name
        }
        if ($line -match "Collector disabled" -and $line -match 'collector="([^"]+)"') {
            $name = $matches[1]
            $result.DisabledCollectors += $name
        }
        if ($line -match "Resource governor started") {
            $result.GovernorEnabled = $true
        }
        if ($line -match "pressure-aware interval scaling") {
            if ($line -match '([a-z_]+).*collector.*started.*pressure') {
                $result.GovernorAwareCollectors += $line
            }
        }
        if ($line -match "EventType|TelemetryEvent|event_payload") {
            $result.EventsDetected++
        }
        if (($line -match "WARNING") -or ($line -match "ERROR")) {
            if (($line -match "CPU") -or ($line -match "collector") -or ($line -match "resource")) {
                $result.Warnings += $line
            }
        }
    }

    return $result
}

function Test-Profile {
    param([hashtable]$Profile, [string]$AgentExePath)

    $profileName = $Profile.Name
    $maxCpu = $Profile.MaxCpuPercent

    Write-Host "`n[$((Get-Date).ToString('HH:mm:ss'))] Testing: $profileName" -ForegroundColor Cyan
    Write-Host "Expected: Process=${($Profile.ExpectedProcessInterval)}s, DNS=${($Profile.ExpectedDnsInterval)}ms, Network=${($Profile.ExpectedNetworkInterval)}ms" -ForegroundColor Gray

    $configPath = "$env:TEMP\validate-$profileName.toml"
    Create-ProfileConfig -Profile $profileName -ConfigPath $configPath

    # Start agent
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $AgentExePath
    $psi.Arguments = "--config=`"$configPath`" --foreground"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $agentProcess = [System.Diagnostics.Process]::Start($psi)
    $agentPid = $agentProcess.Id
    Write-Host "  PID: $agentPid (Admin)" -ForegroundColor Green

    # Let agent initialize
    Start-Sleep -Seconds 4

    # Simulate workload
    Write-Host "  Workload: Creating processes..." -NoNewline
    $workloadStart = Get-Date
    $procCount = 0

    while (((Get-Date) - $workloadStart).TotalSeconds -lt $TestDurationSeconds) {
        for ($i = 0; $i -lt $WorkloadIntensity; $i++) {
            try {
                [System.Diagnostics.Process]::Start("cmd.exe", "/c echo test > nul") | Out-Null
                $procCount++
            } catch {}
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host " done ($procCount procs)" -ForegroundColor Green

    # Collect metrics
    Write-Host "  Metrics:" -ForegroundColor Gray
    $cpuSamples = @()
    $memSamples = @()

    for ($i = 0; $i -lt 8; $i++) {
        try {
            $proc = Get-Process -Id $agentPid -ErrorAction SilentlyContinue
            if ($proc) {
                $cpu = [double]$proc.CPU
                $mem = [double]($proc.WorkingSet64 / 1MB)
                $cpuSamples += $cpu
                $memSamples += $mem
            }
        } catch {}
        Start-Sleep -Seconds 1
    }

    # Get output
    $stdout = $agentProcess.StandardOutput.ReadToEnd()
    $stderr = $agentProcess.StandardError.ReadToEnd()
    $output = $stdout + $stderr

    # Stop agent
    Stop-Process -Id $agentPid -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue

    # Analyze
    $avgCpu = if ($cpuSamples.Count -gt 0) { ($cpuSamples | Measure-Object -Average).Average } else { 0 }
    $maxCpuSample = if ($cpuSamples.Count -gt 0) { ($cpuSamples | Measure-Object -Maximum).Maximum } else { 0 }
    $avgMem = if ($memSamples.Count -gt 0) { ($memSamples | Measure-Object -Average).Average } else { 0 }

    $analysis = Analyze-AgentOutput -Output $output -Profile $Profile

    # Validation
    $cpuOk = $avgCpu -le $maxCpu
    $activeOk = $analysis.ActiveCollectors.Count -ge $Profile.ExpectedMinCollectors

    # Check must-include collectors
    $missingCollectors = @()
    foreach ($must in $Profile.MustInclude) {
        if ($analysis.ActiveCollectors -notmatch $must) {
            $missingCollectors += $must
        }
    }

    # Check must-exclude collectors
    $wrongCollectors = @()
    foreach ($exclude in $Profile.MustExclude) {
        if ($analysis.ActiveCollectors -match $exclude) {
            $wrongCollectors += $exclude
        }
    }

    # Display results
    Write-Host "  Results:" -ForegroundColor Cyan
    Write-Host "    CPU: avg=$($avgCpu.ToString('F1'))% max=$($maxCpuSample.ToString('F1'))% (limit=$maxCpu%) $(if ($cpuOk) { '[OK]' } else { '[FAIL]' })" -ForegroundColor $(if ($cpuOk) { 'Green' } else { 'Red' })
    Write-Host "    Memory: avg=$($avgMem.ToString('F0'))MB" -ForegroundColor Green
    Write-Host "    Collectors: $($analysis.ActiveCollectors.Count) active $(if ($activeOk) { '[OK]' } else { '[FAIL]' })" -ForegroundColor $(if ($activeOk) { 'Green' } else { 'Red' })
    Write-Host "    Governor: $(if ($analysis.GovernorEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($analysis.GovernorEnabled) { 'Green' } else { 'Red' })
    Write-Host "    Pressure-Aware: $($analysis.GovernorAwareCollectors.Count) collectors" -ForegroundColor Green

    if ($missingCollectors.Count -gt 0) {
        Write-Host "    Missing collectors: $($missingCollectors -join ', ')" -ForegroundColor Yellow
    }
    if ($wrongCollectors.Count -gt 0) {
        Write-Host "    Wrong collectors active: $($wrongCollectors -join ', ')" -ForegroundColor Red
    }

    # Show active collectors
    Write-Host "    Active: $($analysis.ActiveCollectors -join ', ')" -ForegroundColor Gray

    $passed = $cpuOk -and $activeOk -and $missingCollectors.Count -eq 0 -and $wrongCollectors.Count -eq 0

    return @{
        Profile = $profileName
        CpuAvg = $avgCpu
        CpuMax = $maxCpuSample
        CpuLimit = $maxCpu
        CpuPassed = $cpuOk
        MemoryAvg = $avgMem
        CollectorsActive = $analysis.ActiveCollectors.Count
        CollectorsPassed = $activeOk
        MissingCollectors = $missingCollectors
        WrongCollectors = $wrongCollectors
        GovernorEnabled = $analysis.GovernorEnabled
        GovernorAwareCount = $analysis.GovernorAwareCollectors.Count
        Passed = $passed
    }
}

# Main
Write-Host "Comprehensive Profile Validation" -ForegroundColor Magenta
Write-Host "BuildDir: $BuildDir" -ForegroundColor Gray
Write-Host "Duration: $TestDurationSeconds seconds per profile" -ForegroundColor Gray
Write-Host "Workload: $WorkloadIntensity processes/sec`n" -ForegroundColor Gray

$agentExe = "$BuildDir\tamandua-agent.exe"
if (-not (Test-Path $agentExe)) {
    Write-Host "ERROR: Agent not found at $agentExe" -ForegroundColor Red
    exit 1
}

$results = @()
foreach ($profile in $profiles) {
    $result = Test-Profile -Profile $profile -AgentExePath $agentExe
    $results += $result
    Start-Sleep -Seconds 2
}

# Summary
Write-Host "`n`n" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

$allPassed = $true
foreach ($result in $results) {
    $status = if ($result.Passed) { "PASS" } else { "FAIL" }
    $color = if ($result.Passed) { "Green" } else { "Red" }

    Write-Host "`n[$status] $($result.Profile)" -ForegroundColor $color
    Write-Host "  CPU: $($result.CpuAvg.ToString('F1'))% avg, $($result.CpuMax.ToString('F1'))% max (limit: $($result.CpuLimit)%)" -ForegroundColor $(if ($result.CpuPassed) { 'Green' } else { 'Red' })
    Write-Host "  Memory: $($result.MemoryAvg.ToString('F0'))MB" -ForegroundColor Green
    Write-Host "  Collectors: $($result.CollectorsActive) active" -ForegroundColor $(if ($result.CollectorsPassed) { 'Green' } else { 'Yellow' })
    Write-Host "  Governor: $(if ($result.GovernorEnabled) { 'ENABLED' } else { 'disabled' }), $($result.GovernorAwareCount) collectors scaling" -ForegroundColor $(if ($result.GovernorEnabled) { 'Green' } else { 'Yellow' })

    if ($result.MissingCollectors.Count -gt 0) {
        Write-Host "  WARNING: Missing collectors: $($result.MissingCollectors -join ', ')" -ForegroundColor Yellow
    }
    if ($result.WrongCollectors.Count -gt 0) {
        Write-Host "  ERROR: Wrong collectors active: $($result.WrongCollectors -join ', ')" -ForegroundColor Red
        $allPassed = $false
    }

    if (-not $result.Passed) {
        $allPassed = $false
    }
}

Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "RESULT: ALL PROFILES VALIDATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "All resource limits respected, all collectors correctly active" -ForegroundColor Green
} else {
    Write-Host "RESULT: VALIDATION FAILED - See errors above" -ForegroundColor Red
}
Write-Host ("=" * 70) -ForegroundColor Cyan
