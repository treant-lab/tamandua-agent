# Admin-Only Profile Validation Script
# Run this with: powershell -NoProfile -ExecutionPolicy Bypass -File admin_profile_test.ps1

# Check admin first
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: Requires Administrator privileges" -ForegroundColor Red
    Write-Host "Run PowerShell as Administrator and try again" -ForegroundColor Yellow
    exit 1
}

Write-Host "
╔════════════════════════════════════════════════════════════════╗
║         TAMANDUA PROFILE VALIDATION (ADMIN)                   ║
║         Tier 2: Governor-Aware Interval Scaling               ║
╚════════════════════════════════════════════════════════════════╝
" -ForegroundColor Green

$BuildDir = "D:\treant\tamandua\apps\tamandua_agent\target\release"
$AgentExe = "$BuildDir\tamandua-agent.exe"
$TestDuration = 40
$Workload = 5

if (-not (Test-Path $AgentExe)) {
    Write-Host "ERROR: Agent not found at $AgentExe" -ForegroundColor Red
    exit 1
}

# Profile specs
$profiles = @(
    @{ Name = "aggressive"; MaxCpu = 20.0; Expected = @("process", "file", "dns", "network", "registry", "etw") }
    @{ Name = "balanced"; MaxCpu = 15.0; Expected = @("process", "file", "dns", "network", "registry") }
    @{ Name = "lightweight"; MaxCpu = 5.0; Expected = @("process", "file", "dns", "network", "usb") }
)

$results = @()

foreach ($profile in $profiles) {
    Write-Host "`n[TEST] $($profile.Name)" -ForegroundColor Cyan

    # Create config
    $config = @"
agent_id = "admin-test-$($profile.Name)"
server_url = "ws://localhost:4000/socket/agent"
auth_token = "test"
performance_profile = "$($profile.Name)"
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
process_smart_diff_enabled = false
"@

    $configPath = "$env:TEMP\admin-test-$($profile.Name).toml"
    $config | Set-Content -Path $configPath -Force

    # Start agent
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $AgentExe
    $psi.Arguments = "--config=`"$configPath`" --foreground"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $pid = $proc.Id
        Write-Host "  PID: $pid (Running...)" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to start agent - $_" -ForegroundColor Red
        continue
    }

    Start-Sleep -Seconds 3

    # Simulate load
    $procCount = 0
    $startTime = Get-Date
    while (((Get-Date) - $startTime).TotalSeconds -lt $TestDuration) {
        for ($i = 0; $i -lt $Workload; $i++) {
            try {
                [System.Diagnostics.Process]::Start("cmd.exe", "/c echo t") | Out-Null
                $procCount++
            } catch {}
        }
        Start-Sleep -Milliseconds 250
    }

    # Collect metrics
    $cpuSamples = @()
    $memSamples = @()

    for ($i = 0; $i -lt 6; $i++) {
        try {
            $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($p) {
                $cpuSamples += [double]$p.CPU
                $memSamples += [double]($p.WorkingSet64 / 1MB)
            }
        } catch {}
        Start-Sleep -Seconds 1
    }

    # Get output
    $output = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()

    # Stop agent
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue

    # Analyze
    $cpu = if ($cpuSamples.Count -gt 0) { ($cpuSamples | Measure-Object -Average).Average } else { 0 }
    $mem = if ($memSamples.Count -gt 0) { ($memSamples | Measure-Object -Average).Average } else { 0 }

    $hasGovernor = $output -match "Resource governor started"
    $hasPressure = $output -match "pressure.*interval|governor.*interval"

    $collectors = @()
    foreach ($exp in $profile.Expected) {
        if ($output -match $exp) {
            $collectors += $exp
        }
    }

    $passed = ($cpu -le $profile.MaxCpu) -and ($collectors.Count -ge 3)

    Write-Host "  CPU: $([math]::Round($cpu, 1))% (limit: $($profile.MaxCpu)%) - $(if ($cpu -le $profile.MaxCpu) { '[OK]' } else { '[FAIL]' })" -ForegroundColor $(if ($cpu -le $profile.MaxCpu) { 'Green' } else { 'Red' })
    Write-Host "  Memory: $([math]::Round($mem, 0))MB" -ForegroundColor Green
    Write-Host "  Governor: $(if ($hasGovernor) { 'ENABLED' } else { 'disabled' }), Pressure-aware: $(if ($hasPressure) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($hasGovernor) { 'Green' } else { 'Yellow' })
    Write-Host "  Collectors: $($collectors -join ', ') ($($collectors.Count) active)" -ForegroundColor $(if ($collectors.Count -ge 3) { 'Green' } else { 'Yellow' })

    $results += @{
        Name = $profile.Name
        Cpu = $cpu
        Memory = $mem
        Passed = $passed
        Collectors = $collectors.Count
    }

    Write-Host ""
}

# Summary
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                     SUMMARY                                    ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$allOk = $true
foreach ($r in $results) {
    $status = if ($r.Passed) { "✓ PASS" } else { "✗ FAIL" }
    $color = if ($r.Passed) { "Green" } else { "Red" }
    Write-Host "$status | $($r.Name): CPU=$([math]::Round($r.Cpu, 1))% Memory=$([math]::Round($r.Memory, 0))MB Collectors=$($r.Collectors)" -ForegroundColor $color
    if (-not $r.Passed) { $allOk = $false }
}

Write-Host ""
if ($allOk) {
    Write-Host "✓ All profiles VALIDATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "✓ Resource usage within limits" -ForegroundColor Green
    Write-Host "✓ Collectors active and functional" -ForegroundColor Green
} else {
    Write-Host "✗ Some profiles FAILED validation" -ForegroundColor Red
}

Write-Host ""
