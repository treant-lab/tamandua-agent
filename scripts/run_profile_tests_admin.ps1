# Profile Compliance Test Runner with Admin Elevation
# Automatically elevates to admin if needed and runs profile tests

param(
    [string]$BuildDir = "D:\treant\tamandua\apps\tamandua_agent\target\debug",
    [int]$TestDurationSeconds = 60,
    [int]$WorkloadIntensity = 5
)

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "⚠️  Not running as admin. Re-launching with elevated privileges..." -ForegroundColor Yellow

    # Re-run this script as admin
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path -Parent $scriptPath
    $testScriptPath = Join-Path $scriptDir "test_profiles.ps1"

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy Bypass",
        "-File `"$testScriptPath`"",
        "-BuildDir `"$BuildDir`"",
        "-TestDurationSeconds $TestDurationSeconds",
        "-WorkloadIntensity $WorkloadIntensity"
    )

    Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs -Wait
    exit $LASTEXITCODE
}

# If we're here, we're running as admin
Write-Host "✓ Running with ADMINISTRATOR privileges" -ForegroundColor Green
Write-Host ""

# Now run the actual test script
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$testScriptPath = Join-Path $scriptDir "test_profiles.ps1"

if (-not (Test-Path $testScriptPath)) {
    Write-Host "[ERROR] Test script not found: $testScriptPath" -ForegroundColor Red
    exit 1
}

Write-Host "Running: $testScriptPath" -ForegroundColor Cyan
Write-Host "BuildDir: $BuildDir" -ForegroundColor Cyan
Write-Host "TestDuration: $TestDurationSeconds seconds" -ForegroundColor Cyan
Write-Host "WorkloadIntensity: $WorkloadIntensity processes/sec" -ForegroundColor Cyan
Write-Host ""

& $testScriptPath -BuildDir $BuildDir -TestDurationSeconds $TestDurationSeconds -WorkloadIntensity $WorkloadIntensity
