<#
.SYNOPSIS
    Validates a Tamandua Agent MSI build and an installed endpoint state.

.DESCRIPTION
    This script is intentionally repo-local and does not install global tooling.
    It can validate:
    - that the MSI file exists
    - that the WiX CLI is available
    - that the expected installer assets are present in the repo
    - that a local installation created the expected service/config layout

.PARAMETER MsiPath
    Optional path to the MSI that was produced by build.ps1

.PARAMETER ServiceName
    Windows service name to validate

.PARAMETER InstallDir
    Expected Program Files installation directory

.PARAMETER ProgramDataDir
    Expected ProgramData root

.PARAMETER ExpectedServerUrl
    Optional server URL to compare against agent.toml
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$MsiPath,

    [Parameter()]
    [string]$ServiceName = "TamanduaAgent",

    [Parameter()]
    [string]$InstallDir = (Join-Path ${env:ProgramFiles} "Tamandua"),

    [Parameter()]
    [string]$ProgramDataDir = (Join-Path ${env:ProgramData} "Tamandua"),

    [Parameter()]
    [string]$ExpectedServerUrl
)

$ErrorActionPreference = "Stop"

function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Write-Ok { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Write-Fail { Write-Host "[FAIL] $args" -ForegroundColor Red }

$failed = $false

function Assert-Path {
    param(
        [string]$Path,
        [string]$Label
    )

    if (Test-Path $Path) {
        Write-Ok "$Label found: $Path"
    }
    else {
        Write-Fail "$Label missing: $Path"
        $script:failed = $true
    }
}

function Assert-Contains {
    param(
        [string]$Value,
        [string]$Expected,
        [string]$Label
    )

    if ($Value -like "*$Expected*") {
        Write-Ok "$Label contains expected value"
    }
    else {
        Write-Fail "$Label missing expected value: $Expected"
        $script:failed = $true
    }
}

Write-Info "Validating repo-side MSI prerequisites"

$repoScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Assert-Path (Join-Path $repoScriptDir "Product.wxs") "Product.wxs"
Assert-Path (Join-Path $repoScriptDir "Service.wxs") "Service.wxs"
Assert-Path (Join-Path $repoScriptDir "write-config.ps1") "write-config.ps1"
Assert-Path (Join-Path $repoScriptDir "License.rtf") "License.rtf"

$wix = Get-Command "wix" -ErrorAction SilentlyContinue
if ($wix) {
    Write-Ok "WiX CLI available: $($wix.Source)"
}
else {
    Write-Warn "WiX CLI not found in PATH. MSI build validation is limited."
}

if ($MsiPath) {
    Assert-Path $MsiPath "MSI artifact"
}

Write-Info "Validating installed agent layout"

$agentExe = Join-Path $InstallDir "tamandua-agent.exe"
$installConfig = Join-Path $InstallDir "config\agent.toml"
$runtimeConfig = Join-Path $ProgramDataDir "config\agent.toml"

Assert-Path $InstallDir "Install directory"
Assert-Path $ProgramDataDir "ProgramData root"
Assert-Path $agentExe "Agent executable"
Assert-Path $installConfig "Installed config seed"
Assert-Path $runtimeConfig "Runtime config"
Assert-Path (Join-Path $ProgramDataDir "logs") "ProgramData logs"
Assert-Path (Join-Path $ProgramDataDir "rules") "ProgramData rules"
Assert-Path (Join-Path $ProgramDataDir "quarantine") "ProgramData quarantine"

try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    Write-Ok "Service found: $ServiceName ($($svc.State))"
    Assert-Contains $svc.PathName '--config' "Service PathName config argument"
    Assert-Contains $svc.PathName ' service' "Service PathName subcommand"
    Assert-Contains $svc.PathName 'Tamandua\config\agent.toml' "Service config path"
}
catch {
    Write-Fail "Service not found: $ServiceName"
    $failed = $true
}

if (Test-Path $runtimeConfig) {
    $config = Get-Content $runtimeConfig -Raw
    Assert-Contains $config 'auth_token = "' "agent.toml auth_token"
    Assert-Contains $config '[auth]' "agent.toml auth section"
    Assert-Contains $config 'server_url = "' "agent.toml server_url"

    if ($ExpectedServerUrl) {
        Assert-Contains $config "server_url = `"$ExpectedServerUrl`"" "agent.toml server_url exact match"
    }
}

$eventLogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\TamanduaAgent"
if (Test-Path $eventLogKey) {
    Write-Ok "Event Log source registered"
}
else {
    Write-Warn "Event Log source not found at $eventLogKey"
}

if ($failed) {
    Write-Host ""
    Write-Fail "Validation failed"
    exit 1
}

Write-Host ""
Write-Ok "Validation passed"
