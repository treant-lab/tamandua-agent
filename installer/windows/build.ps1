<#
.SYNOPSIS
    Build script for Tamandua EDR Agent Windows MSI installer.

.DESCRIPTION
    This script builds the Tamandua EDR Agent and creates an MSI installer package.
    It handles:
    - Building the Rust agent in release mode
    - Creating the configuration helper script
    - Building the MSI using WiX Toolset v4
    - Optional code signing

.PARAMETER Version
    Version number for the installer (default: reads from Cargo.toml)

.PARAMETER ServerUrl
    Default server URL to embed in the installer

.PARAMETER OutputPath
    Output directory for the MSI file

.PARAMETER Configuration
    Build configuration: Release or Debug (default: Release)

.PARAMETER SkipBuild
    Skip building the Rust agent (use existing binary)

.PARAMETER SignCert
    Path to code signing certificate (.pfx)

.PARAMETER SignPassword
    Password for the code signing certificate

.PARAMETER SignTimestamp
    Timestamp server URL for code signing

.PARAMETER WixPath
    Custom path to WiX toolset (default: searches PATH)

.EXAMPLE
    .\build.ps1 -Version "1.0.0" -ServerUrl "wss://edr.company.com/socket/agent"

.EXAMPLE
    .\build.ps1 -SkipBuild -SignCert "cert.pfx" -SignPassword $env:CERT_PASSWORD

.NOTES
    Requirements:
    - Rust toolchain (rustup)
    - WiX Toolset v4+ (https://wixtoolset.org/)
    - Visual Studio Build Tools (for signtool, optional)
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version,

    [Parameter()]
    [string]$ServerUrl = "wss://agents.tamandua.treantlab.org:8443/socket/agent",

    [Parameter()]
    [string]$OutputPath = ".\output",

    [Parameter()]
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [Parameter()]
    [switch]$SkipBuild,

    [Parameter()]
    [string]$SignCert,

    [Parameter()]
    [SecureString]$SignPassword,

    [Parameter()]
    [string]$SignTimestamp = "http://timestamp.digicert.com",

    [Parameter()]
    [string]$WixPath,

    [Parameter()]
    [switch]$Clean,

    [Parameter()]
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Script paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentRoot = (Resolve-Path "$ScriptDir\..\..").Path
$InstallerDir = $ScriptDir

# Colors for output
function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warning { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Write-Error { Write-Host "[ERROR] $args" -ForegroundColor Red }
function Write-Step { Write-Host "`n=== $args ===" -ForegroundColor Magenta }

# Get version from Cargo.toml if not specified
function Get-CargoVersion {
    $cargoPath = Join-Path $AgentRoot "Cargo.toml"
    if (Test-Path $cargoPath) {
        $content = Get-Content $cargoPath -Raw
        if ($content -match 'version\s*=\s*"([^"]+)"') {
            return $matches[1]
        }
    }
    return "0.1.0"
}

# Find WiX toolset
function Find-Wix {
    if ($WixPath -and (Test-Path $WixPath)) {
        return $WixPath
    }

    # Check if wix is in PATH
    $wix = Get-Command "wix" -ErrorAction SilentlyContinue
    if ($wix) {
        return $wix.Source
    }

    # Check common install locations
    $commonPaths = @(
        "${env:ProgramFiles}\WiX Toolset v4\bin\wix.exe",
        "${env:ProgramFiles(x86)}\WiX Toolset v4\bin\wix.exe",
        "${env:USERPROFILE}\.dotnet\tools\wix.exe",
        "${env:USERPROFILE}\.wix\wix.exe"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    # Try dotnet tool
    $dotnetWix = & dotnet tool list -g 2>$null | Select-String "wix"
    if ($dotnetWix) {
        return "wix"
    }

    return $null
}

# Sign a file with code signing certificate
function Sign-File {
    param(
        [string]$FilePath,
        [string]$Certificate,
        [SecureString]$Password,
        [string]$TimestampUrl
    )

    $signtool = Get-Command "signtool" -ErrorAction SilentlyContinue
    if (-not $signtool) {
        # Try to find signtool in Windows SDK
        $sdkPaths = @(
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
            "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
        )
        foreach ($pattern in $sdkPaths) {
            $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -Last 1
            if ($found) {
                $signtool = $found
                break
            }
        }
    }

    if (-not $signtool) {
        Write-Warning "signtool not found - skipping code signing"
        return $false
    }

    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    )

    $args = @(
        "sign",
        "/f", $Certificate,
        "/p", $plainPassword,
        "/fd", "sha256",
        "/tr", $TimestampUrl,
        "/td", "sha256",
        "/v",
        $FilePath
    )

    Write-Info "Signing: $FilePath"
    & $signtool.Source $args

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Code signing failed"
        return $false
    }

    return $true
}

# Main build process
function Build-Installer {
    Write-Step "Tamandua EDR Agent MSI Builder"

    # Determine version
    if (-not $Version) {
        $Version = Get-CargoVersion
    }
    Write-Info "Version: $Version"

    # Find WiX
    $wix = Find-Wix
    if (-not $wix) {
        Write-Error "WiX Toolset not found. Install with: dotnet tool install --global wix"
        Write-Info "Or download from: https://wixtoolset.org/"
        exit 1
    }
    Write-Info "WiX: $wix"

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $OutputPath = (Resolve-Path $OutputPath).Path

    # Clean if requested
    if ($Clean) {
        Write-Step "Cleaning"
        if (Test-Path "$AgentRoot\target") {
            Write-Info "Cleaning Rust target directory..."
            # Don't remove entire target, just the specific build
            Remove-Item "$AgentRoot\target\release\tamandua-agent.exe" -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path "$OutputPath\*.msi") {
            Write-Info "Cleaning previous MSI files..."
            Remove-Item "$OutputPath\*.msi" -Force
        }
        if (Test-Path "$InstallerDir\*.wixobj") {
            Remove-Item "$InstallerDir\*.wixobj" -Force
        }
    }

    # Build agent
    if (-not $SkipBuild) {
        Write-Step "Building Rust Agent"

        Push-Location $AgentRoot
        try {
            $cargoArgs = @("build")
            if ($Configuration -eq "Release") {
                $cargoArgs += "--release"
            }

            Write-Info "Running: cargo $($cargoArgs -join ' ')"
            & cargo $cargoArgs

            if ($LASTEXITCODE -ne 0) {
                Write-Error "Cargo build failed"
                exit 1
            }
        }
        finally {
            Pop-Location
        }
        Write-Success "Agent built successfully"
    }

    # Verify agent binary exists
    $configLower = $Configuration.ToLower()
    $agentExe = Join-Path $AgentRoot "target\$configLower\tamandua-agent.exe"
    if (-not (Test-Path $agentExe)) {
        Write-Error "Agent binary not found: $agentExe"
        Write-Info "Run without -SkipBuild to build the agent first"
        exit 1
    }
    Write-Info "Agent binary: $agentExe"

    # Validate MSI helper assets
    Write-Step "Validating Installer Assets"
    $writeConfigPath = Join-Path $InstallerDir "write-config.ps1"
    if (-not (Test-Path $writeConfigPath)) {
        Write-Error "Required helper script not found: $writeConfigPath"
        exit 1
    }
    Write-Success "Found write-config.ps1"

    # Create License.rtf if it doesn't exist
    $licensePath = Join-Path $InstallerDir "License.rtf"
    if (-not (Test-Path $licensePath)) {
        Write-Info "Creating placeholder license file..."
        $licenseContent = @"
{\rtf1\ansi\deff0
{\fonttbl{\f0 Arial;}}
\f0\fs20
Tamandua EDR Agent License Agreement\par
\par
Copyright (c) 2024 Tamandua Security. All rights reserved.\par
\par
This software is provided under the Apache License 2.0.\par
\par
Licensed under the Apache License, Version 2.0 (the "License");\par
you may not use this file except in compliance with the License.\par
You may obtain a copy of the License at\par
\par
    http://www.apache.org/licenses/LICENSE-2.0\par
\par
Unless required by applicable law or agreed to in writing, software\par
distributed under the License is distributed on an "AS IS" BASIS,\par
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\par
See the License for the specific language governing permissions and\par
limitations under the License.\par
}
"@
        Set-Content -Path $licensePath -Value $licenseContent -Encoding ASCII
    }

    # Sign agent binary if certificate provided
    if ($SignCert -and (Test-Path $SignCert)) {
        Write-Step "Signing Agent Binary"
        Sign-File -FilePath $agentExe -Certificate $SignCert -Password $SignPassword -TimestampUrl $SignTimestamp
    }

    # Build MSI
    Write-Step "Building MSI Installer"

    $msiName = "tamandua-agent-$Version.msi"
    $msiPath = Join-Path $OutputPath $msiName

    # Prepare WiX arguments
    $wixArgs = @(
        "build",
        "-d", "Version=$Version",
        "-d", "DefaultServerUrl=$ServerUrl",
        "-d", "AgentPath=$AgentRoot\target\$configLower",
        "-d", "ConfigPath=$AgentRoot\config",
        "-ext", "WixToolset.UI.wixext",
        "-ext", "WixToolset.Util.wixext",
        "-ext", "WixToolset.Firewall.wixext",
        "-arch", "x64",
        "-o", $msiPath,
        "$InstallerDir\Product.wxs",
        "$InstallerDir\Service.wxs"
    )

    Write-Info "Running: wix $($wixArgs -join ' ')"

    Push-Location $InstallerDir
    try {
        & $wix $wixArgs

        if ($LASTEXITCODE -ne 0) {
            Write-Error "WiX build failed"
            exit 1
        }
    }
    finally {
        Pop-Location
    }

    # Verify MSI was created
    if (-not (Test-Path $msiPath)) {
        Write-Error "MSI file was not created"
        exit 1
    }
    Write-Success "MSI created: $msiPath"

    # Sign MSI if certificate provided
    if ($SignCert -and (Test-Path $SignCert)) {
        Write-Step "Signing MSI Package"
        Sign-File -FilePath $msiPath -Certificate $SignCert -Password $SignPassword -TimestampUrl $SignTimestamp
    }

    # Display summary
    Write-Step "Build Complete"
    $msiInfo = Get-Item $msiPath
    Write-Host ""
    Write-Host "  Output:  $msiPath"
    Write-Host "  Size:    $([math]::Round($msiInfo.Length / 1MB, 2)) MB"
    Write-Host "  Version: $Version"
    Write-Host ""
    Write-Host "Installation Commands:"
    Write-Host ""
    Write-Host "  Interactive:  msiexec /i `"$msiPath`""
    Write-Host ""
    Write-Host "  Silent (Direct Token):"
    Write-Host "    msiexec /i `"$msiPath`" /qn SERVER_URL=`"$ServerUrl`" AGENT_TOKEN=`"<token>`""
    Write-Host ""
    Write-Host "  Silent (Enrollment - Recommended for Enterprise):"
    Write-Host "    msiexec /i `"$msiPath`" /qn ENROLLMENT_URL=`"https://edr.company.com`" ENROLLMENT_TOKEN=`"<one-time-token>`""
    Write-Host ""
    Write-Host "  Silent (with mTLS certificates):"
    Write-Host "    msiexec /i `"$msiPath`" /qn SERVER_URL=`"$ServerUrl`" AGENT_TOKEN=`"<token>`" CA_CERT_PATH=`"C:\certs\ca.pem`" CLIENT_CERT_PATH=`"C:\certs\client.pem`" CLIENT_KEY_PATH=`"C:\certs\client-key.pem`""
    Write-Host ""
    Write-Host "  Uninstall:    msiexec /x `"$msiPath`" /qn"
    Write-Host "  Validate:     powershell -ExecutionPolicy Bypass -File `"$InstallerDir\validate-installation.ps1`" -MsiPath `"$msiPath`""
    Write-Host ""
    Write-Host "Note: AGENT_TOKEN and ENROLLMENT_TOKEN are marked as Hidden and will not appear in MSI logs."
    Write-Host ""
}

# Run
Build-Installer
