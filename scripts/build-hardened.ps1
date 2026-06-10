#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build Tamandua Agent with maximum security hardening

.DESCRIPTION
    This script builds the Tamandua agent using the release-hardened profile
    with additional compiler flags for security hardening on Windows.

    Hardening features include:
    - ASLR with high entropy (64-bit address space randomization)
    - DEP/NX (Data Execution Prevention)
    - Control Flow Guard (CFG)
    - Safe SEH (Structured Exception Handling)
    - Stack overflow protection
    - Integer overflow checks
    - Full LTO and symbol stripping

.PARAMETER Target
    Target triple to build for (default: x86_64-pc-windows-msvc)

.PARAMETER Features
    Cargo features to enable (comma-separated)

.PARAMETER Clean
    Clean build artifacts before building

.EXAMPLE
    .\build-hardened.ps1
    Build for default Windows x64 target

.EXAMPLE
    .\build-hardened.ps1 -Features "yara,ml,compression" -Clean
    Build with specific features and clean first

.NOTES
    Requires:
    - Rust toolchain (1.70+)
    - Windows SDK (for linker)
    - Visual Studio Build Tools
#>

param(
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$Features = "",
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Color output helpers
function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}

# Banner
Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║         Tamandua Agent - Hardened Build Script           ║
║              Maximum Security Configuration               ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Yellow

# Verify we're in the correct directory
$scriptDir = Split-Path -Parent $PSCommandLineDefinition
$agentRoot = Split-Path -Parent $scriptDir

if (-not (Test-Path "$agentRoot\Cargo.toml")) {
    Write-Error "Cargo.toml not found. Please run from apps/tamandua_agent/scripts/"
    exit 1
}

Set-Location $agentRoot

# Check Rust toolchain
Write-Step "Verifying Rust toolchain..."
try {
    $rustVersion = rustc --version
    Write-Success "Rust toolchain: $rustVersion"
} catch {
    Write-Error "Rust toolchain not found. Install from https://rustup.rs/"
    exit 1
}

# Check for target
Write-Step "Checking target: $Target"
$installedTargets = rustup target list --installed
if ($installedTargets -notcontains $Target) {
    Write-Step "Installing target $Target..."
    rustup target add $Target
}
Write-Success "Target $Target is available"

# Clean if requested
if ($Clean) {
    Write-Step "Cleaning build artifacts..."
    cargo clean --profile release-hardened
    Write-Success "Clean complete"
}

# Set RUSTFLAGS for maximum hardening
Write-Step "Configuring security hardening flags..."

$rustFlags = @(
    # Windows-specific security hardening
    "-C", "link-arg=/DYNAMICBASE",      # Address Space Layout Randomization (ASLR)
    "-C", "link-arg=/HIGHENTROPYVA",    # High-entropy 64-bit ASLR
    "-C", "link-arg=/NXCOMPAT",         # Data Execution Prevention (DEP/NX)
    "-C", "link-arg=/GUARD:CF",         # Control Flow Guard
    "-C", "link-arg=/SAFESEH",          # Safe Structured Exception Handling (32-bit only, ignored on x64)

    # Additional hardening
    "-C", "relocation-model=pic",       # Position Independent Code
    "-C", "link-arg=/OPT:REF",          # Remove unreferenced functions/data
    "-C", "link-arg=/OPT:ICF",          # Identical COMDAT folding

    # Stack protection
    "-Z", "stack-protector=all"         # Stack canaries on all functions (requires nightly for -Z flags)
)

# Note: Some -Z flags require nightly. For stable, we skip those.
# Check if we're using nightly
$isNightly = $false
if ($rustVersion -match "nightly") {
    $isNightly = $true
    Write-Success "Detected nightly toolchain - enabling additional hardening"
} else {
    Write-Host "[i] Using stable toolchain - some hardening flags require nightly" -ForegroundColor Yellow
    # Remove nightly-only flags
    $rustFlags = $rustFlags | Where-Object { $_ -notmatch "^-Z" }
}

$env:RUSTFLAGS = $rustFlags -join " "

Write-Host @"

Hardening Configuration:
========================
Profile:        release-hardened
Target:         $Target
Features:       $($Features ? $Features : "(default)")
Toolchain:      $($isNightly ? "nightly" : "stable")

Security Flags Enabled:
- Address Space Layout Randomization (ASLR)
- High Entropy Virtual Address space (HEVA)
- Data Execution Prevention (DEP/NX)
- Control Flow Guard (CFG)
- Position Independent Code (PIC)
- Symbol stripping
- Integer overflow checks
- Panic abort (no unwinding)
- Full Link-Time Optimization (LTO)
$(if ($isNightly) { "- Stack protection (all functions)" })

"@ -ForegroundColor Cyan

# Build command
Write-Step "Building with hardened profile..."

$buildArgs = @(
    "build",
    "--profile", "release-hardened",
    "--target", $Target
)

if ($Features) {
    $buildArgs += "--features"
    $buildArgs += $Features
}

if ($Verbose) {
    $buildArgs += "--verbose"
}

Write-Host "Command: cargo $($buildArgs -join ' ')" -ForegroundColor DarkGray

try {
    $buildStart = Get-Date

    & cargo @buildArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    $buildEnd = Get-Date
    $buildTime = $buildEnd - $buildStart

    Write-Success "Build completed in $($buildTime.TotalSeconds.ToString('F2')) seconds"
} catch {
    Write-Error "Build failed: $_"
    exit 1
}

# Locate binary
$binaryPath = "target\$Target\release-hardened\tamandua-agent.exe"

if (-not (Test-Path $binaryPath)) {
    Write-Error "Binary not found at expected path: $binaryPath"
    exit 1
}

# Display binary info
Write-Step "Binary information:"
$binary = Get-Item $binaryPath
$sizeKB = [math]::Round($binary.Length / 1KB, 2)
$sizeMB = [math]::Round($binary.Length / 1MB, 2)

Write-Host @"

Binary Path:    $binaryPath
Size:           $sizeKB KB ($sizeMB MB)
Created:        $($binary.CreationTime)

"@ -ForegroundColor Gray

# Verify security features (requires dumpbin from Visual Studio)
Write-Step "Verifying security features..."
try {
    $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
    if ($dumpbin) {
        Write-Host "`nSecurity Headers:" -ForegroundColor Yellow
        & dumpbin /headers $binaryPath | Select-String -Pattern "(Dynamic base|NX compatible|Guard|High Entropy)"
        Write-Success "Security verification complete"
    } else {
        Write-Host "[i] dumpbin not found - skipping security verification" -ForegroundColor Yellow
        Write-Host "    Install Visual Studio Build Tools to enable verification" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "[i] Could not verify security features: $_" -ForegroundColor Yellow
}

# Generate checksum
Write-Step "Generating SHA256 checksum..."
$hash = Get-FileHash -Path $binaryPath -Algorithm SHA256
$hashFile = "$binaryPath.sha256"
"$($hash.Hash)  tamandua-agent.exe" | Out-File -FilePath $hashFile -Encoding ASCII
Write-Success "Checksum: $($hash.Hash.Substring(0, 16))..."
Write-Host "           Saved to: $hashFile" -ForegroundColor Gray

# Final summary
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║                  Build Successful!                        ║
╚═══════════════════════════════════════════════════════════╝

Next Steps:
-----------
1. Test the binary:
   ..\target\$Target\release-hardened\tamandua-agent.exe --version

2. Sign the binary (requires code signing certificate):
   signtool sign /sha1 <thumbprint> /tr http://timestamp.digicert.com /td sha256 /fd sha256 $binaryPath

3. Deploy to production environment

"@ -ForegroundColor Green

Write-Success "Hardened build complete!"
