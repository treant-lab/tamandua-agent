<#
.SYNOPSIS
    Configuration writer for Tamandua EDR Agent.

.DESCRIPTION
    This script generates the agent.toml configuration file during installation.
    It is called by the MSI installer with parameters from the installation UI
    or command-line properties.

    Supports two authentication modes:
    1. Direct Token Mode: Provide AGENT_TOKEN directly
    2. Enrollment Mode: Provide ENROLLMENT_URL and ENROLLMENT_TOKEN to obtain
       credentials from the server (recommended for enterprise deployments)

.PARAMETER InstallDir
    Installation directory path

.PARAMETER ServerUrl
    WebSocket URL for the EDR server

.PARAMETER AgentToken
    Authentication token for the agent (legacy direct token mode)

.PARAMETER AgentId
    Unique agent identifier (UUID). Auto-generated if not provided.

.PARAMETER OrganizationId
    Organization identifier for multi-tenant deployments

.PARAMETER EnrollmentUrl
    Server endpoint for agent enrollment (e.g., https://edr.company.com)

.PARAMETER EnrollmentToken
    One-time enrollment token obtained from the management console

.PARAMETER CaCertPath
    Path to CA certificate for mTLS (optional, can be provisioned via enrollment)

.PARAMETER ClientCertPath
    Path to client certificate for mTLS (optional, can be provisioned via enrollment)

.PARAMETER ClientKeyPath
    Path to client private key for mTLS (optional, can be provisioned via enrollment)

.NOTES
    This script is bundled with the MSI installer and runs with SYSTEM privileges.
    Sensitive parameters (tokens, keys) are cleared from memory after use.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [Parameter()]
    [string]$AgentToken = "",

    [Parameter()]
    [string]$AgentId = "",

    [Parameter()]
    [string]$OrganizationId = "",

    [Parameter()]
    [string]$EnrollmentUrl = "",

    [Parameter()]
    [string]$EnrollmentToken = "",

    [Parameter()]
    [string]$CaCertPath = "",

    [Parameter()]
    [string]$ClientCertPath = "",

    [Parameter()]
    [string]$ClientKeyPath = ""
)

$ErrorActionPreference = "Stop"

# Generate Agent ID if not provided
if (-not $AgentId -or $AgentId -eq "") {
    $AgentId = [System.Guid]::NewGuid().ToString()
}

# Normalize paths
$InstallDir = $InstallDir.TrimEnd('\')
$configDir = Join-Path $InstallDir "config"
$programDataRoot = Join-Path $env:ProgramData "Tamandua"
$programDataConfig = Join-Path $programDataRoot "config"
$programDataCerts = Join-Path $programDataRoot "certs"

# Ensure directories exist
$directories = @(
    $configDir,
    $programDataRoot,
    $programDataConfig,
    (Join-Path $programDataRoot "logs"),
    (Join-Path $programDataRoot "rules"),
    (Join-Path $programDataRoot "rules\yara"),
    (Join-Path $programDataRoot "rules\sigma"),
    (Join-Path $programDataRoot "quarantine"),
    (Join-Path $programDataRoot "cache"),
    $programDataCerts
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# mTLS certificate paths (will be populated by enrollment or direct paths)
$effectiveCaCert = ""
$effectiveClientCert = ""
$effectiveClientKey = ""

# ==============================================================================
# Enrollment Mode: Obtain credentials from server
# ==============================================================================
if ($EnrollmentUrl -and $EnrollmentToken) {
    Write-Host "Enrollment mode: Contacting server for credentials..."

    # Collect system information for enrollment
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $computerInfo = Get-CimInstance Win32_ComputerSystem

    $agentInfo = @{
        agent_id = $AgentId
        hostname = $env:COMPUTERNAME
        os_type = "windows"
        os = "windows"
        os_version = $osInfo.Version
        os_build = $osInfo.BuildNumber
        os_name = $osInfo.Caption
        architecture = $env:PROCESSOR_ARCHITECTURE
        arch = $env:PROCESSOR_ARCHITECTURE
        domain = if ($computerInfo.PartOfDomain) { $computerInfo.Domain } else { $null }
        install_path = $InstallDir
        install_time = (Get-Date -Format "o")
        agent_version = "msi"
    }

    $enrollmentBody = @{
        token = $EnrollmentToken
        agent_info = $agentInfo
    } | ConvertTo-Json -Depth 5

    try {
        # Normalize enrollment URL
        $enrollEndpoint = $EnrollmentUrl.TrimEnd('/')
        if (-not $enrollEndpoint.EndsWith('/api/v1/enrollment/exchange')) {
            $enrollEndpoint = "$enrollEndpoint/api/v1/enrollment/exchange"
        }

        Write-Host "Enrolling with: $enrollEndpoint"

        # Use TLS 1.2+
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

        $response = Invoke-RestMethod -Uri $enrollEndpoint `
            -Method Post `
            -Body $enrollmentBody `
            -ContentType "application/json" `
            -TimeoutSec 60

        Write-Host "Enrollment successful!"

        # Extract credentials from response
        if ($response.agent_token) {
            $AgentToken = $response.agent_token
            Write-Host "  - Agent token received"
        }

        if ($response.agent_id) {
            $AgentId = $response.agent_id
            Write-Host "  - Agent ID: $AgentId"
        }

        if ($response.organization_id -and -not $OrganizationId) {
            $OrganizationId = $response.organization_id
            Write-Host "  - Organization ID: $OrganizationId"
        }

        if ($response.server_url) {
            $ServerUrl = $response.server_url
            Write-Host "  - Server URL updated: $ServerUrl"
        }

        # Handle mTLS certificates from enrollment response
        if ($response.ca_certificate) {
            $effectiveCaCert = Join-Path $programDataCerts "ca.pem"
            Set-Content -Path $effectiveCaCert -Value $response.ca_certificate -Encoding UTF8 -Force
            Write-Host "  - CA certificate saved"
        }

        if ($response.client_certificate) {
            $effectiveClientCert = Join-Path $programDataCerts "client.pem"
            Set-Content -Path $effectiveClientCert -Value $response.client_certificate -Encoding UTF8 -Force
            Write-Host "  - Client certificate saved"
        }

        if ($response.client_key) {
            $effectiveClientKey = Join-Path $programDataCerts "client-key.pem"
            Set-Content -Path $effectiveClientKey -Value $response.client_key -Encoding UTF8 -Force
            Write-Host "  - Client key saved"
        }

        # Clear sensitive response data
        $response = $null

    } catch {
        Write-Error "Enrollment failed: $($_.Exception.Message)"
        Write-Error "Response: $($_.ErrorDetails.Message)"

        # Clear sensitive data before exit
        $EnrollmentToken = $null
        $enrollmentBody = $null

        exit 1
    }

    # Clear enrollment token from memory
    $EnrollmentToken = $null
    $enrollmentBody = $null
}

# ==============================================================================
# Direct mTLS Certificate Mode: Copy provided certificates
# ==============================================================================
if ($CaCertPath -and (Test-Path $CaCertPath)) {
    $effectiveCaCert = Join-Path $programDataCerts "ca.pem"
    Copy-Item -Path $CaCertPath -Destination $effectiveCaCert -Force
    Write-Host "CA certificate copied from: $CaCertPath"
}

if ($ClientCertPath -and (Test-Path $ClientCertPath)) {
    $effectiveClientCert = Join-Path $programDataCerts "client.pem"
    Copy-Item -Path $ClientCertPath -Destination $effectiveClientCert -Force
    Write-Host "Client certificate copied from: $ClientCertPath"
}

if ($ClientKeyPath -and (Test-Path $ClientKeyPath)) {
    $effectiveClientKey = Join-Path $programDataCerts "client-key.pem"
    Copy-Item -Path $ClientKeyPath -Destination $effectiveClientKey -Force
    Write-Host "Client key copied from: $ClientKeyPath"
}

# Generate configuration content
$config = @"
# Tamandua Agent Configuration
# ============================
# Generated during installation on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# Installation directory: $InstallDir

# Unique agent identifier (must be a valid UUID)
agent_id = "$AgentId"

# Backend server URL (WebSocket endpoint)
server_url = "$ServerUrl"

# Authentication token for backend communication
auth_token = "$AgentToken"

[auth]
jwt = "$AgentToken"

# Organization ID for multi-tenant deployments
$(if ($OrganizationId) { "organization_id = `"$OrganizationId`"" } else { "# organization_id = `"`"" })

# Heartbeat interval in seconds
heartbeat_interval_seconds = 30

# Telemetry batching configuration
batch_size = 100
batch_timeout_seconds = 5

# Reconnection settings
reconnect_delay_seconds = 5
max_reconnect_attempts = 0  # 0 = infinite

# Connection timeout in seconds
connection_timeout_seconds = 30

# Enable local analysis pipeline
local_analysis_enabled = true

# Enable YARA scanning (requires yara feature)
yara_enabled = false

# Enable entropy-based packed/encrypted file detection
entropy_check_enabled = true
entropy_threshold = 7.2

# Paths to exclude from monitoring
excluded_paths = [
    "C:\\Windows\\WinSxS",
    "C:\\Windows\\Installer",
    "C:\\Windows\\SoftwareDistribution",
    "C:\\Windows\\Temp",
    "C:\\`$Recycle.Bin",
]

# Processes to exclude from monitoring
excluded_processes = [
    "System Idle Process",
    "System",
    "Registry",
    "Memory Compression",
]

# File patterns to monitor for new executables
monitored_file_patterns = [
    "*.exe",
    "*.dll",
    "*.ps1",
    "*.bat",
    "*.cmd",
    "*.vbs",
    "*.js",
    "*.hta",
    "*.scr",
    "*.msi",
    "*.msp",
]

# Honeyfile monitoring (ransomware detection)
honeyfiles_enabled = false
honeyfile_paths = []

# Transport configuration
[transport]
backup_servers = []
cert_pins = []

# TLS configuration
[tls]
enabled = true
skip_verify = false
$(if ($effectiveCaCert) { "ca_cert = `"$($effectiveCaCert -replace '\\', '\\\\')`"" } else { "# ca_cert = `"`"" })
$(if ($effectiveClientCert) { "client_cert = `"$($effectiveClientCert -replace '\\', '\\\\')`"" } else { "# client_cert = `"`"" })
$(if ($effectiveClientKey) { "client_key = `"$($effectiveClientKey -replace '\\', '\\\\')`"" } else { "# client_key = `"`"" })

# Collector configuration
[collectors]
# Core collectors
process_enabled = true
file_enabled = true
network_enabled = true
dns_enabled = true

# Advanced detection collectors
injection_enabled = true
named_pipes_enabled = true
usb_enabled = true
ransomware_canary_enabled = true
driver_blocklist_enabled = true
memory_enabled = true
network_dpi_enabled = true
network_anomaly_enabled = true
cloud_enabled = false
exploit_mitigation_enabled = true
defense_evasion_enabled = true
persistence_enabled = true
script_inspector_enabled = true
credential_theft_enabled = true
lateral_movement_enabled = true
container_enabled = false
process_hollowing_enabled = true
scheduled_tasks_enabled = true
firmware_enabled = false
clipboard_enabled = false
browser_protection_enabled = true
input_capture_enabled = true
office_email_enabled = false
ad_monitor_enabled = true
health_enabled = true
syscall_evasion_enabled = true

# Windows-specific collectors
registry_enabled = true
etw_enabled = true
amsi_enabled = true
lsass_enabled = true
wmi_enabled = true
clr_enabled = true

# Linux-specific collectors (ignored on Windows)
ebpf_enabled = false
"@

# Write configuration to both locations
$configPath = Join-Path $configDir "agent.toml"
$programDataPath = Join-Path $programDataConfig "agent.toml"

try {
    # Write to installation directory
    Set-Content -Path $configPath -Value $config -Encoding UTF8 -Force
    Write-Host "Configuration written to: $configPath"

    # Write to ProgramData (runtime location)
    Set-Content -Path $programDataPath -Value $config -Encoding UTF8 -Force
    Write-Host "Configuration written to: $programDataPath"

    # Set permissions on ProgramData directory
    $acl = Get-Acl $programDataRoot

    # Remove inheritance
    $acl.SetAccessRuleProtection($true, $false)

    # Clear existing rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

    # Add SYSTEM full control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($systemRule)

    # Add Administrators full control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)

    # Apply ACL
    Set-Acl -Path $programDataRoot -AclObject $acl
    Write-Host "Permissions configured for: $programDataRoot"

    # Special restrictive permissions for quarantine directory
    $quarantineDir = Join-Path $programDataRoot "quarantine"
    $quarantineAcl = Get-Acl $quarantineDir
    $quarantineAcl.SetAccessRuleProtection($true, $false)
    $quarantineAcl.Access | ForEach-Object { $quarantineAcl.RemoveAccessRule($_) } | Out-Null
    $quarantineAcl.AddAccessRule($systemRule)
    Set-Acl -Path $quarantineDir -AclObject $quarantineAcl
    Write-Host "Restrictive permissions set on quarantine directory"

    # Special restrictive permissions for certs directory (SYSTEM only)
    $certsAcl = Get-Acl $programDataCerts
    $certsAcl.SetAccessRuleProtection($true, $false)
    $certsAcl.Access | ForEach-Object { $certsAcl.RemoveAccessRule($_) } | Out-Null
    $certsAcl.AddAccessRule($systemRule)
    Set-Acl -Path $programDataCerts -AclObject $certsAcl
    Write-Host "Restrictive permissions set on certificates directory"

    Write-Host ""
    Write-Host "Configuration Summary:"
    Write-Host "  Agent ID:     $AgentId"
    Write-Host "  Server URL:   $ServerUrl"
    Write-Host "  Install Dir:  $InstallDir"
    if ($effectiveCaCert) { Write-Host "  CA Cert:      $effectiveCaCert" }
    if ($effectiveClientCert) { Write-Host "  Client Cert:  $effectiveClientCert" }
    if ($effectiveClientKey) { Write-Host "  Client Key:   $effectiveClientKey" }
    Write-Host ""
    Write-Host "Configuration complete."

    # Clear sensitive variables from memory
    $AgentToken = $null
    $EnrollmentToken = $null
    [System.GC]::Collect()

    exit 0
}
catch {
    # Clear sensitive variables on error
    $AgentToken = $null
    $EnrollmentToken = $null
    [System.GC]::Collect()

    Write-Error "Failed to write configuration: $_"
    exit 1
}
