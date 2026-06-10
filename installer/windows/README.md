# Tamandua EDR Agent - Windows Installer

This directory contains the WiX-based MSI installer for the Tamandua EDR Agent.

## Prerequisites

1. **Rust Toolchain** - Install from https://rustup.rs
2. **WiX Toolset v4** - Install via dotnet:
   ```powershell
   dotnet tool install --global wix
   wix extension add WixToolset.UI.wixext
   wix extension add WixToolset.Util.wixext
   wix extension add WixToolset.Firewall.wixext
   ```
3. **Visual Studio Build Tools** (optional, for code signing)

Notes:
- The current repo MSI path is WiX v4-based.
- The installer no longer depends on `tamandua_installer_ca.dll`; configuration is written by the bundled `write-config.ps1`.
- The service is expected to run with `--config "%ProgramData%\\Tamandua\\config\\agent.toml" service`.

## Authentication Modes

The installer supports two authentication modes:

### 1. Direct Token Mode (Legacy)
Provide a pre-generated JWT token directly. Simple but less secure for large deployments.

```powershell
msiexec /i tamandua-agent.msi /qn SERVER_URL="wss://..." AGENT_TOKEN="<jwt-token>"
```

### 2. Enrollment Mode (Recommended for Enterprise)
Use a one-time enrollment token to register with the server and obtain credentials.
The server provisions the agent with a DB-backed credential and optionally mTLS certificates.

```powershell
msiexec /i tamandua-agent.msi /qn ENROLLMENT_URL="https://edr.company.com" ENROLLMENT_TOKEN="<one-time-token>"
```

**Benefits of Enrollment Mode:**
- One-time tokens can be revoked after use
- Server provisions unique agent credentials
- mTLS certificates can be automatically provisioned
- Token is bound to organization (jti/org binding)
- No need to pre-generate and distribute JWT tokens

## Building the Installer

### Basic Build

```powershell
# Build with default settings
.\build.ps1

# Build with specific version
.\build.ps1 -Version "1.0.0"

# Build with custom server URL
.\build.ps1 -Version "1.0.0" -ServerUrl "wss://edr.company.com/socket/agent"
```

### Build Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Version` | Version number | From Cargo.toml |
| `-ServerUrl` | Default server URL | `wss://localhost:4000/socket/agent` |
| `-OutputPath` | Output directory | `.\output` |
| `-Configuration` | Release or Debug | Release |
| `-SkipBuild` | Skip Rust compilation | false |
| `-SignCert` | Code signing certificate (.pfx) | none |
| `-SignPassword` | Certificate password | none |
| `-Clean` | Clean before build | false |

The build script validates repo-side assets and prints a post-build validation command.

### Code Signing

```powershell
# Build and sign with certificate
.\build.ps1 -SignCert "path\to\cert.pfx" -SignPassword (Read-Host -AsSecureString)
```

## Installation

### Interactive Installation

```powershell
# Standard install (shows UI)
msiexec /i tamandua-agent-1.0.0.msi
```

### Silent Installation

```powershell
# Minimal silent install
msiexec /i tamandua-agent-1.0.0.msi /qn

# Silent install with server configuration
msiexec /i tamandua-agent-1.0.0.msi /qn SERVER_URL="wss://edr.company.com/socket/agent" AGENT_TOKEN="your-token-here"

# Silent install with logging
msiexec /i tamandua-agent-1.0.0.msi /qn /l*v install.log SERVER_URL="wss://..." AGENT_TOKEN="..."

# Silent install to custom directory
msiexec /i tamandua-agent-1.0.0.msi /qn INSTALLFOLDER="D:\Security\Tamandua"
```

### MSI Properties

#### Core Properties

| Property | Description | Required |
|----------|-------------|----------|
| `SERVER_URL` | WebSocket URL to EDR server | Yes (unless using enrollment) |
| `AGENT_TOKEN` | Authentication token (Hidden) | For direct token mode |
| `AGENT_ID` | Custom agent UUID | No (auto-generated) |
| `ORGANIZATION_ID` | Organization identifier | No |
| `INSTALLFOLDER` | Installation directory | No |
| `INSTALL_DRIVER` | Install kernel driver (0/1) | No |

#### Enrollment Properties

| Property | Description | Required |
|----------|-------------|----------|
| `ENROLLMENT_URL` | Server base URL for enrollment | For enrollment mode |
| `ENROLLMENT_TOKEN` | One-time enrollment token (Hidden) | For enrollment mode |

#### mTLS Certificate Properties

| Property | Description | Required |
|----------|-------------|----------|
| `CA_CERT_PATH` | Path to CA certificate (.pem) | Optional |
| `CLIENT_CERT_PATH` | Path to client certificate (.pem) | Optional |
| `CLIENT_KEY_PATH` | Path to client private key (.pem) | Optional |

**Security Note:** Properties marked as `Hidden` are not written to MSI logs. Sensitive tokens
are automatically cleared from memory after use.

## Uninstallation

```powershell
# Interactive uninstall
msiexec /x tamandua-agent-1.0.0.msi

# Silent uninstall
msiexec /x tamandua-agent-1.0.0.msi /qn

# Uninstall by product code (find in registry)
msiexec /x {PRODUCT-CODE-GUID} /qn
```

## Upgrade

The installer supports automatic upgrades. Simply install the new version:

```powershell
# The old version will be automatically uninstalled
msiexec /i tamandua-agent-2.0.0.msi /qn SERVER_URL="..."
```

## File Structure

After installation:

```
C:\Program Files\Tamandua\
├── tamandua-agent.exe      # Main agent executable
├── config\
│   └── agent.toml          # Seed config copied at install time
├── logs\                   # Log directory
└── rules\
    ├── yara\               # YARA rules
    └── sigma\              # Sigma rules

C:\ProgramData\Tamandua\
├── config\
│   └── agent.toml          # Runtime configuration used by the service
├── logs\                   # Runtime logs
├── rules\                  # Downloaded rules
├── quarantine\             # Quarantined files (SYSTEM only)
├── cache\                  # Temporary cache
└── certs\                  # mTLS certificates (SYSTEM only)
    ├── ca.pem              # CA certificate (if using mTLS)
    ├── client.pem          # Client certificate
    └── client-key.pem      # Client private key
```

**Directory Permissions:**
- `quarantine\` - Restricted to SYSTEM only (no admin access)
- `certs\` - Restricted to SYSTEM only (protects private keys)

## Service Management

The agent runs as a Windows service:

```powershell
# Check service status
Get-Service TamanduaAgent

# Start service
Start-Service TamanduaAgent

# Stop service
Stop-Service TamanduaAgent

# Restart service
Restart-Service TamanduaAgent
```

Or use sc.exe:

```cmd
sc query TamanduaAgent
sc start TamanduaAgent
sc stop TamanduaAgent
```

## Troubleshooting

### Installation Logs

```powershell
# Enable verbose logging during install
msiexec /i tamandua-agent.msi /l*v install.log
```

### Service Won't Start

1. Check Windows Event Log: Application > TamanduaAgent
2. Verify runtime configuration: `%ProgramData%\Tamandua\config\agent.toml`
3. Verify service command line contains `--config` before the `service` subcommand
3. Check network connectivity to server
4. Ensure firewall rules are configured

### Agent Not Connecting

1. Verify SERVER_URL is correct (wss:// for TLS, ws:// for plain)
2. Check AGENT_TOKEN is valid
3. Review agent logs: `C:\ProgramData\Tamandua\logs\`

### Post-install Validation

```powershell
.\validate-installation.ps1 -MsiPath .\output\tamandua-agent-0.1.0.msi

# With expected server validation
.\validate-installation.ps1 -ExpectedServerUrl "wss://edr.company.com/socket/agent"
```

## WiX Files

| File | Description |
|------|-------------|
| `Product.wxs` | Main installer definition |
| `Service.wxs` | Windows service configuration |
| `UI.wxs` | Custom UI dialogs |
| `config.wxi` | Configuration variables |
| `build.ps1` | PowerShell build script |
| `validate-installation.ps1` | Repo-local MSI/install validation |
| `License.rtf` | License agreement |

## Customization

### Modify Default Settings

Edit `config.wxi` to change defaults:

```xml
<?define DefaultServerUrl = "wss://your-server.com/socket/agent" ?>
<?define ServiceName = "CustomAgentName" ?>
```

### Add Custom Components

Add files to `Product.wxs`:

```xml
<ComponentGroup Id="CustomComponents" Directory="INSTALLFOLDER">
    <Component Id="CustomFile" Guid="NEW-GUID-HERE">
        <File Source="path\to\file.ext" />
    </Component>
</ComponentGroup>
```

### Modify Service Configuration

Edit `Service.wxs` to change service behavior:

```xml
<ServiceInstall ... Start="demand" ...>  <!-- Change to manual start -->
```

## Enterprise Deployment

### Group Policy (GPO)

1. Copy MSI to network share
2. Create GPO > Computer Configuration > Software Settings > Software Installation
3. Add new package pointing to MSI
4. Configure transform (.mst) with your settings (include ENROLLMENT_URL)

### SCCM/Intune

Create deployment with command line:

```powershell
# Using enrollment (recommended)
msiexec /i tamandua-agent.msi /qn `
  ENROLLMENT_URL="https://tamandua.treantlab.org" `
  ENROLLMENT_TOKEN="%ENROLLMENT_TOKEN%" `
  SERVER_URL="wss://agents.tamandua.treantlab.org:8443/socket/agent" `
  INSTALL_DRIVER=1

# Using direct token (legacy)
msiexec /i tamandua-agent.msi /qn SERVER_URL="wss://..." AGENT_TOKEN="..."
```

**Tip for Intune:** Use a PowerShell script wrapper to securely retrieve the enrollment token
from Azure Key Vault or your secrets management system.

### Ansible/Chef/Puppet

Use the MSI with your configuration management tool's Windows package modules.

Example Ansible task:
```yaml
- name: Install Tamandua Agent
  win_package:
    path: "\\\\fileserver\\share\\tamandua-agent.msi"
    arguments: '/qn ENROLLMENT_URL="{{ tamandua_enrollment_url }}" ENROLLMENT_TOKEN="{{ tamandua_enrollment_token }}" SERVER_URL="{{ tamandua_agent_server_url }}" INSTALL_DRIVER=1'
    state: present
```

### mTLS Certificate Deployment

For environments requiring mTLS (mutual TLS), you have two options:

#### Option 1: Server-Provisioned Certificates (via Enrollment)

The enrollment endpoint can provision certificates automatically:

```json
// POST /api/v1/enrollment/exchange response
{
  "agent_id": "uuid",
  "agent_token": "jwt...",
  "jwt": "jwt...",
  "org_id": "uuid",
  "organization_id": "uuid",
  "server_url": "wss://agents.tamandua.treantlab.org:8443/socket/agent",
  "ca_certificate": "-----BEGIN CERTIFICATE-----\n...",
  "client_certificate": "-----BEGIN CERTIFICATE-----\n...",
  "client_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

#### Option 2: Pre-Deployed Certificates

Stage certificates before installation, then reference them:

```powershell
msiexec /i tamandua-agent.msi /qn `
    SERVER_URL="wss://edr.company.com/socket/agent" `
    AGENT_TOKEN="..." `
    CA_CERT_PATH="C:\Certs\tamandua-ca.pem" `
    CLIENT_CERT_PATH="C:\Certs\agent.pem" `
    CLIENT_KEY_PATH="C:\Certs\agent-key.pem"
```

The certificates will be copied to `%ProgramData%\Tamandua\certs\` with restricted permissions.

#### Certificate Requirements

| Certificate | Format | Purpose |
|-------------|--------|---------|
| CA Certificate | PEM | Verify server identity |
| Client Certificate | PEM | Agent identity (CN should match agent_id) |
| Client Key | PEM (unencrypted) | Agent private key |

**Security Notes:**
- Client key must be unencrypted (service runs as SYSTEM, no password prompt)
- Certificate directory is restricted to SYSTEM account only
- Certificates are removed on uninstall

## Security Notes

### Token Security
- `AGENT_TOKEN` and `ENROLLMENT_TOKEN` are marked as `Hidden="yes"` in the MSI
- These properties are not written to MSI installation logs
- Tokens are cleared from PowerShell memory after configuration is written
- Enrollment tokens are one-time use and should be revoked after successful enrollment

### Credential Security
- Agent token should be rotated regularly (use enrollment mode for easier rotation)
- Enrollment mode binds tokens to organization via jti (JWT ID) claim
- The server validates agent registration with organization binding

### Transport Security
- Use TLS (wss://) in production
- Consider mTLS for high-security environments (see mTLS Certificate Deployment)
- Certificate pinning is supported via the `cert_pins` configuration option

### Directory Permissions
- The agent runs as LocalSystem for full system access
- Quarantine directory is restricted to SYSTEM only
- Certificate directory is restricted to SYSTEM only (protects private keys)
- Configuration files are readable by Administrators

### GUI Installer
The Tauri-based GUI installer (`tamandua_gui`) is a separate application and does not use
these MSI properties. The GUI handles authentication through its own OAuth/SSO flow.
For automated deployments, use the MSI installer with enrollment tokens.
