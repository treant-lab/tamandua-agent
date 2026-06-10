//! USB device control collector
//!
//! Monitors USB device connections, disconnections, and device class changes.
//! Supports device whitelisting by VID/PID and blocking of unauthorized devices.
//!
//! Features:
//! - Device allow/block-listing by VID/PID, class, or serial
//! - Write protection for mass storage devices
//! - Device group policies (IT, Developer, Standard, Kiosk, etc.)
//! - Removable media encryption detection
//! - Real-time policy enforcement
//!
//! Windows: Uses SetupAPI and CM_* functions
//! Linux: Monitors /sys/bus/usb/devices via sysfs polling

// USB device control collector. Platform-specific config fields and helper
// parameters are intentionally kept for upcoming policy enforcement paths.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent, UsbDeviceEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// USB device class codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbDeviceClass {
    /// Mass storage devices (USB drives, external HDDs)
    MassStorage,
    /// Human Interface Devices (keyboards, mice)
    Hid,
    /// Network adapters (USB Ethernet, WiFi dongles)
    NetworkAdapter,
    /// Audio devices
    Audio,
    /// Video devices (webcams)
    Video,
    /// Communications devices (modems)
    Communications,
    /// Printer devices
    Printer,
    /// Hub devices
    Hub,
    /// Smart card readers
    SmartCard,
    /// Wireless controllers (Bluetooth adapters)
    WirelessController,
    /// Unknown or other device class
    Unknown,
}

impl UsbDeviceClass {
    /// Create from USB class code
    pub fn from_class_code(class: u8, subclass: u8, protocol: u8) -> Self {
        match class {
            0x01 => Self::Audio,
            0x02 => Self::Communications,
            0x03 => Self::Hid,
            0x06 => Self::Video,
            0x07 => Self::Printer,
            0x08 => Self::MassStorage,
            0x09 => Self::Hub,
            0x0B => Self::SmartCard,
            0xE0 if subclass == 0x01 && protocol == 0x01 => Self::WirelessController,
            0xFF => {
                // Vendor specific - check subclass for network adapters
                if subclass == 0x01 || subclass == 0x06 {
                    Self::NetworkAdapter
                } else {
                    Self::Unknown
                }
            }
            _ => Self::Unknown,
        }
    }

    /// Check if this device class is considered high-risk
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            Self::MassStorage | Self::NetworkAdapter | Self::WirelessController
        )
    }
}

// ============================================================================
// Device Group Policies
// ============================================================================

/// Device group for policy-based access control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceGroup {
    /// IT administrators - full access
    ITAdmin,
    /// Developers - allow dev-related devices
    Developer,
    /// Standard users - restricted access
    #[default]
    Standard,
    /// Kiosk/shared machines - very restricted
    Kiosk,
    /// Executive - business-class access
    Executive,
    /// Custom group with name
    Custom(u32),
}

/// Write protection mode for storage devices
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WriteProtectionMode {
    /// No write protection - full read/write access
    #[default]
    None,
    /// Read-only mode - block all writes
    ReadOnly,
    /// Audit only - log writes but allow them
    AuditOnly,
    /// Block executable writes - allow data, block .exe/.dll etc
    BlockExecutables,
}

/// Encryption status of removable media
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionStatus {
    /// Unknown encryption status
    Unknown,
    /// Not encrypted
    NotEncrypted,
    /// Encrypted with BitLocker
    BitLocker,
    /// Encrypted with VeraCrypt/TrueCrypt
    VeraCrypt,
    /// Encrypted with FileVault
    FileVault,
    /// LUKS encryption (Linux)
    Luks,
    /// Other encryption detected
    OtherEncryption,
}

/// Policy for a specific device group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGroupPolicy {
    /// Device group this policy applies to
    pub group: DeviceGroup,
    /// Allowed device classes
    pub allowed_classes: HashSet<UsbDeviceClass>,
    /// Blocked device classes (takes precedence)
    pub blocked_classes: HashSet<UsbDeviceClass>,
    /// Allowed VID:PID patterns
    pub allowed_devices: HashSet<String>,
    /// Blocked VID:PID patterns
    pub blocked_devices: HashSet<String>,
    /// Write protection mode for mass storage
    pub write_protection: WriteProtectionMode,
    /// Require encryption for mass storage
    pub require_encryption: bool,
    /// Maximum allowed storage size in GB (0 = unlimited)
    pub max_storage_size_gb: u64,
    /// Allow network adapters
    pub allow_network_adapters: bool,
    /// Allow wireless controllers (Bluetooth)
    pub allow_wireless: bool,
    /// Log all device events (even allowed)
    pub audit_all: bool,
}

impl Default for DeviceGroupPolicy {
    fn default() -> Self {
        Self {
            group: DeviceGroup::Standard,
            allowed_classes: HashSet::from([
                UsbDeviceClass::Hid,
                UsbDeviceClass::Hub,
                UsbDeviceClass::Audio,
            ]),
            blocked_classes: HashSet::new(),
            allowed_devices: HashSet::new(),
            blocked_devices: HashSet::new(),
            write_protection: WriteProtectionMode::None,
            require_encryption: false,
            max_storage_size_gb: 0,
            allow_network_adapters: false,
            allow_wireless: false,
            audit_all: true,
        }
    }
}

impl DeviceGroupPolicy {
    /// Create policy for IT Admins - full access
    pub fn it_admin() -> Self {
        Self {
            group: DeviceGroup::ITAdmin,
            allowed_classes: HashSet::from([
                UsbDeviceClass::MassStorage,
                UsbDeviceClass::Hid,
                UsbDeviceClass::Hub,
                UsbDeviceClass::Audio,
                UsbDeviceClass::Video,
                UsbDeviceClass::NetworkAdapter,
                UsbDeviceClass::WirelessController,
                UsbDeviceClass::SmartCard,
                UsbDeviceClass::Communications,
                UsbDeviceClass::Printer,
            ]),
            blocked_classes: HashSet::new(),
            allowed_devices: HashSet::new(),
            blocked_devices: HashSet::new(),
            write_protection: WriteProtectionMode::None,
            require_encryption: false,
            max_storage_size_gb: 0,
            allow_network_adapters: true,
            allow_wireless: true,
            audit_all: true,
        }
    }

    /// Create policy for Developers - dev-focused access
    pub fn developer() -> Self {
        Self {
            group: DeviceGroup::Developer,
            allowed_classes: HashSet::from([
                UsbDeviceClass::MassStorage,
                UsbDeviceClass::Hid,
                UsbDeviceClass::Hub,
                UsbDeviceClass::Audio,
                UsbDeviceClass::Video,
                UsbDeviceClass::Communications, // For serial devices
            ]),
            blocked_classes: HashSet::new(),
            allowed_devices: HashSet::new(),
            blocked_devices: HashSet::new(),
            write_protection: WriteProtectionMode::AuditOnly,
            require_encryption: false,
            max_storage_size_gb: 128,
            allow_network_adapters: true,
            allow_wireless: false,
            audit_all: true,
        }
    }

    /// Create policy for Kiosk mode - very restricted
    pub fn kiosk() -> Self {
        Self {
            group: DeviceGroup::Kiosk,
            allowed_classes: HashSet::from([UsbDeviceClass::Hid, UsbDeviceClass::Hub]),
            blocked_classes: HashSet::from([
                UsbDeviceClass::MassStorage,
                UsbDeviceClass::NetworkAdapter,
                UsbDeviceClass::WirelessController,
            ]),
            allowed_devices: HashSet::new(),
            blocked_devices: HashSet::new(),
            write_protection: WriteProtectionMode::ReadOnly,
            require_encryption: true,
            max_storage_size_gb: 0,
            allow_network_adapters: false,
            allow_wireless: false,
            audit_all: true,
        }
    }

    /// Check if a device is allowed by this policy
    pub fn is_device_allowed(&self, device: &UsbDevice) -> PolicyDecision {
        let vid_pid = device.vid_pid_string();

        // Check explicit blocks first
        if self.blocked_devices.contains(&vid_pid) {
            return PolicyDecision::Blocked {
                reason: "Device explicitly blocked by policy".to_string(),
            };
        }

        // Check VID wildcard blocks
        let vid_wildcard = format!("{:04X}:*", device.vid);
        if self.blocked_devices.contains(&vid_wildcard) {
            return PolicyDecision::Blocked {
                reason: "Vendor explicitly blocked by policy".to_string(),
            };
        }

        // Check blocked classes
        if self.blocked_classes.contains(&device.device_class) {
            return PolicyDecision::Blocked {
                reason: format!("Device class {:?} blocked by policy", device.device_class),
            };
        }

        // Check explicit allows
        if self.allowed_devices.contains(&vid_pid) || self.allowed_devices.contains(&vid_wildcard) {
            return PolicyDecision::Allowed;
        }

        // Check allowed classes
        if self.allowed_classes.contains(&device.device_class) {
            // Additional checks for specific device types
            if device.device_class == UsbDeviceClass::NetworkAdapter && !self.allow_network_adapters
            {
                return PolicyDecision::Blocked {
                    reason: "Network adapters not allowed for this group".to_string(),
                };
            }
            if device.device_class == UsbDeviceClass::WirelessController && !self.allow_wireless {
                return PolicyDecision::Blocked {
                    reason: "Wireless controllers not allowed for this group".to_string(),
                };
            }
            return PolicyDecision::Allowed;
        }

        // Safety guard: NEVER block HID (keyboards, mice) or Hub devices
        // even if they are classified as Unknown due to detection heuristics.
        // Blocking a hub can disable all downstream devices including keyboard/mouse.
        if device.device_class == UsbDeviceClass::Hid || device.device_class == UsbDeviceClass::Hub
        {
            return PolicyDecision::Allowed;
        }

        // Also check hardware ID for hub/HID patterns that the heuristic may have missed
        let path_upper = device.device_path.to_uppercase();
        if path_upper.contains("ROOT_HUB")
            || path_upper.contains("USB_HUB")
            || path_upper.contains("CLASS_09")
            || path_upper.contains("CLASS_03")
        {
            return PolicyDecision::Allowed;
        }

        // Default deny for unlisted devices
        PolicyDecision::Blocked {
            reason: format!("Device class {:?} not in allowed list", device.device_class),
        }
    }

    /// Get write protection mode for a device
    pub fn get_write_mode(&self, device: &UsbDevice) -> WriteProtectionMode {
        if device.device_class != UsbDeviceClass::MassStorage {
            return WriteProtectionMode::None;
        }
        self.write_protection
    }
}

/// Policy decision result
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Device is allowed
    Allowed,
    /// Device is blocked with reason
    Blocked { reason: String },
    /// Device allowed but with write protection
    AllowedReadOnly { reason: String },
    /// Device allowed but requires encryption
    RequiresEncryption,
}

/// USB policy manager - handles device group policies
#[derive(Debug)]
pub struct UsbPolicyManager {
    /// Policies by device group
    policies: HashMap<DeviceGroup, DeviceGroupPolicy>,
    /// Current device group for this endpoint
    current_group: DeviceGroup,
    /// Active write-protected devices
    write_protected_devices: HashSet<String>,
    /// Encryption enforcement results
    encryption_checks: HashMap<String, EncryptionStatus>,
}

impl Default for UsbPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbPolicyManager {
    /// Create a new policy manager with default policies
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(DeviceGroup::ITAdmin, DeviceGroupPolicy::it_admin());
        policies.insert(DeviceGroup::Developer, DeviceGroupPolicy::developer());
        policies.insert(DeviceGroup::Standard, DeviceGroupPolicy::default());
        policies.insert(DeviceGroup::Kiosk, DeviceGroupPolicy::kiosk());

        Self {
            policies,
            current_group: DeviceGroup::Standard,
            write_protected_devices: HashSet::new(),
            encryption_checks: HashMap::new(),
        }
    }

    /// Set the current device group for this endpoint
    pub fn set_device_group(&mut self, group: DeviceGroup) {
        self.current_group = group;
        info!(group = ?group, "USB policy group changed");
    }

    /// Add or update a policy for a device group
    pub fn set_policy(&mut self, policy: DeviceGroupPolicy) {
        self.policies.insert(policy.group, policy);
    }

    /// Get the current policy
    pub fn current_policy(&self) -> &DeviceGroupPolicy {
        self.policies
            .get(&self.current_group)
            .or_else(|| self.policies.get(&DeviceGroup::Standard))
            .expect("USB policy engine must have at least a Standard policy")
    }

    /// Evaluate a device against current policy
    pub fn evaluate_device(&self, device: &UsbDevice) -> PolicyDecision {
        self.current_policy().is_device_allowed(device)
    }

    /// Check if write protection should be applied
    pub fn should_write_protect(&self, device: &UsbDevice) -> bool {
        matches!(
            self.current_policy().get_write_mode(device),
            WriteProtectionMode::ReadOnly | WriteProtectionMode::BlockExecutables
        )
    }

    /// Check if writes should be audited
    pub fn should_audit_writes(&self, device: &UsbDevice) -> bool {
        matches!(
            self.current_policy().get_write_mode(device),
            WriteProtectionMode::AuditOnly
        )
    }

    /// Apply write protection to a device
    pub async fn apply_write_protection(&mut self, device: &UsbDevice) -> anyhow::Result<()> {
        let mode = self.current_policy().get_write_mode(device);

        match mode {
            WriteProtectionMode::None => Ok(()),
            WriteProtectionMode::ReadOnly => {
                Self::set_device_read_only(device, true).await?;
                self.write_protected_devices
                    .insert(device.device_path.clone());
                info!(
                    vid = format!("{:04X}", device.vid),
                    pid = format!("{:04X}", device.pid),
                    "Applied read-only protection to USB storage"
                );
                Ok(())
            }
            WriteProtectionMode::AuditOnly => {
                // Just mark for auditing, don't block
                debug!(
                    vid = format!("{:04X}", device.vid),
                    pid = format!("{:04X}", device.pid),
                    "USB storage in audit mode - writes will be logged"
                );
                Ok(())
            }
            WriteProtectionMode::BlockExecutables => {
                // This requires a file system filter driver on Windows
                // For now, we'll log the intent
                warn!(
                    vid = format!("{:04X}", device.vid),
                    pid = format!("{:04X}", device.pid),
                    "Executable blocking requires kernel driver - falling back to audit mode"
                );
                Ok(())
            }
        }
    }

    /// Remove write protection from a device
    pub async fn remove_write_protection(&mut self, device: &UsbDevice) -> anyhow::Result<()> {
        if self.write_protected_devices.remove(&device.device_path) {
            Self::set_device_read_only(device, false).await?;
            info!(
                vid = format!("{:04X}", device.vid),
                pid = format!("{:04X}", device.pid),
                "Removed read-only protection from USB storage"
            );
        }
        Ok(())
    }

    /// Check encryption status of a mass storage device
    pub async fn check_encryption(&mut self, device: &UsbDevice) -> EncryptionStatus {
        if device.device_class != UsbDeviceClass::MassStorage {
            return EncryptionStatus::Unknown;
        }

        let status = Self::detect_encryption(device).await;
        self.encryption_checks
            .insert(device.device_path.clone(), status);
        status
    }

    /// Check if encryption is required but not present
    pub async fn requires_encryption(&mut self, device: &UsbDevice) -> bool {
        if !self.current_policy().require_encryption {
            return false;
        }

        if device.device_class != UsbDeviceClass::MassStorage {
            return false;
        }

        let status = self.check_encryption(device).await;
        matches!(
            status,
            EncryptionStatus::NotEncrypted | EncryptionStatus::Unknown
        )
    }

    /// Set a device to read-only mode
    #[cfg(target_os = "windows")]
    async fn set_device_read_only(device: &UsbDevice, read_only: bool) -> anyhow::Result<()> {
        use std::process::Command;

        // On Windows, we need to use diskpart or PowerShell to set read-only
        // This requires finding the disk number from the device path

        // First, try to find the disk number using PowerShell
        let ps_script = format!(
            r#"
            $disk = Get-Disk | Where-Object {{ $_.SerialNumber -eq '{}' -or $_.FriendlyName -like '*{}*' }}
            if ($disk) {{
                Set-Disk -Number $disk.Number -IsReadOnly ${}
                Write-Output "OK"
            }} else {{
                Write-Output "DISK_NOT_FOUND"
            }}
            "#,
            device.serial.as_deref().unwrap_or(""),
            device.product.as_deref().unwrap_or(""),
            if read_only { "$true" } else { "$false" }
        );

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &ps_script,
            ])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("OK") {
            Ok(())
        } else if stdout.contains("DISK_NOT_FOUND") {
            // Fallback: Set registry key for StorageDevicePolicies
            Self::set_storage_write_protect_registry(read_only)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to set read-only: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn set_storage_write_protect_registry(enable: bool) -> anyhow::Result<()> {
        use std::process::Command;

        let value = if enable { "1" } else { "0" };
        let output = Command::new("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                "/v",
                "WriteProtect",
                "/t",
                "REG_DWORD",
                "/d",
                value,
                "/f",
            ])
            .output()?;

        if output.status.success() {
            info!(enable = enable, "Set storage write protect registry key");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to set registry: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(target_os = "linux")]
    async fn set_device_read_only(device: &UsbDevice, read_only: bool) -> anyhow::Result<()> {
        // On Linux, we can use blockdev --setro/--setrw
        // First, find the block device for this USB device

        let block_device = Self::find_linux_block_device(device).await?;

        let arg = if read_only { "--setro" } else { "--setrw" };
        let output = tokio::process::Command::new("blockdev")
            .args([arg, &block_device])
            .output()
            .await?;

        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "blockdev failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(target_os = "linux")]
    async fn find_linux_block_device(device: &UsbDevice) -> anyhow::Result<String> {
        // Find block device under /sys/bus/usb/devices/X-X/X-X:1.0/host*/target*/*/block/
        let sysfs_path = std::path::Path::new(&device.device_path);

        // Look for block devices
        for entry in walkdir::WalkDir::new(sysfs_path)
            .max_depth(6)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.parent().map(|p| p.ends_with("block")).unwrap_or(false) {
                if let Some(name) = path.file_name() {
                    return Ok(format!("/dev/{}", name.to_string_lossy()));
                }
            }
        }

        Err(anyhow::anyhow!("Block device not found for USB device"))
    }

    #[cfg(target_os = "macos")]
    async fn set_device_read_only(device: &UsbDevice, read_only: bool) -> anyhow::Result<()> {
        // macOS doesn't have a simple way to set devices read-only
        // Would need to use a kernel extension or custom mount options
        warn!(
            vid = format!("{:04X}", device.vid),
            pid = format!("{:04X}", device.pid),
            read_only = read_only,
            "Write protection not fully supported on macOS"
        );
        Err(anyhow::anyhow!("Write protection not supported on macOS"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    async fn set_device_read_only(_device: &UsbDevice, _read_only: bool) -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "Write protection not supported on this platform"
        ))
    }

    /// Detect encryption on a storage device
    #[cfg(target_os = "windows")]
    async fn detect_encryption(device: &UsbDevice) -> EncryptionStatus {
        use std::process::Command;

        // Check for BitLocker
        let ps_script = r#"
            $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
            foreach ($vol in $volumes) {
                if ($vol.ProtectionStatus -eq 'On') {
                    Write-Output "BITLOCKER:$($vol.MountPoint)"
                }
            }
        "#;

        if let Ok(output) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("BITLOCKER:") {
                return EncryptionStatus::BitLocker;
            }
        }

        // Check for VeraCrypt by looking for mounted volumes
        if let Ok(output) = Command::new("veracrypt").args(["-t", "-l"]).output() {
            if output.status.success() && !output.stdout.is_empty() {
                return EncryptionStatus::VeraCrypt;
            }
        }

        // If we can read the device but found no encryption markers
        EncryptionStatus::NotEncrypted
    }

    #[cfg(target_os = "linux")]
    async fn detect_encryption(device: &UsbDevice) -> EncryptionStatus {
        // Check for LUKS header
        if let Ok(block_dev) = Self::find_linux_block_device(device).await {
            let output = tokio::process::Command::new("cryptsetup")
                .args(["isLuks", &block_dev])
                .output()
                .await;

            if let Ok(o) = output {
                if o.status.success() {
                    return EncryptionStatus::Luks;
                }
            }
        }

        // Check for VeraCrypt
        if let Ok(output) = tokio::process::Command::new("veracrypt")
            .args(["-t", "-l"])
            .output()
            .await
        {
            if output.status.success() && !output.stdout.is_empty() {
                return EncryptionStatus::VeraCrypt;
            }
        }

        EncryptionStatus::NotEncrypted
    }

    #[cfg(target_os = "macos")]
    async fn detect_encryption(device: &UsbDevice) -> EncryptionStatus {
        use std::process::Command;

        // Check for FileVault/APFS encryption
        let output = Command::new("diskutil")
            .args(["info", &device.device_path])
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("Encrypted: Yes") || stdout.contains("FileVault: Yes") {
                return EncryptionStatus::FileVault;
            }
        }

        EncryptionStatus::NotEncrypted
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    async fn detect_encryption(_device: &UsbDevice) -> EncryptionStatus {
        EncryptionStatus::Unknown
    }

    /// Export current policies as JSON
    pub fn export_policies(&self) -> serde_json::Value {
        serde_json::json!({
            "current_group": self.current_group,
            "policies": self.policies.iter().map(|(group, policy)| {
                (format!("{:?}", group), serde_json::json!({
                    "allowed_classes": policy.allowed_classes.iter()
                        .map(|c| format!("{:?}", c))
                        .collect::<Vec<_>>(),
                    "blocked_classes": policy.blocked_classes.iter()
                        .map(|c| format!("{:?}", c))
                        .collect::<Vec<_>>(),
                    "write_protection": policy.write_protection,
                    "require_encryption": policy.require_encryption,
                    "max_storage_size_gb": policy.max_storage_size_gb,
                }))
            }).collect::<HashMap<_, _>>(),
            "write_protected_devices": self.write_protected_devices.len(),
        })
    }
}

/// USB device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    /// Vendor ID
    pub vid: u16,
    /// Product ID
    pub pid: u16,
    /// Device class
    pub device_class: UsbDeviceClass,
    /// Serial number (if available)
    pub serial: Option<String>,
    /// Manufacturer string
    pub manufacturer: Option<String>,
    /// Product string
    pub product: Option<String>,
    /// Bus number
    pub bus: u8,
    /// Device address on bus
    pub address: u8,
    /// Device path (system-specific)
    pub device_path: String,
    /// USB speed (e.g., "1.5 Mbps", "480 Mbps", "5000 Mbps")
    pub speed: Option<String>,
    /// Number of interfaces
    pub interface_count: u8,
    /// Is device authorized (Linux specific)
    pub is_authorized: bool,
}

impl UsbDevice {
    /// Create a VID:PID string for whitelisting
    pub fn vid_pid_string(&self) -> String {
        format!("{:04X}:{:04X}", self.vid, self.pid)
    }

    /// Check if device matches a whitelist entry
    pub fn matches_whitelist(&self, whitelist: &HashSet<String>) -> bool {
        // Check exact VID:PID match
        if whitelist.contains(&self.vid_pid_string()) {
            return true;
        }

        // Check VID wildcard (e.g., "8086:*" for all Intel devices)
        let vid_wildcard = format!("{:04X}:*", self.vid);
        if whitelist.contains(&vid_wildcard) {
            return true;
        }

        // Check class-based whitelist (e.g., "class:hid")
        let class_entry = format!("class:{:?}", self.device_class).to_lowercase();
        if whitelist.contains(&class_entry) {
            return true;
        }

        false
    }
}

/// USB event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbEventType {
    /// Device connected
    Connected,
    /// Device disconnected
    Disconnected,
    /// Device blocked (unauthorized)
    Blocked,
    /// Device authorized (whitelisted)
    Authorized,
}

/// USB event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEvent {
    /// Event type
    pub event_type: UsbEventType,
    /// Device information
    pub device: UsbDevice,
    /// Whether device was blocked
    pub blocked: bool,
    /// Block reason (if blocked)
    pub block_reason: Option<String>,
}

/// USB device whitelist configuration
#[derive(Debug, Clone, Default)]
pub struct UsbWhitelist {
    /// Whitelisted VID:PID combinations or class patterns
    entries: HashSet<String>,
    /// Whether to block non-whitelisted devices
    enforce_whitelist: bool,
    /// Whether to allow HID devices by default
    allow_hid_by_default: bool,
    /// Whether to allow hubs by default
    allow_hubs_by_default: bool,
}

impl UsbWhitelist {
    /// Create a new whitelist
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
            enforce_whitelist: false,
            allow_hid_by_default: true,
            allow_hubs_by_default: true,
        }
    }

    /// Add a whitelist entry (VID:PID, VID:*, or class:xxx)
    pub fn add(&mut self, entry: String) {
        self.entries.insert(entry.to_uppercase());
    }

    /// Check if device is allowed
    pub fn is_allowed(&self, device: &UsbDevice) -> bool {
        if !self.enforce_whitelist {
            return true;
        }

        // Always allow hubs if configured
        if self.allow_hubs_by_default && device.device_class == UsbDeviceClass::Hub {
            return true;
        }

        // Always allow HID if configured
        if self.allow_hid_by_default && device.device_class == UsbDeviceClass::Hid {
            return true;
        }

        device.matches_whitelist(&self.entries)
    }

    /// Enable whitelist enforcement
    pub fn set_enforce(&mut self, enforce: bool) {
        self.enforce_whitelist = enforce;
    }
}

/// USB device collector with policy-based enforcement
pub struct UsbCollector {
    config: AgentConfig,
    whitelist: UsbWhitelist,
    policy_manager: Arc<RwLock<UsbPolicyManager>>,
    known_devices: HashMap<String, UsbDevice>,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl UsbCollector {
    /// Create a new USB collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Initialize whitelist from config (if available in future)
        let whitelist = UsbWhitelist::new();
        let policy_manager = Arc::new(RwLock::new(UsbPolicyManager::new()));

        let collector = Self {
            config: config.clone(),
            whitelist,
            policy_manager: policy_manager.clone(),
            known_devices: HashMap::new(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            Self::monitor_loop(tx, config_clone, policy_manager).await;
        });

        collector
    }

    /// Set whitelist entries
    pub fn set_whitelist(&mut self, entries: Vec<String>, enforce: bool) {
        self.whitelist = UsbWhitelist::new();
        self.whitelist.set_enforce(enforce);
        for entry in entries {
            self.whitelist.add(entry);
        }
    }

    /// Get a reference to the policy manager
    pub fn policy_manager(&self) -> Arc<RwLock<UsbPolicyManager>> {
        self.policy_manager.clone()
    }

    /// Set the device group for policy enforcement
    pub async fn set_device_group(&self, group: DeviceGroup) {
        let mut manager = self.policy_manager.write().await;
        manager.set_device_group(group);
    }

    /// Update a device group policy
    pub async fn update_policy(&self, policy: DeviceGroupPolicy) {
        let mut manager = self.policy_manager.write().await;
        manager.set_policy(policy);
    }

    /// Get current policy status as JSON
    pub async fn get_policy_status(&self) -> serde_json::Value {
        let manager = self.policy_manager.read().await;
        manager.export_policies()
    }

    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        policy_manager: Arc<RwLock<UsbPolicyManager>>,
    ) {
        let mut known_devices: HashMap<String, UsbDevice> = HashMap::new();

        // Initial scan
        let current = Self::enumerate_devices().await;
        for device in &current {
            known_devices.insert(device.device_path.clone(), device.clone());
            debug!(
                vid = format!("{:04X}", device.vid),
                pid = format!("{:04X}", device.pid),
                product = ?device.product,
                "Initial USB device found"
            );
        }

        info!(count = known_devices.len(), "USB collector initialized");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));

        loop {
            interval.tick().await;

            let current = Self::enumerate_devices().await;
            let current_paths: HashSet<String> =
                current.iter().map(|d| d.device_path.clone()).collect();

            // Check for new devices
            for device in &current {
                if !known_devices.contains_key(&device.device_path) {
                    // New device connected - evaluate against policy
                    let mut manager = policy_manager.write().await;
                    let decision = manager.evaluate_device(device);

                    let (should_block, block_reason) = match &decision {
                        PolicyDecision::Allowed => (false, None),
                        PolicyDecision::Blocked { reason } => (true, Some(reason.clone())),
                        PolicyDecision::AllowedReadOnly { reason } => {
                            // Apply write protection
                            if let Err(e) = manager.apply_write_protection(device).await {
                                warn!(error = %e, "Failed to apply write protection");
                            }
                            (false, Some(format!("Read-only: {}", reason)))
                        }
                        PolicyDecision::RequiresEncryption => {
                            // Check encryption status
                            if manager.requires_encryption(device).await {
                                (true, Some("Unencrypted storage not allowed".to_string()))
                            } else {
                                (false, None)
                            }
                        }
                    };
                    drop(manager); // Release lock

                    // Block device if not allowed
                    if should_block {
                        if let Err(e) = Self::block_device(device).await {
                            error!(
                                error = %e,
                                vid = format!("{:04X}", device.vid),
                                pid = format!("{:04X}", device.pid),
                                reason = ?block_reason,
                                "Failed to block USB device"
                            );
                        } else {
                            info!(
                                vid = format!("{:04X}", device.vid),
                                pid = format!("{:04X}", device.pid),
                                product = ?device.product,
                                reason = ?block_reason,
                                "Blocked USB device by policy"
                            );
                        }
                    } else if device.device_class == UsbDeviceClass::MassStorage {
                        // Log allowed storage device
                        info!(
                            vid = format!("{:04X}", device.vid),
                            pid = format!("{:04X}", device.pid),
                            product = ?device.product,
                            "Mass storage device allowed by policy"
                        );
                    }

                    let event = Self::create_event_with_reason(
                        device,
                        UsbEventType::Connected,
                        should_block,
                        block_reason,
                    );

                    if tx.send(event).await.is_err() {
                        warn!("USB event channel closed");
                        return;
                    }

                    known_devices.insert(device.device_path.clone(), device.clone());
                }
            }

            // Check for removed devices
            let removed: Vec<String> = known_devices
                .keys()
                .filter(|path| !current_paths.contains(*path))
                .cloned()
                .collect();

            for path in removed {
                if let Some(device) = known_devices.remove(&path) {
                    // Remove write protection if it was applied
                    let mut manager = policy_manager.write().await;
                    let _ = manager.remove_write_protection(&device).await;
                    drop(manager);

                    let event = Self::create_event(&device, UsbEventType::Disconnected, false);
                    if tx.send(event).await.is_err() {
                        warn!("USB event channel closed");
                        return;
                    }
                }
            }
        }
    }

    fn create_event_with_reason(
        device: &UsbDevice,
        event_type: UsbEventType,
        blocked: bool,
        reason: Option<String>,
    ) -> TelemetryEvent {
        let severity = match (&event_type, device.device_class.is_high_risk(), blocked) {
            (_, _, true) => Severity::High,
            (UsbEventType::Connected, true, false) => Severity::Medium,
            (UsbEventType::Connected, false, false) => Severity::Low,
            (UsbEventType::Disconnected, _, _) => Severity::Info,
            (UsbEventType::Blocked, _, _) => Severity::High,
            (UsbEventType::Authorized, _, _) => Severity::Info,
        };

        // Determine the appropriate EventType based on USB event
        let telemetry_event_type = match (&event_type, blocked) {
            (_, true) => EventType::UsbBlocked,
            (UsbEventType::Connected, false) => EventType::UsbConnect,
            (UsbEventType::Disconnected, false) => EventType::UsbDisconnect,
            (UsbEventType::Blocked, _) => EventType::UsbBlocked,
            (UsbEventType::Authorized, _) => EventType::UsbConnect,
        };

        // Create the USB device event payload
        let usb_payload = UsbDeviceEvent {
            event_type: format!("{:?}", event_type).to_lowercase(),
            vid: device.vid,
            pid: device.pid,
            device_class: format!("{:?}", device.device_class),
            serial: device.serial.clone(),
            manufacturer: device.manufacturer.clone(),
            product: device.product.clone(),
            bus: device.bus,
            address: device.address,
            device_path: device.device_path.clone(),
            speed: device.speed.clone(),
            blocked,
            block_reason: reason.clone(),
        };

        let mut event = TelemetryEvent::new(
            telemetry_event_type,
            severity,
            EventPayload::Usb(usb_payload),
        );

        // Add metadata for easier querying
        event
            .metadata
            .insert("event_category".to_string(), "usb_device".to_string());
        event
            .metadata
            .insert("vid".to_string(), format!("{:04X}", device.vid));
        event
            .metadata
            .insert("pid".to_string(), format!("{:04X}", device.pid));
        event.metadata.insert(
            "device_class".to_string(),
            format!("{:?}", device.device_class),
        );

        // Add detection for high-risk or blocked devices
        if blocked {
            event.add_detection(Detection {
                detection_type: DetectionType::UsbThreat,
                rule_name: "usb_policy_violation".to_string(),
                confidence: 1.0,
                description: format!(
                    "USB device blocked by policy: {} (VID:{:04X} PID:{:04X}) - {}",
                    device.product.as_deref().unwrap_or("Unknown"),
                    device.vid,
                    device.pid,
                    reason.as_deref().unwrap_or("Policy violation")
                ),
                mitre_tactics: vec!["initial-access".to_string(), "exfiltration".to_string()],
                mitre_techniques: vec!["T1091".to_string(), "T1052.001".to_string()],
            });
        } else if device.device_class.is_high_risk() {
            event.add_detection(Detection {
                detection_type: DetectionType::UsbThreat,
                rule_name: "high_risk_usb_device".to_string(),
                confidence: 0.5,
                description: format!(
                    "High-risk USB device connected: {:?} - {} (VID:{:04X} PID:{:04X})",
                    device.device_class,
                    device.product.as_deref().unwrap_or("Unknown"),
                    device.vid,
                    device.pid
                ),
                mitre_tactics: vec!["initial-access".to_string()],
                mitre_techniques: vec!["T1091".to_string()],
            });
        }

        event
    }

    fn create_event(device: &UsbDevice, event_type: UsbEventType, blocked: bool) -> TelemetryEvent {
        let severity = match (&event_type, device.device_class.is_high_risk(), blocked) {
            (_, _, true) => Severity::High,
            (UsbEventType::Connected, true, false) => Severity::Medium,
            (UsbEventType::Connected, false, false) => Severity::Low,
            (UsbEventType::Disconnected, _, _) => Severity::Info,
            (UsbEventType::Blocked, _, _) => Severity::High,
            (UsbEventType::Authorized, _, _) => Severity::Info,
        };

        let block_reason = if blocked {
            Some("Device not in whitelist".to_string())
        } else {
            None
        };

        // Determine the appropriate EventType based on USB event
        let telemetry_event_type = match (&event_type, blocked) {
            (_, true) => EventType::UsbBlocked,
            (UsbEventType::Connected, false) => EventType::UsbConnect,
            (UsbEventType::Disconnected, false) => EventType::UsbDisconnect,
            (UsbEventType::Blocked, _) => EventType::UsbBlocked,
            (UsbEventType::Authorized, _) => EventType::UsbConnect,
        };

        // Create the USB device event payload
        let usb_payload = UsbDeviceEvent {
            event_type: format!("{:?}", event_type).to_lowercase(),
            vid: device.vid,
            pid: device.pid,
            device_class: format!("{:?}", device.device_class),
            serial: device.serial.clone(),
            manufacturer: device.manufacturer.clone(),
            product: device.product.clone(),
            bus: device.bus,
            address: device.address,
            device_path: device.device_path.clone(),
            speed: device.speed.clone(),
            blocked,
            block_reason: block_reason.clone(),
        };

        let mut event = TelemetryEvent::new(
            telemetry_event_type,
            severity,
            EventPayload::Usb(usb_payload),
        );

        // Add metadata for easier querying
        event
            .metadata
            .insert("event_category".to_string(), "usb_device".to_string());
        event
            .metadata
            .insert("vid".to_string(), format!("{:04X}", device.vid));
        event
            .metadata
            .insert("pid".to_string(), format!("{:04X}", device.pid));
        event.metadata.insert(
            "device_class".to_string(),
            format!("{:?}", device.device_class),
        );

        // Add detection for high-risk or blocked devices
        if blocked {
            event.add_detection(Detection {
                detection_type: DetectionType::UsbThreat,
                rule_name: "unauthorized_usb_device".to_string(),
                confidence: 1.0,
                description: format!(
                    "Unauthorized USB device blocked: {} (VID:{:04X} PID:{:04X})",
                    device.product.as_deref().unwrap_or("Unknown"),
                    device.vid,
                    device.pid
                ),
                mitre_tactics: vec!["initial-access".to_string(), "exfiltration".to_string()],
                mitre_techniques: vec!["T1091".to_string(), "T1052.001".to_string()],
            });
        } else if device.device_class.is_high_risk() {
            event.add_detection(Detection {
                detection_type: DetectionType::UsbThreat,
                rule_name: "high_risk_usb_device".to_string(),
                confidence: 0.5,
                description: format!(
                    "High-risk USB device connected: {:?} - {} (VID:{:04X} PID:{:04X})",
                    device.device_class,
                    device.product.as_deref().unwrap_or("Unknown"),
                    device.vid,
                    device.pid
                ),
                mitre_tactics: vec!["initial-access".to_string()],
                mitre_techniques: vec!["T1091".to_string()],
            });
        }

        event
    }

    /// Enumerate all connected USB devices
    async fn enumerate_devices() -> Vec<UsbDevice> {
        #[cfg(target_os = "windows")]
        return Self::enumerate_devices_windows().await;

        #[cfg(target_os = "linux")]
        return Self::enumerate_devices_linux().await;

        #[cfg(target_os = "macos")]
        return Self::enumerate_devices_macos().await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return Vec::new();
    }

    /// Block an unauthorized USB device
    async fn block_device(device: &UsbDevice) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        return Self::block_device_windows(device).await;

        #[cfg(target_os = "linux")]
        return Self::block_device_linux(device).await;

        #[cfg(target_os = "macos")]
        return Self::block_device_macos(device).await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = device;
            Err(anyhow::anyhow!(
                "USB blocking not supported on this platform"
            ))
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    // ============================================
    // Windows Implementation
    // ============================================

    #[cfg(target_os = "windows")]
    async fn enumerate_devices_windows() -> Vec<UsbDevice> {
        use windows::core::PCWSTR;
        use windows::Win32::Devices::DeviceAndDriverInstallation::{
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
            DIGCF_ALLCLASSES, DIGCF_PRESENT, SPDRP_HARDWAREID, SP_DEVINFO_DATA,
        };
        use windows::Win32::Foundation::HWND;

        let mut devices = Vec::new();

        // Create a null-terminated wide string for "USB"
        let usb_str: Vec<u16> = "USB\0".encode_utf16().collect();

        unsafe {
            // Get device information set for all USB devices
            let device_info_set = match SetupDiGetClassDevsW(
                None,
                PCWSTR::from_raw(usb_str.as_ptr()),
                HWND::default(),
                DIGCF_PRESENT | DIGCF_ALLCLASSES,
            ) {
                Ok(h) => h,
                Err(e) => {
                    error!(error = %e, "Failed to get USB device info set");
                    return devices;
                }
            };

            let mut device_index = 0u32;
            loop {
                let mut dev_info = SP_DEVINFO_DATA {
                    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                    ..Default::default()
                };

                if SetupDiEnumDeviceInfo(device_info_set, device_index, &mut dev_info).is_err() {
                    break;
                }

                // Get Hardware ID to extract VID/PID
                let hardware_id = Self::get_device_registry_property_windows(
                    device_info_set,
                    &dev_info,
                    SPDRP_HARDWAREID,
                );

                if let Some(hwid) = hardware_id {
                    if let Some(device) =
                        Self::parse_hardware_id_windows(&hwid, &dev_info, device_info_set)
                    {
                        devices.push(device);
                    }
                }

                device_index += 1;
            }

            let _ = SetupDiDestroyDeviceInfoList(device_info_set);
        }

        devices
    }

    #[cfg(target_os = "windows")]
    fn get_device_registry_property_windows(
        device_info_set: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
        dev_info: &windows::Win32::Devices::DeviceAndDriverInstallation::SP_DEVINFO_DATA,
        property: u32,
    ) -> Option<String> {
        use windows::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceRegistryPropertyW;

        unsafe {
            let mut buffer = vec![0u8; 1024];
            let mut required_size = 0u32;
            let mut reg_type = 0u32;

            let result = SetupDiGetDeviceRegistryPropertyW(
                device_info_set,
                dev_info,
                property,
                Some(&mut reg_type),
                Some(&mut buffer[..]),
                Some(&mut required_size),
            );

            if result.is_ok() {
                // Convert bytes to u16 (UTF-16)
                let u16_buf: Vec<u16> = buffer
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let end = u16_buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(u16_buf.len());
                Some(String::from_utf16_lossy(&u16_buf[..end]))
            } else {
                None
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_hardware_id_windows(
        hwid: &str,
        dev_info: &windows::Win32::Devices::DeviceAndDriverInstallation::SP_DEVINFO_DATA,
        device_info_set: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    ) -> Option<UsbDevice> {
        use windows::Win32::Devices::DeviceAndDriverInstallation::{SPDRP_FRIENDLYNAME, SPDRP_MFG};

        // Parse VID and PID from hardware ID like "USB\VID_1234&PID_5678"
        let hwid_upper = hwid.to_uppercase();

        let vid = hwid_upper.find("VID_").and_then(|pos| {
            let start = pos + 4;
            let end = std::cmp::min(start + 4, hwid_upper.len());
            u16::from_str_radix(&hwid_upper[start..end], 16).ok()
        })?;

        let pid = hwid_upper.find("PID_").and_then(|pos| {
            let start = pos + 4;
            let end = std::cmp::min(start + 4, hwid_upper.len());
            u16::from_str_radix(&hwid_upper[start..end], 16).ok()
        })?;

        // Get friendly name
        let product = Self::get_device_registry_property_windows(
            device_info_set,
            dev_info,
            SPDRP_FRIENDLYNAME,
        );

        // Get manufacturer
        let manufacturer =
            Self::get_device_registry_property_windows(device_info_set, dev_info, SPDRP_MFG);

        // Extract serial from hardware ID if present
        let serial = hwid_upper
            .find("\\")
            .map(|pos| {
                let remaining = &hwid_upper[pos + 1..];
                remaining.split('&').next().map(|s| s.to_string())
            })
            .flatten();

        // Determine device class using multiple methods:
        // 1. Windows ClassGuid from SP_DEVINFO_DATA (most reliable - set by driver/INF)
        // 2. Hardware ID string patterns (e.g., ROOT_HUB)
        // 3. Heuristics based on VID/PID and product name
        let mut device_class = Self::guess_device_class_windows(vid, pid, &product);

        // Check Windows device setup class GUID from devinfo for better classification
        // USB Hub class GUID: {36FC9E60-C465-11CF-8056-444553540000}
        // HID class GUID: {745A17A0-74D3-11D0-B6FE-00A0C90F57DA}
        let class_guid = format!("{:?}", dev_info.ClassGuid);
        let class_guid_upper = class_guid.to_uppercase();
        if class_guid_upper.contains("36FC9E60") {
            device_class = UsbDeviceClass::Hub;
        } else if class_guid_upper.contains("745A17A0") {
            device_class = UsbDeviceClass::Hid;
        }

        // Also check hardware ID string for hub patterns
        if device_class == UsbDeviceClass::Unknown {
            if hwid_upper.contains("ROOT_HUB")
                || hwid_upper.contains("USB_HUB")
                || hwid_upper.contains("HUB")
            {
                device_class = UsbDeviceClass::Hub;
            } else if hwid_upper.contains("HID")
                || hwid_upper.contains("MOUSE")
                || hwid_upper.contains("KEYBOARD")
            {
                device_class = UsbDeviceClass::Hid;
            }
        }

        Some(UsbDevice {
            vid,
            pid,
            device_class,
            serial,
            manufacturer,
            product,
            bus: 0, // Would need more complex enumeration
            address: 0,
            device_path: hwid.to_string(),
            speed: None,
            interface_count: 0,
            is_authorized: true,
        })
    }

    #[cfg(target_os = "windows")]
    fn guess_device_class_windows(vid: u16, pid: u16, product: &Option<String>) -> UsbDeviceClass {
        // Check product name for hints
        if let Some(ref name) = product {
            let name_lower = name.to_lowercase();
            if name_lower.contains("storage")
                || name_lower.contains("disk")
                || name_lower.contains("flash")
            {
                return UsbDeviceClass::MassStorage;
            }
            if name_lower.contains("keyboard") {
                return UsbDeviceClass::Hid;
            }
            if name_lower.contains("mouse") {
                return UsbDeviceClass::Hid;
            }
            if name_lower.contains("ethernet")
                || name_lower.contains("network")
                || name_lower.contains("lan")
            {
                return UsbDeviceClass::NetworkAdapter;
            }
            if name_lower.contains("bluetooth") {
                return UsbDeviceClass::WirelessController;
            }
            if name_lower.contains("webcam") || name_lower.contains("camera") {
                return UsbDeviceClass::Video;
            }
            if name_lower.contains("audio")
                || name_lower.contains("speaker")
                || name_lower.contains("microphone")
            {
                return UsbDeviceClass::Audio;
            }
            if name_lower.contains("hub") {
                return UsbDeviceClass::Hub;
            }
        }

        // Known VID ranges (partial list)
        // Mass storage VIDs
        let mass_storage_vids = [0x0781, 0x0951, 0x0930, 0x8564]; // SanDisk, Kingston, Toshiba, Transcend
        if mass_storage_vids.contains(&vid) {
            return UsbDeviceClass::MassStorage;
        }

        UsbDeviceClass::Unknown
    }

    #[cfg(target_os = "windows")]
    async fn block_device_windows(device: &UsbDevice) -> anyhow::Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::Devices::DeviceAndDriverInstallation::{
            SetupDiChangeState, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
            SetupDiGetClassDevsW, SetupDiSetClassInstallParamsW, DICS_DISABLE, DICS_FLAG_GLOBAL,
            DIF_PROPERTYCHANGE, DIGCF_ALLCLASSES, DIGCF_PRESENT, SPDRP_HARDWAREID, SP_DEVINFO_DATA,
            SP_PROPCHANGE_PARAMS,
        };
        use windows::Win32::Foundation::HWND;

        // CRITICAL SAFETY CHECK: Never disable HID or Hub devices.
        // Disabling a hub kills all downstream devices (mouse, keyboard).
        // Disabling HID devices directly removes input capability.
        if device.device_class == UsbDeviceClass::Hid || device.device_class == UsbDeviceClass::Hub
        {
            warn!(
                vid = format!("{:04X}", device.vid),
                pid = format!("{:04X}", device.pid),
                class = ?device.device_class,
                "Refusing to disable HID/Hub device - would break input devices"
            );
            return Err(anyhow::anyhow!(
                "Safety: refusing to disable HID/Hub device"
            ));
        }

        // Also check hardware ID for hub/HID patterns
        let path_upper = device.device_path.to_uppercase();
        if path_upper.contains("ROOT_HUB")
            || path_upper.contains("USB_HUB")
            || path_upper.contains("CLASS_09")
            || path_upper.contains("CLASS_03")
        {
            warn!(
                device_path = %device.device_path,
                "Refusing to disable device with hub/HID hardware ID pattern"
            );
            return Err(anyhow::anyhow!(
                "Safety: refusing to disable potential HID/Hub device"
            ));
        }

        // Create a null-terminated wide string for "USB"
        let usb_str: Vec<u16> = "USB\0".encode_utf16().collect();

        unsafe {
            let device_info_set = SetupDiGetClassDevsW(
                None,
                PCWSTR::from_raw(usb_str.as_ptr()),
                HWND::default(),
                DIGCF_PRESENT | DIGCF_ALLCLASSES,
            )?;

            let mut device_index = 0u32;
            let mut found = false;

            loop {
                let mut dev_info = SP_DEVINFO_DATA {
                    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                    ..Default::default()
                };

                if SetupDiEnumDeviceInfo(device_info_set, device_index, &mut dev_info).is_err() {
                    break;
                }

                let hardware_id = Self::get_device_registry_property_windows(
                    device_info_set,
                    &dev_info,
                    SPDRP_HARDWAREID,
                );

                if let Some(hwid) = hardware_id {
                    if hwid
                        .to_uppercase()
                        .contains(&format!("VID_{:04X}", device.vid))
                        && hwid
                            .to_uppercase()
                            .contains(&format!("PID_{:04X}", device.pid))
                    {
                        // Found the device - attempt to disable it
                        // Note: This requires administrator privileges
                        info!(
                            vid = format!("{:04X}", device.vid),
                            pid = format!("{:04X}", device.pid),
                            "Attempting to disable USB device"
                        );

                        // Set up the property change parameters to disable the device
                        let prop_change_params = SP_PROPCHANGE_PARAMS {
                            ClassInstallHeader: windows::Win32::Devices::DeviceAndDriverInstallation::SP_CLASSINSTALL_HEADER {
                                cbSize: std::mem::size_of::<windows::Win32::Devices::DeviceAndDriverInstallation::SP_CLASSINSTALL_HEADER>() as u32,
                                InstallFunction: DIF_PROPERTYCHANGE,
                            },
                            StateChange: DICS_DISABLE,
                            Scope: DICS_FLAG_GLOBAL,
                            HwProfile: 0,
                        };

                        // Set class install params
                        if SetupDiSetClassInstallParamsW(
                            device_info_set,
                            Some(&dev_info),
                            Some(&prop_change_params.ClassInstallHeader),
                            std::mem::size_of::<SP_PROPCHANGE_PARAMS>() as u32,
                        )
                        .is_ok()
                        {
                            // Apply the change
                            if SetupDiChangeState(device_info_set, &mut dev_info).is_ok() {
                                info!(
                                    vid = format!("{:04X}", device.vid),
                                    pid = format!("{:04X}", device.pid),
                                    "USB device disabled successfully"
                                );
                                found = true;
                            } else {
                                warn!(
                                    vid = format!("{:04X}", device.vid),
                                    pid = format!("{:04X}", device.pid),
                                    "Failed to change device state (may require admin)"
                                );
                            }
                        }
                        break;
                    }
                }

                device_index += 1;
            }

            let _ = SetupDiDestroyDeviceInfoList(device_info_set);

            if found {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Device not found or could not be disabled"))
            }
        }
    }

    // ============================================
    // Linux Implementation
    // ============================================

    #[cfg(target_os = "linux")]
    async fn enumerate_devices_linux() -> Vec<UsbDevice> {
        let mut devices = Vec::new();

        let usb_devices_path = std::path::Path::new("/sys/bus/usb/devices");
        if !usb_devices_path.exists() {
            warn!("USB sysfs path not found");
            return devices;
        }

        let entries = match tokio::fs::read_dir(usb_devices_path).await {
            Ok(e) => e,
            Err(e) => {
                error!(error = %e, "Failed to read USB devices directory");
                return devices;
            }
        };

        let mut entries = entries;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip entries that don't look like USB devices (e.g., usb1, 1-0:1.0)
            // Valid device entries are like "1-1", "2-1.4"
            if name.starts_with("usb") || name.contains(':') {
                continue;
            }

            // Check if this is a USB device (has idVendor file)
            let vid_path = path.join("idVendor");
            if !vid_path.exists() {
                continue;
            }

            if let Some(device) = Self::parse_sysfs_device_linux(&path).await {
                devices.push(device);
            }
        }

        devices
    }

    #[cfg(target_os = "linux")]
    async fn parse_sysfs_device_linux(path: &std::path::Path) -> Option<UsbDevice> {
        // Read VID
        let vid = Self::read_sysfs_hex(path, "idVendor").await?;
        // Read PID
        let pid = Self::read_sysfs_hex(path, "idProduct").await?;

        // Read device class info
        let class = Self::read_sysfs_hex(path, "bDeviceClass")
            .await
            .unwrap_or(0) as u8;
        let subclass = Self::read_sysfs_hex(path, "bDeviceSubClass")
            .await
            .unwrap_or(0) as u8;
        let protocol = Self::read_sysfs_hex(path, "bDeviceProtocol")
            .await
            .unwrap_or(0) as u8;

        let device_class = UsbDeviceClass::from_class_code(class, subclass, protocol);

        // Read optional fields
        let serial = Self::read_sysfs_string(path, "serial").await;
        let manufacturer = Self::read_sysfs_string(path, "manufacturer").await;
        let product = Self::read_sysfs_string(path, "product").await;
        let speed = Self::read_sysfs_string(path, "speed")
            .await
            .map(|s| format!("{} Mbps", s));

        // Parse bus and address from path
        let device_path = path.to_string_lossy().to_string();
        let (bus, address) = Self::parse_bus_address_linux(&device_path);

        // Read interface count
        let interface_count = Self::read_sysfs_hex(path, "bNumInterfaces")
            .await
            .unwrap_or(0) as u8;

        // Check if authorized
        let is_authorized = Self::read_sysfs_string(path, "authorized")
            .await
            .map(|s| s.trim() == "1")
            .unwrap_or(true);

        Some(UsbDevice {
            vid,
            pid,
            device_class,
            serial,
            manufacturer,
            product,
            bus,
            address,
            device_path,
            speed,
            interface_count,
            is_authorized,
        })
    }

    #[cfg(target_os = "linux")]
    async fn read_sysfs_hex(path: &std::path::Path, attr: &str) -> Option<u16> {
        let content = tokio::fs::read_to_string(path.join(attr)).await.ok()?;
        u16::from_str_radix(content.trim(), 16).ok()
    }

    #[cfg(target_os = "linux")]
    async fn read_sysfs_string(path: &std::path::Path, attr: &str) -> Option<String> {
        tokio::fs::read_to_string(path.join(attr))
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    #[cfg(target_os = "linux")]
    fn parse_bus_address_linux(device_path: &str) -> (u8, u8) {
        // Path format: /sys/bus/usb/devices/1-2
        // Bus is the first number, address requires reading devnum
        let parts: Vec<&str> = device_path
            .trim_start_matches("/sys/bus/usb/devices/")
            .split('-')
            .collect();

        let bus = parts
            .first()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);

        // Read actual device number
        let devnum_path = format!("{}/devnum", device_path);
        let address = std::fs::read_to_string(&devnum_path)
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0);

        (bus, address)
    }

    #[cfg(target_os = "linux")]
    async fn block_device_linux(device: &UsbDevice) -> anyhow::Result<()> {
        // On Linux, we can deauthorize the device by writing 0 to the authorized file
        // This requires root privileges

        let authorized_path = format!("{}/authorized", device.device_path);

        match tokio::fs::write(&authorized_path, "0").await {
            Ok(_) => {
                info!(
                    vid = format!("{:04X}", device.vid),
                    pid = format!("{:04X}", device.pid),
                    path = %device.device_path,
                    "USB device deauthorized"
                );
                Ok(())
            }
            Err(e) => {
                // Try alternative: unbind the driver
                let driver_path = format!("{}/driver/unbind", device.device_path);
                let device_name = std::path::Path::new(&device.device_path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();

                match tokio::fs::write(&driver_path, &device_name).await {
                    Ok(_) => {
                        info!(
                            vid = format!("{:04X}", device.vid),
                            pid = format!("{:04X}", device.pid),
                            "USB device driver unbound"
                        );
                        Ok(())
                    }
                    Err(e2) => Err(anyhow::anyhow!(
                        "Failed to block device: auth error: {}, unbind error: {}",
                        e,
                        e2
                    )),
                }
            }
        }
    }

    // ============================================
    // macOS Implementation
    // ============================================

    #[cfg(target_os = "macos")]
    async fn enumerate_devices_macos() -> Vec<UsbDevice> {
        use std::process::Command;
        use std::sync::atomic::{AtomicBool, Ordering};

        static SYSTEM_PROFILER_WARNED: AtomicBool = AtomicBool::new(false);

        let mut devices = Vec::new();

        // Use system_profiler to get USB device info
        let output = match Command::new("system_profiler")
            .args(["SPUSBDataType", "-json"])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                if SYSTEM_PROFILER_WARNED.swap(true, Ordering::Relaxed) {
                    debug!(error = %e, "Failed to run system_profiler, falling back to ioreg");
                } else {
                    warn!(error = %e, "Failed to run system_profiler, falling back to ioreg");
                }
                return Self::enumerate_devices_macos_ioreg();
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if SYSTEM_PROFILER_WARNED.swap(true, Ordering::Relaxed) {
                debug!(
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "system_profiler failed, falling back to ioreg for USB inventory"
                );
            } else {
                warn!(
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "system_profiler failed, falling back to ioreg for USB inventory"
                );
            }
            return Self::enumerate_devices_macos_ioreg();
        }

        // Parse JSON output
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            Self::parse_macos_usb_json(&json, &mut devices, 0, 0);
        }

        devices
    }

    #[cfg(target_os = "macos")]
    fn enumerate_devices_macos_ioreg() -> Vec<UsbDevice> {
        use std::process::Command;
        use std::sync::atomic::{AtomicBool, Ordering};

        static IOREG_WARNED: AtomicBool = AtomicBool::new(false);

        let output = match Command::new("ioreg")
            .args(["-r", "-c", "IOUSBHostDevice", "-l"])
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                if IOREG_WARNED.swap(true, Ordering::Relaxed) {
                    debug!(error = %e, "Failed to run ioreg USB fallback");
                } else {
                    warn!(error = %e, "Failed to run ioreg USB fallback");
                }
                return Vec::new();
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if IOREG_WARNED.swap(true, Ordering::Relaxed) {
                debug!(
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "ioreg USB fallback failed"
                );
            } else {
                warn!(
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "ioreg USB fallback failed"
                );
            }
            return Vec::new();
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_macos_ioreg_usb_output(&stdout)
    }

    #[cfg(target_os = "macos")]
    fn parse_macos_ioreg_usb_output(output: &str) -> Vec<UsbDevice> {
        use std::collections::HashMap;

        let mut devices = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_props: HashMap<String, String> = HashMap::new();
        let mut address: u8 = 0;

        for line in output.lines() {
            if line.contains("+-o ") || line.contains("|-o ") {
                Self::push_macos_ioreg_device(
                    &mut devices,
                    current_name.take(),
                    &current_props,
                    &mut address,
                );
                current_props.clear();
                current_name = line
                    .split("-o ")
                    .nth(1)
                    .and_then(|value| value.split("  <").next())
                    .map(|value| value.trim().to_string());
                continue;
            }

            let Some((raw_key, raw_value)) = line.split_once(" = ") else {
                continue;
            };
            let key = raw_key.trim().trim_matches('"').to_string();
            let value = raw_value
                .trim()
                .trim_matches('"')
                .trim_end_matches(',')
                .to_string();
            current_props.insert(key, value);
        }

        Self::push_macos_ioreg_device(
            &mut devices,
            current_name.take(),
            &current_props,
            &mut address,
        );

        devices
    }

    #[cfg(target_os = "macos")]
    fn push_macos_ioreg_device(
        devices: &mut Vec<UsbDevice>,
        name: Option<String>,
        props: &std::collections::HashMap<String, String>,
        address: &mut u8,
    ) {
        let vid = props
            .get("idVendor")
            .or_else(|| props.get("vendor-id"))
            .and_then(|value| Self::parse_macos_ioreg_u16(value))
            .unwrap_or(0);
        let pid = props
            .get("idProduct")
            .or_else(|| props.get("product-id"))
            .and_then(|value| Self::parse_macos_ioreg_u16(value))
            .unwrap_or(0);

        if vid == 0 || pid == 0 {
            return;
        }

        *address = address.saturating_add(1);
        let product = props
            .get("USB Product Name")
            .or_else(|| props.get("Product Name"))
            .cloned()
            .or(name);
        let manufacturer = props
            .get("USB Vendor Name")
            .or_else(|| props.get("Manufacturer"))
            .cloned();
        let serial = props
            .get("USB Serial Number")
            .or_else(|| props.get("Serial Number"))
            .cloned();
        let device_class = product
            .as_ref()
            .map(|value| Self::guess_device_class_macos(value))
            .unwrap_or(UsbDeviceClass::Unknown);

        devices.push(UsbDevice {
            vid,
            pid,
            device_class,
            serial,
            manufacturer,
            product,
            bus: 0,
            address: *address,
            device_path: format!("macos:ioreg:{}", *address),
            speed: props.get("Device Speed").cloned(),
            interface_count: 0,
            is_authorized: true,
        });
    }

    #[cfg(target_os = "macos")]
    fn parse_macos_ioreg_u16(value: &str) -> Option<u16> {
        let value = value.trim();
        if let Some(hex) = value.strip_prefix("0x") {
            return u16::from_str_radix(hex, 16).ok();
        }
        if value.starts_with('<') && value.ends_with('>') && value.len() >= 6 {
            return u16::from_str_radix(&value[1..5], 16).ok();
        }
        value.parse().ok()
    }

    #[cfg(target_os = "macos")]
    fn parse_macos_usb_json(
        value: &serde_json::Value,
        devices: &mut Vec<UsbDevice>,
        bus: u8,
        address_counter: u8,
    ) {
        if let Some(usb_data) = value.get("SPUSBDataType").and_then(|v| v.as_array()) {
            for controller in usb_data {
                Self::parse_macos_usb_item(controller, devices, bus, address_counter);
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn parse_macos_usb_item(
        item: &serde_json::Value,
        devices: &mut Vec<UsbDevice>,
        bus: u8,
        mut address: u8,
    ) {
        // Check if this item has vendor_id (indicating it's a USB device)
        if let (Some(vendor_id), Some(product_id)) = (
            item.get("vendor_id").and_then(|v| v.as_str()),
            item.get("product_id").and_then(|v| v.as_str()),
        ) {
            // Parse VID/PID (format: "0x1234")
            let vid = u16::from_str_radix(vendor_id.trim_start_matches("0x"), 16).unwrap_or(0);
            let pid = u16::from_str_radix(product_id.trim_start_matches("0x"), 16).unwrap_or(0);

            if vid != 0 {
                let product = item.get("_name").and_then(|v| v.as_str()).map(String::from);
                let manufacturer = item
                    .get("manufacturer")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let serial = item
                    .get("serial_num")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let speed = item.get("Speed").and_then(|v| v.as_str()).map(String::from);

                // Determine device class from name or bcd_device
                let device_class = product
                    .as_ref()
                    .map(|p| Self::guess_device_class_macos(p))
                    .unwrap_or(UsbDeviceClass::Unknown);

                address += 1;

                devices.push(UsbDevice {
                    vid,
                    pid,
                    device_class,
                    serial,
                    manufacturer,
                    product,
                    bus,
                    address,
                    device_path: format!("macos:{}:{}", bus, address),
                    speed,
                    interface_count: 0,
                    is_authorized: true,
                });
            }
        }

        // Recursively process child items (for USB hubs)
        if let Some(items) = item.get("_items").and_then(|v| v.as_array()) {
            for child in items {
                Self::parse_macos_usb_item(child, devices, bus, address);
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn guess_device_class_macos(name: &str) -> UsbDeviceClass {
        let name_lower = name.to_lowercase();

        if name_lower.contains("storage")
            || name_lower.contains("disk")
            || name_lower.contains("flash")
        {
            UsbDeviceClass::MassStorage
        } else if name_lower.contains("keyboard")
            || name_lower.contains("mouse")
            || name_lower.contains("trackpad")
        {
            UsbDeviceClass::Hid
        } else if name_lower.contains("ethernet")
            || name_lower.contains("network")
            || name_lower.contains("lan")
        {
            UsbDeviceClass::NetworkAdapter
        } else if name_lower.contains("bluetooth") {
            UsbDeviceClass::WirelessController
        } else if name_lower.contains("webcam")
            || name_lower.contains("camera")
            || name_lower.contains("facetime")
        {
            UsbDeviceClass::Video
        } else if name_lower.contains("audio")
            || name_lower.contains("speaker")
            || name_lower.contains("microphone")
        {
            UsbDeviceClass::Audio
        } else if name_lower.contains("hub") {
            UsbDeviceClass::Hub
        } else {
            UsbDeviceClass::Unknown
        }
    }

    #[cfg(target_os = "macos")]
    async fn block_device_macos(device: &UsbDevice) -> anyhow::Result<()> {
        // macOS doesn't have a simple way to block USB devices without kernel extensions
        // or the newer System Extensions/DriverKit framework
        warn!(
            vid = format!("{:04X}", device.vid),
            pid = format!("{:04X}", device.pid),
            "USB device blocking not fully implemented on macOS"
        );

        // Could potentially use diskutil to unmount mass storage devices
        if device.device_class == UsbDeviceClass::MassStorage {
            use std::process::Command;

            // Try to eject/unmount the device
            let output = Command::new("diskutil")
                .args(["unmountDisk", "force", &device.device_path])
                .output();

            if let Ok(o) = output {
                if o.status.success() {
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!(
            "USB blocking requires additional privileges on macOS"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_class_from_code() {
        assert_eq!(
            UsbDeviceClass::from_class_code(0x08, 0, 0),
            UsbDeviceClass::MassStorage
        );
        assert_eq!(
            UsbDeviceClass::from_class_code(0x03, 0, 0),
            UsbDeviceClass::Hid
        );
        assert_eq!(
            UsbDeviceClass::from_class_code(0x09, 0, 0),
            UsbDeviceClass::Hub
        );
        assert_eq!(
            UsbDeviceClass::from_class_code(0xE0, 0x01, 0x01),
            UsbDeviceClass::WirelessController
        );
    }

    #[test]
    fn test_whitelist() {
        let mut whitelist = UsbWhitelist::new();
        whitelist.set_enforce(true);
        whitelist.add("1234:5678".to_string());
        whitelist.add("8086:*".to_string());
        whitelist.add("class:hid".to_string());

        // Exact match
        let device1 = UsbDevice {
            vid: 0x1234,
            pid: 0x5678,
            device_class: UsbDeviceClass::MassStorage,
            serial: None,
            manufacturer: None,
            product: None,
            bus: 1,
            address: 1,
            device_path: "test".to_string(),
            speed: None,
            interface_count: 1,
            is_authorized: true,
        };
        assert!(whitelist.is_allowed(&device1));

        // VID wildcard match
        let device2 = UsbDevice {
            vid: 0x8086,
            pid: 0x9999,
            device_class: UsbDeviceClass::Unknown,
            serial: None,
            manufacturer: None,
            product: None,
            bus: 1,
            address: 2,
            device_path: "test2".to_string(),
            speed: None,
            interface_count: 1,
            is_authorized: true,
        };
        assert!(whitelist.is_allowed(&device2));

        // Class match
        let device3 = UsbDevice {
            vid: 0xAAAA,
            pid: 0xBBBB,
            device_class: UsbDeviceClass::Hid,
            serial: None,
            manufacturer: None,
            product: None,
            bus: 1,
            address: 3,
            device_path: "test3".to_string(),
            speed: None,
            interface_count: 1,
            is_authorized: true,
        };
        // HID is allowed by default
        assert!(whitelist.is_allowed(&device3));

        // Not in whitelist
        let device4 = UsbDevice {
            vid: 0xDEAD,
            pid: 0xBEEF,
            device_class: UsbDeviceClass::MassStorage,
            serial: None,
            manufacturer: None,
            product: None,
            bus: 1,
            address: 4,
            device_path: "test4".to_string(),
            speed: None,
            interface_count: 1,
            is_authorized: true,
        };
        assert!(!whitelist.is_allowed(&device4));
    }

    #[test]
    fn test_vid_pid_string() {
        let device = UsbDevice {
            vid: 0x1234,
            pid: 0x5678,
            device_class: UsbDeviceClass::Unknown,
            serial: None,
            manufacturer: None,
            product: None,
            bus: 1,
            address: 1,
            device_path: "test".to_string(),
            speed: None,
            interface_count: 1,
            is_authorized: true,
        };
        assert_eq!(device.vid_pid_string(), "1234:5678");
    }

    #[test]
    fn test_high_risk_classes() {
        assert!(UsbDeviceClass::MassStorage.is_high_risk());
        assert!(UsbDeviceClass::NetworkAdapter.is_high_risk());
        assert!(UsbDeviceClass::WirelessController.is_high_risk());
        assert!(!UsbDeviceClass::Hid.is_high_risk());
        assert!(!UsbDeviceClass::Hub.is_high_risk());
        assert!(!UsbDeviceClass::Audio.is_high_risk());
    }
}
