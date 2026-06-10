//! # Handle Protection via ObRegisterCallbacks
//!
//! This module provides documentation and usermode stubs for kernel-mode handle protection
//! using Windows `ObRegisterCallbacks`. This is a critical anti-tampering technique used by
//! enterprise EDR solutions like CrowdStrike Falcon and SentinelOne.
//!
//! ## How It Works
//!
//! Windows kernel drivers can use `ObRegisterCallbacks` to intercept handle operations
//! and strip dangerous access rights from handles to protected processes.
//!
//! ### Callback Flow:
//!
//! 1. Driver registers callback via `ObRegisterCallbacks` with `OB_OPERATION_REGISTRATION`
//! 2. When **any process** opens a handle to the agent, the `PreOperationCallback` fires
//! 3. Callback checks if target PID is in the protected list
//! 4. If protected: Modifies `DesiredAccess` to strip dangerous rights
//! 5. Returns `OB_PREOP_SUCCESS` to allow the (now-neutered) operation
//!
//! ### Access Rights Stripped:
//!
//! The callback strips these dangerous access rights:
//!
//! - `PROCESS_TERMINATE` (0x0001) - Prevents `TerminateProcess()`
//! - `PROCESS_VM_WRITE` (0x0020) - Prevents memory writes (code injection)
//! - `PROCESS_VM_OPERATION` (0x0008) - Prevents `VirtualAllocEx()`, `VirtualProtectEx()`
//! - `PROCESS_CREATE_THREAD` (0x0002) - Prevents remote thread creation
//! - `PROCESS_SUSPEND_RESUME` (0x0800) - Prevents process suspension
//!
//! For thread handles:
//!
//! - `THREAD_TERMINATE` (0x0001) - Prevents thread termination
//! - `THREAD_SUSPEND_RESUME` (0x0002) - Prevents thread suspension
//! - `THREAD_SET_CONTEXT` (0x0010) - Prevents context manipulation
//!
//! ## CrowdStrike / SentinelOne Implementation
//!
//! Both major EDR vendors use this technique. It's why you cannot kill their agents
//! even as Administrator:
//!
//! - **CrowdStrike Falcon**: Uses `csagent.sys` kernel driver with ObRegisterCallbacks
//! - **SentinelOne**: Uses `SentinelAgent.sys` with similar protection
//! - **Windows Defender**: Uses `WdFilter.sys` (also protected by PPL)
//!
//! The attacker gets a handle, but the handle lacks permissions to actually terminate
//! or inject into the protected process. Task Manager, `taskkill`, and PowerShell
//! `Stop-Process` all silently fail.
//!
//! ## Kernel Driver Implementation Requirements
//!
//! ### Required Structures:
//!
//! ```c
//! // Driver-side structures
//! typedef struct _PROTECTED_PROCESS {
//!     ULONG ProcessId;
//!     LARGE_INTEGER ProtectionTime;
//!     ULONG Flags;
//!     LIST_ENTRY ListEntry;
//! } PROTECTED_PROCESS, *PPROTECTED_PROCESS;
//!
//! OB_PREOP_CALLBACK_STATUS PreOperationCallback(
//!     PVOID RegistrationContext,
//!     POB_PRE_OPERATION_INFORMATION OperationInfo
//! );
//! ```
//!
//! ### Registration:
//!
//! ```c
//! OB_CALLBACK_REGISTRATION CallbackReg;
//! OB_OPERATION_REGISTRATION OperationReg[2];
//!
//! // Process callbacks
//! OperationReg[0].ObjectType = PsProcessType;
//! OperationReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
//! OperationReg[0].PreOperation = ProcessPreOperationCallback;
//! OperationReg[0].PostOperation = NULL;
//!
//! // Thread callbacks
//! OperationReg[1].ObjectType = PsThreadType;
//! OperationReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
//! OperationReg[1].PreOperation = ThreadPreOperationCallback;
//! OperationReg[1].PostOperation = NULL;
//!
//! CallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
//! CallbackReg.OperationRegistrationCount = 2;
//! CallbackReg.OperationRegistration = OperationReg;
//! // IMPORTANT: Requires Altitude and needs to be signed with EV cert
//! CallbackReg.Altitude = RTL_CONSTANT_STRING(L"385201");
//!
//! NTSTATUS Status = ObRegisterCallbacks(&CallbackReg, &g_CallbackHandle);
//! ```
//!
//! ## Security Considerations
//!
//! - Driver must be **EV code-signed** for production use
//! - Requires **Microsoft WHQL** certification for broad deployment
//! - Callback must handle race conditions (process may exit during callback)
//! - Must not block system processes (csrss.exe, lsass.exe, etc.)
//! - Should log stripped access attempts for threat detection
//!
//! ## MITRE ATT&CK Coverage
//!
//! - **T1562.001** - Disable or Modify Tools (prevents agent termination)
//! - **T1055** - Process Injection (blocks code injection)
//! - **T1489** - Service Stop (protects agent process)
//!
//! ## TODO: Kernel Driver Implementation
//!
//! See [`KernelDriverTodo`] for the complete implementation checklist.

// This module documents the ObRegisterCallbacks-based handle protection
// surface and provides usermode IOCTL stubs for the kernel driver. Many
// IOCTL codes, request structs, device-name constants and access-mask values
// are reference documentation for the forthcoming driver and intentionally
// exhaustive even before all paths are wired.
#![allow(dead_code, unused_variables)]

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{info, warn};

// =============================================================================
// IOCTL Definitions
// =============================================================================

/// Device type for Tamandua driver IOCTLs
/// FILE_DEVICE_UNKNOWN = 0x22
const FILE_DEVICE_TAMANDUA: u32 = 0x8022; // Custom device type

/// IOCTL method: METHOD_BUFFERED = 0
const METHOD_BUFFERED: u32 = 0;

/// IOCTL access: FILE_ANY_ACCESS = 0
const FILE_ANY_ACCESS: u32 = 0;

/// IOCTL access: FILE_READ_ACCESS = 1
const FILE_READ_ACCESS: u32 = 1;

/// IOCTL access: FILE_WRITE_ACCESS = 2
const FILE_WRITE_ACCESS: u32 = 2;

/// Macro to construct IOCTL codes (matches CTL_CODE from WinIoCtl.h)
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)
}

/// Base function code for handle protection IOCTLs
const HANDLE_PROTECTION_BASE: u32 = 0x900;

/// Add a PID to the protected process list.
///
/// Input: `HandleProtectionRequest` with the PID to protect
/// Output: `HandleProtectionResponse` indicating success/failure
///
/// The driver will register callbacks (if not already registered) and add
/// the specified PID to the protected list. All future handle operations
/// targeting this PID will have dangerous access rights stripped.
pub const IOCTL_ADD_PROTECTED_PID: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    HANDLE_PROTECTION_BASE,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

/// Remove a PID from the protected process list.
///
/// Input: `HandleProtectionRequest` with the PID to unprotect
/// Output: `HandleProtectionResponse` indicating success/failure
///
/// Called during clean shutdown or if protection needs to be temporarily
/// disabled. Does NOT unregister the callback - other PIDs may still be protected.
pub const IOCTL_REMOVE_PROTECTED_PID: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    HANDLE_PROTECTION_BASE + 1,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

/// Query current handle protection status.
///
/// Input: `HandleProtectionRequest` (PID field optional, 0 = overall status)
/// Output: `HandleProtectionStatus` with protection state and statistics
///
/// Returns whether protection is active, how many access strips have occurred,
/// and the list of currently protected PIDs.
pub const IOCTL_QUERY_PROTECTION_STATUS: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    HANDLE_PROTECTION_BASE + 2,
    METHOD_BUFFERED,
    FILE_READ_ACCESS,
);

/// Enable handle protection globally.
///
/// Input: None
/// Output: `HandleProtectionResponse`
///
/// Registers the ObRegisterCallbacks if not already registered.
/// Protection only applies to PIDs in the protected list.
pub const IOCTL_ENABLE_HANDLE_PROTECTION: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    HANDLE_PROTECTION_BASE + 3,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

/// Disable handle protection globally.
///
/// Input: None
/// Output: `HandleProtectionResponse`
///
/// Unregisters all callbacks and clears the protected PID list.
/// Use with caution - leaves agent vulnerable to termination.
pub const IOCTL_DISABLE_HANDLE_PROTECTION: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    HANDLE_PROTECTION_BASE + 4,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

/// Query the list of all stripped access attempts (audit log).
///
/// Input: `AuditLogRequest` with offset and count
/// Output: `AuditLogResponse` with access strip events
///
/// Returns recent handle operations where access rights were stripped.
/// Useful for threat detection and forensics.
pub const IOCTL_QUERY_STRIPPED_ACCESS_LOG: u32 = ctl_code(
    FILE_DEVICE_TAMANDUA,
    HANDLE_PROTECTION_BASE + 5,
    METHOD_BUFFERED,
    FILE_READ_ACCESS,
);

// =============================================================================
// Request/Response Structures
// =============================================================================

/// Protection flags for fine-grained control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HandleProtectionFlags {
    /// Strip PROCESS_TERMINATE
    NoTerminate = 0x0001,
    /// Strip PROCESS_VM_WRITE and PROCESS_VM_OPERATION
    NoMemoryWrite = 0x0002,
    /// Strip PROCESS_CREATE_THREAD
    NoThreadCreate = 0x0004,
    /// Strip PROCESS_SUSPEND_RESUME
    NoSuspend = 0x0008,
    /// Strip THREAD_SET_CONTEXT
    NoContextChange = 0x0010,
    /// All protections enabled
    Full = 0x001F,
}

/// Request structure for handle protection IOCTLs
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HandleProtectionRequest {
    /// Target process ID (0 for global operations)
    pub pid: u32,
    /// Protection flags (see HandleProtectionFlags)
    pub flags: u32,
    /// Reserved for future use
    pub reserved: [u32; 4],
}

impl Default for HandleProtectionRequest {
    fn default() -> Self {
        Self {
            pid: 0,
            flags: HandleProtectionFlags::Full as u32,
            reserved: [0; 4],
        }
    }
}

/// Response structure from handle protection IOCTLs
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HandleProtectionResponse {
    /// NTSTATUS from the operation
    pub status: i32,
    /// Additional error code (Win32 error if applicable)
    pub error_code: u32,
    /// Reserved for future use
    pub reserved: [u32; 4],
}

/// Current handle protection status
#[derive(Debug, Clone, Default)]
pub struct HandleProtectionStatus {
    /// Whether ObRegisterCallbacks is registered
    pub callbacks_registered: bool,
    /// Whether protection is globally enabled
    pub protection_enabled: bool,
    /// Number of PIDs currently protected
    pub protected_pid_count: u32,
    /// List of protected PIDs
    pub protected_pids: Vec<u32>,
    /// Total number of handle operations intercepted
    pub total_operations_intercepted: u64,
    /// Number of process handle access strips
    pub process_access_strips: u64,
    /// Number of thread handle access strips
    pub thread_access_strips: u64,
    /// Number of handle duplicate blocks
    pub handle_duplicate_blocks: u64,
    /// Last strip timestamp (Unix epoch)
    pub last_strip_timestamp: u64,
    /// Current protection flags
    pub active_flags: u32,
}

/// Audit log entry for stripped access
#[derive(Debug, Clone)]
pub struct StrippedAccessEntry {
    /// Timestamp of the event (Unix epoch)
    pub timestamp: u64,
    /// Requesting process ID
    pub requester_pid: u32,
    /// Requesting process name
    pub requester_name: String,
    /// Target protected PID
    pub target_pid: u32,
    /// Original requested access
    pub original_access: u32,
    /// Access after stripping
    pub stripped_access: u32,
    /// Access rights that were removed
    pub removed_access: u32,
    /// Whether this was a process or thread handle
    pub is_thread_handle: bool,
}

// =============================================================================
// Usermode API
// =============================================================================

/// Handle protection manager for usermode communication with kernel driver
pub struct HandleProtectionManager {
    /// Driver device handle
    #[cfg(target_os = "windows")]
    device_handle: Option<windows::Win32::Foundation::HANDLE>,
    /// Connection status
    connected: AtomicBool,
    /// Statistics
    operations_requested: AtomicU64,
    operations_succeeded: AtomicU64,
}

impl HandleProtectionManager {
    /// Create a new handle protection manager
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            device_handle: None,
            connected: AtomicBool::new(false),
            operations_requested: AtomicU64::new(0),
            operations_succeeded: AtomicU64::new(0),
        }
    }

    /// Connect to the kernel driver
    ///
    /// Opens a handle to the Tamandua driver device. This must be called
    /// before any protection operations.
    #[cfg(target_os = "windows")]
    pub fn connect(&mut self) -> Result<()> {
        // Device name for the Tamandua driver
        const DEVICE_NAME: &str = r"\\.\TamanduaDriver";

        info!("Connecting to Tamandua kernel driver for handle protection");

        // STUB — DESIGN-DORMANT, not production. Gated on the unshipped Tamandua
        // kernel driver. No CreateFileW is performed; connect() always fails with a
        // "driver not loaded" error, so every IOCTL op below is unreachable in a
        // connected state. Missing: the kernel driver + the CreateFileW device open.
        warn!("Handle protection requires kernel driver - stub implementation");

        // Stub: Always return "not connected" until driver is implemented
        Err(anyhow!(
            "Tamandua kernel driver not loaded. Handle protection requires the kernel driver \
             to be installed and running. See KERNEL_DRIVER_TODO.md for implementation details."
        ))
    }

    #[cfg(not(target_os = "windows"))]
    pub fn connect(&mut self) -> Result<()> {
        info!("Handle protection via ObRegisterCallbacks is Windows-only");
        Err(anyhow!(
            "Handle protection via ObRegisterCallbacks is only available on Windows"
        ))
    }

    /// Disconnect from the kernel driver
    #[cfg(target_os = "windows")]
    pub fn disconnect(&mut self) {
        use windows::Win32::Foundation::CloseHandle;

        if let Some(handle) = self.device_handle.take() {
            unsafe {
                let _ = CloseHandle(handle);
            }
            self.connected.store(false, Ordering::SeqCst);
            info!("Disconnected from kernel driver");
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn disconnect(&mut self) {
        // No-op on non-Windows
    }

    /// Check if connected to the driver
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Request handle protection for the current process.
    ///
    /// Sends an IOCTL to the kernel driver to add the current process ID
    /// to the protected list. The driver will then strip dangerous access
    /// rights from any handles opened to this process.
    ///
    /// # Flags
    ///
    /// - `HandleProtectionFlags::Full` - Strip all dangerous access rights (recommended)
    /// - Individual flags can be combined for selective protection
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not connected to the driver
    /// - Driver rejects the request
    /// - IOCTL communication fails
    pub fn request_handle_protection(&self) -> Result<()> {
        self.request_handle_protection_with_flags(HandleProtectionFlags::Full as u32)
    }

    /// Request handle protection with specific flags
    pub fn request_handle_protection_with_flags(&self, flags: u32) -> Result<()> {
        self.operations_requested.fetch_add(1, Ordering::SeqCst);

        if !self.is_connected() {
            return Err(anyhow!("Not connected to kernel driver"));
        }

        let pid = std::process::id();
        info!(
            "Requesting handle protection for PID {} with flags 0x{:08X}",
            pid, flags
        );

        let request = HandleProtectionRequest {
            pid,
            flags,
            reserved: [0; 4],
        };

        // TODO: Send IOCTL_ADD_PROTECTED_PID to driver
        // This is a stub implementation

        #[cfg(target_os = "windows")]
        {
            // Actual implementation would use DeviceIoControl:
            //
            // unsafe {
            //     let mut response = HandleProtectionResponse::default();
            //     let mut bytes_returned: u32 = 0;
            //
            //     let result = DeviceIoControl(
            //         self.device_handle.unwrap(),
            //         IOCTL_ADD_PROTECTED_PID,
            //         Some(&request as *const _ as *const c_void),
            //         std::mem::size_of::<HandleProtectionRequest>() as u32,
            //         Some(&mut response as *mut _ as *mut c_void),
            //         std::mem::size_of::<HandleProtectionResponse>() as u32,
            //         Some(&mut bytes_returned),
            //         None,
            //     );
            //
            //     if result.is_ok() && response.status >= 0 {
            //         self.operations_succeeded.fetch_add(1, Ordering::SeqCst);
            //         return Ok(());
            //     }
            // }
        }

        Err(anyhow!(
            "Handle protection IOCTL failed - driver stub not implemented"
        ))
    }

    /// Remove handle protection for a specific PID
    pub fn remove_handle_protection(&self, pid: u32) -> Result<()> {
        self.operations_requested.fetch_add(1, Ordering::SeqCst);

        if !self.is_connected() {
            return Err(anyhow!("Not connected to kernel driver"));
        }

        info!("Removing handle protection for PID {}", pid);

        let request = HandleProtectionRequest {
            pid,
            flags: 0,
            reserved: [0; 4],
        };

        // TODO: Send IOCTL_REMOVE_PROTECTED_PID to driver
        Err(anyhow!(
            "Handle protection removal IOCTL failed - driver stub not implemented"
        ))
    }

    /// Query current handle protection status
    ///
    /// Returns detailed status including:
    /// - Whether protection is active
    /// - List of protected PIDs
    /// - Statistics on intercepted operations
    pub fn get_protection_status(&self) -> Result<HandleProtectionStatus> {
        self.operations_requested.fetch_add(1, Ordering::SeqCst);

        if !self.is_connected() {
            // Return stub status when not connected
            return Ok(HandleProtectionStatus {
                callbacks_registered: false,
                protection_enabled: false,
                protected_pid_count: 0,
                protected_pids: Vec::new(),
                total_operations_intercepted: 0,
                process_access_strips: 0,
                thread_access_strips: 0,
                handle_duplicate_blocks: 0,
                last_strip_timestamp: 0,
                active_flags: 0,
            });
        }

        // TODO: Send IOCTL_QUERY_PROTECTION_STATUS to driver
        Err(anyhow!(
            "Protection status query IOCTL failed - driver stub not implemented"
        ))
    }

    /// Query the stripped access audit log
    ///
    /// Returns a list of recent handle operations where access rights were
    /// stripped. Useful for threat detection - identifies processes attempting
    /// to tamper with the agent.
    ///
    /// # Arguments
    ///
    /// * `offset` - Starting index in the log
    /// * `count` - Maximum number of entries to return
    pub fn get_stripped_access_log(
        &self,
        offset: u32,
        count: u32,
    ) -> Result<Vec<StrippedAccessEntry>> {
        if !self.is_connected() {
            return Ok(Vec::new());
        }

        // TODO: Send IOCTL_QUERY_STRIPPED_ACCESS_LOG to driver
        Err(anyhow!(
            "Stripped access log query IOCTL failed - driver stub not implemented"
        ))
    }

    /// Enable handle protection globally
    pub fn enable_global_protection(&self) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to kernel driver"));
        }

        info!("Enabling global handle protection");
        // TODO: Send IOCTL_ENABLE_HANDLE_PROTECTION to driver
        Err(anyhow!(
            "Enable protection IOCTL failed - driver stub not implemented"
        ))
    }

    /// Disable handle protection globally
    ///
    /// **Warning**: This leaves the agent vulnerable to termination and injection.
    /// Only call this during controlled shutdown.
    pub fn disable_global_protection(&self) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to kernel driver"));
        }

        warn!("Disabling global handle protection - agent will be vulnerable");
        // TODO: Send IOCTL_DISABLE_HANDLE_PROTECTION to driver
        Err(anyhow!(
            "Disable protection IOCTL failed - driver stub not implemented"
        ))
    }
}

impl Default for HandleProtectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HandleProtectionManager {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Request handle protection for the current process.
///
/// This is a convenience function that creates a temporary manager,
/// connects to the driver, and requests protection.
///
/// # Example
///
/// ```rust,ignore
/// use tamandua_agent::protection::handle_protection::request_handle_protection;
///
/// if let Err(e) = request_handle_protection() {
///     warn!("Handle protection not available: {}", e);
///     // Fall back to other protection mechanisms
/// }
/// ```
pub fn request_handle_protection() -> Result<()> {
    let mut manager = HandleProtectionManager::new();
    manager.connect()?;
    manager.request_handle_protection()
}

/// Query handle protection status.
///
/// Returns the current protection status, or a default (disabled) status
/// if the driver is not available.
pub fn get_protection_status() -> Result<HandleProtectionStatus> {
    let mut manager = HandleProtectionManager::new();

    // Try to connect, but return stub status if unavailable
    if manager.connect().is_err() {
        return Ok(HandleProtectionStatus::default());
    }

    manager.get_protection_status()
}

// =============================================================================
// Kernel Driver TODO
// =============================================================================

/// Kernel Driver Implementation Checklist
///
/// This documents the required work to implement handle protection in the
/// kernel driver (`apps/tamandua_driver/`).
///
/// ## Phase 1: Core Callback Implementation
///
/// - [ ] Define `PROTECTED_PROCESS` structure in driver
/// - [ ] Implement protected PID list with spinlock synchronization
/// - [ ] Register `ObRegisterCallbacks` with process and thread types
/// - [ ] Implement `ProcessPreOperationCallback`:
///   - [ ] Check if target PID is in protected list
///   - [ ] Strip dangerous access rights from `DesiredAccess`
///   - [ ] Log stripped access for audit trail
/// - [ ] Implement `ThreadPreOperationCallback` (similar logic)
/// - [ ] Handle callback unregistration on driver unload
///
/// ## Phase 2: IOCTL Interface
///
/// - [ ] Define IOCTL handler dispatch table
/// - [ ] Implement `IOCTL_ADD_PROTECTED_PID`:
///   - [ ] Validate caller is the agent (check signature/PID)
///   - [ ] Add PID to protected list
///   - [ ] Return success/failure status
/// - [ ] Implement `IOCTL_REMOVE_PROTECTED_PID`
/// - [ ] Implement `IOCTL_QUERY_PROTECTION_STATUS`
/// - [ ] Implement `IOCTL_ENABLE/DISABLE_HANDLE_PROTECTION`
///
/// ## Phase 3: Audit Logging
///
/// - [ ] Create circular buffer for stripped access events
/// - [ ] Capture requester PID, name, timestamp, access rights
/// - [ ] Implement `IOCTL_QUERY_STRIPPED_ACCESS_LOG`
/// - [ ] Consider ETW tracing integration for real-time alerts
///
/// ## Phase 4: Security Hardening
///
/// - [ ] Validate IOCTL callers (only agent can add/remove PIDs)
/// - [ ] Prevent callback unregistration by external code
/// - [ ] Handle edge cases (process exit during callback, etc.)
/// - [ ] Add anti-tampering for the driver itself
///
/// ## Phase 5: Testing & Certification
///
/// - [ ] Unit tests with HyperV test signing
/// - [ ] Integration tests with agent
/// - [ ] Performance benchmarking (callback overhead)
/// - [ ] Static analysis (PREfast, SDV)
/// - [ ] WHQL certification preparation
///
/// ## Reference Implementation
///
/// See Microsoft's Object Callback sample:
/// <https://github.com/microsoft/Windows-driver-samples/tree/main/general/obcallback>
///
/// ## Required Driver Structures (C)
///
/// ```c
/// // In tamandua_driver.h
///
/// #define TAMANDUA_DEVICE_TYPE 0x8022
/// #define HANDLE_PROTECTION_BASE 0x900
///
/// #define IOCTL_ADD_PROTECTED_PID \
///     CTL_CODE(TAMANDUA_DEVICE_TYPE, HANDLE_PROTECTION_BASE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/// #define IOCTL_REMOVE_PROTECTED_PID \
///     CTL_CODE(TAMANDUA_DEVICE_TYPE, HANDLE_PROTECTION_BASE + 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/// #define IOCTL_QUERY_PROTECTION_STATUS \
///     CTL_CODE(TAMANDUA_DEVICE_TYPE, HANDLE_PROTECTION_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS)
///
/// typedef struct _PROTECTED_PROCESS_ENTRY {
///     ULONG ProcessId;
///     ULONG Flags;
///     LARGE_INTEGER ProtectionTime;
///     LIST_ENTRY ListEntry;
/// } PROTECTED_PROCESS_ENTRY, *PPROTECTED_PROCESS_ENTRY;
///
/// typedef struct _HANDLE_PROTECTION_CONTEXT {
///     PVOID CallbackHandle;
///     LIST_ENTRY ProtectedProcessList;
///     KSPIN_LOCK ListLock;
///     ULONG ProtectedCount;
///     BOOLEAN Enabled;
///     // Statistics
///     volatile LONG64 TotalOperations;
///     volatile LONG64 ProcessAccessStrips;
///     volatile LONG64 ThreadAccessStrips;
///     volatile LONG64 HandleDupBlocks;
/// } HANDLE_PROTECTION_CONTEXT, *PHANDLE_PROTECTION_CONTEXT;
/// ```
pub struct KernelDriverTodo;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_codes() {
        // Verify IOCTL codes are correctly constructed
        // Format: [DeviceType:16][Access:2][Function:12][Method:2]

        // IOCTL_ADD_PROTECTED_PID should have:
        // DeviceType = 0x8022, Function = 0x900, Method = 0, Access = FILE_WRITE_ACCESS (2)
        let expected_add = (0x8022 << 16) | (2 << 14) | (0x900 << 2) | 0;
        assert_eq!(IOCTL_ADD_PROTECTED_PID, expected_add);

        // IOCTL_QUERY_PROTECTION_STATUS should have FILE_READ_ACCESS (1)
        let expected_query = (0x8022 << 16) | (1 << 14) | (0x902 << 2) | 0;
        assert_eq!(IOCTL_QUERY_PROTECTION_STATUS, expected_query);
    }

    #[test]
    fn test_protection_flags() {
        assert_eq!(HandleProtectionFlags::Full as u32, 0x001F);
        assert_eq!(HandleProtectionFlags::NoTerminate as u32, 0x0001);
    }

    #[test]
    fn test_manager_not_connected() {
        let manager = HandleProtectionManager::new();
        assert!(!manager.is_connected());

        // Should return default status when not connected
        let status = manager.get_protection_status();
        assert!(status.is_ok());
        let status = status.unwrap();
        assert!(!status.callbacks_registered);
        assert!(!status.protection_enabled);
    }

    #[test]
    fn test_request_without_connection() {
        let manager = HandleProtectionManager::new();
        let result = manager.request_handle_protection();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not connected"));
    }

    #[test]
    fn test_convenience_functions() {
        // These should fail gracefully when driver is not available
        let status = get_protection_status();
        assert!(status.is_ok());

        let protect = request_handle_protection();
        // Will fail because driver is not loaded
        assert!(protect.is_err());
    }
}
