//! Windows Compatibility Layer
//!
//! Provides runtime detection and dynamic loading of Windows APIs
//! for maximum compatibility across Windows versions:
//! - Windows 7 SP1 (NT 6.1)
//! - Windows 8/8.1 (NT 6.2/6.3)
//! - Windows 10 (NT 10.0)
//! - Windows 11 (NT 10.0 build 22000+)
//!
//! APIs that don't exist on older versions are loaded dynamically
//! with graceful fallbacks.

#![cfg(target_os = "windows")]
// Wrappers around NtQueryInformationProcess / NtQueryInformationThread /
// NtReadVirtualMemory take opaque Windows HANDLE pointers whose validity is the
// caller's responsibility — the standard Windows FFI convention. Marking each
// wrapper `unsafe fn` would force every defensive collector that introspects a
// process to wrap call sites in `unsafe { ... }` without adding real safety
// information beyond what Windows kernel docs already require.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::c_void;
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Windows version information
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

impl WindowsVersion {
    pub const WIN7: Self = Self {
        major: 6,
        minor: 1,
        build: 0,
    };
    pub const WIN8: Self = Self {
        major: 6,
        minor: 2,
        build: 0,
    };
    pub const WIN81: Self = Self {
        major: 6,
        minor: 3,
        build: 0,
    };
    pub const WIN10: Self = Self {
        major: 10,
        minor: 0,
        build: 0,
    };
    pub const WIN10_1607: Self = Self {
        major: 10,
        minor: 0,
        build: 14393,
    }; // Anniversary Update
    pub const WIN10_1703: Self = Self {
        major: 10,
        minor: 0,
        build: 15063,
    }; // Creators Update
    pub const WIN10_1709: Self = Self {
        major: 10,
        minor: 0,
        build: 16299,
    }; // Fall Creators
    pub const WIN10_1803: Self = Self {
        major: 10,
        minor: 0,
        build: 17134,
    };
    pub const WIN10_1809: Self = Self {
        major: 10,
        minor: 0,
        build: 17763,
    };
    pub const WIN10_1903: Self = Self {
        major: 10,
        minor: 0,
        build: 18362,
    };
    pub const WIN10_2004: Self = Self {
        major: 10,
        minor: 0,
        build: 19041,
    };
    pub const WIN11: Self = Self {
        major: 10,
        minor: 0,
        build: 22000,
    };

    pub fn is_win10_or_later(&self) -> bool {
        *self >= Self::WIN10
    }

    pub fn is_win8_or_later(&self) -> bool {
        *self >= Self::WIN8
    }

    pub fn is_win11(&self) -> bool {
        *self >= Self::WIN11
    }

    pub fn supports_etw_realtime(&self) -> bool {
        // ETW real-time sessions work on all supported versions
        *self >= Self::WIN7
    }

    pub fn supports_amsi(&self) -> bool {
        // AMSI introduced in Windows 10
        *self >= Self::WIN10
    }

    pub fn supports_process_mitigation(&self) -> bool {
        // Process mitigation policies in Windows 8+
        *self >= Self::WIN8
    }

    pub fn supports_ppl(&self) -> bool {
        // Protected Process Light in Windows 8.1+
        *self >= Self::WIN81
    }

    pub fn name(&self) -> &'static str {
        if *self >= Self::WIN11 {
            "Windows 11"
        } else if *self >= Self::WIN10 {
            "Windows 10"
        } else if *self >= Self::WIN81 {
            "Windows 8.1"
        } else if *self >= Self::WIN8 {
            "Windows 8"
        } else if *self >= Self::WIN7 {
            "Windows 7"
        } else {
            "Windows (Legacy)"
        }
    }
}

impl std::fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (NT {}.{} Build {})",
            self.name(),
            self.major,
            self.minor,
            self.build
        )
    }
}

/// Cached Windows version
static WINDOWS_VERSION: OnceLock<WindowsVersion> = OnceLock::new();

/// Get the current Windows version
pub fn get_windows_version() -> WindowsVersion {
    *WINDOWS_VERSION.get_or_init(|| detect_windows_version())
}

fn detect_windows_version() -> WindowsVersion {
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOEXW};

    unsafe {
        let mut osvi: OSVERSIONINFOEXW = std::mem::zeroed();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

        // GetVersionEx is deprecated but works for compatibility detection
        // For accurate Win10+ detection, we use RtlGetVersion via NTDLL
        if let Ok(version) = get_version_from_ntdll() {
            info!(
                version = %version,
                "Windows version detected via RtlGetVersion"
            );
            return version;
        }

        // Fallback to GetVersionEx (may be manifested)
        #[allow(deprecated)]
        if GetVersionExW(&mut osvi as *mut _ as *mut _).is_ok() {
            let version = WindowsVersion {
                major: osvi.dwMajorVersion,
                minor: osvi.dwMinorVersion,
                build: osvi.dwBuildNumber,
            };
            info!(
                version = %version,
                "Windows version detected via GetVersionEx"
            );
            return version;
        }

        // Ultimate fallback: assume Windows 10
        warn!("Could not detect Windows version, assuming Windows 10");
        WindowsVersion::WIN10
    }
}

/// Get accurate version from NTDLL (not affected by manifests)
fn get_version_from_ntdll() -> Result<WindowsVersion, ()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::NTSTATUS;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOEXW) -> NTSTATUS;

    #[repr(C)]
    struct OSVERSIONINFOEXW {
        dw_os_version_info_size: u32,
        dw_major_version: u32,
        dw_minor_version: u32,
        dw_build_number: u32,
        dw_platform_id: u32,
        sz_csd_version: [u16; 128],
        w_service_pack_major: u16,
        w_service_pack_minor: u16,
        w_suite_mask: u16,
        w_product_type: u8,
        w_reserved: u8,
    }

    unsafe {
        let ntdll = GetModuleHandleW(PCWSTR::from_raw(
            "ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr(),
        ))
        .map_err(|_| ())?;

        let rtl_get_version = GetProcAddress(
            ntdll,
            windows::core::PCSTR::from_raw(b"RtlGetVersion\0".as_ptr()),
        );

        if let Some(func) = rtl_get_version {
            let rtl_get_version: RtlGetVersionFn = std::mem::transmute(func);

            let mut osvi: OSVERSIONINFOEXW = std::mem::zeroed();
            osvi.dw_os_version_info_size = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

            let status = rtl_get_version(&mut osvi);
            if status.0 >= 0 {
                return Ok(WindowsVersion {
                    major: osvi.dw_major_version,
                    minor: osvi.dw_minor_version,
                    build: osvi.dw_build_number,
                });
            }
        }

        Err(())
    }
}

/// Dynamic API loader for optional Windows APIs
pub struct DynamicApi {
    module: windows::Win32::Foundation::HMODULE,
}

impl DynamicApi {
    /// Load a DLL dynamically
    pub fn load(dll_name: &str) -> Option<Self> {
        use windows::core::HSTRING;
        use windows::Win32::System::LibraryLoader::LoadLibraryW;

        unsafe {
            match LoadLibraryW(&HSTRING::from(dll_name)) {
                Ok(handle) if !handle.is_invalid() => {
                    debug!(dll = %dll_name, "Loaded dynamic library");
                    Some(Self { module: handle })
                }
                _ => {
                    debug!(dll = %dll_name, "Failed to load dynamic library");
                    None
                }
            }
        }
    }

    /// Get a function pointer from the loaded DLL
    pub unsafe fn get_proc<T>(&self, name: &str) -> Option<T> {
        use windows::Win32::System::LibraryLoader::GetProcAddress;

        let name_cstr = std::ffi::CString::new(name).ok()?;
        let proc = GetProcAddress(
            self.module,
            windows::core::PCSTR::from_raw(name_cstr.as_ptr() as *const u8),
        );

        proc.map(|p| std::mem::transmute_copy(&p))
    }
}

impl Drop for DynamicApi {
    fn drop(&mut self) {
        // Note: We intentionally don't call FreeLibrary here.
        // The DLLs (ntdll.dll, advapi32.dll, amsi.dll) are typically
        // loaded for the entire process lifetime and freeing them
        // could cause issues with other code that depends on them.
        // The OS will clean up when the process exits.
    }
}

/// AMSI API wrapper with dynamic loading (Windows 10+ only)
pub mod amsi {
    use super::*;
    use std::sync::OnceLock;

    static AMSI_API: OnceLock<Option<AmsiApi>> = OnceLock::new();

    pub struct AmsiApi {
        _dll: DynamicApi,
        pub initialize: AmsiInitializeFn,
        pub uninitialize: AmsiUninitializeFn,
        pub open_session: AmsiOpenSessionFn,
        pub close_session: AmsiCloseSessionFn,
        pub scan_buffer: AmsiScanBufferFn,
        pub scan_string: AmsiScanStringFn,
    }

    // AMSI function signatures
    pub type AmsiInitializeFn =
        unsafe extern "system" fn(app_name: *const u16, amsi_context: *mut *mut c_void) -> i32;

    pub type AmsiUninitializeFn = unsafe extern "system" fn(amsi_context: *mut c_void);

    pub type AmsiOpenSessionFn =
        unsafe extern "system" fn(amsi_context: *mut c_void, amsi_session: *mut *mut c_void) -> i32;

    pub type AmsiCloseSessionFn =
        unsafe extern "system" fn(amsi_context: *mut c_void, amsi_session: *mut c_void);

    pub type AmsiScanBufferFn = unsafe extern "system" fn(
        amsi_context: *mut c_void,
        buffer: *const u8,
        length: u32,
        content_name: *const u16,
        amsi_session: *mut c_void,
        result: *mut i32,
    ) -> i32;

    pub type AmsiScanStringFn = unsafe extern "system" fn(
        amsi_context: *mut c_void,
        string: *const u16,
        content_name: *const u16,
        amsi_session: *mut c_void,
        result: *mut i32,
    ) -> i32;

    /// Get AMSI API if available
    pub fn get_amsi_api() -> Option<&'static AmsiApi> {
        AMSI_API
            .get_or_init(|| {
                if !get_windows_version().supports_amsi() {
                    info!("AMSI not available on this Windows version");
                    return None;
                }

                let dll = DynamicApi::load("amsi.dll")?;

                unsafe {
                    let api = AmsiApi {
                        initialize: dll.get_proc("AmsiInitialize")?,
                        uninitialize: dll.get_proc("AmsiUninitialize")?,
                        open_session: dll.get_proc("AmsiOpenSession")?,
                        close_session: dll.get_proc("AmsiCloseSession")?,
                        scan_buffer: dll.get_proc("AmsiScanBuffer")?,
                        scan_string: dll.get_proc("AmsiScanString")?,
                        _dll: dll,
                    };

                    info!("AMSI API loaded successfully");
                    Some(api)
                }
            })
            .as_ref()
    }

    /// AMSI result codes
    pub const AMSI_RESULT_CLEAN: i32 = 0;
    pub const AMSI_RESULT_NOT_DETECTED: i32 = 1;
    pub const AMSI_RESULT_BLOCKED_BY_ADMIN_START: i32 = 0x4000;
    pub const AMSI_RESULT_BLOCKED_BY_ADMIN_END: i32 = 0x4fff;
    pub const AMSI_RESULT_DETECTED: i32 = 32768;

    pub fn is_malicious(result: i32) -> bool {
        result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START
    }
}

/// ETW API wrapper with compatibility for different Windows versions
pub mod etw {
    use super::*;
    use std::sync::OnceLock;

    static ETW_API: OnceLock<Option<EtwApi>> = OnceLock::new();

    pub struct EtwApi {
        _advapi32: DynamicApi,
        pub start_trace: StartTraceFn,
        pub control_trace: ControlTraceFn,
        pub enable_trace_ex2: Option<EnableTraceEx2Fn>, // Win8+
        pub enable_trace: EnableTraceFn,                // Legacy
        pub open_trace: OpenTraceFn,
        pub process_trace: ProcessTraceFn,
        pub close_trace: CloseTraceFn,
    }

    // ETW function signatures
    pub type StartTraceFn = unsafe extern "system" fn(
        trace_handle: *mut u64,
        instance_name: *const u16,
        properties: *mut c_void,
    ) -> u32;

    pub type ControlTraceFn = unsafe extern "system" fn(
        trace_handle: u64,
        instance_name: *const u16,
        properties: *mut c_void,
        control_code: u32,
    ) -> u32;

    pub type EnableTraceEx2Fn = unsafe extern "system" fn(
        trace_handle: u64,
        provider_guid: *const c_void,
        control_code: u32,
        level: u8,
        match_any_keyword: u64,
        match_all_keyword: u64,
        timeout: u32,
        enable_parameters: *const c_void,
    ) -> u32;

    pub type EnableTraceFn = unsafe extern "system" fn(
        enable: u32,
        enable_flag: u32,
        enable_level: u32,
        control_guid: *const c_void,
        trace_handle: u64,
    ) -> u32;

    pub type OpenTraceFn = unsafe extern "system" fn(logfile: *mut c_void) -> u64;

    pub type ProcessTraceFn = unsafe extern "system" fn(
        handle_array: *const u64,
        handle_count: u32,
        start_time: *const i64,
        end_time: *const i64,
    ) -> u32;

    pub type CloseTraceFn = unsafe extern "system" fn(trace_handle: u64) -> u32;

    /// Get ETW API
    pub fn get_etw_api() -> Option<&'static EtwApi> {
        ETW_API
            .get_or_init(|| {
                let advapi32 = DynamicApi::load("advapi32.dll")?;

                unsafe {
                    let api = EtwApi {
                        start_trace: advapi32.get_proc("StartTraceW")?,
                        control_trace: advapi32.get_proc("ControlTraceW")?,
                        enable_trace_ex2: advapi32.get_proc("EnableTraceEx2"), // May not exist on Win7
                        enable_trace: advapi32.get_proc("EnableTrace")?,
                        open_trace: advapi32.get_proc("OpenTraceW")?,
                        process_trace: advapi32.get_proc("ProcessTrace")?,
                        close_trace: advapi32.get_proc("CloseTrace")?,
                        _advapi32: advapi32,
                    };

                    if api.enable_trace_ex2.is_some() {
                        info!("ETW API loaded with EnableTraceEx2 (Win8+ mode)");
                    } else {
                        info!("ETW API loaded with EnableTrace (Win7 compatibility mode)");
                    }

                    Some(api)
                }
            })
            .as_ref()
    }

    // ETW control codes
    pub const EVENT_CONTROL_CODE_DISABLE_PROVIDER: u32 = 0;
    pub const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;
    pub const EVENT_TRACE_CONTROL_STOP: u32 = 1;
    pub const EVENT_TRACE_CONTROL_QUERY: u32 = 0;

    // ETW trace levels
    pub const TRACE_LEVEL_NONE: u8 = 0;
    pub const TRACE_LEVEL_CRITICAL: u8 = 1;
    pub const TRACE_LEVEL_ERROR: u8 = 2;
    pub const TRACE_LEVEL_WARNING: u8 = 3;
    pub const TRACE_LEVEL_INFORMATION: u8 = 4;
    pub const TRACE_LEVEL_VERBOSE: u8 = 5;

    // ETW flags
    pub const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x00000100;
    pub const EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING: u32 = 0x10000000;
    pub const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;

    // Error codes
    pub const ERROR_SUCCESS: u32 = 0;
    pub const ERROR_ALREADY_EXISTS: u32 = 183;
    pub const ERROR_ACCESS_DENIED: u32 = 5;
}

/// NT API for advanced process information
/// Sources: ntinternals.net, geoffchappell.com, ReactOS
pub mod ntapi {
    use super::*;
    use std::sync::OnceLock;

    static NT_API: OnceLock<Option<NtApi>> = OnceLock::new();

    /// Extended NT API with undocumented functions
    pub struct NtApi {
        _ntdll: DynamicApi,
        // Core query functions
        pub nt_query_system_information: NtQuerySystemInformationFn,
        pub nt_query_information_process: NtQueryInformationProcessFn,
        pub nt_query_information_thread: Option<NtQueryInformationThreadFn>,
        pub nt_query_object: Option<NtQueryObjectFn>,
        pub nt_query_virtual_memory: Option<NtQueryVirtualMemoryFn>,
        // Memory functions
        pub nt_read_virtual_memory: Option<NtReadVirtualMemoryFn>,
        pub nt_write_virtual_memory: Option<NtWriteVirtualMemoryFn>,
        // Handle functions
        pub nt_duplicate_object: Option<NtDuplicateObjectFn>,
        pub nt_close: Option<NtCloseFn>,
        // Thread functions (for injection detection)
        pub nt_get_context_thread: Option<NtGetContextThreadFn>,
        pub nt_suspend_thread: Option<NtSuspendThreadFn>,
        pub nt_resume_thread: Option<NtResumeThreadFn>,
    }

    // Function type definitions
    pub type NtQuerySystemInformationFn = unsafe extern "system" fn(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    pub type NtQueryInformationProcessFn = unsafe extern "system" fn(
        process_handle: *mut c_void,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    pub type NtQueryInformationThreadFn = unsafe extern "system" fn(
        thread_handle: *mut c_void,
        thread_information_class: u32,
        thread_information: *mut c_void,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    pub type NtQueryObjectFn = unsafe extern "system" fn(
        handle: *mut c_void,
        object_information_class: u32,
        object_information: *mut c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    pub type NtQueryVirtualMemoryFn = unsafe extern "system" fn(
        process_handle: *mut c_void,
        base_address: *mut c_void,
        memory_information_class: u32,
        memory_information: *mut c_void,
        memory_information_length: usize,
        return_length: *mut usize,
    ) -> i32;

    pub type NtReadVirtualMemoryFn = unsafe extern "system" fn(
        process_handle: *mut c_void,
        base_address: *mut c_void,
        buffer: *mut c_void,
        buffer_size: usize,
        number_of_bytes_read: *mut usize,
    ) -> i32;

    pub type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
        process_handle: *mut c_void,
        base_address: *mut c_void,
        buffer: *const c_void,
        buffer_size: usize,
        number_of_bytes_written: *mut usize,
    ) -> i32;

    pub type NtDuplicateObjectFn = unsafe extern "system" fn(
        source_process_handle: *mut c_void,
        source_handle: *mut c_void,
        target_process_handle: *mut c_void,
        target_handle: *mut *mut c_void,
        desired_access: u32,
        handle_attributes: u32,
        options: u32,
    ) -> i32;

    pub type NtCloseFn = unsafe extern "system" fn(handle: *mut c_void) -> i32;

    pub type NtGetContextThreadFn =
        unsafe extern "system" fn(thread_handle: *mut c_void, thread_context: *mut c_void) -> i32;

    pub type NtSuspendThreadFn = unsafe extern "system" fn(
        thread_handle: *mut c_void,
        previous_suspend_count: *mut u32,
    ) -> i32;

    pub type NtResumeThreadFn = unsafe extern "system" fn(
        thread_handle: *mut c_void,
        previous_suspend_count: *mut u32,
    ) -> i32;

    /// Get NT API
    pub fn get_nt_api() -> Option<&'static NtApi> {
        NT_API
            .get_or_init(|| {
                let ntdll = DynamicApi::load("ntdll.dll")?;

                unsafe {
                    let api = NtApi {
                        nt_query_system_information: ntdll.get_proc("NtQuerySystemInformation")?,
                        nt_query_information_process: ntdll
                            .get_proc("NtQueryInformationProcess")?,
                        nt_query_information_thread: ntdll.get_proc("NtQueryInformationThread"),
                        nt_query_object: ntdll.get_proc("NtQueryObject"),
                        nt_query_virtual_memory: ntdll.get_proc("NtQueryVirtualMemory"),
                        nt_read_virtual_memory: ntdll.get_proc("NtReadVirtualMemory"),
                        nt_write_virtual_memory: ntdll.get_proc("NtWriteVirtualMemory"),
                        nt_duplicate_object: ntdll.get_proc("NtDuplicateObject"),
                        nt_close: ntdll.get_proc("NtClose"),
                        nt_get_context_thread: ntdll.get_proc("NtGetContextThread"),
                        nt_suspend_thread: ntdll.get_proc("NtSuspendThread"),
                        nt_resume_thread: ntdll.get_proc("NtResumeThread"),
                        _ntdll: ntdll,
                    };

                    info!("Extended NT API loaded successfully");
                    Some(api)
                }
            })
            .as_ref()
    }

    // ========================================
    // SYSTEM INFORMATION CLASSES (ntinternals.net)
    // ========================================
    pub const SYSTEM_BASIC_INFORMATION: u32 = 0;
    pub const SYSTEM_PROCESSOR_INFORMATION: u32 = 1;
    pub const SYSTEM_PERFORMANCE_INFORMATION: u32 = 2;
    pub const SYSTEM_TIME_OF_DAY_INFORMATION: u32 = 3;
    pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;
    pub const SYSTEM_CALL_COUNT_INFORMATION: u32 = 6;
    pub const SYSTEM_DEVICE_INFORMATION: u32 = 7;
    pub const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION: u32 = 8;
    pub const SYSTEM_FLAGS_INFORMATION: u32 = 9;
    pub const SYSTEM_MODULE_INFORMATION: u32 = 11;
    pub const SYSTEM_HANDLE_INFORMATION: u32 = 16;
    pub const SYSTEM_OBJECT_INFORMATION: u32 = 17;
    pub const SYSTEM_PAGEFILE_INFORMATION: u32 = 18;
    pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION: u32 = 35;
    pub const SYSTEM_EXTENDED_PROCESS_INFORMATION: u32 = 57;
    pub const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
    pub const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;
    pub const SYSTEM_ISOLATED_USER_MODE_INFORMATION: u32 = 165;

    // ========================================
    // PROCESS INFORMATION CLASSES (geoffchappell.com)
    // ========================================
    pub const PROCESS_BASIC_INFORMATION: u32 = 0;
    pub const PROCESS_QUOTA_LIMITS: u32 = 1;
    pub const PROCESS_IO_COUNTERS: u32 = 2;
    pub const PROCESS_VM_COUNTERS: u32 = 3;
    pub const PROCESS_TIMES: u32 = 4;
    pub const PROCESS_DEBUG_PORT: u32 = 7;
    pub const PROCESS_WOW64_INFORMATION: u32 = 26;
    pub const PROCESS_IMAGE_FILE_NAME: u32 = 27;
    pub const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
    pub const PROCESS_DEBUG_FLAGS: u32 = 31;
    pub const PROCESS_HANDLE_INFORMATION: u32 = 51;
    pub const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
    pub const PROCESS_PROTECTION_INFORMATION: u32 = 61;
    pub const PROCESS_MEMORY_EXHAUSTION_INFO: u32 = 63;

    // ========================================
    // THREAD INFORMATION CLASSES
    // ========================================
    pub const THREAD_BASIC_INFORMATION: u32 = 0;
    pub const THREAD_TIMES: u32 = 1;
    pub const THREAD_PRIORITY: u32 = 2;
    pub const THREAD_BASE_PRIORITY: u32 = 3;
    pub const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
    pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 17; // Anti-debug technique
    pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    pub const THREAD_SUSPEND_COUNT: u32 = 35;

    // ========================================
    // MEMORY INFORMATION CLASSES
    // ========================================
    pub const MEMORY_BASIC_INFORMATION: u32 = 0;
    pub const MEMORY_WORKING_SET_INFORMATION: u32 = 1;
    pub const MEMORY_MAPPED_FILENAME_INFORMATION: u32 = 2;
    pub const MEMORY_REGION_INFORMATION: u32 = 3;
    pub const MEMORY_WORKING_SET_EX_INFORMATION: u32 = 4;

    // ========================================
    // OBJECT INFORMATION CLASSES
    // ========================================
    pub const OBJECT_BASIC_INFORMATION: u32 = 0;
    pub const OBJECT_NAME_INFORMATION: u32 = 1;
    pub const OBJECT_TYPE_INFORMATION: u32 = 2;
    pub const OBJECT_TYPES_INFORMATION: u32 = 3;
    pub const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;

    // ========================================
    // NTSTATUS CODES
    // ========================================
    pub const STATUS_SUCCESS: i32 = 0;
    pub const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
    pub const STATUS_BUFFER_TOO_SMALL: i32 = 0xC0000023u32 as i32;
    pub const STATUS_ACCESS_DENIED: i32 = 0xC0000022u32 as i32;
    pub const STATUS_INVALID_HANDLE: i32 = 0xC0000008u32 as i32;
    pub const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;
    pub const STATUS_NO_MORE_ENTRIES: i32 = 0x8000001Au32 as i32;
    pub const STATUS_BUFFER_OVERFLOW: i32 = 0x80000005u32 as i32;

    // ========================================
    // DUPLICATE HANDLE OPTIONS
    // ========================================
    pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
    pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
    pub const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x00000004;

    // ========================================
    // STRUCTURES
    // ========================================

    /// SYSTEM_HANDLE_TABLE_ENTRY_INFO from ntinternals.net
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SystemHandleTableEntryInfo {
        pub process_id: u16,
        pub creator_back_trace_index: u16,
        pub object_type_index: u8,
        pub handle_attributes: u8,
        pub handle_value: u16,
        pub object: *mut c_void,
        pub granted_access: u32,
    }

    /// SYSTEM_HANDLE_INFORMATION structure
    #[repr(C)]
    pub struct SystemHandleInformation {
        pub number_of_handles: u32,
        pub handles: [SystemHandleTableEntryInfo; 1], // Variable length array
    }

    /// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX for Win8+
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SystemHandleTableEntryInfoEx {
        pub object: *mut c_void,
        pub unique_process_id: usize,
        pub handle_value: usize,
        pub granted_access: u32,
        pub creator_back_trace_index: u16,
        pub object_type_index: u16,
        pub handle_attributes: u32,
        pub reserved: u32,
    }

    /// SYSTEM_EXTENDED_HANDLE_INFORMATION for Win8+
    #[repr(C)]
    pub struct SystemExtendedHandleInformation {
        pub number_of_handles: usize,
        pub reserved: usize,
        pub handles: [SystemHandleTableEntryInfoEx; 1], // Variable length array
    }

    /// PROCESS_BASIC_INFORMATION structure
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ProcessBasicInformation {
        pub exit_status: i32,
        pub peb_base_address: *mut c_void,
        pub affinity_mask: usize,
        pub base_priority: i32,
        pub unique_process_id: usize,
        pub inherited_from_unique_process_id: usize, // Real parent PID
    }

    /// UNICODE_STRING structure
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct UnicodeString {
        pub length: u16,
        pub maximum_length: u16,
        pub buffer: *mut u16,
    }

    /// OBJECT_ATTRIBUTES structure
    #[repr(C)]
    pub struct ObjectAttributes {
        pub length: u32,
        pub root_directory: *mut c_void,
        pub object_name: *mut UnicodeString,
        pub attributes: u32,
        pub security_descriptor: *mut c_void,
        pub security_quality_of_service: *mut c_void,
    }

    /// THREAD_BASIC_INFORMATION structure
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ThreadBasicInformation {
        pub exit_status: i32,
        pub teb_base_address: *mut c_void,
        pub client_id: ClientId,
        pub affinity_mask: usize,
        pub priority: i32,
        pub base_priority: i32,
    }

    /// CLIENT_ID structure
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ClientId {
        pub unique_process: usize,
        pub unique_thread: usize,
    }

    /// MEMORY_BASIC_INFORMATION structure
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct MemoryBasicInformation {
        pub base_address: *mut c_void,
        pub allocation_base: *mut c_void,
        pub allocation_protect: u32,
        pub region_size: usize,
        pub state: u32,
        pub protect: u32,
        pub type_: u32,
    }

    /// PS_PROTECTION structure (for PPL detection)
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct PsProtection {
        pub level: u8,
    }

    impl PsProtection {
        pub fn protection_type(&self) -> u8 {
            self.level & 0x07
        }

        pub fn protection_signer(&self) -> u8 {
            (self.level >> 4) & 0x0F
        }

        pub fn is_protected(&self) -> bool {
            self.level != 0
        }
    }

    // Protection types
    pub const PS_PROTECTED_TYPE_NONE: u8 = 0;
    pub const PS_PROTECTED_TYPE_PROTECTED_LIGHT: u8 = 1;
    pub const PS_PROTECTED_TYPE_PROTECTED: u8 = 2;

    // Protection signers
    pub const PS_PROTECTED_SIGNER_NONE: u8 = 0;
    pub const PS_PROTECTED_SIGNER_AUTHENTICODE: u8 = 1;
    pub const PS_PROTECTED_SIGNER_CODEGEN: u8 = 2;
    pub const PS_PROTECTED_SIGNER_ANTIMALWARE: u8 = 3;
    pub const PS_PROTECTED_SIGNER_LSA: u8 = 4;
    pub const PS_PROTECTED_SIGNER_WINDOWS: u8 = 5;
    pub const PS_PROTECTED_SIGNER_WINTCB: u8 = 6;

    // ========================================
    // HELPER FUNCTIONS
    // ========================================

    /// Get the real parent process ID (not spoofable)
    pub fn get_real_parent_pid(process_handle: *mut c_void) -> Option<u32> {
        let api = get_nt_api()?;
        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;

        let status = unsafe {
            (api.nt_query_information_process)(
                process_handle,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            Some(pbi.inherited_from_unique_process_id as u32)
        } else {
            None
        }
    }

    /// Get process command line using NtQueryInformationProcess
    pub fn get_process_command_line(process_handle: *mut c_void) -> Option<String> {
        let api = get_nt_api()?;

        // First call to get buffer size
        let mut return_length: u32 = 0;
        let status = unsafe {
            (api.nt_query_information_process)(
                process_handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut return_length,
            )
        };

        if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
            return None;
        }

        // Allocate buffer and retry
        let mut buffer: Vec<u8> = vec![0; return_length as usize];
        let status = unsafe {
            (api.nt_query_information_process)(
                process_handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                return_length,
                &mut return_length,
            )
        };

        if status != STATUS_SUCCESS {
            return None;
        }

        // Parse UNICODE_STRING from buffer
        let unicode_str = unsafe { &*(buffer.as_ptr() as *const UnicodeString) };
        if unicode_str.buffer.is_null() || unicode_str.length == 0 {
            return None;
        }

        let char_count = (unicode_str.length / 2) as usize;
        let slice = unsafe { std::slice::from_raw_parts(unicode_str.buffer, char_count) };

        // Strip trailing null terminators — Windows UNICODE_STRING.Length
        // sometimes includes the null terminator in the byte count.
        let trimmed = match slice.iter().rposition(|&c| c != 0) {
            Some(pos) => &slice[..=pos],
            None => return None,
        };

        Some(String::from_utf16_lossy(trimmed))
    }

    /// Check if a process is protected (PPL)
    pub fn is_process_protected(process_handle: *mut c_void) -> Option<PsProtection> {
        let api = get_nt_api()?;
        let mut protection: PsProtection = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;

        let status = unsafe {
            (api.nt_query_information_process)(
                process_handle,
                PROCESS_PROTECTION_INFORMATION,
                &mut protection as *mut _ as *mut c_void,
                std::mem::size_of::<PsProtection>() as u32,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            Some(protection)
        } else {
            None
        }
    }

    /// Get thread start address (useful for detecting injection)
    pub fn get_thread_start_address(thread_handle: *mut c_void) -> Option<usize> {
        let api = get_nt_api()?;
        let query_fn = api.nt_query_information_thread?;

        let mut start_address: usize = 0;
        let mut return_length: u32 = 0;

        let status = unsafe {
            query_fn(
                thread_handle,
                THREAD_QUERY_SET_WIN32_START_ADDRESS,
                &mut start_address as *mut _ as *mut c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            Some(start_address)
        } else {
            None
        }
    }

    /// Check if thread has hide-from-debugger flag (anti-debug technique)
    pub fn is_thread_hidden_from_debugger(thread_handle: *mut c_void) -> bool {
        let api = match get_nt_api() {
            Some(api) => api,
            None => return false,
        };
        let query_fn = match api.nt_query_information_thread {
            Some(f) => f,
            None => return false,
        };

        let mut hidden: u32 = 0;
        let mut return_length: u32 = 0;

        let status = unsafe {
            query_fn(
                thread_handle,
                THREAD_HIDE_FROM_DEBUGGER,
                &mut hidden as *mut _ as *mut c_void,
                std::mem::size_of::<u32>() as u32,
                &mut return_length,
            )
        };

        status == STATUS_SUCCESS && hidden != 0
    }

    /// Read memory from a remote process
    pub fn read_process_memory(
        process_handle: *mut c_void,
        base_address: *mut c_void,
        buffer: &mut [u8],
    ) -> Option<usize> {
        let api = get_nt_api()?;
        let read_fn = api.nt_read_virtual_memory?;

        let mut bytes_read: usize = 0;
        let status = unsafe {
            read_fn(
                process_handle,
                base_address,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                &mut bytes_read,
            )
        };

        if status == STATUS_SUCCESS {
            Some(bytes_read)
        } else {
            None
        }
    }
}

/// WMI API for fallback monitoring on older systems
pub mod wmi {

    /// Check if WMI is available (always true on Windows)
    pub fn is_available() -> bool {
        true
    }

    /// WMI event query for process creation (fallback for ETW)
    pub const PROCESS_CREATE_QUERY: &str =
        "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";

    /// WMI event query for process termination
    pub const PROCESS_DELETE_QUERY: &str =
        "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";
}

/// Capability flags for the current system
#[derive(Debug, Clone)]
pub struct SystemCapabilities {
    pub version: WindowsVersion,
    pub has_etw: bool,
    pub has_etw_ex2: bool,
    pub has_amsi: bool,
    pub has_ppl: bool,
    pub has_process_mitigation: bool,
    pub has_nt_query_system_info: bool,
    pub is_elevated: bool,
}

impl SystemCapabilities {
    pub fn detect() -> Self {
        let version = get_windows_version();
        let has_etw = etw::get_etw_api().is_some();
        let has_etw_ex2 = etw::get_etw_api()
            .map(|api| api.enable_trace_ex2.is_some())
            .unwrap_or(false);
        let has_amsi = amsi::get_amsi_api().is_some();
        let has_nt_query = ntapi::get_nt_api().is_some();

        Self {
            version,
            has_etw,
            has_etw_ex2,
            has_amsi,
            has_ppl: version.supports_ppl(),
            has_process_mitigation: version.supports_process_mitigation(),
            has_nt_query_system_info: has_nt_query,
            is_elevated: is_elevated(),
        }
    }
}

/// Check if the current process is running elevated
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Log system capabilities at startup
pub fn log_capabilities() {
    let caps = SystemCapabilities::detect();

    info!(
        version = %caps.version,
        elevated = caps.is_elevated,
        etw = caps.has_etw,
        etw_ex2 = caps.has_etw_ex2,
        amsi = caps.has_amsi,
        ppl = caps.has_ppl,
        nt_query = caps.has_nt_query_system_info,
        "System capabilities detected"
    );

    if !caps.is_elevated {
        warn!("Running without elevation - some features will be limited");
    }

    if !caps.has_etw {
        warn!("ETW not available - using fallback monitoring");
    }

    if !caps.has_amsi {
        info!("AMSI not available on this Windows version");
    }
}

/// Check if a process (by PID) is running elevated
///
/// Uses OpenProcessToken + GetTokenInformation to query TOKEN_ELEVATION.
/// Returns false if the process cannot be opened or queried.
pub fn is_process_elevated(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    // System and idle processes are always elevated
    if pid == 0 || pid == 4 {
        return true;
    }

    unsafe {
        let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut token_handle = Default::default();
        if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
            let _ = CloseHandle(process_handle);
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Check if a file has a valid Authenticode signature
///
/// Uses WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2.
/// Returns true if the file is signed with a trusted certificate.
pub fn is_file_signed(path: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::GUID;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID =
        GUID::from_u128(0x00AAC56B_CD44_11d0_8CC2_00C04FC295EE_u128);

    // Convert path to wide string with null terminator
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = windows::core::PCWSTR::from_raw(wide_path.as_ptr());
        file_info.hFile = Default::default();
        file_info.pgKnownSubject = std::ptr::null_mut();

        let mut trust_data: WINTRUST_DATA = std::mem::zeroed();
        trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        trust_data.pPolicyCallbackData = std::ptr::null_mut();
        trust_data.pSIPClientData = std::ptr::null_mut();
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.Anonymous.pFile = &mut file_info;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust_data.hWVTStateData = Default::default();
        trust_data.pwszURLReference = windows::core::PWSTR::null();
        trust_data.dwProvFlags = Default::default();
        trust_data.dwUIContext = Default::default();

        let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(
            None,
            &mut action_id,
            &mut trust_data as *mut _ as *mut c_void,
        );

        // 0 = ERROR_SUCCESS = valid signature
        result == 0
    }
}

/// Get the signer name of a signed file
///
/// Uses CryptQueryObject and CertGetNameString to extract the subject CN.
/// Returns None if the file is unsigned or the signer cannot be determined.
pub fn get_file_signer(path: &str) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
        CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
        CERT_INFO, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_CONTENT_TYPE,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_FORMAT_TYPE,
        CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING,
        X509_ASN_ENCODING,
    };

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut encoding: CERT_QUERY_ENCODING_TYPE = Default::default();
        let mut content_type: CERT_QUERY_CONTENT_TYPE = Default::default();
        let mut format_type: CERT_QUERY_FORMAT_TYPE = Default::default();
        let mut cert_store: HCERTSTORE = Default::default();
        let mut msg_handle: *mut c_void = std::ptr::null_mut();

        // Query the file for embedded signature
        let result = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut encoding),
            Some(&mut content_type),
            Some(&mut format_type),
            Some(&mut cert_store),
            Some(&mut msg_handle as *mut *mut c_void),
            None,
        );

        if result.is_err() {
            return None;
        }

        // Get signer info size
        let mut signer_info_size: u32 = 0;
        let param_result = CryptMsgGetParam(
            msg_handle as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut signer_info_size,
        );

        if param_result.is_err() || signer_info_size == 0 {
            let _ = CryptMsgClose(Some(msg_handle as *const c_void));
            let _ = CertCloseStore(cert_store, 0);
            return None;
        }

        // Get signer info
        let mut signer_info_buffer: Vec<u8> = vec![0; signer_info_size as usize];
        let param_result = CryptMsgGetParam(
            msg_handle as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_info_buffer.as_mut_ptr() as *mut c_void),
            &mut signer_info_size,
        );

        if param_result.is_err() {
            let _ = CryptMsgClose(Some(msg_handle as *const c_void));
            let _ = CertCloseStore(cert_store, 0);
            return None;
        }

        // Extract issuer and serial number for certificate lookup
        #[repr(C)]
        struct CMSG_SIGNER_INFO {
            dw_version: u32,
            issuer: windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
            serial_number: windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
            // ... more fields we don't need
        }

        let signer_info = &*(signer_info_buffer.as_ptr() as *const CMSG_SIGNER_INFO);

        // Build CERT_INFO for certificate lookup
        let mut cert_info: CERT_INFO = std::mem::zeroed();
        cert_info.Issuer = signer_info.issuer;
        cert_info.SerialNumber = signer_info.serial_number;

        // Find the signer certificate
        let cert_context = CertFindCertificateInStore(
            cert_store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const _ as *const c_void),
            None,
        );

        let signer_name = if !cert_context.is_null() {
            // Get the simple display name (CN)
            let mut name_buffer: Vec<u16> = vec![0; 256];
            let name_len = CertGetNameStringW(
                cert_context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                None,
                Some(&mut name_buffer),
            );

            if name_len > 1 {
                // name_len includes null terminator
                let name = String::from_utf16_lossy(&name_buffer[..(name_len as usize - 1)]);
                Some(name.trim().to_string())
            } else {
                None
            }
        } else {
            None
        };

        // Cleanup
        if !cert_context.is_null() {
            let _ = CertFreeCertificateContext(Some(cert_context as *const CERT_CONTEXT));
        }
        let _ = CryptMsgClose(Some(msg_handle as *const c_void));
        let _ = CertCloseStore(cert_store, 0);

        signer_name.filter(|s| !s.is_empty())
    }
}
