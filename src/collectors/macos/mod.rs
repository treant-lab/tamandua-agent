//! macOS-specific utilities and helpers
//!
//! This module provides platform-specific functionality for macOS monitoring,
//! including TCC database parsing, XPC service introspection, and system APIs.
//!
//! ## Architecture
//! - **system_apis**: Native FFI wrappers for Security.framework, proc_pidinfo
//! - **tcc_parser**: SQLite parser for TCC.db permission database
//! - **xpc_introspection**: XPC service enumeration and plist parsing

pub mod capabilities;
pub mod system_apis;
pub mod tcc_parser;
pub mod xpc_introspection;

// Capability/prerequisite reporting
pub use capabilities::{
    collect_macos_capability_report, endpoint_security_probe, full_disk_access_probe,
    system_extension_probe, tcc_probe, CapabilityProbe, CapabilityState, MacosCapabilityReport,
    PrereqCheck, PrereqStatus,
};

// System APIs - code signing, process info, FDA
pub use system_apis::{
    check_full_disk_access_detailed, get_process_audit_token, get_process_codesign_info,
    get_process_info_native, get_process_path_native, has_full_disk_access, CodesignInfo,
    FdaStatus, ProcessInfo,
};

// TCC database parsing
pub use tcc_parser::{
    get_system_tcc_path, get_user_tcc_path, parse_tcc_db, TccAuthValue, TccClientType, TccEntry,
    TccService,
};

// XPC introspection and launchd plist parsing
pub use xpc_introspection::{
    enumerate_xpc_services, parse_launchd_plist, parse_launchd_plist_simple, scan_launchd_plists,
    LaunchdPlistConfig, XpcConnection, XpcService, XpcServiceType,
};
