//! macOS Endpoint Security Framework Integration
//!
//! This module provides real-time monitoring capabilities on macOS using
//! Apple's Endpoint Security framework. This is the most powerful and
//! comprehensive monitoring API available on macOS.
//!
//! ## Requirements
//!
//! - macOS 10.15 (Catalina) or later
//! - Endpoint Security entitlement: com.apple.developer.endpoint-security.client
//! - System Extension or MDM-approved deployment
//! - Full Disk Access permission
//!
//! ## Event Types Supported
//!
//! ### Process Events
//! - ES_EVENT_TYPE_AUTH_EXEC: Process execution (can block)
//! - ES_EVENT_TYPE_NOTIFY_FORK: Process fork
//! - ES_EVENT_TYPE_NOTIFY_EXIT: Process exit
//! - ES_EVENT_TYPE_NOTIFY_EXEC: Process execution (notification only)
//!
//! ### File Events
//! - ES_EVENT_TYPE_AUTH_OPEN: File open (can block)
//! - ES_EVENT_TYPE_AUTH_CREATE: File creation (can block)
//! - ES_EVENT_TYPE_AUTH_UNLINK: File deletion (can block)
//! - ES_EVENT_TYPE_AUTH_RENAME: File rename (can block)
//! - ES_EVENT_TYPE_NOTIFY_WRITE: File write (notification only)
//! - ES_EVENT_TYPE_AUTH_MMAP: Memory mapping (can block)
//!
//! ### Network Events
//! - ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: I/O Kit device access
//!
//! ## Architecture
//!
//! The Endpoint Security client runs in a separate thread and dispatches
//! events to the main telemetry pipeline. AUTH events support blocking
//! malicious operations in real-time.

/// Classify `es_new_client` failures into stable prerequisite codes.
///
/// Kept outside the macOS-only module so diagnostics and tests can run on
/// non-macOS hosts without linking EndpointSecurity.framework.
pub fn classify_new_client_result(result: u32) -> (&'static str, &'static str) {
    match result {
        0 => ("success", "EndpointSecurity client created successfully"),
        1 => (
            "invalid_argument",
            "Invalid EndpointSecurity client argument",
        ),
        2 => ("internal", "EndpointSecurity returned an internal error"),
        3 => (
            "missing_entitlement",
            "Missing com.apple.developer.endpoint-security.client entitlement",
        ),
        4 => (
            "not_permitted",
            "EndpointSecurity is not permitted; check TCC/FDA and system policy approval",
        ),
        5 => (
            "not_privileged",
            "EndpointSecurity direct client must run as root or from an approved System Extension",
        ),
        6 => (
            "too_many_clients",
            "macOS refused another EndpointSecurity client because the client limit is reached",
        ),
        _ => ("unknown", "Unknown EndpointSecurity client creation error"),
    }
}

#[cfg(all(target_os = "macos", not(no_endpoint_security)))]
pub mod es_client {
    use super::super::{
        Detection, DetectionType, EventPayload, EventType, FileEvent, ProcessEvent, Severity,
        TelemetryEvent,
    };
    use super::classify_new_client_result;
    use std::collections::HashMap;
    use std::ffi::{c_void, CStr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tracing::{debug, error, info, warn};

    // ========================================================================
    // Endpoint Security FFI Bindings
    // ========================================================================

    /// Endpoint Security client handle
    #[repr(C)]
    pub struct es_client_t {
        _data: [u8; 0],
    }

    /// Endpoint Security message structure
    #[repr(C)]
    pub struct es_message_t {
        pub version: u32,
        pub time: libc::timespec,
        pub mach_time: u64,
        pub deadline: u64,
        pub process: *const es_process_t,
        pub seq_num: u64,
        pub action_type: u32,
        pub event_type: u32,
        pub event: es_event_t,
        pub thread: *const c_void,
        pub global_seq_num: u64,
    }

    /// Process information from ES
    #[repr(C)]
    pub struct es_process_t {
        pub audit_token: audit_token_t,
        pub ppid: i32,
        pub original_ppid: i32,
        pub group_id: i32,
        pub session_id: i32,
        pub codesigning_flags: u32,
        pub is_platform_binary: bool,
        pub is_es_client: bool,
        pub cdhash: [u8; 20],
        pub signing_id: es_string_token_t,
        pub team_id: es_string_token_t,
        pub executable: *const es_file_t,
        pub tty: *const es_file_t,
        pub start_time: libc::timespec,
        pub responsible_audit_token: audit_token_t,
        pub parent_audit_token: audit_token_t,
    }

    /// Audit token for process identification
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct audit_token_t {
        pub val: [u32; 8],
    }

    /// String token from ES
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_string_token_t {
        pub length: usize,
        pub data: *const libc::c_char,
    }

    /// File information from ES
    #[repr(C)]
    pub struct es_file_t {
        pub path: es_string_token_t,
        pub path_truncated: bool,
        pub stat: libc::stat,
    }

    /// Event union (simplified - actual structure is complex)
    #[repr(C)]
    pub union es_event_t {
        pub exec: es_event_exec_t,
        pub fork: es_event_fork_t,
        pub open: es_event_open_t,
        pub create: es_event_create_t,
        pub rename: es_event_rename_t,
        pub unlink: es_event_unlink_t,
        pub write: es_event_write_t,
        pub mmap: es_event_mmap_t,
    }

    /// Exec event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_exec_t {
        pub target: *const es_process_t,
        pub args: es_args_t,
        pub dyld_exec_path: es_string_token_t,
    }

    /// Fork event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_fork_t {
        pub child: *const es_process_t,
    }

    /// Open event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_open_t {
        pub fflag: i32,
        pub file: *const es_file_t,
    }

    /// Create event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_create_t {
        pub destination_type: u32,
        pub destination: es_create_destination_t,
        pub acl: *const c_void,
    }

    /// Create destination union
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union es_create_destination_t {
        pub existing_file: *const es_file_t,
        pub new_path: es_new_path_t,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_new_path_t {
        pub dir: *const es_file_t,
        pub filename: es_string_token_t,
        pub mode: u32,
    }

    /// Rename event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_rename_t {
        pub source: *const es_file_t,
        pub destination_type: u32,
        pub destination: es_rename_destination_t,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union es_rename_destination_t {
        pub existing_file: *const es_file_t,
        pub new_path: es_new_path_t,
    }

    /// Unlink event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_unlink_t {
        pub target: *const es_file_t,
        pub parent_dir: *const es_file_t,
    }

    /// Write event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_write_t {
        pub target: *const es_file_t,
    }

    /// Mmap event data
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_event_mmap_t {
        pub source: *const es_file_t,
        pub file_pos: u64,
        pub flags: i32,
        pub protection: i32,
    }

    /// Command line arguments
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct es_args_t {
        pub count: u32,
        pub args: *const es_string_token_t,
    }

    // ES result codes
    pub const ES_NEW_CLIENT_RESULT_SUCCESS: u32 = 0;
    pub const ES_RESPOND_RESULT_SUCCESS: u32 = 0;
    pub const ES_AUTH_RESULT_ALLOW: u32 = 0;
    pub const ES_AUTH_RESULT_DENY: u32 = 1;

    // Event types
    pub const ES_EVENT_TYPE_AUTH_EXEC: u32 = 0;
    pub const ES_EVENT_TYPE_AUTH_OPEN: u32 = 1;
    pub const ES_EVENT_TYPE_AUTH_CREATE: u32 = 4;
    pub const ES_EVENT_TYPE_AUTH_UNLINK: u32 = 9;
    pub const ES_EVENT_TYPE_AUTH_RENAME: u32 = 10;
    pub const ES_EVENT_TYPE_AUTH_MMAP: u32 = 17;
    pub const ES_EVENT_TYPE_NOTIFY_EXEC: u32 = 42;
    pub const ES_EVENT_TYPE_NOTIFY_FORK: u32 = 43;
    pub const ES_EVENT_TYPE_NOTIFY_EXIT: u32 = 44;
    pub const ES_EVENT_TYPE_NOTIFY_WRITE: u32 = 48;

    // Action types
    pub const ES_ACTION_TYPE_AUTH: u32 = 0;
    pub const ES_ACTION_TYPE_NOTIFY: u32 = 1;

    // Extern declarations for the Endpoint Security framework
    // These are linked at runtime on macOS
    #[cfg(all(target_os = "macos", not(no_endpoint_security)))]
    #[link(name = "EndpointSecurity", kind = "framework")]
    extern "C" {
        fn es_new_client(
            client: *mut *mut es_client_t,
            handler: extern "C" fn(*const es_client_t, *const es_message_t),
        ) -> u32;

        fn es_delete_client(client: *mut es_client_t) -> u32;

        fn es_subscribe(client: *mut es_client_t, events: *const u32, event_count: u32) -> u32;

        fn es_unsubscribe_all(client: *mut es_client_t) -> u32;

        fn es_respond_auth_result(
            client: *const es_client_t,
            message: *const es_message_t,
            result: u32,
            cache: bool,
        ) -> u32;

        fn es_mute_path(client: *mut es_client_t, path: *const libc::c_char, path_type: u32)
            -> u32;
    }

    // ========================================================================
    // Endpoint Security Client Implementation
    // ========================================================================

    /// Configuration for the Endpoint Security client
    #[derive(Debug, Clone)]
    pub struct EndpointSecurityConfig {
        /// Enable blocking mode for AUTH events
        pub blocking_enabled: bool,
        /// Paths to mute (exclude from monitoring)
        pub muted_paths: Vec<String>,
        /// Event types to subscribe to
        pub subscribed_events: Vec<u32>,
        /// Enable process exec monitoring
        pub monitor_exec: bool,
        /// Enable file monitoring
        pub monitor_files: bool,
        /// Enable memory mapping monitoring
        pub monitor_mmap: bool,
    }

    impl Default for EndpointSecurityConfig {
        fn default() -> Self {
            Self {
                blocking_enabled: false, // Start in notification mode
                muted_paths: vec![
                    "/System/".to_string(),
                    "/usr/".to_string(),
                    "/private/var/folders/".to_string(),
                ],
                subscribed_events: vec![
                    ES_EVENT_TYPE_NOTIFY_EXEC,
                    ES_EVENT_TYPE_NOTIFY_FORK,
                    ES_EVENT_TYPE_NOTIFY_EXIT,
                    ES_EVENT_TYPE_NOTIFY_WRITE,
                ],
                monitor_exec: true,
                monitor_files: true,
                monitor_mmap: false, // Can be noisy
            }
        }
    }

    /// Endpoint Security client wrapper
    pub struct EndpointSecurityClient {
        client: *mut es_client_t,
        config: EndpointSecurityConfig,
        running: Arc<AtomicBool>,
        event_tx: mpsc::Sender<TelemetryEvent>,
    }

    // Global sender for the callback (C callback can't capture Rust closures)
    static mut GLOBAL_EVENT_TX: Option<mpsc::Sender<TelemetryEvent>> = None;
    static mut GLOBAL_BLOCKING_ENABLED: bool = false;

    impl EndpointSecurityClient {
        /// Create a new Endpoint Security client
        ///
        /// # Safety
        /// Requires the com.apple.developer.endpoint-security.client entitlement
        pub fn new(
            config: EndpointSecurityConfig,
            event_tx: mpsc::Sender<TelemetryEvent>,
        ) -> Result<Self, String> {
            let mut client: *mut es_client_t = std::ptr::null_mut();

            // Set up global sender for callback
            unsafe {
                GLOBAL_EVENT_TX = Some(event_tx.clone());
                GLOBAL_BLOCKING_ENABLED = config.blocking_enabled;
            }

            // Create the ES client
            let result = unsafe { es_new_client(&mut client, es_event_handler) };

            if result != ES_NEW_CLIENT_RESULT_SUCCESS {
                let (code, error_msg) = classify_new_client_result(result);
                return Err(format!(
                    "Failed to create ES client: {} ({}, code={})",
                    error_msg, result, code
                ));
            }

            info!("Endpoint Security client created successfully");

            let es_client = Self {
                client,
                config,
                running: Arc::new(AtomicBool::new(false)),
                event_tx,
            };

            Ok(es_client)
        }

        /// Start monitoring with configured event subscriptions
        pub fn start(&mut self) -> Result<(), String> {
            if self.running.load(Ordering::SeqCst) {
                return Ok(());
            }

            // Mute paths
            for path in &self.config.muted_paths {
                let c_path = std::ffi::CString::new(path.as_str())
                    .map_err(|e| format!("Invalid path: {}", e))?;
                unsafe {
                    es_mute_path(self.client, c_path.as_ptr(), 0); // 0 = literal path
                }
                debug!("Muted path: {}", path);
            }

            // Subscribe to events
            let events: Vec<u32> = self.config.subscribed_events.clone();
            let result = unsafe { es_subscribe(self.client, events.as_ptr(), events.len() as u32) };

            if result != 0 {
                return Err(format!("Failed to subscribe to events: {}", result));
            }

            self.running.store(true, Ordering::SeqCst);
            info!(
                "Endpoint Security monitoring started with {} event types",
                events.len()
            );

            Ok(())
        }

        /// Stop monitoring
        pub fn stop(&mut self) {
            if !self.running.load(Ordering::SeqCst) {
                return;
            }

            unsafe {
                es_unsubscribe_all(self.client);
            }

            self.running.store(false, Ordering::SeqCst);
            info!("Endpoint Security monitoring stopped");
        }

        /// Check if client is running
        pub fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }

        /// Enable or disable blocking mode
        pub fn set_blocking(&mut self, enabled: bool) {
            self.config.blocking_enabled = enabled;
            unsafe {
                GLOBAL_BLOCKING_ENABLED = enabled;
            }
        }
    }

    impl Drop for EndpointSecurityClient {
        fn drop(&mut self) {
            self.stop();
            if !self.client.is_null() {
                unsafe {
                    es_delete_client(self.client);
                }
            }
        }
    }

    /// Event handler callback invoked by the Endpoint Security framework
    extern "C" fn es_event_handler(client: *const es_client_t, message: *const es_message_t) {
        if message.is_null() {
            return;
        }

        let msg = unsafe { &*message };
        let tx = unsafe { GLOBAL_EVENT_TX.as_ref() };

        if tx.is_none() {
            // Respond to AUTH events even if we can't process them
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                unsafe {
                    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
                }
            }
            return;
        }

        let tx = tx.unwrap();

        // Process the event based on type
        let telemetry_event = match msg.event_type {
            ES_EVENT_TYPE_NOTIFY_EXEC | ES_EVENT_TYPE_AUTH_EXEC => process_exec_event(msg),
            ES_EVENT_TYPE_NOTIFY_FORK => process_fork_event(msg),
            ES_EVENT_TYPE_AUTH_OPEN | ES_EVENT_TYPE_NOTIFY_WRITE => process_file_event(msg),
            ES_EVENT_TYPE_AUTH_CREATE => process_create_event(msg),
            ES_EVENT_TYPE_AUTH_UNLINK => process_unlink_event(msg),
            ES_EVENT_TYPE_AUTH_RENAME => process_rename_event(msg),
            ES_EVENT_TYPE_AUTH_MMAP => process_mmap_event(msg),
            _ => None,
        };

        // Send event if we created one
        if let Some(event) = telemetry_event {
            let _ = tx.blocking_send(event);
        }

        // Respond to AUTH events
        if msg.action_type == ES_ACTION_TYPE_AUTH {
            let result = if unsafe { GLOBAL_BLOCKING_ENABLED } {
                // In blocking mode, you would implement your blocking logic here
                // For now, we allow everything
                ES_AUTH_RESULT_ALLOW
            } else {
                ES_AUTH_RESULT_ALLOW
            };

            unsafe {
                es_respond_auth_result(client, message, result, false);
            }
        }
    }

    // ========================================================================
    // Event Processing Functions
    // ========================================================================

    fn process_exec_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let exec = unsafe { &msg.event.exec };
        let target = unsafe { &*exec.target };
        let process = unsafe { &*msg.process };

        let path = get_executable_path(target);
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let cmdline = get_command_line(exec);
        let pid = get_pid_from_audit_token(&target.audit_token);
        let ppid = target.ppid as u32;

        // Get code signing info
        let (is_signed, signer) = get_codesign_info(target);

        Some(TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid,
                ppid,
                name,
                path,
                cmdline,
                user: get_user_from_audit_token(&target.audit_token),
                sha256: Vec::new(), // Would need to hash the executable
                entropy: 0.0,
                is_elevated: is_elevated_from_audit_token(&target.audit_token),
                parent_name: None, // Would need to look up parent
                parent_path: None,
                is_signed,
                signer,
                start_time: timespec_to_millis(&target.start_time),
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        ))
    }

    fn process_fork_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let fork = unsafe { &msg.event.fork };
        let child = unsafe { &*fork.child };
        let parent = unsafe { &*msg.process };

        let path = get_executable_path(child);
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let parent_path = get_executable_path(parent);
        let parent_name = std::path::Path::new(&parent_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string());

        let (is_signed, signer) = get_codesign_info(child);

        Some(TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid: get_pid_from_audit_token(&child.audit_token),
                ppid: get_pid_from_audit_token(&parent.audit_token),
                name,
                path,
                cmdline: String::new(),
                user: get_user_from_audit_token(&child.audit_token),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: is_elevated_from_audit_token(&child.audit_token),
                parent_name,
                parent_path: Some(parent_path),
                is_signed,
                signer,
                start_time: timespec_to_millis(&child.start_time),
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        ))
    }

    fn process_file_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let (path, operation) = match msg.event_type {
            ES_EVENT_TYPE_AUTH_OPEN => {
                let open = unsafe { &msg.event.open };
                let file = unsafe { &*open.file };
                (get_file_path(file), "open")
            }
            ES_EVENT_TYPE_NOTIFY_WRITE => {
                let write = unsafe { &msg.event.write };
                let file = unsafe { &*write.target };
                (get_file_path(file), "write")
            }
            _ => return None,
        };

        let process = unsafe { &*msg.process };
        let pid = get_pid_from_audit_token(&process.audit_token);
        let process_name = get_process_name(process);

        Some(TelemetryEvent::new(
            EventType::FileModify,
            Severity::Info,
            EventPayload::File(FileEvent {
                path,
                old_path: None,
                operation: operation.to_string(),
                pid,
                process_name,
                sha256: Vec::new(),
                size: 0,
                entropy: 0.0,
                file_type: "unknown".to_string(),
            }),
        ))
    }

    fn process_create_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let create = unsafe { &msg.event.create };
        let process = unsafe { &*msg.process };

        let path = if create.destination_type == 0 {
            // Existing file
            let file = unsafe { &*create.destination.existing_file };
            get_file_path(file)
        } else {
            // New path
            let new_path = unsafe { &create.destination.new_path };
            let dir = unsafe { &*new_path.dir };
            let dir_path = get_file_path(dir);
            let filename = get_string_token(&new_path.filename);
            format!("{}/{}", dir_path, filename)
        };

        let pid = get_pid_from_audit_token(&process.audit_token);
        let process_name = get_process_name(process);

        Some(TelemetryEvent::new(
            EventType::FileCreate,
            Severity::Info,
            EventPayload::File(FileEvent {
                path,
                old_path: None,
                operation: "create".to_string(),
                pid,
                process_name,
                sha256: Vec::new(),
                size: 0,
                entropy: 0.0,
                file_type: "unknown".to_string(),
            }),
        ))
    }

    fn process_unlink_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let unlink = unsafe { &msg.event.unlink };
        let file = unsafe { &*unlink.target };
        let process = unsafe { &*msg.process };

        let path = get_file_path(file);
        let pid = get_pid_from_audit_token(&process.audit_token);
        let process_name = get_process_name(process);

        Some(TelemetryEvent::new(
            EventType::FileDelete,
            Severity::Info,
            EventPayload::File(FileEvent {
                path,
                old_path: None,
                operation: "delete".to_string(),
                pid,
                process_name,
                sha256: Vec::new(),
                size: 0,
                entropy: 0.0,
                file_type: "unknown".to_string(),
            }),
        ))
    }

    fn process_rename_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let rename = unsafe { &msg.event.rename };
        let source = unsafe { &*rename.source };
        let process = unsafe { &*msg.process };

        let old_path = get_file_path(source);
        let new_path = if rename.destination_type == 0 {
            let file = unsafe { &*rename.destination.existing_file };
            get_file_path(file)
        } else {
            let new_path = unsafe { &rename.destination.new_path };
            let dir = unsafe { &*new_path.dir };
            let dir_path = get_file_path(dir);
            let filename = get_string_token(&new_path.filename);
            format!("{}/{}", dir_path, filename)
        };

        let pid = get_pid_from_audit_token(&process.audit_token);
        let process_name = get_process_name(process);

        Some(TelemetryEvent::new(
            EventType::FileRename,
            Severity::Info,
            EventPayload::File(FileEvent {
                path: new_path,
                old_path: Some(old_path),
                operation: "rename".to_string(),
                pid,
                process_name,
                sha256: Vec::new(),
                size: 0,
                entropy: 0.0,
                file_type: "unknown".to_string(),
            }),
        ))
    }

    fn process_mmap_event(msg: &es_message_t) -> Option<TelemetryEvent> {
        let mmap = unsafe { &msg.event.mmap };
        let source = unsafe { &*mmap.source };
        let process = unsafe { &*msg.process };

        // Only care about executable mappings
        const PROT_EXEC: i32 = 0x04;
        if (mmap.protection & PROT_EXEC) == 0 {
            return None;
        }

        let path = get_file_path(source);
        let pid = get_pid_from_audit_token(&process.audit_token);
        let process_name = get_process_name(process);

        Some(TelemetryEvent::new(
            EventType::ModuleLoad,
            Severity::Info,
            EventPayload::File(FileEvent {
                path,
                old_path: None,
                operation: "mmap_exec".to_string(),
                pid,
                process_name,
                sha256: Vec::new(),
                size: 0,
                entropy: 0.0,
                file_type: "executable".to_string(),
            }),
        ))
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn get_string_token(token: &es_string_token_t) -> String {
        if token.data.is_null() || token.length == 0 {
            return String::new();
        }

        unsafe {
            let slice = std::slice::from_raw_parts(token.data as *const u8, token.length);
            String::from_utf8_lossy(slice).to_string()
        }
    }

    fn get_file_path(file: &es_file_t) -> String {
        get_string_token(&file.path)
    }

    fn get_executable_path(process: &es_process_t) -> String {
        if process.executable.is_null() {
            return String::new();
        }
        let file = unsafe { &*process.executable };
        get_file_path(file)
    }

    fn get_process_name(process: &es_process_t) -> String {
        let path = get_executable_path(process);
        std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn get_command_line(exec: &es_event_exec_t) -> String {
        if exec.args.count == 0 || exec.args.args.is_null() {
            return String::new();
        }

        let args = unsafe { std::slice::from_raw_parts(exec.args.args, exec.args.count as usize) };

        args.iter()
            .map(|arg| get_string_token(arg))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn get_pid_from_audit_token(token: &audit_token_t) -> u32 {
        // PID is at index 5 in the audit_token
        token.val[5]
    }

    fn get_user_from_audit_token(token: &audit_token_t) -> String {
        // EUID is at index 1
        let euid = token.val[1];

        // Try to get username from UID
        unsafe {
            let pwd = libc::getpwuid(euid);
            if !pwd.is_null() && !(*pwd).pw_name.is_null() {
                if let Ok(name) = CStr::from_ptr((*pwd).pw_name).to_str() {
                    return name.to_string();
                }
            }
        }

        format!("uid:{}", euid)
    }

    fn is_elevated_from_audit_token(token: &audit_token_t) -> bool {
        // EUID is at index 1, check if root (0)
        token.val[1] == 0
    }

    fn get_codesign_info(process: &es_process_t) -> (bool, Option<String>) {
        // Check codesigning flags
        const CS_VALID: u32 = 0x0001;
        const CS_ADHOC: u32 = 0x0002;

        let is_signed = (process.codesigning_flags & CS_VALID) != 0
            && (process.codesigning_flags & CS_ADHOC) == 0;

        let signer = if is_signed {
            let signing_id = get_string_token(&process.signing_id);
            let team_id = get_string_token(&process.team_id);

            if !team_id.is_empty() {
                Some(format!("{} ({})", signing_id, team_id))
            } else if !signing_id.is_empty() {
                Some(signing_id)
            } else if process.is_platform_binary {
                Some("Apple".to_string())
            } else {
                None
            }
        } else {
            None
        };

        (is_signed, signer)
    }

    fn timespec_to_millis(ts: &libc::timespec) -> u64 {
        (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
    }
}

// ============================================================================
// Fallback for non-macOS platforms
// ============================================================================

#[cfg(any(not(target_os = "macos"), no_endpoint_security))]
pub mod es_client {
    use super::super::TelemetryEvent;
    use tokio::sync::mpsc;

    /// Placeholder configuration for non-macOS platforms
    #[derive(Debug, Clone, Default)]
    pub struct EndpointSecurityConfig;

    /// Placeholder client for non-macOS platforms
    pub struct EndpointSecurityClient;

    impl EndpointSecurityClient {
        pub fn new(
            _config: EndpointSecurityConfig,
            _event_tx: mpsc::Sender<TelemetryEvent>,
        ) -> Result<Self, String> {
            Err("Endpoint Security framework is not available in this build".to_string())
        }

        pub fn start(&mut self) -> Result<(), String> {
            Err("Endpoint Security framework is not available in this build".to_string())
        }

        pub fn stop(&mut self) {}

        pub fn is_running(&self) -> bool {
            false
        }

        pub fn set_blocking(&mut self, _enabled: bool) {}
    }
}

// Re-export the client
pub use es_client::{EndpointSecurityClient, EndpointSecurityConfig};

#[cfg(test)]
mod tests {
    use super::classify_new_client_result;

    #[test]
    fn classifies_endpoint_security_startup_failures() {
        assert_eq!(classify_new_client_result(3).0, "missing_entitlement");
        assert_eq!(classify_new_client_result(4).0, "not_permitted");
        assert_eq!(classify_new_client_result(5).0, "not_privileged");
        assert_eq!(classify_new_client_result(99).0, "unknown");
    }
}
