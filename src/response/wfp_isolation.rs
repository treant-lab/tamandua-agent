//! Windows Filtering Platform (WFP) network isolation
//!
//! Implements network isolation and per-IP blocking using the Windows Filtering
//! Platform kernel API instead of `netsh` commands. WFP filters are applied at
//! the Application Layer Enforcement (ALE) layers, which intercept connection
//! attempts before data reaches the network stack.
//!
//! Key advantages over netsh:
//! - Filters are applied atomically inside WFP transactions
//! - Sublayer-based isolation prevents other tools from overriding our rules
//! - Filter IDs are tracked for precise removal
//! - Drop on module cleanup ensures no orphaned rules
//!
//! Requires SYSTEM or administrator privileges to open the WFP engine.

// WFP isolation. Scaffolded filter-tracking fields retained for future
// per-process and IPv6 isolation paths.
#![allow(dead_code, unused_variables)]

#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(target_os = "windows")]
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Windows-only imports
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
use windows::core::GUID;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HANDLE;

// WFP types are exposed via raw FFI since the `windows` crate v0.52 does not
// provide a fully typed WFP binding.  We declare the FFI functions ourselves
// and call them through the fwpuclnt.dll library.

// ---------------------------------------------------------------------------
// WFP FFI declarations
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod ffi {
    use windows::core::GUID;
    use windows::Win32::Foundation::HANDLE;

    /// WFP display data (name + description)
    #[repr(C)]
    pub struct FWPM_DISPLAY_DATA0 {
        pub name: *mut u16,
        pub description: *mut u16,
    }

    /// WFP sublayer
    #[repr(C)]
    pub struct FWPM_SUBLAYER0 {
        pub sub_layer_key: GUID,
        pub display_data: FWPM_DISPLAY_DATA0,
        pub flags: u32,
        pub provider_key: *const GUID,
        pub provider_data: FWP_BYTE_BLOB,
        pub weight: u16,
    }

    /// Byte blob for provider data
    #[repr(C)]
    pub struct FWP_BYTE_BLOB {
        pub size: u32,
        pub data: *mut u8,
    }

    /// FWP_VALUE0 - used for filter weight
    #[repr(C)]
    pub struct FWP_VALUE0 {
        pub value_type: u32,
        pub value: FWP_VALUE0_UNION,
    }

    #[repr(C)]
    pub union FWP_VALUE0_UNION {
        pub uint8: u8,
        pub uint16: u16,
        pub uint32: u32,
        pub uint64: *mut u64,
        pub int8: i8,
        pub int16: i16,
        pub int32: i32,
        pub int64: *mut i64,
        pub float32: f32,
        pub double64: *mut f64,
        pub byte_array16: *mut FWP_BYTE_ARRAY16,
        pub byte_blob: *mut FWP_BYTE_BLOB,
        pub sid: *mut u8,
        pub sd: *mut u8,
        pub token_information: *mut u8,
        pub token_access_information: *mut u8,
        pub unicode_string: *mut u16,
        pub byte_array6: *mut [u8; 6],
    }

    /// FWP_CONDITION_VALUE0 - used for filter conditions
    #[repr(C)]
    pub struct FWP_CONDITION_VALUE0 {
        pub value_type: u32,
        pub value: FWP_VALUE0_UNION,
    }

    /// 16-byte array for IPv6 addresses
    #[repr(C)]
    pub struct FWP_BYTE_ARRAY16 {
        pub byte_array16: [u8; 16],
    }

    /// Filter condition
    #[repr(C)]
    pub struct FWPM_FILTER_CONDITION0 {
        pub field_key: GUID,
        pub match_type: u32,
        pub condition_value: FWP_CONDITION_VALUE0,
    }

    /// Filter action
    #[repr(C)]
    pub struct FWPM_ACTION0 {
        pub action_type: u32,
        pub filter_type: GUID,
    }

    /// WFP filter
    #[repr(C)]
    pub struct FWPM_FILTER0 {
        pub filter_key: GUID,
        pub display_data: FWPM_DISPLAY_DATA0,
        pub flags: u32,
        pub provider_key: *const GUID,
        pub provider_data: FWP_BYTE_BLOB,
        pub layer_key: GUID,
        pub sub_layer_key: GUID,
        pub weight: FWP_VALUE0,
        pub num_filter_conditions: u32,
        pub filter_condition: *mut FWPM_FILTER_CONDITION0,
        pub action: FWPM_ACTION0,
        // The rest of FWPM_FILTER0 fields are context-specific; zero-pad.
        pub _context_union: [u8; 24],
        pub _reserved: *mut GUID,
        pub filter_id: u64,
        pub effective_weight: FWP_VALUE0,
    }

    // FWP type constants
    pub const FWP_UINT8: u32 = 0;
    pub const FWP_UINT16: u32 = 1;
    pub const FWP_UINT32: u32 = 2;
    pub const FWP_BYTE_ARRAY16_TYPE: u32 = 10;

    // FWP match type constants
    pub const FWP_MATCH_EQUAL: u32 = 0;

    // FWP action types
    pub const FWP_ACTION_BLOCK: u32 = 0x00001001; // FWP_ACTION_FLAG_TERMINATING | FWP_ACTION_BLOCK
    pub const FWP_ACTION_PERMIT: u32 = 0x00001000; // FWP_ACTION_FLAG_TERMINATING | FWP_ACTION_PERMIT

    // FWP_E_ALREADY_EXISTS
    pub const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;

    // Well-known layer GUIDs
    // FWPM_LAYER_ALE_AUTH_CONNECT_V4
    pub const FWPM_LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID::from_values(
        0xc38d57d1,
        0x05a7,
        0x4c33,
        [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
    );

    // FWPM_LAYER_ALE_AUTH_CONNECT_V6
    pub const FWPM_LAYER_ALE_AUTH_CONNECT_V6: GUID = GUID::from_values(
        0x4a72393b,
        0x319f,
        0x44bc,
        [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xce],
    );

    // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
    pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: GUID = GUID::from_values(
        0xe1cd9fe7,
        0xf4b5,
        0x4273,
        [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
    );

    // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
    pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: GUID = GUID::from_values(
        0xa3b42c97,
        0x9f04,
        0x4672,
        [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
    );

    // Condition field GUIDs
    // FWPM_CONDITION_IP_REMOTE_ADDRESS
    pub const FWPM_CONDITION_IP_REMOTE_ADDRESS: GUID = GUID::from_values(
        0xb235ae9a,
        0x1d64,
        0x49b8,
        [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
    );

    // FWPM_CONDITION_IP_LOCAL_ADDRESS
    pub const FWPM_CONDITION_IP_LOCAL_ADDRESS: GUID = GUID::from_values(
        0xd9ee00de,
        0xc1ef,
        0x4617,
        [0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57],
    );

    // FWPM_CONDITION_IP_PROTOCOL
    pub const FWPM_CONDITION_IP_PROTOCOL: GUID = GUID::from_values(
        0x3971ef2b,
        0x623e,
        0x4f9a,
        [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7],
    );

    // FWPM_CONDITION_IP_REMOTE_PORT
    pub const FWPM_CONDITION_IP_REMOTE_PORT: GUID = GUID::from_values(
        0xc35a604d,
        0xd22b,
        0x4e1a,
        [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
    );

    // RPC authentication
    pub const RPC_C_AUTHN_WINNT: u32 = 10;

    // FFI function declarations from fwpuclnt.dll
    #[link(name = "fwpuclnt")]
    extern "system" {
        pub fn FwpmEngineOpen0(
            server_name: *const u16,
            authn_service: u32,
            auth_identity: *const std::ffi::c_void,
            session: *const std::ffi::c_void,
            engine_handle: *mut HANDLE,
        ) -> u32;

        pub fn FwpmEngineClose0(engine_handle: HANDLE) -> u32;

        pub fn FwpmSubLayerAdd0(
            engine_handle: HANDLE,
            sub_layer: *const FWPM_SUBLAYER0,
            sd: *const std::ffi::c_void,
        ) -> u32;

        pub fn FwpmSubLayerDeleteByKey0(engine_handle: HANDLE, key: *const GUID) -> u32;

        pub fn FwpmFilterAdd0(
            engine_handle: HANDLE,
            filter: *const FWPM_FILTER0,
            sd: *const std::ffi::c_void,
            id: *mut u64,
        ) -> u32;

        pub fn FwpmFilterDeleteById0(engine_handle: HANDLE, id: u64) -> u32;

        pub fn FwpmTransactionBegin0(engine_handle: HANDLE, flags: u32) -> u32;

        pub fn FwpmTransactionCommit0(engine_handle: HANDLE) -> u32;

        pub fn FwpmTransactionAbort0(engine_handle: HANDLE) -> u32;
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const TAMANDUA_SUBLAYER: GUID = GUID::from_values(
    0x7A6D_616E, // "taman" in hex-ish
    0x6475,      // "du"
    0x6100,      // "a\0"
    [0xED, 0x52, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01],
);

/// Filter weight: isolation BLOCK rules get a high weight (0xFFFF = 65535)
/// so they take priority over default Windows Firewall rules.
#[cfg(target_os = "windows")]
const BLOCK_WEIGHT: u16 = 0xFFFF;

/// PERMIT exception weight: must be higher than block weight in WFP evaluation
/// order so permit exceptions override the blanket blocks. Because WFP evaluates
/// within a sublayer by weight (highest first) and permits win ties, we use a
/// value that, combined with our action, wins over blocks.
#[cfg(target_os = "windows")]
const PERMIT_WEIGHT: u16 = 0xFFFE;

/// IP block weight: lower than isolation but still above default.
#[cfg(target_os = "windows")]
const IP_BLOCK_WEIGHT: u16 = 0xFF00;

// ---------------------------------------------------------------------------
// Filter tag
// ---------------------------------------------------------------------------

/// Tags allow us to group filters so we can remove them selectively.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterTag {
    /// Full network isolation filters (block + permit exceptions)
    Isolation,
    /// Per-IP block filters added via BlockIP command
    IpBlock,
}

// ---------------------------------------------------------------------------
// WfpIsolation
// ---------------------------------------------------------------------------

/// Manages WFP engine handle, sublayer registration, and filter lifecycle.
///
/// Thread-safety: interior `Mutex` protects the state so the struct can be
/// shared across async tasks via `Arc<WfpIsolation>`.
#[cfg(target_os = "windows")]
pub struct WfpIsolation {
    inner: Mutex<WfpInner>,
}

#[cfg(target_os = "windows")]
struct WfpInner {
    engine_handle: HANDLE,
    engine_open: bool,
    sublayer_key: GUID,
    /// All active filter IDs, tagged for selective removal
    filters: Vec<(u64, FilterTag)>,
    /// Per-IP filter IDs for targeted unblock
    ip_filters: HashMap<String, Vec<u64>>,
}

// HANDLE is Send/Sync-safe for WFP engine handles
#[cfg(target_os = "windows")]
unsafe impl Send for WfpInner {}

#[cfg(target_os = "windows")]
impl WfpIsolation {
    /// Create a new WFP isolation manager. Does NOT open the engine yet.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(WfpInner {
                engine_handle: HANDLE(0),
                engine_open: false,
                sublayer_key: TAMANDUA_SUBLAYER,
                filters: Vec::new(),
                ip_filters: HashMap::new(),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Engine lifecycle
    // -----------------------------------------------------------------------

    /// Open the WFP engine and register the Tamandua sublayer.
    pub fn open_engine(&self) -> Result<(), WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if inner.engine_open {
            debug!("WFP engine already open");
            return Ok(());
        }

        if !is_elevated() {
            return Err(WfpError::NotElevated);
        }

        let mut handle = HANDLE(0);

        let status = unsafe {
            ffi::FwpmEngineOpen0(
                std::ptr::null(),       // local engine
                ffi::RPC_C_AUTHN_WINNT, // NTLM auth
                std::ptr::null(),       // default identity
                std::ptr::null(),       // persistent session
                &mut handle,
            )
        };

        if status != 0 {
            return Err(WfpError::EngineOpen(status));
        }

        inner.engine_handle = handle;
        inner.engine_open = true;
        info!("WFP engine opened successfully");

        // Register our sublayer
        Self::register_sublayer(&inner)?;

        Ok(())
    }

    /// Close the WFP engine.
    pub fn close_engine(&self) -> Result<(), WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if !inner.engine_open {
            return Ok(());
        }

        let status = unsafe { ffi::FwpmEngineClose0(inner.engine_handle) };
        if status != 0 {
            warn!(status, "FwpmEngineClose0 returned non-zero status");
        }

        inner.engine_handle = HANDLE(0);
        inner.engine_open = false;
        info!("WFP engine closed");

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sublayer
    // -----------------------------------------------------------------------

    fn register_sublayer(inner: &WfpInner) -> Result<(), WfpError> {
        let mut name_wide = to_wide("Tamandua EDR Network Isolation");
        let mut desc_wide = to_wide("Network isolation sublayer managed by Tamandua EDR agent");

        let sublayer = ffi::FWPM_SUBLAYER0 {
            sub_layer_key: inner.sublayer_key,
            display_data: ffi::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: desc_wide.as_mut_ptr(),
            },
            flags: 0,
            provider_key: std::ptr::null(),
            provider_data: ffi::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: 0xFFFF,
        };

        let status =
            unsafe { ffi::FwpmSubLayerAdd0(inner.engine_handle, &sublayer, std::ptr::null()) };

        // FWP_E_ALREADY_EXISTS is fine
        if status != 0 && status != ffi::FWP_E_ALREADY_EXISTS {
            return Err(WfpError::SublayerAdd(status));
        }

        info!("WFP sublayer registered (or already exists)");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Network isolation
    // -----------------------------------------------------------------------

    /// Apply full network isolation.
    ///
    /// 1. BLOCK all outbound at ALE_AUTH_CONNECT_V4 / V6
    /// 2. BLOCK all inbound at ALE_AUTH_RECV_ACCEPT_V4 / V6
    /// 3. PERMIT exceptions for loopback, DNS, server IP, and allowed IPs
    pub fn apply_isolation(
        &self,
        server_ip: Option<IpAddr>,
        server_port: Option<u16>,
        allowed_ips: &[IpAddr],
    ) -> Result<Vec<u64>, WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if !inner.engine_open {
            return Err(WfpError::EngineNotOpen);
        }

        // Begin transaction for atomic application
        let status = unsafe { ffi::FwpmTransactionBegin0(inner.engine_handle, 0) };
        if status != 0 {
            return Err(WfpError::TransactionBegin(status));
        }

        let mut filter_ids = Vec::new();

        let result = (|| -> Result<(), WfpError> {
            // --- BLOCK rules (no conditions = match everything) ---

            filter_ids.push(Self::add_block_all_filter(
                &inner,
                "Tamandua: Block All Outbound IPv4",
                ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            )?);

            filter_ids.push(Self::add_block_all_filter(
                &inner,
                "Tamandua: Block All Outbound IPv6",
                ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            )?);

            filter_ids.push(Self::add_block_all_filter(
                &inner,
                "Tamandua: Block All Inbound IPv4",
                ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            )?);

            filter_ids.push(Self::add_block_all_filter(
                &inner,
                "Tamandua: Block All Inbound IPv6",
                ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            )?);

            // --- PERMIT exceptions ---

            // Loopback IPv4 (127.0.0.1)
            filter_ids.extend(Self::add_ip_permit_both_dirs(
                &inner,
                "Tamandua: Permit Loopback IPv4",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )?);

            // Loopback IPv6 (::1)
            filter_ids.extend(Self::add_ip_permit_both_dirs(
                &inner,
                "Tamandua: Permit Loopback IPv6",
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            )?);

            // DNS (UDP port 53, outbound V4 + V6)
            filter_ids.push(Self::add_dns_permit(
                &inner,
                "Tamandua: Permit DNS UDP53 V4",
                ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            )?);
            filter_ids.push(Self::add_dns_permit(
                &inner,
                "Tamandua: Permit DNS UDP53 V6",
                ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            )?);

            // Server IP exception
            if let Some(srv_ip) = server_ip {
                let desc = format!("Tamandua: Permit Server {}", srv_ip);
                if let Some(port) = server_port {
                    filter_ids.extend(Self::add_ip_port_permit(&inner, &desc, srv_ip, port)?);
                } else {
                    filter_ids.extend(Self::add_ip_permit_both_dirs(&inner, &desc, srv_ip)?);
                }
            }

            // Additional allowed IPs
            for ip in allowed_ips {
                let desc = format!("Tamandua: Permit Allowed {}", ip);
                filter_ids.extend(Self::add_ip_permit_both_dirs(&inner, &desc, *ip)?);
            }

            Ok(())
        })();

        match result {
            Ok(()) => {
                let status = unsafe { ffi::FwpmTransactionCommit0(inner.engine_handle) };
                if status != 0 {
                    return Err(WfpError::TransactionCommit(status));
                }

                for &id in &filter_ids {
                    inner.filters.push((id, FilterTag::Isolation));
                }

                info!(
                    filter_count = filter_ids.len(),
                    "WFP network isolation applied"
                );
                Ok(filter_ids)
            }
            Err(e) => {
                unsafe { ffi::FwpmTransactionAbort0(inner.engine_handle) };
                Err(e)
            }
        }
    }

    /// Remove all isolation filters (preserves per-IP block filters).
    pub fn remove_isolation(&self) -> Result<usize, WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if !inner.engine_open {
            return Err(WfpError::EngineNotOpen);
        }

        let mut removed = 0usize;
        let mut remaining = Vec::new();
        let engine_handle = inner.engine_handle;

        for (id, tag) in inner.filters.drain(..) {
            if tag == FilterTag::Isolation {
                let status = unsafe { ffi::FwpmFilterDeleteById0(engine_handle, id) };
                if status == 0 {
                    removed += 1;
                } else {
                    warn!(filter_id = id, status, "Failed to delete isolation filter");
                }
            } else {
                remaining.push((id, tag));
            }
        }

        inner.filters = remaining;
        info!(removed, "WFP isolation filters removed");
        Ok(removed)
    }

    // -----------------------------------------------------------------------
    // Per-IP blocking
    // -----------------------------------------------------------------------

    /// Block a specific IP address (both inbound and outbound).
    pub fn block_ip(&self, ip: IpAddr) -> Result<Vec<u64>, WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if !inner.engine_open {
            return Err(WfpError::EngineNotOpen);
        }

        let ip_str = ip.to_string();
        let mut filter_ids = Vec::new();

        let status = unsafe { ffi::FwpmTransactionBegin0(inner.engine_handle, 0) };
        if status != 0 {
            return Err(WfpError::TransactionBegin(status));
        }

        let result = (|| -> Result<(), WfpError> {
            match ip {
                IpAddr::V4(v4) => {
                    filter_ids.push(Self::add_ipv4_filter(
                        &inner,
                        &format!("Tamandua: Block IP {} Outbound", ip_str),
                        ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        ffi::FWP_ACTION_BLOCK,
                        IP_BLOCK_WEIGHT,
                        v4,
                    )?);
                    filter_ids.push(Self::add_ipv4_filter(
                        &inner,
                        &format!("Tamandua: Block IP {} Inbound", ip_str),
                        ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                        ffi::FWP_ACTION_BLOCK,
                        IP_BLOCK_WEIGHT,
                        v4,
                    )?);
                }
                IpAddr::V6(v6) => {
                    filter_ids.push(Self::add_ipv6_filter(
                        &inner,
                        &format!("Tamandua: Block IP {} Outbound", ip_str),
                        ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        ffi::FWP_ACTION_BLOCK,
                        IP_BLOCK_WEIGHT,
                        v6,
                    )?);
                    filter_ids.push(Self::add_ipv6_filter(
                        &inner,
                        &format!("Tamandua: Block IP {} Inbound", ip_str),
                        ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                        ffi::FWP_ACTION_BLOCK,
                        IP_BLOCK_WEIGHT,
                        v6,
                    )?);
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                let status = unsafe { ffi::FwpmTransactionCommit0(inner.engine_handle) };
                if status != 0 {
                    return Err(WfpError::TransactionCommit(status));
                }

                for &id in &filter_ids {
                    inner.filters.push((id, FilterTag::IpBlock));
                }
                inner.ip_filters.insert(ip_str.clone(), filter_ids.clone());

                info!(ip = %ip_str, filter_count = filter_ids.len(), "WFP IP block applied");
                Ok(filter_ids)
            }
            Err(e) => {
                unsafe { ffi::FwpmTransactionAbort0(inner.engine_handle) };
                Err(e)
            }
        }
    }

    /// Remove block filters for a specific IP address.
    pub fn unblock_ip(&self, ip: IpAddr) -> Result<usize, WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if !inner.engine_open {
            return Err(WfpError::EngineNotOpen);
        }

        let ip_str = ip.to_string();
        let mut removed = 0usize;

        if let Some(ids) = inner.ip_filters.remove(&ip_str) {
            for id in &ids {
                let status = unsafe { ffi::FwpmFilterDeleteById0(inner.engine_handle, *id) };
                if status == 0 {
                    removed += 1;
                } else {
                    warn!(filter_id = id, status, ip = %ip_str, "Failed to delete IP block filter");
                }
            }
            inner.filters.retain(|(id, _)| !ids.contains(id));
        } else {
            warn!(ip = %ip_str, "No WFP filters found for IP");
        }

        info!(ip = %ip_str, removed, "WFP IP block removed");
        Ok(removed)
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    /// Remove ALL Tamandua filters and close the engine.
    pub fn cleanup(&self) -> Result<(), WfpError> {
        let mut inner = self.inner.lock().map_err(|_| WfpError::LockPoisoned)?;

        if !inner.engine_open {
            return Ok(());
        }

        let mut removed = 0usize;
        let engine_handle = inner.engine_handle;
        for (id, _tag) in inner.filters.drain(..) {
            let status = unsafe { ffi::FwpmFilterDeleteById0(engine_handle, id) };
            if status == 0 {
                removed += 1;
            } else {
                debug!(
                    filter_id = id,
                    status, "Failed to remove filter during cleanup"
                );
            }
        }
        inner.ip_filters.clear();

        // Try to remove the sublayer
        let _status =
            unsafe { ffi::FwpmSubLayerDeleteByKey0(inner.engine_handle, &inner.sublayer_key) };

        let status = unsafe { ffi::FwpmEngineClose0(inner.engine_handle) };
        if status != 0 {
            warn!(status, "FwpmEngineClose0 returned non-zero during cleanup");
        }

        inner.engine_handle = HANDLE(0);
        inner.engine_open = false;

        info!(removed, "WFP cleanup complete");
        Ok(())
    }

    /// Check whether isolation is currently active.
    pub fn is_isolated(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .filters
                    .iter()
                    .any(|(_, tag)| *tag == FilterTag::Isolation)
            })
            .unwrap_or(false)
    }

    /// Return the count of active filters.
    pub fn filter_count(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.filters.len())
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Private: filter construction helpers
    // -----------------------------------------------------------------------

    /// Add a BLOCK filter with no conditions (matches everything on the layer).
    fn add_block_all_filter(
        inner: &WfpInner,
        name: &str,
        layer_key: GUID,
    ) -> Result<u64, WfpError> {
        let mut name_wide = to_wide(name);

        let filter = ffi::FWPM_FILTER0 {
            filter_key: GUID::zeroed(),
            display_data: ffi::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            flags: 0,
            provider_key: std::ptr::null(),
            provider_data: ffi::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layer_key,
            sub_layer_key: inner.sublayer_key,
            weight: ffi::FWP_VALUE0 {
                value_type: ffi::FWP_UINT16,
                value: ffi::FWP_VALUE0_UNION {
                    uint16: BLOCK_WEIGHT,
                },
            },
            num_filter_conditions: 0,
            filter_condition: std::ptr::null_mut(),
            action: ffi::FWPM_ACTION0 {
                action_type: ffi::FWP_ACTION_BLOCK,
                filter_type: GUID::zeroed(),
            },
            _context_union: [0u8; 24],
            _reserved: std::ptr::null_mut(),
            filter_id: 0,
            effective_weight: ffi::FWP_VALUE0 {
                value_type: 0,
                value: ffi::FWP_VALUE0_UNION { uint32: 0 },
            },
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            ffi::FwpmFilterAdd0(
                inner.engine_handle,
                &filter,
                std::ptr::null(),
                &mut filter_id,
            )
        };

        if status != 0 {
            return Err(WfpError::FilterAdd(name.to_string(), status));
        }

        debug!(filter_id, name, "WFP block-all filter added");
        Ok(filter_id)
    }

    /// Add PERMIT filters for an IP (both outbound and inbound).
    fn add_ip_permit_both_dirs(
        inner: &WfpInner,
        name: &str,
        ip: IpAddr,
    ) -> Result<Vec<u64>, WfpError> {
        let mut ids = Vec::new();

        match ip {
            IpAddr::V4(v4) => {
                ids.push(Self::add_ipv4_filter(
                    inner,
                    &format!("{} Out", name),
                    ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v4,
                )?);
                ids.push(Self::add_ipv4_filter(
                    inner,
                    &format!("{} In", name),
                    ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v4,
                )?);
            }
            IpAddr::V6(v6) => {
                ids.push(Self::add_ipv6_filter(
                    inner,
                    &format!("{} Out", name),
                    ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v6,
                )?);
                ids.push(Self::add_ipv6_filter(
                    inner,
                    &format!("{} In", name),
                    ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v6,
                )?);
            }
        }

        Ok(ids)
    }

    /// Add PERMIT filters for IP:port (outbound and inbound).
    fn add_ip_port_permit(
        inner: &WfpInner,
        name: &str,
        ip: IpAddr,
        port: u16,
    ) -> Result<Vec<u64>, WfpError> {
        let mut ids = Vec::new();

        match ip {
            IpAddr::V4(v4) => {
                ids.push(Self::add_ipv4_port_filter(
                    inner,
                    &format!("{} Out", name),
                    ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v4,
                    port,
                )?);
                ids.push(Self::add_ipv4_port_filter(
                    inner,
                    &format!("{} In", name),
                    ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v4,
                    port,
                )?);
            }
            IpAddr::V6(v6) => {
                // For IPv6+port, just permit the IP (port filtering is less
                // reliable for IPv6 in some WFP versions)
                ids.push(Self::add_ipv6_filter(
                    inner,
                    &format!("{} Out", name),
                    ffi::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v6,
                )?);
                ids.push(Self::add_ipv6_filter(
                    inner,
                    &format!("{} In", name),
                    ffi::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                    ffi::FWP_ACTION_PERMIT,
                    PERMIT_WEIGHT,
                    v6,
                )?);
            }
        }

        Ok(ids)
    }

    /// Add a DNS PERMIT filter (protocol=UDP, remote_port=53).
    fn add_dns_permit(inner: &WfpInner, name: &str, layer_key: GUID) -> Result<u64, WfpError> {
        let mut name_wide = to_wide(name);

        let mut conditions: [ffi::FWPM_FILTER_CONDITION0; 2] = unsafe { std::mem::zeroed() };

        // Protocol == UDP (17)
        conditions[0].field_key = ffi::FWPM_CONDITION_IP_PROTOCOL;
        conditions[0].match_type = ffi::FWP_MATCH_EQUAL;
        conditions[0].condition_value.value_type = ffi::FWP_UINT8;
        conditions[0].condition_value.value = ffi::FWP_VALUE0_UNION { uint8: 17 };

        // Remote port == 53
        conditions[1].field_key = ffi::FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].match_type = ffi::FWP_MATCH_EQUAL;
        conditions[1].condition_value.value_type = ffi::FWP_UINT16;
        conditions[1].condition_value.value = ffi::FWP_VALUE0_UNION { uint16: 53 };

        let filter = ffi::FWPM_FILTER0 {
            filter_key: GUID::zeroed(),
            display_data: ffi::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            flags: 0,
            provider_key: std::ptr::null(),
            provider_data: ffi::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layer_key,
            sub_layer_key: inner.sublayer_key,
            weight: ffi::FWP_VALUE0 {
                value_type: ffi::FWP_UINT16,
                value: ffi::FWP_VALUE0_UNION {
                    uint16: PERMIT_WEIGHT,
                },
            },
            num_filter_conditions: 2,
            filter_condition: conditions.as_mut_ptr(),
            action: ffi::FWPM_ACTION0 {
                action_type: ffi::FWP_ACTION_PERMIT,
                filter_type: GUID::zeroed(),
            },
            _context_union: [0u8; 24],
            _reserved: std::ptr::null_mut(),
            filter_id: 0,
            effective_weight: ffi::FWP_VALUE0 {
                value_type: 0,
                value: ffi::FWP_VALUE0_UNION { uint32: 0 },
            },
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            ffi::FwpmFilterAdd0(
                inner.engine_handle,
                &filter,
                std::ptr::null(),
                &mut filter_id,
            )
        };

        if status != 0 {
            return Err(WfpError::FilterAdd(name.to_string(), status));
        }

        debug!(filter_id, name, "WFP DNS permit filter added");
        Ok(filter_id)
    }

    /// Add a filter with an IPv4 remote address condition.
    fn add_ipv4_filter(
        inner: &WfpInner,
        name: &str,
        layer_key: GUID,
        action_type: u32,
        weight: u16,
        ipv4: Ipv4Addr,
    ) -> Result<u64, WfpError> {
        let mut name_wide = to_wide(name);
        let ip_u32 = u32::from(ipv4);

        let mut condition: ffi::FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        condition.field_key = ffi::FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.match_type = ffi::FWP_MATCH_EQUAL;
        condition.condition_value.value_type = ffi::FWP_UINT32;
        condition.condition_value.value = ffi::FWP_VALUE0_UNION { uint32: ip_u32 };

        let filter = ffi::FWPM_FILTER0 {
            filter_key: GUID::zeroed(),
            display_data: ffi::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            flags: 0,
            provider_key: std::ptr::null(),
            provider_data: ffi::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layer_key,
            sub_layer_key: inner.sublayer_key,
            weight: ffi::FWP_VALUE0 {
                value_type: ffi::FWP_UINT16,
                value: ffi::FWP_VALUE0_UNION { uint16: weight },
            },
            num_filter_conditions: 1,
            filter_condition: &mut condition,
            action: ffi::FWPM_ACTION0 {
                action_type,
                filter_type: GUID::zeroed(),
            },
            _context_union: [0u8; 24],
            _reserved: std::ptr::null_mut(),
            filter_id: 0,
            effective_weight: ffi::FWP_VALUE0 {
                value_type: 0,
                value: ffi::FWP_VALUE0_UNION { uint32: 0 },
            },
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            ffi::FwpmFilterAdd0(
                inner.engine_handle,
                &filter,
                std::ptr::null(),
                &mut filter_id,
            )
        };

        if status != 0 {
            return Err(WfpError::FilterAdd(name.to_string(), status));
        }

        debug!(filter_id, name, ip = %ipv4, "WFP IPv4 filter added");
        Ok(filter_id)
    }

    /// Add a filter with IPv4 remote address + remote port conditions.
    fn add_ipv4_port_filter(
        inner: &WfpInner,
        name: &str,
        layer_key: GUID,
        action_type: u32,
        weight: u16,
        ipv4: Ipv4Addr,
        port: u16,
    ) -> Result<u64, WfpError> {
        let mut name_wide = to_wide(name);
        let ip_u32 = u32::from(ipv4);

        let mut conditions: [ffi::FWPM_FILTER_CONDITION0; 2] = unsafe { std::mem::zeroed() };

        conditions[0].field_key = ffi::FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[0].match_type = ffi::FWP_MATCH_EQUAL;
        conditions[0].condition_value.value_type = ffi::FWP_UINT32;
        conditions[0].condition_value.value = ffi::FWP_VALUE0_UNION { uint32: ip_u32 };

        conditions[1].field_key = ffi::FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].match_type = ffi::FWP_MATCH_EQUAL;
        conditions[1].condition_value.value_type = ffi::FWP_UINT16;
        conditions[1].condition_value.value = ffi::FWP_VALUE0_UNION { uint16: port };

        let filter = ffi::FWPM_FILTER0 {
            filter_key: GUID::zeroed(),
            display_data: ffi::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            flags: 0,
            provider_key: std::ptr::null(),
            provider_data: ffi::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layer_key,
            sub_layer_key: inner.sublayer_key,
            weight: ffi::FWP_VALUE0 {
                value_type: ffi::FWP_UINT16,
                value: ffi::FWP_VALUE0_UNION { uint16: weight },
            },
            num_filter_conditions: 2,
            filter_condition: conditions.as_mut_ptr(),
            action: ffi::FWPM_ACTION0 {
                action_type,
                filter_type: GUID::zeroed(),
            },
            _context_union: [0u8; 24],
            _reserved: std::ptr::null_mut(),
            filter_id: 0,
            effective_weight: ffi::FWP_VALUE0 {
                value_type: 0,
                value: ffi::FWP_VALUE0_UNION { uint32: 0 },
            },
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            ffi::FwpmFilterAdd0(
                inner.engine_handle,
                &filter,
                std::ptr::null(),
                &mut filter_id,
            )
        };

        if status != 0 {
            return Err(WfpError::FilterAdd(name.to_string(), status));
        }

        debug!(filter_id, name, ip = %ipv4, port, "WFP IPv4+port filter added");
        Ok(filter_id)
    }

    /// Add a filter with an IPv6 remote address condition.
    fn add_ipv6_filter(
        inner: &WfpInner,
        name: &str,
        layer_key: GUID,
        action_type: u32,
        weight: u16,
        ipv6: Ipv6Addr,
    ) -> Result<u64, WfpError> {
        let mut name_wide = to_wide(name);
        let octets = ipv6.octets();
        let mut addr_bytes = ffi::FWP_BYTE_ARRAY16 {
            byte_array16: octets,
        };

        let mut condition: ffi::FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        condition.field_key = ffi::FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.match_type = ffi::FWP_MATCH_EQUAL;
        condition.condition_value.value_type = ffi::FWP_BYTE_ARRAY16_TYPE;
        condition.condition_value.value = ffi::FWP_VALUE0_UNION {
            byte_array16: &mut addr_bytes,
        };

        let filter = ffi::FWPM_FILTER0 {
            filter_key: GUID::zeroed(),
            display_data: ffi::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            flags: 0,
            provider_key: std::ptr::null(),
            provider_data: ffi::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layer_key,
            sub_layer_key: inner.sublayer_key,
            weight: ffi::FWP_VALUE0 {
                value_type: ffi::FWP_UINT16,
                value: ffi::FWP_VALUE0_UNION { uint16: weight },
            },
            num_filter_conditions: 1,
            filter_condition: &mut condition,
            action: ffi::FWPM_ACTION0 {
                action_type,
                filter_type: GUID::zeroed(),
            },
            _context_union: [0u8; 24],
            _reserved: std::ptr::null_mut(),
            filter_id: 0,
            effective_weight: ffi::FWP_VALUE0 {
                value_type: 0,
                value: ffi::FWP_VALUE0_UNION { uint32: 0 },
            },
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            ffi::FwpmFilterAdd0(
                inner.engine_handle,
                &filter,
                std::ptr::null(),
                &mut filter_id,
            )
        };

        if status != 0 {
            return Err(WfpError::FilterAdd(name.to_string(), status));
        }

        debug!(filter_id, name, ip = %ipv6, "WFP IPv6 filter added");
        Ok(filter_id)
    }
}

#[cfg(target_os = "windows")]
impl Drop for WfpIsolation {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            error!(error = %e, "WFP cleanup failed during drop");
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub enum WfpError {
    NotElevated,
    EngineOpen(u32),
    EngineNotOpen,
    SublayerAdd(u32),
    TransactionBegin(u32),
    TransactionCommit(u32),
    FilterAdd(String, u32),
    LockPoisoned,
    UrlParse(String),
    DnsResolve(String),
}

#[cfg(target_os = "windows")]
impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfpError::NotElevated => write!(
                f,
                "Agent is not running with administrator/SYSTEM privileges"
            ),
            WfpError::EngineOpen(s) => write!(f, "Failed to open WFP engine (status 0x{:08X})", s),
            WfpError::EngineNotOpen => write!(f, "WFP engine is not open"),
            WfpError::SublayerAdd(s) => {
                write!(f, "Failed to register WFP sublayer (status 0x{:08X})", s)
            }
            WfpError::TransactionBegin(s) => {
                write!(f, "Failed to begin WFP transaction (status 0x{:08X})", s)
            }
            WfpError::TransactionCommit(s) => {
                write!(f, "Failed to commit WFP transaction (status 0x{:08X})", s)
            }
            WfpError::FilterAdd(name, s) => write!(
                f,
                "Failed to add WFP filter '{}' (status 0x{:08X})",
                name, s
            ),
            WfpError::LockPoisoned => write!(f, "Internal lock poisoned"),
            WfpError::UrlParse(e) => write!(f, "Failed to parse server URL: {}", e),
            WfpError::DnsResolve(e) => write!(f, "Failed to resolve server hostname: {}", e),
        }
    }
}

#[cfg(target_os = "windows")]
impl std::error::Error for WfpError {}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Check if the current process is running elevated (admin/SYSTEM).
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let process = GetCurrentProcess();
        let mut token_handle = HANDLE(0);

        if OpenProcessToken(process, TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Convert a Rust &str to a null-terminated wide (UTF-16) string.
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Parse the Tamandua server URL and extract the IP address and port.
///
/// Returns (ip, port) if the host can be resolved.
#[cfg(target_os = "windows")]
pub fn parse_server_address(server_url: &str) -> Result<(IpAddr, Option<u16>), WfpError> {
    let url = url::Url::parse(server_url).map_err(|e| WfpError::UrlParse(e.to_string()))?;

    let host = url
        .host_str()
        .ok_or_else(|| WfpError::UrlParse("No host in URL".to_string()))?;

    let port = url.port();

    // Try to parse as IP literal first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((ip, port));
    }

    // Otherwise resolve via DNS
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:{}", host, port.unwrap_or(443));
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| WfpError::DnsResolve(format!("{}: {}", host, e)))?;

    if let Some(socket_addr) = addrs.next() {
        Ok((socket_addr.ip(), port))
    } else {
        Err(WfpError::DnsResolve(format!(
            "No addresses found for {}",
            host
        )))
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
static WFP_INSTANCE: OnceLock<Arc<WfpIsolation>> = OnceLock::new();

/// Get or create the global WFP isolation instance.
#[cfg(target_os = "windows")]
pub fn get_wfp() -> Arc<WfpIsolation> {
    WFP_INSTANCE
        .get_or_init(|| Arc::new(WfpIsolation::new()))
        .clone()
}

/// Shut down the global WFP instance (called from agent shutdown).
#[cfg(target_os = "windows")]
pub fn shutdown_wfp() {
    if let Some(wfp) = WFP_INSTANCE.get() {
        if let Err(e) = wfp.cleanup() {
            error!(error = %e, "Failed to clean up WFP on shutdown");
        }
    }
}

// ---------------------------------------------------------------------------
// No-op stubs for non-Windows platforms
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
pub fn shutdown_wfp() {
    // No-op on non-Windows platforms
}
