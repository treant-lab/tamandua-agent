//! Kernel Driver Ring Buffer Consumer
//!
//! Reads telemetry events from the shared memory ring buffer that the
//! Tamandua kernel driver writes to. The driver (producer) writes events
//! into the buffer and advances `WriteIndex`; this consumer reads events
//! and advances `ReadIndex`.
//!
//! ## Memory Layout
//!
//! ```text
//! +----------------------------------+
//! | TAMANDUA_RING_BUFFER_HEADER      |  (fixed size)
//! |   WriteIndex (volatile i32)      |
//! |   ReadIndex  (volatile i32)      |
//! |   BufferSize (u32)               |
//! |   Version    (u32)               |
//! |   Statistics ...                 |
//! |   Flags      (volatile u32)      |
//! |   Reserved[4]                    |
//! +----------------------------------+
//! | Data buffer  [0 .. BufferSize)   |
//! |   Event headers + payloads       |
//! |   (wraps around)                 |
//! +----------------------------------+
//! ```
//!
//! ## Event Format
//!
//! Each event starts with a `TelemetryEventHeader` (32 bytes packed):
//! - `event_type`  : u16  -- one of the TAMANDUA_EVENT_* constants
//! - `event_size`  : u16  -- total size including header, 8-byte aligned
//! - `sequence`    : u32  -- monotonic counter
//! - `timestamp`   : i64  -- kernel `LARGE_INTEGER` (100ns since 1601-01-01)
//! - `process_id`  : u32
//! - `thread_id`   : u32
//! - `session_id`  : u32
//! - `flags`       : u32
//!
//! The payload immediately follows the header and its format depends on
//! `event_type`. See `telemetry.c` and `tamandua.h` in the driver source
//! for the per-type wire formats.

// Kernel-driver ring buffer consumer. Helper parameters retained for
// platform-specific decode paths.
#![allow(dead_code, unused_variables)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use super::{ImageLoadDetectionKind, ImageLoadEvent, TelemetryEventHeader};
use crate::collectors::{
    self, EventPayload, EventType, FileEvent, NetworkEvent, ProcessEvent, RegistryEvent, Severity,
    TelemetryEvent,
};

// ---------------------------------------------------------------------------
// Constants matching the kernel driver (tamandua.h / usermode_api.h)
// ---------------------------------------------------------------------------

/// Named section that the driver creates for shared memory.
///
/// Kernel code creates `\BaseNamedObjects\TamanduaTelemetry`. Win32
/// `OpenFileMappingW` resolves that as `Global\TamanduaTelemetry` for
/// services; passing the NT object-manager path directly fails.
const TELEMETRY_SECTION_NAMES: &[&str] = &[
    "Global\\TamanduaTelemetry",
    "TamanduaTelemetry",
    "\\BaseNamedObjects\\TamanduaTelemetry",
];

/// Protocol version we understand.
const SUPPORTED_PROTOCOL_VERSION: u32 = 1;

/// Maximum size of a single event (driver enforces this too).
const MAX_EVENT_SIZE: u32 = 64 * 1024;

/// Minimum event size (just the header).
const MIN_EVENT_SIZE: usize = std::mem::size_of::<TelemetryEventHeader>();

/// Ring buffer flag: overflow occurred at some point.
const RING_BUFFER_FLAG_OVERFLOW: u32 = 0x0000_0001;
/// Ring buffer flag: kernel has paused event writing.
const RING_BUFFER_FLAG_PAUSED: u32 = 0x0000_0002;

/// Default poll interval when no notification event is available.
const DEFAULT_POLL_INTERVAL_MS: u64 = 10;

/// Maximum events to drain per poll cycle to avoid stalling the tokio runtime.
const MAX_EVENTS_PER_POLL: usize = 512;

/// Process identity cache TTL used to enrich kernel events without doing a
/// full process-table refresh for every file/registry/network callback.
const PROCESS_IDENTITY_TTL_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// Driver event type constants (from tamandua.h)
// ---------------------------------------------------------------------------

mod event_types {
    // Process events
    pub const PROCESS_CREATE: u16 = 0x0001;
    pub const PROCESS_EXIT: u16 = 0x0002;
    pub const THREAD_CREATE: u16 = 0x0003;
    pub const THREAD_EXIT: u16 = 0x0004;
    pub const IMAGE_LOAD: u16 = 0x0005;

    // File events
    pub const FILE_CREATE: u16 = 0x0010;
    pub const FILE_READ: u16 = 0x0011;
    pub const FILE_WRITE: u16 = 0x0012;
    pub const FILE_DELETE: u16 = 0x0013;
    pub const FILE_RENAME: u16 = 0x0014;
    pub const FILE_SET_ATTRIBUTES: u16 = 0x0015;
    pub const FILE_CLOSE: u16 = 0x0016;

    // Registry events
    pub const REG_CREATE_KEY: u16 = 0x0020;
    pub const REG_OPEN_KEY: u16 = 0x0021;
    pub const REG_DELETE_KEY: u16 = 0x0022;
    pub const REG_SET_VALUE: u16 = 0x0023;
    pub const REG_DELETE_VALUE: u16 = 0x0024;
    pub const REG_QUERY_KEY: u16 = 0x0025;
    pub const REG_QUERY_VALUE: u16 = 0x0026;

    // Network events
    pub const NET_CONNECT: u16 = 0x0030;
    pub const NET_DISCONNECT: u16 = 0x0031;
    pub const NET_LISTEN: u16 = 0x0032;
    pub const NET_ACCEPT: u16 = 0x0033;
    pub const NET_SEND: u16 = 0x0034;
    pub const NET_RECEIVE: u16 = 0x0035;
    pub const DNS_QUERY: u16 = 0x0036;

    // Handle events
    pub const HANDLE_CREATE: u16 = 0x0040;
    pub const HANDLE_DUPLICATE: u16 = 0x0041;

    // Syscall monitoring events
    pub const SSDT_TAMPER: u16 = 0x0060;
    pub const SYSCALL_ANOMALY: u16 = 0x0061;
    pub const STACK_PIVOT: u16 = 0x0062;
    pub const ROP_DETECTED: u16 = 0x0063;
    pub const DIRECT_SYSCALL: u16 = 0x006B;

    // ETW/AMSI tamper events
    pub const ETW_TAMPER: u16 = 0x0064;
    pub const AMSI_TAMPER: u16 = 0x0065;
    pub const DLL_UNHOOK: u16 = 0x0066;
    pub const NTDLL_PATCH: u16 = 0x0067;

    // PoolParty injection events
    pub const POOLPARTY_WORKER_FACTORY: u16 = 0x0070;
    pub const POOLPARTY_IO_COMPLETION: u16 = 0x0071;
    pub const POOLPARTY_TIMER_QUEUE: u16 = 0x0072;
    pub const POOLPARTY_DIRECT: u16 = 0x0073;
    pub const POOLPARTY_ALPC: u16 = 0x0074;

    // WFP network events
    pub const NET_BLOCKED: u16 = 0x0081;
    pub const NET_ISOLATED: u16 = 0x0082;

    // Image load detection events
    pub const IMAGE_LOAD_DETAIL: u16 = 0x0090;
    pub const DLL_HIJACK: u16 = 0x0091;
    pub const REFLECTIVE_LOAD: u16 = 0x0092;
    pub const UNSIGNED_DLL: u16 = 0x0093;

    // Alert events
    pub const ALERT_RANSOMWARE: u16 = 0x0100;
    pub const ALERT_INJECTION: u16 = 0x0101;
    pub const ALERT_CREDENTIAL: u16 = 0x0102;
    pub const ALERT_PERSISTENCE: u16 = 0x0103;
    pub const ALERT_EVASION: u16 = 0x0104;
}

// ---------------------------------------------------------------------------
// Ring Buffer Header (mirrors the C struct in telemetry.c / usermode_api.h)
// ---------------------------------------------------------------------------

/// In-memory representation of `TAMANDUA_RING_BUFFER_HEADER`.
///
/// We do NOT use `#[repr(C)]` and read fields directly because the mapping
/// is read-only from user-mode. Instead we read through raw pointers with
/// volatile semantics to match the kernel's `volatile` annotations.
///
/// Offsets (packed, matching telemetry.c definition used by the driver):
///   0x00  WriteIndex          : i32   (volatile)
///   0x04  ReadIndex           : i32   (volatile)
///   0x08  BufferSize          : u32
///   0x0C  Version             : u32
///   0x10  TotalEventsWritten  : i64   (volatile)
///   0x18  TotalEventsDropped  : i64   (volatile)
///   0x20  TotalBytesWritten   : i64   (volatile)
///   0x28  OverflowCount       : i64   (volatile)
///   0x30  SequenceNumber      : i32   (volatile)
///   0x34  Flags               : u32   (volatile)
///   0x38  Reserved[4]         : [u32; 4]  (16 bytes)
///   ---- total header: 0x48 = 72 bytes ----
///   0x48  DataBuffer[0]
const RING_BUFFER_HEADER_SIZE: usize = 72;

/// Wrapper around the raw pointer to the mapped shared memory section.
/// Provides safe volatile reads of the ring buffer header fields.
struct MappedRingBuffer {
    /// Base address of the mapping (ring buffer header).
    base: *const u8,
    /// Total size of the mapping in bytes.
    mapping_size: usize,
    /// Size of the data buffer (from header).
    data_buffer_size: u32,
    /// Whether user-mode can write ReadIndex back into the shared header.
    writable_read_index: bool,
    /// Local fallback cursor used when the section is exposed read-only.
    local_read_index: AtomicI32,
}

// SAFETY: The shared memory mapping is read-only from user-mode and the
// producer (kernel) uses interlocked operations. We only touch WriteIndex
// via volatile reads and ReadIndex via volatile writes. This is safe to
// send across threads.
unsafe impl Send for MappedRingBuffer {}
unsafe impl Sync for MappedRingBuffer {}

#[derive(Debug, Clone)]
struct ProcessIdentity {
    name: String,
    path: String,
    cmdline: String,
    seen_at_ms: u64,
}

static PROCESS_IDENTITY_CACHE: OnceLock<Mutex<HashMap<u32, ProcessIdentity>>> = OnceLock::new();

impl MappedRingBuffer {
    /// Read the current WriteIndex (set by kernel).
    fn write_index(&self) -> i32 {
        unsafe {
            let ptr = self.base as *const i32;
            std::ptr::read_volatile(ptr)
        }
    }

    /// Read the current ReadIndex.
    fn read_index(&self) -> i32 {
        if !self.writable_read_index {
            return self.local_read_index.load(Ordering::Relaxed);
        }

        unsafe {
            let ptr = (self.base as *const i32).add(1);
            std::ptr::read_volatile(ptr)
        }
    }

    /// Update the ReadIndex (consumed by user-mode).
    ///
    /// The consumer maps the shared section read/write so it can advance this
    /// cursor after draining events. The driver is the only writer for event
    /// data; user-mode writes only this cursor field.
    fn set_read_index(&self, value: i32) {
        self.local_read_index.store(value, Ordering::Relaxed);

        if !self.writable_read_index {
            return;
        }

        unsafe {
            let ptr = (self.base as *mut i32).add(1);
            std::ptr::write_volatile(ptr, value);
        }
    }

    fn buffer_size(&self) -> u32 {
        self.data_buffer_size
    }

    fn version(&self) -> u32 {
        unsafe {
            let ptr = (self.base.add(0x0C)) as *const u32;
            std::ptr::read_volatile(ptr)
        }
    }

    fn total_events_written(&self) -> i64 {
        unsafe {
            let ptr = (self.base.add(0x10)) as *const i64;
            std::ptr::read_volatile(ptr)
        }
    }

    fn total_events_dropped(&self) -> i64 {
        unsafe {
            let ptr = (self.base.add(0x18)) as *const i64;
            std::ptr::read_volatile(ptr)
        }
    }

    fn sequence_number(&self) -> u32 {
        unsafe {
            let ptr = (self.base.add(0x30)) as *const i32;
            std::ptr::read_volatile(ptr) as u32
        }
    }

    fn flags(&self) -> u32 {
        unsafe {
            let ptr = (self.base.add(0x34)) as *const u32;
            std::ptr::read_volatile(ptr)
        }
    }

    /// Pointer to the start of the data buffer (right after the header).
    fn data_base(&self) -> *const u8 {
        unsafe { self.base.add(RING_BUFFER_HEADER_SIZE) }
    }

    /// Return `true` if there is data available to read.
    fn has_data(&self) -> bool {
        self.write_index() != self.read_index()
    }

    /// Calculate how many bytes are available to read.
    fn available_bytes(&self) -> u32 {
        let wi = self.write_index();
        let ri = self.read_index();
        let size = self.data_buffer_size;

        if wi >= ri {
            (wi - ri) as u32
        } else {
            size - (ri as u32 - wi as u32)
        }
    }

    /// Read `len` bytes starting at offset `offset` within the data buffer,
    /// correctly handling wrap-around. Returns a newly allocated `Vec<u8>`.
    fn read_data(&self, offset: u32, len: usize) -> Vec<u8> {
        let size = self.data_buffer_size as usize;
        let offset = offset as usize;
        let base = self.data_base();
        let mut buf = vec![0u8; len];

        if offset + len <= size {
            // No wrap -- single contiguous copy.
            unsafe {
                std::ptr::copy_nonoverlapping(base.add(offset), buf.as_mut_ptr(), len);
            }
        } else {
            // Wrap-around -- two copies.
            let first_part = size - offset;
            let second_part = len - first_part;
            unsafe {
                std::ptr::copy_nonoverlapping(base.add(offset), buf.as_mut_ptr(), first_part);
                std::ptr::copy_nonoverlapping(base, buf.as_mut_ptr().add(first_part), second_part);
            }
        }

        buf
    }
}

// ---------------------------------------------------------------------------
// Ring Buffer Consumer (public API)
// ---------------------------------------------------------------------------

/// Statistics about ring buffer consumption.
#[derive(Debug, Clone, Default)]
pub struct RingBufferStats {
    pub events_consumed: u64,
    pub events_converted: u64,
    pub events_skipped: u64,
    pub events_malformed: u64,
    pub channel_drops: u64,
    pub kernel_events_written: u64,
    pub kernel_events_dropped: u64,
    pub reconnect_attempts: u64,
    pub consecutive_failures: u32,
    pub connected: bool,
    pub writable_read_index: bool,
    pub protocol_version: u32,
    pub buffer_size: u32,
    pub write_index: i32,
    pub read_index: i32,
    pub sequence_number: u32,
    pub flags: u32,
    pub raw_event_type_counts: HashMap<String, u64>,
    pub converted_event_type_counts: HashMap<String, u64>,
    pub skipped_event_type_counts: HashMap<String, u64>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

static GLOBAL_RING_BUFFER_STATS: OnceLock<Mutex<RingBufferStats>> = OnceLock::new();

fn global_stats_cell() -> &'static Mutex<RingBufferStats> {
    GLOBAL_RING_BUFFER_STATS.get_or_init(|| Mutex::new(RingBufferStats::default()))
}

fn publish_stats(stats: &std::sync::Mutex<RingBufferStats>) {
    if let (Ok(local), Ok(mut global)) = (stats.lock(), global_stats_cell().lock()) {
        *global = local.clone();
    }
}

/// Return the latest kernel ring buffer statistics visible to IPC.
pub fn global_stats() -> RingBufferStats {
    global_stats_cell()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Consumer that reads kernel telemetry from the shared memory ring buffer
/// and converts them into `TelemetryEvent` values.
pub struct RingBufferConsumer {
    /// Sender side of the channel that feeds into the main collector loop.
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Whether the consumer should keep running.
    running: Arc<AtomicBool>,
    /// Accumulated statistics.
    stats: Arc<std::sync::Mutex<RingBufferStats>>,
    /// Expected last sequence number for gap detection.
    last_sequence: Arc<AtomicU32>,
}

impl RingBufferConsumer {
    /// Create a new ring buffer consumer. Events will be sent on `event_tx`.
    pub fn new(event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        Self {
            event_tx,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(std::sync::Mutex::new(RingBufferStats::default())),
            last_sequence: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Return a handle that can be used to signal the consumer to stop.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Return a snapshot of the current statistics.
    pub fn stats(&self) -> RingBufferStats {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Spawn the consumer as a tokio task. Returns immediately.
    ///
    /// The task will:
    /// 1. Open the shared memory section created by the driver.
    /// 2. Validate the ring buffer header.
    /// 3. Poll for new events every `poll_interval_ms` milliseconds.
    /// 4. Convert kernel events to `TelemetryEvent` and send them on the channel.
    /// 5. Gracefully handle driver disconnection and attempt reconnection.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let last_seq = Arc::clone(&self.last_sequence);
        let event_tx = self.event_tx.clone();

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            info!("Ring buffer consumer starting");

            loop {
                if !running.load(Ordering::Relaxed) {
                    info!("Ring buffer consumer received stop signal");
                    break;
                }

                // Attempt to open and consume from the ring buffer.
                match Self::open_ring_buffer() {
                    Ok(ring) => {
                        info!(
                            version = ring.version(),
                            buffer_size = ring.buffer_size(),
                            "Connected to driver ring buffer"
                        );
                        let start_index = ring.write_index();
                        ring.set_read_index(start_index);
                        last_seq.store(ring.sequence_number(), Ordering::Relaxed);
                        debug!(
                            read_index = start_index,
                            sequence = ring.sequence_number(),
                            "Synchronized driver ring buffer consumer to live tail"
                        );
                        if let Ok(mut s) = stats.lock() {
                            s.connected = true;
                            s.consecutive_failures = 0;
                            s.last_error = None;
                            s.writable_read_index = ring.writable_read_index;
                            s.protocol_version = ring.version();
                            s.buffer_size = ring.buffer_size();
                            s.write_index = ring.write_index();
                            s.read_index = ring.read_index();
                            s.sequence_number = ring.sequence_number();
                            s.flags = ring.flags();
                            s.kernel_events_written = ring.total_events_written() as u64;
                            s.kernel_events_dropped = ring.total_events_dropped() as u64;
                        }
                        publish_stats(&stats);

                        Self::consume_loop(&ring, &event_tx, &*running, &*stats, &*last_seq).await;

                        // If we exit the consume loop while still running,
                        // the driver likely went away. Fall through to
                        // reconnection.
                        if running.load(Ordering::Relaxed) {
                            warn!("Driver ring buffer connection lost, will retry");
                            if let Ok(mut s) = stats.lock() {
                                s.connected = false;
                                s.reconnect_attempts += 1;
                                s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                                s.last_error =
                                    Some("Driver ring buffer connection lost".to_string());
                            }
                            publish_stats(&stats);
                        }
                    }
                    Err(e) => {
                        // Driver not loaded or section not available.
                        debug!(error = %e, "Ring buffer not available (driver may not be loaded)");
                        if let Ok(mut s) = stats.lock() {
                            s.connected = false;
                            s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                            s.last_error = Some(e.to_string());
                        }
                        publish_stats(&stats);
                    }
                }

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                // Back off before retrying.
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }

            info!("Ring buffer consumer stopped");
        })
    }

    // -----------------------------------------------------------------------
    // Private implementation
    // -----------------------------------------------------------------------

    /// Open the shared memory section created by the driver.
    #[cfg(target_os = "windows")]
    fn open_ring_buffer() -> Result<MappedRingBuffer> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE,
        };

        unsafe {
            // Prefer read/write so user-mode can advance the shared ReadIndex.
            // Some lab/protected builds expose the named section read-only;
            // in that case we fall back to a local cursor and still consume
            // kernel events until the producer wraps the ring.
            let desired_access = FILE_MAP_READ.0 | FILE_MAP_WRITE.0;
            let mut last_error = None;
            let mut opened = None;

            for name in TELEMETRY_SECTION_NAMES {
                let section_name: Vec<u16> =
                    name.encode_utf16().chain(std::iter::once(0)).collect();

                match OpenFileMappingW(desired_access, false, PCWSTR(section_name.as_ptr())) {
                    Ok(handle) => {
                        opened = Some((handle, true, *name));
                        break;
                    }
                    Err(rw_error) => {
                        debug!(
                            section_name = *name,
                            error = %rw_error,
                            "Opening driver telemetry section read/write failed"
                        );
                        last_error = Some(rw_error.to_string());

                        match OpenFileMappingW(
                            FILE_MAP_READ.0,
                            false,
                            PCWSTR(section_name.as_ptr()),
                        ) {
                            Ok(handle) => {
                                opened = Some((handle, false, *name));
                                break;
                            }
                            Err(ro_error) => {
                                debug!(
                                    section_name = *name,
                                    error = %ro_error,
                                    "Opening driver telemetry section read-only failed"
                                );
                                last_error = Some(ro_error.to_string());
                            }
                        }
                    }
                }
            }

            let (handle, writable_read_index, opened_name) = opened.ok_or_else(|| {
                anyhow!(
                    "Failed to open telemetry section (driver not loaded?): {}",
                    last_error.unwrap_or_else(|| "no matching section name".to_string())
                )
            })?;

            debug!(
                section_name = opened_name,
                writable_read_index = writable_read_index,
                "Opened driver telemetry section"
            );

            let map_access = if writable_read_index {
                FILE_MAP_READ | FILE_MAP_WRITE
            } else {
                FILE_MAP_READ
            };

            let base = MapViewOfFile(handle, map_access, 0, 0, 0);

            if base.Value.is_null() {
                let _ = CloseHandle(handle);
                return Err(anyhow!("MapViewOfFile returned null"));
            }

            let base_ptr = base.Value as *const u8;

            // Read the header fields to validate the mapping.
            let buffer_size = std::ptr::read_volatile(base_ptr.add(0x08) as *const u32);
            let version = std::ptr::read_volatile(base_ptr.add(0x0C) as *const u32);

            if version != SUPPORTED_PROTOCOL_VERSION {
                let _ = UnmapViewOfFile(base);
                let _ = CloseHandle(handle);
                return Err(anyhow!(
                    "Unsupported ring buffer protocol version {} (expected {})",
                    version,
                    SUPPORTED_PROTOCOL_VERSION
                ));
            }

            if buffer_size == 0 || buffer_size > 256 * 1024 * 1024 {
                let _ = UnmapViewOfFile(base);
                let _ = CloseHandle(handle);
                return Err(anyhow!(
                    "Invalid ring buffer data size: {} bytes",
                    buffer_size
                ));
            }

            let mapping_size = RING_BUFFER_HEADER_SIZE + buffer_size as usize;

            // NOTE: We intentionally do NOT close `handle` here. The
            // mapping stays alive as long as we hold the view. We leak
            // the handle because the consumer runs for the entire agent
            // lifetime and the OS will clean up on exit. A production
            // implementation would store the handle and close it in Drop.
            // (Closing it is safe -- Windows keeps the section alive while
            // the view is mapped.)

            Ok(MappedRingBuffer {
                base: base_ptr,
                mapping_size,
                data_buffer_size: buffer_size,
                writable_read_index,
                local_read_index: AtomicI32::new(std::ptr::read_volatile(
                    (base_ptr as *const i32).add(1),
                )),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn open_ring_buffer() -> Result<MappedRingBuffer> {
        Err(anyhow!("Ring buffer consumer is only supported on Windows"))
    }

    /// Main consumption loop. Runs until the driver disconnects or `running`
    /// is set to `false`.
    async fn consume_loop(
        ring: &MappedRingBuffer,
        event_tx: &mpsc::Sender<TelemetryEvent>,
        running: &AtomicBool,
        stats: &std::sync::Mutex<RingBufferStats>,
        last_seq: &AtomicU32,
    ) {
        let poll_interval = tokio::time::Duration::from_millis(DEFAULT_POLL_INTERVAL_MS);

        let mut overflow_warned = false;

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Check for driver-side flags.
            let flags = ring.flags();
            if flags & RING_BUFFER_FLAG_PAUSED != 0 {
                // Driver has paused telemetry; sleep longer.
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }

            if flags & RING_BUFFER_FLAG_OVERFLOW != 0 && !overflow_warned {
                warn!("Ring buffer overflow detected -- some kernel events were dropped");
                overflow_warned = true;
            }

            if let Ok(mut s) = stats.lock() {
                s.connected = true;
                s.writable_read_index = ring.writable_read_index;
                s.protocol_version = ring.version();
                s.buffer_size = ring.buffer_size();
                s.write_index = ring.write_index();
                s.read_index = ring.read_index();
                s.sequence_number = ring.sequence_number();
                s.flags = flags;
                s.kernel_events_written = ring.total_events_written() as u64;
                s.kernel_events_dropped = ring.total_events_dropped() as u64;
            }

            // Drain available events.
            let mut drained = 0usize;

            while ring.has_data() && drained < MAX_EVENTS_PER_POLL {
                let ri = ring.read_index();
                let available = ring.available_bytes();

                // We need at least a full header to proceed.
                if (available as usize) < MIN_EVENT_SIZE {
                    break;
                }

                // Read the event header.
                let header_bytes = ring.read_data(ri as u32, MIN_EVENT_SIZE);
                let header = match Self::parse_header(&header_bytes) {
                    Some(h) => h,
                    None => {
                        warn!("Malformed event header at read index {}", ri);
                        if let Ok(mut s) = stats.lock() {
                            s.events_malformed += 1;
                            s.kernel_events_dropped = ring.total_events_dropped() as u64;
                        }
                        ring.set_read_index(ring.write_index());
                        break;
                    }
                };

                let event_size = header.event_size as u32;

                // Validate event_size.
                if event_size < MIN_EVENT_SIZE as u32 || event_size > MAX_EVENT_SIZE as u32 {
                    warn!(
                        event_size = event_size,
                        "Invalid event size at read index {}", ri
                    );
                    if let Ok(mut s) = stats.lock() {
                        s.events_malformed += 1;
                        s.kernel_events_dropped = ring.total_events_dropped() as u64;
                    }
                    ring.set_read_index(ring.write_index());
                    break;
                }

                // Make sure the full event is available.
                if available < event_size {
                    // Not enough data yet (partial write). Wait for next poll.
                    break;
                }

                // Read the full event data (header + payload).
                let event_bytes = ring.read_data(ri as u32, event_size as usize);

                // Advance the read index.
                let new_ri = ((ri as u32 + event_size) % ring.buffer_size()) as i32;
                ring.set_read_index(new_ri);

                drained += 1;

                // Sequence gap detection.
                let prev = last_seq.load(Ordering::Relaxed);
                let seq = header.sequence_number;
                if prev != 0 && seq != prev + 1 && seq > prev {
                    let gap = seq - prev - 1;
                    debug!(
                        expected = prev + 1,
                        got = seq,
                        gap = gap,
                        "Sequence gap detected -- {} events missed",
                        gap
                    );
                }
                last_seq.store(seq, Ordering::Relaxed);

                // Extract payload bytes (everything after the header).
                let payload_data = if event_bytes.len() > MIN_EVENT_SIZE {
                    &event_bytes[MIN_EVENT_SIZE..]
                } else {
                    &[]
                };

                // Convert to TelemetryEvent.
                let raw_type_name = Self::event_type_name(header.event_type).to_string();
                if let Ok(mut s) = stats.lock() {
                    *s.raw_event_type_counts
                        .entry(raw_type_name.clone())
                        .or_insert(0) += 1;
                }

                match Self::convert_event(&header, payload_data) {
                    Some(telemetry_event) => {
                        if let Ok(mut s) = stats.lock() {
                            s.events_consumed += 1;
                            s.events_converted += 1;
                            *s.converted_event_type_counts
                                .entry(raw_type_name.clone())
                                .or_insert(0) += 1;
                            s.last_event_at = Some(Utc::now());
                        }

                        // Non-blocking send; drop event if channel is full
                        // rather than blocking the consumer.
                        if event_tx.try_send(telemetry_event).is_err() {
                            if let Ok(mut s) = stats.lock() {
                                s.channel_drops += 1;
                                s.last_error = Some("driver event channel full".to_string());
                            }
                            debug!("Event channel full, dropping kernel event");
                        }
                    }
                    None => {
                        // Event type not (yet) convertible -- skip silently.
                        if let Ok(mut s) = stats.lock() {
                            s.events_consumed += 1;
                            s.events_skipped += 1;
                            *s.skipped_event_type_counts
                                .entry(raw_type_name)
                                .or_insert(0) += 1;
                        }
                    }
                }
            }

            // Update kernel-side statistics snapshot.
            if let Ok(mut s) = stats.lock() {
                s.kernel_events_written = ring.total_events_written() as u64;
                s.kernel_events_dropped = ring.total_events_dropped() as u64;
            }
            publish_stats(stats);

            // Yield to the tokio runtime and wait for next poll.
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Parse a `TelemetryEventHeader` from raw bytes.
    fn parse_header(bytes: &[u8]) -> Option<TelemetryEventHeader> {
        if bytes.len() < MIN_EVENT_SIZE {
            return None;
        }

        // The header is `#[repr(C, packed)]`, so we use unaligned reads.
        let event_type = u16::from_le_bytes([bytes[0], bytes[1]]);
        let event_size = u16::from_le_bytes([bytes[2], bytes[3]]);
        let sequence_number = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let timestamp = i64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let process_id = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let thread_id = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let session_id = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
        let flags = u32::from_le_bytes(bytes[28..32].try_into().ok()?);

        Some(TelemetryEventHeader {
            event_type,
            event_size,
            sequence_number,
            timestamp,
            process_id,
            thread_id,
            session_id,
            flags,
        })
    }

    fn event_type_name(event_type: u16) -> &'static str {
        match event_type {
            event_types::PROCESS_CREATE => "process_create",
            event_types::PROCESS_EXIT => "process_exit",
            event_types::THREAD_CREATE => "thread_create",
            event_types::THREAD_EXIT => "thread_exit",
            event_types::IMAGE_LOAD => "image_load",
            event_types::IMAGE_LOAD_DETAIL => "image_load_detail",
            event_types::FILE_CREATE => "file_create",
            event_types::FILE_WRITE => "file_write",
            event_types::FILE_DELETE => "file_delete",
            event_types::FILE_RENAME => "file_rename",
            event_types::REG_CREATE_KEY => "registry_create_key",
            event_types::REG_SET_VALUE => "registry_set_value",
            event_types::REG_DELETE_KEY => "registry_delete_key",
            event_types::REG_DELETE_VALUE => "registry_delete_value",
            event_types::NET_CONNECT => "network_connect",
            event_types::NET_DISCONNECT => "network_disconnect",
            event_types::NET_LISTEN => "network_listen",
            event_types::NET_ACCEPT => "network_accept",
            event_types::NET_BLOCKED => "network_blocked",
            event_types::NET_ISOLATED => "network_isolated",
            event_types::ALERT_CREDENTIAL => "alert_credential",
            event_types::SSDT_TAMPER => "ssdt_tamper",
            event_types::SYSCALL_ANOMALY => "syscall_anomaly",
            event_types::STACK_PIVOT => "stack_pivot",
            event_types::ROP_DETECTED => "rop_detected",
            event_types::DIRECT_SYSCALL => "direct_syscall",
            event_types::ETW_TAMPER => "etw_tamper",
            event_types::AMSI_TAMPER => "amsi_tamper",
            event_types::DLL_UNHOOK => "dll_unhook",
            event_types::NTDLL_PATCH => "ntdll_patch",
            event_types::DLL_HIJACK => "dll_hijack",
            event_types::REFLECTIVE_LOAD => "reflective_load",
            event_types::UNSIGNED_DLL => "unsigned_dll",
            event_types::POOLPARTY_WORKER_FACTORY => "poolparty_worker_factory",
            event_types::POOLPARTY_IO_COMPLETION => "poolparty_io_completion",
            event_types::POOLPARTY_TIMER_QUEUE => "poolparty_timer_queue",
            event_types::POOLPARTY_DIRECT => "poolparty_direct",
            event_types::POOLPARTY_ALPC => "poolparty_alpc",
            _ => "unknown",
        }
    }

    // -----------------------------------------------------------------------
    // Event Conversion
    // -----------------------------------------------------------------------

    /// Convert a kernel event header + payload into a `TelemetryEvent`.
    /// Returns `None` for event types we do not map yet.
    fn convert_event(header: &TelemetryEventHeader, data: &[u8]) -> Option<TelemetryEvent> {
        let timestamp_ms = Self::kernel_timestamp_to_unix_ms(header.timestamp);

        match header.event_type {
            // ----- Process Events -----
            event_types::PROCESS_CREATE => Self::convert_process_create(header, data, timestamp_ms),
            event_types::PROCESS_EXIT => Self::convert_process_exit(header, data, timestamp_ms),

            // ----- Image/module events -----
            event_types::IMAGE_LOAD
            | event_types::IMAGE_LOAD_DETAIL
            | event_types::DLL_HIJACK
            | event_types::REFLECTIVE_LOAD
            | event_types::UNSIGNED_DLL => {
                Self::convert_image_load_event(header, data, timestamp_ms)
            }

            // ----- File Events -----
            event_types::FILE_CREATE
            | event_types::FILE_WRITE
            | event_types::FILE_DELETE
            | event_types::FILE_RENAME => Self::convert_file_event(header, data, timestamp_ms),

            // ----- Registry Events -----
            event_types::REG_CREATE_KEY
            | event_types::REG_SET_VALUE
            | event_types::REG_DELETE_KEY
            | event_types::REG_DELETE_VALUE => {
                Self::convert_registry_event(header, data, timestamp_ms)
            }

            // ----- Network Events (WFP) -----
            event_types::NET_CONNECT
            | event_types::NET_LISTEN
            | event_types::NET_BLOCKED
            | event_types::NET_ISOLATED => {
                Self::convert_driver_net_event(header, data, timestamp_ms)
            }
            // Legacy / unused types
            event_types::NET_DISCONNECT | event_types::NET_ACCEPT => None,

            // ----- Credential Alert -----
            event_types::ALERT_CREDENTIAL => {
                Self::convert_credential_alert(header, data, timestamp_ms)
            }

            // ----- Kernel protection detections -----
            event_types::SSDT_TAMPER
            | event_types::SYSCALL_ANOMALY
            | event_types::STACK_PIVOT
            | event_types::ROP_DETECTED
            | event_types::DIRECT_SYSCALL => {
                Self::convert_syscall_event(header, data, timestamp_ms)
            }

            event_types::ETW_TAMPER
            | event_types::AMSI_TAMPER
            | event_types::DLL_UNHOOK
            | event_types::NTDLL_PATCH => Self::convert_tamper_event(header, data, timestamp_ms),

            event_types::POOLPARTY_WORKER_FACTORY
            | event_types::POOLPARTY_IO_COMPLETION
            | event_types::POOLPARTY_TIMER_QUEUE
            | event_types::POOLPARTY_DIRECT
            | event_types::POOLPARTY_ALPC => {
                Self::convert_injection_event(header, data, timestamp_ms)
            }

            _ => {
                let et = header.event_type;
                trace!(event_type = et, "Unrecognized kernel event type, skipping");
                None
            }
        }
    }

    // ---- Timestamp conversion ----

    /// Convert a Windows FILETIME (100-nanosecond intervals since
    /// 1601-01-01) to Unix epoch milliseconds.
    fn kernel_timestamp_to_unix_ms(filetime: i64) -> u64 {
        // Difference between Windows epoch (1601-01-01) and Unix epoch
        // (1970-01-01) in 100ns ticks.
        const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
        let unix_100ns = filetime - EPOCH_DIFF;
        if unix_100ns < 0 {
            return 0;
        }
        (unix_100ns / 10_000) as u64 // 100ns -> ms
    }

    // ---- Process events ----

    /// Parse process create event.
    ///
    /// Wire format from `TamanduaTelemetryQueueProcessEvent`:
    ///   [ParentPid:4][ImagePathLen:2][ImagePath:variable][CmdLineLen:2][CmdLine:variable]
    fn convert_process_create(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        let process_id = header.process_id;

        // Need at least ParentPid(4) + ImagePathLen(2) + CmdLineLen(2)
        if data.len() < 8 {
            return None;
        }

        let parent_pid = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let img_path_len = u16::from_le_bytes(data[4..6].try_into().ok()?) as usize;
        let mut offset = 6;

        let image_path = if img_path_len > 0 && offset + img_path_len <= data.len() {
            let path_bytes = &data[offset..offset + img_path_len];
            offset += img_path_len;
            Self::decode_utf16_bytes(path_bytes)
        } else {
            offset = 6; // reset if no path
            String::new()
        };

        let cmdline = if offset + 2 <= data.len() {
            let cmd_len = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if cmd_len > 0 && offset + cmd_len <= data.len() {
                Self::decode_utf16_bytes(&data[offset..offset + cmd_len])
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let live_identity = if image_path.is_empty() || cmdline.is_empty() {
            Self::lookup_process_identity(process_id)
        } else {
            None
        };

        let image_path = if image_path.is_empty() {
            live_identity
                .as_ref()
                .map(|identity| identity.path.clone())
                .unwrap_or_default()
        } else {
            image_path
        };

        let cmdline = if cmdline.is_empty() {
            live_identity
                .as_ref()
                .map(|identity| identity.cmdline.clone())
                .unwrap_or_default()
        } else {
            cmdline
        };

        let name = if image_path.is_empty() {
            live_identity
                .as_ref()
                .map(|identity| identity.name.clone())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| format!("pid:{}", process_id))
        } else {
            image_path
                .rsplit('\\')
                .next()
                .unwrap_or("unknown")
                .to_string()
        };

        Self::remember_process_identity(process_id, name.clone(), image_path.clone());
        let parent_identity = Self::lookup_process_identity(parent_pid);

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::ProcessCreate,
            timestamp: timestamp_ms,
            severity: Severity::Info,
            payload: EventPayload::Process(ProcessEvent {
                pid: process_id,
                ppid: parent_pid,
                name,
                path: image_path,
                cmdline,
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: parent_identity
                    .as_ref()
                    .map(|identity| identity.name.clone())
                    .filter(|name| !name.is_empty()),
                parent_path: parent_identity
                    .as_ref()
                    .map(|identity| identity.path.clone())
                    .filter(|path| !path.is_empty()),
                is_signed: false,
                signer: None,
                start_time: timestamp_ms,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
            detections: Vec::new(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("source".to_string(), "kernel_driver".to_string());
                m.insert("provider".to_string(), "windows_kernel_driver".to_string());
                m.insert(
                    "source_detail".to_string(),
                    "windows_kernel_ring_buffer".to_string(),
                );
                m.insert("raw_event_type".to_string(), "process_create".to_string());
                let seq = header.sequence_number;
                m.insert("sequence".to_string(), seq.to_string());
                m.insert("driver_sequence".to_string(), seq.to_string());
                m
            },
        })
    }

    fn convert_process_exit(
        header: &TelemetryEventHeader,
        _data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        let pid = header.process_id;
        let identity = Self::lookup_process_identity(pid);
        Self::forget_process_identity(pid);

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::ProcessTerminate,
            timestamp: timestamp_ms,
            severity: Severity::Info,
            payload: EventPayload::Process(ProcessEvent {
                pid,
                ppid: 0,
                name: identity
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| format!("pid:{}", pid)),
                path: identity.map(|p| p.path).unwrap_or_default(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
            detections: Vec::new(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("source".to_string(), "kernel_driver".to_string());
                m
            },
        })
    }

    // ---- File events ----

    /// Parse file events.
    ///
    /// Wire format from `TamanduaTelemetryQueueFileEvent`:
    ///   [Access:4][Disposition:4][Status:4][PathLen:2][Path:variable]
    fn convert_file_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        if data.len() < 14 {
            return None;
        }

        let _desired_access = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let _disposition = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let _status = i32::from_le_bytes(data[8..12].try_into().ok()?);
        let path_len = u16::from_le_bytes(data[12..14].try_into().ok()?) as usize;

        let file_path = if path_len > 0 && 14 + path_len <= data.len() {
            Self::decode_utf16_bytes(&data[14..14 + path_len])
        } else {
            String::new()
        };

        let operation = match header.event_type {
            event_types::FILE_CREATE => "create",
            event_types::FILE_WRITE => "write",
            event_types::FILE_DELETE => "delete",
            event_types::FILE_RENAME => "rename",
            _ => "unknown",
        };

        let event_type = match header.event_type {
            event_types::FILE_CREATE => EventType::FileCreate,
            event_types::FILE_WRITE => EventType::FileModify,
            event_types::FILE_DELETE => EventType::FileDelete,
            event_types::FILE_RENAME => EventType::FileRename,
            _ => EventType::FileCreate,
        };

        let name = file_path
            .rsplit('\\')
            .next()
            .unwrap_or("unknown")
            .to_string();
        let process_name = Self::process_name_for_pid(header.process_id);

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: timestamp_ms,
            severity: Severity::Info,
            payload: EventPayload::File(FileEvent {
                path: file_path,
                old_path: None,
                operation: operation.to_string(),
                pid: header.process_id,
                process_name,
                sha256: Vec::new(),
                size: 0,
                entropy: 0.0,
                file_type: String::new(),
            }),
            detections: Vec::new(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("source".to_string(), "kernel_driver".to_string());
                m
            },
        })
    }

    // ---- Network events (Legacy / Unused) ----

    // fn convert_network_event ... removed or commented out as it is superseded by convert_driver_net_event

    // ---- Registry events ----

    /// Parse registry events.
    ///
    /// The kernel queues these via the generic `TamanduaTelemetryQueueEvent`
    /// with a `TAMANDUA_REGISTRY_EVENT` structure. We extract what we can.
    fn convert_registry_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        // Wire format from `TamanduaTelemetryQueueRegistryEvent`:
        // [ValueType:4][ValueDataLength:4][Status:4][KeyPathLen:2][KeyPath][ValueNameLen:2][ValueName]
        if data.len() < 16 {
            return None;
        }

        let value_type = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let value_data_len = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let status = i32::from_le_bytes(data[8..12].try_into().ok()?);
        let key_path_len = u16::from_le_bytes(data[12..14].try_into().ok()?) as usize;
        let mut offset = 14;

        let key_path = if key_path_len > 0 && offset + key_path_len <= data.len() {
            let key = Self::decode_utf16_bytes(&data[offset..offset + key_path_len]);
            offset += key_path_len;
            key
        } else {
            String::new()
        };

        let value_name = if offset + 2 <= data.len() {
            let value_name_len =
                u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if value_name_len > 0 && offset + value_name_len <= data.len() {
                Some(Self::decode_utf16_bytes(
                    &data[offset..offset + value_name_len],
                ))
            } else {
                None
            }
        } else {
            None
        };

        let operation = match header.event_type {
            event_types::REG_CREATE_KEY => "create_key",
            event_types::REG_SET_VALUE => "set_value",
            event_types::REG_DELETE_KEY => "delete_key",
            event_types::REG_DELETE_VALUE => "delete_value",
            _ => "unknown",
        };

        let event_type = match header.event_type {
            event_types::REG_CREATE_KEY => EventType::RegistryCreate,
            event_types::REG_SET_VALUE => EventType::RegistrySetValue,
            event_types::REG_DELETE_KEY | event_types::REG_DELETE_VALUE => {
                EventType::RegistryDelete
            }
            _ => EventType::RegistryCreate,
        };

        let process_name = Self::process_name_for_pid(header.process_id);

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: timestamp_ms,
            severity: Severity::Low,
            payload: EventPayload::Registry(RegistryEvent {
                key_path,
                value_name,
                value_data: None,
                operation: operation.to_string(),
                pid: header.process_id,
                process_name,
            }),
            detections: Vec::new(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("source".to_string(), "kernel_driver".to_string());
                m.insert("value_type".to_string(), value_type.to_string());
                m.insert("value_data_length".to_string(), value_data_len.to_string());
                m.insert(
                    "operation_status".to_string(),
                    format!("0x{:08X}", status as u32),
                );
                m
            },
        })
    }

    // ---- Image load detection events ----

    fn convert_image_load_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        // Use the existing ImageLoadEvent parser from driver/mod.rs.
        let mut image_event = ImageLoadEvent::from_raw(data)?;

        // IMAGE_LOAD and IMAGE_LOAD_DETAIL are telemetry. Only explicit
        // detection event types should produce elevated severity/detections;
        // otherwise stale/padded detail flags can inflate normal DLL loads.
        if matches!(
            header.event_type,
            event_types::IMAGE_LOAD | event_types::IMAGE_LOAD_DETAIL
        ) {
            image_event.detection_kind = ImageLoadDetectionKind::Normal;
        } else {
            image_event.detection_kind = match header.event_type {
                event_types::REFLECTIVE_LOAD => ImageLoadDetectionKind::ReflectiveLoad,
                event_types::DLL_HIJACK => ImageLoadDetectionKind::DllHijack,
                event_types::UNSIGNED_DLL => ImageLoadDetectionKind::UnsignedInSigned,
                _ => image_event.detection_kind,
            };
        }

        if image_event.detection_kind == ImageLoadDetectionKind::UnsignedInSigned
            && image_event.signature_level == 0
            && image_event.signature_type == 0
        {
            image_event.detection_kind = ImageLoadDetectionKind::Normal;
        }

        if image_event.detection_kind == ImageLoadDetectionKind::Normal
            && Self::is_low_value_windows_module_load(&image_event.image_path)
        {
            return None;
        }

        let severity = match image_event.detection_kind {
            ImageLoadDetectionKind::Normal => Severity::Info,
            ImageLoadDetectionKind::DllHijack => Severity::High,
            ImageLoadDetectionKind::ReflectiveLoad => Severity::Critical,
            ImageLoadDetectionKind::UnsignedInSigned => Severity::Medium,
        };

        let event_type = match header.event_type {
            event_types::DLL_HIJACK => EventType::DllSideload,
            event_types::REFLECTIVE_LOAD => EventType::ProcessInject,
            event_types::UNSIGNED_DLL => EventType::ModuleLoad,
            _ => EventType::ModuleLoad,
        };

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("source".to_string(), "kernel_driver".to_string());
        metadata.insert(
            "image_base".to_string(),
            format!("0x{:016X}", image_event.image_base),
        );
        metadata.insert("image_size".to_string(), image_event.image_size.to_string());
        metadata.insert(
            "signature_level".to_string(),
            image_event.signature_level.to_string(),
        );
        if let Some(technique) = image_event.mitre_technique() {
            metadata.insert("mitre_technique".to_string(), technique.to_string());
        }
        metadata.insert(
            "detection_kind".to_string(),
            format!("{:?}", image_event.detection_kind),
        );
        if header.event_type == event_types::UNSIGNED_DLL
            && image_event.signature_level == 0
            && image_event.signature_type == 0
        {
            metadata.insert(
                "detection_suppressed".to_string(),
                "signature_unchecked_not_unsigned".to_string(),
            );
        }

        let mut detections = Vec::new();
        if image_event.detection_kind != ImageLoadDetectionKind::Normal {
            detections.push(collectors::Detection {
                detection_type: collectors::DetectionType::DllSideloading,
                rule_name: format!("kernel_image_load_{:?}", image_event.detection_kind),
                confidence: 0.85,
                description: image_event.detection_description().to_string(),
                mitre_tactics: vec!["defense_evasion".to_string()],
                mitre_techniques: image_event
                    .mitre_technique()
                    .map(|t| vec![t.to_string()])
                    .unwrap_or_default(),
            });
        }

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: timestamp_ms,
            severity,
            payload: EventPayload::File(FileEvent {
                path: image_event.image_path,
                old_path: None,
                operation: "image_load".to_string(),
                pid: header.process_id,
                process_name: Self::process_name_for_pid(header.process_id),
                sha256: Vec::new(),
                size: image_event.image_size,
                entropy: 0.0,
                file_type: "pe_image".to_string(),
            }),
            detections,
            metadata,
        })
    }

    fn is_low_value_windows_module_load(path: &str) -> bool {
        let normalized = path.replace('/', "\\").to_ascii_lowercase();

        normalized.contains("\\windows\\system32\\")
            || normalized.contains("\\windows\\syswow64\\")
            || normalized.contains("\\windows\\winsxs\\")
    }

    // ---- SSDT / Syscall anomaly events ----

    fn convert_syscall_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        let (description, mitre_technique) = match header.event_type {
            event_types::SSDT_TAMPER => (
                "SSDT tamper detected: service table entry modified from baseline",
                "T1562.001",
            ),
            event_types::STACK_PIVOT => (
                "Stack pivot detected: RSP outside thread stack limits",
                "T1055",
            ),
            event_types::ROP_DETECTED => (
                "ROP chain detected: multiple small return-oriented gadgets",
                "T1055",
            ),
            event_types::SYSCALL_ANOMALY => ("Syscall anomaly detected", "T1106"),
            event_types::DIRECT_SYSCALL => (
                "Direct syscall evasion detected (SysWhispers/HellsGate pattern)",
                "T1106",
            ),
            _ => ("Unknown syscall event", "T1106"),
        };

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("source".to_string(), "kernel_driver".to_string());
        metadata.insert("mitre_technique".to_string(), mitre_technique.to_string());

        // Parse SSDT tamper event data if available.
        if header.event_type == event_types::SSDT_TAMPER && data.len() >= 24 {
            let syscall_num = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
            let expected = u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]));
            let actual = u64::from_le_bytes(data[12..20].try_into().unwrap_or([0; 8]));
            metadata.insert("syscall_number".to_string(), syscall_num.to_string());
            metadata.insert(
                "expected_address".to_string(),
                format!("0x{:016X}", expected),
            );
            metadata.insert("actual_address".to_string(), format!("0x{:016X}", actual));
        }

        // Parse stack anomaly event data if available.
        if matches!(
            header.event_type,
            event_types::STACK_PIVOT | event_types::ROP_DETECTED
        ) && data.len() >= 32
        {
            let pid = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
            let tid = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
            let suspicious_addr = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));
            let frame_count = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4]));
            let anomaly_type = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
            metadata.insert("target_pid".to_string(), pid.to_string());
            metadata.insert("target_tid".to_string(), tid.to_string());
            metadata.insert(
                "suspicious_address".to_string(),
                format!("0x{:016X}", suspicious_addr),
            );
            metadata.insert("frame_count".to_string(), frame_count.to_string());
            metadata.insert("anomaly_type".to_string(), anomaly_type.to_string());
        }

        let h_event_type = header.event_type;
        let h_process_id = header.process_id;
        let h_thread_id = header.thread_id;

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::DefenseEvasion,
            timestamp: timestamp_ms,
            severity: Severity::Critical,
            payload: EventPayload::Custom(serde_json::json!({
                "event_class": "syscall_monitoring",
                "kernel_event_type": h_event_type,
                "process_id": h_process_id,
                "thread_id": h_thread_id,
                "description": description,
            })),
            detections: vec![collectors::Detection {
                detection_type: collectors::DetectionType::DefenseEvasion,
                rule_name: format!("kernel_syscall_{:#06X}", h_event_type),
                confidence: 0.90,
                description: description.to_string(),
                mitre_tactics: vec!["defense_evasion".to_string()],
                mitre_techniques: vec![mitre_technique.to_string()],
            }],
            metadata,
        })
    }

    // ---- ETW / AMSI tamper events ----

    fn convert_tamper_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        if crate::driver::LAB_LEVEL < 155 {
            let event_type = header.event_type;
            debug!(
                event_type = event_type,
                lab_level = crate::driver::LAB_LEVEL,
                "Skipping advanced ETW/AMSI tamper event in core driver lab build"
            );
            return None;
        }

        let (description, event_type) = match header.event_type {
            event_types::ETW_TAMPER => (
                "ETW provider tamper detected: event tracing function patched",
                EventType::ETWTamper,
            ),
            event_types::AMSI_TAMPER => (
                "AMSI bypass detected: AmsiScanBuffer function patched",
                EventType::AMSIBypass,
            ),
            event_types::DLL_UNHOOK => (
                "DLL unhooking detected: security DLL hooks removed",
                EventType::DefenseEvasion,
            ),
            event_types::NTDLL_PATCH => (
                "NTDLL tamper detected: critical function bytes modified",
                EventType::DefenseEvasion,
            ),
            _ => ("Unknown tamper event", EventType::DefenseEvasion),
        };

        // Parse TAMANDUA_TAMPER_EVENT_DATA if payload is large enough.
        // Layout: ProcessId(4) + ModuleName(128 WCHAR) + FunctionName(64 CHAR)
        //       + OriginalBytes(16) + PatchedBytes(16) + WasRestored(1) + pad
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("source".to_string(), "kernel_driver".to_string());

        if data.len() >= 4 {
            let tamper_pid = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
            metadata.insert("tamper_pid".to_string(), tamper_pid.to_string());
        }

        // Module name: WCHAR[64] = 128 bytes at offset 4
        if data.len() >= 132 {
            let module_name = Self::decode_utf16_bytes(&data[4..132]);
            if !module_name.is_empty() {
                metadata.insert("module_name".to_string(), module_name);
            }
        }

        // Function name: CHAR[64] = 64 bytes at offset 132
        if data.len() >= 196 {
            let func_bytes = &data[132..196];
            let func_name = std::str::from_utf8(func_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            if !func_name.is_empty() {
                metadata.insert("function_name".to_string(), func_name);
            }
        }

        let h_event_type = header.event_type;
        let h_process_id = header.process_id;

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: timestamp_ms,
            severity: Severity::Critical,
            payload: EventPayload::Custom(serde_json::json!({
                "event_class": "tamper_detection",
                "kernel_event_type": h_event_type,
                "process_id": h_process_id,
                "description": description,
            })),
            detections: vec![collectors::Detection {
                detection_type: collectors::DetectionType::DefenseEvasion,
                rule_name: format!("kernel_tamper_{:#06X}", h_event_type),
                confidence: 0.95,
                description: description.to_string(),
                mitre_tactics: vec!["defense_evasion".to_string()],
                mitre_techniques: vec!["T1562.001".to_string()],
            }],
            metadata,
        })
    }

    // ---- PoolParty injection events ----

    fn convert_injection_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        let variant_name = match header.event_type {
            event_types::POOLPARTY_WORKER_FACTORY => "PoolParty Worker Factory hijack",
            event_types::POOLPARTY_IO_COMPLETION => "PoolParty I/O Completion abuse",
            event_types::POOLPARTY_TIMER_QUEUE => "PoolParty Timer Queue manipulation",
            event_types::POOLPARTY_DIRECT => "PoolParty TP_DIRECT injection",
            event_types::POOLPARTY_ALPC => "PoolParty ALPC injection",
            _ => "Unknown PoolParty variant",
        };

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("source".to_string(), "kernel_driver".to_string());
        metadata.insert("variant".to_string(), variant_name.to_string());
        metadata.insert("mitre_technique".to_string(), "T1055".to_string());

        let h_event_type = header.event_type;
        let h_process_id = header.process_id;

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::ProcessInject,
            timestamp: timestamp_ms,
            severity: Severity::Critical,
            payload: EventPayload::Custom(serde_json::json!({
                "event_class": "poolparty_injection",
                "variant": variant_name,
                "kernel_event_type": h_event_type,
                "process_id": h_process_id,
            })),
            detections: vec![collectors::Detection {
                detection_type: collectors::DetectionType::ProcessHollowing,
                rule_name: format!("kernel_poolparty_{:#06X}", h_event_type),
                confidence: 0.92,
                description: format!(
                    "Kernel detected {}: thread pool injection technique",
                    variant_name
                ),
                mitre_tactics: vec!["defense_evasion".to_string(), "execution".to_string()],
                mitre_techniques: vec!["T1055".to_string()],
            }],
            metadata,
        })
    }

    // ---- Credential Alerts ----

    fn convert_credential_alert(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        if data.len() < 20 {
            return None;
        }

        // Layout: pid(4), tid(4), target(4), desired(4), blocked(4)
        let pid = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let _tid = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let target_pid = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let desired_access = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let blocked_access = u32::from_le_bytes(data[16..20].try_into().ok()?);

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::CredentialAccess,
            timestamp: timestamp_ms,
            severity: Severity::Critical,
            payload: EventPayload::CredentialTheft(crate::collectors::CredentialTheftEvent {
                pid,
                process_name: Self::process_name_for_pid(pid),
                target: if target_pid == 0 {
                    "lsass.exe".to_string()
                } else {
                    format!("pid:{}", target_pid)
                },
                attack_type: crate::collectors::CredentialAttackType::LsassAccess
                    .as_str()
                    .to_string(),
                mitre_technique: "T1003.001".to_string(),
                process_path: "unknown".to_string(),
                process_cmdline: "unknown".to_string(),
                username: "unknown".to_string(),
                blocked: true,
                details: format!(
                    "Kernel blocked suspicious LSASS access: Desired=0x{:X}, Blocked=0x{:X}",
                    desired_access, blocked_access
                ),
            }),
            detections: vec![collectors::Detection {
                detection_type: collectors::DetectionType::CredentialTheft,
                rule_name: "kernel_lsass_block".to_string(),
                confidence: 1.0,
                description: "Kernel driver blocked suspicious access to LSASS".to_string(),
                mitre_tactics: vec!["credential-access".to_string()],
                mitre_techniques: vec!["T1003.001".to_string()],
            }],
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("source".to_string(), "kernel_driver".to_string());
                m.insert(
                    "blocked_access".to_string(),
                    format!("0x{:08X}", blocked_access),
                );
                m
            },
        })
    }

    // ---- WFP blocked network events ----

    // ---- Driver network events (WFP) ----

    fn convert_driver_net_event(
        header: &TelemetryEventHeader,
        data: &[u8],
        timestamp_ms: u64,
    ) -> Option<TelemetryEvent> {
        // TAMANDUA_NET_EVENT layout (packed):
        //   ProcessId(4), RemoteIp(4), RemotePort(2), LocalPort(2),
        //   Protocol(1), Direction(1), Blocked(1), BlockReason(1)
        if data.len() < 16 {
            return None;
        }

        let net_pid = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let remote_ip = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let remote_port = u16::from_le_bytes(data[8..10].try_into().ok()?);
        let local_port = u16::from_le_bytes(data[10..12].try_into().ok()?);
        let protocol = data[12];
        let direction = data[13];
        let blocked = data[14] != 0;
        let block_reason = data[15];

        let reason_str = match block_reason {
            1 => "network_isolation",
            2 => "pid_blocked",
            3 => "ip_blocked",
            _ => "unknown",
        };

        let proto_str = match protocol {
            6 => "tcp",
            17 => "udp",
            _ => "other",
        };

        let event_type = match header.event_type {
            event_types::NET_CONNECT => EventType::NetworkConnect,
            event_types::NET_LISTEN => EventType::NetworkListen,
            // BLOCKED/ISOLATED map to Connect but with severity
            event_types::NET_BLOCKED | event_types::NET_ISOLATED => EventType::NetworkConnect,
            _ => EventType::NetworkConnect,
        };

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("source".to_string(), "kernel_driver".to_string());
        metadata.insert("blocked".to_string(), blocked.to_string());
        if blocked {
            metadata.insert("block_reason".to_string(), reason_str.to_string());
        }

        let mut network_event = NetworkEvent {
            pid: net_pid,
            process_name: Self::process_name_for_pid(net_pid),
            local_ip: String::new(), // WFP callback currently provides only local port reliably.
            local_port,
            remote_ip: Self::ipv4_to_string(remote_ip),
            remote_port,
            protocol: proto_str.to_string(),
            direction: if direction == 0 {
                "outbound".to_string()
            } else {
                "inbound".to_string()
            },
            bytes_sent: 0,
            bytes_received: 0,
            ..Default::default()
        };
        network_event.apply_common_enrichment();

        Some(TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: timestamp_ms,
            severity: if blocked {
                Severity::Medium
            } else {
                Severity::Info
            },
            payload: EventPayload::Network(network_event),
            detections: Vec::new(),
            metadata,
        })
    }

    // ---- Helpers ----

    /// Decode a byte slice of UTF-16LE data to a Rust `String`, stopping
    /// at the first null character.
    fn decode_utf16_bytes(bytes: &[u8]) -> String {
        let u16_iter = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0);
        String::from_utf16_lossy(&u16_iter.collect::<Vec<u16>>())
    }

    fn process_name_for_pid(pid: u32) -> String {
        Self::lookup_process_identity(pid)
            .map(|identity| identity.name)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("pid:{}", pid))
    }

    fn remember_process_identity(pid: u32, name: String, path: String) {
        if pid == 0 || (name.is_empty() && path.is_empty()) {
            return;
        }

        let identity = ProcessIdentity {
            name: if name.is_empty() {
                Self::basename_from_path(&path).unwrap_or_else(|| format!("pid:{}", pid))
            } else {
                name
            },
            path,
            cmdline: String::new(),
            seen_at_ms: Self::now_ms(),
        };

        if let Ok(mut cache) = Self::process_identity_cache().lock() {
            cache.insert(pid, identity);
        }
    }

    fn lookup_process_identity(pid: u32) -> Option<ProcessIdentity> {
        if pid == 0 {
            return None;
        }

        let now_ms = Self::now_ms();
        if let Ok(cache) = Self::process_identity_cache().lock() {
            if let Some(identity) = cache.get(&pid) {
                if now_ms.saturating_sub(identity.seen_at_ms) <= PROCESS_IDENTITY_TTL_MS {
                    return Some(identity.clone());
                }
            }
        }

        let identity = Self::read_process_identity(pid)?;
        if let Ok(mut cache) = Self::process_identity_cache().lock() {
            cache.insert(pid, identity.clone());
        }
        Some(identity)
    }

    fn forget_process_identity(pid: u32) {
        if let Ok(mut cache) = Self::process_identity_cache().lock() {
            cache.remove(&pid);
        }
    }

    fn process_identity_cache() -> &'static Mutex<HashMap<u32, ProcessIdentity>> {
        PROCESS_IDENTITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default()
    }

    fn basename_from_path(path: &str) -> Option<String> {
        path.rsplit(['\\', '/'])
            .next()
            .filter(|name| !name.is_empty())
            .map(ToString::to_string)
    }

    #[cfg(target_os = "windows")]
    fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System};

        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            let path = process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let name = if process.name().is_empty() {
                Self::basename_from_path(&path).unwrap_or_else(|| format!("pid:{}", pid))
            } else {
                process.name().to_string()
            };

            return Some(ProcessIdentity {
                name,
                path,
                cmdline: process.cmd().join(" "),
                seen_at_ms: Self::now_ms(),
            });
        }

        Self::read_process_identity_winapi(pid)
    }

    #[cfg(target_os = "windows")]
    fn read_process_identity_winapi(pid: u32) -> Option<ProcessIdentity> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buffer = vec![0u16; 32768];
            let mut size = buffer.len() as u32;

            let path = if QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
            .is_ok()
                && size > 0
            {
                String::from_utf16_lossy(&buffer[..size as usize])
            } else {
                let len = K32GetProcessImageFileNameW(handle, &mut buffer);
                if len > 0 {
                    String::from_utf16_lossy(&buffer[..len as usize])
                } else {
                    String::new()
                }
            };

            let _ = CloseHandle(handle);

            if path.is_empty() {
                return None;
            }

            Some(ProcessIdentity {
                name: Self::basename_from_path(&path).unwrap_or_else(|| format!("pid:{}", pid)),
                path,
                cmdline: String::new(),
                seen_at_ms: Self::now_ms(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn read_process_identity(_pid: u32) -> Option<ProcessIdentity> {
        None
    }

    /// Convert an IPv4 address in network byte order to a dotted-decimal string.
    fn ipv4_to_string(addr: u32) -> String {
        let bytes = addr.to_be_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}
