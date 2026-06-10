#![no_std]
#![no_main]

//! eBPF uprobe program for LLM API request interception
//!
//! This program attaches to SSL_write in OpenSSL/LibreSSL to intercept
//! HTTPS requests to LLM APIs. It captures the first 4KB of request data
//! and sends it to userspace via ring buffer for parsing and analysis.
//!
//! Requires:
//! - bpf-linker for compilation
//! - CAP_BPF or CAP_SYS_ADMIN to load
//! - Kernel 5.8+ for BPF ring buffer support

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_buf},
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use tamandua_ebpf_common::{LlmRequestEvent, LLM_DATA_MAX_LEN, LLM_EVENT_TYPE_SSL_WRITE, LLM_EVENT_TYPE_SSL_READ};

/// Ring buffer for sending LLM request events to userspace (256KB)
#[map]
static mut LLM_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Uprobe on SSL_write function
///
/// Signature: int SSL_write(SSL *ssl, const void *buf, int num)
/// - ssl: SSL connection pointer
/// - buf: Data buffer to write
/// - num: Number of bytes to write
///
/// We intercept the buffer and check if it looks like JSON (starts with '{' or '[').
/// If so, we capture the first 4KB and send it to userspace for prompt extraction.
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_write_entry(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_ssl_write_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    // SSL_write arguments: SSL *ssl, const void *buf, int num
    // ctx.arg(0) is the SSL pointer (we don't use it)
    // ctx.arg(1) is the buffer pointer
    // ctx.arg(2) is the buffer length

    let buf_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let num: usize = ctx.arg(2).ok_or(1i64)?;

    // Only capture if buffer is non-empty and looks like JSON
    if num == 0 {
        return Ok(0);
    }

    // Read first byte to check if it's JSON
    let mut first_byte = [0u8; 1];
    unsafe {
        bpf_probe_read_user_buf(buf_ptr, &mut first_byte).map_err(|_| 1i64)?;
    }

    // Only capture JSON payloads (starts with '{' or '[')
    if first_byte[0] != b'{' && first_byte[0] != b'[' {
        return Ok(0);
    }

    // Get process context
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Reserve space in ring buffer
    let event = unsafe {
        match LLM_EVENTS.reserve::<LlmRequestEvent>(0) {
            Some(e) => e,
            None => {
                // Ring buffer full, drop event
                info!(ctx, "LLM ring buffer full, dropping event from PID {}", pid);
                return Ok(0);
            }
        }
    };

    // Get pointer to reserved memory
    let event_ptr = event.as_mut_ptr();

    unsafe {
        // Initialize event fields
        (*event_ptr).event_type = LLM_EVENT_TYPE_SSL_WRITE;
        (*event_ptr).pid = pid;
        (*event_ptr).tid = tid;
        (*event_ptr).timestamp_ns = timestamp_ns;
        (*event_ptr).fd = -1; // Socket FD not easily accessible from uprobe
        (*event_ptr).data_len = num as u32;

        // Read process command name
        match bpf_get_current_comm() {
            Ok(comm) => {
                // Copy first 16 bytes of comm to event
                for i in 0..16 {
                    (*event_ptr).comm[i] = comm[i];
                }
            }
            Err(_) => {
                // Failed to get comm, use empty string
                for i in 0..16 {
                    (*event_ptr).comm[i] = 0;
                }
            }
        }

        // Read data from user buffer (up to 4KB)
        let read_len = if num < LLM_DATA_MAX_LEN {
            num
        } else {
            LLM_DATA_MAX_LEN
        };

        // Initialize data buffer to zeros
        for i in 0..LLM_DATA_MAX_LEN {
            (*event_ptr).data[i] = 0;
        }

        // Read the actual data
        bpf_probe_read_user_buf(buf_ptr, &mut (*event_ptr).data[..read_len]).map_err(|_| 1i64)?;
    }

    // Submit event to ring buffer
    event.submit(0);

    Ok(0)
}

/// Uretprobe on SSL_read function (return probe)
///
/// Signature: int SSL_read(SSL *ssl, void *buf, int num)
/// - ssl: SSL connection pointer
/// - buf: Data buffer to read into
/// - num: Maximum number of bytes to read
/// - Returns: Number of bytes actually read, or error (<= 0)
///
/// We intercept on return to capture the actual response data.
/// We check if it looks like JSON (starts with '{' or '[' or is SSE "data:" line).
/// If so, we capture the first 4KB and send it to userspace for response extraction.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_read_entry(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    // SSL_read arguments: SSL *ssl, void *buf, int num
    // ctx.arg(0) is the SSL pointer (we don't use it)
    // ctx.arg(1) is the buffer pointer
    // ctx.arg(2) is the buffer length (max bytes to read)

    let buf_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let num: usize = ctx.arg(2).ok_or(1i64)?;

    // Only capture if buffer is non-empty
    if num == 0 {
        return Ok(0);
    }

    // Read first byte to check if it's JSON or SSE data
    let mut first_bytes = [0u8; 8];
    let check_len = if num < 8 { num } else { 8 };
    unsafe {
        bpf_probe_read_user_buf(buf_ptr, &mut first_bytes[..check_len]).map_err(|_| 1i64)?;
    }

    // Only capture JSON payloads (starts with '{' or '[') or SSE (starts with 'd' for 'data:')
    let is_json = first_bytes[0] == b'{' || first_bytes[0] == b'[';
    let is_sse = first_bytes[0] == b'd' && check_len >= 5
        && first_bytes[1] == b'a' && first_bytes[2] == b't'
        && first_bytes[3] == b'a' && first_bytes[4] == b':';

    if !is_json && !is_sse {
        return Ok(0);
    }

    // Get process context
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Reserve space in ring buffer
    let event = unsafe {
        match LLM_EVENTS.reserve::<LlmRequestEvent>(0) {
            Some(e) => e,
            None => {
                // Ring buffer full, drop event
                info!(ctx, "LLM ring buffer full, dropping SSL_read event from PID {}", pid);
                return Ok(0);
            }
        }
    };

    // Get pointer to reserved memory
    let event_ptr = event.as_mut_ptr();

    unsafe {
        // Initialize event fields - mark as SSL_READ (response)
        (*event_ptr).event_type = LLM_EVENT_TYPE_SSL_READ;
        (*event_ptr).pid = pid;
        (*event_ptr).tid = tid;
        (*event_ptr).timestamp_ns = timestamp_ns;
        (*event_ptr).fd = -1; // Socket FD not easily accessible from uprobe
        (*event_ptr).data_len = num as u32;

        // Read process command name
        match bpf_get_current_comm() {
            Ok(comm) => {
                // Copy first 16 bytes of comm to event
                for i in 0..16 {
                    (*event_ptr).comm[i] = comm[i];
                }
            }
            Err(_) => {
                // Failed to get comm, use empty string
                for i in 0..16 {
                    (*event_ptr).comm[i] = 0;
                }
            }
        }

        // Read data from user buffer (up to 4KB)
        let read_len = if num < LLM_DATA_MAX_LEN {
            num
        } else {
            LLM_DATA_MAX_LEN
        };

        // Initialize data buffer to zeros
        for i in 0..LLM_DATA_MAX_LEN {
            (*event_ptr).data[i] = 0;
        }

        // Read the actual data
        bpf_probe_read_user_buf(buf_ptr, &mut (*event_ptr).data[..read_len]).map_err(|_| 1i64)?;
    }

    // Submit event to ring buffer
    event.submit(0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
