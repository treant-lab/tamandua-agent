//! Tamandua Minifilter Scan Port Client
//!
//! Handles the communication with the kernel driver's pre-execution scan port.
//! Receive scan requests for executable files, perform analysis, and return verdicts.

use anyhow::Result;
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;
#[cfg(target_os = "windows")]
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FILTER_MESSAGE_HEADER,
    FILTER_REPLY_HEADER,
};

// Scan Port Name (must match minifilter.h)
const TAMANDUA_SCAN_PORT_NAME: &str = "\\TamanduaScanPort";

// Message Types
const SCAN_MSG_FILE_CREATE: u32 = 1;
const SCAN_MSG_VERDICT_RESPONSE: u32 = 3;

// Verdicts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    Unknown = 0,
    Allow = 1,
    Block = 2,
    Quarantine = 3,
}

// Verdict Reasons
pub const VERDICT_REASON_YARA: u32 = 0x0001;
pub const VERDICT_REASON_ML: u32 = 0x0002;
pub const VERDICT_REASON_HASH: u32 = 0x0004;
pub const VERDICT_REASON_POLICY: u32 = 0x0008;

#[repr(C, packed)]
struct ScanRequestMsg {
    header: FILTER_MESSAGE_HEADER,
    // Tamandua Scan Request Body
    message_type: u32,
    process_id: u32,
    thread_id: u32,
    file_path: [u16; 520],
    file_size: i64,
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
    is_executable: u8,
}

#[repr(C, packed)]
struct ScanReplyMsg {
    header: FILTER_REPLY_HEADER,
    // Tamandua Scan Response Body
    verdict: u32,
    verdict_reason: u32,
    malware_score: f32,
}

pub struct ScanPortClient {
    running: Arc<AtomicBool>,
}

impl ScanPortClient {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn start(&self, analysis_pipeline: Arc<crate::analyzers::AnalysisPipeline>) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        std::thread::spawn(move || {
            info!("Starting Scan Port Client...");
            if let Err(e) = Self::run_loop(running, analysis_pipeline) {
                error!("Scan Port Client failed: {:?}", e);
            }
        });
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start(&self, _analysis_pipeline: Arc<crate::analyzers::AnalysisPipeline>) {
        warn!("Scan Port Client only supported on Windows");
    }

    #[cfg(target_os = "windows")]
    fn run_loop(
        running: Arc<AtomicBool>,
        _analysis_pipeline: Arc<crate::analyzers::AnalysisPipeline>,
    ) -> Result<()> {
        let port_name: Vec<u16> = TAMANDUA_SCAN_PORT_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let port_handle =
                FilterConnectCommunicationPort(PCWSTR(port_name.as_ptr()), 0, None, 0, None)?;

            info!("Connected to Tamandua Scan Port");

            let request_size = mem::size_of::<ScanRequestMsg>() as u32;
            // Align buffer to 8 bytes using u64 array
            let mut request_buffer = vec![0u64; (request_size as usize + 7) / 8];

            while running.load(Ordering::SeqCst) {
                // Blocking call to receive message from kernel
                let result = FilterGetMessage(
                    port_handle,
                    request_buffer.as_mut_ptr() as *mut FILTER_MESSAGE_HEADER,
                    request_size,
                    None,
                );

                if result.is_err() {
                    let err = result.err().unwrap();
                    if err.code().0 == -2147023896 {
                        // ERROR_INVALID_HANDLE (port closed)
                        warn!("Scan port closed by driver");
                        break;
                    }
                    error!("FilterGetMessage failed: {:?}", err);
                    std::thread::sleep(std::time::Duration::from_millis(100)); // prevent tight loop on error
                    continue;
                }

                // Process Request
                // Safe because we verified size matching mostly (kernel sends fixed size)
                // and we rely on Copy for unaligned reads from packed struct.
                let request = &*(request_buffer.as_ptr() as *const ScanRequestMsg);

                if request.message_type == SCAN_MSG_FILE_CREATE {
                    let pid = request.process_id;
                    // Copy packed path to aligned buffer to avoid unaligned reference
                    let mut file_path_arr = [0u16; 520];
                    std::ptr::copy_nonoverlapping(
                        std::ptr::addr_of!(request.file_path) as *const u16,
                        file_path_arr.as_mut_ptr(),
                        520,
                    );

                    let path_len = file_path_arr.iter().position(|&c| c == 0).unwrap_or(520);
                    let path_string = String::from_utf16_lossy(&file_path_arr[..path_len]);
                    let msg_id = request.header.MessageId; // Copy MessageId out safely

                    debug!("Scan Request: PID={} File={}", pid, path_string);

                    // --- ANALYSIS LOGIC ---
                    // Here we would call the analysis pipeline.
                    let verdict = ScanVerdict::Allow;
                    let score = 0.0;
                    let reason = 0;

                    // --- REPLY ---
                    let reply = ScanReplyMsg {
                        header: FILTER_REPLY_HEADER {
                            Status: windows::Win32::Foundation::NTSTATUS(0),
                            MessageId: msg_id,
                        },
                        verdict: verdict as u32,
                        verdict_reason: reason,
                        malware_score: score,
                    };

                    let reply_size = mem::size_of::<ScanReplyMsg>() as u32;
                    let mut reply_buffer = vec![0u64; (reply_size as usize + 7) / 8];

                    // Copy packed struct into aligned buffer
                    std::ptr::copy_nonoverlapping(
                        &reply as *const ScanReplyMsg as *const u8,
                        reply_buffer.as_mut_ptr() as *mut u8,
                        reply_size as usize,
                    );

                    let reply_result = FilterReplyMessage(
                        port_handle,
                        reply_buffer.as_mut_ptr() as *mut FILTER_REPLY_HEADER,
                        reply_size,
                    );

                    if let Err(e) = reply_result {
                        error!("Failed to send scan reply: {:?}", e);
                    }
                }
            }

            let _ = CloseHandle(port_handle);
        }

        Ok(())
    }
}
