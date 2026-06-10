//! Local analysis modules

#[cfg(test)]
mod tests;

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::Read;
use tracing::warn;

#[cfg(feature = "yara")]
pub mod yara;

#[cfg(feature = "onnx")]
pub mod onnx_scanner;

#[cfg(feature = "onnx")]
pub mod onnx_inference;

pub mod offline_detection;

pub mod alerting;
pub mod behavioral;
pub mod behavioral_chains;
pub mod bof_detector;
pub mod cmdline_spoofing;
pub mod data_staging;
pub mod early_bird;
pub mod etw_tampering;
pub mod explainer;
pub mod heap_spray;
pub mod indirect_syscall;
pub mod integrated_detector;
pub mod local_ml;
pub mod mitre;
pub mod ml_agent_parity_fixture;
pub mod ml_local;
pub mod pipeline;
pub mod return_address;
pub mod sample_submitter;
pub mod stack_pivot;
pub mod supply_chain;
pub mod thread_hijacking;
pub mod threat_intel;

#[cfg(target_os = "macos")]
pub mod macho_parser;

// Re-export sample submitter for easy access
pub use sample_submitter::{SampleMetadata, SamplePayload, SampleSubmitter};

// Re-export local ML engine for easy access
pub use local_ml::{
    DetectionAction, LocalMLConfig, LocalMLEngine, MLDetectionEvent, PreExecutionResult,
};

// Re-export ONNX scanner for easy access
#[cfg(feature = "onnx")]
pub use onnx_scanner::{
    is_executable_file, OnnxScanner, OnnxScannerConfig, ScanResult as OnnxScanResult,
    ScannerStats as OnnxScannerStats,
};

// Re-export ONNX inference engine for easy access
#[cfg(feature = "onnx")]
pub use onnx_inference::{
    InferenceResult, ModelInputFormat, OnnxInferenceConfig, OnnxInferenceEngine,
};

// Re-export offline detection for easy access
pub use offline_detection::{OfflineDetectionConfig, OfflineDetector, OfflineVerdict, Verdict};

// Re-export feature-based ML engine for easy access
pub use ml_local::{LocalMLFeatureEngine, MLClassification, FEATURE_COUNT};

// Re-export ML-3 agent parity fixture support
pub use ml_agent_parity_fixture::{
    load_and_validate_fixture, validate_fixture, AgentParityFixture, DecodedFixtureSample,
    FixtureValidationSummary,
};

// Re-export the pipeline for easy access
pub use pipeline::AnalysisPipeline;

// Re-export behavioral chain analyzer
pub use behavioral_chains::{
    BehavioralChain, BehavioralChainAnalyzer, BehavioralEventType, ChainAlert, ChainSeverity,
};

// Re-export data staging detector
pub use data_staging::{
    DataStagingDetector, FileAccessEvent, FileAccessType, StagingDetection, StagingDetectionType,
};

// Re-export ETW tampering detector
pub use etw_tampering::{
    critical_providers, EtwScanReport, EtwSessionInfo, EtwTamperingDetection, EtwTamperingDetector,
    EtwTamperingType, ProviderState,
};

// Re-export integrated detector
pub use integrated_detector::{
    DetectionEvent, DetectionSeverity, DetectionType, IntegratedDetector, IntegratedDetectorConfig,
};

// Re-export indirect syscall detector (from memory module) for analyzer integration
pub use crate::memory::indirect_syscall_detector::{
    scan_for_indirect_syscalls, IndirectSyscallDetection, IndirectSyscallPattern,
};

// Re-export stack spoofing detector (from memory module) for analyzer integration
pub use crate::memory::stack_spoofing_detector::{
    scan_process_for_stack_spoofing, scan_thread_for_stack_spoofing, FrameAnomaly,
    FrameAnomalyType, ReturnAddressIssue, SpoofingSeverity, StackSpoofingDetection,
    StackSpoofingDetector, StackSpoofingTechnique, SuspiciousReturnAddress,
};

// Re-export BOF (Beacon Object File) detector
pub use bof_detector::{
    BofDetection, BofDetectionType, BofDetector, BofDetectorConfig, CoffInfo, CoffMachine,
};

// Re-export command line spoofing detector (MITRE T1564.010)
pub use cmdline_spoofing::{
    CmdlineSpoofingAlert, DetectionMethod, EnhancedCmdlineSpoofingDetector, SpoofingContext,
    SpoofingDetectorConfig, SpoofingPattern,
};

// Re-export thread hijacking detector (MITRE T1055.003)
pub use thread_hijacking::{
    HijackingTechnique, MemoryRegionType, ShellcodeScanner, ThreadHijackingCollector,
    ThreadHijackingConfig, ThreadHijackingDetector, ThreadHijackingEvent, ThreadOperation,
    ThreadOperationType, ThreadState,
};

// Re-export indirect syscall analyzer (MITRE T1106)
pub use indirect_syscall::{
    IndirectSyscallAnalyzer, IndirectSyscallEvent, IndirectSyscallTechnique, NtdllReadEvent,
};

// Re-export Early Bird APC injection detector (MITRE T1055.004)
pub use early_bird::{
    ApcQueueEvent, EarlyBirdCollector, EarlyBirdConfig, EarlyBirdDetection, EarlyBirdDetector,
    EarlyBirdStage, EarlyBirdStats, MemoryAllocation, SuspendedProcessState,
};

// Re-export Stack Pivot detector for ROP/JOP detection (MITRE T1055.012, T1574)
pub use stack_pivot::{
    check_thread_stack_pivot, scan_process_for_stack_pivots, LikelyTechnique,
    MemoryRegionType as StackPivotMemoryRegionType, StackBounds, StackPivotAlert,
    StackPivotCollector, StackPivotConfig, StackPivotDetector, StackPivotResult,
};

// Re-export Heap Spray detector for exploitation detection (MITRE T1203)
pub use heap_spray::{
    analyze_memory_layout, detect_js_heap_spray, AllocationStats, AllocationTracker, EntropyResult,
    HeapSprayAlert, HeapSprayCollector, HeapSprayConfig, HeapSprayDetector, HeapSprayIndicators,
    JsSprayIndicator, MemoryAnalysis, PatternMatcher, SprayPattern, SprayPatternType, SprayType,
    SuspiciousRegion, TrackedAllocation,
};

// Re-export Return Address validator for ROP chain detection (MITRE T1055, T1574)
pub use return_address::{
    is_after_call_instruction, walk_stack_and_validate, CallInstructionType, GadgetType,
    InvalidFrame, ModuleCache, ModuleInfo as RopModuleInfo, ReturnAddressValidator,
    RopDetectionAlert, RopGadgetInfo, StackFrame as RopStackFrame, ValidationResult,
    ValidatorConfig,
};

/// Global hash cache: keyed by file path, stores (file_size, mtime_secs, sha256, entropy).
/// Avoids re-hashing the same unchanged file on every scan tick.
static HASH_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, (u64, i64, Vec<u8>, f32)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Calculate SHA256 hash and entropy of a file.
///
/// Results are cached by (path, file_size, mtime).  If the file hasn't
/// changed since the last call, the cached hash is returned immediately
/// without reading the file again.
pub async fn hash_file(path: &str) -> Result<(Vec<u8>, f32)> {
    let path = path.to_string();

    tokio::task::spawn_blocking(move || {
        // Check file metadata first (cheap stat call).
        let meta = std::fs::metadata(&path)?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Fast path: return cached result if file unchanged.
        {
            let cache = match HASH_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("Hash cache lock poisoned, recovering");
                    poisoned.into_inner()
                }
            };
            if let Some((cached_size, cached_mtime, hash, entropy)) = cache.get(&path) {
                if *cached_size == size && *cached_mtime == mtime {
                    return Ok((hash.clone(), *entropy));
                }
            }
        }

        // Slow path: read file, compute hash + entropy.
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut byte_counts = [0u64; 256];
        let mut total_bytes = 0u64;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);

            for &byte in &buffer[..bytes_read] {
                byte_counts[byte as usize] += 1;
                total_bytes += 1;
            }
        }

        let hash = hasher.finalize().to_vec();

        let entropy = if total_bytes > 0 {
            let mut entropy = 0.0f64;
            for &count in &byte_counts {
                if count > 0 {
                    let p = count as f64 / total_bytes as f64;
                    entropy -= p * p.log2();
                }
            }
            entropy as f32
        } else {
            0.0
        };

        // Store in cache (cap at 10 000 entries to bound memory).
        {
            let mut cache = match HASH_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("Hash cache lock poisoned during insert, recovering");
                    poisoned.into_inner()
                }
            };
            if cache.len() >= 10_000 {
                cache.clear(); // simple eviction: flush when full
            }
            cache.insert(path, (size, mtime, hash.clone(), entropy));
        }

        Ok((hash, entropy))
    })
    .await?
}

/// Calculate entropy of byte data
pub fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_counts = [0u64; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy as f32
}

/// Check if file is a PE executable
pub fn is_pe_file(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A
}

/// Check if file is an ELF executable
pub fn is_elf_file(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46
}
