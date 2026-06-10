//! Agent-side event triage and smart filtering.
//!
//! Reduces telemetry volume by 80-95% before transmission to the backend.
//! This is critical for scaling beyond ~1K agents — without it the backend
//! drowns in duplicate and low-value events.
//!
//! ## Strategy
//!
//! 1. **Priority classification**: Every event gets a priority (Critical, High,
//!    Medium, Low, Noise). Critical/High always pass. Low/Noise are sampled.
//! 2. **Deduplication**: Identical events within a sliding window are merged
//!    (count incremented, only first + summary sent).
//! 3. **Adaptive sampling**: When under resource pressure (from the governor),
//!    sampling rates tighten further.
//! 4. **Detection passthrough**: Any event with pre-analysis detections attached
//!    always passes regardless of priority.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::collectors::{EventType, Severity, TelemetryEvent};
use crate::resource_governor::GovernorHandle;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Event triage configuration.
///
/// Nested under `[event_triage]` in `agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventTriageConfig {
    /// Enable agent-side triage (default: true).
    pub enabled: bool,

    /// Dedup window in seconds. Events with the same dedup key within this
    /// window are merged (default: 30).
    pub dedup_window_secs: u64,

    /// Maximum dedup table entries before forced flush (default: 10_000).
    pub max_dedup_entries: usize,

    /// Sampling rate for Low-priority events: 1-in-N are kept (default: 10).
    pub low_sample_rate: u32,

    /// Sampling rate for Noise-priority events: 1-in-N are kept (default: 50).
    pub noise_sample_rate: u32,

    /// How often (seconds) to emit triage statistics as a metadata event (default: 60).
    pub stats_interval_secs: u64,
}

impl Default for EventTriageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dedup_window_secs: 30,
            max_dedup_entries: 10_000,
            low_sample_rate: 10,
            noise_sample_rate: 50,
            stats_interval_secs: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// Priority classification
// ---------------------------------------------------------------------------

/// Event priority level assigned by triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventPriority {
    /// Always dropped (e.g. redundant heartbeats).
    Noise,
    /// Sampled aggressively.
    Low,
    /// Sampled mildly.
    Medium,
    /// Always sent.
    High,
    /// Always sent, first in queue.
    Critical,
}

/// Classify an event into a priority tier.
fn classify(event: &TelemetryEvent) -> EventPriority {
    // Any event with detections attached is always high priority.
    if !event.detections.is_empty() {
        return EventPriority::Critical;
    }

    // Severity-based boost.
    match event.severity {
        Severity::Critical => return EventPriority::Critical,
        Severity::High => return EventPriority::High,
        _ => {}
    }

    // Type-based classification.
    match event.event_type {
        // Always critical — active threats.
        EventType::ProcessInject
        | EventType::ProcessHollowing
        | EventType::MemoryPermissionChange
        | EventType::UnbackedThreadStart
        | EventType::ModuleStomping
        | EventType::TransactedHollowing
        | EventType::ThreadHijacking
        | EventType::ProcessDoppelganging
        | EventType::HoneyfileAccess
        | EventType::DecoyServiceAccess
        | EventType::FileExecuteBlocked
        | EventType::DriverLoad
        | EventType::ResponseAction => EventPriority::Critical,

        // High — important security events.
        EventType::ProcessCreate
        | EventType::ProcessTerminate
        | EventType::AuthLogin
        | EventType::AuthFailed
        | EventType::RegistryCreate
        | EventType::RegistrySetValue
        | EventType::RegistryDelete
        | EventType::MemoryScan
        | EventType::ForensicCollection
        | EventType::FileExecute
        | EventType::CertificateAnomaly
        | EventType::NetworkAnomaly
        | EventType::NetworkFingerprint => EventPriority::High,

        // Medium — useful but tolerable loss.
        EventType::FileCreate
        | EventType::FileModify
        | EventType::FileDelete
        | EventType::FileRename
        | EventType::DnsQuery
        | EventType::NetworkConnect
        | EventType::NetworkClose
        | EventType::ModuleLoad
        | EventType::FileIntegrity
        | EventType::WmiActivity => EventPriority::Medium,

        // Low — high volume, low signal individually.
        EventType::NetworkListen | EventType::AuthLogout => EventPriority::Low,

        // Default: medium.
        _ => EventPriority::Medium,
    }
}

// ---------------------------------------------------------------------------
// Dedup key
// ---------------------------------------------------------------------------

/// Compute a deduplication key for an event. Events with the same key within
/// the dedup window are merged.
fn dedup_key(event: &TelemetryEvent) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    // Type is always part of the key.
    std::mem::discriminant(&event.event_type).hash(&mut hasher);

    // Add payload-specific differentiators.
    // We use the serialized payload truncated to keep hashing fast.
    if let Ok(payload_json) = serde_json::to_string(&event.payload) {
        // Use first 256 bytes of the payload — enough to distinguish
        // unique events without hashing megabytes of data.
        let truncated = &payload_json[..payload_json.len().min(256)];
        truncated.hash(&mut hasher);
    }

    hasher.finish()
}

// ---------------------------------------------------------------------------
// Dedup entry
// ---------------------------------------------------------------------------

struct DedupEntry {
    /// First occurrence of this event.
    #[allow(dead_code)]
    first_event: TelemetryEvent,
    /// How many times this event has been seen.
    count: u32,
    /// When this entry was created.
    created_at: Instant,
    /// When this entry was last seen.
    last_seen: Instant,
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Triage statistics for observability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriageStats {
    pub events_received: u64,
    pub events_passed: u64,
    pub events_deduplicated: u64,
    pub events_sampled_out: u64,
    pub events_dropped_noise: u64,
    pub dedup_table_size: usize,
}

impl TriageStats {
    /// Reduction ratio (0.0 = no reduction, 1.0 = all dropped).
    pub fn reduction_ratio(&self) -> f64 {
        if self.events_received == 0 {
            return 0.0;
        }
        1.0 - (self.events_passed as f64 / self.events_received as f64)
    }
}

// ---------------------------------------------------------------------------
// Triage engine
// ---------------------------------------------------------------------------

/// The event triage engine. Sits between collectors and the transport layer.
pub struct EventTriage {
    config: EventTriageConfig,
    governor: Option<GovernorHandle>,
    dedup_table: HashMap<u64, DedupEntry>,
    stats: TriageStats,
    /// Simple counter for sampling (mod N).
    sample_counter: u64,
    last_flush: Instant,
    last_stats: Instant,
}

impl EventTriage {
    pub fn new(config: EventTriageConfig, governor: Option<GovernorHandle>) -> Self {
        Self {
            config,
            governor,
            dedup_table: HashMap::with_capacity(1024),
            stats: TriageStats::default(),
            sample_counter: 0,
            last_flush: Instant::now(),
            last_stats: Instant::now(),
        }
    }

    /// Process a batch of events and return only those that should be sent.
    pub fn filter_batch(&mut self, events: Vec<TelemetryEvent>) -> Vec<TelemetryEvent> {
        if !self.config.enabled {
            return events;
        }

        let mut output = Vec::with_capacity(events.len() / 2);

        for event in events {
            self.stats.events_received += 1;

            if let Some(evt) = self.process_event(event) {
                self.stats.events_passed += 1;
                output.push(evt);
            }
        }

        // Periodic flush of expired dedup entries.
        self.maybe_flush_dedup();

        output
    }

    /// Process a single event. Returns Some if it should be sent.
    fn process_event(&mut self, mut event: TelemetryEvent) -> Option<TelemetryEvent> {
        let priority = classify(&event);

        // 1. Drop noise events entirely.
        if priority == EventPriority::Noise {
            self.stats.events_dropped_noise += 1;
            return None;
        }

        // 2. Critical/High always pass (skip dedup + sampling).
        if priority >= EventPriority::High {
            return Some(event);
        }

        // 3. Deduplication for Medium/Low.
        let key = dedup_key(&event);
        let now = Instant::now();
        let window = Duration::from_secs(self.config.dedup_window_secs);

        if let Some(entry) = self.dedup_table.get_mut(&key) {
            if now.duration_since(entry.created_at) < window {
                // Within dedup window — merge.
                entry.count += 1;
                entry.last_seen = now;
                self.stats.events_deduplicated += 1;
                trace!(
                    event_type = ?event.event_type,
                    count = entry.count,
                    "event deduplicated"
                );
                return None;
            }
            // Window expired — emit summary of old entry and start new one.
            let old_count = entry.count;
            if old_count > 1 {
                // Annotate the new event with the dedup count from the previous window.
                event
                    .metadata
                    .insert("dedup_prev_count".to_string(), old_count.to_string());
            }
            // Reset entry.
            *entry = DedupEntry {
                first_event: event.clone(),
                count: 1,
                created_at: now,
                last_seen: now,
            };
        } else {
            // New event — add to dedup table.
            if self.dedup_table.len() < self.config.max_dedup_entries {
                self.dedup_table.insert(
                    key,
                    DedupEntry {
                        first_event: event.clone(),
                        count: 1,
                        created_at: now,
                        last_seen: now,
                    },
                );
            }
        }

        // 4. Sampling for Low priority.
        if priority == EventPriority::Low {
            let rate = self.effective_sample_rate(self.config.low_sample_rate);
            self.sample_counter += 1;
            if self.sample_counter % rate as u64 != 0 {
                self.stats.events_sampled_out += 1;
                return None;
            }
        }

        // 5. Under pressure, also sample Medium events.
        if priority == EventPriority::Medium {
            if let Some(ref gov) = self.governor {
                let level = gov.pressure_level();
                if level as u8 >= 2 {
                    // Moderate+ pressure: sample medium events too.
                    let rate = match level as u8 {
                        2 => 3u32, // Moderate: 1-in-3
                        3 => 5,    // Heavy: 1-in-5
                        _ => 10,   // Critical: 1-in-10
                    };
                    self.sample_counter += 1;
                    if self.sample_counter % rate as u64 != 0 {
                        self.stats.events_sampled_out += 1;
                        return None;
                    }
                }
            }
        }

        Some(event)
    }

    /// Adjust sample rate based on resource pressure.
    fn effective_sample_rate(&self, base_rate: u32) -> u32 {
        if let Some(ref gov) = self.governor {
            let multiplier = gov.interval_multiplier();
            (base_rate as f32 * multiplier).ceil() as u32
        } else {
            base_rate
        }
    }

    /// Flush expired entries from the dedup table.
    fn maybe_flush_dedup(&mut self) {
        let now = Instant::now();
        // Only flush every dedup_window_secs.
        if now.duration_since(self.last_flush) < Duration::from_secs(self.config.dedup_window_secs)
        {
            return;
        }
        self.last_flush = now;

        let window = Duration::from_secs(self.config.dedup_window_secs);
        self.dedup_table
            .retain(|_, entry| now.duration_since(entry.last_seen) < window);

        self.stats.dedup_table_size = self.dedup_table.len();

        debug!(
            dedup_entries = self.dedup_table.len(),
            received = self.stats.events_received,
            passed = self.stats.events_passed,
            deduped = self.stats.events_deduplicated,
            sampled_out = self.stats.events_sampled_out,
            reduction = format!("{:.1}%", self.stats.reduction_ratio() * 100.0),
            "triage flush"
        );
    }

    /// Get current stats (for health telemetry).
    pub fn stats(&self) -> TriageStats {
        let mut s = self.stats.clone();
        s.dedup_table_size = self.dedup_table.len();
        s
    }

    /// Check if enough time has passed to emit stats.
    pub fn should_emit_stats(&self) -> bool {
        Instant::now().duration_since(self.last_stats)
            >= Duration::from_secs(self.config.stats_interval_secs)
    }

    /// Mark stats as emitted.
    pub fn mark_stats_emitted(&mut self) {
        self.last_stats = Instant::now();
    }

    /// Reset stats counters (called after emitting).
    pub fn reset_stats(&mut self) {
        self.stats = TriageStats::default();
        self.stats.dedup_table_size = self.dedup_table.len();
    }
}
