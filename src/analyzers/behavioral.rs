//! Behavioral ML/Baseline Engine
//!
//! Statistical anomaly detection without external ML libraries.
//! Features:
//! - Process behavior baselines (parent-child, network, file, registry)
//! - Moving average and standard deviation calculation
//! - Z-score based anomaly detection
//! - Time-series analysis (day/night patterns)
//! - Suspicious behavior pattern detection
//! - Risk scoring with decay
//!
//! Generates Detection events with behavioral_anomaly type.

use crate::collectors::{
    Detection, DetectionType, DnsEvent, EventPayload, FileEvent, NetworkEvent, ProcessEvent,
    RegistryEvent, TelemetryEvent,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

// ============================================================================
// Configuration
// ============================================================================

/// Behavioral engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Learning mode duration in hours (default: 48)
    pub learning_duration_hours: u64,
    /// Enable continuous baseline updates after learning
    pub continuous_learning: bool,
    /// Z-score threshold for anomaly detection (default: 3.0)
    pub zscore_threshold: f64,
    /// Risk score threshold for alerting (default: 50.0)
    pub alert_threshold: f32,
    /// Risk score decay rate per hour (default: 5.0)
    pub score_decay_per_hour: f32,
    /// Maximum events to track per process for statistics
    pub max_events_per_process: usize,
    /// Time window for moving average in minutes
    pub moving_average_window_minutes: u64,
    /// Enable time-of-day analysis
    pub time_analysis_enabled: bool,
    /// Path to baseline persistence file
    pub baseline_path: String,
    /// Auto-save interval in minutes
    pub autosave_interval_minutes: u64,
    /// Sensitivity level (1.0 = normal, 2.0 = high sensitivity, 0.5 = low)
    pub sensitivity: f32,
    /// Runtime toggle for exporting the deterministic RiskScore onto the
    /// telemetry stream (behavioral-sequence ML pairing). Compiled only with
    /// the `export_risk_score` feature; defaults to `false` (off) so enabling
    /// the feature does not change behavior unless explicitly opted into.
    #[cfg(feature = "export_risk_score")]
    #[serde(default)]
    pub export_risk_score: bool,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        let baseline_path = if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\baselines.json".to_string()
        } else {
            "/var/lib/tamandua/baselines.json".to_string()
        };

        Self {
            learning_duration_hours: 48,
            continuous_learning: true,
            zscore_threshold: 3.0,
            alert_threshold: 75.0,
            score_decay_per_hour: 5.0,
            max_events_per_process: 1000,
            moving_average_window_minutes: 60,
            time_analysis_enabled: true,
            baseline_path,
            autosave_interval_minutes: 15,
            sensitivity: 1.0,
            #[cfg(feature = "export_risk_score")]
            export_risk_score: false,
        }
    }
}

// ============================================================================
// Statistical Types
// ============================================================================

/// Rolling statistics calculator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingStats {
    /// Circular buffer of values
    values: VecDeque<f64>,
    /// Timestamps for each value
    timestamps: VecDeque<u64>,
    /// Maximum window size
    max_size: usize,
    /// Running sum for efficiency
    sum: f64,
    /// Running sum of squares for variance
    sum_sq: f64,
}

impl RollingStats {
    pub fn new(max_size: usize) -> Self {
        Self {
            values: VecDeque::with_capacity(max_size),
            timestamps: VecDeque::with_capacity(max_size),
            max_size,
            sum: 0.0,
            sum_sq: 0.0,
        }
    }

    pub fn add(&mut self, value: f64, timestamp: u64) {
        // Remove old value if at capacity
        if self.values.len() >= self.max_size {
            if let Some(old) = self.values.pop_front() {
                self.timestamps.pop_front();
                self.sum -= old;
                self.sum_sq -= old * old;
            }
        }

        self.values.push_back(value);
        self.timestamps.push_back(timestamp);
        self.sum += value;
        self.sum_sq += value * value;
    }

    pub fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.sum / self.values.len() as f64
    }

    pub fn variance(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }
        let n = self.values.len() as f64;
        let mean = self.mean();
        (self.sum_sq / n) - (mean * mean)
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn zscore(&self, value: f64) -> f64 {
        let std = self.std_dev();
        if std == 0.0 || std.is_nan() {
            return 0.0;
        }
        (value - self.mean()) / std
    }

    pub fn count(&self) -> usize {
        self.values.len()
    }

    /// Get values within a time window (milliseconds)
    pub fn values_in_window(&self, window_ms: u64) -> Vec<f64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now.saturating_sub(window_ms);

        self.values
            .iter()
            .zip(self.timestamps.iter())
            .filter(|(_, ts)| **ts >= cutoff)
            .map(|(v, _)| *v)
            .collect()
    }
}

/// Hourly activity pattern (24-hour cycle)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyPattern {
    /// Event counts per hour (0-23)
    hourly_counts: [u64; 24],
    /// Total observations
    total_observations: u64,
}

impl Default for HourlyPattern {
    fn default() -> Self {
        Self {
            hourly_counts: [0; 24],
            total_observations: 0,
        }
    }
}

impl HourlyPattern {
    pub fn record(&mut self, hour: usize) {
        if hour < 24 {
            self.hourly_counts[hour] += 1;
            self.total_observations += 1;
        }
    }

    pub fn expected_rate(&self, hour: usize) -> f64 {
        if self.total_observations == 0 || hour >= 24 {
            return 0.0;
        }
        self.hourly_counts[hour] as f64 / self.total_observations as f64
    }

    /// Check if activity at given hour is unusual
    pub fn is_unusual(&self, hour: usize, threshold: f64) -> bool {
        if self.total_observations < 100 {
            return false; // Not enough data
        }
        let rate = self.expected_rate(hour);
        let avg_rate = 1.0 / 24.0;

        // Unusual if significantly different from average
        (rate - avg_rate).abs() > threshold * avg_rate
    }

    /// Check if this is typically a low-activity period
    pub fn is_low_activity_period(&self, hour: usize) -> bool {
        if self.total_observations < 100 {
            return false;
        }
        self.expected_rate(hour) < (1.0 / 48.0) // Less than half the expected uniform rate
    }
}

// ============================================================================
// Baseline Types
// ============================================================================

/// Process behavior baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBaseline {
    /// Process name (lowercase)
    pub name: String,
    /// Known legitimate parent processes
    pub known_parents: HashSet<String>,
    /// Known legitimate child processes
    pub known_children: HashSet<String>,
    /// Normal network destinations (IP:port or domain)
    pub known_network_destinations: HashSet<String>,
    /// Normal file access patterns (directory prefixes)
    pub known_file_patterns: HashSet<String>,
    /// Normal registry access patterns (key prefixes)
    pub known_registry_patterns: HashSet<String>,
    /// Event rate statistics
    pub event_rate_stats: RollingStats,
    /// Network connection rate
    pub network_rate_stats: RollingStats,
    /// File operation rate
    pub file_rate_stats: RollingStats,
    /// Hourly activity pattern
    pub hourly_pattern: HourlyPattern,
    /// Number of observations
    pub observation_count: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Whether this baseline has been manually approved
    pub approved: bool,
}

impl ProcessBaseline {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_lowercase(),
            known_parents: HashSet::new(),
            known_children: HashSet::new(),
            known_network_destinations: HashSet::new(),
            known_file_patterns: HashSet::new(),
            known_registry_patterns: HashSet::new(),
            event_rate_stats: RollingStats::new(1000),
            network_rate_stats: RollingStats::new(500),
            file_rate_stats: RollingStats::new(500),
            hourly_pattern: HourlyPattern::default(),
            observation_count: 0,
            last_seen: 0,
            approved: false,
        }
    }

    /// Update baseline with process event
    pub fn update_from_process(&mut self, event: &ProcessEvent, timestamp: u64) {
        // Record parent
        if let Some(ref parent) = event.parent_name {
            self.known_parents.insert(parent.to_lowercase());
        }

        // Record hourly pattern
        let hour = (timestamp / 3600000) % 24;
        self.hourly_pattern.record(hour as usize);

        self.observation_count += 1;
        self.last_seen = timestamp;
    }

    /// Update baseline with child process spawned
    pub fn record_child(&mut self, child_name: &str) {
        self.known_children.insert(child_name.to_lowercase());
    }

    /// Update with network connection
    pub fn record_network(&mut self, destination: &str, timestamp: u64) {
        self.known_network_destinations
            .insert(destination.to_lowercase());
        self.network_rate_stats.add(1.0, timestamp);
    }

    /// Update with file operation
    pub fn record_file_op(&mut self, path: &str, timestamp: u64) {
        // Store directory prefix
        if let Some(parent) = Path::new(path).parent() {
            self.known_file_patterns
                .insert(parent.to_string_lossy().to_lowercase());
        }
        self.file_rate_stats.add(1.0, timestamp);
    }

    /// Update with registry operation
    pub fn record_registry_op(&mut self, key: &str) {
        // Store key prefix (up to second level)
        let parts: Vec<&str> = key.split('\\').collect();
        if parts.len() >= 2 {
            self.known_registry_patterns
                .insert(parts[..2.min(parts.len())].join("\\").to_lowercase());
        }
    }
}

/// System-wide baseline storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBaseline {
    /// Per-process baselines
    pub process_baselines: HashMap<String, ProcessBaseline>,
    /// Global network destination frequency
    pub global_network_destinations: HashMap<String, u64>,
    /// Known rare network destinations (seen less than threshold)
    pub rare_destinations_threshold: u64,
    /// Learning start time
    pub learning_start_time: u64,
    /// Learning complete flag
    pub learning_complete: bool,
    /// Last save time
    pub last_save_time: u64,
}

impl Default for SystemBaseline {
    fn default() -> Self {
        Self {
            process_baselines: HashMap::new(),
            global_network_destinations: HashMap::new(),
            rare_destinations_threshold: 5,
            learning_start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            learning_complete: false,
            last_save_time: 0,
        }
    }
}

impl SystemBaseline {
    /// Load from file
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&content)?;
        info!(path = %path, "Loaded baseline from file");
        Ok(baseline)
    }

    /// Save to file
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        debug!(path = %path, "Saved baseline to file");
        Ok(())
    }

    /// Get or create process baseline
    pub fn get_or_create_process(&mut self, name: &str) -> &mut ProcessBaseline {
        let name_lower = name.to_lowercase();
        self.process_baselines
            .entry(name_lower.clone())
            .or_insert_with(|| ProcessBaseline::new(&name_lower))
    }

    /// Check if destination is rare globally
    pub fn is_rare_destination(&self, destination: &str) -> bool {
        let dest_lower = destination.to_lowercase();
        self.global_network_destinations
            .get(&dest_lower)
            .map(|c| *c < self.rare_destinations_threshold)
            .unwrap_or(true)
    }

    /// Record a network destination
    pub fn record_destination(&mut self, destination: &str) {
        let dest_lower = destination.to_lowercase();
        *self
            .global_network_destinations
            .entry(dest_lower)
            .or_insert(0) += 1;
    }
}

// ============================================================================
// Risk Scoring
// ============================================================================

/// Risk score entry for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Process identifier (name or PID)
    pub process_key: String,
    /// Current risk score (0-100)
    pub score: f32,
    /// Last update timestamp
    pub last_update: u64,
    /// Contributing factors
    pub factors: Vec<RiskFactor>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub score: f32,
    pub description: String,
    pub timestamp: u64,
}

/// Serializable, export-only snapshot of a process [`RiskScore`].
///
/// This is the on-the-wire DTO emitted as an [`crate::collectors::EventPayload`]
/// when the `export_risk_score` feature is enabled. It deliberately carries only
/// the minimal identity needed to pair a telemetry stream to the deterministic
/// behavioral score (the binding requirement for the behavioral-sequence ML
/// path), plus the score and its contributing factors. It is intentionally a
/// distinct DTO (not a re-export of the live `RiskScore`) so internal-only
/// engine state can never leak onto the stream by accident.
#[cfg(feature = "export_risk_score")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreSnapshot {
    /// Process identity used to key the risk score (process name, lowercased).
    pub process_key: String,
    /// Optional PID when a concrete process is known, for telemetry pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Current deterministic risk score (0-100).
    pub score: f32,
    /// Timestamp (Unix ms) the score was last updated.
    pub last_update: u64,
    /// Timestamp (Unix ms) this snapshot was produced.
    pub snapshot_at: u64,
    /// Contributing risk factors at snapshot time.
    pub factors: Vec<RiskFactor>,
}

#[cfg(feature = "export_risk_score")]
impl RiskScore {
    /// Produce a serializable, export-only [`RiskScoreSnapshot`] for the
    /// telemetry stream. `pid` is optional pairing identity supplied by the
    /// caller (the live `RiskScore` is keyed by process name, not PID).
    pub fn snapshot(&self, pid: Option<u32>) -> RiskScoreSnapshot {
        let snapshot_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        RiskScoreSnapshot {
            process_key: self.process_key.clone(),
            pid,
            score: self.score,
            last_update: self.last_update,
            snapshot_at,
            factors: self.factors.clone(),
        }
    }
}

impl RiskScore {
    pub fn new(process_key: &str) -> Self {
        Self {
            process_key: process_key.to_string(),
            score: 0.0,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            factors: Vec::new(),
        }
    }

    /// Add risk factor
    pub fn add_factor(&mut self, name: &str, score: f32, description: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.factors.push(RiskFactor {
            name: name.to_string(),
            score,
            description: description.to_string(),
            timestamp: now,
        });

        self.score = (self.score + score).min(100.0);
        self.last_update = now;
    }

    /// Apply time decay to score
    pub fn apply_decay(&mut self, decay_per_hour: f32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let hours_elapsed = (now - self.last_update) as f32 / 3600000.0;
        let decay = decay_per_hour * hours_elapsed;

        self.score = (self.score - decay).max(0.0);
        self.last_update = now;

        // Remove old factors (older than 24 hours)
        let cutoff = now - 86400000;
        self.factors.retain(|f| f.timestamp > cutoff);
    }
}

// ============================================================================
// Suspicious Pattern Definitions
// ============================================================================

/// Known suspicious process spawning patterns
#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub name: &'static str,
    pub description: &'static str,
    pub parent_patterns: &'static [&'static str],
    pub child_patterns: &'static [&'static str],
    pub score: f32,
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
}

/// Built-in suspicious patterns
const SUSPICIOUS_PATTERNS: &[SuspiciousPattern] = &[
    SuspiciousPattern {
        name: "office_shell_spawn",
        description: "Office application spawning command shell",
        parent_patterns: &["winword", "excel", "powerpnt", "outlook", "msaccess"],
        child_patterns: &[
            "cmd.exe",
            "powershell",
            "pwsh",
            "wscript",
            "cscript",
            "mshta",
        ],
        score: 25.0,
        mitre_tactic: "execution",
        mitre_technique: "T1204.002",
    },
    SuspiciousPattern {
        name: "browser_process_spawn",
        description: "Browser spawning suspicious process",
        parent_patterns: &["chrome", "firefox", "iexplore", "msedge", "opera"],
        child_patterns: &["cmd.exe", "powershell", "certutil", "bitsadmin", "msiexec"],
        score: 20.0,
        mitre_tactic: "execution",
        mitre_technique: "T1189",
    },
    SuspiciousPattern {
        name: "svchost_unusual_parent",
        description: "svchost.exe with unusual parent",
        parent_patterns: &[], // Will check for NOT services.exe
        child_patterns: &["svchost"],
        score: 30.0,
        mitre_tactic: "defense-evasion",
        mitre_technique: "T1036.004",
    },
    SuspiciousPattern {
        name: "lsass_access",
        description: "Process accessing LSASS memory",
        parent_patterns: &[],
        child_patterns: &["lsass"],
        score: 35.0,
        mitre_tactic: "credential-access",
        mitre_technique: "T1003.001",
    },
    SuspiciousPattern {
        name: "script_from_temp",
        description: "Script execution from temp directory",
        parent_patterns: &[],
        child_patterns: &["wscript", "cscript", "mshta", "powershell"],
        score: 15.0,
        mitre_tactic: "defense-evasion",
        mitre_technique: "T1059",
    },
    SuspiciousPattern {
        name: "services_interactive",
        description: "Services spawning interactive process",
        parent_patterns: &["services.exe"],
        child_patterns: &["notepad", "calc", "mspaint", "explorer"],
        score: 25.0,
        mitre_tactic: "privilege-escalation",
        mitre_technique: "T1543.003",
    },
    SuspiciousPattern {
        name: "wmiprvse_spawn",
        description: "WMI spawning command shell",
        parent_patterns: &["wmiprvse"],
        child_patterns: &["cmd.exe", "powershell", "pwsh"],
        score: 20.0,
        mitre_tactic: "execution",
        mitre_technique: "T1047",
    },
    SuspiciousPattern {
        name: "rundll32_network",
        description: "rundll32 making network connections",
        parent_patterns: &[],
        child_patterns: &["rundll32"],
        score: 15.0,
        mitre_tactic: "defense-evasion",
        mitre_technique: "T1218.011",
    },
    SuspiciousPattern {
        name: "regsvr32_network",
        description: "regsvr32 network activity (Squiblydoo)",
        parent_patterns: &[],
        child_patterns: &["regsvr32"],
        score: 20.0,
        mitre_tactic: "defense-evasion",
        mitre_technique: "T1218.010",
    },
];

/// File encryption detection patterns
struct EncryptionPattern {
    /// Number of file modifications in window
    file_mod_count: u64,
    /// Number of unique extensions changed
    extension_changes: HashSet<String>,
    /// High entropy file count
    high_entropy_count: u64,
    /// Window start time
    window_start: u64,
}

impl Default for EncryptionPattern {
    fn default() -> Self {
        Self {
            file_mod_count: 0,
            extension_changes: HashSet::new(),
            high_entropy_count: 0,
            window_start: 0,
        }
    }
}

// ============================================================================
// Behavioral Analyzer Engine
// ============================================================================

/// Main behavioral analysis engine
pub struct BehavioralAnalyzer {
    /// Configuration
    config: BehavioralConfig,
    /// System baseline (protected by RwLock for concurrent access)
    baseline: Arc<RwLock<SystemBaseline>>,
    /// Risk scores per process
    risk_scores: Arc<RwLock<HashMap<String, RiskScore>>>,
    /// Encryption pattern tracking per process
    encryption_patterns: Arc<RwLock<HashMap<u32, EncryptionPattern>>>,
    /// Parent-child tracking (child PID -> parent PID)
    process_tree: Arc<RwLock<HashMap<u32, u32>>>,
    /// Process name mapping (PID -> name)
    process_names: Arc<RwLock<HashMap<u32, String>>>,
}

impl BehavioralAnalyzer {
    /// Create a new behavioral analyzer
    pub fn new(config: BehavioralConfig) -> Self {
        // Try to load existing baseline
        let baseline = match SystemBaseline::load_from_file(&config.baseline_path) {
            Ok(b) => {
                info!(
                    "Loaded existing baseline with {} processes",
                    b.process_baselines.len()
                );
                b
            }
            Err(_) => {
                info!("Starting with fresh baseline (learning mode)");
                SystemBaseline::default()
            }
        };

        let analyzer = Self {
            config,
            baseline: Arc::new(RwLock::new(baseline)),
            risk_scores: Arc::new(RwLock::new(HashMap::new())),
            encryption_patterns: Arc::new(RwLock::new(HashMap::new())),
            process_tree: Arc::new(RwLock::new(HashMap::new())),
            process_names: Arc::new(RwLock::new(HashMap::new())),
        };

        // Start background tasks
        analyzer.start_background_tasks();

        analyzer
    }

    /// Start background maintenance tasks
    fn start_background_tasks(&self) {
        // Auto-save task
        let baseline = self.baseline.clone();
        let path = self.config.baseline_path.clone();
        let interval = self.config.autosave_interval_minutes;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval * 60));
            loop {
                ticker.tick().await;
                let b = baseline.read().await;
                if let Err(e) = b.save_to_file(&path) {
                    error!(error = %e, "Failed to auto-save baseline");
                }
            }
        });

        // Score decay task
        let risk_scores = self.risk_scores.clone();
        let decay_rate = self.config.score_decay_per_hour;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                ticker.tick().await;
                let mut scores = risk_scores.write().await;
                for score in scores.values_mut() {
                    score.apply_decay(decay_rate);
                }
                // Remove scores that decayed to zero with no factors
                scores.retain(|_, s| s.score > 0.0 || !s.factors.is_empty());
            }
        });
    }

    /// Check if still in learning mode
    pub async fn is_learning(&self) -> bool {
        let baseline = self.baseline.read().await;
        if baseline.learning_complete {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let learning_duration_ms = self.config.learning_duration_hours * 3600 * 1000;
        now < baseline.learning_start_time + learning_duration_ms
    }

    /// Complete learning mode
    pub async fn complete_learning(&self) {
        let mut baseline = self.baseline.write().await;
        baseline.learning_complete = true;
        info!(
            processes = baseline.process_baselines.len(),
            "Learning mode completed"
        );

        // Save baseline
        if let Err(e) = baseline.save_to_file(&self.config.baseline_path) {
            error!(error = %e, "Failed to save baseline after learning");
        }
    }

    /// Manually approve a process baseline
    pub async fn approve_baseline(&self, process_name: &str) {
        let mut baseline = self.baseline.write().await;
        if let Some(pb) = baseline
            .process_baselines
            .get_mut(&process_name.to_lowercase())
        {
            pb.approved = true;
            info!(process = %process_name, "Baseline approved");
        }
    }

    /// Analyze an event and return detections
    pub async fn analyze(&self, event: &TelemetryEvent) -> Vec<Detection> {
        let mut detections = Vec::new();
        let is_learning = self.is_learning().await;
        let timestamp = event.timestamp;

        match &event.payload {
            EventPayload::Process(proc) => {
                // Update process tracking
                {
                    let mut tree = self.process_tree.write().await;
                    tree.insert(proc.pid, proc.ppid);
                    let mut names = self.process_names.write().await;
                    names.insert(proc.pid, proc.name.clone());
                }

                // Update baselines
                {
                    let mut baseline = self.baseline.write().await;
                    let pb = baseline.get_or_create_process(&proc.name);
                    pb.update_from_process(proc, timestamp);

                    // Record child relationship for parent
                    if let Some(ref parent_name) = proc.parent_name {
                        let parent_pb = baseline.get_or_create_process(parent_name);
                        parent_pb.record_child(&proc.name);
                    }
                }

                // Skip detection in learning mode
                if !is_learning {
                    detections.extend(self.analyze_process_behavior(proc, timestamp).await);
                }
            }
            EventPayload::Network(net) => {
                let destination = format!("{}:{}", net.remote_ip, net.remote_port);

                // Update baselines
                {
                    let mut baseline = self.baseline.write().await;
                    baseline.record_destination(&destination);
                    let pb = baseline.get_or_create_process(&net.process_name);
                    pb.record_network(&destination, timestamp);
                }

                if !is_learning {
                    detections.extend(self.analyze_network_behavior(net, timestamp).await);
                }
            }
            EventPayload::File(file) => {
                // Update baselines
                {
                    let mut baseline = self.baseline.write().await;
                    let pb = baseline.get_or_create_process(&file.process_name);
                    pb.record_file_op(&file.path, timestamp);
                }

                if !is_learning {
                    detections.extend(self.analyze_file_behavior(file, timestamp).await);
                }
            }
            EventPayload::Registry(reg) => {
                // Update baselines
                {
                    let mut baseline = self.baseline.write().await;
                    let pb = baseline.get_or_create_process(&reg.process_name);
                    pb.record_registry_op(&reg.key_path);
                }

                if !is_learning {
                    detections.extend(self.analyze_registry_behavior(reg, timestamp).await);
                }
            }
            EventPayload::Dns(dns) => {
                if !is_learning {
                    detections.extend(self.analyze_dns_behavior(dns, timestamp).await);
                }
            }
            _ => {}
        }

        detections
    }

    /// Analyze process behavior for anomalies
    async fn analyze_process_behavior(
        &self,
        proc: &ProcessEvent,
        timestamp: u64,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();
        let sensitivity = self.config.sensitivity;

        // Check suspicious parent-child patterns
        if let Some(ref parent_name) = proc.parent_name {
            let parent_lower = parent_name.to_lowercase();
            let child_lower = proc.name.to_lowercase();

            for pattern in SUSPICIOUS_PATTERNS {
                // LSASS memory access is handled by dedicated credential/LSASS collectors.
                // A normal process tree event like wininit.exe -> lsass.exe is not evidence
                // of credential dumping and must not generate this rule.
                if pattern.name == "lsass_access" {
                    continue;
                }

                // Check parent matches
                let parent_matches = pattern.parent_patterns.is_empty()
                    || pattern
                        .parent_patterns
                        .iter()
                        .any(|p| parent_lower.contains(p));

                // Check child matches
                let child_matches = pattern
                    .child_patterns
                    .iter()
                    .any(|c| child_lower.contains(c));

                if parent_matches && child_matches {
                    // Special case: svchost should have services.exe parent
                    if pattern.name == "svchost_unusual_parent" {
                        if !parent_lower.contains("services.exe") && child_lower.contains("svchost")
                        {
                            self.add_risk(
                                &proc.name,
                                pattern.name,
                                pattern.score * sensitivity,
                                pattern.description,
                            )
                            .await;
                            detections.push(self.create_detection(
                                pattern.name,
                                Self::confidence_from_pattern_score(pattern.score * sensitivity),
                                pattern.description,
                                pattern.mitre_tactic,
                                pattern.mitre_technique,
                            ));
                        }
                    } else {
                        self.add_risk(
                            &proc.name,
                            pattern.name,
                            pattern.score * sensitivity,
                            pattern.description,
                        )
                        .await;
                        detections.push(self.create_detection(
                            pattern.name,
                            Self::confidence_from_pattern_score(pattern.score * sensitivity),
                            pattern.description,
                            pattern.mitre_tactic,
                            pattern.mitre_technique,
                        ));
                    }
                }
            }

            if Self::is_lsass_masquerade(proc, &parent_lower, &child_lower) {
                let desc = format!(
                    "Suspicious LSASS-like process '{}' with parent '{}' and path '{}'",
                    proc.name, parent_name, proc.path
                );
                self.add_risk(&proc.name, "lsass_masquerade", 35.0 * sensitivity, &desc)
                    .await;
                detections.push(self.create_detection(
                    "lsass_masquerade",
                    0.9,
                    &desc,
                    "credential-access",
                    "T1003.001",
                ));
            }

            // Check baseline deviation
            let baseline = self.baseline.read().await;
            if let Some(parent_baseline) =
                baseline.process_baselines.get(&parent_name.to_lowercase())
            {
                if parent_baseline.observation_count >= 50 && !parent_baseline.approved {
                    if !parent_baseline
                        .known_children
                        .contains(&proc.name.to_lowercase())
                    {
                        let desc = format!(
                            "Process '{}' spawned unusual child '{}' (not in baseline)",
                            parent_name, proc.name
                        );
                        self.add_risk(
                            &proc.name,
                            "baseline_deviation_child",
                            10.0 * sensitivity,
                            &desc,
                        )
                        .await;
                        detections.push(self.create_detection(
                            "baseline_deviation_child",
                            0.6,
                            &desc,
                            "defense-evasion",
                            "T1036",
                        ));
                    }
                }
            }
        }

        // Check execution from suspicious paths
        let path_lower = proc.path.to_lowercase();
        if path_lower.contains("\\temp\\")
            || path_lower.contains("\\tmp\\")
            || path_lower.contains("\\appdata\\local\\temp")
            || path_lower.contains("/tmp/")
        {
            let desc = "Process executed from temporary directory";
            self.add_risk(&proc.name, "temp_execution", 10.0 * sensitivity, desc)
                .await;
            detections.push(self.create_detection(
                "temp_execution",
                0.5,
                desc,
                "defense-evasion",
                "T1036.005",
            ));
        }

        // Check for encoded/obfuscated command lines
        let cmdline_lower = proc.cmdline.to_lowercase();
        if cmdline_lower.contains("-encodedcommand")
            || cmdline_lower.contains("-enc ")
            || cmdline_lower.contains("-e ") && cmdline_lower.contains("powershell")
        {
            let desc = "PowerShell with encoded command detected";
            self.add_risk(&proc.name, "encoded_command", 20.0 * sensitivity, desc)
                .await;
            detections.push(self.create_detection(
                "encoded_powershell",
                0.8,
                desc,
                "execution",
                "T1059.001",
            ));
        }

        // Check execution policy bypass
        if cmdline_lower.contains("-executionpolicy") && cmdline_lower.contains("bypass") {
            let desc = "PowerShell execution policy bypass";
            self.add_risk(&proc.name, "policy_bypass", 15.0 * sensitivity, desc)
                .await;
            detections.push(self.create_detection(
                "execution_policy_bypass",
                0.7,
                desc,
                "defense-evasion",
                "T1059.001",
            ));
        }

        detections.extend(
            self.analyze_enterprise_attack_patterns(proc, &path_lower, &cmdline_lower, sensitivity)
                .await,
        );

        // Check for time-of-day anomalies
        if self.config.time_analysis_enabled {
            let hour = ((timestamp / 3600000) % 24) as usize;
            let baseline = self.baseline.read().await;
            if let Some(pb) = baseline.process_baselines.get(&proc.name.to_lowercase()) {
                if pb.hourly_pattern.is_low_activity_period(hour) && pb.observation_count > 100 {
                    let desc = format!(
                        "Process '{}' executed during unusual hours (hour {})",
                        proc.name, hour
                    );
                    self.add_risk(&proc.name, "unusual_time", 5.0 * sensitivity, &desc)
                        .await;
                    detections.push(self.create_detection(
                        "unusual_execution_time",
                        0.4,
                        &desc,
                        "defense-evasion",
                        "T1036",
                    ));
                }
            }
        }

        // Check risk score threshold
        let scores = self.risk_scores.read().await;
        if let Some(score) = scores.get(&proc.name.to_lowercase()) {
            if score.score >= self.config.alert_threshold
                && Self::risk_score_has_actionable_signal(score, self.config.alert_threshold)
            {
                let desc = format!(
                    "Process '{}' exceeded risk threshold: {:.1} (factors: {})",
                    proc.name,
                    score.score,
                    score
                        .factors
                        .iter()
                        .map(|f| f.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                // Use a softer confidence curve: 0.5 + 0.5 * (score - threshold) / (100 - threshold)
                // This maps threshold -> 0.5, max (100) -> 1.0, preventing saturation
                let threshold = self.config.alert_threshold;
                let confidence =
                    0.5 + 0.5 * ((score.score - threshold) / (100.0 - threshold)).min(1.0);
                detections.push(self.create_detection(
                    "high_risk_score",
                    confidence,
                    &desc,
                    "multiple",
                    "multiple",
                ));
            }
        }

        detections
    }

    async fn analyze_enterprise_attack_patterns(
        &self,
        proc: &ProcessEvent,
        path_lower: &str,
        cmdline_lower: &str,
        sensitivity: f32,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();
        let name_lower = proc.name.to_lowercase();
        let image_or_cmd = format!("{} {}", name_lower, cmdline_lower);

        if Self::contains_any(
            &image_or_cmd,
            &["get-process lsass", "process lsass", "lsass.exe"],
        ) && Self::contains_any(&image_or_cmd, &["powershell", "pwsh", "wmic", "tasklist"])
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "lsass_credential_access_probe",
                    18.0 * sensitivity,
                    "Credential access probe targeting LSASS metadata",
                    "credential-access",
                    "T1003.001",
                )
                .await,
            );
        }

        if Self::contains_any(
            &image_or_cmd,
            &[
                "cmdkey.exe /list",
                "login data",
                "tamandua-credential-canary",
                "findstr /i password",
            ],
        ) {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "credential_material_discovery",
                    16.0 * sensitivity,
                    "Credential material discovery or credential-store probing",
                    "credential-access",
                    "T1552.001",
                )
                .await,
            );
        }

        if name_lower == "wmic.exe"
            || cmdline_lower.contains("wmic.exe")
            || cmdline_lower.contains("winrm ")
            || cmdline_lower.contains("invoke-command")
            || cmdline_lower.contains("test-wsman")
            || cmdline_lower.contains("psremoting")
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "remote_management_wmi_winrm",
                    18.0 * sensitivity,
                    "Remote management tooling observed via WMI, WinRM, or PowerShell remoting",
                    "lateral-movement",
                    "T1021.006",
                )
                .await,
            );
        }

        if Self::contains_any(&image_or_cmd, &["net use", "net share", "admin$", "c$"]) {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "lateral_smb_admin_share_probe",
                    12.0 * sensitivity,
                    "SMB admin-share or network-share discovery",
                    "lateral-movement",
                    "T1021.002",
                )
                .await,
            );
        }

        if Self::contains_any(&image_or_cmd, &["schtasks.exe /create", "schtasks /create"]) {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "scheduled_task_privilege_persistence",
                    20.0 * sensitivity,
                    "Scheduled task creation can provide persistence or privilege escalation",
                    "persistence",
                    "T1053.005",
                )
                .await,
            );
        }

        if Self::contains_any(&image_or_cmd, &["sc.exe create", "sc create"]) {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "service_creation_abuse",
                    22.0 * sensitivity,
                    "Windows service creation observed",
                    "persistence",
                    "T1543.003",
                )
                .await,
            );
        }

        if cmdline_lower.contains("enablelua")
            || cmdline_lower.contains("\\policies\\system")
            || cmdline_lower.contains("uac")
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "privilege_escalation_configuration_probe",
                    10.0 * sensitivity,
                    "Privilege escalation relevant configuration was queried",
                    "privilege-escalation",
                    "T1548.002",
                )
                .await,
            );
        }

        if Self::contains_any(
            &image_or_cmd,
            &["curl.exe", "invoke-webrequest", "downloadfile"],
        ) && Self::contains_any(
            &image_or_cmd,
            &[" -o ", " -out", "download", "http://", "https://"],
        ) {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "c2_download_transfer",
                    18.0 * sensitivity,
                    "HTTP transfer pattern consistent with ingress tool transfer or C2 staging",
                    "command-and-control",
                    "T1105",
                )
                .await,
            );
        }

        if Self::contains_any(&image_or_cmd, &["curl.exe -i", "test-netconnection"])
            || (cmdline_lower.matches("curl.exe").count() >= 2 && cmdline_lower.contains("timeout"))
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "c2_beacon_safe_probe",
                    14.0 * sensitivity,
                    "Repeated network probe can indicate beacon-like command-and-control behavior",
                    "command-and-control",
                    "T1071.001",
                )
                .await,
            );
        }

        if Self::contains_any(
            &image_or_cmd,
            &["tar.exe", "makecab.exe", "compress-archive"],
        ) && Self::contains_any(&image_or_cmd, &[".zip", ".cab", ".tar"])
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "archive_staging",
                    14.0 * sensitivity,
                    "Data archive staging observed",
                    "collection",
                    "T1560.001",
                )
                .await,
            );
        }

        if Self::contains_any(&image_or_cmd, &["exfil", "exfil-canary"])
            || (Self::contains_any(&image_or_cmd, &["curl.exe", "invoke-webrequest"])
                && Self::contains_any(&image_or_cmd, &[".zip", "archive", "staged", "canary"]))
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "exfiltration_staging",
                    18.0 * sensitivity,
                    "Local staging followed by network transfer pattern",
                    "exfiltration",
                    "T1041",
                )
                .await,
            );
        }

        if Self::contains_any(&image_or_cmd, &["version.dll", "dll-canary"])
            || (path_lower.contains("\\temp\\") && name_lower.ends_with(".dll"))
        {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "dll_hijack_canary",
                    18.0 * sensitivity,
                    "DLL search order hijack or side-loading canary observed",
                    "defense-evasion",
                    "T1574.001",
                )
                .await,
            );
        }

        if Self::contains_any(
            &image_or_cmd,
            &["regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe"],
        ) {
            let (rule, technique, desc) = if image_or_cmd.contains("regsvr32.exe") {
                (
                    "regsvr32_proxy_execution",
                    "T1218.010",
                    "Regsvr32 signed binary proxy execution",
                )
            } else if image_or_cmd.contains("rundll32.exe") {
                (
                    "rundll32_proxy_execution",
                    "T1218.011",
                    "Rundll32 signed binary proxy execution",
                )
            } else if image_or_cmd.contains("mshta.exe") {
                (
                    "mshta_proxy_execution",
                    "T1218.005",
                    "Mshta signed binary proxy execution",
                )
            } else {
                (
                    "certutil_decode_or_transfer",
                    "T1140",
                    "Certutil encode/decode or transfer behavior",
                )
            };

            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    rule,
                    18.0 * sensitivity,
                    desc,
                    "defense-evasion",
                    technique,
                )
                .await,
            );
        }

        if Self::contains_any(
            &image_or_cmd,
            &[
                "get-mppreference",
                "set-mppreference",
                "vssadmin.exe",
                "delete shadows",
            ],
        ) {
            detections.push(
                self.enterprise_detection(
                    &proc.name,
                    "tamper_defense_evasion_probe",
                    18.0 * sensitivity,
                    "Security-tool or recovery configuration probe observed",
                    "defense-evasion",
                    "T1562.001",
                )
                .await,
            );
        }

        detections
    }

    /// Analyze network behavior for anomalies
    async fn analyze_network_behavior(
        &self,
        net: &NetworkEvent,
        _timestamp: u64,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();
        let sensitivity = self.config.sensitivity;
        let destination = format!("{}:{}", net.remote_ip, net.remote_port);

        // Check for rare destination
        let baseline = self.baseline.read().await;
        if baseline.is_rare_destination(&destination) {
            let desc = format!(
                "Process '{}' connected to rare destination: {}",
                net.process_name, destination
            );
            self.add_risk(
                &net.process_name,
                "rare_destination",
                10.0 * sensitivity,
                &desc,
            )
            .await;
            detections.push(self.create_detection(
                "rare_network_destination",
                0.5,
                &desc,
                "command-and-control",
                "T1071",
            ));
        }

        // Check baseline deviation for process
        if let Some(pb) = baseline
            .process_baselines
            .get(&net.process_name.to_lowercase())
        {
            if pb.observation_count >= 50 {
                // Check if this destination is new for this process
                if !pb
                    .known_network_destinations
                    .contains(&destination.to_lowercase())
                {
                    let desc = format!(
                        "Process '{}' connected to new destination: {} (not in baseline)",
                        net.process_name, destination
                    );
                    self.add_risk(
                        &net.process_name,
                        "new_destination",
                        8.0 * sensitivity,
                        &desc,
                    )
                    .await;
                    detections.push(self.create_detection(
                        "baseline_deviation_network",
                        0.5,
                        &desc,
                        "command-and-control",
                        "T1071",
                    ));
                }

                // Check for connection rate anomaly
                let current_rate = pb.network_rate_stats.count() as f64;
                let zscore = pb.network_rate_stats.zscore(current_rate);
                if zscore.abs() > self.config.zscore_threshold {
                    let desc = format!(
                        "Process '{}' network activity anomaly: z-score {:.2}",
                        net.process_name, zscore
                    );
                    self.add_risk(
                        &net.process_name,
                        "network_rate_anomaly",
                        12.0 * sensitivity,
                        &desc,
                    )
                    .await;
                    detections.push(self.create_detection(
                        "network_rate_anomaly",
                        0.6,
                        &desc,
                        "command-and-control",
                        "T1071",
                    ));
                }
            }
        }

        // Check for suspicious processes making network connections
        let proc_lower = net.process_name.to_lowercase();
        for pattern in SUSPICIOUS_PATTERNS {
            if pattern.name == "rundll32_network" && proc_lower.contains("rundll32") {
                self.add_risk(
                    &net.process_name,
                    pattern.name,
                    pattern.score * sensitivity,
                    pattern.description,
                )
                .await;
                detections.push(self.create_detection(
                    pattern.name,
                    0.6,
                    pattern.description,
                    pattern.mitre_tactic,
                    pattern.mitre_technique,
                ));
            }
            if pattern.name == "regsvr32_network" && proc_lower.contains("regsvr32") {
                self.add_risk(
                    &net.process_name,
                    pattern.name,
                    pattern.score * sensitivity,
                    pattern.description,
                )
                .await;
                detections.push(self.create_detection(
                    pattern.name,
                    0.7,
                    pattern.description,
                    pattern.mitre_tactic,
                    pattern.mitre_technique,
                ));
            }
        }

        detections
    }

    /// Analyze file behavior for anomalies (ransomware detection)
    async fn analyze_file_behavior(&self, file: &FileEvent, timestamp: u64) -> Vec<Detection> {
        let mut detections = Vec::new();
        let sensitivity = self.config.sensitivity;

        // Track potential encryption patterns
        {
            let mut patterns = self.encryption_patterns.write().await;
            let pattern = patterns.entry(file.pid).or_insert_with(|| {
                let mut p = EncryptionPattern::default();
                p.window_start = timestamp;
                p
            });

            // Reset window if too old (5 minute window)
            if timestamp - pattern.window_start > 300000 {
                *pattern = EncryptionPattern::default();
                pattern.window_start = timestamp;
            }

            // Track modifications
            if file.operation == "modify" || file.operation == "write" {
                pattern.file_mod_count += 1;

                // Track extension changes
                if let Some(ext) = Path::new(&file.path).extension() {
                    pattern
                        .extension_changes
                        .insert(ext.to_string_lossy().to_string());
                }

                // Track high entropy files
                if file.entropy > 7.5 {
                    pattern.high_entropy_count += 1;
                }

                // Check for ransomware-like behavior
                // Rapid file modifications + high entropy + multiple extension changes
                if pattern.file_mod_count > 20
                    && pattern.high_entropy_count > 10
                    && pattern.extension_changes.len() > 3
                {
                    let desc = format!(
                        "Potential ransomware: {} modified {} files, {} high-entropy, {} extension changes",
                        file.process_name,
                        pattern.file_mod_count,
                        pattern.high_entropy_count,
                        pattern.extension_changes.len()
                    );
                    self.add_risk(
                        &file.process_name,
                        "ransomware_behavior",
                        40.0 * sensitivity,
                        &desc,
                    )
                    .await;
                    detections.push(Detection {
                        detection_type: DetectionType::Ransomware,
                        rule_name: "mass_file_encryption".to_string(),
                        confidence: 0.9,
                        description: desc,
                        mitre_tactics: vec!["impact".to_string()],
                        mitre_techniques: vec!["T1486".to_string()],
                    });
                }
            }
        }

        // Check baseline deviation for file paths
        let baseline = self.baseline.read().await;
        if let Some(pb) = baseline
            .process_baselines
            .get(&file.process_name.to_lowercase())
        {
            if pb.observation_count >= 50 {
                // Check if accessing unusual directory
                if let Some(parent) = Path::new(&file.path).parent() {
                    let parent_str = parent.to_string_lossy().to_lowercase();
                    let known = pb
                        .known_file_patterns
                        .iter()
                        .any(|p| parent_str.starts_with(p));
                    if !known {
                        let desc = format!(
                            "Process '{}' accessing unusual path: {}",
                            file.process_name, file.path
                        );
                        self.add_risk(
                            &file.process_name,
                            "unusual_file_access",
                            8.0 * sensitivity,
                            &desc,
                        )
                        .await;
                        detections.push(self.create_detection(
                            "baseline_deviation_file",
                            0.5,
                            &desc,
                            "collection",
                            "T1005",
                        ));
                    }
                }

                // Check file operation rate anomaly
                let current_rate = pb.file_rate_stats.count() as f64;
                let zscore = pb.file_rate_stats.zscore(current_rate);
                if zscore > self.config.zscore_threshold {
                    let desc = format!(
                        "Process '{}' file operation rate anomaly: z-score {:.2}",
                        file.process_name, zscore
                    );
                    self.add_risk(
                        &file.process_name,
                        "file_rate_anomaly",
                        15.0 * sensitivity,
                        &desc,
                    )
                    .await;
                    detections.push(self.create_detection(
                        "file_rate_anomaly",
                        0.7,
                        &desc,
                        "impact",
                        "T1486",
                    ));
                }
            }
        }

        detections
    }

    /// Analyze registry behavior for anomalies
    async fn analyze_registry_behavior(
        &self,
        reg: &RegistryEvent,
        _timestamp: u64,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();
        let sensitivity = self.config.sensitivity;
        let key_lower = reg.key_path.to_lowercase();

        // Check for persistence mechanisms
        let persistence_keys = [
            "software\\microsoft\\windows\\currentversion\\run",
            "software\\microsoft\\windows\\currentversion\\runonce",
            "software\\microsoft\\windows nt\\currentversion\\winlogon",
            "system\\currentcontrolset\\services",
            "software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
        ];

        for pk in persistence_keys {
            if key_lower.contains(pk) {
                let desc = format!(
                    "Process '{}' modifying persistence key: {}",
                    reg.process_name, reg.key_path
                );
                self.add_risk(
                    &reg.process_name,
                    "persistence_registry",
                    20.0 * sensitivity,
                    &desc,
                )
                .await;
                detections.push(self.create_detection(
                    "persistence_registry",
                    0.7,
                    &desc,
                    "persistence",
                    "T1547.001",
                ));
                break;
            }
        }

        // Check for security-related registry modifications
        let security_keys = [
            "software\\microsoft\\windows defender",
            "software\\policies\\microsoft\\windows defender",
            "system\\currentcontrolset\\services\\winsock",
            "software\\microsoft\\windows\\currentversion\\policies\\system",
        ];

        for sk in security_keys {
            if key_lower.contains(sk) {
                let desc = format!(
                    "Process '{}' modifying security-related key: {}",
                    reg.process_name, reg.key_path
                );
                self.add_risk(
                    &reg.process_name,
                    "security_registry",
                    25.0 * sensitivity,
                    &desc,
                )
                .await;
                detections.push(self.create_detection(
                    "security_registry_modification",
                    0.8,
                    &desc,
                    "defense-evasion",
                    "T1562.001",
                ));
                break;
            }
        }

        // Check baseline deviation
        let baseline = self.baseline.read().await;
        if let Some(pb) = baseline
            .process_baselines
            .get(&reg.process_name.to_lowercase())
        {
            if pb.observation_count >= 50 {
                let known = pb
                    .known_registry_patterns
                    .iter()
                    .any(|p| key_lower.starts_with(p));
                if !known {
                    let desc = format!(
                        "Process '{}' accessing unusual registry key: {}",
                        reg.process_name, reg.key_path
                    );
                    self.add_risk(
                        &reg.process_name,
                        "unusual_registry",
                        10.0 * sensitivity,
                        &desc,
                    )
                    .await;
                    detections.push(self.create_detection(
                        "baseline_deviation_registry",
                        0.5,
                        &desc,
                        "defense-evasion",
                        "T1112",
                    ));
                }
            }
        }

        detections
    }

    /// Analyze DNS behavior for anomalies
    async fn analyze_dns_behavior(&self, dns: &DnsEvent, _timestamp: u64) -> Vec<Detection> {
        let mut detections = Vec::new();
        let sensitivity = self.config.sensitivity;
        let query_lower = dns.query.to_lowercase();

        // Check for DGA-like domains (high entropy, long random-looking names)
        let entropy = self.calculate_string_entropy(&query_lower);
        if entropy > 4.0 && query_lower.len() > 15 {
            // Check for consonant clusters (common in DGA)
            let consonant_ratio = self.consonant_ratio(&query_lower);
            if consonant_ratio > 0.7 {
                let desc = format!(
                    "Potential DGA domain queried by '{}': {} (entropy: {:.2})",
                    dns.process_name, dns.query, entropy
                );
                self.add_risk(&dns.process_name, "dga_domain", 15.0 * sensitivity, &desc)
                    .await;
                detections.push(self.create_detection(
                    "potential_dga_domain",
                    0.7,
                    &desc,
                    "command-and-control",
                    "T1568.002",
                ));
            }
        }

        // Check for suspicious TLDs
        let suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".work", ".click",
        ];
        for tld in suspicious_tlds {
            if query_lower.ends_with(tld) {
                let desc = format!(
                    "Query to suspicious TLD by '{}': {}",
                    dns.process_name, dns.query
                );
                self.add_risk(
                    &dns.process_name,
                    "suspicious_tld",
                    8.0 * sensitivity,
                    &desc,
                )
                .await;
                detections.push(self.create_detection(
                    "suspicious_tld",
                    0.5,
                    &desc,
                    "command-and-control",
                    "T1071.004",
                ));
                break;
            }
        }

        detections
    }

    /// Add risk to a process
    async fn add_risk(&self, process: &str, factor: &str, score: f32, description: &str) {
        let mut scores = self.risk_scores.write().await;
        let key = process.to_lowercase();
        let risk_score = scores
            .entry(key.clone())
            .or_insert_with(|| RiskScore::new(&key));
        risk_score.add_factor(factor, score, description);
        debug!(process = %process, factor = %factor, score = score, total = risk_score.score, "Risk added");
    }

    fn confidence_from_pattern_score(score: f32) -> f32 {
        (0.45 + (score / 100.0)).clamp(0.45, 0.9)
    }

    fn is_lsass_masquerade(proc: &ProcessEvent, parent_lower: &str, child_lower: &str) -> bool {
        if !child_lower.contains("lsass") {
            return false;
        }

        let path_lower = proc.path.to_lowercase();
        let legitimate_lsass = child_lower == "lsass.exe"
            && parent_lower.contains("wininit.exe")
            && path_lower.ends_with("\\windows\\system32\\lsass.exe");

        !legitimate_lsass
    }

    fn risk_score_has_actionable_signal(score: &RiskScore, alert_threshold: f32) -> bool {
        let strong_signal_factors = [
            "browser_process_spawn",
            "encoded_command",
            "lsass_masquerade",
            "office_shell_spawn",
            "policy_bypass",
            "ransomware_behavior",
            "regsvr32_network",
            "rundll32_network",
            "svchost_unusual_parent",
            "temp_execution",
            "wmiprvse_spawn",
        ];

        if score
            .factors
            .iter()
            .any(|factor| strong_signal_factors.contains(&factor.name.as_str()))
        {
            return true;
        }

        let contextual_signal_factors = [
            "baseline_deviation_child",
            "file_rate_anomaly",
            "network_rate_anomaly",
            "new_destination",
            "rare_destination",
        ];
        let mut contextual_seen = std::collections::HashSet::new();
        for factor in &score.factors {
            if contextual_signal_factors.contains(&factor.name.as_str()) {
                contextual_seen.insert(factor.name.as_str());
            }
        }

        let non_temporal_score: f32 = score
            .factors
            .iter()
            .filter(|factor| factor.name != "unusual_time")
            .map(|factor| factor.score)
            .sum();

        contextual_seen.len() >= 2 && non_temporal_score >= alert_threshold * 0.5
    }

    /// Create a behavioral detection
    fn create_detection(
        &self,
        rule_name: &str,
        confidence: f32,
        description: &str,
        tactic: &str,
        technique: &str,
    ) -> Detection {
        Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("behavioral_{}", rule_name),
            confidence,
            description: description.to_string(),
            mitre_tactics: vec![tactic.to_string()],
            mitre_techniques: vec![technique.to_string()],
        }
    }

    async fn enterprise_detection(
        &self,
        process: &str,
        rule_name: &str,
        score: f32,
        description: &str,
        tactic: &str,
        technique: &str,
    ) -> Detection {
        self.add_risk(process, rule_name, score, description).await;
        self.create_detection(
            rule_name,
            Self::confidence_from_pattern_score(score),
            description,
            tactic,
            technique,
        )
    }

    fn contains_any(haystack: &str, needles: &[&str]) -> bool {
        needles.iter().any(|needle| haystack.contains(needle))
    }

    /// Calculate Shannon entropy of a string
    fn calculate_string_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0u64) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &count in freq.values() {
            let p = count as f64 / len;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Calculate ratio of consonants in a string
    fn consonant_ratio(&self, s: &str) -> f64 {
        let consonants = "bcdfghjklmnpqrstvwxz";
        let vowels = "aeiou";

        let mut consonant_count = 0;
        let mut letter_count = 0;

        for c in s.chars() {
            if consonants.contains(c) {
                consonant_count += 1;
                letter_count += 1;
            } else if vowels.contains(c) {
                letter_count += 1;
            }
        }

        if letter_count == 0 {
            return 0.0;
        }
        consonant_count as f64 / letter_count as f64
    }

    /// Get current risk score for a process
    pub async fn get_risk_score(&self, process: &str) -> Option<f32> {
        let scores = self.risk_scores.read().await;
        scores.get(&process.to_lowercase()).map(|s| s.score)
    }

    /// Get all risk scores
    pub async fn get_all_risk_scores(&self) -> HashMap<String, f32> {
        let scores = self.risk_scores.read().await;
        scores.iter().map(|(k, v)| (k.clone(), v.score)).collect()
    }

    /// Export the current deterministic risk scores as telemetry events.
    ///
    /// Returns an empty vector unless the runtime `export_risk_score` flag is
    /// set on the [`BehavioralConfig`]. Each returned [`TelemetryEvent`] carries
    /// a [`RiskScoreSnapshot`] payload so a downstream consumer can pair a
    /// telemetry stream with the deterministic score (the prerequisite for the
    /// behavioral-sequence ML path). This is read-only: it never mutates scores
    /// and never short-circuits or alters existing detection behavior.
    #[cfg(feature = "export_risk_score")]
    pub async fn export_risk_score_events(&self) -> Vec<TelemetryEvent> {
        if !self.config.export_risk_score {
            return Vec::new();
        }

        // Resolve a best-effort PID for pairing: risk scores are keyed by
        // process name, so map back through the latest known name->PID pair.
        let names = self.process_names.read().await;
        let mut latest_pid_for_name: HashMap<String, u32> = HashMap::new();
        for (pid, name) in names.iter() {
            latest_pid_for_name.insert(name.to_lowercase(), *pid);
        }
        drop(names);

        let scores = self.risk_scores.read().await;
        scores
            .values()
            .map(|score| {
                let pid = latest_pid_for_name.get(&score.process_key).copied();
                let snapshot = score.snapshot(pid);
                TelemetryEvent::new(
                    crate::collectors::EventType::BehavioralRiskScore,
                    crate::collectors::Severity::Info,
                    EventPayload::BehavioralRiskScore(snapshot),
                )
            })
            .collect()
    }

    /// Get detailed risk factors for a process
    pub async fn get_risk_factors(&self, process: &str) -> Vec<RiskFactor> {
        let scores = self.risk_scores.read().await;
        scores
            .get(&process.to_lowercase())
            .map(|s| s.factors.clone())
            .unwrap_or_default()
    }

    /// Get baseline statistics
    pub async fn get_baseline_stats(&self) -> BaselineStats {
        let baseline = self.baseline.read().await;
        BaselineStats {
            process_count: baseline.process_baselines.len(),
            network_destinations: baseline.global_network_destinations.len(),
            learning_complete: baseline.learning_complete,
            learning_start: baseline.learning_start_time,
        }
    }

    /// Force save baseline
    pub async fn save_baseline(&self) -> Result<()> {
        let baseline = self.baseline.read().await;
        baseline.save_to_file(&self.config.baseline_path)
    }

    /// Reset baselines (start fresh learning)
    pub async fn reset_baselines(&self) {
        let mut baseline = self.baseline.write().await;
        *baseline = SystemBaseline::default();
        info!("Baselines reset, starting fresh learning period");
    }

    /// Export baselines as JSON
    pub async fn export_baselines(&self) -> Result<String> {
        let baseline = self.baseline.read().await;
        Ok(serde_json::to_string_pretty(&*baseline)?)
    }

    /// Import baselines from JSON
    pub async fn import_baselines(&self, json: &str) -> Result<()> {
        let imported: SystemBaseline = serde_json::from_str(json)?;
        let mut baseline = self.baseline.write().await;
        *baseline = imported;
        info!("Baselines imported successfully");
        Ok(())
    }
}

/// Baseline statistics
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub process_count: usize,
    pub network_destinations: usize,
    pub learning_complete: bool,
    pub learning_start: u64,
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new(BehavioralConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_stats() {
        let mut stats = RollingStats::new(10);

        // Add some values
        for i in 0..10 {
            stats.add(i as f64, i as u64 * 1000);
        }

        assert_eq!(stats.count(), 10);
        assert!((stats.mean() - 4.5).abs() < 0.001);
        assert!(stats.std_dev() > 0.0);
    }

    #[test]
    fn test_rolling_stats_zscore() {
        let mut stats = RollingStats::new(100);

        // Add normal distribution-like values
        for i in 0..100 {
            stats.add(50.0 + (i % 10) as f64 - 5.0, i as u64 * 1000);
        }

        // Value close to mean should have low z-score
        assert!(stats.zscore(50.0).abs() < 1.0);

        // Value far from mean should have high z-score
        assert!(stats.zscore(100.0).abs() > 2.0);
    }

    #[test]
    fn test_hourly_pattern() {
        let mut pattern = HourlyPattern::default();

        // Simulate work hours activity
        for _ in 0..100 {
            for hour in 9..17 {
                pattern.record(hour);
            }
        }

        // Work hours should have higher rate
        assert!(pattern.expected_rate(12) > pattern.expected_rate(3));

        // Night hours should be low activity
        assert!(pattern.is_low_activity_period(3));
    }

    #[test]
    fn test_process_baseline() {
        let mut baseline = ProcessBaseline::new("test.exe");

        let proc = ProcessEvent {
            pid: 1234,
            ppid: 100,
            name: "test.exe".to_string(),
            path: "C:\\test\\test.exe".to_string(),
            cmdline: "test.exe --flag".to_string(),
            user: "user".to_string(),
            sha256: vec![],
            entropy: 0.0,
            is_elevated: false,
            parent_name: Some("explorer.exe".to_string()),
            parent_path: Some("C:\\Windows\\explorer.exe".to_string()),
            is_signed: true,
            signer: Some("Microsoft".to_string()),
            start_time: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        };

        baseline.update_from_process(&proc, 1000000);

        assert!(baseline.known_parents.contains("explorer.exe"));
        assert_eq!(baseline.observation_count, 1);
    }

    #[test]
    fn test_risk_score_decay() {
        let mut score = RiskScore::new("test.exe");
        score.add_factor("test", 50.0, "test factor");

        // Simulate time passing (force last_update to be old)
        score.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            - 3600000; // 1 hour ago

        score.apply_decay(10.0);

        // Score should have decayed
        assert!(score.score < 50.0);
    }

    #[test]
    fn test_lsass_process_tree_does_not_flag_legitimate_lsass() {
        let proc = ProcessEvent {
            pid: 500,
            ppid: 100,
            name: "lsass.exe".to_string(),
            path: "C:\\Windows\\System32\\lsass.exe".to_string(),
            cmdline: "C:\\Windows\\System32\\lsass.exe".to_string(),
            user: "SYSTEM".to_string(),
            sha256: vec![],
            entropy: 0.0,
            is_elevated: true,
            parent_name: Some("wininit.exe".to_string()),
            parent_path: Some("C:\\Windows\\System32\\wininit.exe".to_string()),
            is_signed: true,
            signer: Some("Microsoft Windows".to_string()),
            start_time: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            environment: None,
        };

        assert!(!BehavioralAnalyzer::is_lsass_masquerade(
            &proc,
            "wininit.exe",
            "lsass.exe"
        ));
    }

    #[test]
    fn test_lsass_masquerade_flags_non_system_lsass() {
        let proc = ProcessEvent {
            pid: 500,
            ppid: 100,
            name: "lsass.exe".to_string(),
            path: "C:\\Users\\Public\\lsass.exe".to_string(),
            cmdline: "C:\\Users\\Public\\lsass.exe".to_string(),
            user: "user".to_string(),
            sha256: vec![],
            entropy: 0.0,
            is_elevated: false,
            parent_name: Some("explorer.exe".to_string()),
            parent_path: Some("C:\\Windows\\explorer.exe".to_string()),
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
        };

        assert!(BehavioralAnalyzer::is_lsass_masquerade(
            &proc,
            "explorer.exe",
            "lsass.exe"
        ));
    }

    #[test]
    fn test_unusual_time_alone_does_not_create_high_risk_score() {
        let mut score = RiskScore::new("pwsh.exe");
        for _ in 0..20 {
            score.add_factor("unusual_time", 5.0, "night execution");
        }

        assert!(!BehavioralAnalyzer::risk_score_has_actionable_signal(
            &score, 75.0
        ));

        score.add_factor("encoded_command", 20.0, "encoded PowerShell");
        assert!(BehavioralAnalyzer::risk_score_has_actionable_signal(
            &score, 75.0
        ));
    }

    #[test]
    fn test_repeated_rare_destination_alone_does_not_create_high_risk_score() {
        let mut score = RiskScore::new("sshd");
        for _ in 0..10 {
            score.add_factor("rare_destination", 10.0, "rare destination");
            score.add_factor("unusual_time", 5.0, "unusual hour");
        }

        assert!(!BehavioralAnalyzer::risk_score_has_actionable_signal(
            &score, 75.0
        ));

        score.add_factor("new_destination", 10.0, "new destination");
        assert!(BehavioralAnalyzer::risk_score_has_actionable_signal(
            &score, 75.0
        ));
    }

    #[tokio::test]
    async fn test_string_entropy() {
        let analyzer = BehavioralAnalyzer::default();

        // Random string should have high entropy
        let random_entropy = analyzer.calculate_string_entropy("xkcd7nq9mzplwo");
        assert!(random_entropy > 3.5);

        // Repeated string should have low entropy
        let repeated_entropy = analyzer.calculate_string_entropy("aaaaaaaaaa");
        assert!(repeated_entropy < 0.1);

        // Normal domain should have medium entropy
        let normal_entropy = analyzer.calculate_string_entropy("google.com");
        assert!(normal_entropy > 2.0 && normal_entropy < 3.5);
    }

    #[tokio::test]
    async fn test_consonant_ratio() {
        let analyzer = BehavioralAnalyzer::default();

        // DGA-like string (many consonants)
        let dga_ratio = analyzer.consonant_ratio("xkcdnqmzplw");
        assert!(dga_ratio > 0.8);

        // Normal word
        let normal_ratio = analyzer.consonant_ratio("hello");
        assert!(normal_ratio < 0.7);
    }

    #[tokio::test]
    async fn test_behavioral_analyzer_learning_mode() {
        let config = BehavioralConfig {
            learning_duration_hours: 0, // Immediate
            ..Default::default()
        };
        let analyzer = BehavioralAnalyzer::new(config);

        // Should not be in learning mode with 0 hours
        // (Actually will be for a tiny bit, but complete_learning can be called)
        analyzer.complete_learning().await;
        assert!(!analyzer.is_learning().await);
    }
}

#[cfg(all(test, feature = "export_risk_score"))]
mod export_risk_score_tests {
    use super::*;

    #[tokio::test]
    async fn test_export_risk_score_disabled_by_default() {
        // Default config has export_risk_score = false
        let analyzer = BehavioralAnalyzer::default();
        let events = analyzer.export_risk_score_events().await;
        assert!(
            events.is_empty(),
            "Should emit nothing when runtime flag is off"
        );
    }

    #[tokio::test]
    async fn test_export_risk_score_enabled_emits_snapshots() {
        let mut config = BehavioralConfig::default();
        config.export_risk_score = true;
        let analyzer = BehavioralAnalyzer::new(config);

        // Seed a risk score so there's something to export
        {
            let mut scores = analyzer.risk_scores.write().await;
            let mut rs = RiskScore::new("testproc".to_string());
            rs.score = 50.0;
            scores.insert("testproc".to_string(), rs);
        }

        let events = analyzer.export_risk_score_events().await;
        assert!(
            !events.is_empty(),
            "Should emit snapshots when enabled + scores exist"
        );
        // Verify the payload type
        if let Some(event) = events.first() {
            match &event.payload {
                EventPayload::BehavioralRiskScore(snap) => {
                    assert_eq!(snap.process_key, "testproc");
                    assert!((snap.score - 50.0).abs() < 0.01);
                }
                _ => panic!("Expected BehavioralRiskScore payload"),
            }
        }
    }
}
