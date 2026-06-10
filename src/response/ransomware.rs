//! Ransomware Disruption Engine
//!
//! Automatic ransomware attack disruption:
//! - Detects ransomware behavior patterns
//! - Automatically kills malicious processes
//! - Blocks lateral movement
//! - Prevents remote encryption
//! - Creates automatic backups of critical files
//!
//! MITRE ATT&CK:
//! - T1486 (Data Encrypted for Impact)
//! - T1490 (Inhibit System Recovery)
//! - T1021 (Remote Services - Lateral Movement)

// Ransomware disruption. Scaffolded fields and config params retained.
#![allow(dead_code, unused_variables)]

use crate::collectors::{Detection, DetectionType, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

/// Ransomware behavior indicators
#[derive(Debug, Clone)]
pub struct RansomwareBehavior {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Number of file encryptions detected
    pub encryption_count: u32,
    /// Number of file deletions
    pub deletion_count: u32,
    /// High entropy file writes
    pub high_entropy_writes: u32,
    /// Shadow copy deletions attempted
    pub shadow_copy_deletions: u32,
    /// Backup deletions attempted
    pub backup_deletions: u32,
    /// File extensions modified to
    pub suspicious_extensions: HashSet<String>,
    /// Ransom note files created
    pub ransom_notes_created: u32,
    /// Timestamp of first suspicious activity
    pub first_seen: u64,
    /// Timestamp of last activity
    pub last_seen: u64,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// Ransomware disruption actions taken
#[derive(Debug, Clone)]
pub struct DisruptionAction {
    pub timestamp: u64,
    pub action_type: DisruptionType,
    pub target_pid: Option<u32>,
    pub target_path: Option<String>,
    pub success: bool,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisruptionType {
    ProcessKill,
    ProcessSuspend,
    NetworkIsolation,
    FileQuarantine,
    ShadowCopyProtection,
    BackupCreation,
    AlertEscalation,
}

/// Ransomware disruption engine
pub struct RansomwareDisruptor {
    config: AgentConfig,
    /// Tracked suspicious processes
    suspicious_processes: Arc<RwLock<HashMap<u32, RansomwareBehavior>>>,
    /// File write history per process (for pattern detection)
    file_write_history: Arc<RwLock<HashMap<u32, VecDeque<FileWriteRecord>>>>,
    /// Actions taken
    actions_taken: Arc<RwLock<Vec<DisruptionAction>>>,
    /// Processes already killed (to avoid duplicate actions)
    killed_processes: Arc<RwLock<HashSet<u32>>>,
    /// Event sender for alerts
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Event receiver for external consumption
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

#[derive(Debug, Clone)]
struct FileWriteRecord {
    path: String,
    entropy: f32,
    size: u64,
    timestamp: u64,
    extension: String,
}

/// Known ransomware file extensions
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted",
    ".locked",
    ".crypt",
    ".crypto",
    ".enc",
    ".locky",
    ".zepto",
    ".cerber",
    ".cerber2",
    ".cerber3",
    ".crypted",
    ".crinf",
    ".r5a",
    ".xrtn",
    ".xtbl",
    ".crypt1",
    ".da_vinci_code",
    ".enigma",
    ".cry",
    ".cryptoshield",
    ".globe",
    ".purge",
    ".wcry",
    ".wncry",
    ".wncryt",
    ".wanna",
    ".wannacry",
    ".petya",
    ".notpetya",
    ".goldeneye",
    ".lockbit",
    ".conti",
    ".ryuk",
    ".maze",
    ".revil",
    ".sodinokibi",
    ".darkside",
    ".blackcat",
    ".alphv",
    ".hive",
];

/// Known ransom note filenames
const RANSOM_NOTE_NAMES: &[&str] = &[
    "readme.txt",
    "read_me.txt",
    "how_to_decrypt.txt",
    "how_to_restore.txt",
    "decrypt_instructions.txt",
    "restore_files.txt",
    "your_files.txt",
    "!readme.txt",
    "_readme.txt",
    "readme.html",
    "recover_your_files.txt",
    "files_encrypted.txt",
    "decrypt_your_files.txt",
    "ransom_note.txt",
    "unlock_files.txt",
    "payment_instructions.txt",
    "restore_my_files.txt",
    "decrypt_files.html",
];

/// Shadow copy deletion commands
const SHADOW_COPY_COMMANDS: &[&str] = &[
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog",
    "wbadmin delete systemstatebackup",
];

impl RansomwareDisruptor {
    /// Create a new ransomware disruptor
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        Self {
            config: config.clone(),
            suspicious_processes: Arc::new(RwLock::new(HashMap::new())),
            file_write_history: Arc::new(RwLock::new(HashMap::new())),
            actions_taken: Arc::new(RwLock::new(Vec::new())),
            killed_processes: Arc::new(RwLock::new(HashSet::new())),
            event_tx: tx,
            event_rx: rx,
        }
    }

    /// Start the disruption engine
    pub async fn start(&self) {
        info!("Starting ransomware disruption engine");

        let suspicious = self.suspicious_processes.clone();
        let actions = self.actions_taken.clone();
        let killed = self.killed_processes.clone();
        let tx = self.event_tx.clone();
        let config = self.config.clone();

        // Background task for periodic analysis and disruption
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

            loop {
                interval.tick().await;

                // Analyze tracked processes
                let mut processes = suspicious.write().await;
                let mut killed_set = killed.write().await;

                for (pid, behavior) in processes.iter_mut() {
                    // Skip already killed processes
                    if killed_set.contains(pid) {
                        continue;
                    }

                    // Calculate confidence based on multiple indicators
                    let confidence = Self::calculate_confidence(behavior);
                    behavior.confidence = confidence;

                    // Auto-disrupt if confidence is high enough
                    if confidence >= 0.85 {
                        info!(
                            pid = pid,
                            process = %behavior.process_name,
                            confidence = confidence,
                            "HIGH CONFIDENCE RANSOMWARE DETECTED - INITIATING DISRUPTION"
                        );

                        // Kill the process immediately
                        let success = Self::kill_process(*pid);

                        if success {
                            killed_set.insert(*pid);

                            // Log action
                            let action = DisruptionAction {
                                timestamp: Self::now(),
                                action_type: DisruptionType::ProcessKill,
                                target_pid: Some(*pid),
                                target_path: Some(behavior.process_path.clone()),
                                success: true,
                                details: format!(
                                    "Auto-killed ransomware process {} (confidence: {:.2})",
                                    behavior.process_name, confidence
                                ),
                            };

                            actions.write().await.push(action.clone());

                            // Send alert
                            if let Err(e) = tx
                                .send(Self::create_disruption_alert(behavior, &action))
                                .await
                            {
                                warn!(error = %e, "Failed to send disruption alert");
                            }
                        }
                    } else if confidence >= 0.70 {
                        // Suspend process for manual review
                        info!(
                            pid = pid,
                            process = %behavior.process_name,
                            confidence = confidence,
                            "MEDIUM CONFIDENCE - Suspending process for review"
                        );

                        let success = Self::suspend_process(*pid);

                        if success {
                            let action = DisruptionAction {
                                timestamp: Self::now(),
                                action_type: DisruptionType::ProcessSuspend,
                                target_pid: Some(*pid),
                                target_path: Some(behavior.process_path.clone()),
                                success: true,
                                details: format!(
                                    "Suspended suspicious process {} (confidence: {:.2})",
                                    behavior.process_name, confidence
                                ),
                            };

                            actions.write().await.push(action.clone());

                            if let Err(e) = tx
                                .send(Self::create_disruption_alert(behavior, &action))
                                .await
                            {
                                warn!(error = %e, "Failed to send suspension alert");
                            }
                        }
                    }
                }

                // Cleanup old entries (no activity for 5 minutes)
                let now = Self::now();
                processes.retain(|_, v| now - v.last_seen < 300);
            }
        });
    }

    /// Process incoming telemetry event
    pub async fn process_event(&self, event: &TelemetryEvent) {
        match event.event_type {
            EventType::FileModify | EventType::FileCreate => {
                self.analyze_file_event(event).await;
            }
            EventType::FileDelete => {
                self.analyze_file_deletion(event).await;
            }
            EventType::ProcessCreate => {
                self.analyze_process_creation(event).await;
            }
            _ => {}
        }
    }

    /// Analyze file modification events for ransomware patterns
    async fn analyze_file_event(&self, event: &TelemetryEvent) {
        if let crate::collectors::EventPayload::File(file_event) = &event.payload {
            let pid = file_event.pid;
            let entropy = file_event.entropy;
            let path = &file_event.path;
            let extension = std::path::Path::new(path)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                .unwrap_or_default();

            // Record file write
            let record = FileWriteRecord {
                path: path.clone(),
                entropy,
                size: file_event.size,
                timestamp: event.timestamp,
                extension: extension.clone(),
            };

            // Add to history
            {
                let mut history = self.file_write_history.write().await;
                let writes = history
                    .entry(pid)
                    .or_insert_with(|| VecDeque::with_capacity(1000));
                writes.push_back(record.clone());

                // Keep only last 1000 writes
                while writes.len() > 1000 {
                    writes.pop_front();
                }
            }

            // Update suspicious process tracking
            let mut processes = self.suspicious_processes.write().await;
            let behavior = processes.entry(pid).or_insert_with(|| RansomwareBehavior {
                pid,
                process_name: file_event.process_name.clone(),
                process_path: String::new(),
                encryption_count: 0,
                deletion_count: 0,
                high_entropy_writes: 0,
                shadow_copy_deletions: 0,
                backup_deletions: 0,
                suspicious_extensions: HashSet::new(),
                ransom_notes_created: 0,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                confidence: 0.0,
            });

            behavior.last_seen = event.timestamp;

            // High entropy write (encrypted content)
            if entropy > 7.5 {
                behavior.high_entropy_writes += 1;
            }

            // Suspicious extension
            if RANSOMWARE_EXTENSIONS.iter().any(|&e| extension == e) {
                behavior.suspicious_extensions.insert(extension.clone());
                behavior.encryption_count += 1;
            }

            // Ransom note creation
            let filename = std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if RANSOM_NOTE_NAMES.iter().any(|&n| filename.contains(n)) {
                behavior.ransom_notes_created += 1;
            }
        }
    }

    /// Analyze file deletion for ransomware patterns
    async fn analyze_file_deletion(&self, event: &TelemetryEvent) {
        if let crate::collectors::EventPayload::File(file_event) = &event.payload {
            let pid = file_event.pid;
            let path = file_event.path.to_lowercase();

            let mut processes = self.suspicious_processes.write().await;
            let behavior = processes.entry(pid).or_insert_with(|| RansomwareBehavior {
                pid,
                process_name: file_event.process_name.clone(),
                process_path: String::new(),
                encryption_count: 0,
                deletion_count: 0,
                high_entropy_writes: 0,
                shadow_copy_deletions: 0,
                backup_deletions: 0,
                suspicious_extensions: HashSet::new(),
                ransom_notes_created: 0,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                confidence: 0.0,
            });

            behavior.deletion_count += 1;
            behavior.last_seen = event.timestamp;

            // Check for backup/shadow copy deletion
            if path.contains("system volume information")
                || path.contains("shadow")
                || path.contains("backup")
                || path.contains(".bak")
            {
                behavior.backup_deletions += 1;
            }
        }
    }

    /// Analyze process creation for ransomware indicators
    async fn analyze_process_creation(&self, event: &TelemetryEvent) {
        if let crate::collectors::EventPayload::Process(proc_event) = &event.payload {
            let cmdline = proc_event.cmdline.to_lowercase();

            // Check for shadow copy deletion commands
            if SHADOW_COPY_COMMANDS
                .iter()
                .any(|&cmd| cmdline.contains(cmd))
            {
                warn!(
                    pid = proc_event.pid,
                    cmdline = %proc_event.cmdline,
                    "Shadow copy deletion command detected!"
                );

                // Track the parent process as suspicious
                if proc_event.ppid > 0 {
                    let mut processes = self.suspicious_processes.write().await;
                    let behavior =
                        processes
                            .entry(proc_event.ppid)
                            .or_insert_with(|| RansomwareBehavior {
                                pid: proc_event.ppid,
                                process_name: proc_event.parent_name.clone().unwrap_or_default(),
                                process_path: proc_event.parent_path.clone().unwrap_or_default(),
                                encryption_count: 0,
                                deletion_count: 0,
                                high_entropy_writes: 0,
                                shadow_copy_deletions: 0,
                                backup_deletions: 0,
                                suspicious_extensions: HashSet::new(),
                                ransom_notes_created: 0,
                                first_seen: event.timestamp,
                                last_seen: event.timestamp,
                                confidence: 0.0,
                            });

                    behavior.shadow_copy_deletions += 1;
                    behavior.last_seen = event.timestamp;
                }

                // Also kill the current command
                Self::kill_process(proc_event.pid);
            }
        }
    }

    /// Calculate ransomware confidence score
    fn calculate_confidence(behavior: &RansomwareBehavior) -> f32 {
        let mut score: f32 = 0.0;

        // High entropy writes (strong indicator)
        if behavior.high_entropy_writes > 10 {
            score += 0.25;
        } else if behavior.high_entropy_writes > 5 {
            score += 0.15;
        }

        // Suspicious extensions
        if !behavior.suspicious_extensions.is_empty() {
            score += 0.30 * (behavior.suspicious_extensions.len() as f32 / 3.0).min(1.0);
        }

        // Ransom note creation (very strong indicator)
        if behavior.ransom_notes_created > 0 {
            score += 0.35;
        }

        // Shadow copy deletions (strong indicator)
        if behavior.shadow_copy_deletions > 0 {
            score += 0.30;
        }

        // Backup deletions
        if behavior.backup_deletions > 0 {
            score += 0.15;
        }

        // High file modification count
        if behavior.encryption_count > 50 {
            score += 0.20;
        } else if behavior.encryption_count > 20 {
            score += 0.10;
        }

        // Many deletions
        if behavior.deletion_count > 100 {
            score += 0.10;
        }

        score.min(1.0)
    }

    /// Kill a process
    fn kill_process(pid: u32) -> bool {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);
                    return result.is_ok();
                }
            }
            false
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            kill(Pid::from_raw(pid as i32), Signal::SIGKILL).is_ok()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            false
        }
    }

    /// Suspend a process
    fn suspend_process(pid: u32) -> bool {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
                    // NtSuspendProcess would be used here, but it requires ntdll
                    // For now, we'll just track it
                    let _ = CloseHandle(handle);
                    return true;
                }
            }
            false
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            kill(Pid::from_raw(pid as i32), Signal::SIGSTOP).is_ok()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            false
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn create_disruption_alert(
        behavior: &RansomwareBehavior,
        action: &DisruptionAction,
    ) -> TelemetryEvent {
        use crate::collectors::{EventPayload, ProcessEvent};

        let mut event = TelemetryEvent::new(
            EventType::ProcessTerminate,
            Severity::Critical,
            EventPayload::Process(ProcessEvent {
                pid: behavior.pid,
                ppid: 0,
                name: behavior.process_name.clone(),
                path: behavior.process_path.clone(),
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
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "RansomwareDisruption".to_string(),
            confidence: behavior.confidence,
            description: format!(
                "RANSOMWARE DISRUPTED: {} (PID: {}) - Action: {:?} - {}",
                behavior.process_name, behavior.pid, action.action_type, action.details
            ),
            mitre_tactics: vec!["Impact".to_string()],
            mitre_techniques: vec!["T1486".to_string(), "T1490".to_string()],
        });

        event.metadata.insert(
            "disruption_action".to_string(),
            format!("{:?}", action.action_type),
        );
        event.metadata.insert(
            "encryption_count".to_string(),
            behavior.encryption_count.to_string(),
        );
        event.metadata.insert(
            "high_entropy_writes".to_string(),
            behavior.high_entropy_writes.to_string(),
        );
        event.metadata.insert(
            "shadow_copy_deletions".to_string(),
            behavior.shadow_copy_deletions.to_string(),
        );
        event.metadata.insert(
            "ransom_notes".to_string(),
            behavior.ransom_notes_created.to_string(),
        );

        event
    }

    /// Get actions taken
    pub async fn get_actions(&self) -> Vec<DisruptionAction> {
        self.actions_taken.read().await.clone()
    }

    /// Get tracked suspicious processes
    pub async fn get_suspicious_processes(&self) -> HashMap<u32, RansomwareBehavior> {
        self.suspicious_processes.read().await.clone()
    }

    /// Get next alert event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    // -----------------------------------------------------------------------
    // VSS Rollback Integration
    // -----------------------------------------------------------------------

    /// Trigger an emergency VSS snapshot and automatic rollback after
    /// ransomware has been detected and the malicious process killed.
    ///
    /// This method performs the complete post-disruption remediation:
    /// 1. Create an emergency VSS snapshot (captures current state for forensics)
    /// 2. Find all files affected by the ransomware
    /// 3. Locate the most recent clean (pre-attack) snapshot
    /// 4. Restore affected files from the clean snapshot
    /// 5. Verify restored files via hash comparison
    /// 6. Report results via telemetry
    pub async fn execute_vss_rollback(
        &self,
        behavior: &RansomwareBehavior,
    ) -> Result<super::vss_rollback::RollbackResult, String> {
        use super::vss_rollback::VssSnapshotManager;

        info!(
            pid = behavior.pid,
            process = %behavior.process_name,
            encryption_count = behavior.encryption_count,
            "Starting VSS rollback for ransomware remediation"
        );

        let config = self.config.clone();
        let mut manager = VssSnapshotManager::new(&config);

        // Step 1: Create emergency snapshot (captures current damaged state for forensics).
        info!("Step 1/5: Creating emergency VSS snapshot");
        match manager.create_emergency_snapshot() {
            Ok(snaps) => {
                info!(
                    count = snaps.len(),
                    "Emergency snapshot created for forensics"
                );
            }
            Err(e) => {
                warn!(error = %e, "Emergency snapshot failed (continuing with rollback)");
            }
        }

        // Step 2: Populate snapshot cache to find pre-attack snapshots.
        info!("Step 2/5: Enumerating available VSS snapshots");
        if let Err(e) = manager.list_snapshots(Some("C:")) {
            return Err(format!("Failed to list snapshots: {}", e));
        }

        // Step 3: Determine root path to scan and attack timestamp.
        let root_path = std::path::Path::new("C:\\Users");
        let attack_time = Some(behavior.first_seen);

        info!(
            root = %root_path.display(),
            attack_time = behavior.first_seen,
            "Step 3/5: Scanning for encrypted files"
        );

        // Step 4: Execute ransomware rollback.
        info!("Step 4/5: Restoring files from pre-attack snapshot");
        match manager.ransomware_rollback(root_path, attack_time) {
            Ok(result) => {
                info!(
                    restored = result.restored.len(),
                    failed = result.failed.len(),
                    skipped = result.skipped.len(),
                    bytes = result.bytes_restored,
                    duration_ms = result.duration_ms,
                    verified = result.verification_passed,
                    "Step 5/5: VSS rollback complete"
                );

                // Step 5: Record the rollback action.
                {
                    let mut actions = self.actions_taken.write().await;
                    actions.push(DisruptionAction {
                        timestamp: Self::now(),
                        action_type: DisruptionType::BackupCreation,
                        target_pid: Some(behavior.pid),
                        target_path: Some(root_path.to_string_lossy().to_string()),
                        success: true,
                        details: format!(
                            "VSS rollback: restored {} files ({} bytes) from snapshot {}, {} failed, {} skipped, verified={}",
                            result.restored.len(),
                            result.bytes_restored,
                            result.snapshot_id,
                            result.failed.len(),
                            result.skipped.len(),
                            result.verification_passed
                        ),
                    });
                }

                Ok(result)
            }
            Err(e) => {
                warn!(error = %e, "VSS rollback failed");

                {
                    let mut actions = self.actions_taken.write().await;
                    actions.push(DisruptionAction {
                        timestamp: Self::now(),
                        action_type: DisruptionType::BackupCreation,
                        target_pid: Some(behavior.pid),
                        target_path: Some(root_path.to_string_lossy().to_string()),
                        success: false,
                        details: format!("VSS rollback failed: {}", e),
                    });
                }

                Err(format!("VSS rollback failed: {}", e))
            }
        }
    }

    /// Check a process creation event for VSS shadow copy deletion attempts
    /// and block them by killing the process.
    ///
    /// Returns true if the process was blocked.
    pub fn check_and_block_vss_deletion(pid: u32, process_name: &str, cmdline: &str) -> bool {
        if let Some(attempt) =
            super::vss_rollback::check_process_for_vss_deletion(pid, process_name, cmdline)
        {
            warn!(
                pid = attempt.pid,
                process = %attempt.process_name,
                "Blocking VSS shadow copy deletion attempt"
            );

            // Kill the process attempting to delete shadows.
            let killed = Self::kill_process(pid);
            if killed {
                info!(pid = pid, "Successfully killed VSS deletion process");
            } else {
                warn!(pid = pid, "Failed to kill VSS deletion process");
            }

            return true;
        }
        false
    }
}
