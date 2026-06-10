//! Network Anomaly Detection Module
//!
//! Detects advanced network-based threats including:
//! - C2 beaconing patterns (regular intervals, jitter analysis)
//! - DNS anomalies (tunneling, DGA, DoH/DoT, fast-flux)
//! - Data exfiltration indicators
//! - Unusual protocol usage
//! - Internal network anomalies (port scanning, lateral movement)
//! - Baseline deviation detection
//!
//! MITRE ATT&CK Mappings:
//! - T1071: Application Layer Protocol
//! - T1041: Exfiltration Over C2 Channel
//! - T1048: Exfiltration Over Alternative Protocol
//! - T1572: Protocol Tunneling
//! - T1568: Dynamic Resolution (DGA)
//! - T1046: Network Service Discovery

// This detector enumerates C2 beaconing, DGA/DoH/DoT/tunneling, exfil and
// lateral-movement baselines. Reserved fields and threshold constants are
// kept exhaustive even when not yet consumed by every detection path.
#![allow(dead_code, unused_variables, unused_assignments)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Maximum history entries to keep per process for baseline learning
const MAX_HISTORY_SIZE: usize = 1000;

/// Window size for beaconing detection (in seconds)
const BEACON_WINDOW_SECONDS: u64 = 300;

/// Minimum connections to trigger beaconing analysis
const MIN_BEACON_CONNECTIONS: usize = 5;

/// Jitter tolerance for beacon detection (percentage)
const JITTER_TOLERANCE: f64 = 0.25;

/// DNS entropy threshold for tunneling detection
const DNS_ENTROPY_THRESHOLD: f64 = 3.5;

/// Maximum label length for normal DNS queries
const MAX_NORMAL_DNS_LABEL_LENGTH: usize = 24;

/// DGA detection: minimum consonant ratio threshold
const DGA_CONSONANT_RATIO_THRESHOLD: f64 = 0.65;

/// Large outbound transfer threshold (bytes)
const LARGE_TRANSFER_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB

/// Port scan detection: unique ports threshold
const PORT_SCAN_THRESHOLD: usize = 20;

/// Port scan detection window (seconds)
const PORT_SCAN_WINDOW_SECONDS: u64 = 60;

/// Network anomaly event payload
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkAnomalyEvent {
    /// Process ID that generated the anomaly
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Anomaly description
    pub description: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Related IP addresses
    pub related_ips: Vec<String>,
    /// Related domains
    pub related_domains: Vec<String>,
    /// Related ports
    pub related_ports: Vec<u16>,
    /// Bytes transferred (if applicable)
    pub bytes_transferred: Option<u64>,
    /// Connection count (if applicable)
    pub connection_count: Option<u32>,
    /// Time pattern analysis (if applicable)
    pub time_pattern: Option<TimePattern>,
    /// Additional context
    pub context: HashMap<String, String>,
}

impl Serialize for NetworkAnomalyEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let remote_ip = self.related_ips.first();
        let remote_port = self.related_ports.first().copied();
        let domain = self.related_domains.first();
        let is_encrypted = remote_port.and_then(|port| {
            if matches!(
                port,
                443 | 4443 | 465 | 563 | 636 | 853 | 989 | 990 | 993 | 995 | 8443
            ) {
                Some(true)
            } else {
                None
            }
        });

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("pid", &self.pid)?;
        map.serialize_entry("process_name", &self.process_name)?;
        map.serialize_entry("anomaly_type", &self.anomaly_type)?;
        map.serialize_entry("description", &self.description)?;
        map.serialize_entry("confidence", &self.confidence)?;
        map.serialize_entry("related_ips", &self.related_ips)?;
        map.serialize_entry("related_domains", &self.related_domains)?;
        map.serialize_entry("related_ports", &self.related_ports)?;
        map.serialize_entry("bytes_transferred", &self.bytes_transferred)?;
        map.serialize_entry("connection_count", &self.connection_count)?;
        map.serialize_entry("time_pattern", &self.time_pattern)?;
        map.serialize_entry("context", &self.context)?;

        if let Some(remote_ip) = remote_ip {
            map.serialize_entry("remote_ip", remote_ip)?;
        }
        if let Some(remote_port) = remote_port {
            map.serialize_entry("remote_port", &remote_port)?;
        }
        if let Some(domain) = domain {
            map.serialize_entry("domain", domain)?;
            map.serialize_entry("domain_candidates", &self.related_domains)?;
        }
        if let Some(is_encrypted) = is_encrypted {
            map.serialize_entry("is_encrypted", &is_encrypted)?;
        }

        map.end()
    }
}

/// Types of network anomalies detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    // Beaconing
    BeaconingDetected,
    BeaconingWithJitter,

    // DNS Anomalies
    DnsTunneling,
    DgaDetected,
    ExcessiveDnsQueries,
    DnsOverHttps,
    DnsOverTls,
    FastFluxDetected,
    UnusualDnsQueryType,

    // Data Exfiltration
    LargeOutboundTransfer,
    RareDestination,
    CloudStorageUpload,
    IcmpTunneling,
    SteganographyIndicator,

    // C2 Patterns
    KnownC2Port,
    SuspiciousHttpPattern,
    CobaltStrikeProfile,
    LongRunningConnection,
    KeepAlivePattern,

    // Protocol Anomalies
    NonStandardPort,
    EncryptedOnUnusualPort,
    IrcDetected,
    TorDetected,
    I2pDetected,
    ProxyVpnUsage,

    // Internal Network
    PortScanDetected,
    InternalReconnaissance,
    UnusualLateralConnection,
    SmbBruteForce,
    RdpBruteForce,

    // Baseline Deviation
    BaselineDeviation,
    UnusualTimeActivity,
    NewDestinationForProcess,
}

/// Time pattern analysis for beaconing detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePattern {
    /// Average interval between connections (milliseconds)
    pub avg_interval_ms: u64,
    /// Standard deviation of intervals
    pub std_deviation_ms: f64,
    /// Detected jitter percentage
    pub jitter_percentage: f64,
    /// Sample count
    pub sample_count: usize,
    /// Is periodic
    pub is_periodic: bool,
}

/// Connection record for tracking
#[derive(Debug, Clone)]
struct ConnectionRecord {
    timestamp: Instant,
    pid: u32,
    process_name: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    protocol: String,
    bytes_sent: u64,
    bytes_received: u64,
}

/// DNS query record for analysis
#[derive(Debug, Clone)]
struct DnsQueryRecord {
    timestamp: Instant,
    pid: u32,
    process_name: String,
    query: String,
    query_type: String,
    responses: Vec<String>,
}

/// Process network baseline
#[derive(Debug, Clone, Default)]
struct ProcessBaseline {
    /// Known destination IPs
    known_destinations: HashSet<String>,
    /// Known destination ports
    known_ports: HashSet<u16>,
    /// Known domains
    known_domains: HashSet<String>,
    /// Active hours bitmap (24 bits for 24 hours)
    active_hours: u32,
    /// Average bytes per hour
    avg_bytes_per_hour: f64,
    /// Connection frequency per hour
    avg_connections_per_hour: f64,
    /// Last update time
    last_updated: Option<Instant>,
    /// Sample count
    sample_count: u64,
}

/// Network Anomaly Detection Collector
pub struct NetworkAnomalyCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl NetworkAnomalyCollector {
    /// Create a new network anomaly collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::monitor_loop(tx, config_clone).await {
                error!(error = %e, "Network anomaly collector error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
    ) -> anyhow::Result<()> {
        info!(
            collector = "network_anomaly",
            mode = "connection_table_and_dns_cache",
            "Network anomaly collector started without requiring packet-capture privileges"
        );

        // State tracking
        let mut connection_history: HashMap<String, VecDeque<ConnectionRecord>> = HashMap::new();
        let mut dns_history: HashMap<String, VecDeque<DnsQueryRecord>> = HashMap::new();
        let mut process_baselines: HashMap<String, ProcessBaseline> = HashMap::new();
        let mut port_scan_tracker: HashMap<String, HashSet<(String, u16)>> = HashMap::new();
        let mut port_scan_timestamps: HashMap<String, Instant> = HashMap::new();
        let mut dns_query_counts: HashMap<String, (Instant, u32)> = HashMap::new();
        let mut domain_ip_mappings: HashMap<String, HashSet<String>> = HashMap::new();

        // Known malicious patterns
        let known_c2_ports: HashSet<u16> = [
            4444, 5555, 6666, 7777, 8888, 9999, // Common RAT ports
            1337, 31337, // Leet ports
            4443, 8443, 8080, 8000, // Alt HTTP/HTTPS
            53, 443, 80, // DNS/HTTPS/HTTP (suspicious when combined with other indicators)
        ]
        .iter()
        .cloned()
        .collect();

        let cloud_storage_domains: HashSet<&str> = [
            "drive.google.com",
            "docs.google.com",
            "dropbox.com",
            "www.dropbox.com",
            "dl.dropboxusercontent.com",
            "onedrive.live.com",
            "1drv.ms",
            "box.com",
            "app.box.com",
            "mega.nz",
            "mediafire.com",
            "wetransfer.com",
            "pastebin.com",
            "ghostbin.com",
            "transfer.sh",
            "file.io",
            "anonfiles.com",
            "gofile.io",
        ]
        .iter()
        .cloned()
        .collect();

        let tor_indicators: HashSet<&str> = [
            "torproject.org",
            ".onion",
            "127.0.0.1:9050",
            "127.0.0.1:9150",
        ]
        .iter()
        .cloned()
        .collect();

        let i2p_indicators: HashSet<&str> =
            [".i2p", "i2p.net", "geti2p.net"].iter().cloned().collect();

        // Analysis interval
        let mut analysis_interval = tokio::time::interval(Duration::from_secs(5));

        // Data collection interval. Uses OS connection tables plus DNS events captured by DnsCollector.
        let mut collection_interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                // Collect network data
                _ = collection_interval.tick() => {
                    // Collect current connections
                    let connections = Self::get_current_connections().await;

                    for conn in connections {
                        let key = format!("{}:{}", conn.pid, conn.process_name);

                        // Update connection history
                        let history = connection_history
                            .entry(key.clone())
                            .or_insert_with(|| VecDeque::with_capacity(MAX_HISTORY_SIZE));

                        if history.len() >= MAX_HISTORY_SIZE {
                            history.pop_front();
                        }
                        history.push_back(conn.clone());

                        // Update baseline
                        Self::update_baseline(
                            &mut process_baselines,
                            &key,
                            &conn.remote_ip,
                            conn.remote_port,
                            None,
                        );

                        // Track port scanning
                        let scan_key = format!("{}:{}", conn.pid, conn.local_ip);
                        let ports = port_scan_tracker.entry(scan_key.clone()).or_insert_with(HashSet::new);
                        ports.insert((conn.remote_ip.clone(), conn.remote_port));

                        // Update port scan timestamp
                        port_scan_timestamps.insert(scan_key, Instant::now());
                    }

                    // Collect DNS queries
                    let dns_queries = Self::get_dns_queries().await;

                    for query in dns_queries {
                        let key = format!("{}:{}", query.pid, query.process_name);

                        // Update DNS history
                        let history = dns_history
                            .entry(key.clone())
                            .or_insert_with(|| VecDeque::with_capacity(MAX_HISTORY_SIZE));

                        if history.len() >= MAX_HISTORY_SIZE {
                            history.pop_front();
                        }
                        history.push_back(query.clone());

                        // Track DNS query counts
                        let count_entry = dns_query_counts.entry(key.clone()).or_insert((Instant::now(), 0));
                        if count_entry.0.elapsed() > Duration::from_secs(60) {
                            *count_entry = (Instant::now(), 1);
                        } else {
                            count_entry.1 += 1;
                        }

                        // Track domain -> IP mappings for fast-flux detection
                        if !query.responses.is_empty() {
                            let ips = domain_ip_mappings.entry(query.query.clone()).or_insert_with(HashSet::new);
                            for response in &query.responses {
                                ips.insert(response.clone());
                            }
                        }

                        // Update baseline
                        Self::update_baseline(
                            &mut process_baselines,
                            &key,
                            &String::new(),
                            0,
                            Some(&query.query),
                        );
                    }
                }

                // Perform anomaly analysis
                _ = analysis_interval.tick() => {
                    let now = Instant::now();

                    // 1. Beaconing Detection
                    for (key, history) in &connection_history {
                        if let Some(event) = Self::detect_beaconing(key, history) {
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return Ok(());
                            }
                        }
                    }

                    // 2. DNS Anomaly Detection
                    for (key, history) in &dns_history {
                        // DNS Tunneling
                        if let Some(event) = Self::detect_dns_tunneling(key, history) {
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }

                        // DGA Detection
                        if let Some(event) = Self::detect_dga(key, history) {
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }

                        // DoH/DoT Detection
                        if let Some(event) = Self::detect_encrypted_dns(key, history) {
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }

                    // 3. Excessive DNS queries
                    for (key, (timestamp, count)) in &dns_query_counts {
                        if timestamp.elapsed() < Duration::from_secs(60) && *count > 100 {
                            let parts: Vec<&str> = key.splitn(2, ':').collect();
                            let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                            let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                            let event = Self::create_anomaly_event(
                                pid,
                                process_name,
                                AnomalyType::ExcessiveDnsQueries,
                                format!("Process made {} DNS queries in 60 seconds", count),
                                0.7,
                                vec!["T1071.004".to_string()],
                            );

                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }

                    // 4. Fast-Flux Detection
                    for (domain, ips) in &domain_ip_mappings {
                        if ips.len() > 10 {
                            let event = Self::create_fast_flux_event(domain, ips);
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }

                    // 5. Port Scan Detection
                    for (key, ports) in &port_scan_tracker {
                        if let Some(timestamp) = port_scan_timestamps.get(key) {
                            if timestamp.elapsed() < Duration::from_secs(PORT_SCAN_WINDOW_SECONDS)
                                && ports.len() >= PORT_SCAN_THRESHOLD
                            {
                                let parts: Vec<&str> = key.splitn(2, ':').collect();
                                let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);

                                let event = Self::create_port_scan_event(pid, ports);
                                if tx.send(event).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }

                    // 6. C2 Port and Pattern Detection
                    for (key, history) in &connection_history {
                        for conn in history.iter() {
                            // Known C2 ports
                            if known_c2_ports.contains(&conn.remote_port) {
                                // Only alert if it's not a well-known service
                                if !Self::is_legitimate_service(&conn.remote_ip, conn.remote_port) {
                                    let event = Self::create_c2_port_event(conn, &known_c2_ports);
                                    if tx.send(event).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }

                            // Long running connections (> 1 hour for suspicious ports)
                            if conn.timestamp.elapsed() > Duration::from_secs(3600) {
                                if known_c2_ports.contains(&conn.remote_port) || conn.remote_port > 10000 {
                                    let event = Self::create_long_connection_event(conn);
                                    if tx.send(event).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }

                    // 7. Cloud Storage Exfiltration Detection
                    for (key, history) in &dns_history {
                        for query in history.iter() {
                            let domain_lower = query.query.to_lowercase();
                            for cloud_domain in &cloud_storage_domains {
                                if domain_lower.contains(cloud_domain) {
                                    let parts: Vec<&str> = key.splitn(2, ':').collect();
                                    let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                                    let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                                    // Check if this is a suspicious process accessing cloud storage
                                    if Self::is_suspicious_process_for_cloud(&process_name) {
                                        let event = Self::create_cloud_exfil_event(pid, &process_name, &query.query);
                                        if tx.send(event).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // 8. Tor/I2P Detection
                    for (key, history) in &dns_history {
                        for query in history.iter() {
                            let domain_lower = query.query.to_lowercase();

                            // Tor detection
                            for tor_ind in &tor_indicators {
                                if domain_lower.contains(tor_ind) {
                                    let parts: Vec<&str> = key.splitn(2, ':').collect();
                                    let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                                    let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                                    let event = Self::create_tor_event(pid, &process_name, &query.query);
                                    if tx.send(event).await.is_err() {
                                        return Ok(());
                                    }
                                    break;
                                }
                            }

                            // I2P detection
                            for i2p_ind in &i2p_indicators {
                                if domain_lower.contains(i2p_ind) {
                                    let parts: Vec<&str> = key.splitn(2, ':').collect();
                                    let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                                    let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                                    let event = Self::create_i2p_event(pid, &process_name, &query.query);
                                    if tx.send(event).await.is_err() {
                                        return Ok(());
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // 9. Baseline Deviation Detection
                    for (key, baseline) in &process_baselines {
                        if baseline.sample_count > 100 {
                            // Check for new destinations
                            if let Some(history) = connection_history.get(key) {
                                for conn in history.iter().rev().take(10) {
                                    if !baseline.known_destinations.contains(&conn.remote_ip) {
                                        let parts: Vec<&str> = key.splitn(2, ':').collect();
                                        let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                                        let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                                        let event = Self::create_baseline_deviation_event(
                                            pid,
                                            &process_name,
                                            &conn.remote_ip,
                                            baseline,
                                        );

                                        if tx.send(event).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 10. SMB/RDP Brute Force Detection
                    for (key, history) in &connection_history {
                        let smb_attempts: Vec<_> = history.iter()
                            .filter(|c| c.remote_port == 445 || c.remote_port == 139)
                            .collect();

                        if smb_attempts.len() > 10 {
                            // Check unique targets
                            let unique_targets: HashSet<_> = smb_attempts.iter()
                                .map(|c| &c.remote_ip)
                                .collect();

                            if unique_targets.len() > 3 {
                                let parts: Vec<&str> = key.splitn(2, ':').collect();
                                let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                                let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                                let event = Self::create_smb_brute_force_event(pid, &process_name, &unique_targets);
                                if tx.send(event).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }

                        let rdp_attempts: Vec<_> = history.iter()
                            .filter(|c| c.remote_port == 3389)
                            .collect();

                        if rdp_attempts.len() > 10 {
                            let unique_targets: HashSet<_> = rdp_attempts.iter()
                                .map(|c| &c.remote_ip)
                                .collect();

                            if unique_targets.len() > 3 {
                                let parts: Vec<&str> = key.splitn(2, ':').collect();
                                let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                                let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                                let event = Self::create_rdp_brute_force_event(pid, &process_name, &unique_targets);
                                if tx.send(event).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }

                    // Cleanup old data
                    Self::cleanup_old_data(
                        &mut connection_history,
                        &mut dns_history,
                        &mut port_scan_tracker,
                        &mut port_scan_timestamps,
                        &mut dns_query_counts,
                        &mut domain_ip_mappings,
                        now,
                    );
                }
            }
        }
    }

    /// Get current network connections (platform-specific)
    async fn get_current_connections() -> Vec<ConnectionRecord> {
        let mut connections = Vec::new();

        #[cfg(target_os = "linux")]
        {
            connections = Self::get_connections_linux().await;
        }

        #[cfg(target_os = "windows")]
        {
            connections = Self::get_connections_windows().await;
        }

        #[cfg(target_os = "macos")]
        {
            connections = Self::get_connections_macos().await;
        }

        connections
    }

    #[cfg(target_os = "linux")]
    async fn get_connections_linux() -> Vec<ConnectionRecord> {
        let mut connections = Vec::new();
        let inode_map = Self::build_socket_inode_map().await;

        // Parse /proc/net/tcp
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            for line in content.lines().skip(1) {
                if let Some(conn) = Self::parse_proc_net_line_linux(line, "tcp", &inode_map) {
                    connections.push(conn);
                }
            }
        }

        // Parse /proc/net/udp
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
            for line in content.lines().skip(1) {
                if let Some(conn) = Self::parse_proc_net_line_linux(line, "udp", &inode_map) {
                    connections.push(conn);
                }
            }
        }

        connections
    }

    #[cfg(target_os = "linux")]
    async fn build_socket_inode_map() -> HashMap<u64, (u32, String)> {
        let mut inode_map: HashMap<u64, (u32, String)> = HashMap::new();

        let proc_dir = match tokio::fs::read_dir("/proc").await {
            Ok(d) => d,
            Err(_) => return inode_map,
        };

        let mut entries = proc_dir;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let comm_path = format!("/proc/{}/comm", pid);
            let process_name = match tokio::fs::read_to_string(&comm_path).await {
                Ok(name) => name.trim().to_string(),
                Err(_) => continue,
            };

            let fd_path = format!("/proc/{}/fd", pid);
            let fd_dir = match tokio::fs::read_dir(&fd_path).await {
                Ok(d) => d,
                Err(_) => continue,
            };

            let mut fd_entries = fd_dir;
            while let Ok(Some(fd_entry)) = fd_entries.next_entry().await {
                let fd_path = fd_entry.path();

                if let Ok(target) = tokio::fs::read_link(&fd_path).await {
                    let target_str = target.to_string_lossy();

                    if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                        if let Ok(inode) = target_str[8..target_str.len() - 1].parse::<u64>() {
                            inode_map.insert(inode, (pid, process_name.clone()));
                        }
                    }
                }
            }
        }

        inode_map
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_line_linux(
        line: &str,
        protocol: &str,
        inode_map: &HashMap<u64, (u32, String)>,
    ) -> Option<ConnectionRecord> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let local = parts[1];
        let remote = parts[2];
        let inode: u64 = parts[9].parse().unwrap_or(0);

        let (local_ip, local_port) = Self::parse_hex_address_linux(local)?;
        let (remote_ip, remote_port) = Self::parse_hex_address_linux(remote)?;

        // Skip listening sockets and localhost
        if remote_port == 0 || remote_ip == "0.0.0.0" || remote_ip == "127.0.0.1" {
            return None;
        }

        let (pid, process_name) = inode_map.get(&inode).cloned().unwrap_or((0, String::new()));

        Some(ConnectionRecord {
            timestamp: Instant::now(),
            pid,
            process_name,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: protocol.to_string(),
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    #[cfg(target_os = "linux")]
    fn parse_hex_address_linux(hex: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        if ip_hex.len() == 8 {
            let ip = u32::from_str_radix(ip_hex, 16).ok()?;
            let ip = format!(
                "{}.{}.{}.{}",
                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff
            );

            let port = u16::from_str_radix(port_hex, 16).ok()?;

            Some((ip, port))
        } else {
            None
        }
    }

    #[cfg(target_os = "windows")]
    async fn get_connections_windows() -> Vec<ConnectionRecord> {
        use std::net::Ipv4Addr;

        let mut connections = Vec::new();

        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        };
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0u8; size as usize];

            let result = unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if result == 0 {
                let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
                let num_entries = table.dwNumEntries as usize;

                if num_entries > 0 {
                    // Cap entries at buffer bounds to prevent out-of-bounds reads
                    let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                    let entry_size = std::mem::size_of_val(&table.table[0]);
                    let max_entries = if entry_size > 0 && buffer.len() > header_size {
                        (buffer.len() - header_size) / entry_size
                    } else {
                        0
                    };
                    let num_entries = num_entries.min(max_entries);

                    let rows_ptr = table.table.as_ptr();

                    for i in 0..num_entries {
                        let row = unsafe { &*rows_ptr.add(i) };

                        let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                        let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());

                        let local_port = u16::from_be(row.dwLocalPort as u16);
                        let remote_port = u16::from_be(row.dwRemotePort as u16);

                        if remote_port == 0 || remote_ip.is_loopback() || remote_ip.is_unspecified()
                        {
                            continue;
                        }

                        let pid = row.dwOwningPid;
                        let process_name = Self::get_process_name_windows(pid);

                        connections.push(ConnectionRecord {
                            timestamp: Instant::now(),
                            pid,
                            process_name,
                            local_ip: local_ip.to_string(),
                            local_port,
                            remote_ip: remote_ip.to_string(),
                            remote_port,
                            protocol: "tcp".to_string(),
                            bytes_sent: 0,
                            bytes_received: 0,
                        });
                    }
                }
            }
        }

        connections
    }

    #[cfg(target_os = "windows")]
    fn get_process_name_windows(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        if pid == 0 || pid == 4 {
            return if pid == 0 {
                "System Idle".to_string()
            } else {
                "System".to_string()
            };
        }

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return format!("pid:{}", pid),
            };

            let mut name_buf = [0u16; 260];
            let len = GetModuleBaseNameW(handle, None, &mut name_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&name_buf[..len as usize])
            } else {
                format!("pid:{}", pid)
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn get_connections_macos() -> Vec<ConnectionRecord> {
        let mut connections = Vec::new();

        // Use lsof to get network connections
        let output = std::process::Command::new("lsof")
            .args(["-i", "-n", "-P", "-F", "pcnPt"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_pid: u32 = 0;
                let mut current_name = String::new();
                let mut current_protocol = String::new();

                for line in stdout.lines() {
                    if line.is_empty() {
                        continue;
                    }

                    let field_type = line.chars().next().unwrap_or(' ');
                    let value = &line[1..];

                    match field_type {
                        'p' => current_pid = value.parse().unwrap_or(0),
                        'c' => current_name = value.to_string(),
                        'P' => current_protocol = value.to_lowercase(),
                        'n' => {
                            if let Some((local, remote)) = value.split_once("->") {
                                if let (Some((lip, lport)), Some((rip, rport))) = (
                                    Self::parse_macos_addr(local),
                                    Self::parse_macos_addr(remote),
                                ) {
                                    if rip != "127.0.0.1" && rip != "::1" {
                                        connections.push(ConnectionRecord {
                                            timestamp: Instant::now(),
                                            pid: current_pid,
                                            process_name: current_name.clone(),
                                            local_ip: lip,
                                            local_port: lport,
                                            remote_ip: rip,
                                            remote_port: rport,
                                            protocol: current_protocol.clone(),
                                            bytes_sent: 0,
                                            bytes_received: 0,
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        connections
    }

    #[cfg(target_os = "macos")]
    fn parse_macos_addr(addr: &str) -> Option<(String, u16)> {
        if addr.starts_with('[') {
            // IPv6
            if let Some(bracket_end) = addr.find(']') {
                let ip = &addr[1..bracket_end];
                let port_str = addr.get(bracket_end + 2..)?;
                let port = port_str.parse().ok()?;
                return Some((ip.to_string(), port));
            }
        } else {
            // IPv4
            if let Some(colon_pos) = addr.rfind(':') {
                let ip = &addr[..colon_pos];
                let port = addr[colon_pos + 1..].parse().ok()?;
                return Some((ip.to_string(), port));
            }
        }
        None
    }

    /// Get recent DNS queries captured by DnsCollector.
    async fn get_dns_queries() -> Vec<DnsQueryRecord> {
        crate::collectors::dns::recent_dns_queries()
            .into_iter()
            .map(|query| DnsQueryRecord {
                timestamp: Instant::now(),
                pid: query.pid,
                process_name: query.process_name,
                query: query.query,
                query_type: query.query_type,
                responses: query.responses,
            })
            .collect()
    }

    /// Detect C2 beaconing patterns
    fn detect_beaconing(key: &str, history: &VecDeque<ConnectionRecord>) -> Option<TelemetryEvent> {
        if history.len() < MIN_BEACON_CONNECTIONS {
            return None;
        }

        // Group connections by destination
        let mut by_destination: HashMap<String, Vec<&ConnectionRecord>> = HashMap::new();
        for conn in history.iter() {
            let dest_key = format!("{}:{}", conn.remote_ip, conn.remote_port);
            by_destination.entry(dest_key).or_default().push(conn);
        }

        for (dest, conns) in by_destination {
            if conns.len() < MIN_BEACON_CONNECTIONS {
                continue;
            }

            // Calculate intervals
            let mut intervals: Vec<u64> = Vec::new();
            for i in 1..conns.len() {
                let interval = conns[i]
                    .timestamp
                    .duration_since(conns[i - 1].timestamp)
                    .as_millis() as u64;
                intervals.push(interval);
            }

            if intervals.is_empty() {
                continue;
            }

            // Calculate statistics
            let avg_interval: f64 = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
            let variance: f64 = intervals
                .iter()
                .map(|&i| {
                    let diff = i as f64 - avg_interval;
                    diff * diff
                })
                .sum::<f64>()
                / intervals.len() as f64;
            let std_dev = variance.sqrt();
            let jitter_pct = std_dev / avg_interval;

            // Check for beaconing pattern
            let is_periodic = jitter_pct < JITTER_TOLERANCE;

            if is_periodic || jitter_pct < 0.5 {
                // Also catch beacons with moderate jitter
                let parts: Vec<&str> = key.splitn(2, ':').collect();
                let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                let dest_parts: Vec<&str> = dest.splitn(2, ':').collect();
                let remote_ip = dest_parts.get(0).map(|s| s.to_string()).unwrap_or_default();
                let remote_port: u16 = dest_parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);

                let anomaly_type = if jitter_pct < JITTER_TOLERANCE {
                    AnomalyType::BeaconingDetected
                } else {
                    AnomalyType::BeaconingWithJitter
                };

                let confidence = if jitter_pct < 0.1 {
                    0.95
                } else if jitter_pct < 0.25 {
                    0.85
                } else {
                    0.7
                };

                let mut anomaly_event = NetworkAnomalyEvent {
                    pid,
                    process_name: process_name.clone(),
                    anomaly_type: anomaly_type.clone(),
                    description: format!(
                        "Potential C2 beaconing detected to {}:{} with {:.1}s avg interval ({:.1}% jitter)",
                        remote_ip, remote_port, avg_interval / 1000.0, jitter_pct * 100.0
                    ),
                    confidence,
                    related_ips: vec![remote_ip.clone()],
                    related_domains: vec![],
                    related_ports: vec![remote_port],
                    bytes_transferred: None,
                    connection_count: Some(conns.len() as u32),
                    time_pattern: Some(TimePattern {
                        avg_interval_ms: avg_interval as u64,
                        std_deviation_ms: std_dev,
                        jitter_percentage: jitter_pct,
                        sample_count: intervals.len(),
                        is_periodic,
                    }),
                    context: HashMap::new(),
                };

                anomaly_event
                    .context
                    .insert("destination".to_string(), dest.clone());

                let mut event = TelemetryEvent::new(
                    EventType::NetworkConnect,
                    Severity::High,
                    EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
                );

                // Add MITRE detection
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: format!("{:?}", anomaly_type),
                    confidence: confidence as f32,
                    description: anomaly_event.description.clone(),
                    mitre_tactics: vec!["command-and-control".to_string()],
                    mitre_techniques: vec!["T1071".to_string(), "T1571".to_string()],
                });

                return Some(event);
            }
        }

        None
    }

    /// Detect DNS tunneling
    fn detect_dns_tunneling(
        key: &str,
        history: &VecDeque<DnsQueryRecord>,
    ) -> Option<TelemetryEvent> {
        for query in history.iter() {
            // Calculate entropy of the query
            let entropy = Self::calculate_entropy(&query.query);

            // Check for long labels (typical of DNS tunneling)
            let max_label_len = query.query.split('.').map(|l| l.len()).max().unwrap_or(0);

            // Check for suspicious TXT/NULL queries
            let suspicious_type =
                query.query_type == "TXT" || query.query_type == "NULL" || query.query_type == "MX";

            // DNS tunneling indicators:
            // - High entropy in subdomain
            // - Long labels
            // - Numeric-heavy content
            // - Base64-like patterns
            let is_tunneling = entropy > DNS_ENTROPY_THRESHOLD
                || max_label_len > MAX_NORMAL_DNS_LABEL_LENGTH
                || (suspicious_type && entropy > 3.0);

            if is_tunneling {
                let parts: Vec<&str> = key.splitn(2, ':').collect();
                let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                let mut anomaly_event = NetworkAnomalyEvent {
                    pid,
                    process_name: process_name.clone(),
                    anomaly_type: AnomalyType::DnsTunneling,
                    description: format!(
                        "Potential DNS tunneling detected: query='{}' entropy={:.2} max_label_len={}",
                        query.query, entropy, max_label_len
                    ),
                    confidence: if entropy > 4.0 { 0.9 } else { 0.75 },
                    related_ips: query.responses.clone(),
                    related_domains: vec![query.query.clone()],
                    related_ports: vec![53],
                    bytes_transferred: None,
                    connection_count: None,
                    time_pattern: None,
                    context: HashMap::new(),
                };

                anomaly_event
                    .context
                    .insert("entropy".to_string(), format!("{:.2}", entropy));
                anomaly_event
                    .context
                    .insert("query_type".to_string(), query.query_type.clone());

                let mut event = TelemetryEvent::new(
                    EventType::DnsQuery,
                    Severity::High,
                    EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
                );

                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "dns_tunneling".to_string(),
                    confidence: anomaly_event.confidence as f32,
                    description: anomaly_event.description.clone(),
                    mitre_tactics: vec![
                        "command-and-control".to_string(),
                        "exfiltration".to_string(),
                    ],
                    mitre_techniques: vec!["T1071.004".to_string(), "T1048.003".to_string()],
                });

                return Some(event);
            }
        }

        None
    }

    /// Detect Domain Generation Algorithm (DGA) domains
    fn detect_dga(key: &str, history: &VecDeque<DnsQueryRecord>) -> Option<TelemetryEvent> {
        let mut suspicious_domains: Vec<(String, f64)> = Vec::new();

        for query in history.iter() {
            // Get the main domain (exclude TLD)
            let parts: Vec<&str> = query.query.split('.').collect();
            if parts.len() < 2 {
                continue;
            }

            let domain_part = parts[0];

            // Skip if too short
            if domain_part.len() < 6 {
                continue;
            }

            // DGA indicators:
            // 1. High consonant ratio
            // 2. Random-looking character distribution
            // 3. Numeric content mixed with letters
            // 4. No vowel patterns (real words have vowels)

            let consonant_ratio = Self::calculate_consonant_ratio(domain_part);
            let entropy = Self::calculate_entropy(domain_part);
            let has_digits = domain_part.chars().any(|c| c.is_ascii_digit());
            let digit_ratio = domain_part.chars().filter(|c| c.is_ascii_digit()).count() as f64
                / domain_part.len() as f64;

            // DGA score
            let dga_score = (consonant_ratio * 0.4)
                + (entropy / 5.0 * 0.3)
                + (if has_digits && digit_ratio > 0.2 {
                    0.3
                } else {
                    0.0
                });

            if dga_score > 0.65 || consonant_ratio > DGA_CONSONANT_RATIO_THRESHOLD {
                suspicious_domains.push((query.query.clone(), dga_score));
            }
        }

        if suspicious_domains.len() >= 3 {
            let parts: Vec<&str> = key.splitn(2, ':').collect();
            let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
            let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

            let avg_score: f64 = suspicious_domains.iter().map(|(_, s)| s).sum::<f64>()
                / suspicious_domains.len() as f64;

            let anomaly_event = NetworkAnomalyEvent {
                pid,
                process_name: process_name.clone(),
                anomaly_type: AnomalyType::DgaDetected,
                description: format!(
                    "Potential DGA activity detected: {} suspicious domains with avg score {:.2}",
                    suspicious_domains.len(),
                    avg_score
                ),
                confidence: (avg_score * 1.2).min(0.95),
                related_ips: vec![],
                related_domains: suspicious_domains
                    .iter()
                    .take(10)
                    .map(|(d, _)| d.clone())
                    .collect(),
                related_ports: vec![53],
                bytes_transferred: None,
                connection_count: Some(suspicious_domains.len() as u32),
                time_pattern: None,
                context: HashMap::new(),
            };

            let mut event = TelemetryEvent::new(
                EventType::DnsQuery,
                Severity::High,
                EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "dga_detected".to_string(),
                confidence: anomaly_event.confidence as f32,
                description: anomaly_event.description.clone(),
                mitre_tactics: vec!["command-and-control".to_string()],
                mitre_techniques: vec!["T1568.002".to_string()],
            });

            return Some(event);
        }

        None
    }

    /// Detect DNS over HTTPS (DoH) or DNS over TLS (DoT)
    fn detect_encrypted_dns(
        key: &str,
        history: &VecDeque<DnsQueryRecord>,
    ) -> Option<TelemetryEvent> {
        // Known DoH/DoT endpoints
        let doh_providers: HashSet<&str> = [
            "dns.google",
            "dns.google.com",
            "dns.cloudflare.com",
            "cloudflare-dns.com",
            "mozilla.cloudflare-dns.com",
            "dns.quad9.net",
            "doh.opendns.com",
            "dns.nextdns.io",
            "dns.adguard.com",
            "doh.cleanbrowsing.org",
        ]
        .iter()
        .cloned()
        .collect();

        for query in history.iter() {
            let domain_lower = query.query.to_lowercase();

            for provider in &doh_providers {
                if domain_lower.contains(provider) {
                    let parts: Vec<&str> = key.splitn(2, ':').collect();
                    let pid: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(0);
                    let process_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                    // Check if this is the browser (less suspicious) or another process
                    let is_browser = process_name.to_lowercase().contains("chrome")
                        || process_name.to_lowercase().contains("firefox")
                        || process_name.to_lowercase().contains("edge")
                        || process_name.to_lowercase().contains("safari");

                    if !is_browser {
                        let anomaly_event = NetworkAnomalyEvent {
                            pid,
                            process_name: process_name.clone(),
                            anomaly_type: AnomalyType::DnsOverHttps,
                            description: format!(
                                "Non-browser process using DNS-over-HTTPS: {} -> {}",
                                process_name, query.query
                            ),
                            confidence: 0.8,
                            related_ips: query.responses.clone(),
                            related_domains: vec![query.query.clone()],
                            related_ports: vec![443],
                            bytes_transferred: None,
                            connection_count: None,
                            time_pattern: None,
                            context: HashMap::new(),
                        };

                        let mut event = TelemetryEvent::new(
                            EventType::DnsQuery,
                            Severity::Medium,
                            EventPayload::Custom(
                                serde_json::to_value(&anomaly_event).unwrap_or_default(),
                            ),
                        );

                        event.add_detection(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "encrypted_dns".to_string(),
                            confidence: 0.8,
                            description: anomaly_event.description.clone(),
                            mitre_tactics: vec!["command-and-control".to_string()],
                            mitre_techniques: vec!["T1071.001".to_string()],
                        });

                        return Some(event);
                    }
                }
            }
        }

        None
    }

    /// Update process baseline
    fn update_baseline(
        baselines: &mut HashMap<String, ProcessBaseline>,
        key: &str,
        remote_ip: &str,
        remote_port: u16,
        domain: Option<&str>,
    ) {
        let baseline = baselines.entry(key.to_string()).or_default();

        if !remote_ip.is_empty() {
            baseline.known_destinations.insert(remote_ip.to_string());
        }

        if remote_port > 0 {
            baseline.known_ports.insert(remote_port);
        }

        if let Some(d) = domain {
            baseline.known_domains.insert(d.to_string());
        }

        // Update active hours (simplified - just mark current hour)
        let hour = chrono::Local::now().hour();
        baseline.active_hours |= 1 << hour;

        baseline.sample_count += 1;
        baseline.last_updated = Some(Instant::now());
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq: HashMap<char, f64> = HashMap::new();
        let len = s.len() as f64;

        for c in s.chars() {
            *freq.entry(c).or_default() += 1.0;
        }

        freq.values()
            .map(|&count| {
                let p = count / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Calculate consonant ratio for DGA detection
    fn calculate_consonant_ratio(s: &str) -> f64 {
        let vowels: HashSet<char> = ['a', 'e', 'i', 'o', 'u'].iter().cloned().collect();
        let letters: Vec<char> = s
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect();

        if letters.is_empty() {
            return 0.0;
        }

        let consonants = letters.iter().filter(|c| !vowels.contains(c)).count();
        consonants as f64 / letters.len() as f64
    }

    /// Check if a destination appears to be a legitimate service
    fn is_legitimate_service(ip: &str, port: u16) -> bool {
        // Well-known service ports that are generally safe
        match port {
            80 | 443 => true,       // HTTP/HTTPS
            22 => true,             // SSH (internal)
            25 | 465 | 587 => true, // SMTP
            110 | 995 => true,      // POP3
            143 | 993 => true,      // IMAP
            53 => true,             // DNS
            123 => true,            // NTP
            _ => false,
        }
    }

    /// Check if process is suspicious for cloud storage access
    fn is_suspicious_process_for_cloud(process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();

        // Normal browsers/apps are not suspicious
        let legitimate = [
            "chrome",
            "firefox",
            "edge",
            "safari",
            "opera",
            "brave",
            "dropbox",
            "onedrive",
            "googledrive",
            "box sync",
            "explorer.exe",
            "finder",
        ];

        for legit in &legitimate {
            if name_lower.contains(legit) {
                return false;
            }
        }

        // Suspicious: shells, scripting engines, etc.
        let suspicious = [
            "cmd.exe",
            "powershell",
            "pwsh",
            "bash",
            "sh",
            "python",
            "perl",
            "ruby",
            "node",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
        ];

        for susp in &suspicious {
            if name_lower.contains(susp) {
                return true;
            }
        }

        // Unknown processes are mildly suspicious
        true
    }

    /// Create a generic anomaly event
    fn create_anomaly_event(
        pid: u32,
        process_name: String,
        anomaly_type: AnomalyType,
        description: String,
        confidence: f64,
        techniques: Vec<String>,
    ) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.clone(),
            anomaly_type: anomaly_type.clone(),
            description: description.clone(),
            confidence,
            related_ips: vec![],
            related_domains: vec![],
            related_ports: vec![],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::Medium,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("{:?}", anomaly_type),
            confidence: confidence as f32,
            description,
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: techniques,
        });

        event
    }

    /// Create fast-flux detection event
    fn create_fast_flux_event(domain: &str, ips: &HashSet<String>) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid: 0,
            process_name: String::new(),
            anomaly_type: AnomalyType::FastFluxDetected,
            description: format!(
                "Fast-flux DNS detected: domain '{}' resolved to {} different IPs",
                domain,
                ips.len()
            ),
            confidence: 0.85,
            related_ips: ips.iter().take(20).cloned().collect(),
            related_domains: vec![domain.to_string()],
            related_ports: vec![53],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::DnsQuery,
            Severity::High,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "fast_flux".to_string(),
            confidence: 0.85,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1568.001".to_string()],
        });

        event
    }

    /// Create port scan detection event
    fn create_port_scan_event(pid: u32, ports: &HashSet<(String, u16)>) -> TelemetryEvent {
        let unique_ips: HashSet<_> = ports.iter().map(|(ip, _)| ip.clone()).collect();
        let unique_ports: HashSet<_> = ports.iter().map(|(_, port)| *port).collect();

        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: String::new(),
            anomaly_type: AnomalyType::PortScanDetected,
            description: format!(
                "Port scan detected: {} unique ports across {} targets",
                unique_ports.len(),
                unique_ips.len()
            ),
            confidence: 0.9,
            related_ips: unique_ips.into_iter().collect(),
            related_domains: vec![],
            related_ports: unique_ports.into_iter().collect(),
            bytes_transferred: None,
            connection_count: Some(ports.len() as u32),
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::High,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "port_scan".to_string(),
            confidence: 0.9,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["discovery".to_string()],
            mitre_techniques: vec!["T1046".to_string()],
        });

        event
    }

    /// Create C2 port detection event
    fn create_c2_port_event(
        conn: &ConnectionRecord,
        _known_ports: &HashSet<u16>,
    ) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid: conn.pid,
            process_name: conn.process_name.clone(),
            anomaly_type: AnomalyType::KnownC2Port,
            description: format!(
                "Connection to known C2 port: {}:{} -> {}:{}",
                conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
            ),
            confidence: 0.7,
            related_ips: vec![conn.remote_ip.clone()],
            related_domains: vec![],
            related_ports: vec![conn.remote_port],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::Medium,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "known_c2_port".to_string(),
            confidence: 0.7,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1571".to_string()],
        });

        event
    }

    /// Create long running connection event
    fn create_long_connection_event(conn: &ConnectionRecord) -> TelemetryEvent {
        let duration_hours = conn.timestamp.elapsed().as_secs() / 3600;

        let anomaly_event = NetworkAnomalyEvent {
            pid: conn.pid,
            process_name: conn.process_name.clone(),
            anomaly_type: AnomalyType::LongRunningConnection,
            description: format!(
                "Long-running connection ({}h) to {}:{}",
                duration_hours, conn.remote_ip, conn.remote_port
            ),
            confidence: 0.65,
            related_ips: vec![conn.remote_ip.clone()],
            related_domains: vec![],
            related_ports: vec![conn.remote_port],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::Low,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "long_connection".to_string(),
            confidence: 0.65,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1071".to_string()],
        });

        event
    }

    /// Create cloud exfiltration event
    fn create_cloud_exfil_event(pid: u32, process_name: &str, domain: &str) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.to_string(),
            anomaly_type: AnomalyType::CloudStorageUpload,
            description: format!(
                "Suspicious process '{}' accessing cloud storage: {}",
                process_name, domain
            ),
            confidence: 0.75,
            related_ips: vec![],
            related_domains: vec![domain.to_string()],
            related_ports: vec![443],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::Medium,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "cloud_exfiltration".to_string(),
            confidence: 0.75,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["exfiltration".to_string()],
            mitre_techniques: vec!["T1567".to_string()],
        });

        event
    }

    /// Create Tor detection event
    fn create_tor_event(pid: u32, process_name: &str, domain: &str) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.to_string(),
            anomaly_type: AnomalyType::TorDetected,
            description: format!(
                "Tor network activity detected: {} -> {}",
                process_name, domain
            ),
            confidence: 0.9,
            related_ips: vec![],
            related_domains: vec![domain.to_string()],
            related_ports: vec![9050, 9150],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::High,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "tor_detected".to_string(),
            confidence: 0.9,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1090.003".to_string()],
        });

        event
    }

    /// Create I2P detection event
    fn create_i2p_event(pid: u32, process_name: &str, domain: &str) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.to_string(),
            anomaly_type: AnomalyType::I2pDetected,
            description: format!(
                "I2P network activity detected: {} -> {}",
                process_name, domain
            ),
            confidence: 0.9,
            related_ips: vec![],
            related_domains: vec![domain.to_string()],
            related_ports: vec![],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::High,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "i2p_detected".to_string(),
            confidence: 0.9,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1090.003".to_string()],
        });

        event
    }

    /// Create baseline deviation event
    fn create_baseline_deviation_event(
        pid: u32,
        process_name: &str,
        new_ip: &str,
        baseline: &ProcessBaseline,
    ) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.to_string(),
            anomaly_type: AnomalyType::NewDestinationForProcess,
            description: format!(
                "Process '{}' connecting to new destination {} (baseline has {} known destinations)",
                process_name,
                new_ip,
                baseline.known_destinations.len()
            ),
            confidence: 0.6,
            related_ips: vec![new_ip.to_string()],
            related_domains: vec![],
            related_ports: vec![],
            bytes_transferred: None,
            connection_count: None,
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::Low,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "baseline_deviation".to_string(),
            confidence: 0.6,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1071".to_string()],
        });

        event
    }

    /// Create SMB brute force event
    fn create_smb_brute_force_event(
        pid: u32,
        process_name: &str,
        targets: &HashSet<&String>,
    ) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.to_string(),
            anomaly_type: AnomalyType::SmbBruteForce,
            description: format!(
                "SMB brute force/enumeration detected: {} targeting {} hosts",
                process_name,
                targets.len()
            ),
            confidence: 0.85,
            related_ips: targets.iter().map(|s| (*s).clone()).collect(),
            related_domains: vec![],
            related_ports: vec![445, 139],
            bytes_transferred: None,
            connection_count: Some(targets.len() as u32),
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::High,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "smb_brute_force".to_string(),
            confidence: 0.85,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec![
                "lateral-movement".to_string(),
                "credential-access".to_string(),
            ],
            mitre_techniques: vec!["T1021.002".to_string(), "T1110".to_string()],
        });

        event
    }

    /// Create RDP brute force event
    fn create_rdp_brute_force_event(
        pid: u32,
        process_name: &str,
        targets: &HashSet<&String>,
    ) -> TelemetryEvent {
        let anomaly_event = NetworkAnomalyEvent {
            pid,
            process_name: process_name.to_string(),
            anomaly_type: AnomalyType::RdpBruteForce,
            description: format!(
                "RDP brute force/enumeration detected: {} targeting {} hosts",
                process_name,
                targets.len()
            ),
            confidence: 0.85,
            related_ips: targets.iter().map(|s| (*s).clone()).collect(),
            related_domains: vec![],
            related_ports: vec![3389],
            bytes_transferred: None,
            connection_count: Some(targets.len() as u32),
            time_pattern: None,
            context: HashMap::new(),
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::High,
            EventPayload::Custom(serde_json::to_value(&anomaly_event).unwrap_or_default()),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "rdp_brute_force".to_string(),
            confidence: 0.85,
            description: anomaly_event.description.clone(),
            mitre_tactics: vec![
                "lateral-movement".to_string(),
                "credential-access".to_string(),
            ],
            mitre_techniques: vec!["T1021.001".to_string(), "T1110".to_string()],
        });

        event
    }

    /// Cleanup old tracking data
    fn cleanup_old_data(
        connection_history: &mut HashMap<String, VecDeque<ConnectionRecord>>,
        dns_history: &mut HashMap<String, VecDeque<DnsQueryRecord>>,
        port_scan_tracker: &mut HashMap<String, HashSet<(String, u16)>>,
        port_scan_timestamps: &mut HashMap<String, Instant>,
        dns_query_counts: &mut HashMap<String, (Instant, u32)>,
        domain_ip_mappings: &mut HashMap<String, HashSet<String>>,
        now: Instant,
    ) {
        let max_age = Duration::from_secs(BEACON_WINDOW_SECONDS);

        // Clean connection history
        for history in connection_history.values_mut() {
            while let Some(front) = history.front() {
                if now.duration_since(front.timestamp) > max_age {
                    history.pop_front();
                } else {
                    break;
                }
            }
        }

        // Remove empty entries
        connection_history.retain(|_, v| !v.is_empty());

        // Clean DNS history
        for history in dns_history.values_mut() {
            while let Some(front) = history.front() {
                if now.duration_since(front.timestamp) > max_age {
                    history.pop_front();
                } else {
                    break;
                }
            }
        }
        dns_history.retain(|_, v| !v.is_empty());

        // Clean port scan tracker
        let scan_max_age = Duration::from_secs(PORT_SCAN_WINDOW_SECONDS);
        let expired_scans: Vec<String> = port_scan_timestamps
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) > scan_max_age)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_scans {
            port_scan_tracker.remove(&key);
            port_scan_timestamps.remove(&key);
        }

        // Clean DNS query counts
        dns_query_counts.retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(120));

        // Limit domain IP mappings size
        if domain_ip_mappings.len() > 1000 {
            // Keep only recent entries (simple approach: clear half)
            let keys: Vec<String> = domain_ip_mappings.keys().take(500).cloned().collect();
            for key in keys {
                domain_ip_mappings.remove(&key);
            }
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (repetitive)
        let low_entropy = NetworkAnomalyCollector::calculate_entropy("aaaaaaaaaa");
        assert!(low_entropy < 1.0);

        // Higher entropy (varied)
        let high_entropy = NetworkAnomalyCollector::calculate_entropy("abcdefghij");
        assert!(high_entropy > 3.0);

        // DNS tunneling like pattern
        let tunnel_entropy =
            NetworkAnomalyCollector::calculate_entropy("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q");
        assert!(tunnel_entropy > 3.5);
    }

    #[test]
    fn test_consonant_ratio() {
        // Normal word
        let normal = NetworkAnomalyCollector::calculate_consonant_ratio("google");
        assert!(normal < 0.65);

        // DGA-like (high consonant)
        let dga = NetworkAnomalyCollector::calculate_consonant_ratio("xcvbnmqwrtpsdfgh");
        assert!(dga > 0.65);
    }

    #[test]
    fn test_suspicious_process_detection() {
        assert!(NetworkAnomalyCollector::is_suspicious_process_for_cloud(
            "powershell.exe"
        ));
        assert!(NetworkAnomalyCollector::is_suspicious_process_for_cloud(
            "cmd.exe"
        ));
        assert!(!NetworkAnomalyCollector::is_suspicious_process_for_cloud(
            "chrome.exe"
        ));
        assert!(!NetworkAnomalyCollector::is_suspicious_process_for_cloud(
            "firefox"
        ));
    }
}
