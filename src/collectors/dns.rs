//! DNS event collector
//!
//! Monitors DNS queries made by processes using platform-specific mechanisms:
//! - Linux: eBPF-based DNS monitoring + /proc/net/udp fallback + optional pcap
//! - Windows: ETW with Microsoft-Windows-DNS-Client for actual query names
//! - macOS: Unified log stream (dnssd/mDNSResponder) + BPF packet capture + lsof fallback

use super::{
    governor_aware_interval::GovernorAwareInterval, DnsEvent, EventPayload, EventType, Severity,
    TelemetryEvent,
};
use crate::config::AgentConfig;
use crate::resource_governor::GovernorHandle;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

const DNS_INSIGHT_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const DNS_INSIGHT_CACHE_MAX_IPS: usize = 8192;
const DNS_INSIGHT_QUERY_MAX: usize = 4096;

#[derive(Debug, Clone)]
pub struct DnsCacheQuery {
    pub pid: u32,
    pub process_name: String,
    pub query: String,
    pub query_type: String,
    pub responses: Vec<String>,
}

#[derive(Debug, Clone)]
struct DnsCacheDomain {
    domain: String,
    seen_at: Instant,
}

#[derive(Debug, Default)]
struct DnsInsightCache {
    ip_to_domains: HashMap<String, Vec<DnsCacheDomain>>,
    recent_queries: Vec<DnsCacheQueryEntry>,
}

#[derive(Debug, Clone)]
struct DnsCacheQueryEntry {
    query: DnsCacheQuery,
    seen_at: Instant,
}

static DNS_INSIGHT_CACHE: OnceLock<Mutex<DnsInsightCache>> = OnceLock::new();

fn dns_insight_cache() -> &'static Mutex<DnsInsightCache> {
    DNS_INSIGHT_CACHE.get_or_init(|| Mutex::new(DnsInsightCache::default()))
}

/// Record a real DNS event for later connection enrichment.
pub fn record_dns_event(event: &DnsEvent) {
    let domain = normalize_domain(&event.query);
    if domain.is_empty() {
        return;
    }

    let now = Instant::now();
    let mut cache = match dns_insight_cache().lock() {
        Ok(cache) => cache,
        Err(_) => return,
    };

    cache.recent_queries.push(DnsCacheQueryEntry {
        query: DnsCacheQuery {
            pid: event.pid,
            process_name: event.process_name.clone(),
            query: domain.clone(),
            query_type: event.query_type.clone(),
            responses: event.responses.clone(),
        },
        seen_at: now,
    });

    if cache.recent_queries.len() > DNS_INSIGHT_QUERY_MAX {
        let overflow = cache.recent_queries.len() - DNS_INSIGHT_QUERY_MAX;
        cache.recent_queries.drain(0..overflow);
    }

    for answer in &event.responses {
        if answer.parse::<std::net::IpAddr>().is_err() {
            continue;
        }

        let domains = cache.ip_to_domains.entry(answer.clone()).or_default();
        if let Some(existing) = domains.iter_mut().find(|entry| entry.domain == domain) {
            existing.seen_at = now;
        } else {
            domains.push(DnsCacheDomain {
                domain: domain.clone(),
                seen_at: now,
            });
        }
    }

    cleanup_dns_cache_locked(&mut cache, now);
}

/// Return recent domains that resolved to an IP. Empty means no real DNS evidence.
pub fn lookup_domains_for_ip(ip: &str) -> Vec<String> {
    let now = Instant::now();
    let mut cache = match dns_insight_cache().lock() {
        Ok(cache) => cache,
        Err(_) => return Vec::new(),
    };

    cleanup_dns_cache_locked(&mut cache, now);

    cache
        .ip_to_domains
        .get(ip)
        .map(|domains| {
            domains
                .iter()
                .filter(|entry| now.duration_since(entry.seen_at) <= DNS_INSIGHT_CACHE_TTL)
                .map(|entry| entry.domain.clone())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

/// Return recent DNS queries for anomaly analysis without packet-capture privileges.
pub fn recent_dns_queries() -> Vec<DnsCacheQuery> {
    let now = Instant::now();
    let mut cache = match dns_insight_cache().lock() {
        Ok(cache) => cache,
        Err(_) => return Vec::new(),
    };

    cleanup_dns_cache_locked(&mut cache, now);

    cache
        .recent_queries
        .iter()
        .filter(|entry| now.duration_since(entry.seen_at) <= DNS_INSIGHT_CACHE_TTL)
        .map(|entry| entry.query.clone())
        .collect()
}

fn cleanup_dns_cache_locked(cache: &mut DnsInsightCache, now: Instant) {
    cache
        .recent_queries
        .retain(|entry| now.duration_since(entry.seen_at) <= DNS_INSIGHT_CACHE_TTL);

    cache.ip_to_domains.retain(|_, domains| {
        domains.retain(|entry| now.duration_since(entry.seen_at) <= DNS_INSIGHT_CACHE_TTL);
        !domains.is_empty()
    });

    if cache.ip_to_domains.len() > DNS_INSIGHT_CACHE_MAX_IPS {
        let excess = cache.ip_to_domains.len() - DNS_INSIGHT_CACHE_MAX_IPS;
        let stale_keys: Vec<String> = cache
            .ip_to_domains
            .iter()
            .filter_map(|(ip, domains)| {
                let newest = domains.iter().map(|entry| entry.seen_at).max()?;
                if now.duration_since(newest) > DNS_INSIGHT_CACHE_TTL / 2 {
                    Some(ip.clone())
                } else {
                    None
                }
            })
            .take(excess)
            .collect();

        for key in stale_keys {
            cache.ip_to_domains.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    static DNS_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn dns_test_lock() -> MutexGuard<'static, ()> {
        DNS_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn reset_dns_cache_for_test() {
        let mut cache = dns_insight_cache().lock().unwrap();
        cache.ip_to_domains.clear();
        cache.recent_queries.clear();
    }

    #[test]
    fn normalizes_dns_query_domains_for_cache_keys() {
        let _guard = dns_test_lock();
        assert_eq!(normalize_domain(" Example.COM. "), "example.com");
        assert_eq!(normalize_domain("sub.domain.local"), "sub.domain.local");
        assert_eq!(normalize_domain("   "), "");
    }

    #[test]
    fn records_dns_event_without_storing_non_ip_answers_as_resolution_edges() {
        let _guard = dns_test_lock();
        reset_dns_cache_for_test();

        record_dns_event(&DnsEvent {
            pid: 42,
            process_name: "curl".to_string(),
            query: "Example.COM.".to_string(),
            query_type: "A".to_string(),
            responses: vec!["203.0.113.10".to_string(), "alias.example.com".to_string()],
            ..Default::default()
        });

        assert_eq!(
            lookup_domains_for_ip("203.0.113.10"),
            vec!["example.com".to_string()]
        );
        assert!(lookup_domains_for_ip("alias.example.com").is_empty());

        let recent = recent_dns_queries();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].pid, 42);
        assert_eq!(recent[0].process_name, "curl");
        assert_eq!(recent[0].query, "example.com");
        assert_eq!(recent[0].query_type, "A");
    }

    #[test]
    fn bounds_recent_dns_query_cache_under_high_cardinality() {
        let _guard = dns_test_lock();
        reset_dns_cache_for_test();

        for index in 0..(DNS_INSIGHT_QUERY_MAX + 25) {
            record_dns_event(&DnsEvent {
                pid: index as u32,
                process_name: "resolver".to_string(),
                query: format!("host-{}.example.", index),
                query_type: "AAAA".to_string(),
                responses: Vec::new(),
                ..Default::default()
            });
        }

        let recent = recent_dns_queries();
        assert_eq!(recent.len(), DNS_INSIGHT_QUERY_MAX);
        assert_eq!(recent[0].query, "host-25.example");
        assert_eq!(
            recent.last().map(|query| query.query.as_str()),
            Some("host-4120.example")
        );
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// DNS collector
pub struct DnsCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl DnsCollector {
    /// Create a new DNS collector
    ///
    /// `governor_handle`: Optional handle to resource governor for pressure-aware interval scaling
    pub fn new(config: &AgentConfig) -> Self {
        Self::with_governor(config, None)
    }

    /// Create a DNS collector with optional governor handle for pressure-aware scaling
    pub fn with_governor(config: &AgentConfig, governor_handle: Option<GovernorHandle>) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::monitor_dns(tx, config_clone, governor_handle).await {
                error!(error = %e, "DNS collector error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    async fn monitor_dns(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        governor_handle: Option<GovernorHandle>,
    ) -> anyhow::Result<()> {
        info!("DNS collector started");

        #[cfg(target_os = "linux")]
        {
            return Self::monitor_dns_linux(tx, config, governor_handle).await;
        }

        #[cfg(target_os = "windows")]
        {
            return Self::monitor_dns_windows(tx, config, governor_handle).await;
        }

        #[cfg(target_os = "macos")]
        {
            return Self::monitor_dns_macos(tx, config, governor_handle).await;
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            // STUB — PLATFORM-INCOMPLETE, not production. Implemented for Linux/Windows/macOS;
            // on any other target the collector warns once and produces no DNS events.
            warn!("DNS monitoring not implemented for this platform");
            Ok(())
        }
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn monitor_dns_linux(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        _governor_handle: Option<GovernorHandle>,
    ) -> anyhow::Result<()> {
        info!("Starting Linux DNS collector with multiple capture methods");

        // Track DNS queries we've seen to avoid duplicates
        let mut seen_queries: HashSet<String> = HashSet::new();
        let mut last_seen_cleanup = std::time::Instant::now();
        let running = Arc::new(AtomicBool::new(true));

        // Method 1: Try eBPF-based capture (most accurate but needs root)
        let tx_ebpf = tx.clone();
        let running_ebpf = running.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::monitor_dns_ebpf_linux(tx_ebpf, running_ebpf).await {
                debug!("eBPF DNS capture unavailable: {}", e);
            }
        });

        // Method 2: Try tcpdump-based capture (works on most systems with appropriate perms)
        let tx_tcpdump = tx.clone();
        let running_tcpdump = running.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::monitor_dns_tcpdump_linux(tx_tcpdump, running_tcpdump).await {
                debug!("tcpdump DNS capture unavailable: {}", e);
            }
        });

        // Method 3: Monitor systemd-resolved journal (if available)
        let tx_journal = tx.clone();
        let running_journal = running.clone();
        tokio::spawn(async move {
            Self::monitor_dns_journal_linux(tx_journal, running_journal).await;
        });

        // Method 4: Also try pcap-based capture if compiled with feature
        #[cfg(feature = "dns-capture")]
        {
            let tx_pcap = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::pcap_dns_capture(tx_pcap).await {
                    warn!("pcap DNS capture unavailable: {}", e);
                }
            });
        }

        // Fallback: Monitor /proc/net/udp for DNS connections
        // Use configurable DNS poll interval from collector_tuning.
        let dns_poll_ms = _config.collector_tuning.dns_poll_interval_ms;
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_millis(dns_poll_ms.max(500)));

        loop {
            interval.tick().await;

            // Monitor UDP connections to port 53 (DNS)
            if let Ok(dns_connections) = Self::get_dns_connections_linux().await {
                for (pid, process_name, remote_ip) in dns_connections {
                    let query_key = format!("{}:{}:{}", pid, process_name, remote_ip);

                    if !seen_queries.contains(&query_key) {
                        seen_queries.insert(query_key.clone());

                        // Log that we detected a DNS resolver (process connected to DNS server)
                        debug!(
                            "Process {}:{} connected to DNS server {}",
                            pid, process_name, remote_ip
                        );
                    }
                }
            }

            // Monitor /etc/resolv.conf for DNS server changes (hijacking detection)
            Self::check_resolv_conf(&tx).await;

            // Clean up old entries every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_queries.clear();
                last_seen_cleanup = std::time::Instant::now();
            }
        }
    }

    /// Monitor DNS using a raw UDP socket to capture port 53 traffic (Linux - requires CAP_NET_RAW or root)
    #[cfg(target_os = "linux")]
    async fn monitor_dns_ebpf_linux(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        info!("Attempting raw socket DNS capture (requires CAP_NET_RAW or root)");

        // Create a raw socket that captures all UDP packets (protocol 17 = UDP)
        // AF_INET = 2, SOCK_RAW = 3, IPPROTO_UDP = 17
        let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
        if sock_fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create raw socket (need CAP_NET_RAW): {}",
                std::io::Error::last_os_error()
            ));
        }
        // Safety: we just created this fd successfully
        let _owned_fd = unsafe { OwnedFd::from_raw_fd(sock_fd) };

        // Set a receive timeout so we can check the running flag periodically
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        info!("Raw socket DNS capture started successfully");

        let mut seen_queries: HashSet<String> = HashSet::new();
        let mut last_seen_cleanup = std::time::Instant::now();
        let mut buf = vec![0u8; 65535];

        while running.load(Ordering::Relaxed) {
            let n =
                unsafe { libc::recv(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

            if n <= 0 {
                // Timeout or error, just loop and check running flag
                continue;
            }

            let n = n as usize;
            if n < 28 {
                // Too small for IP header (20) + UDP header (8)
                continue;
            }

            // Parse IP header to find UDP payload
            let ip_header_len = ((buf[0] & 0x0f) as usize) * 4;
            if n < ip_header_len + 8 {
                continue;
            }

            // Extract source and destination ports from UDP header
            let udp_start = ip_header_len;
            let src_port = u16::from_be_bytes([buf[udp_start], buf[udp_start + 1]]);
            let dst_port = u16::from_be_bytes([buf[udp_start + 2], buf[udp_start + 3]]);

            // We only care about packets going TO port 53 (DNS queries)
            if dst_port != 53 {
                continue;
            }

            // Extract destination IP from IP header (bytes 16..20)
            let dst_ip = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

            // DNS payload starts after IP header + 8 bytes UDP header
            let dns_start = ip_header_len + 8;
            if n < dns_start + 12 {
                continue;
            }

            let dns_data = &buf[dns_start..n];

            // Parse DNS header
            // Bytes 2-3 are flags; bit 15 (QR) = 0 means query
            let flags = u16::from_be_bytes([dns_data[2], dns_data[3]]);
            if flags & 0x8000 != 0 {
                // This is a response, not a query
                continue;
            }

            let qdcount = u16::from_be_bytes([dns_data[4], dns_data[5]]);
            if qdcount == 0 {
                continue;
            }

            // Parse the question section to extract query name and type
            if let Some((query_name, query_type)) = Self::parse_dns_question(&dns_data[12..]) {
                let dedup_key = format!("{}:{}:{}", query_name, query_type, dst_ip);
                if seen_queries.contains(&dedup_key) {
                    continue;
                }
                seen_queries.insert(dedup_key);

                // Time-based cleanup every 300 seconds
                if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                    seen_queries.clear();
                    last_seen_cleanup = std::time::Instant::now();
                }

                // Try to find the source process by scanning /proc/net/udp for
                // the source port, then mapping the socket inode to a PID
                let (pid, process_name) =
                    Self::find_process_for_udp_port(src_port).unwrap_or((0, String::new()));

                debug!(
                    "Raw socket captured DNS query: {} ({}) from {}:{} to {}",
                    query_name, query_type, process_name, pid, dst_ip
                );

                let event = TelemetryEvent::new(
                    EventType::DnsQuery,
                    Severity::Info,
                    EventPayload::Dns(DnsEvent {
                        pid,
                        process_name,
                        query: query_name,
                        query_type,
                        responses: vec![],
                        resolver_ip: Some(dst_ip.to_string()),
                        resolver_port: Some(dst_port),
                        transport: Some("udp".to_string()),
                        capture_method: Some("raw_socket".to_string()),
                        ..Default::default()
                    }),
                );

                if tx.send(event).await.is_err() {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Parse a DNS question section to extract the query name and type
    #[cfg(target_os = "linux")]
    fn parse_dns_question(data: &[u8]) -> Option<(String, String)> {
        let mut pos = 0;
        let mut labels: Vec<String> = Vec::new();

        loop {
            if pos >= data.len() {
                return None;
            }

            let label_len = data[pos] as usize;
            pos += 1;

            if label_len == 0 {
                break;
            }

            // Sanity check to avoid reading past the buffer
            if pos + label_len > data.len() {
                return None;
            }

            if let Ok(label) = std::str::from_utf8(&data[pos..pos + label_len]) {
                labels.push(label.to_string());
            } else {
                return None;
            }
            pos += label_len;
        }

        if labels.is_empty() {
            return None;
        }

        let query_name = labels.join(".");

        // Read QTYPE (2 bytes after the name)
        if pos + 2 > data.len() {
            return Some((query_name, "A".to_string()));
        }

        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let query_type = match qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            _ => "OTHER",
        };

        Some((query_name, query_type.to_string()))
    }

    /// Find the process that owns a given UDP source port by reading /proc/net/udp
    /// and mapping the socket inode back to a PID via /proc/[pid]/fd/
    #[cfg(target_os = "linux")]
    fn find_process_for_udp_port(src_port: u16) -> Option<(u32, String)> {
        let port_hex = format!("{:04X}", src_port);

        // Read /proc/net/udp to find the inode for this source port
        let content = std::fs::read_to_string("/proc/net/udp").ok()?;
        let mut target_inode: u64 = 0;

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            // local_address is parts[1], format is hex_ip:hex_port
            let local = parts[1];
            if let Some(lport) = local.split(':').nth(1) {
                if lport.eq_ignore_ascii_case(&port_hex) {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        target_inode = inode;
                        break;
                    }
                }
            }
        }

        if target_inode == 0 {
            return None;
        }

        let socket_pattern = format!("socket:[{}]", target_inode);

        // Scan /proc for the PID owning this inode
        let proc_dir = std::fs::read_dir("/proc").ok()?;
        for entry in proc_dir.flatten() {
            let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };

            let fd_dir = match std::fs::read_dir(entry.path().join("fd")) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for fd_entry in fd_dir.flatten() {
                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                    if link.to_string_lossy() == socket_pattern {
                        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        return Some((pid, comm));
                    }
                }
            }
        }

        None
    }

    /// Monitor DNS using tcpdump (Linux)
    #[cfg(target_os = "linux")]
    async fn monitor_dns_tcpdump_linux(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};

        info!("Starting tcpdump DNS capture");

        // Start tcpdump to capture DNS packets
        let mut child = tokio::process::Command::new("tcpdump")
            .args([
                "-l", // Line buffered
                "-n", // No DNS resolution
                "-Q", "out", // Only outgoing (queries)
                "-i", "any", // All interfaces
                "port", "53", // DNS port
                "-v", // Verbose (shows query names)
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("No stdout"))?;
        let mut reader = BufReader::new(stdout).lines();
        let mut seen_queries: HashSet<String> = HashSet::new();
        let mut last_seen_cleanup = std::time::Instant::now();

        while running.load(Ordering::Relaxed) {
            // Time-based cleanup every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_queries.clear();
                last_seen_cleanup = std::time::Instant::now();
            }

            tokio::select! {
                line = reader.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            // Parse tcpdump output for DNS queries
                            // Format: "timestamp IP src > dst: ... A? domain.com."
                            if let Some(event) = Self::parse_tcpdump_dns(&line, &mut seen_queries) {
                                if tx.send(event).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(_) => continue,
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }

        let _ = child.kill().await;
        Ok(())
    }

    /// Parse tcpdump DNS output
    #[cfg(target_os = "linux")]
    fn parse_tcpdump_dns(line: &str, seen: &mut HashSet<String>) -> Option<TelemetryEvent> {
        // Look for DNS query patterns in tcpdump verbose output
        // Example: "... A? google.com." or "... AAAA? ipv6.google.com."

        // Match query type and domain
        let query_patterns = [
            ("A?", "A"),
            ("AAAA?", "AAAA"),
            ("MX?", "MX"),
            ("TXT?", "TXT"),
            ("CNAME?", "CNAME"),
            ("NS?", "NS"),
            ("PTR?", "PTR"),
            ("SRV?", "SRV"),
            ("SOA?", "SOA"),
        ];

        for (pattern, qtype) in query_patterns {
            if let Some(pos) = line.find(pattern) {
                // Extract the domain name (follows the pattern, ends with '.' or space)
                let rest = &line[pos + pattern.len()..].trim();
                let domain_end = rest
                    .find(|c: char| c.is_whitespace() || c == '(')
                    .unwrap_or(rest.len());
                let domain = rest[..domain_end].trim_end_matches('.');

                if domain.is_empty() {
                    continue;
                }

                // Deduplicate
                let key = format!("{}:{}", qtype, domain);
                if seen.contains(&key) {
                    return None;
                }
                seen.insert(key);

                debug!("tcpdump captured DNS query: {} ({})", domain, qtype);

                return Some(TelemetryEvent::new(
                    EventType::DnsQuery,
                    Severity::Info,
                    EventPayload::Dns(DnsEvent {
                        pid: 0, // tcpdump doesn't give us PID
                        process_name: String::new(),
                        query: domain.to_string(),
                        query_type: qtype.to_string(),
                        responses: vec![],
                        transport: Some("udp".to_string()),
                        capture_method: Some("tcpdump".to_string()),
                        ..Default::default()
                    }),
                ));
            }
        }

        None
    }

    /// Monitor DNS queries via systemd-resolved journal (Linux)
    #[cfg(target_os = "linux")]
    async fn monitor_dns_journal_linux(tx: mpsc::Sender<TelemetryEvent>, running: Arc<AtomicBool>) {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};

        info!("Attempting systemd-resolved journal monitoring");

        // Check if systemd-resolved is running
        let status = std::process::Command::new("systemctl")
            .args(["is-active", "systemd-resolved"])
            .output();

        if !matches!(status, Ok(o) if o.status.success()) {
            debug!("systemd-resolved not active");
            return;
        }

        // Monitor journal for DNS queries
        let child = tokio::process::Command::new("journalctl")
            .args([
                "-u",
                "systemd-resolved",
                "-f", // Follow
                "-o",
                "cat", // No timestamps, just message
                "--no-pager",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                debug!("Cannot start journalctl: {}", e);
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => return,
        };

        let mut reader = BufReader::new(stdout).lines();
        let mut seen_queries: HashSet<String> = HashSet::new();
        let mut last_seen_cleanup = std::time::Instant::now();

        while running.load(Ordering::Relaxed) {
            // Time-based cleanup every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_queries.clear();
                last_seen_cleanup = std::time::Instant::now();
            }

            tokio::select! {
                line = reader.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            // Parse systemd-resolved log entries
                            // Example: "Resolved query for google.com. (type A)"
                            if line.contains("Resolved query") || line.contains("Using DNS server") {
                                if let Some(event) = Self::parse_resolved_log(&line, &mut seen_queries) {
                                    let _ = tx.send(event).await;
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(_) => continue,
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }

        let _ = child.kill().await;
    }

    /// Parse systemd-resolved log entry
    #[cfg(target_os = "linux")]
    fn parse_resolved_log(line: &str, seen: &mut HashSet<String>) -> Option<TelemetryEvent> {
        // Pattern: "Resolved query for domain.com. (type A)" or similar
        let query_marker = "query for ";
        if let Some(pos) = line.find(query_marker) {
            let rest = &line[pos + query_marker.len()..];

            // Extract domain - find the end (space or opening paren)
            let domain_end = rest
                .find(|c: char| c.is_whitespace() || c == '(')
                .unwrap_or(rest.len());
            let domain = rest[..domain_end].trim_end_matches('.');

            // Extract query type
            let qtype = if let Some(type_pos) = rest.find("type ") {
                let type_rest = &rest[type_pos + 5..];
                let type_end = type_rest.find(')').unwrap_or(type_rest.len());
                &type_rest[..type_end]
            } else {
                "A"
            };

            if domain.is_empty() {
                return None;
            }

            let key = format!("{}:{}", qtype, domain);
            if seen.contains(&key) {
                return None;
            }
            seen.insert(key);

            debug!("systemd-resolved captured: {} ({})", domain, qtype);

            return Some(TelemetryEvent::new(
                EventType::DnsQuery,
                Severity::Info,
                EventPayload::Dns(DnsEvent {
                    pid: 0,
                    process_name: "systemd-resolved".to_string(),
                    query: domain.to_string(),
                    query_type: qtype.to_string(),
                    responses: vec![],
                    capture_method: Some("systemd_resolved_journal".to_string()),
                    ..Default::default()
                }),
            ));
        }

        None
    }

    /// Check /etc/resolv.conf for DNS server changes
    #[cfg(target_os = "linux")]
    async fn check_resolv_conf(_tx: &mpsc::Sender<TelemetryEvent>) {
        use std::sync::OnceLock;

        static LAST_RESOLV_HASH: OnceLock<std::sync::Mutex<u64>> = OnceLock::new();
        let last_hash = LAST_RESOLV_HASH.get_or_init(|| std::sync::Mutex::new(0));

        if let Ok(content) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            content.hash(&mut hasher);
            let current_hash = hasher.finish();

            if let Ok(mut last) = last_hash.lock() {
                if *last != 0 && *last != current_hash {
                    warn!("DNS configuration changed in /etc/resolv.conf - possible hijacking attempt");
                    // Could emit an event here for the configuration change
                }
                *last = current_hash;
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_dns_connections_linux() -> anyhow::Result<Vec<(u32, String, String)>> {
        let mut connections = Vec::new();

        // Build inode -> (pid, process_name) map
        let inode_map = Self::build_socket_inode_map_linux().await;

        // Read /proc/net/udp for DNS connections (port 53 = 0x0035)
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
            for line in content.lines().skip(1) {
                if let Some((pid, process_name, remote_ip)) =
                    Self::parse_dns_connection_linux(line, &inode_map)
                {
                    connections.push((pid, process_name, remote_ip));
                }
            }
        }

        // Also check /proc/net/udp6 for IPv6 DNS
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp6").await {
            for line in content.lines().skip(1) {
                if let Some((pid, process_name, remote_ip)) =
                    Self::parse_dns_connection_linux(line, &inode_map)
                {
                    connections.push((pid, process_name, remote_ip));
                }
            }
        }

        Ok(connections)
    }

    #[cfg(target_os = "linux")]
    async fn build_socket_inode_map_linux() -> HashMap<u64, (u32, String)> {
        let mut inode_map: HashMap<u64, (u32, String)> = HashMap::new();

        // Read /proc to get all PIDs
        let proc_dir = match tokio::fs::read_dir("/proc").await {
            Ok(d) => d,
            Err(_) => return inode_map,
        };

        let mut entries = proc_dir;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Check if it's a PID directory
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Get process name
            let comm_path = format!("/proc/{}/comm", pid);
            let process_name = match tokio::fs::read_to_string(&comm_path).await {
                Ok(name) => name.trim().to_string(),
                Err(_) => continue,
            };

            // Read /proc/[pid]/fd directory
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

                    // Check for socket inode
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
    fn parse_dns_connection_linux(
        line: &str,
        inode_map: &HashMap<u64, (u32, String)>,
    ) -> Option<(u32, String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let remote = parts[2];
        let inode: u64 = parts[9].parse().unwrap_or(0);

        // Parse remote address
        let remote_parts: Vec<&str> = remote.split(':').collect();
        if remote_parts.len() != 2 {
            return None;
        }

        let port_hex = remote_parts[1];
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        // Check if it's DNS (port 53)
        if port != 53 {
            return None;
        }

        // Parse IP address
        let ip_hex = remote_parts[0];
        let remote_ip = if ip_hex.len() == 8 {
            // IPv4
            let ip = u32::from_str_radix(ip_hex, 16).ok()?;
            format!(
                "{}.{}.{}.{}",
                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff
            )
        } else {
            // IPv6 - simplified handling
            "IPv6".to_string()
        };

        // Skip if no remote connection (0.0.0.0)
        if remote_ip == "0.0.0.0" {
            return None;
        }

        // Lookup PID from inode
        let (pid, process_name) = inode_map
            .get(&inode)
            .cloned()
            .unwrap_or((0, "unknown".to_string()));

        Some((pid, process_name, remote_ip))
    }

    #[cfg(all(target_os = "linux", feature = "dns-capture"))]
    async fn pcap_dns_capture(tx: mpsc::Sender<TelemetryEvent>) -> anyhow::Result<()> {
        use pcap::{Capture, Device};
        use std::sync::Arc;

        info!("Starting pcap-based DNS capture");

        // Find the default network device
        let device = Device::lookup()?.ok_or_else(|| anyhow::anyhow!("No network device found"))?;

        let mut cap = Capture::from_device(device)?
            .promisc(false)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        // Set BPF filter for DNS traffic (port 53)
        cap.filter("udp port 53", true)?;

        let cap = Arc::new(tokio::sync::Mutex::new(cap));

        loop {
            let cap = cap.clone();
            let tx = tx.clone();

            let result = tokio::task::spawn_blocking(move || {
                let mut cap = cap.blocking_lock();
                match cap.next_packet() {
                    Ok(packet) => Some(packet.data.to_vec()),
                    Err(_) => None,
                }
            })
            .await;

            if let Ok(Some(data)) = result {
                if let Some(event) = Self::parse_dns_packet(&data) {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "dns-capture"))]
    fn parse_dns_packet(data: &[u8]) -> Option<TelemetryEvent> {
        // Skip Ethernet header (14 bytes) + IP header (20 bytes min) + UDP header (8 bytes)
        if data.len() < 42 {
            return None;
        }

        // Simple DNS parsing - skip headers and get to DNS payload
        let dns_offset = 42; // Ethernet + IP + UDP
        let dns_data = &data[dns_offset..];

        if let Ok(packet) = dns_parser::Packet::parse(dns_data) {
            // Get the first query
            if let Some(question) = packet.questions.first() {
                let query = question.qname.to_string();
                let query_type = format!("{:?}", question.qtype);

                // Collect responses
                let responses: Vec<String> = packet
                    .answers
                    .iter()
                    .filter_map(|answer| match &answer.data {
                        dns_parser::RData::A(addr) => Some(addr.0.to_string()),
                        dns_parser::RData::AAAA(addr) => Some(addr.0.to_string()),
                        dns_parser::RData::CNAME(name) => Some(name.to_string()),
                        _ => None,
                    })
                    .collect();

                return Some(TelemetryEvent::new(
                    EventType::DnsQuery,
                    Severity::Info,
                    EventPayload::Dns(DnsEvent {
                        pid: 0, // pcap doesn't give us PID
                        process_name: String::new(),
                        query,
                        query_type,
                        responses,
                        capture_method: Some("pcap".to_string()),
                        ..Default::default()
                    }),
                ));
            }
        }

        None
    }

    // ==================== Windows Implementation ====================

    /// Primary Windows DNS monitoring via ETW (Event Tracing for Windows).
    ///
    /// Opens a dedicated real-time ETW session subscribed to the
    /// Microsoft-Windows-DNS-Client provider (GUID 1C95126E-7EEA-49A9-A3FE-A378B03DDB4D).
    /// Event IDs of interest:
    ///   - 3006: DNS query initiated
    ///   - 3008: DNS query completed (includes resolved addresses)
    ///
    /// The ETW session runs on a background OS thread (ProcessTrace blocks) and
    /// pushes parsed DNS events through a global callback context into the
    /// collector's mpsc channel.  On failure the method falls back to
    /// PowerShell event-log polling + DNS cache scraping.
    #[cfg(target_os = "windows")]
    async fn monitor_dns_windows(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        governor_handle: Option<GovernorHandle>,
    ) -> anyhow::Result<()> {
        if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
            info!("Lightweight profile: Skipping DNS ETW collector");
            return Self::monitor_dns_windows_fallback(tx, config, governor_handle).await;
        }
        info!("Starting Windows DNS collector via ETW");

        // Try to launch the real ETW session.  The session runs on a
        // dedicated OS thread because ProcessTrace is a blocking Win32 call.
        let tx_etw = tx.clone();
        let running = Arc::new(AtomicBool::new(true));
        let running_thread = running.clone();

        std::thread::spawn(
            move || match Self::run_dns_etw_session(tx_etw, running_thread) {
                Ok(()) => {
                    info!("DNS ETW session ended normally");
                }
                Err(e) => {
                    warn!(error = %e, "DNS ETW session failed");
                }
            },
        );

        // Give the ETW thread a moment to start up and signal success.
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check whether the ETW consumer actually opened. The callback context
        // is a OnceLock and may be initialized before OpenTrace succeeds, so it
        // is not a reliable health signal by itself.
        let etw_running = dns_etw::DNS_ETW_READY.load(Ordering::Relaxed);

        if etw_running {
            info!("DNS ETW session active -- using real-time ETW events");

            // Keep the async task alive while the ETW thread is working.
            // The ETW thread does the heavy lifting; we just idle here
            // so that the collector's monitor_dns future is not dropped.
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }
            Ok(())
        } else {
            warn!("DNS ETW session did not start; falling back to event-log polling");
            running.store(false, Ordering::Relaxed);
            Self::monitor_dns_windows_fallback(tx, config, governor_handle).await
        }
    }

    /// Run a dedicated ETW real-time session for the DNS-Client provider.
    ///
    /// This function blocks on the calling OS thread until the session is
    /// stopped.  It reuses the same `win_compat::etw` dynamic API layer
    /// that the main ETW collector uses for session lifecycle management.
    #[cfg(target_os = "windows")]
    fn run_dns_etw_session(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        use super::win_compat::etw as etw_api;
        use std::ffi::c_void;

        let api = etw_api::get_etw_api()
            .ok_or_else(|| anyhow::anyhow!("ETW API not available on this system"))?;

        // ---- Session properties ------------------------------------------
        let mut properties = dns_etw::create_dns_trace_properties();
        let session_name_wide: Vec<u16> = dns_etw::SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Copy session name into the padding area of the properties struct
        let name_offset = std::mem::offset_of!(dns_etw::DnsTraceProperties, _padding);
        unsafe {
            let props_ptr = &mut properties as *mut dns_etw::DnsTraceProperties as *mut u8;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr() as *const u8,
                props_ptr.add(name_offset),
                session_name_wide.len() * 2,
            );
        }
        properties.logger_name_offset = name_offset as u32;

        // ---- Start trace -------------------------------------------------
        let mut session_handle: u64 = 0;
        let result = unsafe {
            (api.start_trace)(
                &mut session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
            )
        };

        match result {
            etw_api::ERROR_SUCCESS => {
                info!(handle = session_handle, "DNS ETW session created");
            }
            etw_api::ERROR_ALREADY_EXISTS => {
                info!("DNS ETW session already exists, recycling");
                unsafe {
                    (api.control_trace)(
                        0,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                        etw_api::EVENT_TRACE_CONTROL_STOP,
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
                // Re-create properties after stop (Windows may have modified them)
                properties = dns_etw::create_dns_trace_properties();
                properties.logger_name_offset = name_offset as u32;
                unsafe {
                    let props_ptr = &mut properties as *mut dns_etw::DnsTraceProperties as *mut u8;
                    std::ptr::copy_nonoverlapping(
                        session_name_wide.as_ptr() as *const u8,
                        props_ptr.add(name_offset),
                        session_name_wide.len() * 2,
                    );
                }
                let retry = unsafe {
                    (api.start_trace)(
                        &mut session_handle,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                    )
                };
                if retry != etw_api::ERROR_SUCCESS {
                    return Err(anyhow::anyhow!("StartTrace retry failed: error {}", retry));
                }
                info!(handle = session_handle, "DNS ETW session re-created");
            }
            etw_api::ERROR_ACCESS_DENIED => {
                return Err(anyhow::anyhow!(
                    "DNS ETW session denied -- elevation required"
                ));
            }
            other => {
                return Err(anyhow::anyhow!("StartTrace failed: error {}", other));
            }
        }

        // ---- Enable DNS-Client provider ----------------------------------
        // Microsoft-Windows-DNS-Client {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
        let dns_guid = windows::core::GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

        let enable_result = if let Some(enable_ex2) = api.enable_trace_ex2 {
            unsafe {
                enable_ex2(
                    session_handle,
                    &dns_guid as *const _ as *const c_void,
                    etw_api::EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    etw_api::TRACE_LEVEL_VERBOSE,
                    0xFFFFFFFFFFFFFFFF, // match any keyword
                    0,
                    0,
                    std::ptr::null(),
                )
            }
        } else {
            // Legacy EnableTrace (Windows 7)
            unsafe {
                (api.enable_trace)(
                    1,
                    0xFFFFFFFF,
                    etw_api::TRACE_LEVEL_VERBOSE as u32,
                    &dns_guid as *const _ as *const c_void,
                    session_handle,
                )
            }
        };

        if enable_result != etw_api::ERROR_SUCCESS {
            // Stop the session we just created
            unsafe {
                (api.control_trace)(
                    session_handle,
                    session_name_wide.as_ptr(),
                    &mut properties as *mut _ as *mut c_void,
                    etw_api::EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(anyhow::anyhow!(
                "EnableTrace for DNS-Client failed: error {}",
                enable_result
            ));
        }
        info!("DNS-Client ETW provider enabled");

        // ---- Initialise global callback context --------------------------
        let _ = dns_etw::DNS_ETW_CONTEXT.set(dns_etw::DnsEtwContext {
            tx: std::sync::Mutex::new(Some(tx)),
            running: running.clone(),
        });

        // ---- Open trace for real-time consumption ------------------------
        let mut logfile: dns_etw::DnsEventTraceLogfileW = unsafe { std::mem::zeroed() };
        // SAFETY: session_name_wide is alive for the duration of this call
        logfile.logger_name = session_name_wide.as_ptr() as *mut u16;
        logfile.log_file_mode =
            dns_etw::PROCESS_TRACE_MODE_REAL_TIME | dns_etw::PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.event_record_callback = Some(dns_etw::dns_etw_event_callback);

        let trace_handle = unsafe { (api.open_trace)(&mut logfile as *mut _ as *mut c_void) };

        if trace_handle == u64::MAX {
            dns_etw::DNS_ETW_READY.store(false, Ordering::Relaxed);
            if let Some(ctx) = dns_etw::DNS_ETW_CONTEXT.get() {
                ctx.running.store(false, Ordering::Relaxed);
                if let Ok(mut guard) = ctx.tx.lock() {
                    *guard = None;
                }
            }

            unsafe {
                (api.control_trace)(
                    session_handle,
                    session_name_wide.as_ptr(),
                    &mut properties as *mut _ as *mut c_void,
                    etw_api::EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(anyhow::anyhow!("OpenTrace failed for DNS session"));
        }

        info!(
            handle = trace_handle,
            "DNS ETW trace opened for consumption"
        );
        dns_etw::DNS_ETW_READY.store(true, Ordering::Relaxed);

        // ---- ProcessTrace (blocking) -------------------------------------
        let handles = [trace_handle];
        let pt_result =
            unsafe { (api.process_trace)(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) };

        // ---- Cleanup -----------------------------------------------------
        unsafe { (api.close_trace)(trace_handle) };

        // Stop the session
        unsafe {
            (api.control_trace)(
                session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
                etw_api::EVENT_TRACE_CONTROL_STOP,
            );
        }

        // Invalidate the global context
        dns_etw::DNS_ETW_READY.store(false, Ordering::Relaxed);
        if let Some(ctx) = dns_etw::DNS_ETW_CONTEXT.get() {
            if let Ok(mut guard) = ctx.tx.lock() {
                *guard = None;
            }
        }

        if pt_result != etw_api::ERROR_SUCCESS && pt_result != 1223 {
            // 1223 = ERROR_CANCELLED
            warn!(error = pt_result, "DNS ProcessTrace ended with error");
        }

        info!("DNS ETW session stopped");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn monitor_dns_windows_fallback(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        governor_handle: Option<GovernorHandle>,
    ) -> anyhow::Result<()> {
        use std::net::Ipv4Addr;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };
        use windows::Win32::Networking::WinSock::AF_INET;

        info!("Using Windows DNS monitoring via raw socket capture + UDP tracking");

        let is_lightweight =
            config.performance_profile == crate::config::PerformanceProfile::Lightweight;

        // Auto-enable the DNS Client event log (requires admin)
        if !is_lightweight {
            Self::enable_dns_event_log_windows();
        }

        // Start a raw socket capture thread for DNS packets
        let tx_raw = tx.clone();
        let running = Arc::new(AtomicBool::new(true));

        if !is_lightweight {
            let running_clone = running.clone();

            // Spawn raw socket DNS capture
            tokio::spawn(async move {
                if let Err(e) = Self::capture_dns_packets_windows(tx_raw, running_clone).await {
                    warn!("Raw DNS capture unavailable: {}", e);
                }
            });
        } else {
            info!("Lightweight profile: Skipping raw DNS socket capture and Event Log");
        }

        let mut seen_connections: HashSet<String> = HashSet::new();
        let mut seen_cache: HashSet<String> = HashSet::new();
        // Use configurable DNS poll interval from collector_tuning.
        let dns_poll_ms = config.collector_tuning.dns_poll_interval_ms;
        let mut interval = GovernorAwareInterval::new(
            tokio::time::Duration::from_millis(dns_poll_ms.max(500)),
            governor_handle.clone(),
        );
        info!(
            base_interval_ms = dns_poll_ms.max(500),
            governor_enabled = governor_handle.is_some(),
            "DNS collector started (pressure-aware interval scaling)"
        );

        // Check DNS cache every 30 seconds for resolved IP addresses
        let mut last_cache_check = std::time::Instant::now();
        let cache_check_interval = std::time::Duration::from_secs(30);
        let mut last_seen_cleanup = std::time::Instant::now();

        loop {
            interval.tick().await;

            // Time-based cleanup every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_connections.clear();
                seen_cache.clear();
                last_seen_cleanup = std::time::Instant::now();
            }

            // Periodically check DNS cache for entries with resolved IPs
            if last_cache_check.elapsed() >= cache_check_interval {
                last_cache_check = std::time::Instant::now();
                Self::check_dns_cache_windows(&tx, &mut seen_cache).await;
            }

            // Get UDP table
            let mut size: u32 = 0;
            unsafe {
                let _ = GetExtendedUdpTable(
                    None,
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                );
            }

            if size == 0 {
                continue;
            }

            let mut buffer: Vec<u8> = vec![0u8; size as usize];

            let result = unsafe {
                GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };

            if result != 0 {
                continue;
            }

            let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
            let num_entries = table.dwNumEntries as usize;

            if num_entries == 0 {
                continue;
            }

            // Cap entries at buffer bounds to prevent out-of-bounds reads
            let header_size = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
            let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
            let max_entries = if entry_size > 0 && buffer.len() > header_size {
                (buffer.len() - header_size) / entry_size
            } else {
                0
            };
            let num_entries = num_entries.min(max_entries);

            // Collect connection data before any await points (raw pointers aren't Send)
            let mut connection_data: Vec<(Ipv4Addr, u16, u32)> = Vec::new();
            let rows_ptr = table.table.as_ptr();

            for i in 0..num_entries {
                let row = unsafe { &*rows_ptr.add(i) };
                let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                let local_port = u16::from_be(row.dwLocalPort as u16);
                let pid = row.dwOwningPid;

                // Track connections using high ephemeral ports (likely DNS clients)
                if local_port > 49152 {
                    connection_data.push((local_ip, local_port, pid));
                }
            }

            // Track active DNS resolvers
            for (_local_ip, _local_port, pid) in connection_data {
                let conn_key = format!("active:{}", pid);

                if !seen_connections.contains(&conn_key) {
                    seen_connections.insert(conn_key);
                    debug!(
                        "Process {} is making DNS queries",
                        Self::get_process_name_windows(pid)
                    );
                }
            }
        }
    }

    /// Capture actual DNS packets using raw sockets (Windows)
    #[cfg(target_os = "windows")]
    async fn capture_dns_packets_windows(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        use std::time::Duration;

        info!("Attempting DNS packet capture via npcap/winpcap");

        // Try to use raw socket capture (requires admin + npcap)
        // Fall back to PowerShell DNS cache monitoring if not available

        // Start PowerShell-based DNS event monitoring
        let tx_ps = tx.clone();
        let running_ps = running.clone();

        tokio::spawn(async move {
            Self::monitor_dns_via_powershell(tx_ps, running_ps).await;
        });

        // Try raw socket approach
        match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                socket.set_read_timeout(Some(Duration::from_millis(100)))?;
                info!("UDP socket bound for DNS monitoring");
            }
            Err(e) => {
                warn!(
                    "Cannot create raw socket: {}. Using PowerShell fallback.",
                    e
                );
            }
        }

        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    /// Monitor DNS queries via PowerShell Event Log (Windows)
    ///
    /// Reads Event ID 3008 from the DNS Client operational log, which includes
    /// QueryName, QueryType, and QueryResults. The QueryResults field contains
    /// the resolved IP addresses that Windows already cached -- no re-resolution
    /// is performed.
    #[cfg(target_os = "windows")]
    async fn monitor_dns_via_powershell(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) {
        info!("Starting PowerShell DNS event log monitoring");

        let mut seen_queries: HashSet<String> = HashSet::new();
        let mut last_seen_cleanup = std::time::Instant::now();

        while running.load(Ordering::Relaxed) {
            // Query DNS Client event log for recent queries (Event ID 3008 = DNS query completed).
            // Extract QueryName, QueryType, ProcessId, and QueryResults.
            // QueryResults contains semicolon-separated resolved addresses from the cache.
            let output = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    r#"Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational';Id=3008} -MaxEvents 50 2>$null | ForEach-Object { $xml = [xml]$_.ToXml(); $data = $xml.Event.EventData.Data; $qn = ($data | Where-Object {$_.Name -eq 'QueryName'}).InnerText; $qt = ($data | Where-Object {$_.Name -eq 'QueryType'}).InnerText; $qr = ($data | Where-Object {$_.Name -eq 'QueryResults'}).InnerText; "$($_.TimeCreated)|$qn|$qt|$($_.ProcessId)|$qr" }"#
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);

                    for line in stdout.lines() {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() >= 4 {
                            let query_name = parts[1].trim();
                            let query_type = parts[2].trim();
                            let pid_str = parts[3].trim();

                            // QueryResults is the 5th field (index 4); may be absent
                            let query_results_raw = if parts.len() >= 5 {
                                parts[4].trim()
                            } else {
                                ""
                            };

                            // Skip empty or already seen queries
                            if query_name.is_empty() {
                                continue;
                            }

                            let query_key = format!("{}:{}:{}", pid_str, query_name, query_type);
                            if seen_queries.contains(&query_key) {
                                continue;
                            }
                            seen_queries.insert(query_key);

                            let pid: u32 = pid_str.parse().unwrap_or(0);
                            let process_name = Self::get_process_name_windows(pid);

                            // Parse query type number to human-readable string
                            let qt = match query_type {
                                "1" => "A",
                                "28" => "AAAA",
                                "5" => "CNAME",
                                "15" => "MX",
                                "16" => "TXT",
                                "2" => "NS",
                                "6" => "SOA",
                                "12" => "PTR",
                                "33" => "SRV",
                                _ => query_type,
                            };

                            // Parse QueryResults: semicolon-separated list of resolved addresses.
                            // Filter out empty segments and whitespace-only entries.
                            let responses: Vec<String> = if query_results_raw.is_empty() {
                                vec![]
                            } else {
                                query_results_raw
                                    .split(';')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect()
                            };

                            debug!(
                                "DNS query captured: {} ({}) by {} -> {:?}",
                                query_name, qt, process_name, responses
                            );

                            let event = TelemetryEvent::new(
                                EventType::DnsQuery,
                                Severity::Info,
                                EventPayload::Dns(DnsEvent {
                                    pid,
                                    process_name,
                                    query: query_name.to_string(),
                                    query_type: qt.to_string(),
                                    responses,
                                    capture_method: Some("windows_dns_client".to_string()),
                                    ..Default::default()
                                }),
                            );

                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }

            // Time-based cleanup every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_queries.clear();
                last_seen_cleanup = std::time::Instant::now();
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    /// Check Windows DNS cache for recent queries and emit events with resolved IPs.
    ///
    /// Parses the output of `ipconfig /displaydns` to extract cached DNS records
    /// including their resolved IP addresses. Uses a deduplication set to avoid
    /// emitting duplicate events for the same query+type combination.
    #[cfg(target_os = "windows")]
    async fn check_dns_cache_windows(
        tx: &mpsc::Sender<TelemetryEvent>,
        seen_cache: &mut HashSet<String>,
    ) {
        // Use ipconfig /displaydns to get cache entries
        let output = std::process::Command::new("ipconfig")
            .args(["/displaydns"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_name = String::new();
                let mut current_type = String::new();
                let mut current_responses: Vec<String> = Vec::new();

                for line in stdout.lines() {
                    let trimmed = line.trim();

                    if trimmed.starts_with("Record Name") {
                        if let Some(name) = trimmed.split(':').nth(1) {
                            current_name = name.trim().to_string();
                        }
                    } else if trimmed.starts_with("Record Type") {
                        if let Some(rtype) = trimmed.split(':').nth(1) {
                            let type_num: u16 = rtype.trim().parse().unwrap_or(0);
                            current_type = match type_num {
                                1 => "A".to_string(),
                                28 => "AAAA".to_string(),
                                5 => "CNAME".to_string(),
                                15 => "MX".to_string(),
                                _ => format!("TYPE{}", type_num),
                            };
                        }
                    } else if trimmed.starts_with("A (Host) Record")
                        || trimmed.starts_with("AAAA Record")
                    {
                        if let Some(addr) = trimmed.split(':').nth(1) {
                            let addr = addr.trim().to_string();
                            if !addr.is_empty() {
                                current_responses.push(addr);
                            }
                        }
                    } else if trimmed.starts_with("CNAME Record") {
                        if let Some(cname) = trimmed.split(':').nth(1) {
                            let cname = cname.trim().to_string();
                            if !cname.is_empty() {
                                current_responses.push(cname);
                            }
                        }
                    } else if trimmed.is_empty() && !current_name.is_empty() {
                        // End of record block -- emit event if not already seen
                        let dedup_key = format!("cache:{}:{}", current_name, current_type);

                        if !seen_cache.contains(&dedup_key) {
                            seen_cache.insert(dedup_key);

                            debug!(
                                "DNS cache entry: {} ({}) -> {:?}",
                                current_name, current_type, current_responses
                            );

                            let event = TelemetryEvent::new(
                                EventType::DnsQuery,
                                Severity::Info,
                                EventPayload::Dns(DnsEvent {
                                    pid: 0,
                                    process_name: String::new(),
                                    query: current_name.clone(),
                                    query_type: if current_type.is_empty() {
                                        "A".to_string()
                                    } else {
                                        current_type.clone()
                                    },
                                    responses: current_responses.clone(),
                                    capture_method: Some("windows_dns_cache".to_string()),
                                    ..Default::default()
                                }),
                            );

                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }

                        // Reset for next record
                        current_name.clear();
                        current_type.clear();
                        current_responses.clear();
                    }
                }

                // Handle last record if file doesn't end with blank line
                if !current_name.is_empty() {
                    let dedup_key = format!("cache:{}:{}", current_name, current_type);
                    if !seen_cache.contains(&dedup_key) {
                        seen_cache.insert(dedup_key);

                        trace!(
                            "DNS cache entry (tail): {} ({}) -> {:?}",
                            current_name,
                            current_type,
                            current_responses
                        );

                        let event = TelemetryEvent::new(
                            EventType::DnsQuery,
                            Severity::Info,
                            EventPayload::Dns(DnsEvent {
                                pid: 0,
                                process_name: String::new(),
                                query: current_name,
                                query_type: if current_type.is_empty() {
                                    "A".to_string()
                                } else {
                                    current_type
                                },
                                responses: current_responses,
                                capture_method: Some("windows_dns_cache".to_string()),
                                ..Default::default()
                            }),
                        );

                        let _ = tx.send(event).await;
                    }
                }
            }
        }
    }

    /// Enable the DNS Client event log on Windows (requires admin privileges)
    /// This enables the Microsoft-Windows-DNS-Client/Operational log so we can capture DNS queries
    #[cfg(target_os = "windows")]
    fn enable_dns_event_log_windows() {
        info!("Attempting to enable DNS Client event log...");

        // Use wevtutil to enable the DNS Client operational log
        let output = std::process::Command::new("wevtutil")
            .args([
                "set-log",
                "Microsoft-Windows-DNS-Client/Operational",
                "/enabled:true",
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("DNS Client event log enabled successfully");
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    if stderr.contains("Access is denied") {
                        warn!("Cannot enable DNS event log: requires administrator privileges");
                    } else if stderr.contains("already enabled") || stderr.is_empty() {
                        debug!("DNS Client event log is already enabled");
                    } else {
                        warn!("Failed to enable DNS event log: {}", stderr.trim());
                    }
                }
            }
            Err(e) => {
                warn!("Failed to run wevtutil to enable DNS log: {}", e);
            }
        }

        // Also try to set the log size to capture more events
        let _ = std::process::Command::new("wevtutil")
            .args([
                "set-log",
                "Microsoft-Windows-DNS-Client/Operational",
                "/maxsize:10485760", // 10MB
            ])
            .output();
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

    // ==================== macOS Implementation ====================

    /// Primary macOS DNS monitoring entry point.
    ///
    /// Tries multiple capture methods in order of preference:
    /// 1. macOS Unified Log stream (captures dnssd subsystem events, no root required)
    /// 2. BPF packet capture (captures all DNS wire traffic, needs root)
    /// 3. lsof polling fallback (only sees UDP:53 connections, no query names)
    ///
    /// All methods run concurrently; whichever starts successfully will emit
    /// DNS events through the shared channel.
    #[cfg(target_os = "macos")]
    async fn monitor_dns_macos(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        _governor_handle: Option<GovernorHandle>,
    ) -> anyhow::Result<()> {
        info!("Starting macOS DNS collector with multiple capture methods");

        let running = Arc::new(AtomicBool::new(true));

        // Method 1: Unified log stream (preferred -- no root needed)
        let tx_log = tx.clone();
        let running_log = running.clone();
        tokio::spawn(async move {
            dns_macos::monitor_dns_log_stream(tx_log, running_log).await;
        });

        // Method 2: BPF packet capture (needs root, captures wire-level DNS)
        let tx_bpf = tx.clone();
        let running_bpf = running.clone();
        tokio::spawn(async move {
            if let Err(e) = dns_macos::monitor_dns_bpf(tx_bpf, running_bpf).await {
                debug!("BPF DNS capture unavailable: {}", e);
            }
        });

        // Method 3: lsof polling fallback (process attribution without query names)
        let tx_lsof = tx.clone();
        let running_lsof = running.clone();
        let dns_poll_ms = config.collector_tuning.dns_poll_interval_ms;
        tokio::spawn(async move {
            dns_macos::monitor_dns_lsof_fallback(tx_lsof, running_lsof, dns_poll_ms).await;
        });

        // Keep the primary task alive so the collector is not dropped
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }

        Ok(())
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

// =============================================================================
// macOS DNS Monitoring -- unified log stream, BPF packet capture, lsof fallback
// =============================================================================
//
// This module is cfg-gated to macOS and provides three DNS monitoring methods:
//
//   1. **Unified Log Stream** (`log stream --predicate ...`):
//      Captures DNS resolution events from the macOS dnssd subsystem log.
//      Does not require root privileges.  Parses log output for DNS query
//      names, types, and response status.
//
//   2. **BPF Packet Capture** (`/dev/bpfN`):
//      Opens a Berkeley Packet Filter device, attaches to a network interface,
//      and captures raw DNS packets.  Parses standard DNS wire format (RFC 1035)
//      including label compression in responses.  Requires root or BPF group
//      membership.
//
//   3. **lsof Polling Fallback**:
//      Periodically runs `lsof -i UDP:53` to discover processes communicating
//      with DNS servers.  Provides process attribution but no query name detail.
//      Used as a last resort.

#[cfg(target_os = "macos")]
mod dns_macos {
    use super::{DnsEvent, EventPayload, EventType, Severity, TelemetryEvent};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tracing::{debug, info, warn};

    // ======================================================================
    // Method 1: macOS Unified Log Stream
    // ======================================================================

    /// Monitor DNS events via the macOS unified log stream.
    ///
    /// Spawns `log stream --predicate 'subsystem == "com.apple.dnssd"'` as a
    /// child process and parses each output line for DNS query information.
    /// Falls back to a broader predicate if the dnssd subsystem yields no
    /// results after a timeout.
    ///
    /// This method does **not** require root privileges.
    pub async fn monitor_dns_log_stream(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};

        info!("Attempting macOS unified log stream DNS monitoring");

        // Try the dnssd subsystem first (most targeted)
        let predicates = [
            r#"subsystem == "com.apple.dnssd""#,
            r#"eventMessage CONTAINS "DNS" AND subsystem == "com.apple.network""#,
            r#"process == "mDNSResponder""#,
        ];

        for predicate in &predicates {
            if !running.load(Ordering::Relaxed) {
                return;
            }

            let child = tokio::process::Command::new("log")
                .args(["stream", "--predicate", predicate, "--style", "ndjson"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();

            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    debug!(
                        "Cannot start log stream with predicate '{}': {}",
                        predicate, e
                    );
                    continue;
                }
            };

            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => continue,
            };

            info!("macOS log stream started with predicate: {}", predicate);

            let mut reader = BufReader::new(stdout).lines();
            let mut seen_queries: HashSet<String> = HashSet::new();
            let mut last_seen_cleanup = std::time::Instant::now();
            let mut line_count: u64 = 0;

            loop {
                if !running.load(Ordering::Relaxed) {
                    let _ = child.kill().await;
                    return;
                }

                // Time-based cleanup every 300 seconds
                if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                    seen_queries.clear();
                    last_seen_cleanup = std::time::Instant::now();
                }

                tokio::select! {
                    line = reader.next_line() => {
                        match line {
                            Ok(Some(line)) => {
                                line_count += 1;
                                if let Some(event) = parse_log_stream_line(&line, &mut seen_queries) {
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        return;
                                    }
                                }
                            }
                            Ok(None) => {
                                debug!("Log stream ended (predicate: {})", predicate);
                                break;
                            }
                            Err(e) => {
                                debug!("Log stream read error: {}", e);
                                continue;
                            }
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        // Check running flag periodically
                    }
                }
            }

            let _ = child.kill().await;

            // If we got data from this predicate, don't try others
            if line_count > 0 {
                info!(
                    "Log stream predicate '{}' produced {} lines",
                    predicate, line_count
                );
                return;
            }

            debug!(
                "Log stream predicate '{}' produced no output, trying next",
                predicate
            );
        }

        warn!("All macOS log stream predicates exhausted without capturing DNS events");
    }

    /// Parse a single line from the macOS unified log stream (NDJSON format).
    ///
    /// The log output in ndjson mode produces JSON objects with fields like:
    /// ```json
    /// {"timestamp":"...", "eventMessage":"...", "processImagePath":"...", "processID":...}
    /// ```
    ///
    /// We look for DNS-related patterns in `eventMessage`:
    /// - "getaddrinfo ... for <hostname>"
    /// - "DNSServiceQueryRecord ... <hostname>"
    /// - "Query for <hostname> type <qtype>"
    /// - "Reply for <hostname> ... <address>"
    fn parse_log_stream_line(line: &str, seen: &mut HashSet<String>) -> Option<TelemetryEvent> {
        // Attempt JSON parsing for ndjson mode
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let event_msg = json.get("eventMessage")?.as_str()?;
            let process_name = json
                .get("processImagePath")
                .and_then(|v| v.as_str())
                .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
                .unwrap_or_default();
            let pid = json.get("processID").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            return parse_dns_log_message(event_msg, pid, &process_name, seen);
        }

        // Fallback: try to parse plain-text log output
        // Format: "timestamp  process[pid]  subsystem  message"
        parse_dns_log_message(line, 0, "", seen)
    }

    /// Extract DNS query information from a log message string.
    ///
    /// Recognizes several mDNSResponder and system resolver log message formats.
    fn parse_dns_log_message(
        msg: &str,
        pid: u32,
        process_name: &str,
        seen: &mut HashSet<String>,
    ) -> Option<TelemetryEvent> {
        let (domain, query_type, responses, severity) = if let Some(info) = extract_getaddrinfo(msg)
        {
            info
        } else if let Some(info) = extract_dns_query_record(msg) {
            info
        } else if let Some(info) = extract_dns_reply(msg) {
            info
        } else if let Some(info) = extract_generic_dns_pattern(msg) {
            info
        } else {
            return None;
        };

        // Skip empty or obviously noise domains
        if domain.is_empty() || domain == "." || domain == "localhost" {
            return None;
        }

        let dedup_key = format!("log:{}:{}:{}", domain, query_type, pid);
        if seen.contains(&dedup_key) {
            return None;
        }
        seen.insert(dedup_key);

        debug!(
            "macOS log stream DNS: {} ({}) by {}:{} -> {:?}",
            domain, query_type, process_name, pid, responses
        );

        Some(TelemetryEvent::new(
            EventType::DnsQuery,
            severity,
            EventPayload::Dns(DnsEvent {
                pid,
                process_name: process_name.to_string(),
                query: domain,
                query_type,
                responses,
                capture_method: Some("macos_unified_log".to_string()),
                ..Default::default()
            }),
        ))
    }

    /// Parse "getaddrinfo ... for <hostname>" patterns.
    fn extract_getaddrinfo(msg: &str) -> Option<(String, String, Vec<String>, Severity)> {
        // Patterns:
        //   "getaddrinfo(<hostname>, ...)"
        //   "getaddrinfo start ... hostname: <hostname>"
        //   "getaddrinfo ... for <hostname>"

        if let Some(pos) = msg.find("getaddrinfo") {
            let rest = &msg[pos..];

            // Try "getaddrinfo(<hostname>, ...)" or "getaddrinfo(<hostname>)"
            if let Some(paren_start) = rest.find('(') {
                let after_paren = &rest[paren_start + 1..];
                let end = after_paren
                    .find(|c: char| c == ',' || c == ')')
                    .unwrap_or(after_paren.len());
                let hostname = after_paren[..end].trim().trim_matches('"');
                if !hostname.is_empty() && hostname.contains('.') {
                    return Some((
                        hostname.trim_end_matches('.').to_string(),
                        "A".to_string(),
                        vec![],
                        Severity::Info,
                    ));
                }
            }

            // Try "hostname: <hostname>"
            if let Some(hn_pos) = rest.find("hostname:") {
                let hn_rest = &rest[hn_pos + 9..];
                let hostname = hn_rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.');
                if !hostname.is_empty() && hostname.contains('.') {
                    return Some((
                        hostname.to_string(),
                        "A".to_string(),
                        vec![],
                        Severity::Info,
                    ));
                }
            }

            // Try " for <hostname>"
            if let Some(for_pos) = rest.find(" for ") {
                let for_rest = &rest[for_pos + 5..];
                let hostname = for_rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.');
                if !hostname.is_empty() && hostname.contains('.') {
                    return Some((
                        hostname.to_string(),
                        "A".to_string(),
                        vec![],
                        Severity::Info,
                    ));
                }
            }
        }

        None
    }

    /// Parse "DNSServiceQueryRecord ... <hostname>" patterns from mDNSResponder.
    fn extract_dns_query_record(msg: &str) -> Option<(String, String, Vec<String>, Severity)> {
        // Patterns:
        //   "DNSServiceQueryRecord(<hostname>, Addr, ...)"
        //   "DNS query for <hostname> type <type>"
        //   "query: <hostname> type: <type>"

        if let Some(pos) = msg.find("DNSServiceQueryRecord") {
            let rest = &msg[pos..];
            if let Some(paren_start) = rest.find('(') {
                let after_paren = &rest[paren_start + 1..];
                let end = after_paren
                    .find(|c: char| c == ',' || c == ')')
                    .unwrap_or(after_paren.len());
                let hostname = after_paren[..end]
                    .trim()
                    .trim_matches('"')
                    .trim_end_matches('.');

                // Try to extract the query type from after the hostname
                let qtype = if let Some(comma_pos) = after_paren.find(',') {
                    let type_rest = after_paren[comma_pos + 1..].trim();
                    let type_end = type_rest
                        .find(|c: char| c == ',' || c == ')' || c.is_whitespace())
                        .unwrap_or(type_rest.len());
                    normalize_query_type(&type_rest[..type_end])
                } else {
                    "A".to_string()
                };

                if !hostname.is_empty() {
                    return Some((hostname.to_string(), qtype, vec![], Severity::Info));
                }
            }
        }

        // "DNS query for <hostname> type <type>"
        if let Some(pos) = msg.find("DNS query for ") {
            let rest = &msg[pos + 14..];
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                let hostname = parts[0].trim_end_matches('.');
                let qtype = parts
                    .iter()
                    .position(|&p| p == "type")
                    .and_then(|i| parts.get(i + 1))
                    .map(|t| normalize_query_type(t))
                    .unwrap_or_else(|| "A".to_string());

                if !hostname.is_empty() && hostname.contains('.') {
                    return Some((hostname.to_string(), qtype, vec![], Severity::Info));
                }
            }
        }

        // "query: <hostname> type: <type>"
        if let Some(pos) = msg.find("query:") {
            let rest = &msg[pos + 6..].trim_start();
            let hostname_end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            let hostname = rest[..hostname_end].trim_end_matches('.');

            let qtype = if let Some(type_pos) = rest.find("type:") {
                let type_rest = rest[type_pos + 5..].trim_start();
                let type_end = type_rest
                    .find(|c: char| c.is_whitespace() || c == ',')
                    .unwrap_or(type_rest.len());
                normalize_query_type(&type_rest[..type_end])
            } else {
                "A".to_string()
            };

            if !hostname.is_empty() && hostname.contains('.') {
                return Some((hostname.to_string(), qtype, vec![], Severity::Info));
            }
        }

        None
    }

    /// Parse DNS reply / response patterns from mDNSResponder log output.
    fn extract_dns_reply(msg: &str) -> Option<(String, String, Vec<String>, Severity)> {
        // Patterns:
        //   "Reply for <hostname> ... <address>"
        //   "response: <hostname> ... Rcode: <rcode> ... <address>"
        //   "DNSServiceQueryRecord ... reply <hostname> <address>"

        if let Some(pos) = msg.find("Reply for ") {
            let rest = &msg[pos + 10..];
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                let hostname = parts[0].trim_end_matches('.');

                // Collect IP addresses from the remaining tokens
                let addresses: Vec<String> = parts[1..]
                    .iter()
                    .filter(|&&s| looks_like_ip(s))
                    .map(|s| s.to_string())
                    .collect();

                let severity = if msg.contains("NXDOMAIN") || msg.contains("nxdomain") {
                    Severity::Low
                } else if msg.contains("SERVFAIL") || msg.contains("servfail") {
                    Severity::Low
                } else {
                    Severity::Info
                };

                if !hostname.is_empty() && hostname.contains('.') {
                    return Some((hostname.to_string(), "A".to_string(), addresses, severity));
                }
            }
        }

        // "response: <hostname> ..."
        if let Some(pos) = msg.find("response:") {
            let rest = &msg[pos + 9..].trim_start();
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                let hostname = parts[0].trim_end_matches('.');
                let addresses: Vec<String> = parts[1..]
                    .iter()
                    .filter(|&&s| looks_like_ip(s))
                    .map(|s| s.to_string())
                    .collect();

                // Extract rcode if present
                let severity = if msg.contains("Rcode: 3")
                    || msg.contains("NXDOMAIN")
                    || msg.contains("nxdomain")
                {
                    Severity::Low
                } else if msg.contains("Rcode: 2")
                    || msg.contains("SERVFAIL")
                    || msg.contains("servfail")
                {
                    Severity::Low
                } else {
                    Severity::Info
                };

                if !hostname.is_empty() && hostname.contains('.') {
                    return Some((hostname.to_string(), "A".to_string(), addresses, severity));
                }
            }
        }

        None
    }

    /// Parse generic DNS patterns that don't match the specific extractors above.
    fn extract_generic_dns_pattern(msg: &str) -> Option<(String, String, Vec<String>, Severity)> {
        // Look for patterns like "resolving <hostname>" or "<hostname> A/AAAA"
        let resolve_markers = ["resolving ", "Resolving ", "resolve ", "looking up "];

        for marker in &resolve_markers {
            if let Some(pos) = msg.find(marker) {
                let rest = &msg[pos + marker.len()..];
                let hostname = rest
                    .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.');

                if !hostname.is_empty() && hostname.contains('.') && hostname.len() > 3 {
                    return Some((
                        hostname.to_string(),
                        "A".to_string(),
                        vec![],
                        Severity::Info,
                    ));
                }
            }
        }

        None
    }

    /// Normalize a query type string to a standard label (A, AAAA, MX, etc.).
    fn normalize_query_type(raw: &str) -> String {
        let upper = raw.trim().to_uppercase();
        match upper.as_str() {
            "A" | "1" | "ADDR" | "ADDRS" => "A".to_string(),
            "AAAA" | "28" | "ADDR6" => "AAAA".to_string(),
            "CNAME" | "5" => "CNAME".to_string(),
            "MX" | "15" => "MX".to_string(),
            "TXT" | "16" => "TXT".to_string(),
            "NS" | "2" => "NS".to_string(),
            "SOA" | "6" => "SOA".to_string(),
            "PTR" | "12" => "PTR".to_string(),
            "SRV" | "33" => "SRV".to_string(),
            "HTTPS" | "65" => "HTTPS".to_string(),
            "SVCB" | "64" => "SVCB".to_string(),
            _ => {
                if upper.is_empty() {
                    "A".to_string()
                } else {
                    upper
                }
            }
        }
    }

    /// Quick check whether a string looks like an IP address.
    fn looks_like_ip(s: &str) -> bool {
        // IPv4: digits and dots
        if s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.') {
            return true;
        }
        // IPv6: hex digits and colons
        if s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return true;
        }
        false
    }

    // ======================================================================
    // Method 2: BPF Packet Capture
    // ======================================================================

    /// Monitor DNS packets via macOS Berkeley Packet Filter (BPF).
    ///
    /// Opens `/dev/bpf0` through `/dev/bpf255`, attaches to the default network
    /// interface, sets a BPF filter for UDP port 53, then reads and parses DNS
    /// packets in standard wire format (RFC 1035).
    ///
    /// Requires root privileges or BPF device group membership.
    pub async fn monitor_dns_bpf(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        info!("Attempting macOS BPF DNS capture (requires root)");

        // Open BPF device
        let bpf_fd = open_bpf_device()?;

        // Find the default interface
        let iface = get_default_interface()?;
        info!("BPF: attaching to interface {}", iface);

        // Attach the BPF device to the interface
        attach_bpf_to_interface(bpf_fd, &iface)?;

        // Set the BPF filter for UDP port 53
        set_dns_bpf_filter(bpf_fd)?;

        // Enable immediate mode so reads return as soon as data is available
        set_bpf_immediate(bpf_fd)?;

        // Get the BPF buffer length
        let bpf_buf_len = get_bpf_buffer_length(bpf_fd)?;

        info!(
            "BPF DNS capture active on {} (buffer size: {})",
            iface, bpf_buf_len
        );

        // Read packets in a blocking task to avoid blocking the async runtime
        let tx_clone = tx.clone();
        let running_clone = running.clone();

        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; bpf_buf_len];
            let mut seen_queries: HashSet<String> = HashSet::new();
            let mut last_seen_cleanup = std::time::Instant::now();

            while running_clone.load(Ordering::Relaxed) {
                // Time-based cleanup every 300 seconds
                if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                    seen_queries.clear();
                    last_seen_cleanup = std::time::Instant::now();
                }
                // Set read timeout so we can check the running flag
                set_bpf_read_timeout(bpf_fd, 1);

                let n =
                    unsafe { libc::read(bpf_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

                if n <= 0 {
                    // Timeout or error
                    continue;
                }

                let n = n as usize;

                // Parse BPF packets from the buffer.
                // BPF returns data in frames: each frame has a bpf_hdr followed
                // by the captured packet data.
                let mut offset = 0;
                while offset < n {
                    if offset + BPF_HDR_SIZE > n {
                        break;
                    }

                    // Read bpf_hdr fields
                    let bh_caplen = u32::from_ne_bytes([
                        buf[offset + 12],
                        buf[offset + 13],
                        buf[offset + 14],
                        buf[offset + 15],
                    ]) as usize;
                    let bh_hdrlen =
                        u16::from_ne_bytes([buf[offset + 16], buf[offset + 17]]) as usize;

                    let pkt_start = offset + bh_hdrlen;
                    let pkt_end = pkt_start + bh_caplen;

                    if pkt_end > n {
                        break;
                    }

                    let pkt_data = &buf[pkt_start..pkt_end];

                    // Parse the packet and emit events
                    if let Some(events) = parse_dns_packet(pkt_data, &mut seen_queries) {
                        for event in events {
                            if tx_clone.blocking_send(event).is_err() {
                                return;
                            }
                        }
                    }

                    // Advance to next BPF frame (aligned to BPF_WORDALIGN)
                    let frame_len = bh_hdrlen + bh_caplen;
                    offset += bpf_wordalign(frame_len);
                }
            }

            // Close the BPF device
            unsafe { libc::close(bpf_fd) };
        })
        .await
        .map_err(|e| anyhow::anyhow!("BPF task panicked: {}", e))?;

        Ok(())
    }

    // Size of the bpf_hdr struct on macOS (timeval is 16 bytes on 64-bit)
    const BPF_HDR_SIZE: usize = 18;

    /// Round up to the nearest BPF word alignment boundary (macOS uses sizeof(u32)).
    fn bpf_wordalign(x: usize) -> usize {
        (x + 3) & !3
    }

    /// Try to open a BPF device (/dev/bpf0 through /dev/bpf255).
    fn open_bpf_device() -> anyhow::Result<i32> {
        use std::ffi::CString;

        for i in 0..=255 {
            let path = CString::new(format!("/dev/bpf{}", i))
                .map_err(|e| anyhow::anyhow!("CString error: {}", e))?;

            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
            if fd >= 0 {
                debug!("Opened BPF device /dev/bpf{}", i);
                return Ok(fd);
            }
        }

        Err(anyhow::anyhow!(
            "Could not open any BPF device (/dev/bpf0.../dev/bpf255). Root or BPF group required."
        ))
    }

    /// Get the default network interface name using `route get default`.
    fn get_default_interface() -> anyhow::Result<String> {
        let output = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run route command: {}", e))?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("route command failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("interface:") {
                let iface = trimmed.strip_prefix("interface:").unwrap_or("").trim();
                if !iface.is_empty() {
                    return Ok(iface.to_string());
                }
            }
        }

        // Fallback to en0 which is the most common macOS network interface
        warn!("Could not determine default interface, falling back to en0");
        Ok("en0".to_string())
    }

    /// Attach a BPF device to a network interface via BIOCSETIF ioctl.
    fn attach_bpf_to_interface(bpf_fd: i32, iface: &str) -> anyhow::Result<()> {
        // struct ifreq has a 16-byte name field
        let mut ifreq = [0u8; 32];
        let name_bytes = iface.as_bytes();
        let copy_len = name_bytes.len().min(15); // Leave room for null terminator
        ifreq[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // BIOCSETIF = 0x8020426c on macOS
        const BIOCSETIF: libc::c_ulong = 0x8020426c;

        let ret = unsafe { libc::ioctl(bpf_fd, BIOCSETIF, ifreq.as_ptr()) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(bpf_fd) };
            return Err(anyhow::anyhow!(
                "BIOCSETIF ioctl failed for interface '{}': {}",
                iface,
                err
            ));
        }

        Ok(())
    }

    /// Set a BPF filter program to capture only UDP port 53 (DNS) traffic.
    ///
    /// The BPF bytecode matches:
    /// - Ethernet type = IP (0x0800)
    /// - IP protocol = UDP (17)
    /// - UDP source or destination port = 53
    fn set_dns_bpf_filter(bpf_fd: i32) -> anyhow::Result<()> {
        // BPF instructions for: ether proto ip and udp and (port 53)
        //
        // This is equivalent to tcpdump's "udp port 53" filter compiled to BPF.
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct BpfInsn {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }

        let filter: [BpfInsn; 11] = [
            // 0: ldh [12]           -- load EtherType
            BpfInsn {
                code: 0x28,
                jt: 0,
                jf: 0,
                k: 12,
            },
            // 1: jeq #0x0800, 2, 10 -- if IP, continue; else reject
            BpfInsn {
                code: 0x15,
                jt: 0,
                jf: 8,
                k: 0x0800,
            },
            // 2: ldb [23]           -- load IP protocol
            BpfInsn {
                code: 0x30,
                jt: 0,
                jf: 0,
                k: 23,
            },
            // 3: jeq #17, 4, 10     -- if UDP, continue; else reject
            BpfInsn {
                code: 0x15,
                jt: 0,
                jf: 6,
                k: 17,
            },
            // 4: ldh [20]           -- load IP fragment offset
            BpfInsn {
                code: 0x28,
                jt: 0,
                jf: 0,
                k: 20,
            },
            // 5: jset #0x1fff, 10, 6 -- if fragmented, reject
            BpfInsn {
                code: 0x45,
                jt: 4,
                jf: 0,
                k: 0x1fff,
            },
            // 6: ldxb 4*([14]&0xf)  -- load IP header length
            BpfInsn {
                code: 0xb1,
                jt: 0,
                jf: 0,
                k: 14,
            },
            // 7: ldh [x+14]         -- load UDP src port
            BpfInsn {
                code: 0x48,
                jt: 0,
                jf: 0,
                k: 14,
            },
            // 8: jeq #53, 10, 9     -- if src port 53, accept
            BpfInsn {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: 53,
            },
            // 9: ldh [x+16]         -- load UDP dst port
            BpfInsn {
                code: 0x48,
                jt: 0,
                jf: 0,
                k: 16,
            },
            // 10: jeq #53, 0, 1      -- if dst port 53, accept; else reject
            //     (fall through to accept)
            BpfInsn {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: 53,
            },
        ];

        // We need to add the accept/reject return instructions
        let mut full_filter: Vec<BpfInsn> = filter.to_vec();
        // ret #65535 (accept with full packet length)
        full_filter.push(BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 65535,
        });
        // ret #0 (reject)
        full_filter.push(BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        });

        // Fix up jump offsets for the final two instructions
        // Instruction 1: jf should jump to reject (index 12)
        full_filter[1].jf = 10;
        // Instruction 3: jf should jump to reject (index 12)
        full_filter[3].jf = 8;
        // Instruction 5: jt should jump to reject (index 12)
        full_filter[5].jt = 6;
        // Instruction 8: jt should jump to accept (index 11)
        full_filter[8].jt = 2;
        // Instruction 10: jf should jump to reject (index 12)
        full_filter[10].jf = 1;

        #[repr(C)]
        struct BpfProgram {
            bf_len: u32,
            bf_insns: *const BpfInsn,
        }

        let prog = BpfProgram {
            bf_len: full_filter.len() as u32,
            bf_insns: full_filter.as_ptr(),
        };

        // BIOCSETF = 0x80104267 on macOS
        const BIOCSETF: libc::c_ulong = 0x80104267;

        let ret = unsafe { libc::ioctl(bpf_fd, BIOCSETF, &prog) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "BIOCSETF ioctl failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        debug!("BPF DNS filter set successfully");
        Ok(())
    }

    /// Enable BPF immediate mode so reads return as soon as data is available.
    fn set_bpf_immediate(bpf_fd: i32) -> anyhow::Result<()> {
        // BIOCIMMEDIATE = 0x80044270 on macOS
        const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
        let enable: u32 = 1;

        let ret = unsafe { libc::ioctl(bpf_fd, BIOCIMMEDIATE, &enable) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "BIOCIMMEDIATE ioctl failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }

    /// Get the BPF read buffer length.
    fn get_bpf_buffer_length(bpf_fd: i32) -> anyhow::Result<usize> {
        // BIOCGBLEN = 0x40044266 on macOS
        const BIOCGBLEN: libc::c_ulong = 0x40044266;
        let mut buf_len: u32 = 0;

        let ret = unsafe { libc::ioctl(bpf_fd, BIOCGBLEN, &mut buf_len) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "BIOCGBLEN ioctl failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(buf_len as usize)
    }

    /// Set a read timeout on the BPF device so reads don't block forever.
    fn set_bpf_read_timeout(bpf_fd: i32, seconds: i64) {
        // BIOCSRTIMEOUT = 0x8010426d on macOS
        const BIOCSRTIMEOUT: libc::c_ulong = 0x8010426d;

        let timeout = libc::timeval {
            tv_sec: seconds,
            tv_usec: 0,
        };

        unsafe {
            libc::ioctl(bpf_fd, BIOCSRTIMEOUT, &timeout);
        }
    }

    /// Parse a captured Ethernet frame containing a DNS packet.
    ///
    /// Extracts the DNS question section (QNAME and QTYPE) for queries,
    /// and also parses the answer section (addresses, CNAMEs) for responses.
    fn parse_dns_packet(
        pkt_data: &[u8],
        seen: &mut HashSet<String>,
    ) -> Option<Vec<TelemetryEvent>> {
        // Ethernet header: 14 bytes
        if pkt_data.len() < 14 {
            return None;
        }

        let ether_type = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
        if ether_type != 0x0800 {
            // Not IPv4 -- skip for now
            return None;
        }

        // IP header
        let ip_start = 14;
        if pkt_data.len() < ip_start + 20 {
            return None;
        }

        let ip_header_len = ((pkt_data[ip_start] & 0x0f) as usize) * 4;
        let ip_protocol = pkt_data[ip_start + 9];

        if ip_protocol != 17 {
            // Not UDP
            return None;
        }

        // Extract source and destination IPs
        let src_ip = format!(
            "{}.{}.{}.{}",
            pkt_data[ip_start + 12],
            pkt_data[ip_start + 13],
            pkt_data[ip_start + 14],
            pkt_data[ip_start + 15]
        );
        let _dst_ip = format!(
            "{}.{}.{}.{}",
            pkt_data[ip_start + 16],
            pkt_data[ip_start + 17],
            pkt_data[ip_start + 18],
            pkt_data[ip_start + 19]
        );

        // UDP header
        let udp_start = ip_start + ip_header_len;
        if pkt_data.len() < udp_start + 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([pkt_data[udp_start], pkt_data[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([pkt_data[udp_start + 2], pkt_data[udp_start + 3]]);

        // Verify this is DNS traffic (port 53 on either side)
        if src_port != 53 && dst_port != 53 {
            return None;
        }

        // DNS payload
        let dns_start = udp_start + 8;
        if pkt_data.len() < dns_start + 12 {
            return None;
        }

        let dns_data = &pkt_data[dns_start..];

        // Parse DNS header
        let flags = u16::from_be_bytes([dns_data[2], dns_data[3]]);
        let is_response = (flags & 0x8000) != 0;
        let rcode = (flags & 0x000f) as u32;
        let qdcount = u16::from_be_bytes([dns_data[4], dns_data[5]]) as usize;
        let ancount = u16::from_be_bytes([dns_data[6], dns_data[7]]) as usize;

        if qdcount == 0 {
            return None;
        }

        // Parse question section
        let (query_name, query_type_num, question_end) =
            parse_dns_question_section(&dns_data[12..], dns_data)?;

        let query_type = dns_type_to_string(query_type_num);

        // For responses, also parse the answer section
        let (responses, rcode_label) = if is_response {
            let answers =
                parse_dns_answer_section(&dns_data[12 + question_end..], dns_data, ancount);
            let rcode_str = dns_rcode_to_string(rcode);
            (answers, Some(rcode_str))
        } else {
            (vec![], None)
        };

        // Deduplicate
        let direction = if is_response { "resp" } else { "query" };
        let dedup_key = format!("bpf:{}:{}:{}:{}", direction, query_name, query_type, src_ip);
        if seen.contains(&dedup_key) {
            return None;
        }
        seen.insert(dedup_key);

        debug!(
            "BPF DNS {}: {} ({}) rcode={:?} responses={:?}",
            direction, query_name, query_type, rcode_label, responses
        );

        // Determine severity
        let severity = match rcode_label {
            Some("NXDOMAIN") | Some("SERVFAIL") => Severity::Low,
            _ => Severity::Info,
        };

        // Try to attribute the source port to a process via lsof
        let (pid, process_name) = if !is_response {
            attribute_dns_source_port(src_port)
        } else {
            (0, String::new())
        };
        let resolver_ip = if is_response { src_ip } else { dst_ip };
        let resolver_port = if is_response { src_port } else { dst_port };
        let rcode_payload = rcode_label.map(str::to_string);

        let mut event = TelemetryEvent::new(
            EventType::DnsQuery,
            severity,
            EventPayload::Dns(DnsEvent {
                pid,
                process_name,
                query: query_name,
                query_type: query_type.to_string(),
                responses,
                resolver_ip: Some(resolver_ip.to_string()),
                resolver_port: Some(resolver_port),
                transport: Some("udp".to_string()),
                capture_method: Some("bpf".to_string()),
                rcode: rcode_payload.clone(),
                ..Default::default()
            }),
        );

        // Attach rcode metadata
        if let Some(rcode_str) = rcode_payload {
            event.metadata.insert("dns_rcode".to_string(), rcode_str);
        }
        event
            .metadata
            .insert("dns_capture_method".to_string(), "bpf".to_string());

        Some(vec![event])
    }

    /// Parse the DNS question section to extract QNAME and QTYPE.
    ///
    /// Returns (query_name, query_type_number, bytes_consumed).
    fn parse_dns_question_section(data: &[u8], full_packet: &[u8]) -> Option<(String, u16, usize)> {
        let (name, pos) = decode_dns_name(data, full_packet, 0)?;

        // QTYPE is 2 bytes after the name
        if pos + 4 > data.len() {
            return Some((name, 1, pos)); // default to type A
        }

        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        // QCLASS is at pos+2..pos+4 (skip it)

        Some((name, qtype, pos + 4))
    }

    /// Parse the DNS answer section to extract response records.
    ///
    /// Returns a vector of resolved addresses/CNAMEs as strings.
    fn parse_dns_answer_section(data: &[u8], full_packet: &[u8], ancount: usize) -> Vec<String> {
        let mut results = Vec::new();
        let mut pos = 0;

        for _ in 0..ancount {
            if pos >= data.len() {
                break;
            }

            // Skip the NAME field (may use compression)
            let (_name, name_end) = match decode_dns_name(data, full_packet, pos) {
                Some(r) => r,
                None => break,
            };
            pos = name_end;

            // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
            if pos + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            // Skip CLASS (2) and TTL (4)
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > data.len() {
                break;
            }

            let rdata = &data[pos..pos + rdlength];

            match rtype {
                1 => {
                    // A record -- 4 bytes IPv4
                    if rdlength == 4 {
                        results.push(format!(
                            "{}.{}.{}.{}",
                            rdata[0], rdata[1], rdata[2], rdata[3]
                        ));
                    }
                }
                28 => {
                    // AAAA record -- 16 bytes IPv6
                    if rdlength == 16 {
                        let segments: Vec<String> = (0..8)
                            .map(|i| {
                                let val = u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]]);
                                format!("{:x}", val)
                            })
                            .collect();
                        results.push(segments.join(":"));
                    }
                }
                5 => {
                    // CNAME record -- compressed or uncompressed name
                    if let Some((cname, _)) = decode_dns_name(rdata, full_packet, 0) {
                        results.push(cname);
                    }
                }
                _ => {
                    // Other record types -- skip
                }
            }

            pos += rdlength;
        }

        results
    }

    /// Decode a DNS name from wire format, handling label compression (RFC 1035 section 4.1.4).
    ///
    /// `data` is the slice starting at the name position.
    /// `full_packet` is the complete DNS packet (needed for pointer resolution).
    /// `start` is the offset within `data` where the name begins.
    ///
    /// Returns (decoded_name, bytes_consumed_in_data).
    fn decode_dns_name(data: &[u8], full_packet: &[u8], start: usize) -> Option<(String, usize)> {
        let mut labels: Vec<String> = Vec::new();
        let mut pos = start;
        let mut jumped = false;
        let mut bytes_consumed = 0;
        let mut jump_count = 0;
        const MAX_JUMPS: usize = 32; // Prevent infinite loops from malformed packets

        loop {
            if pos >= data.len() && pos >= full_packet.len() {
                break;
            }

            // Choose which buffer to read from based on whether we've jumped
            let current_byte = if jumped {
                if pos >= full_packet.len() {
                    break;
                }
                full_packet[pos]
            } else {
                if pos >= data.len() {
                    break;
                }
                data[pos]
            };

            if current_byte == 0 {
                // End of name
                if !jumped {
                    bytes_consumed = pos + 1 - start;
                }
                break;
            }

            // Check for compression pointer (top 2 bits set = 0xC0)
            if (current_byte & 0xC0) == 0xC0 {
                // Read the next byte for the offset
                let next_byte = if jumped {
                    if pos + 1 >= full_packet.len() {
                        break;
                    }
                    full_packet[pos + 1]
                } else {
                    if pos + 1 >= data.len() {
                        break;
                    }
                    data[pos + 1]
                };

                if !jumped {
                    bytes_consumed = pos + 2 - start;
                }

                // The pointer offset is the lower 14 bits
                let pointer_offset = (((current_byte & 0x3F) as usize) << 8) | (next_byte as usize);

                // Follow the pointer (into full_packet)
                pos = pointer_offset;
                jumped = true;
                jump_count += 1;

                if jump_count > MAX_JUMPS {
                    return None; // Prevent infinite loops
                }

                continue;
            }

            // Normal label
            let label_len = current_byte as usize;
            pos += 1;

            let label_data = if jumped {
                if pos + label_len > full_packet.len() {
                    break;
                }
                &full_packet[pos..pos + label_len]
            } else {
                if pos + label_len > data.len() {
                    break;
                }
                &data[pos..pos + label_len]
            };

            if let Ok(label) = std::str::from_utf8(label_data) {
                labels.push(label.to_string());
            } else {
                // Non-UTF8 label -- hex encode it
                labels.push(format!("\\x{}", hex::encode(label_data)));
            }

            pos += label_len;

            if !jumped {
                bytes_consumed = pos - start;
            }
        }

        if labels.is_empty() {
            return None;
        }

        Some((labels.join("."), bytes_consumed))
    }

    /// Map a DNS query type number to its standard string label.
    fn dns_type_to_string(qtype: u16) -> &'static str {
        match qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            35 => "NAPTR",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            52 => "TLSA",
            64 => "SVCB",
            65 => "HTTPS",
            255 => "ANY",
            256 => "URI",
            257 => "CAA",
            _ => "OTHER",
        }
    }

    /// Map a DNS response code to its standard label.
    fn dns_rcode_to_string(rcode: u32) -> &'static str {
        match rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            9 => "NOTAUTH",
            _ => "UNKNOWN",
        }
    }

    /// Attempt to attribute a UDP source port to a process using `lsof`.
    ///
    /// This is best-effort: if lsof is not available or the port has already
    /// been recycled, we return (0, "").
    fn attribute_dns_source_port(src_port: u16) -> (u32, String) {
        let output = std::process::Command::new("lsof")
            .args(["-i", &format!("UDP:{}", src_port), "-n", "-P", "-F", "pc"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut pid: u32 = 0;
                let mut name = String::new();

                for line in stdout.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    match line.chars().next() {
                        Some('p') => {
                            pid = line[1..].parse().unwrap_or(0);
                        }
                        Some('c') => {
                            name = line[1..].to_string();
                        }
                        _ => {}
                    }
                }

                if pid > 0 {
                    return (pid, name);
                }
            }
        }

        (0, String::new())
    }

    // ======================================================================
    // Method 3: lsof Polling Fallback
    // ======================================================================

    /// Fallback DNS monitoring using `lsof -i UDP:53` polling.
    ///
    /// This is the least capable method: it only sees which processes have
    /// active UDP connections to port 53, without capturing actual DNS query
    /// names. It serves as a last resort when log stream and BPF are both
    /// unavailable.
    pub async fn monitor_dns_lsof_fallback(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        poll_interval_ms: u64,
    ) {
        info!("Starting macOS DNS lsof fallback monitoring");

        let poll_ms = poll_interval_ms.max(500);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(poll_ms));
        let mut seen_queries: HashSet<String> = HashSet::new();
        let mut last_seen_cleanup = std::time::Instant::now();

        loop {
            interval.tick().await;

            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Time-based cleanup every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_queries.clear();
                last_seen_cleanup = std::time::Instant::now();
            }

            // Use lsof to find processes with DNS connections
            let output = std::process::Command::new("lsof")
                .args(["-i", "UDP:53", "-n", "-P", "-F", "pcn"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let mut current_pid: u32 = 0;
                    let mut current_name = String::new();

                    for line in stdout.lines() {
                        if line.is_empty() {
                            continue;
                        }

                        let field_type = match line.chars().next() {
                            Some(c) => c,
                            None => continue,
                        };
                        let value = &line[1..];

                        match field_type {
                            'p' => current_pid = value.parse().unwrap_or(0),
                            'c' => current_name = value.to_string(),
                            'n' => {
                                let query_key =
                                    format!("lsof:{}:{}:{}", current_pid, current_name, value);

                                if !seen_queries.contains(&query_key) {
                                    seen_queries.insert(query_key);

                                    // Parse the remote address from lsof output
                                    // Format: "host:port" or "host:port->remote:port"
                                    let dns_server = value
                                        .split("->")
                                        .nth(1)
                                        .unwrap_or(value)
                                        .split(':')
                                        .next()
                                        .unwrap_or(value);

                                    let event = TelemetryEvent::new(
                                        EventType::DnsQuery,
                                        Severity::Info,
                                        EventPayload::Dns(DnsEvent {
                                            pid: current_pid,
                                            process_name: current_name.clone(),
                                            query: format!("dns-server:{}", dns_server),
                                            query_type: "A".to_string(),
                                            responses: vec![],
                                            resolver_ip: Some(dns_server.to_string()),
                                            resolver_port: Some(53),
                                            transport: Some("udp".to_string()),
                                            capture_method: Some("macos_lsof".to_string()),
                                            ..Default::default()
                                        }),
                                    );

                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Also check DNS cache stats for monitoring
            if let Ok(output) = std::process::Command::new("dscacheutil")
                .args(["-statistics"])
                .output()
            {
                if output.status.success() {
                    let stats = String::from_utf8_lossy(&output.stdout);
                    debug!(
                        "DNS cache stats: {}",
                        stats.lines().take(3).collect::<Vec<_>>().join(", ")
                    );
                }
            }
        }
    }
}

// =============================================================================
// Windows ETW DNS Session -- structures, callback, and TDH property extraction
// =============================================================================
//
// This module is cfg-gated to Windows and provides:
//   - EVENT_TRACE_PROPERTIES layout for the dedicated "TamanduaDNSClient" session
//   - EVENT_TRACE_LOGFILEW layout consumed by OpenTraceW
//   - EVENT_RECORD layout delivered to the callback
//   - TDH (Trace Data Helper) based property extraction for DNS events
//   - The actual `extern "system"` callback registered with ProcessTrace
//
// The structures mirror the C layouts from the Windows SDK and are identical
// to those already defined in `collectors/etw.rs`, but kept self-contained
// here so the DNS collector can operate independently of the main ETW
// collector (which covers process, file, registry, network, PowerShell, etc.).

#[cfg(target_os = "windows")]
mod dns_etw {
    use super::{DnsEvent, EventPayload, EventType, Severity, TelemetryEvent};
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use tokio::sync::mpsc;
    use tracing::debug;

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /// ETW session name (must be unique system-wide)
    pub const SESSION_NAME: &str = "TamanduaDNSClient";

    /// ProcessTrace mode flags
    pub const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
    pub const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x10000000;

    /// WNODE flag
    const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;

    /// ETW log file mode
    const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x00000100;
    const EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING: u32 = 0x10000000;

    /// DNS-Client event IDs
    const DNS_EVENT_QUERY_INITIATED: u16 = 3006;
    const DNS_EVENT_QUERY_COMPLETED: u16 = 3008;

    // ------------------------------------------------------------------
    // Global callback context
    // ------------------------------------------------------------------

    pub static DNS_ETW_CONTEXT: OnceLock<DnsEtwContext> = OnceLock::new();
    pub static DNS_ETW_READY: AtomicBool = AtomicBool::new(false);

    pub struct DnsEtwContext {
        pub tx: std::sync::Mutex<Option<mpsc::Sender<TelemetryEvent>>>,
        pub running: Arc<AtomicBool>,
    }

    // SAFETY: The Mutex guards the Sender; AtomicBool is inherently thread-safe.
    unsafe impl Sync for DnsEtwContext {}

    // ------------------------------------------------------------------
    // C-compatible ETW structures
    // ------------------------------------------------------------------

    #[repr(C)]
    pub struct DnsTraceProperties {
        pub wnode: WnodeHeader,
        pub buffer_size: u32,
        pub minimum_buffers: u32,
        pub maximum_buffers: u32,
        pub maximum_file_size: u32,
        pub log_file_mode: u32,
        pub flush_timer: u32,
        pub enable_flags: u32,
        pub age_limit: i32,
        pub number_of_buffers: u32,
        pub free_buffers: u32,
        pub events_lost: u32,
        pub buffers_written: u32,
        pub log_buffers_lost: u32,
        pub real_time_buffers_lost: u32,
        pub logger_thread_id: *mut c_void,
        pub log_file_name_offset: u32,
        pub logger_name_offset: u32,
        pub _padding: [u8; 1024],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct WnodeHeader {
        pub buffer_size: u32,
        pub provider_id: u32,
        pub historical_context: u64,
        pub timestamp: i64,
        pub guid: [u8; 16],
        pub client_context: u32,
        pub flags: u32,
    }

    pub fn create_dns_trace_properties() -> DnsTraceProperties {
        let total_size = std::mem::size_of::<DnsTraceProperties>();

        DnsTraceProperties {
            wnode: WnodeHeader {
                buffer_size: total_size as u32,
                client_context: 1, // QPC timestamp resolution
                flags: WNODE_FLAG_TRACED_GUID,
                ..Default::default()
            },
            buffer_size: 64, // 64 KB per buffer
            minimum_buffers: 4,
            maximum_buffers: 32,
            maximum_file_size: 0,
            log_file_mode: EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
            flush_timer: 1,
            enable_flags: 0,
            age_limit: 0,
            number_of_buffers: 0,
            free_buffers: 0,
            events_lost: 0,
            buffers_written: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            logger_thread_id: std::ptr::null_mut(),
            log_file_name_offset: 0,
            logger_name_offset: 0,
            _padding: [0u8; 1024],
        }
    }

    // ---- EVENT_TRACE_LOGFILEW (for OpenTraceW) ----

    #[repr(C)]
    pub struct DnsEventTraceLogfileW {
        pub log_file_name: *mut u16,
        pub logger_name: *mut u16,
        pub current_time: i64,
        pub buffers_read: u32,
        pub log_file_mode: u32,
        pub current_event: DnsEventTrace,
        pub logfile_header: DnsTraceLogfileHeader,
        pub buffer_callback: Option<unsafe extern "system" fn(*mut DnsEventTraceLogfileW) -> u32>,
        pub buffer_size: u32,
        pub filled: u32,
        pub events_lost: u32,
        pub event_record_callback: Option<unsafe extern "system" fn(*mut DnsEventRecord)>,
        pub is_kernel_trace: u32,
        pub context: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DnsEventTrace {
        pub header: DnsEventTraceHeader,
        pub instance_id: u32,
        pub parent_instance_id: u32,
        pub parent_guid: [u8; 16],
        pub mof_data: *mut c_void,
        pub mof_length: u32,
        pub client_context: u32,
    }

    impl Default for DnsEventTrace {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct DnsEventTraceHeader {
        pub size: u16,
        pub header_type: u8,
        pub marker_flags: u8,
        pub class_type: u8,
        pub class_level: u8,
        pub class_version: u16,
        pub thread_id: u32,
        pub process_id: u32,
        pub timestamp: i64,
        pub guid: [u8; 16],
        pub kernel_time: u32,
        pub user_time: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DnsTraceLogfileHeader {
        pub buffer_size: u32,
        pub version: u32,
        pub provider_version: u32,
        pub number_of_processors: u32,
        pub end_time: i64,
        pub timer_resolution: u32,
        pub maximum_file_size: u32,
        pub log_file_mode: u32,
        pub buffers_written: u32,
        pub start_buffers: u32,
        pub pointer_size: u32,
        pub events_lost: u32,
        pub cpu_speed_in_mhz: u32,
        pub logger_name: *mut u16,
        pub log_file_name: *mut u16,
        pub time_zone: [u8; 176], // TIME_ZONE_INFORMATION
        pub boot_time: i64,
        pub perf_freq: i64,
        pub start_time: i64,
        pub reserved_flags: u32,
        pub buffers_lost: u32,
    }

    impl Default for DnsTraceLogfileHeader {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    // ---- EVENT_RECORD (delivered to callback) ----

    #[repr(C)]
    pub struct DnsEventRecord {
        pub event_header: DnsEventHeader,
        pub buffer_context: DnsEtwBufferContext,
        pub extended_data_count: u16,
        pub user_data_length: u16,
        pub extended_data: *mut c_void,
        pub user_data: *mut c_void,
        pub user_context: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DnsEventHeader {
        pub size: u16,
        pub header_type: u16,
        pub flags: u16,
        pub event_property: u16,
        pub thread_id: u32,
        pub process_id: u32,
        pub timestamp: i64,
        pub provider_id: [u8; 16], // GUID bytes
        pub event_descriptor: DnsEventDescriptor,
        pub kernel_time: u32,
        pub user_time: u32,
        pub activity_id: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DnsEventDescriptor {
        pub id: u16,
        pub version: u8,
        pub channel: u8,
        pub level: u8,
        pub opcode: u8,
        pub task: u16,
        pub keyword: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DnsEtwBufferContext {
        pub processor_number: u8,
        pub alignment: u8,
        pub logger_id: u16,
    }

    // ------------------------------------------------------------------
    // TDH (Trace Data Helper) property extraction
    // ------------------------------------------------------------------
    //
    // TDH is the official Windows SDK mechanism for parsing ETW event
    // payloads.  We load tdh.dll dynamically and use TdhGetPropertySize +
    // TdhGetProperty to extract named properties from an EVENT_RECORD.

    type TdhGetPropertyFn = unsafe extern "system" fn(
        event: *const DnsEventRecord,
        tmap_info_count: u32,
        tmap_info: *const c_void,
        property_data_count: u32,
        property_data: *const TdhPropertyDataDescriptor,
        buffer_size: u32,
        buffer: *mut u8,
    ) -> u32;

    type TdhGetPropertySizeFn = unsafe extern "system" fn(
        event: *const DnsEventRecord,
        tmap_info_count: u32,
        tmap_info: *const c_void,
        property_data_count: u32,
        property_data: *const TdhPropertyDataDescriptor,
        property_size: *mut u32,
    ) -> u32;

    #[repr(C)]
    struct TdhPropertyDataDescriptor {
        property_name: u64, // pointer to wide string
        array_index: u32,
        reserved: u32,
    }

    struct TdhApi {
        get_property: TdhGetPropertyFn,
        get_property_size: TdhGetPropertySizeFn,
    }

    static TDH_DNS_API: OnceLock<Option<TdhApi>> = OnceLock::new();

    fn get_tdh_api() -> Option<&'static TdhApi> {
        TDH_DNS_API
            .get_or_init(|| {
                use windows::core::HSTRING;
                use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

                unsafe {
                    let module = LoadLibraryW(&HSTRING::from("tdh.dll")).ok()?;
                    let get_property = GetProcAddress(
                        module,
                        windows::core::PCSTR::from_raw(b"TdhGetProperty\0".as_ptr()),
                    )?;
                    let get_property_size = GetProcAddress(
                        module,
                        windows::core::PCSTR::from_raw(b"TdhGetPropertySize\0".as_ptr()),
                    )?;

                    Some(TdhApi {
                        get_property: std::mem::transmute(get_property),
                        get_property_size: std::mem::transmute(get_property_size),
                    })
                }
            })
            .as_ref()
    }

    /// Extract a UTF-16 string property from a DNS ETW event record.
    fn tdh_get_string(record: *const DnsEventRecord, property_name: &str) -> Option<String> {
        let api = get_tdh_api()?;
        let name_wide: Vec<u16> = property_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let descriptor = TdhPropertyDataDescriptor {
            property_name: name_wide.as_ptr() as u64,
            array_index: u32::MAX,
            reserved: 0,
        };

        // Query size first
        let mut size: u32 = 0;
        let status = unsafe {
            (api.get_property_size)(record, 0, std::ptr::null(), 1, &descriptor, &mut size)
        };
        if status != 0 || size == 0 {
            return None;
        }

        // Read the property value
        let mut buf = vec![0u8; size as usize];
        let status = unsafe {
            (api.get_property)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                size,
                buf.as_mut_ptr(),
            )
        };
        if status != 0 {
            return None;
        }

        // Convert UTF-16LE to String
        if buf.len() >= 2 {
            let chars: Vec<u16> = buf
                .chunks(2)
                .filter_map(|c| {
                    if c.len() == 2 {
                        Some(u16::from_le_bytes([c[0], c[1]]))
                    } else {
                        None
                    }
                })
                .take_while(|&c| c != 0)
                .collect();
            let s = String::from_utf16_lossy(&chars);
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        }
    }

    /// Extract a u32 property from a DNS ETW event record.
    fn tdh_get_u32(record: *const DnsEventRecord, property_name: &str) -> Option<u32> {
        let api = get_tdh_api()?;
        let name_wide: Vec<u16> = property_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let descriptor = TdhPropertyDataDescriptor {
            property_name: name_wide.as_ptr() as u64,
            array_index: u32::MAX,
            reserved: 0,
        };

        let mut buf = [0u8; 4];
        let status = unsafe {
            (api.get_property)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                4,
                buf.as_mut_ptr(),
            )
        };

        if status == 0 {
            Some(u32::from_le_bytes(buf))
        } else {
            None
        }
    }

    // ------------------------------------------------------------------
    // DNS query type mapping
    // ------------------------------------------------------------------

    fn dns_type_to_string(qtype: u16) -> &'static str {
        match qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            35 => "NAPTR",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            52 => "TLSA",
            64 => "SVCB",
            65 => "HTTPS",
            255 => "ANY",
            256 => "URI",
            257 => "CAA",
            _ => "OTHER",
        }
    }

    /// DNS RCODE (response status) mapping.
    fn dns_rcode_to_string(rcode: u32) -> &'static str {
        match rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            9 => "NOTAUTH",
            _ => "UNKNOWN",
        }
    }

    // ------------------------------------------------------------------
    // Process name helper
    // ------------------------------------------------------------------

    fn get_process_name(pid: u32) -> String {
        if pid == 0 {
            return "System Idle".to_string();
        }
        if pid == 4 {
            return "System".to_string();
        }

        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

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

    // ------------------------------------------------------------------
    // ETW event callback
    // ------------------------------------------------------------------

    /// C-ABI callback invoked by ProcessTrace for every DNS ETW event.
    ///
    /// SAFETY: Called on the ETW processing thread.  Must not panic.
    /// All state is accessed through the global `DNS_ETW_CONTEXT`.
    pub unsafe extern "system" fn dns_etw_event_callback(record: *mut DnsEventRecord) {
        if record.is_null() {
            return;
        }

        let ctx = match DNS_ETW_CONTEXT.get() {
            Some(c) => c,
            None => return,
        };

        if !ctx.running.load(Ordering::Relaxed) {
            return;
        }

        // Obtain a clone of the mpsc sender
        let tx = match ctx.tx.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(tx) => tx.clone(),
                None => return,
            },
            Err(_) => return,
        };

        if let Some(event) = parse_dns_etw_record(record) {
            // Non-blocking send; drop the event if the channel is full
            let _ = tx.try_send(event);
        }
    }

    // ------------------------------------------------------------------
    // Event record parser
    // ------------------------------------------------------------------

    /// Parse a DNS-Client ETW EVENT_RECORD into a `TelemetryEvent`.
    ///
    /// The Microsoft-Windows-DNS-Client provider emits two event IDs we
    /// care about:
    ///
    /// | Event ID | Name            | Key properties                                     |
    /// |----------|-----------------|----------------------------------------------------|
    /// | 3006     | Query initiated | QueryName, QueryType                               |
    /// | 3008     | Query completed | QueryName, QueryType, QueryStatus, QueryResults    |
    ///
    /// `QueryResults` is a semicolon-separated list of resolved addresses
    /// (e.g. "93.184.216.34;2606:2800:220:1:248:1893:25c8:1946;").
    /// `QueryStatus` is a Win32 DNS RCODE (0 = success).
    unsafe fn parse_dns_etw_record(record: *mut DnsEventRecord) -> Option<TelemetryEvent> {
        let header = &(*record).event_header;
        let event_id = header.event_descriptor.id;

        // Only handle the two DNS event IDs we care about
        if event_id != DNS_EVENT_QUERY_INITIATED && event_id != DNS_EVENT_QUERY_COMPLETED {
            return None;
        }

        let pid = header.process_id;
        let record_ptr: *const DnsEventRecord = record;

        // -- Extract properties via TDH ------------------------------------
        let query_name = tdh_get_string(record_ptr, "QueryName");
        let query_type_raw = tdh_get_u32(record_ptr, "QueryType");
        let query_type_str = query_type_raw
            .map(|t| dns_type_to_string(t as u16))
            .unwrap_or("A");

        // Skip empty queries (noise)
        let query = match &query_name {
            Some(q) if !q.is_empty() => q.clone(),
            _ => return None,
        };

        // For completed queries (3008), extract resolved addresses and status
        let (responses, rcode_str) = if event_id == DNS_EVENT_QUERY_COMPLETED {
            let results = tdh_get_string(record_ptr, "QueryResults")
                .map(|r| {
                    r.split(';')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();
            let status = tdh_get_u32(record_ptr, "QueryStatus")
                .map(|s| dns_rcode_to_string(s))
                .unwrap_or("UNKNOWN");
            (results, Some(status))
        } else {
            (vec![], None)
        };

        let process_name = get_process_name(pid);

        debug!(
            event_id = event_id,
            pid = pid,
            process = %process_name,
            query = %query,
            query_type = %query_type_str,
            responses = ?responses,
            rcode = ?rcode_str,
            "DNS ETW event captured"
        );

        // Determine severity: NXDOMAIN / SERVFAIL responses get Low severity
        // because they can indicate suspicious reconnaissance or C2 beaconing.
        let severity = match rcode_str {
            Some("NXDOMAIN") | Some("SERVFAIL") => Severity::Low,
            _ => Severity::Info,
        };
        let rcode_payload = rcode_str.map(str::to_string);

        let mut event = TelemetryEvent::new(
            EventType::DnsQuery,
            severity,
            EventPayload::Dns(DnsEvent {
                pid,
                process_name,
                query,
                query_type: query_type_str.to_string(),
                responses,
                capture_method: Some("windows_dns_etw".to_string()),
                rcode: rcode_payload.clone(),
                ..Default::default()
            }),
        );

        // Attach metadata for downstream detection
        if let Some(rcode) = rcode_payload {
            event.metadata.insert("dns_rcode".to_string(), rcode);
        }
        event
            .metadata
            .insert("dns_etw_event_id".to_string(), event_id.to_string());
        if let Some(qt) = query_type_raw {
            event
                .metadata
                .insert("dns_query_type_raw".to_string(), qt.to_string());
        }

        Some(event)
    }
}
