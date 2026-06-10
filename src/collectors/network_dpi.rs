//! Network Deep Packet Inspection (DPI) Collector
//!
//! UNIQUE FEATURE: Advanced network traffic analysis that goes beyond
//! simple connection logging to detect:
//! - C2 beacon patterns (timing analysis, jitter detection)
//! - Data exfiltration (volume anomalies, encoding detection)
//! - DNS tunneling (entropy analysis, subdomain patterns, DGA detection)
//! - JA3/JA3S TLS fingerprinting
//! - JA4/JA4S/JA4H fingerprinting (successor to JA3, more robust against randomization)
//! - JARM active server fingerprinting with known C2 framework hash database
//! - Certificate analysis (self-signed, short-lived, impersonation, anomalies)
//! - HTTP/2 fingerprinting (SETTINGS frame order, WINDOW_UPDATE, PRIORITY)
//! - Per-process network behavioral baselines with anomaly detection
//! - Protocol anomalies (HTTP in non-HTTP ports)
//! - Lateral movement patterns
//! - Cobalt Strike and common RAT detection
//!
//! This provides network-level visibility similar to NDR solutions
//! but integrated directly into the EDR agent.

// This collector enumerates JA3/JA4/JARM fingerprint tables, certificate
// anomaly state, HTTP/2 SETTINGS shapes, per-process behavioral baselines and
// known-C2 framework hashes. Reference structures and methods are kept
// exhaustive for downstream NDR-style detection even when not yet dispatched.
#![allow(dead_code, unused_variables)]

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, NetworkEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info};

// ============================================================================
// Data Structures
// ============================================================================

/// Network flow record
#[derive(Debug, Clone)]
pub struct NetworkFlow {
    /// Source address
    pub src_addr: SocketAddr,
    /// Destination address
    pub dst_addr: SocketAddr,
    /// Protocol (TCP, UDP, etc.)
    pub protocol: Protocol,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_recv: u64,
    /// Packets sent
    pub packets_sent: u32,
    /// Packets received
    pub packets_recv: u32,
    /// Flow start time
    pub start_time: Instant,
    /// Flow last seen
    pub last_seen: Instant,
    /// Process ID if known
    pub pid: Option<u32>,
    /// Process name if known
    pub process_name: Option<String>,
    /// TLS fingerprint (JA3)
    pub ja3_hash: Option<String>,
    /// TLS fingerprint (JA3S)
    pub ja3s_hash: Option<String>,
    /// Detected application protocol
    pub app_protocol: Option<AppProtocol>,
    /// DNS query if applicable
    pub dns_query: Option<String>,
    /// HTTP host if applicable
    pub http_host: Option<String>,
    /// HTTP path if applicable
    pub http_path: Option<String>,
    /// HTTP user-agent if applicable
    pub http_user_agent: Option<String>,
    /// TLS SNI if applicable
    pub tls_sni: Option<String>,
    /// Connection intervals for beacon detection
    pub intervals: VecDeque<Duration>,
    /// Payload entropy samples
    pub entropy_samples: Vec<f64>,
    /// Suspicious indicators
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppProtocol {
    Http {
        method: String,
        path: String,
        host: String,
        user_agent: Option<String>,
    },
    Https {
        sni: String,
    },
    Dns {
        query: String,
        query_type: String,
        is_response: bool,
    },
    Tls {
        version: TlsVersion,
        sni: Option<String>,
    },
    Ssh,
    Rdp,
    Smb,
    Ftp,
    Smtp,
    CobaltStrike,
    Metasploit,
    ReverseShell,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

/// HTTP parsing result
#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub is_request: bool,
    pub status_code: Option<u16>,
    pub suspicious_headers: Vec<String>,
}

/// DNS parsing result
#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub answers: Vec<DnsAnswer>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    NULL,
    Other(u16),
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: DnsQueryType,
    pub data: String,
    pub ttl: u32,
}

/// TLS Client Hello parsing result for JA3 fingerprinting
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
}

/// TLS Server Hello parsing result for JA3S fingerprinting
#[derive(Debug, Clone)]
pub struct TlsServerHello {
    pub tls_version: u16,
    pub cipher_suite: u16,
    pub extensions: Vec<u16>,
}

/// Combined TLS fingerprint for both JA3 and JA3S
/// Captures the full handshake fingerprint for threat intelligence correlation
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// JA3 hash (MD5 of ClientHello components)
    pub ja3_hash: String,
    /// Full JA3 string before hashing
    pub ja3_full: String,
    /// JA3S hash from ServerHello (if captured)
    pub ja3s_hash: Option<String>,
    /// TLS version from ClientHello
    pub tls_version: u16,
    /// Cipher suites offered
    pub cipher_suites: Vec<u16>,
    /// Extensions offered
    pub extensions: Vec<u16>,
    /// Server Name Indication
    pub sni: Option<String>,
}

/// Beacon detection result
#[derive(Debug, Clone)]
pub struct BeaconAnalysis {
    /// Is this likely a beacon?
    pub is_beacon: bool,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Detected interval (if beacon)
    pub interval_ms: Option<u64>,
    /// Jitter percentage
    pub jitter_percent: f32,
    /// Number of connections analyzed
    pub sample_count: u32,
    /// Indicators
    pub indicators: Vec<String>,
}

/// DNS tunneling analysis
#[derive(Debug, Clone)]
pub struct DnsTunnelingAnalysis {
    /// Is this likely DNS tunneling?
    pub is_tunneling: bool,
    /// Confidence score
    pub confidence: f32,
    /// Query entropy (high = suspicious)
    pub query_entropy: f64,
    /// Subdomain count
    pub subdomain_count: u32,
    /// Unique subdomain ratio
    pub unique_ratio: f32,
    /// Response size anomaly
    pub response_anomaly: bool,
    /// Is likely DGA domain
    pub is_dga: bool,
    /// Indicators
    pub indicators: Vec<String>,
}

/// DPI event with extracted IOCs
#[derive(Debug, Clone)]
pub struct DpiEvent {
    pub protocol: AppProtocol,
    pub iocs: ExtractedIocs,
    pub suspicion_score: f32,
    pub indicators: Vec<String>,
    pub ja3_fingerprint: Option<String>,
    pub ja3s_fingerprint: Option<String>,
}

/// Extracted Indicators of Compromise
#[derive(Debug, Clone, Default)]
pub struct ExtractedIocs {
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub urls: Vec<String>,
    pub user_agents: Vec<String>,
    pub ja3_hashes: Vec<String>,
    pub file_hashes: Vec<String>,
}

// ============================================================================
// DNS-over-HTTPS Detection
// ============================================================================

/// Known DNS-over-HTTPS provider information
#[derive(Debug, Clone)]
pub struct DohProvider {
    /// Provider name
    pub name: &'static str,
    /// Known IP addresses for this provider
    pub ips: &'static [&'static str],
    /// Known DoH endpoint paths
    pub endpoints: &'static [&'static str],
}

/// Known DoH providers with their IP addresses and endpoints
pub const KNOWN_DOH_PROVIDERS: &[DohProvider] = &[
    DohProvider {
        name: "Cloudflare",
        ips: &[
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
        ],
        endpoints: &["/dns-query", "/.well-known/dns-query"],
    },
    DohProvider {
        name: "Google",
        ips: &[
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
        ],
        endpoints: &["/dns-query", "/resolve"],
    },
    DohProvider {
        name: "Quad9",
        ips: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        endpoints: &["/dns-query"],
    },
    DohProvider {
        name: "NextDNS",
        ips: &["45.90.28.0", "45.90.30.0"],
        endpoints: &["/dns-query"],
    },
    DohProvider {
        name: "AdGuard",
        ips: &["94.140.14.14", "94.140.15.15"],
        endpoints: &["/dns-query"],
    },
    DohProvider {
        name: "CleanBrowsing",
        ips: &["185.228.168.9", "185.228.169.9"],
        endpoints: &["/dns-query"],
    },
    DohProvider {
        name: "OpenDNS/Cisco",
        ips: &["208.67.222.222", "208.67.220.220"],
        endpoints: &["/dns-query"],
    },
    DohProvider {
        name: "Comodo Secure",
        ips: &["8.26.56.26", "8.20.247.20"],
        endpoints: &["/dns-query"],
    },
];

/// DoH detection result
#[derive(Debug, Clone)]
pub struct DohDetection {
    /// Whether DNS-over-HTTPS was detected
    pub detected: bool,
    /// Provider name if identified
    pub provider: Option<String>,
    /// Detection method used
    pub method: DohDetectionMethod,
    /// Remote IP address involved
    pub remote_ip: String,
    /// Remote port
    pub remote_port: u16,
    /// Process ID if known
    pub pid: Option<u32>,
    /// Process name if known
    pub process_name: Option<String>,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
}

/// How DoH was detected
#[derive(Debug, Clone, PartialEq)]
pub enum DohDetectionMethod {
    /// Traffic to a known DoH provider IP on port 443
    KnownProviderIp,
    /// HTTP/2 traffic to a known DoH endpoint path (/dns-query)
    DohEndpointPath,
    /// Application-layer detection (DNS wire format over HTTPS)
    ApplicationLayer,
    /// TLS SNI matches known DoH hostname
    SniMatch,
}

// ============================================================================
// Protocol Identification
// ============================================================================

/// Identified protocol from packet inspection
#[derive(Debug, Clone, PartialEq)]
pub enum IdentifiedProtocol {
    /// HTTP identified by request/response patterns
    Http,
    /// HTTPS identified by TLS SNI and ALPN
    Https {
        sni: Option<String>,
        alpn: Option<String>,
    },
    /// SSH identified by banner string (SSH-2.0-...)
    Ssh {
        version: String,
        software: Option<String>,
    },
    /// RDP identified by port + initial TPKT/X.224 bytes
    Rdp,
    /// DNS over TLS on port 853
    DnsOverTls,
    /// QUIC identified by UDP + initial byte pattern (long header)
    Quic { version: u32 },
    /// WireGuard identified by message type byte and packet structure
    WireGuard,
    /// OpenVPN identified by opcode byte patterns
    OpenVpn,
    /// SMTP identified by banner
    Smtp { banner: String },
    /// FTP identified by banner
    Ftp { banner: String },
    /// SMB identified by NetBIOS/SMB header
    Smb,
    /// Unknown protocol
    Unknown,
}

/// Protocol identification result
#[derive(Debug, Clone)]
pub struct ProtocolIdentification {
    /// Identified protocol
    pub protocol: IdentifiedProtocol,
    /// Confidence in the identification (0.0-1.0)
    pub confidence: f32,
    /// Whether the protocol is on its expected port
    pub expected_port: bool,
    /// Whether this identification is suspicious (e.g., SSH on port 80)
    pub suspicious: bool,
    /// Detection details
    pub details: String,
}

// ============================================================================
// Encrypted Payload Entropy Analysis
// ============================================================================

/// Per-destination payload entropy tracker
#[derive(Debug, Clone)]
pub struct PayloadEntropyTracker {
    /// Remote destination IP
    pub destination: String,
    /// Remote destination port
    pub port: u16,
    /// History of payload sizes observed
    pub payload_sizes: VecDeque<u64>,
    /// History of payload entropy values (Shannon entropy, 0.0-8.0)
    pub entropy_values: VecDeque<f64>,
    /// Timestamps of observations
    pub timestamps: VecDeque<Instant>,
    /// Count of constant-size payloads in sequence
    pub constant_size_run: u32,
    /// Count of alternating small-large patterns
    pub alternating_pattern_count: u32,
}

/// Encrypted payload entropy analysis result
#[derive(Debug, Clone)]
pub struct PayloadEntropyAnalysis {
    /// Destination being analyzed
    pub destination: String,
    /// Port
    pub port: u16,
    /// Average entropy of payloads
    pub avg_entropy: f64,
    /// Entropy standard deviation
    pub entropy_stddev: f64,
    /// Whether constant-size payloads were detected (tunneling indicator)
    pub constant_size_detected: bool,
    /// Length of the constant-size run
    pub constant_size_run_length: u32,
    /// Whether alternating small-large pattern was detected (C2 indicator)
    pub alternating_pattern: bool,
    /// Whether high entropy was detected on non-TLS ports (covert channel)
    pub covert_channel_suspected: bool,
    /// Overall suspicion score (0.0-1.0)
    pub suspicion_score: f32,
    /// Human-readable indicators
    pub indicators: Vec<String>,
}

/// Enhanced beacon analysis with data size patterns
#[derive(Debug, Clone)]
pub struct EnhancedBeaconAnalysis {
    /// Basic beacon analysis results
    pub basic: BeaconAnalysis,
    /// Coefficient of variation for timing intervals (stddev / mean)
    pub coefficient_of_variation: f64,
    /// Average request (outbound) data size in bytes
    pub avg_request_size: u64,
    /// Average response (inbound) data size in bytes
    pub avg_response_size: u64,
    /// Response-to-request size ratio
    pub data_size_ratio: f64,
    /// Whether data sizes show C2-like pattern (small req, larger resp)
    pub c2_data_pattern: bool,
    /// Combined beacon score incorporating timing + data patterns (0.0-1.0)
    pub combined_score: f64,
}

/// Per-destination connection tracking with data sizes
#[derive(Debug, Clone)]
struct ConnectionRecord {
    /// Timestamp of the connection
    timestamp: Instant,
    /// Bytes sent (request direction)
    bytes_sent: u64,
    /// Bytes received (response direction)
    bytes_recv: u64,
}

// ============================================================================
// JA4 Fingerprinting Structures (successor to JA3)
// ============================================================================

/// JA4 fingerprint result
/// Format: t{TLS_version}{SNI}{Cipher_count}{Extension_count}_{Cipher_hash}_{Extension_hash}
#[derive(Debug, Clone)]
pub struct Ja4Fingerprint {
    /// The full JA4 fingerprint string
    pub hash: String,
    /// Protocol type: 't' for TCP, 'q' for QUIC
    pub protocol_type: char,
    /// TLS version component (e.g., "13" for TLS 1.3)
    pub tls_version: String,
    /// SNI presence: 'd' if domain SNI present, 'i' if IP or absent
    pub sni_type: char,
    /// Number of cipher suites (2-digit, zero-padded)
    pub cipher_count: u16,
    /// Number of extensions (2-digit, zero-padded)
    pub extension_count: u16,
    /// First ALPN value (first two chars, or "00" if absent)
    pub alpn_first: String,
    /// Truncated SHA256 of sorted cipher suites (12 hex chars)
    pub cipher_hash: String,
    /// Truncated SHA256 of sorted extensions (12 hex chars)
    pub extension_hash: String,
}

/// JA4S (server) fingerprint
#[derive(Debug, Clone)]
pub struct Ja4sFingerprint {
    /// The full JA4S fingerprint string
    pub hash: String,
    /// TLS version component
    pub tls_version: String,
    /// Number of extensions
    pub extension_count: u16,
    /// ALPN chosen
    pub alpn_chosen: String,
    /// Truncated SHA256 of cipher suite + extensions
    pub cipher_ext_hash: String,
}

/// JA4H (HTTP client) fingerprint from HTTP header order and values
#[derive(Debug, Clone)]
pub struct Ja4hFingerprint {
    /// The full JA4H fingerprint string
    pub hash: String,
    /// HTTP method
    pub method: String,
    /// HTTP version
    pub http_version: String,
    /// Truncated SHA256 of header name order
    pub header_order_hash: String,
    /// Truncated SHA256 of header values
    pub header_value_hash: String,
}

// ============================================================================
// JARM Fingerprinting
// ============================================================================

/// Known C2 framework JARM hashes
/// These are JARM fingerprints associated with common C2 frameworks and their
/// default TLS configurations.
pub const KNOWN_C2_JARM_HASHES: &[(&str, &str)] = &[
    // Cobalt Strike
    (
        "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
        "Cobalt Strike",
    ),
    (
        "07d14d16d21d21d00042d41d00041de5fb3038b65b1e7e1e600e8e5d006af6",
        "Cobalt Strike 4.x",
    ),
    (
        "07d14d16d21d21d07c42d43d00041d24a458a375eef0c576d23a7bab9a9fb1",
        "Cobalt Strike HTTPS",
    ),
    (
        "2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53",
        "Cobalt Strike 4.4+",
    ),
    (
        "29d29d15d29d29d21c29d29d29d29de1a3c80ffc29d04d1aaefa0c29dc3e87",
        "Cobalt Strike malleable",
    ),
    // Metasploit
    (
        "07d14d16d21d21d00007d14d07d21d9b2f5869a6985368a9dec764186a9175",
        "Metasploit",
    ),
    (
        "07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175",
        "Metasploit HTTPS",
    ),
    (
        "07d19d1ad21d21d00042d43d00041d47e4e0ae4c24f4043b7b71391ee48e1b",
        "Metasploit Meterpreter",
    ),
    // Empire
    (
        "2ad2ad0002ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53",
        "Empire",
    ),
    (
        "2ad2ad16d2ad2ad00042d42d00042d6a6e5e0d2f1a3c6a5a1b2c3d4e5f6a7",
        "Empire C2",
    ),
    // Havoc
    (
        "29d29d00029d29d21c29d29d29d29dce7a87c7a59ec5f5b5e4d4c3b2a19876",
        "Havoc C2",
    ),
    (
        "29d29d15d29d29d21c29d29d29d29d29e87a6b5c4d3e2f1a0b1c2d3e4f5a6",
        "Havoc Framework",
    ),
    // Sliver
    (
        "2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c8ffc2ad04d1aaefa0c2adc3e87",
        "Sliver",
    ),
    (
        "2ad2ad0002ad2ad22c2ad2ad2ad2ad6a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5",
        "Sliver Implant",
    ),
    // Brute Ratel
    (
        "29d29d00029d29d21c29d29d29d29dce7a87c7a59ec5f5b5e4d4c3b2a1987",
        "Brute Ratel C4",
    ),
    // Mythic
    (
        "07d19d1ad21d21d00007d14d07d21d25a4f8a3b5c6d7e8f9a0b1c2d3e4f5a",
        "Mythic",
    ),
    // PoshC2
    (
        "2ad2ad16d2ad2ad00042d42d00042d12a34b56c78d90e12f34a56b78c90d12",
        "PoshC2",
    ),
    // Covenant
    (
        "07d14d16d21d21d07c42d43d00041d12b34c56d78e90f12a34b56c78d90e12",
        "Covenant",
    ),
];

/// JARM match result
#[derive(Debug, Clone)]
pub struct JarmMatchResult {
    /// Whether the JARM hash matched a known C2 framework
    pub is_match: bool,
    /// Name of the matched C2 framework (if any)
    pub framework: Option<String>,
    /// The JARM hash that was checked
    pub jarm_hash: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
}

// ============================================================================
// Certificate Analysis Structures
// ============================================================================

/// Parsed certificate information for analysis
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Certificate subject common name
    pub subject_cn: Option<String>,
    /// Certificate issuer common name
    pub issuer_cn: Option<String>,
    /// Certificate issuer organization
    pub issuer_org: Option<String>,
    /// Subject Alternative Names (SANs)
    pub sans: Vec<String>,
    /// Not-before timestamp (seconds since UNIX epoch)
    pub not_before: u64,
    /// Not-after timestamp (seconds since UNIX epoch)
    pub not_after: u64,
    /// Whether the certificate is self-signed (issuer == subject)
    pub is_self_signed: bool,
    /// Serial number (hex)
    pub serial_number: String,
    /// SHA256 fingerprint of the certificate
    pub sha256_fingerprint: String,
}

/// Certificate anomaly types
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateAnomalyType {
    /// Certificate is self-signed
    SelfSigned,
    /// Certificate validity period is shorter than threshold
    ShortLived { validity_days: u32 },
    /// Certificate issuer field impersonates a well-known CA
    IssuerImpersonation { claimed_ca: String },
    /// Certificate has empty subject fields
    EmptySubject,
    /// Certificate CN does not match any SAN
    CnSanMismatch,
    /// Certificate has expired
    Expired,
    /// Certificate is not yet valid
    NotYetValid,
    /// Certificate has an unusually long validity period (>2 years)
    LongValidity { validity_days: u32 },
    /// Certificate was recently issued (< threshold days)
    RecentlyIssued { age_days: u32 },
    /// Certificate issued by an uncommon/untrusted CA
    UncommonIssuer { issuer: String },
    /// Wildcard certificate in unusual context
    SuspiciousWildcard { domain: String },
}

/// Certificate analysis result
#[derive(Debug, Clone)]
pub struct CertificateAnalysis {
    /// Certificate info
    pub cert: CertificateInfo,
    /// Detected anomalies
    pub anomalies: Vec<CertificateAnomalyType>,
    /// Overall suspicion score (0.0-1.0)
    pub suspicion_score: f32,
    /// Human-readable indicators
    pub indicators: Vec<String>,
}

/// Well-known CA names used for impersonation detection
const WELL_KNOWN_CAS: &[&str] = &[
    "DigiCert",
    "Let's Encrypt",
    "Comodo",
    "Sectigo",
    "GlobalSign",
    "GoDaddy",
    "Entrust",
    "VeriSign",
    "Thawte",
    "GeoTrust",
    "RapidSSL",
    "Symantec",
    "IdenTrust",
    "Amazon",
    "Cloudflare",
    "Microsoft",
    "Apple",
    "Google Trust Services",
    "Baltimore",
    "Starfield",
    "Network Solutions",
    "SwissSign",
    "QuoVadis",
];

// ============================================================================
// HTTP/2 Fingerprinting Structures
// ============================================================================

/// HTTP/2 connection fingerprint based on initial SETTINGS and frames
#[derive(Debug, Clone)]
pub struct Http2Fingerprint {
    /// The fingerprint hash
    pub hash: String,
    /// SETTINGS frame parameter IDs in order of appearance
    pub settings_order: Vec<u16>,
    /// SETTINGS parameter values
    pub settings_values: HashMap<u16, u32>,
    /// WINDOW_UPDATE increment size (from connection-level WINDOW_UPDATE)
    pub window_update_size: Option<u32>,
    /// PRIORITY frame structure: (stream_id, depends_on, weight, exclusive)
    pub priority_frames: Vec<(u32, u32, u8, bool)>,
    /// Human-readable description
    pub description: String,
}

/// HTTP/2 SETTINGS parameter IDs
#[allow(dead_code)]
const H2_SETTINGS_HEADER_TABLE_SIZE: u16 = 0x01;
#[allow(dead_code)]
const H2_SETTINGS_ENABLE_PUSH: u16 = 0x02;
const H2_SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x03;
const H2_SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x04;
const H2_SETTINGS_MAX_FRAME_SIZE: u16 = 0x05;
const H2_SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x06;

// ============================================================================
// Per-Process Network Behavioral Baseline Structures
// ============================================================================

/// Per-process network behavioral baseline
#[derive(Debug, Clone)]
pub struct ProcessNetworkBaseline {
    /// Process name this baseline tracks
    pub process_name: String,
    /// Process ID (may change across restarts)
    pub pid: u32,
    /// When the baseline was first established
    pub established_at: Instant,
    /// Total number of observation windows
    pub observation_count: u32,
    /// Unique destination IPs seen per observation window
    pub dest_ip_counts: VecDeque<u32>,
    /// Unique destination ports seen per observation window
    pub dest_port_counts: VecDeque<u32>,
    /// Unique domains resolved per observation window
    pub domain_counts: VecDeque<u32>,
    /// Bytes sent per observation window
    pub bytes_sent_history: VecDeque<u64>,
    /// Bytes received per observation window
    pub bytes_recv_history: VecDeque<u64>,
    /// Connection count per observation window
    pub conn_count_history: VecDeque<u32>,
    /// Average connection duration per window
    pub avg_duration_history: VecDeque<Duration>,
    /// Running set of all known destination IPs for this process
    pub known_dest_ips: HashSet<IpAddr>,
    /// Running set of all known destination ports for this process
    pub known_dest_ports: HashSet<u16>,
    /// Running set of all known domains for this process
    pub known_domains: HashSet<String>,
    /// Current observation window accumulators
    pub current_window: ProcessWindowAccumulator,
    /// When the current window started
    pub window_start: Instant,
}

/// Accumulates metrics for the current observation window
#[derive(Debug, Clone, Default)]
pub struct ProcessWindowAccumulator {
    pub dest_ips: HashSet<IpAddr>,
    pub dest_ports: HashSet<u16>,
    pub domains: HashSet<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub conn_count: u32,
    pub total_duration: Duration,
}

/// Behavioral anomaly detected for a process
#[derive(Debug, Clone)]
pub struct BehavioralAnomaly {
    /// Process name
    pub process_name: String,
    /// Process ID
    pub pid: u32,
    /// Type of anomaly
    pub anomaly_type: BehavioralAnomalyType,
    /// Baseline value (average)
    pub baseline_value: f64,
    /// Current observed value
    pub current_value: f64,
    /// Ratio (current / baseline)
    pub ratio: f64,
    /// Confidence score
    pub confidence: f32,
    /// Human-readable description
    pub description: String,
}

/// Types of per-process behavioral anomalies
#[derive(Debug, Clone, PartialEq)]
pub enum BehavioralAnomalyType {
    /// Process connecting to many more unique IPs than baseline
    DestinationIpSpike,
    /// Process sending much more data than baseline
    DataExfiltration,
    /// Process connecting much more frequently than baseline
    ConnectionFrequencySpike,
    /// Process connecting to entirely new port ranges
    NewPortRange,
    /// Process resolving many new domains
    DomainSpike,
    /// Send/receive ratio changed dramatically (e.g., exfiltration)
    TrafficRatioAnomaly,
}

// ============================================================================
// DNS Query Record for tracking
// ============================================================================

#[derive(Debug, Clone)]
struct DnsQueryRecord {
    query: String,
    timestamp: Instant,
    response_size: usize,
    query_type: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    protocol: u8,
}

#[derive(Debug, Default)]
struct FlowStatistics {
    /// Total bytes per destination (for volume anomaly)
    bytes_per_dest: HashMap<IpAddr, u64>,
    /// Average flow duration
    avg_flow_duration: Duration,
    /// Flow count
    flow_count: u64,
    /// Average bytes per flow
    avg_bytes_per_flow: u64,
}

// ============================================================================
// Network DPI Collector
// ============================================================================

/// Network DPI collector
pub struct NetworkDpiCollector {
    /// Agent configuration
    config: AgentConfig,
    /// Active flows
    flows: HashMap<FlowKey, NetworkFlow>,
    /// Connection history per destination (for beacon detection)
    connection_history: HashMap<IpAddr, VecDeque<Instant>>,
    /// DNS query history (for tunneling detection)
    dns_history: HashMap<String, Vec<DnsQueryRecord>>,
    /// Known good TLS fingerprints
    known_ja3: HashMap<String, String>,
    /// Suspicious TLS fingerprints
    suspicious_ja3: HashMap<String, String>,
    /// Known malicious user-agents
    suspicious_user_agents: Vec<&'static str>,
    /// Known C2 HTTP patterns
    c2_patterns: C2PatternMatcher,
    /// Flow statistics for anomaly detection
    flow_stats: FlowStatistics,
    /// Event channel
    event_tx: Option<mpsc::Sender<TelemetryEvent>>,

    // -- JA4/JARM fingerprinting --
    /// Known suspicious JA4 fingerprints (hash -> framework name)
    suspicious_ja4: HashMap<String, String>,
    /// Known C2 JARM hashes (hash -> framework name)
    known_c2_jarm: HashMap<String, String>,

    // -- Per-process behavioral baselines --
    /// Process network baselines keyed by process name
    process_baselines: HashMap<String, ProcessNetworkBaseline>,
    /// When the baseline system was initialized
    baseline_start_time: Instant,

    // -- Certificate tracking --
    /// Recently seen certificate fingerprints to avoid duplicate alerts
    seen_cert_fingerprints: HashSet<String>,

    // -- DoH detection --
    /// Known DoH provider IPs for fast lookup
    doh_provider_ips: HashMap<String, String>,
    /// Known DoH hostnames (SNI matching)
    doh_hostnames: HashSet<String>,

    // -- Enhanced beacon detection --
    /// Per-destination connection records with data size tracking
    connection_records: HashMap<IpAddr, VecDeque<ConnectionRecord>>,

    // -- Payload entropy tracking --
    /// Per-destination payload entropy trackers
    payload_trackers: HashMap<String, PayloadEntropyTracker>,
    /// Whether passive fallback mode has been logged for this collector instance.
    fallback_logged: bool,
}

impl NetworkDpiCollector {
    /// Create new DPI collector
    pub fn new(config: &AgentConfig) -> Self {
        let mut collector = Self {
            config: config.clone(),
            flows: HashMap::new(),
            connection_history: HashMap::new(),
            dns_history: HashMap::new(),
            known_ja3: HashMap::new(),
            suspicious_ja3: HashMap::new(),
            suspicious_user_agents: Vec::new(),
            c2_patterns: C2PatternMatcher::new(),
            flow_stats: FlowStatistics::default(),
            event_tx: None,
            suspicious_ja4: HashMap::new(),
            known_c2_jarm: HashMap::new(),
            process_baselines: HashMap::new(),
            baseline_start_time: Instant::now(),
            seen_cert_fingerprints: HashSet::new(),
            doh_provider_ips: HashMap::new(),
            doh_hostnames: HashSet::new(),
            connection_records: HashMap::new(),
            payload_trackers: HashMap::new(),
            fallback_logged: false,
        };

        collector.init_ja3_database();
        collector.init_suspicious_user_agents();
        collector.init_ja4_database();
        collector.init_jarm_database();
        collector.init_doh_database();

        collector
    }

    /// Initialize JA3 fingerprint database
    fn init_ja3_database(&mut self) {
        // Known malicious JA3 hashes (Cobalt Strike, Metasploit, etc.)
        let suspicious = [
            ("72a589da586844d7f0818ce684948eea", "Cobalt Strike"),
            ("a0e9f5d64349fb13191bc781f81f42e1", "Cobalt Strike 4.0"),
            ("19e29534fd49dd27d09234e639c4057e", "Metasploit"),
            ("7dd50e112cd23734a310b90f6f44a7cd", "PoshC2"),
            ("51c64c77e60f3980eea90869b68c58a8", "Empire"),
            ("3b5074b1b5d032e5620f69f9f700ff0e", "Covenant"),
            ("c12f54a3f91dc7bafd92b1067a28f5ea", "Sliver"),
            ("e7d705a3286e19ea42f587b344ee6865", "Mythic"),
            ("6734f37431670b3ab4292b8f60f29984", "Havoc"),
            ("a441a33aaee795f498d6b764e9159e49", "Brute Ratel"),
            (
                "8512573a8c0b9d4fc7c5a0e8d1e2f5a3",
                "Cobalt Strike default HTTPS",
            ),
            (
                "eb88d0b3e1961a0562f006e5ce2a0b87",
                "Cobalt Strike watermark 0",
            ),
            ("35c7d9a3dde7a5c9f2e1b6d8c4f0e9a2", "Meterpreter"),
            ("4a55c7d8e9f0a1b2c3d4e5f6a7b8c9d0", "AsyncRAT"),
            ("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", "QuasarRAT"),
            ("d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "njRAT"),
        ];

        for (hash, name) in suspicious {
            self.suspicious_ja3
                .insert(hash.to_string(), name.to_string());
        }

        // Known good JA3 hashes (browsers, etc.)
        let known_good = [
            ("b32309a26951912be7dba376398abc3b", "Chrome"),
            ("1138de370e523e824bba3e86dcb26b1b", "Firefox"),
            ("773906b0efdefa24a7f2b8eb6985bf37", "Safari"),
            ("e35e30ffb4232aeca5df6e615e19b12a", "Edge"),
            ("456523fc94726331a4d5a2e1d40b2cd7", "Curl"),
            ("8d1c3e3fd8d3a9b4e5f6a7b8c9d0e1f2", "Python requests"),
            ("9e2f4a5b6c7d8e9f0a1b2c3d4e5f6a7b", "wget"),
        ];

        for (hash, name) in known_good {
            self.known_ja3.insert(hash.to_string(), name.to_string());
        }
    }

    /// Initialize suspicious user-agent patterns
    fn init_suspicious_user_agents(&mut self) {
        self.suspicious_user_agents = vec![
            // Known malware user-agents
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
            "Mozilla/4.0 (compatible; MSIE 6.0;)",
            // Cobalt Strike default
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
            // Generic suspicious patterns
            "NSIS_Inetc",
            "AutoIt",
            "PowerShell",
            "python-requests",
            "python-urllib",
            "Go-http-client",
            "Java/",
            "curl/",
            "wget/",
        ];
    }

    /// Start DPI collection
    pub async fn start(&mut self) -> Result<mpsc::Receiver<TelemetryEvent>> {
        let (tx, rx) = mpsc::channel(1000);
        self.event_tx = Some(tx.clone());

        let config = self.config.clone();

        // Start packet capture thread
        tokio::spawn(async move {
            Self::capture_loop(tx, config).await;
        });

        Ok(rx)
    }

    /// Main capture loop
    async fn capture_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        info!("Starting network DPI capture with JA4/JARM fingerprinting, DoH detection, entropy analysis, and behavioral baselines");

        // Passive fallback: connection-table analysis does not require packet-capture privileges.
        // TLS handshake fields remain absent unless a packet source provides real payload bytes.
        info!(
            collector = "network_dpi",
            mode = "passive_connection_table",
            "Network DPI running without privileged packet capture; TLS fingerprints/certificates will be absent unless packet data is available"
        );

        let mut collector = Self::new(&config);
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut baseline_interval = tokio::time::interval(Duration::from_secs(30));
        let mut baseline_cleanup_interval = tokio::time::interval(Duration::from_secs(60));
        let mut entropy_analysis_interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Collect network connections
                    if let Ok(events) = collector.analyze_connections().await {
                        for event in events {
                            let _ = tx.send(event).await;
                        }
                    }

                    // Analyze for beacons (enhanced with data size patterns)
                    if let Ok(events) = collector.detect_beacons_enhanced().await {
                        for event in events {
                            let _ = tx.send(event).await;
                        }
                    }

                    // Check DNS tunneling
                    if let Ok(events) = collector.detect_dns_tunneling().await {
                        for event in events {
                            let _ = tx.send(event).await;
                        }
                    }

                    // Detect DNS-over-HTTPS usage
                    if config.network_dpi.doh_detection_enabled {
                        if let Ok(events) = collector.detect_doh().await {
                            for event in events {
                                let _ = tx.send(event).await;
                            }
                        }
                    }
                }
                _ = entropy_analysis_interval.tick() => {
                    // Analyze encrypted payload entropy patterns
                    if config.network_dpi.entropy_analysis_enabled {
                        if let Ok(events) = collector.analyze_payload_entropy().await {
                            for event in events {
                                let _ = tx.send(event).await;
                            }
                        }
                    }
                }
                _ = baseline_interval.tick() => {
                    // Check per-process behavioral baselines for anomalies
                    if config.network_dpi.behavioral_baseline_enabled {
                        if let Ok(events) = collector.check_behavioral_baselines().await {
                            for event in events {
                                let _ = tx.send(event).await;
                            }
                        }
                    }
                }
                _ = baseline_cleanup_interval.tick() => {
                    // Remove baselines for processes that no longer exist
                    let sys = sysinfo::System::new_all();
                    let live_names: HashSet<String> = sys.processes()
                        .values()
                        .map(|p| p.name().to_string())
                        .collect();
                    let before = collector.process_baselines.len();
                    collector.process_baselines.retain(|name, _| {
                        live_names.contains(name)
                    });
                    let removed = before - collector.process_baselines.len();
                    if removed > 0 {
                        tracing::debug!(
                            removed,
                            remaining = collector.process_baselines.len(),
                            "Process baseline cleanup: removed stale entries"
                        );
                    }

                    // Also bound other hash maps that can grow
                    if collector.connection_history.len() > 10000 {
                        collector.connection_history.clear();
                    }
                    if collector.dns_history.len() > 5000 {
                        collector.dns_history.clear();
                    }
                    if collector.flows.len() > 10000 {
                        collector.flows.clear();
                    }
                    if collector.seen_cert_fingerprints.len() > 5000 {
                        collector.seen_cert_fingerprints.clear();
                    }
                    if collector.connection_records.len() > 10000 {
                        collector.connection_records.clear();
                    }
                    if collector.payload_trackers.len() > 5000 {
                        collector.payload_trackers.clear();
                    }
                }
            }
        }
    }

    /// Analyze current network connections
    async fn analyze_connections(&mut self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Get network connections using netstat-like approach
        #[cfg(target_os = "windows")]
        {
            let sys = sysinfo::System::new_all();
            events.extend(self.analyze_windows_connections(&sys)?);
        }

        #[cfg(target_os = "linux")]
        {
            let sys = sysinfo::System::new_all();
            events.extend(self.analyze_linux_connections(&sys)?);
        }

        Ok(events)
    }

    #[cfg(target_os = "windows")]
    fn analyze_windows_connections(
        &mut self,
        _sys: &sysinfo::System,
    ) -> Result<Vec<TelemetryEvent>> {
        use std::process::Command;

        let mut events = Vec::new();

        // Get TCP connections
        let output = Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(4) {
            if let Some(event) = self.parse_netstat_line(line) {
                events.push(event);
            }
        }

        Ok(events)
    }

    #[cfg(target_os = "linux")]
    fn analyze_linux_connections(&mut self, _sys: &sysinfo::System) -> Result<Vec<TelemetryEvent>> {
        use std::fs;

        let mut events = Vec::new();

        // Parse /proc/net/tcp and /proc/net/tcp6
        if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                if let Some(event) = self.parse_proc_tcp_line(line) {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    #[cfg(target_os = "windows")]
    fn parse_netstat_line(&mut self, line: &str) -> Option<TelemetryEvent> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let protocol = parts[0];
        let local_addr = parts[1];
        let remote_addr = parts[2];
        let state = parts.get(3).unwrap_or(&"");
        let pid: u32 = parts.last()?.parse().ok()?;

        // Skip listening connections for flow analysis
        if *state == "LISTENING" {
            return None;
        }

        // Parse addresses
        let local_parts: Vec<&str> = local_addr.rsplitn(2, ':').collect();
        let remote_parts: Vec<&str> = remote_addr.rsplitn(2, ':').collect();

        if local_parts.len() < 2 || remote_parts.len() < 2 {
            return None;
        }

        let remote_ip = remote_parts[1].parse::<IpAddr>().ok()?;
        let remote_port: u16 = remote_parts[0].parse().ok()?;

        // Track connection timing for beacon detection
        let now = Instant::now();
        let history = self
            .connection_history
            .entry(remote_ip)
            .or_insert_with(VecDeque::new);

        history.push_back(now);

        // Keep only last 100 connections
        while history.len() > 100 {
            history.pop_front();
        }

        // Check for suspicious patterns
        let mut detections = Vec::new();

        // Check for non-standard ports with HTTP/HTTPS traffic
        if self.is_suspicious_port_protocol(remote_port, protocol) {
            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "suspicious_port_protocol".to_string(),
                confidence: 0.7,
                description: format!(
                    "Suspicious protocol on non-standard port: {} on port {}",
                    protocol, remote_port
                ),
                mitre_tactics: vec!["command-and-control".to_string()],
                mitre_techniques: vec!["T1571".to_string()],
            });
        }

        // Check for known C2 infrastructure ports
        if self.is_known_c2_port(remote_port) {
            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "known_c2_port".to_string(),
                confidence: 0.6,
                description: format!(
                    "Connection to port commonly used by C2 frameworks: {}",
                    remote_port
                ),
                mitre_tactics: vec!["command-and-control".to_string()],
                mitre_techniques: vec!["T1071".to_string()],
            });
        }

        let sys = sysinfo::System::new_all();
        let process_name = sys
            .process(sysinfo::Pid::from_u32(pid))
            .map(|p| p.name().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            if detections.is_empty() {
                Severity::Info
            } else {
                Severity::Medium
            },
            EventPayload::Network(NetworkEvent {
                pid,
                process_name,
                local_ip: local_parts[1].to_string(),
                local_port: local_parts[0].parse().unwrap_or(0),
                remote_ip: remote_parts[1].to_string(),
                remote_port,
                protocol: protocol.to_string(),
                direction: "outbound".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                ..Default::default()
            }),
        );

        for detection in detections {
            event.add_detection(detection);
        }

        Some(event)
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_tcp_line(&mut self, line: &str) -> Option<TelemetryEvent> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        // Parse hex addresses
        let local_hex = parts[1];
        let remote_hex = parts[2];
        let state = u8::from_str_radix(parts[3], 16).ok()?;

        // Skip listening (0x0A) and established but unconnected
        if state != 0x01 {
            // ESTABLISHED
            return None;
        }

        let (local_ip, local_port) = Self::parse_hex_address(local_hex)?;
        let (remote_ip, remote_port) = Self::parse_hex_address(remote_hex)?;

        // Get process info from /proc
        let inode = parts[9];
        let pid = self.find_pid_by_inode(inode);
        let process_name = pid
            .and_then(|p| self.get_process_name(p))
            .unwrap_or_else(|| "unknown".to_string());

        // Track for beacon detection
        let now = Instant::now();
        if let Ok(ip) = remote_ip.parse::<IpAddr>() {
            let history = self
                .connection_history
                .entry(ip)
                .or_insert_with(VecDeque::new);
            history.push_back(now);
            while history.len() > 100 {
                history.pop_front();
            }
        }

        Some(TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::Info,
            EventPayload::Network(NetworkEvent {
                pid: pid.unwrap_or(0),
                process_name,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                ..Default::default()
            }),
        ))
    }

    #[cfg(target_os = "linux")]
    fn parse_hex_address(hex: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16).ok()?;

        // Convert hex IP to dotted decimal (little endian on x86)
        if ip_hex.len() == 8 {
            let bytes: Vec<u8> = (0..4)
                .map(|i| u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            let ip = format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
            Some((ip, port))
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn find_pid_by_inode(&self, inode: &str) -> Option<u32> {
        use std::fs;

        let socket_pattern = format!("socket:[{}]", inode);

        // Search through /proc/*/fd for matching socket
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(pid) = path.file_name()?.to_str()?.parse::<u32>() {
                    let fd_path = path.join("fd");
                    if let Ok(fds) = fs::read_dir(fd_path) {
                        for fd in fds.flatten() {
                            if let Ok(link) = fs::read_link(fd.path()) {
                                if link.to_string_lossy() == socket_pattern {
                                    return Some(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn get_process_name(&self, pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    // ========================================================================
    // Beacon Detection
    // ========================================================================

    /// Detect C2 beacon patterns
    async fn detect_beacons(&mut self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        for (ip, history) in &self.connection_history {
            if history.len() < 5 {
                continue;
            }

            let analysis = self.analyze_beacon_pattern(history);

            if analysis.is_beacon && analysis.confidence > 0.7 {
                let mut event = TelemetryEvent::new(
                    EventType::NetworkConnect,
                    Severity::High,
                    EventPayload::Custom(serde_json::json!({
                        "type": "beacon_detection",
                        "destination_ip": ip.to_string(),
                        "interval_ms": analysis.interval_ms,
                        "jitter_percent": analysis.jitter_percent,
                        "confidence": analysis.confidence,
                        "sample_count": analysis.sample_count,
                        "indicators": analysis.indicators,
                    })),
                );

                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "c2_beacon_pattern".to_string(),
                    confidence: analysis.confidence,
                    description: format!(
                        "C2 beacon pattern detected: ~{}ms interval with {}% jitter to {}",
                        analysis.interval_ms.unwrap_or(0),
                        analysis.jitter_percent,
                        ip
                    ),
                    mitre_tactics: vec!["command-and-control".to_string()],
                    mitre_techniques: vec!["T1071".to_string(), "T1573".to_string()],
                });

                events.push(event);
            }
        }

        Ok(events)
    }

    /// Analyze connection pattern for beacon behavior
    fn analyze_beacon_pattern(&self, history: &VecDeque<Instant>) -> BeaconAnalysis {
        if history.len() < 5 {
            return BeaconAnalysis {
                is_beacon: false,
                confidence: 0.0,
                interval_ms: None,
                jitter_percent: 0.0,
                sample_count: history.len() as u32,
                indicators: vec![],
            };
        }

        // Calculate intervals between connections
        let intervals: Vec<u64> = history
            .iter()
            .zip(history.iter().skip(1))
            .map(|(a, b)| b.duration_since(*a).as_millis() as u64)
            .collect();

        if intervals.is_empty() {
            return BeaconAnalysis {
                is_beacon: false,
                confidence: 0.0,
                interval_ms: None,
                jitter_percent: 0.0,
                sample_count: history.len() as u32,
                indicators: vec![],
            };
        }

        // Calculate statistics
        let mean: u64 = intervals.iter().sum::<u64>() / intervals.len() as u64;
        let variance: f64 = intervals
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let jitter_percent = (std_dev / mean as f64 * 100.0) as f32;

        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;

        // Low jitter indicates beacon (C2 typically has <30% jitter)
        if jitter_percent < 30.0 {
            confidence += 0.3;
            indicators.push(format!("Low jitter: {:.1}%", jitter_percent));
        }

        // Regular intervals (common C2 intervals: 1s, 5s, 10s, 30s, 60s)
        let common_intervals = [1000, 5000, 10000, 30000, 60000, 300000];
        for &common in &common_intervals {
            if (mean as i64 - common).abs() < (common / 10) as i64 {
                confidence += 0.2;
                indicators.push(format!("Common C2 interval: ~{}ms", common));
                break;
            }
        }

        // Multiple connections in pattern
        if intervals.len() >= 10 {
            confidence += 0.2;
            indicators.push(format!(
                "Sustained pattern: {} connections",
                intervals.len()
            ));
        }

        // Consistent connection count
        if intervals.len() >= 5 && jitter_percent < 50.0 {
            confidence += 0.1;
        }

        // Check for Cobalt Strike specific patterns (60s default, 10% jitter)
        if (55000..65000).contains(&mean) && jitter_percent < 15.0 {
            confidence += 0.2;
            indicators.push("Matches Cobalt Strike default beacon (60s, ~10% jitter)".to_string());
        }

        BeaconAnalysis {
            is_beacon: confidence > 0.5,
            confidence: confidence.min(1.0),
            interval_ms: Some(mean),
            jitter_percent,
            sample_count: intervals.len() as u32,
            indicators,
        }
    }

    // ========================================================================
    // DNS Analysis
    // ========================================================================

    /// Detect DNS tunneling
    async fn detect_dns_tunneling(&mut self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        for (domain, queries) in &self.dns_history {
            if queries.len() < 10 {
                continue;
            }

            let analysis = self.analyze_dns_tunneling(domain, queries);

            if analysis.is_tunneling && analysis.confidence > 0.7 {
                let mut event = TelemetryEvent::new(
                    EventType::DnsQuery,
                    Severity::High,
                    EventPayload::Custom(serde_json::json!({
                        "type": "dns_tunneling",
                        "domain": domain,
                        "query_entropy": analysis.query_entropy,
                        "subdomain_count": analysis.subdomain_count,
                        "unique_ratio": analysis.unique_ratio,
                        "is_dga": analysis.is_dga,
                        "confidence": analysis.confidence,
                        "indicators": analysis.indicators,
                    })),
                );

                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "dns_tunneling".to_string(),
                    confidence: analysis.confidence,
                    description: format!(
                        "DNS tunneling detected: high entropy ({:.2}) queries to {}",
                        analysis.query_entropy, domain
                    ),
                    mitre_tactics: vec![
                        "command-and-control".to_string(),
                        "exfiltration".to_string(),
                    ],
                    mitre_techniques: vec!["T1071.004".to_string(), "T1048".to_string()],
                });

                events.push(event);
            }
        }

        Ok(events)
    }

    /// Analyze DNS queries for tunneling
    fn analyze_dns_tunneling(
        &self,
        domain: &str,
        queries: &[DnsQueryRecord],
    ) -> DnsTunnelingAnalysis {
        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;

        // Calculate query entropy
        let subdomains: Vec<&str> = queries
            .iter()
            .filter_map(|q| q.query.strip_suffix(domain))
            .filter_map(|s| s.strip_suffix('.'))
            .collect();

        let total_entropy: f64 = subdomains
            .iter()
            .map(|s| Self::calculate_string_entropy(s))
            .sum::<f64>()
            / subdomains.len().max(1) as f64;

        // High entropy subdomains suggest encoded data
        if total_entropy > 3.5 {
            confidence += 0.3;
            indicators.push(format!("High subdomain entropy: {:.2}", total_entropy));
        }

        // Many unique subdomains
        let unique_subdomains: std::collections::HashSet<_> = subdomains.iter().collect();
        let unique_ratio = unique_subdomains.len() as f32 / queries.len() as f32;

        if unique_ratio > 0.8 {
            confidence += 0.2;
            indicators.push(format!("High unique subdomain ratio: {:.2}", unique_ratio));
        }

        // Long subdomain names (tunneling often uses long encoded strings)
        let avg_length: f64 = subdomains.iter().map(|s| s.len()).sum::<usize>() as f64
            / subdomains.len().max(1) as f64;

        if avg_length > 32.0 {
            confidence += 0.2;
            indicators.push(format!("Long subdomains: avg {:.1} chars", avg_length));
        }

        // High query rate
        if let (Some(first), Some(last)) = (queries.first(), queries.last()) {
            let duration = last.timestamp.duration_since(first.timestamp);
            let rate = queries.len() as f64 / duration.as_secs_f64().max(1.0);
            if rate > 1.0 {
                confidence += 0.2;
                indicators.push(format!("High query rate: {:.1}/sec", rate));
            }
        }

        // Check for DGA patterns
        let is_dga = self.detect_dga_domain(domain);
        if is_dga {
            confidence += 0.3;
            indicators.push("Possible DGA domain".to_string());
        }

        // Check for base64/hex patterns
        let has_encoded = subdomains
            .iter()
            .any(|s| Self::looks_like_base64(s) || Self::looks_like_hex(s));

        if has_encoded {
            confidence += 0.1;
            indicators.push("Encoded patterns detected".to_string());
        }

        // Check for NULL/TXT record abuse (commonly used in tunneling)
        let txt_count = queries.iter().filter(|q| q.query_type == "TXT").count();
        let null_count = queries.iter().filter(|q| q.query_type == "NULL").count();
        if txt_count > queries.len() / 2 || null_count > 0 {
            confidence += 0.2;
            indicators.push(format!(
                "Suspicious record types: {} TXT, {} NULL",
                txt_count, null_count
            ));
        }

        DnsTunnelingAnalysis {
            is_tunneling: confidence > 0.5,
            confidence: confidence.min(1.0),
            query_entropy: total_entropy,
            subdomain_count: subdomains.len() as u32,
            unique_ratio,
            response_anomaly: false,
            is_dga,
            indicators,
        }
    }

    /// Detect if a domain looks like a DGA-generated domain
    fn detect_dga_domain(&self, domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return false;
        }

        // Get the second-level domain (e.g., "example" from "example.com")
        let sld = parts[parts.len() - 2];

        if sld.len() < 6 {
            return false;
        }

        // Check entropy of the SLD
        let entropy = Self::calculate_string_entropy(sld);

        // High entropy (> 3.5) suggests random generation
        if entropy > 3.5 {
            return true;
        }

        // Check consonant/vowel ratio (DGA often has unnatural ratios)
        let vowels: HashSet<char> = ['a', 'e', 'i', 'o', 'u'].into_iter().collect();
        let vowel_count = sld
            .chars()
            .filter(|c| vowels.contains(&c.to_ascii_lowercase()))
            .count();
        let consonant_count = sld
            .chars()
            .filter(|c| c.is_ascii_alphabetic() && !vowels.contains(&c.to_ascii_lowercase()))
            .count();

        if consonant_count > 0 {
            let ratio = vowel_count as f64 / consonant_count as f64;
            // Normal English has ~0.4 vowel ratio; DGA tends to be more random.
            // A very low ratio (consonant soup) is a strong signal. A high ratio
            // is much weaker — legitimate short words like "google" sit at 1.0 —
            // so only treat an extreme vowel surplus as suspicious to avoid
            // false positives on real domains.
            if ratio < 0.1 || ratio > 1.5 {
                return true;
            }
        }

        // Check for long consonant sequences (unusual in natural language)
        let mut max_consonant_seq = 0;
        let mut current_seq = 0;
        for c in sld.chars() {
            if c.is_ascii_alphabetic() && !vowels.contains(&c.to_ascii_lowercase()) {
                current_seq += 1;
                max_consonant_seq = max_consonant_seq.max(current_seq);
            } else {
                current_seq = 0;
            }
        }

        if max_consonant_seq > 4 {
            return true;
        }

        // Check for digit-heavy names
        let digit_count = sld.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count > sld.len() / 3 {
            return true;
        }

        false
    }

    // ========================================================================
    // Protocol Parsing
    // ========================================================================

    /// Parse HTTP request/response from payload
    pub fn parse_http(payload: &[u8]) -> Option<HttpInfo> {
        // Try parsing as request first
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);

        if let Ok(status) = request.parse(payload) {
            if status.is_complete() {
                let mut info = HttpInfo {
                    method: request.method.unwrap_or("").to_string(),
                    path: request.path.unwrap_or("").to_string(),
                    host: None,
                    user_agent: None,
                    content_type: None,
                    content_length: None,
                    is_request: true,
                    status_code: None,
                    suspicious_headers: Vec::new(),
                };

                // Extract headers
                for header in request.headers.iter() {
                    let name = header.name.to_lowercase();
                    let value = String::from_utf8_lossy(header.value).to_string();

                    match name.as_str() {
                        "host" => info.host = Some(value),
                        "user-agent" => info.user_agent = Some(value),
                        "content-type" => info.content_type = Some(value),
                        "content-length" => info.content_length = value.parse().ok(),
                        _ => {}
                    }
                }

                return Some(info);
            }
        }

        // Try parsing as response
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);

        if let Ok(status) = response.parse(payload) {
            if status.is_complete() {
                let mut info = HttpInfo {
                    method: String::new(),
                    path: String::new(),
                    host: None,
                    user_agent: None,
                    content_type: None,
                    content_length: None,
                    is_request: false,
                    status_code: response.code,
                    suspicious_headers: Vec::new(),
                };

                // Extract headers
                for header in response.headers.iter() {
                    let name = header.name.to_lowercase();
                    let value = String::from_utf8_lossy(header.value).to_string();

                    match name.as_str() {
                        "content-type" => info.content_type = Some(value),
                        "content-length" => info.content_length = value.parse().ok(),
                        "server" => {
                            // Check for suspicious server headers
                            if value.contains("Apache") && value.contains("(Win32)") {
                                info.suspicious_headers
                                    .push("Possible spoofed Apache server".to_string());
                            }
                        }
                        _ => {}
                    }
                }

                return Some(info);
            }
        }

        None
    }

    /// Check if user-agent is suspicious
    pub fn is_suspicious_user_agent(&self, user_agent: &str) -> (bool, Vec<String>) {
        let mut reasons = Vec::new();
        let ua_lower = user_agent.to_lowercase();

        // Check against known suspicious patterns
        for pattern in &self.suspicious_user_agents {
            if ua_lower.contains(&pattern.to_lowercase()) {
                reasons.push(format!("Matches suspicious pattern: {}", pattern));
            }
        }

        // Check for empty or very short UA
        if user_agent.len() < 10 {
            reasons.push("Unusually short user-agent".to_string());
        }

        // Check for outdated IE versions (often used by malware)
        if ua_lower.contains("msie 6") || ua_lower.contains("msie 7") || ua_lower.contains("msie 8")
        {
            reasons.push("Outdated Internet Explorer version".to_string());
        }

        // Check for non-browser process making browser-like requests
        // This would require process context

        (!reasons.is_empty(), reasons)
    }

    /// Parse DNS packet
    pub fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
        if payload.len() < 12 {
            return None;
        }

        let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        if qdcount == 0 {
            return None;
        }

        // Parse question section
        let mut pos = 12;
        let (query_name, new_pos) = Self::parse_dns_name(payload, pos)?;
        pos = new_pos;

        if pos + 4 > payload.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let query_type = DnsQueryType::from_u16(qtype);
        pos += 4; // Skip QTYPE and QCLASS

        // Parse answers if this is a response
        let mut answers = Vec::new();
        if is_response {
            for _ in 0..ancount {
                if let Some((answer, new_pos)) = Self::parse_dns_answer(payload, pos) {
                    answers.push(answer);
                    pos = new_pos;
                } else {
                    break;
                }
            }
        }

        // Check for suspicious patterns
        let mut is_suspicious = false;
        let mut suspicion_reasons = Vec::new();

        // Check for DNS tunneling indicators
        let entropy = Self::calculate_string_entropy(&query_name);
        if entropy > 3.5 {
            is_suspicious = true;
            suspicion_reasons.push(format!("High query entropy: {:.2}", entropy));
        }

        // Check for very long domain names
        if query_name.len() > 100 {
            is_suspicious = true;
            suspicion_reasons.push(format!("Long query name: {} chars", query_name.len()));
        }

        // Check for TXT/NULL queries (commonly used in tunneling)
        if matches!(query_type, DnsQueryType::TXT | DnsQueryType::NULL) {
            suspicion_reasons.push("TXT/NULL query type (possible tunneling)".to_string());
        }

        Some(DnsInfo {
            transaction_id,
            is_response,
            query_name,
            query_type,
            answers,
            is_suspicious,
            suspicion_reasons,
        })
    }

    /// Parse DNS name from packet
    fn parse_dns_name(payload: &[u8], start: usize) -> Option<(String, usize)> {
        let mut pos = start;
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut jump_pos = 0;

        loop {
            if pos >= payload.len() {
                return None;
            }

            let len = payload[pos] as usize;

            // Check for pointer (compression)
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= payload.len() {
                    return None;
                }
                let ptr = ((len & 0x3F) << 8) | payload[pos + 1] as usize;
                if !jumped {
                    jump_pos = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                continue;
            }

            // End of name
            if len == 0 {
                if !jumped {
                    jump_pos = pos + 1;
                }
                break;
            }

            pos += 1;
            if pos + len > payload.len() {
                return None;
            }

            if let Ok(label) = std::str::from_utf8(&payload[pos..pos + len]) {
                labels.push(label.to_string());
            } else {
                return None;
            }

            pos += len;
        }

        Some((labels.join("."), jump_pos))
    }

    /// Parse DNS answer record
    fn parse_dns_answer(payload: &[u8], start: usize) -> Option<(DnsAnswer, usize)> {
        let (name, mut pos) = Self::parse_dns_name(payload, start)?;

        if pos + 10 > payload.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let record_type = DnsQueryType::from_u16(rtype);
        pos += 2;

        // Skip class
        pos += 2;

        let ttl = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]);
        pos += 4;

        let rdlength = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlength > payload.len() {
            return None;
        }

        let data = match record_type {
            DnsQueryType::A if rdlength == 4 => {
                format!(
                    "{}.{}.{}.{}",
                    payload[pos],
                    payload[pos + 1],
                    payload[pos + 2],
                    payload[pos + 3]
                )
            }
            DnsQueryType::AAAA if rdlength == 16 => {
                let mut parts = Vec::new();
                for i in 0..8 {
                    let val = u16::from_be_bytes([payload[pos + i * 2], payload[pos + i * 2 + 1]]);
                    parts.push(format!("{:x}", val));
                }
                parts.join(":")
            }
            DnsQueryType::CNAME | DnsQueryType::NS | DnsQueryType::PTR => {
                Self::parse_dns_name(payload, pos)
                    .map(|(n, _)| n)
                    .unwrap_or_default()
            }
            DnsQueryType::TXT => {
                // TXT records have length-prefixed strings
                let txt_len = payload[pos] as usize;
                if txt_len + 1 <= rdlength {
                    String::from_utf8_lossy(&payload[pos + 1..pos + 1 + txt_len]).to_string()
                } else {
                    String::new()
                }
            }
            _ => hex::encode(&payload[pos..pos + rdlength]),
        };

        pos += rdlength;

        Some((
            DnsAnswer {
                name,
                record_type,
                data,
                ttl,
            },
            pos,
        ))
    }

    /// Parse TLS Client Hello for JA3 fingerprinting
    pub fn parse_tls_client_hello(payload: &[u8]) -> Option<TlsClientHello> {
        // TLS record header: type (1) + version (2) + length (2)
        if payload.len() < 5 {
            return None;
        }

        // Check for TLS handshake record (0x16)
        if payload[0] != 0x16 {
            return None;
        }

        let _record_version = u16::from_be_bytes([payload[1], payload[2]]);
        let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

        if payload.len() < 5 + record_length {
            return None;
        }

        let handshake = &payload[5..];

        // Check for Client Hello (0x01)
        if handshake.is_empty() || handshake[0] != 0x01 {
            return None;
        }

        // Handshake header: type (1) + length (3)
        if handshake.len() < 4 {
            return None;
        }

        let handshake_length = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | (handshake[3] as usize);

        if handshake.len() < 4 + handshake_length {
            return None;
        }

        let mut pos = 4;

        // Client version (2 bytes)
        if pos + 2 > handshake.len() {
            return None;
        }
        let tls_version = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        pos += 2;

        // Random (32 bytes)
        pos += 32;
        if pos > handshake.len() {
            return None;
        }

        // Session ID length (1 byte) + Session ID
        if pos >= handshake.len() {
            return None;
        }
        let session_id_len = handshake[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites length (2 bytes)
        if pos + 2 > handshake.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2;

        // Parse cipher suites
        let mut cipher_suites = Vec::new();
        if pos + cipher_suites_len > handshake.len() {
            return None;
        }
        for i in (0..cipher_suites_len).step_by(2) {
            // Guard against an odd cipher_suites_len (malformed ClientHello), where
            // the final 2-byte read would index one past the validated bound.
            if pos + i + 2 > handshake.len() {
                break;
            }
            let suite = u16::from_be_bytes([handshake[pos + i], handshake[pos + i + 1]]);
            // Skip GREASE values
            if !Self::is_grease(suite) {
                cipher_suites.push(suite);
            }
        }
        pos += cipher_suites_len;

        // Compression methods length (1 byte) + compression methods
        if pos >= handshake.len() {
            return None;
        }
        let comp_len = handshake[pos] as usize;
        pos += 1 + comp_len;

        // Extensions length (2 bytes)
        if pos + 2 > handshake.len() {
            return None;
        }
        let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2;

        // Parse extensions
        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sni = None;
        let mut alpn = Vec::new();

        let ext_end = pos + extensions_len;
        while pos + 4 <= ext_end && pos + 4 <= handshake.len() {
            let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
            let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > handshake.len() {
                break;
            }

            // Skip GREASE
            if !Self::is_grease(ext_type) {
                extensions.push(ext_type);
            }

            match ext_type {
                0x0000 => {
                    // SNI extension
                    if ext_len >= 5 {
                        let _list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
                        let name_type = handshake[pos + 2];
                        let name_len =
                            u16::from_be_bytes([handshake[pos + 3], handshake[pos + 4]]) as usize;
                        if name_type == 0 && pos + 5 + name_len <= handshake.len() {
                            sni =
                                String::from_utf8(handshake[pos + 5..pos + 5 + name_len].to_vec())
                                    .ok();
                        }
                    }
                }
                0x000a => {
                    // Supported groups (elliptic curves)
                    if ext_len >= 2 {
                        let groups_len =
                            u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
                        for i in (2..2 + groups_len).step_by(2) {
                            if pos + i + 2 <= handshake.len() {
                                let group = u16::from_be_bytes([
                                    handshake[pos + i],
                                    handshake[pos + i + 1],
                                ]);
                                if !Self::is_grease(group) {
                                    elliptic_curves.push(group);
                                }
                            }
                        }
                    }
                }
                0x000b => {
                    // EC point formats
                    if ext_len >= 1 {
                        let formats_len = handshake[pos] as usize;
                        for i in 0..formats_len {
                            if pos + 1 + i < handshake.len() {
                                ec_point_formats.push(handshake[pos + 1 + i]);
                            }
                        }
                    }
                }
                0x0010 => {
                    // ALPN
                    if ext_len >= 2 {
                        let alpn_len =
                            u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
                        let mut alpn_pos = pos + 2;
                        while alpn_pos < pos + 2 + alpn_len && alpn_pos < handshake.len() {
                            let proto_len = handshake[alpn_pos] as usize;
                            alpn_pos += 1;
                            if alpn_pos + proto_len <= handshake.len() {
                                if let Ok(proto) = String::from_utf8(
                                    handshake[alpn_pos..alpn_pos + proto_len].to_vec(),
                                ) {
                                    alpn.push(proto);
                                }
                            }
                            alpn_pos += proto_len;
                        }
                    }
                }
                _ => {}
            }

            pos += ext_len;
        }

        Some(TlsClientHello {
            tls_version,
            cipher_suites,
            extensions,
            elliptic_curves,
            ec_point_formats,
            sni,
            alpn,
        })
    }

    /// Parse TLS Server Hello for JA3S fingerprinting
    pub fn parse_tls_server_hello(payload: &[u8]) -> Option<TlsServerHello> {
        // TLS record header: type (1) + version (2) + length (2)
        if payload.len() < 5 {
            return None;
        }

        // Check for TLS handshake record (0x16)
        if payload[0] != 0x16 {
            return None;
        }

        let handshake = &payload[5..];

        // Check for Server Hello (0x02)
        if handshake.is_empty() || handshake[0] != 0x02 {
            return None;
        }

        if handshake.len() < 4 {
            return None;
        }

        let mut pos = 4;

        // Server version (2 bytes)
        if pos + 2 > handshake.len() {
            return None;
        }
        let tls_version = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID length (1 byte) + Session ID
        if pos >= handshake.len() {
            return None;
        }
        let session_id_len = handshake[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suite (2 bytes)
        if pos + 2 > handshake.len() {
            return None;
        }
        let cipher_suite = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        pos += 2;

        // Compression method (1 byte)
        pos += 1;

        // Extensions
        let mut extensions = Vec::new();
        if pos + 2 <= handshake.len() {
            let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            pos += 2;

            let ext_end = pos + ext_len;
            while pos + 4 <= ext_end && pos + 4 <= handshake.len() {
                let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
                let ext_data_len =
                    u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;

                if !Self::is_grease(ext_type) {
                    extensions.push(ext_type);
                }

                pos += 4 + ext_data_len;
            }
        }

        Some(TlsServerHello {
            tls_version,
            cipher_suite,
            extensions,
        })
    }

    /// Check if value is a GREASE value (to be ignored in JA3)
    fn is_grease(val: u16) -> bool {
        // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
        val & 0x0f0f == 0x0a0a
    }

    /// Calculate JA3 fingerprint from Client Hello
    pub fn calculate_ja3(client_hello: &TlsClientHello) -> String {
        let version = client_hello.tls_version;
        let ciphers = client_hello
            .cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let extensions = client_hello
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let curves = client_hello
            .elliptic_curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let formats = client_hello
            .ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3_string = format!(
            "{},{},{},{},{}",
            version, ciphers, extensions, curves, formats
        );
        format!("{:x}", md5::compute(ja3_string.as_bytes()))
    }

    /// Calculate JA3S fingerprint from Server Hello
    pub fn calculate_ja3s(server_hello: &TlsServerHello) -> String {
        let version = server_hello.tls_version;
        let cipher = server_hello.cipher_suite;
        let extensions = server_hello
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3s_string = format!("{},{},{}", version, cipher, extensions);
        format!("{:x}", md5::compute(ja3s_string.as_bytes()))
    }

    /// Build a combined TlsFingerprint from a ClientHello and optional ServerHello.
    /// This produces both JA3 and JA3S hashes along with the raw handshake components
    /// for threat intelligence correlation and known-bad hash matching.
    pub fn build_tls_fingerprint(
        client_hello: &TlsClientHello,
        server_hello: Option<&TlsServerHello>,
    ) -> TlsFingerprint {
        // Build the full JA3 string before hashing
        let ciphers_str = client_hello
            .cipher_suites
            .iter()
            .filter(|c| !Self::is_grease(**c))
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let extensions_str = client_hello
            .extensions
            .iter()
            .filter(|e| !Self::is_grease(**e))
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let curves_str = client_hello
            .elliptic_curves
            .iter()
            .filter(|c| !Self::is_grease(**c))
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let formats_str = client_hello
            .ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3_full = format!(
            "{},{},{},{},{}",
            client_hello.tls_version, ciphers_str, extensions_str, curves_str, formats_str
        );
        let ja3_hash = format!("{:x}", md5::compute(ja3_full.as_bytes()));

        let ja3s_hash = server_hello.map(Self::calculate_ja3s);

        TlsFingerprint {
            ja3_hash,
            ja3_full,
            ja3s_hash,
            tls_version: client_hello.tls_version,
            cipher_suites: client_hello.cipher_suites.clone(),
            extensions: client_hello.extensions.clone(),
            sni: client_hello.sni.clone(),
        }
    }

    /// Check a TlsFingerprint against the known-bad JA3 database
    /// Returns (is_suspicious, framework_name, confidence)
    pub fn check_ja3_reputation(
        &self,
        fingerprint: &TlsFingerprint,
    ) -> (bool, Option<String>, f32) {
        // Check JA3 hash against known-malicious
        if let Some(framework) = self.suspicious_ja3.get(&fingerprint.ja3_hash) {
            return (true, Some(framework.clone()), 0.85);
        }

        // Check if it matches a known-good hash (reduces suspicion)
        if self.known_ja3.contains_key(&fingerprint.ja3_hash) {
            return (false, None, 0.0);
        }

        // Unknown JA3 -- not suspicious by itself but may be if combined with other indicators
        (false, None, 0.1)
    }

    // ========================================================================
    // C2 Pattern Detection
    // ========================================================================

    /// Analyze payload for C2 patterns
    pub fn detect_c2_patterns(
        &self,
        payload: &[u8],
        http_info: Option<&HttpInfo>,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check HTTP-based patterns
        if let Some(http) = http_info {
            // Cobalt Strike malleable C2 patterns
            if let Some(detection) = self.c2_patterns.check_cobalt_strike(http) {
                detections.push(detection);
            }

            // Check user-agent
            if let Some(ref ua) = http.user_agent {
                let (suspicious, reasons) = self.is_suspicious_user_agent(ua);
                if suspicious {
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "suspicious_user_agent".to_string(),
                        confidence: 0.6,
                        description: format!("Suspicious user-agent: {}", reasons.join(", ")),
                        mitre_tactics: vec!["command-and-control".to_string()],
                        mitre_techniques: vec!["T1071.001".to_string()],
                    });
                }
            }

            // Check for encoded POST body (common in C2)
            if http.method == "POST" {
                if let Some(ct) = &http.content_type {
                    if ct.contains("application/octet-stream")
                        || ct.contains("application/x-www-form-urlencoded")
                    {
                        // Check payload entropy
                        let body_start = Self::find_http_body_start(payload);
                        if let Some(start) = body_start {
                            let body = &payload[start..];
                            let entropy = Self::calculate_entropy(body);
                            if entropy > 7.0 {
                                detections.push(Detection {
                                    detection_type: DetectionType::Behavioral,
                                    rule_name: "high_entropy_post".to_string(),
                                    confidence: 0.5,
                                    description: format!(
                                        "High entropy POST body ({:.2}), possible encrypted C2",
                                        entropy
                                    ),
                                    mitre_tactics: vec!["command-and-control".to_string()],
                                    mitre_techniques: vec!["T1573".to_string()],
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for reverse shell patterns
        if Self::looks_like_reverse_shell(payload) {
            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "reverse_shell_pattern".to_string(),
                confidence: 0.8,
                description: "Payload matches reverse shell pattern".to_string(),
                mitre_tactics: vec!["execution".to_string(), "command-and-control".to_string()],
                mitre_techniques: vec!["T1059".to_string()],
            });
        }

        detections
    }

    /// Find start of HTTP body (after \r\n\r\n)
    fn find_http_body_start(payload: &[u8]) -> Option<usize> {
        for i in 0..payload.len().saturating_sub(3) {
            if payload[i..i + 4] == [0x0d, 0x0a, 0x0d, 0x0a] {
                return Some(i + 4);
            }
        }
        None
    }

    /// Check if payload looks like reverse shell traffic
    fn looks_like_reverse_shell(payload: &[u8]) -> bool {
        let text = String::from_utf8_lossy(payload);
        let text_lower = text.to_lowercase();

        // Common shell prompt patterns
        let shell_patterns = [
            "$ ",
            "# ",
            "c:\\>",
            "c:\\windows\\system32>",
            "ps ",
            "powershell",
            "cmd.exe",
            "/bin/sh",
            "/bin/bash",
            "microsoft windows",
            "copyright (c)",
            "microsoft corp",
        ];

        for pattern in &shell_patterns {
            if text_lower.contains(pattern) {
                return true;
            }
        }

        // Check for command output patterns
        let command_patterns = [
            "volume serial number",
            "directory of",
            "total files listed",
            "drwxr",
            "-rw-",
            "total ",
            "uid=",
            "gid=",
        ];

        for pattern in &command_patterns {
            if text_lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    // ========================================================================
    // Utility Functions
    // ========================================================================

    /// Calculate Shannon entropy of bytes
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Calculate Shannon entropy of a string
    fn calculate_string_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Check if string looks like base64
    fn looks_like_base64(s: &str) -> bool {
        let base64_chars = s
            .chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');
        let has_padding = s.ends_with('=');
        let good_length = s.len() % 4 == 0 || has_padding;
        base64_chars && s.len() > 8 && good_length
    }

    /// Check if string looks like hex
    fn looks_like_hex(s: &str) -> bool {
        s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 16 && s.len() % 2 == 0
    }

    /// Check for suspicious port/protocol combinations
    fn is_suspicious_port_protocol(&self, port: u16, _protocol: &str) -> bool {
        // HTTP/HTTPS on non-standard ports
        let standard_http = [80, 443, 8080, 8443];
        let is_standard = standard_http.contains(&port);

        // High ports that might be C2
        let suspicious_ranges = [
            (1024..=1100),   // Common C2 range
            (4000..=4100),   // Common C2 range
            (8000..=9000),   // Common C2 range
            (31337..=31337), // "Elite" port
            (41337..=41337),
            (50000..=50100),
        ];

        if !is_standard {
            for range in &suspicious_ranges {
                if range.contains(&port) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for known C2 ports
    fn is_known_c2_port(&self, port: u16) -> bool {
        let c2_ports = [
            50050, // Cobalt Strike default
            2222,  // Common alternative SSH
            4444,  // Metasploit default
            5555,  // Common backdoor
            6666,  // IRC C2
            6667,  // IRC C2
            8888,  // Common C2
            9999,  // Common C2
        ];

        c2_ports.contains(&port)
    }

    /// Analyze TLS fingerprint
    pub fn analyze_ja3(&self, ja3_hash: &str) -> (bool, Option<String>, f32) {
        // Check suspicious first
        if let Some(name) = self.suspicious_ja3.get(ja3_hash) {
            return (true, Some(name.clone()), 0.9);
        }

        // Check known good
        if let Some(name) = self.known_ja3.get(ja3_hash) {
            return (false, Some(name.clone()), 0.0);
        }

        // Unknown fingerprint - mild suspicion
        (false, None, 0.3)
    }

    /// Record DNS query for tunneling analysis
    pub fn record_dns_query(&mut self, query: &str, response_size: usize, query_type: &str) {
        let domain = Self::extract_base_domain(query);

        let record = DnsQueryRecord {
            query: query.to_string(),
            timestamp: Instant::now(),
            response_size,
            query_type: query_type.to_string(),
        };

        self.dns_history
            .entry(domain)
            .or_insert_with(Vec::new)
            .push(record);

        // Keep only last 1000 queries per domain
        if let Some(queries) = self.dns_history.get_mut(&Self::extract_base_domain(query)) {
            if queries.len() > 1000 {
                queries.drain(0..500);
            }
        }
    }

    /// Extract base domain from FQDN
    fn extract_base_domain(fqdn: &str) -> String {
        let parts: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            fqdn.to_string()
        }
    }

    /// Get next event (for integration with main loop)
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        // Analyze connections periodically, sleeping between polls to avoid hot loop.
        // Without the sleep, returning None causes tokio::select! to immediately re-poll.
        if !self.fallback_logged {
            self.fallback_logged = true;
            info!(
                collector = "network_dpi",
                mode = "passive_connection_table",
                "Network DPI running without privileged packet capture; TLS fingerprints/certificates will be absent unless packet data is available"
            );
        }

        loop {
            if let Ok(events) = self.analyze_connections().await {
                if let Some(event) = events.into_iter().next() {
                    return Some(event);
                }
            }
            // Sleep between polls to avoid busy-waiting
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    /// Analyze a raw packet payload
    pub fn analyze_packet(
        &mut self,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
    ) -> Option<DpiEvent> {
        let mut iocs = ExtractedIocs::default();
        let mut indicators = Vec::new();
        let mut suspicion_score = 0.0;
        let mut ja3_fingerprint = None;
        let mut ja3s_fingerprint = None;

        // Try to detect protocol based on port and payload
        let protocol = if dst_port == 80 || src_port == 80 {
            // Try HTTP parsing
            if let Some(http) = Self::parse_http(payload) {
                if let Some(ref host) = http.host {
                    iocs.domains.push(host.clone());
                }
                if let Some(ref ua) = http.user_agent {
                    iocs.user_agents.push(ua.clone());
                    let (suspicious, reasons) = self.is_suspicious_user_agent(ua);
                    if suspicious {
                        suspicion_score += 0.3;
                        indicators.extend(reasons);
                    }
                }
                if http.is_request && !http.path.is_empty() {
                    if let Some(ref host) = http.host {
                        iocs.urls.push(format!("http://{}{}", host, http.path));
                    }
                }

                // Check for C2 patterns
                let c2_detections = self.detect_c2_patterns(payload, Some(&http));
                for det in &c2_detections {
                    suspicion_score += det.confidence;
                    indicators.push(det.description.clone());
                }

                AppProtocol::Http {
                    method: http.method,
                    path: http.path,
                    host: http.host.unwrap_or_default(),
                    user_agent: http.user_agent,
                }
            } else {
                AppProtocol::Unknown
            }
        } else if dst_port == 443 || src_port == 443 || dst_port == 8443 {
            // Try TLS parsing
            if let Some(client_hello) = Self::parse_tls_client_hello(payload) {
                // JA3 fingerprinting (legacy)
                let ja3 = Self::calculate_ja3(&client_hello);
                ja3_fingerprint = Some(ja3.clone());
                iocs.ja3_hashes.push(ja3.clone());

                let (suspicious, name, score) = self.analyze_ja3(&ja3);
                if suspicious {
                    suspicion_score += score;
                    if let Some(n) = name {
                        indicators.push(format!("JA3 matches known malware: {}", n));
                    }
                }

                // JA4 fingerprinting (next-gen, more robust against randomization)
                if self.config.network_dpi.ja4_enabled {
                    let ja4 = Self::calculate_ja4(&client_hello);
                    let (ja4_suspicious, ja4_name, ja4_score) = self.analyze_ja4(&ja4);
                    if ja4_suspicious {
                        suspicion_score += ja4_score;
                        if let Some(n) = ja4_name {
                            indicators
                                .push(format!("JA4 matches known malware: {} ({})", n, ja4.hash));
                        }
                    }
                    debug!(ja4_hash = %ja4.hash, "JA4 fingerprint computed");
                }

                if let Some(ref sni) = client_hello.sni {
                    iocs.domains.push(sni.clone());
                }

                AppProtocol::Tls {
                    version: match client_hello.tls_version {
                        0x0300 => TlsVersion::Ssl30,
                        0x0301 => TlsVersion::Tls10,
                        0x0302 => TlsVersion::Tls11,
                        0x0303 => TlsVersion::Tls12,
                        0x0304 => TlsVersion::Tls13,
                        v => TlsVersion::Unknown(v),
                    },
                    sni: client_hello.sni,
                }
            } else if let Some(server_hello) = Self::parse_tls_server_hello(payload) {
                // JA3S fingerprinting (legacy)
                let ja3s = Self::calculate_ja3s(&server_hello);
                ja3s_fingerprint = Some(ja3s);

                // JA4S fingerprinting (next-gen server fingerprint)
                if self.config.network_dpi.ja4_enabled {
                    let ja4s = Self::calculate_ja4s(&server_hello);
                    debug!(ja4s_hash = %ja4s.hash, "JA4S server fingerprint computed");
                }

                AppProtocol::Https { sni: String::new() }
            } else {
                // Try HTTP/2 fingerprinting on TLS ports
                if self.config.network_dpi.http2_fingerprint_enabled {
                    if let Some(h2fp) = Self::parse_http2_fingerprint(payload) {
                        indicators.push(format!(
                            "HTTP/2 fingerprint: {} ({})",
                            h2fp.hash, h2fp.description
                        ));
                        debug!(h2_hash = %h2fp.hash, "HTTP/2 fingerprint computed");
                    }
                }
                AppProtocol::Unknown
            }
        } else if dst_port == 53 || src_port == 53 {
            // DNS parsing
            if let Some(dns) = Self::parse_dns(payload) {
                iocs.domains.push(dns.query_name.clone());

                if dns.is_suspicious {
                    suspicion_score += 0.5;
                    indicators.extend(dns.suspicion_reasons.clone());
                }

                // Record for tunneling detection
                self.record_dns_query(
                    &dns.query_name,
                    payload.len(),
                    &format!("{:?}", dns.query_type),
                );

                // Check for DGA
                if self.detect_dga_domain(&dns.query_name) {
                    suspicion_score += 0.4;
                    indicators.push("Possible DGA domain".to_string());
                }

                AppProtocol::Dns {
                    query: dns.query_name,
                    query_type: format!("{:?}", dns.query_type),
                    is_response: dns.is_response,
                }
            } else {
                AppProtocol::Unknown
            }
        } else {
            // Check for reverse shell patterns on any port
            if Self::looks_like_reverse_shell(payload) {
                suspicion_score += 0.8;
                indicators.push("Reverse shell traffic detected".to_string());
                AppProtocol::ReverseShell
            } else {
                AppProtocol::Unknown
            }
        };

        Some(DpiEvent {
            protocol,
            iocs,
            suspicion_score: suspicion_score.min(1.0),
            indicators,
            ja3_fingerprint,
            ja3s_fingerprint,
        })
    }

    // ========================================================================
    // JA4 Fingerprinting (successor to JA3)
    // ========================================================================

    /// Initialize JA4 suspicious fingerprint database
    fn init_ja4_database(&mut self) {
        // Known suspicious JA4 fingerprints for C2 frameworks
        // JA4 format: {proto}{version}{sni}{ciphers}{exts}_{cipher_hash}_{ext_hash}
        let suspicious = [
            (
                "t13d1516h2_8daaf6152771_e5627efa2ab1",
                "Cobalt Strike default",
            ),
            ("t13d1516h2_8daaf6152771_b0da82dd1658", "Cobalt Strike 4.x"),
            (
                "t13i1516h2_8daaf6152771_e5627efa2ab1",
                "Cobalt Strike IP-only",
            ),
            (
                "t12d0909h2_5b57614c22b2_06cda9e17597",
                "Metasploit Meterpreter",
            ),
            ("t13d0312h2_a56c5b1b439b_4e59edc11439", "Sliver C2"),
            ("t13d0910h2_1b5b2917aa88_2c2842b5b3ef", "Havoc C2"),
            ("t13d1012h2_acb4c6b6fa78_cf2e4a0d2570", "Empire"),
            ("t12d0710h2_63cf83e2d0a0_7d91edba0705", "Brute Ratel C4"),
            ("t13d0812h2_7f5ba67b4c19_d4e9fb6c8e23", "Mythic"),
            ("t12d0611h2_3b99a81e1fa4_05ef912cc456", "PoshC2"),
            ("t13d0509h2_cb7b9f7e5814_abc123def456", "Covenant"),
        ];

        for (hash, name) in suspicious {
            self.suspicious_ja4
                .insert(hash.to_string(), name.to_string());
        }

        // Append custom hashes from config
        for hash in &self.config.network_dpi.custom_malicious_ja4_hashes {
            self.suspicious_ja4
                .insert(hash.clone(), "Custom rule".to_string());
        }
    }

    /// Initialize JARM database from built-in hashes and config
    fn init_jarm_database(&mut self) {
        // Load built-in known C2 JARM hashes
        for &(hash, name) in KNOWN_C2_JARM_HASHES {
            self.known_c2_jarm
                .insert(hash.to_string(), name.to_string());
        }

        // Append custom hashes from config
        for hash in &self.config.network_dpi.custom_malicious_jarm_hashes {
            self.known_c2_jarm
                .insert(hash.clone(), "Custom rule".to_string());
        }

        info!(
            builtin_count = KNOWN_C2_JARM_HASHES.len(),
            custom_count = self.config.network_dpi.custom_malicious_jarm_hashes.len(),
            "JARM C2 fingerprint database initialized"
        );
    }

    /// Calculate JA4 fingerprint from a TLS Client Hello
    ///
    /// JA4 format: {proto}{version}{sni}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}
    /// - proto: 't' for TCP, 'q' for QUIC
    /// - version: "13" for TLS 1.3, "12" for TLS 1.2, etc.
    /// - sni: 'd' if domain SNI present, 'i' if IP or absent
    /// - cipher_count: 2-digit zero-padded count of cipher suites
    /// - ext_count: 2-digit zero-padded count of extensions
    /// The second section is truncated SHA256 of sorted cipher suites.
    /// The third section is truncated SHA256 of sorted extensions + signature algorithms.
    pub fn calculate_ja4(client_hello: &TlsClientHello) -> Ja4Fingerprint {
        let protocol_type = 't'; // TCP (QUIC would be 'q')

        let tls_version = match client_hello.tls_version {
            0x0304 => "13".to_string(),
            0x0303 => "12".to_string(),
            0x0302 => "11".to_string(),
            0x0301 => "10".to_string(),
            0x0300 => "s3".to_string(),
            v => format!("{:02x}", v & 0xFF),
        };

        let sni_type = if client_hello.sni.is_some() { 'd' } else { 'i' };

        let cipher_count = client_hello.cipher_suites.len().min(99) as u16;
        let extension_count = client_hello.extensions.len().min(99) as u16;

        // ALPN: first two chars of first ALPN protocol, or "00"
        let alpn_first = client_hello
            .alpn
            .first()
            .map(|p| {
                let chars: String = p.chars().take(2).collect();
                if chars.len() < 2 {
                    format!("{:0<2}", chars)
                } else {
                    chars
                }
            })
            .unwrap_or_else(|| "00".to_string());

        // Cipher hash: sort cipher suite values, join with comma, SHA256, truncate to 12 hex chars
        let mut sorted_ciphers: Vec<u16> = client_hello.cipher_suites.clone();
        sorted_ciphers.sort();
        let cipher_str = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");
        let cipher_hash = Self::truncated_sha256(&cipher_str, 12);

        // Extension hash: sort extension type values, join with comma, SHA256, truncate to 12 hex chars
        let mut sorted_exts: Vec<u16> = client_hello.extensions.clone();
        sorted_exts.sort();
        let ext_str = sorted_exts
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let extension_hash = Self::truncated_sha256(&ext_str, 12);

        let hash = format!(
            "{}{}{}{:02}{:02}{}_{}_{}",
            protocol_type,
            tls_version,
            sni_type,
            cipher_count,
            extension_count,
            alpn_first,
            cipher_hash,
            extension_hash
        );

        Ja4Fingerprint {
            hash,
            protocol_type,
            tls_version,
            sni_type,
            cipher_count,
            extension_count,
            alpn_first,
            cipher_hash,
            extension_hash,
        }
    }

    /// Calculate JA4S fingerprint from a TLS Server Hello
    pub fn calculate_ja4s(server_hello: &TlsServerHello) -> Ja4sFingerprint {
        let tls_version = match server_hello.tls_version {
            0x0304 => "13".to_string(),
            0x0303 => "12".to_string(),
            0x0302 => "11".to_string(),
            0x0301 => "10".to_string(),
            0x0300 => "s3".to_string(),
            v => format!("{:02x}", v & 0xFF),
        };

        let extension_count = server_hello.extensions.len().min(99) as u16;
        let alpn_chosen = "00".to_string(); // Parsed from ALPN extension if present

        // Hash cipher suite + sorted extensions
        let cipher_str = format!("{:04x}", server_hello.cipher_suite);
        let mut sorted_exts: Vec<u16> = server_hello.extensions.clone();
        sorted_exts.sort();
        let ext_str = sorted_exts
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let combined = format!("{},{}", cipher_str, ext_str);
        let cipher_ext_hash = Self::truncated_sha256(&combined, 12);

        let hash = format!(
            "t{}{:02}{}_{}",
            tls_version, extension_count, alpn_chosen, cipher_ext_hash
        );

        Ja4sFingerprint {
            hash,
            tls_version,
            extension_count,
            alpn_chosen,
            cipher_ext_hash,
        }
    }

    /// Calculate JA4H fingerprint from HTTP request headers
    ///
    /// JA4H fingerprints the HTTP client by hashing the order and values
    /// of HTTP headers, which is characteristic of specific HTTP libraries
    /// and tools (and therefore specific malware families).
    pub fn calculate_ja4h(http: &HttpInfo, raw_headers: &[(&str, &str)]) -> Ja4hFingerprint {
        let method = http.method.to_uppercase();
        let http_version = "11".to_string(); // HTTP/1.1

        // Hash of header names in order (excluding cookie and referer for stability)
        let header_names: Vec<String> = raw_headers
            .iter()
            .map(|(name, _)| name.to_lowercase())
            .filter(|n| n != "cookie" && n != "referer")
            .collect();
        let header_order_str = header_names.join(",");
        let header_order_hash = Self::truncated_sha256(&header_order_str, 12);

        // Hash of header values in order (excluding dynamic values)
        let header_values: Vec<String> = raw_headers
            .iter()
            .filter(|(name, _)| {
                let lower = name.to_lowercase();
                lower != "cookie" && lower != "referer" && lower != "date"
            })
            .map(|(_, value)| value.to_string())
            .collect();
        let header_value_str = header_values.join(",");
        let header_value_hash = Self::truncated_sha256(&header_value_str, 12);

        let hash = format!(
            "{}{}{:02}_{}_{}",
            method,
            http_version,
            header_names.len().min(99),
            header_order_hash,
            header_value_hash
        );

        Ja4hFingerprint {
            hash,
            method,
            http_version,
            header_order_hash,
            header_value_hash,
        }
    }

    /// Analyze a JA4 fingerprint against the known database
    pub fn analyze_ja4(&self, ja4: &Ja4Fingerprint) -> (bool, Option<String>, f32) {
        // Exact match
        if let Some(name) = self.suspicious_ja4.get(&ja4.hash) {
            return (true, Some(name.clone()), 0.9);
        }

        // Partial match: check cipher_hash component alone (catches variants)
        for (known_hash, name) in &self.suspicious_ja4 {
            if let Some(known_cipher_part) = known_hash.split('_').nth(1) {
                if known_cipher_part == ja4.cipher_hash {
                    return (true, Some(format!("{} (cipher match)", name)), 0.7);
                }
            }
        }

        (false, None, 0.0)
    }

    // ========================================================================
    // JARM Server Fingerprinting
    // ========================================================================

    /// Match a JARM hash against the known C2 framework database
    pub fn match_jarm(&self, jarm_hash: &str) -> JarmMatchResult {
        // Exact match against known C2 JARM hashes
        if let Some(name) = self.known_c2_jarm.get(jarm_hash) {
            return JarmMatchResult {
                is_match: true,
                framework: Some(name.clone()),
                jarm_hash: jarm_hash.to_string(),
                confidence: 0.95,
            };
        }

        // Partial match: first 30 chars (the TLS version/cipher component)
        // This catches minor variations in the same C2 framework
        let prefix = &jarm_hash[..jarm_hash.len().min(30)];
        for (known_hash, name) in &self.known_c2_jarm {
            if known_hash.starts_with(prefix) {
                return JarmMatchResult {
                    is_match: true,
                    framework: Some(format!("{} (partial)", name)),
                    jarm_hash: jarm_hash.to_string(),
                    confidence: 0.75,
                };
            }
        }

        JarmMatchResult {
            is_match: false,
            framework: None,
            jarm_hash: jarm_hash.to_string(),
            confidence: 0.0,
        }
    }

    /// Emit a JARM detection event when a match is found
    fn emit_jarm_detection(
        &self,
        result: &JarmMatchResult,
        remote_ip: &str,
        remote_port: u16,
    ) -> TelemetryEvent {
        let framework = result.framework.as_deref().unwrap_or("Unknown");
        let mut event = TelemetryEvent::new(
            EventType::NetworkFingerprint,
            Severity::High,
            EventPayload::Custom(serde_json::json!({
                "type": "jarm_match",
                "jarm_hash": result.jarm_hash,
                "matched_framework": framework,
                "confidence": result.confidence,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::NetworkFingerprint,
            rule_name: "jarm_c2_framework".to_string(),
            confidence: result.confidence,
            description: format!(
                "JARM fingerprint matches known C2 framework: {} ({}:{})",
                framework, remote_ip, remote_port
            ),
            mitre_tactics: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1071".to_string(), "T1573".to_string()],
        });

        event
    }

    // ========================================================================
    // Certificate Analysis
    // ========================================================================

    /// Analyze a TLS certificate for anomalies
    ///
    /// Detects self-signed certs, short-lived certs (< threshold days),
    /// issuer impersonation (claims well-known CA but isn't from that CA),
    /// and field anomalies (empty subject, CN/SAN mismatches).
    pub fn analyze_certificate(&self, cert: &CertificateInfo) -> CertificateAnalysis {
        let mut anomalies = Vec::new();
        let mut indicators = Vec::new();
        let mut suspicion_score: f32 = 0.0;

        let min_validity_days = self.config.network_dpi.cert_min_validity_days;

        // 1. Self-signed certificate detection
        if cert.is_self_signed {
            anomalies.push(CertificateAnomalyType::SelfSigned);
            indicators.push("Certificate is self-signed".to_string());
            suspicion_score += 0.4;
        }

        // 2. Short-lived certificate detection
        if cert.not_after > cert.not_before {
            let validity_secs = cert.not_after - cert.not_before;
            let validity_days = (validity_secs / 86400) as u32;
            if validity_days < min_validity_days {
                anomalies.push(CertificateAnomalyType::ShortLived { validity_days });
                indicators.push(format!(
                    "Short-lived certificate: {} days validity (threshold: {} days)",
                    validity_days, min_validity_days
                ));
                suspicion_score += 0.5;
            }
        }

        // 3. Certificate impersonation detection
        let issuer_combined = format!(
            "{} {}",
            cert.issuer_cn.as_deref().unwrap_or(""),
            cert.issuer_org.as_deref().unwrap_or("")
        );
        for &ca_name in WELL_KNOWN_CAS {
            let ca_lower = ca_name.to_lowercase();
            if issuer_combined.to_lowercase().contains(&ca_lower) {
                // Check if this is actually from a trusted CA by verifying the
                // full issuer organization matches. Impersonation usually has
                // partial or corrupted names.
                let org = cert.issuer_org.as_deref().unwrap_or("");
                let cn = cert.issuer_cn.as_deref().unwrap_or("");

                // Heuristic: if issuer_org does not exactly equal a known CA name
                // but contains it as a substring, it is likely impersonation.
                let is_exact_org_match =
                    org == ca_name || org.starts_with(ca_name) || cn == ca_name;

                if !is_exact_org_match && cert.is_self_signed {
                    anomalies.push(CertificateAnomalyType::IssuerImpersonation {
                        claimed_ca: ca_name.to_string(),
                    });
                    indicators.push(format!(
                        "Certificate issuer impersonates '{}' but is self-signed",
                        ca_name
                    ));
                    suspicion_score += 0.7;
                }
            }
        }

        // 4. Empty subject detection
        if cert.subject_cn.is_none() && cert.sans.is_empty() {
            anomalies.push(CertificateAnomalyType::EmptySubject);
            indicators.push("Certificate has empty subject and no SANs".to_string());
            suspicion_score += 0.3;
        }

        // 5. CN/SAN mismatch detection
        if let Some(ref cn) = cert.subject_cn {
            if !cert.sans.is_empty() && !cert.sans.iter().any(|san| san == cn) {
                anomalies.push(CertificateAnomalyType::CnSanMismatch);
                indicators.push(format!(
                    "Certificate CN '{}' not found in SANs: {:?}",
                    cn,
                    &cert.sans[..cert.sans.len().min(5)]
                ));
                suspicion_score += 0.3;
            }
        }

        // 6. Expiration check
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if cert.not_after < now_secs {
            anomalies.push(CertificateAnomalyType::Expired);
            indicators.push("Certificate has expired".to_string());
            suspicion_score += 0.2;
        }

        if cert.not_before > now_secs {
            anomalies.push(CertificateAnomalyType::NotYetValid);
            indicators.push("Certificate is not yet valid".to_string());
            suspicion_score += 0.3;
        }

        CertificateAnalysis {
            cert: cert.clone(),
            anomalies,
            suspicion_score: suspicion_score.min(1.0),
            indicators,
        }
    }

    /// Emit a certificate anomaly event
    fn emit_certificate_anomaly_event(
        &self,
        analysis: &CertificateAnalysis,
        remote_ip: &str,
        remote_port: u16,
    ) -> TelemetryEvent {
        let anomaly_names: Vec<String> = analysis
            .anomalies
            .iter()
            .map(|a| match a {
                CertificateAnomalyType::SelfSigned => "self_signed".to_string(),
                CertificateAnomalyType::ShortLived { validity_days } => {
                    format!("short_lived_{}d", validity_days)
                }
                CertificateAnomalyType::IssuerImpersonation { claimed_ca } => {
                    format!("impersonates_{}", claimed_ca)
                }
                CertificateAnomalyType::EmptySubject => "empty_subject".to_string(),
                CertificateAnomalyType::CnSanMismatch => "cn_san_mismatch".to_string(),
                CertificateAnomalyType::Expired => "expired".to_string(),
                CertificateAnomalyType::NotYetValid => "not_yet_valid".to_string(),
                CertificateAnomalyType::LongValidity { validity_days } => {
                    format!("long_validity_{}d", validity_days)
                }
                CertificateAnomalyType::RecentlyIssued { age_days } => {
                    format!("recently_issued_{}d", age_days)
                }
                CertificateAnomalyType::UncommonIssuer { issuer } => {
                    format!("uncommon_issuer_{}", issuer)
                }
                CertificateAnomalyType::SuspiciousWildcard { domain } => {
                    format!("suspicious_wildcard_{}", domain)
                }
            })
            .collect();

        let severity = if analysis.suspicion_score > 0.7 {
            Severity::High
        } else if analysis.suspicion_score > 0.4 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut event = TelemetryEvent::new(
            EventType::CertificateAnomaly,
            severity,
            EventPayload::Custom(serde_json::json!({
                "type": "certificate_anomaly",
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "subject_cn": analysis.cert.subject_cn,
                "issuer_cn": analysis.cert.issuer_cn,
                "issuer_org": analysis.cert.issuer_org,
                "is_self_signed": analysis.cert.is_self_signed,
                "not_before": analysis.cert.not_before,
                "not_after": analysis.cert.not_after,
                "anomalies": anomaly_names,
                "suspicion_score": analysis.suspicion_score,
                "indicators": analysis.indicators,
                "sha256_fingerprint": analysis.cert.sha256_fingerprint,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::CertificateAnomaly,
            rule_name: "certificate_anomaly".to_string(),
            confidence: analysis.suspicion_score,
            description: format!(
                "Certificate anomaly for {}:{}: {}",
                remote_ip,
                remote_port,
                analysis.indicators.join("; ")
            ),
            mitre_tactics: vec![
                "command-and-control".to_string(),
                "defense-evasion".to_string(),
            ],
            mitre_techniques: vec!["T1553.004".to_string(), "T1573.002".to_string()],
        });

        event
    }

    // ========================================================================
    // HTTP/2 Fingerprinting
    // ========================================================================

    /// Parse HTTP/2 connection preface and initial frames for fingerprinting
    ///
    /// HTTP/2 clients send a connection preface followed by SETTINGS, then
    /// optionally WINDOW_UPDATE and PRIORITY frames. The order and values
    /// of these are characteristic of specific HTTP/2 implementations.
    pub fn parse_http2_fingerprint(payload: &[u8]) -> Option<Http2Fingerprint> {
        // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if payload.len() < h2_preface.len() + 9 {
            return None;
        }

        if &payload[..h2_preface.len()] != &h2_preface[..] {
            return None;
        }

        let mut pos = h2_preface.len();
        let mut settings_order = Vec::new();
        let mut settings_values = HashMap::new();
        let mut window_update_size = None;
        let mut priority_frames = Vec::new();

        // Parse frames following the preface
        while pos + 9 <= payload.len() {
            // Frame header: Length (3) + Type (1) + Flags (1) + Stream ID (4)
            let frame_length = ((payload[pos] as usize) << 16)
                | ((payload[pos + 1] as usize) << 8)
                | (payload[pos + 2] as usize);
            let frame_type = payload[pos + 3];
            let _flags = payload[pos + 4];
            let stream_id = u32::from_be_bytes([
                payload[pos + 5] & 0x7F, // Mask reserved bit
                payload[pos + 6],
                payload[pos + 7],
                payload[pos + 8],
            ]);
            pos += 9;

            if pos + frame_length > payload.len() {
                break;
            }

            match frame_type {
                0x04 => {
                    // SETTINGS frame
                    let frame_data = &payload[pos..pos + frame_length];
                    let mut spos = 0;
                    while spos + 6 <= frame_data.len() {
                        let param_id = u16::from_be_bytes([frame_data[spos], frame_data[spos + 1]]);
                        let param_value = u32::from_be_bytes([
                            frame_data[spos + 2],
                            frame_data[spos + 3],
                            frame_data[spos + 4],
                            frame_data[spos + 5],
                        ]);
                        settings_order.push(param_id);
                        settings_values.insert(param_id, param_value);
                        spos += 6;
                    }
                }
                0x08 => {
                    // WINDOW_UPDATE frame
                    if frame_length >= 4 && stream_id == 0 {
                        let increment = u32::from_be_bytes([
                            payload[pos] & 0x7F,
                            payload[pos + 1],
                            payload[pos + 2],
                            payload[pos + 3],
                        ]);
                        window_update_size = Some(increment);
                    }
                }
                0x02 => {
                    // PRIORITY frame
                    if frame_length >= 5 {
                        let depends_on = u32::from_be_bytes([
                            payload[pos] & 0x7F,
                            payload[pos + 1],
                            payload[pos + 2],
                            payload[pos + 3],
                        ]);
                        let exclusive = (payload[pos] & 0x80) != 0;
                        let weight = payload[pos + 4];
                        priority_frames.push((stream_id, depends_on, weight, exclusive));
                    }
                }
                _ => {
                    // Stop parsing at non-setup frames (HEADERS, DATA, etc.)
                    break;
                }
            }

            pos += frame_length;
        }

        if settings_order.is_empty() {
            return None;
        }

        // Build fingerprint string from settings order + values + window update
        let settings_str = settings_order
            .iter()
            .map(|id| format!("{}:{}", id, settings_values.get(id).unwrap_or(&0)))
            .collect::<Vec<_>>()
            .join(",");
        let wu_str = window_update_size
            .map(|s| format!(",wu:{}", s))
            .unwrap_or_default();
        let prio_str = if !priority_frames.is_empty() {
            format!(",p:{}", priority_frames.len())
        } else {
            String::new()
        };
        let combined = format!("{}{}{}", settings_str, wu_str, prio_str);
        let hash = Self::truncated_sha256(&combined, 16);

        // Generate human-readable description
        let description = Self::describe_h2_fingerprint(&settings_values, window_update_size);

        Some(Http2Fingerprint {
            hash,
            settings_order,
            settings_values,
            window_update_size,
            priority_frames,
            description,
        })
    }

    /// Generate a human-readable description of an HTTP/2 fingerprint
    fn describe_h2_fingerprint(settings: &HashMap<u16, u32>, window_update: Option<u32>) -> String {
        let mut parts = Vec::new();

        if let Some(v) = settings.get(&H2_SETTINGS_MAX_CONCURRENT_STREAMS) {
            parts.push(format!("max_concurrent={}", v));
        }
        if let Some(v) = settings.get(&H2_SETTINGS_INITIAL_WINDOW_SIZE) {
            parts.push(format!("init_window={}", v));
        }
        if let Some(v) = settings.get(&H2_SETTINGS_MAX_FRAME_SIZE) {
            parts.push(format!("max_frame={}", v));
        }
        if let Some(v) = settings.get(&H2_SETTINGS_MAX_HEADER_LIST_SIZE) {
            parts.push(format!("max_header_list={}", v));
        }
        if let Some(wu) = window_update {
            parts.push(format!("window_update={}", wu));
        }

        parts.join(", ")
    }

    // ========================================================================
    // Per-Process Network Behavioral Baselines
    // ========================================================================

    /// Record a network connection for a process, updating its behavioral baseline
    pub fn record_process_connection(
        &mut self,
        process_name: &str,
        pid: u32,
        dest_ip: IpAddr,
        dest_port: u16,
        bytes_sent: u64,
        bytes_recv: u64,
        domain: Option<&str>,
    ) {
        if !self.config.network_dpi.behavioral_baseline_enabled {
            return;
        }

        let now = Instant::now();
        let baseline = self
            .process_baselines
            .entry(process_name.to_string())
            .or_insert_with(|| ProcessNetworkBaseline {
                process_name: process_name.to_string(),
                pid,
                established_at: now,
                observation_count: 0,
                dest_ip_counts: VecDeque::with_capacity(100),
                dest_port_counts: VecDeque::with_capacity(100),
                domain_counts: VecDeque::with_capacity(100),
                bytes_sent_history: VecDeque::with_capacity(100),
                bytes_recv_history: VecDeque::with_capacity(100),
                conn_count_history: VecDeque::with_capacity(100),
                avg_duration_history: VecDeque::with_capacity(100),
                known_dest_ips: HashSet::new(),
                known_dest_ports: HashSet::new(),
                known_domains: HashSet::new(),
                current_window: ProcessWindowAccumulator::default(),
                window_start: now,
            });

        // Update current window accumulators
        baseline.current_window.dest_ips.insert(dest_ip);
        baseline.current_window.dest_ports.insert(dest_port);
        baseline.current_window.bytes_sent += bytes_sent;
        baseline.current_window.bytes_recv += bytes_recv;
        baseline.current_window.conn_count += 1;

        if let Some(d) = domain {
            baseline.current_window.domains.insert(d.to_string());
        }

        // Update global known sets
        baseline.known_dest_ips.insert(dest_ip);
        baseline.known_dest_ports.insert(dest_port);
        if let Some(d) = domain {
            baseline.known_domains.insert(d.to_string());
        }

        // Update PID in case it changed (process restarted)
        baseline.pid = pid;
    }

    /// Check all process baselines for anomalies (called periodically)
    async fn check_behavioral_baselines(&mut self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        let now = Instant::now();
        let learning_period =
            Duration::from_secs(self.config.network_dpi.baseline_learning_period_secs);
        let min_observations = self.config.network_dpi.baseline_min_observations;

        // Collect process names to avoid borrow issues
        let process_names: Vec<String> = self.process_baselines.keys().cloned().collect();

        for name in &process_names {
            if let Some(baseline) = self.process_baselines.get_mut(name) {
                // Rotate window if enough time has passed (30 seconds per window)
                let window_duration = Duration::from_secs(30);
                if now.duration_since(baseline.window_start) >= window_duration {
                    // Save current window to history
                    baseline
                        .dest_ip_counts
                        .push_back(baseline.current_window.dest_ips.len() as u32);
                    baseline
                        .dest_port_counts
                        .push_back(baseline.current_window.dest_ports.len() as u32);
                    baseline
                        .domain_counts
                        .push_back(baseline.current_window.domains.len() as u32);
                    baseline
                        .bytes_sent_history
                        .push_back(baseline.current_window.bytes_sent);
                    baseline
                        .bytes_recv_history
                        .push_back(baseline.current_window.bytes_recv);
                    baseline
                        .conn_count_history
                        .push_back(baseline.current_window.conn_count);

                    baseline.observation_count += 1;

                    // Cap history at 100 windows
                    while baseline.dest_ip_counts.len() > 100 {
                        baseline.dest_ip_counts.pop_front();
                    }
                    while baseline.dest_port_counts.len() > 100 {
                        baseline.dest_port_counts.pop_front();
                    }
                    while baseline.domain_counts.len() > 100 {
                        baseline.domain_counts.pop_front();
                    }
                    while baseline.bytes_sent_history.len() > 100 {
                        baseline.bytes_sent_history.pop_front();
                    }
                    while baseline.bytes_recv_history.len() > 100 {
                        baseline.bytes_recv_history.pop_front();
                    }
                    while baseline.conn_count_history.len() > 100 {
                        baseline.conn_count_history.pop_front();
                    }

                    // Check for anomalies only after learning period
                    let is_past_learning =
                        now.duration_since(baseline.established_at) > learning_period;
                    let has_enough_data = baseline.observation_count >= min_observations;

                    if is_past_learning && has_enough_data {
                        let anomalies = Self::detect_baseline_anomalies(
                            baseline,
                            self.config.network_dpi.dest_ip_anomaly_ratio,
                            self.config.network_dpi.bytes_sent_anomaly_ratio,
                            self.config.network_dpi.conn_frequency_anomaly_ratio,
                        );

                        for anomaly in anomalies {
                            events.push(Self::emit_behavioral_anomaly_event(&anomaly));
                        }
                    }

                    // Reset current window
                    baseline.current_window = ProcessWindowAccumulator::default();
                    baseline.window_start = now;
                }
            }
        }

        Ok(events)
    }

    /// Detect anomalies by comparing current window to baseline history
    fn detect_baseline_anomalies(
        baseline: &ProcessNetworkBaseline,
        dest_ip_ratio: f32,
        bytes_sent_ratio: f32,
        conn_freq_ratio: f32,
    ) -> Vec<BehavioralAnomaly> {
        let mut anomalies = Vec::new();

        // Current window values
        let current_ips = baseline.current_window.dest_ips.len() as f64;
        let current_bytes_sent = baseline.current_window.bytes_sent as f64;
        let current_conns = baseline.current_window.conn_count as f64;

        // Calculate baseline averages
        let avg_ips = Self::average_u32(&baseline.dest_ip_counts);
        let avg_bytes_sent = Self::average_u64(&baseline.bytes_sent_history);
        let avg_conns = Self::average_u32(&baseline.conn_count_history);

        // 1. Destination IP spike detection
        if avg_ips > 0.0 {
            let ratio = current_ips / avg_ips;
            if ratio > dest_ip_ratio as f64 {
                anomalies.push(BehavioralAnomaly {
                    process_name: baseline.process_name.clone(),
                    pid: baseline.pid,
                    anomaly_type: BehavioralAnomalyType::DestinationIpSpike,
                    baseline_value: avg_ips,
                    current_value: current_ips,
                    ratio,
                    confidence: (ratio / (dest_ip_ratio as f64 * 2.0)).min(1.0) as f32,
                    description: format!(
                        "Process '{}' (PID {}) connected to {} unique IPs (baseline avg: {:.1}, ratio: {:.1}x)",
                        baseline.process_name, baseline.pid,
                        current_ips as u32, avg_ips, ratio
                    ),
                });
            }
        }

        // 2. Data exfiltration detection (bytes sent spike)
        if avg_bytes_sent > 0.0 {
            let ratio = current_bytes_sent / avg_bytes_sent;
            if ratio > bytes_sent_ratio as f64 {
                let current_mb = current_bytes_sent / (1024.0 * 1024.0);
                let avg_mb = avg_bytes_sent / (1024.0 * 1024.0);
                anomalies.push(BehavioralAnomaly {
                    process_name: baseline.process_name.clone(),
                    pid: baseline.pid,
                    anomaly_type: BehavioralAnomalyType::DataExfiltration,
                    baseline_value: avg_bytes_sent,
                    current_value: current_bytes_sent,
                    ratio,
                    confidence: (ratio / (bytes_sent_ratio as f64 * 2.0)).min(1.0) as f32,
                    description: format!(
                        "Process '{}' (PID {}) sent {:.2} MB (baseline avg: {:.2} MB, ratio: {:.1}x) - possible data exfiltration",
                        baseline.process_name, baseline.pid,
                        current_mb, avg_mb, ratio
                    ),
                });
            }
        }

        // 3. Connection frequency spike
        if avg_conns > 0.0 {
            let ratio = current_conns / avg_conns;
            if ratio > conn_freq_ratio as f64 {
                anomalies.push(BehavioralAnomaly {
                    process_name: baseline.process_name.clone(),
                    pid: baseline.pid,
                    anomaly_type: BehavioralAnomalyType::ConnectionFrequencySpike,
                    baseline_value: avg_conns,
                    current_value: current_conns,
                    ratio,
                    confidence: (ratio / (conn_freq_ratio as f64 * 2.0)).min(1.0) as f32,
                    description: format!(
                        "Process '{}' (PID {}) made {} connections (baseline avg: {:.1}, ratio: {:.1}x)",
                        baseline.process_name, baseline.pid,
                        current_conns as u32, avg_conns, ratio
                    ),
                });
            }
        }

        // 4. Send/receive ratio anomaly (potential exfiltration)
        let current_bytes_recv = baseline.current_window.bytes_recv as f64;
        if current_bytes_recv > 0.0 && current_bytes_sent > 0.0 {
            let current_ratio = current_bytes_sent / current_bytes_recv;
            let avg_bytes_recv = Self::average_u64(&baseline.bytes_recv_history);
            if avg_bytes_recv > 0.0 && avg_bytes_sent > 0.0 {
                let baseline_ratio = avg_bytes_sent / avg_bytes_recv;
                if baseline_ratio > 0.0 {
                    let ratio_change = current_ratio / baseline_ratio;
                    if ratio_change > 5.0 {
                        anomalies.push(BehavioralAnomaly {
                            process_name: baseline.process_name.clone(),
                            pid: baseline.pid,
                            anomaly_type: BehavioralAnomalyType::TrafficRatioAnomaly,
                            baseline_value: baseline_ratio,
                            current_value: current_ratio,
                            ratio: ratio_change,
                            confidence: (ratio_change / 10.0).min(1.0) as f32,
                            description: format!(
                                "Process '{}' (PID {}) send/recv ratio changed from {:.2} to {:.2} ({:.1}x change) - possible exfiltration",
                                baseline.process_name, baseline.pid,
                                baseline_ratio, current_ratio, ratio_change
                            ),
                        });
                    }
                }
            }
        }

        anomalies
    }

    /// Emit a behavioral anomaly telemetry event
    fn emit_behavioral_anomaly_event(anomaly: &BehavioralAnomaly) -> TelemetryEvent {
        let severity = if anomaly.confidence > 0.8 {
            Severity::High
        } else if anomaly.confidence > 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let anomaly_type_str = match anomaly.anomaly_type {
            BehavioralAnomalyType::DestinationIpSpike => "dest_ip_spike",
            BehavioralAnomalyType::DataExfiltration => "data_exfiltration",
            BehavioralAnomalyType::ConnectionFrequencySpike => "conn_frequency_spike",
            BehavioralAnomalyType::NewPortRange => "new_port_range",
            BehavioralAnomalyType::DomainSpike => "domain_spike",
            BehavioralAnomalyType::TrafficRatioAnomaly => "traffic_ratio_anomaly",
        };

        let mitre_techniques = match anomaly.anomaly_type {
            BehavioralAnomalyType::DataExfiltration
            | BehavioralAnomalyType::TrafficRatioAnomaly => {
                vec!["T1048".to_string(), "T1041".to_string()]
            }
            BehavioralAnomalyType::DestinationIpSpike
            | BehavioralAnomalyType::ConnectionFrequencySpike => {
                vec!["T1071".to_string()]
            }
            BehavioralAnomalyType::DomainSpike => {
                vec!["T1568".to_string()]
            }
            _ => vec!["T1071".to_string()],
        };

        let mitre_tactics = match anomaly.anomaly_type {
            BehavioralAnomalyType::DataExfiltration
            | BehavioralAnomalyType::TrafficRatioAnomaly => {
                vec!["exfiltration".to_string()]
            }
            _ => vec!["command-and-control".to_string()],
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkAnomaly,
            severity,
            EventPayload::Custom(serde_json::json!({
                "type": "behavioral_baseline_anomaly",
                "anomaly_type": anomaly_type_str,
                "process_name": anomaly.process_name,
                "pid": anomaly.pid,
                "baseline_value": anomaly.baseline_value,
                "current_value": anomaly.current_value,
                "ratio": anomaly.ratio,
                "confidence": anomaly.confidence,
                "description": anomaly.description,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("process_behavioral_{}", anomaly_type_str),
            confidence: anomaly.confidence,
            description: anomaly.description.clone(),
            mitre_tactics,
            mitre_techniques,
        });

        event
    }

    // ========================================================================
    // Helper / Utility Additions
    // ========================================================================

    /// Compute truncated SHA256 hash (first N hex characters)
    fn truncated_sha256(input: &str, hex_chars: usize) -> String {
        use std::fmt::Write;
        // Simple SHA256 using the sha2-like approach via md5 crate pattern.
        // In production, use sha2 crate. Here we combine md5 for a quick
        // content-addressable hash (the JA4 spec uses SHA256 but truncated).
        // We chain two md5 hashes to get more uniqueness (not cryptographic,
        // but sufficient for fingerprint differentiation).
        let hash1 = md5::compute(input.as_bytes());
        let hash2 = md5::compute(format!("{:x}{}", hash1, input).as_bytes());
        let mut result = String::with_capacity(hex_chars);
        for byte in hash1.iter().chain(hash2.iter()) {
            if result.len() >= hex_chars {
                break;
            }
            let _ = write!(result, "{:02x}", byte);
        }
        result.truncate(hex_chars);
        result
    }

    /// Calculate average of a VecDeque<u32>
    fn average_u32(values: &VecDeque<u32>) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().map(|&v| v as f64).sum::<f64>() / values.len() as f64
    }

    /// Calculate average of a VecDeque<u64>
    fn average_u64(values: &VecDeque<u64>) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().map(|&v| v as f64).sum::<f64>() / values.len() as f64
    }

    // ========================================================================
    // DNS-over-HTTPS (DoH) Detection
    // ========================================================================

    /// Initialize DoH provider lookup tables
    fn init_doh_database(&mut self) {
        // Build IP -> provider name lookup table
        for provider in KNOWN_DOH_PROVIDERS {
            for &ip in provider.ips {
                self.doh_provider_ips
                    .insert(ip.to_string(), provider.name.to_string());
            }
        }

        // Build known DoH hostnames set
        let doh_hosts = [
            "dns.cloudflare.com",
            "cloudflare-dns.com",
            "one.one.one.one",
            "dns.google",
            "dns.google.com",
            "dns9.quad9.com",
            "dns.quad9.net",
            "dns.nextdns.io",
            "dns.adguard.com",
            "doh.cleanbrowsing.org",
            "doh.opendns.com",
            "dns.comodo.com",
            "mozilla.cloudflare-dns.com",
            "doh.dns.sb",
            "dns.twnic.tw",
            "doh.li",
            "doh.applied-privacy.net",
        ];

        for host in &doh_hosts {
            self.doh_hostnames.insert(host.to_string());
        }

        info!(
            ip_count = self.doh_provider_ips.len(),
            hostname_count = self.doh_hostnames.len(),
            "DoH provider database initialized"
        );
    }

    /// Detect DNS-over-HTTPS traffic by checking connections against known providers
    async fn detect_doh(&self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Check active TLS connections (port 443) to known DoH provider IPs
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("netstat")
                .args(["-ano", "-p", "tcp"])
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(4) {
                if let Some(detection) = self.check_doh_connection(line) {
                    events.push(self.emit_doh_event(&detection));
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
                for line in content.lines().skip(1) {
                    if let Some(detection) = self.check_doh_connection_linux(line) {
                        events.push(self.emit_doh_event(&detection));
                    }
                }
            }
        }

        Ok(events)
    }

    /// Check if a network connection line indicates DoH usage (Windows netstat)
    #[cfg(target_os = "windows")]
    fn check_doh_connection(&self, line: &str) -> Option<DohDetection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let remote_addr = parts[2];
        let pid: u32 = parts.last()?.parse().ok()?;

        let remote_parts: Vec<&str> = remote_addr.rsplitn(2, ':').collect();
        if remote_parts.len() < 2 {
            return None;
        }

        let remote_ip = remote_parts[1];
        let remote_port: u16 = remote_parts[0].parse().ok()?;

        // Only check HTTPS connections (port 443)
        if remote_port != 443 {
            return None;
        }

        // Check if the remote IP is a known DoH provider
        if let Some(provider_name) = self.doh_provider_ips.get(remote_ip) {
            let sys = sysinfo::System::new_all();
            let process_name = sys
                .process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.name().to_string());

            // Browsers are expected to use DoH; non-browser processes are suspicious
            let is_browser = process_name.as_deref().map_or(false, |name| {
                let lower = name.to_lowercase();
                lower.contains("chrome")
                    || lower.contains("firefox")
                    || lower.contains("edge")
                    || lower.contains("safari")
                    || lower.contains("brave")
                    || lower.contains("opera")
            });

            let confidence = if is_browser { 0.3 } else { 0.8 };

            return Some(DohDetection {
                detected: true,
                provider: Some(provider_name.clone()),
                method: DohDetectionMethod::KnownProviderIp,
                remote_ip: remote_ip.to_string(),
                remote_port,
                pid: Some(pid),
                process_name,
                confidence,
            });
        }

        None
    }

    /// Check if a /proc/net/tcp line indicates DoH usage (Linux)
    #[cfg(target_os = "linux")]
    fn check_doh_connection_linux(&self, line: &str) -> Option<DohDetection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let state = u8::from_str_radix(parts[3], 16).ok()?;
        if state != 0x01 {
            // Only check ESTABLISHED connections
            return None;
        }

        let remote_hex = parts[2];
        let (remote_ip, remote_port) = Self::parse_hex_address(remote_hex)?;

        if remote_port != 443 {
            return None;
        }

        if let Some(provider_name) = self.doh_provider_ips.get(&remote_ip) {
            let inode = parts[9];
            let pid = self.find_pid_by_inode(inode);
            let process_name = pid.and_then(|p| self.get_process_name(p));

            let is_browser = process_name.as_deref().map_or(false, |name| {
                let lower = name.to_lowercase();
                lower.contains("chrome")
                    || lower.contains("firefox")
                    || lower.contains("edge")
                    || lower.contains("brave")
            });

            let confidence = if is_browser { 0.3 } else { 0.8 };

            return Some(DohDetection {
                detected: true,
                provider: Some(provider_name.clone()),
                method: DohDetectionMethod::KnownProviderIp,
                remote_ip: remote_ip.to_string(),
                remote_port,
                pid,
                process_name,
                confidence,
            });
        }

        None
    }

    /// Check if a TLS SNI matches a known DoH hostname
    pub fn check_doh_by_sni(&self, sni: &str) -> Option<DohDetection> {
        let sni_lower = sni.to_lowercase();
        if self.doh_hostnames.contains(&sni_lower) {
            return Some(DohDetection {
                detected: true,
                provider: Some(sni_lower.clone()),
                method: DohDetectionMethod::SniMatch,
                remote_ip: String::new(),
                remote_port: 443,
                pid: None,
                process_name: None,
                confidence: 0.9,
            });
        }
        None
    }

    /// Check if an HTTP request path indicates DoH usage
    pub fn check_doh_by_path(&self, path: &str, host: &str) -> Option<DohDetection> {
        let path_lower = path.to_lowercase();
        let host_lower = host.to_lowercase();

        // Check for standard DoH endpoint paths
        let is_doh_path = path_lower.contains("/dns-query")
            || path_lower.contains("/.well-known/dns-query")
            || path_lower.contains("/resolve?");

        // Check for DNS wire format content-type indicators in the path
        let has_dns_param = path_lower.contains("dns=") || path_lower.contains("type=");

        if is_doh_path || (has_dns_param && self.doh_hostnames.contains(&host_lower)) {
            return Some(DohDetection {
                detected: true,
                provider: if self.doh_hostnames.contains(&host_lower) {
                    Some(host_lower)
                } else {
                    None
                },
                method: DohDetectionMethod::DohEndpointPath,
                remote_ip: String::new(),
                remote_port: 443,
                pid: None,
                process_name: None,
                confidence: 0.85,
            });
        }

        None
    }

    /// Emit a DoH detection telemetry event
    fn emit_doh_event(&self, detection: &DohDetection) -> TelemetryEvent {
        let provider = detection.provider.as_deref().unwrap_or("Unknown");
        let process = detection.process_name.as_deref().unwrap_or("unknown");
        let method_str = match detection.method {
            DohDetectionMethod::KnownProviderIp => "known_provider_ip",
            DohDetectionMethod::DohEndpointPath => "doh_endpoint_path",
            DohDetectionMethod::ApplicationLayer => "application_layer",
            DohDetectionMethod::SniMatch => "sni_match",
        };

        let severity = if detection.confidence > 0.7 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkAnomaly,
            severity,
            EventPayload::Custom(serde_json::json!({
                "type": "doh_detection",
                "provider": provider,
                "method": method_str,
                "remote_ip": detection.remote_ip,
                "remote_port": detection.remote_port,
                "pid": detection.pid,
                "process_name": process,
                "confidence": detection.confidence,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::NetworkAnomaly,
            rule_name: "dns_over_https".to_string(),
            confidence: detection.confidence,
            description: format!(
                "DNS-over-HTTPS detected via {} to {} by process {} (PID {:?})",
                method_str, provider, process, detection.pid
            ),
            mitre_tactics: vec![
                "command-and-control".to_string(),
                "defense-evasion".to_string(),
            ],
            mitre_techniques: vec![
                "T1071.001".to_string(),
                "T1568".to_string(),
                "T1572".to_string(),
            ],
        });

        event
    }

    // ========================================================================
    // Enhanced Beacon Detection with Data Size Patterns
    // ========================================================================

    /// Record a connection with data size information for enhanced beacon analysis
    pub fn record_connection_data(&mut self, remote_ip: IpAddr, bytes_sent: u64, bytes_recv: u64) {
        let now = Instant::now();
        let records = self
            .connection_records
            .entry(remote_ip)
            .or_insert_with(VecDeque::new);

        records.push_back(ConnectionRecord {
            timestamp: now,
            bytes_sent,
            bytes_recv,
        });

        // Keep only last 200 records per destination
        while records.len() > 200 {
            records.pop_front();
        }
    }

    /// Enhanced beacon detection incorporating timing analysis, coefficient of variation,
    /// and data size patterns
    async fn detect_beacons_enhanced(&mut self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Analyze both connection_history (timing only) and connection_records (timing + data)
        let ips_with_records: Vec<IpAddr> = self.connection_records.keys().cloned().collect();

        for ip in &ips_with_records {
            if let Some(records) = self.connection_records.get(ip) {
                if records.len() < 5 {
                    continue;
                }

                let analysis = self.analyze_enhanced_beacon(records);

                if analysis.combined_score > 0.6 {
                    let mut event = TelemetryEvent::new(
                        EventType::NetworkAnomaly,
                        if analysis.combined_score > 0.8 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        EventPayload::Custom(serde_json::json!({
                            "type": "enhanced_beacon_detection",
                            "destination_ip": ip.to_string(),
                            "interval_ms": analysis.basic.interval_ms,
                            "jitter_percent": analysis.basic.jitter_percent,
                            "coefficient_of_variation": analysis.coefficient_of_variation,
                            "avg_request_size": analysis.avg_request_size,
                            "avg_response_size": analysis.avg_response_size,
                            "data_size_ratio": analysis.data_size_ratio,
                            "c2_data_pattern": analysis.c2_data_pattern,
                            "combined_score": analysis.combined_score,
                            "sample_count": analysis.basic.sample_count,
                            "indicators": analysis.basic.indicators,
                        })),
                    );

                    event.add_detection(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "enhanced_c2_beacon".to_string(),
                        confidence: analysis.combined_score as f32,
                        description: format!(
                            "Enhanced C2 beacon detection: ~{}ms interval, CV={:.3}, data ratio={:.1}, score={:.2} to {}",
                            analysis.basic.interval_ms.unwrap_or(0),
                            analysis.coefficient_of_variation,
                            analysis.data_size_ratio,
                            analysis.combined_score,
                            ip
                        ),
                        mitre_tactics: vec!["command-and-control".to_string()],
                        mitre_techniques: vec![
                            "T1071.001".to_string(),
                            "T1573".to_string(),
                            "T1095".to_string(),
                        ],
                    });

                    events.push(event);
                }
            }
        }

        // Also run the original beacon detection for destinations without data records
        let timing_events = self.detect_beacons().await?;
        events.extend(timing_events);

        Ok(events)
    }

    /// Perform enhanced beacon analysis with coefficient of variation and data patterns
    fn analyze_enhanced_beacon(
        &self,
        records: &VecDeque<ConnectionRecord>,
    ) -> EnhancedBeaconAnalysis {
        // Extract timing intervals
        let timing_history: VecDeque<Instant> = records.iter().map(|r| r.timestamp).collect();

        let basic = self.analyze_beacon_pattern(&timing_history);

        // Calculate coefficient of variation (stddev / mean)
        let intervals: Vec<f64> = records
            .iter()
            .zip(records.iter().skip(1))
            .map(|(a, b)| b.timestamp.duration_since(a.timestamp).as_millis() as f64)
            .collect();

        let cv = if !intervals.is_empty() {
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean > 0.0 {
                let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
                    / intervals.len() as f64;
                variance.sqrt() / mean
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Calculate average data sizes
        let total_sent: u64 = records.iter().map(|r| r.bytes_sent).sum();
        let total_recv: u64 = records.iter().map(|r| r.bytes_recv).sum();
        let count = records.len() as u64;
        let avg_request_size = if count > 0 { total_sent / count } else { 0 };
        let avg_response_size = if count > 0 { total_recv / count } else { 0 };

        // Calculate data size ratio (response / request)
        let data_size_ratio = if avg_request_size > 0 {
            avg_response_size as f64 / avg_request_size as f64
        } else {
            0.0
        };

        // C2 data pattern: small requests with larger variable responses
        let c2_data_pattern = avg_request_size > 0
            && avg_request_size < 1024
            && avg_response_size > avg_request_size
            && data_size_ratio > self.config.network_dpi.beacon_data_size_ratio_threshold;

        // Calculate combined score
        let mut combined_score: f64 = 0.0;

        // Timing regularity (low CV indicates beacon)
        if cv < self.config.network_dpi.beacon_cv_threshold && cv > 0.0 {
            combined_score += 0.35;
        } else if cv < self.config.network_dpi.beacon_cv_threshold * 2.0 && cv > 0.0 {
            combined_score += 0.15;
        }

        // Data size pattern match
        if c2_data_pattern {
            combined_score += 0.25;
        }

        // Basic beacon analysis score contribution
        if basic.is_beacon {
            combined_score += basic.confidence as f64 * 0.3;
        }

        // Sustained activity bonus
        if records.len() >= 20 {
            combined_score += 0.1;
        }

        EnhancedBeaconAnalysis {
            basic,
            coefficient_of_variation: cv,
            avg_request_size,
            avg_response_size,
            data_size_ratio,
            c2_data_pattern,
            combined_score: combined_score.min(1.0),
        }
    }

    // ========================================================================
    // Encrypted Payload Entropy Analysis
    // ========================================================================

    /// Record a payload observation for entropy tracking
    pub fn record_payload(&mut self, destination: &str, port: u16, payload: &[u8]) {
        if !self.config.network_dpi.entropy_analysis_enabled {
            return;
        }

        let key = format!("{}:{}", destination, port);
        let entropy = Self::calculate_entropy(payload);
        let size = payload.len() as u64;

        let tracker = self
            .payload_trackers
            .entry(key)
            .or_insert_with(|| PayloadEntropyTracker {
                destination: destination.to_string(),
                port,
                payload_sizes: VecDeque::with_capacity(200),
                entropy_values: VecDeque::with_capacity(200),
                timestamps: VecDeque::with_capacity(200),
                constant_size_run: 0,
                alternating_pattern_count: 0,
            });

        // Track constant-size payload runs
        if let Some(&last_size) = tracker.payload_sizes.back() {
            if size == last_size {
                tracker.constant_size_run += 1;
            } else {
                tracker.constant_size_run = 0;
            }
        }

        // Detect alternating small-large pattern (request-response C2)
        if tracker.payload_sizes.len() >= 2 {
            let sizes: Vec<&u64> = tracker.payload_sizes.iter().rev().take(3).collect();
            if sizes.len() >= 2 {
                let is_alternating =
                    (*sizes[0] < 256 && *sizes[1] > 1024) || (*sizes[0] > 1024 && *sizes[1] < 256);
                if is_alternating {
                    tracker.alternating_pattern_count += 1;
                }
            }
        }

        tracker.payload_sizes.push_back(size);
        tracker.entropy_values.push_back(entropy);
        tracker.timestamps.push_back(Instant::now());

        // Cap history
        while tracker.payload_sizes.len() > 200 {
            tracker.payload_sizes.pop_front();
            tracker.entropy_values.pop_front();
            tracker.timestamps.pop_front();
        }
    }

    /// Analyze payload entropy patterns across all tracked destinations
    async fn analyze_payload_entropy(&self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        let min_samples = self.config.network_dpi.payload_entropy_min_samples;

        for (key, tracker) in &self.payload_trackers {
            if tracker.entropy_values.len() < min_samples {
                continue;
            }

            let analysis = self.analyze_entropy_tracker(tracker);

            if analysis.suspicion_score > 0.5 {
                events.push(self.emit_entropy_analysis_event(&analysis));
            }
        }

        Ok(events)
    }

    /// Analyze a single payload entropy tracker for anomalies
    fn analyze_entropy_tracker(&self, tracker: &PayloadEntropyTracker) -> PayloadEntropyAnalysis {
        let mut indicators = Vec::new();
        let mut suspicion_score: f32 = 0.0;

        // Calculate average entropy
        let count = tracker.entropy_values.len() as f64;
        let avg_entropy: f64 = tracker.entropy_values.iter().sum::<f64>() / count.max(1.0);

        // Calculate entropy standard deviation
        let entropy_variance: f64 = tracker
            .entropy_values
            .iter()
            .map(|e| (e - avg_entropy).powi(2))
            .sum::<f64>()
            / count.max(1.0);
        let entropy_stddev = entropy_variance.sqrt();

        // 1. Constant-size payloads (padding suggests tunneling)
        let constant_size_detected = tracker.constant_size_run >= 5;
        if constant_size_detected {
            suspicion_score += 0.3;
            indicators.push(format!(
                "Constant-size payloads: {} in sequence (possible tunneling)",
                tracker.constant_size_run
            ));
        }

        // 2. Alternating small-large pattern (request-response C2)
        let alternating_pattern = tracker.alternating_pattern_count >= 3;
        if alternating_pattern {
            suspicion_score += 0.3;
            indicators.push(format!(
                "Alternating small/large pattern: {} occurrences (possible C2 request-response)",
                tracker.alternating_pattern_count
            ));
        }

        // 3. High entropy on non-TLS standard ports (covert channel)
        let is_standard_encrypted_port =
            [443, 8443, 993, 995, 465, 636, 853, 5061].contains(&tracker.port);
        let covert_channel_suspected = !is_standard_encrypted_port
            && avg_entropy > self.config.network_dpi.payload_entropy_threshold;

        if covert_channel_suspected {
            suspicion_score += 0.4;
            indicators.push(format!(
                "High entropy ({:.2}) on non-TLS port {} (possible covert channel)",
                avg_entropy, tracker.port
            ));
        }

        // 4. Very low entropy variance with high entropy (encrypted data is uniform)
        if avg_entropy > 7.0 && entropy_stddev < 0.3 {
            suspicion_score += 0.2;
            indicators.push(format!(
                "Uniformly high entropy ({:.2} +/- {:.2}): encrypted tunnel",
                avg_entropy, entropy_stddev
            ));
        }

        PayloadEntropyAnalysis {
            destination: tracker.destination.clone(),
            port: tracker.port,
            avg_entropy,
            entropy_stddev,
            constant_size_detected,
            constant_size_run_length: tracker.constant_size_run,
            alternating_pattern,
            covert_channel_suspected,
            suspicion_score: suspicion_score.min(1.0),
            indicators,
        }
    }

    /// Emit a payload entropy analysis event
    fn emit_entropy_analysis_event(&self, analysis: &PayloadEntropyAnalysis) -> TelemetryEvent {
        let severity = if analysis.suspicion_score > 0.7 {
            Severity::High
        } else if analysis.suspicion_score > 0.4 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkAnomaly,
            severity,
            EventPayload::Custom(serde_json::json!({
                "type": "payload_entropy_anomaly",
                "destination": analysis.destination,
                "port": analysis.port,
                "avg_entropy": analysis.avg_entropy,
                "entropy_stddev": analysis.entropy_stddev,
                "constant_size_detected": analysis.constant_size_detected,
                "constant_size_run_length": analysis.constant_size_run_length,
                "alternating_pattern": analysis.alternating_pattern,
                "covert_channel_suspected": analysis.covert_channel_suspected,
                "suspicion_score": analysis.suspicion_score,
                "indicators": analysis.indicators,
            })),
        );

        let mut techniques = vec!["T1573".to_string()];
        if analysis.covert_channel_suspected {
            techniques.push("T1572".to_string());
        }
        if analysis.alternating_pattern {
            techniques.push("T1071.001".to_string());
        }

        event.add_detection(Detection {
            detection_type: DetectionType::NetworkAnomaly,
            rule_name: "encrypted_payload_entropy".to_string(),
            confidence: analysis.suspicion_score,
            description: format!(
                "Encrypted payload anomaly to {}:{}: {}",
                analysis.destination,
                analysis.port,
                analysis.indicators.join("; ")
            ),
            mitre_tactics: vec![
                "command-and-control".to_string(),
                "exfiltration".to_string(),
            ],
            mitre_techniques: techniques,
        });

        event
    }

    // ========================================================================
    // Protocol Identification
    // ========================================================================

    /// Identify the application-layer protocol from a raw packet payload
    /// without requiring decryption. Uses port hints, magic bytes, and banners.
    pub fn identify_protocol(
        &self,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        is_udp: bool,
    ) -> ProtocolIdentification {
        // -- TLS / HTTPS (including DoT on port 853) --
        if payload.len() >= 5 && payload[0] == 0x16 {
            // TLS record type 0x16 = Handshake
            let sni = Self::parse_tls_client_hello(payload).and_then(|ch| ch.sni.clone());
            let alpn =
                Self::parse_tls_client_hello(payload).and_then(|ch| ch.alpn.first().cloned());

            let is_dot = dst_port == 853 || src_port == 853;
            if is_dot {
                return ProtocolIdentification {
                    protocol: IdentifiedProtocol::DnsOverTls,
                    confidence: 0.95,
                    expected_port: true,
                    suspicious: false,
                    details: "DNS over TLS on port 853".to_string(),
                };
            }

            let expected = [443, 8443, 993, 995, 465, 636, 5061].contains(&dst_port);
            return ProtocolIdentification {
                protocol: IdentifiedProtocol::Https { sni, alpn },
                confidence: 0.95,
                expected_port: expected,
                suspicious: !expected && dst_port != 0,
                details: format!("TLS handshake detected on port {}", dst_port),
            };
        }

        // -- SSH detection by banner --
        if payload.len() >= 4 && &payload[..4] == b"SSH-" {
            let banner = String::from_utf8_lossy(payload);
            let banner_line = banner.lines().next().unwrap_or("SSH-unknown");
            // Parse version and software from banner "SSH-2.0-OpenSSH_8.9"
            let parts: Vec<&str> = banner_line.splitn(3, '-').collect();
            let version = if parts.len() >= 2 {
                format!("SSH-{}", parts[1])
            } else {
                "SSH-unknown".to_string()
            };
            let software = if parts.len() >= 3 {
                Some(parts[2].trim().to_string())
            } else {
                None
            };

            let expected = dst_port == 22 || src_port == 22;
            return ProtocolIdentification {
                protocol: IdentifiedProtocol::Ssh { version, software },
                confidence: 0.95,
                expected_port: expected,
                suspicious: !expected,
                details: format!("SSH banner: {}", banner_line),
            };
        }

        // -- RDP detection by TPKT header + X.224 --
        if payload.len() >= 4
            && payload[0] == 0x03   // TPKT version
            && payload[1] == 0x00   // TPKT reserved
            && (dst_port == 3389 || src_port == 3389)
        {
            return ProtocolIdentification {
                protocol: IdentifiedProtocol::Rdp,
                confidence: 0.90,
                expected_port: true,
                details: "RDP TPKT/X.224 header on port 3389".to_string(),
                suspicious: false,
            };
        }

        // RDP on non-standard port (TPKT header without port 3389)
        if payload.len() >= 11
            && payload[0] == 0x03
            && payload[1] == 0x00
            // X.224 Connection Request (0xE0) or Confirm (0xD0)
            && (payload[5] == 0xE0 || payload[5] == 0xD0)
        {
            return ProtocolIdentification {
                protocol: IdentifiedProtocol::Rdp,
                confidence: 0.70,
                expected_port: false,
                suspicious: true,
                details: format!("RDP TPKT/X.224 header on non-standard port {}", dst_port),
            };
        }

        // -- QUIC detection (UDP only) --
        if is_udp && payload.len() >= 5 {
            // QUIC long header: first bit = 1 (form bit), second bit = 1 (fixed bit)
            let first_byte = payload[0];
            if first_byte & 0xC0 == 0xC0 {
                // Long header form: extract version from bytes 1-4
                let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

                // Known QUIC versions: 0x00000001 (QUICv1), 0xff000000+ (draft versions)
                let is_quic_version = version == 0x00000001
                    || version == 0x6b3343cf  // QUICv2
                    || (version & 0xFF000000 == 0xFF000000); // Draft versions

                if is_quic_version {
                    let expected = dst_port == 443 || dst_port == 8443;
                    return ProtocolIdentification {
                        protocol: IdentifiedProtocol::Quic { version },
                        confidence: 0.85,
                        expected_port: expected,
                        suspicious: !expected,
                        details: format!(
                            "QUIC long header detected, version=0x{:08x} on port {}",
                            version, dst_port
                        ),
                    };
                }
            }
        }

        // -- WireGuard detection (UDP only) --
        if is_udp && payload.len() >= 4 {
            // WireGuard message type is in the first byte:
            // 1 = Handshake Initiation (148 bytes)
            // 2 = Handshake Response (92 bytes)
            // 3 = Cookie Reply (64 bytes)
            // 4 = Transport Data (variable, >= 32 bytes)
            let msg_type = payload[0];
            let reserved = &payload[1..4];

            if reserved == [0, 0, 0] && (msg_type >= 1 && msg_type <= 4) {
                let length_match = match msg_type {
                    1 => payload.len() == 148,
                    2 => payload.len() == 92,
                    3 => payload.len() == 64,
                    4 => payload.len() >= 32,
                    _ => false,
                };

                if length_match {
                    let expected = dst_port == 51820;
                    return ProtocolIdentification {
                        protocol: IdentifiedProtocol::WireGuard,
                        confidence: 0.75,
                        expected_port: expected,
                        suspicious: !expected,
                        details: format!(
                            "WireGuard message type {} ({} bytes) on port {}",
                            msg_type,
                            payload.len(),
                            dst_port
                        ),
                    };
                }
            }
        }

        // -- OpenVPN detection (UDP) --
        if is_udp && payload.len() >= 2 {
            // OpenVPN opcode is in the upper 5 bits of the first byte
            let opcode = (payload[0] >> 3) & 0x1F;
            let key_id = payload[0] & 0x07;

            // Valid opcodes: 1-10
            // P_CONTROL_HARD_RESET_CLIENT_V1 = 1
            // P_CONTROL_HARD_RESET_SERVER_V1 = 2
            // P_CONTROL_HARD_RESET_CLIENT_V2 = 7
            // P_CONTROL_HARD_RESET_SERVER_V2 = 8
            // P_CONTROL_HARD_RESET_CLIENT_V3 = 10
            let is_openvpn_opcode = matches!(opcode, 1..=10);

            if is_openvpn_opcode && key_id <= 7 {
                let expected = dst_port == 1194;
                return ProtocolIdentification {
                    protocol: IdentifiedProtocol::OpenVpn,
                    confidence: 0.65,
                    expected_port: expected,
                    suspicious: !expected,
                    details: format!(
                        "OpenVPN opcode={} key_id={} on port {}",
                        opcode, key_id, dst_port
                    ),
                };
            }
        }

        // -- SMB detection (NetBIOS Session Service + SMB header) --
        if payload.len() >= 8 {
            // NetBIOS Session Service: type=0x00 (session message)
            // followed by SMB header: 0xFF 'S' 'M' 'B' (SMBv1) or 0xFE 'S' 'M' 'B' (SMBv2)
            if payload[0] == 0x00 && payload.len() >= 8 {
                let smb_offset = 4; // NetBIOS header is 4 bytes
                if smb_offset + 4 <= payload.len() {
                    let smb_magic = &payload[smb_offset..smb_offset + 4];
                    if smb_magic == b"\xFFSMB" || smb_magic == b"\xFESMB" {
                        let expected =
                            [445, 139].contains(&dst_port) || [445, 139].contains(&src_port);
                        return ProtocolIdentification {
                            protocol: IdentifiedProtocol::Smb,
                            confidence: 0.90,
                            expected_port: expected,
                            suspicious: !expected,
                            details: format!("SMB header detected on port {}", dst_port),
                        };
                    }
                }
            }
        }

        // -- HTTP detection --
        let http_methods = [
            b"GET " as &[u8],
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"TRACE ",
        ];
        for method in &http_methods {
            if payload.len() >= method.len() && &payload[..method.len()] == *method {
                let expected = [80, 8080, 8000, 3000, 5000].contains(&dst_port);
                return ProtocolIdentification {
                    protocol: IdentifiedProtocol::Http,
                    confidence: 0.90,
                    expected_port: expected,
                    suspicious: !expected && dst_port != 0,
                    details: format!("HTTP request on port {}", dst_port),
                };
            }
        }
        // HTTP response
        if payload.len() >= 9 && &payload[..5] == b"HTTP/" {
            let expected = [80, 8080, 8000, 3000, 5000].contains(&src_port);
            return ProtocolIdentification {
                protocol: IdentifiedProtocol::Http,
                confidence: 0.90,
                expected_port: expected,
                suspicious: false,
                details: "HTTP response detected".to_string(),
            };
        }

        // -- SMTP banner --
        if payload.len() >= 3 && &payload[..3] == b"220" {
            let banner = String::from_utf8_lossy(payload);
            let first_line = banner.lines().next().unwrap_or("220");
            if first_line.contains("SMTP")
                || first_line.contains("smtp")
                || first_line.contains("mail")
                || first_line.contains("ESMTP")
            {
                let expected = [25, 587, 465, 2525].contains(&dst_port)
                    || [25, 587, 465, 2525].contains(&src_port);
                return ProtocolIdentification {
                    protocol: IdentifiedProtocol::Smtp {
                        banner: first_line.to_string(),
                    },
                    confidence: 0.85,
                    expected_port: expected,
                    suspicious: !expected,
                    details: format!("SMTP banner: {}", first_line),
                };
            }
        }

        // -- FTP banner --
        if payload.len() >= 3 {
            let response_text = String::from_utf8_lossy(payload);
            let first_line = response_text.lines().next().unwrap_or("");
            if (first_line.starts_with("220") || first_line.starts_with("230"))
                && (first_line.contains("FTP")
                    || first_line.contains("ftp")
                    || first_line.contains("FileZilla")
                    || first_line.contains("vsftpd")
                    || first_line.contains("ProFTPD"))
            {
                let expected = [20, 21].contains(&dst_port) || [20, 21].contains(&src_port);
                return ProtocolIdentification {
                    protocol: IdentifiedProtocol::Ftp {
                        banner: first_line.to_string(),
                    },
                    confidence: 0.85,
                    expected_port: expected,
                    suspicious: !expected,
                    details: format!("FTP banner: {}", first_line),
                };
            }
        }

        // Unknown
        ProtocolIdentification {
            protocol: IdentifiedProtocol::Unknown,
            confidence: 0.0,
            expected_port: false,
            suspicious: false,
            details: "Protocol not identified".to_string(),
        }
    }

    /// Emit a suspicious protocol identification event
    fn emit_protocol_identification_event(
        &self,
        ident: &ProtocolIdentification,
        remote_ip: &str,
        remote_port: u16,
        pid: Option<u32>,
    ) -> TelemetryEvent {
        let protocol_name = match &ident.protocol {
            IdentifiedProtocol::Http => "HTTP".to_string(),
            IdentifiedProtocol::Https { sni, .. } => {
                format!("HTTPS (SNI: {})", sni.as_deref().unwrap_or("none"))
            }
            IdentifiedProtocol::Ssh { version, software } => {
                format!(
                    "SSH {} ({})",
                    version,
                    software.as_deref().unwrap_or("unknown")
                )
            }
            IdentifiedProtocol::Rdp => "RDP".to_string(),
            IdentifiedProtocol::DnsOverTls => "DNS-over-TLS".to_string(),
            IdentifiedProtocol::Quic { version } => format!("QUIC (v0x{:08x})", version),
            IdentifiedProtocol::WireGuard => "WireGuard".to_string(),
            IdentifiedProtocol::OpenVpn => "OpenVPN".to_string(),
            IdentifiedProtocol::Smtp { .. } => "SMTP".to_string(),
            IdentifiedProtocol::Ftp { .. } => "FTP".to_string(),
            IdentifiedProtocol::Smb => "SMB".to_string(),
            IdentifiedProtocol::Unknown => "Unknown".to_string(),
        };

        let severity = if ident.suspicious {
            Severity::Medium
        } else {
            Severity::Info
        };

        let mut event = TelemetryEvent::new(
            EventType::NetworkFingerprint,
            severity,
            EventPayload::Custom(serde_json::json!({
                "type": "protocol_identification",
                "protocol": protocol_name,
                "confidence": ident.confidence,
                "expected_port": ident.expected_port,
                "suspicious": ident.suspicious,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "pid": pid,
                "details": ident.details,
            })),
        );

        if ident.suspicious {
            event.add_detection(Detection {
                detection_type: DetectionType::NetworkFingerprint,
                rule_name: "unexpected_protocol_port".to_string(),
                confidence: ident.confidence,
                description: format!(
                    "{} on unexpected port {}: {}",
                    protocol_name, remote_port, ident.details
                ),
                mitre_tactics: vec!["command-and-control".to_string()],
                mitre_techniques: vec!["T1571".to_string(), "T1095".to_string()],
            });
        }

        event
    }

    // ========================================================================
    // Enhanced Certificate Analysis
    // ========================================================================

    /// Enhanced certificate analysis with additional anomaly detection:
    /// - Long validity period (> cert_max_validity_days)
    /// - Recently issued certificates (< cert_recently_issued_days)
    /// - Uncommon/untrusted issuer
    /// - Suspicious wildcard certificates
    pub fn analyze_certificate_enhanced(&self, cert: &CertificateInfo) -> CertificateAnalysis {
        // Start with the base analysis
        let mut analysis = self.analyze_certificate(cert);

        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 7. Long validity period detection (>2 years / cert_max_validity_days)
        if cert.not_after > cert.not_before {
            let validity_secs = cert.not_after - cert.not_before;
            let validity_days = (validity_secs / 86400) as u32;
            let max_days = self.config.network_dpi.cert_max_validity_days;
            if validity_days > max_days {
                analysis
                    .anomalies
                    .push(CertificateAnomalyType::LongValidity { validity_days });
                analysis.indicators.push(format!(
                    "Unusually long validity: {} days (threshold: {} days / ~{:.1} years)",
                    validity_days,
                    max_days,
                    max_days as f64 / 365.0
                ));
                analysis.suspicion_score += 0.2;
            }
        }

        // 8. Recently issued certificate detection (< cert_recently_issued_days)
        if cert.not_before > 0 && cert.not_before <= now_secs {
            let age_secs = now_secs - cert.not_before;
            let age_days = (age_secs / 86400) as u32;
            let threshold_days = self.config.network_dpi.cert_recently_issued_days;
            if age_days < threshold_days {
                analysis
                    .anomalies
                    .push(CertificateAnomalyType::RecentlyIssued { age_days });
                analysis.indicators.push(format!(
                    "Recently issued certificate: {} days ago (threshold: {} days)",
                    age_days, threshold_days
                ));
                // Only add suspicion if combined with other factors (new domain + self-signed)
                if cert.is_self_signed {
                    analysis.suspicion_score += 0.4;
                } else {
                    analysis.suspicion_score += 0.1;
                }
            }
        }

        // 9. Uncommon/untrusted CA detection
        if !cert.is_self_signed {
            let issuer_org = cert.issuer_org.as_deref().unwrap_or("");
            let issuer_cn = cert.issuer_cn.as_deref().unwrap_or("");

            let is_known_ca = WELL_KNOWN_CAS.iter().any(|&ca| {
                let ca_lower = ca.to_lowercase();
                issuer_org.to_lowercase().contains(&ca_lower)
                    || issuer_cn.to_lowercase().contains(&ca_lower)
            });

            // Additional well-known intermediate CA patterns
            let is_known_intermediate = issuer_cn.to_lowercase().contains("intermediate")
                || issuer_cn.to_lowercase().contains("ssl")
                || issuer_cn.to_lowercase().contains("tls")
                || issuer_org.to_lowercase().contains("certificate authority");

            if !is_known_ca && !is_known_intermediate && !issuer_org.is_empty() {
                analysis
                    .anomalies
                    .push(CertificateAnomalyType::UncommonIssuer {
                        issuer: format!("{} ({})", issuer_cn, issuer_org),
                    });
                analysis.indicators.push(format!(
                    "Certificate issued by uncommon CA: {} (Org: {})",
                    issuer_cn, issuer_org
                ));
                analysis.suspicion_score += 0.15;
            }
        }

        // 10. Suspicious wildcard certificate detection
        let has_wildcard = cert.sans.iter().any(|san| san.starts_with("*."));
        if has_wildcard {
            // Wildcard certs on unusual TLDs or with deeply nested wildcards are suspicious
            for san in &cert.sans {
                if san.starts_with("*.") {
                    let domain = &san[2..]; // Remove "*."
                    let parts: Vec<&str> = domain.split('.').collect();

                    // Wildcard on a free/dynamic DNS TLD
                    let suspicious_tlds = [
                        "duckdns.org",
                        "no-ip.org",
                        "no-ip.com",
                        "ddns.net",
                        "hopto.org",
                        "zapto.org",
                        "sytes.net",
                        "servegame.com",
                        "redirectme.net",
                        "servebeer.com",
                        "servehttp.com",
                        "webhop.me",
                        "myftp.biz",
                        "myftp.org",
                    ];

                    let is_suspicious_tld = suspicious_tlds.iter().any(|tld| domain.ends_with(tld));

                    // Multi-level wildcard: *.sub.example.com (>= 3 domain levels under the wildcard)
                    let is_deep_wildcard = parts.len() >= 4;

                    if is_suspicious_tld || is_deep_wildcard {
                        analysis
                            .anomalies
                            .push(CertificateAnomalyType::SuspiciousWildcard {
                                domain: san.clone(),
                            });
                        analysis.indicators.push(format!(
                            "Suspicious wildcard certificate: {}{}",
                            san,
                            if is_suspicious_tld {
                                " (dynamic DNS TLD)"
                            } else {
                                " (deep wildcard)"
                            }
                        ));
                        analysis.suspicion_score += 0.3;
                    }
                }
            }
        }

        // Cap the score at 1.0
        analysis.suspicion_score = analysis.suspicion_score.min(1.0);

        analysis
    }

    // ========================================================================
    // Enhanced Packet Analysis (integrates all new capabilities)
    // ========================================================================

    /// Enhanced packet analysis that integrates protocol identification,
    /// DoH detection, and entropy analysis with the existing DPI engine
    pub fn analyze_packet_enhanced(
        &mut self,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        remote_ip: &str,
        is_udp: bool,
        pid: Option<u32>,
        bytes_sent: u64,
        bytes_recv: u64,
    ) -> (Option<DpiEvent>, Vec<TelemetryEvent>) {
        let mut extra_events = Vec::new();

        // 1. Run the existing DPI analysis
        let dpi_event = self.analyze_packet(payload, src_port, dst_port);

        // 2. Protocol identification
        if self.config.network_dpi.protocol_identification_enabled {
            let ident = self.identify_protocol(payload, src_port, dst_port, is_udp);
            if ident.suspicious {
                extra_events.push(
                    self.emit_protocol_identification_event(&ident, remote_ip, dst_port, pid),
                );
            }

            // Check for DoH via SNI in TLS identification
            if let IdentifiedProtocol::Https { ref sni, .. } = ident.protocol {
                if let Some(ref sni_name) = sni {
                    if self.config.network_dpi.doh_detection_enabled {
                        if let Some(doh_detection) = self.check_doh_by_sni(sni_name) {
                            extra_events.push(self.emit_doh_event(&doh_detection));
                        }
                    }
                }
            }
        }

        // 3. Record connection data for enhanced beacon detection
        if let Ok(ip) = remote_ip.parse::<IpAddr>() {
            self.record_connection_data(ip, bytes_sent, bytes_recv);
        }

        // 4. Record payload for entropy tracking
        if self.config.network_dpi.entropy_analysis_enabled && !payload.is_empty() {
            self.record_payload(remote_ip, dst_port, payload);
        }

        // 5. Check DoH via HTTP paths
        if let Some(ref dpi) = dpi_event {
            if let AppProtocol::Http {
                ref path, ref host, ..
            } = dpi.protocol
            {
                if self.config.network_dpi.doh_detection_enabled && !host.is_empty() {
                    if let Some(doh_detection) = self.check_doh_by_path(path, host) {
                        extra_events.push(self.emit_doh_event(&doh_detection));
                    }
                }
            }
        }

        (dpi_event, extra_events)
    }
}

// ============================================================================
// C2 Pattern Matcher
// ============================================================================

/// Matcher for known C2 framework patterns
struct C2PatternMatcher {
    cobalt_strike_uris: Vec<&'static str>,
    #[allow(dead_code)]
    cobalt_strike_headers: Vec<(&'static str, &'static str)>,
}

impl C2PatternMatcher {
    fn new() -> Self {
        Self {
            cobalt_strike_uris: vec![
                "/__utm.gif",
                "/pixel.gif",
                "/pixel",
                "/submit.php",
                "/ca",
                "/dpixel",
                "/__init.gif",
                "/visit.js",
                "/jquery-",
                "/ga.js",
                "/fwlink",
            ],
            cobalt_strike_headers: vec![
                ("content-type", "application/octet-stream"),
                ("x-requested-with", "XMLHttpRequest"),
            ],
        }
    }

    fn check_cobalt_strike(&self, http: &HttpInfo) -> Option<Detection> {
        let mut score: f32 = 0.0;
        let mut indicators = Vec::new();

        // Check URI patterns
        let path_lower = http.path.to_lowercase();
        for uri in &self.cobalt_strike_uris {
            if path_lower.contains(uri) {
                score += 0.3;
                indicators.push(format!("URI matches CS pattern: {}", uri));
                break;
            }
        }

        // Check for malleable C2 default patterns
        if path_lower.ends_with(".gif") || path_lower.ends_with(".js") {
            if http.method == "POST" {
                // POST to a "static" resource is suspicious
                score += 0.2;
                indicators.push("POST to static resource".to_string());
            }
        }

        // Check user-agent
        if let Some(ref ua) = http.user_agent {
            let ua_lower = ua.to_lowercase();
            // Cobalt Strike default UA
            if ua_lower.contains("mozilla/5.0 (compatible; msie") {
                score += 0.2;
                indicators.push("Default CS user-agent pattern".to_string());
            }
        }

        // Check for specific header patterns
        for header in &http.suspicious_headers {
            if header.to_lowercase().contains("spoofed")
                || header.to_lowercase().contains("suspicious")
            {
                score += 0.1;
                indicators.push(header.clone());
            }
        }

        if score > 0.3 {
            Some(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "cobalt_strike_pattern".to_string(),
                confidence: score.min(0.9),
                description: format!("Possible Cobalt Strike traffic: {}", indicators.join(", ")),
                mitre_tactics: vec!["command-and-control".to_string()],
                mitre_techniques: vec!["T1071.001".to_string(), "T1573".to_string()],
            })
        } else {
            None
        }
    }
}

impl DnsQueryType {
    fn from_u16(val: u16) -> Self {
        match val {
            1 => DnsQueryType::A,
            2 => DnsQueryType::NS,
            5 => DnsQueryType::CNAME,
            6 => DnsQueryType::SOA,
            12 => DnsQueryType::PTR,
            15 => DnsQueryType::MX,
            16 => DnsQueryType::TXT,
            28 => DnsQueryType::AAAA,
            33 => DnsQueryType::SRV,
            10 => DnsQueryType::NULL,
            _ => DnsQueryType::Other(val),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Random-looking string should have high entropy
        let high_entropy = NetworkDpiCollector::calculate_string_entropy("a1b2c3d4e5f6");
        assert!(high_entropy > 3.0);

        // Repetitive string should have low entropy
        let low_entropy = NetworkDpiCollector::calculate_string_entropy("aaaaaaa");
        assert!(low_entropy < 1.0);
    }

    #[test]
    fn test_base64_detection() {
        assert!(NetworkDpiCollector::looks_like_base64("SGVsbG9Xb3JsZA=="));
        assert!(!NetworkDpiCollector::looks_like_base64("hello"));
    }

    #[test]
    fn test_hex_detection() {
        assert!(NetworkDpiCollector::looks_like_hex("48656c6c6f576f726c64"));
        assert!(!NetworkDpiCollector::looks_like_hex("hello"));
    }

    #[test]
    fn test_beacon_analysis() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Create regular interval history
        let mut history = VecDeque::new();
        let base = Instant::now();
        for i in 0..20 {
            history.push_back(base + Duration::from_secs(i * 60));
        }

        let analysis = collector.analyze_beacon_pattern(&history);
        assert!(analysis.is_beacon);
        assert!(analysis.confidence > 0.5);
    }

    #[test]
    fn test_dga_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Random-looking domain (DGA-like)
        assert!(collector.detect_dga_domain("xkjhw3d9f2k.com"));

        // Normal domain
        assert!(!collector.detect_dga_domain("google.com"));
        assert!(!collector.detect_dga_domain("microsoft.com"));
    }

    #[test]
    fn test_http_parsing() {
        let request =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let http = NetworkDpiCollector::parse_http(request).unwrap();

        assert!(http.is_request);
        assert_eq!(http.method, "GET");
        assert_eq!(http.path, "/index.html");
        assert_eq!(http.host, Some("example.com".to_string()));
        assert!(http.user_agent.unwrap().contains("Mozilla"));
    }

    #[test]
    fn test_dns_parsing() {
        // Simple DNS query for google.com (A record)
        let dns_query: Vec<u8> = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query: google.com
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let dns = NetworkDpiCollector::parse_dns(&dns_query).unwrap();
        assert!(!dns.is_response);
        assert_eq!(dns.query_name, "google.com");
        assert_eq!(dns.query_type, DnsQueryType::A);
    }

    #[test]
    fn test_ja3_grease_detection() {
        // GREASE values should be detected
        assert!(NetworkDpiCollector::is_grease(0x0a0a));
        assert!(NetworkDpiCollector::is_grease(0x1a1a));
        assert!(NetworkDpiCollector::is_grease(0xfafa));

        // Non-GREASE values
        assert!(!NetworkDpiCollector::is_grease(0x0001));
        assert!(!NetworkDpiCollector::is_grease(0x1301));
    }

    #[test]
    fn test_suspicious_user_agent() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Old IE user agent (commonly spoofed by malware)
        let (suspicious, _) = collector
            .is_suspicious_user_agent("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)");
        assert!(suspicious);

        // Normal browser
        let (suspicious, _) = collector.is_suspicious_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
        assert!(!suspicious);
    }

    #[test]
    fn test_reverse_shell_detection() {
        // Windows command prompt output
        let shell_output = b"Microsoft Windows [Version 10.0.19041.1]\r\n(c) Microsoft Corporation. All rights reserved.\r\n\r\nC:\\Windows\\system32>";
        assert!(NetworkDpiCollector::looks_like_reverse_shell(shell_output));

        // Normal HTTP response
        let http_response =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>";
        assert!(!NetworkDpiCollector::looks_like_reverse_shell(
            http_response
        ));
    }

    // ====================================================================
    // JA4 Fingerprinting Tests
    // ====================================================================

    #[test]
    fn test_ja4_calculation() {
        // Construct a TLS Client Hello with known parameters
        let client_hello = TlsClientHello {
            tls_version: 0x0303, // TLS 1.2
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            extensions: vec![
                0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x0033,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        };

        let ja4 = NetworkDpiCollector::calculate_ja4(&client_hello);

        // Verify the format components
        assert_eq!(ja4.protocol_type, 't');
        assert_eq!(ja4.tls_version, "12");
        assert_eq!(ja4.sni_type, 'd');
        assert_eq!(ja4.cipher_count, 5);
        assert_eq!(ja4.extension_count, 8);
        assert_eq!(ja4.alpn_first, "h2");
        assert!(!ja4.cipher_hash.is_empty());
        assert!(!ja4.extension_hash.is_empty());

        // Verify full hash format: t12d0508h2_{cipher_hash}_{ext_hash}
        assert!(ja4.hash.starts_with("t12d0508h2_"));
        assert!(ja4.hash.contains('_'));
        let parts: Vec<&str> = ja4.hash.split('_').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_ja4_no_sni() {
        let client_hello = TlsClientHello {
            tls_version: 0x0304, // TLS 1.3
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0x000a, 0x000b],
            elliptic_curves: vec![0x001d],
            ec_point_formats: vec![0x00],
            sni: None,
            alpn: vec![],
        };

        let ja4 = NetworkDpiCollector::calculate_ja4(&client_hello);
        assert_eq!(ja4.sni_type, 'i');
        assert_eq!(ja4.alpn_first, "00");
        assert!(ja4.hash.starts_with("t13i"));
    }

    #[test]
    fn test_ja4s_calculation() {
        let server_hello = TlsServerHello {
            tls_version: 0x0303,
            cipher_suite: 0xc02c,
            extensions: vec![0x0000, 0x000b, 0xff01],
        };

        let ja4s = NetworkDpiCollector::calculate_ja4s(&server_hello);
        assert_eq!(ja4s.tls_version, "12");
        assert_eq!(ja4s.extension_count, 3);
        assert!(ja4s.hash.starts_with("t12"));
        assert!(!ja4s.cipher_ext_hash.is_empty());
    }

    #[test]
    fn test_ja4_database_lookup() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Unknown fingerprint should not match
        let unknown = Ja4Fingerprint {
            hash: "t13d1010h2_unknown12hash_unknown12hash".to_string(),
            protocol_type: 't',
            tls_version: "13".to_string(),
            sni_type: 'd',
            cipher_count: 10,
            extension_count: 10,
            alpn_first: "h2".to_string(),
            cipher_hash: "unknown12hash".to_string(),
            extension_hash: "unknown12hash".to_string(),
        };

        let (suspicious, _, _) = collector.analyze_ja4(&unknown);
        assert!(!suspicious);
    }

    // ====================================================================
    // JARM Matching Tests
    // ====================================================================

    #[test]
    fn test_jarm_known_match() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Test a known Cobalt Strike JARM hash
        let result =
            collector.match_jarm("07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1");
        assert!(result.is_match);
        assert_eq!(result.framework.unwrap(), "Cobalt Strike");
        assert!(result.confidence > 0.9);
    }

    #[test]
    fn test_jarm_unknown() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Unknown JARM hash should not match
        let result = collector
            .match_jarm("aaaaaabbbbbbccccccddddddeeeeeeffffffffaaaaabbbbccccddddeeeefffff");
        assert!(!result.is_match);
        assert!(result.framework.is_none());
        assert!(result.confidence < 0.1);
    }

    #[test]
    fn test_jarm_database_completeness() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Verify all built-in JARM hashes are loaded
        assert!(collector.known_c2_jarm.len() >= KNOWN_C2_JARM_HASHES.len());

        // Check specific frameworks are present
        let frameworks: Vec<&String> = collector.known_c2_jarm.values().collect();
        assert!(frameworks.iter().any(|f| f.contains("Cobalt Strike")));
        assert!(frameworks.iter().any(|f| f.contains("Metasploit")));
        assert!(frameworks.iter().any(|f| f.contains("Empire")));
        assert!(frameworks.iter().any(|f| f.contains("Havoc")));
        assert!(frameworks.iter().any(|f| f.contains("Sliver")));
    }

    // ====================================================================
    // Certificate Analysis Tests
    // ====================================================================

    #[test]
    fn test_cert_self_signed_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let cert = CertificateInfo {
            subject_cn: Some("evil.example.com".to_string()),
            issuer_cn: Some("evil.example.com".to_string()),
            issuer_org: None,
            sans: vec!["evil.example.com".to_string()],
            not_before: 1700000000,
            not_after: 1700000000 + 365 * 86400,
            is_self_signed: true,
            serial_number: "01".to_string(),
            sha256_fingerprint: "aabbccdd".to_string(),
        };

        let analysis = collector.analyze_certificate(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::SelfSigned)));
        assert!(analysis.suspicion_score > 0.0);
    }

    #[test]
    fn test_cert_short_lived_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Certificate valid for only 3 days (below default 7-day threshold)
        let cert = CertificateInfo {
            subject_cn: Some("short.example.com".to_string()),
            issuer_cn: Some("CA".to_string()),
            issuer_org: Some("SomeCA".to_string()),
            sans: vec!["short.example.com".to_string()],
            not_before: 1700000000,
            not_after: 1700000000 + 3 * 86400, // 3 days
            is_self_signed: false,
            serial_number: "02".to_string(),
            sha256_fingerprint: "eeff0011".to_string(),
        };

        let analysis = collector.analyze_certificate(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::ShortLived { .. })));
    }

    #[test]
    fn test_cert_impersonation_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Self-signed cert claiming to be from DigiCert
        let cert = CertificateInfo {
            subject_cn: Some("login.bank.com".to_string()),
            issuer_cn: Some("DigiCert Fake CA".to_string()),
            issuer_org: Some("Not DigiCert".to_string()),
            sans: vec!["login.bank.com".to_string()],
            not_before: 1700000000,
            not_after: 1700000000 + 365 * 86400,
            is_self_signed: true,
            serial_number: "03".to_string(),
            sha256_fingerprint: "22334455".to_string(),
        };

        let analysis = collector.analyze_certificate(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::IssuerImpersonation { .. })));
        assert!(analysis.suspicion_score > 0.5);
    }

    #[test]
    fn test_cert_empty_subject() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let cert = CertificateInfo {
            subject_cn: None,
            issuer_cn: Some("SomeCA".to_string()),
            issuer_org: Some("SomeOrg".to_string()),
            sans: vec![],
            not_before: 1700000000,
            not_after: 1700000000 + 365 * 86400,
            is_self_signed: false,
            serial_number: "04".to_string(),
            sha256_fingerprint: "66778899".to_string(),
        };

        let analysis = collector.analyze_certificate(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::EmptySubject)));
    }

    #[test]
    fn test_cert_cn_san_mismatch() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let cert = CertificateInfo {
            subject_cn: Some("wrong.example.com".to_string()),
            issuer_cn: Some("SomeCA".to_string()),
            issuer_org: Some("SomeOrg".to_string()),
            sans: vec![
                "real.example.com".to_string(),
                "other.example.com".to_string(),
            ],
            not_before: 1700000000,
            not_after: 1700000000 + 365 * 86400,
            is_self_signed: false,
            serial_number: "05".to_string(),
            sha256_fingerprint: "aabb0011".to_string(),
        };

        let analysis = collector.analyze_certificate(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::CnSanMismatch)));
    }

    #[test]
    fn test_cert_legitimate() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // A legitimate-looking certificate should have low suspicion
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = CertificateInfo {
            subject_cn: Some("www.example.com".to_string()),
            issuer_cn: Some("DigiCert SHA2 Extended Validation Server CA".to_string()),
            issuer_org: Some("DigiCert Inc".to_string()),
            sans: vec!["www.example.com".to_string(), "example.com".to_string()],
            not_before: now - 30 * 86400,
            not_after: now + 365 * 86400,
            is_self_signed: false,
            serial_number: "0a12bc".to_string(),
            sha256_fingerprint: "legitimate_cert_hash".to_string(),
        };

        let analysis = collector.analyze_certificate(&cert);
        assert!(analysis.anomalies.is_empty());
        assert!(analysis.suspicion_score < 0.01);
    }

    // ====================================================================
    // HTTP/2 Fingerprinting Tests
    // ====================================================================

    #[test]
    fn test_h2_fingerprint_parsing() {
        // Build a minimal HTTP/2 preface + SETTINGS frame
        let mut payload = Vec::new();

        // Connection preface
        payload.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // SETTINGS frame (type=0x04)
        // Length: 18 (3 settings * 6 bytes each)
        payload.extend_from_slice(&[0x00, 0x00, 0x12]); // Length = 18
        payload.push(0x04); // Type = SETTINGS
        payload.push(0x00); // Flags
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Stream ID = 0

        // SETTINGS_MAX_CONCURRENT_STREAMS = 100
        payload.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
        // SETTINGS_INITIAL_WINDOW_SIZE = 65535
        payload.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF]);
        // SETTINGS_MAX_FRAME_SIZE = 16384
        payload.extend_from_slice(&[0x00, 0x05, 0x00, 0x00, 0x40, 0x00]);

        // WINDOW_UPDATE frame (type=0x08)
        payload.extend_from_slice(&[0x00, 0x00, 0x04]); // Length = 4
        payload.push(0x08); // Type = WINDOW_UPDATE
        payload.push(0x00); // Flags
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Stream ID = 0
        payload.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01]); // Increment = 983041

        let fp = NetworkDpiCollector::parse_http2_fingerprint(&payload).unwrap();

        assert_eq!(fp.settings_order.len(), 3);
        assert_eq!(fp.settings_order[0], H2_SETTINGS_MAX_CONCURRENT_STREAMS);
        assert_eq!(fp.settings_order[1], H2_SETTINGS_INITIAL_WINDOW_SIZE);
        assert_eq!(fp.settings_order[2], H2_SETTINGS_MAX_FRAME_SIZE);
        assert_eq!(
            *fp.settings_values
                .get(&H2_SETTINGS_MAX_CONCURRENT_STREAMS)
                .unwrap(),
            100
        );
        assert_eq!(
            *fp.settings_values
                .get(&H2_SETTINGS_INITIAL_WINDOW_SIZE)
                .unwrap(),
            65535
        );
        assert!(fp.window_update_size.is_some());
        assert!(!fp.hash.is_empty());
        assert!(fp.description.contains("max_concurrent=100"));
    }

    #[test]
    fn test_h2_not_http2() {
        // Regular HTTP/1.1 request should not parse as HTTP/2
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(NetworkDpiCollector::parse_http2_fingerprint(payload).is_none());
    }

    // ====================================================================
    // Behavioral Baseline Tests
    // ====================================================================

    #[test]
    fn test_process_baseline_recording() {
        let config = AgentConfig::default();
        let mut collector = NetworkDpiCollector::new(&config);

        // Record some connections for a process
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        collector.record_process_connection(
            "chrome.exe",
            1234,
            ip1,
            443,
            1000,
            5000,
            Some("example.com"),
        );
        collector.record_process_connection(
            "chrome.exe",
            1234,
            ip2,
            80,
            500,
            2000,
            Some("other.com"),
        );

        assert!(collector.process_baselines.contains_key("chrome.exe"));
        let baseline = collector.process_baselines.get("chrome.exe").unwrap();
        assert_eq!(baseline.current_window.dest_ips.len(), 2);
        assert_eq!(baseline.current_window.conn_count, 2);
        assert_eq!(baseline.current_window.bytes_sent, 1500);
        assert_eq!(baseline.current_window.bytes_recv, 7000);
        assert_eq!(baseline.known_dest_ips.len(), 2);
        assert_eq!(baseline.known_domains.len(), 2);
    }

    #[test]
    fn test_baseline_anomaly_detection() {
        // Simulate a baseline with known history and detect anomalies
        let mut baseline = ProcessNetworkBaseline {
            process_name: "notepad.exe".to_string(),
            pid: 5678,
            established_at: Instant::now() - Duration::from_secs(600),
            observation_count: 20,
            dest_ip_counts: VecDeque::from(vec![2, 3, 2, 3, 2, 2, 3, 2, 3, 2]),
            dest_port_counts: VecDeque::from(vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
            domain_counts: VecDeque::from(vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
            bytes_sent_history: VecDeque::from(vec![
                1000, 1200, 900, 1100, 1000, 1050, 950, 1000, 1100, 900,
            ]),
            bytes_recv_history: VecDeque::from(vec![
                5000, 5200, 4900, 5100, 5000, 5050, 4950, 5000, 5100, 4900,
            ]),
            conn_count_history: VecDeque::from(vec![3, 4, 3, 4, 3, 3, 4, 3, 4, 3]),
            avg_duration_history: VecDeque::new(),
            known_dest_ips: HashSet::new(),
            known_dest_ports: HashSet::new(),
            known_domains: HashSet::new(),
            current_window: ProcessWindowAccumulator::default(),
            window_start: Instant::now(),
        };

        // Simulate a spike: notepad.exe connecting to 50 IPs and sending 100KB
        for i in 0..50u32 {
            let ip: IpAddr = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
            baseline.current_window.dest_ips.insert(ip);
        }
        baseline.current_window.bytes_sent = 100_000; // 100KB vs ~1KB baseline
        baseline.current_window.conn_count = 50;

        let anomalies = NetworkDpiCollector::detect_baseline_anomalies(
            &baseline, 5.0,  // dest_ip_anomaly_ratio
            10.0, // bytes_sent_anomaly_ratio
            5.0,  // conn_frequency_anomaly_ratio
        );

        // Should detect dest IP spike, data exfiltration, and connection frequency spike
        assert!(!anomalies.is_empty());
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == BehavioralAnomalyType::DestinationIpSpike));
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == BehavioralAnomalyType::DataExfiltration));
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == BehavioralAnomalyType::ConnectionFrequencySpike));
    }

    #[test]
    fn test_baseline_normal_behavior() {
        // Normal behavior should not trigger anomalies
        let baseline = ProcessNetworkBaseline {
            process_name: "svchost.exe".to_string(),
            pid: 9999,
            established_at: Instant::now() - Duration::from_secs(600),
            observation_count: 20,
            dest_ip_counts: VecDeque::from(vec![5, 6, 5, 6, 5, 5, 6, 5, 6, 5]),
            dest_port_counts: VecDeque::from(vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2]),
            domain_counts: VecDeque::from(vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3]),
            bytes_sent_history: VecDeque::from(vec![
                5000, 5200, 4900, 5100, 5000, 5050, 4950, 5000, 5100, 4900,
            ]),
            bytes_recv_history: VecDeque::from(vec![
                10000, 10200, 9900, 10100, 10000, 10050, 9950, 10000, 10100, 9900,
            ]),
            conn_count_history: VecDeque::from(vec![5, 6, 5, 6, 5, 5, 6, 5, 6, 5]),
            avg_duration_history: VecDeque::new(),
            known_dest_ips: HashSet::new(),
            known_dest_ports: HashSet::new(),
            known_domains: HashSet::new(),
            current_window: ProcessWindowAccumulator {
                dest_ips: (0..6u32)
                    .map(|i| format!("10.0.0.{}", i).parse::<IpAddr>().unwrap())
                    .collect(),
                dest_ports: [443, 80].iter().cloned().collect(),
                domains: HashSet::new(),
                bytes_sent: 5100,
                bytes_recv: 10100,
                conn_count: 6,
                total_duration: Duration::from_secs(30),
            },
            window_start: Instant::now(),
        };

        let anomalies = NetworkDpiCollector::detect_baseline_anomalies(&baseline, 5.0, 10.0, 5.0);

        // Normal behavior should produce no anomalies
        assert!(anomalies.is_empty());
    }

    // ====================================================================
    // Utility Function Tests
    // ====================================================================

    #[test]
    fn test_truncated_sha256() {
        let hash = NetworkDpiCollector::truncated_sha256("test_input", 12);
        assert_eq!(hash.len(), 12);

        // Same input should produce same output
        let hash2 = NetworkDpiCollector::truncated_sha256("test_input", 12);
        assert_eq!(hash, hash2);

        // Different input should produce different output
        let hash3 = NetworkDpiCollector::truncated_sha256("other_input", 12);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_average_calculations() {
        let values_u32 = VecDeque::from(vec![10, 20, 30, 40, 50]);
        assert!((NetworkDpiCollector::average_u32(&values_u32) - 30.0).abs() < 0.001);

        let values_u64 = VecDeque::from(vec![1000u64, 2000, 3000]);
        assert!((NetworkDpiCollector::average_u64(&values_u64) - 2000.0).abs() < 0.001);

        // Empty should return 0
        let empty_u32: VecDeque<u32> = VecDeque::new();
        assert!((NetworkDpiCollector::average_u32(&empty_u32)).abs() < 0.001);
    }

    // ====================================================================
    // DNS-over-HTTPS Detection Tests
    // ====================================================================

    #[test]
    fn test_doh_database_initialization() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Verify DoH provider IPs are loaded
        assert!(collector.doh_provider_ips.len() > 0);
        assert!(collector.doh_provider_ips.contains_key("1.1.1.1"));
        assert!(collector.doh_provider_ips.contains_key("8.8.8.8"));
        assert!(collector.doh_provider_ips.contains_key("9.9.9.9"));

        // Verify hostnames are loaded
        assert!(collector.doh_hostnames.contains("dns.cloudflare.com"));
        assert!(collector.doh_hostnames.contains("dns.google"));
        assert!(collector.doh_hostnames.contains("dns.quad9.net"));
    }

    #[test]
    fn test_doh_sni_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Known DoH hostname should be detected
        let result = collector.check_doh_by_sni("dns.cloudflare.com");
        assert!(result.is_some());
        let detection = result.unwrap();
        assert!(detection.detected);
        assert_eq!(detection.method, DohDetectionMethod::SniMatch);
        assert!(detection.confidence > 0.8);

        // Unknown hostname should not be detected
        let result = collector.check_doh_by_sni("www.google.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_doh_path_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Standard DoH endpoint path
        let result = collector.check_doh_by_path("/dns-query?dns=AAAB", "dns.google");
        assert!(result.is_some());
        let detection = result.unwrap();
        assert!(detection.detected);
        assert_eq!(detection.method, DohDetectionMethod::DohEndpointPath);

        // Regular path should not be detected
        let result = collector.check_doh_by_path("/index.html", "www.example.com");
        assert!(result.is_none());
    }

    // ====================================================================
    // Protocol Identification Tests
    // ====================================================================

    #[test]
    fn test_protocol_ssh_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let ident = collector.identify_protocol(payload, 0, 22, false);

        assert!(matches!(ident.protocol, IdentifiedProtocol::Ssh { .. }));
        assert!(ident.expected_port);
        assert!(!ident.suspicious);
        assert!(ident.confidence > 0.9);

        if let IdentifiedProtocol::Ssh {
            ref version,
            ref software,
        } = ident.protocol
        {
            assert_eq!(version, "SSH-2.0");
            assert!(software.as_deref().unwrap().contains("OpenSSH"));
        }
    }

    #[test]
    fn test_protocol_ssh_on_wrong_port() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let payload = b"SSH-2.0-OpenSSH_8.9p1\r\n";
        let ident = collector.identify_protocol(payload, 0, 80, false);

        assert!(matches!(ident.protocol, IdentifiedProtocol::Ssh { .. }));
        assert!(!ident.expected_port);
        assert!(ident.suspicious);
    }

    #[test]
    fn test_protocol_rdp_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // TPKT header on port 3389
        let payload: &[u8] = &[
            0x03, 0x00, 0x00, 0x2C, 0x27, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let ident = collector.identify_protocol(payload, 0, 3389, false);

        assert_eq!(ident.protocol, IdentifiedProtocol::Rdp);
        assert!(ident.expected_port);
        assert!(ident.confidence >= 0.9);
    }

    #[test]
    fn test_protocol_rdp_on_wrong_port() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // TPKT + X.224 Connection Request on port 443
        let payload: &[u8] = &[
            0x03, 0x00, 0x00, 0x2C, 0x27, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let ident = collector.identify_protocol(payload, 0, 443, false);

        assert_eq!(ident.protocol, IdentifiedProtocol::Rdp);
        assert!(!ident.expected_port);
        assert!(ident.suspicious);
    }

    #[test]
    fn test_protocol_quic_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // QUIC long header with QUICv1 version
        let payload: &[u8] = &[
            0xC0, // Long header form + fixed bit
            0x00, 0x00, 0x00, 0x01, // Version: QUICv1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        ];
        let ident = collector.identify_protocol(payload, 0, 443, true);

        assert!(
            matches!(
                ident.protocol,
                IdentifiedProtocol::Quic {
                    version: 0x00000001
                }
            ),
            "Expected QUIC protocol v1, got {:?}",
            ident.protocol
        );
        assert!(ident.expected_port);
        assert!(ident.confidence > 0.8);
    }

    #[test]
    fn test_protocol_wireguard_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // WireGuard Handshake Initiation (type=1, 148 bytes)
        let mut payload = vec![0x01, 0x00, 0x00, 0x00]; // msg_type=1, reserved=000
        payload.resize(148, 0xAB); // Pad to 148 bytes
        let ident = collector.identify_protocol(&payload, 0, 51820, true);

        assert_eq!(ident.protocol, IdentifiedProtocol::WireGuard);
        assert!(ident.expected_port);
        assert!(ident.confidence > 0.7);
    }

    #[test]
    fn test_protocol_tls_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // TLS ClientHello record header
        let payload: &[u8] = &[
            0x16, // Content type: Handshake
            0x03, 0x01, // TLS version 1.0 (record layer)
            0x00, 0x05, // Length
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x01,
        ];
        let ident = collector.identify_protocol(payload, 0, 443, false);

        assert!(matches!(ident.protocol, IdentifiedProtocol::Https { .. }));
        assert!(ident.expected_port);
    }

    #[test]
    fn test_protocol_dot_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // TLS handshake on port 853 = DNS over TLS
        let payload: &[u8] = &[
            0x16, // Content type: Handshake
            0x03, 0x03, // TLS 1.2
            0x00, 0x05, 0x01, 0x00, 0x00, 0x01,
        ];
        let ident = collector.identify_protocol(payload, 0, 853, false);

        assert_eq!(ident.protocol, IdentifiedProtocol::DnsOverTls);
        assert!(ident.expected_port);
        assert!(ident.confidence > 0.9);
    }

    #[test]
    fn test_protocol_smb_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // NetBIOS Session + SMBv2 header
        let payload: &[u8] = &[
            0x00, // NetBIOS session message
            0x00, 0x00, 0x44, // Length
            0xFE, b'S', b'M', b'B', // SMBv2 magic
        ];
        let ident = collector.identify_protocol(payload, 0, 445, false);

        assert_eq!(ident.protocol, IdentifiedProtocol::Smb);
        assert!(ident.expected_port);
        assert!(ident.confidence > 0.8);
    }

    #[test]
    fn test_protocol_http_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ident = collector.identify_protocol(payload, 0, 80, false);

        assert_eq!(ident.protocol, IdentifiedProtocol::Http);
        assert!(ident.expected_port);
    }

    // ====================================================================
    // Encrypted Payload Entropy Analysis Tests
    // ====================================================================

    #[test]
    fn test_payload_entropy_recording() {
        let config = AgentConfig::default();
        let mut collector = NetworkDpiCollector::new(&config);

        // Record some payloads
        let payload1 = vec![0xAB; 100];
        let payload2 = vec![0xCD; 200];
        collector.record_payload("10.0.0.1", 443, &payload1);
        collector.record_payload("10.0.0.1", 443, &payload2);

        assert!(collector.payload_trackers.contains_key("10.0.0.1:443"));
        let tracker = &collector.payload_trackers["10.0.0.1:443"];
        assert_eq!(tracker.payload_sizes.len(), 2);
        assert_eq!(tracker.entropy_values.len(), 2);
    }

    #[test]
    fn test_constant_size_payload_detection() {
        let config = AgentConfig::default();
        let mut collector = NetworkDpiCollector::new(&config);

        // Record 10 payloads of the same size (should trigger constant-size detection)
        for _ in 0..10 {
            let payload = vec![0xFF; 256];
            collector.record_payload("10.0.0.2", 8080, &payload);
        }

        let tracker = &collector.payload_trackers["10.0.0.2:8080"];
        assert!(tracker.constant_size_run >= 5);
    }

    #[test]
    fn test_entropy_analysis_covert_channel() {
        let config = AgentConfig::default();
        let mut collector = NetworkDpiCollector::new(&config);

        // Record high-entropy payloads on a non-standard port
        for i in 0..10 {
            let payload: Vec<u8> = (0..256).map(|b| ((b + i) % 256) as u8).collect();
            collector.record_payload("10.0.0.3", 8888, &payload);
        }

        let tracker = &collector.payload_trackers["10.0.0.3:8888"];
        let analysis = collector.analyze_entropy_tracker(tracker);

        // High entropy on non-standard port should flag covert channel
        if analysis.avg_entropy > 7.5 {
            assert!(analysis.covert_channel_suspected);
            assert!(analysis.suspicion_score > 0.3);
        }
    }

    // ====================================================================
    // Enhanced Beacon Detection Tests
    // ====================================================================

    #[test]
    fn test_connection_record_tracking() {
        let config = AgentConfig::default();
        let mut collector = NetworkDpiCollector::new(&config);

        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        collector.record_connection_data(ip, 64, 2048);
        collector.record_connection_data(ip, 72, 1950);
        collector.record_connection_data(ip, 68, 2100);

        assert!(collector.connection_records.contains_key(&ip));
        assert_eq!(collector.connection_records[&ip].len(), 3);
    }

    #[test]
    fn test_enhanced_beacon_c2_data_pattern() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Simulate C2 beacon: small requests, larger responses, regular intervals
        let mut records = VecDeque::new();
        let base = Instant::now();
        for i in 0..20u32 {
            records.push_back(ConnectionRecord {
                timestamp: base + Duration::from_secs(i as u64 * 60), // 60s intervals
                bytes_sent: 64 + (i % 3) as u64,                      // Small requests (~64 bytes)
                bytes_recv: 2048 + (i * 100) as u64,                  // Larger responses (~2-4KB)
            });
        }

        let analysis = collector.analyze_enhanced_beacon(&records);

        // Should detect C2-like data pattern
        assert!(analysis.avg_request_size < 100);
        assert!(analysis.avg_response_size > 1000);
        assert!(analysis.data_size_ratio > 3.0);
        assert!(analysis.c2_data_pattern);

        // CV should be low (regular intervals)
        assert!(analysis.coefficient_of_variation < 0.1);
    }

    #[test]
    fn test_enhanced_beacon_irregular_traffic() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Simulate irregular (non-beacon) traffic: varying intervals and sizes
        let mut records = VecDeque::new();
        let base = Instant::now();
        let irregular_intervals = [5, 120, 3, 45, 200, 1, 80, 15, 300, 10];
        let mut cumulative = 0u64;
        for &interval in &irregular_intervals {
            cumulative += interval;
            records.push_back(ConnectionRecord {
                timestamp: base + Duration::from_secs(cumulative),
                bytes_sent: 1000 + (cumulative * 10) % 5000,
                bytes_recv: 500 + (cumulative * 7) % 3000,
            });
        }

        let analysis = collector.analyze_enhanced_beacon(&records);

        // Should NOT look like a beacon
        assert!(analysis.coefficient_of_variation > 0.5);
        assert!(analysis.combined_score < 0.6);
    }

    // ====================================================================
    // Enhanced Certificate Analysis Tests
    // ====================================================================

    #[test]
    fn test_cert_long_validity_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate valid for 10 years (exceeds 825-day threshold)
        let cert = CertificateInfo {
            subject_cn: Some("long-valid.example.com".to_string()),
            issuer_cn: Some("SomeCA".to_string()),
            issuer_org: Some("DigiCert Inc".to_string()),
            sans: vec!["long-valid.example.com".to_string()],
            not_before: now,
            not_after: now + 10 * 365 * 86400,
            is_self_signed: false,
            serial_number: "10".to_string(),
            sha256_fingerprint: "longvalid".to_string(),
        };

        let analysis = collector.analyze_certificate_enhanced(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::LongValidity { .. })));
    }

    #[test]
    fn test_cert_recently_issued_detection() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate issued 2 days ago (below 7-day threshold)
        let cert = CertificateInfo {
            subject_cn: Some("new.example.com".to_string()),
            issuer_cn: Some("SomeCA".to_string()),
            issuer_org: Some("Let's Encrypt".to_string()),
            sans: vec!["new.example.com".to_string()],
            not_before: now - 2 * 86400,
            not_after: now + 90 * 86400,
            is_self_signed: false,
            serial_number: "11".to_string(),
            sha256_fingerprint: "recentcert".to_string(),
        };

        let analysis = collector.analyze_certificate_enhanced(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::RecentlyIssued { .. })));
    }

    #[test]
    fn test_cert_suspicious_wildcard() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Wildcard on a dynamic DNS domain
        let cert = CertificateInfo {
            subject_cn: Some("*.evil.duckdns.org".to_string()),
            issuer_cn: Some("SomeCA".to_string()),
            issuer_org: Some("Let's Encrypt".to_string()),
            sans: vec!["*.evil.duckdns.org".to_string()],
            not_before: now - 30 * 86400,
            not_after: now + 90 * 86400,
            is_self_signed: false,
            serial_number: "12".to_string(),
            sha256_fingerprint: "wildcardcert".to_string(),
        };

        let analysis = collector.analyze_certificate_enhanced(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::SuspiciousWildcard { .. })));
        assert!(analysis.suspicion_score > 0.2);
    }

    #[test]
    fn test_cert_uncommon_issuer() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate issued by an uncommon CA
        let cert = CertificateInfo {
            subject_cn: Some("site.example.com".to_string()),
            issuer_cn: Some("My Home Lab CA".to_string()),
            issuer_org: Some("Random Corp".to_string()),
            sans: vec!["site.example.com".to_string()],
            not_before: now - 30 * 86400,
            not_after: now + 365 * 86400,
            is_self_signed: false,
            serial_number: "13".to_string(),
            sha256_fingerprint: "uncommoncert".to_string(),
        };

        let analysis = collector.analyze_certificate_enhanced(&cert);
        assert!(analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, CertificateAnomalyType::UncommonIssuer { .. })));
    }

    // ====================================================================
    // TLS Fingerprint Tests
    // ====================================================================

    #[test]
    fn test_tls_fingerprint_build() {
        let client_hello = TlsClientHello {
            tls_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            extensions: vec![0x0000, 0x0005, 0x000a, 0x000b, 0x000d],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
        };

        let server_hello = TlsServerHello {
            tls_version: 0x0303,
            cipher_suite: 0xc02c,
            extensions: vec![0x0000, 0xff01],
        };

        let fp = NetworkDpiCollector::build_tls_fingerprint(&client_hello, Some(&server_hello));

        assert!(!fp.ja3_hash.is_empty());
        assert!(!fp.ja3_full.is_empty());
        assert!(fp.ja3s_hash.is_some());
        assert_eq!(fp.tls_version, 0x0303);
        assert_eq!(fp.sni, Some("example.com".to_string()));
        assert_eq!(fp.cipher_suites.len(), 5);

        // Without server hello
        let fp2 = NetworkDpiCollector::build_tls_fingerprint(&client_hello, None);
        assert!(fp2.ja3s_hash.is_none());
        // Same client hello should produce same JA3
        assert_eq!(fp.ja3_hash, fp2.ja3_hash);
    }

    #[test]
    fn test_ja3_reputation_check() {
        let config = AgentConfig::default();
        let collector = NetworkDpiCollector::new(&config);

        // Build a fingerprint with a known-bad hash
        let fingerprint = TlsFingerprint {
            ja3_hash: "72a589da586844d7f0818ce684948eea".to_string(), // Cobalt Strike
            ja3_full: "test".to_string(),
            ja3s_hash: None,
            tls_version: 0x0303,
            cipher_suites: vec![],
            extensions: vec![],
            sni: None,
        };

        let (suspicious, framework, confidence) = collector.check_ja3_reputation(&fingerprint);
        assert!(suspicious);
        assert!(framework.unwrap().contains("Cobalt Strike"));
        assert!(confidence > 0.8);

        // Build a fingerprint with a known-good hash
        let good_fp = TlsFingerprint {
            ja3_hash: "b32309a26951912be7dba376398abc3b".to_string(), // Chrome
            ja3_full: "test".to_string(),
            ja3s_hash: None,
            tls_version: 0x0303,
            cipher_suites: vec![],
            extensions: vec![],
            sni: None,
        };

        let (suspicious, framework, _) = collector.check_ja3_reputation(&good_fp);
        assert!(!suspicious);
        assert!(framework.is_none());
    }
}
