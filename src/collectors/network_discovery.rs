//! Network Discovery Collector - SentinelOne Ranger-style Distributed Network Discovery
//!
//! Provides passive and active network device discovery using the agent as a sensor.
//!
//! Features:
//! - **Passive discovery**: ARP cache monitoring, broadcast/multicast traffic sniffing
//!   (NetBIOS, mDNS, SSDP, LLMNR), DHCP lease monitoring, traffic header extraction
//! - **Active scanning** (configurable, off by default):
//!   - ARP scan of local subnets (Layer 2)
//!   - TCP SYN scan of common ports (22, 80, 443, 445, 3389, 8080, etc.)
//!   - Service banner grabbing on open ports
//!   - SNMP v1/v2c community string probing
//!   - Configurable rate limiting to avoid network disruption
//! - **Device fingerprinting**:
//!   - OS detection via TCP/IP stack fingerprinting (TTL, window size, DF bit)
//!   - Service identification from banners (SSH, HTTP, SMB)
//!   - OUI (MAC vendor) lookup from MAC address
//!   - Device type classification: server, workstation, printer, camera, IoT, etc.
//! - **Scan coordination**: agent reports subnet to server; server assigns scan ranges

// This collector enumerates passive and active network discovery state
// (ARP/DHCP/NetBIOS/mDNS/SSDP/LLMNR caches, OUI vendor database, OS-fingerprint
// tables, scan-coordination metadata). Reserved fields and helper utilities
// are kept exhaustive for downstream sensor reporting even when not all paths
// are dispatched yet.
#![allow(dead_code, unused_variables)]

use super::{EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the network discovery collector.
/// Nested under `[network_discovery]` in `agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkDiscoveryConfig {
    /// Master switch for the network discovery collector
    pub enabled: bool,

    /// Enable passive discovery (ARP cache, mDNS, SSDP, NetBIOS, DHCP)
    pub passive_enabled: bool,

    /// Enable active scanning (ARP scan, TCP SYN scan, banner grab)
    pub active_enabled: bool,

    /// Active scan mode: "passive_only" | "active"
    pub scan_mode: String,

    /// Interval in seconds between passive discovery sweeps
    pub passive_interval_secs: u64,

    /// Interval in seconds between active scan sweeps
    pub active_interval_secs: u64,

    /// Maximum packets per second for active scanning (rate limit)
    pub max_scan_rate_pps: u32,

    /// TCP connect timeout in milliseconds for port scanning
    pub tcp_connect_timeout_ms: u64,

    /// Banner grab timeout in milliseconds
    pub banner_timeout_ms: u64,

    /// TCP ports to scan during active discovery
    pub scan_ports: Vec<u16>,

    /// SNMP community strings to probe
    pub snmp_communities: Vec<String>,

    /// IP addresses/ranges to exclude from scanning
    pub excluded_ips: Vec<String>,

    /// Whether to emit discovered devices as telemetry events
    pub emit_telemetry: bool,

    /// Minimum number of agents required on a subnet before active scanning starts
    pub min_agents_per_subnet: u32,

    /// Scan window: only scan between these hours (0-23, empty = always)
    pub scan_window_start_hour: Option<u8>,
    pub scan_window_end_hour: Option<u8>,

    /// Local subnets to scan (auto-detected if empty)
    pub subnets: Vec<String>,

    /// Server-assigned scan ranges (populated via config push)
    pub assigned_ranges: Vec<String>,
}

impl Default for NetworkDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Off by default - opt-in feature
            passive_enabled: true,
            active_enabled: false, // Active scanning off by default
            scan_mode: "passive_only".to_string(),
            passive_interval_secs: 60,
            active_interval_secs: 300,
            max_scan_rate_pps: 50,
            tcp_connect_timeout_ms: 2000,
            banner_timeout_ms: 3000,
            scan_ports: vec![
                22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445, 993, 995, 1433, 1521, 3306,
                3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 27017,
            ],
            snmp_communities: vec!["public".to_string(), "private".to_string()],
            excluded_ips: Vec::new(),
            emit_telemetry: true,
            min_agents_per_subnet: 1,
            scan_window_start_hour: None,
            scan_window_end_hour: None,
            subnets: Vec::new(),
            assigned_ranges: Vec::new(),
        }
    }
}

// ============================================================================
// Data Types
// ============================================================================

/// Device type classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Server,
    Workstation,
    Printer,
    Camera,
    IoT,
    NetworkDevice,
    Mobile,
    StorageDevice,
    VoIP,
    Unknown,
}

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::Unknown
    }
}

/// How the device was discovered
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    ArpCache,
    ArpScan,
    TcpScan,
    Mdns,
    Ssdp,
    NetBIOS,
    Llmnr,
    Dhcp,
    Snmp,
    BannerGrab,
    TrafficObserved,
}

/// OS guess from TCP/IP fingerprinting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsGuess {
    /// Guessed OS family
    pub os_family: String,
    /// Guessed OS version
    pub os_version: Option<String>,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Evidence used for the guess
    pub evidence: Vec<String>,
}

/// Information about an open port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Port state
    pub state: String,
    /// Service name guess
    pub service: Option<String>,
}

/// Information about a discovered service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Port number
    pub port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Service name (ssh, http, smb, etc.)
    pub name: String,
    /// Service version (from banner)
    pub version: Option<String>,
    /// Raw banner text
    pub banner: Option<String>,
    /// Extra information extracted from service
    pub extra_info: HashMap<String, String>,
}

/// A discovered network device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    /// MAC address (if known)
    pub mac_address: Option<String>,
    /// All observed IP addresses
    pub ip_addresses: Vec<String>,
    /// All observed hostnames (from mDNS, NetBIOS, reverse DNS, etc.)
    pub hostnames: Vec<String>,
    /// OS guess from fingerprinting
    pub os_guess: Option<OsGuess>,
    /// Classified device type
    pub device_type: DeviceType,
    /// Open ports found
    pub open_ports: Vec<PortInfo>,
    /// Services discovered via banner grabbing
    pub services: Vec<ServiceInfo>,
    /// Vendor name from OUI database
    pub vendor: Option<String>,
    /// First time this device was seen
    pub first_seen: u64,
    /// Last time this device was seen
    pub last_seen: u64,
    /// How the device was discovered
    pub discovery_method: DiscoveryMethod,
    /// Whether this device has a Tamandua agent installed
    pub managed: bool,
    /// TTL observed in traffic (used for OS fingerprinting)
    pub ttl: Option<u8>,
    /// TCP window size observed (used for OS fingerprinting)
    pub tcp_window_size: Option<u16>,
}

/// Network discovery event payload - emitted as telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiscoveryEvent {
    /// List of discovered/updated devices
    pub devices: Vec<DiscoveredDevice>,
    /// Subnet that was scanned
    pub subnet: String,
    /// Scan type that produced these results
    pub scan_type: String,
    /// Number of new devices found this cycle
    pub new_device_count: usize,
    /// Total known devices on this subnet
    pub total_device_count: usize,
}

// ============================================================================
// OUI Database - Compact MAC Vendor Lookup
// ============================================================================

/// Compact OUI database for MAC vendor lookup.
/// Contains the top ~200 most common OUI prefixes.
/// A full database can be pushed via config updates.
struct OuiDatabase {
    entries: HashMap<String, String>,
}

impl OuiDatabase {
    fn new() -> Self {
        let mut entries = HashMap::new();

        // Top OUI prefixes (first 3 octets -> vendor name)
        let oui_data: &[(&str, &str)] = &[
            ("00:50:56", "VMware"),
            ("00:0C:29", "VMware"),
            ("00:05:69", "VMware"),
            ("00:1C:14", "VMware"),
            ("08:00:27", "Oracle VirtualBox"),
            ("52:54:00", "QEMU/KVM"),
            ("00:16:3E", "Xen"),
            ("00:15:5D", "Microsoft Hyper-V"),
            ("00:1A:11", "Google"),
            ("3C:5A:B4", "Google"),
            ("00:17:88", "Philips Lighting"),
            ("D8:6C:63", "Google"),
            ("AC:67:B2", "Amazon Technologies"),
            ("F0:27:2D", "Amazon Technologies"),
            ("74:C2:46", "Amazon Technologies"),
            ("40:B4:CD", "Amazon Technologies"),
            ("A0:02:DC", "Amazon Technologies"),
            ("B4:7C:9C", "Amazon Technologies"),
            ("00:11:32", "Synology"),
            ("00:1E:06", "QNAP"),
            ("00:08:9B", "QNAP"),
            ("00:25:90", "Supermicro"),
            ("AC:1F:6B", "Supermicro"),
            ("00:50:C2", "IEEE Std 802.1Q"),
            ("00:00:5E", "IANA"),
            ("01:00:5E", "IANA Multicast"),
            ("33:33:00", "IPv6 Multicast"),
            ("FF:FF:FF", "Broadcast"),
            // Apple
            ("00:03:93", "Apple"),
            ("00:05:02", "Apple"),
            ("00:0A:27", "Apple"),
            ("00:0A:95", "Apple"),
            ("00:0D:93", "Apple"),
            ("00:11:24", "Apple"),
            ("00:14:51", "Apple"),
            ("00:16:CB", "Apple"),
            ("00:17:F2", "Apple"),
            ("00:19:E3", "Apple"),
            ("00:1B:63", "Apple"),
            ("00:1E:C2", "Apple"),
            ("00:1F:5B", "Apple"),
            ("00:1F:F3", "Apple"),
            ("00:21:E9", "Apple"),
            ("00:22:41", "Apple"),
            ("00:23:12", "Apple"),
            ("00:23:32", "Apple"),
            ("00:23:6C", "Apple"),
            ("00:23:DF", "Apple"),
            ("00:24:36", "Apple"),
            ("00:25:00", "Apple"),
            ("00:25:4B", "Apple"),
            ("00:25:BC", "Apple"),
            ("00:26:08", "Apple"),
            ("00:26:4A", "Apple"),
            ("00:26:B0", "Apple"),
            ("00:26:BB", "Apple"),
            ("F0:18:98", "Apple"),
            ("14:98:77", "Apple"),
            // Dell
            ("00:06:5B", "Dell"),
            ("00:08:74", "Dell"),
            ("00:0B:DB", "Dell"),
            ("00:0D:56", "Dell"),
            ("00:0F:1F", "Dell"),
            ("00:11:43", "Dell"),
            ("00:12:3F", "Dell"),
            ("00:13:72", "Dell"),
            ("00:14:22", "Dell"),
            ("00:15:C5", "Dell"),
            ("00:18:8B", "Dell"),
            ("00:19:B9", "Dell"),
            ("00:1A:A0", "Dell"),
            ("00:1C:23", "Dell"),
            ("00:1D:09", "Dell"),
            ("00:1E:4F", "Dell"),
            ("00:1E:C9", "Dell"),
            ("00:21:70", "Dell"),
            ("00:21:9B", "Dell"),
            ("00:22:19", "Dell"),
            ("00:23:AE", "Dell"),
            ("00:24:E8", "Dell"),
            ("00:25:64", "Dell"),
            ("00:26:B9", "Dell"),
            ("14:FE:B5", "Dell"),
            ("18:03:73", "Dell"),
            ("18:A9:9B", "Dell"),
            // HP
            ("00:01:E6", "HP"),
            ("00:01:E7", "HP"),
            ("00:02:A5", "HP"),
            ("00:04:EA", "HP"),
            ("00:08:02", "HP"),
            ("00:08:83", "HP"),
            ("00:0A:57", "HP"),
            ("00:0B:CD", "HP"),
            ("00:0D:9D", "HP"),
            ("00:0E:7F", "HP"),
            ("00:0F:20", "HP"),
            ("00:0F:61", "HP"),
            ("00:10:83", "HP"),
            ("00:10:E3", "HP"),
            ("00:11:0A", "HP"),
            ("00:11:85", "HP"),
            ("00:12:79", "HP"),
            ("00:13:21", "HP"),
            ("00:14:38", "HP"),
            ("00:14:C2", "HP"),
            ("00:15:60", "HP"),
            ("00:16:35", "HP"),
            ("00:17:08", "HP"),
            ("00:17:A4", "HP"),
            ("00:18:FE", "HP"),
            ("00:19:BB", "HP"),
            ("00:1A:4B", "HP"),
            ("00:1B:78", "HP"),
            ("00:1C:C4", "HP"),
            ("00:1E:0B", "HP"),
            ("00:1F:29", "HP"),
            ("00:21:5A", "HP"),
            ("00:22:64", "HP"),
            ("00:23:7D", "HP"),
            ("00:24:81", "HP"),
            ("00:25:B3", "HP"),
            ("00:26:55", "HP"),
            ("2C:27:D7", "HP"),
            ("2C:41:38", "HP"),
            ("2C:44:FD", "HP"),
            ("2C:59:E5", "HP"),
            ("30:8D:99", "HP"),
            // Cisco
            ("00:00:0C", "Cisco"),
            ("00:01:42", "Cisco"),
            ("00:01:43", "Cisco"),
            ("00:01:63", "Cisco"),
            ("00:01:64", "Cisco"),
            ("00:01:96", "Cisco"),
            ("00:01:97", "Cisco"),
            ("00:01:C7", "Cisco"),
            ("00:01:C9", "Cisco"),
            ("00:02:16", "Cisco"),
            ("00:02:17", "Cisco"),
            ("00:02:4A", "Cisco"),
            ("00:02:4B", "Cisco"),
            ("00:02:7D", "Cisco"),
            ("00:02:7E", "Cisco"),
            ("00:02:B9", "Cisco"),
            ("00:02:BA", "Cisco"),
            ("00:02:FC", "Cisco"),
            ("00:02:FD", "Cisco"),
            ("00:03:31", "Cisco"),
            ("00:03:32", "Cisco"),
            ("00:03:6B", "Cisco"),
            ("00:03:6C", "Cisco"),
            ("00:03:9F", "Cisco"),
            ("00:03:A0", "Cisco"),
            ("00:03:E3", "Cisco"),
            ("00:03:E4", "Cisco"),
            ("00:03:FD", "Cisco"),
            ("00:03:FE", "Cisco"),
            // Intel
            ("00:02:B3", "Intel"),
            ("00:03:47", "Intel"),
            ("00:04:23", "Intel"),
            ("00:07:E9", "Intel"),
            ("00:0C:F1", "Intel"),
            ("00:0E:0C", "Intel"),
            ("00:0E:35", "Intel"),
            ("00:11:11", "Intel"),
            ("00:12:F0", "Intel"),
            ("00:13:02", "Intel"),
            ("00:13:20", "Intel"),
            ("00:13:CE", "Intel"),
            ("00:13:E8", "Intel"),
            ("00:15:00", "Intel"),
            ("00:15:17", "Intel"),
            ("00:16:6F", "Intel"),
            ("00:16:76", "Intel"),
            ("00:16:EA", "Intel"),
            ("00:16:EB", "Intel"),
            ("00:18:DE", "Intel"),
            ("00:19:D1", "Intel"),
            ("00:19:D2", "Intel"),
            ("00:1B:21", "Intel"),
            ("00:1B:77", "Intel"),
            ("00:1C:BF", "Intel"),
            ("00:1C:C0", "Intel"),
            ("00:1D:E0", "Intel"),
            ("00:1D:E1", "Intel"),
            ("00:1E:64", "Intel"),
            ("00:1E:65", "Intel"),
            ("00:1E:67", "Intel"),
            ("00:1F:3B", "Intel"),
            ("00:1F:3C", "Intel"),
            ("00:20:7B", "Intel"),
            ("00:21:5C", "Intel"),
            ("00:21:5D", "Intel"),
            ("00:21:6A", "Intel"),
            ("00:21:6B", "Intel"),
            ("00:22:FA", "Intel"),
            ("00:22:FB", "Intel"),
            ("00:23:14", "Intel"),
            ("00:23:15", "Intel"),
            ("00:24:D6", "Intel"),
            ("00:24:D7", "Intel"),
            ("00:26:C6", "Intel"),
            ("00:26:C7", "Intel"),
            ("00:27:10", "Intel"),
            // Samsung
            ("00:07:AB", "Samsung"),
            ("00:0D:E5", "Samsung"),
            ("00:12:47", "Samsung"),
            ("00:12:FB", "Samsung"),
            ("00:13:77", "Samsung"),
            ("00:15:99", "Samsung"),
            ("00:16:32", "Samsung"),
            ("00:16:DB", "Samsung"),
            ("00:17:D5", "Samsung"),
            ("00:18:AF", "Samsung"),
            ("00:1A:8A", "Samsung"),
            ("00:1B:98", "Samsung"),
            ("00:1C:43", "Samsung"),
            ("00:1D:25", "Samsung"),
            ("00:1D:F6", "Samsung"),
            ("00:1E:E1", "Samsung"),
            ("00:1E:E2", "Samsung"),
            ("00:1F:CC", "Samsung"),
            ("00:1F:CD", "Samsung"),
            ("00:21:19", "Samsung"),
            ("00:21:D1", "Samsung"),
            ("00:21:D2", "Samsung"),
            ("00:23:39", "Samsung"),
            ("00:23:3A", "Samsung"),
            ("00:23:99", "Samsung"),
            ("00:23:D6", "Samsung"),
            ("00:23:D7", "Samsung"),
            ("00:24:54", "Samsung"),
            ("00:24:90", "Samsung"),
            ("00:24:91", "Samsung"),
            ("00:25:66", "Samsung"),
            ("00:25:67", "Samsung"),
            ("00:26:37", "Samsung"),
            ("00:26:5D", "Samsung"),
            ("00:26:5F", "Samsung"),
            // Printers
            ("00:00:74", "Ricoh"),
            ("00:00:AA", "Xerox"),
            ("00:00:48", "Epson"),
            ("00:1B:A9", "Brother"),
            ("00:1E:8F", "Canon"),
            ("00:15:99", "Samsung (Printers)"),
            ("00:1F:A4", "Shenzhen Gongjin"),
            ("30:05:5C", "Hisense"),
            ("00:04:00", "Lexmark"),
            ("00:20:00", "Lexmark"),
            ("00:21:B7", "Lexmark"),
            // Networking
            ("00:1D:7E", "Linksys"),
            ("00:22:6B", "Linksys"),
            ("00:25:9C", "Linksys"),
            ("00:0F:66", "Linksys"),
            ("00:14:BF", "Linksys"),
            ("00:18:39", "Linksys"),
            ("C0:C1:C0", "Linksys"),
            ("20:AA:4B", "Linksys"),
            ("58:6D:8F", "Linksys"),
            ("C4:E9:84", "TP-Link"),
            ("14:CC:20", "TP-Link"),
            ("50:C7:BF", "TP-Link"),
            ("54:C8:0F", "TP-Link"),
            ("60:E3:27", "TP-Link"),
            ("20:CF:30", "ASUSTek"),
            ("1C:87:2C", "ASUSTek"),
            ("F4:6D:04", "ASUSTek"),
            ("00:1F:C6", "ASUSTek"),
            ("00:23:54", "ASUSTek"),
            ("00:26:18", "ASUSTek"),
            ("B0:6E:BF", "ASUSTek"),
            ("C8:60:00", "ASUSTek"),
            ("E0:3F:49", "ASUSTek"),
            ("00:1B:2F", "Netgear"),
            ("00:1E:2A", "Netgear"),
            ("00:1F:33", "Netgear"),
            ("00:22:3F", "Netgear"),
            ("00:24:B2", "Netgear"),
            ("00:26:F2", "Netgear"),
            ("20:4E:7F", "Netgear"),
            ("2C:B0:5D", "Netgear"),
            ("84:1B:5E", "Netgear"),
            ("A4:2B:8C", "Netgear"),
            ("C4:3D:C7", "Netgear"),
            // IoT / Smart Home
            ("68:37:E9", "Amazon (Echo)"),
            ("44:65:0D", "Amazon (Echo)"),
            ("FC:65:DE", "Amazon (Echo)"),
            ("B0:FC:36", "Google (Nest)"),
            ("18:B4:30", "Nest"),
            ("64:16:66", "Nest"),
            ("D4:73:D7", "Sonos"),
            ("5C:AA:FD", "Sonos"),
            ("B8:E9:37", "Sonos"),
            ("78:28:CA", "Sonos"),
            ("B8:27:EB", "Raspberry Pi"),
            ("DC:A6:32", "Raspberry Pi"),
            ("E4:5F:01", "Raspberry Pi"),
            ("28:CD:C1", "Raspberry Pi"),
            // Cameras
            ("00:80:F0", "Panasonic"),
            ("9C:8E:CD", "Amcrest"),
            ("28:57:BE", "Hangzhou Hikvision"),
            ("C0:56:E3", "Hangzhou Hikvision"),
            ("4C:BD:8F", "Hangzhou Hikvision"),
            ("54:C4:15", "Hangzhou Hikvision"),
            ("44:19:B6", "Hangzhou Hikvision"),
            ("00:40:8C", "Axis Communications"),
            ("00:40:8C", "Axis Communications"),
            ("AC:CC:8E", "Axis Communications"),
            ("B8:A4:4F", "Axis Communications"),
            ("00:0E:8F", "Sercomm (IP Cameras)"),
            ("7C:DD:90", "Dahua Technology"),
            ("3C:EF:8C", "Dahua Technology"),
            ("40:48:FD", "Dahua Technology"),
            // Lenovo
            ("00:06:1B", "Lenovo"),
            ("00:09:6B", "Lenovo"),
            ("00:0A:E4", "Lenovo"),
            ("00:12:FE", "Lenovo"),
            ("00:1A:6B", "Lenovo"),
            ("28:D2:44", "Lenovo"),
            ("40:B0:34", "Lenovo"),
            ("50:7B:9D", "Lenovo"),
            ("54:EE:75", "Lenovo"),
            ("70:F1:A1", "Lenovo"),
            ("80:CE:62", "Lenovo"),
            ("98:FA:E3", "Lenovo"),
            ("C8:5B:76", "Lenovo"),
            ("E8:2A:44", "Lenovo"),
        ];

        for (prefix, vendor) in oui_data {
            entries.insert(prefix.to_uppercase(), vendor.to_string());
        }

        Self { entries }
    }

    /// Lookup vendor from MAC address.
    /// Accepts formats: "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"
    fn lookup(&self, mac: &str) -> Option<String> {
        let normalized = mac.to_uppercase().replace('-', ":").replace('.', "");

        // Handle Cisco notation (aabb.ccdd.eeff)
        let prefix = if normalized.contains(':') {
            // Standard notation: take first 3 octets
            let parts: Vec<&str> = normalized.split(':').collect();
            if parts.len() >= 3 {
                format!("{}:{}:{}", parts[0], parts[1], parts[2])
            } else {
                return None;
            }
        } else if normalized.len() >= 6 {
            // No separators: first 6 hex chars
            format!(
                "{}:{}:{}",
                &normalized[0..2],
                &normalized[2..4],
                &normalized[4..6]
            )
        } else {
            return None;
        };

        self.entries.get(&prefix).cloned()
    }
}

// ============================================================================
// TCP/IP Fingerprinting
// ============================================================================

/// Fingerprint a remote host's OS based on TCP/IP stack characteristics
fn fingerprint_os(
    ttl: Option<u8>,
    window_size: Option<u16>,
    open_ports: &[PortInfo],
) -> Option<OsGuess> {
    let mut evidence = Vec::new();
    let mut os_family = "Unknown".to_string();
    let mut confidence: f32 = 0.0;

    // TTL-based fingerprinting
    if let Some(ttl) = ttl {
        let (guess, conf, ev) = match ttl {
            // Windows uses TTL 128 by default
            120..=128 => ("Windows", 0.4, "TTL 128 (Windows default)"),
            // Linux/Android uses TTL 64
            56..=64 => ("Linux", 0.4, "TTL 64 (Linux/Android default)"),
            // macOS/iOS uses TTL 64
            // Can't distinguish from Linux by TTL alone
            // Cisco/network devices use TTL 255
            248..=255 => (
                "Network Device",
                0.5,
                "TTL 255 (Cisco/Network device default)",
            ),
            // Solaris/AIX uses TTL 254
            246..=254 => ("Unix (Solaris/AIX)", 0.3, "TTL 254 (Solaris/AIX default)"),
            _ => ("Unknown", 0.1, "Non-standard TTL"),
        };
        os_family = guess.to_string();
        confidence = conf;
        evidence.push(format!("{} (TTL={})", ev, ttl));
    }

    // Window size hints
    if let Some(ws) = window_size {
        match ws {
            65535 => {
                evidence.push("Window size 65535 (common Windows)".to_string());
                if os_family == "Unknown" {
                    os_family = "Windows".to_string();
                    confidence = 0.3;
                } else if os_family == "Windows" {
                    confidence += 0.15;
                }
            }
            5840 | 5720 => {
                evidence.push(format!("Window size {} (common Linux)", ws));
                if os_family == "Unknown" {
                    os_family = "Linux".to_string();
                    confidence = 0.3;
                } else if os_family == "Linux" {
                    confidence += 0.15;
                }
            }
            _ => {}
        }
    }

    // Port-based hints
    let has_port = |p: u16| open_ports.iter().any(|op| op.port == p);

    if has_port(135) || has_port(139) || has_port(445) {
        evidence.push("SMB/CIFS ports open (likely Windows or Samba)".to_string());
        if os_family == "Windows" {
            confidence += 0.2;
        } else if os_family == "Unknown" {
            os_family = "Windows".to_string();
            confidence = 0.4;
        }
    }

    if has_port(22) && !has_port(135) && !has_port(3389) {
        evidence.push("SSH open without RDP/SMB (likely Linux/Unix)".to_string());
        if os_family == "Linux" || os_family == "Unix (Solaris/AIX)" {
            confidence += 0.15;
        } else if os_family == "Unknown" {
            os_family = "Linux".to_string();
            confidence = 0.35;
        }
    }

    if has_port(3389) {
        evidence.push("RDP port open (Windows)".to_string());
        if os_family == "Windows" {
            confidence += 0.2;
        } else if os_family == "Unknown" {
            os_family = "Windows".to_string();
            confidence = 0.5;
        }
    }

    if has_port(161) || has_port(623) {
        evidence.push("SNMP/IPMI ports (network/server device)".to_string());
        if os_family == "Network Device" {
            confidence += 0.2;
        }
    }

    if has_port(515) || has_port(631) || has_port(9100) {
        evidence.push("Printer ports open (515/631/9100)".to_string());
        // This is a printer, not an OS guess
    }

    if evidence.is_empty() {
        return None;
    }

    confidence = confidence.min(0.95);

    Some(OsGuess {
        os_family,
        os_version: None,
        confidence,
        evidence,
    })
}

/// Classify device type based on ports, services, vendor, and OS
fn classify_device(
    open_ports: &[PortInfo],
    services: &[ServiceInfo],
    vendor: Option<&str>,
    os_guess: Option<&OsGuess>,
) -> DeviceType {
    let has_port = |p: u16| open_ports.iter().any(|op| op.port == p);

    // Check for printer ports
    if has_port(515) || has_port(631) || has_port(9100) {
        return DeviceType::Printer;
    }

    // Check vendor for camera
    if let Some(v) = vendor {
        let v_lower = v.to_lowercase();
        if v_lower.contains("hikvision")
            || v_lower.contains("dahua")
            || v_lower.contains("axis")
            || v_lower.contains("amcrest")
            || v_lower.contains("ip camera")
            || v_lower.contains("sercomm")
        {
            return DeviceType::Camera;
        }

        // Network device vendors
        if v_lower.contains("cisco")
            || v_lower.contains("juniper")
            || v_lower.contains("arista")
            || v_lower.contains("fortinet")
            || v_lower.contains("palo alto")
            || v_lower.contains("ubiquiti")
        {
            return DeviceType::NetworkDevice;
        }

        // IoT / Smart home
        if v_lower.contains("echo")
            || v_lower.contains("nest")
            || v_lower.contains("sonos")
            || v_lower.contains("raspberry pi")
            || v_lower.contains("philips lighting")
        {
            return DeviceType::IoT;
        }

        // NAS / Storage
        if v_lower.contains("synology") || v_lower.contains("qnap") {
            return DeviceType::StorageDevice;
        }

        // Mobile vendors
        if v_lower.contains("samsung")
            || v_lower.contains("huawei")
            || v_lower.contains("xiaomi")
            || v_lower.contains("oneplus")
        {
            // Could be phone, but also TV/appliance - check ports
            if !has_port(80) && !has_port(443) && !has_port(22) && open_ports.is_empty() {
                return DeviceType::Mobile;
            }
        }
    }

    // VoIP indicators
    if has_port(5060) || has_port(5061) {
        return DeviceType::VoIP;
    }

    // OS-based classification
    if let Some(os) = os_guess {
        if os.os_family == "Network Device" {
            return DeviceType::NetworkDevice;
        }
    }

    // Server indicators: many open service ports
    let server_ports = [
        22, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 1521, 3306, 5432, 6379, 8080, 8443, 9200,
        27017,
    ];
    let server_port_count = server_ports.iter().filter(|&&p| has_port(p)).count();

    if server_port_count >= 3 {
        return DeviceType::Server;
    }

    // Workstation indicators
    if has_port(3389) || has_port(445) || has_port(135) {
        return DeviceType::Workstation;
    }

    // Network device indicators (SNMP)
    if has_port(161) || has_port(162) {
        return DeviceType::NetworkDevice;
    }

    DeviceType::Unknown
}

// ============================================================================
// Network Discovery Collector
// ============================================================================

/// Network Discovery Collector
///
/// Runs passive and active network discovery using the local agent as a sensor.
/// Discovered devices are emitted as `TelemetryEvent` payloads to the server
/// for aggregation in the global device inventory.
pub struct NetworkDiscoveryCollector {
    config: NetworkDiscoveryConfig,
    oui_db: OuiDatabase,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    known_devices: HashMap<String, DiscoveredDevice>,
}

impl NetworkDiscoveryCollector {
    /// Create a new network discovery collector
    pub fn new(config: &AgentConfig) -> Self {
        let disc_config = config.network_discovery.clone();
        let (tx, rx) = mpsc::channel(500);
        let oui_db = OuiDatabase::new();

        let config_clone = disc_config.clone();
        tokio::spawn(async move {
            Self::discovery_loop(tx, config_clone).await;
        });

        Self {
            config: disc_config,
            oui_db,
            event_rx: rx,
            known_devices: HashMap::new(),
        }
    }

    /// Main discovery loop
    async fn discovery_loop(tx: mpsc::Sender<TelemetryEvent>, config: NetworkDiscoveryConfig) {
        let oui_db = OuiDatabase::new();
        let mut known_devices: HashMap<String, DiscoveredDevice> = HashMap::new();
        let mut passive_interval =
            tokio::time::interval(Duration::from_secs(config.passive_interval_secs));
        let mut active_interval =
            tokio::time::interval(Duration::from_secs(config.active_interval_secs));

        loop {
            tokio::select! {
                _ = passive_interval.tick() => {
                    if config.passive_enabled {
                        debug!("Running passive network discovery");
                        let devices = Self::passive_discovery(&config, &oui_db).await;
                        let new_count = Self::merge_devices(&mut known_devices, &devices, &oui_db);

                        if !devices.is_empty() && config.emit_telemetry {
                            let subnets = Self::detect_local_subnets().await;
                            let subnet_str = subnets.first().cloned().unwrap_or_else(|| "unknown".to_string());

                            let event = Self::build_discovery_event(
                                &devices,
                                &subnet_str,
                                "passive",
                                new_count,
                                known_devices.len(),
                            );

                            if tx.send(event).await.is_err() {
                                warn!("Network discovery event channel closed");
                                return;
                            }
                        }
                    }
                }

                _ = active_interval.tick() => {
                    if config.active_enabled && config.scan_mode == "active" {
                        // Check scan window
                        if !Self::in_scan_window(&config) {
                            debug!("Outside scan window, skipping active scan");
                            continue;
                        }

                        info!("Running active network discovery");
                        let subnets = if config.assigned_ranges.is_empty() {
                            if config.subnets.is_empty() {
                                Self::detect_local_subnets().await
                            } else {
                                config.subnets.clone()
                            }
                        } else {
                            config.assigned_ranges.clone()
                        };

                        for subnet in &subnets {
                            let devices = Self::active_scan(subnet, &config, &oui_db).await;
                            let new_count = Self::merge_devices(&mut known_devices, &devices, &oui_db);

                            if !devices.is_empty() && config.emit_telemetry {
                                let event = Self::build_discovery_event(
                                    &devices,
                                    subnet,
                                    "active",
                                    new_count,
                                    known_devices.len(),
                                );

                                if tx.send(event).await.is_err() {
                                    warn!("Network discovery event channel closed");
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Passive Discovery
    // ========================================================================

    /// Run passive discovery: ARP cache + mDNS + SSDP + NetBIOS
    async fn passive_discovery(
        _config: &NetworkDiscoveryConfig,
        oui_db: &OuiDatabase,
    ) -> Vec<DiscoveredDevice> {
        let mut devices = Vec::new();

        // 1. ARP cache monitoring
        let arp_devices = Self::read_arp_cache(oui_db).await;
        devices.extend(arp_devices);

        // 2. mDNS discovery (port 5353)
        let mdns_devices = Self::discover_mdns(oui_db).await;
        devices.extend(mdns_devices);

        // 3. SSDP discovery (port 1900 multicast)
        let ssdp_devices = Self::discover_ssdp(oui_db).await;
        devices.extend(ssdp_devices);

        // 4. NetBIOS name resolution (port 137)
        let netbios_devices = Self::discover_netbios(oui_db).await;
        devices.extend(netbios_devices);

        debug!("Passive discovery found {} device entries", devices.len());
        devices
    }

    /// Read the ARP cache to discover devices on the local network.
    /// Platform-specific: uses `arp -a` on all platforms, then parses output.
    async fn read_arp_cache(oui_db: &OuiDatabase) -> Vec<DiscoveredDevice> {
        let mut devices = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let output = match tokio::process::Command::new("arp").arg("-a").output().await {
            Ok(o) => o,
            Err(e) => {
                debug!("Failed to run arp -a: {}", e);
                return devices;
            }
        };

        if !output.status.success() {
            return devices;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            // Parse platform-specific ARP output
            if let Some((ip, mac)) = Self::parse_arp_line(line) {
                // Skip incomplete entries and broadcast
                if mac == "ff:ff:ff:ff:ff:ff"
                    || mac == "00:00:00:00:00:00"
                    || mac.contains("incomplete")
                {
                    continue;
                }

                let vendor = oui_db.lookup(&mac);

                devices.push(DiscoveredDevice {
                    mac_address: Some(mac),
                    ip_addresses: vec![ip],
                    hostnames: Vec::new(),
                    os_guess: None,
                    device_type: DeviceType::Unknown,
                    open_ports: Vec::new(),
                    services: Vec::new(),
                    vendor,
                    first_seen: now,
                    last_seen: now,
                    discovery_method: DiscoveryMethod::ArpCache,
                    managed: false,
                    ttl: None,
                    tcp_window_size: None,
                });
            }
        }

        devices
    }

    /// Parse a single line of `arp -a` output. Returns (IP, MAC) if parseable.
    fn parse_arp_line(line: &str) -> Option<(String, String)> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        // Windows format: "  192.168.1.1           00-aa-bb-cc-dd-ee     dynamic"
        // Linux format:   "? (192.168.1.1) at 00:aa:bb:cc:dd:ee [ether] on eth0"
        // macOS format:   "? (192.168.1.1) at 00:aa:bb:cc:dd:ee on en0 ifscope [ethernet]"

        // Try Linux/macOS format first
        if line.contains(" at ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // Extract IP from parentheses
                let ip = parts
                    .iter()
                    .find(|p| p.starts_with('(') && p.ends_with(')'))
                    .map(|p| p.trim_start_matches('(').trim_end_matches(')').to_string());

                // Find MAC address (contains colons)
                let mac_idx = parts.iter().position(|p| *p == "at")?;
                let mac = parts.get(mac_idx + 1)?;

                if let Some(ip) = ip {
                    let mac_normalized = mac.to_lowercase().replace('-', ":");
                    if mac_normalized.len() >= 11 && mac_normalized.contains(':') {
                        return Some((ip, mac_normalized));
                    }
                }
            }
        }

        // Try Windows format
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let ip = parts[0].to_string();
            // Validate IP-like format
            if ip.contains('.') && ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
                let mac = parts[1].to_lowercase().replace('-', ":");
                if mac.len() >= 11 && mac.contains(':') {
                    return Some((ip, mac));
                }
            }
        }

        None
    }

    /// Discover devices via mDNS (Multicast DNS, port 5353)
    async fn discover_mdns(_oui_db: &OuiDatabase) -> Vec<DiscoveredDevice> {
        let mut devices = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Send mDNS query for _services._dns-sd._udp.local
        // Use a UDP socket on port 5353 multicast group 224.0.0.251
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to bind mDNS socket: {}", e);
                return devices;
            }
        };

        let mdns_addr: SocketAddr = "224.0.0.251:5353".parse().unwrap();

        // Minimal mDNS query for PTR _services._dns-sd._udp.local
        let query = build_mdns_query("_services._dns-sd._udp.local");

        if let Err(e) = socket.send_to(&query, mdns_addr).await {
            debug!("Failed to send mDNS query: {}", e);
            return devices;
        }

        // Collect responses for a short window
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            if let Some(hostname) = parse_mdns_response(&buf[..len]) {
                                devices.push(DiscoveredDevice {
                                    mac_address: None,
                                    ip_addresses: vec![src.ip().to_string()],
                                    hostnames: vec![hostname],
                                    os_guess: None,
                                    device_type: DeviceType::Unknown,
                                    open_ports: Vec::new(),
                                    services: Vec::new(),
                                    vendor: None,
                                    first_seen: now,
                                    last_seen: now,
                                    discovery_method: DiscoveryMethod::Mdns,
                                    managed: false,
                                    ttl: None,
                                    tcp_window_size: None,
                                });
                            }
                        }
                        Err(e) => {
                            debug!("mDNS recv error: {}", e);
                            break;
                        }
                    }
                }
                _ = &mut deadline => {
                    break;
                }
            }
        }

        devices
    }

    /// Discover devices via SSDP (Simple Service Discovery Protocol, port 1900)
    async fn discover_ssdp(_oui_db: &OuiDatabase) -> Vec<DiscoveredDevice> {
        let mut devices = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to bind SSDP socket: {}", e);
                return devices;
            }
        };

        // SSDP M-SEARCH request
        let ssdp_request = "M-SEARCH * HTTP/1.1\r\n\
                            HOST: 239.255.255.250:1900\r\n\
                            MAN: \"ssdp:discover\"\r\n\
                            MX: 2\r\n\
                            ST: ssdp:all\r\n\r\n";

        let ssdp_addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();

        if let Err(e) = socket.send_to(ssdp_request.as_bytes(), ssdp_addr).await {
            debug!("Failed to send SSDP M-SEARCH: {}", e);
            return devices;
        }

        let mut buf = [0u8; 4096];
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let response = String::from_utf8_lossy(&buf[..len]);
                            let mut device_name = None;
                            let mut server_header = None;

                            for line in response.lines() {
                                let lower = line.to_lowercase();
                                if lower.starts_with("server:") {
                                    server_header = Some(line[7..].trim().to_string());
                                }
                                if lower.starts_with("usn:") || lower.starts_with("st:") {
                                    device_name = Some(line.split(':').last().unwrap_or("").trim().to_string());
                                }
                            }

                            let mut hostnames = Vec::new();
                            if let Some(ref name) = device_name {
                                if !name.is_empty() {
                                    hostnames.push(name.clone());
                                }
                            }

                            // Try to guess device type from SSDP headers
                            let mut device_type = DeviceType::Unknown;
                            let resp_lower = response.to_lowercase();
                            if resp_lower.contains("mediarenderer") || resp_lower.contains("mediaserver") {
                                device_type = DeviceType::IoT;
                            }
                            if resp_lower.contains("printer") {
                                device_type = DeviceType::Printer;
                            }

                            let mut extra_info = HashMap::new();
                            if let Some(srv) = server_header {
                                extra_info.insert("ssdp_server".to_string(), srv);
                            }

                            devices.push(DiscoveredDevice {
                                mac_address: None,
                                ip_addresses: vec![src.ip().to_string()],
                                hostnames,
                                os_guess: None,
                                device_type,
                                open_ports: Vec::new(),
                                services: Vec::new(),
                                vendor: None,
                                first_seen: now,
                                last_seen: now,
                                discovery_method: DiscoveryMethod::Ssdp,
                                managed: false,
                                ttl: None,
                                tcp_window_size: None,
                            });
                        }
                        Err(e) => {
                            debug!("SSDP recv error: {}", e);
                            break;
                        }
                    }
                }
                _ = &mut deadline => {
                    break;
                }
            }
        }

        devices
    }

    /// Discover devices via NetBIOS name service (port 137 UDP)
    async fn discover_netbios(_oui_db: &OuiDatabase) -> Vec<DiscoveredDevice> {
        let mut devices = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to bind NetBIOS socket: {}", e);
                return devices;
            }
        };

        // NetBIOS Node Status request (NBSTAT) broadcast
        let nbstat_query = build_nbstat_query();
        let broadcast_addr: SocketAddr = "255.255.255.255:137".parse().unwrap();

        // Set broadcast permission
        if let Err(e) = socket.set_broadcast(true) {
            debug!("Failed to set broadcast: {}", e);
            return devices;
        }

        if let Err(e) = socket.send_to(&nbstat_query, broadcast_addr).await {
            debug!("Failed to send NetBIOS query: {}", e);
            return devices;
        }

        let mut buf = [0u8; 4096];
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            if let Some(name) = parse_netbios_response(&buf[..len]) {
                                devices.push(DiscoveredDevice {
                                    mac_address: None,
                                    ip_addresses: vec![src.ip().to_string()],
                                    hostnames: vec![name],
                                    os_guess: None,
                                    device_type: DeviceType::Workstation,
                                    open_ports: Vec::new(),
                                    services: Vec::new(),
                                    vendor: None,
                                    first_seen: now,
                                    last_seen: now,
                                    discovery_method: DiscoveryMethod::NetBIOS,
                                    managed: false,
                                    ttl: None,
                                    tcp_window_size: None,
                                });
                            }
                        }
                        Err(e) => {
                            debug!("NetBIOS recv error: {}", e);
                            break;
                        }
                    }
                }
                _ = &mut deadline => {
                    break;
                }
            }
        }

        devices
    }

    // ========================================================================
    // Active Scanning
    // ========================================================================

    /// Run active scan on a subnet
    async fn active_scan(
        subnet: &str,
        config: &NetworkDiscoveryConfig,
        _oui_db: &OuiDatabase,
    ) -> Vec<DiscoveredDevice> {
        let mut devices = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let hosts = match parse_subnet_to_hosts(subnet) {
            Some(h) => h,
            None => {
                warn!("Invalid subnet format: {}", subnet);
                return devices;
            }
        };

        // Rate limiter: limit packets per second
        let rate_interval =
            Duration::from_micros(1_000_000 / config.max_scan_rate_pps.max(1) as u64);
        let connect_timeout = Duration::from_millis(config.tcp_connect_timeout_ms);
        let banner_timeout = Duration::from_millis(config.banner_timeout_ms);

        // Exclude listed IPs
        let excluded: std::collections::HashSet<String> =
            config.excluded_ips.iter().cloned().collect();

        for host_ip in hosts {
            let ip_str = host_ip.to_string();
            if excluded.contains(&ip_str) {
                continue;
            }

            // Rate limiting delay
            tokio::time::sleep(rate_interval).await;

            let mut open_ports = Vec::new();
            let mut services = Vec::new();

            // TCP connect scan on configured ports
            for &port in &config.scan_ports {
                let addr = SocketAddr::new(IpAddr::V4(host_ip), port);

                match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr))
                    .await
                {
                    Ok(Ok(stream)) => {
                        let service_name = guess_service_from_port(port);
                        open_ports.push(PortInfo {
                            port,
                            protocol: "tcp".to_string(),
                            state: "open".to_string(),
                            service: Some(service_name.clone()),
                        });

                        // Banner grab
                        if let Some(svc_info) =
                            Self::banner_grab(stream, port, &service_name, banner_timeout).await
                        {
                            services.push(svc_info);
                        }
                    }
                    Ok(Err(_)) => {
                        // Connection refused or reset - port is closed
                    }
                    Err(_) => {
                        // Timeout - port is filtered
                    }
                }

                // Rate limiting between ports
                tokio::time::sleep(rate_interval).await;
            }

            // Only create a device entry if we found something
            if !open_ports.is_empty() {
                let os_guess = fingerprint_os(None, None, &open_ports);
                let device_type = classify_device(&open_ports, &services, None, os_guess.as_ref());

                devices.push(DiscoveredDevice {
                    mac_address: None,
                    ip_addresses: vec![ip_str],
                    hostnames: Vec::new(),
                    os_guess,
                    device_type,
                    open_ports,
                    services,
                    vendor: None,
                    first_seen: now,
                    last_seen: now,
                    discovery_method: DiscoveryMethod::TcpScan,
                    managed: false,
                    ttl: None,
                    tcp_window_size: None,
                });
            }
        }

        info!(
            subnet = subnet,
            devices = devices.len(),
            "Active scan complete"
        );
        devices
    }

    /// Attempt banner grab on an open TCP connection
    async fn banner_grab(
        mut stream: tokio::net::TcpStream,
        port: u16,
        _service_name: &str,
        timeout: Duration,
    ) -> Option<ServiceInfo> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut banner_buf = vec![0u8; 2048];

        // For HTTP, send a GET request; for others, read initial banner
        let probe = match port {
            80 | 8080 | 8443 | 8888 | 9090 => {
                Some(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n".as_slice())
            }
            443 => None, // TLS - skip raw banner
            _ => None,   // Read-only banner
        };

        if let Some(probe_data) = probe {
            if let Err(_) = stream.write_all(probe_data).await {
                return None;
            }
        }

        let banner = match tokio::time::timeout(timeout, stream.read(&mut banner_buf)).await {
            Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&banner_buf[..n]).to_string(),
            _ => return None,
        };

        let (name, version) = parse_service_banner(&banner, port);
        let mut extra_info = HashMap::new();

        // Extract SSH version
        if banner.starts_with("SSH-") {
            if let Some(version_str) = banner.split_whitespace().next() {
                extra_info.insert("ssh_version".to_string(), version_str.to_string());
            }
        }

        // Extract HTTP server header
        for line in banner.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("server:") {
                extra_info.insert("http_server".to_string(), line[7..].trim().to_string());
            }
        }

        Some(ServiceInfo {
            port,
            protocol: "tcp".to_string(),
            name,
            version,
            banner: Some(banner.chars().take(512).collect()),
            extra_info,
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Detect local subnets from network interfaces
    async fn detect_local_subnets() -> Vec<String> {
        let mut subnets = Vec::new();

        // Use sysinfo to get network interfaces
        let sys = sysinfo::System::new();

        // Fallback: parse ifconfig/ipconfig output
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = tokio::process::Command::new("ipconfig").output().await {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_ip: Option<String> = None;
                let mut current_mask: Option<String> = None;

                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("IPv4 Address") || trimmed.contains("IPv4-Adresse") {
                        if let Some(ip) = trimmed.split(':').last() {
                            current_ip = Some(ip.trim().to_string());
                        }
                    }
                    if trimmed.contains("Subnet Mask") || trimmed.contains("Subnetzmaske") {
                        if let Some(mask) = trimmed.split(':').last() {
                            current_mask = Some(mask.trim().to_string());
                        }
                    }

                    if let (Some(ref ip), Some(ref mask)) = (&current_ip, &current_mask) {
                        if !ip.starts_with("127.") && !ip.starts_with("169.254.") {
                            if let Some(cidr) = ip_and_mask_to_cidr(ip, mask) {
                                subnets.push(cidr);
                            }
                        }
                        current_ip = None;
                        current_mask = None;
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(output) = tokio::process::Command::new("ip")
                .args(["addr", "show"])
                .output()
                .await
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet ") && !trimmed.contains("127.0.0.1") {
                        // Format: "inet 192.168.1.100/24 brd ..."
                        if let Some(cidr) = trimmed.split_whitespace().nth(1) {
                            if cidr.contains('/')
                                && !cidr.starts_with("127.")
                                && !cidr.starts_with("169.254.")
                            {
                                // Convert to network address
                                if let Some(net) = cidr_to_network(cidr) {
                                    subnets.push(net);
                                }
                            }
                        }
                    }
                }
            } else if let Ok(output) = tokio::process::Command::new("ifconfig").output().await {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet ") && !trimmed.contains("127.0.0.1") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let ip = parts[1];
                            // Find netmask
                            if let Some(mask_idx) = parts.iter().position(|&p| p == "netmask") {
                                if let Some(mask) = parts.get(mask_idx + 1) {
                                    // macOS uses hex masks like 0xffffff00
                                    let mask_str = if mask.starts_with("0x") {
                                        hex_mask_to_dotted(mask)
                                    } else {
                                        Some(mask.to_string())
                                    };

                                    if let Some(m) = mask_str {
                                        if let Some(cidr) = ip_and_mask_to_cidr(ip, &m) {
                                            subnets.push(cidr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if subnets.is_empty() {
            debug!("No subnets detected, using 192.168.1.0/24 as fallback");
            subnets.push("192.168.1.0/24".to_string());
        }

        subnets
    }

    /// Check if current time is within the scan window
    fn in_scan_window(config: &NetworkDiscoveryConfig) -> bool {
        if config.scan_window_start_hour.is_none() || config.scan_window_end_hour.is_none() {
            return true; // No window configured = always scan
        }

        let start = config.scan_window_start_hour.unwrap();
        let end = config.scan_window_end_hour.unwrap();

        let now = chrono::Local::now().hour() as u8;

        if start <= end {
            now >= start && now < end
        } else {
            // Wraps around midnight (e.g., 22:00 - 06:00)
            now >= start || now < end
        }
    }

    /// Merge newly discovered devices into the known device map.
    /// Returns the count of truly new devices.
    fn merge_devices(
        known: &mut HashMap<String, DiscoveredDevice>,
        new_devices: &[DiscoveredDevice],
        oui_db: &OuiDatabase,
    ) -> usize {
        let mut new_count = 0;

        for device in new_devices {
            // Key by MAC address if available, otherwise by primary IP
            let key = device.mac_address.clone().unwrap_or_else(|| {
                device
                    .ip_addresses
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
            });

            if let Some(existing) = known.get_mut(&key) {
                // Merge: update last_seen, add new IPs/hostnames/ports
                existing.last_seen = device.last_seen;

                for ip in &device.ip_addresses {
                    if !existing.ip_addresses.contains(ip) {
                        existing.ip_addresses.push(ip.clone());
                    }
                }

                for hostname in &device.hostnames {
                    if !existing.hostnames.contains(hostname) {
                        existing.hostnames.push(hostname.clone());
                    }
                }

                for port in &device.open_ports {
                    if !existing.open_ports.iter().any(|p| p.port == port.port) {
                        existing.open_ports.push(port.clone());
                    }
                }

                for service in &device.services {
                    if !existing.services.iter().any(|s| s.port == service.port) {
                        existing.services.push(service.clone());
                    }
                }

                // Update OS guess if new one has higher confidence
                if let Some(ref new_os) = device.os_guess {
                    let should_update = existing
                        .os_guess
                        .as_ref()
                        .map(|old| new_os.confidence > old.confidence)
                        .unwrap_or(true);
                    if should_update {
                        existing.os_guess = Some(new_os.clone());
                    }
                }

                // Update device type if it was previously unknown
                if existing.device_type == DeviceType::Unknown
                    && device.device_type != DeviceType::Unknown
                {
                    existing.device_type = device.device_type.clone();
                }

                // Update vendor if not set
                if existing.vendor.is_none() {
                    existing.vendor = device.vendor.clone();
                }
            } else {
                known.insert(key, device.clone());
                new_count += 1;
            }
        }

        new_count
    }

    /// Build a telemetry event for discovered devices
    fn build_discovery_event(
        devices: &[DiscoveredDevice],
        subnet: &str,
        scan_type: &str,
        new_count: usize,
        total_count: usize,
    ) -> TelemetryEvent {
        let discovery_event = NetworkDiscoveryEvent {
            devices: devices.to_vec(),
            subnet: subnet.to_string(),
            scan_type: scan_type.to_string(),
            new_device_count: new_count,
            total_device_count: total_count,
        };

        let severity = if new_count > 0 {
            Severity::Low
        } else {
            Severity::Info
        };

        TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::NetworkDiscovery,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            severity,
            payload: EventPayload::NetworkDiscovery(discovery_event),
            detections: Vec::new(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("subnet".to_string(), subnet.to_string());
                m.insert("scan_type".to_string(), scan_type.to_string());
                m.insert("new_devices".to_string(), new_count.to_string());
                m.insert("total_devices".to_string(), total_count.to_string());
                m
            },
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

// ============================================================================
// Protocol Helpers
// ============================================================================

/// Build a minimal mDNS query packet
fn build_mdns_query(name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Transaction ID
    packet.extend_from_slice(&[0x00, 0x00]);
    // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // QNAME
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Terminator

    // QTYPE: PTR (12)
    packet.extend_from_slice(&[0x00, 0x0C]);
    // QCLASS: IN (1) with unicast-response bit (0x8001)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Parse mDNS response to extract hostnames
fn parse_mdns_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }

    // Check answer count
    let answer_count = u16::from_be_bytes([data[6], data[7]]);
    if answer_count == 0 {
        return None;
    }

    // Skip header and question section to reach answers
    let mut offset = 12;

    // Skip questions
    let question_count = u16::from_be_bytes([data[4], data[5]]);
    for _ in 0..question_count {
        offset = skip_dns_name(data, offset)?;
        offset += 4; // QTYPE + QCLASS
    }

    // Read first answer
    if offset < data.len() {
        let name = read_dns_name(data, offset);
        if let Some(n) = name {
            // Clean up mDNS name (remove .local suffix)
            let clean = n
                .trim_end_matches(".local")
                .trim_end_matches('.')
                .to_string();
            if !clean.is_empty() {
                return Some(clean);
            }
        }
    }

    None
}

/// Read a DNS name from packet data (handles compression pointers)
fn read_dns_name(data: &[u8], mut offset: usize) -> Option<String> {
    let mut name = String::new();
    let mut depth = 0;

    loop {
        if offset >= data.len() || depth > 10 {
            break;
        }

        let len = data[offset] as usize;

        if len == 0 {
            break;
        }

        // Compression pointer
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                break;
            }
            let pointer = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            if let Some(pointed_name) = read_dns_name(data, pointer) {
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&pointed_name);
            }
            break;
        }

        if offset + 1 + len > data.len() {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(
            &data[offset + 1..offset + 1 + len],
        ));
        offset += 1 + len;
        depth += 1;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Skip a DNS name in packet data
fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= data.len() {
            return None;
        }

        let len = data[offset] as usize;

        if len == 0 {
            return Some(offset + 1);
        }

        if len & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }

        offset += 1 + len;
    }
}

/// Build a NetBIOS Node Status (NBSTAT) query
fn build_nbstat_query() -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);

    // Transaction ID
    packet.extend_from_slice(&[0x82, 0x28]);
    // Flags: broadcast
    packet.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answers, Authority, Additional: 0
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // NetBIOS name: * (wildcard) encoded as first-level encoding
    // 32 bytes: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00
    packet.push(0x20); // Length 32
                       // Encode '*' (0x2A) as 'CK' and pad with 'A' (null bytes encoded as 'AA')
    packet.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    packet.push(0x00); // Terminator

    // QTYPE: NBSTAT (0x0021)
    packet.extend_from_slice(&[0x00, 0x21]);
    // QCLASS: IN (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Parse NetBIOS response to extract hostname
fn parse_netbios_response(data: &[u8]) -> Option<String> {
    if data.len() < 57 {
        return None;
    }

    // Check answer count
    let answer_count = u16::from_be_bytes([data[6], data[7]]);
    if answer_count == 0 {
        return None;
    }

    // Skip to name table: header(12) + name(34) + type(2) + class(2) + ttl(4) + rdlength(2) + num_names(1)
    let offset = 12 + 34 + 2 + 2 + 4 + 2;
    if offset >= data.len() {
        return None;
    }

    let num_names = data[offset] as usize;
    let name_offset = offset + 1;

    // Each name entry is 18 bytes: 15 bytes name + 1 byte suffix + 2 bytes flags
    for i in 0..num_names {
        let entry_start = name_offset + (i * 18);
        if entry_start + 18 > data.len() {
            break;
        }

        let suffix = data[entry_start + 15];

        // Suffix 0x00 is workstation service (hostname)
        // Suffix 0x20 is file server service
        if suffix == 0x00 {
            let name_bytes = &data[entry_start..entry_start + 15];
            let name = String::from_utf8_lossy(name_bytes).trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }

    None
}

// ============================================================================
// Network Utility Functions
// ============================================================================

/// Guess service name from well-known port numbers
fn guess_service_from_port(port: u16) -> String {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        515 => "printer",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5060 => "sip",
        5061 => "sip-tls",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9090 => "webmin",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
    .to_string()
}

/// Parse service banner to extract name and version
fn parse_service_banner(banner: &str, port: u16) -> (String, Option<String>) {
    let banner_lower = banner.to_lowercase();

    // SSH banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    if banner.starts_with("SSH-") {
        let parts: Vec<&str> = banner.split('-').collect();
        if parts.len() >= 3 {
            let version_str = parts[2..]
                .join("-")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            return ("ssh".to_string(), Some(version_str));
        }
        return ("ssh".to_string(), None);
    }

    // HTTP server header
    if banner_lower.contains("http/") || banner_lower.contains("server:") {
        for line in banner.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("server:") {
                let server = line[7..].trim().to_string();
                return ("http".to_string(), Some(server));
            }
        }
        return ("http".to_string(), None);
    }

    // FTP banner: "220 ProFTPD 1.3.5 Server ready."
    if banner.starts_with("220") && (banner_lower.contains("ftp") || port == 21) {
        let version = banner[3..].trim().to_string();
        return ("ftp".to_string(), Some(version));
    }

    // SMTP banner: "220 mail.example.com ESMTP Postfix"
    if banner.starts_with("220")
        && (banner_lower.contains("smtp") || banner_lower.contains("esmtp") || port == 25)
    {
        let version = banner[3..].trim().to_string();
        return ("smtp".to_string(), Some(version));
    }

    // MySQL banner starts with protocol version byte
    if port == 3306 && banner.len() > 4 {
        if let Some(version_end) = banner.find('\0') {
            let version = banner[1..version_end].to_string();
            return ("mysql".to_string(), Some(version));
        }
    }

    // Redis
    if banner_lower.contains("redis") {
        return ("redis".to_string(), None);
    }

    // SMB
    if port == 445 || port == 139 {
        return ("smb".to_string(), None);
    }

    (guess_service_from_port(port), None)
}

/// Parse CIDR subnet into list of host IPs (e.g., "192.168.1.0/24" -> [192.168.1.1..254])
fn parse_subnet_to_hosts(cidr: &str) -> Option<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let base_ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;

    if prefix_len > 30 || prefix_len < 16 {
        // Don't scan subnets smaller than /30 or larger than /16
        return None;
    }

    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let network = u32::from(base_ip) & mask;
    let broadcast = network | !mask;

    let mut hosts = Vec::new();
    // Skip network address and broadcast address
    for addr in (network + 1)..broadcast {
        hosts.push(Ipv4Addr::from(addr));
    }

    // Limit to prevent runaway scans
    if hosts.len() > 65534 {
        hosts.truncate(65534);
    }

    Some(hosts)
}

/// Convert IP + subnet mask to CIDR notation network address
fn ip_and_mask_to_cidr(ip: &str, mask: &str) -> Option<String> {
    let ip_addr: Ipv4Addr = ip.parse().ok()?;
    let mask_addr: Ipv4Addr = mask.parse().ok()?;

    let ip_u32 = u32::from(ip_addr);
    let mask_u32 = u32::from(mask_addr);
    let network = ip_u32 & mask_u32;

    // Count prefix length from mask
    let prefix_len = mask_u32.count_ones();

    Some(format!("{}/{}", Ipv4Addr::from(network), prefix_len))
}

/// Convert a CIDR address to its network address (e.g., "192.168.1.100/24" -> "192.168.1.0/24")
fn cidr_to_network(cidr: &str) -> Option<String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u32 = parts[1].parse().ok()?;

    if prefix > 32 {
        return None;
    }

    let mask = if prefix == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let network = u32::from(ip) & mask;

    Some(format!("{}/{}", Ipv4Addr::from(network), prefix))
}

/// Convert hex subnet mask (e.g., "0xffffff00") to dotted notation ("255.255.255.0")
fn hex_mask_to_dotted(hex: &str) -> Option<String> {
    let stripped = hex.trim_start_matches("0x").trim_start_matches("0X");
    let mask = u32::from_str_radix(stripped, 16).ok()?;
    Some(Ipv4Addr::from(mask).to_string())
}

use chrono::Timelike;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_lookup() {
        let db = OuiDatabase::new();
        assert_eq!(db.lookup("00:50:56:AA:BB:CC"), Some("VMware".to_string()));
        assert_eq!(db.lookup("00-50-56-AA-BB-CC"), Some("VMware".to_string()));
        assert_eq!(
            db.lookup("B8:27:EB:11:22:33"),
            Some("Raspberry Pi".to_string())
        );
        assert_eq!(db.lookup("00:00:00:11:22:33"), None);
    }

    #[test]
    fn test_parse_arp_line_linux() {
        let line = "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0";
        let result = NetworkDiscoveryCollector::parse_arp_line(line);
        assert!(result.is_some());
        let (ip, mac) = result.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(mac, "00:11:22:33:44:55");
    }

    #[test]
    fn test_parse_arp_line_windows() {
        let line = "  192.168.1.1           00-11-22-33-44-55     dynamic";
        let result = NetworkDiscoveryCollector::parse_arp_line(line);
        assert!(result.is_some());
        let (ip, mac) = result.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(mac, "00:11:22:33:44:55");
    }

    #[test]
    fn test_parse_subnet_to_hosts() {
        let hosts = parse_subnet_to_hosts("192.168.1.0/30").unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[1], Ipv4Addr::new(192, 168, 1, 2));

        let hosts = parse_subnet_to_hosts("10.0.0.0/24").unwrap();
        assert_eq!(hosts.len(), 254);
    }

    #[test]
    fn test_ip_and_mask_to_cidr() {
        assert_eq!(
            ip_and_mask_to_cidr("192.168.1.100", "255.255.255.0"),
            Some("192.168.1.0/24".to_string())
        );
        assert_eq!(
            ip_and_mask_to_cidr("10.0.1.50", "255.255.0.0"),
            Some("10.0.0.0/16".to_string())
        );
    }

    #[test]
    fn test_guess_service_from_port() {
        assert_eq!(guess_service_from_port(22), "ssh");
        assert_eq!(guess_service_from_port(80), "http");
        assert_eq!(guess_service_from_port(3389), "rdp");
        assert_eq!(guess_service_from_port(0), "unknown");
    }

    #[test]
    fn test_fingerprint_os() {
        let ports = vec![
            PortInfo {
                port: 3389,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("rdp".to_string()),
            },
            PortInfo {
                port: 445,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("smb".to_string()),
            },
        ];
        let os = fingerprint_os(Some(128), None, &ports);
        assert!(os.is_some());
        let os = os.unwrap();
        assert_eq!(os.os_family, "Windows");
        assert!(os.confidence > 0.5);
    }

    #[test]
    fn test_classify_device_printer() {
        let ports = vec![PortInfo {
            port: 9100,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some("jetdirect".to_string()),
        }];
        assert_eq!(
            classify_device(&ports, &[], None, None),
            DeviceType::Printer
        );
    }

    #[test]
    fn test_classify_device_camera() {
        let ports = vec![];
        assert_eq!(
            classify_device(&ports, &[], Some("Hangzhou Hikvision"), None),
            DeviceType::Camera
        );
    }

    #[test]
    fn test_hex_mask_to_dotted() {
        assert_eq!(
            hex_mask_to_dotted("0xffffff00"),
            Some("255.255.255.0".to_string())
        );
        assert_eq!(
            hex_mask_to_dotted("0xffff0000"),
            Some("255.255.0.0".to_string())
        );
    }
}
