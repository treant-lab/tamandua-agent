//! Unit tests for network collector

use tamandua_agent::collectors::network::*;
use tamandua_agent::collectors::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_connections() {
        let connections = enumerate_network_connections();

        // Should find at least some connections (including loopback)
        assert!(!connections.is_empty());

        for conn in connections.iter().take(5) {
            // Validate connection data
            assert!(conn.pid >= 0);
            assert!(!conn.local_ip.is_empty());
            assert!(conn.local_port > 0 || conn.protocol == "icmp");
            assert!(["tcp", "udp", "icmp"].contains(&conn.protocol.as_str()));
        }
    }

    #[test]
    fn test_parse_ip_address() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("127.0.0.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("fe80::1"));
        assert!(!is_valid_ip("not.an.ip"));
        assert!(!is_valid_ip("999.999.999.999"));
    }

    #[test]
    fn test_protocol_detection() {
        assert!(is_tcp_protocol("tcp"));
        assert!(is_tcp_protocol("tcp4"));
        assert!(is_tcp_protocol("tcp6"));
        assert!(!is_tcp_protocol("udp"));

        assert!(is_udp_protocol("udp"));
        assert!(is_udp_protocol("udp4"));
        assert!(is_udp_protocol("udp6"));
        assert!(!is_udp_protocol("tcp"));
    }

    #[test]
    fn test_connection_state() {
        let states = vec!["ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT"];

        for state in states {
            assert!(is_valid_connection_state(state));
        }

        assert!(!is_valid_connection_state("INVALID"));
    }

    #[test]
    fn test_filter_loopback() {
        let connections = vec![
            NetworkConnection {
                pid: 1234,
                process_name: "test".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 8080,
                remote_ip: "127.0.0.1".to_string(),
                remote_port: 9090,
                protocol: "tcp".to_string(),
                state: "ESTABLISHED".to_string(),
            },
            NetworkConnection {
                pid: 1234,
                process_name: "test".to_string(),
                local_ip: "192.168.1.100".to_string(),
                local_port: 8080,
                remote_ip: "8.8.8.8".to_string(),
                remote_port: 443,
                protocol: "tcp".to_string(),
                state: "ESTABLISHED".to_string(),
            },
        ];

        let filtered: Vec<_> = connections
            .into_iter()
            .filter(|c| !is_loopback(&c.remote_ip))
            .collect();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].remote_ip, "8.8.8.8");
    }

    #[tokio::test]
    async fn test_network_collector_creation() {
        let config = tamandua_agent::config::CollectorsConfig::default();
        let collector = NetworkCollector::new(config.network_poll_interval_seconds);
        assert!(collector.is_some());
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn test_connection_direction() {
        // Local server (listening)
        let listen_conn = NetworkConnection {
            pid: 1234,
            process_name: "server".to_string(),
            local_ip: "0.0.0.0".to_string(),
            local_port: 80,
            remote_ip: "0.0.0.0".to_string(),
            remote_port: 0,
            protocol: "tcp".to_string(),
            state: "LISTEN".to_string(),
        };

        assert_eq!(get_connection_direction(&listen_conn), "inbound");

        // Outbound connection
        let outbound_conn = NetworkConnection {
            pid: 1234,
            process_name: "client".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_port: 50000,
            remote_ip: "8.8.8.8".to_string(),
            remote_port: 443,
            protocol: "tcp".to_string(),
            state: "ESTABLISHED".to_string(),
        };

        assert_eq!(get_connection_direction(&outbound_conn), "outbound");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_netstat_parsing() {
        let netstat_output = r#"
  TCP    192.168.1.100:50000    8.8.8.8:443            ESTABLISHED     1234
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  UDP    0.0.0.0:53             *:*                                    1000
        "#;

        let connections = parse_netstat_output(netstat_output);
        assert!(!connections.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_unix_netstat_parsing() {
        let netstat_output = r#"
tcp4       0      0  192.168.1.100.50000    8.8.8.8.443            ESTABLISHED
tcp4       0      0  *.80                   *.*                    LISTEN
udp4       0      0  *.53                   *.*
        "#;

        let connections = parse_netstat_output(netstat_output);
        assert!(!connections.is_empty());
    }

    #[test]
    fn test_connection_bytes_tracking() {
        let mut tracker = ConnectionBytesTracker::new();

        let conn_id = "192.168.1.100:50000->8.8.8.8:443";
        tracker.update(conn_id, 1000, 2000);

        if let Some(stats) = tracker.get(conn_id) {
            assert_eq!(stats.bytes_sent, 1000);
            assert_eq!(stats.bytes_received, 2000);
        }

        // Update again
        tracker.update(conn_id, 1500, 2500);

        if let Some(stats) = tracker.get(conn_id) {
            assert_eq!(stats.bytes_sent, 1500);
            assert_eq!(stats.bytes_received, 2500);
        }
    }
}
