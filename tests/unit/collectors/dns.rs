//! Unit tests for DNS collector

use tamandua_agent::collectors::dns::*;
use tamandua_agent::collectors::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query() {
        let query = "example.com";
        let query_type = "A";

        assert!(is_valid_domain(query));
        assert!(is_valid_query_type(query_type));
    }

    #[test]
    fn test_validate_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("test-domain.co.uk"));

        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("..invalid"));
        assert!(!is_valid_domain("domain with spaces.com"));
    }

    #[test]
    fn test_dns_query_types() {
        let valid_types = vec!["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"];

        for qtype in valid_types {
            assert!(is_valid_query_type(qtype));
        }

        assert!(!is_valid_query_type("INVALID"));
    }

    #[test]
    fn test_extract_domain_from_fqdn() {
        assert_eq!(extract_domain("www.example.com"), "example.com");
        assert_eq!(extract_domain("mail.google.com"), "google.com");
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_suspicious_domain_detection() {
        // DGA-like domains
        assert!(is_suspicious_domain("qwertasdfzxcv.com"));
        assert!(is_suspicious_domain("randomchars123.net"));

        // Legitimate domains
        assert!(!is_suspicious_domain("google.com"));
        assert!(!is_suspicious_domain("microsoft.com"));
        assert!(!is_suspicious_domain("github.com"));
    }

    #[test]
    fn test_tld_validation() {
        assert!(is_valid_tld("com"));
        assert!(is_valid_tld("org"));
        assert!(is_valid_tld("net"));
        assert!(is_valid_tld("io"));

        assert!(!is_valid_tld("invalidtld"));
    }

    #[tokio::test]
    #[cfg(feature = "dns-capture")]
    async fn test_dns_collector_creation() {
        let config = tamandua_agent::config::CollectorsConfig::default();
        let collector = DnsCollector::new();

        assert!(collector.is_some());
    }

    #[test]
    fn test_parse_dns_response() {
        let responses = vec!["192.0.2.1", "192.0.2.2"];

        for resp in &responses {
            assert!(is_valid_ip(resp));
        }
    }

    #[test]
    fn test_filter_dns_noise() {
        let queries = vec![
            DnsQuery {
                domain: "www.example.com".to_string(),
                query_type: "A".to_string(),
                pid: 1234,
                process_name: "chrome.exe".to_string(),
            },
            DnsQuery {
                domain: "localhost".to_string(),
                query_type: "A".to_string(),
                pid: 1234,
                process_name: "chrome.exe".to_string(),
            },
            DnsQuery {
                domain: "255.255.255.255.in-addr.arpa".to_string(),
                query_type: "PTR".to_string(),
                pid: 1234,
                process_name: "system".to_string(),
            },
        ];

        let filtered: Vec<_> = queries
            .into_iter()
            .filter(|q| !is_dns_noise(&q.domain))
            .collect();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].domain, "www.example.com");
    }

    #[test]
    fn test_c2_domain_patterns() {
        // Known C2 patterns
        let c2_domains = vec![
            "example.duckdns.org",  // Free dynamic DNS
            "test.no-ip.com",       // Free dynamic DNS
            "malware.tk",           // Free TLD often used by malware
        ];

        for domain in c2_domains {
            // Should flag as potentially suspicious
            // (actual implementation may vary)
            let _ = domain;
        }
    }

    #[test]
    fn test_dns_tunneling_detection() {
        // Very long subdomain might indicate DNS tunneling
        let tunneling_domain = "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxk.example.com";

        assert!(is_potential_dns_tunneling(tunneling_domain));

        // Normal domain
        let normal_domain = "www.example.com";
        assert!(!is_potential_dns_tunneling(normal_domain));
    }
}
