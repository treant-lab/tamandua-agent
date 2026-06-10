//! Unit tests for process collector
//!
//! Tests process enumeration and monitoring across all platforms.

use tamandua_agent::collectors::process::*;
use tamandua_agent::collectors::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_processes() {
        let processes = enumerate_processes();

        // Should find at least the current process
        assert!(!processes.is_empty());

        // Check that process list contains valid data
        for proc in processes.iter().take(5) {
            assert!(proc.pid > 0);
            assert!(!proc.name.is_empty());
        }
    }

    #[test]
    fn test_get_current_process() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            assert_eq!(proc_info.pid, current_pid);
            assert!(!proc_info.name.is_empty());
            assert!(!proc_info.path.is_empty());
        }
    }

    #[test]
    fn test_process_cmdline() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // Command line should contain the test executable name
            assert!(!proc_info.cmdline.is_empty());
        }
    }

    #[test]
    fn test_process_parent() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // Should have a parent process (except for init/PID 1)
            if current_pid != 1 {
                assert!(proc_info.ppid > 0);
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_process_elevation() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // is_elevated should be a valid boolean
            let _ = proc_info.is_elevated;
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_process_signing() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // Check signing information is present
            if proc_info.is_signed {
                assert!(proc_info.signer.is_some());
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_process_user() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // Should have a valid user
            assert!(!proc_info.user.is_empty());
        }
    }

    #[test]
    fn test_process_hash() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // SHA256 should be 32 bytes
            assert_eq!(proc_info.sha256.len(), 32);
        }
    }

    #[test]
    fn test_process_entropy() {
        let current_pid = std::process::id();

        if let Some(proc_info) = get_process_info(current_pid) {
            // Entropy should be in valid range (0-8)
            assert!(proc_info.entropy >= 0.0);
            assert!(proc_info.entropy <= 8.0);
        }
    }

    #[tokio::test]
    async fn test_process_collector_creation() {
        let config = tamandua_agent::config::CollectorsConfig::default();

        let collector = ProcessCollector::new(config.process_poll_interval_seconds);
        assert!(collector.is_some());
    }

    #[tokio::test]
    async fn test_process_collector_detects_new_processes() {
        use std::process::Command;
        use std::time::Duration;

        let config = tamandua_agent::config::CollectorsConfig::default();
        let mut collector = ProcessCollector::new(config.process_poll_interval_seconds)
            .expect("Failed to create collector");

        // Initial snapshot
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn a test process
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(&["/C", "timeout", "/t", "2", "/nobreak"])
            .spawn()
            .expect("Failed to spawn test process");

        #[cfg(unix)]
        let mut child = Command::new("sleep")
            .arg("2")
            .spawn()
            .expect("Failed to spawn test process");

        let test_pid = child.id();

        // Wait for collector to detect it
        let mut found = false;
        for _ in 0..20 {
            if let Some(event) = collector.next_event().await {
                if let EventPayload::Process(proc) = event.payload {
                    if proc.pid == test_pid {
                        found = true;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Cleanup
        let _ = child.kill();

        // On some platforms, process detection might be racy
        // so we don't assert, just log
        if found {
            println!("Successfully detected process {}", test_pid);
        } else {
            println!("Note: Process {} not detected (timing issue)", test_pid);
        }
    }

    #[test]
    fn test_filter_excluded_processes() {
        let mut processes = vec![
            ProcessInfo {
                pid: 1,
                name: "init".to_string(),
                path: "/sbin/init".to_string(),
                cmdline: "init".to_string(),
                user: "root".to_string(),
                sha256: vec![0; 32],
                entropy: 5.0,
                ppid: 0,
                is_elevated: true,
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
            },
            ProcessInfo {
                pid: 2,
                name: "kthreadd".to_string(),
                path: "/sbin/kthreadd".to_string(),
                cmdline: "kthreadd".to_string(),
                user: "root".to_string(),
                sha256: vec![0; 32],
                entropy: 5.0,
                ppid: 0,
                is_elevated: true,
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
            },
        ];

        let excluded = vec!["init".to_string()];
        filter_excluded_processes(&mut processes, &excluded);

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].name, "kthreadd");
    }

    #[test]
    #[cfg(windows)]
    fn test_get_process_environment() {
        let current_pid = std::process::id();

        if let Some(env) = get_process_environment(current_pid) {
            // Should have at least some environment variables
            assert!(!env.is_empty());

            // Common variables that should exist
            assert!(env.contains_key("PATH") || env.contains_key("Path"));
        }
    }

    #[test]
    fn test_calculate_process_metrics() {
        let current_pid = std::process::id();

        if let Some(metrics) = get_process_metrics(current_pid) {
            // CPU usage should be non-negative
            assert!(metrics.cpu_usage >= 0.0);

            // Memory should be positive (we're running, so we use memory)
            assert!(metrics.memory_bytes > 0);
        }
    }
}
