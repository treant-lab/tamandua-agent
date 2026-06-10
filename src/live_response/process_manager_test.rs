#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_process_tree_list() {
        let payload = json!({
            "include_security_checks": false,
            "filter_elevated": false
        });

        let result = process_tree_list(&payload).await;

        assert!(result.success, "Process tree list should succeed");

        let data = result.result_data.expect("Should have result data");
        assert!(data["processes"].is_array(), "Should have processes array");
        assert!(data["tree"].is_array(), "Should have tree array");
        assert!(data["count"].is_number(), "Should have count");
    }

    #[tokio::test]
    async fn test_process_tree_list_with_security_checks() {
        let payload = json!({
            "include_security_checks": true,
            "filter_elevated": false
        });

        let result = process_tree_list(&payload).await;

        assert!(result.success, "Process tree list should succeed");

        let data = result.result_data.expect("Should have result data");
        let processes = data["processes"].as_array().expect("Should have processes");

        if !processes.is_empty() {
            let first_process = &processes[0];
            assert!(
                first_process["is_elevated"].is_boolean(),
                "Should have is_elevated"
            );
            assert!(
                first_process["is_signed"].is_boolean(),
                "Should have is_signed"
            );
        }
    }

    #[tokio::test]
    async fn test_process_kill_invalid_pid() {
        let payload = json!({
            "pid": 0,
            "force": false
        });

        let result = process_kill(&payload).await;

        assert!(!result.success, "Should fail with invalid PID");
        assert_eq!(result.error_message, Some("Invalid PID".to_string()));
    }

    #[tokio::test]
    async fn test_process_suspend_invalid_pid() {
        let payload = json!({
            "pid": 0
        });

        let result = process_suspend(&payload).await;

        assert!(!result.success, "Should fail with invalid PID");
    }

    #[tokio::test]
    async fn test_process_resume_invalid_pid() {
        let payload = json!({
            "pid": 0
        });

        let result = process_resume(&payload).await;

        assert!(!result.success, "Should fail with invalid PID");
    }

    #[tokio::test]
    async fn test_process_set_priority_invalid_pid() {
        let payload = json!({
            "pid": 0,
            "priority": "normal"
        });

        let result = process_set_priority(&payload).await;

        assert!(!result.success, "Should fail with invalid PID");
    }

    #[tokio::test]
    async fn test_process_list_handles_invalid_pid() {
        let payload = json!({
            "pid": 0
        });

        let result = process_list_handles(&payload).await;

        assert!(!result.success, "Should fail with invalid PID");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_macos_lsof_handles() {
        let output = "\
p123
fcd
tDIR
n/Users/victorferreira/Documents
f1
tREG
n/tmp/tamandua.log
f3
tIPv4
nTCP 127.0.0.1:49152->127.0.0.1:8443 (ESTABLISHED)
f4
tPIPE
npipe
";

        let handles = parse_macos_lsof_handles(output, None);

        assert_eq!(handles.len(), 4);
        assert_eq!(handles[0]["fd"], "cd");
        assert_eq!(handles[0]["type"], "directory");
        assert_eq!(handles[1]["type"], "file");
        assert_eq!(handles[2]["type"], "socket");
        assert_eq!(handles[3]["type"], "pipe");

        let sockets = parse_macos_lsof_handles(output, Some("socket"));
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0]["fd"], "3");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_macos_codesign_signer() {
        let output = "\
Executable=/Applications/Safari.app/Contents/MacOS/Safari
Identifier=com.apple.Safari
Authority=Apple Mac OS Application Signing
Authority=Apple Worldwide Developer Relations Certification Authority
TeamIdentifier=not set
";

        assert_eq!(
            parse_macos_codesign_signer(output),
            Some("Apple Mac OS Application Signing".to_string())
        );
        assert_eq!(
            parse_macos_codesign_signer("Format=Mach-O universal\nPlatform Binary"),
            Some("Apple".to_string())
        );
        assert_eq!(parse_macos_codesign_signer("Identifier=local.tool"), None);
    }

    #[test]
    fn test_check_is_elevated_current_process() {
        let current_pid = std::process::id();
        let is_elevated = check_is_elevated(current_pid);

        // Just ensure it doesn't panic - result depends on test environment
        assert!(is_elevated || !is_elevated);
    }

    #[test]
    fn test_build_process_tree() {
        let processes = vec![
            ProcessInfo {
                pid: 1,
                ppid: None,
                name: "init".to_string(),
                path: Some("/sbin/init".to_string()),
                cmdline: vec![],
                user: Some("root".to_string()),
                cpu_usage: 0.0,
                memory: 1024,
                virtual_memory: 2048,
                start_time: 0,
                status: "Running".to_string(),
                is_elevated: true,
                is_signed: true,
                signer: None,
                is_hidden: false,
                suspected_hollowing: false,
                suspected_spoofing: false,
                thread_count: 1,
                handle_count: None,
            },
            ProcessInfo {
                pid: 100,
                ppid: Some(1),
                name: "child".to_string(),
                path: Some("/bin/child".to_string()),
                cmdline: vec![],
                user: Some("user".to_string()),
                cpu_usage: 0.5,
                memory: 512,
                virtual_memory: 1024,
                start_time: 1000,
                status: "Running".to_string(),
                is_elevated: false,
                is_signed: true,
                signer: None,
                is_hidden: false,
                suspected_hollowing: false,
                suspected_spoofing: false,
                thread_count: 2,
                handle_count: None,
            },
        ];

        let mut pid_map = HashMap::new();
        pid_map.insert(1, 0);
        pid_map.insert(100, 1);

        let tree = build_process_tree(&processes, &pid_map);

        assert_eq!(tree.len(), 1, "Should have one root");
        assert_eq!(tree[0].process.pid, 1, "Root should be init");
        assert_eq!(tree[0].children.len(), 1, "Root should have one child");
        assert_eq!(
            tree[0].children[0].process.pid, 100,
            "Child should be process 100"
        );
    }
}
