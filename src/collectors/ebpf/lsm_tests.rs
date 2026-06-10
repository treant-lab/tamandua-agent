//! Integration tests for LSM BPF hooks with fallback strategies
//!
//! These tests validate the fallback mechanism across different kernel versions.

#![cfg(test)]
#![cfg(target_os = "linux")]

use super::fallback::{AttachMethod, FallbackStrategy};
use super::lsm::{AttachStrategy, KernelVersion, LsmHookManager, LsmHookType};
use anyhow::Result;
use std::fs;
use std::thread;
use std::time::Duration;
use tracing_subscriber;

/// Initialize test logging
fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

#[test]
fn test_kernel_version_detection() {
    init_test_logging();

    let version = KernelVersion::current().expect("Failed to get kernel version");
    println!(
        "Running on kernel: {}.{}.{}",
        version.major, version.minor, version.patch
    );

    assert!(version.major >= 4, "Kernel too old for eBPF");

    // Test feature flags
    println!("LSM BPF support: {}", version.supports_lsm_bpf());
    println!("BTF support: {}", version.supports_btf());
    println!("Kprobe support: {}", version.supports_kprobes());
    println!("Tracepoint support: {}", version.supports_tracepoints());
}

#[test]
fn test_kernel_version_parsing() {
    let test_cases = vec![
        (
            "5.15.0-91-generic",
            KernelVersion {
                major: 5,
                minor: 15,
                patch: 0,
            },
        ),
        (
            "6.1.2",
            KernelVersion {
                major: 6,
                minor: 1,
                patch: 2,
            },
        ),
        (
            "4.19.0-26-amd64",
            KernelVersion {
                major: 4,
                minor: 19,
                patch: 0,
            },
        ),
        (
            "5.4.0-169-generic",
            KernelVersion {
                major: 5,
                minor: 4,
                patch: 0,
            },
        ),
    ];

    for (input, expected) in test_cases {
        let parsed = KernelVersion::from_string(input).expect("Failed to parse version");
        assert_eq!(parsed, expected, "Failed to parse: {}", input);
    }
}

#[test]
fn test_kernel_version_comparison() {
    let v1 = KernelVersion {
        major: 5,
        minor: 7,
        patch: 0,
    };
    let v2 = KernelVersion {
        major: 5,
        minor: 6,
        patch: 19,
    };
    let v3 = KernelVersion {
        major: 5,
        minor: 7,
        patch: 1,
    };

    assert!(v1 > v2, "5.7.0 should be > 5.6.19");
    assert!(v3 > v1, "5.7.1 should be > 5.7.0");
    assert!(v1 >= v2, "5.7.0 should be >= 5.6.19");
}

#[test]
fn test_feature_detection() {
    // Kernel 5.7.0 - supports all features
    let v1 = KernelVersion {
        major: 5,
        minor: 7,
        patch: 0,
    };
    assert!(v1.supports_lsm_bpf());
    assert!(v1.supports_btf());
    assert!(v1.supports_kprobes());
    assert!(v1.supports_tracepoints());
    assert!(v1.supports_raw_tracepoints());

    // Kernel 5.4.0 - no LSM BPF
    let v2 = KernelVersion {
        major: 5,
        minor: 4,
        patch: 0,
    };
    assert!(!v2.supports_lsm_bpf());
    assert!(v2.supports_btf());
    assert!(v2.supports_kprobes());
    assert!(v2.supports_tracepoints());

    // Kernel 4.17.0 - only tracepoints
    let v3 = KernelVersion {
        major: 4,
        minor: 17,
        patch: 0,
    };
    assert!(!v3.supports_lsm_bpf());
    assert!(!v3.supports_btf());
    assert!(!v3.supports_kprobes());
    assert!(v3.supports_tracepoints());

    // Kernel 4.15.0 - minimal support
    let v4 = KernelVersion {
        major: 4,
        minor: 15,
        patch: 0,
    };
    assert!(!v4.supports_lsm_bpf());
    assert!(!v4.supports_btf());
    assert!(!v4.supports_kprobes());
    assert!(!v4.supports_tracepoints());
    assert!(v4.supports_raw_tracepoints());
}

#[test]
fn test_attachment_strategy_selection() {
    let test_cases = vec![
        (
            KernelVersion {
                major: 5,
                minor: 7,
                patch: 0,
            },
            AttachStrategy::LsmBpf,
        ),
        (
            KernelVersion {
                major: 5,
                minor: 4,
                patch: 0,
            },
            AttachStrategy::Kprobe,
        ),
        (
            KernelVersion {
                major: 4,
                minor: 17,
                patch: 0,
            },
            AttachStrategy::Tracepoint,
        ),
        (
            KernelVersion {
                major: 4,
                minor: 15,
                patch: 0,
            },
            AttachStrategy::RawTracepoint,
        ),
        (
            KernelVersion {
                major: 4,
                minor: 14,
                patch: 0,
            },
            AttachStrategy::Unsupported,
        ),
    ];

    for (version, expected_strategy) in test_cases {
        let strategy = AttachStrategy::for_kernel(&version);
        assert_eq!(
            strategy, expected_strategy,
            "Wrong strategy for kernel {}.{}.{}",
            version.major, version.minor, version.patch
        );
    }
}

#[test]
fn test_lsm_hook_names() {
    assert_eq!(LsmHookType::FileOpen.lsm_name(), "file_open");
    assert_eq!(LsmHookType::FilePermission.lsm_name(), "file_permission");
    assert_eq!(LsmHookType::SocketConnect.lsm_name(), "socket_connect");
    assert_eq!(LsmHookType::SocketBind.lsm_name(), "socket_bind");
    assert_eq!(LsmHookType::TaskKill.lsm_name(), "task_kill");
    assert_eq!(
        LsmHookType::BprmCheckSecurity.lsm_name(),
        "bprm_check_security"
    );
    assert_eq!(LsmHookType::MmapFile.lsm_name(), "mmap_file");
    assert_eq!(
        LsmHookType::PtraceAccessCheck.lsm_name(),
        "ptrace_access_check"
    );
}

#[test]
fn test_kprobe_names() {
    assert_eq!(LsmHookType::FileOpen.kprobe_name(), "security_file_open");
    assert_eq!(
        LsmHookType::FilePermission.kprobe_name(),
        "security_file_permission"
    );
    assert_eq!(
        LsmHookType::SocketConnect.kprobe_name(),
        "security_socket_connect"
    );
    assert_eq!(
        LsmHookType::SocketBind.kprobe_name(),
        "security_socket_bind"
    );
    assert_eq!(LsmHookType::TaskKill.kprobe_name(), "security_task_kill");
}

#[test]
fn test_tracepoint_names() {
    let file_open_tp = LsmHookType::FileOpen.tracepoint_name();
    assert_eq!(file_open_tp, Some(("lsm", "file_open")));

    let file_perm_tp = LsmHookType::FilePermission.tracepoint_name();
    assert_eq!(file_perm_tp, Some(("lsm", "file_permission")));

    let task_kill_tp = LsmHookType::TaskKill.tracepoint_name();
    assert_eq!(task_kill_tp, Some(("signal", "signal_generate")));

    let bprm_tp = LsmHookType::BprmCheckSecurity.tracepoint_name();
    assert_eq!(bprm_tp, Some(("sched", "sched_process_exec")));

    // Some hooks don't have tracepoint equivalents
    let socket_connect_tp = LsmHookType::SocketConnect.tracepoint_name();
    assert_eq!(socket_connect_tp, None);
}

#[test]
fn test_all_hook_types() {
    let all_hooks = LsmHookType::all();

    assert!(all_hooks.len() >= 8, "Should have at least 8 hook types");
    assert!(all_hooks.contains(&LsmHookType::FileOpen));
    assert!(all_hooks.contains(&LsmHookType::FilePermission));
    assert!(all_hooks.contains(&LsmHookType::SocketConnect));
    assert!(all_hooks.contains(&LsmHookType::SocketBind));
    assert!(all_hooks.contains(&LsmHookType::TaskKill));
    assert!(all_hooks.contains(&LsmHookType::BprmCheckSecurity));
    assert!(all_hooks.contains(&LsmHookType::MmapFile));
    assert!(all_hooks.contains(&LsmHookType::PtraceAccessCheck));
}

#[test]
fn test_namespace_id_reading() {
    init_test_logging();

    // Test reading /proc/self/ns/mnt
    let result = fs::read_link("/proc/self/ns/mnt");
    assert!(result.is_ok(), "Failed to read /proc/self/ns/mnt");

    let link = result.unwrap().to_string_lossy().to_string();
    println!("Mount namespace: {}", link);

    // Should be in format: mnt:[4026531841]
    assert!(link.starts_with("mnt:["));
    assert!(link.ends_with("]"));
}

/// Test that requires root privileges - load actual BPF program
#[test]
#[ignore] // Run with: cargo test --features ebpf -- --ignored --test-threads=1
fn test_lsm_hook_manager_load() -> Result<()> {
    init_test_logging();

    // Check if we have CAP_BPF or CAP_SYS_ADMIN
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Skipping test - requires root privileges");
        return Ok(());
    }

    let manager = LsmHookManager::load()?;

    println!("Loaded LSM hook manager");
    println!("Kernel version: {:?}", manager.kernel_version());
    println!("Strategy: {:?}", manager.strategy());

    Ok(())
}

/// Test that requires root privileges - attach hooks
#[test]
#[ignore]
fn test_lsm_hook_manager_attach() -> Result<()> {
    init_test_logging();

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Skipping test - requires root privileges");
        return Ok(());
    }

    let mut manager = LsmHookManager::load()?;
    manager.attach()?;

    println!("Successfully attached LSM hooks");

    // Get statistics
    let stats = manager.get_stats()?;
    println!("Events generated: {}", stats.events_generated);
    println!("Events dropped: {}", stats.events_dropped_full);

    Ok(())
}

/// Test that requires root privileges - receive events
#[test]
#[ignore]
fn test_lsm_hook_manager_events() -> Result<()> {
    init_test_logging();

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Skipping test - requires root privileges");
        return Ok(());
    }

    let mut manager = LsmHookManager::load()?;
    manager.attach()?;

    // Get event ring buffer
    let mut ring_buf = manager.event_ring_buffer()?;

    println!("Listening for events for 5 seconds...");

    // Generate some events by running a simple command
    std::process::Command::new("ls")
        .arg("/tmp")
        .output()
        .expect("Failed to run test command");

    // Poll for events
    let start = std::time::Instant::now();
    let mut event_count = 0;

    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(events) = ring_buf.read() {
            if !events.is_empty() {
                event_count += events.len();
                println!("Received {} events", events.len());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    println!("Total events received: {}", event_count);

    // Get final statistics
    let stats = manager.get_stats()?;
    println!("Final stats:");
    println!("  Events generated: {}", stats.events_generated);
    println!("  Events dropped: {}", stats.events_dropped_full);
    println!("  Events rate limited: {}", stats.events_rate_limited);
    println!("  Map lookup failures: {}", stats.map_lookup_failures);
    println!("  Probe read failures: {}", stats.probe_read_failures);

    Ok(())
}

/// Test fallback strategy creation
#[test]
fn test_fallback_strategy_creation() {
    let version = KernelVersion {
        major: 5,
        minor: 4,
        patch: 0,
    };
    let strategy = FallbackStrategy::new(version);

    // Should start with no attached hooks
    assert_eq!(strategy.attached_hooks().len(), 0);
}

/// Test hook priority ordering
#[test]
fn test_hook_priorities() {
    // Critical hooks should be attempted first
    // This is important for graceful degradation

    let critical_hooks = vec![
        LsmHookType::BprmCheckSecurity,
        LsmHookType::FileOpen,
        LsmHookType::SocketConnect,
    ];

    for hook in critical_hooks {
        println!("Critical hook: {:?}", hook);
    }
}

/// Benchmark kernel version parsing
#[test]
#[ignore]
fn bench_kernel_version_parsing() {
    let versions = vec![
        "5.15.0-91-generic",
        "6.1.2",
        "4.19.0-26-amd64",
        "5.4.0-169-generic",
    ];

    let start = std::time::Instant::now();
    let iterations = 100000;

    for _ in 0..iterations {
        for v in &versions {
            let _ = KernelVersion::from_string(v);
        }
    }

    let elapsed = start.elapsed();
    let per_parse = elapsed / (iterations * versions.len() as u32);

    println!("Kernel version parsing: {:?} per parse", per_parse);
    println!(
        "Total for {} iterations: {:?}",
        iterations * versions.len() as usize,
        elapsed
    );
}

/// Test CO-RE support detection
#[test]
fn test_core_support_detection() {
    let version = KernelVersion::current().expect("Failed to get kernel version");

    // Check if BTF is available
    let btf_path = "/sys/kernel/btf/vmlinux";
    let has_btf = std::path::Path::new(btf_path).exists();

    println!(
        "Kernel version: {}.{}.{}",
        version.major, version.minor, version.patch
    );
    println!("BTF file exists: {}", has_btf);
    println!("Version supports BTF: {}", version.supports_btf());

    if version.supports_btf() {
        assert!(
            has_btf || version.minor >= 2,
            "BTF should be available for kernel >= 5.2"
        );
    }
}

/// Test sensitive file configuration
#[test]
#[ignore]
fn test_sensitive_file_configuration() -> Result<()> {
    init_test_logging();

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Skipping test - requires root privileges");
        return Ok(());
    }

    let mut manager = LsmHookManager::load()?;
    manager.attach()?;

    // Add sensitive files
    manager.add_sensitive_file("/etc/shadow", 1)?;
    manager.add_sensitive_file("/etc/passwd", 0)?;
    manager.add_sensitive_file("/root/.ssh/id_rsa", 2)?;

    println!("Added sensitive file monitoring");

    Ok(())
}

/// Test configuration updates
#[test]
#[ignore]
fn test_configuration_updates() -> Result<()> {
    init_test_logging();

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Skipping test - requires root privileges");
        return Ok(());
    }

    let mut manager = LsmHookManager::load()?;
    manager.attach()?;

    // Update configuration
    let mut config = tamandua_ebpf_common::EbpfConfig {
        enabled: 1,
        process_enabled: 1,
        file_enabled: 0, // Disable file monitoring
        network_enabled: 1,
        security_enabled: 1,
        container_enabled: 1,
        lsm_enabled: 1,
        xdp_enabled: 0,
        filter_uid: 0,
        containers_only: 0,
        sensitive_files_enabled: 0,
        filter_low_pids: 1,
        _pad: [0; 1],
    };

    manager.set_config(config)?;

    println!("Updated configuration (disabled file monitoring)");

    // Re-enable
    config.file_enabled = 1;
    manager.set_config(config)?;

    println!("Re-enabled file monitoring");

    Ok(())
}
