//! Tests for container escape detection enhancements in eBPF collector.
//!
//! These tests verify that container escape attempts are properly detected
//! by the Tamandua EDR agent's eBPF Linux collector and that the resulting
//! telemetry events are tagged with the correct MITRE ATT&CK techniques
//! (T1611 Escape to Host, T1055 Process Injection, T1552 Unsecured
//! Credentials).
//!
//! ## Production-side wiring
//!
//! The parser entry points (`parse_namespace_event`, `parse_ptrace`,
//! `parse_sensitive_access`) and the underlying `BpfNamespaceEvent`,
//! `BpfPtraceEvent`, `BpfFileEvent`, `EbpfEventHeader` structs are
//! re-exported as `pub(crate)` from `ebpf_linux::inner`. The tests below
//! drive those parsers with synthetic ring-buffer payloads.
//!
//! All 5 tests are now active. Test 3
//! (`test_mount_from_container_privilege_escalation`) drives the new
//! `parse_mount_event` parser with a synthetic `BpfMountEvent` payload
//! that simulates a containerized process mounting a host-sensitive path.
//! A kernel-side `lsm/sb_mount` (or `tp/syscalls/sys_enter_mount`) hook
//! that emits the matching ring-buffer payload is the remaining piece of
//! the kernel build that this test does NOT cover -- the test validates
//! the userspace parser in isolation.

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    // Pull in shared telemetry types (EventType, Severity, Detection,
    // TelemetryEvent) from `crate::collectors` ...
    use super::super::*;
    // ... and the BPF-side layouts + parser entry points from the
    // `ebpf_linux` submodule, where they are re-exported as `pub(crate)`.
    use super::super::ebpf_linux::{
        parse_mount_event, parse_namespace_event, parse_ptrace, parse_sensitive_access,
        BpfEventType, BpfFileEvent, BpfMountEvent, BpfNamespaceEvent, BpfPtraceEvent,
        EbpfEventHeader, ProcessEnricher,
    };

    // ------------------------------------------------------------------
    // Layout constants -- must mirror the private constants in
    // `ebpf_linux::inner`. They are re-stated here so that the synthetic
    // event buffers we build below have exactly the same byte layout as
    // the BPF C-side structs.
    // ------------------------------------------------------------------
    const MAX_COMM_LEN: usize = 64;
    const MAX_PATH_LEN: usize = 256;
    const MAX_FSTYPE_LEN: usize = 64;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Reinterpret a `repr(C) + Copy` struct as a byte slice. Used to feed
    /// the production parsers with the exact same layout the kernel side
    /// emits to the ring buffer.
    fn as_bytes<T: Copy>(value: &T) -> Vec<u8> {
        let size = std::mem::size_of::<T>();
        // SAFETY: `T` is `repr(C)` and `Copy`, so reading its bytes is
        // sound for the duration of the borrow.
        let slice = unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size) };
        slice.to_vec()
    }

    /// Build an `EbpfEventHeader` with the given `cgroup_id` and `comm`.
    fn make_header(cgroup_id: u64, pid: u32, comm: &str) -> EbpfEventHeader {
        let mut comm_buf = [0u8; MAX_COMM_LEN];
        let bytes = comm.as_bytes();
        let n = bytes.len().min(MAX_COMM_LEN - 1);
        comm_buf[..n].copy_from_slice(&bytes[..n]);
        EbpfEventHeader {
            event_type: 0,
            pid,
            tid: pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            timestamp_ns: 0,
            comm: comm_buf,
            cgroup_id,
            mnt_ns: 0,
            pid_ns: 0,
        }
    }

    /// Build a synthetic `BpfNamespaceEvent` payload.
    fn make_namespace_event(
        cgroup_id: u64,
        pid: u32,
        ns_type: u32,
        old_ns: u32,
        new_ns: u32,
        is_escape: u8,
    ) -> Vec<u8> {
        let event = BpfNamespaceEvent {
            header: make_header(cgroup_id, pid, "evil"),
            ns_type,
            old_ns,
            new_ns,
            flags: 0,
            is_escape,
            _pad: [0; 7],
        };
        as_bytes(&event)
    }

    /// Build a synthetic `BpfPtraceEvent` payload.
    fn make_ptrace_event(cgroup_id: u64, pid: u32, target_pid: u32, request: u32) -> Vec<u8> {
        let mut target_comm = [0u8; MAX_COMM_LEN];
        let n = b"systemd".len();
        target_comm[..n].copy_from_slice(b"systemd");
        let event = BpfPtraceEvent {
            header: make_header(cgroup_id, pid, "evil"),
            target_pid,
            request,
            addr: 0,
            data: 0,
            target_comm,
        };
        as_bytes(&event)
    }

    /// Build a synthetic `BpfFileEvent` payload for sensitive-file access.
    fn make_file_event(cgroup_id: u64, pid: u32, path: &str) -> Vec<u8> {
        let mut path_buf = [0u8; MAX_PATH_LEN];
        let bytes = path.as_bytes();
        let n = bytes.len().min(MAX_PATH_LEN - 1);
        path_buf[..n].copy_from_slice(&bytes[..n]);
        let event = BpfFileEvent {
            header: make_header(cgroup_id, pid, "evil"),
            path: path_buf,
            fd: 3,
            flags: 0,
            mode: 0,
            _pad: 0,
            inode: 0,
            dev: 0,
            size: 0,
        };
        as_bytes(&event)
    }

    /// Build a synthetic `BpfMountEvent` payload modelling a containerized
    /// process attempting to mount a host-sensitive `source` onto `target`.
    fn make_mount_event(
        cgroup_id: u64,
        pid: u32,
        source: &str,
        target: &str,
        fstype: &str,
        flags: u64,
    ) -> Vec<u8> {
        let mut source_buf = [0u8; MAX_PATH_LEN];
        let s = source.as_bytes();
        let ns = s.len().min(MAX_PATH_LEN - 1);
        source_buf[..ns].copy_from_slice(&s[..ns]);

        let mut target_buf = [0u8; MAX_PATH_LEN];
        let t = target.as_bytes();
        let nt = t.len().min(MAX_PATH_LEN - 1);
        target_buf[..nt].copy_from_slice(&t[..nt]);

        let mut fstype_buf = [0u8; MAX_FSTYPE_LEN];
        let f = fstype.as_bytes();
        let nf = f.len().min(MAX_FSTYPE_LEN - 1);
        fstype_buf[..nf].copy_from_slice(&f[..nf]);

        let event = BpfMountEvent {
            header: make_header(cgroup_id, pid, "evil"),
            source: source_buf,
            target: target_buf,
            fstype: fstype_buf,
            flags,
        };
        as_bytes(&event)
    }

    /// Find a detection by rule name.
    fn find_detection<'a>(evt: &'a TelemetryEvent, rule_name: &str) -> Option<&'a Detection> {
        evt.detections.iter().find(|d| d.rule_name == rule_name)
    }

    // ------------------------------------------------------------------
    // Synthetic scenario helper -- preserves the original intent doc so
    // that future readers understand which BPF event shape each test
    // exercises.
    // ------------------------------------------------------------------
    #[allow(dead_code)]
    struct SyntheticEscapeScenario {
        cgroup_id: u64,
        pid: u32,
        ppid: u32,
        comm: &'static str,
        ns_type: u32,
        old_ns: u32,
        new_ns: u32,
        is_escape: u8,
        target_pid: u32,
        ptrace_request: u32,
        path: &'static str,
    }

    impl SyntheticEscapeScenario {
        const fn container_attacker() -> Self {
            Self {
                cgroup_id: 0xdead_beef_cafe_f00d,
                pid: 4242,
                ppid: 1,
                comm: "evil",
                ns_type: 0,
                old_ns: 4_026_531_836,
                new_ns: 4_026_531_836,
                is_escape: 0,
                target_pid: 0,
                ptrace_request: 0,
                path: "",
            }
        }
    }

    // ==================================================================
    // Test 1 (T1611): Namespace change from a containerized process into
    // the host PID namespace must be flagged as a container escape with
    // `Severity::Critical` and MITRE technique `T1611`.
    // ==================================================================
    #[test]
    fn test_namespace_escape_from_container_to_host() {
        let scenario = SyntheticEscapeScenario {
            ns_type: 0x20000000, // CLONE_NEWPID
            old_ns: 4_026_532_000,
            new_ns: 1, // host namespace
            is_escape: 1,
            ..SyntheticEscapeScenario::container_attacker()
        };

        let buf = make_namespace_event(
            scenario.cgroup_id,
            scenario.pid,
            scenario.ns_type,
            scenario.old_ns,
            scenario.new_ns,
            scenario.is_escape,
        );
        let mut enricher = ProcessEnricher::new();
        let evt = parse_namespace_event(&buf, BpfEventType::NamespaceEscape, &mut enricher)
            .expect("detector must emit an event for container escape");

        assert_eq!(evt.event_type, EventType::ContainerEscape);
        assert_eq!(evt.severity, Severity::Critical);
        let det = find_detection(&evt, "container_escape_ebpf")
            .expect("container_escape_ebpf rule must fire");
        assert!(
            det.mitre_techniques.iter().any(|t| t == "T1611"),
            "container escape detection must carry T1611, got {:?}",
            det.mitre_techniques,
        );
    }

    // ==================================================================
    // Test 2 (T1611): `setns(2)` / `unshare(2)` invoked from a process
    // whose `cgroup_id != 0` produces a High-or-Critical alert tagged
    // with `T1611`. Even when the BPF side did not pre-classify the
    // event as an escape (`is_escape = 0`), the userspace parser still
    // attaches `T1611` because `namespace_change_ebpf` lists `T1611`
    // among its techniques.
    // ==================================================================
    #[test]
    fn test_setns_unshare_from_container_triggers_alert() {
        let scenario = SyntheticEscapeScenario {
            ns_type: 0x00020000, // CLONE_NEWNS (mount namespace)
            old_ns: 4_026_532_001,
            new_ns: 4_026_531_840,
            is_escape: 0,
            ..SyntheticEscapeScenario::container_attacker()
        };

        let buf = make_namespace_event(
            scenario.cgroup_id,
            scenario.pid,
            scenario.ns_type,
            scenario.old_ns,
            scenario.new_ns,
            scenario.is_escape,
        );
        let mut enricher = ProcessEnricher::new();
        let evt = parse_namespace_event(&buf, BpfEventType::NamespaceEscape, &mut enricher)
            .expect("detector must emit an event for setns/unshare from container");

        // Severity must be at least High (BPF-classified escape -> Critical,
        // unclassified namespace change -> High).
        let sev_ok = matches!(evt.severity, Severity::High | Severity::Critical);
        assert!(
            sev_ok,
            "expected High or Critical severity, got {:?}",
            evt.severity,
        );

        // At least one detection must carry T1611.
        let has_t1611 = evt
            .detections
            .iter()
            .any(|d| d.mitre_techniques.iter().any(|t| t == "T1611"));
        assert!(
            has_t1611,
            "at least one detection must tag T1611, got detections={:?}",
            evt.detections
                .iter()
                .map(|d| (&d.rule_name, &d.mitre_techniques))
                .collect::<Vec<_>>(),
        );
    }

    // ==================================================================
    // Test 3 (T1611): mount(2) from inside a container against a
    // sensitive host path. Drives `parse_mount_event` with a synthetic
    // `BpfMountEvent` that simulates a containerized process bind-mounting
    // `/var/run/docker.sock` into its rootfs. The userspace parser must
    // emit `EventType::ContainerEscape`, `Severity::Critical`, the rule
    // `container_mount_escape_ebpf`, and tag `T1611`.
    // ==================================================================
    #[test]
    fn test_mount_from_container_privilege_escalation() {
        const MS_BIND: u64 = 0x1000;
        let scenario = SyntheticEscapeScenario {
            path: "/var/run/docker.sock",
            ..SyntheticEscapeScenario::container_attacker()
        };

        let buf = make_mount_event(
            scenario.cgroup_id,
            scenario.pid,
            scenario.path,
            "/mnt/host-docker.sock",
            "none",
            MS_BIND,
        );
        let mut enricher = ProcessEnricher::new();
        let evt = parse_mount_event(&buf, &mut enricher)
            .expect("parser must emit a detection for a container -> host bind mount");

        assert_eq!(evt.event_type, EventType::ContainerEscape);
        assert_eq!(
            evt.severity,
            Severity::Critical,
            "container -> host runtime-socket bind mount must be Critical",
        );

        let det = find_detection(&evt, "container_mount_escape_ebpf")
            .expect("container_mount_escape_ebpf rule must fire");
        assert!(
            det.mitre_techniques.iter().any(|t| t == "T1611"),
            "container mount escape detection must carry T1611, got {:?}",
            det.mitre_techniques,
        );

        // Sanity: host-side mounts (cgroup_id == 0) must NOT trigger the
        // detector -- the host is allowed to mount its own runtime sockets.
        let host_buf = make_mount_event(
            0,
            scenario.pid,
            scenario.path,
            "/mnt/host-docker.sock",
            "none",
            MS_BIND,
        );
        let mut enricher2 = ProcessEnricher::new();
        assert!(
            parse_mount_event(&host_buf, &mut enricher2).is_none(),
            "host-originated mount (cgroup_id=0) must not produce a detection",
        );

        // Sanity: a benign in-container mount (e.g. tmpfs on /dev/shm) must
        // also be silent -- only host-sensitive sources are escape-relevant.
        let benign_buf = make_mount_event(
            scenario.cgroup_id,
            scenario.pid,
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            0,
        );
        let mut enricher3 = ProcessEnricher::new();
        assert!(
            parse_mount_event(&benign_buf, &mut enricher3).is_none(),
            "benign in-container tmpfs mount must not produce a detection",
        );
    }

    // ==================================================================
    // Test 4 (T1055 + T1611): ptrace(PTRACE_ATTACH) from a containerized
    // process against a low host PID must be tagged BOTH `T1055.008`
    // and `T1611`. Severity is High for ATTACH, Critical for POKETEXT.
    // ==================================================================
    #[test]
    fn test_ptrace_container_to_host() {
        let scenario = SyntheticEscapeScenario {
            ptrace_request: 16, // PTRACE_ATTACH
            target_pid: 1,      // pid 1 in the host pid_ns (systemd / init)
            ..SyntheticEscapeScenario::container_attacker()
        };

        let buf = make_ptrace_event(
            scenario.cgroup_id,
            scenario.pid,
            scenario.target_pid,
            scenario.ptrace_request,
        );
        let mut enricher = ProcessEnricher::new();
        let evt = parse_ptrace(&buf, &mut enricher)
            .expect("detector must emit an event for ptrace attach");

        // PTRACE_ATTACH -> High; POKETEXT/POKEDATA -> Critical. This test
        // uses ATTACH so we expect High.
        assert_eq!(evt.severity, Severity::High);

        let det = find_detection(&evt, "ptrace_injection_ebpf")
            .expect("ptrace_injection_ebpf rule must fire");
        let has_t1055 = det
            .mitre_techniques
            .iter()
            .any(|t| t == "T1055.008" || t == "T1055");
        let has_t1611 = det.mitre_techniques.iter().any(|t| t == "T1611");
        assert!(
            has_t1055,
            "expected T1055/T1055.008 in techniques: {:?}",
            det.mitre_techniques,
        );
        assert!(
            has_t1611,
            "container-originated ptrace must add T1611: {:?}",
            det.mitre_techniques,
        );
    }

    // ==================================================================
    // Test 5 (T1552 + T1611): sensitive-file read from a containerized
    // process must produce `Severity::Critical` and tag BOTH `T1552`
    // (or `T1552.001`) and `T1611`.
    // ==================================================================
    #[test]
    fn test_sensitive_file_access_from_container() {
        let scenario = SyntheticEscapeScenario {
            path: "/etc/shadow",
            ..SyntheticEscapeScenario::container_attacker()
        };

        let buf = make_file_event(scenario.cgroup_id, scenario.pid, scenario.path);
        let mut enricher = ProcessEnricher::new();
        let evt = parse_sensitive_access(&buf, &mut enricher)
            .expect("detector must emit an event for sensitive file access");

        assert_eq!(
            evt.severity,
            Severity::Critical,
            "container context must escalate severity to Critical",
        );

        let det = find_detection(&evt, "sensitive_file_access_ebpf")
            .expect("sensitive_file_access_ebpf rule must fire");
        let has_t1552 = det
            .mitre_techniques
            .iter()
            .any(|t| t == "T1552" || t == "T1552.001");
        let has_t1611 = det.mitre_techniques.iter().any(|t| t == "T1611");
        assert!(
            has_t1552,
            "expected T1552/T1552.001 in techniques: {:?}",
            det.mitre_techniques,
        );
        assert!(
            has_t1611,
            "container-originated credential access must add T1611: {:?}",
            det.mitre_techniques,
        );
    }
}
