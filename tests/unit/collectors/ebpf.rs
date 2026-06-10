//! Unit tests for the Linux eBPF collector public API.
//!
//! These tests exercise the externally visible surface of the
//! `tamandua_agent::collectors::ebpf_linux` module:
//!
//!   * `LinuxEbpfCapabilities` -- kernel-feature probing, sufficiency
//!     gating, and the `maturity_label()` bucketing used by the
//!     readiness scorecard.
//!   * `EbpfLinuxHealth` / `EbpfLinuxHealthState` -- the runtime health
//!     state machine consumed by `SystemHealthEvent` and the collector
//!     status reporter.
//!   * `publish_latest_health` / `latest_health` -- the cross-thread
//!     health publication slot used by `SystemHealthCollector`.
//!
//! The parser entry points (`parse_namespace_event`, `parse_ptrace`,
//! `parse_sensitive_access`, `parse_mount_event`) are exposed only as
//! `pub(crate)` and therefore live in the sibling in-crate test module
//! `crate::collectors::ebpf_container_escape_tests`.

#[cfg(target_os = "linux")]
mod linux_tests {
    use tamandua_agent::collectors::ebpf_linux::{
        latest_health, publish_latest_health, EbpfLinuxHealth, EbpfLinuxHealthState,
        LinuxEbpfCapabilities,
    };

    // ------------------------------------------------------------------
    // LinuxEbpfCapabilities
    // ------------------------------------------------------------------

    /// `detect()` must always return a well-formed snapshot. We do not
    /// assert specific feature flags because they depend on the host
    /// kernel, but the invariants below must hold on every Linux box.
    #[test]
    fn test_capabilities_detect_returns_snapshot() {
        let caps = LinuxEbpfCapabilities::detect();

        // kernel_version (0, 0, 0) only happens when /proc/version is
        // unreadable -- on a real Linux test host the major version must
        // be non-zero.
        assert!(
            caps.kernel_version.0 > 0,
            "kernel major version must be detected, got {:?}",
            caps.kernel_version,
        );

        // object_path is populated from the default EbpfLinuxConfig.
        assert!(
            !caps.object_path.is_empty(),
            "object_path must be set from the default config",
        );
    }

    /// `is_sufficient()` is the gate the collector uses to decide
    /// whether to enter `Active`. Whenever it returns true,
    /// `missing_prerequisites` must be empty -- and vice versa.
    #[test]
    fn test_capabilities_sufficiency_implies_no_missing_prereqs() {
        let caps = LinuxEbpfCapabilities::detect();
        if caps.is_sufficient() {
            assert!(
                caps.missing_prerequisites.is_empty(),
                "is_sufficient()=true but missing_prerequisites={:?}",
                caps.missing_prerequisites,
            );
        } else {
            assert!(
                !caps.missing_prerequisites.is_empty(),
                "is_sufficient()=false but missing_prerequisites is empty",
            );
        }
    }

    /// `maturity_label()` is the bucket the readiness scorecard ingests.
    /// It must be one of the three documented strings.
    #[test]
    fn test_capabilities_maturity_label_in_known_set() {
        let caps = LinuxEbpfCapabilities::detect();
        let label = caps.maturity_label();
        assert!(
            matches!(label, "lab_ready" | "partial" | "unavailable"),
            "unexpected maturity_label: {}",
            label,
        );

        // The label must be consistent with the sufficiency gate.
        if caps.is_sufficient() {
            assert_eq!(
                label, "lab_ready",
                "sufficient capabilities must report lab_ready, got {}",
                label,
            );
        }
    }

    /// `detect_for_object()` with a non-existent BPF object file must
    /// flag the missing object as a prerequisite.
    #[test]
    fn test_capabilities_missing_object_path_reported() {
        let bogus = "/nonexistent/path/to/tamandua_agent.bpf.o";
        let caps = LinuxEbpfCapabilities::detect_for_object(bogus);
        assert!(!caps.object_path_exists);
        assert!(
            caps.missing_prerequisites
                .iter()
                .any(|m| m.contains("BPF object file not found")),
            "missing_prerequisites must mention the missing object: {:?}",
            caps.missing_prerequisites,
        );
        assert!(
            !caps.is_sufficient(),
            "is_sufficient() must be false when the BPF object is missing",
        );
    }

    // ------------------------------------------------------------------
    // EbpfLinuxHealth state machine + publication slot
    // ------------------------------------------------------------------

    fn make_health(state: EbpfLinuxHealthState, maturity: &'static str) -> EbpfLinuxHealth {
        use tamandua_agent::collectors::ebpf_linux::EbpfLinuxStatsSnapshot;
        EbpfLinuxHealth {
            state: state.clone(),
            maturity,
            ebpf_active: matches!(state, EbpfLinuxHealthState::Active),
            capabilities: LinuxEbpfCapabilities::default(),
            missing_prerequisites: Vec::new(),
            stats: EbpfLinuxStatsSnapshot {
                events_received: 0,
                events_processed: 0,
                events_dropped_rate_limit: 0,
                events_dropped_channel_full: 0,
                parse_errors: 0,
                enrichment_misses: 0,
            },
        }
    }

    #[test]
    fn test_health_publish_then_latest_roundtrip() {
        let health = make_health(EbpfLinuxHealthState::Active, "lab_ready");
        publish_latest_health(health.clone());
        let observed = latest_health().expect("latest_health() must return after publish");
        assert_eq!(observed.state, EbpfLinuxHealthState::Active);
        assert_eq!(observed.maturity, "lab_ready");
        assert!(observed.ebpf_active);
    }

    #[test]
    fn test_health_state_transitions_publish_through_slot() {
        // Active -> Degraded -> Unavailable. The slot must always hold
        // the most-recently published snapshot.
        for (state, label) in [
            (EbpfLinuxHealthState::Active, "lab_ready"),
            (EbpfLinuxHealthState::Degraded, "partial"),
            (EbpfLinuxHealthState::Unavailable, "unavailable"),
        ] {
            let h = make_health(state.clone(), label);
            publish_latest_health(h);
            let observed = latest_health().expect("latest_health() must return after publish");
            assert_eq!(observed.state, state);
            assert_eq!(observed.maturity, label);
            assert_eq!(
                observed.ebpf_active,
                matches!(state, EbpfLinuxHealthState::Active),
                "ebpf_active must mirror the Active variant",
            );
        }
    }
}

// On non-Linux platforms the eBPF collector is compiled as a stub. We
// still verify that the public `EbpfLinuxCollector` symbol is reachable
// so the wider workspace cross-compiles cleanly.
#[cfg(not(target_os = "linux"))]
mod non_linux_tests {
    #[test]
    fn test_ebpf_collector_symbol_is_reachable_on_non_linux() {
        // The stub `EbpfLinuxCollector` is unit-sized and has no public
        // constructor. Resolving its type path is enough to prove the
        // re-export compiles on the current platform.
        fn _assert_type<T>() {}
        _assert_type::<tamandua_agent::collectors::ebpf_linux::EbpfLinuxCollector>();
    }
}
