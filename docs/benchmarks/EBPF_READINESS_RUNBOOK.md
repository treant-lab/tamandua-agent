# Linux eBPF/LSM Readiness Runbook

Status: operational runbook
Last updated: 2026-06-03

Use this runbook to validate eBPF and LSM-BPF readiness on a Linux lab host
before deploying the Tamandua agent in collector-active mode. Do not claim a
Linux 300 result, or any defensive baseline that depends on the eBPF
collector, unless this runbook has been completed and the readiness probe is
green on the exact target host (kernel image, distro, hardening profile).

## Purpose

The Tamandua agent's primary Linux telemetry path is the eBPF collector at
`apps/tamandua_agent/src/collectors/ebpf_linux.rs`. It uses `aya` to load a
CO-RE BPF object, attaches tracepoints/kprobes for process, file, network,
and memory events, and prefers LSM-BPF hooks for security events when the
kernel supports them. If prerequisites are missing the collector degrades
silently to "inactive" and the agent falls back to the auditd-backed ring
buffer collector.

This runbook is the manual gate that prevents "agent installed but eBPF
silently inactive" from being mistaken for a real defensive baseline. It
also classifies failure modes so that a red Linux benchmark is routed to
`infra`/`kernel` rather than `detector`.

## Prerequisites

The eBPF collector requires all of the following on the target host:

- Kernel `>= 5.7` for LSM-BPF hooks. Kernels `5.5`–`5.6` provide `fentry`
  and most tracepoints/kprobes but cannot attach LSM programs; this is the
  hard line between "Active" and "Degraded".
- Ring buffer (`BPF_MAP_TYPE_RINGBUF`) requires kernel `>= 5.8`.
- BTF available at `/sys/kernel/btf/vmlinux`. Required for CO-RE relocation.
- `CONFIG_BPF_LSM=y` in the running kernel config and `lsm=` boot parameter
  containing `bpf`.
- BPF filesystem mounted at `/sys/fs/bpf`.
- Tracing filesystem available at `/sys/kernel/debug/tracing` or
  `/sys/kernel/tracing`.
- The agent process must run as root or with effective `CAP_BPF` plus
  `CAP_PERFMON` (kernel `>= 5.8`); on older kernels `CAP_SYS_ADMIN` is
  required.
- The CO-RE BPF object referenced by `EbpfLinuxConfig.bpf_object_path` must
  exist and be readable.

These match the fields populated by `LinuxEbpfCapabilities::detect_for_object`
in the collector. The probe described below reads the same surfaces.

## Manual Pre-Checks

Before touching the target host, verify the agent-side eBPF API and test
surface from the repository checkout:

```bash
cd apps/tamandua_agent
cargo test --test ebpf --no-default-features
```

On Linux this target exercises `LinuxEbpfCapabilities`, the eBPF health
publication slot, and the health state machine. On non-Linux hosts it only
checks that the public `ebpf_linux` stub surface still cross-compiles. This
test is a code preflight, not a host-readiness artifact; a green result here
does not replace the Linux readiness probe below.

Run these on the target host before the automated probe. Each check has a
green answer; record the actual answer in the run notes.

```bash
# 1. Kernel version (need >= 5.7 for LSM, >= 5.8 for ring buffer)
uname -r

# 2. BTF availability (must exist and be non-empty)
ls -l /sys/kernel/btf/vmlinux
test -s /sys/kernel/btf/vmlinux && echo "btf-ok" || echo "btf-missing"

# 3. Kernel build config: BPF, BPF_LSM, BPF_SYSCALL, DEBUG_INFO_BTF
#    Try the running-kernel exported config first, then fall back to /boot.
( zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" ) \
  | grep -E 'CONFIG_BPF(=|_LSM=|_SYSCALL=|_EVENTS=|JIT=)|CONFIG_DEBUG_INFO_BTF='

# 4. LSM list must include bpf (and ideally be ordered so bpf is loaded)
cat /sys/kernel/security/lsm
cat /proc/cmdline | tr ' ' '\n' | grep -E '^lsm='

# 5. BPF filesystem and tracing filesystem
mount | grep -E 'bpf|tracefs|debugfs'
ls /sys/fs/bpf
ls /sys/kernel/debug/tracing 2>/dev/null || ls /sys/kernel/tracing

# 6. Effective capabilities for the user/unit that will run the agent
capsh --print
getcap "$(command -v tamandua-agent)" 2>/dev/null || echo "no file caps set"

# 7. Confirm the CO-RE BPF object exists where the agent expects it
ls -l /opt/tamandua/bpf/tamandua.bpf.o
```

A "green" host shows: kernel `>= 5.7`, non-empty `vmlinux`, all four
`CONFIG_*` lines `=y`, `bpf` present in the LSM list, `/sys/fs/bpf` mounted,
tracing fs available, agent context holds `cap_bpf` and `cap_perfmon` (or
runs as root), and the BPF object file is present.

## Run The Readiness Probe

The Python probe wraps the same detection surfaces as
`LinuxEbpfCapabilities` and emits a structured benchmark artifact under
`docs/benchmarks/runs/`.

```bash
python tools/detection_validation/run_profile.py \
  --profile linux_ebpf_readiness_probe
```

The profile is intended to be run on the same Linux host that will receive
the agent. If you are gating from the orchestrator, use SSH or the bounded
lab transport — do not run the probe against the orchestrator's own kernel
unless that is the deployment target.

The probe writes three files under `docs/benchmarks/runs/`:

- `<timestamp>-linux-ebpf-readiness-probe.json` — raw capability snapshot
- `<timestamp>-linux-ebpf-readiness-probe.comparison.json` — diff vs. prior
- `<timestamp>-linux-ebpf-readiness-probe.md` — operator-facing summary

## Interpreting Probe Output

The probe maps the `LinuxEbpfCapabilities` snapshot onto the same three
states the collector reports through `EbpfLinuxHealth`:

- `active` — collector loaded and attached. All prerequisites are satisfied,
  BTF is present, capabilities are sufficient, and the BPF object loaded
  cleanly. This is the only state under which a Linux benchmark may be run
  in collector-backed mode.
- `degraded` — prerequisites are satisfied but at least one optional
  capability is missing (typically: LSM hooks unavailable on kernel
  `5.0`–`5.6`, ring buffer unavailable on kernel `< 5.8`, or BPF object
  failed to load despite a sufficient kernel). The agent will run with a
  reduced tracepoint/kprobe-only attach set. Linux 300 results obtained in
  `degraded` must be tagged `coverage-reduced` and may not be used to claim
  parity with Windows ETW.
- `unavailable` — at least one hard prerequisite is missing (kernel too old,
  BTF missing, no capabilities, BPF object missing). The eBPF collector
  cannot run. Any benchmark on this host runs through the auditd fallback
  and must be classified `infra`/`kernel` rather than `detector`.

The probe's `missing_prerequisites` array is authoritative; it mirrors the
`Vec<String>` produced by the collector's capability detection.

## Common Failure Modes And Remediation

### BTF missing (`/sys/kernel/btf/vmlinux` absent or empty)

Typical on long-term-support kernels built without `CONFIG_DEBUG_INFO_BTF=y`
or on minimal cloud images.

- Preferred: install the matching kernel-debuginfo package and reboot, or
  switch to a distro kernel that ships BTF (`Ubuntu >= 20.10`,
  `Fedora >= 31`, `RHEL >= 8.6` with the BTF-enabled kernel,
  `Debian >= 11` with the appropriate kernel).
- Fallback: ship an externally built `vmlinux` BTF blob via the
  `BTF_CUSTOM_PATH` environment variable supported by `aya` and point the
  agent's loader at it. This is a workaround for one-off lab runs only and
  must be noted in the benchmark artifact.
- Do not "fix" BTF by disabling CO-RE; the collector requires it.

### Kernel `< 5.7` (no LSM-BPF)

The collector will degrade. Tracepoints, kprobes, kretprobes, and (on
`>= 5.5`) `fentry` still work, but the security-event surface that depends
on LSM hooks (`security_file_open`, `bpf`, `ptrace_access_check`,
`task_alloc`, etc.) will not be attached.

- Preferred: upgrade to a `>= 5.10` LTS kernel.
- Acceptable: run in `degraded` mode and document the gap; the tracepoint
  fallback covers most process/file/network events but loses LSM-grade
  policy semantics.
- Not acceptable: claim LSM-backed detections on this host.

### Missing `CAP_BPF` / `CAP_PERFMON`

The collector's `load_and_attach` path explicitly rejects this with
`"Not root and CAP_BPF not available"`.

- Preferred: run the agent as a systemd unit with the capabilities granted
  explicitly. Example unit fragment (do not commit secrets):
  ```ini
  [Service]
  AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
  CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
  NoNewPrivileges=yes
  ```
  On kernels `< 5.8` substitute `CAP_SYS_ADMIN` in place of
  `CAP_BPF`/`CAP_PERFMON`.
- Acceptable: run as root under a hardened unit (`ProtectSystem=strict`,
  `PrivateTmp=yes`, `ProtectKernelTunables=yes`).
- Not acceptable: granting `CAP_SYS_ADMIN` to the agent on a kernel that
  supports `CAP_BPF`; this widens the blast radius unnecessarily.

### SELinux or AppArmor blocking BPF / ring buffer / tracefs

The collector loads but immediately fails to attach, and `dmesg` shows AVC
denials or AppArmor `DENIED operation="open"` lines against
`/sys/fs/bpf`, `/sys/kernel/debug/tracing`, or `bpf()` syscalls.

- SELinux: capture the denials and generate a candidate policy delta with
  `audit2allow`, review it manually, and ship it as a named module
  (`tamandua-agent.pp`). Do not run permissive in production.
  ```bash
  ausearch -m AVC,USER_AVC -ts recent | audit2allow -M tamandua-agent
  ```
- AppArmor: extend the agent profile to allow `capability bpf`,
  `capability perfmon`, `/sys/fs/bpf/** rw`, and the tracefs paths the
  collector uses. Reload with `apparmor_parser -r`.
- Re-run the probe after policy changes; do not assume a one-line `dmesg`
  clear means the attach surface is healthy.

### BPF object missing or incompatible

`object_path_exists=false` or `BpfLoader::load_file` failing typically means
the agent package was installed without its BPF artifacts, or a CO-RE
relocation failed because the running kernel's BTF disagrees with the
object's expected types.

- Verify the path matches `EbpfLinuxConfig.bpf_object_path` (default
  `/opt/tamandua/bpf/tamandua.bpf.o`).
- Re-install the agent package; do not hand-copy the BPF object across
  distros.
- For CO-RE relocation failures: capture the `aya` error chain (the
  collector logs it at `error!` level with `Failed to load BPF object`) and
  attach it to the benchmark artifact before re-running.

## Escalation To The Fallback Ring Buffer Collector

If the probe reports `unavailable` and the host cannot be fixed within the
benchmark window, escalate to the auditd-backed fallback collector. This is
documented in `docs/apps/tamandua_agent/LINUX_AUDITD_INTEGRATION.md`. The
fallback is not eBPF; it is a separate ingestion path and must be marked as
such on every artifact it produces.

Rules of escalation:

- The auditd fallback is acceptable for Linux benchmarks classified
  `coverage-reduced` only. It does not satisfy LSM-backed detection claims.
- Do not run the eBPF collector and the auditd collector concurrently on
  the same host during a benchmark; pick one and record the choice.
- The benchmark lane for fallback runs is `claim-boundary` (gated) or
  `infra-fallback`, never `enterprise-eval`.
- A passing fallback run still leaves the eBPF readiness gap open on the
  roadmap. Reopen the kernel/distro remediation ticket.

## Sign-Off Checklist

Sign off the runbook only when every box below is checked on the target
host and the probe artifact is attached to the benchmark run notes.

- [ ] `uname -r` recorded; kernel `>= 5.7` (or escalation accepted).
- [ ] `/sys/kernel/btf/vmlinux` exists and is non-empty.
- [ ] `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
      confirmed in the running-kernel config.
- [ ] `lsm=` boot line includes `bpf` (or default LSM list includes it).
- [ ] `/sys/fs/bpf` mounted; tracing fs available.
- [ ] Agent context holds `CAP_BPF` and `CAP_PERFMON` (or root, with the
      hardened systemd unit applied).
- [ ] CO-RE BPF object present at the configured path.
- [ ] Agent eBPF API preflight target passed:
      `cargo test --test ebpf --no-default-features` from
      `apps/tamandua_agent`.
- [ ] `linux_ebpf_readiness_probe` artifact recorded and probe state is
      `active` (or `degraded` with `coverage-reduced` tag and explicit
      acceptance).
- [ ] If `unavailable`: escalation path chosen and benchmark lane reclassed
      to `infra-fallback` or `claim-boundary`.
- [ ] No SELinux/AppArmor AVC denials in `dmesg` during the probe window.
- [ ] Sign-off operator, hostname, kernel version, and probe artifact
      filename recorded in the benchmark run notes.
