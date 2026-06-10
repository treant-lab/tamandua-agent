# Tamandua Agent

Cross-platform endpoint telemetry and response agent for the
[Tamandua EDR](https://github.com/treant-lab) platform. Written in Rust for
Windows, Linux, and macOS.

The agent collects process, file, network, DNS, and registry telemetry, performs
local analysis (hashing, entropy, signature verification), and executes response
commands (kill, quarantine, isolate) issued by the Tamandua server over an
authenticated WebSocket channel.

## Overview

- **Collectors** (`src/collectors/`) — emit `TelemetryEvent`s via `next_event()`.
  Platform-native sources: Windows ETW, Linux eBPF (CO-RE/BTF via `aya`, with an
  auditd fallback on kernels < 5.7), macOS EndpointSecurity-equivalents.
- **Transport** (`src/transport/`) — WebSocket client with mTLS + JWT auth.
- **Response** (`src/response/`) — command execution (kill / quarantine / isolate).
- **Analyzers** (`src/analyzers/`) — local hash and entropy analysis.
- **Deception** (`src/deception/`) — honeyfile monitoring.

## Build

Requires a stable Rust toolchain (`rustup`, edition 2021).

```bash
cargo build --release            # native build
cargo build                      # debug build
```

Cross-compilation targets (musl static + ARM) are exercised in CI; see
`.github/workflows/ci.yml`.

> **Windows note:** the `windows` crate features must match your installed
> Windows SDK.

### Optional features

- `yara` — enables YARA scanning (requires `libclang` for the `yara` crate bindings).

## Test

```bash
cargo test
cargo test collectors::process     # a single module
cargo clippy --all-targets         # lint
cargo fmt --check                  # formatting
```

## Run

```bash
RUST_LOG=debug cargo run -- --server wss://localhost:4000/socket/agent
```

Environment variables:

| Variable | Purpose |
|---|---|
| `TAMANDUA_SERVER_URL` | e.g. `wss://localhost:4000/socket/agent` |
| `TAMANDUA_AGENT_ID` | auto-generated UUID if unset |
| `TAMANDUA_TOKEN` | JWT used for agent authentication |

In production, mTLS is required and the certificate CN must match the agent ID.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Please run `cargo fmt`, `cargo clippy`,
and `cargo test` before opening a PR.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
