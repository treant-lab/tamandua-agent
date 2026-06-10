# Contributing to tamandua-agent

This component is part of the Tamandua EDR platform. For the canonical
contribution guide — code of conduct, contribution tracks, and community
norms — see the community repository:

  https://github.com/treant-lab/tamandua-community

Please also read this component's [README](./README.md) for details.

## Component build & test

```bash
cargo build --release
cargo test
cargo clippy --all-targets
cargo fmt --check
```

## Before opening a PR

- Run `cargo fmt`, `cargo clippy`, and `cargo test` before opening a PR.
- Keep changes scoped; avoid unrelated refactors.
- Do not commit secrets or large binaries.
- Do not fabricate or overstate results; preserve benchmark caveats verbatim.
