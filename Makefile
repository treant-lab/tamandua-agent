# Tamandua Agent Build System

.PHONY: all build build-release build-ebpf build-ebpf-release install clean

# Default: build everything in debug mode
all: build

# Build agent (without eBPF)
build:
	cargo build

# Build agent with eBPF support
build-ebpf: build-ebpf-programs
	cargo build --features ebpf

# Build in release mode
build-release:
	cargo build --release

# Build everything in release mode with eBPF
build-release-ebpf: build-ebpf-programs-release
	cargo build --release --features ebpf

# Build eBPF programs only (debug)
build-ebpf-programs: check-bpf-linker
	@echo "Building eBPF programs..."
	cd ebpf-programs && cargo +nightly build -Z build-std=core --target bpfel-unknown-none
	@echo "eBPF programs built successfully"

# Build eBPF programs only (release)
build-ebpf-programs-release: check-bpf-linker
	@echo "Building eBPF programs (release)..."
	cd ebpf-programs && cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release
	@echo "eBPF programs built successfully"

# Install eBPF programs
install-ebpf: build-ebpf-programs-release
	@echo "Installing eBPF programs..."
	sudo mkdir -p /opt/tamandua/ebpf
	sudo cp ebpf-programs/target/bpfel-unknown-none/release/tamandua-ebpf /opt/tamandua/ebpf/
	@echo "eBPF programs installed to /opt/tamandua/ebpf/"

# Install agent
install: build-release
	@echo "Installing agent..."
	sudo mkdir -p /opt/tamandua/bin
	sudo cp target/release/tamandua-agent /opt/tamandua/bin/
	@echo "Agent installed to /opt/tamandua/bin/"

# Install everything
install-all: install install-ebpf
	@echo "Full installation complete"

# Check for bpf-linker
check-bpf-linker:
	@which bpf-linker > /dev/null || (echo "bpf-linker not found. Install with: cargo install bpf-linker" && exit 1)

# Install build dependencies
deps:
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker

# Clean build artifacts
clean:
	cargo clean
	cd ebpf-programs && cargo clean || true

# Run tests
test:
	cargo test

# Run clippy
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt -- --check

# Run the agent (development mode)
run:
	RUST_LOG=debug cargo run

# Help
help:
	@echo "Tamandua Agent Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build              - Build agent (debug)"
	@echo "  build-release      - Build agent (release)"
	@echo "  build-ebpf         - Build agent with eBPF support"
	@echo "  build-ebpf-programs - Build eBPF programs only"
	@echo "  install            - Install agent to /opt/tamandua"
	@echo "  install-ebpf       - Install eBPF programs"
	@echo "  install-all        - Install everything"
	@echo "  deps               - Install build dependencies"
	@echo "  clean              - Clean build artifacts"
	@echo "  test               - Run tests"
	@echo "  lint               - Run clippy"
	@echo "  fmt                - Format code"
	@echo "  run                - Run agent in debug mode"
