# Tamandua EDR Agent - Multi-stage Docker Build
# Base image without eBPF support (for cross-platform compatibility)
#
# Build: docker build -t tamandua-agent:latest .
# Run:   docker run -d --name tamandua-agent tamandua-agent:latest

# =============================================================================
# Build Arguments
# =============================================================================
ARG RUST_VERSION=1.77
ARG TARGET_ARCH=x86_64-unknown-linux-gnu
ARG FEATURES=compression,performance,no-ebpf

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM rust:${RUST_VERSION}-bookworm AS builder

ARG TARGET_ARCH
ARG FEATURES

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    clang \
    llvm \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Set up build environment
WORKDIR /build

# Copy dependency manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Copy xtask workspace member (required for workspace build)
COPY xtask/ ./xtask/

# Create dummy src/main.rs to build dependencies first
RUN mkdir -p src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    echo 'pub fn lib_dummy() {}' > src/lib.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release --features "${FEATURES}" 2>/dev/null || true

# Remove dummy source files
RUN rm -rf src/

# Copy actual source code
COPY src/ ./src/
COPY build.rs ./

# Copy proto files if they exist
COPY proto/ ./proto/ 2>/dev/null || true

# Touch the main.rs to force rebuild with actual source
RUN touch src/main.rs

# Build release binary
RUN cargo build --release --features "${FEATURES}" \
    --target ${TARGET_ARCH} 2>/dev/null || \
    cargo build --release --features "${FEATURES}"

# Strip the binary to reduce size
RUN strip --strip-all /build/target/release/tamandua-agent 2>/dev/null || \
    strip --strip-all /build/target/${TARGET_ARCH}/release/tamandua-agent 2>/dev/null || \
    echo "Binary stripping skipped (cross-compiled or not found)"

# Copy binary to a known location
RUN cp /build/target/release/tamandua-agent /tamandua-agent 2>/dev/null || \
    cp /build/target/${TARGET_ARCH}/release/tamandua-agent /tamandua-agent

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -g 1000 tamandua && \
    useradd -u 1000 -g tamandua -m -s /sbin/nologin tamandua

# Create required directories
RUN mkdir -p /etc/tamandua /var/lib/tamandua && \
    chown -R tamandua:tamandua /etc/tamandua /var/lib/tamandua

# Copy binary from builder
COPY --from=builder /tamandua-agent /usr/local/bin/tamandua-agent

# Set binary permissions
RUN chmod 755 /usr/local/bin/tamandua-agent

# Set environment variables
ENV TAMANDUA_CONFIG_DIR=/etc/tamandua
ENV TAMANDUA_DATA_DIR=/var/lib/tamandua
ENV RUST_LOG=info,tamandua_agent=debug

# Expose metrics port
EXPOSE 9100

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9100/health || exit 1

# Switch to non-root user
USER tamandua

# Set working directory
WORKDIR /var/lib/tamandua

# Labels
LABEL org.opencontainers.image.source="https://github.com/treant-lab/tamandua-agent"
LABEL org.opencontainers.image.description="Tamandua EDR Agent"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Tamandua Security"
LABEL org.opencontainers.image.title="Tamandua Agent"
LABEL org.opencontainers.image.version="0.1.0"

# Entrypoint
ENTRYPOINT ["/usr/local/bin/tamandua-agent"]
