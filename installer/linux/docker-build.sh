#!/bin/bash
#
# Docker-based build script for Tamandua Agent Linux packages
# Builds packages in a container for consistent, reproducible builds
#
# Usage:
#   ./docker-build.sh [OPTIONS]
#
# Options:
#   --version VERSION    Package version (default: from Cargo.toml)
#   --arch ARCH          Target architecture: amd64, arm64 (default: amd64)
#   --deb-only           Build only DEB package
#   --rpm-only           Build only RPM package
#   --no-cache           Build Docker image without cache
#   --push               Push to package repository after build
#   --help               Show this help message
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$AGENT_DIR/../.." && pwd)"

# Default values
VERSION=""
ARCH="amd64"
BUILD_DEB=true
BUILD_RPM=true
NO_CACHE=""
PUSH=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    head -20 "$0" | tail -16
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version) VERSION="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --deb-only) BUILD_RPM=false; shift ;;
        --rpm-only) BUILD_DEB=false; shift ;;
        --no-cache) NO_CACHE="--no-cache"; shift ;;
        --push) PUSH=true; shift ;;
        --help|-h) show_help ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Get version from Cargo.toml
if [ -z "$VERSION" ]; then
    VERSION=$(grep '^version' "$AGENT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi

# Docker image name
IMAGE_NAME="tamandua-agent-builder"

# Create Dockerfile for build
DOCKERFILE="$SCRIPT_DIR/build/Dockerfile.builder"
mkdir -p "$SCRIPT_DIR/build"

cat > "$DOCKERFILE" << 'DOCKERFILE_CONTENT'
# Multi-stage builder for Tamandua Agent Linux packages
FROM rust:1.75-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    dpkg-dev \
    rpm \
    lintian \
    fakeroot \
    devscripts \
    && rm -rf /var/lib/apt/lists/*

# Install additional Rust targets
RUN rustup target add x86_64-unknown-linux-gnu \
    && rustup target add aarch64-unknown-linux-gnu

# For ARM64 cross-compilation
RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*

# Create cargo config for cross-compilation
RUN mkdir -p /root/.cargo && cat > /root/.cargo/config.toml << 'EOF'
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
EOF

WORKDIR /build

# Copy source
COPY . /build/

# Set entrypoint
ENTRYPOINT ["/build/apps/tamandua_agent/installer/linux/build.sh"]
DOCKERFILE_CONTENT

log_info "Building Docker image for package building..."

# Build Docker image
docker build $NO_CACHE -t "$IMAGE_NAME" -f "$DOCKERFILE" "$REPO_ROOT"

# Prepare build arguments
BUILD_ARGS="--version $VERSION --arch $ARCH --output /output"

if [ "$BUILD_DEB" = false ]; then
    BUILD_ARGS="$BUILD_ARGS --rpm-only"
fi

if [ "$BUILD_RPM" = false ]; then
    BUILD_ARGS="$BUILD_ARGS --deb-only"
fi

# Create output directory
OUTPUT_DIR="$SCRIPT_DIR/dist"
mkdir -p "$OUTPUT_DIR"

log_info "Building packages in container..."

# Run build in container
docker run --rm \
    -v "$OUTPUT_DIR:/output" \
    "$IMAGE_NAME" \
    $BUILD_ARGS

log_success "Build complete! Packages are in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

# Optional: Push to repository
if [ "$PUSH" = true ]; then
    log_info "Pushing packages to repository..."
    # Add repository push logic here
    # Examples:
    # - aptly repo add ...
    # - createrepo --update ...
    # - aws s3 cp ...
    log_warn "Package push not configured. Edit docker-build.sh to add repository details."
fi
