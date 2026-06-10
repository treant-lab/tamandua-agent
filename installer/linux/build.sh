#!/bin/bash
#
# Tamandua Agent Linux Package Builder
# Builds DEB and RPM packages for enterprise deployment
#
# Usage:
#   ./build.sh [OPTIONS]
#
# Options:
#   --version VERSION    Package version (default: from Cargo.toml)
#   --arch ARCH          Target architecture: amd64, arm64 (default: amd64)
#   --target TARGET      Rust target triple (auto-detected from arch)
#   --deb-only           Build only DEB package
#   --rpm-only           Build only RPM package
#   --skip-build         Skip Rust compilation (use existing binary)
#   --features FEATURES  Cargo features to enable (comma-separated)
#   --output DIR         Output directory for packages (default: ./dist)
#   --clean              Clean build artifacts before building
#   --help               Show this help message
#

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$AGENT_DIR/../.." && pwd)"

# Default values
VERSION=""
ARCH="amd64"
TARGET=""
BUILD_DEB=true
BUILD_RPM=true
SKIP_BUILD=false
FEATURES="compression"
OUTPUT_DIR="$SCRIPT_DIR/dist"
CLEAN=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    head -25 "$0" | tail -21
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --deb-only)
            BUILD_RPM=false
            shift
            ;;
        --rpm-only)
            BUILD_DEB=false
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --features)
            FEATURES="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            ;;
    esac
done

# Detect version from Cargo.toml if not specified
if [ -z "$VERSION" ]; then
    VERSION=$(grep '^version' "$AGENT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
    log_info "Detected version from Cargo.toml: $VERSION"
fi

# Map architecture to Rust target
case "$ARCH" in
    amd64|x86_64)
        ARCH="amd64"
        TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
        RPM_ARCH="x86_64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        TARGET="${TARGET:-aarch64-unknown-linux-gnu}"
        RPM_ARCH="aarch64"
        ;;
    *)
        log_error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

log_info "Building Tamandua Agent v$VERSION for $ARCH ($TARGET)"

# Build directories
BUILD_DIR="$SCRIPT_DIR/build"
DEB_BUILD_DIR="$BUILD_DIR/deb"
RPM_BUILD_DIR="$BUILD_DIR/rpm"
STAGING_DIR="$BUILD_DIR/staging"

# Clean if requested
if [ "$CLEAN" = true ]; then
    log_info "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    rm -rf "$OUTPUT_DIR"
fi

# Create directories
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$STAGING_DIR"

# Build the Rust binary
build_binary() {
    log_info "Building Rust binary..."

    cd "$AGENT_DIR"

    # Check if target is installed
    if ! rustup target list --installed | grep -q "$TARGET"; then
        log_info "Installing Rust target: $TARGET"
        rustup target add "$TARGET"
    fi

    # Build with release profile
    CARGO_FEATURES=""
    if [ -n "$FEATURES" ]; then
        CARGO_FEATURES="--features $FEATURES"
    fi

    cargo build --release --target "$TARGET" $CARGO_FEATURES

    BINARY_PATH="$AGENT_DIR/target/$TARGET/release/tamandua-agent"

    if [ ! -f "$BINARY_PATH" ]; then
        log_error "Binary not found at: $BINARY_PATH"
        exit 1
    fi

    # Copy to staging
    cp "$BINARY_PATH" "$STAGING_DIR/tamandua-agent"

    log_success "Binary built: $BINARY_PATH"
}

# Prepare common files
prepare_files() {
    log_info "Preparing package files..."

    # Copy config example
    cp "$AGENT_DIR/config/agent.toml" "$STAGING_DIR/agent.toml.example"

    # Copy systemd service
    cp "$SCRIPT_DIR/tamandua-agent.service" "$STAGING_DIR/"

    # Copy license and readme if they exist
    if [ -f "$REPO_ROOT/LICENSE" ]; then
        cp "$REPO_ROOT/LICENSE" "$STAGING_DIR/"
    else
        # Create Apache 2.0 license placeholder
        cat > "$STAGING_DIR/LICENSE" << 'EOF'
Apache License, Version 2.0

Copyright 2024-2026 Tamandua Security

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
EOF
    fi

    if [ -f "$AGENT_DIR/README.md" ]; then
        cp "$AGENT_DIR/README.md" "$STAGING_DIR/"
    else
        cat > "$STAGING_DIR/README.md" << 'EOF'
# Tamandua EDR Agent

Endpoint Detection and Response agent for Linux systems.

## Configuration

Edit `/etc/tamandua/agent.toml` to configure the agent.

## Service Management

```bash
# Start the agent
sudo systemctl start tamandua-agent

# Check status
sudo systemctl status tamandua-agent

# View logs
journalctl -u tamandua-agent -f
```

## Documentation

See https://github.com/treant-lab/tamandua-agent for full documentation.
EOF
    fi

    log_success "Files prepared in staging directory"
}

# Build DEB package
build_deb() {
    log_info "Building DEB package..."

    local DEB_NAME="tamandua-agent_${VERSION}_${ARCH}"
    local DEB_ROOT="$DEB_BUILD_DIR/$DEB_NAME"

    # Clean and create directory structure
    rm -rf "$DEB_ROOT"
    mkdir -p "$DEB_ROOT/DEBIAN"
    mkdir -p "$DEB_ROOT/usr/bin"
    mkdir -p "$DEB_ROOT/etc/tamandua"
    mkdir -p "$DEB_ROOT/usr/lib/systemd/system"
    mkdir -p "$DEB_ROOT/var/lib/tamandua/cache"
    mkdir -p "$DEB_ROOT/var/lib/tamandua/quarantine"
    mkdir -p "$DEB_ROOT/var/lib/tamandua/rules/yara"
    mkdir -p "$DEB_ROOT/var/lib/tamandua/rules/sigma"
    mkdir -p "$DEB_ROOT/var/log/tamandua"
    mkdir -p "$DEB_ROOT/usr/share/doc/tamandua-agent"

    # Copy binary
    cp "$STAGING_DIR/tamandua-agent" "$DEB_ROOT/usr/bin/"
    chmod 755 "$DEB_ROOT/usr/bin/tamandua-agent"

    # Copy config
    cp "$STAGING_DIR/agent.toml.example" "$DEB_ROOT/etc/tamandua/"
    chmod 640 "$DEB_ROOT/etc/tamandua/agent.toml.example"

    # Copy systemd service
    cp "$STAGING_DIR/tamandua-agent.service" "$DEB_ROOT/usr/lib/systemd/system/"
    chmod 644 "$DEB_ROOT/usr/lib/systemd/system/tamandua-agent.service"

    # Copy documentation
    cp "$STAGING_DIR/LICENSE" "$DEB_ROOT/usr/share/doc/tamandua-agent/"
    cp "$STAGING_DIR/README.md" "$DEB_ROOT/usr/share/doc/tamandua-agent/"

    # Process control file (substitute variables)
    sed -e "s/\${VERSION}/$VERSION/g" \
        -e "s/\${ARCH}/$ARCH/g" \
        "$SCRIPT_DIR/debian/control" > "$DEB_ROOT/DEBIAN/control"

    # Copy maintainer scripts
    cp "$SCRIPT_DIR/debian/postinst" "$DEB_ROOT/DEBIAN/"
    cp "$SCRIPT_DIR/debian/prerm" "$DEB_ROOT/DEBIAN/"
    cp "$SCRIPT_DIR/debian/postrm" "$DEB_ROOT/DEBIAN/"
    cp "$SCRIPT_DIR/debian/conffiles" "$DEB_ROOT/DEBIAN/"

    chmod 755 "$DEB_ROOT/DEBIAN/postinst"
    chmod 755 "$DEB_ROOT/DEBIAN/prerm"
    chmod 755 "$DEB_ROOT/DEBIAN/postrm"
    chmod 644 "$DEB_ROOT/DEBIAN/conffiles"
    chmod 644 "$DEB_ROOT/DEBIAN/control"

    # Calculate installed size
    INSTALLED_SIZE=$(du -sk "$DEB_ROOT" | cut -f1)
    echo "Installed-Size: $INSTALLED_SIZE" >> "$DEB_ROOT/DEBIAN/control"

    # Build the package
    DEB_FILE="$OUTPUT_DIR/${DEB_NAME}.deb"
    dpkg-deb --build --root-owner-group "$DEB_ROOT" "$DEB_FILE"

    log_success "DEB package created: $DEB_FILE"

    # Verify package
    if command -v lintian > /dev/null 2>&1; then
        log_info "Running lintian checks..."
        lintian --no-tag-display-limit "$DEB_FILE" || true
    fi
}

# Build RPM package
build_rpm() {
    log_info "Building RPM package..."

    local RPM_NAME="tamandua-agent-${VERSION}"

    # Create RPM build directory structure
    rm -rf "$RPM_BUILD_DIR"
    mkdir -p "$RPM_BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Create source tarball
    local TARBALL_DIR="$RPM_BUILD_DIR/SOURCES/$RPM_NAME"
    mkdir -p "$TARBALL_DIR"

    cp "$STAGING_DIR/tamandua-agent" "$TARBALL_DIR/"
    cp "$STAGING_DIR/agent.toml.example" "$TARBALL_DIR/"
    cp "$STAGING_DIR/tamandua-agent.service" "$TARBALL_DIR/"
    cp "$STAGING_DIR/LICENSE" "$TARBALL_DIR/"
    cp "$STAGING_DIR/README.md" "$TARBALL_DIR/"

    # Create tarball
    cd "$RPM_BUILD_DIR/SOURCES"
    tar czf "${RPM_NAME}.tar.gz" "$RPM_NAME"
    rm -rf "$RPM_NAME"

    # Copy spec file
    cp "$SCRIPT_DIR/rpm/tamandua-agent.spec" "$RPM_BUILD_DIR/SPECS/"

    # Build RPM
    cd "$RPM_BUILD_DIR"
    rpmbuild --define "_topdir $RPM_BUILD_DIR" \
             --define "version $VERSION" \
             --target "$RPM_ARCH" \
             -bb SPECS/tamandua-agent.spec

    # Copy RPM to output
    RPM_FILE=$(find "$RPM_BUILD_DIR/RPMS" -name "*.rpm" -type f | head -1)
    if [ -n "$RPM_FILE" ]; then
        cp "$RPM_FILE" "$OUTPUT_DIR/"
        log_success "RPM package created: $OUTPUT_DIR/$(basename "$RPM_FILE")"
    else
        log_error "RPM build failed - no RPM file found"
        exit 1
    fi
}

# Main build process
main() {
    log_info "Starting package build process..."
    log_info "  Version: $VERSION"
    log_info "  Architecture: $ARCH"
    log_info "  Target: $TARGET"
    log_info "  Features: $FEATURES"
    log_info "  Output: $OUTPUT_DIR"

    # Check required tools
    if [ "$BUILD_DEB" = true ] && ! command -v dpkg-deb > /dev/null 2>&1; then
        log_error "dpkg-deb not found. Install: sudo apt-get install dpkg-dev"
        exit 1
    fi

    if [ "$BUILD_RPM" = true ] && ! command -v rpmbuild > /dev/null 2>&1; then
        log_error "rpmbuild not found. Install: sudo apt-get install rpm or sudo dnf install rpm-build"
        exit 1
    fi

    # Build binary
    if [ "$SKIP_BUILD" = false ]; then
        build_binary
    else
        log_warn "Skipping binary build (using existing binary)"
        if [ ! -f "$STAGING_DIR/tamandua-agent" ]; then
            BINARY_PATH="$AGENT_DIR/target/$TARGET/release/tamandua-agent"
            if [ -f "$BINARY_PATH" ]; then
                cp "$BINARY_PATH" "$STAGING_DIR/tamandua-agent"
            else
                log_error "No binary found. Run without --skip-build first."
                exit 1
            fi
        fi
    fi

    # Prepare common files
    prepare_files

    # Build packages
    if [ "$BUILD_DEB" = true ]; then
        build_deb
    fi

    if [ "$BUILD_RPM" = true ]; then
        build_rpm
    fi

    # Summary
    echo ""
    log_success "Build complete!"
    echo ""
    log_info "Packages created in: $OUTPUT_DIR"
    ls -la "$OUTPUT_DIR"/*.{deb,rpm} 2>/dev/null || true
    echo ""

    # Installation instructions
    if [ "$BUILD_DEB" = true ]; then
        echo "DEB Installation:"
        echo "  sudo dpkg -i $OUTPUT_DIR/tamandua-agent_${VERSION}_${ARCH}.deb"
        echo "  sudo apt-get install -f  # Install dependencies if needed"
        echo ""
    fi

    if [ "$BUILD_RPM" = true ]; then
        echo "RPM Installation:"
        echo "  sudo rpm -i $OUTPUT_DIR/tamandua-agent-${VERSION}-*.rpm"
        echo "  # or with dnf/yum:"
        echo "  sudo dnf install $OUTPUT_DIR/tamandua-agent-${VERSION}-*.rpm"
        echo ""
    fi
}

# Run main
main
