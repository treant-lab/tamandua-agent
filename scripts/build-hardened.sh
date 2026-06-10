#!/usr/bin/env bash
set -euo pipefail

# Tamandua Agent - Hardened Build Script (Linux/macOS)
# Maximum security configuration for production deployments

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${CYAN}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_info() {
    echo -e "${GRAY}[i]${NC} $1"
}

# Banner
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║         Tamandua Agent - Hardened Build Script           ║
║              Maximum Security Configuration               ║
╚═══════════════════════════════════════════════════════════╝
EOF

# Parse arguments
TARGET="${1:-x86_64-unknown-linux-gnu}"
FEATURES="${2:-}"
CLEAN="${3:-}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux*)
        PLATFORM="linux"
        DEFAULT_TARGET="x86_64-unknown-linux-gnu"
        ;;
    Darwin*)
        PLATFORM="macos"
        DEFAULT_TARGET="x86_64-apple-darwin"
        ;;
    *)
        print_error "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Use default target if not specified
if [ "$TARGET" = "x86_64-unknown-linux-gnu" ] && [ "$PLATFORM" = "macos" ]; then
    TARGET="$DEFAULT_TARGET"
fi

# Verify we're in the correct directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ ! -f "$AGENT_ROOT/Cargo.toml" ]; then
    print_error "Cargo.toml not found. Please run from apps/tamandua_agent/scripts/"
    exit 1
fi

cd "$AGENT_ROOT"

# Check Rust toolchain
print_step "Verifying Rust toolchain..."
if ! command -v rustc &> /dev/null; then
    print_error "Rust toolchain not found. Install from https://rustup.rs/"
    exit 1
fi
RUST_VERSION=$(rustc --version)
print_success "Rust toolchain: $RUST_VERSION"

# Check if nightly
IS_NIGHTLY=false
if [[ "$RUST_VERSION" == *"nightly"* ]]; then
    IS_NIGHTLY=true
    print_success "Detected nightly toolchain - enabling additional hardening"
else
    print_info "Using stable toolchain - some hardening flags require nightly"
fi

# Check for target
print_step "Checking target: $TARGET"
if ! rustup target list --installed | grep -q "^$TARGET$"; then
    print_step "Installing target $TARGET..."
    rustup target add "$TARGET"
fi
print_success "Target $TARGET is available"

# Clean if requested
if [ "$CLEAN" = "--clean" ] || [ "$CLEAN" = "clean" ]; then
    print_step "Cleaning build artifacts..."
    cargo clean --profile release-hardened
    print_success "Clean complete"
fi

# Set RUSTFLAGS for maximum hardening
print_step "Configuring security hardening flags..."

RUSTFLAGS="-C relocation-model=pic"  # Position Independent Code

if [ "$PLATFORM" = "linux" ]; then
    # Linux-specific hardening
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-z,relro"           # Read-only relocations
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-z,now"             # Immediate binding (full RELRO)
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-z,noexecstack"     # Non-executable stack
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--as-needed"        # Only link needed libraries
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--no-undefined"     # No undefined symbols

    # Stack canaries (requires nightly)
    if [ "$IS_NIGHTLY" = true ]; then
        RUSTFLAGS="$RUSTFLAGS -Z stack-protector=all"         # Stack canaries on all functions
    fi

elif [ "$PLATFORM" = "macos" ]; then
    # macOS-specific hardening
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-pie"               # Position Independent Executable
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-dead_strip"        # Remove dead code
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-no_compact_unwind" # Better stack unwinding security

    # Stack canaries (requires nightly)
    if [ "$IS_NIGHTLY" = true ]; then
        RUSTFLAGS="$RUSTFLAGS -Z stack-protector=all"
    fi
fi

export RUSTFLAGS

cat << EOF

${CYAN}Hardening Configuration:${NC}
========================
Profile:        release-hardened
Target:         $TARGET
Platform:       $PLATFORM
Features:       ${FEATURES:-"(default)"}
Toolchain:      $($IS_NIGHTLY && echo "nightly" || echo "stable")

${CYAN}Security Flags Enabled:${NC}
- Position Independent Code (PIC)
EOF

if [ "$PLATFORM" = "linux" ]; then
    cat << EOF
- Full RELRO (immediate binding)
- Non-executable stack
- No undefined symbols
EOF
elif [ "$PLATFORM" = "macos" ]; then
    cat << EOF
- Position Independent Executable (PIE)
- Dead code stripping
EOF
fi

cat << EOF
- Symbol stripping
- Integer overflow checks
- Panic abort (no unwinding)
- Full Link-Time Optimization (LTO)
EOF

if [ "$IS_NIGHTLY" = true ]; then
    echo "- Stack protection (all functions)"
fi

echo ""

# Build command
print_step "Building with hardened profile..."

BUILD_ARGS=(
    "build"
    "--profile" "release-hardened"
    "--target" "$TARGET"
)

if [ -n "$FEATURES" ]; then
    BUILD_ARGS+=("--features" "$FEATURES")
fi

echo -e "${GRAY}Command: cargo ${BUILD_ARGS[*]}${NC}"

BUILD_START=$(date +%s)

if cargo "${BUILD_ARGS[@]}"; then
    BUILD_END=$(date +%s)
    BUILD_TIME=$((BUILD_END - BUILD_START))
    print_success "Build completed in ${BUILD_TIME} seconds"
else
    print_error "Build failed"
    exit 1
fi

# Locate binary
BINARY_NAME="tamandua-agent"
BINARY_PATH="target/$TARGET/release-hardened/$BINARY_NAME"

if [ ! -f "$BINARY_PATH" ]; then
    print_error "Binary not found at expected path: $BINARY_PATH"
    exit 1
fi

# Display binary info
print_step "Binary information:"
BINARY_SIZE=$(stat -f%z "$BINARY_PATH" 2>/dev/null || stat -c%s "$BINARY_PATH" 2>/dev/null)
SIZE_KB=$((BINARY_SIZE / 1024))
SIZE_MB=$((SIZE_KB / 1024))

cat << EOF

${GRAY}Binary Path:    $BINARY_PATH
Size:           $SIZE_KB KB ($SIZE_MB MB)${NC}

EOF

# Verify security features
print_step "Verifying security features..."

if [ "$PLATFORM" = "linux" ]; then
    if command -v checksec &> /dev/null; then
        echo -e "${YELLOW}Security Headers:${NC}"
        checksec --file="$BINARY_PATH" --format=cli
        print_success "Security verification complete"
    else
        print_info "checksec not found - install pax-utils for security verification"

        # Basic checks with readelf
        if command -v readelf &> /dev/null; then
            echo -e "${YELLOW}Basic security checks:${NC}"

            # Check for PIE
            if readelf -h "$BINARY_PATH" | grep -q "Type:.*DYN"; then
                echo -e "${GREEN}✓${NC} PIE enabled"
            else
                echo -e "${RED}✗${NC} PIE not enabled"
            fi

            # Check for RELRO
            if readelf -l "$BINARY_PATH" | grep -q "GNU_RELRO"; then
                echo -e "${GREEN}✓${NC} RELRO enabled"
            else
                echo -e "${RED}✗${NC} RELRO not enabled"
            fi

            # Check for stack canary
            if readelf -s "$BINARY_PATH" | grep -q "__stack_chk_fail"; then
                echo -e "${GREEN}✓${NC} Stack canary enabled"
            else
                echo -e "${YELLOW}!${NC} Stack canary not detected (may require nightly)"
            fi
        fi
    fi

elif [ "$PLATFORM" = "macos" ]; then
    if command -v otool &> /dev/null; then
        echo -e "${YELLOW}Security Headers:${NC}"

        # Check for PIE
        if otool -hv "$BINARY_PATH" | grep -q "PIE"; then
            echo -e "${GREEN}✓${NC} PIE enabled"
        else
            echo -e "${RED}✗${NC} PIE not enabled"
        fi

        # Check for stack canaries
        if otool -I "$BINARY_PATH" | grep -q "___stack_chk"; then
            echo -e "${GREEN}✓${NC} Stack canary enabled"
        else
            echo -e "${YELLOW}!${NC} Stack canary not detected (may require nightly)"
        fi

        print_success "Security verification complete"
    else
        print_info "otool not found - security verification skipped"
    fi
fi

# Generate checksum
print_step "Generating SHA256 checksum..."
if command -v sha256sum &> /dev/null; then
    HASH=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)
    echo "$HASH  $BINARY_NAME" > "$BINARY_PATH.sha256"
elif command -v shasum &> /dev/null; then
    HASH=$(shasum -a 256 "$BINARY_PATH" | cut -d' ' -f1)
    echo "$HASH  $BINARY_NAME" > "$BINARY_PATH.sha256"
else
    print_error "sha256sum/shasum not found - cannot generate checksum"
    exit 1
fi

print_success "Checksum: ${HASH:0:16}..."
echo -e "${GRAY}           Saved to: $BINARY_PATH.sha256${NC}"

# Final summary
cat << EOF

╔═══════════════════════════════════════════════════════════╗
║                  Build Successful!                        ║
╚═══════════════════════════════════════════════════════════╝

${GREEN}Next Steps:${NC}
-----------
1. Test the binary:
   ../target/$TARGET/release-hardened/$BINARY_NAME --version

2. Sign the binary (optional):
EOF

if [ "$PLATFORM" = "macos" ]; then
    cat << EOF
   codesign --sign "Developer ID Application" --options runtime --timestamp $BINARY_PATH
EOF
elif [ "$PLATFORM" = "linux" ]; then
    cat << EOF
   gpg --detach-sign --armor $BINARY_PATH
EOF
fi

cat << EOF

3. Deploy to production environment

EOF

print_success "Hardened build complete!"
