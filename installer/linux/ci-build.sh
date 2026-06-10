#!/bin/bash
#
# CI/CD build script for Tamandua Agent Linux packages
# Designed for GitHub Actions, GitLab CI, Jenkins, etc.
#
# Environment Variables:
#   TAMANDUA_VERSION     - Package version (required for release builds)
#   TAMANDUA_ARCH        - Target architecture (default: amd64)
#   TAMANDUA_FEATURES    - Cargo features to enable
#   TAMANDUA_SIGNING_KEY - GPG key ID for signing packages
#   AWS_S3_BUCKET        - S3 bucket for package upload
#   PACKAGECLOUD_TOKEN   - Token for packagecloud.io upload
#
# Exit codes:
#   0 - Success
#   1 - Build failed
#   2 - Test failed
#   3 - Upload failed
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration from environment
VERSION="${TAMANDUA_VERSION:-}"
ARCH="${TAMANDUA_ARCH:-amd64}"
FEATURES="${TAMANDUA_FEATURES:-compression}"
SIGNING_KEY="${TAMANDUA_SIGNING_KEY:-}"
S3_BUCKET="${AWS_S3_BUCKET:-}"
PACKAGECLOUD_TOKEN="${PACKAGECLOUD_TOKEN:-}"

# CI detection
CI_SYSTEM="unknown"
if [ -n "${GITHUB_ACTIONS:-}" ]; then
    CI_SYSTEM="github"
    # Get version from tag if not specified
    if [ -z "$VERSION" ] && [ -n "${GITHUB_REF_NAME:-}" ]; then
        VERSION="${GITHUB_REF_NAME#v}"
    fi
elif [ -n "${GITLAB_CI:-}" ]; then
    CI_SYSTEM="gitlab"
    if [ -z "$VERSION" ] && [ -n "${CI_COMMIT_TAG:-}" ]; then
        VERSION="${CI_COMMIT_TAG#v}"
    fi
elif [ -n "${JENKINS_URL:-}" ]; then
    CI_SYSTEM="jenkins"
fi

# Fallback to Cargo.toml version
if [ -z "$VERSION" ]; then
    VERSION=$(grep '^version' "$AGENT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi

echo "=== Tamandua Agent CI Build ==="
echo "CI System: $CI_SYSTEM"
echo "Version: $VERSION"
echo "Architecture: $ARCH"
echo "Features: $FEATURES"
echo ""

# Install dependencies (for Ubuntu/Debian CI runners)
install_deps() {
    echo "Installing build dependencies..."

    if command -v apt-get > /dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            pkg-config \
            libssl-dev \
            dpkg-dev \
            rpm \
            lintian \
            fakeroot
    elif command -v dnf > /dev/null 2>&1; then
        sudo dnf install -y \
            gcc \
            openssl-devel \
            rpm-build \
            dpkg
    fi
}

# Build packages
build_packages() {
    echo "Building packages..."

    cd "$SCRIPT_DIR"

    ./build.sh \
        --version "$VERSION" \
        --arch "$ARCH" \
        --features "$FEATURES" \
        --clean

    echo ""
    echo "Build complete. Packages:"
    ls -la "$SCRIPT_DIR/dist/"
}

# Run package tests
test_packages() {
    echo "Testing packages..."

    local DEB_PKG="$SCRIPT_DIR/dist/tamandua-agent_${VERSION}_${ARCH}.deb"
    local RPM_PKG=$(ls "$SCRIPT_DIR/dist/"tamandua-agent-"${VERSION}"-*.rpm 2>/dev/null | head -1)

    # Test DEB
    if [ -f "$DEB_PKG" ]; then
        echo "Testing DEB package structure..."
        dpkg-deb --info "$DEB_PKG"
        dpkg-deb --contents "$DEB_PKG"

        # Lintian check
        if command -v lintian > /dev/null 2>&1; then
            echo "Running lintian..."
            lintian --no-tag-display-limit "$DEB_PKG" || true
        fi
    fi

    # Test RPM
    if [ -f "$RPM_PKG" ]; then
        echo "Testing RPM package structure..."
        rpm -qip "$RPM_PKG"
        rpm -qlp "$RPM_PKG"
    fi

    echo "Package tests complete."
}

# Sign packages
sign_packages() {
    if [ -z "$SIGNING_KEY" ]; then
        echo "No signing key configured, skipping signing."
        return 0
    fi

    echo "Signing packages with key: $SIGNING_KEY"

    local DEB_PKG="$SCRIPT_DIR/dist/tamandua-agent_${VERSION}_${ARCH}.deb"
    local RPM_PKG=$(ls "$SCRIPT_DIR/dist/"tamandua-agent-"${VERSION}"-*.rpm 2>/dev/null | head -1)

    # Sign DEB
    if [ -f "$DEB_PKG" ] && command -v dpkg-sig > /dev/null 2>&1; then
        dpkg-sig --sign builder -k "$SIGNING_KEY" "$DEB_PKG"
    fi

    # Sign RPM
    if [ -f "$RPM_PKG" ]; then
        rpm --define "_gpg_name $SIGNING_KEY" --addsign "$RPM_PKG"
    fi

    echo "Signing complete."
}

# Upload to S3
upload_s3() {
    if [ -z "$S3_BUCKET" ]; then
        echo "No S3 bucket configured, skipping S3 upload."
        return 0
    fi

    echo "Uploading to S3: $S3_BUCKET"

    aws s3 cp "$SCRIPT_DIR/dist/" "s3://$S3_BUCKET/packages/linux/$VERSION/" \
        --recursive \
        --include "*.deb" \
        --include "*.rpm"

    # Update latest symlink
    aws s3 cp "$SCRIPT_DIR/dist/" "s3://$S3_BUCKET/packages/linux/latest/" \
        --recursive \
        --include "*.deb" \
        --include "*.rpm"

    echo "S3 upload complete."
}

# Upload to packagecloud.io
upload_packagecloud() {
    if [ -z "$PACKAGECLOUD_TOKEN" ]; then
        echo "No packagecloud token configured, skipping packagecloud upload."
        return 0
    fi

    echo "Uploading to packagecloud.io..."

    # Install packagecloud CLI if needed
    if ! command -v package_cloud > /dev/null 2>&1; then
        gem install package_cloud
    fi

    local DEB_PKG="$SCRIPT_DIR/dist/tamandua-agent_${VERSION}_${ARCH}.deb"
    local RPM_PKG=$(ls "$SCRIPT_DIR/dist/"tamandua-agent-"${VERSION}"-*.rpm 2>/dev/null | head -1)

    # Push DEB to multiple Ubuntu/Debian versions
    if [ -f "$DEB_PKG" ]; then
        for distro in ubuntu/focal ubuntu/jammy ubuntu/noble debian/bullseye debian/bookworm; do
            package_cloud push tamandua/agent/$distro "$DEB_PKG" || true
        done
    fi

    # Push RPM to RHEL/Fedora
    if [ -f "$RPM_PKG" ]; then
        for distro in el/8 el/9 fedora/38 fedora/39; do
            package_cloud push tamandua/agent/$distro "$RPM_PKG" || true
        done
    fi

    echo "Packagecloud upload complete."
}

# Generate checksums
generate_checksums() {
    echo "Generating checksums..."

    cd "$SCRIPT_DIR/dist"

    sha256sum *.deb *.rpm 2>/dev/null > SHA256SUMS || true
    sha512sum *.deb *.rpm 2>/dev/null > SHA512SUMS || true

    echo "Checksums:"
    cat SHA256SUMS
}

# Create GitHub release assets
prepare_release_assets() {
    echo "Preparing release assets..."

    local RELEASE_DIR="$SCRIPT_DIR/dist/release"
    mkdir -p "$RELEASE_DIR"

    # Copy packages
    cp "$SCRIPT_DIR/dist/"*.deb "$RELEASE_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/dist/"*.rpm "$RELEASE_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/dist/SHA256SUMS" "$RELEASE_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/dist/SHA512SUMS" "$RELEASE_DIR/" 2>/dev/null || true

    # Create installation instructions
    cat > "$RELEASE_DIR/INSTALL.md" << EOF
# Tamandua Agent v$VERSION Installation

## Debian/Ubuntu (DEB)

\`\`\`bash
# Download
wget https://github.com/treant-lab/tamandua-agent/releases/download/v$VERSION/tamandua-agent_${VERSION}_${ARCH}.deb

# Install
sudo dpkg -i tamandua-agent_${VERSION}_${ARCH}.deb
sudo apt-get install -f  # Install dependencies if needed

# Configure
sudo vi /etc/tamandua/agent.toml

# Start
sudo systemctl start tamandua-agent
sudo systemctl enable tamandua-agent
\`\`\`

## RHEL/CentOS/Fedora (RPM)

\`\`\`bash
# Download
wget https://github.com/treant-lab/tamandua-agent/releases/download/v$VERSION/tamandua-agent-${VERSION}-1.x86_64.rpm

# Install
sudo rpm -i tamandua-agent-${VERSION}-1.x86_64.rpm
# or with dnf:
sudo dnf install tamandua-agent-${VERSION}-1.x86_64.rpm

# Configure
sudo vi /etc/tamandua/agent.toml

# Start
sudo systemctl start tamandua-agent
sudo systemctl enable tamandua-agent
\`\`\`

## Verify Installation

\`\`\`bash
# Check service status
systemctl status tamandua-agent

# View logs
journalctl -u tamandua-agent -f

# Check agent version
tamandua-agent --version
\`\`\`
EOF

    echo "Release assets prepared in: $RELEASE_DIR"
    ls -la "$RELEASE_DIR"
}

# Main
main() {
    local cmd="${1:-all}"

    case "$cmd" in
        deps)
            install_deps
            ;;
        build)
            build_packages
            ;;
        test)
            test_packages
            ;;
        sign)
            sign_packages
            ;;
        upload)
            upload_s3
            upload_packagecloud
            ;;
        checksums)
            generate_checksums
            ;;
        release)
            prepare_release_assets
            ;;
        all)
            install_deps
            build_packages
            test_packages
            generate_checksums
            sign_packages
            ;;
        full)
            install_deps
            build_packages
            test_packages
            generate_checksums
            sign_packages
            upload_s3
            upload_packagecloud
            prepare_release_assets
            ;;
        *)
            echo "Usage: $0 {deps|build|test|sign|upload|checksums|release|all|full}"
            exit 1
            ;;
    esac
}

main "$@"
