#!/bin/bash
# notarize.sh - Notarization script for macOS Tamandua Agent
#
# This script handles the complete notarization workflow for macOS:
# 1. Creates a ZIP archive of the app bundle
# 2. Submits to Apple's notary service
# 3. Waits for notarization to complete
# 4. Staples the notarization ticket to the app
# 5. Verifies the notarization was successful
#
# Usage: ./notarize.sh <app-path> <bundle-id>
#
# Required environment variables:
#   APPLE_ID                  - Apple ID email address
#   NOTARYTOOL_APP_PASSWORD   - App-specific password for notarytool
#   APPLE_DEVELOPER_TEAM_ID   - Apple Developer Team ID
#
# Optional environment variables:
#   NOTARIZE_TIMEOUT         - Timeout in minutes (default: 30)
#   NOTARIZE_VERBOSE         - Set to "true" for verbose output
#
# Example:
#   export APPLE_ID="developer@example.com"
#   export NOTARYTOOL_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"
#   export APPLE_DEVELOPER_TEAM_ID="XXXXXXXXXX"
#   ./notarize.sh "./Tamandua.app" "com.tamandua.agent"

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

APP_PATH="${1:-}"
BUNDLE_ID="${2:-}"
TIMEOUT_MINUTES="${NOTARIZE_TIMEOUT:-30}"
VERBOSE="${NOTARIZE_VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

cleanup() {
    # Clean up temporary files
    if [[ -f "${ZIP_PATH:-}" ]]; then
        rm -f "${ZIP_PATH}"
        log_info "Cleaned up temporary ZIP file"
    fi
}

trap cleanup EXIT

usage() {
    echo "Usage: $0 <app-path> <bundle-id>"
    echo ""
    echo "Arguments:"
    echo "  app-path    Path to the .app bundle to notarize"
    echo "  bundle-id   Bundle identifier (e.g., com.tamandua.agent)"
    echo ""
    echo "Required environment variables:"
    echo "  APPLE_ID                  Apple ID email address"
    echo "  NOTARYTOOL_APP_PASSWORD   App-specific password"
    echo "  APPLE_DEVELOPER_TEAM_ID   Apple Developer Team ID"
    echo ""
    echo "Example:"
    echo "  APPLE_ID=dev@example.com NOTARYTOOL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \\"
    echo "    APPLE_DEVELOPER_TEAM_ID=XXXXXXXXXX ./notarize.sh ./App.app com.example.app"
    exit 1
}

validate_environment() {
    local missing_vars=()

    if [[ -z "${APPLE_ID:-}" ]]; then
        missing_vars+=("APPLE_ID")
    fi

    if [[ -z "${NOTARYTOOL_APP_PASSWORD:-}" ]]; then
        missing_vars+=("NOTARYTOOL_APP_PASSWORD")
    fi

    if [[ -z "${APPLE_DEVELOPER_TEAM_ID:-}" ]]; then
        missing_vars+=("APPLE_DEVELOPER_TEAM_ID")
    fi

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        exit 1
    fi

    # Validate app path exists
    if [[ ! -d "${APP_PATH}" ]]; then
        log_error "App bundle not found: ${APP_PATH}"
        exit 1
    fi

    # Check for code signature
    if ! codesign --verify --deep --strict "${APP_PATH}" 2>/dev/null; then
        log_error "App bundle is not properly code signed: ${APP_PATH}"
        log_error "Please sign the app with 'codesign --sign \"Developer ID Application: ...\" --options runtime'"
        exit 1
    fi

    log_success "Environment validated"
}

create_zip() {
    log_info "Creating ZIP archive for notarization..."

    ZIP_PATH="${APP_PATH}.zip"

    # Use ditto to create a proper ZIP that preserves macOS metadata
    ditto -c -k --keepParent "${APP_PATH}" "${ZIP_PATH}"

    if [[ ! -f "${ZIP_PATH}" ]]; then
        log_error "Failed to create ZIP archive"
        exit 1
    fi

    local size
    size=$(du -h "${ZIP_PATH}" | cut -f1)
    log_success "Created ZIP archive: ${ZIP_PATH} (${size})"
}

submit_for_notarization() {
    log_info "Submitting to Apple notary service..."
    log_info "This may take several minutes..."

    local verbose_flag=""
    if [[ "${VERBOSE}" == "true" ]]; then
        verbose_flag="--verbose"
    fi

    # Submit and wait for notarization
    if ! xcrun notarytool submit "${ZIP_PATH}" \
        --apple-id "${APPLE_ID}" \
        --password "${NOTARYTOOL_APP_PASSWORD}" \
        --team-id "${APPLE_DEVELOPER_TEAM_ID}" \
        --wait \
        --timeout "${TIMEOUT_MINUTES}m" \
        ${verbose_flag}; then

        log_error "Notarization failed"

        # Try to get the log for the last submission
        log_info "Attempting to retrieve notarization log..."
        xcrun notarytool log \
            --apple-id "${APPLE_ID}" \
            --password "${NOTARYTOOL_APP_PASSWORD}" \
            --team-id "${APPLE_DEVELOPER_TEAM_ID}" \
            "$(xcrun notarytool history --apple-id "${APPLE_ID}" --password "${NOTARYTOOL_APP_PASSWORD}" --team-id "${APPLE_DEVELOPER_TEAM_ID}" 2>/dev/null | head -2 | tail -1 | awk '{print $1}')" \
            2>/dev/null || true

        exit 1
    fi

    log_success "Notarization completed successfully"
}

staple_ticket() {
    log_info "Stapling notarization ticket to app bundle..."

    if ! xcrun stapler staple "${APP_PATH}"; then
        log_error "Failed to staple notarization ticket"
        exit 1
    fi

    log_success "Notarization ticket stapled successfully"
}

verify_notarization() {
    log_info "Verifying notarization..."

    # Verify with spctl (Gatekeeper)
    if ! spctl --assess --type execute -v "${APP_PATH}" 2>&1; then
        log_error "Gatekeeper assessment failed"
        exit 1
    fi

    # Verify stapling
    if ! xcrun stapler validate "${APP_PATH}"; then
        log_warning "Stapler validation warning (this may be normal)"
    fi

    log_success "Notarization verified successfully"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Tamandua macOS Notarization Script                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # Validate arguments
    if [[ -z "${APP_PATH}" ]] || [[ -z "${BUNDLE_ID}" ]]; then
        usage
    fi

    log_info "App Path:   ${APP_PATH}"
    log_info "Bundle ID:  ${BUNDLE_ID}"
    log_info "Timeout:    ${TIMEOUT_MINUTES} minutes"
    echo ""

    # Run notarization workflow
    validate_environment
    create_zip
    submit_for_notarization
    staple_ticket
    verify_notarization

    echo ""
    log_success "╔══════════════════════════════════════════════════════════════╗"
    log_success "║                 NOTARIZATION COMPLETE                        ║"
    log_success "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "The app bundle is now notarized and ready for distribution."
    log_info "Users will be able to run it without Gatekeeper warnings."
    echo ""
}

main "$@"
