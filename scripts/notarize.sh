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
#   NOTARIZE_REQUIRE_ENDPOINT_SECURITY
#                            - Require EndpointSecurity entitlement (default: true)
#   NOTARIZE_REQUIRE_SYSTEM_EXTENSION
#                            - Require a bundled .systemextension (default: true)
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
REQUIRE_ENDPOINT_SECURITY="${NOTARIZE_REQUIRE_ENDPOINT_SECURITY:-true}"
REQUIRE_SYSTEM_EXTENSION="${NOTARIZE_REQUIRE_SYSTEM_EXTENSION:-true}"
ENDPOINT_SECURITY_ENTITLEMENT="com.apple.developer.endpoint-security.client"
SYSTEM_EXTENSION_INSTALL_ENTITLEMENT="com.apple.developer.system-extension.install"

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

app_executable_path() {
    local executable_name
    executable_name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "${APP_PATH}/Contents/Info.plist" 2>/dev/null || true)
    if [[ -z "${executable_name}" ]]; then
        log_error "Could not read CFBundleExecutable from ${APP_PATH}/Contents/Info.plist"
        exit 1
    fi
    printf '%s/Contents/MacOS/%s\n' "${APP_PATH}" "${executable_name}"
}

require_endpointsecurity_entitlement() {
    local target_path="$1"
    local target_label="$2"
    local entitlements

    if [[ ! -e "${target_path}" ]]; then
        log_error "${target_label} not found: ${target_path}"
        exit 1
    fi

    entitlements=$(codesign -d --entitlements :- "${target_path}" 2>/dev/null || true)
    if echo "${entitlements}" | grep -q "${ENDPOINT_SECURITY_ENTITLEMENT}"; then
        log_success "${target_label} has ${ENDPOINT_SECURITY_ENTITLEMENT}"
    else
        log_error "${target_label} is missing ${ENDPOINT_SECURITY_ENTITLEMENT}"
        log_error "A notarized macOS EDR bundle without this entitlement can install but will report degraded sensor health."
        exit 1
    fi
}

require_system_extension_install_entitlement() {
    local target_path="$1"
    local target_label="$2"
    local entitlements

    if [[ ! -e "${target_path}" ]]; then
        log_error "${target_label} not found: ${target_path}"
        exit 1
    fi

    entitlements=$(codesign -d --entitlements :- "${target_path}" 2>/dev/null || true)
    if echo "${entitlements}" | grep -q "${SYSTEM_EXTENSION_INSTALL_ENTITLEMENT}"; then
        log_success "${target_label} has ${SYSTEM_EXTENSION_INSTALL_ENTITLEMENT}"
    else
        log_error "${target_label} is missing ${SYSTEM_EXTENSION_INSTALL_ENTITLEMENT}"
        log_error "A notarized macOS EDR bundle without this entitlement cannot install the bundled System Extension."
        exit 1
    fi
}

verify_endpointsecurity_entitlements() {
    if [[ "${REQUIRE_ENDPOINT_SECURITY}" != "true" ]]; then
        log_warning "Skipping EndpointSecurity entitlement verification"
        return
    fi

    local executable_path
    executable_path=$(app_executable_path)
    require_endpointsecurity_entitlement "${executable_path}" "App executable"
    require_system_extension_install_entitlement "${executable_path}" "App executable"

    local sysext_root="${APP_PATH}/Contents/Library/SystemExtensions"
    local found_sysext=false
    if [[ -d "${sysext_root}" ]]; then
        while IFS= read -r -d '' sysext_path; do
            found_sysext=true
            require_endpointsecurity_entitlement "${sysext_path}" "System Extension $(basename "${sysext_path}")"
            require_system_extension_install_entitlement "${sysext_path}" "System Extension $(basename "${sysext_path}")"
        done < <(find "${sysext_root}" -maxdepth 1 -type d -name '*.systemextension' -print0)
    fi
    if [[ "${found_sysext}" != "true" ]]; then
        if [[ "${REQUIRE_SYSTEM_EXTENSION}" == "true" ]]; then
            log_error "No .systemextension bundle found under ${sysext_root}"
            log_error "A release macOS EDR app without the Tamandua System Extension cannot satisfy sensor health."
            exit 1
        fi
        log_warning "No .systemextension bundle found; continuing because NOTARIZE_REQUIRE_SYSTEM_EXTENSION is not true"
    fi
}

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

    verify_endpointsecurity_entitlements

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

    # Verify stapling. Release macOS artifacts must be locally verifiable; an
    # unstapled ticket can leave lab installs dependent on network lookup and
    # makes readiness failures harder to distinguish from entitlement issues.
    if ! xcrun stapler validate "${APP_PATH}"; then
        log_error "Stapled notarization ticket validation failed"
        exit 1
    fi

    verify_endpointsecurity_entitlements

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
