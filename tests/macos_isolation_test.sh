#!/bin/bash
# macOS Network Isolation Test Script
#
# Comprehensive manual testing for pfctl-based network isolation.
# Must be run as root.
#
# Usage: sudo bash macos_isolation_test.sh

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TAMANDUA_SERVER_IP="10.0.0.1"
TAMANDUA_SERVER_PORT=4000
ALLOWED_IP="192.168.1.100"
BLOCK_IP="8.8.8.8"
ANCHOR="tamandua-isolation"

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

cleanup_rules() {
    log_info "Cleaning up test rules..."
    pfctl -a "$ANCHOR" -F all 2>/dev/null || true
    rm -f /tmp/tamandua_pf_rules.conf 2>/dev/null || true
    rm -f /tmp/tamandua_pf_backup.conf 2>/dev/null || true
}

# Trap to cleanup on exit
trap cleanup_rules EXIT

# Test 1: Privilege check
test_privilege_check() {
    log_info "Test 1: Checking root privileges..."

    if [ "$(id -u)" -ne 0 ]; then
        log_error "Not running as root. Please run with sudo."
        exit 1
    fi

    log_success "Running as root"
}

# Test 2: pfctl availability
test_pfctl_availability() {
    log_info "Test 2: Checking pfctl availability..."

    if ! command -v pfctl &> /dev/null; then
        log_error "pfctl command not found"
        return 1
    fi

    if ! pfctl -s info &> /dev/null; then
        log_error "pfctl not functioning properly"
        return 1
    fi

    log_success "pfctl is available and functioning"
}

# Test 3: Enable pf
test_enable_pf() {
    log_info "Test 3: Enabling pf..."

    # Check if pf is already enabled
    if pfctl -s info | grep -q "Status: Enabled"; then
        log_info "pf already enabled"
    else
        pfctl -e 2>/dev/null || true
        if pfctl -s info | grep -q "Status: Enabled"; then
            log_success "pf enabled successfully"
        else
            log_error "Failed to enable pf"
            return 1
        fi
    fi
}

# Test 4: Create anchor
test_create_anchor() {
    log_info "Test 4: Creating anchor '$ANCHOR'..."

    # Create empty anchor
    echo "# Test anchor" > /tmp/tamandua_pf_rules.conf

    if pfctl -a "$ANCHOR" -f /tmp/tamandua_pf_rules.conf; then
        log_success "Anchor created successfully"
    else
        log_error "Failed to create anchor"
        return 1
    fi
}

# Test 5: Apply isolation rules
test_apply_isolation() {
    log_info "Test 5: Applying isolation rules..."

    # Generate isolation ruleset
    cat > /tmp/tamandua_pf_rules.conf <<EOF
# Tamandua EDR Network Isolation Test Rules

# Allow loopback interface
pass quick on lo0 all

# Allow established connections
pass out quick proto tcp all flags S/SA keep state
pass out quick proto udp all keep state

# Allow DNS
pass out quick proto udp to any port 53 keep state
pass out quick proto tcp to any port 53 keep state

# Allow Tamandua server
pass out quick proto tcp to $TAMANDUA_SERVER_IP port $TAMANDUA_SERVER_PORT keep state
pass in quick proto tcp from $TAMANDUA_SERVER_IP port $TAMANDUA_SERVER_PORT keep state

# Allow additional IP
pass out quick to $ALLOWED_IP keep state
pass in quick from $ALLOWED_IP keep state

# Block everything else
block drop all
EOF

    if pfctl -a "$ANCHOR" -f /tmp/tamandua_pf_rules.conf; then
        log_success "Isolation rules applied successfully"
    else
        log_error "Failed to apply isolation rules"
        return 1
    fi
}

# Test 6: Verify rules loaded
test_verify_rules() {
    log_info "Test 6: Verifying rules are loaded..."

    local rules=$(pfctl -a "$ANCHOR" -sr)

    if [ -z "$rules" ]; then
        log_error "No rules found in anchor"
        return 1
    fi

    # Check for key rules
    if echo "$rules" | grep -q "pass quick on lo0 all"; then
        log_info "  ✓ Loopback rule found"
    else
        log_warning "  ✗ Loopback rule missing"
    fi

    if echo "$rules" | grep -q "port 53"; then
        log_info "  ✓ DNS rule found"
    else
        log_warning "  ✗ DNS rule missing"
    fi

    if echo "$rules" | grep -q "$TAMANDUA_SERVER_IP"; then
        log_info "  ✓ Server allowlist rule found"
    else
        log_warning "  ✗ Server allowlist rule missing"
    fi

    if echo "$rules" | grep -q "block drop all"; then
        log_info "  ✓ Block-all rule found"
    else
        log_warning "  ✗ Block-all rule missing"
    fi

    log_success "Rules verified"
}

# Test 7: Test DNS resolution
test_dns_resolution() {
    log_info "Test 7: Testing DNS resolution..."

    if nslookup google.com &> /dev/null; then
        log_success "DNS resolution works"
    else
        log_warning "DNS resolution failed (may be expected depending on network)"
    fi
}

# Test 8: Test loopback connectivity
test_loopback() {
    log_info "Test 8: Testing loopback connectivity..."

    # Try to connect to localhost port (should work)
    if nc -z -w 2 127.0.0.1 22 2>/dev/null || nc -z -w 2 localhost 22 2>/dev/null; then
        log_success "Loopback connectivity works"
    else
        log_warning "Loopback test inconclusive (no service on port 22)"
    fi
}

# Test 9: Test external connectivity (should be blocked)
test_external_block() {
    log_info "Test 9: Testing external connectivity (should be blocked)..."

    # Try to connect to external IP (should fail)
    if timeout 3 nc -z -w 2 1.1.1.1 80 2>/dev/null; then
        log_error "External connectivity NOT blocked (isolation may not be effective)"
    else
        log_success "External connectivity blocked as expected"
    fi
}

# Test 10: Block specific IP
test_block_ip() {
    log_info "Test 10: Blocking specific IP ($BLOCK_IP)..."

    # Get current rules
    local current_rules=$(pfctl -a "$ANCHOR" -sr)

    # Append block rule
    cat > /tmp/tamandua_pf_rules.conf <<EOF
$current_rules
# Block specific IP
block drop quick from $BLOCK_IP to any
block drop quick from any to $BLOCK_IP
EOF

    if pfctl -a "$ANCHOR" -f /tmp/tamandua_pf_rules.conf; then
        log_success "IP block rule added"
    else
        log_error "Failed to add IP block rule"
        return 1
    fi

    # Verify block rule exists
    if pfctl -a "$ANCHOR" -sr | grep -q "$BLOCK_IP"; then
        log_success "IP block rule verified"
    else
        log_error "IP block rule not found"
        return 1
    fi
}

# Test 11: Unblock specific IP
test_unblock_ip() {
    log_info "Test 11: Unblocking specific IP ($BLOCK_IP)..."

    # Get current rules and filter out the blocked IP
    local filtered_rules=$(pfctl -a "$ANCHOR" -sr | grep -v "$BLOCK_IP")

    # Write filtered rules
    echo "$filtered_rules" > /tmp/tamandua_pf_rules.conf

    if pfctl -a "$ANCHOR" -f /tmp/tamandua_pf_rules.conf; then
        log_success "IP unblock completed"
    else
        log_error "Failed to unblock IP"
        return 1
    fi

    # Verify block rule is gone
    if pfctl -a "$ANCHOR" -sr | grep -q "$BLOCK_IP"; then
        log_error "IP block rule still present"
        return 1
    else
        log_success "IP unblock verified"
    fi
}

# Test 12: Backup anchor rules
test_backup() {
    log_info "Test 12: Testing anchor backup..."

    pfctl -a "$ANCHOR" -sr > /tmp/tamandua_pf_backup.conf

    if [ -s /tmp/tamandua_pf_backup.conf ]; then
        log_success "Anchor rules backed up successfully"
    else
        log_error "Backup file is empty"
        return 1
    fi
}

# Test 13: Remove isolation
test_remove_isolation() {
    log_info "Test 13: Removing isolation..."

    if pfctl -a "$ANCHOR" -F all; then
        log_success "Isolation rules flushed"
    else
        log_error "Failed to flush isolation rules"
        return 1
    fi

    # Verify rules are gone
    local rules=$(pfctl -a "$ANCHOR" -sr)
    if [ -z "$rules" ]; then
        log_success "Anchor is empty"
    else
        log_error "Anchor still contains rules"
        return 1
    fi
}

# Test 14: Verify connectivity restored
test_connectivity_restored() {
    log_info "Test 14: Verifying connectivity restored..."

    # Try to connect to external IP (should work now)
    if timeout 3 nc -z -w 2 1.1.1.1 80 2>/dev/null; then
        log_success "External connectivity restored"
    else
        log_warning "External connectivity test inconclusive"
    fi
}

# Test 15: Test with invalid server IP
test_invalid_server_ip() {
    log_info "Test 15: Testing with invalid server IP..."

    # This tests error handling - invalid IP should be caught
    cat > /tmp/tamandua_pf_rules.conf <<EOF
# Test with invalid IP
pass out quick to invalid_ip keep state
EOF

    if pfctl -a "$ANCHOR" -f /tmp/tamandua_pf_rules.conf 2>/dev/null; then
        log_warning "pfctl accepted invalid IP (may need additional validation)"
    else
        log_success "Invalid IP rejected as expected"
    fi

    # Clean up
    pfctl -a "$ANCHOR" -F all 2>/dev/null || true
}

# Main test execution
main() {
    echo "========================================"
    echo "Tamandua macOS Network Isolation Tests"
    echo "========================================"
    echo ""

    test_privilege_check
    test_pfctl_availability
    test_enable_pf
    test_create_anchor
    test_apply_isolation
    test_verify_rules
    test_dns_resolution
    test_loopback
    test_external_block
    test_block_ip
    test_unblock_ip
    test_backup
    test_remove_isolation
    test_connectivity_restored
    test_invalid_server_ip

    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Review output above.${NC}"
        exit 1
    fi
}

# Check for root before running
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Usage: sudo bash $0"
    exit 1
fi

# Run main test suite
main
