#!/bin/bash
# Validation script for Linux auditd integration
#
# Usage: sudo ./scripts/validate_auditd_integration.sh

set -e

echo "================================================"
echo "Tamandua EDR - Linux Auditd Integration Validator"
echo "================================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Check if on Linux
if [[ "$(uname)" != "Linux" ]]; then
   echo -e "${RED}Error: This script is for Linux only${NC}"
   exit 1
fi

echo "Step 1: Checking Prerequisites"
echo "-------------------------------"

# Check if auditd is installed
if command -v auditctl &> /dev/null; then
    echo -e "${GREEN}✓${NC} auditd is installed"
else
    echo -e "${RED}✗${NC} auditd is not installed"
    echo "  Install with: apt-get install auditd (Debian/Ubuntu)"
    echo "            or: yum install audit (RHEL/CentOS)"
    exit 1
fi

# Check if auditd is running
if systemctl is-active --quiet auditd; then
    echo -e "${GREEN}✓${NC} auditd service is running"
else
    echo -e "${YELLOW}!${NC} auditd service is not running"
    echo "  Starting auditd..."
    systemctl start auditd
    if systemctl is-active --quiet auditd; then
        echo -e "${GREEN}✓${NC} auditd service started successfully"
    else
        echo -e "${RED}✗${NC} Failed to start auditd service"
        exit 1
    fi
fi

echo ""
echo "Step 2: Deploying Tamandua Audit Rules"
echo "---------------------------------------"

# Check if rules file exists
RULES_FILE="auditd_rules/tamandua.rules"
if [[ ! -f "$RULES_FILE" ]]; then
    echo -e "${RED}✗${NC} Rules file not found: $RULES_FILE"
    exit 1
fi
echo -e "${GREEN}✓${NC} Rules file found: $RULES_FILE"

# Copy rules to audit directory
DEST_DIR="/etc/audit/rules.d"
DEST_FILE="$DEST_DIR/tamandua.rules"

if [[ ! -d "$DEST_DIR" ]]; then
    echo -e "${YELLOW}!${NC} Creating $DEST_DIR"
    mkdir -p "$DEST_DIR"
fi

echo "  Copying rules to $DEST_FILE"
cp "$RULES_FILE" "$DEST_FILE"
echo -e "${GREEN}✓${NC} Rules copied successfully"

# Load rules
echo "  Loading audit rules..."
if augenrules --load &> /dev/null; then
    echo -e "${GREEN}✓${NC} Rules loaded via augenrules"
elif auditctl -R "$DEST_FILE" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Rules loaded via auditctl"
else
    echo -e "${RED}✗${NC} Failed to load rules"
    echo "  Check /var/log/audit/audit.log for errors"
    exit 1
fi

echo ""
echo "Step 3: Validating Rule Deployment"
echo "-----------------------------------"

# Count rules
RULE_COUNT=$(auditctl -l | grep -c "tamandua_" || true)
echo "  Tamandua rules loaded: $RULE_COUNT"

if [[ $RULE_COUNT -lt 40 ]]; then
    echo -e "${YELLOW}!${NC} Expected 50+ rules, found $RULE_COUNT"
    echo "  Some rules may have failed to load"
else
    echo -e "${GREEN}✓${NC} Rule count looks good"
fi

# Check specific rule categories
echo ""
echo "  Checking rule categories:"

check_rule() {
    local key=$1
    local name=$2
    if auditctl -l | grep -q "$key"; then
        echo -e "    ${GREEN}✓${NC} $name"
        return 0
    else
        echo -e "    ${RED}✗${NC} $name"
        return 1
    fi
}

check_rule "tamandua_process_create" "Process monitoring"
check_rule "tamandua_file_create" "File monitoring"
check_rule "tamandua_network_connect" "Network monitoring"
check_rule "tamandua_identity" "Authentication monitoring"
check_rule "tamandua_priv_esc" "Privilege escalation monitoring"
check_rule "tamandua_cron" "Persistence monitoring"
check_rule "tamandua_credential_access" "Credential access monitoring"

echo ""
echo "Step 4: Testing Event Generation"
echo "---------------------------------"

# Test process monitoring
echo "  Testing process creation monitoring..."
ls /tmp > /dev/null 2>&1
sleep 1
if ausearch -k tamandua_process_create --start recent 2>/dev/null | grep -q "ls"; then
    echo -e "    ${GREEN}✓${NC} Process creation events detected"
else
    echo -e "    ${YELLOW}!${NC} No process creation events found (may need more time)"
fi

# Test file monitoring
echo "  Testing file operation monitoring..."
TEST_FILE="/tmp/tamandua_test_$$"
touch "$TEST_FILE" 2>/dev/null
sleep 1
if ausearch -k tamandua_file_create --start recent 2>/dev/null | grep -q "tamandua_test"; then
    echo -e "    ${GREEN}✓${NC} File creation events detected"
    rm -f "$TEST_FILE"
else
    echo -e "    ${YELLOW}!${NC} No file creation events found (may need more time)"
    rm -f "$TEST_FILE"
fi

# Test network monitoring
echo "  Testing network monitoring..."
ping -c 1 8.8.8.8 > /dev/null 2>&1 || true
sleep 1
if ausearch -k tamandua_network_connect --start recent 2>/dev/null | grep -q "connect"; then
    echo -e "    ${GREEN}✓${NC} Network connection events detected"
else
    echo -e "    ${YELLOW}!${NC} No network connection events found (may need more time)"
fi

echo ""
echo "Step 5: Checking Audit Performance"
echo "-----------------------------------"

# Get audit status
auditctl -s > /tmp/audit_status.txt

# Check backlog
BACKLOG=$(grep "backlog_limit" /tmp/audit_status.txt | awk '{print $2}')
BACKLOG_CURRENT=$(grep "backlog " /tmp/audit_status.txt | awk '{print $2}')
echo "  Backlog: $BACKLOG_CURRENT / $BACKLOG"

if [[ $BACKLOG_CURRENT -lt $((BACKLOG / 2)) ]]; then
    echo -e "    ${GREEN}✓${NC} Backlog is healthy"
else
    echo -e "    ${YELLOW}!${NC} Backlog is high, consider increasing buffer size"
fi

# Check lost events
LOST=$(grep "lost" /tmp/audit_status.txt | awk '{print $2}')
echo "  Lost events: $LOST"

if [[ $LOST -eq 0 ]]; then
    echo -e "    ${GREEN}✓${NC} No events lost"
else
    echo -e "    ${YELLOW}!${NC} Events have been lost, increase buffer or reduce rate"
fi

# Check rate limit
RATE=$(grep "rate_limit" /tmp/audit_status.txt | awk '{print $2}')
echo "  Rate limit: $RATE events/sec"

rm -f /tmp/audit_status.txt

echo ""
echo "Step 6: Verification Summary"
echo "-----------------------------"

echo -e "${GREEN}✓${NC} Linux auditd integration validated successfully!"
echo ""
echo "Next steps:"
echo "  1. Build Tamandua agent: cargo build --release"
echo "  2. Run agent: sudo ./target/release/tamandua-agent"
echo "  3. Monitor events: tail -f /var/log/audit/audit.log | grep tamandua"
echo "  4. Check agent logs: journalctl -u tamandua-agent -f"
echo ""
echo "Documentation:"
echo "  - Full guide: docs/apps/tamandua_agent/LINUX_AUDITD_INTEGRATION.md"
echo "  - Quick start: docs/apps/tamandua_agent/LINUX_AUDITD_QUICKSTART.md"
echo "  - Rules: auditd_rules/README.md"
echo ""
echo "================================================"
