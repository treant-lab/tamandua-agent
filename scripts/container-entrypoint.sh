#!/bin/sh
# Tamandua EDR Agent - Container Entrypoint Script
# Detects container runtime, validates eBPF capabilities, and starts the agent.
#
# This script is POSIX sh compatible (no bash-isms) for maximum portability.

set -e

# =============================================================================
# Configuration
# =============================================================================
AGENT_BINARY="/usr/local/bin/tamandua-agent"
DATA_DIR="${TAMANDUA_DATA_DIR:-/var/lib/tamandua}"
CONFIG_DIR="${TAMANDUA_CONFIG_DIR:-/etc/tamandua}"
EBPF_ENABLED="${TAMANDUA_EBPF_ENABLED:-false}"

# =============================================================================
# Logging Functions
# =============================================================================
log_info() {
    printf '[INFO] %s\n' "$1"
}

log_warn() {
    printf '[WARN] %s\n' "$1" >&2
}

log_error() {
    printf '[ERROR] %s\n' "$1" >&2
}

# =============================================================================
# Container Runtime Detection
# =============================================================================
detect_container_runtime() {
    CONTAINER_RUNTIME="unknown"
    CONTAINER_ID=""

    # Check for Docker (creates /.dockerenv)
    if [ -f "/.dockerenv" ]; then
        CONTAINER_RUNTIME="docker"
    # Check for Podman (creates /run/.containerenv)
    elif [ -f "/run/.containerenv" ]; then
        CONTAINER_RUNTIME="podman"
        # Podman stores container ID in /run/.containerenv
        if [ -r "/run/.containerenv" ]; then
            CONTAINER_ID=$(grep -o 'id="[^"]*"' /run/.containerenv 2>/dev/null | cut -d'"' -f2 || true)
        fi
    fi

    # Fallback: check cgroup for container signatures
    if [ "$CONTAINER_RUNTIME" = "unknown" ] && [ -r "/proc/1/cgroup" ]; then
        CGROUP_CONTENT=$(cat /proc/1/cgroup 2>/dev/null || true)

        if echo "$CGROUP_CONTENT" | grep -q "docker"; then
            CONTAINER_RUNTIME="docker"
        elif echo "$CGROUP_CONTENT" | grep -q "podman"; then
            CONTAINER_RUNTIME="podman"
        elif echo "$CGROUP_CONTENT" | grep -q "containerd\|cri-containerd"; then
            CONTAINER_RUNTIME="containerd"
        elif echo "$CGROUP_CONTENT" | grep -q "kubepods"; then
            CONTAINER_RUNTIME="kubernetes"
        elif echo "$CGROUP_CONTENT" | grep -q "lxc"; then
            CONTAINER_RUNTIME="lxc"
        fi

        # Extract container ID from cgroup path (works for Docker, containerd)
        if [ -z "$CONTAINER_ID" ]; then
            CONTAINER_ID=$(echo "$CGROUP_CONTENT" | grep -o '[a-f0-9]\{64\}' | head -1 || true)
            # Shorten to 12 chars like Docker does
            if [ -n "$CONTAINER_ID" ]; then
                CONTAINER_ID=$(echo "$CONTAINER_ID" | cut -c1-12)
            fi
        fi
    fi

    # cgroup v2 fallback
    if [ "$CONTAINER_RUNTIME" = "unknown" ] && [ -r "/proc/1/mountinfo" ]; then
        MOUNTINFO=$(cat /proc/1/mountinfo 2>/dev/null || true)
        if echo "$MOUNTINFO" | grep -q "containers"; then
            CONTAINER_RUNTIME="containerd"
        fi
    fi

    # Export for agent use
    export CONTAINER_RUNTIME
    export CONTAINER_ID
}

# =============================================================================
# eBPF Capability Validation
# =============================================================================
validate_ebpf_capabilities() {
    EBPF_AVAILABLE="true"
    EBPF_WARNINGS=""

    # Check if /sys/fs/bpf is mounted
    if [ ! -d "/sys/fs/bpf" ]; then
        EBPF_AVAILABLE="false"
        EBPF_WARNINGS="${EBPF_WARNINGS}bpffs not mounted at /sys/fs/bpf; "
    elif [ ! -w "/sys/fs/bpf" ]; then
        EBPF_AVAILABLE="false"
        EBPF_WARNINGS="${EBPF_WARNINGS}/sys/fs/bpf not writable; "
    fi

    # Check if debugfs is accessible
    if [ ! -d "/sys/kernel/debug/tracing" ]; then
        EBPF_WARNINGS="${EBPF_WARNINGS}debugfs/tracing not available (kprobes may not work); "
    fi

    # Check for BTF support (required for CO-RE)
    BTF_AVAILABLE="false"
    if [ -f "/sys/kernel/btf/vmlinux" ]; then
        BTF_AVAILABLE="true"
    elif [ -f "/boot/vmlinux-$(uname -r)" ]; then
        BTF_AVAILABLE="true"
    fi

    if [ "$BTF_AVAILABLE" = "false" ]; then
        EBPF_WARNINGS="${EBPF_WARNINGS}BTF not available (CO-RE may not work); "
    fi

    # Check kernel version (eBPF CAP_BPF requires 5.8+)
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

    if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]; }; then
        EBPF_WARNINGS="${EBPF_WARNINGS}kernel ${KERNEL_VERSION} < 5.8 (CAP_BPF not available, using CAP_SYS_ADMIN fallback); "
    fi

    # Try to access /proc (required for process monitoring)
    HOST_PROC="${HOST_PROC:-/proc}"
    if [ ! -d "$HOST_PROC" ] || [ ! -r "$HOST_PROC/1/stat" ]; then
        EBPF_WARNINGS="${EBPF_WARNINGS}procfs not accessible at ${HOST_PROC}; "
    fi

    export EBPF_AVAILABLE
    export BTF_AVAILABLE
}

# =============================================================================
# Directory Setup
# =============================================================================
setup_directories() {
    # Ensure data directory exists and is writable
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR" 2>/dev/null || log_warn "Could not create data directory: $DATA_DIR"
    fi

    if [ ! -w "$DATA_DIR" ]; then
        log_warn "Data directory not writable: $DATA_DIR"
    fi

    # Ensure config directory exists
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR" 2>/dev/null || log_warn "Could not create config directory: $CONFIG_DIR"
    fi
}

# =============================================================================
# Signal Handling
# =============================================================================
# PID of the agent process (set after exec)
AGENT_PID=""

cleanup() {
    log_info "Received shutdown signal, stopping agent..."
    if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill -TERM "$AGENT_PID" 2>/dev/null || true
        # Wait for graceful shutdown (up to 30 seconds)
        WAIT_COUNT=0
        while [ $WAIT_COUNT -lt 30 ] && kill -0 "$AGENT_PID" 2>/dev/null; do
            sleep 1
            WAIT_COUNT=$((WAIT_COUNT + 1))
        done
        # Force kill if still running
        if kill -0 "$AGENT_PID" 2>/dev/null; then
            log_warn "Agent did not stop gracefully, forcing termination"
            kill -KILL "$AGENT_PID" 2>/dev/null || true
        fi
    fi
    exit 0
}

# Trap signals for graceful shutdown
trap cleanup SIGTERM SIGINT SIGHUP

# =============================================================================
# Startup Information
# =============================================================================
log_startup_info() {
    log_info "========================================"
    log_info "Tamandua EDR Agent - Container Startup"
    log_info "========================================"
    log_info "Container Runtime: ${CONTAINER_RUNTIME}"

    if [ -n "$CONTAINER_ID" ]; then
        log_info "Container ID: ${CONTAINER_ID}"
    fi

    log_info "Hostname: $(hostname)"
    log_info "Kernel: $(uname -r)"

    # Mask server URL for security (show only host)
    if [ -n "$TAMANDUA_SERVER_URL" ]; then
        SERVER_HOST=$(echo "$TAMANDUA_SERVER_URL" | sed 's|.*://||' | cut -d'/' -f1 | cut -d':' -f1)
        log_info "Server: ${SERVER_HOST}:****"
    fi

    if [ -n "$TAMANDUA_AGENT_ID" ]; then
        log_info "Agent ID: ${TAMANDUA_AGENT_ID}"
    fi

    if [ "$EBPF_ENABLED" = "true" ]; then
        log_info "eBPF: enabled"
        log_info "eBPF Available: ${EBPF_AVAILABLE}"
        log_info "BTF Available: ${BTF_AVAILABLE}"

        if [ -n "$EBPF_WARNINGS" ]; then
            log_warn "eBPF Warnings: ${EBPF_WARNINGS}"
        fi

        if [ "$EBPF_AVAILABLE" = "false" ]; then
            log_warn "eBPF not fully available - some collectors may be disabled"
            log_warn "Ensure container is running with: --privileged or --cap-add=BPF --cap-add=SYS_ADMIN"
        fi
    else
        log_info "eBPF: disabled"
    fi

    log_info "Config Dir: ${CONFIG_DIR}"
    log_info "Data Dir: ${DATA_DIR}"
    log_info "========================================"
}

# =============================================================================
# Main
# =============================================================================
main() {
    # Detect container runtime
    detect_container_runtime

    # Validate eBPF if enabled
    if [ "$EBPF_ENABLED" = "true" ]; then
        validate_ebpf_capabilities
    fi

    # Setup directories
    setup_directories

    # Log startup information
    log_startup_info

    # Verify agent binary exists
    if [ ! -x "$AGENT_BINARY" ]; then
        log_error "Agent binary not found or not executable: $AGENT_BINARY"
        exit 1
    fi

    log_info "Starting Tamandua agent..."

    # Start agent with exec (replaces shell process)
    # Pass through any command-line arguments
    exec "$AGENT_BINARY" "$@"
}

# Run main with all script arguments
main "$@"
