# Makefile for building eBPF programs
#
# Prerequisites:
#   - clang >= 11
#   - llvm >= 11
#   - linux-headers (for kernel headers)
#   - bpftool (optional, for debugging)
#
# Usage:
#   make all          # Build all BPF programs
#   make clean        # Clean build artifacts
#   make install      # Install to /opt/tamandua/bpf/
#   make vmlinux      # Generate vmlinux.h from running kernel

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
BPF_DIR := $(CURDIR)
BUILD_DIR := $(BPF_DIR)/build
INSTALL_DIR := /opt/tamandua/bpf

# Kernel headers
KERNEL_RELEASE := $(shell uname -r)
KERNEL_HEADERS := /lib/modules/$(KERNEL_RELEASE)/build

# BPF programs
BPF_SOURCES := lsm_hooks.bpf.c
BPF_OBJECTS := $(patsubst %.bpf.c,$(BUILD_DIR)/%.o,$(BPF_SOURCES))

# Compiler flags
INCLUDES := -I$(BPF_DIR) -I$(KERNEL_HEADERS)/include -I$(KERNEL_HEADERS)/include/uapi -I$(KERNEL_HEADERS)/arch/$(ARCH)/include/uapi
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -D__BPF_TRACING__ $(INCLUDES)
CFLAGS += -Wall -Werror
CFLAGS += -fno-stack-protector
CFLAGS += -Wno-unused-value -Wno-pointer-sign
CFLAGS += -Wno-compare-distinct-pointer-types
CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
CFLAGS += -Wno-address-of-packed-member
CFLAGS += -Wno-tautological-compare
CFLAGS += -Wno-unknown-warning-option

# Debug flags (uncomment for verbose output)
# CFLAGS += -v

.PHONY: all clean install vmlinux help check-deps

all: check-deps $(BUILD_DIR) $(BPF_OBJECTS)

$(BUILD_DIR):
	@echo "Creating build directory..."
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.bpf.c vmlinux.h
	@echo "Building $@..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "Built: $@"

vmlinux: vmlinux.h

vmlinux.h:
	@echo "Generating vmlinux.h from running kernel..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: BTF not available (/sys/kernel/btf/vmlinux not found)"; \
		echo "Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h.new
	@mv vmlinux.h.new vmlinux.h
	@echo "Generated vmlinux.h ($(shell wc -l < vmlinux.h) lines)"

check-deps:
	@echo "Checking build dependencies..."
	@which $(CLANG) >/dev/null 2>&1 || (echo "ERROR: clang not found"; exit 1)
	@which $(LLVM_STRIP) >/dev/null 2>&1 || (echo "ERROR: llvm-strip not found"; exit 1)
	@$(CLANG) --version | grep -q 'clang version 1[1-9]' || (echo "WARNING: clang >= 11 recommended")
	@echo "Dependencies OK"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

install: all
	@echo "Installing BPF programs to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@cp $(BPF_OBJECTS) $(INSTALL_DIR)/
	@echo "Installed $(words $(BPF_OBJECTS)) BPF programs"

verify:
	@echo "Verifying BPF programs..."
	@for obj in $(BPF_OBJECTS); do \
		echo "Verifying $$obj..."; \
		llvm-objdump -d $$obj | head -20; \
		echo ""; \
	done

help:
	@echo "Tamandua eBPF Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build all BPF programs (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install BPF programs to $(INSTALL_DIR)"
	@echo "  vmlinux      - Generate vmlinux.h from running kernel"
	@echo "  verify       - Verify BPF programs (disassemble)"
	@echo "  check-deps   - Check build dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  CLANG        - C compiler (default: clang)"
	@echo "  LLVM_STRIP   - Strip tool (default: llvm-strip)"
	@echo "  BPFTOOL      - BPF tool (default: bpftool)"
	@echo "  ARCH         - Target architecture (default: auto-detect)"
	@echo ""
	@echo "Examples:"
	@echo "  make all                    # Build all programs"
	@echo "  make CLANG=clang-14 all     # Use specific clang version"
	@echo "  make install                # Build and install"

# Debug target for showing variables
debug:
	@echo "BPF_DIR: $(BPF_DIR)"
	@echo "BUILD_DIR: $(BUILD_DIR)"
	@echo "INSTALL_DIR: $(INSTALL_DIR)"
	@echo "KERNEL_RELEASE: $(KERNEL_RELEASE)"
	@echo "KERNEL_HEADERS: $(KERNEL_HEADERS)"
	@echo "ARCH: $(ARCH)"
	@echo "CLANG: $(CLANG)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "BPF_SOURCES: $(BPF_SOURCES)"
	@echo "BPF_OBJECTS: $(BPF_OBJECTS)"
