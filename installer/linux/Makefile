# Tamandua Agent Linux Package Makefile
#
# Usage:
#   make deb            - Build DEB package
#   make rpm            - Build RPM package
#   make all            - Build both DEB and RPM
#   make docker-all     - Build packages in Docker container
#   make clean          - Clean build artifacts
#   make test-install   - Test package installation in Docker
#
# Variables:
#   VERSION=1.0.0       - Override package version
#   ARCH=amd64          - Target architecture (amd64, arm64)
#   FEATURES=yara,onnx  - Cargo features to enable

SHELL := /bin/bash

# Get version from Cargo.toml by default
VERSION ?= $(shell grep '^version' ../../Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
ARCH ?= amd64
FEATURES ?= compression

# Directories
SCRIPT_DIR := $(shell pwd)
AGENT_DIR := $(SCRIPT_DIR)/../..
DIST_DIR := $(SCRIPT_DIR)/dist
BUILD_DIR := $(SCRIPT_DIR)/build

# Package names
DEB_PACKAGE := tamandua-agent_$(VERSION)_$(ARCH).deb
RPM_PACKAGE := tamandua-agent-$(VERSION)-1.$(shell uname -m).rpm

.PHONY: all deb rpm clean docker-all docker-deb docker-rpm test-install test-deb test-rpm help

# Default target
all: deb rpm

# Build DEB package
deb:
	@echo "Building DEB package v$(VERSION) for $(ARCH)..."
	./build.sh --version $(VERSION) --arch $(ARCH) --features $(FEATURES) --deb-only
	@echo "Package: $(DIST_DIR)/$(DEB_PACKAGE)"

# Build RPM package
rpm:
	@echo "Building RPM package v$(VERSION) for $(ARCH)..."
	./build.sh --version $(VERSION) --arch $(ARCH) --features $(FEATURES) --rpm-only
	@echo "Package: $(DIST_DIR)/tamandua-agent-$(VERSION)-*.rpm"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	@echo "Clean complete"

# Docker-based builds (for cross-platform)
docker-all:
	@echo "Building all packages in Docker..."
	./docker-build.sh --version $(VERSION) --arch $(ARCH)

docker-deb:
	@echo "Building DEB package in Docker..."
	./docker-build.sh --version $(VERSION) --arch $(ARCH) --deb-only

docker-rpm:
	@echo "Building RPM package in Docker..."
	./docker-build.sh --version $(VERSION) --arch $(ARCH) --rpm-only

# Test package installation
test-install: test-deb test-rpm

# Test DEB installation in Ubuntu container
test-deb:
	@echo "Testing DEB package installation..."
	@if [ ! -f "$(DIST_DIR)/$(DEB_PACKAGE)" ]; then \
		echo "DEB package not found. Run 'make deb' first."; \
		exit 1; \
	fi
	docker run --rm -v "$(DIST_DIR):/packages:ro" ubuntu:22.04 bash -c "\
		apt-get update && \
		dpkg -i /packages/$(DEB_PACKAGE) || apt-get install -f -y && \
		tamandua-agent --version && \
		systemctl cat tamandua-agent && \
		echo 'DEB installation test: PASSED'"

# Test RPM installation in Fedora container
test-rpm:
	@echo "Testing RPM package installation..."
	@RPM=$$(ls $(DIST_DIR)/tamandua-agent-$(VERSION)-*.rpm 2>/dev/null | head -1); \
	if [ -z "$$RPM" ]; then \
		echo "RPM package not found. Run 'make rpm' first."; \
		exit 1; \
	fi; \
	docker run --rm -v "$(DIST_DIR):/packages:ro" fedora:39 bash -c "\
		dnf install -y /packages/$$(basename $$RPM) && \
		tamandua-agent --version && \
		systemctl cat tamandua-agent && \
		echo 'RPM installation test: PASSED'"

# Sign packages (requires GPG key)
sign-deb:
	@echo "Signing DEB package..."
	@if [ ! -f "$(DIST_DIR)/$(DEB_PACKAGE)" ]; then \
		echo "DEB package not found. Run 'make deb' first."; \
		exit 1; \
	fi
	dpkg-sig --sign builder $(DIST_DIR)/$(DEB_PACKAGE)

sign-rpm:
	@echo "Signing RPM package..."
	@RPM=$$(ls $(DIST_DIR)/tamandua-agent-$(VERSION)-*.rpm 2>/dev/null | head -1); \
	if [ -z "$$RPM" ]; then \
		echo "RPM package not found. Run 'make rpm' first."; \
		exit 1; \
	fi
	rpm --addsign "$$RPM"

# Help
help:
	@echo "Tamandua Agent Linux Package Builder"
	@echo ""
	@echo "Usage: make [target] [VARIABLE=value]"
	@echo ""
	@echo "Targets:"
	@echo "  all           Build both DEB and RPM packages (default)"
	@echo "  deb           Build DEB package only"
	@echo "  rpm           Build RPM package only"
	@echo "  clean         Remove build artifacts"
	@echo "  docker-all    Build packages in Docker container"
	@echo "  docker-deb    Build DEB in Docker"
	@echo "  docker-rpm    Build RPM in Docker"
	@echo "  test-install  Test package installation"
	@echo "  test-deb      Test DEB installation in Ubuntu container"
	@echo "  test-rpm      Test RPM installation in Fedora container"
	@echo "  sign-deb      Sign DEB package with GPG"
	@echo "  sign-rpm      Sign RPM package with GPG"
	@echo "  help          Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION       Package version (default: from Cargo.toml)"
	@echo "  ARCH          Target architecture: amd64, arm64 (default: amd64)"
	@echo "  FEATURES      Cargo features (default: compression)"
	@echo ""
	@echo "Examples:"
	@echo "  make deb VERSION=1.2.0"
	@echo "  make all ARCH=arm64"
	@echo "  make docker-all VERSION=1.0.0 ARCH=amd64"
