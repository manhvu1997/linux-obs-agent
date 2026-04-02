# ──────────────────────────────────────────────────────────────────────────────
# Makefile for linux-obs-agent
#
# Targets:
#   make generate   – compile eBPF C programs and generate Go scaffolding
#   make build      – build the obs-agent binary
#   make all        – generate + build
#   make vmlinux    – download/generate vmlinux.h via bpftool
#   make clean      – remove build artifacts
#   make lint       – run golangci-lint
#   make image      – build Docker image
# ──────────────────────────────────────────────────────────────────────────────

BINARY        := obs-agent
BUILD_DIR     := ./build
CMD_DIR       := ./cmd/agent
HEADERS_DIR   := ./internal/ebpf/headers

# Compiler settings
CLANG         ?= clang
LLVM_STRIP    ?= llvm-strip
CFLAGS        := -O2 -g -Wall -Werror -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Go settings
GO            ?= go
GOFLAGS       ?=
CGO_ENABLED   := 0
GOOS          := linux

# Image settings
IMAGE_REPO    ?= ghcr.io/youorg/obs-agent
IMAGE_TAG     ?= latest

.PHONY: all generate build clean lint image vmlinux deps

# ─── Default ──────────────────────────────────────────────────────────────────

all: generate build

# ─── Dependencies ─────────────────────────────────────────────────────────────

deps:
	$(GO) mod download
	$(GO) get -tool github.com/cilium/ebpf/cmd/bpf2go

# ─── vmlinux.h ────────────────────────────────────────────────────────────────
# vmlinux.h is generated from the running kernel's BTF data.
# It provides all kernel struct definitions for CO-RE (Compile Once, Run Everywhere).
# Alternative: download a pre-built one from https://github.com/aquasecurity/btfhub-archive

vmlinux:
	@echo ">>> Generating vmlinux.h from running kernel"
	@mkdir -p $(HEADERS_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS_DIR)/vmlinux.h 2>/dev/null || \
		echo "Warning: bpftool vmlinux generation failed – using pre-built headers"
	@echo ">>> Done: $(HEADERS_DIR)/vmlinux.h"

# ─── eBPF code generation ─────────────────────────────────────────────────────
# bpf2go:
#   1. Compiles each .bpf.c with clang to a .o (little-endian and big-endian)
#   2. Embeds the .o as a Go []byte in generated _bpfel.go / _bpfeb.go files
#   3. Generates type-safe Go structs for maps and programs

generate: deps
	@echo ">>> Generating eBPF Go scaffolding"
	@# Ensure vmlinux.h exists
	@if [ ! -f $(HEADERS_DIR)/vmlinux.h ]; then \
		echo ">>> vmlinux.h not found, generating..."; \
		$(MAKE) vmlinux; \
	fi
	CC=$(CLANG) $(GO) generate ./internal/ebpf/...
	@echo ">>> Generation complete"

# ─── Build ────────────────────────────────────────────────────────────────────

build:
	@echo ">>> Building $(BINARY)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) \
		$(GO) build $(GOFLAGS) \
		-ldflags "-s -w \
			-X main.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) \
			-X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
			-X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
		-o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)
	@echo ">>> Binary: $(BUILD_DIR)/$(BINARY)"
	@ls -lh $(BUILD_DIR)/$(BINARY)

# ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD_DIR)
	find . -name '*_bpfel.go' -o -name '*_bpfeb.go' \
	       -o -name '*_bpfel.o' -o -name '*_bpfeb.o' | xargs rm -f

# ─── Lint ─────────────────────────────────────────────────────────────────────

lint:
	golangci-lint run ./...

# ─── Docker image ─────────────────────────────────────────────────────────────
# Multi-stage: builder image has clang/llvm for eBPF compilation.

image:
	docker build -t $(IMAGE_REPO):$(IMAGE_TAG) \
		--build-arg VERSION=$(shell git describe --tags --always) \
		-f deploy/Dockerfile .

# ─── Install (to /usr/local/bin) ─────────────────────────────────────────────

install: build
	sudo install -m 0755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	sudo mkdir -p /etc/obs-agent
	sudo install -m 0644 deploy/config.yaml.example /etc/obs-agent/config.yaml
	sudo install -m 0644 deploy/obs-agent.service /etc/systemd/system/obs-agent.service
	sudo systemctl daemon-reload
	@echo ">>> Installed. Run: sudo systemctl enable --now obs-agent"
