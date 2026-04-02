# ──────────────────────────────────────────────────────────────────────────────
# Multi-stage Dockerfile for linux-obs-agent
#
# Stage 1 (builder): Ubuntu with clang/llvm/libbpf + Go toolchain
#   Compiles eBPF C programs → .o objects (embedded in binary via bpf2go)
#   Builds the Go binary (static, no CGO)
#
# Stage 2 (runtime): distroless/static for minimal attack surface
#   <10MB final image, no shell, no package manager
# ──────────────────────────────────────────────────────────────────────────────

# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM --platform=linux/amd64 ubuntu:24.04 AS builder

ARG VERSION=dev
ARG TARGETARCH=amd64

# Install build dependencies
RUN apt-get update \
    && apt-get install -y software-properties-common \
    && add-apt-repository ppa:longsleep/golang-backports \
    && apt-get install -y --no-install-recommends \
    # eBPF toolchain
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    linux-tools-generic \
    linux-image-generic \
    # Go toolchain
    golang-1.26 \
    # Utilities
    ca-certificates \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

# symlink so `go` is on PATH
RUN ln -sf /usr/lib/go-1.26/bin/go /usr/local/bin/go

# linux-tools-generic puts bpftool under a versioned subdir; symlink to PATH
RUN BPFTOOL=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -1) \
    && [ -n "$BPFTOOL" ] && ln -sf "$BPFTOOL" /usr/local/bin/bpftool || true

WORKDIR /build

# Cache Go module downloads as a separate layer
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Ensure go.sum is complete (handles the case where go.sum is missing or stale).
RUN go mod tidy

# Generate vmlinux.h from the kernel BTF.
# In docker build, /sys/kernel/btf/vmlinux is not accessible, so we fall back to
# extracting BTF from the vmlinuz shipped by linux-image-generic.
RUN mkdir -p internal/ebpf/headers && \
    VMLINUZ=$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1) && \
    { [ -f /sys/kernel/btf/vmlinux ] && \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c \
        > internal/ebpf/headers/vmlinux.h 2>/dev/null; } || \
    { [ -n "$VMLINUZ" ] && \
        bpftool btf dump file "$VMLINUZ" format c \
        > internal/ebpf/headers/vmlinux.h 2>/dev/null; } || \
    echo "Warning: bpftool vmlinux generation failed – using pre-built headers"

# Compile eBPF objects + generate Go scaffolding
RUN make generate

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /obs-agent ./cmd/agent

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
# Using distroless for minimal footprint & 0-CVE base image.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="linux-obs-agent"
LABEL org.opencontainers.image.description="eBPF-powered Linux observability agent"
LABEL org.opencontainers.image.url="https://github.com/manhvu1997/linux-obs-agent"

COPY --from=builder /obs-agent /obs-agent
COPY --from=builder /build/deploy/config.yaml.example /etc/obs-agent/config.yaml

# The agent needs to run as root (or with required capabilities) to load eBPF.
# For Kubernetes: use securityContext.capabilities.add instead of root.
USER root

EXPOSE 9200

ENTRYPOINT ["/obs-agent"]
CMD ["-config", "/etc/obs-agent/config.yaml"]
