# linux-obs-agent

**Production-grade Linux observability daemon** with always-on baseline metrics and on-demand eBPF deep-dive tracing.

Written in Go · eBPF via [cilium/ebpf](https://github.com/cilium/ebpf) · < 2% CPU · < 100 MB RAM · No CGO · Fully static binary

---

## What is this?

`linux-obs-agent` is a lightweight daemon that runs on any Linux host and provides two layers of observability:

1. **Baseline metrics** — continuous `/proc` polling (CPU, memory, disk, network, load) exposed as Prometheus gauges at `:9200/metrics`.
2. **On-demand eBPF deep-dive** — eBPF modules activate automatically when thresholds are breached (high CPU, IO wait, run-queue latency, TCP retransmits) and deactivate when pressure subsides — zero kernel overhead at idle.

A companion **db-inspector sidecar** binary attaches to application pods and traces slow database queries (MongoDB, MySQL) using uprobes and syscall tracepoints.

---

## Main Features

| Feature | Description |
|---|---|
| **CPU profiling** | Flame-graph-ready stack traces via `perf_event` at 99 Hz — activates only when CPU > 85% |
| **IO latency** | Block-layer tracepoints measure per-request disk latency — activates on high IOWait |
| **Run-queue latency** | Scheduler tracepoints detect CPU starvation and lock contention |
| **TCP retransmit** | Detects network congestion and packet loss per flow |
| **Fsync tracer** | Always-on: tracks which processes are hammering `fsync`/`fdatasync`, with per-PID stats aggregated in-kernel |
| **MongoDB tracer** | Always-on: hooks connect/write/read syscalls to identify slow MongoDB queries |
| **MySQL tracer** | Always-on: uprobes on `mysqld!dispatch_command` to capture slow SQL queries with exact text |
| **Prometheus metrics** | 20+ gauges/counters at `:9200/metrics`, compatible with any Prometheus stack |
| **HTTP exporter** | Pushes gzip-compressed snapshots to a central collector on a configurable interval |
| **`/api/diagnose`** | On-demand JSON endpoint with fsync, MongoDB, and MySQL analysis in one call |
| **Process inspector** | Top-20 processes by CPU/RSS enriched with K8s pod/container metadata |

---

## Build

### With Docker (recommended)

The multi-stage Dockerfile handles everything — clang, LLVM, Go, eBPF compilation — no local toolchain needed.

```bash
# Build obs-agent image
docker build -t obs-agent:latest -f deploy/Dockerfile .

# Build db-inspector sidecar image
docker build -t db-inspector:latest -f deploy/Dockerfile.db-inspector .

# Or use Make targets
make image IMAGE_TAG=v1.0.0
make image-inspector IMAGE_TAG=v1.0.0
```

### With Podman

Podman is a drop-in replacement for Docker here:

```bash
# Build obs-agent
podman build -t obs-agent:latest -f deploy/Dockerfile .

# Build db-inspector sidecar
podman build -t db-inspector:latest -f deploy/Dockerfile.db-inspector .

# Run (needs privileged + host PID namespace for eBPF)
podman run --privileged --pid=host \
  -v /sys:/sys -v /proc:/proc:ro \
  -p 9200:9200 \
  -v /etc/obs-agent/config.yaml:/etc/obs-agent/config.yaml:ro \
  obs-agent:latest
```

> **Note:** eBPF requires access to `/sys/fs/bpf`, `/sys/kernel/debug`, and the host PID namespace. Use `--privileged` for development; in production use explicit capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`).

### From source (requires clang + Go 1.26+)

```bash
# Install build dependencies (Ubuntu/Debian)
sudo apt-get install -y clang llvm libbpf-dev bpftool golang-1.26

# Install build dependencies (Fedora/RHEL)
sudo dnf install -y clang llvm libbpf-devel bpftool golang

# Build everything
make all
# Produces: ./build/obs-agent  and  ./build/db-inspector

# Run
sudo ./build/obs-agent -config deploy/config.yaml.example -loglevel debug
```

---

## Configuration

Copy the annotated example and edit as needed:

```bash
cp deploy/config.yaml.example config.yaml
```

### Key sections

```yaml
agent:
  log_level: info           # debug | info | warn | error
  metrics_addr: ":9200"     # Prometheus endpoint

collect:
  interval: 5s              # /proc poll interval

ebpf:
  enabled: true
  active_duration: 60s      # how long an eBPF module stays active after triggering
  cool_down: 120s           # minimum time before re-triggering the same module

trigger:
  cpu_usage_percent: 85.0   # activate cpu_profile above this CPU %
  iowait_percent: 20.0      # activate io_latency above this IOWait %
  load_normalised: 1.5      # activate runqlat when load/cpu ratio exceeds this
  ctx_switch_delta: 100000  # activate runqlat above this context-switches/s
  net_error_delta: 100      # activate tcp_retransmit above this errors/s

fsync:
  enabled: true
  slow_threshold_us: 5000   # emit event only when a single fsync call > 5 ms
  poll_interval: 5s
  cpu_threshold: 85.0       # publish fsync snapshot when CPU exceeds this %
  mem_threshold: 85.0       # publish fsync snapshot when memory exceeds this %

mongo:
  enabled: false            # set true if your app connects to MongoDB
  port: 27017
  slow_query_threshold_ms: 2000

mysql:
  enabled: false            # set true if mysqld is running on this host
  mysqld_path: /usr/sbin/mysqld
  slow_query_threshold_ms: 2000

exporter:
  url: ""                   # push to a central collector (leave empty to disable)
  flush_interval: 30s
```

### Environment variable overrides

| Variable | Description |
|---|---|
| `MONGODB_TRACING_ENABLED=true` | Enable MongoDB tracer at runtime |
| `MONGODB_SLOW_QUERY_THRESHOLD_MS=500` | Override MongoDB slow-query threshold |
| `MYSQL_TRACING_ENABLED=true` | Enable MySQL tracer at runtime |
| `MYSQL_SLOW_QUERY_THRESHOLD_MS=100` | Override MySQL slow-query threshold |
| `MYSQL_MYSQLD_PATH=/usr/bin/mysqld` | Override mysqld binary path |

### Query the diagnose endpoint

```bash
# All analysis in one call
curl -s localhost:9200/api/diagnose | jq .

# Specific reports
curl -s localhost:9200/api/diagnose | jq .fsync_report
curl -s localhost:9200/api/diagnose | jq .mongo_report
curl -s localhost:9200/api/diagnose | jq .mysql_report
```

---

## How to Contribute

1. Fork the repo and create a feature branch.
2. Make your changes — keep each PR focused on one thing.
3. Run `make lint` and fix any issues before submitting.
4. Open a PR with a clear description of *what* and *why*.

### Project layout

```
internal/ebpf/          ← eBPF C programs + Go loaders (one subdir per module)
internal/model/types.go ← all shared data structs (add new fields here)
internal/config/        ← configuration schema + defaults
internal/exporter/      ← Prometheus + HTTP export
cmd/agent/main.go       ← daemon entry point
cmd/db-inspector/main.go← sidecar entry point
deploy/                 ← Dockerfiles, systemd unit, Kubernetes manifests
```

---

## Adding a New eBPF Tracing Module

Follow these six steps — existing code does not need to change for new modules.

### Step 1 — Write the eBPF C program

Create `internal/ebpf/mymodule/mymodule.bpf.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Your maps and SEC() programs here
```

Add a `gen.go` next to it:

```go
package mymodule

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$CFLAGS" MyModule mymodule.bpf.c -- -I../headers
```

### Step 2 — Write the Go loader

Create `internal/ebpf/mymodule/loader.go` implementing `Start(ctx)`, `Stop()`, and an `Events` channel. Use `internal/ebpf/fsync/loader.go` as a reference.

### Step 3 — Register the module ID

In [internal/ebpf/manager.go](internal/ebpf/manager.go), add:

```go
ModMyModule ModuleID = "mymodule"
```

Then add `case ModMyModule:` branches in `startModule()` and `stopModule()`.

### Step 4 — Add a trigger rule

In [internal/trigger/engine.go](internal/trigger/engine.go), add a condition that calls `manager.Activate(ModMyModule)` when the relevant threshold is breached.

### Step 5 — Expose results

Add a new field to the appropriate struct in [internal/model/types.go](internal/model/types.go) and update [internal/exporter/prometheus.go](internal/exporter/prometheus.go) to register its Prometheus metric.

### Adding a new database inspector (MongoDB/MySQL pattern)

For a database-specific slow-query tracer, follow the pattern in `internal/dbinspector/`:

1. `internal/ebpf/mydb_query/` — eBPF C + loader
2. `internal/mydb/analyzer.go` — poll loop (copy `internal/mongo/analyzer.go`)
3. `internal/dbinspector/mydb.go` — 10-line adapter implementing the `DBInspector` interface
4. Add `MyDBConfig` to `internal/config/db_inspector_config.go`
5. Register in `cmd/db-inspector/main.go`
6. Add `MyDBReport` field to `model.DBInspectReport`

Zero changes to existing inspector code.

---

## Kubernetes Deployment

```bash
# DaemonSet (obs-agent on every node)
kubectl apply -f deploy/daemonset.yaml

# db-inspector sidecar
kubectl apply -f deploy/db-inspector.yaml

# Verify
kubectl -n obs-system get pods -o wide
curl $(kubectl -n obs-system get pod -l app=obs-agent -o jsonpath='{.items[0].status.podIP}'):9200/metrics
```

---

## Required Linux Capabilities

| Capability | Purpose |
|---|---|
| `CAP_BPF` | Load BPF programs and create BPF maps (kernel ≥ 5.8) |
| `CAP_PERFMON` | Open `perf_event` file descriptors for CPU profiling (kernel ≥ 5.8) |
| `CAP_SYS_ADMIN` | Fallback for `CAP_BPF` on kernels < 5.8; pin to `/sys/fs/bpf` |
| `CAP_SYS_PTRACE` | Read `/proc/[pid]/io` across all processes |
