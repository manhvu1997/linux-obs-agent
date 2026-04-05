# linux-obs-agent

> **Production-grade Linux observability daemon** with baseline metrics + on-demand eBPF deep-dive.  
> Written in Go · eBPF via [cilium/ebpf](https://github.com/cilium/ebpf) · < 2% CPU · < 100 MB RAM

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Project Structure](#2-project-structure)
3. [Module Reference](#3-module-reference)
4. [eBPF Programs](#4-ebpf-programs)
5. [Trigger Engine](#5-trigger-engine)
6. [Fsync Tracer](#6-fsync-tracer)
7. [Data Flow](#7-data-flow)
8. [Build Pipeline](#8-build-pipeline)
9. [Installation & Running](#9-installation--running)
10. [Kubernetes Deployment](#10-kubernetes-deployment)
11. [Security & Capabilities](#11-security--capabilities)
12. [Prometheus Metrics](#12-prometheus-metrics)
13. [Performance Budget](#13-performance-budget)
14. [Extending the Agent](#14-extending-the-agent)

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              obs-agent daemon                                │
│                                                                              │
│  ┌─────────────────────┐   5s poll   ┌────────────────────────────────────┐ │
│  │  Collector          │ ──────────► │  NodeMetrics channel (buffered 4)  │ │
│  │  /proc/stat         │             └────────────────────────────────────┘ │
│  │  /proc/meminfo      │                     │              │               │
│  │  /proc/diskstats    │                     ▼              ▼               │
│  │  /proc/net/dev      │    ┌──────────────────┐  ┌──────────────────────┐ │
│  │  /proc/loadavg      │    │  Trigger Engine  │  │  Fsync Analyzer      │ │
│  └─────────────────────┘    │  (10s eval)      │  │  (always-on, 5s poll)│ │
│                             │  CPU>85% → ...   │  │  LRU map aggregation │ │
│  ┌─────────────────────┐    │  IOWait>20% → ...│  │  /proc enrichment    │ │
│  │  Process Inspector  │    └────────┬─────────┘  │  app classification  │ │
│  │  /proc/[pid]/stat   │             │             └──────────┬───────────┘ │
│  │  /proc/[pid]/status │             ▼                        │             │
│  │  /proc/[pid]/io     │    ┌────────────────────────────┐   │ CPU>85%     │
│  │  (top-20 by CPU/RSS)│    │       eBPF Manager         │   │ OR Mem>85%  │
│  └─────────────────────┘    │  ┌──────────┐ ┌─────────┐  │   ▼             │
│                             │  │cpu_profile│ │io_latency│  │ ┌───────────┐ │
│  ┌─────────────────────┐    │  └──────────┘ └─────────┘  │ │FsyncAnalysis│ │
│  │  Prometheus Exporter│◄───│  ┌──────────┐ ┌─────────┐  │ │cached in   │ │
│  │  :9200/metrics      │    │  │ runqlat  │ │tcp_retr.│  │ │  memory    │ │
│  │  GET /api/diagnose  │◄───┘  └──────────┘ └─────────┘  │ └─────┬─────┘ │
│  └─────────────────────┘    │  All INACTIVE until triggered│       │       │
│                             └────────────────────────────┘ │       │       │
│  ┌─────────────────────┐                                    └───────┘       │
│  │  HTTP Exporter      │ ──► push ── (batch+gzip Snapshot)                  │
│  └─────────────────────┘                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
                         │                          │
               Ring Buffer / Map             kprobe/kretprobe
                         │                          │
                  Linux Kernel               Linux Kernel
             ┌────────────────────┐    ┌─────────────────────────┐
             │  perf_event (CPU)  │    │  __x64_sys_fsync        │
             │  block tracepoints │    │  __x64_sys_fdatasync    │
             │  sched tracepoints │    │  __x64_sys_sync_file_   │
             │  tcp tracepoints   │    │    range                │
             └────────────────────┘    │  LRU_HASH[pid] → stats  │
                                       └─────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **ebpf-go (cilium/ebpf), not BCC** | No Python/LLVM dependency at runtime; eBPF bytecode is compiled at build time and embedded in the binary |
| **Lazy eBPF activation** | Zero kernel overhead when thresholds are not breached |
| **Ring buffer for events** | BPF_MAP_TYPE_RINGBUF (kernel ≥5.8) has lower overhead than perf_event_array; no per-CPU buffers |
| **CO-RE (BTF)** | One binary runs on any kernel ≥5.4 with BTF enabled; no per-kernel compilation |
| **No CGO** | Fully static binary, trivial to ship as a scratch/distroless container |
| **Fsync LRU aggregation** | In-kernel BPF_MAP_TYPE_LRU_HASH aggregates per-PID stats; userspace polls once every 5 s instead of once per syscall |

---

## 2. Project Structure

```
linux-obs-agent/
├── cmd/agent/
│   └── main.go                  ← daemon entry point, signal handling
│
├── internal/
│   ├── config/
│   │   └── config.go            ← YAML config with defaults + validation
│   │
│   ├── model/
│   │   └── types.go             ← all data structs (metrics, events, snapshot)
│   │
│   ├── collector/
│   │   ├── collector.go         ← orchestrator: runs all scrapers every 5s
│   │   ├── cpu.go               ← /proc/stat → CPUMetrics (delta-based)
│   │   └── system.go            ← /proc/meminfo, /proc/diskstats, /proc/net/dev
│   │
│   ├── ebpf/
│   │   ├── manager.go           ← module lifecycle: lazy start, auto-stop, cool-down
│   │   ├── cpu_profile/
│   │   │   ├── cpu_profile.bpf.c ← eBPF C: perf_event sampling + stack traces
│   │   │   ├── gen.go           ← //go:generate bpf2go directive
│   │   │   └── loader.go        ← Go: load, attach perf_event per CPU, consume ringbuf
│   │   ├── io_latency/
│   │   │   ├── io_latency.bpf.c  ← eBPF C: block_rq_issue/complete latency
│   │   │   ├── gen.go
│   │   │   └── loader.go
│   │   ├── runqlat/
│   │   │   ├── runqlat.bpf.c    ← eBPF C: sched_wakeup → sched_switch delta
│   │   │   ├── gen.go
│   │   │   └── loader.go
│   │   ├── tcp_retransmit/
│   │   │   ├── tcp_retransmit.bpf.c ← eBPF C: tp_btf/tcp_retransmit_skb
│   │   │   ├── gen.go
│   │   │   └── loader.go
│   │   └── fsync/               ← NEW: always-on fsync latency tracer
│   │       ├── fsync.bpf.c      ← eBPF C: kprobe/kretprobe + LRU_HASH aggregation
│   │       ├── gen.go
│   │       └── loader.go        ← Go: attach kprobes, TopOffenders() map poll
│   │
│   ├── trigger/
│   │   └── engine.go            ← threshold evaluator → calls ebpf.Manager.Activate
│   │
│   ├── fsync/                   ← NEW: userspace fsync analysis loop
│   │   └── analyzer.go          ← polls LRU map, enriches PIDs, publishes FsyncAnalysis
│   │
│   ├── process/
│   │   └── inspector.go         ← /proc/[pid] scanner, top-N CPU/RSS, K8s metadata
│   │
│   └── exporter/
│       ├── exporter.go          ← HTTP batch+gzip exporter with retry
│       └── prometheus.go        ← :9200/metrics + GET /api/diagnose (now incl. fsync)
│
├── deploy/
│   ├── Dockerfile               ← multi-stage: clang builder + distroless runtime
│   ├── obs-agent.service        ← systemd unit (capabilities, cgroups limits)
│   ├── config.yaml.example      ← annotated config reference
│   └── daemonset.yaml           ← Kubernetes DaemonSet + ServiceMonitor
│
├── Makefile                     ← generate / build / install / image targets
└── go.mod
```

---

## 3. Module Reference

### `internal/config`
Single source of truth for all tunable parameters. `config.Defaults()` returns a valid config; `config.Load(path)` merges a YAML file on top. Fields use `time.Duration` so the YAML can say `60s` or `1m`.

### `internal/model`
Pure data structs – no methods, no imports except `time`. Everything the agent produces is defined here. The `Snapshot` struct is the wire format sent to the central server.

### `internal/collector`
Always-on. Reads `/proc` every `collect.interval` (default 5s). The `Collector.Metrics` channel is buffered to 4 so a slow consumer doesn't block scraping. Delta-based rates (bytes/s, ops/s) are computed from two consecutive samples.

### `internal/ebpf/manager`
Central eBPF lifecycle controller. Maintains a `moduleState` per module (active/inactive, lastStop for cool-down). `Activate()` is idempotent – calling it twice while a module is active is a no-op. Auto-stop is implemented via `context.WithTimeout`.

### `internal/trigger`
Stateless evaluator that runs every `trigger.eval_interval`. Reads the latest `NodeMetrics` snapshot from the collector (non-blocking `Latest()` call) and calls `manager.Activate()` when thresholds are breached. The manager handles cool-down so the trigger engine can fire freely.

### `internal/process`
Scans all `/proc/[pid]` directories every `process.scan_interval`. Uses a two-sample delta for CPU% and IO rates. Container/K8s metadata is extracted from the cgroup path (works for cgroupv1 and cgroupv2) and optionally from `/proc/[pid]/environ`.

### `internal/fsync`
Always-on fsync analysis loop. `Analyzer.Start()` loads the eBPF module at agent startup and runs a `time.Ticker` every `fsync.poll_interval` (default 5 s). On each tick it batch-reads the in-kernel LRU map, enriches each PID entry with `/proc/<pid>/cmdline` and cgroup path, classifies known workloads (databases, log agents, antivirus), and atomically stores the result as a `*model.FsyncAnalysis`. The snapshot is only published when the system is under pressure (`CPU > cpu_threshold OR Mem > mem_threshold`), so `GET /api/diagnose` always reflects the most-recent high-pressure picture.

### `internal/exporter`
Two export paths:
1. **Prometheus** (`exporter/prometheus.go`): Gauges/counters updated on every scrape (`/metrics`). Zero background work.
2. **HTTP** (`exporter/exporter.go`): Batches eBPF events in memory, flushes every `flush_interval` as a gzipped JSON `Snapshot` POST.

---

## 4. eBPF Programs

### 4.1 CPU Profiler (`cpu_profile.bpf.c`)

**Mechanism**: `perf_event` (PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK)

```
perf_event fires at 99 Hz on each CPU
    │
    ▼
SEC("perf_event") profile_cpu(ctx)
    │
    ├── bpf_get_stackid(ctx, &stack_traces, 0)          → kernel stack ID
    ├── bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK) → user stack ID
    │
    ├── Increment counts[{pid,comm,kstack,ustack}]++   (BPF_MAP_TYPE_HASH)
    │   (flamegraph-ready: fold by pid+stacks, count = weight)
    │
    └── Push cpu_sample_event → BPF_MAP_TYPE_RINGBUF
```

**Maps used**:
- `stack_traces` (STACK_TRACE, 10240 entries) – kernel stores raw instruction pointers
- `counts` (HASH, 10240 entries) – aggregated sample counts per unique stack
- `events` (RINGBUF, 256KB) – per-sample events for real-time hot-PID detection

**Go side**: `Loader.TopPIDs(n)` iterates `counts` and returns the top-N by sample count, ready for flamegraph generation.

### 4.2 IO Latency (`io_latency.bpf.c`)

**Mechanism**: Block layer tracepoints (available since kernel 4.x)

```
block_rq_issue (request submitted to driver)
    │  store: io_start[{dev,sector}] = {ts_ns, pid, comm}
    │
    ▼
block_rq_complete (driver signals done)
    │  lookup io_start[{dev,sector}]
    │  latency_us = (now - start.ts_ns) / 1000
    │
    ├── latency_hist[log2(latency_us)]++   (in-kernel histogram)
    │
    └── if latency_us > slow_threshold_us:
            push io_event → RINGBUF
```

**Why tracepoints?** Tracepoints are stable ABI. The alternative (kprobes on `blk_mq_start_request`) would break across kernel versions.

**Configurable threshold**: The `slow_io_threshold_us` global variable is compiled as `const volatile` so bpf2go exposes it as a settable variable from Go without recompiling the eBPF program.

### 4.3 Run Queue Latency (`runqlat.bpf.c`)

**Mechanism**: BTF-based tracepoints (`tp_btf`) for scheduler events

```
sched_wakeup / sched_wakeup_new
    │  start[pid] = bpf_ktime_get_ns()
    │
sched_switch (next task gets CPU)
    │  lat_us = (now - start[next->pid]) / 1000
    │  delete start[next->pid]
    │
    ├── hist[log2(lat_us)]++
    │
    └── if lat_us > runqlat_threshold_us:
            push runq_event → RINGBUF
```

**Why tp_btf?** `tp_btf` programs receive typed kernel structs directly (via BTF), avoiding the need to cast raw tracepoint arguments. This is more portable than raw tracepoints.

### 4.4 TCP Retransmit (`tcp_retransmit.bpf.c`)

**Mechanism**: `tp_btf/tcp_retransmit_skb` (kernel ≥ 5.4 with BTF)

```
tcp_retransmit_skb(sock *sk, skb *skb)
    │
    ├── Read sk->__sk_common: family, saddr, daddr, sport, dport, state
    │   (BPF_CORE_READ for CO-RE safety)
    │
    ├── Update retransmit_count[{saddr,daddr,sport,dport}]++  (LRU_HASH)
    │   (rate-limiting / per-flow aggregation)
    │
    └── push retransmit_event → RINGBUF
```

**IPv4 and IPv6**: The same program handles both by checking `skc_family` and reading the appropriate address union.

### 4.5 Fsync Tracer (`fsync.bpf.c`)

**Mechanism**: kprobe/kretprobe pairs on three syscall entry points (kernel ≥ 4.x, no BTF required)

```
kprobe/__x64_sys_fsync          kprobe/__x64_sys_fdatasync      kprobe/__x64_sys_sync_file_range
    │                               │                               │
    └───────────────────────────────┴───────────────────────────────┘
                                    │
                           record_entry():
                           fsync_start[tid] = bpf_ktime_get_ns()
                                    │
                          [syscall executes in kernel]
                                    │
kretprobe/__x64_sys_fsync  kretprobe/__x64_sys_fdatasync  kretprobe/__x64_sys_sync_file_range
    │                               │                               │
    └───────────────────────────────┴───────────────────────────────┘
                                    │
                           record_exit(syscall_nr):
                           latency_ns = now - fsync_start[tid]
                           delete fsync_start[tid]
                                    │
                    ┌───────────────┴───────────────────────┐
                    │                                       │
             fsync_stats[tgid]:                   if latency_us > slow_threshold_us:
             total_calls++           (atomic)         push fsync_event → RINGBUF
             total_latency_ns += Δ   (atomic)         (outliers only, drop-safe)
             max_latency_ns = max(Δ)
             last_seen_ts = now
             comm = bpf_get_current_comm()
                    │
         BPF_MAP_TYPE_LRU_HASH
         max_entries = 10 240
         (auto-evicts least-recently-used)
```

**Maps used**:
- `fsync_start` (HASH, 65 536 entries) – transient per-TID entry timestamps; always deleted in kretprobe so no stale growth
- `fsync_stats` (LRU_HASH, 10 240 entries) – accumulated per-PID stats; LRU eviction bounds memory automatically
- `events` (RINGBUF, 256 KB) – outlier events only (latency > `slow_fsync_threshold_us`, default 5 ms)

**Why kprobes (not fentry)?**: The fsync syscall wrappers (`__x64_sys_*`) are architecture-specific entry stubs that exist on all kernels ≥ 4.x without BTF. This makes the module usable on older distributions.

**Configurable threshold**: `slow_fsync_threshold_us` is a `const volatile` global, rewritten at load time from Go via `spec.Variables["slow_fsync_threshold_us"].Set(v)`. At 10 k+ fsync/s with a 5 ms threshold, the ringbuf emits near-zero events; all aggregation happens in the LRU map with atomic ops only.

**Userspace polling** (`internal/fsync/analyzer.go`):

```
Every 5 s (poll_interval):
    TopOffenders(n=20, stale=60s):
        iterate LRU map → skip entries older than 60 s
        sort by total_calls desc
        return top-20
            │
            ├── /proc/<pid>/cmdline   – full command line
            ├── /proc/<pid>/cgroup    – cgroup / container path
            └── classify comm+cmdline → app_type
                  "database"   : mongod, mysql, postgres, redis, cassandra
                  "log_agent"  : loki, filebeat, fluentd, promtail, vector
                  "antivirus"  : clamd, falcon, crowdstrike, cylance
                  ""           : unknown
            │
            ▼
    if CPU > 85% OR Mem > 85%:
        atomic.Store(&latest, &FsyncAnalysis{...})   ← available to /api/diagnose
```

---

## 5. Trigger Engine

The trigger engine runs in a tight `time.Ticker` loop (default every 10s). It calls `collector.Latest()` which returns the cached metric snapshot without I/O.

### Rule Table

| Condition | Modules Activated | Root cause diagnosis |
|---|---|---|
| `cpu_usage > 85%` | `cpu_profile` | On-CPU stack sampling → identify hot functions/processes |
| `iowait > 20%` | `io_latency` | Slow disk identification, which process is causing IO |
| `load/cpu > 1.5 AND cpu < 50%` | `io_latency` + `runqlat` | IO wait causing D-state processes → high load with low CPU |
| `ctx_switches/s > 100k` | `runqlat` | Scheduler thrashing, lock contention |
| `load/cpu > 1.5` | `runqlat` | CPU oversubscription, run-queue saturation |
| `net_errors/s > 100` | `tcp_retransmit` | Network congestion, bad cables, MTU mismatch |

### State Machine per Module

```
         Activate() called
              │
   ┌──────────▼──────────┐
   │  Check: in cooldown? │──── YES ──► skip (log at Debug)
   └──────────┬──────────┘
              │ NO
   ┌──────────▼──────────┐
   │   Check: active?    │──── YES ──► skip (idempotent)
   └──────────┬──────────┘
              │ NO
   ┌──────────▼──────────────────────────────┐
   │  context.WithTimeout(ctx, active_duration) │
   │  startModule() → load eBPF → attach       │
   │  state.active = true                       │
   └──────────┬──────────────────────────────┘
              │
         [active_duration expires]
              │
   ┌──────────▼──────────┐
   │  stopModule()        │
   │  state.active = false │
   │  state.lastStop = now │  ← cooldown starts here
   └─────────────────────┘
```

---

## 6. Fsync Tracer

### Overview

The fsync tracer is **always-on** (unlike other eBPF modules that activate on-demand). It attaches six kprobe/kretprobe hooks at agent startup and continuously aggregates per-PID statistics in a kernel-side LRU map. Because aggregation happens in-kernel with atomic ops, userspace only needs to read the map once every 5 seconds — no per-syscall wakeups at any call rate.

### Observed process categories

| App Type | Matched processes |
|---|---|
| `database` | `mongod`, `mongos`, `cassandra`, `redis-server`, `mysqld`, `postgres`, `postmaster` |
| `log_agent` | `loki`, `promtail`, `filebeat`, `fluentd`, `fluent-bit`, `logstash`, `vector` |
| `antivirus` | `clamd`, `clamav`, `sophos`, `cylance`, `falcon`, `crowdstrike`, `carbonblack`, `eset` |

Classification is substring-based on `comm` + `cmdline` (case-insensitive), so renamed binaries like `mongod_r3` still match.

### GET /api/diagnose — FsyncReport field

`FsyncReport` is included in the diagnose response **only when the system was under pressure** (CPU > 85 % OR Memory > 85 %) during a recent 5-second poll cycle.

```bash
curl -s http://localhost:9200/api/diagnose | jq .fsync_report
```

```json
{
  "type": "fsync_analysis",
  "timestamp": "2026-04-05T10:12:00Z",
  "system": {
    "cpu_percent": 91.2,
    "mem_percent": 72.1
  },
  "top_offenders": [
    {
      "pid": 567,
      "comm": "mongod",
      "cmdline": "/usr/bin/mongod --config /etc/mongod.conf",
      "cgroup_path": "/system.slice/mongod.service",
      "fsync_calls": 1200,
      "avg_latency_ms": 3.2,
      "max_latency_ms": 25.1,
      "app_type": "database"
    },
    {
      "pid": 534,
      "comm": "loki",
      "cmdline": "/usr/bin/loki -config.file /etc/loki/config.yaml",
      "cgroup_path": "/system.slice/loki.service",
      "fsync_calls": 800,
      "avg_latency_ms": 5.5,
      "max_latency_ms": 40.3,
      "app_type": "log_agent"
    }
  ]
}
```

### Configuration (`fsync:` section in config.yaml)

```yaml
fsync:
  enabled: true
  slow_threshold_us: 5000   # emit ringbuf event only when a single call > 5 ms
  poll_interval: 5s          # how often to batch-read the in-kernel LRU map
  top_n: 20                  # max offenders in each FsyncAnalysis
  stale_seconds: 60          # ignore PIDs not seen in the last 60 s
  cpu_threshold: 85.0        # publish snapshot when CPU exceeds this %
  mem_threshold: 85.0        # publish snapshot when memory exceeds this %
```

### Test the tracer

```bash
# 1. Generate fsync load with dd (forces fdatasync after each write)
dd if=/dev/zero of=/tmp/fsync_test bs=4k count=10000 conv=fdatasync

# 2. Stress with fio (multiple parallel fsyncs)
fio --name=fsync-stress --ioengine=sync --rw=write --bs=4k \
    --size=1G --numjobs=4 --fsync=1 --filename=/tmp/fio_fsync

# 3. Watch the analyzer output
sudo ./build/obs-agent -loglevel debug 2>&1 | grep fsync

# 4. Query the diagnose endpoint
curl -s localhost:9200/api/diagnose | jq '.fsync_report.top_offenders[:3]'
```

### Verify loaded kprobes

```bash
# After agent starts, confirm the six hooks are attached:
sudo bpftool prog list | grep kprobe
# Expected output includes:
#   kprobe  name kprobe_fsync
#   kprobe  name kretprobe_fsync
#   kprobe  name kprobe_fdatasync
#   kprobe  name kretprobe_fdatasync
#   kprobe  name kprobe_sync_file_range
#   kprobe  name kretprobe_sync_file_range

# Inspect the LRU stats map:
sudo bpftool map show name fsync_stats
sudo bpftool map dump name fsync_stats
```

---

## 7. Data Flow

```
/proc polling (5s)
    │
    ├── NodeMetrics{CPU, Mem, Load, Disk, Net}
    │           │
    │           ├──► Prometheus Gauges (scraped on-demand, ~0 CPU)
    │           │
    │           ├──► Trigger Engine evaluates thresholds
    │           │         │
    │           │         └──► ebpf.Manager.Activate(module)
    │           │                       │
    │           │              Linux Kernel (eBPF attached)
    │           │                       │
    │           │              Ring Buffer events
    │           │                       │
    │           │              ebpf.Manager.Events channel
    │           │                       │
    │           │         ┌─────────────┤
    │           │         │             │
    │           │    Prometheus     HTTP Exporter
    │           │    counter++      QueueEvent()
    │           │                       │
    │           │                  [flush_interval]
    │           │                       │
    │           └── Snapshot{metrics + topProcs + ebpfEvents}
    │                                   │
    │                             gzip + POST
    │                                   │
    │                         Central Collector Server
    │
    └──► Fsync Analyzer (always-on, independent loop)
                │
          [every 5s]
                │
         iterate LRU map (fsync_stats)
                │
         enrich /proc/<pid>/cmdline, /cgroup
                │
         if CPU>85% OR Mem>85%:
                │
         atomic.Store(latest FsyncAnalysis)
                │
         GET /api/diagnose → .fsync_report
```

---

## 8. Build Pipeline

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt-get install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool \
    golang-1.26

# Fedora / RHEL
sudo dnf install -y \
    clang llvm libbpf-devel \
    kernel-devel \
    bpftool \
    golang
```

### Step-by-step

#### Step 1: Generate vmlinux.h (once per kernel version)

```bash
make vmlinux
# Equivalent to:
bpftool btf dump file /sys/kernel/btf/vmlinux format c \
    > internal/ebpf/headers/vmlinux.h
```

`vmlinux.h` contains every kernel struct definition. It's generated from the running kernel's BTF (BPF Type Format) metadata at `/sys/kernel/btf/vmlinux`. This enables **CO-RE** – the eBPF programs are compiled once and run on any kernel that has BTF enabled (virtually all modern distributions).

#### Step 2: Compile eBPF C → Go scaffolding

```bash
make generate
# Equivalent to running in each ebpf/* package:
go generate ./internal/ebpf/...
```

What `bpf2go` does under the hood:
```
cpu_profile.bpf.c
    │
    ├── clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    │         -I./headers cpu_profile.bpf.c \
    │         -o cpu_profile_bpfel.o          ← little-endian (x86/arm)
    │
    ├── clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    │         -mlittle-endian=false \
    │         -o cpu_profile_bpfeb.o          ← big-endian (s390x, mips)
    │
    └── generates cpu_profile_bpfel.go / cpu_profile_bpfeb.go:
        ┌──────────────────────────────────────────┐
        │  //go:embed cpu_profile_bpfel.o          │
        │  var _CpuProfileBytes []byte             │
        │                                          │
        │  type CpuProfileObjects struct {         │
        │    ProfileCpu  *ebpf.Program             │
        │    StackTraces *ebpf.Map                 │
        │    Counts      *ebpf.Map                 │
        │    Events      *ebpf.Map                 │
        │  }                                       │
        │                                          │
        │  func loadCpuProfileObjects(             │
        │    objs *CpuProfileObjects,              │
        │    opts *ebpf.CollectionOptions,         │
        │  ) error { … }                           │
        └──────────────────────────────────────────┘
```

The compiled `.o` is embedded via `//go:embed`, so the final binary has **zero runtime dependencies** on clang/LLVM.

#### Step 3: Build the Go binary

```bash
make build
# Produces: ./build/obs-agent  (static, ~15MB)

# Verify it's truly static:
file ./build/obs-agent
# obs-agent: ELF 64-bit LSB executable, statically linked
```

#### Step 4: Run

```bash
# Development (with full debug output):
sudo ./build/obs-agent -config deploy/config.yaml.example -loglevel debug

# Check metrics:
curl -s localhost:9200/metrics | grep obs_agent
```

---

## 9. Installation & Running

### Bare metal / VM

```bash
# 1. Build
make all

# 2. Create system user (no login shell)
sudo useradd --system --no-create-home --shell /sbin/nologin obs-agent

# 3. Install binary + config + systemd unit
sudo make install

# 4. Edit config
sudo vim /etc/obs-agent/config.yaml

# 5. Enable and start
sudo systemctl enable --now obs-agent

# 6. Check status
sudo systemctl status obs-agent
sudo journalctl -u obs-agent -f
```

### Verify eBPF programs are loaded (when triggered)

```bash
# Check loaded BPF programs after a trigger fires:
sudo bpftool prog list | grep -E 'perf_event|tracepoint'

# Inspect ring buffer maps:
sudo bpftool map list | grep ringbuf

# Watch live events (debug mode):
sudo ./build/obs-agent -loglevel debug 2>&1 | grep ebpf
```

### Test trigger manually

```bash
# Force high CPU to trigger cpu_profile eBPF:
stress-ng --cpu 0 --timeout 30s &

# Force IO to trigger io_latency eBPF:
fio --name=test --ioengine=libaio --rw=randread --bs=4k \
    --numjobs=4 --iodepth=32 --size=1G --filename=/tmp/fio.tmp
```

---

## 10. Kubernetes Deployment

```bash
# Deploy
kubectl apply -f deploy/daemonset.yaml

# Verify
kubectl -n obs-system get pods -o wide
kubectl -n obs-system logs -l app=obs-agent --tail=50

# Check metrics from any pod
kubectl -n obs-system exec -it ds/obs-agent -- \
    wget -qO- localhost:9200/metrics | grep obs_agent_cpu
```

### Grafana Dashboard

Import the pre-built dashboard (query examples):

```promql
# CPU usage per node
obs_agent_cpu_usage_percent

# IOWait heatmap
obs_agent_cpu_iowait_percent{job="obs-agent"}

# eBPF trigger rate (how often thresholds are breached)
rate(obs_agent_ebpf_events_total[5m])

# Slow IO events from eBPF
increase(obs_agent_ebpf_events_total{module="io_latency"}[1m])

# TCP retransmits detected by eBPF
increase(obs_agent_ebpf_events_total{module="tcp_retransmit"}[1m])

# Top disk IO utilization
topk(5, obs_agent_disk_io_util_percent)

# Memory pressure
obs_agent_mem_available_bytes / obs_agent_mem_total_bytes
```

---

## 11. Security & Capabilities

### Required Linux Capabilities

| Capability | Required For | Kernel Version |
|---|---|---|
| `CAP_BPF` | Load BPF programs, create BPF maps | ≥ 5.8 |
| `CAP_PERFMON` | Open `perf_event` file descriptors for CPU profiling | ≥ 5.8 |
| `CAP_SYS_ADMIN` | Fallback for `CAP_BPF` on kernels < 5.8; pin to `/sys/fs/bpf` | All |
| `CAP_SYS_PTRACE` | Read `/proc/[pid]/io` for all processes | All |
| `CAP_DAC_READ_SEARCH` | Read `/proc/[pid]/environ` for K8s metadata | All (optional) |

### Principle of Least Privilege

The systemd unit (`deploy/obs-agent.service`) uses:

```ini
User=obs-agent              # not root
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE
NoNewPrivileges=yes         # cannot escalate further
MemoryMax=200M              # OOM kill before impacting host
CPUQuota=10%                # hard CPU cap
```

### BPF Verifier Safety

All eBPF programs are verified by the kernel before loading:
- All map lookups are null-checked before dereferencing
- Loop bounds are statically bounded (`MAX_ENTRIES`, `i < 64`)
- Stack usage is within the 512-byte BPF stack limit
- No unbounded loops
- `BPF_F_USER_STACK` flag on `bpf_get_stackid` – gracefully fails if user stacks aren't available
- Fsync: `fsync_start` entries are always deleted in the kretprobe – no unbounded map growth

---

## 12. Prometheus Metrics

All metrics are prefixed with `obs_agent_`.

| Metric | Type | Description |
|---|---|---|
| `cpu_usage_percent` | Gauge | Total CPU utilization (user+sys) |
| `cpu_user_percent` | Gauge | User-space CPU time |
| `cpu_sys_percent` | Gauge | Kernel CPU time |
| `cpu_iowait_percent` | Gauge | % of time CPUs waiting for IO |
| `cpu_steal_percent` | Gauge | VM steal time |
| `cpu_ctx_switches_per_sec` | Gauge | Context switches/s |
| `procs_running` | Gauge | Processes in R state |
| `procs_blocked` | Gauge | Processes in D (IO wait) state |
| `mem_total_bytes` | Gauge | Total physical memory |
| `mem_used_bytes` | Gauge | Used memory (total - free - buffers - cache) |
| `mem_available_bytes` | Gauge | Available memory (kernel estimate) |
| `mem_swap_percent` | Gauge | Swap utilization % |
| `load1` / `load5` / `load15` | Gauge | Load averages |
| `disk_read_bytes_per_sec{device}` | Gauge | Read throughput |
| `disk_write_bytes_per_sec{device}` | Gauge | Write throughput |
| `disk_io_util_percent{device}` | Gauge | IO utilization (iostat %util) |
| `disk_avg_wait_ms{device}` | Gauge | Average IO wait time |
| `net_rx_bytes_per_sec{interface}` | Gauge | Receive throughput |
| `net_tx_bytes_per_sec{interface}` | Gauge | Transmit throughput |
| `net_rx_errors_total{interface}` | Gauge | RX errors (cumulative) |
| `ebpf_events_total{module}` | Counter | eBPF events emitted per module |
| `ebpf_events_total{module="fsync"}` | Counter | Fsync outlier events (latency > threshold) |

---

## 13. Performance Budget

| Component | CPU | Memory |
|---|---|---|
| `/proc` polling (5s interval) | ~0.05% | — |
| Process inspector (10s, top-20) | ~0.08% | ~2 MB |
| Prometheus handler | ~0.01% (on scrape) | ~5 MB |
| eBPF cpu_profile (active, 99Hz) | ~0.3% | ~15 MB (maps) |
| eBPF io_latency (active) | ~0.05% per IOPS | ~8 MB |
| eBPF runqlat (active) | ~0.1% | ~8 MB |
| eBPF tcp_retransmit (active) | ~0.02% per conn | ~4 MB |
| **eBPF fsync (always-on)** | **~0.01% at 10k fsync/s** | **~1 MB (LRU map + ringbuf)** |
| **Fsync analyzer poll (5s)** | **~0.001%** | **< 1 MB** |
| Go runtime overhead | ~0.02% | ~12 MB |
| **Total (all eBPF active + fsync)** | **~0.61%** | **~55 MB** |
| **Total (no trigger-eBPF, fsync only)** | **~0.17%** | **~20 MB** |

All measurements are on a 4-core 8GB VM under moderate load. The systemd unit enforces hard limits (`CPUQuota=10%`, `MemoryMax=200M`) as a safety net.

**Fsync overhead detail**: At 10 000 fsync/s with a 5 ms slow threshold, the kprobe/kretprobe pair executes ~20 000 times/s. Each execution does one map lookup + one atomic add (~50 ns each). Total: ~1 ms/s ≈ **0.01% CPU** on a single core. The ringbuf emits zero events at normal latencies.

---

## 14. Extending the Agent

### Adding a new eBPF module

1. Create `internal/ebpf/mymodule/mymodule.bpf.c` with the eBPF C program
2. Add `gen.go` with the `//go:generate` directive
3. Implement `loader.go` with `Start()`, `Stop()`, and an `Events chan model.EBPFEvent`
4. Add `ModMyModule ModuleID = "mymodule"` to `internal/ebpf/manager.go`
5. Add the `case ModMyModule:` branch in `startModule()` and `stopModule()`
6. Add a trigger rule in `internal/trigger/engine.go`

### Adding a new baseline metric

1. Add the field to the appropriate struct in `internal/model/types.go`
2. Read it in the appropriate collector in `internal/collector/`
3. Register a Prometheus gauge/counter in `internal/exporter/prometheus.go`

### Flamegraph output

The `cpu_profile` module stores aggregated stack counts in the `counts` map. To generate a flamegraph:

```go
// In your HTTP handler or CLI tool:
events := manager.CPUTopPIDs(1000)
// Write folded stacks format for flamegraph.pl or speedscope:
for _, e := range events {
    fmt.Printf("%s;%s %d\n",
        e.Comm,
        resolveSymbols(e.Ustack),  // addr2line / /proc/[pid]/maps
        e.SampleCount,
    )
}
```
