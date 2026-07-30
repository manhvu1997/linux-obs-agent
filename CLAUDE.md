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
7. [DB Inspector Sidecar](#7-db-inspector-sidecar)
8. [Data Flow](#8-data-flow)
9. [Build Pipeline](#9-build-pipeline)
10. [Installation & Running](#10-installation--running)
11. [Kubernetes Deployment](#11-kubernetes-deployment)
12. [Security & Capabilities](#12-security--capabilities)
13. [Prometheus Metrics](#13-prometheus-metrics)
14. [Performance Budget](#14-performance-budget)
15. [Extending the Agent](#15-extending-the-agent)
16. [MySQL Slow Query Tracer](#16-mysql-slow-query-tracer)
17. [Run-Queue Analysis & On-Demand CPU Profiling](#17-run-queue-analysis--on-demand-cpu-profiling)
18. [Off-CPU Profiling — the module that explains iowait](#18-off-cpu-profiling--the-module-that-explains-iowait)
19. [Correlated I/O Diagnosis — connecting the chain](#19-correlated-io-diagnosis--connecting-the-chain)

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
├── cmd/
│   ├── agent/
│   │   └── main.go                  ← daemon entry point, signal handling
│   └── db-inspector/
│       └── main.go                  ← sidecar entry point: /healthz + /api/inspect
│
├── internal/
│   ├── config/
│   │   ├── config.go                ← YAML config with defaults + validation
│   │   └── db_inspector_config.go   ← slim config for db-inspector sidecar
│   │
│   ├── model/
│   │   └── types.go                 ← all data structs (metrics, events, snapshot,
│   │                                   DBInspectReport, InspectReport)
│   │
│   ├── collector/
│   │   ├── collector.go             ← orchestrator: runs all scrapers every 5s
│   │   ├── cpu.go                   ← /proc/stat → CPUMetrics (delta-based)
│   │   ├── psi.go                   ← /proc/pressure/{io,cpu,memory} (PSI)
│   │   ├── vmstat.go                ← /proc/vmstat dirty/writeback/pgpg deltas
│   │   ├── dstate.go                ← D-state census + wchan + blocked duration
│   │   └── system.go                ← /proc/meminfo, /proc/diskstats, /proc/net/dev
│   │
│   ├── ebpf/
│   │   ├── manager.go               ← module lifecycle: lazy start, auto-stop, cool-down
│   │   ├── profiler.go              ← on-demand ProfilePID: cache → reuse → sample
│   │   ├── cpu_profile/
│   │   │   ├── cpu_profile.bpf.c    ← eBPF C: perf_event sampling + stack traces
│   │   │   │                          (target_tgid filter, emit_events gate)
│   │   │   ├── gen.go               ← //go:generate bpf2go directive
│   │   │   └── loader.go            ← Go: Config/New, perf_event per CPU, ringbuf
│   │   ├── io_latency/
│   │   │   ├── io_latency.bpf.c     ← eBPF C: block_rq_issue/complete latency
│   │   │   ├── gen.go
│   │   │   └── loader.go
│   │   ├── runqlat/
│   │   │   ├── runqlat.bpf.c        ← eBPF C: sched_wakeup → sched_switch delta,
│   │   │   │                          global histogram + per-TGID LRU aggregate
│   │   │   ├── gen.go
│   │   │   └── loader.go            ← Go: Histogram(), TopOffenders() map poll
│   │   ├── tcp_retransmit/
│   │   │   ├── tcp_retransmit.bpf.c ← eBPF C: tp_btf/tcp_retransmit_skb
│   │   │   ├── gen.go
│   │   │   └── loader.go
│   │   ├── offcpu/                  ← off-CPU (blocked time) profiler
│   │   │   ├── offcpu.bpf.c         ← eBPF C: sched_switch block/wake + stacks
│   │   │   ├── gen.go
│   │   │   └── loader.go            ← Go: AllStacks() map read, no ringbuf
│   │   ├── fsync/                   ← always-on fsync latency tracer
│   │   │   ├── fsync.bpf.c          ← eBPF C: kprobe/kretprobe + LRU_HASH aggregation
│   │   │   ├── gen.go
│   │   │   └── loader.go            ← Go: attach kprobes, TopOffenders() map poll
│   │   └── mongo_query/             ← client-side MongoDB query latency tracer
│   │       ├── mongo_query.bpf.c    ← eBPF C: syscall tracepoints on connect/write/read
│   │       ├── gen.go
│   │       └── loader.go            ← Go: track connections to port 27017, parse OP_MSG
│   │
│   ├── trigger/
│   │   └── engine.go                ← threshold evaluator → calls ebpf.Manager.Activate
│   │
│   ├── procinfo/
│   │   └── procinfo.go              ← shared /proc readers (cmdline, cgroup)
│   │
│   ├── iodiag/
│   │   └── classify.go              ← correlation engine → io_diagnosis verdict
│   │
│   ├── offcpu/
│   │   ├── report.go                ← blocked-time report builder (on-demand)
│   │   └── folded.go                ← off-CPU flamegraph folded stacks
│   │
│   ├── runq/
│   │   └── report.go                ← level-2 run-queue report builder (on-demand)
│   │
│   ├── cpuprofile/
│   │   ├── report.go                ← BuildReport / BuildReportForPID (symbolized)
│   │   ├── folded.go                ← WriteFolded: flamegraph-ready folded stacks
│   │   ├── symbols.go               ← exported resolvers (shared with offcpu)
│   │   ├── kallsyms.go              ← kernel symbol resolution (/proc/kallsyms)
│   │   └── usersym.go               ← user symbol resolution (ELF + /proc/pid/maps)
│   │
│   ├── fsync/
│   │   └── analyzer.go              ← polls LRU map, enriches PIDs, publishes FsyncAnalysis
│   │
│   ├── mongo/
│   │   └── analyzer.go              ← polls mongo_query eBPF maps, publishes MongoAnalysis
│   │
│   ├── dbinspector/                 ← extensible DB inspector interface + registry
│   │   ├── inspector.go             ← DBInspector interface (Name/Start/Report)
│   │   ├── registry.go              ← Registry: Register, StartAll, Report
│   │   └── mongo.go                 ← MongoInspector adapter (wraps mongo.Analyzer)
│   │
│   ├── process/
│   │   └── inspector.go             ← /proc/[pid] scanner, top-N CPU/RSS, K8s metadata
│   │
│   └── exporter/
│       ├── exporter.go              ← HTTP batch+gzip exporter with retry
│       └── prometheus.go            ← :9200/metrics, GET /api/diagnose, GET /api/profile
│
├── deploy/
│   ├── Dockerfile                   ← multi-stage: clang builder + distroless runtime
│   ├── Dockerfile.db-inspector      ← same builder, produces slim db-inspector binary
│   ├── obs-agent.service            ← systemd unit (capabilities, cgroups limits)
│   ├── config.yaml.example          ← annotated config reference
│   ├── daemonset.yaml               ← Kubernetes DaemonSet + ServiceMonitor
│   ├── db-inspector.yaml            ← Kubernetes sidecar ConfigMap + Deployment + Service
│   └── db-inspector-config.yaml.example ← annotated db-inspector config reference
│
├── Makefile                         ← generate / build / build-inspector / install / image
└── go.mod
```

---

## 3. Module Reference

### `internal/config`
Single source of truth for all tunable parameters. `config.Defaults()` returns a valid config; `config.Load(path)` merges a YAML file on top. Fields use `time.Duration` so the YAML can say `60s` or `1m`. `config.LoadDBInspector(path)` loads the slim sidecar config (log level, listen addr, mongo settings only).

### `internal/model`
Pure data structs – no methods, no imports except `time`. Everything the agent produces is defined here. The `Snapshot` struct is the wire format sent to the central server. `DBInspectReport` and `InspectReport` are the wire types for the db-inspector `/api/inspect` endpoint.

### `internal/collector`
Always-on. Reads `/proc` every `collect.interval` (default 5s). The `Collector.Metrics` channel is buffered to 4 so a slow consumer doesn't block scraping. Delta-based rates (bytes/s, ops/s) are computed from two consecutive samples.

### `internal/ebpf/manager`
Central eBPF lifecycle controller. Maintains a `moduleState` per module (active/inactive, lastStop for cool-down). `Activate()` is idempotent – calling it twice while a module is active is a no-op. Auto-stop is implemented via `context.WithTimeout`.

### `internal/runq`
On-demand builder for the level-2 run-queue report. `BuildReport(loader, metrics, opts)` reads the per-TGID LRU map, filters to processes whose **max** wait breached `process_threshold_us`, enriches each with `/proc` cmdline + cgroup, and folds the global histogram into non-empty labelled buckets. No goroutine, no polling — called from `GET /api/diagnose` only, mirroring `internal/cpuprofile`.

### `internal/cpuprofile`
Symbolization and report building for the CPU profiler. `BuildReport` aggregates all processes; `BuildReportForPID` scopes to one (skipping the 1 %-of-system noise floor, since a single target is 100 % of its own profile). `WriteFolded` streams folded stacks straight to an `http.ResponseWriter` for flamegraph rendering. Kernel symbols come from `/proc/kallsyms`, user symbols from ELF + `/proc/<pid>/maps`, both cached with periodic eviction.

### `internal/iodiag`
Correlation engine.  `Classify(metrics, offcpuReport, thresholds)` walks node → device → blocked tasks → process → stack and returns a `model.IODiagnosis`: a verdict, a confidence, the evidence chain, the raw numbers behind it, and the list of signals that were missing.  Pure function over one `NodeMetrics` snapshot — no state, no I/O, called on demand from `/api/diagnose`.

### `internal/offcpu`
On-demand builder for the blocked-time report.  Aggregates the `offcpu` eBPF counts map by process, folds identical blocking sites across threads, and renders each site as a combined stack (user frames, then the kernel frames that actually blocked, tagged `_[k]`).  Reuses `internal/cpuprofile`'s symbol caches via its exported resolvers rather than building its own.  `WriteFolded` emits off-CPU flamegraph input weighted by **microseconds blocked** instead of sample count.

### `internal/trigger`
Stateless evaluator that runs every `trigger.eval_interval`. Reads the latest `NodeMetrics` snapshot from the collector (non-blocking `Latest()` call) and calls `manager.Activate()` when thresholds are breached. The manager handles cool-down so the trigger engine can fire freely.

### `internal/process`
Scans all `/proc/[pid]` directories every `process.scan_interval`. Uses a two-sample delta for CPU% and IO rates. Container/K8s metadata is extracted from the cgroup path (works for cgroupv1 and cgroupv2) and optionally from `/proc/[pid]/environ`.

### `internal/fsync`
Always-on fsync analysis loop. `Analyzer.Start()` loads the eBPF module at agent startup and runs a `time.Ticker` every `fsync.poll_interval` (default 5 s). On each tick it batch-reads the in-kernel LRU map, enriches each PID entry with `/proc/<pid>/cmdline` and cgroup path, classifies known workloads (databases, log agents, antivirus), and atomically stores the result as a `*model.FsyncAnalysis`. The snapshot is only published when the system is under pressure (`CPU > cpu_threshold OR Mem > mem_threshold`), so `GET /api/diagnose` always reflects the most-recent high-pressure picture.

### `internal/mongo`
MongoDB slow-query analysis loop. `Analyzer.Start()` loads the `mongo_query` eBPF module and runs a poll ticker. On each tick it reads the in-kernel LRU stats map and recent slow-query events, enriches PIDs via `/proc`, and atomically stores a `*model.MongoAnalysis`. Accepts a `nil` collector — when nil, the snapshot is always published regardless of CPU/mem pressure (sidecar mode).

### `internal/dbinspector`
Extensible registry for database inspectors. `DBInspector` is a three-method interface (`Name()`, `Start()`, `Report()`). `Registry.StartAll()` launches each inspector in its own goroutine. `Registry.Report()` aggregates all inspector snapshots into a single `*model.InspectReport`. Adding a new database requires only a new adapter file implementing `DBInspector` — zero changes to existing code.

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

**Config globals**:
- `target_tgid` (default 0 = system-wide) – restricts sampling to one process, **compared against TGID** so every thread of the target is captured. Set by the on-demand profiler (§17).
- `emit_events` (default 1) – when 0, the per-sample ringbuf write is skipped entirely and `counts` is the only data source. Targeted profiles set this to 0: the ringbuf duplicates data already in `counts`, and consuming it costs two `stack_traces` lookups per sample in userspace.

**Go side**:
- `cpu_profile.New(Config{...})` – explicit construction (`NewLoader(hz)` remains the system-wide default used by the trigger engine). `MaxEntries` shrinks the `counts` / `stack_traces` maps for targeted runs.
- `Loader.TopPIDs(n)` returns the top-N `(pid, stack)` entries by sample count. Note this is per unique stack key, **not** per process — use `cpuprofile.BuildReport` for the per-process view.
- `cpuprofile.BuildReport(l)` / `BuildReportForPID(l, tgid)` – symbolized, aggregated report.
- `cpuprofile.WriteFolded(l, tgid, w)` – streams folded stacks for flamegraph rendering.

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
    │  start[pid] = bpf_ktime_get_ns()      (LRU_HASH – tasks that wake and
    │                                        then exit never reach switch)
sched_switch (next task gets CPU)
    │  lat_us = (now - start[next->pid]) / 1000
    │  delete start[next->pid]
    │
    ├── hist[log2(lat_us)]++                ← every switch, unconditionally
    │
    ├── if lat_us >= runq_track_min_us:     ← aggregation floor (default 100us)
    │       runq_stats[tgid]:               (LRU_HASH, 8192 entries)
    │         tracked_switches++    (atomic)
    │         total_latency_ns += Δ (atomic)
    │         slow_events++         (atomic, when >= runqlat_threshold_us)
    │         max_latency_ns = max(Δ)
    │         last_seen_ts = now
    │         comm = next->comm
    │
    └── if lat_us >= runqlat_threshold_us:
            push runq_event → RINGBUF
```

**Why tp_btf?** `tp_btf` programs receive typed kernel structs directly (via BTF), avoiding the need to cast raw tracepoint arguments. This is more portable than raw tracepoints.

**Why the `runq_track_min_us` floor?** `sched_switch` fires 100k–500k times/s on a busy host. Aggregating every one of them into the per-process map would cost a lookup plus three atomics per switch. The floor skips the sub-100 µs waits that carry no diagnostic signal, removing >90 % of the map writes — while the global histogram still counts every switch, so no distribution fidelity is lost.

**Configurable thresholds**: both `runqlat_threshold_us` and `runq_track_min_us` are `const volatile` globals rewritten at load time via `spec.Variables[...].Set(v)`.

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

## 7. DB Inspector Sidecar

### Overview

`db-inspector` is a **slim sidecar binary** that deploys alongside application pods and exposes a single `GET /api/inspect` endpoint with per-database slow-query diagnostics. Unlike the full `obs-agent` DaemonSet (which has CPU profiler, IO latency, fsync tracer, trigger engine, proc collector, etc.), the sidecar contains only the MongoDB query tracer and a minimal HTTP server.

**Why a separate binary instead of configuring obs-agent:**
- Config-disabling still boots all components; a dedicated binary is smaller with zero dead code
- The sidecar's public API surface is intentionally narrow (`/healthz`, `/api/inspect`)
- Does not require node-level deployment — one sidecar per application pod

### Architecture

```
Pod:
  ┌─────────────────────┐    ┌──────────────────────────────────────────┐
  │  app container      │    │  db-inspector sidecar                    │
  │  (mongodb client)   │    │                                          │
  │                     │    │  DBInspector Registry                    │
  │  connects →         │    │  ┌─────────────────────────────────────┐ │
  │    mongodb:27017    │◄───┤  │ MongoInspector                      │ │
  └─────────────────────┘    │  │  └── mongo.Analyzer (eBPF)          │ │
                             │  │       hooks: connect/write/read/close│ │
                             │  │       tracks connections to :27017   │ │
                             │  └─────────────────────────────────────┘ │
                             │  ┌─────────────────────────────────────┐ │
                             │  │ (MySQLInspector) ← future           │ │
                             │  └─────────────────────────────────────┘ │
                             │                                          │
                             │  GET /api/inspect  →  InspectReport     │
                             │  GET /healthz      →  "ok"              │
                             └──────────────────────────────────────────┘
         hostPID: true, CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE, CAP_SYS_ADMIN
```

### DBInspector Interface

```go
// internal/dbinspector/inspector.go
type DBInspector interface {
    Name() string                        // "mongo", "mysql", ...
    Start(ctx context.Context) error     // blocks until ctx cancelled
    Report() *model.DBInspectReport      // nil = no data yet
}
```

### GET /api/inspect Response

```json
{
  "timestamp": "2026-04-18T10:00:00Z",
  "databases": [
    {
      "database": "mongo",
      "mongo_report": {
        "type": "mongo_analysis",
        "timestamp": "2026-04-18T10:00:00Z",
        "slow_threshold_ms": 500,
        "recent_slow_queries": [
          {
            "pid": 1234, "tid": 1234, "fd": 7,
            "latency_ms": 3512.4,
            "op_type": "find",
            "collection": "users",
            "dest_addr": "127.0.0.1:27017",
            "comm": "app-server"
          }
        ],
        "top_processes": [
          {
            "pid": 1234, "comm": "app-server",
            "total_queries": 500, "slow_queries": 12,
            "avg_latency_ms": 45.2, "max_latency_ms": 3512.4
          }
        ]
      }
    }
  ]
}
```

### Configuration

```yaml
# deploy/db-inspector-config.yaml.example
log_level: info
listen_addr: ":9201"

mongo:
  enabled: true
  port: 27017
  slow_query_threshold_ms: 500
  poll_interval: 5s
  top_n: 20
  stale_seconds: 60
  max_recent_queries: 100
```

Environment variable overrides: `MONGODB_TRACING_ENABLED=true`, `MONGODB_SLOW_QUERY_THRESHOLD_MS=200`.

### Kubernetes Deployment

```bash
# Apply ConfigMap + example Deployment patch + Service
kubectl apply -f deploy/db-inspector.yaml

# Health check
kubectl exec -it <pod> -c db-inspector -- wget -qO- localhost:9201/healthz

# Inspect slow queries
kubectl exec -it <pod> -c db-inspector -- \
    wget -qO- localhost:9201/api/inspect | jq '.databases[0].mongo_report'
```

Required pod-level settings (see `deploy/db-inspector.yaml`):
- `spec.hostPID: true` — sidecar must see `/proc/[pid]` for all node processes
- Container capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`
- Volume mounts: `/proc` (read-only), `/sys` (writable), `/sys/fs/bpf`, `/sys/kernel/debug`

### Build

```bash
# Binary
make build-inspector
# Produces: ./build/db-inspector

# Docker image
make image-inspector IMAGE_TAG=v1.0.0
```

### Extending to New Databases

To add MySQL (or any other database):

1. `internal/ebpf/mysql_query/` — new eBPF C file + loader (hooks on port 3306)
2. `internal/mysql/analyzer.go` — same pattern as `internal/mongo/analyzer.go`
3. `internal/dbinspector/mysql.go` — 10-line adapter implementing `DBInspector`
4. Add `MySQLConfig` to `DBInspectorConfig` in `internal/config/db_inspector_config.go`
5. Add `if cfg.MySQL.Enabled { registry.Register(dbinspector.NewMySQLInspector(&cfg.MySQL)) }` in `cmd/db-inspector/main.go`
6. Add `MySQLReport *MySQLAnalysis` to `model.DBInspectReport`

Zero changes to existing code for each new database.

---

## 8. Data Flow

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

## 9. Build Pipeline

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

> **`-Wno-missing-declarations` is required.** `bpftool btf dump` on kernels ≥ 6.x emits nested forward declarations (`struct ns_tree;`, `union pipe_index;`, `struct __fs_path;`, …) that clang reports as *"declaration does not declare anything"*. With `-Werror` this fails every module's build. All `gen.go` cflags therefore carry `-Wno-missing-declarations`; `-Werror` is retained so genuine warnings in our own `.bpf.c` files still fail the build. If you add a new eBPF module, copy the full cflag string from an existing `gen.go`.

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

## 10. Installation & Running

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

## 11. Kubernetes Deployment

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

## 12. Security & Capabilities

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

## 13. Prometheus Metrics

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

## 14. Performance Budget

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

## 15. Extending the Agent

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
## 16. MySQL Slow Query Tracer

### Overview

The MySQL tracer is an **always-on server-side** analyzer that attaches uprobes directly to the running `mysqld` binary. Unlike the MongoDB tracer (which hooks client-side syscalls), this tracer hooks `dispatch_command` inside mysqld itself — capturing the exact SQL text before it executes, with no wire-protocol parsing and full TLS compatibility.

### Hook mechanism

```
uprobe: mysqld!dispatch_command(THD *thd, COM_DATA *com_data, enum command)
    │  command == COM_QUERY (3)?  No → return 0 (zero overhead)
    │  Yes:
    │  start_ts = bpf_ktime_get_ns()
    │  query_str = com_data[0..7]   (COM_QUERY_DATA.query_str at union offset 0)
    │  bpf_probe_read_user_str(pending.query, 256, query_str)
    │  mysql_pending[tid] = {start_ts, query, comm}
    │
uretprobe: mysqld!dispatch_command
    │  pending = mysql_pending[tid]
    │  latency_ns = now - pending.start_ts
    │  delete mysql_pending[tid]
    │
    ├── mysql_pid_stats[tgid]:   total_queries++, total_latency_ns += Δ, ...
    │
    └── if latency_ns > slow_query_threshold_ns:
            push mysql_slow_event_t → RINGBUF
```

### Configuration (`mysql:` section in config.yaml)

```yaml
mysql:
  enabled: true
  mysqld_path: /usr/sbin/mysqld      # path to mysqld binary for uprobe
  slow_query_threshold_ms: 100       # emit ringbuf event when query > 100 ms
  poll_interval: 5s
  top_n: 20
  stale_seconds: 60
  max_recent_queries: 100
```

Environment variable overrides: `MYSQL_TRACING_ENABLED=true`, `MYSQL_SLOW_QUERY_THRESHOLD_MS=50`, `MYSQL_MYSQLD_PATH=/usr/bin/mysqld`.

### GET /api/diagnose — MySQLReport field

```bash
curl -s http://localhost:9200/api/diagnose | jq .mysql_report
```

```json
{
  "type": "mysql_analysis",
  "timestamp": "2026-04-19T10:00:00Z",
  "slow_threshold_ms": 100,
  "mysqld_path": "/usr/sbin/mysqld",
  "recent_slow_queries": [
    {
      "pid": 1234, "tid": 1234,
      "latency_ms": 532.1,
      "query": "SELECT * FROM users WHERE id = 1",
      "comm": "mysqld"
    }
  ],
  "top_processes": [
    {
      "pid": 1234, "comm": "mysqld",
      "total_queries": 500, "slow_queries": 12,
      "avg_latency_ms": 45.2, "max_latency_ms": 532.1
    }
  ]
}
```

### Verify uprobes are loaded

```bash
sudo bpftool prog list | grep -E 'uprobe|kprobe'
# Expected:
#   kprobe  name uprobe_dispatch     (uprobe type shows as kprobe in bpftool)
#   kprobe  name uretprobe_dispatch

sudo bpftool map show name mysql_pid_stats
sudo bpftool map show name mysql_pending
```

## 17. Run-Queue Analysis & On-Demand CPU Profiling

### Overview

Answers the question *"which process is stalling, and why?"* using a **two-level threshold** scheme plus a click-through profiler. Nothing runs in the background: level 1 reuses the lazy `Manager.Activate` state machine, the level-2 report is built only when `/api/diagnose` is called, and profiling samples only while a request is in flight.

```
Level 1 (node)      cpu_usage% > runq.node_cpu_threshold
                    OR load1/NumCPU > runq.node_load_threshold
                         │  trigger engine → Manager.Activate(ModRunQLat)
                         ▼
Level 2 (process)   per-TGID MAX run-queue wait >= runq.process_threshold_us
                         │  GET /api/diagnose → .runqueue_report.top_offenders[]
                         ▼  each offender carries "profile_url"
On demand           GET /api/profile?pid=N
                    → PID-filtered perf_event sampling for N seconds
                    → symbolized CPUProfileReport, or folded stacks for a flamegraph
```

**Why two levels?** Level 1 keeps the scheduler tracepoints unloaded on a healthy node (zero overhead). Level 2 keeps the report to the processes that actually stalled, instead of listing every process that ever ran. CPU% alone is not a sufficient level-1 gate — run-queue oversubscription typically presents as **high load with moderate CPU**, so either signal opens the gate.

### GET /api/diagnose — RunQueueReport field

Absent entirely when the node never breached level 1, or when no process breached level 2.

```bash
curl -s localhost:9200/api/diagnose | jq .runqueue_report
```

```json
{
  "type": "runqueue_analysis",
  "timestamp": "2026-07-27T17:20:00Z",
  "system": { "cpu_percent": 93.4, "load_normalised": 3.1, "num_cpu": 8 },
  "thresholds": {
    "node_cpu_percent": 85.0, "node_load": 1.5,
    "process_us": 10000, "track_min_us": 100
  },
  "histogram": [
    { "range": "128us-255us", "low_us": 127, "high_us": 254, "count": 84210 },
    { "range": "8.19ms-16.38ms", "low_us": 8191, "high_us": 16382, "count": 312 }
  ],
  "top_offenders": [
    {
      "pid": 4821, "comm": "catalog",
      "cmdline": "/app/catalog -config /etc/catalog.yaml",
      "cgroup_path": "/kubepods/burstable/pod.../catalog",
      "tracked_switches": 18432, "slow_events": 291,
      "avg_latency_ms": 1.84, "max_latency_ms": 47.2,
      "profile_url": "/api/profile?pid=4821"
    }
  ]
}
```

> `avg_latency_ms` is the mean over **tracked** waits (≥ `track_min_us`), not over every context switch — sub-threshold waits are deliberately not aggregated in-kernel. `slow_events` counts waits ≥ `process_us`.

### GET /api/profile — click-through per-process profile

```bash
# JSON (default): symbolized, aggregated, scoped to the one process
curl -s "localhost:9200/api/profile?pid=4821&duration=5s" | jq .report

# Folded stacks → flamegraph
curl -s "localhost:9200/api/profile?pid=4821&format=folded" > out.folded
flamegraph.pl out.folded > flame.svg      # or drop out.folded into speedscope.app
```

| Parameter | Default | Notes |
|---|---|---|
| `pid` | — | required; the target process (all its threads are sampled) |
| `duration` | `profile.default_duration` (10s) | capped at `profile.max_duration`; ignored on a cache hit |
| `format` | `json` | `folded` streams flamegraph-ready text |

| Condition | Status |
|---|---|
| success | 200 |
| missing/invalid `pid`, or `duration` > max | 400 |
| no such process | 404 |
| another profile already sampling | 429 + `Retry-After` |
| eBPF or `profile.enabled` off | 503 |

**Resolution order in `Manager.ProfilePID`** (cheapest first):

1. **Result cache** – a profile for the same PID within `profile.cache_ttl` is returned as-is (`"cached": true`). Clicking through a list of offenders and back costs nothing.
2. **Reuse the live system-wide profiler** – if the trigger engine already activated `cpu_profile` (i.e. the node is hot, which is exactly when an operator clicks through), the target's stacks are already in its `counts` map. Extract them: **zero extra sampling, instant response** (`"reused": true`).
3. **Dedicated PID-filtered profiler** – load a fresh `cpu_profile` instance with `target_tgid` set and `emit_events` off, sample for `duration`, build the report while the maps are still open, then tear it down.

Deliberately independent of the `Activate`/cool-down state machine: an operator's click must never be silently swallowed by a cool-down window. Profiling is **single-flight agent-wide** — two concurrent perf_event sets would double the sampling cost on an already-stressed node.

### Configuration

See the `runq:` and `profile:` sections in `deploy/config.yaml.example`. Environment overrides: `RUNQ_ENABLED`, `RUNQ_NODE_CPU_THRESHOLD`, `RUNQ_NODE_LOAD_THRESHOLD`, `RUNQ_PROCESS_THRESHOLD_US`, `PROFILE_ENABLED`, `PROFILE_MAX_DURATION`.

`runq.process_threshold_us` is the single source of truth: it is both the level-2 report filter and the value pushed into the kernel as `runqlat_threshold_us`, so `slow_events` counts exactly the level-2 breaches. The old `ebpf.runqlat_threshold_us` is deprecated and consulted only as a fallback when `runq.process_threshold_us` is 0.

### Test

```bash
# Spike CPU and load to breach level 1
stress-ng --cpu $(nproc) --fork 8 --timeout 120s &

sudo bpftool map dump name runq_stats | head       # per-TGID entries appear
curl -s localhost:9200/api/diagnose | jq '.runqueue_report.top_offenders[0]'

PID=$(curl -s localhost:9200/api/diagnose | jq -r '.runqueue_report.top_offenders[0].pid')
curl -s "localhost:9200/api/profile?pid=$PID&duration=5s" | jq '.report.processes[0]'
```

Negative check: with the node idle, `.runqueue_report` must be **absent** and `bpftool prog list | grep sched` must show nothing.

### Overhead

| Component | CPU | Memory |
|---|---|---|
| runqlat per-process aggregation (active, 200k switches/s, 100 µs floor) | ~0.02 % | ~0.5 MB (LRU map) |
| Run-queue report build (per `/api/diagnose` call) | ~1 ms | — |
| On-demand profile (only while sampling, PID-filtered) | ~0.1 % for `duration` | ~1.2 MB, freed at window end |

---

## 18. Off-CPU Profiling — the module that explains iowait

### Why an on-CPU profiler cannot answer this

`cpu_profile` samples with `perf_event`, which fires **only on a CPU that is running a task**. A task asleep in `TASK_UNINTERRUPTIBLE` (D state) — precisely what iowait accounts for — is by definition not on a CPU and is never sampled. No amount of CPU profiling will ever explain iowait; it is a structural limitation, not a tuning problem.

`offcpu` inverts the question: it records the stack **at the moment a task blocks**, plus the time until it wakes.

### Mechanism (`offcpu.bpf.c`)

One `tp_btf/sched_switch` program, two halves:

```
sched_switch(prev, next)
  ├── prev is LEAVING the CPU
  │     state = prev->__state          (CO-RE: `state` on kernels < 5.14)
  │     if not (state & track_state):  return   ← preempted, not blocked
  │     blocked[prev->pid] = {
  │         ts    = bpf_ktime_get_ns(),
  │         kstack = bpf_get_stackid(ctx, &stack_traces, 0),
  │         ustack = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK),
  │         comm, tgid }
  │     ^ `current` is still prev at this tracepoint, so the stack walk
  │       captures the blocking task — this is what makes it attributable.
  │
  └── next is ENTERING the CPU
        info  = blocked[next->pid]        (copied out BEFORE delete)
        delta = now - info.ts             ← time spent off-CPU
        if delta < min_block_us: return
        counts[{tgid, pid, kstack, ustack, comm}] += delta
```

**Maps**: `stack_traces` (STACK_TRACE), `blocked` (LRU_HASH, 65 536 — LRU because a task can block and then exit without ever being scheduled again), `counts` (LRU_HASH, 10 240). No ring buffer at all — everything aggregates in-kernel and userspace reads the map once, on demand.

**Overhead gate**: the expensive operation is `bpf_get_stackid`, and it runs **only when prev is actually blocking**. Involuntary preemption leaves prev in `TASK_RUNNING` and returns before any stack walk — on a busy host that is the large majority of context switches.

**CO-RE task state**: kernel 5.14 renamed `task_struct.state` → `__state` and narrowed it from `long` to `unsigned int`. Both shapes are declared as standalone `preserve_access_index` structs so the program compiles against either `vmlinux.h` and CO-RE picks the right one at load time.

### Reading iowait correctly

**iowait is idle time in disguise.** A CPU going idle charges the tick to `iowait` rather than `idle` whenever any task on its runqueue sits in D state. The kernel's own documentation calls the value unreliable. So:

| Symptom | Meaning |
|---|---|
| high iowait + high `disk_io_util_percent` + load > NumCPU | genuine I/O saturation — use `offcpu_report` and `io_latency` |
| high iowait + `io_util_percent` ≈ 0 + low load | **the box is idle** with something parked in D state (io_uring workers do this). Not a problem. |

A worked example: `iowait 81.6%`, `idle 0%`, `load1 0.47` on 2 CPUs, `io_util 0%`, `write 1.6 KB/s`. That machine is 82% idle — the iowait is pure accounting.

### GET /api/diagnose — `offcpu_report`

Present only while the module is active (triggered by `iowait > offcpu.iowait_threshold`).

```json
{
  "type": "offcpu_profile",
  "window": { "min_block_us": 1000, "tracked_states": "uninterruptible" },
  "system": { "total_blocked_ms": 48210.5, "total_events": 1932, "processes": 6 },
  "processes": [
    {
      "pid": 920070, "comm": "dragonfly",
      "blocked_ms": 41022.3, "max_blocked_ms": 812.4, "events": 1541,
      "threads_sampled": 4, "percent_of_total": 85.09,
      "top_stacks": [
        {
          "symbol_stack": [
            "io_uring_submit_and_get_events",
            "__io_uring_enter_[k]", "io_cqring_wait_[k]", "schedule_[k]"
          ],
          "blocked_ms": 38110.2, "max_blocked_ms": 812.4,
          "events": 1402, "percent": 92.9
        }
      ]
    }
  ]
}
```

> `blocked_ms` is wall-clock time **summed across threads** — 8 threads each blocked 1 s over a 1 s window reports 8000 ms. Compare stacks against each other, not against the window.

### GET /api/profile?mode=offcpu

The same click-through as the on-CPU profiler, answering the opposite question:

```bash
# where is this process blocked?
curl -s "localhost:9200/api/profile?pid=$PID&mode=offcpu&duration=10s" | jq .offcpu_report

# off-CPU flamegraph (weight = microseconds blocked, not sample count)
curl -s "localhost:9200/api/profile?pid=$PID&mode=offcpu&format=folded" > offcpu.folded
flamegraph.pl --title="Off-CPU Time" --countname=us offcpu.folded > offcpu.svg
```

Same resolution order as §17 — cache → reuse the live system-wide module → dedicated PID-filtered window — with one difference: there is no minimum-sample heuristic. A single 4-second D-state stall is one event and is exactly the thing worth reporting, so any data from the live module is returned.

The result cache is keyed by `(pid, mode)`: an on-CPU profile must never be served for an off-CPU request, since they answer opposite questions.

### Configuration

See the `offcpu:` section in `deploy/config.yaml.example`. Environment overrides: `OFFCPU_ENABLED`, `OFFCPU_IOWAIT_THRESHOLD`, `OFFCPU_MIN_BLOCK_US`, `OFFCPU_TRACK_INTERRUPTIBLE`.

`track_interruptible` defaults **off**. Enabling it also attributes ordinary S-state sleeps (epoll, futex, nanosleep), which on an idle-ish server dwarfs everything else and buries the D-state stalls you are hunting.

### Test

```bash
# Generate genuine D-state blocking
fio --name=blk --ioengine=sync --rw=randread --bs=4k --size=2G \
    --numjobs=4 --direct=1 --filename=/tmp/fio.tmp &

curl -s localhost:9200/api/diagnose | jq '.offcpu_report.processes[0].top_stacks[0]'
# expect a kernel stack ending in schedule_[k] / io_schedule_[k]

sudo bpftool map show name counts       # bounded at max_map_entries
sudo bpftool prog list | grep tracing   # handle_switch attached
```

### Overhead

| Component | CPU | Memory |
|---|---|---|
| offcpu (active, D-state only, ~5k blocks/s) | ~0.05 % | ~6 MB (stack_traces + counts) |
| Report build (per `/api/diagnose` call) | ~5 ms (symbolization, cached after first) | — |

---

## 19. Correlated I/O Diagnosis — connecting the chain

### The problem

The agent produced good *symptoms* but did not connect them. Each signal is ambiguous on its own:

| Signal | What it cannot tell you |
|---|---|
| iowait | whether the machine is stalled or merely idle |
| disk throughput | whether the device is slow or saturated |
| a CPU profile | anything at all about a blocked task — it only samples running ones |
| a D-state count | *what* the task is stuck on, or *why* |

`io_diagnosis` walks the layers in order and emits a verdict **with the evidence**, so the reasoning is auditable rather than trusted:

```
node → device → blocked tasks → process → stack
```

### Same-window collection

Correlation is only sound if every signal describes the same instant, so these are collected in one `collect()` cycle alongside CPU/mem/disk/net rather than on separate tickers:

| Source | Field | Why it matters |
|---|---|---|
| `/proc/pressure/{io,cpu,memory}` | `metrics.pressure` | **The decisive signal.** `io.full` = time when *nothing* could progress. Distinguishes a real stall from idle-time-relabelled-as-iowait. |
| `/proc/vmstat` | `metrics.vmstat` | `nr_dirty`, `nr_writeback`, `nr_dirtied`, `nr_written`, `pgpgin`, `pgpgout`, `pswpin/out` — separates writeback congestion from device latency |
| `/proc/[pid]/stat` + `wchan` | `metrics.d_state` | Tasks currently in D, the kernel function each sleeps in, and how long each has been continuously blocked |
| `/proc/diskstats` fields 12/14 | `metrics.disk[].in_flight`, `.avg_queue_depth`, `.read_avg_wait_ms`, `.write_avg_wait_ms` | Already parsed but previously discarded. High in-flight + low throughput = slow device, not busy one |
| eBPF `io_latency` | `io_latency_histogram` | The biolatency distribution — computed in-kernel all along, previously unreachable |
| eBPF `offcpu` | `offcpu_report` | The blocking stack (§18) |

**D-state duration without eBPF**: the scanner remembers when each PID was first seen in D and clears it the moment it leaves, so `in_d_state_ms` is a continuously-blocked duration quantised to the scan interval. That is what makes the "blocked > 1 s" rule work even when the eBPF modules are off.

### Verdicts

| Verdict | Condition | Meaning |
|---|---|---|
| `storage_latency_stall` | iowait high **AND** throughput low **AND** (task blocked >1s in the storage path **OR** avg wait/request > 50 ms) | The device is **slow, not busy**. More IOPS capacity will not help — per-request latency is the problem. Look beneath the device: network storage RTT, hypervisor steal, cgroup `io.max`, failing disk. |
| `high_disk_throughput` | util ≥ 70% **AND** throughput high | Genuine saturation — a capacity problem. |
| `writeback_congestion` | dirty ratio ≥ 15% **AND** iowait high | Stall is in the page cache; writers throttled in `balance_dirty_pages`. Not the device's fault. |
| `iowait_accounting_artifact` | iowait high **BUT** device idle **AND** nothing blocked >1s **AND** no PSI pressure | **Not a problem.** The CPU was idle while a task sat parked in D state (io_uring workers do this). Do not page anyone. |
| `healthy` / `inconclusive` | — | Nothing to report / signals conflict |

`confidence` degrades as links go missing, and `missing[]` names exactly which signal was absent (`psi`, `d_state census`, `offcpu_report`) so a low-confidence verdict is actionable rather than mysterious.

### Example — the artifact case

```bash
curl -s localhost:9200/api/diagnose | jq .io_diagnosis
```

```json
{
  "type": "io_diagnosis",
  "verdict": "iowait_accounting_artifact",
  "confidence": "medium",
  "summary": "iowait 81.6% is an accounting artifact, NOT an I/O problem: sda is idle (0.0% util, 0.00 MB/s), load/cpu is 0.24 and nothing blocked longer than 1000ms. The CPU was idle while a task sat parked in D state.",
  "chain": [
    { "stage": "node",          "confirmed": true,  "detail": "iowait 81.6%, idle 0.0%, load/cpu 0.24, 2 procs blocked; PSI io some=0.1% full=0.0%" },
    { "stage": "device",        "confirmed": true,  "detail": "sda: util 0.0%, 0.00 MB/s, avg wait 0.50 ms, in-flight 0" },
    { "stage": "blocked_tasks", "confirmed": true,  "detail": "2 task(s) in D state, longest 340ms; iou-wrk-920070(920412) [kthread] 340ms" },
    { "stage": "process",       "confirmed": false, "detail": "not attributed — off-CPU profiler was not active" },
    { "stage": "stack",         "confirmed": false, "detail": "no blocking stacks; enable offcpu or query /api/profile?mode=offcpu" }
  ],
  "next_steps": [
    "No action needed. iowait is idle time charged differently when any task on the runqueue is in D state.",
    "Alert on PSI io.full (pressure.io.full.avg10) instead of iowait — it measures lost work rather than idle time."
  ]
}
```

### Alerting recommendation

**Alert on `pressure.io.full.avg10`, not on `cpu.iowait_percent`.** PSI measures work that could not proceed; iowait measures idle time that happened to coincide with a D-state task. The example above is exactly why the second one pages people at 3am for nothing.

### Configuration

`io_diag:` in `deploy/config.yaml.example`, plus the `collect.d_state_*` knobs. All thresholds are echoed into the report so a consumer can re-derive the verdict.

### Test

```bash
# Genuine device latency (requires a slow or throttled device)
fio --name=lat --ioengine=sync --rw=randread --bs=4k --size=1G \
    --direct=1 --numjobs=2 --filename=/tmp/fio.tmp &
curl -s localhost:9200/api/diagnose | jq '.io_diagnosis.verdict, .io_diagnosis.chain'

# Writeback congestion
dd if=/dev/zero of=/tmp/big bs=1M count=20000 &
watch -n1 "curl -s localhost:9200/api/diagnose | jq -c '.metrics.vmstat, .io_diagnosis.verdict'"

# Verify the same-window signals are present
curl -s localhost:9200/api/diagnose | jq '.metrics.pressure, .metrics.vmstat, .metrics.d_state'
```

### Not yet covered

These were requested and are **not** implemented — they need new eBPF modules rather than wiring:

- **biostacks** — the submitting stack at `blk_mq_start_request`. `io_latency` records pid/comm/dev/sector/latency but no stack, so block I/O cannot yet be attributed to a call path. (`offcpu` covers the blocking side, which overlaps but is not the same thing.)
- **fileslower / ext4slower / xfsslower** — VFS- and filesystem-level slow-operation tracing.
- **`writeback:writeback_start` / `writeback_written` tracepoints** — the `writeback` module hooks reclaim, not these.
- **syncsnoop** — largely covered by the existing always-on `fsync` tracer (§6).

---

## 20. Review output
Use codex to review output of this code each change