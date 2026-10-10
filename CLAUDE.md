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
20. [Process Families, Network Flows & Query Digests](#20-process-families-network-flows--query-digests)
21. [Review output](#21-review-output)
22. [ClickHouse Export](#22-clickhouse-export)

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
│   │   ├── mongo_query/             ← client-side MongoDB query latency tracer
│   │   │   ├── mongo_query.bpf.c    ← eBPF C: syscall tracepoints on connect/write/read
│   │   │   ├── gen.go
│   │   │   └── loader.go            ← Go: track connections to port 27017, parse OP_MSG
│   │   └── netflow/                 ← always-on TCP flow accounting
│   │       ├── netflow.bpf.c        ← inet_sock_set_state, inet_csk_accept,
│   │       │                          tcp_sendmsg, tcp_cleanup_rbuf
│   │       ├── gen.go
│   │       └── loader.go            ← implements netflow.Source
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
│   ├── sqldigest/sqldigest.go       ← SQL → normalised digest (DB-agnostic)
│   ├── querystats/querystats.go     ← rolling per-digest CPU/runq/bytes, culprit/victim roles
│   ├── netinv/netinv.go             ← on-demand /proc TCP inventory (listen ports, connections)
│   ├── netflow/                     ← windowed per-process/family flow accounting
│   ├── procreport/procreport.go     ← builds process_report
│   ├── promcollect/                 ← family, MySQL and node (disk, PSI) Prometheus collectors
│   ├── mysql/cmdmap/cmdmap.go       ← MySQL command → class + digest
│   ├── mysql/mysqldsym/             ← mysqld hook symbols + prepare() layout per MySQL
│   │                                   version (testdata/*.syms, cmd/symdump)
│   │
│   ├── process/
│   │   └── inspector.go             ← /proc/[pid] scanner, top-N CPU/RSS, K8s metadata
│   │
│   ├── chsink/                      ← optional ClickHouse export (§22)
│   │   ├── schema.go                ← DDL generator + `clickhouse-schema` subcommand
│   │   ├── client.go                ← HTTP INSERT client, ok/retry/reject classification
│   │   ├── rows.go                  ← row types, builders, JSONEachRow encoding
│   │   ├── sink.go                  ← flush loop, bounded buffer, self-metrics
│   │   └── snapshot.go              ← diagnose snapshot triggers + privacy stripping
│   │
│   ├── drain/buffer.go              ← per-interval accumulator shared by the producers' drains
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
│   ├── db-inspector-config.yaml.example ← annotated db-inspector config reference
│   ├── clickhouse/
│   │   ├── schema.sql               ← default output of `obs-agent clickhouse-schema`
│   │   └── queries.sql              ← ad-hoc queries for the obs tables
│   └── grafana/                     ← gen/ (generator), two dashboard JSONs, README.md
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
| `cpu_count` | Gauge | CPUs usable by the agent (`runtime.NumCPU()`): the divisor of `family_cpu_percent` and process CPU%, so `percent / 100 * cpu_count` = cores |
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
| `family_*` (cpu_percent, mem_rss_bytes, processes, net_*, inbound/outbound bytes) | Gauge/Counter | Per process family; never per PID. See §20 |
| `mysql_*` (queries, query_cpu/runq_wait/wall seconds, query_bytes (`flow="out"` only: result bytes), query_disk_read/write bytes, query_io_wait/redo_wait seconds, digest_*, digest_info, events_dropped) | Counter | Per command class and per query digest. Per command: disk bytes always, `io_wait` / `redo_wait` only while measured over the whole digest window. Per digest (`mysql.prometheus_digests`, default `minimal`): cpu, calls, disk reads; `full` adds runq wait, bytes out, io wait. `events_dropped` counts commands genuinely lost (fallback ring buffer full or consumer behind). See §20 |
| `mysql_query_disk_read_bytes_total{command}` / `mysql_query_disk_write_bytes_total{command}` | Counter | Bytes MySQL statements caused to be read from / written to storage (task I/O accounting) |
| `mysql_query_io_wait_seconds_total{command}` / `mysql_query_redo_wait_seconds_total{command}` | Counter | Block-I/O wait (delay accounting) / commit wait in `log_write_up_to`; absent while not measured |
| `mysql_digest_disk_read_bytes_total{digest_id}` | Counter | Disk-read bytes per digest (`minimal` and `full`) |
| `mysql_digest_io_wait_seconds_total{digest_id}` | Counter | Block-I/O wait per digest (`full` only, while measured) |
| `mysql_query_cpu_coverage_ratio` | Gauge | CPU inside `dispatch_command` ÷ the traced mysqld processes' CPU over the digest window; absent while unknown; not clamped, can read slightly above 1 |
| `mysql_io_wait_available` / `mysql_redo_wait_available` | Gauge | 1 when per-statement block-I/O / commit wait is measured over the whole digest window, else 0 |
| `node_disk_read_bytes_total` / `node_disk_write_bytes_total` | Counter | Bytes read / written by the node's physical disks (whole devices without slaves; no loop, zram, dm, md); absent when `/proc/diskstats` is unreadable |
| `node_physical_disks` | Gauge | Number of disks counted in `node_disk_*_bytes_total` |
| `pressure_io_full_avg10` / `pressure_io_some_avg10` / `pressure_cpu_some_avg10` | Gauge | PSI avg10 in percent; only when PSI is available |
| `family_inbound_peer_bytes_total{family,peer_ip,service_port,flow}` | Counter | Inbound client bytes; top `netflow.max_inbound_peers` IPs node-wide, overflow `other`. See §20 |
| `mysql_digest_coverage_ratio` | Gauge | Share (0–1) of window query CPU explained by the exported digest series. See §20 |
| `mysql_agg_overflow_total` | Counter | Commands that bypassed in-kernel aggregation because the map was full (processed as full events; totals stay exact) |
| `mysql_text_events_dropped_total` | Counter | Statement text events dropped because the consumer was behind; first-sight texts are re-requested (no command lost; the hash's commands may show under a text-unavailable placeholder until the resend) |
| `mysql_hash_mismatch_total` | Counter | Kernel text hashes found inconsistent: a verification sample or resend whose digest differed from the cached one, or a first-sight text whose kernel hash differed from the Go reference; the hash is switched to exact per-event processing |
| `clickhouse_{rows_sent_total,rows_dropped_total,buffer_bytes,last_success_timestamp_seconds,snapshots_total,host_info}` | Counter/Gauge | ClickHouse sink health; registered only when `clickhouse.enabled`. See §22 |

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
| **eBPF netflow (always-on, ~100k hook calls/s)** — estimated, not measured | **~0.4%** | **~6 MB (maps)** |
| **MySQL tracer with in-kernel aggregation (20k QPS)** — estimated, not measured; kernel text hashing unmeasured | **~0.2 % kernel + < 0.1 % userspace (~0.3 %)** | **~35 MB typical**: kernel maps ~25 MB (agg 2 × 16 384 × (16 + 80) B ≈ 3.1 MB, `cmd_events` ringbuf 4 MB, `text_events` ringbuf 1 MB, `text_seen` LRU ~2–3 MB, `ps_text` ~9 MB, `mysql_pending` 8 192 × 640 B ≈ 5.2 MB, slow events ringbuf 256 KB; the per-PID stats map is removed, −1.3 MB) + userspace ~10 MB (digests ~5 MB, text cache ~5 MB) |
| **MySQL commit-wait uprobes** (uprobe + uretprobe on `log_write_up_to`; they trap on **every** call by any mysqld thread — the "inside `dispatch_command`" filter runs in BPF after the trap, and the uretprobe hijacks every return. On MySQL 5.7 the page cleaners call it once per flushed page; 8.0 guards that call) — estimated, not measured | **~2–5 µs per call** on the calling mysqld thread (≈ 0.2–0.5 % of one core at 1 000 commits/s; on 5.7 with heavy flushing, add one call per flushed page). `mysql.commit_wait: false` removes it | — (state lives in `mysql_pending`) |
| **Kernel delay accounting** (`enable_delayacct` / `kernel.task_delayacct=1`; needed for per-statement disk wait) — estimated, not measured | **kernel-wide, typically < 1 %** (paid by every task, not the agent) | — |
| **Family grouping (10s scan)** — estimated, not measured | **~0.02%** | **< 1 MB** |
| **ClickHouse export (drains + 60 s flush, 20k QPS)** — estimated, not measured; `host_stats` adds one row per host per flush (negligible) | **~0.1–0.2 % (digest drain) + a few ms/min encoding** | **≤ 32 MB buffer + per-interval drain maps** |
| netinv (per /api/diagnose) — estimated, not measured | 20–50 ms per call | transient |
| **Total (all eBPF active + fsync + netflow + MySQL)** — estimated, not measured | **~1.4%** | **~98 MB** |
| **Total (no trigger-eBPF; fsync + netflow + MySQL)** — estimated, not measured | **~0.9%** | **~63 MB** |

The totals are the sum of the rows above, except ClickHouse export (off by default; adds ~0.1–0.2 % and up to 32 MB when enabled), netinv (per `/api/diagnose` call, transient), the commit-wait uprobes (proportional to the commit rate, see the row) and kernel delay accounting (a kernel-wide cost, only when it is on). The measured rows (4-core 8GB VM, moderate load) sum to ~0.64 % / ~56 MB with every trigger module active and ~0.17 % / ~21 MB without; the totals add the estimated rows: netflow (~0.4 % / ~6 MB), the MySQL tracer (~0.3 % / ~35 MB typical, only when `mysql.enabled`) and family grouping (~0.02 % / ~1 MB). MySQL worst cases on top: the text cache holds up to 32 768 hashes (~150 B each, ~5 MB) plus one record per **distinct** digest among them (~0.65 KB: id + normalised text, +~0.5 KB sample only with `mysql.sample_queries`), so if every cached hash were its own digest it reaches ~26 MB (~43 MB with samples), i.e. +21 / +38 MB. Kernel map memory is not Go heap (charged to the agent's memory cgroup on kernels ≥ 5.11). **Unmeasured**: the kernel text-hashing cost — `text_hash` runs up to 511 loop iterations per COM_QUERY / COM_STMT_PREPARE at `dispatch_command` entry, and a prepare is hashed twice (also in `Prepared_statement::prepare`) — is not in the MySQL CPU estimate. All totals are **estimated, not measured**. The systemd unit enforces hard limits (`CPUQuota=10%`, `MemoryMax=200M`) as a safety net.

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
    │  every command is measured (emit_all_queries: true, the default;
    │  with false only COM_QUERY (3) and COM_STMT_EXECUTE (23) are tracked)
    │  baselines: start_ts, on-CPU (se.sum_exec_runtime), run-queue
    │      (sched_info.run_delay), ioac.read_bytes / ioac.write_bytes,
    │      delays->blkio_delay; comm
    │  COM_QUERY / COM_STMT_PREPARE (22): query_str = com_data[0..7],
    │      length = com_data[8..11]  (same layout for both commands)
    │      bpf_probe_read_user_str(pending.query, 512, query_str)
    │  delete ps_exec[tid]; mysql_pending[tid] = {…}
    │
uprobe: Prepared_statement::prepare / execute_loop   (optional, §20)
    │  ps_text[Prepared_statement*] = text;  ps_exec[tid] = Prepared_statement*
    │
uprobe / uretprobe: InnoDB log_write_up_to   (optional: commit wait)
    │  traps on EVERY call by any mysqld thread (off: mysql.commit_wait: false);
    │  counts only while mysql_pending[tid] exists, outermost frame only
    │  entry: snapshot ts, on-CPU, run-queue, blkio_delay
    │  return: redo_wait += max(0, Δwall − Δcpu − Δrunq − Δblkio)
    │
uretprobe: mysqld!dispatch_command
    │  pending = mysql_pending[tid]
    │  wall, cpu, runq, bytes_out, disk_read/write bytes (Δioac),
    │  io_wait (Δblkio_delay), redo_wait   (cpu/runq/io_wait/redo_wait ≤ wall)
    │  COM_STMT_EXECUTE: text = ps_text[ps_exec[tid]] when recovered
    │
    ├── COM_QUERY and COM_STMT_EXECUTE only:
    │     if latency_ns >= slow_query_threshold_ns:
    │         push mysql_slow_event_t {…, query, command} → events RINGBUF
    │         (→ recent_slow_queries; no text → the placeholder of §20)
    │
    ├── every command: agg_<active>[{tgid, command, text hash}] += sums; text once per hash → text_events RINGBUF; map full / unsafe hash → full mysql_cmd_event_t on cmd_events (§20)
    │
    └── delete ps_exec[tid], mysql_pending[tid]
```

The kernel object reads `ioac` and `delays` through local CO-RE flavor structs guarded by `bpf_core_field_exists`, so it loads on kernels built without `CONFIG_TASK_IO_ACCOUNTING` / `CONFIG_TASK_DELAY_ACCT`; the missing signals are then reported unavailable in `mysql_report.accounting` (§20). The four time parts (on-CPU, run-queue wait, block-I/O wait, commit wait) are disjoint by construction. The commit-wait probes attach only with `emit_all_queries: true` and `mysql.commit_wait: true` (default; env `MYSQL_COMMIT_WAIT`), and only when mysqld's symbol table has `log_write_up_to` (both probes attach or neither). They trap on every `log_write_up_to` call by any mysqld thread, not only inside statements (see §14 for the cost; on MySQL 5.7 write-heavy hosts consider `commit_wait: false`).

### Configuration (`mysql:` section in config.yaml)

```yaml
mysql:
  enabled: true
  mysqld_path: /usr/sbin/mysqld      # path to mysqld binary for uprobe
  slow_query_threshold_ms: 100       # emit ringbuf event when query > 100 ms
  poll_interval: 5s
  max_recent_queries: 100
  enable_delayacct: false            # true: write 1 to /proc/sys/kernel/task_delayacct at start if it reads 0
```

Environment variable overrides: `MYSQL_TRACING_ENABLED=true`, `MYSQL_SLOW_QUERY_THRESHOLD_MS=50`, `MYSQL_MYSQLD_PATH=/usr/bin/mysqld`, `MYSQL_ENABLE_DELAYACCT=true`.

### MySQL version compatibility

Hook symbols are chosen by `internal/mysql/mysqldsym` from the binary's
symbol names, by **signature rules, never substrings**: a name that matches
no rule is refused rather than guessed, because a uprobe on the wrong function
or arguments read from the wrong registers records garbage silently. Checked
against real `mysqld` builds (`.dynsym`; fixtures in
`internal/mysql/mysqldsym/testdata/*.syms`):

| MySQL | `dispatch_command` | `Prepared_statement::prepare` | layout (query, length) | `log_write_up_to` |
|---|---|---|---|---|
| 5.7.42 | `_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command` | `…prepareEPKcm` | `query_first` (RSI, RDX) | `…tomb` |
| 8.0.11, 8.0.19 | same | `…prepareEPKcm` | `query_first` | `…toR5log_tmb` |
| 8.0.14 | same | `…prepareEPKcmb` | `query_first` | `…toR5log_tmb` |
| 8.0.28 | same | `…prepareEPKcmPP10Item_param` | `query_first` | `…toR5log_tmb` |
| 8.0.36, 8.0.46, 8.4.11, 9.7.2, 26.7.0 | same | `…prepareEP3THDPKcmPP10Item_param` | `thd_first` (RDX, RCX) | `…toR5log_tmb` |

- `dispatch_command` is matched **exactly**. 8.0.11 also exports
  `xpl::dispatcher::dispatch_command` (X plugin) before it, which the former
  substring search hooked by mistake. MariaDB (`dispatch_command(enum
  server_command, THD*, …)`) is refused at start with the candidates listed.
- `prepare`: the method itself (`_ZN…`, not a nested lambda `_ZZN…`, not a
  `.cold`/`.isra` part) with an optional leading `THD*` followed by `(const
  char*, size_t)`. Trailing parameters do not move the registers.
- `execute_loop`: any arguments (only `this` is read). The arguments differ
  in every series (5.7 `EbPhS0_`, early 8.0 `EP6Stringb`, 8.0.36+ `EP3THDP6Stringb`).
- `COM_DATA` (query pointer + `unsigned int` length first) and
  `enum_server_command` (prepare 22, execute 23) are unchanged through trunk.
- The start log prints `mysqld hooks: dispatch=ok prepare=<layout> execute_loop=ok|unavailable redo=ok|unavailable` (`redo` = the `log_write_up_to` commit-wait probes; `unavailable` also when `emit_all_queries` is off or `mysql.commit_wait` is false).

**Adding a release** (9.x, 26.x+): extract its `mysqld` (e.g. from the
`mysql-community-server-core` .deb), run
`go run ./internal/mysql/mysqldsym/cmd/symdump -label "<version> (<package>)" <mysqld> > internal/mysql/mysqldsym/testdata/<version>.syms`,
add the expected hooks to `TestCompatMatrix`, run the tests. A changed
signature fails there, naming the hook. Then run the runtime matrix on a
Linux x86_64 host: `make generate` first **as your user** (not under sudo:
root's toolchain would generate root-owned files), then
`sudo make test-mysql-matrix` (add `GO=$(command -v go)` if root's PATH has no
Go; Docker; images from `MYSQL_IMAGES`, default
`mysql:5.7 mysql:8.0 mysql:8.4 mysql:9`). The target refuses to run without
the generated code. It attaches through `/proc/<pid>/root/usr/sbin/mysqld` and
runs every integration test: verifier acceptance of literal skipping
(`TestLiteralSkipLoaded`), in-kernel aggregation, kernel/Go hash parity, the
unsafe-hash fallback, command events and a server-side prepared statement's
recovered text. A failing image is reported and the next one still runs; the
exit status is non-zero if any failed.

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
  ]
}
```

### Verify uprobes are loaded

```bash
sudo bpftool prog list | grep -E 'uprobe|kprobe'
# Expected:
#   kprobe  name uprobe_dispatch_command     (uprobe type shows as kprobe in bpftool)
#   kprobe  name uretprobe_dispatch_command
#   kprobe  name uprobe_log_write_up_to      (commit wait, when redo=ok)
#   kprobe  name uretprobe_log_write_up_to

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
| `/proc/[pid]/stat` + `wchan` | `metrics.d_state` | Tasks in D, the kernel function each sleeps in, how long each was continuously blocked, and `blocked_sample_percent` |
| `/proc/[pid]/fdinfo/*` | `metrics.blocking_hooks` | fanotify holders, flagged when in a **permission** class — the agents that put *other* processes into D state |
| `/proc/diskstats` fields 12/14 | `metrics.disk[].in_flight`, `.avg_queue_depth`, `.read_avg_wait_ms`, `.write_avg_wait_ms` | Already parsed but previously discarded. High in-flight + low throughput = slow device, not busy one |
| eBPF `io_latency` | `io_latency_histogram` | The biolatency distribution — computed in-kernel all along, previously unreachable |
| eBPF `offcpu` | `offcpu_report` | The blocking stack (§18) |

**Two things the D-state census must get right**, both learned from a real miss:

1. **Threads, not just processes.** The blocked task is usually a *worker thread* — an antivirus scanner thread, an io_uring worker, a JVM GC thread — which never appears as a top-level `/proc/<pid>` entry. Scanning only top-level PIDs reports `count: 0` while `/proc/stat`'s `procs_blocked` says `1`. Threads are therefore scanned **by default** (`collect.d_state_skip_threads: false`).

2. **Sub-sampling, not one point sample.** A machine can spend 80% of its time with something blocked while no single instant lands on a long block: many short waits, constantly. One sample per 5 s collection interval sees nothing. The census runs its own 250 ms ticker and reports the aggregate — `blocked_sample_percent` is the field that catches this pattern, and a high value with a *low* `longest_ms` is the signature of a synchronous userspace hook rather than a slow device.

`in_d_state_ms` is a continuously-blocked duration quantised to the sub-sample interval, which makes the "blocked > 1 s" rule work with no eBPF at all.

### Verdicts

| Verdict | Condition | Meaning |
|---|---|---|
| `storage_latency_stall` | iowait high **AND** throughput low **AND** (task blocked >1s in the storage path **OR** avg wait/request > 50 ms) | The device is **slow, not busy**. More IOPS capacity will not help — per-request latency is the problem. Look beneath the device: network storage RTT, hypervisor steal, cgroup `io.max`, failing disk. |
| `high_disk_throughput` | util ≥ 70% **AND** throughput high | Genuine saturation — a capacity problem. |
| `writeback_congestion` | dirty ratio ≥ 15% **AND** iowait high | Stall is in the page cache; writers throttled in `balance_dirty_pages`. Not the device's fault. |
| `stall_without_device_io` | PSI `io.full` high **BUT** the device is idle | **Work genuinely could not proceed, and it is not block I/O.** Usual cause: an on-access antivirus/audit agent holding fanotify in *permission* mode — every file access waits for its verdict in D state, producing iowait with zero disk traffic because the file is in page cache. Also: NFS/CIFS/FUSE, cgroup `io.max` throttling. |
| `iowait_accounting_artifact` | iowait high **BUT** PSI `io.full` **LOW** **AND** device idle **AND** nothing blocked >1s | **Not a problem.** The CPU was idle while a task sat parked in D state (io_uring workers do this). Do not page anyone. |
| `healthy` / `inconclusive` | — | Nothing to report / signals conflict |

> **PSI is authoritative.** `io.full` measures time in which no task could make progress. When it is high the machine is genuinely stalling, and no combination of "the device looks idle" or "load is low" may override that. An earlier version let a low-load shortcut win over PSI and reported a real 81%-full stall as an accounting artifact — the exact failure this ordering now prevents.

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

## 20. Process Families, Network Flows & Query Digests

### Why

In a MySQL CPU incident every query's wall time inflates, so the slow-query
list fills with *victims*. This feature separates the query pattern that
**consumes** the CPU from the queries that only **waited** for it, and shows
which services (process families) are heavy and who they talk to.

```
wall = on-CPU  +  run-queue wait  +  block-I/O wait  +  commit wait  +  other (locks, network, …)
       culprit     cascade victim     disk victim        commit victim
```

The same split names the query that **reads** the disk (`io_role: culprit`) apart from the queries that only waited for block I/O or for the redo log.

### Components

| Unit | What it does |
|---|---|
| `ebpf/netflow` | Always-on. Counts TCP bytes and connections per {tgid, direction, peer, service port} in an LRU map. Owner is recorded at connect/accept (process context); bytes are charged to the current process at `tcp_sendmsg` / `tcp_cleanup_rbuf`. |
| `ebpf/mysql_query` | Per `dispatch_command`: wall, on-CPU (`se.sum_exec_runtime` Δ), run-queue wait (`sched_info.run_delay` Δ), result bytes (`tcp_sendmsg` / `unix_stream_sendmsg` returns), storage bytes read / written (`ioac.read_bytes` / `write_bytes` Δ), block-I/O wait (`delays->blkio_delay` Δ) and commit wait (optional `log_write_up_to` uprobes, §16). Summed in the kernel per {tgid, command, literal-skipping text hash} (`internal/mysql/sqlhash` is the Go reference); text crosses once per hash; the analyzer drains the map every poll. Optional uprobes on `Prepared_statement::prepare` / `execute_loop` recover the SQL text of `COM_STMT_EXECUTE`. |
| `sqldigest` + `querystats` | Normalise SQL → digest; aggregate over a 60 s window; rank by **total** CPU; label `cpu_role: culprit` (≥ 20 % of the node's CPU used over the window **and** the node ≥ 50 % busy), `io_role: culprit` (≥ 20 % of the physical disks' reads **and** the node reading ≥ 5 MB/s) or `victim_of` `cpu` / `disk` / `commit` (measured waits ≥ 50 % of its time, slow; the largest wait names it). |
| `process` | Groups processes into families by systemd unit (`nginx.service`), falling back to `.scope` / cgroup path. |
| `netinv` | On demand only: listening ports and live connections (`src → dst`, client → server) from `/proc/net/tcp*` + `/proc/<pid>/fd`. |

### GET /api/diagnose

- `process_report.top_cpu[]` / `top_mem[]` — top `process.report_top_cpu` / `report_top_mem` processes (default `report_top_n`, 10) with `listening_ports`, `network` (inbound/outbound conns and bytes over the window, `top_peers`), `connections` (≤ 50, `connections_truncated`), `profile_url`.
- `process_report.top_families_cpu[]` / `top_families_mem[]` — top `process.report_top_families_cpu` / `report_top_families_mem` families (default `report_top_n`, 10) with `process_count`, `root_pid`, `top_members`, summed `network`.
- `mysql_report.top_digests[]` — top `mysql.top_digests` (20) by on-CPU time; `top_digests_by_wait[]` (10) by measured wait (run queue + block I/O + commit, each only when available; digests with none are not listed); `top_digests_by_disk_read[]` (10) by disk bytes read (present only when per-statement disk bytes were measured in every poll of the window; digests that read nothing are not listed); `top_digests_by_bytes_out[]` (10). Per digest (W = `digest_window`, 60 s; every sum is over the same polls as the node numbers):

  | Field | Formula | Reading |
  |---|---|---|
  | `calls_per_sec` | calls ÷ W | load |
  | `cpu_cores` | cpu ÷ W | "keeps 1.3 cores busy" |
  | `percent_of_node_cpu_used` | cpu ÷ node CPU used × 100 | **CPU culprit:** "did 27 % of all CPU work on this server" |
  | `latency_ms_avg` / `_max` | wall ÷ calls; max | user-visible latency |
  | `time_breakdown_percent` | `cpu`, `cpu_wait` (run queue), `disk_wait` (block I/O), `commit_wait` (redo log), `other` = max(wall, Σ parts) − Σ parts; each ÷ max(wall, Σ available parts) × 100 | where the time went (sums to 100); an unavailable part is absent and its time stays in `other` |
  | `bytes_out_per_call` | bytes sent ÷ calls | result size |
  | `disk_read_mb_per_sec` | disk read bytes ÷ W ÷ 2²⁰ | read load |
  | `percent_of_disk_read` | disk read bytes ÷ physical-disk reads × 100 | **disk culprit:** "is 71 % of the disk's reads" |
  | `disk_read_pages_per_call` | disk read bytes ÷ calls ÷ 16 384 | 1–4 = buffer-pool misses → grow `innodb_buffer_pool_size`; hundreds+ = scan → `EXPLAIN`, index, `LIMIT` |
  | `disk_write_mb_per_sec` | disk write bytes ÷ W ÷ 2²⁰ | non-zero on a SELECT = spills to disk |
  | `cpu_role: culprit` | `percent_of_node_cpu_used` ≥ `cpu_culprit_percent_of_node_cpu_used` (20) **and** node CPU used ≥ `cpu_culprit_min_node_cpu_used_percent` (50) % | an idle server never has a culprit |
  | `io_role: culprit` | `percent_of_disk_read` ≥ `io_culprit_percent_of_disk_read` (20) **and** node disk read ≥ `io_culprit_min_node_disk_read_mb_per_sec` (5) MB/s | a quiet disk never has a culprit |
  | `victim_of: cpu \| disk \| commit` | Σ available waits (`cpu_wait` + `disk_wait` + `commit_wait`) ≥ `victim_wait_percent` (50) **and** `latency_ms_avg` ≥ `slow_query_threshold_ms`; the value is the largest available wait (ties: cpu, disk, commit) | slow because it waited — for a CPU, for block I/O, or for the redo log |

  A value whose input is unavailable is omitted, never 0. The disk fields need per-statement disk bytes in every poll of the window; `percent_of_disk_read` also needs the node's physical-disk bytes in every poll and a non-zero total. The `<other>` overflow digest never gets a role.
- Report level: `node` {`num_cpu`, `cpu_used_cores`, `cpu_used_percent`} over W (from `/proc/stat`, same polls); `query_cpu_coverage_percent` = Σ digest CPU ÷ CPU of the traced mysqld processes × 100 — how much of mysqld's CPU the digests explain (the rest: connection handling outside `dispatch_command`, InnoDB background threads); omitted while any poll in the window lacked a mysqld baseline: for the first window after the agent starts, after a mysqld restart, and whenever a mysqld PID comes back after a quiet window (with several mysqld instances, one quiet-then-active instance omits it node-wide for one window). `node` also carries `disk_read_mb_per_sec` / `disk_write_mb_per_sec`: bytes of the **physical disks** over W (whole devices under `/sys/block` with an empty `slaves/` — so no dm-*/md* — and not loop/ram/zram/sr/fd/nbd; without `/sys/block`, names like `sd*`, `vd*`, `xvd*`, `hd*`, `nvme*n*`, `mmcblk*`), omitted unless every poll in the window had a valid `/proc/diskstats` delta. `query_disk_read_coverage_percent` = Σ digest disk read bytes ÷ physical-disk read bytes × 100 — how much of the disk's reads the statements explain (the rest: read-ahead, page cleaners, purge, other processes). It does not need node CPU, so it can be present while `node` (and with it `node.disk_*`) is absent: the `node` block is built only when node CPU is available for every poll. `victims` {`cpu`, `disk`, `commit`: n} over **all** digests (victims burn little CPU and rarely reach the top lists): `victims.cpu` counts the slow digests whose measured waits sum to ≥ `victim_wait_percent` and whose largest wait is the run queue, and likewise `disk` (block I/O) and `commit` (redo log). A key is present, possibly 0, exactly when that wait is measured for the whole window. `accounting` says which signals were measured in every poll of the window (otherwise the newest reason a poll gave; `disk_bytes`, `disk_wait` and `commit_wait` — never `cpu_wait` — read `unknown` before the first host sample):

  | Key | Values | When not `ok` |
  |---|---|---|
  | `cpu_wait` | `ok` \| `run_delay_unavailable` | kernel without scheduler stats (`run_delay` reads 0) |
  | `disk_bytes` | `ok` \| `io_accounting_unavailable` | kernel without `CONFIG_TASK_IO_ACCOUNTING` (no `task_struct.ioac` in BTF) |
  | `disk_wait` | `ok` \| `blkio_delay_unavailable` \| `delayacct_disabled` | `blkio_delay_unavailable`: kernel without `CONFIG_TASK_DELAY_ACCT`; `delayacct_disabled`: delay accounting is off (the default since kernel 5.14 unless booted with `delayacct`; older kernels booted `nodelayacct`) → `sysctl kernel.task_delayacct=1` or `mysql.enable_delayacct: true` (re-read every poll) |
  | `commit_wait` | `ok` \| `log_write_up_to_unavailable` \| `commit_wait_disabled` | `log_write_up_to_unavailable`: mysqld without the `log_write_up_to` symbol, an attach error, or `emit_all_queries: false`; `commit_wait_disabled`: `mysql.commit_wait: false` (probes never attached) |

  `thresholds` echoes the role cut-offs.
- `mysql_report.overload_cause` (built per `/api/diagnose` call by `internal/overload`, on a copy) — the CPU and the disk are assessed separately, each with four checks, always all reported:

  | Check | CPU (`resource: "cpu"`) passes when | Disk (`resource: "disk"`) passes when |
  |---|---|---|
  | `node_saturated` | node CPU used over W (`mysql_report.node`; the latest collector sample when unavailable, `missing: node_cpu_window`) ≥ `overload_node_cpu_percent` (85) **or** load1 ÷ NumCPU ≥ `overload_node_load` (1.5) | this call's `io_diagnosis.verdict` ∈ {`high_disk_throughput`, `storage_latency_stall`, `writeback_congestion`} (`missing: io_diagnosis` when there is none). `io_diagnosis` is built from the **latest collector sample**, not the digest window |
  | `mysqld_top_consumer` | the top digest's mysqld PID belongs to the #1 process family by CPU | the top disk-read digest's mysqld family is #1 by storage read bytes/s (`/proc/<pid>/io`, needs `process.include_io`, default true) |
  | `dominant_digest` | the top digest by CPU has `cpu_role: culprit` | the top digest by disk reads has `io_role: culprit` |
  | `victims` | ≥ 1 digest with `victim_of: cpu` (largest wait is the run queue) | ≥ 1 digest with `victim_of` `disk` or `commit` (largest wait is disk / commit) |

  Only measured waits count: a wait whose `accounting` entry (`cpu_wait`, `disk_wait`, `commit_wait`) is not `ok` is listed in `missing`, its victim count is omitted from `evidence`, and the victims check detail says so (e.g. `disk waits not measured (accounting.disk_wait = delayacct_disabled)`).

  `verdict`: `query_cpu_overload` / `query_disk_overload` (checks 1–3; confidence high with victims, medium without — or when no relevant wait is measured (CPU: `cpu_wait`; disk: neither `disk_wait` nor `commit_wait`), with a summary clause saying victims could not be measured — low without process families — for the disk, without per-family read bytes, `missing: family_disk_io`, e.g. `process.include_io: false`), `node_not_saturated`, `not_mysql`, `no_dominant_query`, `no_data`. CPU `no_dominant_query` has confidence low when a culprit is impossible by construction: no `mysql_report.node`, so no `percent_of_node_cpu_used`, or the node saturated by load while its window CPU used is below `cpu_culprit_min_node_cpu_used_percent` — then check `io_diagnosis`. Disk `no_dominant_query` has confidence low without per-family read bytes or without `percent_of_disk_read`; disk `no_data` (`missing: query_disk_reads`: no statement read from disk, or `accounting.disk_bytes` is not `ok`) becomes `node_not_saturated` when the disk is not saturated. Which assessment is reported: the saturated one; with neither saturated, the CPU one; with **both** saturated, a `query_*_overload` verdict wins over any other, otherwise the one whose top digest has the larger share (`percent_of_node_cpu_used` vs `percent_of_disk_read`), and the other assessment is in `secondary` (same shape, never nested further). `digest` {`digest_id`, `digest_text`, `calls_per_sec`, `bytes_out_per_call`, plus `cpu_cores`, `percent_of_node_cpu_used`, `cpu_role` (cpu) or `disk_read_mb_per_sec`, `percent_of_disk_read`, `disk_read_pages_per_call`, `io_role` (disk)}; a `query_disk_overload` summary adds the pages-per-call reading (≤ 4: buffer-pool misses; ≥ 100: a scan). `evidence` (disk: `io_verdict`, `node_disk_read_mb_per_sec`, `query_disk_read_coverage_percent`, `disk_victims`, `commit_victims`, `top_disk_family`, `top_disk_family_read_mb_per_sec`, `mysql_family_disk_read_mb_per_sec`; cpu: `cpu_victims`, the node CPU, load and PSI fields (`psi_cpu_some_avg10` omitted when PSI is unavailable, `load_normalised` when the CPU count is unknown), `top_family*`, `mysql_family_cpu_percent`, `query_cpu_coverage_percent` — the victim counts are the `victims` values above, present (0 included) exactly when that wait is measured) and `thresholds` carry every number used. Each assessment carries only its own resource's `evidence` and `thresholds` fields and `digest.cpu_cores` only for the CPU: the other resource's fields are omitted, never 0 (also in `secondary`). When the reported verdict is `query_disk_overload`, or `secondary` is one, `io_diagnosis.next_steps` starts with a pointer to `mysql_report.overload_cause` (or `mysql_report.overload_cause.secondary`) and the digest (a copy; the cached diagnosis is untouched).

```bash
curl -s localhost:9200/api/diagnose | jq '.mysql_report.top_digests[] | {digest_text, cpu_role, victim_of, cpu_cores, percent_of_node_cpu_used, time_breakdown_percent}'
curl -s localhost:9200/api/diagnose | jq '.mysql_report | {accounting, node, query_disk_read_coverage_percent, disk: .top_digests_by_disk_read[0] | {digest_text, disk_read_mb_per_sec, percent_of_disk_read, disk_read_pages_per_call, io_role, time_breakdown_percent}}'
curl -s localhost:9200/api/diagnose | jq '.mysql_report.overload_cause | {verdict, resource, confidence, summary, digest, checks, secondary: .secondary.verdict}'
curl -s localhost:9200/api/diagnose | jq '.process_report.top_families_cpu[] | {family, process_count, cpu_percent, net: .network.inbound}'
```

### Configuration

`process.report_top_n`, `report_top_cpu`, `report_top_mem`, `report_top_families_cpu`, `report_top_families_mem`, `process.family_by`, `process.max_connections_per_process`, `process.max_peers_per_process`; `mysql.emit_all_queries`, `digest_window`, `top_digests`, `sticky_digests_max`, `sticky_digest_ttl`, `cpu_culprit_percent_of_node_cpu_used`, `cpu_culprit_min_node_cpu_used_percent`, `victim_wait_percent`, `io_culprit_percent_of_disk_read`, `io_culprit_min_node_disk_read_mb_per_sec`, `enable_delayacct`, `commit_wait`, `overload_node_cpu_percent`, `overload_node_load`, `sample_queries`, `fold_system_schemas`; `process.include_io` (per-family read bytes for the disk `mysqld_top_consumer` check); and the `netflow:` section. See `deploy/config.yaml.example`. Environment overrides: `NETFLOW_ENABLED`, `NETFLOW_INCLUDE_LOOPBACK`, `MYSQL_EMIT_ALL_QUERIES`, `MYSQL_DIGEST_WINDOW`, `MYSQL_SAMPLE_QUERIES`, `MYSQL_FOLD_SYSTEM_SCHEMAS`, `MYSQL_ENABLE_DELAYACCT`, `MYSQL_COMMIT_WAIT`.

Removed `mysql:` keys still load but are ignored, with one startup warning each: `culprit_cpu_share_percent` (now `cpu_culprit_percent_of_node_cpu_used`), `culprit_min_cpu_percent` (now `cpu_culprit_min_node_cpu_used_percent`), `victim_runq_ratio` (now `victim_wait_percent`), `overload_min_node_cpu_percent`, `top_n`, `stale_seconds` (no replacement).

### Prometheus

Never labelled by PID, client port or raw SQL. Caps: 50 families, 100 outbound peers, 100 inbound peers, 200 outbound service ports (node-wide), 50 sticky digests; overflow → `"other"`. A label value that is not valid UTF-8 after sanitising is logged and its series skipped, never a failed scrape.

| Metric | Labels |
|---|---|
| `obs_agent_family_cpu_percent`, `_mem_rss_bytes`, `_processes` | `family` |
| `obs_agent_family_net_bytes_total` | `family, direction, flow` |
| `obs_agent_family_net_connections_opened_total`, `_active` | `family, direction` |
| `obs_agent_family_inbound_bytes_total` | `family, service_port, flow` |
| `obs_agent_family_outbound_peer_bytes_total` | `family, peer_ip, service_port, flow` |
| `obs_agent_family_inbound_peer_bytes_total` | `family, peer_ip, service_port, flow` |
| `obs_agent_mysql_queries_total`, `_query_cpu_seconds_total`, `_query_runq_wait_seconds_total`, `_query_wall_seconds_total` | `command` |
| `obs_agent_mysql_query_bytes_total` (result bytes; `flow="out"` only) | `command, flow` |
| `obs_agent_mysql_query_disk_read_bytes_total`, `_query_disk_write_bytes_total` (always) | `command` |
| `obs_agent_mysql_query_io_wait_seconds_total`, `_query_redo_wait_seconds_total` (absent while not measured over the whole digest window: a counter stuck at 0 would read as "no wait") | `command` |
| `obs_agent_mysql_digest_{cpu_seconds,calls,disk_read_bytes}_total` (`minimal`, `full`); `…_{runq_wait_seconds,bytes_out,io_wait_seconds}_total` (`full`; `io_wait` only while measured) | `digest_id` |
| `obs_agent_mysql_digest_info` (=1) | `digest_id, digest_text` |
| `obs_agent_mysql_digest_coverage_ratio` | — |
| `obs_agent_mysql_query_cpu_coverage_ratio` (≈ 0–1, not clamped, absent while unknown) | — |
| `obs_agent_mysql_io_wait_available`, `obs_agent_mysql_redo_wait_available` (1/0) | — |
| `obs_agent_node_disk_read_bytes_total`, `obs_agent_node_disk_write_bytes_total` (counters), `obs_agent_node_physical_disks` (gauge) | — |
| `obs_agent_pressure_io_full_avg10`, `_io_some_avg10`, `_cpu_some_avg10` (gauges, percent; only when PSI is available) | — |
| `obs_agent_mysql_events_dropped_total` (commands lost), `obs_agent_mysql_text_events_dropped_total` (texts re-requested) | — |
| `obs_agent_mysql_agg_overflow_total`, `obs_agent_mysql_hash_mismatch_total` | — |

**Inbound peers**: `…_inbound_peer_bytes_total` is the client side (`service_port` is the local listening port). `netflow.max_inbound_peers` (default 100, `NETFLOW_MAX_INBOUND_PEERS`) caps distinct `peer_ip` values node-wide; further peers fold into `peer_ip="other"`; `0` disables the series. Idle labels expire like the outbound ones.

**Digest modes** (`mysql.prometheus_digests`, env `MYSQL_PROMETHEUS_DIGESTS`):

| Mode | Per-digest series |
|---|---|
| `minimal` (default) | Top `prometheus_minimal_top_n` (20) digests by lifetime CPU ∪ top 20 by lifetime disk read (a ranking admits only digests with a non-zero value, so a server without disk reads exports the CPU top only): `…digest_cpu_seconds_total`, `…digest_calls_total`, `…digest_disk_read_bytes_total` + `digest_info`, plus one `digest_id="other"` series per counter (everything not exported; it drops when a digest joins the set — a counter reset, read it with `rate()`) |
| `full` | Sticky set (`sticky_digests_max`): the three `minimal` counters plus `…digest_runq_wait_seconds_total`, `…digest_bytes_out_total`, `…digest_io_wait_seconds_total` (while measured) + `digest_info`; no `other` |
| `off` | None, no `digest_info`; per-command metrics, `events_dropped_total` and the coverage ratios remain |

`obs_agent_mysql_digest_coverage_ratio` = window CPU of the digests exported in the current mode ÷ the window's total query CPU (0 in `off`, 1 when there is no query CPU; clamped to 1). `obs_agent_mysql_query_cpu_coverage_ratio` = `query_cpu_coverage_percent` ÷ 100 (statement CPU ÷ the traced mysqld processes' CPU over the digest window); absent while unknown and **not clamped** (tick granularity), so it can read slightly above 1. The `*_available` gauges are 1 when the per-statement block-I/O / commit wait is measured over the whole digest window (`accounting.disk_wait` / `commit_wait` = `ok`). `minimal` keeps the series count bounded on fleets; `full` is needed only for the per-digest runq / bytes out / io wait series (and `MySQLDigestResultSizeSpike`). ClickHouse (§22) keeps the long tail — series grow as servers × digests × series-per-digest.

Node series (`internal/promcollect/node.go`): `obs_agent_node_disk_{read,write}_bytes_total` are read from `/proc/diskstats` at scrape time over the physical disks (the same selection as `mysql_report.node.disk_*`); an unreadable file yields no series, never a 0. The PSI gauges come from the collector's latest sample and are absent without `/proc/pressure`.

Join digest text in Grafana: `topk(10, rate(obs_agent_mysql_digest_cpu_seconds_total[5m])) * on(instance, digest_id) group_left(digest_text) obs_agent_mysql_digest_info`.

Alert rules: `deploy/prometheus/obs-agent-alerts.yaml` (tests: `promtool test rules deploy/prometheus/obs-agent-alerts_test.yaml`). Policy: page (critical) on symptoms users feel, ticket (warning/info) on causes. Every MySQL `description` is a numbered runbook, and the Overview dashboard draws each threshold on the panel it names. Ratios are over `[5m]`, per `instance`:

| Alert | Severity | Condition (`for`) | Overview panel |
|---|---|---|---|
| `MySQLQueriesStarvedForCPU` | critical | query runq wait ÷ query wall > 0.3 **and** avg node CPU ≥ 85 % (5m) | Where query time goes |
| `MySQLQueriesStalledOnDisk` | critical | (query io wait + redo wait) ÷ query wall > 0.3 **and** PSI io.full avg10 > 10 (5m); an absent wait counts as 0 | Where query time goes |
| `MySQLDigestCPUHog` | warning | one digest's CPU ÷ node CPU cores in use > 0.2 **and** node CPU ≥ 85 % (5m) | % of node CPU used by top digests; Top CPU digest stat |
| `MySQLDigestDiskReadHog` | warning | one digest's disk reads ÷ node physical-disk reads > 0.2 **and** node reads > 5 MiB/s (5m) | % of node disk reads by top digests; Top disk-read digest stat |
| `MySQLCommitsStalledOnRedo` | warning | query redo wait ÷ query wall > 0.2 (5m) | Commit wait share |
| `MySQLDigestResultSizeSpike` | warning | bytes out per call over `[10m]` > 5 × the same a day earlier **and** > 5 MB/s (10m); needs `prometheus_digests: full` | — |
| `MySQLQueriesSpillingToDisk` | info | `query` + `stmt_execute` disk writes > 10 MiB/s (5m) | Query disk writes by command |
| `ObsAgentMySQLIOWaitUnavailable` | info | `obs_agent_mysql_io_wait_available == 0` (30m) — fires on every host with `kernel.task_delayacct=0` and `mysql.enable_delayacct` off (the default on most modern kernels) | Accounting availability |
| `ObsAgentMySQLAccountingDegraded` | info | events dropped, agg overflow or hash mismatches rising over `[10m]` (10m) | Dropped, overflow and hash mismatches (no threshold line) |

The digest alerts exclude `digest_id="other"` and need the digest in the exported set.

### Accuracy and limits

- Per-call CPU is ± one scheduler tick (1–4 ms); per-digest **totals** are accurate, and so are `cpu_cores` and `percent_of_node_cpu_used`. A digest whose calls each use well under 1 ms of CPU has an unreliable `time_breakdown_percent.cpu`.
- `cpu_cores` and `node.cpu_used_cores` divide by the full window, so they are understated during the agent's first window; percentages are not (numerator and denominator cover the same polls). They also divide by the configured `digest_window`, not by the span the window's 5 s buckets actually cover: with a `poll_interval` that does not divide 5 s, or a `digest_window` that is not a multiple of 5 s, they can be off by up to one poll's worth (percentages are unaffected).
- `query_cpu_coverage_percent` compares in-kernel on-CPU time with `/proc` utime+stime (different tick granularity) and is not clamped: a value slightly above 100 means the digests explain all of mysqld's CPU.
- Query text is captured up to 511 bytes (`truncated: true` beyond).
- Digest windows are built from per-poll sums: a command is attributed to the poll that drained it (≤ `poll_interval`, 5 s, later than it ran).
- A statement's whole CPU is charged to the poll in which it completes, while node and mysqld CPU accrue poll by poll. A statement longer than the window, or a failed drain whose entries arrive with the next poll, can therefore push `percent_of_node_cpu_used`, `cpu_cores` and `query_cpu_coverage_percent` above their nominal maxima (100 %, NumCPU, 100 %) for one window.
- `latency_ms_max` is best effort: two CPUs updating the same statement at the same instant can lose one maximum (no compare-and-swap before kernel 5.12). Sums are exact.
- A statement whose text never reached the agent (text event dropped, see `text_events_dropped_total`) is attributed for one poll to a placeholder and its text is requested again: `<text unavailable>` for COM_QUERY, `prepare: <text unavailable>` (its own digest) for COM_STMT_PREPARE, and for COM_STMT_EXECUTE the execute placeholder `<COM_STMT_EXECUTE: prepared before agent start, text unavailable>` — the same row as statements prepared before the agent attached.
- Kernel/Go hash consistency is checked continuously: every first-sight text is re-hashed in Go (`sqlhash.KernelHash`, or `ExactHash` in the fallback below) and every 1/1024 verification resend and text resend is compared with the cached digest. Any disagreement marks that hash unsafe (its commands then arrive as exact full events) and counts in `hash_mismatch_total`.
- If a kernel's verifier rejects the literal-skipping hash loop, the loader retries once with `literal_skip = 0` (exact-text FNV-1a) and logs one warning. Digests and totals stay exact, but statements that differ only in literals no longer share a kernel entry (more agg entries, text events and overflow risk).
- The drain flips the active aggregation buffer and waits 50 ms before reading the old one: since kernel 6.1 uprobe programs run under `migrate_disable()` and can be preempted mid-update on a `preempt=full` kernel, and a saturated CPU is the scenario being diagnosed. An update still running after 50 ms lands in the drained buffer and is returned by a later drain of it, unless it hits an entry between that entry's iteration and its delete (tiny window: that increment is lost).
- Not verified, possible on kernels ≥ 6.1 with `preempt=full`: the per-CPU scratch slots (`pending_scratch`, `ps_scratch`) and the per-CPU `dropped` / `agg_overflow` counters assume no preemption between fill and copy. Two mysqld threads interleaving on one CPU can store one command's timestamps or text with the other's, or lose a counter increment. With the hash check above, a text paired with the wrong hash reads as a mismatch: harmless (the hash goes to exact processing), but `hash_mismatch_total` can rise slightly on saturated hosts without any real kernel/Go drift.
- **Privacy:** `top_digests[].sample_query` is the raw text of the first execution of each digest, **literals included** — potentially secrets (e.g. `CREATE USER … IDENTIFIED BY '…'`). `digest_text` (and the `digest_info` metric) is literal-free. Set `mysql.sample_queries: false` (`MYSQL_SAMPLE_QUERIES=false`) to never store or emit it. `/api/diagnose` and `/metrics` are unauthenticated (with peer IPs and cmdlines): restrict network access to `:9200`.
- `COM_STMT_EXECUTE` (server-side prepared statements) carries the SQL text recovered from its `COM_STMT_PREPARE` — see *Prepared statements and command names* below for when it cannot be recovered.
- Process-level network covers TCP only (no UDP, no unix sockets). Pre-existing idle connections are invisible to eBPF until they carry traffic; the `/proc` `connections` list still shows them.
- `listening_ports` / `connections` come from `/proc/1/net/tcp{,6}` — pid 1's (the host's, with `hostPID: true`) network namespace — falling back to the agent's own namespace when that cannot be read. Processes in **other** network namespaces (containers with their own netns) have no ports/connections listed; their traffic is still counted by the netflow eBPF module.
- Window rates (`bytes_*_per_sec`) cover only polled intervals: the first poll after start is a baseline, so rates are 0 until the second poll.
- Uprobes attach to the mysqld binary inode: a mysqld restart is traced automatically; a package upgrade that replaces the binary needs an agent restart.
- Sent bytes (`bytes_tx`, netflow) count `tcp_sendmsg` returns. `sendfile`/`splice` on kernels < 6.5 go through `tcp_sendpage` and are **not** counted (nginx static files, Kafka); MySQL is unaffected. Received bytes are counted at `tcp_cleanup_rbuf` and can be double counted for reads using `MSG_WAITALL` / `SO_RCVLOWAT > 1`; kTLS/sockmap receive paths are not attributed to the reading process.
- The eBPF programs are **x86_64 only** (register-level access via a local `pt_regs` layout); on other architectures the netflow and mysql_query loaders refuse to start (`network_source: "unavailable: …"`). The kernel floor is **5.5** (BTF/CO-RE helpers such as `bpf_probe_read_kernel`), not 5.4.
- The result-bytes kretprobes use `RetprobeMaxActive=2048` via tracefs when available. When tracefs is unavailable the loader falls back to the kernel default instance count, and with the default many concurrent slow-client senders can make the kernel drop kretprobe returns and under-count `bytes_out` / `bytes_tx`. Tracefs-based probes can leave `ebpf_*` events in `/sys/kernel/tracing/kprobe_events` after a crash.
- Lifetime counters for a family or outbound-peer label that was idle for more than 1 h restart from 0 if it returns (bounded memory; a normal Prometheus counter reset).
- `COM_QUERY` length is read as a 4-byte `unsigned int` (MySQL 5.7 through 26.x). `run_delay` needs scheduler stats; on kernels where it reads 0 the report sets `accounting.cpu_wait: run_delay_unavailable`, omits `time_breakdown_percent.cpu_wait` and `victims.cpu`, and leaves run-queue wait out of `victim_of` and `top_digests_by_wait`.
- Per-statement disk bytes are the thread's `ioac` deltas, charged at bio submission to the thread that submitted it: a read merged into another task's in-flight read counts for the first submitter. InnoDB read-ahead, page cleaners and other background reads are not per statement, so `percent_of_disk_read` summed over all statements can be < 100 % (`query_disk_read_coverage_percent` says how much is explained). Buffered writes are charged when the page is dirtied, not when it is flushed.
- `disk_wait` is `delays->blkio_delay`: synchronous block-I/O wait, excluding swap-in. It needs delay accounting on in every poll of the window (see `accounting.disk_wait`).
- Commit wait needs `log_write_up_to` in mysqld's symbols (and `emit_all_queries: true`, `mysql.commit_wait: true`). Nested calls count once (the outermost frame); sequential calls inside one command add up. A thread's own fsync of the log counts once, as block-I/O wait (`disk_wait`) — for the block I/O itself. With delay accounting off (`accounting.disk_wait` not `ok`) that fsync is not subtracted, so it shows as commit wait; `disk_wait` is then omitted, so nothing is counted twice. **ext4 caveat:** an fsync that waits for the jbd2 journal commit sleeps outside `io_schedule`, so that wait is not block-I/O wait; inside a `log_write_up_to` frame it shows as commit wait (outside one, in `other`).
- The kernel object reads `task_struct.ioac` / `delays` through CO-RE flavor structs guarded by `bpf_core_field_exists`, so it loads on kernels without `CONFIG_TASK_IO_ACCOUNTING` / `CONFIG_TASK_DELAY_ACCT`; those signals are then reported unavailable in `accounting` and their values omitted.
- `query_disk_read_coverage_percent` can be present while `node.disk_*` is absent: the `node` block needs node CPU for every poll, the coverage does not.
- Node disk bytes may double count on stacked devices that still look physical (`zd*` ZFS zvols, `drbd*`, `rbd*`: whole devices with an empty `slaves/`) — their I/O can also be counted on the local disks beneath (for `rbd*`, when Ceph OSDs run on the same node). `percent_of_disk_read` (and the coverage) can exceed 100 % when statements read through NFS or swap in from zram: those reads are charged to the thread's `ioac` but are not in the physical-disk count.
- Without PSI (`/proc/pressure` absent), `io_diagnosis` relies on iowait, which accrues only on idle CPUs: on a CPU-saturated node it can read `healthy` while the disk is saturated, so a disk overload may not appear as `secondary` of a CPU verdict.
- The disk `mysqld_top_consumer` check needs per-process I/O (`process.include_io`, default true); without per-family read bytes the disk verdict has low confidence and `missing: family_disk_io`.
- `bytes_in` (it was the SQL text length, not network bytes) is removed from digests, commands, Prometheus (`obs_agent_mysql_query_bytes_total{flow="in"}` is gone) and ClickHouse (`clickhouse-schema -alter` drops the column, §22).
- **Not verified at runtime in the development environment** (compile-checked only, on arm64 Linux): verifier acceptance, attach behaviour and byte/connection counts on x86_64. Run the verification commands in the spec/plan before relying on the numbers.

### Prepared statements and command names

`COM_STMT_EXECUTE` (command 23) carries only a statement id; the SQL was sent earlier with `COM_STMT_PREPARE` (22). Two optional uprobes connect them:

```
COM_STMT_PREPARE → mysqld_stmt_prepare → Prepared_statement::prepare(…query, length…)
    uprobe: ps_text[Prepared_statement*] = query text   (LRU_HASH, 16 384 entries)
COM_STMT_EXECUTE → mysqld_stmt_execute → Prepared_statement::execute_loop(…)
    uprobe: ps_exec[tid] = Prepared_statement*          (only inside a COM_STMT_EXECUTE dispatch_command)
uretprobe dispatch_command (COM_STMT_EXECUTE): text = ps_text[ps_exec[tid]]; ps_exec[tid] deleted for every command
```

- An execute with recovered text gets **the same digest** as the same statement sent as `COM_QUERY` (`command` stays `stmt_execute`). The prepare itself is a separate `stmt_prepare` digest, `prepare: <normalised text>`.
- **Statements prepared before the agent attached** (pooled connections) are reported as `<COM_STMT_EXECUTE: prepared before agent start, text unavailable>`. The text appears only when the **client** sends `COM_STMT_PREPARE` again (a new or recycled connection, or the driver re-preparing). A server-side re-prepare (triggered by DDL / metadata change) does **not** refresh it: mysqld prepares a temporary copy and swaps its contents into the original statement, so the original `Prepared_statement*` keeps whatever text — or none — it already had.
- `ps_text` holds **16 384** statements (LRU). With more live prepared statements than that across all sessions, the least recently prepared are evicted and their later executes show `prepared before agent start` too. (An entry evicted and re-filled concurrently can in rare cases pair an execute with the wrong text, or send a verification text that does not match its hash; userspace then detects the mismatch and marks the hash unsafe, so that statement is pinned to the exact full-event path.)
- `COM_STMT_FETCH` (server-side cursors) runs without `execute_loop`; its cost shows under `<COM_STMT_FETCH>` without text.
- A prepared `CALL p(?)` whose procedure runs `EXECUTE s` re-enters `execute_loop`; the outermost statement wins, so the whole command is attributed to the `CALL`.
- Needs `Prepared_statement::prepare` and `Prepared_statement::execute_loop` in mysqld's symbol table (`.symtab`, then `.dynsym`). Supported `prepare` layouts: `thd_first` `prepare(THD*, const char*, size_t, …)` (8.0.36+, 8.4, 9.x, 26.x) and `query_first` `prepare(const char*, size_t, …)` (5.7, 8.0 up to at least 8.0.28); the layout is chosen from the mangled name — see *MySQL version compatibility* in §16. Otherwise (stripped binary, unknown overload, attach error) the agent logs one warning, `PreparedTextTracking` is off and executes keep the placeholder `<COM_STMT_EXECUTE: prepared, text unavailable>`.
- Prepared executes also feed `recent_slow_queries`, with the recovered text when available (also with `emit_all_queries: false`). A slow execute without recovered text shows the same placeholder as its digest, never an empty `query`.
- Other commands get readable placeholders from MySQL 8.x `enum_server_command`: `<COM_PING>`, `<COM_REFRESH>`, `<COM_STMT_CLOSE>`, `<COM_RESET_CONNECTION>`, …; an unknown number stays `<COM command N>` (class `other`).
- **System-schema folding** (`mysql.fold_system_schemas`, default `true`): every statement that qualifies an object with `information_schema.`, `performance_schema.`, `sys.` or `mysql.` (exporter and monitoring queries) is merged into one digest `<system schemas: information_schema, performance_schema, sys, mysql>` with no `sample_query`; its command class is unchanged. Only a schema *qualifier* counts — `select sys from t` or a column `t.mysql` is not folded. An unqualified query run with `USE mysql` is not folded either. False positives: a user table or alias literally named `sys` or `mysql` used as a qualifier (`sys.col`) is folded too, and ORM-driven `information_schema` introspection is merged into the one sample-less row (its CPU is still counted there). Disable with `fold_system_schemas: false` or `MYSQL_FOLD_SYSTEM_SCHEMAS=false`.
- **Runtime not verified** in the development environment (compile-checked only on arm64 Linux): verifier acceptance of the new programs, the 8.4 register layout and the recovered text on x86_64 with a real mysqld. Run the commands below first.

Verification (x86_64 host with MySQL 8.4, as root):

```bash
sudo ./obs-agent -config /etc/obs-agent/config.yaml -loglevel debug > /tmp/obs-agent.log 2>&1 &
sleep 5; grep -i "prepared" /tmp/obs-agent.log   # expect "prepared-statement text tracking enabled" + layout
sysbench oltp_point_select --mysql-user=… --mysql-password=… --tables=1 --table-size=100000 --db-ps-mode=auto --threads=8 --time=60 run &
sleep 20; curl -s localhost:9200/api/diagnose | jq '.mysql_report.top_digests[] | {command, digest_text, calls, cpu_cores}' | head -40
# expect command "stmt_execute" with digest_text "select c from sbtest1 where id = ?" and a "prepare: select c from sbtest1 where id = ?" row;
# connections opened BEFORE the agent started show "prepared before agent start".
sudo bpftool map show name ps_text; sudo bpftool map show name ps_exec
```

### Overhead

| Component | CPU | Memory |
|---|---|---|
| netflow eBPF (~100k hook calls/s) | ~0.4 % | ~6 MB maps |
| mysql in-kernel aggregation (20k QPS) | ~0.2 % kernel + < 0.1 % userspace; kernel text hashing (≤ 511 iterations per COM_QUERY / COM_STMT_PREPARE at entry, prepares hashed twice) unmeasured | agg maps 2 × 16 384 × 96 B (~3.1 MB) + `mysql_pending` 8 192 × 640 B (~5.2 MB) + `cmd_events` ringbuf 4 MB + `text_events` ringbuf 1 MB + `text_seen` LRU 32 768 (~2–3 MB) + digests (~5 MB) + text cache (~5 MB typical; ≤ ~26 MB, ≤ ~43 MB with `sample_queries`, if every cached hash is a distinct digest) |
| mysql prepared-statement text (`ps_text` 16 384 × 520 B, `ps_exec`) | one map update per prepare / execute | ~9 MB maps (preallocated LRU) |
| mysql commit wait (`log_write_up_to` uprobe + uretprobe; trap on every call by any mysqld thread — the BPF filter runs after the trap, the uretprobe hijacks every return; MySQL 5.7 page cleaners call it once per flushed page, 8.0 guards that call). Off with `mysql.commit_wait: false` | ~2–5 µs per call on mysqld threads | — |
| kernel delay accounting (`enable_delayacct`) | kernel-wide, typically < 1 % | — |
| family grouping (10 s scan) | ~0.02 % | < 1 MB |
| netinv (per /api/diagnose) | 20–50 ms per call | transient |

All figures in this table are **estimated, not measured**.

---

## 21. Review output
This code can be use codex to review output of this code each change, so please review carefully after write code

---

## 22. ClickHouse Export

### Why

Prometheus cost is series count: servers × digests × ~5 (500 servers × 1 000 digests ≈ 2.5 M series). Prometheus therefore keeps the low-cardinality, alertable signals (§20 modes cap the digests); **ClickHouse keeps the long tail** — every MySQL digest, slow query, network peer (inbound and outbound) and process family — as delta rows that are exact under `sum()`, plus full `/api/diagnose` snapshots for after-the-fact forensics. Off by default: with `clickhouse.enabled: false` no drain is enabled, no goroutine starts and nothing is allocated. Transport is plain HTTP (`net/http`), no ClickHouse driver, no CGO.

```
querystats / netflow / mysql slow / process families ──Drain*()──►  chsink.Sink (flush_interval)
                                                                       │ rows → JSONEachRow+gzip → bounded buffer
chsink.Snapshotter (check_interval) ── BuildDiagnoseReport ───────────┤
                                                                       ▼
                                         POST {url}/?query=INSERT INTO db.table FORMAT JSONEachRow
                                              &async_insert=1&wait_for_async_insert=1
                                              &input_format_skip_unknown_fields=1
```

`input_format_skip_unknown_fields=1` lets a newer agent insert into a not-yet-migrated table: columns the table lacks are skipped (their data is lost until the migration) instead of rejecting the batch.

Each producer's `Drain*` swaps its accumulator out in O(1) under its lock; rows are built outside the lock. A window is "everything since the previous drain", so rows never overlap.

### Tables

All in database `clickhouse.database` (default `obs`), `MergeTree` partitioned by day with `ttl_only_drop_parts = 1`, every row carries `host`, all times UTC. Interval tables carry `window_start`/`window_end`; values are **deltas** for that interval, so `sum()` over any range is exact (`family_stats` holds avg/max gauges instead). Derived values (shares, rates, per call) are computed in SQL, never stored; NULL means "not measured"; no row is written without signal.

| Table | One row per |
|---|---|
| `mysql_digest_stats` | host, pid, digest, interval — calls, cpu/runq/wall/wall_max ns, `bytes_out`, `disk_read_bytes`, `disk_write_bytes` (always measured), `io_wait_ns`, `redo_wait_ns` (`Nullable`: NULL unless every poll of the interval measured that wait — `accounting.disk_wait` / `commit_wait` — and a host window exists) |
| `host_stats` | host, interval — the denominators: `cpu_count`, `node_cpu_used_ns`, `mysqld_cpu_ns`, `disk_read_bytes`, `disk_write_bytes` (physical disks). Value columns are `Nullable`: NULL unless every poll of the interval had a valid delta, so `sum()` skips them instead of mixing in a partial value. `cpu_count` is not nullable: 0 when no poll had a valid node CPU delta (`node_cpu_used_ns` is then NULL). No row when no poll ran or nothing moved |
| `mysql_digest_text` | digest (`ReplacingMergeTree`, no TTL) — `digest_text`, `sample_query` (NULL unless both privacy flags below) |
| `mysql_slow_queries` | slow query — latency, `digest_id` computed from the event text, `query` |
| `netflow_peer_stats` | host, family, pid, direction, peer (`IPv6`; IPv4 as `::ffff:a.b.c.d`), service port, interval — bytes rx/tx, conns opened/closed |
| `family_stats` | host, family, interval — `cpu_percent_avg/max`, `rss_bytes_max`, `processes_max` |
| `diagnose_snapshots` | captured snapshot — `reason`, `verdict`, `report` (exact `/api/diagnose` JSON, ZSTD) |

**Shares over a range** join the two on the same hosts and the same range: % of node CPU used = `sum(mysql_digest_stats.cpu_ns) / sum(host_stats.node_cpu_used_ns) × 100`, % of disk reads = `sum(disk_read_bytes) / sum(host_stats.disk_read_bytes) × 100`, node CPU used % = `sum(node_cpu_used_ns) / sumIf(cpu_count × window seconds × 1e9, node_cpu_used_ns IS NOT NULL) × 100`, a digest's disk wait % = `sum(io_wait_ns) / sumIf(wall_ns, io_wait_ns IS NOT NULL) × 100` (same for `redo_wait_ns`) — a denominator counts only the rows whose Nullable numerator was measured (queries in `deploy/clickhouse/queries.sql`). Divide through `nullIf(x, 0)`, not `greatest(x, 1)` (which ignores NULL on ClickHouse ≥ 24.12).

**Minor folding** (`clickhouse.min_digest_share_percent`, default `0.1`, `0` disables, valid `0 ≤ x < 100`): per interval and per (pid, command), digests under that % of the interval's query CPU **and** under that % of its query disk reads **and** with no execution at or above `mysql.slow_query_threshold_ms` are merged into one row `digest_id = '<minor>'` (text `<minor digests: …>`, sent once). Sums stay exact; one-off cheap statements stop producing rows. When an interval's total of a signal is 0, every digest counts as under the share for it. Folding happens after the `max_digest_keys` cap (`other`). Neither `<minor>` nor `other` gets a `cpuRole` / `ioRole` in the Analysis dashboard.

The `host` column is `agent.node_name`, else `os.Hostname()`. (The `hostname` field inside the diagnose JSON is always `os.Hostname()`.) `obs_agent_clickhouse_host_info{host}` exposes the value so Prometheus `instance` can be joined to it.

### Schema & retention

The agent **never runs DDL**; its user needs only `INSERT`.

```bash
obs-agent clickhouse-schema [-database obs] [-retention 30d] [-snapshot-retention 14d] [-alter]
obs-agent clickhouse-schema -retention 30d | clickhouse-client --multiquery   # create
obs-agent clickhouse-schema -alter -retention 60d | clickhouse-client --multiquery   # migrate + set TTL
```

Without `-alter` it prints `CREATE DATABASE/TABLE IF NOT EXISTS` plus a commented `CREATE USER … GRANT INSERT`. With `-alter` it prints the migration of an existing database — `ALTER TABLE mysql_digest_stats ADD COLUMN IF NOT EXISTS` the disk and wait columns, `DROP COLUMN IF EXISTS bytes_in`, `CREATE TABLE IF NOT EXISTS host_stats` — followed by `ALTER TABLE … MODIFY TTL` for every table, so one command both migrates and sets retention; every statement is idempotent (running it twice is safe). Retention accepts whole days only (`Nd`, ≥ 1). `deploy/clickhouse/schema.sql` is the default output (a test keeps them equal). Defaults: 30 d, snapshots 14 d.

**Rollout order:** upgrade the agents **first**, then run `obs-agent clickhouse-schema -alter | clickhouse-client --multiquery`. Older agents still send `bytes_in` without `input_format_skip_unknown_fields`, so their batches are rejected once the column is dropped. Upgraded agents writing to an unmigrated database lose only the new columns (skipped) and the `host_stats` batches (unknown table: rejected, counted in `rows_dropped_total{reason="rejected"}`, so `ObsAgentClickHouseDropping` can fire) until the migration. Rows written before the migration read `disk_read_bytes` / `disk_write_bytes` = 0 (non-Nullable defaults) and `io_wait_ns` / `redo_wait_ns` = NULL: disk shares are meaningful only for ranges after the migration time.

### Delivery

- Every `flush_interval` (default 60 s, min 10 s): drain → rows → one gzip JSONEachRow batch per non-empty table → bounded buffer → send up to `max_batches_per_flush`, oldest first.
- **Retry** (batch kept; one Warn on healthy→failing, one Info on recovery): network error, timeout, HTTP 429, 5xx, or a body containing `TOO_MANY_SIMULTANEOUS_QUERIES`. **Reject** (batch dropped, `rows_dropped_total{reason="rejected"}`, Error log with the first 512 bytes of the body, rate-limited): any other 4xx (auth, unknown table, schema mismatch).
- Buffer over `max_buffer_bytes` (32 MB): `diagnose_snapshots` batches are evicted first, then the oldest (`reason="buffer_full"`). A single batch larger than the limit is dropped up front. Over `max_digest_keys` / `max_flow_keys` per interval, new keys fold into an overflow key (`digest_id = 'other'` per pid; peer `::`, port 0) so totals stay correct (`reason="drain_cap"` counts events folded into overflow keys); slow queries beyond `max_slow_queries_per_flush` are dropped and counted.
- Digest text is sent once per digest (bounded seen-set of 50 000, cleared when full — `ReplacingMergeTree` absorbs resends). If the batch that carried a text is dropped (eviction, reject, shutdown), the text is re-sent with the next stats for that digest.
- Startup `Ping()` failure only warns. Shutdown does one final drain and send bounded by `clickhouse.timeout` (the rest counted `reason="shutdown"`), but the agent's exit waits at most 5 s.
- The agent never blocks, panics or exits because of ClickHouse. Alerts: `ObsAgentClickHouseExportStalled`, `ObsAgentClickHouseDropping` (`deploy/prometheus/obs-agent-alerts.yaml`).

### Snapshots

Every `snapshots.check_interval` (30 s) the Snapshotter looks for a **reason**: an eBPF module is active (`module:<id>[,<id>…]`), or the I/O verdict (`iodiag.Classify` on the latest metrics) is not `healthy`, `inconclusive` or `iowait_accounting_artifact` (`io_verdict:<verdict>`; both → `module:…;io_verdict:…`). It then builds the same report as `GET /api/diagnose` (`exporter.BuildDiagnoseReport`, so it needs `agent.metrics_addr`). At most one snapshot per `snapshots.min_interval` (5 m) per host; a reason different from the last captured one bypasses the limit once. A panic while building is recovered and the snapshot skipped. `obs_agent_clickhouse_snapshots_total{reason_kind=module|io_verdict|both}`.

### Privacy

- Raw SQL with literals leaves the host **only when `clickhouse.include_sample_queries` AND `mysql.sample_queries` are both true**. Otherwise `mysql_slow_queries.query` carries the literal-free digest text, `mysql_digest_text.sample_query` is NULL, and snapshots strip every `sample_query` and replace each slow-query text with its digest text (on a copy — the live `/api/diagnose` report is untouched). The agent enforces this AND in code (`ClickHouseConfig.EffectiveIncludeSamples`), so `mysql.sample_queries: false` also stops raw slow-query text from being exported.
- Snapshots (and `/api/diagnose`) still contain **process cmdlines (which may hold secrets such as `--password=`) and peer IPs**; these leave the host whenever `clickhouse.enabled` is true. Restrict who can read the ClickHouse database as you would `:9200`.
- The password is never logged (`ClickHouseConfig` redacts it); prefer `password_file` or the Secret-backed env vars in `deploy/daemonset.yaml`.

### Dashboards

`deploy/grafana/obs-agent-overview.json` (Prometheus) and `obs-agent-analysis.json` (ClickHouse, official `grafana-clickhouse-datasource`, read-only user).

- **Overview**: a "Firing obs-agent alerts" list (needs Grafana unified alerting evaluating the Prometheus rules, or an Alertmanager data source; filtered with `{instance=~"${instance:regex}"}`); "What is overloading this server?" (top CPU digest — % of node CPU used, top disk-read digest — % of node disk reads, query CPU coverage); "MySQL — who uses the server" (% of node CPU used / % of node disk reads by top digests, MySQL query CPU vs mysqld CPU, Top digests (last 5m) — a merged table of cores, % node CPU, disk MB/s, % disk read, pages/call); "MySQL — who is waiting" (Where query time goes, Commit wait share, Query disk writes by command, queries per second); Node, Disk & network (physical-disk throughput, PSI io full / some), Process families, Agent health (coverage, dropped/overflow/mismatches, accounting availability, ClickHouse sink). Panels behind an alert draw its threshold as a dashed line and name the alert (§20 alert table).
- **Analysis**: "Top digests" — `cpuCores` (average over the range; dilutes a burst), `peakCores` (highest rate of one flush interval on one host), `pctNodeCpu` / `pctDiskRead` (÷ `host_stats` totals of the same hosts and range), `readMBs`, `writeMBs`, `pagesPerCall`, `cpuWaitPct` / `diskWaitPct` / `commitWaitPct`, `latencyMsAvg` / `latencyMsMax`, and the role columns `cpuRole` (pctNodeCpu ≥ 20 and node CPU ≥ 50 % used), `ioRole` (pctDiskRead ≥ 20 and node reads ≥ 5 MiB/s), `victimOf` (latencyMsAvg ≥ `slow_ms` and waits ≥ 50 % of wall). The role columns pool all selected hosts over the whole dashboard range with the default thresholds hard-coded, so they are indicative; `mysql_report.overload_cause` in `/api/diagnose` is the per-node verdict. Also: % of node CPU used / % of node disk reads — top 10 digests, Node CPU used and disk reads, CPU of the top 10 digests, CPU regression vs 7 days earlier, a digest drill-down (calls and latency, Where the digest's time goes, per host), slow queries, families, network, and Snapshots (with `overload_cause.verdict` / `digest_id` extracted from each report).

Each picks its data source at view time with a picker variable (`ds_prometheus` / `ds_clickhouse`, no import-time inputs) and both are **generated**: edit `deploy/grafana/gen/main.go`, then `go run ./deploy/grafana/gen`. Setup and import steps: `deploy/grafana/README.md`. The Overview → Analysis link carries `host`, `family` and the time range. ClickHouse time series bucket by `greatest($__interval_s, ${flush_s})`: rows are one per `flush_interval`, and a narrower Grafana bucket holds a whole row or none, which overstated rates by `flush_interval / $__interval` (≈3× on a 6 h range). The hidden constants `flush_s` (60) and `slow_ms` (100) must equal the agents' `clickhouse.flush_interval` and `mysql.slow_query_threshold_ms`. `window_end` is the agent host's wall clock: an unsynchronised host clock shifts every ClickHouse panel against Prometheus. The Overview's "MySQL query CPU vs mysqld CPU (cores)" panel compares query CPU (inside `dispatch_command`, what digests can explain) with the mysqld family's CPU (`family_cpu_percent / 100 × cpu_count`, family picked by the `mysql_family` variable); the gap is mysqld CPU outside any query. Ad-hoc SQL: `deploy/clickhouse/queries.sql`.

### Configuration

`clickhouse:` in `deploy/config.yaml.example` (url, database, username, password / password_file, timeout, tls_insecure_skip_verify, flush_interval, max_buffer_bytes, max_batches_per_flush, max_digest_keys, max_flow_keys, max_slow_queries_per_flush, min_digest_share_percent, include_sample_queries, `snapshots.{enabled,check_interval,min_interval}`), plus `mysql.prometheus_digests`, `mysql.prometheus_minimal_top_n`, `netflow.max_inbound_peers`. Environment overrides: `CLICKHOUSE_ENABLED`, `CLICKHOUSE_URL`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USERNAME`, `CLICKHOUSE_PASSWORD`, `MYSQL_PROMETHEUS_DIGESTS`, `NETFLOW_MAX_INBOUND_PEERS`. Validation runs only when enabled: http(s) `url`; `database` matches `^[A-Za-z_][A-Za-z0-9_]*$`; `flush_interval` ≥ 10 s; 0 < `timeout` < `flush_interval`; `snapshots.min_interval` ≥ `check_interval`; all `max_*` > 0; `password_file` readable (content trimmed); 0 ≤ `min_digest_share_percent` < 100. Always validated: `prometheus_digests` ∈ {full, minimal, off}, `prometheus_minimal_top_n` ≥ 1, `max_inbound_peers` ≥ 0.

### Test

```bash
make test-clickhouse        # Docker: clickhouse-server, applies schema.sql, one sink cycle + snapshot, queries back sum()s
promtool test rules deploy/prometheus/obs-agent-alerts_test.yaml
go test ./internal/chsink/ ./internal/querystats/ ./internal/netflow/ ./internal/process/ ./internal/promcollect/ ./internal/config/ ./internal/drain/ ./deploy/grafana/gen/

# Smoke test against a real ClickHouse (agent running with clickhouse.enabled: true):
curl -s localhost:9200/metrics | grep obs_agent_clickhouse
clickhouse-client -q "SELECT table, count() FROM system.parts WHERE database='obs' AND active GROUP BY table"
clickhouse-client -q "SELECT digest_id, sum(calls), sum(cpu_ns)/1e9 FROM obs.mysql_digest_stats WHERE window_end > now() - INTERVAL 10 MINUTE GROUP BY digest_id ORDER BY 3 DESC LIMIT 10"
clickhouse-client -q "SELECT host, count(), sum(node_cpu_used_ns)/1e9 FROM obs.host_stats WHERE window_end > now() - INTERVAL 10 MINUTE GROUP BY host"

# Existing database: upgrade the agents, then migrate twice (the second run must be a no-op) and confirm inserts continue
obs-agent clickhouse-schema -alter | clickhouse-client --multiquery
obs-agent clickhouse-schema -alter | clickhouse-client --multiquery
```

Then import both dashboards and check the Overview alert list and the merged "Top digests (last 5m)" table.

**Verification status.** Unit tests for chsink, querystats, netflow, process, promcollect, config, drain and the dashboard generator run anywhere with Go 1.26. `internal/mysql`, `internal/exporter` and `cmd/agent` import generated eBPF code and need `make generate` on Linux. `promtool test rules` runs in devbox. `make test-clickhouse` (Docker), the `-alter` migration and the dashboard import have **not been run** in the development environment, and nothing was checked against a real ClickHouse cluster, a real Grafana or a real mysqld. Overhead figures (§14) are **estimated, not measured**.

### Limits

- Rows are at `flush_interval` grain; sub-minute analysis uses Prometheus.
- Netflow window jitter up to one `netflow.poll_interval` (5 s): the accumulator sees deltas only per poll.
- The host and digest drains are separate (drained back to back each flush): a poll that straddles a flush is split across adjacent windows; when wait availability changes, one window may carry a measured wait that includes one unmeasured poll; sums over a range stay exact.
- Family stats fold the family scans that complete inside the window; a window with no scan yields no rows.
- Digests beyond `max_digest_keys` per interval fold into `digest_id = 'other'` per pid; minor digests into `<minor>` per (pid, command) (`min_digest_share_percent`); peers beyond `max_flow_keys` into `::`/0; slow queries beyond `max_slow_queries_per_flush` are dropped (counted). A digest that is minor in most intervals has most of its cost under `<minor>`.
- Shares need `host_stats` rows for the same hosts and range as the digest rows; `host_stats` NULL values are skipped by `sum()`, so a range with unmeasured intervals divides by a smaller total (a digest's % of node CPU / disk reads reads high). Ratios whose **numerator** is Nullable count only the intervals that measured it: node CPU used % (and the `cpuRole` 50 % gate) divides by the CPU capacity of the intervals with a valid node delta, and `diskWaitPct` / `commitWaitPct` (and `victimOf`) by the wall time of the intervals that measured that wait — before this, unmeasured intervals counted as 0 and those values read low. Disk columns of rows written before the migration read 0.
- `MySQLSlowEvent` has no CPU / run-queue / bytes, so `mysql_slow_queries` lacks those columns; use `mysql_digest_stats`.
- `mysql_slow_queries.digest_id` is computed from the event text: statements folded by `fold_system_schemas`, and prepared executes without recovered text, may not join to `mysql_digest_stats`.
- Dashboards: per-cell data links, a Snapshots link column and a load ÷ CPUs panel are **not implemented**. Snapshots are read with the SQL in `deploy/grafana/README.md`.
- MongoDB digests, Kafka/collector transports and agent-managed schema migrations are not covered.
