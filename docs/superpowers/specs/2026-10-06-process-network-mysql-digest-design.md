# Process Families, Network Flows & MySQL Query Digests — Design

**Date:** 2026-10-06
**Status:** Approved in brainstorming, pending written-spec review
**Branch:** `feat/process-network-mysql-digest`

---

## 1. Problem & intent

`/api/diagnose` today lists the top processes by CPU only, ranks each process
individually (a pool of 50 php-fpm workers never surfaces as one heavy
service), has no notion of who a process talks to, and the MySQL tracer only
measures wall-clock latency.

The motivating incident: **MySQL under high CPU**. Once the CPU saturates,
*every* query's wall latency inflates, so the slow-query list fills with
victims and hides the query that caused the saturation.

### Goals

| # | Goal | Use case |
|---|---|---|
| G1 | Top-10 processes by CPU and by memory, **and** top-10 process *families* (systemd unit) by CPU and by memory | A — incident triage |
| G2 | Per process / family: inbound and outbound connection counts, bytes rx/tx, listening ports, top peers | A + B |
| G3 | Per process: live connection list with `src → dst` for both directions | A |
| G4 | Per MySQL query digest: **on-CPU time**, run-queue wait, wall time, bytes in/out — ranked by total CPU to separate culprit from cascade victims | A |
| G5 | Bounded-cardinality Prometheus metrics + alert rules for G1–G4 | B — continuous monitoring |

### Non-goals

- Security / anomaly detection (new destinations, new listeners).
- Databases other than MySQL for query digests (the data model is generic; only MySQL is wired).
- Prepared-statement text recovery (`COM_STMT_EXECUTE`) — measured, but under a placeholder digest.
- Unix-socket and UDP traffic at the process/family level.
- Long-term per-query / per-connection history store (ClickHouse/Loki) — future spec.
- Grafana dashboard JSON — optional follow-up.

### Environment assumptions

- Bare-metal / VM hosts, MySQL ≥ 8.0, peak < 20k QPS per host.
- Kernel ≥ 5.4 with BTF (project baseline).
- MySQL runs one-thread-per-connection (default), so the `dispatch_command` thread is the thread that sends the result.

### Why CPU time, not bytes, is the primary ranking

Bytes-out catches large-result queries, but the most CPU-expensive MySQL
queries (full scans, `GROUP BY` over unindexed columns, bad joins) examine
millions of rows and *send* a handful. CPU cost tracks rows **examined**;
bytes tracks rows **sent**. Further, a high-QPS cheap query can dominate CPU
without any single execution being slow or large.

Wall time decomposes as:

```
wall = on-CPU  +  run-queue wait  +  blocked (I/O, locks)
       culprit     cascade victim     I/O / lock contention
```

The kernel already maintains `task->se.sum_exec_runtime` and
`task->sched_info.run_delay` per thread. Reading both at `dispatch_command`
entry and exit gives per-query CPU and run-queue wait. Aggregating per digest
and ranking by **total** CPU identifies culprits; high run-queue wait with low
CPU identifies victims. Bytes-out remains as a secondary ranking.

---

## 2. Architecture

```
                       ┌───────────────── always-on ─────────────────┐
 kernel                │                                             │
  sock:inet_sock_set_state ─┐                                        │
  kretprobe inet_csk_accept ┤                                        │
  k(ret)probe tcp_sendmsg ──┼─► netflow.bpf.c ─► flow_stats (LRU)    │
  kprobe tcp_cleanup_rbuf ──┘   key {tgid, dir, family, peer, port}  │
                                                                      │
  uprobe/uretprobe mysqld!dispatch_command ─► mysql_query.bpf.c      │
     + task se.sum_exec_runtime, sched_info.run_delay                │
     + kretprobe tcp_sendmsg/unix_stream_sendmsg bytes while tid is mid-command         │
     ─► RINGBUF: one event per command                               │
                       └─────────────────────────────────────────────┘
 userspace
  internal/netflow    poll flow_stats every 5s → per-PID / per-family totals, rates, counters
  internal/sqldigest  NEW, generic: Normalize(sql) → digest
  internal/mysql      consume command events → per-digest aggregates (rolling window)
  internal/process    + family grouping; top-10 CPU/mem for processes AND families
  internal/netinv     NEW, on-demand: /proc/net/tcp{,6} + /proc/<pid>/fd
  exporter            /api/diagnose `process_report`, extended `mysql_report`; /metrics
```

### Units

| Unit | Responsibility | Depends on |
|---|---|---|
| `internal/ebpf/netflow/` (new) | In-kernel per-(tgid, direction, peer, service port) byte and connection counters | kernel BTF |
| `internal/ebpf/mysql_query/` (extended) | Per-command CPU, run-queue wait, wall, bytes in/out; emits every command | existing uprobe |
| `internal/sqldigest/` (new) | Pure `Normalize(sql) (Digest, error-free)`; DB-agnostic | — |
| `internal/mysql/` (extended) | Consumes command events → rolling per-digest aggregates; role classification; sticky export set | sqldigest |
| `internal/process/` (extended) | Family key from cgroup; top-N processes and families by CPU and memory | existing scan |
| `internal/netinv/` (new) | On-demand inventory: listening sockets, live connections, socket-inode → PID | /proc |
| `internal/netflow/` (new) | Polls `flow_stats`, maintains monotonic counters across LRU eviction, joins to PIDs/families, pushes `listen_ports` | ebpf/netflow, netinv (listen parse), process |
| `internal/querystats/` (new) | Generic, DB-agnostic rolling per-digest aggregation, roles, sticky export set | sqldigest |
| `internal/procreport/` (new) | Pure builder for `process_report` from inspector, netflow and netinv inputs | interfaces only |
| `internal/promcollect/` (new) | Prometheus `Collector`s for family and MySQL metrics | netflow, querystats |
| `internal/exporter/` (extended) | Wires the above into `/api/diagnose` and `/metrics` | all above |

**Testability rule:** packages that import a bpf2go loader only compile on a
Linux build host after `make generate`. All logic therefore lives in pure
packages (`sqldigest`, `querystats`, `netinv`, `netflow`, `procreport`,
`promcollect`, `process`) that depend on interfaces; eBPF packages are thin
loaders.

**Independence:** `mysql_query` does its own byte counting and does not share maps with
`netflow`; either can be disabled alone. `netinv` runs only when `/api/diagnose`
is called, except its cheap LISTEN-only parse that `netflow` reuses every 30 s.

---

## 3. eBPF design

### 3.1 `netflow.bpf.c`

**Attribution rule.** Several TCP state transitions run in softirq where
`current` is unrelated. The *owner* is therefore recorded only in
process-context hooks and stored per socket; bytes are charged to the
*current* tgid at send/receive time (both process context), which correctly
attributes sockets handed from a parent to a forked worker.

| Hook | Context | Action |
|---|---|---|
| `tp/sock/inet_sock_set_state` CLOSE→SYN_SENT (TCP only) | process (`connect()`) | `sock_meta[sk] = {owner=tgid, dir=OUT, family, peer=daddr, svc_port=dport}` |
| `kretprobe/inet_csk_accept` | process (`accept()`) | `sock_meta[ret_sk] = {owner=tgid, dir=IN, family, peer=daddr, svc_port=lport}`; `flow_stats[owner,IN,…].opened++` |
| `inet_sock_set_state` SYN_SENT→ESTABLISHED | softirq | `flow_stats[stored owner,OUT,…].opened++` |
| `inet_sock_set_state` →CLOSE | any | if `sock_meta[sk]`: `closed++` on stored owner; delete `sock_meta[sk]` |
| `kprobe/tcp_sendmsg` + `kretprobe/tcp_sendmsg` | process | entry stashes `sk` per tid; exit adds positive return value to `bytes_tx` for current tgid |
| `kprobe/tcp_cleanup_rbuf(sk, copied)` | process | `copied > 0` → `bytes_rx` for current tgid |

Byte hooks resolve direction/peer/port from `sock_meta[sk]`. **Lazy adoption**
for sockets with no `sock_meta` (pre-existing at agent start, or accept hook
unavailable): create the entry on first bytes, direction = `IN` if the local
port is in `listen_ports`, else `OUT`; count it as `opened`.

**Maps**

| Map | Type | Entries | Key → Value |
|---|---|---|---|
| `sock_meta` | LRU_HASH | 65 536 | `sk ptr` → `{owner_tgid, dir, family, peer_ip[16], svc_port}` |
| `send_args` | HASH | 16 384 | `tid` → `sk ptr` (deleted in kretprobe) |
| `flow_stats` | LRU_HASH | 16 384 | `{tgid, dir, family, peer_ip[16], svc_port}` → `{bytes_tx, bytes_rx, opened, closed, last_seen_ns}` (atomic adds) |
| `listen_ports` | HASH | 4 096 | `{family, port}` → `u8` (written by userspace) |

Config globals (`const volatile`): `include_loopback` (default 1).
No ring buffer. IPv4 stored as v4-mapped in `peer_ip[16]`.

### 3.2 `mysql_query.bpf.c` extensions

**uprobe `dispatch_command(thd, com_data, command)`** — now for every command:

```c
task = (struct task_struct *)bpf_get_current_task();
pending[tid] = {
  start_ts   = bpf_ktime_get_ns(),
  command,
  cpu_start  = BPF_CORE_READ(task, se.sum_exec_runtime),
  rq_start   = BPF_CORE_READ(task, sched_info.run_delay),
  bytes_in   = command == COM_QUERY ? com_data->com_query.length : 0,  // union offset 8
  bytes_out  = 0,
  query_len,  query[512]   // COM_QUERY only
};
```

**`kretprobe/tcp_sendmsg` + `kretprobe/unix_stream_sendmsg`** — if `pending[tid]`
exists, add a positive (int) return value to `bytes_out`. Covers TCP, unix-socket
and userspace-TLS clients (bytes on the wire, post-encryption).
`sock_sendmsg` was rejected: since kernel 6.6 `send()`/`write()` reach the
protocol through the static, inlinable `__sock_sendmsg`, so a `sock_sendmsg`
probe silently misses traffic. The protocol `sendmsg` functions are called via
`proto_ops` function pointers and can never be inlined. The pending entry is
built in a per-CPU scratch map because it exceeds the 512-byte BPF stack.

**uretprobe `dispatch_command`** — compute `wall_ns`, `cpu_ns`, `runq_ns`;
reserve a ringbuf record directly (no stack copy of the query) and submit
`mysql_cmd_event_t {pid, tid, command, wall_ns, cpu_ns, runq_ns, bytes_in,
bytes_out, query_len, truncated, query[512], comm}`. Existing per-PID stats
map and slow-query event are kept unchanged. On reserve failure increment a
per-CPU `dropped` counter.

Ringbuf grows 256 KB → 4 MB (≈ 12 MB/s at 20k QPS × ~600 B).

Config globals: `emit_all_queries` (default 1; 0 restores slow-only behaviour).

### 3.3 Accuracy caveats (documented in AGENTS.md)

1. `sum_exec_runtime` is updated at ticks/switches → per-call CPU is ± one
   tick (1–4 ms). Error is unbiased; **per-digest totals are accurate**;
   `cpu_ms_avg` is unreliable for sub-millisecond queries.
2. `run_delay` requires scheduler stats (on by default on Ubuntu/RHEL kernels).
   See §6 fallback.
3. Query text truncated at 512 bytes; digests may merge queries differing only
   after byte 512 (`truncated: true`).
4. Non-`COM_QUERY` commands are reported under placeholder digests, e.g.
   `<COM_STMT_EXECUTE: prepared, text unavailable>`.

---

## 4. Userspace components

### 4.1 `internal/sqldigest`

`Normalize(sql string) Digest` where
`Digest{ID string /*first 16 hex of sha256(Text)*/, Text string, Normalized bool}`.

Rules, applied by a single-pass tokenizer (no regex backtracking):
- strip `/* … */`, `-- …`, `# …` comments;
- string literals `'…'`/`"…"` (with escapes), numbers, hex `0x…`, `X'…'`, `TRUE/FALSE/NULL` literals → `?`;
- `IN (?, ?, …)` → `IN (?+)`; `VALUES (…),(…)` → `VALUES (?+)`;
- collapse whitespace; lower-case keywords and identifiers (backtick-quoted identifiers keep case);
- unterminated literal (truncated text) → replace remainder with `?`, `Normalized` stays true.
Never panics; on any internal failure returns whitespace-collapsed raw text with `Normalized=false`.

### 4.2 `internal/mysql` analyzer extensions

- Ring-buffer reader goroutine → `digestTable` keyed by `(pid, digest.ID)`.
- Rolling window (`digest_window`, default 60 s) implemented as 12 × 5 s buckets.
- Per digest: `calls, cpu_ns_total, cpu_ns_max, runq_ns_total, wall_ns_total, wall_ns_max, bytes_in_total, bytes_out_total, sample_query, truncated, command`.
- Also lifetime monotonic counters per digest (for Prometheus) and per command class.
- `cpu_share_percent = digest.cpu_total / Σ cpu_total (same pid) × 100` — relative to the
  pid's *query* CPU only, so on an idle server a monitoring digest can reach 80–90 % of
  almost nothing.
- `cpu_percent_of_core = digest.cpu_total / window × 100` (absolute scale); report-level
  `query_cpu_ms_total = Σ cpu_total` (all pids).
- Role: `culprit` if `cpu_share_percent ≥ culprit_cpu_share_percent` (20) **and**
  `cpu_percent_of_core ≥ culprit_min_cpu_percent` (5, i.e. ≥ 3 s CPU per 60 s);
  `victim` if `runq_avg > cpu_avg × victim_runq_ratio` (5) **and** `wall_avg ≥ slow_query_threshold_ms`; else `""`.
  With `cpu_accounting = run_delay_unavailable`, `victim` uses `(wall_avg − cpu_avg)` in place of `runq_avg`.
- `cpu_accounting` detection: after ≥ 1 000 commands where `wall − cpu > 10 ms` and Σ `runq_ns == 0` → `run_delay_unavailable`.
- Sticky export set: digest enters when it is in the top-20 by CPU or by bytes-out; leaves after `sticky_digest_ttl` (1 h) without qualifying; capped at `sticky_digests_max` (50), evicting the least recently qualifying.
- Memory bound: `digestTable` capped at 5 000 digests per window; overflow aggregated into digest `<other>`.

### 4.3 `internal/process` extensions

- `FamilyKey(cgroupLine)`: last path component ending in `.service`; else `.scope`
  (e.g. `session-42.scope`); else the full cgroup v2 path (or v1 `name=systemd`/`cpu` controller path); `"unknown"` if unreadable. `family_by: cgroup` uses the full path always.
- Must read all lines of `/proc/<pid>/cgroup` (today only the first line is read; on cgroup v1 that is not the systemd hierarchy).
- Families: sum CPU%, RSS, process count; `root_pid` = oldest process (lowest start time) in the family; `top_members` = top-5 by CPU.
- New accessors `TopFamiliesCPU()`, `TopFamiliesMem()`, `Families() map[string][]uint32` (for netflow join).
- New `process.report_top_n` (default **10**) drives `process_report`. The existing `process.top_n` (default 20) and `top_processes` are unchanged for backward compatibility.

### 4.4 `internal/netinv`

- `ParseNetTCP(r io.Reader, family)` for `/proc/net/tcp` and `/proc/net/tcp6`.
- `Listening()` → LISTEN sockets `{family, addr, port, inode}` (used every 30 s by netflow to fill `listen_ports`).
- `ForPIDs(pids []uint32)` → per PID: listening ports and connections, by mapping `/proc/<pid>/fd/*` socket inodes to parsed rows. Direction: `IN` if local port ∈ that process's (or host's) listening set, else `OUT`. `src`/`dst` rendered client→server.
- Sort ESTABLISHED, CLOSE_WAIT, TIME_WAIT, others; cap `max_connections_per_process` (50); report `connections_truncated`.
- TIME_WAIT sockets have no owning fd; they are attributed only when their local port is a listening port of the process (inbound), otherwise omitted.

### 4.5 `internal/netflow` analyzer

- Every `poll_interval` (5 s): batch-read `flow_stats`; for each key compute delta vs previous value (value < previous ⇒ entry was evicted and re-created ⇒ delta = value); add to monotonic counters and to a rolling `window` (60 s).
- Join tgid → family via `process.Families()`; aggregate per family.
- Active connections = `opened − closed` per (tgid, dir), clamped ≥ 0.
- Every `listen_refresh_interval` (30 s): `netinv.Listening()` → rewrite `listen_ports`.
- Remove counters for tgids gone for > 10 min (family counters persist).

---

## 5. External interfaces

### 5.1 `/api/diagnose` — `process_report` (new field)

```json
"process_report": {
  "type": "process_analysis",
  "timestamp": "…",
  "window_seconds": 60,
  "network_source": "ebpf",
  "top_cpu":  [ProcessEntry ×10],
  "top_mem":  [ProcessEntry ×10],
  "top_families_cpu": [FamilyEntry ×10],
  "top_families_mem": [FamilyEntry ×10]
}
```

**ProcessEntry**

```json
{
  "pid": 2314, "ppid": 1, "comm": "mysqld",
  "cmdline": "/usr/sbin/mysqld --defaults-file=/etc/mysql/my.cnf",
  "family": "mysql.service",
  "cpu_percent": 87.2, "mem_rss_bytes": 6442450944, "mem_percent": 61.8,
  "threads": 212, "open_files": 3120,
  "listening_ports": [{"proto":"tcp","addr":"0.0.0.0","port":3306}],
  "network": {
    "inbound":  {"conns_active":480,"conns_opened":1210,"conns_closed":1190,
                 "bytes_rx":18200000,"bytes_tx":940000000,
                 "bytes_rx_per_sec":303333,"bytes_tx_per_sec":15666666},
    "outbound": {"conns_active":2, "…": "…"},
    "top_peers": [
      {"direction":"inbound","peer_ip":"10.0.3.15","service_port":3306,
       "conns_active":120,"bytes_rx":4100000,"bytes_tx":610000000}
    ]
  },
  "connections": [
    {"direction":"inbound","state":"ESTABLISHED","src":"10.0.3.15:51844","dst":"10.0.1.7:3306"}
  ],
  "connections_truncated": 430,
  "connections_error": "",
  "profile_url": "/api/profile?pid=2314"
}
```

- `network`: eBPF totals over `window_seconds` (includes closed connections). `top_peers` capped at `max_peers_per_process` (20), ranked by `bytes_rx + bytes_tx`.
- `connections`: live sockets from `netinv`, client→server orientation.

**FamilyEntry**: `family, root_pid, root_cmdline, process_count, cpu_percent,
mem_rss_bytes, mem_percent, listening_ports (union), network (summed, merged
top_peers), top_members [{pid, comm, cpu_percent, mem_rss_bytes} ×5]`. No
`connections` list.

### 5.2 `/api/diagnose` — `mysql_report` (extended)

New fields (existing unchanged): `window_seconds`, `cpu_accounting`
(`ok | run_delay_unavailable`), `query_cpu_ms_total`, `dropped_events`,
`thresholds {culprit_cpu_share_percent, culprit_min_cpu_percent, victim_runq_ratio}`,
`top_digests` (top-20 by `cpu_ms_total`), `top_digests_by_bytes_out` (top-10).

Digest entry:

```json
{
  "pid": 2314, "digest_id": "9f2c1a…", "command": "query",
  "digest_text": "select status , count ( * ) from orders where created_at > ? group by status",
  "sample_query": "SELECT status, COUNT(*) FROM orders WHERE created_at > '2026-10-01' GROUP BY status",
  "normalized": true, "truncated": false,
  "calls": 120,
  "cpu_ms_total": 48000, "cpu_ms_avg": 400, "cpu_ms_max": 910,
  "runq_wait_ms_avg": 5.1,
  "wall_ms_avg": 410, "wall_ms_max": 1300,
  "bytes_in_total": 14400, "bytes_out_total": 24000, "bytes_out_avg": 200,
  "cpu_share_percent": 71.4,
  "cpu_percent_of_core": 80.0,
  "role": "culprit"
}
```

### 5.3 Prometheus metrics

Rule: no PID, client-port, or raw-SQL labels. All label sets are capped; overflow → `"other"`.

| Metric | Type | Labels |
|---|---|---|
| `obs_agent_family_cpu_percent` | gauge | `family` |
| `obs_agent_family_mem_rss_bytes` | gauge | `family` |
| `obs_agent_family_processes` | gauge | `family` |
| `obs_agent_family_net_bytes_total` | counter | `family, direction, flow` |
| `obs_agent_family_net_connections_opened_total` | counter | `family, direction` |
| `obs_agent_family_net_connections_active` | gauge | `family, direction` |
| `obs_agent_family_inbound_bytes_total` | counter | `family, service_port, flow` |
| `obs_agent_family_outbound_peer_bytes_total` | counter | `family, peer_ip, service_port, flow` |
| `obs_agent_mysql_queries_total` | counter | `command` |
| `obs_agent_mysql_query_cpu_seconds_total` | counter | `command` |
| `obs_agent_mysql_query_runq_wait_seconds_total` | counter | `command` |
| `obs_agent_mysql_query_wall_seconds_total` | counter | `command` |
| `obs_agent_mysql_query_bytes_total` | counter | `command, flow` |
| `obs_agent_mysql_digest_cpu_seconds_total` | counter | `digest_id` |
| `obs_agent_mysql_digest_calls_total` | counter | `digest_id` |
| `obs_agent_mysql_digest_bytes_out_total` | counter | `digest_id` |
| `obs_agent_mysql_digest_runq_wait_seconds_total` | counter | `digest_id` |
| `obs_agent_mysql_digest_info` | gauge (=1) | `digest_id, digest_text` (≤ 120 chars) |
| `obs_agent_mysql_events_dropped_total` | counter | — |

`command ∈ {query, stmt_execute, other}`. Caps: `max_families` 50,
`max_outbound_peers` 100, `sticky_digests_max` 50. Metrics are implemented
as Prometheus `Collector`s reading analyzer snapshots at scrape time, so
series for evicted labels disappear cleanly.

### 5.4 Alert rules — `deploy/prometheus/obs-agent-alerts.yaml`

Eight rules, each with `annotations.diagnose: "http://{{ $labels.instance }}/api/diagnose"`:

| Alert | Expression (abridged) | for |
|---|---|---|
| `MySQLQueryDigestCPUHog` | digest CPU rate / total query CPU rate > 0.30 **and** node CPU > 85 | 5m |
| `MySQLQueriesStarvedForCPU` | runq-wait rate / wall rate > 0.30 | 5m |
| `MySQLDigestResultSizeSpike` | bytes/call > 5× same window 1d ago **and** > 5 MB/s | 10m |
| `ProcessFamilyCPUHigh` | `family_cpu_percent > 80` | 10m |
| `ProcessFamilyMemoryExhaustion` | `predict_linear(rss[1h], 4h) > 0.9 × mem_total` | 15m |
| `OutboundTrafficAnomaly` | peer rate > 3× 1w ago **and** > 10 MB/s | 10m |
| `ConnectionChurnHigh` | opened rate > 500/s per family+direction | 10m |
| `ObsAgentMySQLEventsDropped` | dropped rate > 0 | 10m |

Thresholds are starting points to tune against baselines. Full expressions:

```yaml
- alert: MySQLQueryDigestCPUHog
  expr: |
    (sum by (instance, digest_id) (rate(obs_agent_mysql_digest_cpu_seconds_total[5m]))
      / on (instance) group_left
     sum by (instance) (rate(obs_agent_mysql_query_cpu_seconds_total[5m]))) > 0.30
    and on (instance) obs_agent_cpu_usage_percent > 85
  for: 5m
- alert: MySQLQueriesStarvedForCPU
  expr: |
    sum by (instance) (rate(obs_agent_mysql_query_runq_wait_seconds_total[5m]))
      / sum by (instance) (rate(obs_agent_mysql_query_wall_seconds_total[5m])) > 0.30
  for: 5m
- alert: MySQLDigestResultSizeSpike
  expr: |
    (rate(obs_agent_mysql_digest_bytes_out_total[10m]) / rate(obs_agent_mysql_digest_calls_total[10m]))
      > 5 * (rate(obs_agent_mysql_digest_bytes_out_total[10m] offset 1d)
             / rate(obs_agent_mysql_digest_calls_total[10m] offset 1d))
    and rate(obs_agent_mysql_digest_bytes_out_total[10m]) > 5e6
  for: 10m
- alert: ProcessFamilyCPUHigh
  expr: obs_agent_family_cpu_percent > 80
  for: 10m
- alert: ProcessFamilyMemoryExhaustion
  expr: |
    predict_linear(obs_agent_family_mem_rss_bytes[1h], 4*3600)
      > on (instance) group_left obs_agent_mem_total_bytes * 0.9
  for: 15m
- alert: OutboundTrafficAnomaly
  expr: |
    sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total[10m]))
      > 3 * sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total[10m] offset 1w))
    and sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total[10m])) > 10e6
  for: 10m
- alert: ConnectionChurnHigh
  expr: sum by (instance, family, direction) (rate(obs_agent_family_net_connections_opened_total[5m])) > 500
  for: 10m
- alert: ObsAgentMySQLEventsDropped
  expr: rate(obs_agent_mysql_events_dropped_total[5m]) > 0
  for: 10m
```

---

## 6. Error handling

| Failure | Behaviour |
|---|---|
| `netflow` attach fails | Warn, continue; `network` omitted; `network_source: "unavailable: <reason>"`. Process/family top-N unaffected. |
| `inet_csk_accept` kretprobe unavailable | Lazy adoption only; `inbound_accounting: "lazy"` in `process_report`. |
| `run_delay` always 0 | `cpu_accounting: "run_delay_unavailable"`; victim rule uses `wall − cpu`; `MySQLQueriesStarvedForCPU` stays silent (no data). |
| `mysqld` restart | Uprobes are attached to the binary inode, so a restarted mysqld is traced automatically. A package upgrade that replaces the binary (new inode) requires an agent restart — documented, out of scope. |
| Ringbuf full | `dropped_events` increments; digests undercount; kernel per-PID totals remain exact. |
| `/proc/<pid>` vanished / EACCES during inventory | Skip; `connections_error` set. |
| SQL normaliser edge case | Never fails; `normalized: false` with collapsed raw text. |
| Cardinality overflow | Fold into `"other"` / `<other>`. |

---

## 7. Configuration

```yaml
process:
  report_top_n: 10              # NEW; existing top_n (20) unchanged
  family_by: systemd_unit       # systemd_unit | cgroup
  max_connections_per_process: 50
  max_peers_per_process: 20

netflow:                        # NEW section
  enabled: true
  poll_interval: 5s
  window: 60s
  include_loopback: true
  listen_refresh_interval: 30s
  max_families: 50
  max_outbound_peers: 100

mysql:                          # existing; new keys
  emit_all_queries: true
  digest_window: 60s
  top_digests: 20
  sticky_digests_max: 50
  sticky_digest_ttl: 1h
  culprit_cpu_share_percent: 20
  culprit_min_cpu_percent: 5
  victim_runq_ratio: 5
```

Env overrides: `NETFLOW_ENABLED`, `NETFLOW_INCLUDE_LOOPBACK`, `MYSQL_EMIT_ALL_QUERIES`,
`MYSQL_DIGEST_WINDOW`. Validation: windows ≥ poll interval; caps ≥ 1; ratios > 0.
`mysql.enabled` remains default false.

---

## 8. Testing

**Unit (table-driven, run on macOS/Linux, no root):**
- `sqldigest.Normalize`: literals, escapes, `IN`/`VALUES` lists, comments, backticks, unicode, truncated mid-literal, garbage bytes.
- `process.FamilyKey`: cgroup v1/v2, `.service`, `.scope`, `session-N.scope`, kubepods, empty.
- `netinv.ParseNetTCP`: v4/v6 fixtures, state mapping, direction, client→server rendering.
- `netflow` counter accumulation across LRU eviction (value drop), window roll-off, active clamping.
- `mysql` digest aggregation, role assignment, `cpu_accounting` detection, sticky set TTL and cap, `<other>` overflow.
- Prometheus collectors: label caps, `"other"` folding, `_info` join.

**eBPF on a Linux VM (manual, documented in AGENTS.md):**
- Both modules load; hooks visible in `bpftool prog list`.
- `curl` ↔ `nc -l` transfer: `bytes_tx/rx` within 1 % of transfer size.
- 1 000 sub-10 ms connections: `opened`/`closed` exact.

**MySQL end-to-end acceptance:**
1. `sysbench oltp_read_only` background load (victims).
2. Culprit: unindexed `SELECT … COUNT(*) … GROUP BY` over 10M rows in a loop.
3. `stress-ng` to saturate CPU.
4. **Pass:** culprit digest #1 in `top_digests` with `role: culprit`; sysbench point-selects carry `role: victim`; `MySQLQueryDigestCPUHog` fires in a local Prometheus.
5. `SELECT *` large-result query tops `top_digests_by_bytes_out`.

**Overhead:** at 20k QPS agent CPU < 2 %, RSS < 100 MB.

Each change is reviewed with Codex per CLAUDE.md §20.

---

## 9. Overhead budget (to add to AGENTS.md §14)

| Component | CPU | Memory |
|---|---|---|
| `netflow` eBPF (~100k hook calls/s) | ~0.4 % | ~6 MB maps |
| `mysql_query` per-command events (20k QPS) | ~0.3 % kernel + ~1 % userspace digesting | 4 MB ringbuf + ~5 MB digest table |
| Family grouping (existing 10 s scan) | ~0.02 % | < 1 MB |
| `netinv` (per `/api/diagnose`) | 20–50 ms per call | transient |

---

## 10. Documentation updates

AGENTS.md / CLAUDE.md: project structure (§2), module reference (§3), new
eBPF sections for `netflow` and the MySQL extensions (§4, §16), Prometheus
metric table (§13), performance budget (§14), and a new section
"Process families, network flows & query digests" with the diagnose
examples and alert rules above.
