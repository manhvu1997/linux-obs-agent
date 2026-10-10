# obs-agent Grafana dashboards

| File | Data source | Purpose |
|---|---|---|
| `obs-agent-overview.json` | Prometheus | Firing alerts, what is overloading the server, MySQL who uses / who waits (with the alert thresholds drawn), node, disk, families, agent health |
| `obs-agent-analysis.json` | ClickHouse | Every digest with node-relative shares (from `host_stats`), culprit/victim roles, slow queries, families, inbound/outbound peers, diagnose snapshots |

Both are generated: edit `deploy/grafana/gen/main.go`, then run `go run ./deploy/grafana/gen`.

## Setup

1. Install the ClickHouse plugin (4.x): `grafana-cli plugins install grafana-clickhouse-datasource`, restart Grafana.
2. Add a ClickHouse data source (HTTP, port 8123 or 8443) with a **read-only** user:
   `CREATE USER grafana IDENTIFIED BY '…'; GRANT SELECT ON obs.* TO grafana;`
   (the agent's `obs_agent` user only has INSERT).
3. Dashboards → Import → upload each JSON. Import asks for no data source.
4. Alert list: the Overview's first panel ("Firing obs-agent alerts") lists alerts from Grafana's
   unified alerting. It shows the obs-agent rules only when Grafana sees them: load
   `deploy/prometheus/obs-agent-alerts.yaml` into the Prometheus that Grafana uses as a data source
   (data-source-managed rules), or add an Alertmanager data source. Its instance filter is
   `{instance=~"${instance:regex}"}`, so it follows the instance variable.
5. If your agents use a `clickhouse.flush_interval` other than 60 s or a `mysql.slow_query_threshold_ms`
   other than 100, set the hidden constants `flush_s` / `slow_ms` (Analysis → Dashboard settings →
   Variables) and save.

### Re-importing after an upgrade

The dashboards keep their UIDs (`obs-agent-overview`, `obs-agent-analysis`): Import → upload → choose
**Overwrite**. Edits made in Grafana are lost, including the `flush_s` / `slow_ms` values — set them again.
The Analysis dashboard needs the current ClickHouse schema (`host_stats`, disk and wait columns):
upgrade the agents, then run `obs-agent clickhouse-schema -alter | clickhouse-client --multiquery`.

## Rows

| Dashboard | Row | What it answers |
|---|---|---|
| Overview | Firing obs-agent alerts | which obs-agent alerts fire or are pending for the selected instances |
| Overview | What is overloading this server? | the top CPU digest (% of node CPU used), the top disk-read digest (% of node disk reads), query CPU coverage |
| Overview | MySQL — who uses the server | % of node CPU / disk reads by top digests (alert thresholds dashed), query CPU vs mysqld CPU, Top digests (last 5m) merged table |
| Overview | MySQL — who is waiting | where query time goes (CPU, waiting for CPU, disk, commit, other), commit wait share, query disk writes, queries/s |
| Overview | Node | CPU, load and blocked tasks, memory, context switches |
| Overview | Disk & network | utilisation, average wait, throughput, physical-disk throughput, PSI io full / some, network |
| Overview | Process families | top families by CPU / RSS, TCP bytes, inbound clients, outbound peers |
| Overview | Agent health | coverage, dropped / overflow / mismatches, accounting availability, ClickHouse sink |
| Analysis | MySQL digests | Top digests with shares, roles and waits; % of node CPU / disk reads per bucket; node CPU used and disk reads; CPU regression |
| Analysis | Digest drill-down | calls and latency, where the digest's time goes, per host (set the `digest` variable) |

## Choosing the data source

Each dashboard has a data source picker as its first variable: **Prometheus** (`ds_prometheus`) on the
Overview, **ClickHouse** (`ds_clickhouse`) on the Analysis dashboard. It lists every data source of
that type and starts on the default one; switch it at any time (e.g. staging vs prod) and every panel
and the host/family lists follow. To pin one in a link, add `var-ds_prometheus=<data source name or uid>`
(or `var-ds_clickhouse=…`) to the URL.

## Linking

The Overview's "MySQL & Network Analysis" link carries `var-host`, `var-family` and the time
range ("All" arrives as `$__all`, which the Analysis variables accept). It does not carry a ClickHouse data source:
the Analysis dashboard opens on its default ClickHouse data source. Prometheus `instance` (`host:9200`) differs from the ClickHouse `host` column (hostname);
the link uses `obs_agent_clickhouse_host_info{host}` to translate, so it only works for agents with
`clickhouse.enabled: true`.

## Reading the ClickHouse panels

- Rows are one per agent `clickhouse.flush_interval`; time series bucket by at least that much and show
  rates (cores, calls/s, bytes/s), so they do not change with zoom. If your agents use a flush interval
  other than 60 s, set the hidden constant `flush_s` (Dashboard settings → Variables) to it.
- "Top digests": `cpuCores` is averaged over the whole range and hides short bursts; sort by
  `peakCores` to find them. `pctNodeCpu` / `pctDiskRead` divide by the node totals in `host_stats`
  of the same hosts and range (NULL = not measured; no `host_stats` rows = no share). `victimOf` uses
  the hidden constant `slow_ms`, which must equal the agents' `mysql.slow_query_threshold_ms` (default 100).
- The role columns (`cpuRole`, `ioRole`, `victimOf`) pool all selected hosts over the whole dashboard
  range and use the default thresholds (20 % of node CPU with the node ≥ 50 % used; 20 % of disk reads
  with ≥ 5 MiB/s; waits ≥ 50 % of wall) — they are indicative. The per-node verdict is
  `mysql_report.overload_cause` in `/api/diagnose`.
- Disk columns of rows written before the schema migration read 0, so disk shares are meaningful only
  for ranges after it; wait columns of those rows are NULL.
- Every panel's description (the (i) icon) states its formula and how to read it; panels behind an
  alert draw the alert's threshold as a dashed red line and name the alert and its severity.
- `window_end` is stamped with the agent host's clock. If ClickHouse panels look shifted against the
  Prometheus ones, check NTP on that host (`timedatectl`, `chronyc tracking`).

## Reading a snapshot

The Snapshots table lists them; fetch one report with:

```sql
SELECT report FROM obs.diagnose_snapshots WHERE host = 'db-01' AND ts = '2026-10-08 03:12:30' FORMAT TSVRaw
```
Pipe it to `jq` — it is exactly what `/api/diagnose` returned at that moment.
