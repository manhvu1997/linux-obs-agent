# obs-agent Grafana dashboards

| File | Data source | Purpose |
|---|---|---|
| `obs-agent-overview.json` | Prometheus | Live node, families, MySQL by command, top digests, ClickHouse sink health |
| `obs-agent-analysis.json` | ClickHouse | Every digest, slow queries, families, inbound/outbound peers, diagnose snapshots |

Both are generated: edit `deploy/grafana/gen/main.go`, then run `go run ./deploy/grafana/gen`.

## Setup

1. Install the ClickHouse plugin (4.x): `grafana-cli plugins install grafana-clickhouse-datasource`, restart Grafana.
2. Add a ClickHouse data source (HTTP, port 8123 or 8443) with a **read-only** user:
   `CREATE USER grafana IDENTIFIED BY '…'; GRANT SELECT ON obs.* TO grafana;`
   (the agent's `obs_agent` user only has INSERT).
3. Dashboards → Import → upload each JSON → pick the Prometheus / ClickHouse data source when asked.

## Linking

The Overview's "MySQL & Network Analysis" link carries `var-host`, `var-family` and the time
range ("All" arrives as `$__all`, which the Analysis variables accept). Prometheus `instance` (`host:9200`) differs from the ClickHouse `host` column (hostname);
the link uses `obs_agent_clickhouse_host_info{host}` to translate, so it only works for agents with
`clickhouse.enabled: true`.

## Reading a snapshot

The Snapshots table lists them; fetch one report with:

```sql
SELECT report FROM obs.diagnose_snapshots WHERE host = 'db-01' AND ts = '2026-10-08 03:12:30' FORMAT TSVRaw
```
Pipe it to `jq` — it is exactly what `/api/diagnose` returned at that moment.
