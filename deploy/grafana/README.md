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
3. Dashboards → Import → upload each JSON. Import asks for no data source.

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

## Reading a snapshot

The Snapshots table lists them; fetch one report with:

```sql
SELECT report FROM obs.diagnose_snapshots WHERE host = 'db-01' AND ts = '2026-10-08 03:12:30' FORMAT TSVRaw
```
Pipe it to `jq` — it is exactly what `/api/diagnose` returned at that moment.
