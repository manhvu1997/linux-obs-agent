// Command gen writes the Grafana dashboards in deploy/grafana from the panel
// definitions below. Run from the repo root: go run ./deploy/grafana/gen
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type DS struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

var (
	promDS = DS{"prometheus", "${DS_PROMETHEUS}"}
	chDS   = DS{"grafana-clickhouse-datasource", "${DS_CLICKHOUSE}"}
)

type Target struct {
	RefID        string `json:"refId"`
	Datasource   DS     `json:"datasource"`
	Expr         string `json:"expr,omitempty"`
	LegendFormat string `json:"legendFormat,omitempty"`
	Instant      bool   `json:"instant,omitempty"`
	Format       any    `json:"format,omitempty"`
	RawSQL       string `json:"rawSql,omitempty"`
	EditorType   string `json:"editorType,omitempty"`
	QueryType    string `json:"queryType,omitempty"`
}

type GridPos struct {
	H int `json:"h"`
	W int `json:"w"`
	X int `json:"x"`
	Y int `json:"y"`
}

type Link struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	TargetBlank bool   `json:"targetBlank,omitempty"`
}

type Panel struct {
	ID          int            `json:"id"`
	Type        string         `json:"type"`
	Title       string         `json:"title"`
	GridPos     GridPos        `json:"gridPos"`
	Datasource  DS             `json:"datasource"`
	Targets     []Target       `json:"targets,omitempty"`
	FieldConfig map[string]any `json:"fieldConfig"`
	Options     map[string]any `json:"options,omitempty"`
	Collapsed   bool           `json:"collapsed,omitempty"`
	Description string         `json:"description,omitempty"`
}

type Var struct {
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Type       string `json:"type"`
	Datasource *DS    `json:"datasource,omitempty"`
	Query      any    `json:"query,omitempty"`
	Definition string `json:"definition,omitempty"`
	Multi      bool   `json:"multi,omitempty"`
	IncludeAll bool   `json:"includeAll,omitempty"`
	Refresh    int    `json:"refresh,omitempty"`
	Hide       int    `json:"hide,omitempty"`
	Current    any    `json:"current,omitempty"`
}

type Input struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	PluginID string `json:"pluginId"`
}

type Dashboard struct {
	Inputs        []Input           `json:"__inputs"`
	UID           string            `json:"uid"`
	Title         string            `json:"title"`
	Tags          []string          `json:"tags"`
	SchemaVersion int               `json:"schemaVersion"`
	Time          map[string]string `json:"time"`
	Refresh       string            `json:"refresh"`
	Templating    struct {
		List []Var `json:"list"`
	} `json:"templating"`
	Links  []map[string]any `json:"links"`
	Panels []Panel          `json:"panels"`
}

// layout assigns ids and grid positions: rows full width, panels in a
// 2-column grid of height 8 (tables 12 wide, unless w is set via width).
type builder struct {
	panels []Panel
	y, x   int
}

func (b *builder) row(title string) {
	if b.x != 0 {
		b.y += 8
		b.x = 0
	}
	b.panels = append(b.panels, Panel{Type: "row", Title: title, GridPos: GridPos{H: 1, W: 24, Y: b.y},
		Datasource: DS{}, FieldConfig: map[string]any{"defaults": map[string]any{}, "overrides": []any{}}})
	b.y++
}

func (b *builder) add(p Panel, w int) {
	if b.x+w > 24 {
		b.y += 8
		b.x = 0
	}
	p.GridPos = GridPos{H: 8, W: w, X: b.x, Y: b.y}
	if p.FieldConfig == nil {
		p.FieldConfig = map[string]any{"defaults": map[string]any{}, "overrides": []any{}}
	}
	b.panels = append(b.panels, p)
	b.x += w
}

func (b *builder) done() []Panel {
	for i := range b.panels {
		b.panels[i].ID = i + 1
	}
	return b.panels
}

func unit(u string) map[string]any {
	return map[string]any{"defaults": map[string]any{"unit": u}, "overrides": []any{}}
}

func prom(title, u string, exprs ...[2]string) Panel {
	p := Panel{Type: "timeseries", Title: title, Datasource: promDS, FieldConfig: unit(u)}
	for i, e := range exprs {
		p.Targets = append(p.Targets, Target{RefID: string(rune('A' + i)), Datasource: promDS, Expr: e[0], LegendFormat: e[1]})
	}
	return p
}

func promTable(title, expr string) Panel {
	return Panel{Type: "table", Title: title, Datasource: promDS, FieldConfig: unit("none"),
		Targets: []Target{{RefID: "A", Datasource: promDS, Expr: expr, Instant: true, Format: "table"}}}
}

func chTS(title, u, sql string) Panel {
	return Panel{Type: "timeseries", Title: title, Datasource: chDS, FieldConfig: unit(u),
		Targets: []Target{{RefID: "A", Datasource: chDS, RawSQL: sql, EditorType: "sql", QueryType: "timeseries", Format: 0}}}
}

func chTable(title, sql string) Panel {
	return Panel{Type: "table", Title: title, Datasource: chDS, FieldConfig: unit("none"),
		Targets: []Target{{RefID: "A", Datasource: chDS, RawSQL: sql, EditorType: "sql", QueryType: "table", Format: 1}}}
}

const (
	inst  = `instance=~"$instance"`
	hostF = `host IN (${host:singlequote})`
)

func overview() Dashboard {
	var d Dashboard
	d.Inputs = []Input{{Name: "DS_PROMETHEUS", Label: "Prometheus", Type: "datasource", PluginID: "prometheus"}}
	d.UID, d.Title, d.Tags = "obs-agent-overview", "obs-agent Overview", []string{"obs-agent"}
	d.SchemaVersion, d.Time, d.Refresh = 39, map[string]string{"from": "now-6h", "to": "now"}, "1m"
	d.Templating.List = []Var{
		{Name: "instance", Type: "query", Datasource: &promDS, Query: "label_values(obs_agent_cpu_usage_percent, instance)",
			Definition: "label_values(obs_agent_cpu_usage_percent, instance)", Multi: true, IncludeAll: true, Refresh: 2},
		{Name: "family", Type: "query", Datasource: &promDS, Query: `label_values(obs_agent_family_cpu_percent{` + inst + `}, family)`,
			Definition: `label_values(obs_agent_family_cpu_percent{` + inst + `}, family)`, Multi: true, IncludeAll: true, Refresh: 2},
		{Name: "chhost", Label: "ClickHouse host", Type: "query", Datasource: &promDS,
			Query: `label_values(obs_agent_clickhouse_host_info{` + inst + `}, host)`, Definition: `label_values(obs_agent_clickhouse_host_info{` + inst + `}, host)`,
			Multi: true, IncludeAll: true, Refresh: 2, Hide: 2},
	}
	d.Links = []map[string]any{{"title": "MySQL & Network Analysis (ClickHouse)", "type": "link", "targetBlank": true,
		"url": "/d/obs-agent-analysis/obs-agent-analysis?${chhost:queryparam}&${family:queryparam}&$__url_time_range"}}

	b := &builder{}
	b.row("Node")
	b.add(prom("CPU", "percent",
		[2]string{`obs_agent_cpu_usage_percent{` + inst + `}`, "{{instance}} usage"},
		[2]string{`obs_agent_cpu_iowait_percent{` + inst + `}`, "{{instance}} iowait"},
		[2]string{`obs_agent_cpu_steal_percent{` + inst + `}`, "{{instance}} steal"}), 12)
	b.add(prom("Load (1m) and blocked tasks", "short",
		[2]string{`obs_agent_load1{` + inst + `}`, "{{instance}} load1"},
		[2]string{`obs_agent_procs_blocked{` + inst + `}`, "{{instance}} D-state"}), 12)
	b.add(prom("Memory available", "percent",
		[2]string{`100 * obs_agent_mem_available_bytes{` + inst + `} / obs_agent_mem_total_bytes{` + inst + `}`, "{{instance}}"}), 12)
	b.add(prom("Context switches", "ops",
		[2]string{`obs_agent_cpu_ctx_switches_per_sec{` + inst + `}`, "{{instance}}"}), 12)

	b.row("Disk & network")
	b.add(prom("Disk utilisation", "percent", [2]string{`obs_agent_disk_io_util_percent{` + inst + `}`, "{{instance}} {{device}}"}), 12)
	b.add(prom("Disk average wait", "ms", [2]string{`obs_agent_disk_avg_wait_ms{` + inst + `}`, "{{instance}} {{device}}"}), 12)
	b.add(prom("Disk throughput", "Bps",
		[2]string{`obs_agent_disk_read_bytes_per_sec{` + inst + `}`, "{{instance}} {{device}} read"},
		[2]string{`obs_agent_disk_write_bytes_per_sec{` + inst + `}`, "{{instance}} {{device}} write"}), 12)
	b.add(prom("Network throughput", "Bps",
		[2]string{`obs_agent_net_rx_bytes_per_sec{` + inst + `}`, "{{instance}} {{interface}} rx"},
		[2]string{`obs_agent_net_tx_bytes_per_sec{` + inst + `}`, "{{instance}} {{interface}} tx"}), 12)

	b.row("Process families")
	fam := inst + `,family=~"$family"`
	b.add(prom("Top families by CPU", "percent", [2]string{`topk(10, obs_agent_family_cpu_percent{` + fam + `})`, "{{instance}} {{family}}"}), 12)
	b.add(prom("Top families by RSS", "bytes", [2]string{`topk(10, obs_agent_family_mem_rss_bytes{` + fam + `})`, "{{instance}} {{family}}"}), 12)
	b.add(prom("Family TCP bytes by direction", "Bps",
		[2]string{`sum by (instance, family, direction) (rate(obs_agent_family_net_bytes_total{` + fam + `}[$__rate_interval]))`, "{{instance}} {{family}} {{direction}}"}), 12)
	b.add(prom("Top inbound clients", "Bps",
		[2]string{`topk(10, sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_inbound_peer_bytes_total{` + fam + `}[$__rate_interval])))`, "{{family}} ← {{peer_ip}}:{{service_port}}"}), 12)
	b.add(prom("Top outbound peers", "Bps",
		[2]string{`topk(10, sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total{` + fam + `}[$__rate_interval])))`, "{{family}} → {{peer_ip}}:{{service_port}}"}), 12)

	b.row("MySQL")
	b.add(prom("Queries per second by command", "ops",
		[2]string{`sum by (instance, command) (rate(obs_agent_mysql_queries_total{` + inst + `}[$__rate_interval]))`, "{{instance}} {{command}}"}), 12)
	b.add(prom("Query CPU and run-queue wait (cores)", "short",
		[2]string{`sum by (instance) (rate(obs_agent_mysql_query_cpu_seconds_total{` + inst + `}[$__rate_interval]))`, "{{instance}} on-CPU"},
		[2]string{`sum by (instance) (rate(obs_agent_mysql_query_runq_wait_seconds_total{` + inst + `}[$__rate_interval]))`, "{{instance}} waiting for CPU"}), 12)
	b.add(promTable("Top digests by CPU (cores, last 5m)",
		`topk(10, rate(obs_agent_mysql_digest_cpu_seconds_total{`+inst+`}[5m]) * on (instance, digest_id) group_left (digest_text) obs_agent_mysql_digest_info{`+inst+`})`), 12)
	b.add(prom("Digest coverage and dropped events", "short",
		[2]string{`obs_agent_mysql_digest_coverage_ratio{` + inst + `}`, "{{instance}} coverage"},
		[2]string{`rate(obs_agent_mysql_events_dropped_total{` + inst + `}[$__rate_interval])`, "{{instance}} dropped/s"}), 12)

	b.row("Agent")
	b.add(prom("ClickHouse rows sent / dropped", "short",
		[2]string{`sum by (instance, table) (rate(obs_agent_clickhouse_rows_sent_total{` + inst + `}[$__rate_interval]))`, "{{instance}} sent {{table}}"},
		[2]string{`sum by (instance, table, reason) (rate(obs_agent_clickhouse_rows_dropped_total{` + inst + `}[$__rate_interval]))`, "{{instance}} dropped {{table}} {{reason}}"}), 12)
	b.add(prom("ClickHouse buffer and staleness", "short",
		[2]string{`obs_agent_clickhouse_buffer_bytes{` + inst + `}`, "{{instance}} buffer bytes"},
		[2]string{`time() - obs_agent_clickhouse_last_success_timestamp_seconds{` + inst + `}`, "{{instance}} seconds since last insert"}), 12)
	b.add(prom("Diagnose snapshots", "short",
		[2]string{`sum by (instance, reason_kind) (increase(obs_agent_clickhouse_snapshots_total{` + inst + `}[$__range]))`, "{{instance}} {{reason_kind}}"}), 12)
	b.add(prom("eBPF events by module", "ops",
		[2]string{`sum by (instance, module) (rate(obs_agent_ebpf_events_total{` + inst + `}[$__rate_interval]))`, "{{instance}} {{module}}"}), 12)
	d.Panels = b.done()
	return d
}

func analysis() Dashboard {
	var d Dashboard
	d.Inputs = []Input{{Name: "DS_CLICKHOUSE", Label: "ClickHouse", Type: "datasource", PluginID: "grafana-clickhouse-datasource"}}
	d.UID, d.Title, d.Tags = "obs-agent-analysis", "obs-agent MySQL & Network Analysis", []string{"obs-agent", "clickhouse"}
	d.SchemaVersion, d.Time, d.Refresh = 39, map[string]string{"from": "now-6h", "to": "now"}, ""
	d.Templating.List = []Var{
		{Name: "host", Type: "query", Datasource: &chDS, Multi: true, IncludeAll: true, Refresh: 2,
			Query: "SELECT DISTINCT host FROM obs.family_stats WHERE $__timeFilter(window_end) ORDER BY host"},
		{Name: "family", Type: "query", Datasource: &chDS, Multi: true, IncludeAll: true, Refresh: 2,
			Query: "SELECT DISTINCT family FROM obs.family_stats WHERE $__timeFilter(window_end) AND " + hostF + " ORDER BY family"},
		{Name: "digest", Label: "Digest id (drill-down)", Type: "textbox", Query: "", Current: map[string]any{"value": ""}},
	}
	d.Links = []map[string]any{{"title": "obs-agent Overview (Prometheus)", "type": "link", "targetBlank": true,
		"url": "/d/obs-agent-overview/obs-agent-overview?$__url_time_range"}}

	b := &builder{}
	b.row("MySQL digests")
	b.add(chTable("Top digests by CPU", `SELECT s.digest_id AS digest, any(t.digest_text) AS text, sum(s.calls) AS calls,
  sum(s.cpu_ns) / 1e9 AS cpuSec,
  sum(s.cpu_ns) / greatest(sum(s.calls), 1) / 1e6 AS cpuMsAvg,
  sum(s.runq_ns) / greatest(sum(s.calls), 1) / 1e6 AS runqMsAvg,
  sum(s.wall_ns) / greatest(sum(s.calls), 1) / 1e6 AS wallMsAvg,
  sum(s.bytes_out) AS bytesOut
FROM obs.mysql_digest_stats AS s
LEFT JOIN (SELECT digest_id, digest_text FROM obs.mysql_digest_text FINAL) AS t ON t.digest_id = s.digest_id
WHERE $__timeFilter(s.window_end) AND s.`+hostF+`
GROUP BY s.digest_id ORDER BY cpuSec DESC LIMIT 50`), 24)
	b.add(chTS("CPU of the top 10 digests (cores)", "short", `SELECT $__timeInterval(window_end) AS time, digest_id AS digest,
  sum(cpu_ns) / 1e9 / $__interval_s AS cores
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+`
  AND digest_id IN (SELECT digest_id FROM obs.mysql_digest_stats WHERE $__timeFilter(window_end) AND `+hostF+`
                    GROUP BY digest_id ORDER BY sum(cpu_ns) DESC LIMIT 10)
GROUP BY time, digest ORDER BY time`), 12)
	b.add(chTable("CPU regression vs 7 days earlier", `SELECT digest_id AS digest,
  sumIf(cpu_ns, $__timeFilter(window_end)) / 1e9 AS cpuSecNow,
  sumIf(cpu_ns, window_end >= $__fromTime - INTERVAL 7 DAY AND window_end < $__toTime - INTERVAL 7 DAY) / 1e9 AS cpuSecWeekAgo,
  cpuSecNow / greatest(cpuSecWeekAgo, 0.001) AS ratio
FROM obs.mysql_digest_stats
WHERE (window_end >= $__fromTime - INTERVAL 7 DAY) AND `+hostF+`
  AND ($__timeFilter(window_end) OR window_end < $__toTime - INTERVAL 7 DAY)
GROUP BY digest_id HAVING cpuSecNow > 1 ORDER BY ratio DESC LIMIT 30`), 12)

	b.row("Digest drill-down (set the digest variable)")
	digF := "digest_id = '${digest}'"
	b.add(chTS("Calls and average latency", "short", `SELECT $__timeInterval(window_end) AS time, sum(calls) AS calls,
  sum(cpu_ns) / greatest(sum(calls), 1) / 1e6 AS cpuMsAvg,
  sum(wall_ns) / greatest(sum(calls), 1) / 1e6 AS wallMsAvg,
  sum(runq_ns) / greatest(sum(calls), 1) / 1e6 AS runqMsAvg
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+digF+`
GROUP BY time ORDER BY time`), 12)
	b.add(chTable("Per host", `SELECT host, sum(calls) AS calls, sum(cpu_ns) / 1e9 AS cpuSec,
  sum(wall_ns) / greatest(sum(calls), 1) / 1e6 AS wallMsAvg
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+digF+`
GROUP BY host ORDER BY cpuSec DESC`), 12)

	b.row("Slow queries")
	b.add(chTable("Latest slow queries (digest filter optional)", `SELECT ts, host, pid, latency_ms AS latencyMs, digest_id AS digest, query
FROM obs.mysql_slow_queries
WHERE $__timeFilter(ts) AND `+hostF+` AND ('${digest}' = '' OR `+digF+`)
ORDER BY ts DESC LIMIT 200`), 24)
	b.add(chTS("Slow queries per interval", "short", `SELECT $__timeInterval(ts) AS time, host, count() AS slow
FROM obs.mysql_slow_queries
WHERE $__timeFilter(ts) AND `+hostF+`
GROUP BY time, host ORDER BY time`), 12)

	b.row("Process families")
	famF := "family IN (${family:singlequote})"
	b.add(chTS("Family CPU (avg)", "percent", `SELECT $__timeInterval(window_end) AS time, family, avg(cpu_percent_avg) AS cpu
FROM obs.family_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY time, family ORDER BY time`), 12)
	b.add(chTS("Family RSS (max)", "bytes", `SELECT $__timeInterval(window_end) AS time, family, max(rss_bytes_max) AS rss
FROM obs.family_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY time, family ORDER BY time`), 12)
	b.add(chTable("Top families", `SELECT host, family, avg(cpu_percent_avg) AS cpuAvg, max(cpu_percent_max) AS cpuMax,
  max(rss_bytes_max) AS rssMax, max(processes_max) AS processes
FROM obs.family_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY host, family ORDER BY cpuAvg DESC LIMIT 50`), 12)

	b.row("Network")
	peer := "replaceRegexpOne(toString(peer_ip), '^::ffff:', '')"
	b.add(chTable("Top inbound clients", `SELECT `+peer+` AS peer, service_port AS port, family,
  sum(bytes_rx + bytes_tx) AS bytes, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+` AND direction = 'inbound'
GROUP BY peer, port, family ORDER BY bytes DESC LIMIT 50`), 12)
	b.add(chTable("Top outbound peers", `SELECT `+peer+` AS peer, service_port AS port, family,
  sum(bytes_rx + bytes_tx) AS bytes, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+` AND direction = 'outbound'
GROUP BY peer, port, family ORDER BY bytes DESC LIMIT 50`), 12)
	b.add(chTS("TCP bytes by direction", "bytes", `SELECT $__timeInterval(window_end) AS time, direction,
  sum(bytes_rx + bytes_tx) AS bytes
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY time, direction ORDER BY time`), 12)
	b.add(chTable("Who talks to MySQL (inbound :3306)", `SELECT host, `+peer+` AS client, sum(bytes_rx) AS bytesIn,
  sum(bytes_tx) AS bytesOut, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND direction = 'inbound' AND service_port = 3306
GROUP BY host, client ORDER BY bytesOut DESC LIMIT 50`), 12)

	b.row("Diagnose snapshots")
	b.add(chTable("Snapshots (fetch one with the query in deploy/grafana/README.md)", `SELECT ts, host, reason, verdict, length(report) AS reportBytes
FROM obs.diagnose_snapshots
WHERE $__timeFilter(ts) AND `+hostF+`
ORDER BY ts DESC LIMIT 100`), 24)
	d.Panels = b.done()
	return d
}

func dashboards() map[string]Dashboard {
	return map[string]Dashboard{
		"obs-agent-overview.json": overview(),
		"obs-agent-analysis.json": analysis(),
	}
}

func render(d Dashboard) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	for name, d := range dashboards() {
		b, err := render(d)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		path := filepath.Join("deploy", "grafana", name)
		if err := os.WriteFile(path, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", path)
	}
}
