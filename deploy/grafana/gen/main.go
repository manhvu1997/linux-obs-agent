// Command gen writes the Grafana dashboards in deploy/grafana from the panel
// definitions below. Run from the repo root: go run ./deploy/grafana/gen
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/manhvu1997/linux-obs-agent/internal/chsink"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

type DS struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

// Every panel and query variable points at the dashboard's datasource
// template variable, so the viewer picks the datasource at view time.
var (
	promDS = DS{"prometheus", "${ds_prometheus}"}
	chDS   = DS{"grafana-clickhouse-datasource", "${ds_clickhouse}"}
)

// dsVar is the datasource picker; it must come first in the variable list
// because the query variables after it use it.
func dsVar(name, label, pluginID string) Var {
	return Var{Name: name, Label: label, Type: "datasource", Query: pluginID, Refresh: 1}
}

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

	Transformations []map[string]any `json:"transformations,omitempty"`
}

type Var struct {
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Type       string `json:"type"`
	Datasource *DS    `json:"datasource,omitempty"`
	Query      any    `json:"query,omitempty"`
	Definition string `json:"definition,omitempty"`
	Regex      string `json:"regex,omitempty"`
	Multi      bool   `json:"multi,omitempty"`
	IncludeAll bool   `json:"includeAll,omitempty"`
	Refresh    int    `json:"refresh,omitempty"`
	Hide       int    `json:"hide,omitempty"`
	Current    any    `json:"current,omitempty"`
}

type Dashboard struct {
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

// layout assigns ids and grid positions: rows full width, panels left to
// right (height 8 unless added with addH), wrapping when a line is full.
type builder struct {
	panels []Panel
	y, x   int
	lineH  int // height of the tallest panel on the current line
}

func (b *builder) newLine() {
	if b.x != 0 {
		b.y += b.lineH
		b.x, b.lineH = 0, 0
	}
}

func (b *builder) row(title string) {
	b.newLine()
	b.panels = append(b.panels, Panel{Type: "row", Title: title, GridPos: GridPos{H: 1, W: 24, Y: b.y},
		Datasource: DS{}, FieldConfig: map[string]any{"defaults": map[string]any{}, "overrides": []any{}}})
	b.y++
}

func (b *builder) add(p Panel, w int) { b.addH(p, w, 8) }

func (b *builder) addH(p Panel, w, h int) {
	if b.x+w > 24 {
		b.newLine()
	}
	p.GridPos = GridPos{H: h, W: w, X: b.x, Y: b.y}
	if p.FieldConfig == nil {
		p.FieldConfig = map[string]any{"defaults": map[string]any{}, "overrides": []any{}}
	}
	b.panels = append(b.panels, p)
	b.x += w
	b.lineH = max(b.lineH, h)
}

func (b *builder) done() []Panel {
	for i := range b.panels {
		b.panels[i].ID = i + 1
	}
	return b.panels
}

// descr is every panel's description: what it computes and how to read it.
func descr(formula, reading string) string { return "Formula: " + formula + "\nReading: " + reading }

// alertRule mirrors one rule of deploy/prometheus/obs-agent-alerts.yaml
// (TestAlertPanelsMatchRules keeps them in step).
type alertRule struct {
	Name, Severity, Literal string  // Literal: the threshold text in the rule expression
	Threshold               float64 // in the panel's unit
	Panel                   bool    // drawn on an Overview panel
	Below                   bool    // fires below the line (red below, green above)
}

var alertRules = []alertRule{
	{"MySQLQueriesStarvedForCPU", "critical", "> 0.3", 30, true, false},
	{"MySQLQueriesStalledOnDisk", "critical", "> 0.3", 30, true, false},
	{"MySQLDigestCPUHog", "warning", "> 0.2", 20, true, false},
	{"MySQLDigestDiskReadHog", "warning", "> 0.2", 20, true, false},
	{"MySQLCommitsStalledOnRedo", "warning", "> 0.2", 20, true, false},
	{"MySQLQueriesSpillingToDisk", "info", "> 10 * 1048576", 10 * 1048576, true, false},
	{"ObsAgentMySQLIOWaitUnavailable", "info", "== 0", 0.5, true, true},
	{"ObsAgentMySQLAccountingDegraded", "info", "increase(obs_agent_mysql_hash_mismatch_total[10m]) > 0", 0, false, false},
}

func rule(name string) alertRule {
	for _, r := range alertRules {
		if r.Name == name {
			return r
		}
	}
	panic("unknown alert " + name)
}

// withAlert draws r's threshold as a dashed red line and names the alert.
func withAlert(p Panel, r alertRule) Panel {
	p = dashedLine(p, r.Threshold, r.Below)
	p.Description += fmt.Sprintf("\nAlert: %s (%s) fires at %v.", r.Name, r.Severity, r.Threshold)
	return p
}

// dashedLine draws v as a dashed threshold line: green below and red above,
// or the reverse when invert is set (a value that is bad when low).
func dashedLine(p Panel, v float64, invert bool) Panel {
	low, high := "green", "red"
	if invert {
		low, high = "red", "green"
	}
	if p.FieldConfig == nil {
		p.FieldConfig = map[string]any{"defaults": map[string]any{}, "overrides": []any{}}
	}
	d, _ := p.FieldConfig["defaults"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		p.FieldConfig["defaults"] = d
	}
	d["thresholds"] = map[string]any{"mode": "absolute", "steps": []any{
		map[string]any{"color": low, "value": nil}, map[string]any{"color": high, "value": v}}}
	custom, _ := d["custom"].(map[string]any)
	if custom == nil {
		custom = map[string]any{}
		d["custom"] = custom
	}
	custom["thresholdsStyle"] = map[string]any{"mode": "dashed"}
	return p
}

func unit(u string) map[string]any {
	return map[string]any{"defaults": map[string]any{"unit": u}, "overrides": []any{}}
}

// withColumnUnits adds a per-column unit override for each field name.
func withColumnUnits(fc map[string]any, units map[string]string) map[string]any {
	names := make([]string, 0, len(units))
	for n := range units {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic JSON
	ov := []any{}
	for _, n := range names {
		ov = append(ov, map[string]any{
			"matcher":    map[string]any{"id": "byName", "options": n},
			"properties": []any{map[string]any{"id": "unit", "value": units[n]}},
		})
	}
	fc["overrides"] = ov
	return fc
}

func prom(title, u string, exprs ...[2]string) Panel {
	p := Panel{Type: "timeseries", Title: title, Datasource: promDS, FieldConfig: unit(u)}
	for i, e := range exprs {
		p.Targets = append(p.Targets, Target{RefID: string(rune('A' + i)), Datasource: promDS, Expr: e[0], LegendFormat: e[1]})
	}
	return p
}

// promTable runs each expression as an instant table query (refIds A, B, …).
func promTable(title string, exprs ...string) Panel {
	p := Panel{Type: "table", Title: title, Datasource: promDS, FieldConfig: unit("none")}
	for i, e := range exprs {
		p.Targets = append(p.Targets, Target{RefID: string(rune('A' + i)), Datasource: promDS, Expr: e, Instant: true, Format: "table"})
	}
	return p
}

// promStat shows the current value of each series of one instant query: a
// range query would also show series that were on top earlier but not now.
func promStat(title, u, expr, legend string) Panel {
	p := prom(title, u, [2]string{expr, legend})
	p.Type = "stat"
	p.Targets[0].Instant = true
	p.Options = map[string]any{"reduceOptions": map[string]any{"calcs": []any{"lastNotNull"}},
		"textMode": "value_and_name", "colorMode": "background"}
	return p
}

func textPanel(title, markdown string) Panel {
	return Panel{Type: "text", Title: title, Datasource: promDS, Options: map[string]any{"mode": "markdown", "content": markdown}}
}

// described sets p's description (see descr).
func described(p Panel, formula, reading string) Panel {
	p.Description = descr(formula, reading)
	return p
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

	// Interval tables hold one row per clickhouse.flush_interval. A bucket
	// narrower than that holds a whole row or nothing, so rates divided by
	// $__interval_s were overstated by flush_interval / $__interval. Buckets
	// are therefore never narrower than the flush_s variable.
	flushBucketS = "greatest($__interval_s, ${flush_s})"
	flushBucket  = "toDateTime(intDiv(toUInt32(window_end), " + flushBucketS + ") * " + flushBucketS + ", 'UTC')"

	// alertWin is the rate window of the MySQL alert rules; panels that draw
	// an alert's threshold use it so the line and the rule agree.
	alertWin = "5m"
)

func overview() Dashboard {
	var d Dashboard
	d.UID, d.Title, d.Tags = "obs-agent-overview", "obs-agent Overview", []string{"obs-agent"}
	d.SchemaVersion, d.Time, d.Refresh = 39, map[string]string{"from": "now-6h", "to": "now"}, "1m"
	d.Templating.List = []Var{
		dsVar("ds_prometheus", "Prometheus", "prometheus"),
		{Name: "instance", Type: "query", Datasource: &promDS, Query: "label_values(obs_agent_cpu_usage_percent, instance)",
			Definition: "label_values(obs_agent_cpu_usage_percent, instance)", Multi: true, IncludeAll: true, Refresh: 2},
		{Name: "family", Type: "query", Datasource: &promDS, Query: `label_values(obs_agent_family_cpu_percent{` + inst + `}, family)`,
			Definition: `label_values(obs_agent_family_cpu_percent{` + inst + `}, family)`, Multi: true, IncludeAll: true, Refresh: 2},
		{Name: "host", Label: "ClickHouse host", Type: "query", Datasource: &promDS,
			Query: `label_values(obs_agent_clickhouse_host_info{` + inst + `}, host)`, Definition: `label_values(obs_agent_clickhouse_host_info{` + inst + `}, host)`,
			Multi: true, IncludeAll: true, Refresh: 2, Hide: 2},
		{Name: "mysql_family", Label: "mysqld family", Type: "query", Datasource: &promDS,
			Query: `label_values(obs_agent_family_cpu_percent{` + inst + `}, family)`, Definition: `label_values(obs_agent_family_cpu_percent{` + inst + `}, family)`,
			Regex: `/^(?!.*exporter).*(mysql|mariadb).*$/i`, Multi: true, IncludeAll: true, Refresh: 2},
	}
	d.Links = []map[string]any{{"title": "MySQL & Network Analysis (ClickHouse)", "type": "link", "targetBlank": true,
		"url": "/d/obs-agent-analysis/obs-agent-analysis?${host:queryparam}&${family:queryparam}&$__url_time_range"}}

	// Query building blocks. Panels that draw an alert threshold evaluate the
	// alert's own expression over the alert's window (alertWin), so a point
	// above the dashed line is a point where the rule's condition held.
	sumq := func(m string) string {
		return `sum by (instance) (rate(` + m + `{` + inst + `}[` + alertWin + `]))`
	}
	// Node CPU cores in use: the alert's denominator, never the instant gauge.
	nodeCores := func(win string) string {
		return `(avg_over_time(obs_agent_cpu_usage_percent{` + inst + `}[` + win + `]) / 100 * obs_agent_cpu_count{` + inst + `})`
	}
	perDigest := func(m, win string) string {
		return `sum by (instance, digest_id) (rate(` + m + `{` + inst + `,digest_id!="other"}[` + win + `]))`
	}
	// The node's disk read rate as a denominator: a node that read nothing
	// is filtered out (no point) instead of giving NaN or +Inf.
	nodeRead := func(win string) string {
		return `(rate(obs_agent_node_disk_read_bytes_total{` + inst + `}[` + win + `]) > 0)`
	}
	withText := ` * on (instance, digest_id) group_left (digest_text) obs_agent_mysql_digest_info{` + inst + `}`
	const (
		digCPU  = "obs_agent_mysql_digest_cpu_seconds_total"
		digRead = "obs_agent_mysql_digest_disk_read_bytes_total"
		qCPU    = "obs_agent_mysql_query_cpu_seconds_total"
		qRunq   = "obs_agent_mysql_query_runq_wait_seconds_total"
		qIO     = "obs_agent_mysql_query_io_wait_seconds_total"
		qRedo   = "obs_agent_mysql_query_redo_wait_seconds_total"
		qWall   = "obs_agent_mysql_query_wall_seconds_total"
	)

	b := &builder{}
	b.add(Panel{Type: "alertlist", Title: "Firing obs-agent alerts", Datasource: promDS,
		Options: map[string]any{"viewMode": "list", "groupMode": "default", "maxItems": 20, "sortOrder": 1,
			"stateFilter":              map[string]any{"firing": true, "pending": true},
			"alertInstanceLabelFilter": `{instance=~"${instance:regex}"}`}}, 24)

	b.row("What is overloading this server?")
	b.add(withAlert(described(promStat("Top CPU digest — % of node CPU used", "percent",
		`100 * topk by (instance) (1, `+perDigest(digCPU, alertWin)+` / on (instance) group_left () `+nodeCores(alertWin)+`)`+withText,
		"{{instance}} {{digest_text}}"),
		"the heaviest digest's on-CPU seconds per second ÷ node CPU cores in use (avg cpu_usage_percent / 100 × cpu_count) × 100, over 5m, per instance.",
		"share of all CPU work on the server done by the heaviest statement; red (above the line) means a CPU culprit — "+
			"the alert also needs node CPU ≥ 85%. Needs the digest in the exported set (prometheus_digests minimal or full)."),
		rule("MySQLDigestCPUHog")), 8)
	b.add(withAlert(described(promStat("Top disk-read digest — % of node disk reads", "percent",
		`100 * topk by (instance) (1, `+perDigest(digRead, alertWin)+` / on (instance) group_left () `+nodeRead(alertWin)+`)`+withText,
		"{{instance}} {{digest_text}}"),
		"the heaviest digest's disk-read bytes per second ÷ the node's physical-disk read bytes per second × 100, over 5m, per instance.",
		"share of the disk's reads caused by one statement; red means a disk culprit — the alert also needs node disk reads > 5 MiB/s. "+
			"No value when the disk read nothing (the denominator is filtered with > 0)."),
		rule("MySQLDigestDiskReadHog")), 8)
	coverage := promStat("Query CPU coverage", "percent", `100 * obs_agent_mysql_query_cpu_coverage_ratio{`+inst+`}`, "{{instance}}")
	// Neither high nor low is an alarm: a neutral colour, not Grafana's default red from 80.
	coverage.FieldConfig["defaults"].(map[string]any)["thresholds"] = map[string]any{"mode": "absolute",
		"steps": []any{map[string]any{"color": "blue", "value": nil}}}
	b.add(described(coverage,
		"CPU spent inside statements (dispatch_command) ÷ mysqld's CPU × 100.",
		"how much of mysqld's CPU the statements explain; low = CPU outside query execution (connections, InnoDB background threads, replication). "+
			"Absent when mysqld's CPU is not known."), 8)

	b.row("MySQL — who uses the server")
	b.addH(textPanel("How to read this row", "1. A digest above the dashed line in **% of node CPU used** is the CPU culprit; above it in **% of node disk reads** the disk culprit.\n"+
		"2. Check **Query CPU vs mysqld CPU**: if mysqld's CPU is far above query CPU, the load is outside statements.\n"+
		"3. **Top digests** shows cores, shares and pages per call: 1–4 pages = buffer-pool misses, hundreds = a scan.\n"+
		"4. Confirm in /api/diagnose → mysql_report.overload_cause, which also says whether the node is saturated at all."), 24, 4)
	b.add(withAlert(described(prom("% of node CPU used by top digests", "percent",
		[2]string{`100 * topk(10, ` + perDigest(digCPU, alertWin) + ` / on (instance) group_left () ` + nodeCores(alertWin) + `)`, "{{instance}} {{digest_id}}"}),
		"per digest: on-CPU seconds per second ÷ node CPU cores in use (avg cpu_usage_percent / 100 × cpu_count) × 100, over 5m (the alert's window); top 10.",
		"a line above the dashed 20% line is a statement doing a fifth of all CPU work on the server; the alert also needs node CPU ≥ 85%. "+
			"Digest text: obs_agent_mysql_digest_info or the Top digests table."),
		rule("MySQLDigestCPUHog")), 12)
	b.add(withAlert(described(prom("% of node disk reads by top digests", "percent",
		[2]string{`100 * topk(10, ` + perDigest(digRead, alertWin) + ` / on (instance) group_left () ` + nodeRead(alertWin) + `)`, "{{instance}} {{digest_id}}"}),
		"per digest: disk-read bytes per second ÷ the node's physical-disk read bytes per second × 100, over 5m (the alert's window); top 10.",
		"a line above the dashed 20% line is a statement causing a fifth of the disk's reads; the alert also needs node disk reads > 5 MiB/s."),
		rule("MySQLDigestDiskReadHog")), 12)
	b.add(described(prom("MySQL query CPU vs mysqld CPU (cores)", "short",
		[2]string{`sum by (instance) (rate(obs_agent_mysql_query_cpu_seconds_total{` + inst + `}[$__rate_interval]))`, "{{instance}} query CPU (attributed to digests)"},
		[2]string{`sum by (instance) (obs_agent_family_cpu_percent{` + inst + `,family=~"$mysql_family"}) / 100 * on (instance) obs_agent_cpu_count{` + inst + `}`, "{{instance}} mysqld family CPU"}),
		"query CPU = rate of on-CPU seconds inside dispatch_command (cores); mysqld family CPU = family_cpu_percent / 100 × cpu_count (cores).",
		"query CPU is what digests can explain. The gap up to the mysqld family's CPU is spent outside statements (reading the next packet, network, "+
			"InnoDB background threads) and cannot be attributed to a query. Pick the mysqld family with the mysqld family variable if the default regex misses it."), 12)
	digSum := func(m string) string {
		return `sum by (digest_id) (rate(` + m + `{` + inst + `,digest_id!="other"}[5m]))`
	}
	top := promTable("Top digests (last 5m)",
		digSum(digCPU),
		`100 * `+digSum(digCPU)+` / scalar(sum(`+nodeCores("5m")+`))`,
		digSum(digRead)+` / 1048576`,
		`100 * `+digSum(digRead)+` / on () group_left () sum(`+nodeRead("5m")+`)`,
		digSum(digRead)+` / `+digSum("obs_agent_mysql_digest_calls_total")+` / 16384`)
	top.Transformations = []map[string]any{{"id": "merge", "options": map[string]any{}},
		{"id": "organize", "options": map[string]any{
			"renameByName":  map[string]any{"Value #A": "cores", "Value #B": "% node CPU", "Value #C": "disk MB/s", "Value #D": "% disk read", "Value #E": "pages/call"},
			"excludeByName": map[string]any{"Time": true}}}}
	top.Options = map[string]any{"sortBy": []any{map[string]any{"displayName": "cores", "desc": true}}}
	top.FieldConfig = withColumnUnits(top.FieldConfig, map[string]string{"% node CPU": "percent", "% disk read": "percent"})
	b.add(described(top,
		"over the last 5m, summed over the selected instances: cores = digest on-CPU s/s; % node CPU = cores ÷ node CPU cores in use × 100; "+
			"disk MB/s = digest disk-read bytes/s ÷ 1048576; % disk read = digest ÷ node physical-disk read bytes/s × 100; "+
			"pages/call = disk-read bytes per call ÷ 16384 (InnoDB page).",
		"the top rows by cores and % disk read are the culprits. pages/call 1–4 = buffer-pool misses (grow innodb_buffer_pool_size), "+
			"hundreds = a scan (EXPLAIN, index, LIMIT). Only exported digests appear (prometheus_digests minimal: top 20 by CPU ∪ top 20 by disk read); "+
			"the long tail is in the Analysis dashboard."), 24)

	b.row("MySQL — who is waiting")
	share := func(m string) string { return `100 * ` + sumq(m) + ` / ` + sumq(qWall) }
	orZero := func(m string) string { return `(` + sumq(m) + ` or 0 * ` + sumq(qWall) + `)` }
	where := prom("Where query time goes (%)", "percent",
		[2]string{share(qRunq), "{{instance}} waiting for CPU"},
		[2]string{share(qCPU), "{{instance}} on CPU"},
		[2]string{share(qIO), "{{instance}} disk wait"},
		[2]string{share(qRedo), "{{instance}} commit wait"},
		[2]string{`clamp_min(100 - 100 * (` + sumq(qCPU) + ` + ` + sumq(qRunq) + ` + ` + orZero(qIO) + ` + ` + orZero(qRedo) + `) / ` + sumq(qWall) + `, 0)`, "{{instance}} other (locks, network, unmeasured)"})
	where.FieldConfig["defaults"].(map[string]any)["custom"] = map[string]any{"stacking": map[string]any{"mode": "normal"}, "fillOpacity": 40}
	where = described(where,
		"each part's seconds per second ÷ statement wall seconds per second × 100, over 5m (the alerts' window), stacked: waiting for CPU (run-queue), "+
			"on CPU, disk wait (block I/O), commit wait (redo log), other = 100 − the rest (locks, network, and any wait that is not measured).",
		"waiting for CPU is the bottom band, so its top edge reads directly against the dashed 30% line (MySQLQueriesStarvedForCPU, also needs node CPU ≥ 85%). "+
			"For MySQLQueriesStalledOnDisk add the disk and commit bands (also needs PSI io full > 10). Victims of CPU overload show mostly 'waiting for CPU': "+
			"do not tune them, find the culprit in the row above. Missing disk/commit bands = not measured (see Accounting availability).")
	where = withAlert(withAlert(where, rule("MySQLQueriesStarvedForCPU")), rule("MySQLQueriesStalledOnDisk"))
	b.add(where, 12)
	b.add(withAlert(described(prom("Commit wait share (%)", "percent", [2]string{share(qRedo), "{{instance}}"}),
		"redo-log wait seconds per second ÷ statement wall seconds per second × 100, over 5m.",
		"above the dashed line statements spend more than a fifth of their time waiting for the redo log fsync: check the log device "+
			"(Disk average wait, Disk utilisation), batch small transactions, or innodb_flush_log_at_trx_commit."),
		rule("MySQLCommitsStalledOnRedo")), 12)
	b.add(withAlert(described(prom("Query disk writes by command", "Bps",
		[2]string{`sum by (instance, command) (rate(obs_agent_mysql_query_disk_write_bytes_total{` + inst + `}[` + alertWin + `]))`, "{{instance}} {{command}}"},
		[2]string{`sum by (instance) (rate(obs_agent_mysql_query_disk_write_bytes_total{` + inst + `,command=~"query|stmt_execute"}[` + alertWin + `]))`, "{{instance}} query + stmt_execute (alerted)"}),
		"bytes per second written to disk by mysqld threads while running statements, by command, over 5m; plus query + stmt_execute summed, which is what the alert compares.",
		"SELECTs writing to disk are on-disk temporary tables or sorts: the 'query + stmt_execute' line above the dashed 10 MiB/s line fires the alert. "+
			"Add an index for the ORDER BY / GROUP BY or raise tmp_table_size / sort_buffer_size."),
		rule("MySQLQueriesSpillingToDisk")), 12)
	b.add(described(prom("Queries per second by command", "ops",
		[2]string{`sum by (instance, command) (rate(obs_agent_mysql_queries_total{` + inst + `}[$__rate_interval]))`, "{{instance}} {{command}}"}),
		"rate of commands handled by dispatch_command, by command class.",
		"a step change in rate explains a step change in CPU or wait; a falling rate with rising wait shares means statements are slowing down."), 12)

	b.row("Node")
	b.add(dashedLine(described(prom("CPU", "percent",
		[2]string{`obs_agent_cpu_usage_percent{` + inst + `}`, "{{instance}} usage"},
		[2]string{`obs_agent_cpu_iowait_percent{` + inst + `}`, "{{instance}} iowait"},
		[2]string{`obs_agent_cpu_steal_percent{` + inst + `}`, "{{instance}} steal"}),
		"/proc/stat deltas over the 5 s collection interval: usage = user + system, iowait and steal as a share of all CPU time.",
		"the dashed 85% line is the node-saturation condition of MySQLQueriesStarvedForCPU and MySQLDigestCPUHog. "+
			"iowait is idle time while a task waits for I/O, not lost work: read PSI io instead. High steal = the hypervisor is taking the CPU."), 85, false), 12)
	b.add(described(prom("Load (1m) and blocked tasks", "short",
		[2]string{`obs_agent_load1{` + inst + `}`, "{{instance}} load1"},
		[2]string{`obs_agent_procs_blocked{` + inst + `}`, "{{instance}} D-state"}),
		"load1 from /proc/loadavg; D-state = procs_blocked from /proc/stat.",
		"load above the CPU count with low CPU usage means tasks wait on I/O (D-state), not on CPU."), 12)
	b.add(described(prom("Memory available", "percent",
		[2]string{`100 * obs_agent_mem_available_bytes{` + inst + `} / obs_agent_mem_total_bytes{` + inst + `}`, "{{instance}}"}),
		"MemAvailable ÷ MemTotal × 100 (/proc/meminfo).",
		"falling toward 0 means page-cache pressure and then swapping or OOM; a shrinking page cache also turns cached reads into disk reads."), 12)
	b.add(described(prom("Context switches", "ops",
		[2]string{`obs_agent_cpu_ctx_switches_per_sec{` + inst + `}`, "{{instance}}"}),
		"context switches per second from /proc/stat.",
		"a sudden rise without more work usually means lock contention or too many threads competing for the CPUs."), 12)

	b.row("Disk & network")
	b.add(described(prom("Disk utilisation", "percent", [2]string{`obs_agent_disk_io_util_percent{` + inst + `}`, "{{instance}} {{device}}"}),
		"share of time the device had at least one request in flight (iostat %util), per device.",
		"near 100% a single-queue device is saturated; NVMe and RAID can serve more at 100%, so check Disk average wait too."), 12)
	b.add(described(prom("Disk average wait", "ms", [2]string{`obs_agent_disk_avg_wait_ms{` + inst + `}`, "{{instance}} {{device}}"}),
		"time spent on completed requests ÷ completed requests, per device and collection interval (iostat await).",
		"rising wait at the same throughput = the device became slower (or a deep queue); for the redo log device this drives commit wait."), 12)
	b.add(described(prom("Disk throughput", "Bps",
		[2]string{`obs_agent_disk_read_bytes_per_sec{` + inst + `}`, "{{instance}} {{device}} read"},
		[2]string{`obs_agent_disk_write_bytes_per_sec{` + inst + `}`, "{{instance}} {{device}} write"}),
		"bytes read and written per second, per device (all devices, including dm and md).",
		"compare with Physical-disk throughput, which counts each byte once; stacked devices (dm over sda) count the same I/O twice here."), 12)
	b.add(described(prom("Physical-disk throughput", "Bps",
		[2]string{`rate(obs_agent_node_disk_read_bytes_total{` + inst + `}[$__rate_interval])`, "{{instance}} read"},
		[2]string{`rate(obs_agent_node_disk_write_bytes_total{` + inst + `}[$__rate_interval])`, "{{instance}} write"}),
		"rate of bytes read and written by the node's physical disks (whole devices without slaves; no loop, zram, dm or md).",
		"the denominator of '% of node disk reads'; MySQLDigestDiskReadHog needs reads above 5 MiB/s."), 12)
	b.add(dashedLine(described(prom("PSI io full / some (%)", "percent",
		[2]string{`obs_agent_pressure_io_full_avg10{` + inst + `}`, "{{instance}} io full"},
		[2]string{`obs_agent_pressure_io_some_avg10{` + inst + `}`, "{{instance}} io some"}),
		"/proc/pressure/io avg10: full = share of time no task could progress because of I/O, some = at least one task waited.",
		"io full is lost work, unlike iowait; the dashed 10% line is the io-full condition of MySQLQueriesStalledOnDisk. Absent when the kernel has no PSI."), 10, false), 12)
	b.add(described(prom("Network throughput", "Bps",
		[2]string{`obs_agent_net_rx_bytes_per_sec{` + inst + `}`, "{{instance}} {{interface}} rx"},
		[2]string{`obs_agent_net_tx_bytes_per_sec{` + inst + `}`, "{{instance}} {{interface}} tx"}),
		"bytes received and sent per second, per interface (/proc/net/dev).",
		"a flat line at the link speed means the network is saturated; large tx from mysqld = large result sets."), 12)

	b.row("Process families")
	fam := inst + `,family=~"$family"`
	b.add(described(prom("Top families by CPU", "percent", [2]string{`topk(10, obs_agent_family_cpu_percent{` + fam + `})`, "{{instance}} {{family}}"}),
		"CPU of all processes of a family (systemd unit or cgroup) ÷ CPUs usable by the agent × 100; top 10.",
		"the family at the top is what burns the node's CPU; if it is not mysqld, MySQL is not the cause (overload_cause verdict not_mysql)."), 12)
	b.add(described(prom("Top families by RSS", "bytes", [2]string{`topk(10, obs_agent_family_mem_rss_bytes{` + fam + `})`, "{{instance}} {{family}}"}),
		"summed resident memory of a family's processes; top 10.",
		"steady growth is a leak or a growing cache; compare with Memory available."), 12)
	b.add(described(prom("Family TCP bytes by direction", "Bps",
		[2]string{`sum by (instance, family, direction) (rate(obs_agent_family_net_bytes_total{` + fam + `}[$__rate_interval]))`, "{{instance}} {{family}} {{direction}}"}),
		"rate of TCP bytes (sent + received) per family, inbound (it serves) and outbound (it calls).",
		"which service carries the traffic; inbound to mysqld is its clients."), 12)
	b.add(described(prom("Top inbound clients", "Bps",
		[2]string{`topk(10, sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_inbound_peer_bytes_total{` + fam + `}[$__rate_interval])))`, "{{family}} ← {{peer_ip}}:{{service_port}}"}),
		"rate of TCP bytes per client IP and local listening port; top 10 (overflow folds into peer_ip other).",
		"the client sending or fetching the most data; for :3306 this is the application host behind a heavy query."), 12)
	b.add(described(prom("Top outbound peers", "Bps",
		[2]string{`topk(10, sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total{` + fam + `}[$__rate_interval])))`, "{{family}} → {{peer_ip}}:{{service_port}}"}),
		"rate of TCP bytes per remote IP and service port a family connects to; top 10.",
		"the dependencies a service talks to most; a new top peer after a deploy is worth checking."), 12)

	b.row("Agent health")
	b.add(described(prom("Coverage", "percentunit",
		[2]string{`obs_agent_mysql_digest_coverage_ratio{` + inst + `}`, "{{instance}} digest series ÷ query CPU"},
		[2]string{`obs_agent_mysql_query_cpu_coverage_ratio{` + inst + `}`, "{{instance}} query CPU ÷ mysqld CPU"}),
		"digest coverage = window CPU of the exported digest series ÷ all query CPU; query CPU coverage = CPU inside statements ÷ mysqld CPU.",
		"low digest coverage = the Prometheus digest panels miss much of the load (use the Analysis dashboard); "+
			"low query CPU coverage = mysqld's CPU goes outside statements."), 12)
	acc := described(prom("Dropped, overflow and hash mismatches", "ops",
		[2]string{`rate(obs_agent_mysql_events_dropped_total{` + inst + `}[$__rate_interval])`, "{{instance}} events dropped"},
		[2]string{`rate(obs_agent_mysql_agg_overflow_total{` + inst + `}[$__rate_interval])`, "{{instance}} aggregation overflow"},
		[2]string{`rate(obs_agent_mysql_hash_mismatch_total{` + inst + `}[$__rate_interval])`, "{{instance}} hash mismatch"}),
		"per-second rates of the three MySQL accounting counters.",
		"all should be 0. Dropped events undercount digest totals; overflow keeps totals exact at a higher cost; a hash mismatch falls back to exact processing.")
	acc.Description += "\nAlert ObsAgentMySQLAccountingDegraded (info) fires when any of them stays above 0 for 10m."
	b.add(acc, 12)
	b.add(withAlert(described(prom("Accounting availability", "none",
		[2]string{`obs_agent_mysql_io_wait_available{` + inst + `}`, "{{instance}} disk wait measured"},
		[2]string{`obs_agent_mysql_redo_wait_available{` + inst + `}`, "{{instance}} commit wait measured"}),
		"1 when the agent can measure per-statement disk wait (task delay accounting) or commit wait (redo-log hooks), 0 when not.",
		"below the dashed line the disk or commit band of 'Where query time goes' is missing and its time is counted as 'other'; "+
			"mysql_report.accounting says why. The alert covers disk wait (for 30m)."),
		rule("ObsAgentMySQLIOWaitUnavailable")), 12)
	b.add(described(prom("ClickHouse rows sent / dropped", "short",
		[2]string{`sum by (instance, table) (rate(obs_agent_clickhouse_rows_sent_total{` + inst + `}[$__rate_interval]))`, "{{instance}} sent {{table}}"},
		[2]string{`sum by (instance, table, reason) (rate(obs_agent_clickhouse_rows_dropped_total{` + inst + `}[$__rate_interval]))`, "{{instance}} dropped {{table}} {{reason}}"}),
		"rows per second inserted into ClickHouse, and dropped by table and reason.",
		"rejected = schema or auth mismatch; buffer_full = ClickHouse down longer than the buffer holds; drain_cap = keys folded into overflow (totals stay exact)."), 12)
	b.add(described(prom("ClickHouse buffer and staleness", "short",
		[2]string{`obs_agent_clickhouse_buffer_bytes{` + inst + `}`, "{{instance}} buffer bytes"},
		[2]string{`time() - obs_agent_clickhouse_last_success_timestamp_seconds{` + inst + `}`, "{{instance}} seconds since last insert"}),
		"bytes waiting in the agent's send buffer; seconds since the last successful insert.",
		"staleness should stay below two flush intervals; a growing buffer means ClickHouse is not accepting inserts."), 12)
	b.add(described(prom("Diagnose snapshots", "short",
		[2]string{`sum by (instance, reason_kind) (increase(obs_agent_clickhouse_snapshots_total{` + inst + `}[$__range]))`, "{{instance}} {{reason_kind}}"}),
		"diagnose snapshots captured over the dashboard's range, by reason kind (module, io_verdict, both).",
		"each one is a full /api/diagnose report stored in ClickHouse; read them in the Analysis dashboard's Snapshots table."), 12)
	b.add(described(prom("eBPF events by module", "ops",
		[2]string{`sum by (instance, module) (rate(obs_agent_ebpf_events_total{` + inst + `}[$__rate_interval]))`, "{{instance}} {{module}}"}),
		"events per second emitted by each eBPF module's ring buffer.",
		"non-zero only while a module is active or emitting outliers; a module that never shows up was never triggered."), 12)
	d.Panels = b.done()
	return d
}

func analysis() Dashboard {
	var d Dashboard
	d.UID, d.Title, d.Tags = "obs-agent-analysis", "obs-agent MySQL & Network Analysis", []string{"obs-agent", "clickhouse"}
	d.SchemaVersion, d.Time, d.Refresh = 39, map[string]string{"from": "now-6h", "to": "now"}, ""
	d.Templating.List = []Var{
		dsVar("ds_clickhouse", "ClickHouse", "grafana-clickhouse-datasource"),
		{Name: "host", Type: "query", Datasource: &chDS, Multi: true, IncludeAll: true, Refresh: 2,
			Query: "SELECT DISTINCT host FROM obs.family_stats WHERE $__timeFilter(window_end) ORDER BY host"},
		{Name: "family", Type: "query", Datasource: &chDS, Multi: true, IncludeAll: true, Refresh: 2,
			Query: "SELECT DISTINCT family FROM obs.family_stats WHERE $__timeFilter(window_end) AND " + hostF + " ORDER BY family"},
		{Name: "digest", Label: "Digest id (drill-down)", Type: "textbox", Query: "", Current: map[string]any{"value": ""}},
		// Must equal the agents' clickhouse.flush_interval in seconds (edit in dashboard settings).
		{Name: "flush_s", Label: "ClickHouse flush interval (s)", Type: "constant", Query: "60", Hide: 2},
		// Must equal the agents' mysql.slow_query_threshold_ms (edit in dashboard settings).
		{Name: "slow_ms", Label: "Slow threshold (ms)", Type: "constant", Query: "100", Hide: 2},
	}
	d.Links = []map[string]any{{"title": "obs-agent Overview (Prometheus)", "type": "link", "targetBlank": true,
		"url": "/d/obs-agent-overview/obs-agent-overview?$__url_time_range"}}

	// Node totals of the selected hosts over the selected range, from
	// host_stats: the denominators of every "% of node" share. They divide
	// through nullIf(x, 0), never greatest(x, 1): greatest ignores NULL on
	// ClickHouse >= 24.12, which would turn "not measured" into a huge share.
	hostSum := func(col string) string {
		return `(SELECT sum(` + col + `) FROM obs.host_stats WHERE $__timeFilter(window_end) AND ` + hostF + `)`
	}
	// CPU capacity of the intervals that measured node CPU: an interval whose
	// node_cpu_used_ns is NULL must not add capacity (it would read low).
	nodeCPUCapacityS := `(SELECT sumIf(cpu_count * dateDiff('second', window_start, window_end), node_cpu_used_ns IS NOT NULL) FROM obs.host_stats WHERE $__timeFilter(window_end) AND ` + hostF + `)`
	rangeS := `greatest(dateDiff('second', $__fromTime, $__toTime), 1)`

	b := &builder{}
	b.row("MySQL digests")
	topDigests := chTable("Top digests", `SELECT s.digest_id AS digest, any(t.digest_text) AS text, sum(s.calls) AS callCount,
  sum(s.cpu_ns) / 1e9 / `+rangeS+` AS cpuCores,
  max(s.cpu_ns / greatest(dateDiff('second', s.window_start, s.window_end), 1)) / 1e9 AS peakCores,
  100 * sum(s.cpu_ns) / nullIf(`+hostSum("node_cpu_used_ns")+`, 0) AS pctNodeCpu,
  sum(s.disk_read_bytes) / `+rangeS+` / 1048576 AS readMBs,
  100 * sum(s.disk_read_bytes) / nullIf(`+hostSum("disk_read_bytes")+`, 0) AS pctDiskRead,
  sum(s.disk_read_bytes) / greatest(sum(s.calls), 1) / 16384 AS pagesPerCall,
  sum(s.disk_write_bytes) / `+rangeS+` / 1048576 AS writeMBs,
  100 * sum(s.runq_ns) / greatest(sum(s.wall_ns), 1) AS cpuWaitPct,
  100 * sum(s.io_wait_ns) / nullIf(sumIf(s.wall_ns, s.io_wait_ns IS NOT NULL), 0) AS diskWaitPct,
  100 * sum(s.redo_wait_ns) / nullIf(sumIf(s.wall_ns, s.redo_wait_ns IS NOT NULL), 0) AS commitWaitPct,
  sum(s.wall_ns) / greatest(sum(s.calls), 1) / 1e6 AS latencyMsAvg,
  max(s.wall_max_ns) / 1e6 AS latencyMsMax,
  if(s.digest_id NOT IN ('`+chsink.MinorDigestID+`', '`+querystats.OtherDigestID+`') AND pctNodeCpu >= 20 AND 100 * `+hostSum("node_cpu_used_ns")+` / nullIf(`+nodeCPUCapacityS+` * 1e9, 0) >= 50, 'culprit', '') AS cpuRole,
  if(s.digest_id NOT IN ('`+chsink.MinorDigestID+`', '`+querystats.OtherDigestID+`') AND pctDiskRead >= 20 AND `+hostSum("disk_read_bytes")+` / `+rangeS+` / 1048576 >= 5, 'culprit', '') AS ioRole,
  multiIf(latencyMsAvg < ${slow_ms} OR cpuWaitPct + ifNull(diskWaitPct, 0) + ifNull(commitWaitPct, 0) < 50, '',
          cpuWaitPct >= ifNull(diskWaitPct, 0) AND cpuWaitPct >= ifNull(commitWaitPct, 0), 'cpu',
          ifNull(diskWaitPct, 0) >= ifNull(commitWaitPct, 0), 'disk', 'commit') AS victimOf
FROM obs.mysql_digest_stats AS s
LEFT JOIN (SELECT digest_id, digest_text FROM obs.mysql_digest_text FINAL) AS t ON t.digest_id = s.digest_id
WHERE $__timeFilter(s.window_end) AND s.`+hostF+`
GROUP BY s.digest_id ORDER BY cpuCores DESC LIMIT 50`)
	topDigests.FieldConfig = withColumnUnits(topDigests.FieldConfig, map[string]string{
		"cpuCores": "short", "peakCores": "short", "pctNodeCpu": "percent", "pctDiskRead": "percent",
		"cpuWaitPct": "percent", "diskWaitPct": "percent", "commitWaitPct": "percent",
		"readMBs": "MiBs", "writeMBs": "MiBs", "latencyMsAvg": "ms", "latencyMsMax": "ms",
	})
	b.add(described(topDigests,
		"per digest over the selected range and hosts: cpuCores = cpu_ns ÷ range seconds (average cores busy); peakCores = the highest cpu_ns ÷ window of one "+
			"flush interval on one host; pctNodeCpu = cpu_ns ÷ host_stats node_cpu_used_ns × 100; readMBs / writeMBs = disk bytes ÷ range seconds; "+
			"pctDiskRead = disk_read_bytes ÷ host_stats disk_read_bytes × 100; pagesPerCall = disk_read_bytes per call ÷ 16384; "+
			"cpuWaitPct = runq_ns ÷ wall_ns × 100; diskWaitPct / commitWaitPct = io_wait_ns / redo_wait_ns ÷ wall_ns of the intervals that measured that wait × 100; latencyMsAvg = wall_ns per call, latencyMsMax = wall_max_ns. "+
			"cpuRole = culprit when pctNodeCpu ≥ 20 and the node CPU was ≥ 50% used (over the intervals with a node CPU delta); ioRole = culprit when pctDiskRead ≥ 20 and the node read ≥ 5 MiB/s; "+
			"the folded <minor> and overflow other rows never get a role. victimOf = cpu / disk / commit (the largest wait) when latencyMsAvg ≥ slow_ms and the three waits are ≥ 50% of wall.",
		"cpuCores is averaged over the whole range and dilutes a short burst: sort by peakCores to find bursts. A culprit consumes the resource; a victim only waited "+
			"for it — fix culprits, not victims. pagesPerCall 1–4 = buffer-pool misses, hundreds = a scan. A NULL wait or % column means not measured "+
			"(no delay accounting, no redo hooks, or no host_stats rows). slow_ms must equal mysql.slow_query_threshold_ms (dashboard settings → variables)."), 24)
	// shareTS: the 10 digests with the most col over the range, as a share
	// of host_stats.hostCol per bucket.
	shareTS := func(col, hostCol string) string {
		return `SELECT d.time AS time, d.digest AS digest, 100 * d.v / nullIf(h.v, 0) AS pct
FROM (SELECT ` + flushBucket + ` AS time, digest_id AS digest, sum(` + col + `) AS v FROM obs.mysql_digest_stats
      WHERE $__timeFilter(window_end) AND ` + hostF + `
        AND digest_id IN (SELECT digest_id FROM obs.mysql_digest_stats WHERE $__timeFilter(window_end) AND ` + hostF + `
                          GROUP BY digest_id ORDER BY sum(` + col + `) DESC LIMIT 10)
      GROUP BY time, digest) AS d
INNER JOIN (SELECT ` + flushBucket + ` AS time, sum(` + hostCol + `) AS v
            FROM obs.host_stats WHERE $__timeFilter(window_end) AND ` + hostF + ` GROUP BY time) AS h ON h.time = d.time
ORDER BY time`
	}
	b.add(described(chTS("% of node CPU used — top 10 digests", "percent", shareTS("cpu_ns", "node_cpu_used_ns")),
		"per bucket (≥ flush interval): digest cpu_ns ÷ host_stats node_cpu_used_ns × 100, for the 10 digests with the most CPU over the range.",
		"above 20% (and a busy node) a digest is a CPU culprit; a bucket without host_stats rows shows no point."), 12)
	b.add(described(chTS("% of node disk reads — top 10 digests", "percent", shareTS("disk_read_bytes", "disk_read_bytes")),
		"per bucket: digest disk_read_bytes ÷ host_stats disk_read_bytes × 100, for the 10 digests with the most disk reads over the range.",
		"above 20% (and node reads ≥ 5 MiB/s) a digest is a disk culprit; compare pagesPerCall in Top digests to tell misses from scans."), 12)
	nodeTS := chTS("Node CPU used and disk reads", "percent", `SELECT `+flushBucket+` AS time,
  100 * sum(node_cpu_used_ns) / nullIf(sumIf(cpu_count * dateDiff('second', window_start, window_end), node_cpu_used_ns IS NOT NULL) * 1e9, 0) AS cpuUsedPct,
  sum(disk_read_bytes) / `+flushBucketS+` / 1048576 AS diskReadMBs
FROM obs.host_stats
WHERE $__timeFilter(window_end) AND `+hostF+`
GROUP BY time ORDER BY time`)
	nodeTS.FieldConfig = withColumnUnits(nodeTS.FieldConfig, map[string]string{"diskReadMBs": "MiBs"})
	b.add(described(nodeTS,
		"per bucket over the selected hosts: cpuUsedPct = node_cpu_used_ns ÷ (cpu_count × window seconds × 1e9) × 100 over the intervals with a node CPU delta; diskReadMBs = physical-disk read bytes ÷ bucket seconds ÷ 1048576.",
		"the context for the shares beside it: a 40% share of an idle node is not an overload. Roles in Top digests use 50% CPU and 5 MiB/s."), 12)
	b.add(described(chTS("CPU of the top 10 digests (cores)", "short", `SELECT `+flushBucket+` AS time, digest_id AS digest,
  sum(cpu_ns) / 1e9 / `+flushBucketS+` AS cores
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+`
  AND digest_id IN (SELECT digest_id FROM obs.mysql_digest_stats WHERE $__timeFilter(window_end) AND `+hostF+`
                    GROUP BY digest_id ORDER BY sum(cpu_ns) DESC LIMIT 10)
GROUP BY time, digest ORDER BY time`),
		"per bucket: digest cpu_ns ÷ 1e9 ÷ bucket seconds (cores), for the 10 digests with the most CPU over the range, summed over the selected hosts.",
		"absolute cores, independent of node size; a digest that jumps here and in '% of node CPU used' is the one to EXPLAIN."), 12)
	b.add(described(chTable("CPU regression vs 7 days earlier", `SELECT digest_id AS digest,
  sumIf(cpu_ns, $__timeFilter(window_end)) / 1e9 AS cpuSecNow,
  sumIf(cpu_ns, window_end >= $__fromTime - INTERVAL 7 DAY AND window_end < $__toTime - INTERVAL 7 DAY) / 1e9 AS cpuSecWeekAgo,
  cpuSecNow / greatest(cpuSecWeekAgo, 0.001) AS ratio
FROM obs.mysql_digest_stats
WHERE (window_end >= $__fromTime - INTERVAL 7 DAY) AND `+hostF+`
  AND ($__timeFilter(window_end) OR window_end < $__toTime - INTERVAL 7 DAY)
GROUP BY digest_id HAVING cpuSecNow > 1 ORDER BY ratio DESC LIMIT 30`),
		"per digest: CPU seconds in the selected range ÷ CPU seconds in the same range 7 days earlier (digests with > 1 CPU second now).",
		"ratio ≫ 1 = the digest got more expensive or more frequent than last week (a new query shows a huge ratio); check calls in the drill-down."), 12)

	b.row("Digest drill-down (set the digest variable)")
	digF := "digest_id = '${digest}'"
	b.add(described(chTS("Calls per second and average latency", "short", `SELECT `+flushBucket+` AS time, sum(calls) / `+flushBucketS+` AS callsPerSec,
  sum(cpu_ns) / greatest(sum(calls), 1) / 1e6 AS cpuMsAvg,
  sum(wall_ns) / greatest(sum(calls), 1) / 1e6 AS wallMsAvg,
  sum(runq_ns) / greatest(sum(calls), 1) / 1e6 AS runqMsAvg
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+digF+`
GROUP BY time ORDER BY time`),
		"per bucket for the selected digest: calls ÷ bucket seconds; cpu, wall and run-queue ns per call ÷ 1e6 (ms).",
		"more calls at the same cost = the caller changed; the same calls at a higher cpuMsAvg = the plan or the data changed."), 12)
	b.add(described(chTS("Where the digest's time goes (%)", "percent", `SELECT `+flushBucket+` AS time,
  100 * sum(cpu_ns) / greatest(sum(wall_ns), 1) AS cpuPct,
  100 * sum(runq_ns) / greatest(sum(wall_ns), 1) AS cpuWaitPct,
  100 * sum(io_wait_ns) / nullIf(sumIf(wall_ns, io_wait_ns IS NOT NULL), 0) AS diskWaitPct,
  100 * sum(redo_wait_ns) / nullIf(sumIf(wall_ns, redo_wait_ns IS NOT NULL), 0) AS commitWaitPct
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+digF+`
GROUP BY time ORDER BY time`),
		"per bucket for the selected digest: cpu_ns and runq_ns ÷ wall_ns × 100; io_wait_ns and redo_wait_ns ÷ wall_ns of the intervals that measured that wait × 100.",
		"cpuPct high = the statement itself is expensive; cpuWaitPct high = a victim of CPU overload; diskWaitPct = buffer-pool misses or scans; "+
			"commitWaitPct = redo-log fsync. The rest of 100% is locks, network or unmeasured; a missing line means not measured."), 12)
	b.add(described(chTable("Per host", `SELECT host, sum(calls) AS callCount, sum(cpu_ns) / 1e9 AS cpuSec,
  sum(wall_ns) / greatest(sum(calls), 1) / 1e6 AS wallMsAvg
FROM obs.mysql_digest_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+digF+`
GROUP BY host ORDER BY cpuSec DESC`),
		"per host for the selected digest: calls, CPU seconds, and wall ns per call ÷ 1e6.",
		"one host much slower than the others for the same statement points at that host (data, hardware, load), not the query."), 12)

	b.row("Slow queries")
	b.add(described(chTable("Latest slow queries (digest filter optional)", `SELECT ts, host, pid, latency_ms AS latencyMs, digest_id AS digest, query
FROM obs.mysql_slow_queries
WHERE $__timeFilter(ts) AND `+hostF+` AND ('${digest}' = '' OR `+digF+`)
ORDER BY ts DESC LIMIT 200`),
		"the newest 200 statements slower than mysql.slow_query_threshold_ms; query is literal-free unless both sample-query privacy flags are on.",
		"slow is not guilty: check victimOf in Top digests before tuning a slow statement."), 24)
	b.add(described(chTS("Slow queries per interval", "short", `SELECT $__timeInterval(ts) AS time, host, count() AS slow
FROM obs.mysql_slow_queries
WHERE $__timeFilter(ts) AND `+hostF+`
GROUP BY time, host ORDER BY time`),
		"count of slow statements per Grafana interval and host (one row per slow statement, so any bucket width is exact).",
		"a burst on every host at once = shared cause (network, storage, a batch job); on one host = that host."), 12)

	b.row("Process families")
	famF := "family IN (${family:singlequote})"
	b.add(described(chTS("Family CPU (avg)", "percent", `SELECT `+flushBucket+` AS time, family, avg(cpu_percent_avg) AS cpu
FROM obs.family_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY time, family ORDER BY time`),
		"per bucket: average of the family's cpu_percent_avg (CPU of all its processes ÷ CPUs × 100), averaged over the selected hosts.",
		"which service burned CPU when; compare with mysqld to see whether MySQL was the heavy one."), 12)
	b.add(described(chTS("Family RSS (max)", "bytes", `SELECT `+flushBucket+` AS time, family, max(rss_bytes_max) AS rss
FROM obs.family_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY time, family ORDER BY time`),
		"per bucket: the highest summed RSS of the family's processes on any selected host.",
		"steady growth is a leak or a growing cache."), 12)
	b.add(described(chTable("Top families", `SELECT host, family, avg(cpu_percent_avg) AS cpuAvg, max(cpu_percent_max) AS cpuMax,
  max(rss_bytes_max) AS rssMax, max(processes_max) AS processes
FROM obs.family_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY host, family ORDER BY cpuAvg DESC LIMIT 50`),
		"per host and family over the range: average and peak CPU %, peak RSS and peak process count.",
		"cpuMax ≫ cpuAvg = bursty; a process count that keeps growing = a fork storm or leaked workers."), 12)

	b.row("Network")
	peer := "replaceRegexpOne(toString(peer_ip), '^::ffff:', '')"
	b.add(described(chTable("Top inbound clients", `SELECT `+peer+` AS peer, service_port AS port, family,
  sum(bytes_rx + bytes_tx) AS bytes, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+` AND direction = 'inbound'
GROUP BY peer, port, family ORDER BY bytes DESC LIMIT 50`),
		"per client IP, local port and family over the range: TCP bytes both ways and connections opened (peer :: / port 0 = overflow).",
		"the clients behind the traffic; many connections with few bytes = no connection pool."), 12)
	b.add(described(chTable("Top outbound peers", `SELECT `+peer+` AS peer, service_port AS port, family,
  sum(bytes_rx + bytes_tx) AS bytes, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+` AND direction = 'outbound'
GROUP BY peer, port, family ORDER BY bytes DESC LIMIT 50`),
		"per remote IP, service port and family over the range: TCP bytes both ways and connections opened.",
		"the dependencies each service calls most."), 12)
	b.add(described(chTS("TCP throughput by direction", "Bps", `SELECT `+flushBucket+` AS time, direction,
  sum(bytes_rx + bytes_tx) / `+flushBucketS+` AS bytesPerSec
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND `+famF+`
GROUP BY time, direction ORDER BY time`),
		"per bucket: TCP bytes (both ways) ÷ bucket seconds, inbound vs outbound, for the selected families.",
		"a change in inbound is a change in client demand; in outbound, in what the services fetch."), 12)
	b.add(described(chTable("Who talks to MySQL (inbound :3306)", `SELECT host, `+peer+` AS client, sum(bytes_rx) AS bytesIn,
  sum(bytes_tx) AS bytesOut, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE $__timeFilter(window_end) AND `+hostF+` AND direction = 'inbound' AND service_port = 3306
GROUP BY host, client ORDER BY bytesOut DESC LIMIT 50`),
		"per MySQL host and client IP over the range: bytes received (queries), sent (results) and connections opened on port 3306.",
		"the client with the largest bytesOut fetches the biggest results; match it to a digest with a large bytes_out."), 12)

	b.row("Diagnose snapshots")
	b.add(described(chTable("Snapshots (fetch one with the query in deploy/grafana/README.md)", `SELECT ts, host, reason, verdict,
  JSONExtractString(report, 'mysql_report', 'overload_cause', 'verdict') AS overload,
  JSONExtractString(report, 'mysql_report', 'overload_cause', 'digest', 'digest_id') AS overloadDigest,
  length(report) AS reportBytes
FROM obs.diagnose_snapshots
WHERE $__timeFilter(ts) AND `+hostF+`
ORDER BY ts DESC LIMIT 100`),
		"the newest 100 diagnose snapshots: why each was taken (reason), the I/O verdict, and overload_cause verdict and digest extracted from the stored report.",
		"a snapshot is the exact /api/diagnose output at that moment; fetch the full report with the SQL in deploy/grafana/README.md."), 24)
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
