package main

import "strings"

// explain is a PostgreSQL panel's help (the ⓘ tooltip), written for an
// on-call engineer who is not a PostgreSQL expert: what is drawn, what good
// and bad look like, the next action, and the exact formula.
func explain(what, goodBad, ifBad, formula string) string {
	return "What: " + what + "\nGood / bad: " + goodBad + "\nIf bad: " + ifBad + "\nFormula: " + formula
}

func explained(p Panel, what, goodBad, ifBad, formula string) Panel {
	p.Description = explain(what, goodBad, ifBad, formula)
	return p
}

// pgAlertRules mirror the obs-agent-postgres group of
// deploy/prometheus/obs-agent-alerts.yaml (TestAlertPanelsMatchRules).
var pgAlertRules = []alertRule{
	{"PostgresQueriesStarvedForCPU", "critical", "> 0.3", 30, true, false},
	{"PostgresQueriesStalledOnDisk", "critical", "> 0.3", 30, true, false},
	{"PostgresDigestCPUHog", "warning", "> 0.2", 20, true, false},
	{"PostgresDigestDiskReadHog", "warning", "> 0.2", 20, true, false},
	{"PostgresCommitsStalledOnWAL", "warning", "> 0.2", 20, true, false},
	{"PostgresSyncReplicationSlow", "warning", "> 0.2", 20, true, false},
	{"PostgresBackgroundCPUHigh", "warning", ">= 0.5", 50, true, false},
	{"ObsAgentPostgresTracingShed", "warning", "== 0", 0.5, true, true},
	{"ObsAgentPostgresAccountingDegraded", "info", "increase(obs_agent_postgres_hash_mismatch_total[10m]) > 0", 0, false, false},
}

// steps sets a stat's colour steps: green below warn, orange to bad, red above.
func steps(p Panel, warn, bad float64) Panel {
	p.FieldConfig["defaults"].(map[string]any)["thresholds"] = map[string]any{"mode": "absolute", "steps": []any{
		map[string]any{"color": "green", "value": nil}, map[string]any{"color": "orange", "value": warn},
		map[string]any{"color": "red", "value": bad}}}
	return p
}

// chText is a text panel bound to the ClickHouse datasource variable.
func chText(title, markdown string) Panel {
	p := textPanel(title, markdown)
	p.Datasource = chDS
	return p
}

func pgRule(name string) alertRule {
	for _, r := range pgAlertRules {
		if r.Name == name {
			return r
		}
	}
	panic("unknown postgres alert " + name)
}

const (
	pgInst = `instance=~"$instance",cluster=~"$cluster"`
	pgHost = `host IN (${host:singlequote}) AND cluster IN (${cluster:singlequote})`

	pgIntro = "**How to use this dashboard** — answer five questions in order; each row answers one.\n\n" +
		"1. **Is the server overloaded?** CPU, load, disk stall.\n" +
		"2. **Is it PostgreSQL?** The cluster's CPU against other process families.\n" +
		"3. **Queries or background work?** CPU by backend type: client queries, or autovacuum, checkpointer, I/O workers.\n" +
		"4. **Which query?** The digests with the largest share of the node's CPU or disk reads.\n" +
		"5. **Cause or victim?** Where query time goes: a query that mostly *waits* is a victim — fix the culprit, not the victim.\n\n" +
		"**Words used here.** *Digest*: one query shape — the SQL with its values replaced by `?`, so `id = 1` and `id = 2` count together. " +
		"*Run-queue wait*: time a query was ready to run but no CPU was free. *WAL*: PostgreSQL's write-ahead log; a commit waits for it to reach disk. " +
		"*Backend type*: what a PostgreSQL process does (client connection, autovacuum, checkpointer, I/O worker…). " +
		"The full evidence for one moment is in `/api/diagnose` → `postgres_report.overload_cause`."
)

func pgOverview() Dashboard {
	var d Dashboard
	d.UID, d.Title, d.Tags = "obs-agent-postgres-overview", "obs-agent PostgreSQL Overview", []string{"obs-agent", "postgres"}
	d.SchemaVersion, d.Time, d.Refresh = 39, map[string]string{"from": "now-6h", "to": "now"}, "1m"
	d.Templating.List = []Var{
		dsVar("ds_prometheus", "Prometheus", "prometheus"),
		{Name: "instance", Type: "query", Datasource: &promDS, Query: "label_values(obs_agent_postgres_tracing_active, instance)",
			Definition: "label_values(obs_agent_postgres_tracing_active, instance)", Multi: true, IncludeAll: true, Refresh: 2},
		{Name: "cluster", Type: "query", Datasource: &promDS, Query: `label_values(obs_agent_postgres_queries_total{instance=~"$instance"}, cluster)`,
			Definition: `label_values(obs_agent_postgres_queries_total{instance=~"$instance"}, cluster)`, Multi: true, IncludeAll: true, Refresh: 2},
	}
	d.Links = []map[string]any{{"title": "PostgreSQL Analysis (ClickHouse)", "type": "link", "targetBlank": true,
		"url": "/d/obs-agent-postgres-analysis/obs-agent-postgresql-analysis?$__url_time_range"}}
	ratio := func(num, den string) string {
		return `100 * sum by (instance, cluster) (rate(` + num + `{` + pgInst + `,command="client"}[` + alertWin + `]))` +
			` / sum by (instance, cluster) (rate(` + den + `{` + pgInst + `,command="client"}[` + alertWin + `]))`
	}
	nodeCores := `(avg_over_time(obs_agent_cpu_usage_percent{instance=~"$instance"}[` + alertWin + `]) / 100 * obs_agent_cpu_count{instance=~"$instance"})`
	perDigest := func(m string) string {
		return `sum by (instance, cluster, digest_id) (rate(` + m + `{` + pgInst + `,digest_id!="other"}[` + alertWin + `]))`
	}
	const wall = "obs_agent_postgres_query_wall_seconds_total"

	b := &builder{}
	b.addH(textPanel("How to use this dashboard", pgIntro), 24, 7)
	b.add(Panel{Type: "alertlist", Title: "Firing obs-agent alerts", Datasource: promDS,
		Options: map[string]any{"viewMode": "list", "groupMode": "default", "maxItems": 20, "sortOrder": 1,
			"stateFilter":              map[string]any{"firing": true, "pending": true},
			"alertInstanceLabelFilter": `{instance=~"${instance:regex}"}`}}, 24)

	b.row("1. Is the server overloaded?")
	b.addH(textPanel("Question 1", "Red here means the machine itself is out of CPU or stuck on disk. If everything is green, slow queries have another cause (locks, the network, the client)."), 24, 2)
	b.add(explained(steps(promStat("Node CPU used", "percent", `avg_over_time(obs_agent_cpu_usage_percent{instance=~"$instance"}[5m])`, "{{instance}}"), 70, 85),
		"how busy all CPUs of the server were, averaged over 5 minutes.",
		"below 70% is comfortable; above 85% queries start to wait for a CPU.",
		"go to row 3 and 4 to see who uses the CPU.",
		"avg_over_time(obs_agent_cpu_usage_percent[5m])."), 6)
	b.add(explained(steps(promStat("Load per CPU", "short", `obs_agent_load1{instance=~"$instance"} / obs_agent_cpu_count{instance=~"$instance"}`, "{{instance}}"), 1, 1.5),
		"processes running or waiting to run, per CPU (1-minute load average).",
		"below 1 is fine; above 1.5 means work queues up for CPUs or disk.",
		"if CPU is low but load is high, look at the disk stall panel.",
		"obs_agent_load1 ÷ obs_agent_cpu_count."), 6)
	b.add(explained(steps(promStat("Disk stall (PSI io full)", "percent", `obs_agent_pressure_io_full_avg10{instance=~"$instance"}`, "{{instance}}"), 2, 10),
		"share of time in which nothing on the server could progress because of disk I/O.",
		"0–2% is normal; above 10% the disk is stalling the machine.",
		"open row 5 'Where query time goes' and the disk-read panels in row 4.",
		"obs_agent_pressure_io_full_avg10 (kernel PSI, avg10). Absent on kernels without /proc/pressure."), 6)
	b.add(withAlert(explained(promStat("Tracing active", "short", `obs_agent_postgres_tracing_active{instance=~"$instance"}`, "{{instance}}"),
		"whether the agent's statement probes are attached (1) or not (0).",
		"1 is normal. 0 means the agent protected the database by detaching (statement rate too high) or could not load.",
		"read postgres_report.accounting.state in /api/diagnose; the probes re-attach after postgres.shed_cooldown.",
		"obs_agent_postgres_tracing_active."), pgRule("ObsAgentPostgresTracingShed")), 6)

	b.row("2. Is it PostgreSQL?")
	b.addH(textPanel("Question 2", "Compare the PostgreSQL cluster with the other process families. If another family is on top, the database is a victim of a neighbour."), 24, 2)
	b.add(explained(prom("PostgreSQL cluster CPU vs top process families (cores)", "short",
		[2]string{`sum by (instance, cluster) (rate(obs_agent_postgres_backend_cpu_seconds_total{` + pgInst + `}[$__rate_interval]))`, "{{instance}} {{cluster}}"},
		[2]string{`topk(5, obs_agent_family_cpu_percent{instance=~"$instance"} / 100 * on (instance) group_left () obs_agent_cpu_count{instance=~"$instance"})`, "{{instance}} family {{family}}"}),
		"CPU cores used by each PostgreSQL cluster and by the five busiest process families.",
		"the cluster near the top while the node is busy means PostgreSQL is the main CPU user.",
		"if another family is on top, look at process_report in /api/diagnose instead of the queries.",
		"cluster: Σ rate(obs_agent_postgres_backend_cpu_seconds_total); family: obs_agent_family_cpu_percent / 100 × cpu_count."), 24)

	b.row("3. Queries or background work?")
	b.addH(textPanel("Question 3", "Client queries are what applications send. Background work (autovacuum, checkpoints, I/O workers) is PostgreSQL maintaining itself; it has different fixes."), 24, 2)
	b.add(withAlert(explained(prom("CPU by backend type (% of cluster)", "percent",
		[2]string{`100 * sum by (instance, cluster, backend_type) (rate(obs_agent_postgres_backend_cpu_seconds_total{` + pgInst + `}[` + alertWin + `]))` +
			` / on (instance, cluster) group_left () sum by (instance, cluster) (rate(obs_agent_postgres_backend_cpu_seconds_total{` + pgInst + `}[` + alertWin + `]))`, "{{instance}} {{cluster}} {{backend_type}}"}),
		"each backend type's share of the cluster's CPU: client, autovacuum, checkpointer, io_worker, walsender…",
		"client usually dominates; a background type above the dashed 50% line on a busy node is the cause.",
		"autovacuum: check table bloat and autovacuum cost limits; checkpointer: raise max_wal_size; io_worker: queries are reading (row 4).",
		"rate(backend_cpu_seconds_total) per type ÷ the cluster's total × 100, over 5m (the alert's window)."), pgRule("PostgresBackgroundCPUHigh")), 12)
	cov := promStat("Statement CPU coverage", "percent", `100 * obs_agent_postgres_query_cpu_coverage_ratio{`+pgInst+`}`, "{{instance}} {{cluster}}")
	cov.FieldConfig["defaults"].(map[string]any)["thresholds"] = map[string]any{"mode": "absolute",
		"steps": []any{map[string]any{"color": "blue", "value": nil}}}
	b.add(explained(cov,
		"how much of the cluster's CPU was spent inside statements the agent could see.",
		"high (70–100%) means queries explain the load; low means background work or connection handling.",
		"if low, read the backend-type panel on the left.",
		"statement CPU ÷ cluster CPU × 100 (obs_agent_postgres_query_cpu_coverage_ratio)."), 6)
	b.add(explained(prom("Disk reads by backend type (MB/s)", "MiBs",
		[2]string{`sum by (instance, cluster, backend_type) (rate(obs_agent_postgres_backend_disk_read_bytes_total{` + pgInst + `}[$__rate_interval])) / 1048576`, "{{instance}} {{cluster}} {{backend_type}}"}),
		"storage reads by each backend type of the cluster.",
		"on PostgreSQL 18+ the io_worker line carries the reads of queries; autovacuum reading a lot means vacuuming big tables.",
		"compare with row 4's disk-read shares; on PostgreSQL 18+ enable postgres.sql to split io_worker reads per query.",
		"rate(obs_agent_postgres_backend_disk_read_bytes_total) / 1048576 (needs process.include_io)."), 6)

	b.row("4. Which query?")
	b.addH(textPanel("Question 4", "A line above the dashed line is one query shape doing a fifth of all the server's CPU work or disk reads: that is the culprit to fix."), 24, 2)
	withText := ` * on (instance, cluster, digest_id) group_left (digest_text) obs_agent_postgres_digest_info{` + pgInst + `}`
	b.add(withAlert(explained(prom("% of node CPU used by top digests", "percent",
		[2]string{`100 * topk(10, ` + perDigest("obs_agent_postgres_digest_cpu_seconds_total") + ` / on (instance) group_left () ` + nodeCores + `)` + withText, "{{instance}} {{digest_text}}"}),
		"for the ten heaviest query shapes, their share of all CPU work on the server.",
		"no line above the dashed 20% line is normal; one above it is a CPU culprit (the alert also needs the node ≥ 85% busy).",
		"run EXPLAIN (ANALYZE, BUFFERS) on it, add an index or cache, or slow its caller down.",
		"rate(digest_cpu_seconds_total) ÷ node CPU cores in use × 100, over 5m."), pgRule("PostgresDigestCPUHog")), 12)
	b.add(withAlert(explained(prom("% of node disk reads by top digests", "percent",
		[2]string{`100 * topk(10, ` + perDigest("obs_agent_postgres_digest_disk_read_bytes_total") + ` / on (instance) group_left () (rate(obs_agent_node_disk_read_bytes_total{instance=~"$instance"}[` + alertWin + `]) > 0))` + withText, "{{instance}} {{digest_text}}"}),
		"for the ten heaviest query shapes, their share of the disk's reads.",
		"no line above 20% is normal; one above it reads a fifth of the disk (alert needs > 5 MiB/s). Empty on PostgreSQL 18+ async I/O.",
		"1–4 pages per call: add RAM / shared_buffers; hundreds: a scan — add an index or a LIMIT.",
		"rate(digest_disk_read_bytes_total) ÷ rate(node_disk_read_bytes_total) × 100, over 5m."), pgRule("PostgresDigestDiskReadHog")), 12)
	dig := func(m string) string {
		return `sum by (cluster, digest_id) (rate(` + m + `{` + pgInst + `,digest_id!="other"}[5m]))`
	}
	top := promTable("Top digests (last 5m)",
		dig("obs_agent_postgres_digest_cpu_seconds_total"),
		`100 * `+dig("obs_agent_postgres_digest_cpu_seconds_total")+` / scalar(sum(`+nodeCores+`))`,
		dig("obs_agent_postgres_digest_calls_total"),
		dig("obs_agent_postgres_digest_disk_read_bytes_total")+` / 1048576`)
	top.Transformations = []map[string]any{{"id": "merge", "options": map[string]any{}},
		{"id": "organize", "options": map[string]any{
			"renameByName":  map[string]any{"Value #A": "cores", "Value #B": "% node CPU", "Value #C": "calls/s", "Value #D": "disk MB/s"},
			"excludeByName": map[string]any{"Time": true}}}}
	top.Options = map[string]any{"sortBy": []any{map[string]any{"displayName": "cores", "desc": true}}}
	top.FieldConfig = withColumnUnits(top.FieldConfig, map[string]string{"% node CPU": "percent"})
	b.add(explained(top,
		"the heaviest query shapes right now: CPU cores, share of node CPU, calls per second, disk reads.",
		"a few cores spread over many digests is normal; one digest with a large share is the culprit.",
		"copy its digest_id into the Analysis dashboard for history, or read its text in postgres_report.",
		"per digest over 5m: rate(cpu seconds), ÷ node cores × 100, rate(calls), rate(disk read bytes) / 1048576."), 24)

	b.row("5. Cause or victim?")
	b.addH(textPanel("Question 5", "A slow query that mostly waits for a CPU, the disk or the WAL is a victim of something else. Fix the culprit from row 4 first."), 24, 2)
	wt := withAlert(explained(prom("Where query time goes", "percent",
		[2]string{ratio("obs_agent_postgres_query_cpu_seconds_total", wall), "{{cluster}} on CPU"},
		[2]string{ratio("obs_agent_postgres_query_runq_wait_seconds_total", wall), "{{cluster}} waiting for CPU"},
		[2]string{`100 * (sum by (instance, cluster) (rate(obs_agent_postgres_query_io_wait_seconds_total{` + pgInst + `,command="client"}[` + alertWin + `])) or 0 * sum by (instance, cluster) (rate(` + wall + `{` + pgInst + `,command="client"}[` + alertWin + `])))` +
			` / sum by (instance, cluster) (rate(` + wall + `{` + pgInst + `,command="client"}[` + alertWin + `])) + ` + ratio("obs_agent_postgres_query_wal_wait_seconds_total", wall), "{{cluster}} waiting for disk + WAL"}),
		"of all time spent in client queries: running on a CPU, waiting for a CPU, and waiting for disk or the WAL.",
		"waiting lines under the dashed 30% line are fine; above it queries are victims of a busy CPU or a slow disk.",
		"CPU wait high: fix the CPU culprit (row 4) or add CPU. Disk + WAL high: check the disk and PostgresCommitsStalledOnWAL.",
		"rate(part) ÷ rate(query_wall_seconds_total) × 100 for command=client, over 5m; an unmeasured wait counts as 0."),
		pgRule("PostgresQueriesStarvedForCPU"))
	b.add(withAlert(wt, pgRule("PostgresQueriesStalledOnDisk")), 12)
	b.add(withAlert(explained(prom("WAL wait share", "percent",
		[2]string{ratio("obs_agent_postgres_query_wal_wait_seconds_total", wall), "{{instance}} {{cluster}}"}),
		"share of client-query time spent waiting for the write-ahead log to reach disk (mostly COMMIT).",
		"a few percent is normal; above the dashed 20% line commits are slow.",
		"check the WAL disk's latency; consider group commit (commit_delay) or synchronous_commit=off where safe.",
		"rate(query_wal_wait_seconds_total) ÷ rate(query_wall_seconds_total) × 100, command=client, over 5m."), pgRule("PostgresCommitsStalledOnWAL")), 12)
	b.add(withAlert(explained(prom("Sync-replication wait share", "percent",
		[2]string{ratio("obs_agent_postgres_query_syncrep_wait_seconds_total", wall), "{{instance}} {{cluster}}"}),
		"share of client-query time spent waiting for synchronous standbys to confirm.",
		"empty when synchronous replication is not used; above the dashed 20% line a standby is slow.",
		"check pg_stat_replication lag, the standby's disk and network.",
		"rate(query_syncrep_wait_seconds_total) ÷ rate(query_wall_seconds_total) × 100, command=client, over 5m."), pgRule("PostgresSyncReplicationSlow")), 12)
	b.add(explained(prom("Statements per second by command", "ops",
		[2]string{`sum by (instance, cluster, command) (rate(obs_agent_postgres_queries_total{` + pgInst + `}[$__rate_interval]))`, "{{instance}} {{cluster}} {{command}}"}),
		"executed statements per second: client queries, fastpath calls, autovacuum and replication commands.",
		"compare with yesterday: a jump in client statements often explains a CPU rise.",
		"find the caller of the digest that grew in row 4.",
		"rate(obs_agent_postgres_queries_total) by command."), 12)

	b.row("Agent health")
	b.addH(textPanel("Agent health", "Whether the numbers above are complete. Missing signals are shown as unavailable, never as zero."), 24, 2)
	b.add(explained(prom("Accounting availability", "short",
		[2]string{`obs_agent_postgres_io_wait_available{` + pgInst + `}`, "{{cluster}} disk wait measured"},
		[2]string{`obs_agent_postgres_wal_wait_available{` + pgInst + `}`, "{{cluster}} WAL wait measured"},
		[2]string{`obs_agent_postgres_enrichment_up{` + pgInst + `}`, "{{cluster}} pg_stat_statements enrichment"}),
		"which optional signals are measured (1) or not (0).",
		"disk wait 0 usually means kernel delay accounting is off; enrichment 0 means postgres.sql is not configured or failing.",
		"enable delay accounting (postgres.enable_delayacct) or fix the DSN; see accounting in /api/diagnose.",
		"io_wait_available, wal_wait_available, enrichment_up gauges."), 12)
	b.add(explained(prom("Dropped, overflow, mismatches, unmatched credit", "short",
		[2]string{`rate(obs_agent_postgres_events_dropped_total{instance=~"$instance"}[$__rate_interval])`, "{{instance}} dropped/s"},
		[2]string{`rate(obs_agent_postgres_agg_overflow_total{instance=~"$instance"}[$__rate_interval])`, "{{instance}} overflow/s"},
		[2]string{`rate(obs_agent_postgres_hash_mismatch_total{instance=~"$instance"}[$__rate_interval])`, "{{instance}} mismatches/s"},
		[2]string{`rate(obs_agent_postgres_credit_dropped_total{instance=~"$instance"}[$__rate_interval])`, "{{instance}} unmatched credit/s"}),
		"rates of the agent's own accounting problems.",
		"all flat at zero is healthy; dropped above zero means totals undercount.",
		"check the agent's CPU limit and the number of distinct statements.",
		"rate() of the four obs_agent_postgres_*_total health counters."), 12)
	d.Panels = b.done()
	return d
}

func pgAnalysis() Dashboard {
	var d Dashboard
	d.UID, d.Title, d.Tags = "obs-agent-postgres-analysis", "obs-agent PostgreSQL Analysis", []string{"obs-agent", "postgres", "clickhouse"}
	d.SchemaVersion, d.Time, d.Refresh = 39, map[string]string{"from": "now-6h", "to": "now"}, ""
	d.Templating.List = []Var{
		dsVar("ds_clickhouse", "ClickHouse", "grafana-clickhouse-datasource"),
		{Name: "host", Type: "query", Datasource: &chDS, Multi: true, IncludeAll: true, Refresh: 2,
			Query: "SELECT DISTINCT host FROM obs.pg_digest_stats WHERE $__timeFilter(window_end) ORDER BY host"},
		{Name: "cluster", Type: "query", Datasource: &chDS, Multi: true, IncludeAll: true, Refresh: 2,
			Query: "SELECT DISTINCT cluster FROM obs.pg_digest_stats WHERE $__timeFilter(window_end) AND " + hostF + " ORDER BY cluster"},
		{Name: "digest", Label: "Digest id (drill-down)", Type: "textbox", Query: "", Current: map[string]any{"value": ""}},
		{Name: "flush_s", Label: "ClickHouse flush interval (s)", Type: "constant", Query: "60", Hide: 2},
	}
	d.Links = []map[string]any{{"title": "PostgreSQL Overview (Prometheus)", "type": "link", "targetBlank": true,
		"url": "/d/obs-agent-postgres-overview/obs-agent-postgresql-overview?$__url_time_range"}}
	rangeS := `greatest(dateDiff('second', $__fromTime, $__toTime), 1)`
	hostSum := func(col string) string {
		return `(SELECT sum(` + col + `) FROM obs.host_stats WHERE $__timeFilter(window_end) AND ` + hostF + `)`
	}

	b := &builder{}
	b.addH(chText("How to use this dashboard", strings.Replace(pgIntro, "each row answers one", "this dashboard keeps the history (ClickHouse) behind the Overview", 1)), 24, 7)
	b.row("Which query? (history)")
	b.addH(chText("Question 4", "The query shapes that used the most CPU over the chosen time range, with their waits. Fix culprits (large share), not victims (mostly waiting)."), 24, 2)
	top := chTable("Top digests", `SELECT s.digest_id AS digest, any(t.digest_text) AS text, sum(s.calls) AS callCount,
  sum(s.cpu_ns) / 1e9 / `+rangeS+` AS cpuCores,
  100 * sum(s.cpu_ns) / nullIf(`+hostSum("node_cpu_used_ns")+`, 0) AS pctNodeCpu,
  sum(s.disk_read_bytes) / `+rangeS+` / 1048576 AS readMBs,
  100 * sum(s.runq_ns) / greatest(sum(s.wall_ns), 1) AS cpuWaitPct,
  100 * sum(s.io_wait_ns) / nullIf(sumIf(s.wall_ns, s.io_wait_ns IS NOT NULL), 0) AS diskWaitPct,
  100 * sum(s.wal_wait_ns) / nullIf(sumIf(s.wall_ns, s.wal_wait_ns IS NOT NULL), 0) AS walWaitPct,
  100 * sum(s.shared_blks_hit) / nullIf(sum(s.shared_blks_hit) + sum(s.shared_blks_read), 0) AS hitPct,
  sum(s.temp_blks_written) * 8192 / `+rangeS+` / 1048576 AS tempMBs,
  max(s.disk_estimated) AS diskEstimated,
  sum(s.wall_ns) / greatest(sum(s.calls), 1) / 1e6 AS latencyMsAvg,
  max(s.wall_max_ns) / 1e6 AS latencyMsMax
FROM obs.pg_digest_stats AS s
LEFT JOIN (SELECT digest_id, digest_text FROM obs.pg_digest_text FINAL) AS t ON t.digest_id = s.digest_id
WHERE $__timeFilter(s.window_end) AND s.`+hostF+` AND s.cluster IN (${cluster:singlequote})
GROUP BY s.digest_id ORDER BY cpuCores DESC LIMIT 50`)
	top.FieldConfig = withColumnUnits(top.FieldConfig, map[string]string{"cpuCores": "short", "pctNodeCpu": "percent",
		"cpuWaitPct": "percent", "diskWaitPct": "percent", "walWaitPct": "percent", "hitPct": "percent",
		"readMBs": "MiBs", "tempMBs": "MiBs", "latencyMsAvg": "ms", "latencyMsMax": "ms"})
	b.add(explained(top,
		"the heaviest query shapes over the selected time range: cores, share of node CPU, disk, waits, cache hits, temp spill, latency.",
		"one digest with a large pctNodeCpu is a culprit; high cpuWaitPct / diskWaitPct / walWaitPct with low CPU marks a victim.",
		"hitPct well below 99% = reads miss shared_buffers; tempMBs > 0 = sorts spill to disk (raise work_mem for that query).",
		"per digest: cpu_ns ÷ range s; ÷ host_stats node CPU × 100; waits ÷ wall of the intervals that measured them; hit = hit ÷ (hit + read)."), 24)
	b.add(explained(chTS("CPU of the top 10 digests (cores)", "short", `SELECT `+flushBucket+` AS time, digest_id AS digest, sum(cpu_ns) / 1e9 / `+flushBucketS+` AS cores
FROM obs.pg_digest_stats
WHERE $__timeFilter(window_end) AND `+pgHost+`
  AND digest_id IN (SELECT digest_id FROM obs.pg_digest_stats WHERE $__timeFilter(window_end) AND `+pgHost+` GROUP BY digest_id ORDER BY sum(cpu_ns) DESC LIMIT 10)
GROUP BY time, digest ORDER BY time`),
		"CPU cores used over time by the ten heaviest query shapes.",
		"steady lines are normal; a line that jumps at the incident time is the suspect.",
		"put that digest_id into the 'digest' variable to see its calls and latency.",
		"Σ cpu_ns per flush interval ÷ interval seconds."), 24)

	b.row("Queries or background work? (history)")
	b.addH(chText("Question 3", "PostgreSQL's own processes over time: client backends run queries; autovacuum, checkpointer and I/O workers are background work with their own fixes."), 24, 2)
	b.add(explained(chTS("CPU by backend type (cores)", "short", `SELECT `+flushBucket+` AS time, backend_type, sum(cpu_ns) / 1e9 / `+flushBucketS+` AS cores
FROM obs.pg_backend_stats WHERE $__timeFilter(window_end) AND `+pgHost+`
GROUP BY time, backend_type ORDER BY time`),
		"CPU cores used by each kind of PostgreSQL process over time.",
		"client usually on top; autovacuum or checkpointer rising during the incident points at background work.",
		"autovacuum: check bloat and cost limits; checkpointer: raise max_wal_size.",
		"Σ pg_backend_stats.cpu_ns per flush interval ÷ interval seconds."), 12)
	b.add(explained(chTS("Disk reads by backend type (MB/s)", "MiBs", `SELECT `+flushBucket+` AS time, backend_type, sum(disk_read_bytes) / `+flushBucketS+` / 1048576 AS read
FROM obs.pg_backend_stats WHERE $__timeFilter(window_end) AND `+pgHost+`
GROUP BY time, backend_type ORDER BY time`),
		"storage reads of each kind of PostgreSQL process over time.",
		"on PostgreSQL 18+ io_worker carries the reads of queries; a rise matches query reads.",
		"see 'Estimated disk reads per digest' below to split io_worker reads per query.",
		"Σ pg_backend_stats.disk_read_bytes per flush interval ÷ interval seconds (NULL when process.include_io is off)."), 12)
	b.add(explained(chTable("Estimated disk reads per digest (PostgreSQL 18+)", `SELECT r.digest_id AS digest, r.cluster AS clusterName,
  io.io_bytes * r.sr / nullIf(tot.total, 0) / `+rangeS+` / 1048576 AS estReadMBs
FROM (SELECT host, cluster, digest_id, sum(shared_blks_read) AS sr FROM obs.pg_digest_stats
      WHERE $__timeFilter(window_end) AND `+pgHost+` AND disk_estimated = 1 GROUP BY host, cluster, digest_id) AS r
INNER JOIN (SELECT host, cluster, sum(shared_blks_read) AS total FROM obs.pg_digest_stats
            WHERE $__timeFilter(window_end) AND `+pgHost+` AND disk_estimated = 1 GROUP BY host, cluster) AS tot ON tot.host = r.host AND tot.cluster = r.cluster
INNER JOIN (SELECT host, cluster, sum(disk_read_bytes) AS io_bytes FROM obs.pg_backend_stats
            WHERE $__timeFilter(window_end) AND `+pgHost+` AND backend_type = 'io_worker' GROUP BY host, cluster) AS io ON io.host = r.host AND io.cluster = r.cluster
ORDER BY estReadMBs DESC LIMIT 20`),
		"on PostgreSQL 18+ (reads done by I/O workers), each query's estimated share of the disk reads.",
		"empty on PostgreSQL 16/17 or without postgres.sql — then use readMBs in Top digests.",
		"treat the top rows like disk culprits: check their plans and indexes.",
		"io_worker read bytes × digest shared_blks_read ÷ all shared_blks_read, ÷ range seconds."), 24)

	b.row("Digest drill-down and slow statements")
	b.addH(chText("Question 5", "Type a digest id in the 'digest' variable to follow one query shape; the slow statements table shows single slow executions and whether they ran or waited."), 24, 2)
	b.add(explained(chTS("Calls and latency of the selected digest", "short", `SELECT `+flushBucket+` AS time, sum(calls) / `+flushBucketS+` AS callsPerSec,
  sum(wall_ns) / greatest(sum(calls), 1) / 1e6 AS latencyMsAvg
FROM obs.pg_digest_stats WHERE $__timeFilter(window_end) AND `+pgHost+` AND digest_id = '${digest}'
GROUP BY time ORDER BY time`),
		"calls per second and average latency of the digest typed in the 'digest' variable.",
		"latency rising while calls stay flat means the query waits more (see the wait columns in Top digests).",
		"if calls rose, find the application that sends it.",
		"Σ calls ÷ interval seconds; Σ wall_ns ÷ Σ calls."), 24)
	b.add(explained(chTable("Slow statements", `SELECT ts, host, cluster, pid, latency_ms, cpu_ms, digest_id, query
FROM obs.pg_slow_queries WHERE $__timeFilter(ts) AND `+pgHost+`
ORDER BY latency_ms DESC LIMIT 200`),
		"the slowest single client statements in the range (one row per slow execution).",
		"many rows of the same digest at the incident time point at it; a slow row with little cpu_ms waited.",
		"compare cpu_ms with latency_ms: mostly CPU = the query itself is heavy; mostly waiting = a victim.",
		"pg_slow_queries rows with latency ≥ postgres.slow_query_threshold_ms; query is digest text unless raw samples are allowed."), 24)
	d.Panels = b.done()
	return d
}
