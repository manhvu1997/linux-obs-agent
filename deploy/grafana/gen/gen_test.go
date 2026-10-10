package main

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/manhvu1997/linux-obs-agent/internal/chsink"
)

func TestGeneratedFilesUpToDate(t *testing.T) {
	for name, d := range dashboards() {
		want, err := render(d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile("../" + name)
		if err != nil || string(got) != string(want) {
			t.Fatalf("deploy/grafana/%s is stale; run: go run ./deploy/grafana/gen", name)
		}
	}
}

// dsVars returns the "${name}" references of d's datasource-type template
// variables: the only datasource uids panels and queries may use.
func dsVars(d Dashboard) map[string]bool {
	m := map[string]bool{}
	for _, tv := range d.Templating.List {
		if tv.Type == "datasource" {
			m["${"+tv.Name+"}"] = true
		}
	}
	return m
}

// dsViolations lists every panel, target and template variable of d whose
// datasource uid is not one of d's own datasource variables.
func dsViolations(d Dashboard) []string {
	ok := dsVars(d)
	var v []string
	for _, p := range d.Panels {
		if p.Type == "row" {
			continue
		}
		if !ok[p.Datasource.UID] {
			v = append(v, "panel "+p.Title+": "+p.Datasource.UID)
		}
		for _, tg := range p.Targets {
			if !ok[tg.Datasource.UID] {
				v = append(v, "target of "+p.Title+": "+tg.Datasource.UID)
			}
		}
	}
	for _, tv := range d.Templating.List {
		if tv.Datasource != nil && !ok[tv.Datasource.UID] {
			v = append(v, "variable "+tv.Name+": "+tv.Datasource.UID)
		}
	}
	return v
}

func TestPanelsUseDatasourceVariables(t *testing.T) {
	for name, d := range dashboards() {
		if v := dsViolations(d); len(v) > 0 {
			t.Errorf("%s: datasources not bound to the dashboard's datasource variable: %v", name, v)
		}
	}
}

func TestDatasourceCheckRejectsHardCodedUID(t *testing.T) {
	bad := DS{"prometheus", "abc123"}
	var d Dashboard
	d.Templating.List = []Var{{Name: "ds_prometheus", Type: "datasource", Query: "prometheus"}, {Name: "v", Datasource: &bad}}
	d.Panels = []Panel{{Type: "timeseries", Title: "p", Datasource: promDS, Targets: []Target{{Datasource: bad}}}}
	if v := dsViolations(d); len(v) != 2 {
		t.Fatalf("want 2 violations, got %v", v)
	}
	d.Panels[0].Datasource = bad
	if v := dsViolations(d); len(v) != 3 {
		t.Fatalf("want 3 violations, got %v", v)
	}
	// A leftover import placeholder is a violation too.
	d.Panels[0].Datasource = DS{"prometheus", "${DS_PROMETHEUS}"}
	if v := dsViolations(d); len(v) != 3 {
		t.Fatalf("${DS_PROMETHEUS} must be rejected, got %v", v)
	}
}

// Each dashboard picks its datasource at view time: exactly one datasource
// variable, listed first so the query variables after it can use it.
func TestDatasourceVariable(t *testing.T) {
	want := map[string]struct{ name, plugin string }{
		"obs-agent-overview.json": {"ds_prometheus", "prometheus"},
		"obs-agent-analysis.json": {"ds_clickhouse", "grafana-clickhouse-datasource"},
	}
	for file, d := range dashboards() {
		w := want[file]
		var ds []Var
		for _, tv := range d.Templating.List {
			if tv.Type == "datasource" {
				ds = append(ds, tv)
			}
		}
		if len(ds) != 1 || ds[0].Name != w.name || ds[0].Query != w.plugin {
			t.Fatalf("%s: datasource variables = %+v, want one %s for plugin %s", file, ds, w.name, w.plugin)
		}
		if d.Templating.List[0].Name != w.name {
			t.Errorf("%s: %s must be the first template variable", file, w.name)
		}
		b, err := render(d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"__inputs"`) || strings.Contains(string(b), "${DS_") {
			t.Errorf("%s: still contains import-time datasource inputs", file)
		}
	}
}

var (
	macroRe  = regexp.MustCompile(`\$__\w+|\$\{[^}]*\}|'[^']*'`)
	tableRe  = regexp.MustCompile(`obs\.([a-z_0-9]+)`)
	qualRe   = regexp.MustCompile(`\b\w+\.`)
	identRe  = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)
	aliasRe  = regexp.MustCompile(`(?i)\bAS\s+([A-Za-z_]\w*)`)
	colRe    = regexp.MustCompile(`^\s+([a-z_][a-z_0-9]*)\s+\S`)
	createRe = regexp.MustCompile(`CREATE TABLE IF NOT EXISTS obs\.([a-z_0-9]+)`)
)

// sqlWords is the allow-list of lowercase SQL keywords and functions that may
// appear in the dashboard queries. Anything else lowercase must be a column of
// a table the same query reads from, or an alias declared with AS. Tokens with
// an uppercase letter (camelCase aliases, sumIf, toString, ...) are skipped.
var sqlWords = map[string]bool{
	"select": true, "distinct": true, "from": true, "where": true, "and": true, "or": true,
	"not": true, "in": true, "as": true, "left": true, "join": true, "on": true, "group": true,
	"by": true, "order": true, "desc": true, "asc": true, "limit": true, "having": true,
	"interval": true, "day": true, "hour": true, "final": true, "using": true, "between": true,
	"sum": true, "avg": true, "max": true, "min": true, "count": true, "greatest": true,
	"length": true, "any": true, "if": true,
}

// parseSchema maps table -> column set from the CREATE TABLE statements.
func parseSchema(ddl string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	var cur map[string]bool
	for _, line := range strings.Split(ddl, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		if m := createRe.FindStringSubmatch(line); m != nil {
			cur = map[string]bool{}
			out[m[1]] = cur
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, ")") {
			cur = nil
			continue
		}
		if m := colRe.FindStringSubmatch(line); m != nil {
			cur[m[1]] = true
		}
	}
	return out
}

// sqlViolations checks one query against the schema.
func sqlViolations(sql string, schema map[string]map[string]bool) []string {
	var v []string
	sql = macroRe.ReplaceAllString(sql, " ")
	cols := map[string]bool{}
	for _, m := range tableRe.FindAllStringSubmatch(sql, -1) {
		tc, ok := schema[m[1]]
		if !ok {
			v = append(v, "unknown table obs."+m[1])
			continue
		}
		for c := range tc {
			cols[c] = true
		}
	}
	aliases := map[string]bool{}
	for _, m := range aliasRe.FindAllStringSubmatch(sql, -1) {
		aliases[m[1]] = true
		// A ClickHouse alias is visible in the whole SELECT and shadows the
		// column: `sum(calls) AS calls, sum(cpu_ns) / sum(calls)` becomes
		// sum(sum(calls)) and fails with ILLEGAL_AGGREGATION.
		if cols[m[1]] {
			v = append(v, "alias "+m[1]+" shadows a column")
		}
	}
	sql = tableRe.ReplaceAllString(sql, " ")
	sql = qualRe.ReplaceAllString(sql, " ")
	for _, id := range identRe.FindAllString(sql, -1) {
		if id != strings.ToLower(id) || sqlWords[id] || aliases[id] || cols[id] {
			continue
		}
		v = append(v, "unknown identifier "+id)
	}
	return v
}

func TestClickHouseSQLReferencesSchema(t *testing.T) {
	ddl, err := chsink.CreateDDL(chsink.DefaultSchemaOptions())
	if err != nil {
		t.Fatal(err)
	}
	schema := parseSchema(ddl)
	if len(schema) < 5 {
		t.Fatalf("schema parse found only %d tables", len(schema))
	}
	d := dashboards()["obs-agent-analysis.json"]
	for _, p := range d.Panels {
		for _, tg := range p.Targets {
			for _, msg := range sqlViolations(tg.RawSQL, schema) {
				t.Errorf("panel %q: %s", p.Title, msg)
			}
			if !strings.Contains(tg.RawSQL, "$__timeFilter(") {
				t.Errorf("panel %q: query has no $__timeFilter", p.Title)
			}
		}
	}
	for _, tv := range d.Templating.List {
		if tv.Type == "query" {
			if s, _ := tv.Query.(string); s != "" {
				for _, msg := range sqlViolations(s, schema) {
					t.Errorf("variable %s: %s", tv.Name, msg)
				}
			}
		}
	}
}

func TestSQLCheckerRejectsBogusQueries(t *testing.T) {
	ddl, _ := chsink.CreateDDL(chsink.DefaultSchemaOptions())
	schema := parseSchema(ddl)
	bad := []string{
		"SELECT window_start FROM obs.mysql_slow_queries WHERE $__timeFilter(ts)",               // column of another table
		"SELECT digest_idd FROM obs.mysql_digest_stats",                                         // typo
		"SELECT host FROM obs.no_such_table",                                                    // unknown table
		"SELECT sum(calls) AS calls, sum(cpu_ns) / sum(calls) AS c FROM obs.mysql_digest_stats", // alias shadows column
	}
	for _, q := range bad {
		if len(sqlViolations(q, schema)) == 0 {
			t.Errorf("checker accepted %q", q)
		}
	}
}

func TestJSONIsValidDashboard(t *testing.T) {
	for name, d := range dashboards() {
		b, _ := render(d)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: invalid dashboard JSON: %v", name, err)
		}
		if title, _ := m["title"].(string); title == "" {
			t.Fatalf("%s: missing title", name)
		}
		if uid, _ := m["uid"].(string); uid == "" {
			t.Fatalf("%s: missing uid", name)
		}
	}
}

// Interval tables hold one row per flush_interval (60 s by default). A time
// series bucketed by Grafana's $__interval (≈20 s on a 6 h range) puts one
// whole row into some buckets and none into others, so dividing by
// $__interval_s overstated a rate by flush_interval / $__interval. Every
// panel over window_end must bucket by at least the flush interval.
func TestIntervalPanelsBucketByFlushInterval(t *testing.T) {
	bareInterval := regexp.MustCompile(`/\s*\$__interval_s`)
	d := dashboards()["obs-agent-analysis.json"]
	for _, p := range d.Panels {
		for _, tg := range p.Targets {
			if !strings.Contains(tg.RawSQL, "window_end") {
				continue
			}
			if strings.Contains(tg.RawSQL, "$__timeInterval(window_end)") {
				t.Errorf("panel %q: buckets interval rows by $__timeInterval; use flushBucket", p.Title)
			}
			if bareInterval.MatchString(tg.RawSQL) {
				t.Errorf("panel %q: divides by bare $__interval_s; use flushBucketS", p.Title)
			}
		}
	}
	var flush *Var
	for i, tv := range d.Templating.List {
		if tv.Name == "flush_s" {
			flush = &d.Templating.List[i]
		}
	}
	if flush == nil || flush.Type != "constant" || flush.Query != "60" {
		t.Fatalf("want a constant flush_s variable defaulting to 60, got %+v", flush)
	}
}

func TestTopDigestsHasPeakCores(t *testing.T) {
	for _, p := range dashboards()["obs-agent-analysis.json"].Panels {
		if p.Title == "Top digests" {
			if !strings.Contains(p.Targets[0].RawSQL, "AS peakCores") {
				t.Fatal("Top digests has no peakCores column")
			}
			return
		}
	}
	t.Fatal("Top digests panel not found")
}

func TestOverviewHasMySQLCPUCoverage(t *testing.T) {
	d := dashboards()["obs-agent-overview.json"]
	found := false
	for _, p := range d.Panels {
		if p.Title != "MySQL query CPU vs mysqld CPU (cores)" {
			continue
		}
		found = true
		var all string
		for _, tg := range p.Targets {
			all += tg.Expr + "\n"
		}
		for _, want := range []string{"obs_agent_mysql_query_cpu_seconds_total", "obs_agent_cpu_count", `family=~"$mysql_family"`} {
			if !strings.Contains(all, want) {
				t.Errorf("coverage panel does not use %s", want)
			}
		}
	}
	if !found {
		t.Fatal("overview has no MySQL query CPU vs mysqld CPU panel")
	}
	for _, tv := range d.Templating.List {
		if tv.Name == "mysql_family" {
			if tv.Regex == "" || !tv.IncludeAll {
				t.Errorf("mysql_family must default to a regex-filtered All, got %+v", tv)
			}
			return
		}
	}
	t.Error("overview has no mysql_family variable")
}

// Every panel states what it computes and how to read it (spec §7.4).
func TestPanelsDescribeFormulaAndReading(t *testing.T) {
	for name, d := range dashboards() {
		for _, p := range d.Panels {
			if p.Type == "row" || p.Type == "text" || p.Type == "alertlist" {
				continue
			}
			if !strings.Contains(p.Description, "Formula:") || !strings.Contains(p.Description, "Reading:") {
				t.Errorf("%s: panel %q lacks a Formula:/Reading: description", name, p.Title)
			}
		}
	}
}

type ruleFile struct {
	Groups []struct {
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

func readRuleFile(t *testing.T) ruleFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "prometheus", "obs-agent-alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var rf ruleFile
	if err := yaml.Unmarshal(b, &rf); err != nil {
		t.Fatal(err)
	}
	return rf
}

// A panel behind an alert draws the alert's threshold as a dashed line, names
// the alert and its severity, and both agree with the rule file.
func TestAlertPanelsMatchRules(t *testing.T) {
	rf := readRuleFile(t)
	rules := map[string]struct{ expr, severity string }{}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			rules[r.Alert] = struct{ expr, severity string }{r.Expr, r.Labels["severity"]}
		}
	}
	for _, ar := range alertRules {
		r, ok := rules[ar.Name]
		if !ok {
			t.Errorf("alertRules names %s, which is not in the rule file", ar.Name)
			continue
		}
		if r.severity != ar.Severity {
			t.Errorf("%s: severity %q in gen, %q in rules", ar.Name, ar.Severity, r.severity)
		}
		if !strings.Contains(r.expr, ar.Literal) {
			t.Errorf("%s: threshold literal %q not in the rule expression", ar.Name, ar.Literal)
		}
	}
	used := map[string]bool{}
	for _, p := range dashboards()["obs-agent-overview.json"].Panels {
		for _, ar := range alertRules {
			if !strings.Contains(p.Description, "Alert: "+ar.Name+" (") {
				continue
			}
			used[ar.Name] = true
			if got := thresholdOf(p); got != ar.Threshold {
				t.Errorf("panel %q: threshold line %v, alert %s fires at %v", p.Title, got, ar.Name, ar.Threshold)
			}
			d, _ := p.FieldConfig["defaults"].(map[string]any)
			custom, _ := d["custom"].(map[string]any)
			style, _ := custom["thresholdsStyle"].(map[string]any)
			if style["mode"] != "dashed" {
				t.Errorf("panel %q: threshold style %v, want dashed", p.Title, style["mode"])
			}
			// The side of the line where the alert fires is red.
			wantLow, wantHigh := "green", "red"
			if ar.Below {
				wantLow, wantHigh = "red", "green"
			}
			if lo, hi := thresholdColors(p); lo != wantLow || hi != wantHigh {
				t.Errorf("panel %q: colours %s below / %s above the line, want %s / %s", p.Title, lo, hi, wantLow, wantHigh)
			}
			// The line is the rule's literal in the panel's unit.
			want, ok := literalThreshold(ar.Literal)
			if !ok {
				t.Errorf("%s: cannot read a number from literal %q", ar.Name, ar.Literal)
				continue
			}
			if u, _ := d["unit"].(string); u == "percent" {
				want *= 100
			}
			if strings.HasPrefix(strings.TrimSpace(ar.Literal), "==") {
				// A 0/1 gauge compared for equality: the line sits half-way to the other state.
				if math.Abs(ar.Threshold-want) != 0.5 {
					t.Errorf("%s: line %v does not separate %v from the other state", ar.Name, ar.Threshold, want)
				}
			} else if math.Abs(ar.Threshold-want) > 1e-9 {
				t.Errorf("%s: literal %q is %v in the panel unit, Threshold is %v", ar.Name, ar.Literal, want, ar.Threshold)
			}
		}
	}
	for _, ar := range alertRules {
		if ar.Panel && !used[ar.Name] {
			t.Errorf("no Overview panel draws alert %s", ar.Name)
		}
	}
}

var literalRe = regexp.MustCompile(`(?:>=|<=|==|!=|>|<)\s*([0-9.e+]+(?:\s*\*\s*[0-9.e+]+)*)\s*$`)

// literalThreshold evaluates the number of a rule literal such as "> 0.3",
// "== 0" or "> 10 * 1048576" (a product of numbers after the last comparison).
func literalThreshold(lit string) (float64, bool) {
	m := literalRe.FindStringSubmatch(strings.TrimSpace(lit))
	if m == nil {
		return 0, false
	}
	v := 1.0
	for _, f := range strings.Split(m[1], "*") {
		x, err := strconv.ParseFloat(strings.TrimSpace(f), 64)
		if err != nil {
			return 0, false
		}
		v *= x
	}
	return v, true
}

func TestLiteralThreshold(t *testing.T) {
	for lit, want := range map[string]float64{"> 0.3": 0.3, "== 0": 0, "> 10 * 1048576": 10 * 1048576, "increase(x[10m]) > 0": 0} {
		if got, ok := literalThreshold(lit); !ok || got != want {
			t.Errorf("literalThreshold(%q) = %v %v, want %v", lit, got, ok, want)
		}
	}
	if _, ok := literalThreshold("rate(x[5m])"); ok {
		t.Error("a literal without a comparison must not parse")
	}
}

// thresholdColors returns the colours below and above a panel's line.
func thresholdColors(p Panel) (string, string) {
	d, _ := p.FieldConfig["defaults"].(map[string]any)
	th, _ := d["thresholds"].(map[string]any)
	steps, _ := th["steps"].([]any)
	if len(steps) < 2 {
		return "", ""
	}
	lo, _ := steps[0].(map[string]any)["color"].(string)
	hi, _ := steps[1].(map[string]any)["color"].(string)
	return lo, hi
}

// thresholdOf returns the red step of a panel's dashed threshold, or -1.
func thresholdOf(p Panel) float64 {
	d, _ := p.FieldConfig["defaults"].(map[string]any)
	th, _ := d["thresholds"].(map[string]any)
	steps, _ := th["steps"].([]any)
	if len(steps) < 2 {
		return -1
	}
	v, _ := steps[1].(map[string]any)["value"].(float64)
	return v
}

func TestOverviewTopRows(t *testing.T) {
	ps := dashboards()["obs-agent-overview.json"].Panels
	if ps[0].Type != "alertlist" || ps[0].Title != "Firing obs-agent alerts" {
		t.Fatalf("first panel = %s %q, want the firing-alerts list", ps[0].Type, ps[0].Title)
	}
	titles := map[string]bool{}
	for _, p := range ps {
		titles[p.Title] = true
	}
	for _, want := range []string{"What is overloading this server?", "MySQL — who uses the server", "MySQL — who is waiting", "Agent health",
		"Top CPU digest — % of node CPU used", "Top disk-read digest — % of node disk reads", "Where query time goes (%)"} {
		if !titles[want] {
			t.Errorf("Overview lacks %q", want)
		}
	}
}

func TestAnalysisTopDigestsColumns(t *testing.T) {
	for _, p := range dashboards()["obs-agent-analysis.json"].Panels {
		if p.Title != "Top digests" {
			continue
		}
		for _, col := range []string{"cpuCores", "peakCores", "pctNodeCpu", "readMBs", "pctDiskRead", "pagesPerCall", "writeMBs",
			"cpuWaitPct", "diskWaitPct", "commitWaitPct", "latencyMsAvg", "latencyMsMax", "cpuRole", "ioRole", "victimOf"} {
			if !strings.Contains(p.Targets[0].RawSQL, "AS "+col) {
				t.Errorf("Top digests lacks column %s", col)
			}
		}
		return
	}
	t.Fatal("Analysis has no 'Top digests' panel")
}

// The alert runbooks send the operator to named Overview panels and to
// columns of the Analysis 'Top digests' table: every one of them must exist,
// matched by title prefix (a title may carry a unit suffix such as " (%)").
func TestRunbookPanelsExist(t *testing.T) {
	want := map[string]bool{}
	for _, s := range []string{"Where query time goes", "MySQL — who uses the server", "% of node CPU used by top digests",
		"% of node disk reads by top digests", "Commit wait share", "Query disk writes by command", "Disk average wait", "Disk utilisation"} {
		want[s] = true
	}
	// Plus every panel a runbook names as "Overview → '<title>'".
	ref := regexp.MustCompile(`Overview → '([^']+)'`)
	for _, g := range readRuleFile(t).Groups {
		for _, r := range g.Rules {
			for _, m := range ref.FindAllStringSubmatch(r.Annotations["description"], -1) {
				want[m[1]] = true
			}
		}
	}
	ov := dashboards()["obs-agent-overview.json"].Panels
	for w := range want {
		found := false
		for _, p := range ov {
			if strings.HasPrefix(p.Title, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("a runbook names Overview panel %q, which does not exist", w)
		}
	}
	for _, p := range dashboards()["obs-agent-analysis.json"].Panels {
		if p.Title == "Top digests" {
			for _, col := range []string{"cpuCores", "pctNodeCpu"} {
				if !strings.Contains(p.Targets[0].RawSQL, "AS "+col) {
					t.Errorf("a runbook names Analysis 'Top digests' column %s, which does not exist", col)
				}
			}
			return
		}
	}
	t.Error("a runbook names the Analysis 'Top digests' table, which does not exist")
}

var grafanaVarRe = regexp.MustCompile(`"\$\{?[a-z_]+\}?"`)

// promQL returns every Prometheus expression of the Overview with Grafana's
// macros replaced by values Prometheus accepts.
func promQL() map[string]string {
	r := strings.NewReplacer("$__rate_interval", "5m", "$__interval", "1m", "$__range", "1h")
	out := map[string]string{}
	for _, p := range dashboards()["obs-agent-overview.json"].Panels {
		for _, tg := range p.Targets {
			if tg.Expr == "" {
				continue
			}
			out[p.Title+" "+tg.RefID] = grafanaVarRe.ReplaceAllString(r.Replace(tg.Expr), `".*"`)
		}
	}
	return out
}

// Every Overview expression must parse. Prometheus has no offline parser in
// promtool's query command, so each expression is wrapped as a recording rule
// and checked with promtool check rules (skipped when promtool is absent; run
// the tests under devbox, which provides it).
func TestPromQLParses(t *testing.T) {
	bin, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool not on PATH; run: devbox run -- go test ./deploy/grafana/gen/")
	}
	exprs := promQL()
	if len(exprs) < 20 {
		t.Fatalf("found only %d expressions", len(exprs))
	}
	type rec struct {
		Record string `yaml:"record"`
		Expr   string `yaml:"expr"`
	}
	type group struct {
		Name  string `yaml:"name"`
		Rules []rec  `yaml:"rules"`
	}
	for name, e := range exprs {
		if strings.Contains(e, "$") {
			t.Errorf("%s: unreplaced Grafana variable in %s", name, e)
			continue
		}
		b, err := yaml.Marshal(map[string][]group{"groups": {{Name: "g", Rules: []rec{{Record: "x", Expr: e}}}}})
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "r.yaml")
		if err := os.WriteFile(f, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "check", "rules", f).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse:\n%s\n%s", name, e, out)
		}
	}
}

// The promtool check above must actually reject the parse trap it guards.
func TestPromQLCheckRejectsGroupLeftParenTrap(t *testing.T) {
	bin, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool not on PATH")
	}
	f := filepath.Join(t.TempDir(), "r.yaml")
	bad := "groups:\n  - name: g\n    rules:\n      - record: x\n        expr: a / on (instance) group_left (b / 100 * c)\n"
	if err := os.WriteFile(f, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(bin, "check", "rules", f).Run(); err == nil {
		t.Fatal("promtool accepted group_left followed by a parenthesised expression")
	}
}

// greatestArgs returns the argument text of every greatest(...) call in sql.
func greatestArgs(sql string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(sql[i:], "greatest(")
		if j < 0 {
			return out
		}
		start := i + j + len("greatest(")
		depth, k := 1, start
		for ; k < len(sql) && depth > 0; k++ {
			switch sql[k] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		out = append(out, sql[start:k-1])
		i = start
	}
}

// nodeTotalRe matches a value that comes from host_stats: the table itself,
// a column only host_stats has, or the h alias the share panels join it as.
var nodeTotalRe = regexp.MustCompile(`host_stats|node_cpu_used_ns|mysqld_cpu_ns|cpu_count|\bh\.`)

// greatest() ignores NULL arguments on ClickHouse >= 24.12, so greatest(x, 1)
// over an unmeasured (NULL) node total returns 1 and the share becomes
// ~100 × the numerator. Node-total denominators must use nullIf(x, 0).
func TestNodeTotalsNotGuardedByGreatest(t *testing.T) {
	d := dashboards()["obs-agent-analysis.json"]
	var sqls []string
	for _, p := range d.Panels {
		for _, tg := range p.Targets {
			sqls = append(sqls, tg.RawSQL)
		}
	}
	for _, tv := range d.Templating.List {
		if s, _ := tv.Query.(string); s != "" {
			sqls = append(sqls, s)
		}
	}
	for _, sql := range sqls {
		for _, a := range greatestArgs(sql) {
			if nodeTotalRe.MatchString(a) {
				t.Errorf("greatest() over a host_stats total (use nullIf(..., 0)): greatest(%s)", a)
			}
		}
	}
	if got := greatestArgs("greatest(sum(a), 1) + greatest((SELECT sum(b) FROM obs.host_stats), 1)"); len(got) != 2 || !nodeTotalRe.MatchString(got[1]) {
		t.Fatalf("greatestArgs self-check failed: %q", got)
	}
}

// Grafana expands a multi-value variable in the alert list's label filter with
// the glob format, which matches nothing on "All" with more than one instance.
func TestAlertListFilterUsesRegexFormat(t *testing.T) {
	for _, p := range dashboards()["obs-agent-overview.json"].Panels {
		if p.Type == "alertlist" {
			if f, _ := p.Options["alertInstanceLabelFilter"].(string); !strings.Contains(f, "${instance:regex}") {
				t.Errorf("alert list filter %q does not use ${instance:regex}", f)
			}
			return
		}
	}
	t.Fatal("no alert list")
}

// Without explicit thresholds Grafana colours a background stat red from 80,
// so a healthy high value would show red.
func TestBackgroundStatsHaveThresholds(t *testing.T) {
	for name, d := range dashboards() {
		for _, p := range d.Panels {
			if p.Type != "stat" || p.Options["colorMode"] != "background" {
				continue
			}
			def, _ := p.FieldConfig["defaults"].(map[string]any)
			th, _ := def["thresholds"].(map[string]any)
			if steps, _ := th["steps"].([]any); len(steps) == 0 {
				t.Errorf("%s: background stat %q has no explicit thresholds", name, p.Title)
			}
		}
	}
}

// A node that read nothing must give no point, not NaN or +Inf: every
// division by the node's disk read rate filters it with > 0.
func TestNodeDiskReadDenominatorGuarded(t *testing.T) {
	any := regexp.MustCompile(`rate\(obs_agent_node_disk_read_bytes_total\{[^}]*\}\[[^\]]+\]\)`)
	guarded := regexp.MustCompile(`\(rate\(obs_agent_node_disk_read_bytes_total\{[^}]*\}\[[^\]]+\]\) > 0\)`)
	n := 0
	for _, p := range dashboards()["obs-agent-overview.json"].Panels {
		for _, tg := range p.Targets {
			if !strings.Contains(tg.Expr, "digest_disk_read_bytes_total") {
				continue
			}
			all := len(any.FindAllString(tg.Expr, -1))
			if all == 0 {
				continue
			}
			n++
			if g := len(guarded.FindAllString(tg.Expr, -1)); g != all {
				t.Errorf("panel %q %s: node disk read denominator not guarded with > 0: %s", p.Title, tg.RefID, tg.Expr)
			}
		}
	}
	if n < 3 {
		t.Fatalf("found only %d digest ÷ node disk read expressions", n)
	}
}
