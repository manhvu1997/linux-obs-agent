package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

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

func isVar(uid string) bool { return uid == "${DS_PROMETHEUS}" || uid == "${DS_CLICKHOUSE}" }

// dsViolations lists every panel, target and template variable of d whose
// datasource uid is not one of the import variables.
func dsViolations(d Dashboard) []string {
	var v []string
	for _, p := range d.Panels {
		if p.Type == "row" {
			continue
		}
		if !isVar(p.Datasource.UID) {
			v = append(v, "panel "+p.Title+": "+p.Datasource.UID)
		}
		for _, tg := range p.Targets {
			if !isVar(tg.Datasource.UID) {
				v = append(v, "target of "+p.Title+": "+tg.Datasource.UID)
			}
		}
	}
	for _, tv := range d.Templating.List {
		if tv.Datasource != nil && !isVar(tv.Datasource.UID) {
			v = append(v, "variable "+tv.Name+": "+tv.Datasource.UID)
		}
	}
	return v
}

func TestPanelsUseDatasourceVariables(t *testing.T) {
	for name, d := range dashboards() {
		if v := dsViolations(d); len(v) > 0 {
			t.Errorf("%s: hard-coded datasources: %v", name, v)
		}
	}
}

func TestDatasourceCheckRejectsHardCodedUID(t *testing.T) {
	bad := DS{"prometheus", "abc123"}
	var d Dashboard
	d.Panels = []Panel{{Type: "timeseries", Title: "p", Datasource: promDS, Targets: []Target{{Datasource: bad}}}}
	d.Templating.List = []Var{{Name: "v", Datasource: &bad}}
	if v := dsViolations(d); len(v) != 2 {
		t.Fatalf("want 2 violations, got %v", v)
	}
	d.Panels[0].Datasource = bad
	if v := dsViolations(d); len(v) != 3 {
		t.Fatalf("want 3 violations, got %v", v)
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
	"length": true, "any": true,
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
		"SELECT window_start FROM obs.mysql_slow_queries WHERE $__timeFilter(ts)", // column of another table
		"SELECT digest_idd FROM obs.mysql_digest_stats",                           // typo
		"SELECT host FROM obs.no_such_table",                                      // unknown table
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
