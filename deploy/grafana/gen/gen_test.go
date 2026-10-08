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

func TestPanelsUseDatasourceVariables(t *testing.T) {
	for name, d := range dashboards() {
		for _, p := range d.Panels {
			if p.Type == "row" {
				continue
			}
			if uid := p.Datasource.UID; uid != "${DS_PROMETHEUS}" && uid != "${DS_CLICKHOUSE}" {
				t.Errorf("%s / %q: datasource uid %q is not a variable", name, p.Title, uid)
			}
		}
	}
}

var (
	snakeRe = regexp.MustCompile(`\b[a-z]+(?:_[a-z0-9]+)+\b`)
	macroRe = regexp.MustCompile(`\$__\w+|\$\{[^}]*\}|'[^']*'`)
)

// Every snake_case identifier in a ClickHouse query must be a table or a
// column of schema.sql. Aliases are camelCase by convention, so a typo in a
// column name cannot hide as an alias.
func TestClickHouseSQLReferencesSchema(t *testing.T) {
	ddl, err := chsink.CreateDDL(chsink.DefaultSchemaOptions())
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, id := range snakeRe.FindAllString(ddl, -1) {
		known[id] = true
	}
	for _, p := range dashboards()["obs-agent-analysis.json"].Panels {
		for _, tg := range p.Targets {
			sql := macroRe.ReplaceAllString(tg.RawSQL, " ")
			for _, id := range snakeRe.FindAllString(sql, -1) {
				if !known[id] {
					t.Errorf("panel %q: %q is not a table or column in schema.sql", p.Title, id)
				}
			}
			if !strings.Contains(tg.RawSQL, "$__timeFilter(") {
				t.Errorf("panel %q: query has no $__timeFilter", p.Title)
			}
		}
	}
	for _, v := range dashboards()["obs-agent-analysis.json"].Templating.List {
		if v.Type == "query" {
			if s, _ := v.Query.(string); s != "" {
				for _, id := range snakeRe.FindAllString(macroRe.ReplaceAllString(s, " "), -1) {
					if !known[id] {
						t.Errorf("variable %s: %q unknown", v.Name, id)
					}
				}
			}
		}
	}
}

func TestJSONIsValidDashboard(t *testing.T) {
	for name, d := range dashboards() {
		b, _ := render(d)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil || m["title"] == "" || m["uid"] == "" {
			t.Fatalf("%s: invalid dashboard JSON: %v", name, err)
		}
	}
}
