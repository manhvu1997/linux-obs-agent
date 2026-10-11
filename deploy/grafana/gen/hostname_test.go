package main

import (
	"fmt"
	"strings"
	"testing"
)

func varByName(d Dashboard, name string) (Var, int, bool) {
	for i, v := range d.Templating.List {
		if v.Name == name {
			return v, i, true
		}
	}
	return Var{}, -1, false
}

// Every dashboard is selected by hostname first: the visible "host" variable
// comes right after the datasource variable.
func TestDashboardsSelectByHostname(t *testing.T) {
	for file, d := range dashboards() {
		v, i, ok := varByName(d, "host")
		if !ok {
			t.Errorf("%s: no host variable", file)
			continue
		}
		if i != 1 || v.Label != "Hostname" || v.Hide != 0 || !v.Multi || !v.IncludeAll {
			t.Errorf("%s: host variable = %+v at %d, want the visible multi-value 'Hostname' variable right after the datasource", file, v, i)
		}
	}
}

// Overview instances follow the chosen hostnames (obs_agent_host_info), and
// the host list comes from the always-on metric, not the ClickHouse one.
func TestOverviewInstancesFollowHostname(t *testing.T) {
	for _, file := range []string{"obs-agent-overview.json", "obs-agent-postgres-overview.json"} {
		d := dashboards()[file]
		h, _, _ := varByName(d, "host")
		q := fmt.Sprint(h.Query)
		if !strings.Contains(q, "obs_agent_host_info") || strings.Contains(q, "clickhouse_host_info") {
			t.Errorf("%s: host variable query %q, want obs_agent_host_info", file, q)
		}
		in, _, ok := varByName(d, "instance")
		iq := fmt.Sprint(in.Query)
		if !ok || !strings.Contains(iq, "obs_agent_host_info") || !strings.Contains(iq, `host=~"$host"`) {
			t.Errorf("%s: instance variable query %q, want obs_agent_host_info filtered by $host", file, iq)
		}
	}
	// PostgreSQL lists only hosts and instances that run the tracer.
	d := dashboards()["obs-agent-postgres-overview.json"]
	for _, name := range []string{"host", "instance"} {
		v, _, _ := varByName(d, name)
		if q := fmt.Sprint(v.Query); !strings.Contains(q, "obs_agent_postgres_tracing_active") {
			t.Errorf("postgres overview %s variable %q does not restrict to PostgreSQL hosts", name, q)
		}
	}
}

// Links between Overview and Analysis carry the chosen hostnames.
func TestLinksCarryHost(t *testing.T) {
	for file, d := range dashboards() {
		for _, l := range d.Links {
			if u, _ := l["url"].(string); !strings.Contains(u, "${host:queryparam}") {
				t.Errorf("%s: link %q does not pass ${host:queryparam}", file, u)
			}
		}
	}
}

func panelByTitle(d Dashboard, title string) (Panel, bool) {
	for _, p := range d.Panels {
		if p.Title == title {
			return p, true
		}
	}
	return Panel{}, false
}

// The backend-type CPU chart is a share of the node, not of the cluster:
// 90 % client must mean 90 % of the machine.
func TestBackendCPUIsShareOfNode(t *testing.T) {
	d := dashboards()["obs-agent-postgres-overview.json"]
	for _, p := range d.Panels {
		if strings.Contains(p.Title, "% of cluster") {
			t.Errorf("panel %q still plots a share of the cluster", p.Title)
		}
	}
	p, ok := panelByTitle(d, "CPU by backend type (% of node CPU)")
	if !ok {
		t.Fatal("no 'CPU by backend type (% of node CPU)' panel")
	}
	var perType, node bool
	for _, tg := range p.Targets {
		perType = perType || (strings.Contains(tg.Expr, "obs_agent_postgres_backend_cpu_seconds_total") && strings.Contains(tg.Expr, "obs_agent_cpu_count"))
		node = node || strings.Contains(tg.Expr, "obs_agent_cpu_usage_percent")
	}
	if !perType || !node {
		t.Errorf("targets %+v: want backend CPU ÷ cpu_count and a node CPU used line", p.Targets)
	}
	if strings.Contains(p.Description, "Alert: ") {
		t.Error("the % of node chart must not carry the share-of-cluster alert line")
	}
	bg, ok := panelByTitle(d, "Background share of PostgreSQL CPU")
	if !ok || !strings.Contains(bg.Description, "Alert: PostgresBackgroundCPUHigh (") {
		t.Error("the PostgresBackgroundCPUHigh line must be on 'Background share of PostgreSQL CPU'")
	}
}

// PostgreSQL shows who talks to it, like MySQL: inbound clients and outbound
// peers of the PostgreSQL family, live (Prometheus) and history (ClickHouse).
func TestPostgresPeerPanels(t *testing.T) {
	ov := dashboards()["obs-agent-postgres-overview.json"]
	if v, _, ok := varByName(ov, "pg_family"); !ok || !strings.Contains(v.Regex, "postgres") {
		t.Errorf("postgres overview pg_family variable = %+v", v)
	}
	for title, metric := range map[string]string{
		"Top inbound clients of PostgreSQL":   "obs_agent_family_inbound_peer_bytes_total",
		"Top outbound peers of PostgreSQL":    "obs_agent_family_outbound_peer_bytes_total",
		"PostgreSQL connections by direction": "obs_agent_family_net_connections_active",
	} {
		p, ok := panelByTitle(ov, title)
		if !ok || len(p.Targets) == 0 || !strings.Contains(p.Targets[0].Expr, metric) || !strings.Contains(p.Targets[0].Expr, `family=~"$pg_family"`) {
			t.Errorf("postgres overview panel %q missing or not on %s for $pg_family", title, metric)
		}
	}
	an := dashboards()["obs-agent-postgres-analysis.json"]
	if _, _, ok := varByName(an, "pg_family"); !ok {
		t.Error("postgres analysis has no pg_family variable")
	}
	for _, title := range []string{"Top inbound clients of PostgreSQL", "Top outbound peers of PostgreSQL"} {
		p, ok := panelByTitle(an, title)
		if !ok || !strings.Contains(p.Targets[0].RawSQL, "obs.netflow_peer_stats") || !strings.Contains(p.Targets[0].RawSQL, "${pg_family:singlequote}") {
			t.Errorf("postgres analysis panel %q missing or not on netflow_peer_stats for $pg_family", title)
		}
	}
}

// The live Top digests tables are one row per host: every column joins the
// hostname from obs_agent_host_info, and shares divide by that host's node.
func TestTopDigestTablesPerHost(t *testing.T) {
	for _, file := range []string{"obs-agent-overview.json", "obs-agent-postgres-overview.json"} {
		p, ok := panelByTitle(dashboards()[file], "Top digests (last 5m)")
		if !ok {
			t.Fatalf("%s: no 'Top digests (last 5m)' table", file)
		}
		for _, tg := range p.Targets {
			if !strings.Contains(tg.Expr, "group_left (host) obs_agent_host_info") {
				t.Errorf("%s target %s: no hostname join: %s", file, tg.RefID, tg.Expr)
			}
			if strings.Contains(tg.Expr, "scalar(") {
				t.Errorf("%s target %s divides by a total over all hosts: %s", file, tg.RefID, tg.Expr)
			}
		}
	}
}
