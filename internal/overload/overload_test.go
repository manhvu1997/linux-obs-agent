package overload

import (
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func metrics(cpu, load1 float64, ncpu int) model.NodeMetrics {
	var m model.NodeMetrics
	m.CPU.UsagePercent = cpu
	m.LoadAvg.Load1 = load1
	m.LoadAvg.NumCPU = ncpu
	return m
}

func f(v float64) *float64 { return &v }

// report: the top digest did pct % of the node's CPU work; the node used nodeUsed % over the window.
func report(role string, pct, nodeUsed float64, victims int) *model.MySQLAnalysis {
	return &model.MySQLAnalysis{
		WindowSeconds:           60,
		Node:                    &model.MySQLNodeWindow{NumCPU: 8, CPUUsedCores: nodeUsed / 100 * 8, CPUUsedPercent: nodeUsed},
		QueryCPUCoveragePercent: f(58),
		Victims:                 map[string]int{"cpu": victims},
		Thresholds:              &model.QueryRoleThresholds{CPUCulpritPercentOfNodeCPUUsed: 20, CPUCulpritMinNodeCPUUsedPercent: 50},
		TopDigests: []model.QueryDigestStats{{
			PID: 42, DigestID: "abc", DigestText: "select * from t", Command: "query", SampleQuery: "select * from t where id = 7",
			CPUCores: pct / 100 * nodeUsed / 100 * 8, PercentOfNodeCPUUsed: f(pct), CallsPerSec: 40, BytesOutPerCall: 1300, CPURole: role,
		}},
	}
}

var (
	mysqlTop = []model.FamilyStats{{Family: "mysql.service", CPUPercent: 70}, {Family: "nginx.service", CPUPercent: 10}}
	nginxTop = []model.FamilyStats{{Family: "nginx.service", CPUPercent: 70}, {Family: "mysql.service", CPUPercent: 10}}
	pidFam   = map[uint32]string{42: "mysql.service"}
)

func TestVerdicts(t *testing.T) {
	cases := []struct {
		name     string
		m        model.NodeMetrics
		r        *model.MySQLAnalysis
		fams     []model.FamilyStats
		want     model.OverloadVerdict
		wantConf model.IOConfidence
	}{
		{"culprit, saturated, victims", metrics(20, 1, 8), report("culprit", 27, 90, 2), mysqlTop, model.OverloadQueryCPU, model.ConfidenceHigh},
		{"culprit, saturated, no victims", metrics(20, 1, 8), report("culprit", 27, 90, 0), mysqlTop, model.OverloadQueryCPU, model.ConfidenceMedium},
		{"culprit, saturated, no families", metrics(20, 1, 8), report("culprit", 27, 90, 1), nil, model.OverloadQueryCPU, model.ConfidenceLow},
		{"saturated by load only", metrics(20, 16, 8), report("culprit", 27, 60, 1), mysqlTop, model.OverloadQueryCPU, model.ConfidenceHigh},
		{"idle node", metrics(90, 1, 8), report("", 90, 5, 0), mysqlTop, model.OverloadNodeNotSaturated, model.ConfidenceHigh},
		{"another family burns the CPU", metrics(20, 1, 8), report("culprit", 27, 90, 1), nginxTop, model.OverloadNotMySQL, model.ConfidenceHigh},
		{"spread over many digests", metrics(20, 1, 8), report("", 9, 90, 1), mysqlTop, model.OverloadNoDominantQuery, model.ConfidenceHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := Inputs{Metrics: c.m, MySQL: c.r, Families: c.fams}
			if c.fams != nil {
				in.PIDFamilies = pidFam
			}
			got := Assess(in, Thresholds{}, time.Unix(0, 0))
			if got.Verdict != c.want || got.Confidence != c.wantConf || got.Resource != "cpu" {
				t.Fatalf("verdict %s/%s/%s, want %s/%s/cpu; summary %s", got.Verdict, got.Confidence, got.Resource, c.want, c.wantConf, got.Summary)
			}
			if len(got.Checks) != 4 {
				t.Fatalf("checks = %d, want 4 (always all reported)", len(got.Checks))
			}
		})
	}
}

func TestWindowValueWinsOverLatestSample(t *testing.T) {
	// latest 5 s sample says 95 %, but over the window the node used 40 %.
	got := Assess(Inputs{Metrics: metrics(95, 1, 8), MySQL: report("", 30, 40, 0), Families: mysqlTop, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
	if got.Verdict != model.OverloadNodeNotSaturated || got.Evidence.NodeCPUSource != "window" {
		t.Fatalf("verdict %s source %s", got.Verdict, got.Evidence.NodeCPUSource)
	}
}

func TestNoWindowFallsBackToSample(t *testing.T) {
	// Without mysql_report.node no digest can have percent_of_node_cpu_used or
	// a cpu_role (querystats needs the node window for both).
	r := report("", 27, 90, 1)
	r.Node = nil
	r.TopDigests[0].PercentOfNodeCPUUsed = nil
	got := Assess(Inputs{Metrics: metrics(92, 1, 8), MySQL: r, Families: mysqlTop, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
	if got.Evidence.NodeCPUSource != "sample" || !got.Checks[0].Passed || !contains(got.Missing, "node_cpu_window") {
		t.Fatalf("source %s node check %v missing %v", got.Evidence.NodeCPUSource, got.Checks[0].Passed, got.Missing)
	}
	if got.Verdict != model.OverloadNoDominantQuery || got.Confidence != model.ConfidenceLow {
		t.Fatalf("verdict %s/%s, want no_dominant_query/low; summary %s", got.Verdict, got.Confidence, got.Summary)
	}
	if !strings.Contains(got.Checks[0].Detail, "latest collector sample") {
		t.Fatalf("node detail %q", got.Checks[0].Detail)
	}
}

// Built from real querystats output: no AddHost, so no node block, no
// percent_of_node_cpu_used and no cpu_role on any digest.
func TestNoNodeBlockFromRealQuerystats(t *testing.T) {
	a := querystats.New(querystats.Config{SlowWallNs: 10_000_000})
	at := time.Unix(1_800_000_000, 0)
	a.AddDeltas([]querystats.Delta{
		{PID: 42, Command: "query", Digest: sqldigest.Normalize("SELECT * FROM t WHERE id = 1"), Calls: 1000, CPUNs: 400e9, WallNs: 420e9, WallMaxNs: 1e9},
		{PID: 42, Command: "query", Digest: sqldigest.Normalize("SELECT * FROM u WHERE id = 1"), Calls: 10, CPUNs: 1e9, WallNs: 2e9, WallMaxNs: 300e6},
	}, at)
	snap := a.Snapshot(at.Add(time.Second))
	if snap.Node != nil || snap.TopByCPU[0].PercentOfNodeCPUUsed != nil || snap.TopByCPU[0].CPURole != "" {
		t.Fatalf("precondition: node %+v top %+v", snap.Node, snap.TopByCPU[0])
	}
	r := &model.MySQLAnalysis{WindowSeconds: snap.WindowSeconds, Node: snap.Node, QueryCPUCoveragePercent: snap.QueryCPUCoveragePercent,
		Thresholds: &snap.Thresholds, TopDigests: snap.TopByCPU, TopDigestsByWait: snap.TopByWait,
		Victims: snap.Victims, Accounting: snap.Accounting}
	got := Assess(Inputs{Metrics: metrics(92, 1, 8), MySQL: r, Families: mysqlTop, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
	if got.Verdict != model.OverloadNoDominantQuery || got.Confidence != model.ConfidenceLow {
		t.Fatalf("verdict %s/%s, want no_dominant_query/low; summary %s", got.Verdict, got.Confidence, got.Summary)
	}
	for _, want := range []string{"Node is saturated (CPU used 92.0%", "unavailable", "mysql_report.node"} {
		if !strings.Contains(got.Summary, want) {
			t.Fatalf("summary %q lacks %q", got.Summary, want)
		}
	}
}

// load/cpu 2.0 saturates the node while it used only 30 % of its CPU over the
// window: below the culprit floor (50 %), no digest can be a CPU culprit.
func TestLoadOnlySaturationBelowCulpritFloor(t *testing.T) {
	got := Assess(Inputs{Metrics: metrics(20, 16, 8), MySQL: report("", 60, 30, 0), Families: mysqlTop, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
	if !got.Checks[0].Passed {
		t.Fatalf("node check must pass on load: %s", got.Checks[0].Detail)
	}
	if got.Verdict != model.OverloadNoDominantQuery || got.Confidence != model.ConfidenceLow {
		t.Fatalf("verdict %s/%s, want no_dominant_query/low; summary %s", got.Verdict, got.Confidence, got.Summary)
	}
	for _, want := range []string{"saturated by load (load/cpu 2.00)", "not CPU (CPU used 30.0%", "io_diagnosis"} {
		if !strings.Contains(got.Summary, want) {
			t.Fatalf("summary %q lacks %q", got.Summary, want)
		}
	}
	if strings.Contains(got.Summary, "Node CPU is saturated") {
		t.Fatalf("summary %q claims CPU saturation", got.Summary)
	}
}

func TestSaturatedSummaryWording(t *testing.T) {
	for _, c := range []struct {
		r    *model.MySQLAnalysis
		fams []model.FamilyStats
	}{{report("", 9, 90, 1), mysqlTop}, {report("culprit", 27, 90, 1), nginxTop}} {
		got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: c.r, Families: c.fams, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
		if !strings.Contains(got.Summary, "Node is saturated (CPU used 90.0%, load/cpu 0.12)") {
			t.Fatalf("%s summary %q", got.Verdict, got.Summary)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestNilAndNoData(t *testing.T) {
	if Assess(Inputs{Metrics: metrics(90, 1, 8)}, Thresholds{}, time.Unix(0, 0)) != nil {
		t.Fatal("nil MySQL report must give nil")
	}
	r := report("culprit", 27, 90, 0)
	r.TopDigests = []model.QueryDigestStats{{DigestID: "other"}}
	got := Assess(Inputs{Metrics: metrics(90, 1, 8), MySQL: r}, Thresholds{}, time.Unix(0, 0))
	if got.Verdict != model.OverloadNoData || got.Digest != nil {
		t.Fatalf("verdict %s digest %+v", got.Verdict, got.Digest)
	}
}

func TestDigestBlockEvidenceAndSummary(t *testing.T) {
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: report("culprit", 27, 90, 1), Families: mysqlTop, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
	d := got.Digest
	if d == nil || d.DigestID != "abc" || d.PercentOfNodeCPUUsed == nil || *d.PercentOfNodeCPUUsed != 27 || d.CallsPerSec != 40 || d.CPURole != "culprit" {
		t.Fatalf("digest = %+v", d)
	}
	ev := got.Evidence
	if ev.NodeCPUUsedPercent != 90 || ev.NumCPU != 8 || ev.QueryCPUCoveragePercent == nil || *ev.QueryCPUCoveragePercent != 58 || ev.CPUVictims != 1 || ev.WindowSeconds != 60 {
		t.Fatalf("evidence = %+v", ev)
	}
	th := got.Thresholds
	if th.NodeCPUPercent != 85 || th.NodeLoad != 1.5 || th.CPUCulpritPercentOfNodeCPUUsed != 20 || th.CPUCulpritMinNodeCPUUsedPercent != 50 {
		t.Fatalf("thresholds = %+v", th)
	}
	for _, want := range []string{"abc", "27% of all CPU work", "mysql.service", "58% of mysqld CPU"} {
		if !strings.Contains(got.Summary, want) {
			t.Fatalf("summary %q lacks %q", got.Summary, want)
		}
	}
}
