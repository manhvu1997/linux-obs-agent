package overload

import (
	"encoding/json"
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
		Accounting:              allMeasured(),
		Thresholds:              &model.QueryRoleThresholds{CPUCulpritPercentOfNodeCPUUsed: 20, CPUCulpritMinNodeCPUUsedPercent: 50},
		TopDigests: []model.QueryDigestStats{{
			PID: 42, DigestID: "abc", DigestText: "select * from t", Command: "query", SampleQuery: "select * from t where id = 7",
			CPUCores: pct / 100 * nodeUsed / 100 * 8, PercentOfNodeCPUUsed: f(pct), CallsPerSec: 40, BytesOutPerCall: 1300, CPURole: role,
		}},
	}
}

// allMeasured: every wait measured in every poll of the window.
func allMeasured() map[string]string {
	return map[string]string{"cpu_wait": "ok", "disk_bytes": "ok", "disk_wait": "ok", "commit_wait": "ok"}
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
	// latest collector sample says 95 %, but over the window the node used 40 %.
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
	if ev.NodeCPUUsedPercent == nil || *ev.NodeCPUUsedPercent != 90 || ev.NumCPU != 8 || ev.QueryCPUCoveragePercent == nil || *ev.QueryCPUCoveragePercent != 58 ||
		ev.CPUVictims == nil || *ev.CPUVictims != 1 || ev.WindowSeconds != 60 {
		t.Fatalf("evidence = %+v", ev)
	}
	th := got.Thresholds
	if th.NodeCPUPercent != 85 || th.NodeLoad != 1.5 || th.CPUCulpritPercentOfNodeCPUUsed != 20 || th.CPUCulpritMinNodeCPUUsedPercent != 50 {
		t.Fatalf("thresholds = %+v", th)
	}
	for _, want := range []string{"abc", "27% of all CPU work", "mysql.service", "58% of mysqld CPU", "largest wait is the run queue"} {
		if !strings.Contains(got.Summary, want) {
			t.Fatalf("summary %q lacks %q", got.Summary, want)
		}
	}
}

var (
	mysqlDiskTop  = []model.FamilyStats{{Family: "mysql.service", CPUPercent: 70, ReadBytesPerSec: 40 << 20}, {Family: "backup.service", CPUPercent: 5, ReadBytesPerSec: 1 << 20}}
	backupDiskTop = []model.FamilyStats{{Family: "mysql.service", CPUPercent: 70, ReadBytesPerSec: 2 << 20}, {Family: "backup.service", CPUPercent: 5, ReadBytesPerSec: 80 << 20}}
)

// diskReport: the top disk-read digest reads pct % of the node's disk reads.
func diskReport(ioRole string, pct float64, victims, commit int) *model.MySQLAnalysis {
	r := report("", 5, 40, 0) // CPU side quiet
	rd := 30.0
	r.Node.DiskReadMBPerSec = &rd
	r.Victims = map[string]int{"cpu": 0, "disk": victims, "commit": commit}
	r.Thresholds.IOCulpritPercentOfDiskRead, r.Thresholds.IOCulpritMinNodeDiskReadMBPerSec = 20, 5
	r.TopDigestsByDiskRead = []model.QueryDigestStats{{PID: 42, DigestID: "scan", DigestText: "select * from big", Command: "query",
		DiskReadMBPerSec: f(pct / 100 * rd), PercentOfDiskRead: f(pct), DiskReadPagesPerCall: f(640), IORole: ioRole}}
	return r
}

func TestDiskVerdicts(t *testing.T) {
	for _, c := range []struct {
		name     string
		io       model.IOVerdict
		r        *model.MySQLAnalysis
		fams     []model.FamilyStats
		want     model.OverloadVerdict
		wantConf model.IOConfidence
	}{
		{"scan saturates the disk, victims", model.VerdictHighDiskThroughput, diskReport("culprit", 70, 2, 0), mysqlDiskTop, model.OverloadQueryDisk, model.ConfidenceHigh},
		{"commit victims count for disk", model.VerdictStorageLatencyStall, diskReport("culprit", 70, 0, 3), mysqlDiskTop, model.OverloadQueryDisk, model.ConfidenceHigh},
		{"no victims", model.VerdictHighDiskThroughput, diskReport("culprit", 70, 0, 0), mysqlDiskTop, model.OverloadQueryDisk, model.ConfidenceMedium},
		{"reads spread out", model.VerdictHighDiskThroughput, diskReport("", 8, 1, 0), mysqlDiskTop, model.OverloadNoDominantQuery, model.ConfidenceHigh},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: c.r, Families: c.fams, PIDFamilies: pidFam, IOVerdict: c.io}, Thresholds{}, time.Unix(0, 0))
			if got.Resource != "disk" || got.Verdict != c.want || got.Confidence != c.wantConf {
				t.Fatalf("%s/%s/%s; summary %s", got.Resource, got.Verdict, got.Confidence, got.Summary)
			}
			if len(got.Checks) != 4 || got.Secondary != nil {
				t.Fatalf("checks %d secondary %+v", len(got.Checks), got.Secondary)
			}
		})
	}
}

func TestDiskNotMySQL(t *testing.T) {
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: diskReport("culprit", 70, 1, 0), Families: backupDiskTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	if got.Verdict != model.OverloadNotMySQL || got.Resource != "disk" || !strings.Contains(got.Summary, "backup.service") {
		t.Fatalf("%s/%s: %s", got.Resource, got.Verdict, got.Summary)
	}
}

func TestDiskSummaryExplainsPagesPerCall(t *testing.T) {
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: diskReport("culprit", 70, 1, 0), Families: mysqlDiskTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	for _, want := range []string{"scan", "70% of the disk's reads", "640 pages per call", "EXPLAIN"} {
		if !strings.Contains(got.Summary, want) {
			t.Fatalf("summary %q lacks %q", got.Summary, want)
		}
	}
}

func TestBothResourcesSecondary(t *testing.T) {
	r := diskReport("culprit", 40, 1, 0)
	cpu := report("culprit", 27, 90, 1)
	r.Node.CPUUsedPercent, r.Node.CPUUsedCores = 90, 7.2
	r.TopDigests, r.Victims["cpu"] = cpu.TopDigests, 1
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: r, Families: mysqlDiskTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	// disk share 40 % > cpu share 27 %: disk is the verdict, cpu the secondary.
	if got.Verdict != model.OverloadQueryDisk || got.Secondary == nil || got.Secondary.Verdict != model.OverloadQueryCPU || got.Secondary.Secondary != nil {
		t.Fatalf("primary %s/%s secondary %+v", got.Resource, got.Verdict, got.Secondary)
	}
}

func TestOnlyCPUSaturatedNoSecondary(t *testing.T) {
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: report("culprit", 27, 90, 1), Families: mysqlTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHealthy}, Thresholds{}, time.Unix(0, 0))
	if got.Resource != "cpu" || got.Verdict != model.OverloadQueryCPU || got.Secondary != nil {
		t.Fatalf("%s/%s secondary %+v", got.Resource, got.Verdict, got.Secondary)
	}
}

func TestAnnotateIODiagnosis(t *testing.T) {
	io := &model.IODiagnosis{Verdict: model.VerdictHighDiskThroughput, NextSteps: []string{"existing step"}}
	oc := &model.QueryOverload{Verdict: model.OverloadQueryDisk, Digest: &model.OverloadDigest{DigestID: "scan"}}
	out := AnnotateIODiagnosis(io, oc)
	if len(out.NextSteps) != 2 || !strings.Contains(out.NextSteps[0], "overload_cause") || !strings.Contains(out.NextSteps[0], "scan") {
		t.Fatalf("next_steps = %v", out.NextSteps)
	}
	if len(io.NextSteps) != 1 {
		t.Fatal("the input diagnosis was mutated")
	}
	if got := AnnotateIODiagnosis(io, &model.QueryOverload{Verdict: model.OverloadQueryCPU}); got != io {
		t.Fatal("non-disk verdict must return the input unchanged")
	}
	if AnnotateIODiagnosis(nil, oc) != nil {
		t.Fatal("nil diagnosis stays nil")
	}
}

// keys returns the JSON object keys of v.
func keys(t *testing.T, v any) map[string]bool {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

var (
	cpuEvidenceKeys = []string{"node_cpu_used_percent", "node_cpu_source", "node_cpu_used_cores", "num_cpu", "load_normalised",
		"psi_cpu_some_avg10", "psi_available", "top_family", "top_family_cpu_percent", "mysql_family_cpu_percent",
		"query_cpu_coverage_percent", "cpu_victims"}
	diskEvidenceKeys = []string{"io_verdict", "node_disk_read_mb_per_sec", "query_disk_read_coverage_percent", "disk_victims",
		"commit_victims", "top_disk_family", "top_disk_family_read_mb_per_sec", "mysql_family_disk_read_mb_per_sec"}
	cpuThresholdKeys  = []string{"node_cpu_percent", "node_load", "cpu_culprit_percent_of_node_cpu_used", "cpu_culprit_min_node_cpu_used_percent"}
	diskThresholdKeys = []string{"io_culprit_percent_of_disk_read", "io_culprit_min_node_disk_read_mb_per_sec"}
)

// assertResourceJSON: r carries its own resource's fields and none of the other's.
func assertResourceJSON(t *testing.T, r *model.QueryOverload) {
	t.Helper()
	ownEv, otherEv, ownTh, otherTh := cpuEvidenceKeys, diskEvidenceKeys, cpuThresholdKeys, diskThresholdKeys
	if r.Resource == "disk" {
		ownEv, otherEv, ownTh, otherTh = diskEvidenceKeys, cpuEvidenceKeys, diskThresholdKeys, cpuThresholdKeys
	}
	ev, th := keys(t, r.Evidence), keys(t, r.Thresholds)
	for _, k := range otherEv {
		if ev[k] {
			t.Errorf("%s evidence has %q: %v", r.Resource, k, ev)
		}
	}
	for _, k := range ownEv {
		if !ev[k] {
			t.Errorf("%s evidence lacks %q: %v", r.Resource, k, ev)
		}
	}
	for _, k := range otherTh {
		if th[k] {
			t.Errorf("%s thresholds have %q", r.Resource, k)
		}
	}
	for _, k := range ownTh {
		if !th[k] {
			t.Errorf("%s thresholds lack %q", r.Resource, k)
		}
	}
	if r.Digest != nil {
		if has := keys(t, r.Digest)["cpu_cores"]; has != (r.Resource == "cpu") {
			t.Errorf("%s digest cpu_cores present = %v", r.Resource, has)
		}
	}
}

func TestEvidenceJSONHasOnlyOwnResource(t *testing.T) {
	// PSI available so psi_* are filled for the CPU assessment.
	m := metrics(20, 1, 8)
	m.Pressure.CPU.Available, m.Pressure.CPU.Some.Avg10 = true, 12
	cpu := Assess(Inputs{Metrics: m, MySQL: report("culprit", 27, 90, 0), Families: mysqlTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHealthy}, Thresholds{}, time.Unix(0, 0))
	if cpu.Resource != "cpu" || cpu.Secondary != nil {
		t.Fatalf("precondition: %s secondary %+v", cpu.Resource, cpu.Secondary)
	}
	assertResourceJSON(t, cpu)
	if !strings.Contains(string(mustJSON(t, cpu.Evidence)), `"cpu_victims":0`) {
		t.Errorf("measured cpu_wait with no victims must report cpu_victims 0: %s", mustJSON(t, cpu.Evidence))
	}

	diskFams := []model.FamilyStats{{Family: "mysql.service", CPUPercent: 70, ReadBytesPerSec: 40 << 20}, {Family: "backup.service", CPUPercent: 5, ReadBytesPerSec: 1 << 20}}
	r := diskReport("culprit", 70, 0, 0)
	r.QueryDiskReadCoveragePercent = f(80)
	disk := Assess(Inputs{Metrics: m, MySQL: r, Families: diskFams, PIDFamilies: pidFam, IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	if disk.Resource != "disk" || disk.Secondary != nil {
		t.Fatalf("precondition: %s secondary %+v", disk.Resource, disk.Secondary)
	}
	assertResourceJSON(t, disk)
}

func TestBothResourcesSecondaryJSONClean(t *testing.T) {
	r := diskReport("culprit", 40, 1, 0)
	r.QueryDiskReadCoveragePercent = f(80)
	r.Node.CPUUsedPercent, r.Node.CPUUsedCores = 90, 7.2
	r.TopDigests, r.Victims["cpu"] = report("culprit", 27, 90, 1).TopDigests, 1
	m := metrics(20, 1, 8)
	m.Pressure.CPU.Available = true
	got := Assess(Inputs{Metrics: m, MySQL: r, Families: mysqlDiskTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	if got.Resource != "disk" || got.Secondary == nil || got.Secondary.Resource != "cpu" {
		t.Fatalf("primary %s secondary %+v", got.Resource, got.Secondary)
	}
	assertResourceJSON(t, got)
	assertResourceJSON(t, got.Secondary)
}

func TestCPUEvidenceOmitsUnavailablePSIAndLoad(t *testing.T) {
	// PSI unavailable: no psi_cpu_some_avg10 (psi_available false is kept).
	m := metrics(20, 1, 8)
	r := Assess(Inputs{Metrics: m, MySQL: report("culprit", 27, 90, 0), Families: mysqlTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHealthy}, Thresholds{}, time.Unix(0, 0))
	if r.Resource != "cpu" {
		t.Fatalf("precondition: resource %s", r.Resource)
	}
	ev := keys(t, r.Evidence)
	if ev["psi_cpu_some_avg10"] {
		t.Errorf("PSI unavailable must omit psi_cpu_some_avg10: %s", mustJSON(t, r.Evidence))
	}
	if !ev["psi_available"] || !ev["load_normalised"] {
		t.Errorf("psi_available and load_normalised must stay: %s", mustJSON(t, r.Evidence))
	}

	// NumCPU unknown: no load_normalised.
	m = metrics(20, 1, 0)
	m.Pressure.CPU.Available, m.Pressure.CPU.Some.Avg10 = true, 12
	r = Assess(Inputs{Metrics: m, MySQL: report("culprit", 27, 90, 0), Families: mysqlTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHealthy}, Thresholds{}, time.Unix(0, 0))
	ev = keys(t, r.Evidence)
	if ev["load_normalised"] {
		t.Errorf("NumCPU 0 must omit load_normalised: %s", mustJSON(t, r.Evidence))
	}
	if !ev["psi_cpu_some_avg10"] {
		t.Errorf("PSI available must report psi_cpu_some_avg10: %s", mustJSON(t, r.Evidence))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDiskWaitNotMeasured(t *testing.T) {
	r := diskReport("culprit", 70, 0, 2)
	r.Accounting["disk_wait"] = "delayacct_disabled"
	delete(r.Victims, "disk") // querystats omits the kind when its wait is unmeasured
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: r, Families: mysqlDiskTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	if !contains(got.Missing, "disk_wait") || contains(got.Missing, "commit_wait") {
		t.Fatalf("missing %v, want disk_wait only", got.Missing)
	}
	vc := got.Checks[3]
	for _, want := range []string{"disk waits not measured (accounting.disk_wait = delayacct_disabled)", "2 digest(s) with victim_of commit", "largest wait is disk / commit"} {
		if !strings.Contains(vc.Detail, want) {
			t.Fatalf("victims detail %q lacks %q", vc.Detail, want)
		}
	}
	if !vc.Passed || got.Verdict != model.OverloadQueryDisk || got.Confidence != model.ConfidenceHigh {
		t.Fatalf("commit victims still count: passed %v %s/%s", vc.Passed, got.Verdict, got.Confidence)
	}
	ev := keys(t, got.Evidence)
	if ev["disk_victims"] || !ev["commit_victims"] {
		t.Fatalf("evidence keys %v: want commit_victims only", ev)
	}
}

func TestNoDiskWaitMeasuredMediumConfidence(t *testing.T) {
	r := diskReport("culprit", 70, 0, 0)
	r.Accounting["disk_wait"], r.Accounting["commit_wait"] = "delayacct_disabled", "log_write_up_to_unavailable"
	r.Victims = map[string]int{"cpu": 0}
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: r, Families: mysqlDiskTop, PIDFamilies: pidFam,
		IOVerdict: model.VerdictHighDiskThroughput}, Thresholds{}, time.Unix(0, 0))
	if got.Verdict != model.OverloadQueryDisk || got.Confidence != model.ConfidenceMedium {
		t.Fatalf("%s/%s, want query_disk_overload/medium", got.Verdict, got.Confidence)
	}
	if !contains(got.Missing, "disk_wait") || !contains(got.Missing, "commit_wait") {
		t.Fatalf("missing %v", got.Missing)
	}
	if !strings.Contains(got.Summary, "victims could not be measured") || strings.Contains(got.Summary, "0 digest(s)") {
		t.Fatalf("summary %q", got.Summary)
	}
	ev := keys(t, got.Evidence)
	if ev["disk_victims"] || ev["commit_victims"] {
		t.Fatalf("unmeasured victim counts emitted: %v", ev)
	}
}

func TestCPUWaitNotMeasured(t *testing.T) {
	r := report("culprit", 27, 90, 0)
	r.Accounting["cpu_wait"] = "run_delay_unavailable"
	r.Victims = map[string]int{"disk": 0, "commit": 0}
	got := Assess(Inputs{Metrics: metrics(20, 1, 8), MySQL: r, Families: mysqlTop, PIDFamilies: pidFam}, Thresholds{}, time.Unix(0, 0))
	if got.Verdict != model.OverloadQueryCPU || got.Confidence != model.ConfidenceMedium || !contains(got.Missing, "cpu_wait") {
		t.Fatalf("%s/%s missing %v", got.Verdict, got.Confidence, got.Missing)
	}
	if !strings.Contains(got.Checks[3].Detail, "CPU waits not measured (accounting.cpu_wait = run_delay_unavailable)") || got.Checks[3].Passed {
		t.Fatalf("victims check %+v", got.Checks[3])
	}
	if !strings.Contains(got.Summary, "victims could not be measured") || got.Evidence.CPUVictims != nil {
		t.Fatalf("summary %q cpu_victims %v", got.Summary, got.Evidence.CPUVictims)
	}
}

func TestAnnotateIODiagnosisSecondary(t *testing.T) {
	io := &model.IODiagnosis{Verdict: model.VerdictHighDiskThroughput, NextSteps: []string{"existing step"}}
	oc := &model.QueryOverload{Verdict: model.OverloadQueryCPU, Resource: "cpu", Digest: &model.OverloadDigest{DigestID: "hot"},
		Secondary: &model.QueryOverload{Verdict: model.OverloadQueryDisk, Resource: "disk", Digest: &model.OverloadDigest{DigestID: "scan"}}}
	out := AnnotateIODiagnosis(io, oc)
	if len(out.NextSteps) != 2 || !strings.Contains(out.NextSteps[0], "overload_cause.secondary") || !strings.Contains(out.NextSteps[0], "scan") {
		t.Fatalf("next_steps = %v", out.NextSteps)
	}
	if len(io.NextSteps) != 1 {
		t.Fatal("the input diagnosis was mutated")
	}
	oc.Secondary.Verdict = model.OverloadNoDominantQuery
	if AnnotateIODiagnosis(io, oc) != io {
		t.Fatal("a non-overload secondary must leave the diagnosis unchanged")
	}
}
