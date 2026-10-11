package overload

import (
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const pgFam = "postgresql@16-main.service"

var (
	pgTop    = []model.FamilyStats{{Family: pgFam, CPUPercent: 80, ReadBytesPerSec: 200 << 20}, {Family: "nginx.service", CPUPercent: 5}}
	pgPIDFam = map[uint32]string{100: pgFam}
)

func pgAccounting() map[string]string {
	return map[string]string{"cpu_wait": "ok", "disk_bytes": "ok", "disk_wait": "ok",
		PGAccountingWAL: "ok", PGAccountingSyncRep: "not_attached"}
}

// pgReport: node 90 % used; the top digest did pct % of the CPU work.
func pgReport(role string, pct float64) Report {
	return Report{
		WindowSeconds: 60, Cluster: pgFam, ServerPID: 100,
		Node:       &model.MySQLNodeWindow{NumCPU: 8, CPUUsedCores: 7.2, CPUUsedPercent: 90},
		Thresholds: &model.QueryRoleThresholds{CPUCulpritPercentOfNodeCPUUsed: 20, CPUCulpritMinNodeCPUUsedPercent: 50},
		Accounting: pgAccounting(),
		Victims:    map[string]int{"cpu": 3, "disk": 0, PGVictimWAL: 0},
		TopDigests: []model.QueryDigestStats{{PID: 100, DigestID: "d1", DigestText: "select * from orders", Command: "client",
			CPUCores: 2.9, PercentOfNodeCPUUsed: f(pct), CallsPerSec: 4, CPURole: role}},
	}
}

func pgInputs() Inputs {
	return Inputs{Metrics: metrics(90, 1, 8), Families: pgTop, PIDFamilies: pgPIDFam}
}

func TestPostgresQueryCPUOverload(t *testing.T) {
	r := AssessEngine(PostgresEngine, pgReport("culprit", 40), pgInputs(), Thresholds{}, 50, time.Unix(0, 0))
	if r.Verdict != model.OverloadQueryCPU || r.Confidence != model.ConfidenceHigh || r.Cluster != pgFam {
		t.Fatalf("got %s/%s cluster %q: %s", r.Verdict, r.Confidence, r.Cluster, r.Summary)
	}
	if r.Checks[1].Name != "postgres_top_consumer" || !r.Checks[1].Passed {
		t.Fatalf("process check %+v", r.Checks[1])
	}
	if r.Evidence.PostgresFamily != pgFam || r.Evidence.MySQLFamily != "" {
		t.Fatalf("family evidence %+v", r.Evidence)
	}
	if !strings.Contains(r.Summary, "of postgres CPU") && r.Evidence.QueryCPUCoveragePercent != nil {
		t.Fatalf("summary %q", r.Summary)
	}
	if r.Thresholds.BackgroundDominantPercent != 50 {
		t.Fatalf("thresholds %+v", r.Thresholds)
	}
}

func TestPostgresBackgroundCPU(t *testing.T) {
	rep := pgReport("", 5)
	rep.Backends = []BackendUsage{{Type: "client", CPUCores: 1}, {Type: "autovacuum", CPUCores: 3}, {Type: "checkpointer", CPUCores: 0.2}}
	r := AssessEngine(PostgresEngine, rep, pgInputs(), Thresholds{}, 50, time.Unix(0, 0))
	if r.Verdict != model.OverloadBackground || r.Evidence.BackgroundType != "autovacuum" {
		t.Fatalf("got %s %+v: %s", r.Verdict, r.Evidence, r.Summary)
	}
	if *r.Evidence.BackgroundCPUCores != 3 || *r.Evidence.ClusterCPUCores != 4.2 || !strings.Contains(r.Summary, "autovacuum backends use 3.0 of the cluster's 4.2 cores") {
		t.Fatalf("summary %q", r.Summary)
	}
}

func TestPostgresBackgroundBelowThresholdIsNoDominantQuery(t *testing.T) {
	rep := pgReport("", 5)
	rep.Backends = []BackendUsage{{Type: "client", CPUCores: 3}, {Type: "autovacuum", CPUCores: 1}}
	if r := AssessEngine(PostgresEngine, rep, pgInputs(), Thresholds{}, 50, time.Unix(0, 0)); r.Verdict != model.OverloadNoDominantQuery {
		t.Fatalf("got %s", r.Verdict)
	}
}

func TestPostgresBackgroundWithoutDigests(t *testing.T) {
	rep := pgReport("", 5)
	rep.TopDigests = nil
	rep.Backends = []BackendUsage{{Type: "autovacuum", CPUCores: 3}, {Type: "client", CPUCores: 0.1}}
	r := AssessEngine(PostgresEngine, rep, pgInputs(), Thresholds{}, 50, time.Unix(0, 0))
	if r.Verdict != model.OverloadBackground || !r.Checks[1].Passed || r.Digest != nil {
		t.Fatalf("got %s %+v", r.Verdict, r.Checks)
	}
}

func TestPostgresNotPostgres(t *testing.T) {
	in := pgInputs()
	in.Families = []model.FamilyStats{{Family: "java.service", CPUPercent: 70}, {Family: pgFam, CPUPercent: 10}}
	r := AssessEngine(PostgresEngine, pgReport("culprit", 40), in, Thresholds{}, 50, time.Unix(0, 0))
	if r.Verdict != model.OverloadNotPostgres || !strings.Contains(r.Summary, "not postgres's "+pgFam) {
		t.Fatalf("got %s: %s", r.Verdict, r.Summary)
	}
}

func TestPostgresOptionalSyncRepNotMissing(t *testing.T) {
	in := pgInputs()
	in.IOVerdict = model.VerdictHighDiskThroughput
	rep := pgReport("culprit", 40)
	rep.TopDigestsByDiskRead = []model.QueryDigestStats{{PID: 100, DigestID: "d2", PercentOfDiskRead: f(70), DiskReadMBPerSec: f(140), IORole: "culprit"}}
	rep.Victims["disk"] = 2
	rep.DiskEstimated = true
	r := AssessEngine(PostgresEngine, rep, in, Thresholds{}, 50, time.Unix(0, 0))
	disk := r
	if r.Resource != "disk" {
		disk = r.Secondary
	}
	if disk == nil || disk.Verdict != model.OverloadQueryDisk {
		t.Fatalf("disk assessment %+v", disk)
	}
	for _, m := range disk.Missing {
		if m == PGAccountingSyncRep {
			t.Fatal("an unattached optional wait must not be reported missing")
		}
	}
	if disk.Confidence != model.ConfidenceMedium || disk.Evidence.DiskEstimated == nil {
		t.Fatalf("estimated disk must cap confidence at medium: %s %+v", disk.Confidence, disk.Evidence)
	}
	if !strings.Contains(disk.Checks[3].Detail, "largest wait is disk / wal;") {
		t.Fatalf("victims detail %q", disk.Checks[3].Detail)
	}
}

func TestPickClusterPrefersOverload(t *testing.T) {
	a := &model.QueryOverload{Verdict: model.OverloadNodeNotSaturated, Cluster: "a", Checks: []model.OverloadCheck{{Passed: false}}}
	b := &model.QueryOverload{Verdict: model.OverloadQueryCPU, Cluster: "b", Checks: []model.OverloadCheck{{Passed: true}}}
	c := &model.QueryOverload{Verdict: model.OverloadBackground, Cluster: "c", Checks: []model.OverloadCheck{{Passed: true}}}
	p := PickCluster([]*model.QueryOverload{a, nil, c, b})
	if p.Cluster != "b" || len(p.OtherClusters) != 2 || p.OtherClusters[0].Cluster != "c" {
		t.Fatalf("picked %+v", p)
	}
	if a.OtherClusters != nil || b.OtherClusters != nil {
		t.Fatal("inputs must not be modified")
	}
	if PickCluster(nil) != nil {
		t.Fatal("no clusters → nil")
	}
}

func TestAnnotateBackgroundDisk(t *testing.T) {
	d := &model.IODiagnosis{NextSteps: []string{"x"}}
	oc := &model.QueryOverload{Verdict: model.OverloadBackground, Resource: "disk", Evidence: model.OverloadEvidence{BackgroundType: "checkpointer"}}
	got := AnnotateIODiagnosisFor(d, oc, "postgres_report")
	if len(got.NextSteps) != 2 || !strings.Contains(got.NextSteps[0], "postgres_report.overload_cause names the background work") || len(d.NextSteps) != 1 {
		t.Fatalf("got %v", got.NextSteps)
	}
}
