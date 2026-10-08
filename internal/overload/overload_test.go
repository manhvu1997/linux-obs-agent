package overload

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

var now = time.Unix(1_800_000_000, 0)

func metrics(cpu, load1 float64, ncpu int) model.NodeMetrics {
	var m model.NodeMetrics
	m.CPU.UsagePercent = cpu
	m.LoadAvg.Load1 = load1
	m.LoadAvg.NumCPU = ncpu
	return m
}

func mysqlReport(role string, ofNode float64, victims int) *model.MySQLAnalysis {
	return &model.MySQLAnalysis{
		VictimDigests: victims,
		Thresholds:    &model.QueryRoleThresholds{CulpritCPUSharePercent: 20, CulpritMinCPUPercent: 5},
		TopDigests: []model.QueryDigestStats{{
			PID: 42, DigestID: "abc", DigestText: "select * from t",
			CPUSharePercent: 80, CPUPercentOfCore: ofNode * 8, CPUPercentOfNode: ofNode, Role: role,
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
		in       Inputs
		verdict  model.OverloadVerdict
		conf     model.IOConfidence
		checksOK []bool // node, mysqld, digest, victims
	}{
		{"all four pass", Inputs{metrics(95, 4, 8), mysqlReport(querystats.RoleCulprit, 50, 3), mysqlTop, pidFam},
			model.OverloadByQuery, model.ConfidenceHigh, []bool{true, true, true, true}},
		{"no victims lowers confidence", Inputs{metrics(95, 4, 8), mysqlReport(querystats.RoleCulprit, 50, 0), mysqlTop, pidFam},
			model.OverloadByQuery, model.ConfidenceMedium, []bool{true, true, true, false}},
		{"saturated by load alone", Inputs{metrics(40, 16, 8), mysqlReport(querystats.RoleCulprit, 50, 1), mysqlTop, pidFam},
			model.OverloadByQuery, model.ConfidenceHigh, []bool{true, true, true, true}},
		{"idle node: culprit is not an overload", Inputs{metrics(20, 1, 8), mysqlReport(querystats.RoleCulprit, 50, 1), mysqlTop, pidFam},
			model.OverloadNodeNotSaturated, model.ConfidenceHigh, []bool{false, true, true, true}},
		{"other family burns the CPU", Inputs{metrics(95, 4, 8), mysqlReport(querystats.RoleCulprit, 50, 1), nginxTop, pidFam},
			model.OverloadNotMySQL, model.ConfidenceHigh, []bool{true, false, true, true}},
		{"culprit but small share of node", Inputs{metrics(95, 4, 8), mysqlReport(querystats.RoleCulprit, 5, 1), mysqlTop, pidFam},
			model.OverloadNoDominantQuery, model.ConfidenceHigh, []bool{true, true, false, true}},
		{"large share of node but not culprit", Inputs{metrics(95, 4, 8), mysqlReport("", 50, 1), mysqlTop, pidFam},
			model.OverloadNoDominantQuery, model.ConfidenceHigh, []bool{true, true, false, true}},
		{"no process families", Inputs{metrics(95, 4, 8), mysqlReport(querystats.RoleCulprit, 50, 1), nil, nil},
			model.OverloadByQuery, model.ConfidenceLow, []bool{true, false, true, true}},
	}
	for _, c := range cases {
		r := Assess(c.in, Thresholds{}, now)
		if r.Verdict != c.verdict || r.Confidence != c.conf {
			t.Errorf("%s: verdict %s/%s, want %s/%s (%s)", c.name, r.Verdict, r.Confidence, c.verdict, c.conf, r.Summary)
		}
		if len(r.Checks) != 4 {
			t.Fatalf("%s: %d checks, want 4", c.name, len(r.Checks))
		}
		for i, want := range c.checksOK {
			if r.Checks[i].Passed != want {
				t.Errorf("%s: check %s passed=%v, want %v (%s)", c.name, r.Checks[i].Name, r.Checks[i].Passed, want, r.Checks[i].Detail)
			}
		}
	}
}

func TestNilAndNoData(t *testing.T) {
	if Assess(Inputs{Metrics: metrics(95, 4, 8)}, Thresholds{}, now) != nil {
		t.Fatal("nil MySQL report must yield nil")
	}
	r := Assess(Inputs{Metrics: metrics(95, 4, 8), MySQL: &model.MySQLAnalysis{
		TopDigests: []model.QueryDigestStats{{DigestID: querystats.OtherDigestID, Role: querystats.RoleCulprit}},
	}}, Thresholds{}, now)
	if r.Verdict != model.OverloadNoData || r.DigestID != "" {
		t.Fatalf("only <other> digest: verdict %s digest %q, want no_data and no candidate", r.Verdict, r.DigestID)
	}
}

func TestEvidenceAndThresholdsEchoed(t *testing.T) {
	r := Assess(Inputs{metrics(95, 4, 8), mysqlReport(querystats.RoleCulprit, 50, 2), mysqlTop, pidFam}, Thresholds{}, now)
	e := r.Evidence
	if e.LoadNormalised != 0.5 || e.NumCPU != 8 || e.DigestCPUPercentOfNode != 50 || e.VictimDigests != 2 ||
		e.MySQLFamily != "mysql.service" || e.MySQLFamilyCPU != 70 || e.TopFamily != "mysql.service" {
		t.Fatalf("evidence = %+v", e)
	}
	th := r.Thresholds
	if th.NodeCPUPercent != 85 || th.NodeLoad != 1.5 || th.MinNodeCPUPercent != 20 || th.CulpritCPUSharePct != 20 {
		t.Fatalf("thresholds = %+v", th)
	}
	if r.PID != 42 || r.DigestID != "abc" {
		t.Fatalf("candidate = %d/%s", r.PID, r.DigestID)
	}
}
