package chsink

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestReason(t *testing.T) {
	cases := []struct {
		active  []string
		verdict string
		want    string
	}{
		{nil, "healthy", ""},
		{nil, "inconclusive", ""},
		{nil, "iowait_accounting_artifact", ""},
		{nil, "", ""},
		{[]string{"runqlat", "cpu_profile"}, "healthy", "module:cpu_profile,runqlat"},
		{nil, "storage_latency_stall", "io_verdict:storage_latency_stall"},
		{[]string{"offcpu"}, "writeback_congestion", "module:offcpu;io_verdict:writeback_congestion"},
	}
	for _, tc := range cases {
		if got := Reason(tc.active, tc.verdict); got != tc.want {
			t.Errorf("Reason(%v, %q) = %q, want %q", tc.active, tc.verdict, got, tc.want)
		}
	}
}

func newTestSnapshotter(ins *fakeIns, state func() ([]string, string), build func() model.DiagnoseReport) (*Snapshotter, *Sink) {
	cfg := testCfg()
	cfg.Snapshots.Enabled = true
	cfg.Snapshots.CheckInterval = 30 * time.Second
	cfg.Snapshots.MinInterval = 5 * time.Minute
	sink := NewSink(cfg, "h", ins, Sources{}, tStart)
	return NewSnapshotter(cfg, "h", sink, state, build), sink
}

func TestCheckRateLimitAndNewReason(t *testing.T) {
	reason := []string{"cpu_profile"}
	builds := 0
	ins := &fakeIns{}
	s, sink := newTestSnapshotter(ins,
		func() ([]string, string) { return reason, "healthy" },
		func() model.DiagnoseReport { builds++; return model.DiagnoseReport{Hostname: "h"} })
	ctx := context.Background()
	if !s.Check(ctx, tStart) {
		t.Fatal("first check must capture")
	}
	if s.Check(ctx, tStart.Add(time.Minute)) {
		t.Fatal("same reason inside min_interval must not capture")
	}
	reason = []string{"cpu_profile", "runqlat"}
	if !s.Check(ctx, tStart.Add(2*time.Minute)) {
		t.Fatal("a new reason bypasses the rate limit")
	}
	if !s.Check(ctx, tStart.Add(8*time.Minute)) {
		t.Fatal("same reason after min_interval must capture")
	}
	if builds != 3 || len(ins.sent) != 3 {
		t.Fatalf("builds=%d sent=%d, want 3 and 3", builds, len(ins.sent))
	}
	if v := testutil.ToFloat64(sink.m.snapshots.WithLabelValues("module")); v != 3 {
		t.Fatalf("snapshots_total{module} = %v", v)
	}
}

func TestCheckNoReasonSkipsBuild(t *testing.T) {
	built := false
	s, _ := newTestSnapshotter(&fakeIns{},
		func() ([]string, string) { return nil, "healthy" },
		func() model.DiagnoseReport { built = true; return model.DiagnoseReport{} })
	if s.Check(context.Background(), tStart) || built {
		t.Fatal("no reason must not build or capture")
	}
}

func TestSnapshotRowContent(t *testing.T) {
	ins := &fakeIns{}
	s, _ := newTestSnapshotter(ins,
		func() ([]string, string) { return nil, "storage_latency_stall" },
		func() model.DiagnoseReport {
			return model.DiagnoseReport{Hostname: "h", IODiagnosis: &model.IODiagnosis{Verdict: "storage_latency_stall"}}
		})
	s.Check(context.Background(), tStart)
	if len(ins.sent) != 1 || ins.sent[0].table != TableSnapshots {
		t.Fatalf("sent = %v", ins.tables())
	}
	row := decodeRowsForTest(t, ins.sent[0].body)[0]
	if row["reason"] != "io_verdict:storage_latency_stall" || row["verdict"] != "storage_latency_stall" ||
		row["ts"] != "2026-10-08 00:00:00" || row["host"] != "h" {
		t.Fatalf("row = %v", row)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(row["report"].(string)), &rep); err != nil || rep["hostname"] != "h" {
		t.Fatalf("report column is not the diagnose JSON: %v", err)
	}
}

func TestBuildPanicRecovered(t *testing.T) {
	s, _ := newTestSnapshotter(&fakeIns{},
		func() ([]string, string) { return []string{"offcpu"}, "" },
		func() model.DiagnoseReport { panic("boom") })
	if s.Check(context.Background(), tStart) {
		t.Fatal("panicking build must not capture")
	}
}

func mysqlReport() *model.MySQLAnalysis {
	return &model.MySQLAnalysis{
		TopDigests:           []model.QueryDigestStats{{DigestID: "a", SampleQuery: "select * from u where pw='secret'"}},
		TopDigestsByBytesOut: []model.QueryDigestStats{{DigestID: "a", SampleQuery: "select * from u where pw='secret'"}},
		TopDigestsByWait:     []model.QueryDigestStats{{DigestID: "w", SampleQuery: "SELECT 'secret'"}},
		TopDigestsByDiskRead: []model.QueryDigestStats{{DigestID: "d", SampleQuery: "SELECT * FROM big WHERE pw='secret'"}},
		RecentSlowQueries:    []model.MySQLSlowEvent{{Query: "select * from u where pw='secret'"}},
	}
}

func TestStripSensitiveDoesNotMutateSource(t *testing.T) {
	shared := mysqlReport()
	out := StripSensitive(model.DiagnoseReport{MySQLReport: shared}, false)
	js, _ := json.Marshal(out)
	if strings.Contains(string(js), "secret") {
		t.Fatalf("stripped report still has literals: %s", js)
	}
	if shared.TopDigests[0].SampleQuery == "" || shared.RecentSlowQueries[0].Query == "" ||
		!strings.Contains(shared.RecentSlowQueries[0].Query, "secret") {
		t.Fatal("StripSensitive mutated the analyzer's shared report")
	}
	if out.MySQLReport.RecentSlowQueries[0].Query == "" {
		t.Fatal("slow query text must be replaced by its digest text, not emptied")
	}
	if out.MySQLReport.TopDigestsByWait[0].SampleQuery != "" || shared.TopDigestsByWait[0].SampleQuery == "" {
		t.Fatalf("top_digests_by_wait sample: out %q, source %q", out.MySQLReport.TopDigestsByWait[0].SampleQuery, shared.TopDigestsByWait[0].SampleQuery)
	}
	if out.MySQLReport.TopDigestsByDiskRead[0].SampleQuery != "" || shared.TopDigestsByDiskRead[0].SampleQuery == "" {
		t.Fatalf("top_digests_by_disk_read sample: out %q, source %q", out.MySQLReport.TopDigestsByDiskRead[0].SampleQuery, shared.TopDigestsByDiskRead[0].SampleQuery)
	}
}

func TestStripSensitiveIncludeKeeps(t *testing.T) {
	out := StripSensitive(model.DiagnoseReport{MySQLReport: mysqlReport()}, true)
	if out.MySQLReport.TopDigests[0].SampleQuery == "" {
		t.Fatal("include=true must keep samples")
	}
}
