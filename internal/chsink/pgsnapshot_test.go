package chsink

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func pgReport() model.DiagnoseReport {
	return model.DiagnoseReport{Hostname: "h", PostgresReport: &model.PostgresAnalysis{Clusters: []model.PostgresCluster{{
		Cluster:           "c",
		TopDigests:        []model.PGDigestStats{{DigestID: "a", SampleQuery: "select * from users where pw = 'secret'"}},
		RecentSlowQueries: []model.PGSlowQuery{{DigestID: "a", SampleQuery: "select * from users where pw = 'secret'"}},
	}}}}
}

func TestPostgresVerdictTriggersSnapshot(t *testing.T) {
	ins := &fakeIns{}
	shared := pgReport()
	s, sink := newTestSnapshotter(ins, func() ([]string, string) { return nil, "healthy" },
		func() model.DiagnoseReport { return shared })
	verdict := "node_not_saturated"
	s.SetPostgres(func() string { return verdict }, false)
	ctx := context.Background()
	if s.Check(ctx, tStart) {
		t.Fatal("a non-overload verdict must not trigger")
	}
	verdict = "background_overload"
	if !s.Check(ctx, tStart) {
		t.Fatal("background_overload must trigger")
	}
	if v := testutil.ToFloat64(sink.m.snapshots.WithLabelValues("postgres_verdict")); v != 1 {
		t.Fatalf("snapshots_total{postgres_verdict} = %v", v)
	}
	rows := gunzipRows(t, ins.sent[0].body)
	if rows[0]["reason"] != "postgres_verdict:background_overload" || strings.Contains(rows[0]["report"].(string), "secret") {
		t.Fatalf("row %v", rows[0])
	}
	if shared.PostgresReport.Clusters[0].TopDigests[0].SampleQuery == "" {
		t.Fatal("stripping must not mutate the shared report")
	}
}

func TestReasonKindMultiple(t *testing.T) {
	if k := reasonKind("module:cpu_profile;postgres_verdict:query_cpu_overload"); k != "both" {
		t.Fatalf("kind %q", k)
	}
	if k := reasonKind("io_verdict:storage_latency_stall"); k != "io_verdict" {
		t.Fatalf("kind %q", k)
	}
}

func TestStripPostgresKeepsWhenIncluded(t *testing.T) {
	r := StripPostgres(pgReport(), true)
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), "secret") {
		t.Fatal("include=true keeps samples")
	}
}
