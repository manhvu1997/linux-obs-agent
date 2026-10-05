package promcollect

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func snap(text string) *querystats.Snapshot {
	return &querystats.Snapshot{
		Commands: map[string]model.QueryCounters{"query": {Calls: 2, CPUNs: 1_500_000_000, RunqNs: 500_000_000, WallNs: 3_000_000_000, BytesIn: 100, BytesOut: 9000}},
		Exported: []querystats.ExportedDigest{{ID: "aaa", Text: text, Counters: model.QueryCounters{Calls: 2, CPUNs: 1_500_000_000, BytesOut: 9000}}},
	}
}

func TestMySQLCollector(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap("select * from t") }, func() uint64 { return 7 })
	want := `
# HELP obs_agent_mysql_digest_cpu_seconds_total On-CPU seconds spent executing statements of this digest.
# TYPE obs_agent_mysql_digest_cpu_seconds_total counter
obs_agent_mysql_digest_cpu_seconds_total{digest_id="aaa"} 1.5
# HELP obs_agent_mysql_events_dropped_total Per-statement events lost (ring buffer full or consumer behind); digest totals undercount when this rises.
# TYPE obs_agent_mysql_events_dropped_total counter
obs_agent_mysql_events_dropped_total 7
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_digest_cpu_seconds_total", "obs_agent_mysql_events_dropped_total"); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLCollectorNilSnapshot(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return nil }, func() uint64 { return 0 })
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_queries_total"); n != 0 {
		t.Fatalf("got %d series before any snapshot", n)
	}
}

func TestMySQLCollectorInvalidUTF8Label(t *testing.T) {
	long := strings.Repeat("ễ", 100) + "\xff"
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap(long) }, func() uint64 { return 0 })
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed — one bad digest must not break /metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "obs_agent_mysql_digest_info" {
			continue
		}
		for _, lp := range mf.GetMetric()[0].GetLabel() {
			if lp.GetName() == "digest_text" && (!utf8.ValidString(lp.GetValue()) || len(lp.GetValue()) > 120) {
				t.Fatalf("digest_text label invalid or too long (%d bytes)", len(lp.GetValue()))
			}
		}
	}
}

func TestSanitizeLabel(t *testing.T) {
	if got := SanitizeLabel("abcdef", 4); got != "abcd" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeLabel("ễễ", 4); got != "ễ" { // 3-byte rune; never split it
		t.Fatalf("got %q", got)
	}
}
