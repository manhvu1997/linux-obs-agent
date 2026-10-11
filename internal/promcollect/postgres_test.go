package promcollect

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func pgView(diskBytes string) postgres.ClusterView {
	cov := 71.0
	return postgres.ClusterView{
		Name: "postgresql@16-main.service", PostmasterPID: 100,
		Snapshot: &querystats.Snapshot{
			QueryCPUMsTotal: 5000, QueryCPUCoveragePercent: &cov,
			Commands: map[string]model.QueryCounters{"client": {Calls: 10, CPUNs: 5e9, WallNs: 9e9, DiskReadBytes: 1 << 20, RedoWaitNs: 1e9}},
			Exported: []querystats.ExportedDigest{{ID: "d1", Text: "select * from orders where id = ?",
				Counters: model.QueryCounters{Calls: 10, CPUNs: 5e9, DiskReadBytes: 1 << 20}, WindowCPUNs: 5e9}},
		},
		Accounting: map[string]string{"disk_bytes": diskBytes, "disk_wait": "ok", "wal_wait": "ok", "syncrep_wait": "not_attached", "cpu_wait": "ok"},
		Backends:   map[string]postgres.BackendLife{"autovacuum": {CPUSeconds: 12, ReadBytes: 4096}},
	}
}

func collect(t *testing.T, c prometheus.Collector) string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			b.WriteString(mf.GetName())
			for _, l := range m.GetLabel() {
				b.WriteString(" " + l.GetName() + "=" + l.GetValue())
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func TestPostgresCollectorSeries(t *testing.T) {
	c := NewPostgresCollector(func() []postgres.ClusterView { return []postgres.ClusterView{pgView("ok")} },
		PostgresHealth{Active: func() bool { return true }}, config.DigestsMinimal, 20, true)
	out := collect(t, c)
	for _, want := range []string{
		"obs_agent_postgres_queries_total cluster=postgresql@16-main.service command=client",
		"obs_agent_postgres_query_wal_wait_seconds_total cluster=postgresql@16-main.service command=client",
		"obs_agent_postgres_query_disk_read_bytes_total cluster=postgresql@16-main.service command=client",
		"obs_agent_postgres_digest_cpu_seconds_total cluster=postgresql@16-main.service digest_id=d1",
		"obs_agent_postgres_digest_cpu_seconds_total cluster=postgresql@16-main.service digest_id=other",
		"obs_agent_postgres_digest_info cluster=postgresql@16-main.service digest_id=d1 digest_text=select * from orders where id = ?",
		"obs_agent_postgres_backend_cpu_seconds_total backend_type=autovacuum cluster=postgresql@16-main.service",
		"obs_agent_postgres_query_cpu_coverage_ratio cluster=postgresql@16-main.service",
		"obs_agent_postgres_tracing_active\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "syncrep_wait_seconds_total") {
		t.Error("an unattached wait must be absent, not 0")
	}
	if strings.Contains(out, "pid") {
		t.Error("never label by pid")
	}
}

func TestPostgresCollectorAsyncDiskAbsent(t *testing.T) {
	c := NewPostgresCollector(func() []postgres.ClusterView { return []postgres.ClusterView{pgView("io_method_async")} },
		PostgresHealth{}, config.DigestsOff, 20, false)
	out := collect(t, c)
	if strings.Contains(out, "query_disk_read_bytes_total") || strings.Contains(out, "digest_cpu_seconds_total") || strings.Contains(out, "backend_disk_read_bytes_total") {
		t.Fatalf("absent series emitted:\n%s", out)
	}
}

// Under PG 18 async I/O (accounting.disk_bytes != ok) the digest disk-read
// series would carry 0 / partial values: they are not emitted, in any mode.
func TestPostgresDigestDiskReadGatedOnDiskBytes(t *testing.T) {
	for _, mode := range []string{config.DigestsMinimal, config.DigestsFull} {
		for _, tc := range []struct {
			disk string
			want bool
		}{{"ok", true}, {"io_method_async", false}} {
			c := NewPostgresCollector(func() []postgres.ClusterView { return []postgres.ClusterView{pgView(tc.disk)} },
				PostgresHealth{Active: func() bool { return true }}, mode, 20, true)
			got := strings.Contains(collect(t, c), "obs_agent_postgres_digest_disk_read_bytes_total")
			if got != tc.want {
				t.Errorf("mode %s disk_bytes=%s: digest disk series present=%v, want %v", mode, tc.disk, got, tc.want)
			}
		}
	}
}
