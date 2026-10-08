//go:build integration

package chsink

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func chExec(t *testing.T, base, q string) string {
	t.Helper()
	resp, err := http.Post(base+"/", "text/plain", strings.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: HTTP %d %s", q, resp.StatusCode, b)
	}
	return strings.TrimSpace(string(b))
}

func statements(ddl string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(ddl, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		cur.WriteString(line + "\n")
		if strings.HasSuffix(strings.TrimSpace(line), ";") {
			out = append(out, strings.TrimSuffix(strings.TrimSpace(cur.String()), ";"))
			cur.Reset()
		}
	}
	return out
}

func TestIntegrationRoundTrip(t *testing.T) {
	base := os.Getenv("CLICKHOUSE_TEST_URL")
	if base == "" {
		t.Skip("CLICKHOUSE_TEST_URL not set (make test-clickhouse)")
	}
	db := fmt.Sprintf("obs_it_%d", time.Now().UnixNano())
	ddl, err := CreateDDL(SchemaOptions{Database: db, RetentionDays: 30, SnapshotRetentionDays: 14})
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range statements(ddl) {
		chExec(t, base, st)
	}
	defer chExec(t, base, "DROP DATABASE "+db)

	cfg := &config.ClickHouseConfig{URL: base, Database: db, Timeout: 10 * time.Second, FlushInterval: time.Minute,
		MaxBufferBytes: 1 << 20, MaxBatchesPerFlush: 20,
		Snapshots: config.ClickHouseSnapshotConfig{Enabled: true, CheckInterval: time.Second, MinInterval: time.Minute}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := Sources{
		Digests: func() ([]querystats.DigestDelta, uint64) {
			return []querystats.DigestDelta{
				{PID: 1, DigestID: "a", Command: "query", Text: "select ?", Calls: 3, CPUNs: 300},
				{PID: 1, DigestID: "b", Command: "query", Text: "update t set x = ?", Calls: 2, CPUNs: 200},
			}, 0
		},
		Flows: func() ([]netflow.FlowDelta, uint64) {
			return []netflow.FlowDelta{{TGID: 9, Family: "mysql.service", Direction: "inbound",
				Peer: netip.MustParseAddr("10.0.0.2"), ServicePort: 3306, BytesRx: 10, BytesTx: 100, Opened: 1}}, 0
		},
		Slow: func() ([]model.MySQLSlowEvent, uint64) {
			return []model.MySQLSlowEvent{{PID: 1, TID: 2, Comm: "mysqld", LatencyMs: 900, Query: "select 1", Timestamp: time.Now()}}, 0
		},
		Families: func() []process.FamilyWindow {
			return []process.FamilyWindow{{Family: "mysql.service", CPUPercentAvg: 5}}
		},
		Comm: func(uint32) string { return "mysqld" },
	}
	start := time.Now().Add(-time.Minute)
	sink := NewSink(cfg, "it-host", client, src, start)
	sink.Flush(context.Background(), time.Now())
	snap := NewSnapshotter(cfg, "it-host", sink,
		func() ([]string, string) { return []string{"cpu_profile"}, "" },
		func() model.DiagnoseReport { return model.DiagnoseReport{Hostname: "it-host"} })
	if !snap.Check(context.Background(), time.Now()) {
		t.Fatal("snapshot not captured")
	}

	for table, want := range map[string]string{
		TableDigestStats: "2", TableDigestText: "2", TableSlowQueries: "1",
		TablePeerStats: "1", TableFamilyStats: "1", TableSnapshots: "1",
	} {
		if got := chExec(t, base, "SELECT count() FROM "+db+"."+table); got != want {
			t.Errorf("%s rows = %s, want %s", table, got, want)
		}
	}
	if got := chExec(t, base, "SELECT sum(calls) FROM "+db+".mysql_digest_stats"); got != "5" {
		t.Errorf("sum(calls) = %s, want 5", got)
	}
	if got := chExec(t, base, "SELECT toString(peer_ip) FROM "+db+".netflow_peer_stats"); got != "::ffff:10.0.0.2" {
		t.Errorf("peer_ip = %s", got)
	}

	chExec(t, base, "DROP TABLE "+db+".family_stats")
	sink.Flush(context.Background(), time.Now().Add(time.Minute))
	if v := testutil.ToFloat64(sink.m.dropped.WithLabelValues(TableFamilyStats, "rejected")); v != 1 {
		t.Errorf("missing table: rejected = %v, want 1", v)
	}
}
