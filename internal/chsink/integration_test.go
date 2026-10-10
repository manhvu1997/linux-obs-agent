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
		MaxBufferBytes: 1 << 20, MaxBatchesPerFlush: 20, MinDigestSharePercent: 0.1,
		Snapshots: config.ClickHouseSnapshotConfig{Enabled: true, CheckInterval: time.Second, MinInterval: time.Minute}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := Sources{
		// "a" dominates; "b" and "c" are each under 0.1 % of the query CPU
		// and disk reads and faster than SlowWallNs: they fold into <minor>.
		Digests: func() ([]querystats.DigestDelta, uint64) {
			return []querystats.DigestDelta{
				{PID: 1, DigestID: "a", Command: "query", Text: "select ?", Calls: 3, CPUNs: 1_000_000, WallNs: 3_000_000, WallMaxNs: 1_500_000,
					DiskReadBytes: 16384, DiskWriteBytes: 4096, IOWaitNs: 700, RedoWaitNs: 500},
				{PID: 1, DigestID: "b", Command: "query", Text: "update t set x = ?", Calls: 2, CPUNs: 200, WallNs: 400, WallMaxNs: 300,
					IOWaitNs: 7, RedoWaitNs: 5},
				{PID: 1, DigestID: "c", Command: "query", Text: "select ? from dual", Calls: 1, CPUNs: 100, WallNs: 200, WallMaxNs: 200,
					IOWaitNs: 3, RedoWaitNs: 2},
			}, 0
		},
		// Disk wait not measurable in this interval, commit wait measured.
		Host: func() querystats.HostWindow {
			return querystats.HostWindow{Samples: 12, NumCPU: 4, NodeCPUUsedNs: 90e9, MysqldCPUNs: 30e9,
				DiskReadBytes: 1 << 20, DiskWriteBytes: 1 << 18,
				NodeOK: true, MysqldOK: true, DiskOK: true, IOWaitOK: false, RedoWaitOK: true}
		},
		SlowWallNs: 100_000_000,
		Flows: func() ([]netflow.FlowDelta, uint64) {
			return []netflow.FlowDelta{{TGID: 9, Family: "mysql.service", Direction: "inbound",
				Peer: netip.MustParseAddr("10.0.0.2"), ServicePort: 3306, BytesRx: 10, BytesTx: 100, Opened: 1}}, 0
		},
		Slow: func() ([]model.SlowQuery, uint64) {
			return []model.SlowQuery{{DigestID: "d1", Event: model.MySQLSlowEvent{PID: 1, TID: 2, Comm: "mysqld", LatencyMs: 900, Query: "select 1", Timestamp: time.Now()}}}, 0
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
		TablePeerStats: "1", TableFamilyStats: "1", TableSnapshots: "1", TableHostStats: "1",
	} {
		if got := chExec(t, base, "SELECT count() FROM "+db+"."+table); got != want {
			t.Errorf("%s rows = %s, want %s", table, got, want)
		}
	}
	if got := chExec(t, base, "SELECT sum(calls) FROM "+db+".mysql_digest_stats"); got != "6" {
		t.Errorf("sum(calls) = %s, want 6", got)
	}
	ds := db + ".mysql_digest_stats"
	for q, want := range map[string]string{
		// Folding: b and c became one <minor> row; sums stay exact.
		"SELECT count() FROM " + ds + " WHERE digest_id = '" + MinorDigestID + "'":                             "1",
		"SELECT sum(calls), sum(cpu_ns) FROM " + ds + " WHERE digest_id = '" + MinorDigestID + "'":             "3\t300",
		"SELECT digest_text FROM " + db + ".mysql_digest_text FINAL WHERE digest_id = '" + MinorDigestID + "'": MinorDigestText,
		// IOWaitOK=false: every row's io_wait_ns is NULL, and sum() over the
		// all-NULL column is NULL (not 0).
		"SELECT countIf(io_wait_ns IS NULL) = count() FROM " + ds: "1",
		"SELECT isNull(sum(io_wait_ns)) FROM " + ds:               "1",
		// RedoWaitOK=true: measured, including the folded row.
		"SELECT countIf(redo_wait_ns IS NULL) FROM " + ds:               "0",
		"SELECT sum(redo_wait_ns) FROM " + ds:                           "507",
		"SELECT sum(disk_read_bytes), sum(disk_write_bytes) FROM " + ds: "16384\t4096",
		// host_stats: one row, all values measured.
		"SELECT cpu_count, node_cpu_used_ns, mysqld_cpu_ns, disk_read_bytes, disk_write_bytes FROM " + db + ".host_stats": "4\t90000000000\t30000000000\t1048576\t262144",
	} {
		if got := chExec(t, base, q); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
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

// oldDigestStatsDDL is mysql_digest_stats as created before the disk and wait
// columns (with bytes_in): the table a pre-upgrade database still has.
const oldDigestStatsDDL = `CREATE TABLE %s.mysql_digest_stats (
  window_start DateTime('UTC'),
  window_end   DateTime('UTC'),
  host         LowCardinality(String),
  pid          UInt32,
  digest_id    String,
  command      LowCardinality(String),
  calls        UInt64,
  cpu_ns       UInt64,
  runq_ns      UInt64,
  wall_ns      UInt64,
  wall_max_ns  UInt64,
  bytes_in     UInt64,
  bytes_out    UInt64
) ENGINE = MergeTree
PARTITION BY toDate(window_end)
ORDER BY (host, digest_id, window_end)
TTL window_end + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1`

// TestIntegrationMigration: a new agent writing into a pre-upgrade database
// keeps inserting digest rows (unknown fields skipped) and loses only
// host_stats; after `clickhouse-schema -alter` (applied twice: idempotent)
// the disk and wait columns and host_stats are populated.
func TestIntegrationMigration(t *testing.T) {
	base := os.Getenv("CLICKHOUSE_TEST_URL")
	if base == "" {
		t.Skip("CLICKHOUSE_TEST_URL not set (make test-clickhouse)")
	}
	db := fmt.Sprintf("obs_mig_%d", time.Now().UnixNano())
	opts := SchemaOptions{Database: db, RetentionDays: 30, SnapshotRetentionDays: 14}
	ddl, err := CreateDDL(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range statements(ddl) {
		chExec(t, base, st)
	}
	defer chExec(t, base, "DROP DATABASE "+db)
	// Turn it into the pre-upgrade schema: no host_stats, the old digest table.
	chExec(t, base, "DROP TABLE "+db+".host_stats")
	chExec(t, base, "DROP TABLE "+db+".mysql_digest_stats")
	chExec(t, base, fmt.Sprintf(oldDigestStatsDDL, db))

	cfg := &config.ClickHouseConfig{URL: base, Database: db, Timeout: 10 * time.Second, FlushInterval: time.Minute,
		MaxBufferBytes: 1 << 20, MaxBatchesPerFlush: 20}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	src := Sources{
		Digests: func() ([]querystats.DigestDelta, uint64) {
			return []querystats.DigestDelta{
				{PID: 1, DigestID: "a", Command: "query", Text: "select ?", Calls: 3, CPUNs: 300, WallNs: 900,
					DiskReadBytes: 16384, DiskWriteBytes: 4096, IOWaitNs: 70, RedoWaitNs: 50},
				{PID: 1, DigestID: "b", Command: "query", Text: "update t set x = ?", Calls: 2, CPUNs: 200, WallNs: 600,
					DiskReadBytes: 8192, IOWaitNs: 30, RedoWaitNs: 20},
			}, 0
		},
		Host: func() querystats.HostWindow {
			return querystats.HostWindow{Samples: 12, NumCPU: 4, NodeCPUUsedNs: 90e9, MysqldCPUNs: 30e9,
				DiskReadBytes: 1 << 20, DiskWriteBytes: 1 << 18,
				NodeOK: true, MysqldOK: true, DiskOK: true, IOWaitOK: true, RedoWaitOK: true}
		},
		SlowWallNs: 100_000_000,
	}
	t0 := time.Now().Add(-3 * time.Minute).UTC().Truncate(time.Second)
	end1, end2 := t0.Add(time.Minute), t0.Add(2*time.Minute)
	sink := NewSink(cfg, "mig-host", client, src, t0)
	ds := db + ".mysql_digest_stats"
	at := func(end time.Time) string { return " WHERE window_end = toDateTime('" + chTime(end) + "', 'UTC')" }

	// Before the migration: digest rows land, host_stats is rejected.
	sink.Flush(context.Background(), end1)
	if got := chExec(t, base, "SELECT count(), sum(calls) FROM "+ds+at(end1)); got != "2\t5" {
		t.Errorf("pre-migration digest rows = %q, want 2 rows, 5 calls", got)
	}
	if v := testutil.ToFloat64(sink.m.dropped.WithLabelValues(TableHostStats, "rejected")); v != 1 {
		t.Errorf("host_stats before migration: rejected = %v, want 1", v)
	}
	if got := chExec(t, base, "EXISTS TABLE "+db+".host_stats"); got != "0" {
		t.Errorf("host_stats exists before the migration: %s", got)
	}

	mig, err := MigrateDDL(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // idempotent
		for _, st := range statements(mig) {
			chExec(t, base, st)
		}
	}
	if got := chExec(t, base, "SELECT groupArray(name) FROM (SELECT name FROM system.columns WHERE database = '"+db+
		"' AND table = 'mysql_digest_stats' AND name IN ('bytes_in', 'disk_read_bytes', 'disk_write_bytes', 'io_wait_ns', 'redo_wait_ns') ORDER BY position)"); got != "['disk_read_bytes','disk_write_bytes','io_wait_ns','redo_wait_ns']" {
		t.Errorf("migrated columns = %s", got)
	}

	// After the migration: everything is populated.
	sink.Flush(context.Background(), end2)
	for q, want := range map[string]string{
		"SELECT count(), sum(disk_read_bytes), sum(disk_write_bytes), sum(io_wait_ns), sum(redo_wait_ns) FROM " + ds + at(end2): "2\t24576\t4096\t100\t70",
		"SELECT count(), any(cpu_count), any(disk_read_bytes) FROM " + db + ".host_stats" + at(end2):                            "1\t4\t1048576",
		// Rows written before the migration: disk bytes read 0, waits NULL.
		"SELECT countIf(disk_read_bytes = 0 AND disk_write_bytes = 0 AND io_wait_ns IS NULL AND redo_wait_ns IS NULL) FROM " + ds + at(end1): "2",
	} {
		if got := chExec(t, base, q); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
}
