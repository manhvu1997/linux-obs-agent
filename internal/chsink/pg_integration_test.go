//go:build integration

package chsink

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/pgdrain"
)

func TestIntegrationPostgres(t *testing.T) {
	base := os.Getenv("CLICKHOUSE_TEST_URL")
	if base == "" {
		t.Skip("CLICKHOUSE_TEST_URL not set (make test-clickhouse)")
	}
	db := fmt.Sprintf("obs_pg_it_%d", time.Now().UnixNano())
	ddl, err := CreateDDL(SchemaOptions{Database: db, RetentionDays: 30, SnapshotRetentionDays: 14})
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range statements(ddl) {
		chExec(t, base, st)
	}
	defer chExec(t, base, "DROP DATABASE "+db)
	cfg := &config.ClickHouseConfig{URL: base, Database: db, Timeout: 10 * time.Second, FlushInterval: time.Minute,
		MaxBufferBytes: 1 << 20, MaxBatchesPerFlush: 20}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sink := NewSink(cfg, "it-host", client, Sources{Postgres: func() pgdrain.Drain { return pgDrain(true) },
		PostgresSlowWallNs: 100_000_000}, time.Now().Add(-time.Minute))
	sink.Flush(context.Background(), time.Now())
	for table, want := range map[string]string{TablePGDigestStats: "1", TablePGDigestText: "1",
		TablePGSlowQueries: "1", TablePGBackends: "1", TableHostStats: "1"} {
		if got := chExec(t, base, "SELECT count() FROM "+db+"."+table); got != want {
			t.Errorf("%s rows = %s, want %s", table, got, want)
		}
	}
	got := chExec(t, base, "SELECT isNull(disk_read_bytes), disk_estimated, wal_wait_ns, isNull(syncrep_wait_ns), shared_blks_read FROM "+db+".pg_digest_stats")
	if got != "1\t1\t1000000000\t1\t10" {
		t.Errorf("pg_digest_stats NULL rules: %q", got)
	}
	if got := chExec(t, base, "SELECT isNull(mysqld_cpu_ns) FROM "+db+".host_stats"); got != "1" {
		t.Errorf("host_stats.mysqld_cpu_ns from PostgreSQL must be NULL, got %s", got)
	}
}
