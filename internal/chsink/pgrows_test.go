package chsink

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/pgdrain"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func pgDrain(async bool) pgdrain.Drain {
	d := sqldigest.NormalizeDialect("select * from orders where id = 1", sqldigest.Postgres)
	hw := querystats.HostWindow{Samples: 12, NumCPU: 8, NodeCPUUsedNs: 400e9, NodeOK: true, DiskOK: true,
		DiskReadBytes: 1 << 30, IOWaitOK: true, RedoWaitOK: true, DiskBytesOK: !async, MysqldCPUNs: 7e9, MysqldOK: true}
	return pgdrain.Drain{
		Clusters: []pgdrain.Cluster{{Cluster: "postgresql@16-main.service", PostmasterPID: 100, Host: hw, DiskEstimated: async,
			Digests: []querystats.DigestDelta{{PID: 100, DigestID: d.ID, Command: "client", Text: d.Text,
				Sample: "select * from orders where id = 1", Calls: 10, CPUNs: 5e9, WallNs: 9e9, WallMaxNs: 2e9,
				DiskReadBytes: 4096, RedoWaitNs: 1e9, ReplicaWaitNs: 7}},
			Enrich: map[string]pgdrain.Enrich{d.ID: {SharedHit: 90, SharedRead: 10, TempWritten: 0}},
			Slow:   []model.PGSlowQuery{{PID: 7, DigestID: d.ID, DigestText: d.Text, SampleQuery: "select * from orders where id = 1", LatencyMs: 500, Timestamp: time.Unix(1, 0)}}}},
		Backends: []pgdrain.Backend{{Cluster: "postgresql@16-main.service", Type: "autovacuum", CPUNs: 3e9, ReadBytes: 1 << 20, IOMeasured: true, ProcessesMax: 2},
			{Cluster: "postgresql@16-main.service", Type: "walwriter"}},
	}
}

func TestPGDigestRowsNullRules(t *testing.T) {
	d := pgDrain(true)
	rows := pgDigestRows("h", flushWindow{tStart, tStart.Add(time.Minute)}, d.Clusters[0], d.Clusters[0].Digests)
	r := rows[0]
	if r.DiskReadBytes != nil || r.DiskWriteBytes != nil || r.DiskEstimated != 1 {
		t.Fatalf("async disk must be NULL with disk_estimated = 1: %+v", r)
	}
	if r.WALWaitNs == nil || *r.WALWaitNs != 1e9 || r.SyncRepWaitNs != nil || r.IOWaitNs == nil {
		t.Fatalf("waits %+v", r)
	}
	if r.SharedBlksRead == nil || *r.SharedBlksRead != 10 || r.Cluster != "postgresql@16-main.service" || r.PostmasterPID != 100 {
		t.Fatalf("enrichment / identity %+v", r)
	}
	sync := pgDrain(false)
	if rr := pgDigestRows("h", flushWindow{}, sync.Clusters[0], sync.Clusters[0].Digests); rr[0].DiskReadBytes == nil || *rr[0].DiskReadBytes != 4096 {
		t.Fatalf("measured disk %+v", rr[0])
	}
}

func TestPGSlowRowsPrivacy(t *testing.T) {
	ev := pgDrain(false).Clusters[0].Slow
	if q := pgSlowRows("h", "c", ev, false)[0].Query; q != "select * from orders where id = ?" {
		t.Fatalf("stripped query %q", q)
	}
	if q := pgSlowRows("h", "c", ev, true)[0].Query; q != "select * from orders where id = 1" {
		t.Fatalf("raw query %q", q)
	}
}

func TestPGBackendRowsSkipEmpty(t *testing.T) {
	rows := pgBackendRows("h", flushWindow{}, pgDrain(false).Backends)
	if len(rows) != 1 || rows[0].BackendType != "autovacuum" || rows[0].DiskReadBytes == nil {
		t.Fatalf("rows %+v", rows)
	}
}

func gunzipRows(t *testing.T, gz []byte) []map[string]any {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestFlushPostgresTablesAndHostStats(t *testing.T) {
	ins := &fakeIns{}
	s := NewSink(testCfg(), "h", ins, Sources{Postgres: func() pgdrain.Drain { return pgDrain(false) }}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	got := map[string][]byte{}
	for _, x := range ins.sent {
		got[x.table] = x.body
	}
	for _, tb := range []string{TablePGDigestStats, TablePGDigestText, TablePGSlowQueries, TablePGBackends, TableHostStats} {
		if got[tb] == nil {
			t.Errorf("no %s batch (sent %v)", tb, ins.tables())
		}
	}
	host := gunzipRows(t, got[TableHostStats])[0]
	if host["mysqld_cpu_ns"] != nil {
		t.Fatalf("PostgreSQL-sourced host_stats must leave mysqld_cpu_ns NULL: %v", host)
	}
	text := gunzipRows(t, got[TablePGDigestText])[0]
	if text["sample_query"] != nil {
		t.Fatalf("sample_query needs PostgresIncludeSamples: %v", text)
	}
	// Text is sent once.
	ins.sent = nil
	s.Flush(context.Background(), tStart.Add(2*time.Minute))
	for _, x := range ins.sent {
		if x.table == TablePGDigestText {
			t.Fatal("pg digest text resent")
		}
	}
}
