package chsink

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

type sent struct {
	table string
	body  []byte
}

type fakeIns struct {
	mu       sync.Mutex
	outcomes []Outcome // consumed per call; empty = OK
	sent     []sent
	hook     func()
}

func (f *fakeIns) Insert(_ context.Context, table string, gz []byte) (Outcome, error) {
	if f.hook != nil {
		f.hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := OutcomeOK
	if len(f.outcomes) > 0 {
		out, f.outcomes = f.outcomes[0], f.outcomes[1:]
	}
	if out == OutcomeOK {
		f.sent = append(f.sent, sent{table, gz})
	}
	return out, nil
}

func (f *fakeIns) tables() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var t []string
	for _, s := range f.sent {
		t = append(t, s.table)
	}
	return t
}

func testCfg() *config.ClickHouseConfig {
	return &config.ClickHouseConfig{FlushInterval: time.Minute, Timeout: time.Second,
		MaxBufferBytes: 1 << 20, MaxBatchesPerFlush: 10}
}

var tStart = time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

func digestSource(ids ...string) func() ([]querystats.DigestDelta, uint64) {
	return func() ([]querystats.DigestDelta, uint64) {
		var out []querystats.DigestDelta
		for _, id := range ids {
			out = append(out, querystats.DigestDelta{PID: 1, DigestID: id, Text: "t " + id, Calls: 1})
		}
		return out, 0
	}
}

func TestFlushWindowsContiguous(t *testing.T) {
	ins := &fakeIns{}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart)
	s.Flush(context.Background(), tStart.Add(60*time.Second+400*time.Millisecond))
	s.Flush(context.Background(), tStart.Add(120*time.Second))
	var windows [][2]any
	for _, x := range ins.sent {
		if x.table == TableDigestStats {
			r := decodeRowsForTest(t, x.body)[0]
			windows = append(windows, [2]any{r["window_start"], r["window_end"]})
		}
	}
	want := [][2]any{
		{"2026-10-08 00:00:00", "2026-10-08 00:01:00"},
		{"2026-10-08 00:01:00", "2026-10-08 00:02:00"},
	}
	if len(windows) != 2 || windows[0] != want[0] || windows[1] != want[1] {
		t.Fatalf("windows = %v, want %v", windows, want)
	}
}

func TestFlushNilSources(t *testing.T) {
	ins := &fakeIns{}
	s := NewSink(testCfg(), "h", ins, Sources{}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	if len(ins.sent) != 0 {
		t.Fatalf("nil sources produced batches: %v", ins.tables())
	}
}

func TestDigestTextSentOnce(t *testing.T) {
	ins := &fakeIns{}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a", "b")}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	s.Flush(context.Background(), tStart.Add(2*time.Minute))
	n := 0
	for _, x := range ins.sent {
		if x.table == TableDigestText {
			n += len(decodeRowsForTest(t, x.body))
		}
	}
	if n != 2 {
		t.Fatalf("digest text rows = %d, want 2 (once per id)", n)
	}
}

func TestRetryKeepsBatchesInOrder(t *testing.T) {
	ins := &fakeIns{outcomes: []Outcome{OutcomeRetry}}
	cfg := testCfg()
	s := NewSink(cfg, "h", ins, Sources{Families: nil, Digests: digestSource("a")}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute)) // stats batch retried, text batch not tried
	if len(ins.sent) != 0 {
		t.Fatalf("sent after retry: %v", ins.tables())
	}
	s.Flush(context.Background(), tStart.Add(2*time.Minute))
	got := ins.tables()
	want := []string{TableDigestStats, TableDigestText, TableDigestStats}
	if len(got) != len(want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tables = %v, want %v", got, want)
		}
	}
	if v := testutil.ToFloat64(s.m.sent.WithLabelValues(TableDigestStats)); v != 2 {
		t.Fatalf("rows_sent{mysql_digest_stats} = %v, want 2", v)
	}
}

func TestRejectDropsAndCounts(t *testing.T) {
	ins := &fakeIns{outcomes: []Outcome{OutcomeReject}}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	if v := testutil.ToFloat64(s.m.dropped.WithLabelValues(TableDigestStats, "rejected")); v != 1 {
		t.Fatalf("rejected = %v, want 1", v)
	}
	if got := ins.tables(); len(got) != 1 || got[0] != TableDigestText {
		t.Fatalf("after reject the next batch must still go: %v", got)
	}
}

func TestBufferEvictsSnapshotsFirstThenOldest(t *testing.T) {
	cfg := testCfg()
	cfg.MaxBufferBytes = 250
	s := NewSink(cfg, "h", &fakeIns{}, Sources{}, tStart)
	s.enqueue(batch{table: TableFamilyStats, rows: 1, body: make([]byte, 100)})
	s.enqueue(batch{table: TableSnapshots, rows: 1, body: make([]byte, 100)})
	s.enqueue(batch{table: TablePeerStats, rows: 1, body: make([]byte, 100)}) // 300 > 250: snapshot goes
	if v := testutil.ToFloat64(s.m.dropped.WithLabelValues(TableSnapshots, "buffer_full")); v != 1 {
		t.Fatalf("snapshot not evicted first")
	}
	s.enqueue(batch{table: TableDigestStats, rows: 1, body: make([]byte, 100)}) // oldest (family) goes
	if v := testutil.ToFloat64(s.m.dropped.WithLabelValues(TableFamilyStats, "buffer_full")); v != 1 {
		t.Fatalf("oldest not evicted second")
	}
	if s.bufBytes != 200 || len(s.buf) != 2 {
		t.Fatalf("buffer = %d bytes, %d batches", s.bufBytes, len(s.buf))
	}
}

func TestOversizedBatchDropped(t *testing.T) {
	cfg := testCfg()
	cfg.MaxBufferBytes = 10
	s := NewSink(cfg, "h", &fakeIns{}, Sources{}, tStart)
	s.enqueue(batch{table: TableFamilyStats, rows: 3, body: make([]byte, 11)})
	if len(s.buf) != 0 || testutil.ToFloat64(s.m.dropped.WithLabelValues(TableFamilyStats, "buffer_full")) != 3 {
		t.Fatalf("oversized batch kept: %d batches", len(s.buf))
	}
}

func TestMaxBatchesPerFlush(t *testing.T) {
	cfg := testCfg()
	cfg.MaxBatchesPerFlush = 2
	ins := &fakeIns{}
	s := NewSink(cfg, "h", ins, Sources{}, tStart)
	for i := 0; i < 3; i++ {
		s.enqueue(batch{table: TableFamilyStats, rows: 1, body: []byte{1}})
	}
	s.send(context.Background())
	if len(ins.sent) != 2 || len(s.buf) != 1 {
		t.Fatalf("sent %d, left %d; want 2 and 1", len(ins.sent), len(s.buf))
	}
}

func TestClockStepBack(t *testing.T) {
	ins := &fakeIns{}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart.Add(time.Hour))
	s.Flush(context.Background(), tStart) // wall clock is now before the window start
	r := decodeRowsForTest(t, ins.sent[0].body)[0]
	if r["window_start"] != r["window_end"] || r["window_end"] != "2026-10-08 00:00:00" {
		t.Fatalf("window = %v..%v, want an empty window at the new time", r["window_start"], r["window_end"])
	}
}

func TestEvictionDuringSendKeepsOtherBatches(t *testing.T) {
	cfg := testCfg()
	cfg.MaxBufferBytes = 150
	ins := &fakeIns{}
	s := NewSink(cfg, "h", ins, Sources{}, tStart)
	s.enqueue(batch{table: TableFamilyStats, rows: 1, body: make([]byte, 60)})
	s.enqueue(batch{table: TablePeerStats, rows: 1, body: make([]byte, 60)})
	once := sync.Once{}
	ins.hook = func() { // while the family batch is in flight, a new batch evicts it
		once.Do(func() { s.enqueue(batch{table: TableDigestStats, rows: 1, body: make([]byte, 60)}) })
	}
	s.send(context.Background())
	got := ins.tables()
	want := []string{TableFamilyStats, TablePeerStats, TableDigestStats}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("sent %v, want %v (no batch lost to a wrong removal)", got, want)
	}
}

func TestRunShutdownCountsUnsent(t *testing.T) {
	ins := &fakeIns{outcomes: []Outcome{OutcomeRetry, OutcomeRetry, OutcomeRetry}}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Run(ctx) // returns after the final flush
	if v := testutil.ToFloat64(s.m.dropped.WithLabelValues(TableDigestStats, "shutdown")); v != 1 {
		t.Fatalf("shutdown drops = %v, want 1", v)
	}
}

func TestHostInfoMetric(t *testing.T) {
	s := NewSink(testCfg(), "db-01", &fakeIns{}, Sources{}, tStart)
	if v := testutil.ToFloat64(s.m.hostInfo.WithLabelValues("db-01")); v != 1 {
		t.Fatalf("host_info = %v", v)
	}
}

func TestOversizedKeepsOlderBatches(t *testing.T) {
	cfg := testCfg()
	cfg.MaxBufferBytes = 100
	s := NewSink(cfg, "h", &fakeIns{}, Sources{}, tStart)
	s.enqueue(batch{table: TableFamilyStats, rows: 1, body: make([]byte, 30)})
	s.enqueue(batch{table: TablePeerStats, rows: 1, body: make([]byte, 30)})
	s.enqueue(batch{table: TableDigestStats, rows: 4, body: make([]byte, 101)})
	if len(s.buf) != 2 || s.bufBytes != 60 {
		t.Fatalf("older batches lost: %d batches, %d bytes", len(s.buf), s.bufBytes)
	}
	if v := testutil.ToFloat64(s.m.dropped.WithLabelValues(TableDigestStats, "buffer_full")); v != 4 {
		t.Fatalf("oversized drop = %v, want 4", v)
	}
}

func textCount(ins *fakeIns, t *testing.T) int {
	n := 0
	for _, x := range ins.sent {
		if x.table == TableDigestText {
			n += len(decodeRowsForTest(t, x.body))
		}
	}
	return n
}

func TestEvictedDigestTextIsResent(t *testing.T) {
	cfg := testCfg()
	ins := &fakeIns{}
	s := NewSink(cfg, "h", ins, Sources{Digests: digestSource("a")}, tStart)
	cfg.MaxBufferBytes = 1 // every batch is dropped as buffer_full
	s.Flush(context.Background(), tStart.Add(time.Minute))
	if textCount(ins, t) != 0 {
		t.Fatal("nothing should have been sent")
	}
	cfg.MaxBufferBytes = 1 << 20
	s.Flush(context.Background(), tStart.Add(2*time.Minute))
	if n := textCount(ins, t); n != 1 {
		t.Fatalf("text rows after eviction = %d, want 1 (resent)", n)
	}
}

func TestRejectedDigestTextIsResent(t *testing.T) {
	ins := &fakeIns{outcomes: []Outcome{OutcomeOK, OutcomeReject}} // stats ok, text rejected
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	s.Flush(context.Background(), tStart.Add(2*time.Minute))
	if n := textCount(ins, t); n != 1 {
		t.Fatalf("text rows after reject = %d, want 1 (resent)", n)
	}
}

func TestDeliveredDigestTextNotResent(t *testing.T) {
	ins := &fakeIns{}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	s.Flush(context.Background(), tStart.Add(2*time.Minute))
	if n := textCount(ins, t); n != 1 {
		t.Fatalf("text rows = %d, want 1", n)
	}
}

func TestShutdownForgetsDigestText(t *testing.T) {
	ins := &fakeIns{outcomes: []Outcome{OutcomeRetry}}
	s := NewSink(testCfg(), "h", ins, Sources{Digests: digestSource("a")}, tStart)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Run(ctx)
	if !s.seen.addNew("a") {
		t.Fatal("id still marked seen after its text was dropped at shutdown")
	}
}

func TestFlushHostStatsWaitsAndMinorFold(t *testing.T) {
	ins := &fakeIns{}
	cfg := testCfg()
	cfg.MinDigestSharePercent = 0.1
	src := Sources{
		Digests: func() ([]querystats.DigestDelta, uint64) {
			return []querystats.DigestDelta{
				fdd(1, "big", "query", 1_000_000, 0, 5),
				fdd(1, "tiny1", "query", 10, 0, 5),
				fdd(1, "tiny2", "query", 20, 0, 5),
				fdd(1, "cheap-but-slow", "query", 10, 0, 5_000),
			}, 0
		},
		Host: func() querystats.HostWindow {
			return querystats.HostWindow{Samples: 12, NumCPU: 8, NodeCPUUsedNs: 3e11, MysqldCPUNs: 1e11, DiskReadBytes: 5, DiskWriteBytes: 6,
				NodeOK: true, MysqldOK: true, DiskOK: true, IOWaitOK: true, RedoWaitOK: false}
		},
		SlowWallNs: 1_000,
	}
	s := NewSink(cfg, "h", ins, src, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))

	var host, stats, texts []map[string]any
	for _, x := range ins.sent {
		switch x.table {
		case TableHostStats:
			host = append(host, decodeRowsForTest(t, x.body)...)
		case TableDigestStats:
			stats = append(stats, decodeRowsForTest(t, x.body)...)
		case TableDigestText:
			texts = append(texts, decodeRowsForTest(t, x.body)...)
		}
	}
	if len(host) != 1 || host[0]["cpu_count"] != float64(8) || host[0]["node_cpu_used_ns"] != float64(3e11) ||
		host[0]["host"] != "h" || host[0]["window_end"] != "2026-10-08 00:01:00" {
		t.Fatalf("host_stats rows = %+v", host)
	}
	ids := map[string]map[string]any{}
	for _, r := range stats {
		ids[r["digest_id"].(string)] = r
	}
	if len(stats) != 3 || ids["big"] == nil || ids["cheap-but-slow"] == nil || ids[MinorDigestID] == nil {
		t.Fatalf("digest rows = %+v, want big, cheap-but-slow and one <minor>", stats)
	}
	if m := ids[MinorDigestID]; m["calls"] != float64(2) || m["cpu_ns"] != float64(30) {
		t.Fatalf("<minor> = %+v", m)
	}
	if r := ids["big"]; r["io_wait_ns"] != float64(1) || r["redo_wait_ns"] != nil {
		t.Fatalf("waits must follow the host window flags: %+v", r)
	}
	var minorText bool
	for _, r := range texts {
		if r["digest_id"] == MinorDigestID {
			minorText = r["digest_text"] == MinorDigestText
		}
		if r["digest_id"] == "tiny1" || r["digest_id"] == "tiny2" {
			t.Fatalf("folded digest must not get a text row: %+v", r)
		}
	}
	if !minorText {
		t.Fatalf("digest_text rows = %+v, want the <minor> text", texts)
	}
}

func TestFlushWithoutHostSourceWritesNullWaits(t *testing.T) {
	ins := &fakeIns{}
	src := Sources{Digests: func() ([]querystats.DigestDelta, uint64) {
		return []querystats.DigestDelta{{PID: 1, DigestID: "a", Command: "query", Calls: 1, IOWaitNs: 7, RedoWaitNs: 9}}, 0
	}}
	s := NewSink(testCfg(), "h", ins, src, tStart)
	s.Flush(context.Background(), tStart.Add(time.Minute))
	for _, x := range ins.sent {
		if x.table == TableHostStats {
			t.Fatal("nil Sources.Host must not write host_stats")
		}
		if x.table == TableDigestStats {
			r := decodeRowsForTest(t, x.body)[0]
			if v, ok := r["io_wait_ns"]; !ok || v != nil {
				t.Fatalf("io_wait_ns = %v (present %v), want null", v, ok)
			}
			if v, ok := r["redo_wait_ns"]; !ok || v != nil {
				t.Fatalf("redo_wait_ns = %v (present %v), want null", v, ok)
			}
		}
	}
}
