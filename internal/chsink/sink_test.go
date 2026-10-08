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
