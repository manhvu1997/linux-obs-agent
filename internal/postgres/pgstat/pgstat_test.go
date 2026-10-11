package pgstat

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeConn struct {
	s      Settings
	rows   []Row
	err    error
	closed bool
	asked  []int64
}

func (f *fakeConn) Settings(context.Context) (Settings, error) { return f.s, nil }
func (f *fakeConn) Statements(_ context.Context, ids []int64, col string) ([]Row, error) {
	f.asked = ids
	if col != "shared_blk_read_time" {
		return nil, errors.New("wrong column for 17")
	}
	return f.rows, f.err
}
func (f *fakeConn) Close() { f.closed = true }

func TestPollDeltas(t *testing.T) {
	c := &fakeConn{s: Settings{VersionNum: 170002, ComputeQueryID: "auto", IOMethod: ""}}
	e := NewEnricher(func(context.Context, int) (Conn, error) { return c, nil })
	t0 := time.Unix(0, 0)
	c.rows = []Row{{QueryID: 7, Calls: 10, SharedRead: 100}, {QueryID: 7, Calls: 5, SharedRead: 50}}
	e.Poll(context.Background(), 5432, []int64{7}, t0)
	c.rows = []Row{{QueryID: 7, Calls: 20, SharedRead: 400, SharedHit: 10}}
	e.Poll(context.Background(), 5432, []int64{7}, t0.Add(time.Minute))
	v := e.Snapshot(5432)
	if !v.Known || v.Status != StatusOK || v.Window != time.Minute || v.At != t0.Add(time.Minute) ||
		v.Deltas[7].Calls != 5 || v.Deltas[7].SharedRead != 250 || v.Deltas[7].SharedHit != 10 {
		t.Fatalf("view %+v", v)
	}
	if len(c.asked) != 1 || c.asked[0] != 7 {
		t.Fatalf("query filtered by ids: %v", c.asked)
	}
}

// Review Focus 4.
func TestDiffRowsSkipsReset(t *testing.T) {
	prev := map[int64]Row{1: {QueryID: 1, Calls: 100, SharedRead: 1000}, 2: {QueryID: 2, Calls: 5}}
	cur := map[int64]Row{1: {QueryID: 1, Calls: 3, SharedRead: 10}, 2: {QueryID: 2, Calls: 9}, 3: {QueryID: 3, Calls: 1}}
	d := diffRows(prev, cur)
	if _, ok := d[1]; ok {
		t.Fatal("a reset queryid must be skipped, not negative or huge")
	}
	if d[2].Calls != 4 {
		t.Fatalf("delta %+v", d[2])
	}
	if _, ok := d[3]; ok {
		t.Fatal("a new queryid has no delta yet")
	}
}

func TestFailuresBackOff(t *testing.T) {
	dials := 0
	e := NewEnricher(func(context.Context, int) (Conn, error) { dials++; return nil, ErrAuth })
	t0 := time.Unix(0, 0)
	e.Poll(context.Background(), 5432, nil, t0)
	if v := e.Snapshot(5432); v.Status != StatusAuth {
		t.Fatalf("status %q", v.Status)
	}
	e.Poll(context.Background(), 5432, nil, t0.Add(time.Minute))
	if dials != 1 {
		t.Fatalf("auth failure must back off for 5 min, dialled %d times", dials)
	}
	e.Poll(context.Background(), 5432, nil, t0.Add(6*time.Minute))
	if dials != 2 {
		t.Fatalf("retry after back-off, dialled %d", dials)
	}
}

func TestComputeQueryIDOff(t *testing.T) {
	c := &fakeConn{s: Settings{VersionNum: 160015, ComputeQueryID: "off"}}
	e := NewEnricher(func(context.Context, int) (Conn, error) { return c, nil })
	e.Poll(context.Background(), 1, []int64{1}, time.Unix(0, 0))
	if v := e.Snapshot(1); v.Status != StatusNoQueryID {
		t.Fatalf("status %q", v.Status)
	}
}

func TestSettingsHelpers(t *testing.T) {
	if (Settings{VersionNum: 160015}).ReadTimeColumn() != "blk_read_time" || (Settings{VersionNum: 180006}).ReadTimeColumn() != "shared_blk_read_time" {
		t.Fatal("read time column by version")
	}
	if !(Settings{SyncStandbys: "ANY 1 (s1, s2)"}).SyncRep() || (Settings{SyncStandbys: " "}).SyncRep() {
		t.Fatal("sync rep detection")
	}
	if Classify(errors.New("x")) != "error: x" {
		t.Fatal("classify")
	}
}

// Poll after Close must not reopen a connection, and overlapping Polls of one
// cluster are serialised (run under -race).
func TestPollAfterCloseAndConcurrent(t *testing.T) {
	var mu sync.Mutex
	dials := 0
	e := NewEnricher(func(context.Context, int) (Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		return &fakeConn{s: Settings{VersionNum: 170002, ComputeQueryID: "auto"}}, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e.Poll(context.Background(), 5432, []int64{1}, time.Unix(int64(i), 0))
			e.Snapshot(5432)
		}(i)
	}
	wg.Wait()
	e.Close()
	before := dials
	e.Poll(context.Background(), 5432, []int64{1}, time.Unix(100, 0))
	e.Forget(5432)
	if dials != before || e.Snapshot(5432).Status != StatusNotConfigured {
		t.Fatalf("Poll after Close reconnected: dials %d -> %d", before, dials)
	}
}

func TestPollAfterForgetDoesNotReconnect(t *testing.T) {
	dials := 0
	e := NewEnricher(func(context.Context, int) (Conn, error) {
		dials++
		return &fakeConn{s: Settings{VersionNum: 170002, ComputeQueryID: "auto"}}, nil
	})
	e.Poll(context.Background(), 5432, nil, time.Unix(0, 0))
	e.Forget(5432)
	e.Poll(context.Background(), 5432, nil, time.Unix(1, 0)) // a fresh state: allowed
	if dials != 2 {
		t.Fatalf("dials %d", dials)
	}
}
