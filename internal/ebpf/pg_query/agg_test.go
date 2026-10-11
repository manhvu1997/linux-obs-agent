package pg_query

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDrainRowsMapsFieldsAndDeletes(t *testing.T) {
	k1 := PgQueryAggKeyT{Postmaster: 100, Kind: 1, Hash: 7}
	k2 := PgQueryAggKeyT{Postmaster: 100, Kind: 2, Hash: 8}
	v := PgQueryAggValT{Calls: 3, WallNs: 1000, WallMaxNs: 600, CpuNs: 400, RunqNs: 50, DiskReadBytes: 8192,
		DiskWriteBytes: 4096, IoWaitNs: 10, WalWaitNs: 20, SyncrepWaitNs: 30}
	var deleted []PgQueryAggKeyT
	out, err := drainRows(func(y func(PgQueryAggKeyT, PgQueryAggValT)) error { y(k1, v); y(k2, PgQueryAggValT{}); return nil },
		func(k PgQueryAggKeyT) error { deleted = append(deleted, k); return nil })
	if err != nil || len(out) != 2 || len(deleted) != 2 {
		t.Fatalf("%v %+v %v", err, out, deleted)
	}
	e := out[0]
	if e.Postmaster != 100 || e.Kind != 1 || e.Hash != 7 || e.Calls != 3 || e.WallNs != 1000 || e.WallMaxNs != 600 ||
		e.CPUNs != 400 || e.RunqNs != 50 || e.DiskReadBytes != 8192 || e.DiskWriteBytes != 4096 ||
		e.IOWaitNs != 10 || e.WALWaitNs != 20 || e.SyncRepWaitNs != 30 {
		t.Fatalf("%+v", e)
	}
}

func TestDrainRowsKeepsEntriesWhoseDeleteFailed(t *testing.T) {
	k1, k2 := PgQueryAggKeyT{Hash: 1}, PgQueryAggKeyT{Hash: 2}
	boom := errors.New("boom")
	out, err := drainRows(func(y func(PgQueryAggKeyT, PgQueryAggValT)) error {
		y(k1, PgQueryAggValT{})
		y(k2, PgQueryAggValT{})
		return nil
	},
		func(k PgQueryAggKeyT) error {
			if k.Hash == 1 {
				return boom
			}
			return ebpf.ErrKeyNotExist
		})
	if !errors.Is(err, boom) || len(out) != 1 || out[0].Hash != 2 {
		t.Fatalf("%v %+v", err, out)
	}
}

func TestLoaderGuardedBeforeStart(t *testing.T) {
	l := NewLoader(0)
	if _, err := l.DrainAgg(); err == nil {
		t.Fatal("DrainAgg")
	}
	if _, err := l.OpenSessions(); err == nil {
		t.Fatal("OpenSessions")
	}
	if l.ClearSessions() == nil || l.SetClusters(nil) == nil {
		t.Fatal("ClearSessions/SetClusters")
	}
	if _, err := l.QueryIDs(); err == nil {
		t.Fatal("QueryIDs")
	}
	l.ForgetText(1)
	l.MarkUnsafe(1)
	_ = l.Dropped() + l.AggOverflow()
	l.Stop()
}
