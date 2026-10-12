package postgres

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// The generic crediting rules are tested in internal/inflight; these tests
// cover the mapping of pg_query sessions and aggregation entries.

func allKnown(uint64) bool { return true }

// A long interval is credited while it runs; when it closes, its full sums
// arrive in a drain and the credit is subtracted from every credited field.
func TestCreditThenSettle(t *testing.T) {
	cur := procCounters{CPU: 5e9, Runq: 1e9, Read: 300, Write: 30, Blkio: 2e9}
	c := newCreditor(5e9, func(uint32) (procCounters, error) { return cur, nil })
	s := pgtrace.Session{TID: 7, Postmaster: 100, Kind: pgtrace.KindClient, Hash: 42, OpenTS: 1e9,
		CPU: 1e9, Runq: 0, ReadBytes: 100, WriteBytes: 10, Blkio: 0}

	cr := c.Credit([]pgtrace.Session{s}, 7e9, allKnown) // open 6 s: credited from the kernel baselines
	if len(cr) != 1 || cr[0].Key != (aggKey{100, pgtrace.KindClient, 42}) ||
		cr[0].CPU != 4e9 || cr[0].Runq != 1e9 || cr[0].Read != 200 || cr[0].Write != 20 || cr[0].Blkio != 2e9 {
		t.Fatalf("credit %+v", cr)
	}
	c.Credit(nil, 13e9, allKnown) // closed
	entries := c.Settle([]pgtrace.AggEntry{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: 42, Calls: 1,
		WallNs: 20e9, CPUNs: 9e9, RunqNs: 3e9, DiskReadBytes: 250, DiskWriteBytes: 20, IOWaitNs: 2e9, WALWaitNs: 7}})
	e := entries[0]
	if e.CPUNs != 5e9 || e.RunqNs != 2e9 || e.DiskReadBytes != 50 || e.DiskWriteBytes != 0 || e.IOWaitNs != 0 {
		t.Fatalf("settled %+v", e)
	}
	if e.Calls != 1 || e.WallNs != 20e9 || e.WALWaitNs != 7 {
		t.Fatalf("calls, wall and waits are never credited, so never settled: %+v", e)
	}
}

// Hash 0 (fastpath, no text) is always known; any other hash only once its
// text is cached.
func TestKnownHash(t *testing.T) {
	c := newCreditor(0, func(uint32) (procCounters, error) { return procCounters{CPU: 1e9}, nil })
	none := func(uint64) bool { return false }
	if cr := c.Credit([]pgtrace.Session{{TID: 1, Hash: 42}}, 1, none); len(cr) != 0 {
		t.Fatal("unknown text must not be credited")
	}
	if cr := c.Credit([]pgtrace.Session{{TID: 2, Kind: pgtrace.KindFastpath}}, 1, none); len(cr) != 1 {
		t.Fatal("hash 0 must be credited without text")
	}
}

// A closed interval that arrives as a command event carries full sums: what
// was credited while it ran is subtracted.
func TestSettleCmdSubtractsCredit(t *testing.T) {
	c := newCreditor(5e9, func(uint32) (procCounters, error) { return procCounters{CPU: 5e9}, nil })
	s := pgtrace.Session{TID: 7, Postmaster: 100, Kind: pgtrace.KindClient, Hash: 42, OpenTS: 1e9}
	c.Credit([]pgtrace.Session{s}, 7e9, allKnown)
	p := procCounters{CPU: 9e9}
	c.SettleCmd(aggKey{100, pgtrace.KindClient, 42}, 7, &p)
	if p.CPU != 4e9 {
		t.Fatalf("cpu %d, want 4e9", p.CPU)
	}
}
