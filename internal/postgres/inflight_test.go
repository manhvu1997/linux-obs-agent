package postgres

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

func allKnown(uint64) bool { return true }

// A long interval is credited while it runs; when it closes, its full sums
// arrive in a drain and the credit is subtracted: the total is exact.
func TestCreditThenSettle(t *testing.T) {
	cur := procCounters{CPU: 5e9}
	c := newCreditor(5e9, func(uint32) (procCounters, error) { return cur, nil })
	s := pgtrace.Session{TID: 7, Postmaster: 100, Kind: pgtrace.KindClient, Hash: 42, OpenTS: 1e9}

	cr := c.Credit([]pgtrace.Session{s}, 7e9, allKnown) // open 6 s: credited
	if len(cr) != 1 || cr[0].CPU != 5e9 || cr[0].Hash != 42 {
		t.Fatalf("credit %+v", cr)
	}
	cur.CPU = 8e9
	cr = c.Credit([]pgtrace.Session{s}, 12e9, allKnown)
	if len(cr) != 1 || cr[0].CPU != 3e9 {
		t.Fatalf("second credit must be the increment: %+v", cr)
	}
	// Closed: the kernel reports 9 s of CPU for the whole interval.
	c.Credit(nil, 13e9, allKnown)
	entries := c.Settle([]pgtrace.AggEntry{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: 42, Calls: 1, CPUNs: 9e9}})
	if entries[0].CPUNs != 1e9 {
		t.Fatalf("settled cpu %d, want 1e9 (9 − 8 credited)", entries[0].CPUNs)
	}
	if len(c.owed) != 0 {
		t.Fatal("owed must be paid")
	}
}

func TestYoungOrUnknownNotCredited(t *testing.T) {
	c := newCreditor(5e9, func(uint32) (procCounters, error) { return procCounters{CPU: 1e9}, nil })
	s := pgtrace.Session{TID: 7, Hash: 42, OpenTS: 1e9}
	if cr := c.Credit([]pgtrace.Session{s}, 3e9, allKnown); len(cr) != 0 {
		t.Fatal("younger than minAge must not be credited")
	}
	if cr := c.Credit([]pgtrace.Session{s}, 9e9, func(uint64) bool { return false }); len(cr) != 0 {
		t.Fatal("unknown text must not be credited")
	}
}

// The closing drain can arrive later than the session disappears: owed
// carries over, then is dropped and counted after two more drains.
func TestOwedCarriesThenDrops(t *testing.T) {
	c := newCreditor(0, func(uint32) (procCounters, error) { return procCounters{CPU: 4e9}, nil })
	s := pgtrace.Session{TID: 1, Postmaster: 1, Kind: 1, Hash: 9, OpenTS: 0}
	c.Credit([]pgtrace.Session{s}, 1, allKnown)
	c.Credit(nil, 2, allKnown)
	c.Settle(nil) // age 1
	e := c.Settle([]pgtrace.AggEntry{{Postmaster: 1, Kind: 1, Hash: 9, CPUNs: 3e9}})
	if e[0].CPUNs != 0 || c.owed[aggKey{1, 1, 9}].c.CPU != 1e9 {
		t.Fatalf("partial settle: %+v owed %+v", e, c.owed)
	}
	c.Settle(nil)
	c.Settle(nil)
	if len(c.owed) != 0 || c.dropped != 1 {
		t.Fatalf("owed %+v dropped %d", c.owed, c.dropped)
	}
}

// Review Focus: an interval already running when the agent started has no
// session (the kernel saw no RUNNING report): nothing to credit, no panic.
func TestNoSessionsNoCredit(t *testing.T) {
	c := newCreditor(0, func(uint32) (procCounters, error) { t.Fatal("must not read /proc"); return procCounters{}, nil })
	if cr := c.Credit(nil, 1e12, allKnown); cr != nil {
		t.Fatal("no credit expected")
	}
	if e := c.Settle([]pgtrace.AggEntry{{CPUNs: 5}}); e[0].CPUNs != 5 {
		t.Fatal("entries untouched without owed")
	}
}

// A closed interval that arrives as a command event carries full sums: what
// was credited while it ran is subtracted, whether or not the creditor has
// already noticed the session is gone.
func TestSettleCmdSubtractsCredit(t *testing.T) {
	for _, noticed := range []bool{false, true} {
		cur := procCounters{CPU: 5e9}
		c := newCreditor(5e9, func(uint32) (procCounters, error) { return cur, nil })
		s := pgtrace.Session{TID: 7, Postmaster: 100, Kind: pgtrace.KindClient, Hash: 42, OpenTS: 1e9}
		c.Credit([]pgtrace.Session{s}, 7e9, allKnown)
		if noticed {
			c.Credit(nil, 8e9, allKnown)
		}
		p := procCounters{CPU: 9e9}
		c.SettleCmd(aggKey{100, pgtrace.KindClient, 42}, 7, &p)
		if p.CPU != 4e9 || len(c.credited) != 0 || len(c.owed) != 0 && c.owed[aggKey{100, pgtrace.KindClient, 42}].c.CPU != 0 {
			t.Fatalf("noticed=%v: cpu %d credited %v owed %v", noticed, p.CPU, c.credited, c.owed)
		}
	}
}
