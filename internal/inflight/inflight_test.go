package inflight

import "testing"

type key struct {
	PID  uint32
	Hash uint64
}

func allKnown(key) bool { return true }

func reader(cur *Counters) func(uint32) (Counters, error) {
	return func(uint32) (Counters, error) { return *cur, nil }
}

// A long statement is credited while it runs; when it ends, its full sums
// arrive in a drain and the credit is subtracted: the total is exact.
func TestCreditThenPay(t *testing.T) {
	cur := Counters{CPU: 5e9, Read: 100}
	c := New[key](5e9, reader(&cur))
	s := Session[key]{TID: 7, OpenTS: 1e9, Key: key{100, 42}}

	cr := c.Credit([]Session[key]{s}, 7e9, allKnown) // open 6 s: credited
	if len(cr) != 1 || cr[0].CPU != 5e9 || cr[0].Read != 100 || cr[0].Key != (key{100, 42}) {
		t.Fatalf("credit %+v", cr)
	}
	cur.CPU = 8e9
	cr = c.Credit([]Session[key]{s}, 12e9, allKnown)
	if len(cr) != 1 || cr[0].CPU != 3e9 || cr[0].Read != 0 {
		t.Fatalf("second credit must be the increment: %+v", cr)
	}
	// Ended: the kernel reports 9 s of CPU and 150 bytes for the whole statement.
	c.Credit(nil, 13e9, allKnown)
	p := Counters{CPU: 9e9, Read: 150}
	c.Pay(key{100, 42}, &p)
	c.Age()
	if p.CPU != 1e9 || p.Read != 50 {
		t.Fatalf("paid %+v, want cpu 1e9 (9 − 8 credited), read 50", p)
	}
	if len(c.owed) != 0 {
		t.Fatal("owed must be paid")
	}
}

// The baseline is the kernel's, not the first read: progress made before the
// statement reached minAge is credited at once.
func TestCreditFromKernelBaseline(t *testing.T) {
	cur := Counters{CPU: 50e9}
	c := New[key](5e9, reader(&cur))
	s := Session[key]{TID: 7, OpenTS: 0, Key: key{1, 1}, Base: Counters{CPU: 40e9}}
	if cr := c.Credit([]Session[key]{s}, 10e9, allKnown); len(cr) != 1 || cr[0].CPU != 10e9 {
		t.Fatalf("credit %+v, want 10e9 (50 − 40 baseline)", cr)
	}
}

func TestYoungOrUnknownNotCredited(t *testing.T) {
	c := New[key](5e9, func(uint32) (Counters, error) { return Counters{CPU: 1e9}, nil })
	s := Session[key]{TID: 7, OpenTS: 1e9, Key: key{1, 42}}
	if cr := c.Credit([]Session[key]{s}, 3e9, allKnown); len(cr) != 0 {
		t.Fatal("younger than minAge must not be credited")
	}
	if cr := c.Credit([]Session[key]{s}, 9e9, func(key) bool { return false }); len(cr) != 0 {
		t.Fatal("unknown key must not be credited")
	}
	if cr := c.Credit([]Session[key]{s}, 0, allKnown); len(cr) != 0 {
		t.Fatal("a session opened after now (clock skew) must not be credited")
	}
}

// The closing drain can arrive later than the session disappears: owed
// carries over, then is dropped and counted after two more drains.
func TestOwedCarriesThenDrops(t *testing.T) {
	c := New[key](0, func(uint32) (Counters, error) { return Counters{CPU: 4e9}, nil })
	s := Session[key]{TID: 1, Key: key{1, 9}}
	c.Credit([]Session[key]{s}, 1, allKnown)
	c.Credit(nil, 2, allKnown)
	c.Age() // age 1
	p := Counters{CPU: 3e9}
	c.Pay(key{1, 9}, &p)
	c.Age()
	if p.CPU != 0 || c.owed[key{1, 9}].c.CPU != 1e9 {
		t.Fatalf("partial pay: %+v owed %+v", p, c.owed)
	}
	c.Age()
	if len(c.owed) != 0 || c.Dropped() != 1 {
		t.Fatalf("owed %+v dropped %d", c.owed, c.Dropped())
	}
}

func TestNoSessionsNoCredit(t *testing.T) {
	c := New[key](0, func(uint32) (Counters, error) { t.Fatal("must not read /proc"); return Counters{}, nil })
	if cr := c.Credit(nil, 1e12, allKnown); cr != nil {
		t.Fatal("no credit expected")
	}
	p := Counters{CPU: 5}
	c.Pay(key{}, &p)
	if p.CPU != 5 {
		t.Fatal("sums untouched without owed")
	}
}

// An unreadable thread (exited between the session list and the read) is
// skipped, not credited as zero.
func TestReadErrorSkipped(t *testing.T) {
	c := New[key](0, func(uint32) (Counters, error) { return Counters{}, errNoThread })
	if cr := c.Credit([]Session[key]{{TID: 1, Key: key{1, 1}}}, 1, allKnown); len(cr) != 0 || len(c.credited) != 0 {
		t.Fatalf("credit %+v credited %v", cr, c.credited)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoThread = errString("no such thread")

// A statement that ends as a command event carries full sums: what was
// credited while it ran is subtracted, whether or not the creditor has
// already noticed the session is gone.
func TestSettleCmdSubtractsCredit(t *testing.T) {
	for _, noticed := range []bool{false, true} {
		cur := Counters{CPU: 5e9}
		c := New[key](5e9, reader(&cur))
		s := Session[key]{TID: 7, OpenTS: 1e9, Key: key{100, 42}}
		c.Credit([]Session[key]{s}, 7e9, allKnown)
		if noticed {
			c.Credit(nil, 8e9, allKnown)
		}
		p := Counters{CPU: 9e9}
		c.SettleCmd(key{100, 42}, 7, &p)
		if p.CPU != 4e9 || len(c.credited) != 0 || len(c.owed) != 0 && c.owed[key{100, 42}].c.CPU != 0 {
			t.Fatalf("noticed=%v: cpu %d credited %v owed %v", noticed, p.CPU, c.credited, c.owed)
		}
	}
}

// A session list read before SettleCmd must not re-credit the session
// SettleCmd just settled.
func TestStaleSessionListAfterSettleCmd(t *testing.T) {
	cur := Counters{CPU: 5e9}
	c := New[key](5e9, reader(&cur))
	s := Session[key]{TID: 7, OpenTS: 1e9, Key: key{100, 42}}
	list := []Session[key]{s}
	c.Credit(list, 7e9, allKnown)
	p := Counters{CPU: 9e9}
	c.SettleCmd(key{100, 42}, 7, &p)
	cur.CPU = 6e9
	if cr := c.Credit(list, 8e9, allKnown); len(cr) != 0 || len(c.credited) != 0 {
		t.Fatalf("stale list re-credited a settled session: %+v %v", cr, c.credited)
	}
	c.Credit(nil, 9e9, allKnown) // the session is gone from a fresh list: tombstone pruned
	if len(c.tomb) != 0 {
		t.Fatalf("tombstones must be pruned: %v", c.tomb)
	}
}

// Two statements ending under the same key in one drain (several connections
// running the same export): owed accumulates and is paid from the summed entry.
func TestSameKeyTwoSessions(t *testing.T) {
	cur := Counters{CPU: 3e9}
	c := New[key](0, reader(&cur))
	a := Session[key]{TID: 1, Key: key{1, 7}}
	b := Session[key]{TID: 2, Key: key{1, 7}}
	if cr := c.Credit([]Session[key]{a, b}, 1, allKnown); len(cr) != 2 {
		t.Fatalf("credit %+v", cr)
	}
	c.Credit(nil, 2, allKnown)
	p := Counters{CPU: 10e9} // both ended: 5 s each
	c.Pay(key{1, 7}, &p)
	c.Age()
	if p.CPU != 4e9 || len(c.owed) != 0 {
		t.Fatalf("paid %+v owed %v", p, c.owed)
	}
}

func TestResetForgetsEverything(t *testing.T) {
	c := New[key](0, func(uint32) (Counters, error) { return Counters{CPU: 1}, nil })
	c.Credit([]Session[key]{{TID: 1, Key: key{1, 1}}}, 1, allKnown)
	c.Credit(nil, 2, allKnown)
	c.Reset()
	if len(c.credited) != 0 || len(c.owed) != 0 || len(c.tomb) != 0 {
		t.Fatal("Reset left state behind")
	}
}
