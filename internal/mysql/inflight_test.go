package mysql

import (
	"errors"
	"testing"
	"time"

	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/inflight"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/sqlhash"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/textcache"
)

const exportQuery = "select * from `tickets`"

// creditAnalyzer is an analyzer whose thread counters, tgids and clock are
// fakes: *cur is every thread's current counters.
func creditAnalyzer(t *testing.T, cur *inflight.Counters) *Analyzer {
	t.Helper()
	a := testAnalyzer()
	a.text = textcache.New(16, textcache.Hooks{Forget: func(uint32, uint64) {}, MarkUnsafe: func(uint32, uint64) {}})
	a.cred = inflight.New[aggKey](a.minAgeNs, func(uint32) (inflight.Counters, error) { return *cur, nil })
	a.readOwner = func(uint32) (uint32, string, error) { return 2578, "connection", nil }
	a.agg.EnableDrain(100)
	return a
}

func cpuOf(ds []querystats.DigestDelta, text string) (cpu, read, calls uint64) {
	for _, d := range ds {
		if d.Text == text {
			cpu, read, calls = cpu+d.CPUNs, read+d.DiskReadBytes, calls+d.Calls
		}
	}
	return
}

// The incident: a 2-hour full-table SELECT. Its CPU and disk reads arrive
// poll by poll while it runs, and the final sums only add what was not
// credited yet: the total is exact and no window gets the whole statement.
func TestLongStatementCreditedWhileRunning(t *testing.T) {
	cur := inflight.Counters{CPU: 5e9, Read: 100 << 20}
	a := creditAnalyzer(t, &cur)
	h := sqlhash.KernelHash([]byte(exportQuery))
	open := []mysqlq.OpenCommand{{TID: 7, Command: cmdmap.ComQuery, Hash: h, OpenTS: 1e9, Query: exportQuery,
		QueryLen: uint32(len(exportQuery)), CPU: 1e9, Comm: "connection"}}
	now := time.Unix(1_800_000_000, 0)

	// Poll 1: running 10 s; text never seen (the kernel sends it on return):
	// learned from the in-flight copy, then credited from the entry baseline.
	a.tick(now, a.creditInFlight(nil, open, true, 11e9, true, true), true)
	ds, _ := a.agg.DrainDigests()
	if cpu, read, calls := cpuOf(ds, exportQuery); cpu != 4e9 || read != 100<<20 || calls != 0 {
		t.Fatalf("poll 1: cpu %d read %d calls %d, want 4e9 (5 − 1 baseline), 100 MiB, 0 calls (%+v)", cpu, read, calls, ds)
	}

	// Poll 2: still running; only the increment.
	cur = inflight.Counters{CPU: 8e9, Read: 300 << 20}
	a.tick(now.Add(5*time.Second), a.creditInFlight(nil, open, true, 16e9, true, true), true)
	ds, _ = a.agg.DrainDigests()
	if cpu, read, _ := cpuOf(ds, exportQuery); cpu != 3e9 || read != 200<<20 {
		t.Fatalf("poll 2: cpu %d read %d, want the increment 3e9 / 200 MiB", cpu, read)
	}

	// Poll 3: returned with 9 s of CPU and 350 MiB in total; 7 s and 300 MiB
	// were credited, so this poll gets the rest and the one call.
	end := []mysqlq.AggEntry{{PID: 2578, Command: cmdmap.ComQuery, Hash: h, Calls: 1, WallNs: 20e9, WallMaxNs: 20e9,
		CPUNs: 9e9, DiskReadBytes: 350 << 20}}
	a.tick(now.Add(10*time.Second), a.creditInFlight(end, nil, true, 21e9, true, true), true)
	ds, _ = a.agg.DrainDigests()
	if cpu, read, calls := cpuOf(ds, exportQuery); cpu != 2e9 || read != 50<<20 || calls != 1 {
		t.Fatalf("poll 3: cpu %d read %d calls %d, want the residue 2e9 / 50 MiB and the call", cpu, read, calls)
	}
	if a.CreditDropped() != 0 {
		t.Fatalf("credit dropped = %d", a.CreditDropped())
	}
}

// A command younger than a poll is neither credited nor costs a /proc read.
func TestYoungCommandNotCredited(t *testing.T) {
	cur := inflight.Counters{CPU: 5e9}
	a := creditAnalyzer(t, &cur)
	a.readOwner = func(uint32) (uint32, string, error) { t.Fatal("owner read for a young command"); return 0, "", nil }
	open := []mysqlq.OpenCommand{{TID: 7, Command: cmdmap.ComQuery, OpenTS: 10e9}}
	if got := a.creditInFlight(nil, open, true, 12e9, true, true); len(got) != 0 {
		t.Fatalf("credited %+v", got)
	}
}

// A thread whose owner cannot be read is not credited (no key), but keeps
// its earlier credit: it still counts as running.
func TestOwnerErrorKeepsSession(t *testing.T) {
	cur := inflight.Counters{CPU: 5e9}
	a := creditAnalyzer(t, &cur)
	open := []mysqlq.OpenCommand{{TID: 7, Command: 18, OpenTS: 1e9, Comm: "connection"}} // COM_BINLOG_DUMP: no text, hash 0
	if got := a.creditInFlight(nil, open, true, 11e9, true, true); len(got) != 1 || got[0].PID != 2578 || got[0].Hash != 0 {
		t.Fatalf("credit %+v", got)
	}
	a.readOwner = func(uint32) (uint32, string, error) { return 0, "", errors.New("gone") }
	cur.CPU = 6e9
	if got := a.creditInFlight(nil, open, true, 16e9, true, true); len(got) != 0 {
		t.Fatalf("credited without a tgid: %+v", got)
	}
	if n, _ := a.cred.Tracked(); n != 1 {
		t.Fatal("the session must stay credited, not be treated as ended")
	}
}

// An unreadable mysql_pending map credits nothing and ages nothing, but
// what is owed is still paid.
func TestOpenCommandsErrorStillPays(t *testing.T) {
	cur := inflight.Counters{CPU: 5e9}
	a := creditAnalyzer(t, &cur)
	open := []mysqlq.OpenCommand{{TID: 7, Command: 18, OpenTS: 1e9, Comm: "connection"}}
	a.creditInFlight(nil, open, true, 11e9, true, true) // 5 s credited
	a.creditInFlight(nil, nil, true, 16e9, true, true)  // ended: owed
	end := []mysqlq.AggEntry{{PID: 2578, Command: 18, Calls: 1, CPUNs: 6e9}}
	got := a.creditInFlight(end, nil, false, 21e9, true, true)
	if len(got) != 1 || got[0].CPUNs != 1e9 {
		t.Fatalf("got %+v, want the owed 5e9 paid from 6e9", got)
	}
}

// A long statement that ends as a fallback command event (unsafe hash or a
// full aggregation map) carries its full sums: the credit is subtracted.
func TestCmdEventSettlesCredit(t *testing.T) {
	cur := inflight.Counters{CPU: 5e9}
	a := creditAnalyzer(t, &cur)
	h := sqlhash.KernelHash([]byte(exportQuery))
	open := []mysqlq.OpenCommand{{TID: 7, Command: cmdmap.ComQuery, Hash: h, OpenTS: 1e9, Query: exportQuery,
		QueryLen: uint32(len(exportQuery)), Comm: "connection"}}
	a.creditInFlight(nil, open, true, 11e9, true, true)
	ev := mysqlq.CmdEvent{PID: 2578, TID: 7, Command: cmdmap.ComQuery, Query: exportQuery, QueryLen: uint32(len(exportQuery)),
		WallNs: 20e9, CPUNs: 9e9}
	a.settleCmd(&ev, true)
	if ev.CPUNs != 4e9 {
		t.Fatalf("event cpu %d, want 4e9 (9 − 5 credited)", ev.CPUNs)
	}
	if n, o := a.cred.Tracked(); n != 0 || o != 0 {
		t.Fatalf("credited %d owed %d after settling", n, o)
	}
}

// A stale mysql_pending entry (the command never returned: mysqld crashed or
// the thread died) whose TID now belongs to another thread is not credited:
// the thread's name no longer matches the one captured at entry.
func TestReusedTIDNotCredited(t *testing.T) {
	cur := inflight.Counters{CPU: 50e9}
	a := creditAnalyzer(t, &cur)
	a.readOwner = func(uint32) (uint32, string, error) { return 31337, "java", nil }
	open := []mysqlq.OpenCommand{{TID: 7, Command: 18, OpenTS: 1e9, Comm: "connection"}}
	if got := a.creditInFlight(nil, open, true, 11e9, true, true); len(got) != 0 {
		t.Fatalf("credited another process's thread: %+v", got)
	}
}
