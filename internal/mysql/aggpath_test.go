package mysql

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/mysql/sqlhash"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
)

func testAnalyzer() *Analyzer {
	return NewAnalyzer(&config.MySQLConfig{SampleQueries: true, FoldSystemSchemas: true, DigestWindow: time.Minute, TopDigests: 20}, nil)
}

// A drained entry whose text was learned becomes one digest with its sums.
func TestAggEntriesBecomeDigests(t *testing.T) {
	a := testAnalyzer()
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	a.learnText(mysqlq.TextEvent{Command: 3, Hash: 99, Query: "SELECT * FROM t WHERE id = 5", QueryLen: 28}, true, false)
	now := time.Unix(1_800_000_000, 0)
	a.applyAgg([]mysqlq.AggEntry{{PID: 1, Command: 3, Hash: 99, Calls: 40, CPUNs: 40e6, WallNs: 80e6, WallMaxNs: 3e6}}, now, true)
	s := a.agg.Snapshot(now.Add(time.Second))
	if len(s.TopByCPU) != 1 || s.TopByCPU[0].Calls != 40 || s.TopByCPU[0].DigestText != "select * from t where id = ?" {
		t.Fatalf("got %+v", s.TopByCPU)
	}
}

// Disk bytes and waits of an aggregated entry reach the command counters.
func TestAggEntryCarriesDiskAndWaits(t *testing.T) {
	a := testAnalyzer()
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	a.learnText(mysqlq.TextEvent{Command: 3, Hash: 99, Query: "SELECT * FROM t WHERE id = 5", QueryLen: 28}, true, false)
	now := time.Unix(1_800_000_000, 0)
	a.applyAgg([]mysqlq.AggEntry{{PID: 1, Command: 3, Hash: 99, Calls: 4, CPUNs: 4e6, WallNs: 20e6, WallMaxNs: 6e6,
		DiskReadBytes: 16384, DiskWriteBytes: 512, IOWaitNs: 5e6, RedoWaitNs: 1e6}}, now, true)
	c := a.agg.Snapshot(now.Add(time.Second)).Commands["query"]
	if c.DiskReadBytes != 16384 || c.DiskWriteBytes != 512 || c.IOWaitNs != 5e6 || c.RedoWaitNs != 1e6 {
		t.Fatalf("command counters = %+v", c)
	}
}

// The fallback (full event) path carries them too.
func TestCmdEventCarriesDiskAndWaits(t *testing.T) {
	a := testAnalyzer()
	now := time.Unix(1_800_000_000, 0)
	a.agg.Add(a.toEvent(mysqlq.CmdEvent{PID: 1, Command: 3, Query: "SELECT 1", QueryLen: 8, WallNs: 9e6, CPUNs: 1e6,
		DiskReadBytes: 32768, DiskWriteBytes: 7, IOWaitNs: 4e6, RedoWaitNs: 2e6}, now, true))
	c := a.agg.Snapshot(now.Add(time.Second)).Commands["query"]
	if c.DiskReadBytes != 32768 || c.DiskWriteBytes != 7 || c.IOWaitNs != 4e6 || c.RedoWaitNs != 2e6 {
		t.Fatalf("command counters = %+v", c)
	}
}

// Review focus 3: commands delivered as fallback events are counted too.
func TestFallbackEventsBecomeDeltas(t *testing.T) {
	a := testAnalyzer()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		a.agg.Add(a.toEvent(mysqlq.CmdEvent{PID: 1, Command: 3, Query: "SELECT 1", QueryLen: 8, WallNs: 1e6, CPUNs: 1e6}, now, true))
	}
	if s := a.agg.Snapshot(now.Add(time.Second)); s.TopByCPU[0].Calls != 3 {
		t.Fatalf("calls = %d", s.TopByCPU[0].Calls)
	}
}

// Prepare texts classify as "prepare: …", execute texts as the query digest.
func TestLearnTextClassifiesByCommand(t *testing.T) {
	a := testAnalyzer()
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	a.learnText(mysqlq.TextEvent{Command: 22, Hash: 5, Query: "SELECT ?", QueryLen: 8}, true, false)
	a.learnText(mysqlq.TextEvent{Command: 23, Hash: 5, Query: "SELECT ?", QueryLen: 8}, true, false)
	p, _ := a.text.resolve(textKey{22, 5}, aggSums{Calls: 1}, nil)
	e, _ := a.text.resolve(textKey{23, 5}, aggSums{Calls: 1}, nil)
	if p.Command != "stmt_prepare" || p.Digest.Text != "prepare: select ?" || e.Command != "stmt_execute" || e.Digest.Text != "select ?" {
		t.Fatalf("prepare %+v / execute %+v", p, e)
	}
}

type unsafeLog []textKey

func (u *unsafeLog) hooks() textCacheHooks {
	return textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(c uint32, h uint64) { *u = append(*u, textKey{c, h}) }}
}

// Every first-sight text is checked against the Go reference of the kernel
// hash: a kernel/Go drift marks the hash unsafe and counts a mismatch.
func TestLearnTextKernelHashDriftCheck(t *testing.T) {
	const q = "SELECT * FROM t WHERE id = 5"
	for _, c := range []struct {
		name        string
		cmd         uint32
		hash        uint64
		literalSkip bool
		verify      bool
		wantUnsafe  bool
	}{
		{"query, matching hash", 3, sqlhash.KernelHash([]byte(q)), true, false, false},
		{"query, drifted hash", 3, sqlhash.KernelHash([]byte(q)) ^ 1, true, false, true},
		{"prepare, drifted hash", 22, 12345, true, false, true},
		{"execute, drifted hash", 23, 12345, true, false, true},
		{"exact-text fallback, matching hash", 3, sqlhash.ExactHash([]byte(q)), false, false, false},
		{"exact-text fallback, drifted hash", 3, sqlhash.KernelHash([]byte(q)), false, false, true},
		{"verification resend is not hash-checked", 3, 777, true, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := testAnalyzer()
			var u unsafeLog
			a.text = newTextCache(16, u.hooks())
			a.learnText(mysqlq.TextEvent{Command: c.cmd, Hash: c.hash, Query: q, QueryLen: uint32(len(q)), Verify: c.verify}, true, c.literalSkip)
			if got := len(u) == 1 && u[0] == (textKey{c.cmd, c.hash}); got != c.wantUnsafe || (!c.wantUnsafe && len(u) != 0) {
				t.Fatalf("unsafe = %v, want unsafe %v", u, c.wantUnsafe)
			}
			if want := map[bool]uint64{true: 1, false: 0}[c.wantUnsafe]; a.text.mismatches() != want {
				t.Fatalf("mismatches = %d, want %d", a.text.mismatches(), want)
			}
			// The text is still learned: entries already aggregated under the
			// hash resolve to it.
			if _, ok := a.text.resolve(textKey{c.cmd, c.hash}, aggSums{Calls: 1}, nil); !ok {
				t.Fatal("text not learned")
			}
		})
	}
}

// A resend whose digest changed and whose hash also fails the drift check
// counts one mismatch, not two.
func TestLearnTextChangedDigestCountsOnce(t *testing.T) {
	a := testAnalyzer()
	var u unsafeLog
	a.text = newTextCache(16, u.hooks())
	const qa, qb = "SELECT a FROM t", "SELECT b FROM t"
	h := sqlhash.KernelHash([]byte(qa))
	a.learnText(mysqlq.TextEvent{Command: 3, Hash: h, Query: qa, QueryLen: uint32(len(qa))}, true, true)
	a.learnText(mysqlq.TextEvent{Command: 3, Hash: h, Query: qb, QueryLen: uint32(len(qb))}, true, true)
	if a.text.mismatches() != 1 || len(u) != 1 {
		t.Fatalf("mismatches = %d, unsafe = %v; want 1 each", a.text.mismatches(), u)
	}
}

// Lost texts: COM_QUERY and COM_STMT_PREPARE get distinct placeholders (and
// digest ids); a lost COM_STMT_EXECUTE text shows the execute placeholder.
func TestLostTextPlaceholdersPerCommand(t *testing.T) {
	a := testAnalyzer()
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	now := time.Unix(1_800_000_000, 0)
	lost := []mysqlq.AggEntry{
		{PID: 1, Command: 3, Hash: 101, Calls: 1, CPUNs: 3e6, WallNs: 3e6, WallMaxNs: 3e6},
		{PID: 1, Command: 22, Hash: 102, Calls: 1, CPUNs: 2e6, WallNs: 2e6, WallMaxNs: 2e6},
		{PID: 1, Command: 23, Hash: 103, Calls: 1, CPUNs: 1e6, WallNs: 1e6, WallMaxNs: 1e6},
	}
	a.applyAgg(lost, now, true) // parked
	a.applyAgg(nil, now, true)  // still unknown a tick later: placeholders
	byText := map[string]string{}
	for _, d := range a.agg.Snapshot(now.Add(time.Second)).TopByCPU {
		byText[d.DigestText] = d.DigestID
	}
	q, p, e := byText["<text unavailable>"], byText["prepare: <text unavailable>"],
		byText["<COM_STMT_EXECUTE: prepared before agent start, text unavailable>"]
	if q == "" || p == "" || e == "" || q == p {
		t.Fatalf("digests = %v", byText)
	}
}
