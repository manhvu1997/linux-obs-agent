// internal/querystats/querystats_test.go
package querystats

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

var t0 = time.Unix(1_800_000_000, 0)

func ev(sql string, at time.Time, cpuMs, runqMs, wallMs float64, out uint64) Event {
	ms := func(v float64) uint64 { return uint64(v * 1e6) }
	return Event{
		PID: 100, Command: "query", Digest: sqldigest.Normalize(sql), SampleQuery: sql,
		CPUNs: ms(cpuMs), RunqNs: ms(runqMs), WallNs: ms(wallMs), BytesOut: out, At: at,
	}
}

func cfg() Config {
	return Config{SlowWallNs: 10_000_000}
}

func TestRanksByTotalCPUNotPerCall(t *testing.T) {
	a := New(cfg())
	for i := 0; i < 10; i++ { // A: 10 × 400ms = 4000ms
		a.Add(ev("SELECT status, COUNT(*) FROM orders GROUP BY status", t0, 400, 5, 410, 200))
	}
	for i := 0; i < 5000; i++ { // C: 5000 × 3ms = 15000ms, never slow
		a.Add(ev("SELECT * FROM carts WHERE user_id = 1", t0, 3, 0.1, 3.2, 500))
	}
	for i := 0; i < 1000; i++ { // B: 1000 × 0.003ms = 3ms
		a.Add(ev("SELECT * FROM users WHERE id = 1", t0, 0.003, 38, 41, 1200))
	}
	s := a.Snapshot(t0.Add(time.Second))
	got := []string{s.TopByCPU[0].DigestText, s.TopByCPU[1].DigestText, s.TopByCPU[2].DigestText}
	want := []string{
		"select * from carts where user_id = ?",
		"select status , count ( * ) from orders group by status",
		"select * from users where id = ?",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rank %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestWindowRollOff(t *testing.T) {
	a := New(cfg())
	a.Add(ev("SELECT 1", t0, 1, 0, 1, 1))
	if s := a.Snapshot(t0.Add(30 * time.Second)); len(s.TopByCPU) != 1 {
		t.Fatalf("want 1 digest inside window, got %d", len(s.TopByCPU))
	}
	if s := a.Snapshot(t0.Add(61 * time.Second)); len(s.TopByCPU) != 0 {
		t.Fatalf("want 0 digests after window, got %d", len(s.TopByCPU))
	}
}

func TestMaxDigestsOverflowToOther(t *testing.T) {
	c := cfg()
	c.MaxDigests = 2
	a := New(c)
	a.Add(ev("SELECT a FROM t1", t0, 1, 0, 1, 1))
	a.Add(ev("SELECT a FROM t2", t0, 1, 0, 1, 1))
	a.Add(ev("SELECT a FROM t3", t0, 1, 0, 1, 1))
	s := a.Snapshot(t0.Add(time.Second))
	var other bool
	for _, d := range s.TopByCPU {
		if d.DigestID == OtherDigestID && d.DigestText == OtherDigestText {
			other = true
		}
	}
	if len(s.TopByCPU) != 3 || !other {
		t.Fatalf("want 2 digests + <other>, got %+v", s.TopByCPU)
	}
}

func TestStickyExportSurvivesThenExpires(t *testing.T) {
	a := New(cfg())
	a.Add(ev("SELECT COUNT(*) FROM big", t0, 400, 0, 400, 1))
	id := sqldigest.Normalize("SELECT COUNT(*) FROM big").ID
	a.Snapshot(t0.Add(time.Second))
	if !exported(a.Snapshot(t0.Add(30*time.Minute)), id) {
		t.Fatal("digest should stay exported for the sticky TTL after leaving the top list")
	}
	if exported(a.Snapshot(t0.Add(62*time.Minute)), id) {
		t.Fatal("digest should be dropped after the sticky TTL")
	}
}

func TestStickyCap(t *testing.T) {
	c := cfg()
	c.StickyMax = 2
	a := New(c)
	a.Add(ev("SELECT a FROM t1", t0, 3, 0, 3, 1))
	a.Add(ev("SELECT a FROM t2", t0, 2, 0, 2, 1))
	a.Add(ev("SELECT a FROM t3", t0, 1, 0, 1, 1))
	if s := a.Snapshot(t0.Add(time.Second)); len(s.Exported) != 2 {
		t.Fatalf("exported = %d, want cap 2", len(s.Exported))
	}
}

func TestCommandCountersAndBytesRanking(t *testing.T) {
	a := New(cfg())
	a.Add(ev("SELECT * FROM t", t0, 1, 0, 1, 9_000_000))
	a.Add(ev("SELECT COUNT(*) FROM t", t0, 50, 0, 50, 10))
	s := a.Snapshot(t0.Add(time.Second))
	if got := s.TopByBytesOut[0].DigestText; got != "select * from t" {
		t.Fatalf("top by bytes = %q", got)
	}
	q := s.Commands["query"]
	if q.Calls != 2 || q.BytesOut != 9_000_010 || q.CPUNs != 51_000_000 {
		t.Fatalf("command counters = %+v", q)
	}
}

func exported(s Snapshot, id string) bool {
	for _, e := range s.Exported {
		if e.ID == id {
			return true
		}
	}
	return false
}

func exportedCounters(s Snapshot, id string) (ExportedDigest, bool) {
	for _, e := range s.Exported {
		if e.ID == id {
			return e, true
		}
	}
	return ExportedDigest{}, false
}

func TestStickyDigestSurvivesLifeOverflow(t *testing.T) {
	c := cfg()
	c.MaxDigests = 2
	a := New(c)
	a.Add(ev("SELECT a FROM t1", t0, 1, 0, 1, 1))
	a.Add(ev("SELECT a FROM t2", t0, 1, 0, 1, 1))
	later := t0.Add(70 * time.Second)
	for i := 0; i < 5; i++ {
		a.Add(ev("SELECT a FROM t3", later, 5, 0, 5, 1))
	}
	d := sqldigest.Normalize("SELECT a FROM t3")
	s := a.Snapshot(t0.Add(71 * time.Second))
	e, ok := exportedCounters(s, d.ID)
	if !ok {
		t.Fatalf("sticky digest missing from Exported: %+v", s.Exported)
	}
	if e.Counters.Calls < 5 || e.Text != d.Text {
		t.Fatalf("got %+v, want calls>=5 text %q", e, d.Text)
	}
}

func TestOtherDigestHasNoRoleAndIsNotSticky(t *testing.T) {
	c := cfg()
	c.MaxDigests = 1
	a := New(c)
	a.Add(ev("SELECT a FROM t0", t0, 1, 0, 1, 1))
	for _, n := range []string{"b", "c", "d", "e"} {
		a.Add(ev("SELECT a FROM "+n, t0, 5, 0, 5, 1))
	}
	s := a.Snapshot(t0.Add(time.Second))
	found := false
	for _, d := range s.TopByCPU {
		if d.DigestID == OtherDigestID {
			found = true
			if d.CPURole != "" || d.VictimOf != "" {
				t.Fatalf("other cpu_role = %q, victim_of = %q", d.CPURole, d.VictimOf)
			}
		}
	}
	if !found {
		t.Fatal("no <other> entry")
	}
	if _, ok := exportedCounters(s, OtherDigestID); ok {
		t.Fatal("<other> must not be exported")
	}
}

func TestStickyFromTopNBytesNotTopNBytesList(t *testing.T) {
	a := New(cfg())
	names := "abcdefghijklmnopqrstuvwxy" // 25 digests
	var target string
	for i := 0; i < 25; i++ {
		sql := "SELECT x FROM t" + string(names[i])
		var out uint64 = 1
		switch {
		case i < 10:
			out = 1000
		case i == 24:
			out = 500 // 11th by bytes, lowest by CPU
			target = sql
		}
		a.Add(ev(sql, t0, float64(25-i), 0, float64(25-i), out))
	}
	s := a.Snapshot(t0.Add(time.Second))
	if len(s.TopByBytesOut) != 10 {
		t.Fatalf("TopByBytesOut = %d, want 10", len(s.TopByBytesOut))
	}
	if _, ok := exportedCounters(s, sqldigest.Normalize(target).ID); !ok {
		t.Fatal("11th-by-bytes digest should be sticky (top-N bytes)")
	}
}

func TestStickyCounterMonotonic(t *testing.T) {
	a := New(cfg())
	sql := "SELECT COUNT(*) FROM big"
	id := sqldigest.Normalize(sql).ID
	a.Add(ev(sql, t0, 400, 2, 410, 7))
	before, ok := exportedCounters(a.Snapshot(t0.Add(time.Second)), id)
	if !ok {
		t.Fatal("not exported initially")
	}
	mid, ok := exportedCounters(a.Snapshot(t0.Add(5*time.Minute)), id)
	if !ok {
		t.Fatal("should stay sticky outside window")
	}
	a.Add(ev(sql, t0.Add(6*time.Minute), 400, 2, 410, 7))
	after, ok := exportedCounters(a.Snapshot(t0.Add(6*time.Minute+time.Second)), id)
	if !ok {
		t.Fatal("not exported after re-entry")
	}
	for _, p := range [][2]model.QueryCounters{{before.Counters, mid.Counters}, {mid.Counters, after.Counters}} {
		x, y := p[0], p[1]
		if y.Calls < x.Calls || y.CPUNs < x.CPUNs || y.RunqNs < x.RunqNs || y.WallNs < x.WallNs || y.BytesOut < x.BytesOut {
			t.Fatalf("counters decreased: %+v -> %+v", x, y)
		}
	}
	if after.Counters.Calls != 2 {
		t.Fatalf("calls = %d, want 2", after.Counters.Calls)
	}
}

func TestCPUCoresAndQueryTotal(t *testing.T) {
	a := New(cfg()) // 60 s window
	for i := 0; i < 3; i++ {
		a.Add(ev("SELECT 1 FROM a", t0, 1000, 0, 1000, 1)) // 3 s
	}
	a.Add(ev("SELECT 1 FROM b", t0, 600, 0, 600, 1)) // 0.6 s
	s := a.Snapshot(t0.Add(time.Second))
	if s.QueryCPUMsTotal != 3600 {
		t.Fatalf("query_cpu_ms_total = %v, want 3600", s.QueryCPUMsTotal)
	}
	if got := s.TopByCPU[0].CPUCores; got != 0.05 {
		t.Fatalf("cpu_cores = %v, want 0.05 (3 s / 60 s)", got)
	}
}

func TestVictimDigestsCountedBeyondTopN(t *testing.T) {
	c := cfg()
	c.TopN = 1
	a := New(c)
	for i := 0; i < 100; i++ {
		a.Add(ev("SELECT COUNT(*) FROM big", t0, 400, 5, 410, 20))
		for _, n := range []string{"a", "b"} {
			// waits 30 of 50 ms (60 %) and slow (≥ 10 ms): victim_of cpu.
			a.Add(ev("SELECT v"+n+" FROM t", t0, 1, 30, 50, 0))
		}
	}
	s := a.Snapshot(t0.Add(time.Second))
	if len(s.TopByCPU) != 1 || s.TopByCPU[0].VictimOf != "" {
		t.Fatalf("top = %+v, want only the non-victim big scan listed", s.TopByCPU)
	}
	if got := s.Victims[VictimCPU]; got != 2 {
		t.Fatalf("victims[cpu] = %d, want 2 counted beyond top_digests", got)
	}
}
