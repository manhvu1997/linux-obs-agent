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

// A digest that reads the disk but burns little CPU is still exported via stickyDisk.
// TopN=1 ensures only the high-CPU query is in byCPU; high BytesOut on CPU query
// ensures neither is in stickyOut; only disk query is in stickyDisk.
func TestDiskReadDigestIsSticky(t *testing.T) {
	c := cfg()
	c.TopN = 1
	a := New(c)
	cpu := digestDelta(1, "SELECT a FROM t", 10, 9e9)
	cpu.BytesOut = 1000 // high result size; won't help disk query win stickyOut
	disk := digestDelta(1, "SELECT * FROM big", 10, 1e6)
	disk.DiskReadBytes = 500 << 20
	a.AddDeltas([]Delta{cpu, disk}, t0)
	h := okHost(30e9, 40e9, 4e9)
	h.DiskOK, h.DiskReadBytes = true, 600<<20
	a.AddHost(h, t0)
	s := a.Snapshot(t0)
	if !exported(s, disk.Digest.ID) {
		t.Fatal("top disk-read digest missing from the export set (stickyDisk)")
	}
	for _, e := range s.Exported {
		if e.ID == disk.Digest.ID && e.Counters.DiskReadBytes != 500<<20 {
			t.Fatalf("lifetime disk read = %d", e.Counters.DiskReadBytes)
		}
	}
}

// markSticky seeds disk/io/redo counters from window stats when a digest
// re-enters the sticky set. Without seeding, these counters start at zero and
// never increase.
func TestMarkStickyDiskSeeding(t *testing.T) {
	c := cfg()
	c.StickyTTL = time.Hour
	a := New(c)
	disk := digestDelta(1, "SELECT * FROM big", 10, 1e6)
	disk.DiskReadBytes = 500 << 20
	disk.IOWaitNs = 100e6
	disk.RedoWaitNs = 50e6

	// First snapshot: disk digest is in the window and gets marked sticky.
	a.AddDeltas([]Delta{disk}, t0)
	h := okHost(30e9, 40e9, 4e9)
	h.DiskOK, h.DiskReadBytes = true, 600<<20
	a.AddHost(h, t0)
	s1 := a.Snapshot(t0)
	if !exported(s1, disk.Digest.ID) {
		t.Fatal("disk digest not exported initially")
	}

	// Second snapshot: disk digest is outside the window, but stays sticky.
	s2 := a.Snapshot(t0.Add(61 * time.Second))
	if !exported(s2, disk.Digest.ID) {
		t.Fatal("disk digest should stay sticky after leaving window")
	}

	// Third snapshot: disk digest re-enters the window with new data.
	// markSticky seeds its counters from the window, so the lifetime counters increase.
	disk2 := digestDelta(1, "SELECT * FROM big", 5, 2e6)
	disk2.DiskReadBytes = 200 << 20
	disk2.IOWaitNs = 50e6
	disk2.RedoWaitNs = 30e6
	a.AddDeltas([]Delta{disk2}, t0.Add(62*time.Second))
	h2 := okHost(30e9, 40e9, 4e9)
	h2.DiskOK, h2.DiskReadBytes = true, 600<<20
	a.AddHost(h2, t0.Add(62*time.Second))
	s3 := a.Snapshot(t0.Add(62 * time.Second))

	for _, e := range s3.Exported {
		if e.ID == disk.Digest.ID {
			// Lifetime Calls: 10 (initial) + 5 (re-entry) = 15
			if e.Counters.Calls != 15 {
				t.Fatalf("calls: got %d, want 15", e.Counters.Calls)
			}
			// Lifetime DiskReadBytes must include both the seeded value (500 MB)
			// from the first snapshot and the new value (200 MB) from re-entry.
			// With seeding: 500<<20 + 200<<20; without: 0 + 200<<20.
			expected := (500 + 200) << 20
			if e.Counters.DiskReadBytes != uint64(expected) {
				t.Fatalf("disk read: got %d, want %d (suggests no seeding)",
					e.Counters.DiskReadBytes, expected)
			}
			// Same logic for io/redo: initial (100e6 + 50e6) + re-entry (50e6 + 30e6)
			if e.Counters.IOWaitNs != 150e6 {
				t.Fatalf("io wait: got %d, want 150e6", e.Counters.IOWaitNs)
			}
			if e.Counters.RedoWaitNs != 80e6 {
				t.Fatalf("redo wait: got %d, want 80e6", e.Counters.RedoWaitNs)
			}
			return
		}
	}
	t.Fatal("disk digest not found in exported")
}
