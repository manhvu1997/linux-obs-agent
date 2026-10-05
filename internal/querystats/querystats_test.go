// internal/querystats/querystats_test.go
package querystats

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

var t0 = time.Unix(1_800_000_000, 0)

func ev(sql string, at time.Time, cpuMs, runqMs, wallMs float64, out uint64) Event {
	ms := func(v float64) uint64 { return uint64(v * 1e6) }
	return Event{
		PID: 100, Command: "query", Digest: sqldigest.Normalize(sql), SampleQuery: sql,
		CPUNs: ms(cpuMs), RunqNs: ms(runqMs), WallNs: ms(wallMs), BytesIn: uint64(len(sql)), BytesOut: out, At: at,
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

func TestRoles(t *testing.T) {
	a := New(cfg())
	for i := 0; i < 100; i++ {
		a.Add(ev("SELECT COUNT(*) FROM big", t0, 400, 5, 410, 20))
		a.Add(ev("SELECT * FROM users WHERE id = 1", t0, 0.003, 38, 41, 1200))
	}
	s := a.Snapshot(t0.Add(time.Second))
	roles := map[string]string{}
	for _, d := range s.TopByCPU {
		roles[d.DigestText] = d.Role
	}
	if roles["select count ( * ) from big"] != RoleCulprit {
		t.Fatalf("big scan role = %q", roles["select count ( * ) from big"])
	}
	if roles["select * from users where id = ?"] != RoleVictim {
		t.Fatalf("point select role = %q", roles["select * from users where id = ?"])
	}
	if s.CPUAccounting != AccountingOK {
		t.Fatalf("accounting = %q", s.CPUAccounting)
	}
}

func TestRunDelayUnavailableFallback(t *testing.T) {
	a := New(cfg())
	for i := 0; i < 1000; i++ {
		a.Add(ev("SELECT * FROM users WHERE id = 1", t0, 1, 0, 50, 10))
	}
	a.Add(ev("SELECT COUNT(*) FROM big", t0, 5000, 0, 5000, 10))
	s := a.Snapshot(t0.Add(time.Second))
	if s.CPUAccounting != AccountingNoRunDelay {
		t.Fatalf("accounting = %q", s.CPUAccounting)
	}
	for _, d := range s.TopByCPU {
		if d.DigestText == "select * from users where id = ?" && d.Role != RoleVictim {
			t.Fatalf("expected victim via wall-cpu fallback, got %q", d.Role)
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
