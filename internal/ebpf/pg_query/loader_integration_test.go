//go:build linux && ebpf_integration

package pg_query

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pghash"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgsym"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// Needs root and a running PostgreSQL (make test-pg-matrix runs this against
// postgres:16…19 in Docker):
//
//	PG_POSTMASTER_PID  host PID of the postmaster (docker inspect -f '{{.State.Pid}}')
//	PG_DSN             e.g. postgres://postgres:secret@127.0.0.1:15432/postgres?sslmode=disable
//
// reattach re-attaches the probes startLoader attached (after l.DetachAll).
var reattach func()

func startLoader(t *testing.T) (*Loader, *pgx.Conn, uint32) {
	t.Helper()
	pidS, dsn := os.Getenv("PG_POSTMASTER_PID"), os.Getenv("PG_DSN")
	if pidS == "" || dsn == "" {
		t.Skip("PG_POSTMASTER_PID / PG_DSN not set (make test-pg-matrix)")
	}
	pid64, err := strconv.ParseUint(pidS, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	pid := uint32(pid64)
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	v, syms, err := pgsym.ReadELF(exe)
	if err != nil {
		t.Fatal(err)
	}
	h, err := pgsym.Resolve(v, syms)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	l := NewLoader(100_000_000)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := l.Start(ctx); err != nil {
		t.Fatalf("start (run as root): %v", err)
	}
	t.Cleanup(l.Stop)
	if err := l.SetClusters(map[uint32]pgtrace.ClusterConst{pid: {Running: h.States.Running, Fastpath: h.States.Fastpath}}); err != nil {
		t.Fatal(err)
	}
	bin := pgtrace.Binary{Key: pgtrace.BinaryKey{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, Path: exe, QueryID: true,
		Hooks: pgtrace.Hooks{Activity: h.Activity, PortalRun: h.PortalRun, QueryID: h.QueryID, XLogFlush: h.XLogFlush, SyncRep: h.SyncRep, Parallel: h.Parallel}}
	reattach = func() {
		if _, err := l.Attach(bin); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.Attach(bin)
	if err != nil {
		t.Fatal(err)
	}
	if !got.WAL || !got.Parallel {
		t.Fatalf("optional hooks not attached: %+v", got)
	}
	t.Logf("PostgreSQL %s, literal_skip=%v", v, l.LiteralSkip())
	// Connected after the probes: every statement of this session is traced.
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return l, conn, pid
}

func textHash(l *Loader, q string) uint64 {
	if l.LiteralSkip() {
		return pghash.KernelHash([]byte(q))
	}
	return pghash.ExactHash([]byte(q))
}

// drainFor sums the drained entries of (kind, hash) over a few drains.
func drainFor(t *testing.T, l *Loader, kind uint32, hash uint64) pgtrace.AggEntry {
	t.Helper()
	var sum pgtrace.AggEntry
	for i := 0; i < 3; i++ {
		es, err := l.DrainAgg()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if e.Kind == kind && e.Hash == hash {
				sum.Calls += e.Calls
				sum.CPUNs += e.CPUNs
				sum.WallNs += e.WallNs
			}
		}
	}
	return sum
}

func TestLiteralSkipLoaded(t *testing.T) {
	l, _, _ := startLoader(t)
	if !l.LiteralSkip() {
		t.Fatal("the verifier rejected literal-skipping pg_text_hash (exact-text fallback loaded); see the Warn log")
	}
}

func TestSimpleProtocolCalls(t *testing.T) {
	l, conn, _ := startLoader(t)
	ctx := context.Background()
	q := "SELECT 42 AS answer"
	for i := 0; i < 20; i++ {
		if _, err := conn.Exec(ctx, q, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
	}
	if e := drainFor(t, l, pgtrace.KindClient, textHash(l, q)); e.Calls != 20 || e.WallNs == 0 {
		t.Fatalf("simple protocol: %+v, want 20 calls", e)
	}
}

func TestExtendedProtocolAndBatchCalls(t *testing.T) {
	l, conn, _ := startLoader(t)
	ctx := context.Background()
	q := "SELECT $1::int + 1"
	for i := 0; i < 10; i++ {
		if _, err := conn.Exec(ctx, q, i); err != nil { // cached prepared statement: Bind/Execute
			t.Fatal(err)
		}
	}
	b := &pgx.Batch{}
	for i := 0; i < 50; i++ {
		b.Queue(q, i) // 50 Executes, one Sync
	}
	if err := conn.SendBatch(ctx, b).Close(); err != nil {
		t.Fatal(err)
	}
	if e := drainFor(t, l, pgtrace.KindClient, textHash(l, q)); e.Calls != 60 {
		t.Fatalf("extended protocol + batch: %d calls, want 60", e.Calls)
	}
}

func TestTextEventMatchesGoHash(t *testing.T) {
	l, conn, _ := startLoader(t)
	q := "SELECT 'parity' AS x, 7 AS y"
	if _, err := conn.Exec(context.Background(), q, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-l.Texts():
			if ev.Text == q {
				if ev.Hash != textHash(l, q) {
					t.Fatalf("kernel hash %x, Go %x", ev.Hash, textHash(l, q))
				}
				return
			}
		case <-deadline:
			t.Fatal("no text event")
		}
	}
}

func TestParallelWorkerCPUOnLeaderDigest(t *testing.T) {
	l, conn, _ := startLoader(t)
	ctx := context.Background()
	for _, s := range []string{
		"CREATE TABLE IF NOT EXISTS obs_par AS SELECT g AS id, md5(g::text) AS v FROM generate_series(1, 2000000) g",
		"SET max_parallel_workers_per_gather = 2", "SET parallel_setup_cost = 0", "SET parallel_tuple_cost = 0",
		"SET min_parallel_table_scan_size = 0",
	} {
		if _, err := conn.Exec(ctx, s, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
	}
	q := "SELECT count(*) FROM obs_par WHERE v LIKE '%ab%'"
	if _, err := conn.Exec(ctx, q, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if e := drainFor(t, l, pgtrace.KindParallel, textHash(l, q)); e.CPUNs == 0 {
		t.Fatal("no parallel-worker CPU on the leader's hash")
	}
}

func TestLongStatementVisibleInFlight(t *testing.T) {
	l, conn, _ := startLoader(t)
	// ~8 s of wall time plus a bounded CPU burst (about a second): long enough to be open
	// at the 3 s check, cheap in temp space, and never minutes.
	q := "SELECT pg_sleep(8), (SELECT count(*) FROM generate_series(1, 3000000))"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := conn.Exec(ctx, q, pgx.QueryExecModeSimpleProtocol); done <- err }()
	time.Sleep(3 * time.Second)
	ss, err := l.OpenSessions()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range ss {
		found = found || (s.Hash == textHash(l, q) && s.Kind == pgtrace.KindClient)
	}
	if !found {
		t.Fatalf("running statement not in OpenSessions: %+v", ss)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the long statement did not finish within 60 s")
	}
}

// The measured cost replaces the estimate in CLAUDE.md §14. It runs
// "SELECT $1::int" with one argument, so pgx uses the extended protocol
// (Parse once, then Bind/Execute from its statement cache); a warm-up round and
// alternating traced / untraced rounds keep caches and drift out of the figure.
func TestTraceCostPerStatement(t *testing.T) {
	l, conn, _ := startLoader(t)
	ctx := context.Background()
	const n, rounds = 20000, 6
	run := func(count int) time.Duration {
		t0 := time.Now()
		for i := 0; i < count; i++ {
			if _, err := conn.Exec(ctx, "SELECT $1::int", i); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(t0)
	}
	run(n / 4) // warm-up: statement cache, plan cache, CPU frequency
	var traced, plain time.Duration
	for r := 0; r < rounds; r++ {
		traced += run(n)
		l.DetachAll()
		plain += run(n)
		reattach()
	}
	total := rounds * n
	t.Logf("per statement (SELECT $1::int, extended protocol, %d alternating rounds of %d): traced %v, untraced %v, added %v",
		rounds, n, traced/time.Duration(total), plain/time.Duration(total), (traced-plain)/time.Duration(total))
}
