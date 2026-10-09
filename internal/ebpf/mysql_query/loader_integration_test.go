//go:build linux && ebpf_integration

package mysql_query

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/manhvu1997/linux-obs-agent/internal/mysql/sqlhash"
)

// Needs root and a running mysqld (any supported version; `make
// test-mysql-matrix` runs this against MySQL 5.7, 8.0, 8.4 and 9.x in Docker).
//
//	MYSQLD_PATH  the mysqld binary to attach to (default /usr/sbin/mysqld; for a
//	             container: /proc/<pid>/root/usr/sbin/mysqld)
//	MYSQL_DSN    go-sql-driver DSN, e.g. "root:secret@tcp(127.0.0.1:3306)/"
func startLoader(t *testing.T) (*Loader, *sql.DB) {
	t.Helper()
	path := os.Getenv("MYSQLD_PATH")
	if path == "" {
		path = "/usr/sbin/mysqld"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no mysqld at %s", path)
	}
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		t.Skip("MYSQL_DSN not set")
	}
	l := NewLoader(100_000_000, path, true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := l.Start(ctx); err != nil {
		t.Fatalf("start (run as root): %v", err)
	}
	t.Cleanup(l.Stop)
	// Opened after the probes are attached, so its statements are prepared
	// while the agent watches.
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return l, db
}

// waitCmd returns the first command event matching ok within 5 s.
func waitCmd(t *testing.T, l *Loader, ok func(CmdEvent) bool) CmdEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-l.CmdEvents:
			if ok(ev) {
				return ev
			}
		case <-deadline:
			t.Fatal("no matching cmd event within 5s")
		}
	}
}

func TestCmdEventCarriesCPUAndBytes(t *testing.T) {
	l, db := startLoader(t)
	const q = "SELECT REPEAT('a', 100000) AS big"
	// Aggregated commands no longer reach CmdEvents; mark the statement unsafe
	// so this test keeps exercising the full-event path.
	l.MarkUnsafe(3, sqlhash.KernelHash([]byte(q)))
	var big string
	if err := db.QueryRow(q).Scan(&big); err != nil { // no args: COM_QUERY
		t.Fatal(err)
	}
	ev := waitCmd(t, l, func(ev CmdEvent) bool { return ev.Command == 3 && strings.Contains(ev.Query, q) })
	if ev.BytesOut < 100000 {
		t.Fatalf("bytes_out = %d, want >= 100000", ev.BytesOut)
	}
	if ev.CPUNs > ev.WallNs || ev.RunqNs > ev.WallNs || ev.WallNs == 0 {
		t.Fatalf("timing invariant broken: %+v", ev)
	}
	if ev.BytesIn != uint64(len(q)) {
		t.Fatalf("bytes_in = %d", ev.BytesIn)
	}
}

// TestPreparedStatementTextRecovered checks the version-specific part: the
// Prepared_statement::prepare register layout chosen by mysqldsym.
func TestPreparedStatementTextRecovered(t *testing.T) {
	l, db := startLoader(t)
	if !l.PreparedTextTracking() {
		t.Fatal("prepared-statement text tracking is off for this mysqld (see the loader's warning)")
	}
	const q = "SELECT ? + 41 AS answer"
	l.MarkUnsafe(23, sqlhash.KernelHash([]byte(q))) // keep the full-event path
	stmt, err := db.Prepare(q)                      // binary protocol: COM_STMT_PREPARE
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	var answer int
	if err := stmt.QueryRow(1).Scan(&answer); err != nil { // COM_STMT_EXECUTE
		t.Fatal(err)
	}
	ev := waitCmd(t, l, func(ev CmdEvent) bool { return ev.Command == 23 })
	if ev.Query != q {
		t.Fatalf("COM_STMT_EXECUTE text = %q, want %q", ev.Query, q)
	}
}

// drainUntil drains until pred holds for the accumulated entries or 5 s pass.
func drainUntil(t *testing.T, l *Loader, pred func([]AggEntry) bool) []AggEntry {
	t.Helper()
	var all []AggEntry
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := l.DrainAgg()
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, got...)
		if pred(all) {
			return all
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition not met; entries: %+v", all)
	return nil
}

// 50 executions that differ only in literals land in one entry.
func TestAggregatesIdenticalShapes(t *testing.T) {
	l, db := startLoader(t)
	for i := 0; i < 50; i++ {
		var n int
		if err := db.QueryRow(fmt.Sprintf("SELECT %d + 1", i)).Scan(&n); err != nil {
			t.Fatal(err)
		}
	}
	want := sqlhash.KernelHash([]byte("SELECT 0 + 1"))
	drainUntil(t, l, func(es []AggEntry) bool {
		var calls uint64
		for _, e := range es {
			if e.Command == 3 && e.Hash == want {
				calls += e.Calls
			}
		}
		return calls == 50
	})
}

// Every first-sight text event's hash equals the Go reference.
func TestKernelHashMatchesGo(t *testing.T) {
	l, db := startLoader(t)
	stmts := []string{
		"SELECT 'it''s', \"q\", 1.5, -3, 0x1F, 1e3 /* it's */",
		"SELECT `2col` FROM (SELECT 1 AS `2col`) t -- c\n",
		"SELECT 1abc FROM (SELECT 1 AS 1abc) t # x\n",
	}
	for _, s := range stmts {
		rows, err := db.Query(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		rows.Close()
	}
	// Only the statements issued above count; text events from other clients
	// of the same mysqld are ignored.
	want := make(map[string]bool, len(stmts))
	for _, s := range stmts {
		want[s] = true
	}
	seen := 0
	deadline := time.After(5 * time.Second)
	for seen < len(stmts) {
		select {
		case ev := <-l.TextEvents:
			if ev.Command != 3 || !want[ev.Query] {
				continue
			}
			if got := sqlhash.KernelHash([]byte(ev.Query)); got != ev.Hash {
				t.Fatalf("kernel hash %#x != Go %#x for %q", ev.Hash, got, ev.Query)
			}
			delete(want, ev.Query) // each statement counts once (verify resends)
			seen++
		case <-deadline:
			t.Fatalf("saw %d of %d expected text events", seen, len(stmts))
		}
	}
}

// Statements marked unsafe take the same fallback path as an overflowing
// aggregation map: delivered as full events, not aggregated.
func TestUnsafeHashFallsBackToFullEvents(t *testing.T) {
	l, db := startLoader(t)
	const q = "SELECT 7 + 1"
	l.MarkUnsafe(3, sqlhash.KernelHash([]byte(q)))
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	waitCmd(t, l, func(ev CmdEvent) bool { return ev.Command == 3 && ev.Query == q })
}
