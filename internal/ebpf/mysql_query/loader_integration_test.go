//go:build linux && ebpf_integration

package mysql_query

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
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
	stmt, err := db.Prepare(q) // binary protocol: COM_STMT_PREPARE
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
