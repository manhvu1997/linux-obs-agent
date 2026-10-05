//go:build linux && ebpf_integration

package mysql_query

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Needs a running local mysqld and the mysql client.
// MYSQLD_PATH (default /usr/sbin/mysqld), MYSQL_TEST_ARGS e.g. "-uroot -psecret -h127.0.0.1".
func TestCmdEventCarriesCPUAndBytes(t *testing.T) {
	path := os.Getenv("MYSQLD_PATH")
	if path == "" {
		path = "/usr/sbin/mysqld"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no mysqld at %s", path)
	}
	if _, err := exec.LookPath("mysql"); err != nil {
		t.Skip("mysql client not installed")
	}
	l := NewLoader(100_000_000, path, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatalf("start (run as root): %v", err)
	}
	defer l.Stop()

	args := append(strings.Fields(os.Getenv("MYSQL_TEST_ARGS")), "-e", "SELECT REPEAT('a', 100000) AS big")
	if out, err := exec.Command("mysql", args...).CombinedOutput(); err != nil {
		t.Fatalf("mysql: %v: %s", err, out)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-l.CmdEvents:
			if ev.Command != 3 || !strings.Contains(ev.Query, "REPEAT('a', 100000)") {
				continue
			}
			if ev.BytesOut < 100000 {
				t.Fatalf("bytes_out = %d, want >= 100000", ev.BytesOut)
			}
			if ev.CPUNs > ev.WallNs || ev.RunqNs > ev.WallNs || ev.WallNs == 0 {
				t.Fatalf("timing invariant broken: %+v", ev)
			}
			if ev.BytesIn != uint64(len("SELECT REPEAT('a', 100000) AS big")) {
				t.Fatalf("bytes_in = %d", ev.BytesIn)
			}
			return
		case <-deadline:
			t.Fatal("no cmd event for the test query within 5s")
		}
	}
}
