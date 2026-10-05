package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProcStatStartTimeAndWeirdComm(t *testing.T) {
	// comm contains spaces and parentheses; starttime is field 22 = 987654.
	line := "4821 (my (weird) proc) S 1 4821 4821 0 -1 4194560 1000 0 0 0 " +
		"150 50 0 0 20 0 7 0 987654 123456789 2048 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	p := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(p, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := readProcStat(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.comm != "my (weird) proc" || s.ppid != 1 || s.utime != 150 || s.stime != 50 ||
		s.numThreads != 7 || s.starttime != 987654 || s.vsize != 123456789 || s.rss != 2048 {
		t.Fatalf("parsed = %+v", s)
	}
}
