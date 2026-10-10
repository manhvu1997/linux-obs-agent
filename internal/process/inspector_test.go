package process

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestDeltaRates(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	prev := prevSample{cpuTime: 1000, readBytes: 10 << 20, writeBytes: 4 << 20, ioOK: true, startTime: 77, sampleTime: t0}
	at := func(cpu, rd, wr uint64) prevSample {
		return prevSample{cpuTime: cpu, readBytes: rd, writeBytes: wr, ioOK: true, startTime: 77, sampleTime: t0.Add(10 * time.Second)}
	}
	// 200 ticks (2 s of CPU) over 10 s on 2 CPUs = 10 %; 10 MiB read, 1 MiB written over 10 s.
	cpu, r, w := deltaRates(prev, at(1200, 20<<20, 5<<20), 2)
	if cpu != 10 || r != 1<<20 || w != float64(1<<20)/10 {
		t.Fatalf("normal: cpu %v read %v write %v", cpu, r, w)
	}
	for _, c := range []struct {
		name string
		cur  prevSample
	}{
		{"cpu counter went backwards", at(900, 20<<20, 5<<20)},
		{"read counter reset", at(1200, 1<<20, 5<<20)},
		{"write counter reset", at(1200, 20<<20, 1<<20)},
		{"pid reused (new start time)", func() prevSample { s := at(1200, 20<<20, 5<<20); s.startTime = 99; return s }()},
	} {
		cpu, r, w := deltaRates(prev, c.cur, 2)
		if cpu < 0 || cpu > 100 || r < 0 || r > 1<<30 || w < 0 || w > 1<<30 {
			t.Errorf("%s: cpu %v read %v write %v (wrapped)", c.name, cpu, r, w)
		}
	}
	if cpu, r, w := deltaRates(prev, func() prevSample { s := at(1200, 20<<20, 5<<20); s.startTime = 99; return s }(), 2); cpu != 0 || r != 0 || w != 0 {
		t.Errorf("pid reuse must give 0 for this scan: %v %v %v", cpu, r, w)
	}
	// /proc/<pid>/io unreadable in the previous scan: no I/O rate (it would be the whole history).
	noIO := prev
	noIO.ioOK, noIO.readBytes, noIO.writeBytes = false, 0, 0
	if _, r, w := deltaRates(noIO, at(1200, 20<<20, 5<<20), 2); r != 0 || w != 0 {
		t.Errorf("no previous I/O sample: read %v write %v", r, w)
	}
}
