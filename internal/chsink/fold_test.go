package chsink

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func fdd(pid uint32, id, cmd string, cpu, disk, wallMax uint64) querystats.DigestDelta {
	return querystats.DigestDelta{PID: pid, DigestID: id, Command: cmd, Text: id, Calls: 1, CPUNs: cpu, WallNs: wallMax, WallMaxNs: wallMax, DiskReadBytes: disk, IOWaitNs: 1}
}

func TestFoldMinorKeepsTotals(t *testing.T) {
	in := []querystats.DigestDelta{
		fdd(1, "big", "query", 1_000_000, 1_000_000, 5),
		fdd(1, "tiny1", "query", 10, 10, 5),
		fdd(1, "tiny2", "query", 20, 0, 7),
		fdd(1, "tiny3", "stmt_execute", 30, 0, 5),
		fdd(2, "tiny4", "query", 40, 0, 5),
	}
	out := foldMinor(in, 0.1, 1_000)
	var cpu, disk, calls, io uint64
	minor := map[string]querystats.DigestDelta{}
	for _, x := range out {
		cpu, disk, calls, io = cpu+x.CPUNs, disk+x.DiskReadBytes, calls+x.Calls, io+x.IOWaitNs
		if x.DigestID == MinorDigestID {
			minor[string(rune('0'+x.PID))+x.Command] = x
		}
	}
	if cpu != 1_000_100 || disk != 1_000_010 || calls != 5 || io != 5 {
		t.Fatalf("totals cpu %d disk %d calls %d io %d changed", cpu, disk, calls, io)
	}
	if len(out) != 4 { // big + <minor> per (pid, command): (1,query) (1,stmt_execute) (2,query)
		t.Fatalf("rows = %d: %+v", len(out), out)
	}
	if m := minor["1query"]; m.Calls != 2 || m.WallMaxNs != 7 || m.Text != MinorDigestText || m.Sample != "" {
		t.Fatalf("minor (1, query) = %+v", m)
	}
}

func TestFoldMinorKeepsSlow(t *testing.T) {
	in := []querystats.DigestDelta{fdd(1, "big", "query", 1_000_000, 0, 5), fdd(1, "cheap-but-slow", "query", 10, 0, 5_000)}
	for _, x := range foldMinor(in, 0.1, 1_000) {
		if x.DigestID == MinorDigestID {
			t.Fatal("a statement with a slow execution must keep its own row")
		}
	}
}

func TestFoldMinorDisabled(t *testing.T) {
	in := []querystats.DigestDelta{fdd(1, "big", "query", 1_000_000, 0, 5), fdd(1, "tiny", "query", 1, 0, 5)}
	if out := foldMinor(in, 0, 1_000); len(out) != 2 {
		t.Fatalf("share 0 must disable folding, got %d rows", len(out))
	}
}
