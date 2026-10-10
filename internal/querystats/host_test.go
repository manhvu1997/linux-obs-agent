package querystats

import (
	"math"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func digestDelta(pid uint32, sql string, calls, cpuNs uint64) Delta {
	return Delta{PID: pid, Command: "query", Digest: sqldigest.Normalize(sql), Calls: calls,
		CPUNs: cpuNs, CPUMaxNs: cpuNs, WallNs: cpuNs, WallMaxNs: cpuNs}
}

func okHost(used, total, mysqld uint64) HostDelta {
	return HostDelta{NodeOK: true, NodeCPUUsedNs: used, NodeCPUTotalNs: total, NumCPU: 8, MysqldCPUNs: mysqld}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestNodeBlockAndCoverage(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{digestDelta(100, "SELECT 1", 10, 2e9)}, t0)
	// 5 s poll on 8 CPUs: total 40 s of capacity, 30 s used; mysqld used 4 s.
	a.AddHost(okHost(30e9, 40e9, 4e9), t0)
	s := a.Snapshot(t0)
	if s.Node == nil || s.Node.NumCPU != 8 || !near(s.Node.CPUUsedPercent, 75) || !near(s.Node.CPUUsedCores, 0.5) {
		t.Fatalf("node = %+v", s.Node) // 30 s used over a 60 s window = 0.5 cores
	}
	if s.QueryCPUCoveragePercent == nil || !near(*s.QueryCPUCoveragePercent, 50) {
		t.Fatalf("coverage = %v, want 50", s.QueryCPUCoveragePercent)
	}
}

func TestHostSamplesAccumulateWithinBucket(t *testing.T) {
	a := New(cfg())
	a.AddHost(okHost(10e9, 40e9, 1e9), t0)
	a.AddHost(okHost(20e9, 40e9, 1e9), t0.Add(2*time.Second)) // same 5 s bucket
	a.AddDeltas([]Delta{digestDelta(100, "SELECT 1", 1, 1e9)}, t0)
	s := a.Snapshot(t0.Add(2 * time.Second))
	if s.Node == nil || !near(s.Node.CPUUsedPercent, 37.5) || s.QueryCPUCoveragePercent == nil || !near(*s.QueryCPUCoveragePercent, 50) {
		t.Fatalf("node %+v coverage %v", s.Node, s.QueryCPUCoveragePercent)
	}
}

func TestNoHostSamplesOmitsNodeAndCoverage(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{digestDelta(100, "SELECT 1", 1, 1e9)}, t0)
	s := a.Snapshot(t0)
	if s.Node != nil || s.QueryCPUCoveragePercent != nil {
		t.Fatalf("node %+v coverage %v, want both nil", s.Node, s.QueryCPUCoveragePercent)
	}
}

func TestNodeOmittedWhenAPollMissedTheNode(t *testing.T) {
	a := New(cfg())
	a.AddHost(HostDelta{NodeOK: false, MysqldCPUNs: 1e9}, t0)
	a.AddHost(okHost(10e9, 40e9, 1e9), t0.Add(5*time.Second))
	if s := a.Snapshot(t0.Add(5 * time.Second)); s.Node != nil {
		t.Fatalf("node = %+v, want nil while the failed poll is in the window", s.Node)
	}
	a.AddHost(okHost(10e9, 40e9, 1e9), t0.Add(60*time.Second))
	if s := a.Snapshot(t0.Add(60 * time.Second)); s.Node == nil {
		t.Fatal("node must return once the failed poll left the window")
	}
}

func TestCoverageOmittedWhilePartialPollInWindow(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{digestDelta(100, "SELECT 1", 1, 1e9)}, t0)
	a.AddHost(HostDelta{NodeOK: true, NodeCPUUsedNs: 1e9, NodeCPUTotalNs: 40e9, NumCPU: 8, MysqldPartial: true}, t0)
	a.AddDeltas([]Delta{digestDelta(100, "SELECT 1", 1, 1e9)}, t0.Add(5*time.Second))
	a.AddHost(okHost(1e9, 40e9, 2e9), t0.Add(5*time.Second))
	if s := a.Snapshot(t0.Add(5 * time.Second)); s.QueryCPUCoveragePercent != nil {
		t.Fatalf("coverage = %v, want nil while a partial poll is in the window", *s.QueryCPUCoveragePercent)
	}
	s := a.Snapshot(t0.Add(60 * time.Second)) // t0 bucket left the window
	if s.QueryCPUCoveragePercent == nil || !near(*s.QueryCPUCoveragePercent, 50) {
		t.Fatalf("coverage = %v, want 50", s.QueryCPUCoveragePercent)
	}
}

func TestWindowPIDs(t *testing.T) {
	a := New(cfg())
	// The old poll first: t0−120 s maps to the same ring slot as t0, and a late
	// delta for an older epoch is counted into the newer bucket by design.
	a.AddDeltas([]Delta{digestDelta(200, "SELECT 1", 1, 1)}, t0.Add(-120*time.Second))
	a.AddDeltas([]Delta{digestDelta(300, "SELECT 1", 1, 1), digestDelta(100, "SELECT 2", 1, 1)}, t0)
	got := a.WindowPIDs(t0)
	if len(got) != 2 || got[0] != 100 || got[1] != 300 {
		t.Fatalf("pids = %v, want [100 300]", got)
	}
}
