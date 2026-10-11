package querystats

import (
	"math"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// A zero-call delta (in-flight credit, parallel worker share) is recorded:
// its CPU counts, and no per-call value divides by zero.
func TestZeroCallDeltaKeepsCPUWithoutNaN(t *testing.T) {
	a := New(cfg())
	d := sqldigest.Normalize("SELECT * FROM big")
	a.AddDeltas([]Delta{{PID: 7, Command: "parallel", Digest: d, CPUNs: 5e9, DiskReadBytes: 1 << 20}}, t0)
	a.AddHost(busyHost(36e9), t0)
	s := a.Snapshot(t0)
	if len(s.TopByCPU) != 1 {
		t.Fatalf("zero-call delta dropped: %+v", s.TopByCPU)
	}
	g := s.TopByCPU[0]
	if g.CPUNs != 5e9 || g.Calls != 0 || math.IsNaN(g.LatencyMsAvg) || g.LatencyMsAvg != 0 ||
		g.DiskReadPagesPerCall != nil || g.VictimOf != "" || math.IsInf(g.BytesOutPerCall, 0) {
		t.Fatalf("got %+v", g)
	}
}

func TestZeroDeltaIgnored(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{{PID: 7, Command: "client", Digest: sqldigest.Normalize("select 1")}}, t0)
	if s := a.Snapshot(t0); len(s.TopByCPU) != 0 {
		t.Fatalf("empty delta recorded: %+v", s.TopByCPU)
	}
}

// The digest's command comes from the first delta with calls.
func TestCommandFromFirstDeltaWithCalls(t *testing.T) {
	a := New(cfg())
	d := sqldigest.Normalize("SELECT * FROM big")
	a.AddDeltas([]Delta{
		{PID: 7, Command: "parallel", Digest: d, CPUNs: 1e9},
		{PID: 7, Command: "client", Digest: d, Calls: 1, CPUNs: 1e9, WallNs: 2e9, WallMaxNs: 2e9},
	}, t0)
	if c := a.Snapshot(t0).TopByCPU[0].Command; c != "client" {
		t.Fatalf("command %q, want client", c)
	}
}

func TestReplicaWaitOffByDefault(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{{PID: 1, Command: "client", Digest: sqldigest.Normalize("COMMIT"),
		Calls: 1, WallNs: 1e9, WallMaxNs: 1e9, ReplicaWaitNs: 9e8}}, t0)
	a.AddHost(busyHost(36e9), t0)
	s := a.Snapshot(t0)
	if _, ok := s.Accounting[AccountingKeyReplicaWait]; ok {
		t.Fatal("replica_wait must be absent unless Config.ReplicaWait")
	}
	if s.TopByCPU[0].TimeBreakdown.ReplicaWait != nil {
		t.Fatal("replica part must be absent")
	}
	if _, ok := s.Victims[VictimReplica]; ok {
		t.Fatal("replica victims must be absent")
	}
}

func TestReplicaWaitVictim(t *testing.T) {
	c := cfg()
	c.ReplicaWait = true
	c.SlowWallNs = 100e6
	a := New(c)
	a.AddDeltas([]Delta{{PID: 1, Command: "client", Digest: sqldigest.Normalize("COMMIT"),
		Calls: 1, WallNs: 1e9, WallMaxNs: 1e9, CPUNs: 1e8, ReplicaWaitNs: 8e8}}, t0)
	a.AddHost(busyHost(36e9), t0)
	s := a.Snapshot(t0)
	g := s.TopByCPU[0]
	if g.VictimOf != VictimReplica || g.TimeBreakdown.ReplicaWait == nil || !near(*g.TimeBreakdown.ReplicaWait, 80) {
		t.Fatalf("%+v %+v", g, g.TimeBreakdown)
	}
	if s.Accounting[AccountingKeyReplicaWait] != AccountingOK || s.Victims[VictimReplica] != 1 {
		t.Fatalf("accounting %v victims %v", s.Accounting, s.Victims)
	}
	a.AddHost(HostDelta{NodeOK: true, NodeCPUUsedNs: 1, NodeCPUTotalNs: 40e9, NumCPU: 8, ReplicaWaitReason: "not_attached"}, t0)
	if got := a.Snapshot(t0).Accounting[AccountingKeyReplicaWait]; got != "not_attached" {
		t.Fatalf("reason %q", got)
	}
}

func TestPageBytes(t *testing.T) {
	c := cfg()
	c.PageBytes = 8192
	a := New(c)
	a.AddDeltas([]Delta{{PID: 1, Command: "client", Digest: sqldigest.Normalize("select 1"),
		Calls: 2, WallNs: 2e6, WallMaxNs: 1e6, DiskReadBytes: 4 * 8192}}, t0)
	a.AddHost(busyHost(36e9), t0)
	g := a.Snapshot(t0).TopByCPU[0]
	if g.DiskReadPagesPerCall == nil || *g.DiskReadPagesPerCall != 2 {
		t.Fatalf("pages %v", g.DiskReadPagesPerCall)
	}
}

func TestReplicaDrains(t *testing.T) {
	c := cfg()
	c.ReplicaWait = true
	a := New(c)
	a.EnableDrain(10)
	a.EnableHostDrain()
	a.AddDeltas([]Delta{{PID: 1, Command: "client", Digest: sqldigest.Normalize("COMMIT"), Calls: 1, WallNs: 1e9, WallMaxNs: 1e9, ReplicaWaitNs: 5e8}}, t0)
	a.AddHost(HostDelta{NodeOK: true, NodeCPUUsedNs: 1, NodeCPUTotalNs: 40e9, NumCPU: 8, ReplicaWaitReason: "not_attached"}, t0)
	d, _ := a.DrainDigests()
	if len(d) != 1 || d[0].ReplicaWaitNs != 5e8 {
		t.Fatalf("drain %+v", d)
	}
	if hw := a.DrainHost(); hw.ReplicaWaitOK {
		t.Fatal("ReplicaWaitOK must be false after a poll with a reason")
	}
}
