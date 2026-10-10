package querystats

import (
	"testing"
	"time"
)

// One 5 s poll: node 8 CPUs, capacity 40 s.
func busyHost(usedNs uint64) HostDelta {
	return HostDelta{NodeOK: true, NodeCPUUsedNs: usedNs, NodeCPUTotalNs: 40e9, NumCPU: 8, MysqldCPUNs: usedNs}
}

func TestPerDigestFormulas(t *testing.T) {
	a := New(cfg()) // window 60 s
	a.AddDeltas([]Delta{{PID: 1, Command: "query", Digest: digestDelta(1, "SELECT a FROM t", 1, 1).Digest,
		Calls: 120, CPUNs: 12e9, RunqNs: 6e9, WallNs: 24e9, WallMaxNs: 2e9, BytesOut: 120_000}}, t0)
	a.AddHost(busyHost(36e9), t0) // node used 36 s of 40 s → 90 %
	s := a.Snapshot(t0)
	d := s.TopByCPU[0]
	if !near(d.CallsPerSec, 2) || !near(d.CPUCores, 0.2) || !near(d.LatencyMsAvg, 200) || !near(d.LatencyMsMax, 2000) || !near(d.BytesOutPerCall, 1000) {
		t.Fatalf("got %+v", d)
	}
	if d.PercentOfNodeCPUUsed == nil || !near(*d.PercentOfNodeCPUUsed, 100*12.0/36) {
		t.Fatalf("percent_of_node_cpu_used = %v", d.PercentOfNodeCPUUsed)
	}
	tb := d.TimeBreakdown
	if tb == nil || !near(tb.CPU, 50) || tb.CPUWait == nil || !near(*tb.CPUWait, 25) || !near(tb.Other, 25) {
		t.Fatalf("breakdown = %+v", tb)
	}
	if d.CPUNs != 12e9 || d.RunqNs != 6e9 || d.WallNs != 24e9 || d.BytesOut != 120_000 {
		t.Fatalf("raw sums = %+v", d)
	}
	if s.Accounting[AccountingKeyCPUWait] != AccountingOK {
		t.Fatalf("accounting = %v", s.Accounting)
	}
}

func TestTimeBreakdownSumsTo100(t *testing.T) {
	a := New(cfg())
	// cpu + runq (5 ms) exceed wall (4 ms) by tick rounding.
	a.AddDeltas([]Delta{{PID: 1, Command: "query", Digest: digestDelta(1, "SELECT 1", 1, 1).Digest,
		Calls: 1, CPUNs: 3e6, RunqNs: 2e6, WallNs: 4e6, WallMaxNs: 4e6}}, t0)
	tb := a.Snapshot(t0).TopByCPU[0].TimeBreakdown
	if tb == nil || tb.CPUWait == nil || tb.Other < 0 || !near(tb.CPU+*tb.CPUWait+tb.Other, 100) || !near(tb.Other, 0) {
		t.Fatalf("breakdown = %+v", tb)
	}
}

func TestCPUCulpritNeedsShareAndBusyNode(t *testing.T) {
	for _, c := range []struct {
		name             string
		digestNs, usedNs uint64
		want             string
	}{
		{"busy node, big share", 10e9, 36e9, RoleCulprit}, // 27.8 % of 90 % used
		{"busy node, small share", 5e9, 36e9, ""},         // 13.9 %
		{"node at the floor", 8e9, 20e9, RoleCulprit},     // 40 % of exactly 50 % used
		{"node below the floor", 8e9, 19e9, ""},           // 42 % of 47.5 % used
	} {
		t.Run(c.name, func(t *testing.T) {
			a := New(cfg())
			a.AddDeltas([]Delta{digestDelta(1, "SELECT a FROM t", 10, c.digestNs)}, t0)
			a.AddHost(busyHost(c.usedNs), t0)
			if got := a.Snapshot(t0).TopByCPU[0].CPURole; got != c.want {
				t.Fatalf("cpu_role = %q, want %q", got, c.want)
			}
		})
	}
}

func TestIdleNodeHasNoCPUCulprit(t *testing.T) {
	a := New(cfg())
	// exporter queries: 90 % of all query CPU, but the node is 5 % busy.
	a.AddDeltas([]Delta{digestDelta(1, "SELECT * FROM information_schema.processlist", 100, 9e8), digestDelta(1, "SELECT 1", 10, 1e8)}, t0)
	a.AddHost(busyHost(2e9), t0)
	for _, d := range a.Snapshot(t0).TopByCPU {
		if d.CPURole != "" {
			t.Fatalf("%s: cpu_role %q on an idle node", d.DigestText, d.CPURole)
		}
	}
}

func TestNoNodeNoPercentNoCulprit(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{digestDelta(1, "SELECT a FROM t", 10, 30e9)}, t0)
	d := a.Snapshot(t0).TopByCPU[0]
	if d.PercentOfNodeCPUUsed != nil || d.CPURole != "" {
		t.Fatalf("without node samples: percent %v role %q", d.PercentOfNodeCPUUsed, d.CPURole)
	}
}

func TestVictimOfCPU(t *testing.T) {
	a := New(cfg()) // slow threshold 10 ms
	a.AddDeltas([]Delta{
		// waited 60 % of a 50 ms average: victim
		{PID: 1, Command: "query", Digest: digestDelta(1, "SELECT v FROM t", 1, 1).Digest, Calls: 10, CPUNs: 100e6, RunqNs: 300e6, WallNs: 500e6, WallMaxNs: 60e6},
		// waited 60 % but fast (5 ms average): not a victim
		{PID: 1, Command: "query", Digest: digestDelta(1, "SELECT f FROM t", 1, 1).Digest, Calls: 10, CPUNs: 10e6, RunqNs: 30e6, WallNs: 50e6, WallMaxNs: 6e6},
	}, t0)
	s := a.Snapshot(t0)
	got := map[string]string{}
	for _, d := range s.TopByCPU {
		got[d.DigestText] = d.VictimOf
	}
	if got["select v from t"] != VictimCPU || got["select f from t"] != "" {
		t.Fatalf("victim_of = %v", got)
	}
	if s.Victims[VictimCPU] != 1 {
		t.Fatalf("victims = %v", s.Victims)
	}
	if len(s.TopByWait) == 0 || s.TopByWait[0].DigestText != "select v from t" {
		t.Fatalf("top_by_wait = %+v", s.TopByWait)
	}
}

func TestNoRunDelayOmitsCPUWait(t *testing.T) {
	a := New(cfg())
	// 1000 calls that clearly waited (wall − cpu > 10 ms each) with run_delay 0.
	a.AddDeltas([]Delta{{PID: 1, Command: "query", Digest: digestDelta(1, "SELECT v FROM t", 1, 1).Digest,
		Calls: 1000, CPUNs: 1e9, WallNs: 50e9, WallMaxNs: 60e6}}, t0)
	s := a.Snapshot(t0.Add(time.Second))
	d := s.TopByCPU[0]
	if s.Accounting[AccountingKeyCPUWait] != AccountingNoRunDelay || d.TimeBreakdown == nil || d.TimeBreakdown.CPUWait != nil || d.VictimOf != "" || len(s.TopByWait) != 0 {
		t.Fatalf("accounting %v breakdown %+v victim %q by_wait %d", s.Accounting, d.TimeBreakdown, d.VictimOf, len(s.TopByWait))
	}
	if !near(d.TimeBreakdown.CPU, 2) || !near(d.TimeBreakdown.Other, 98) {
		t.Fatalf("breakdown = %+v", d.TimeBreakdown)
	}
}

func TestOtherDigestHasNoNewRoles(t *testing.T) {
	c := cfg()
	c.MaxDigests = 1
	a := New(c)
	a.AddDeltas([]Delta{digestDelta(1, "SELECT a FROM t", 10, 1e6), digestDelta(1, "SELECT b FROM t", 10, 30e9)}, t0) // b folds into <other>
	a.AddHost(busyHost(36e9), t0)
	found := false
	for _, d := range a.Snapshot(t0).TopByCPU {
		if d.DigestID != OtherDigestID {
			continue
		}
		found = true
		if d.CPURole != "" || d.VictimOf != "" {
			t.Fatalf("<other> got roles %q / %q", d.CPURole, d.VictimOf)
		}
	}
	if !found {
		t.Fatal("no <other> row in TopByCPU")
	}
}

func TestThresholdsEchoed(t *testing.T) {
	th := New(cfg()).Snapshot(t0).Thresholds
	if th.CPUCulpritPercentOfNodeCPUUsed != 20 || th.CPUCulpritMinNodeCPUUsedPercent != 50 || th.VictimWaitPercent != 50 || th.VictimMinLatencyMs != 10 {
		t.Fatalf("thresholds = %+v", th)
	}
}
