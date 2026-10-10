package querystats

import (
	"reflect"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// One delta of N calls must produce the same snapshot as N single events.
func TestAddDeltasEqualsRepeatedAdd(t *testing.T) {
	e := ev("SELECT * FROM carts WHERE user_id = 1", t0, 3, 0.1, 3.2, 500)
	e.DiskReadBytes, e.DiskWriteBytes, e.IOWaitNs, e.RedoWaitNs = 16384, 100, 50_000, 20_000
	byEvent, byDelta := New(cfg()), New(cfg())
	for i := 0; i < 1000; i++ {
		byEvent.Add(e)
	}
	d := DeltaFromEvent(e)
	d.Calls, d.CPUNs, d.RunqNs, d.WallNs = 1000, 1000*e.CPUNs, 1000*e.RunqNs, 1000*e.WallNs
	d.BytesOut = 1000 * e.BytesOut
	d.DiskReadBytes, d.DiskWriteBytes, d.IOWaitNs, d.RedoWaitNs = 1000*e.DiskReadBytes, 1000*e.DiskWriteBytes, 1000*e.IOWaitNs, 1000*e.RedoWaitNs
	byDelta.AddDeltas([]Delta{d}, t0)
	now := t0.Add(time.Second)
	a, b := byEvent.Snapshot(now), byDelta.Snapshot(now)
	if !reflect.DeepEqual(a.TopByCPU, b.TopByCPU) || !reflect.DeepEqual(a.Commands, b.Commands) {
		t.Fatalf("snapshots differ:\nevents %+v\ndeltas %+v", a.TopByCPU, b.TopByCPU)
	}
}

func TestAddDeltasKeepsMaxima(t *testing.T) {
	a := New(cfg())
	d := DeltaFromEvent(ev("SELECT 1", t0, 1, 0, 2, 0))
	d.Calls, d.CPUNs, d.WallNs, d.WallMaxNs = 10, 10e6, 20e6, 9e6
	a.AddDeltas([]Delta{d}, t0)
	s := a.Snapshot(t0.Add(time.Second))
	if got := s.TopByCPU[0].LatencyMsMax; got != 9 {
		t.Fatalf("latency max = %v, want 9", got)
	}
}

func TestAddDeltasZeroCallsIgnored(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{{PID: 1, Command: "query"}}, t0)
	if s := a.Snapshot(t0.Add(time.Second)); len(s.TopByCPU) != 0 {
		t.Fatalf("zero-call delta produced %d digests", len(s.TopByCPU))
	}
}

// Run-delay detection works on sums: 1000 waited calls with zero run_delay.
func TestRunDelayUnavailableFromDeltas(t *testing.T) {
	a := New(cfg())
	d := DeltaFromEvent(ev("SELECT SLEEP(1)", t0, 0, 0, 50, 0))
	d.Calls, d.WallNs = 1000, 1000*50e6
	a.AddDeltas([]Delta{d}, t0)
	if s := a.Snapshot(t0.Add(time.Second)); s.Accounting[AccountingKeyCPUWait] != AccountingNoRunDelay {
		t.Fatalf("accounting = %v", s.Accounting)
	}
}

func TestDeltaCarriesDiskAndWaits(t *testing.T) {
	a := New(cfg())
	a.EnableDrain(10)
	a.AddDeltas([]Delta{{PID: 1, Command: "query", Digest: sqldigest.Normalize("SELECT 1"), Calls: 2, WallNs: 10, WallMaxNs: 6,
		DiskReadBytes: 32768, DiskWriteBytes: 100, IOWaitNs: 3, RedoWaitNs: 2}}, t0)
	c := a.Snapshot(t0).Commands["query"]
	if c.DiskReadBytes != 32768 || c.DiskWriteBytes != 100 || c.IOWaitNs != 3 || c.RedoWaitNs != 2 {
		t.Fatalf("command counters = %+v", c)
	}
	dd, _ := a.DrainDigests()
	if len(dd) != 1 || dd[0].DiskReadBytes != 32768 || dd[0].IOWaitNs != 3 || dd[0].RedoWaitNs != 2 {
		t.Fatalf("drain = %+v", dd)
	}
}
