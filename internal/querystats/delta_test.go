package querystats

import (
	"reflect"
	"testing"
	"time"
)

// One delta of N calls must produce the same snapshot as N single events.
func TestAddDeltasEqualsRepeatedAdd(t *testing.T) {
	e := ev("SELECT * FROM carts WHERE user_id = 1", t0, 3, 0.1, 3.2, 500)
	byEvent, byDelta := New(cfg()), New(cfg())
	for i := 0; i < 1000; i++ {
		byEvent.Add(e)
	}
	d := DeltaFromEvent(e)
	d.Calls, d.CPUNs, d.RunqNs, d.WallNs = 1000, 1000*e.CPUNs, 1000*e.RunqNs, 1000*e.WallNs
	d.BytesIn, d.BytesOut = 1000*e.BytesIn, 1000*e.BytesOut
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
	d.Calls, d.CPUNs, d.WallNs, d.CPUMaxNs, d.WallMaxNs = 10, 10e6, 20e6, 7e6, 9e6
	a.AddDeltas([]Delta{d}, t0)
	s := a.Snapshot(t0.Add(time.Second))
	if got := s.TopByCPU[0]; got.CPUMsMax != 7 || got.WallMsMax != 9 {
		t.Fatalf("maxima = %v / %v, want 7 / 9", got.CPUMsMax, got.WallMsMax)
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
	if s := a.Snapshot(t0.Add(time.Second)); s.CPUAccounting != AccountingNoRunDelay {
		t.Fatalf("CPUAccounting = %q", s.CPUAccounting)
	}
}
