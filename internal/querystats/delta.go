package querystats

import (
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// Delta is the sum of Calls executions of one statement shape by one PID,
// as drained from the kernel's aggregation map. A single Event is a Delta of
// one call (DeltaFromEvent).
//
// WallMaxNs must be set whenever Calls > 1: it is folded with max() and is
// not derived from the sums, so a zero there loses the digest's maximum. For
// one call it equals WallNs.
type Delta struct {
	PID         uint32
	Command     string
	Digest      sqldigest.Digest
	SampleQuery string
	Truncated   bool
	Calls       uint64
	WallNs      uint64
	WallMaxNs   uint64
	CPUNs       uint64
	RunqNs      uint64
	BytesIn     uint64
	BytesOut    uint64
}

// DeltaFromEvent converts one measured call.
func DeltaFromEvent(e Event) Delta {
	return Delta{
		PID: e.PID, Command: e.Command, Digest: e.Digest, SampleQuery: e.SampleQuery, Truncated: e.Truncated,
		Calls: 1, WallNs: e.WallNs, WallMaxNs: e.WallNs, CPUNs: e.CPUNs,
		RunqNs: e.RunqNs, BytesIn: e.BytesIn, BytesOut: e.BytesOut,
	}
}

// AddDeltas records every delta at time at under one lock. Deltas with zero
// calls are ignored.
func (a *Aggregator) AddDeltas(ds []Delta, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range ds {
		if d.Calls > 0 {
			a.addDeltaLocked(d, at)
		}
	}
}
