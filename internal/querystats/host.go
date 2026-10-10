package querystats

import (
	"sort"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// HostDelta is what the node and the traced mysqld processes did between
// two polls. Recorded with AddHost at the same time as that poll's
// AddDeltas, so window numerators and denominators cover the same polls.
type HostDelta struct {
	NodeCPUUsedNs  uint64 // all CPUs: user+nice+system+irq+softirq+steal
	NodeCPUTotalNs uint64 // all CPUs, every state (capacity)
	NumCPU         int
	NodeOK         bool   // false: no valid node delta for this poll
	MysqldCPUNs    uint64 // Σ utime+stime of the traced PIDs
	MysqldPartial  bool   // a traced PID had no usable baseline (new, restarted or gone)
}

// hostAcc is one bucket's host deltas.
type hostAcc struct {
	samples                     int
	nodeUsed, nodeTotal, mysqld uint64
	numCPU                      int
	nodeMissing, mysqldPartial  bool
}

// AddHost records one poll's host deltas into the bucket of at.
func (a *Aggregator) AddHost(h HostDelta, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	x := &a.bucketFor(at).host
	x.samples++
	if h.NodeOK {
		x.nodeUsed += h.NodeCPUUsedNs
		x.nodeTotal += h.NodeCPUTotalNs
		x.numCPU = h.NumCPU
	} else {
		x.nodeMissing = true
	}
	x.mysqld += h.MysqldCPUNs
	x.mysqldPartial = x.mysqldPartial || h.MysqldPartial
}

// WindowPIDs returns the PIDs with digest data in the window ending at now,
// ascending: the processes whose CPU the coverage denominator must include.
func (a *Aggregator) WindowPIDs(now time.Time) []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := map[uint32]bool{}
	for _, b := range a.inWindow(now) {
		for k := range b.m {
			seen[k.pid] = true
		}
	}
	out := make([]uint32, 0, len(seen))
	for pid := range seen {
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// hostWindow is the host deltas summed over the window's buckets.
type hostWindow struct {
	hostAcc
	numCPUEpoch int64
}

func (a *Aggregator) hostTotals(bs []*bucket) hostWindow {
	var w hostWindow
	for _, b := range bs {
		x := b.host
		w.samples += x.samples
		w.nodeUsed += x.nodeUsed
		w.nodeTotal += x.nodeTotal
		w.mysqld += x.mysqld
		w.nodeMissing = w.nodeMissing || x.nodeMissing
		w.mysqldPartial = w.mysqldPartial || x.mysqldPartial
		if x.numCPU > 0 && (w.numCPU == 0 || b.epoch > w.numCPUEpoch) {
			w.numCPU, w.numCPUEpoch = x.numCPU, b.epoch
		}
	}
	return w
}

// nodeUsedNs is the node CPU used over the window, ok only when every poll
// in it had a valid node delta.
func (w hostWindow) nodeUsedNs() (uint64, bool) {
	if w.samples == 0 || w.nodeMissing || w.nodeTotal == 0 {
		return 0, false
	}
	return w.nodeUsed, true
}

func (w hostWindow) node(window time.Duration) *model.MySQLNodeWindow {
	used, ok := w.nodeUsedNs()
	if !ok {
		return nil
	}
	return &model.MySQLNodeWindow{
		NumCPU:         w.numCPU,
		CPUUsedCores:   float64(used) / float64(window.Nanoseconds()),
		CPUUsedPercent: 100 * float64(used) / float64(w.nodeTotal),
	}
}
