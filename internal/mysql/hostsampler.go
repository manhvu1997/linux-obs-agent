package mysql

import (
	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/procinfo"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// hostSampler turns cumulative CPU counters into per-poll deltas. Used only
// from the poll goroutine.
type hostSampler struct {
	nodeCPU  func() (collector.NodeCPUTimes, error)
	pidCPU   func(pid uint32) (uint64, error)
	prevNode collector.NodeCPUTimes
	haveNode bool
	prevPID  map[uint32]uint64
}

func newHostSampler() *hostSampler {
	return &hostSampler{nodeCPU: collector.ReadNodeCPUTimes, pidCPU: procinfo.ReadCPUTimeNs, prevPID: map[uint32]uint64{}}
}

// prime takes the node baseline so the first poll already has a delta.
func (h *hostSampler) prime() {
	if n, err := h.nodeCPU(); err == nil {
		h.prevNode, h.haveNode = n, true
	}
}

// sample returns the deltas since the previous call for the node and pids
// (the PIDs with digest data in the window). A PID seen for the first time,
// restarted (counter went backwards) or unreadable makes the mysqld total
// partial for this poll.
func (h *hostSampler) sample(pids []uint32) querystats.HostDelta {
	var d querystats.HostDelta
	n, err := h.nodeCPU()
	switch {
	case err != nil:
		h.haveNode = false
	case h.haveNode && n.UsedNs >= h.prevNode.UsedNs && n.TotalNs > h.prevNode.TotalNs:
		d.NodeOK = true
		d.NodeCPUUsedNs, d.NodeCPUTotalNs, d.NumCPU = n.UsedNs-h.prevNode.UsedNs, n.TotalNs-h.prevNode.TotalNs, n.NumCPU
		h.prevNode = n
	default: // no baseline, or counters went backwards: rebaseline
		h.prevNode, h.haveNode = n, true
	}
	next := make(map[uint32]uint64, len(pids))
	for _, pid := range pids {
		v, err := h.pidCPU(pid)
		if err != nil {
			d.MysqldPartial = true
			continue
		}
		if p, ok := h.prevPID[pid]; ok && v >= p {
			d.MysqldCPUNs += v - p
		} else {
			d.MysqldPartial = true
		}
		next[pid] = v
	}
	h.prevPID = next
	return d
}
