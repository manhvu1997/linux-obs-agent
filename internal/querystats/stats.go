package querystats

import (
	"math"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	// VictimCPU / VictimDisk / VictimCommit: victim_of for a digest whose
	// largest measured wait is the run queue, block I/O, or the redo log
	// (waits >= victim_wait_percent, slow).
	VictimCPU    = "cpu"
	VictimDisk   = "disk"
	VictimCommit = "commit"
	// InnoDBPageBytes is the default InnoDB page size (disk_read_pages_per_call).
	InnoDBPageBytes = 16384
	// AccountingKeyCPUWait is the accounting entry for run-queue time.
	AccountingKeyCPUWait = "cpu_wait"
	// AccountingKeyDiskBytes / AccountingKeyDiskWait / AccountingKeyCommitWait
	// are the accounting entries for per-statement disk bytes, block-I/O wait
	// and commit wait.
	AccountingKeyDiskBytes  = "disk_bytes"
	AccountingKeyDiskWait   = "disk_wait"
	AccountingKeyCommitWait = "commit_wait"
	// accountingUnknown: no host sample in the window says whether a signal is available.
	accountingUnknown = "unknown"
)

// nodeDenom is the node's CPU over the same polls as the digests.
type nodeDenom struct {
	usedNs      uint64
	usedPercent float64
}

// avail: which per-statement signals every poll in the window measured.
type avail struct{ runq, diskBytes, ioWait, redo bool }

// diskDenom is the node's physical-disk reads over the same polls.
type diskDenom struct {
	readBytes    uint64
	readMBPerSec float64
}

// addNewStats fills the window statistics of one digest (spec §6.1–6.2).
func (a *Aggregator) addNewStats(s *model.QueryDigestStats, k key, x *acc, av avail, nd *nodeDenom, dd *diskDenom) {
	w := a.cfg.Window
	calls := float64(x.calls)
	s.CPUNs, s.RunqNs, s.WallNs, s.BytesOut = x.cpu, x.runq, x.wall, x.out
	s.CallsPerSec = calls / w.Seconds()
	s.CPUCores = float64(x.cpu) / float64(w.Nanoseconds())
	s.LatencyMsAvg = float64(x.wall) / calls / 1e6
	s.LatencyMsMax = float64(x.wallMax) / 1e6
	s.BytesOutPerCall = float64(x.out) / calls
	if nd != nil {
		p := 100 * float64(x.cpu) / float64(nd.usedNs)
		s.PercentOfNodeCPUUsed = &p
	}
	s.DiskReadBytes, s.DiskWriteBytes, s.IOWaitNs, s.RedoWaitNs = x.diskRead, x.diskWrite, x.ioWait, x.redoWait
	if av.diskBytes {
		r, wr := mbPerSec(x.diskRead, w), mbPerSec(x.diskWrite, w)
		pages := float64(x.diskRead) / calls / InnoDBPageBytes
		s.DiskReadMBPerSec, s.DiskWriteMBPerSec, s.DiskReadPagesPerCall = &r, &wr, &pages
		if dd != nil && dd.readBytes > 0 {
			p := 100 * float64(x.diskRead) / float64(dd.readBytes)
			s.PercentOfDiskRead = &p
		}
	}
	s.TimeBreakdown = breakdown(x, av)
	if k.id == OtherDigestID {
		return
	}
	if p := s.PercentOfNodeCPUUsed; p != nil && *p >= a.cfg.CPUCulpritPercentOfNodeUsed && nd.usedPercent >= a.cfg.CPUCulpritMinNodeUsedPercent {
		s.CPURole = RoleCulprit
	}
	if p := s.PercentOfDiskRead; p != nil && *p >= a.cfg.IOCulpritPercentOfDiskRead && dd.readMBPerSec >= a.cfg.IOCulpritMinNodeDiskReadMBPerSec {
		s.IORole = RoleCulprit
	}
	s.VictimOf = victimOf(s.TimeBreakdown, s.LatencyMsAvg >= float64(a.cfg.SlowWallNs)/1e6, a.cfg.VictimWaitPercent)
}

// breakdown splits wall time into on-CPU, waiting for a CPU, block-I/O wait,
// commit wait and the rest, in percent summing to 100. The four measured
// parts are disjoint (the kernel subtracts CPU, run-queue and block-I/O time
// from commit wait); on short calls they can still exceed wall by a tick, so
// they are divided by max(wall, their sum). An unavailable part is absent and
// its time stays in "other".
func breakdown(x *acc, av avail) *model.TimeBreakdown {
	if x.wall == 0 {
		return nil
	}
	parts := float64(x.cpu)
	if av.runq {
		parts += float64(x.runq)
	}
	if av.ioWait {
		parts += float64(x.ioWait)
	}
	if av.redo {
		parts += float64(x.redoWait)
	}
	den := math.Max(float64(x.wall), parts)
	pct := func(v uint64) *float64 { p := 100 * float64(v) / den; return &p }
	tb := &model.TimeBreakdown{CPU: 100 * float64(x.cpu) / den, Other: 100 * (den - parts) / den}
	if av.runq {
		tb.CPUWait = pct(x.runq)
	}
	if av.ioWait {
		tb.DiskWait = pct(x.ioWait)
	}
	if av.redo {
		tb.CommitWait = pct(x.redoWait)
	}
	return tb
}

// victimOf: slow, and the available waits are at least minPct of its time;
// the kind is the largest wait (ties: cpu, disk, commit).
func victimOf(tb *model.TimeBreakdown, slow bool, minPct float64) string {
	if tb == nil || !slow {
		return ""
	}
	kind, top, sum := "", 0.0, 0.0
	for _, w := range []struct {
		v    *float64
		kind string
	}{{tb.CPUWait, VictimCPU}, {tb.DiskWait, VictimDisk}, {tb.CommitWait, VictimCommit}} {
		if w.v == nil {
			continue
		}
		sum += *w.v
		if *w.v > top {
			kind, top = w.kind, *w.v
		}
	}
	if sum < minPct || kind == "" {
		return ""
	}
	return kind
}

// waitNs is the digest's measured waiting time (run queue, block I/O, commit).
func waitNs(s model.QueryDigestStats, av avail) uint64 {
	var n uint64
	if av.runq {
		n += s.RunqNs
	}
	if av.ioWait {
		n += s.IOWaitNs
	}
	if av.redo {
		n += s.RedoWaitNs
	}
	return n
}

// nonZero keeps the digests whose metric is positive.
func nonZero(in []model.QueryDigestStats, metric func(model.QueryDigestStats) float64) []model.QueryDigestStats {
	out := make([]model.QueryDigestStats, 0, len(in))
	for _, s := range in {
		if metric(s) > 0 {
			out = append(out, s)
		}
	}
	return out
}
