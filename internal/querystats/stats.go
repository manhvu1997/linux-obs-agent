package querystats

import (
	"math"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	// VictimCPU is victim_of for a digest slowed mostly by waiting for a CPU.
	VictimCPU = "cpu"
	// AccountingKeyCPUWait is the accounting entry for run-queue time.
	AccountingKeyCPUWait = "cpu_wait"
)

// nodeDenom is the node's CPU over the same polls as the digests.
type nodeDenom struct {
	usedNs      uint64
	usedPercent float64
}

// addNewStats fills the window statistics of one digest (spec §6.1–6.2).
func (a *Aggregator) addNewStats(s *model.QueryDigestStats, k key, x *acc, acct string, nd *nodeDenom) {
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
	s.TimeBreakdown = breakdown(x, acct == AccountingOK)
	if k.id == OtherDigestID {
		return
	}
	if p := s.PercentOfNodeCPUUsed; p != nil && *p >= a.cfg.CPUCulpritPercentOfNodeUsed && nd.usedPercent >= a.cfg.CPUCulpritMinNodeUsedPercent {
		s.CPURole = RoleCulprit
	}
	if tb := s.TimeBreakdown; tb != nil && tb.CPUWait != nil && *tb.CPUWait >= a.cfg.VictimWaitPercent &&
		s.LatencyMsAvg >= float64(a.cfg.SlowWallNs)/1e6 {
		s.VictimOf = VictimCPU
	}
}

// breakdown splits wall time into on-CPU, waiting for a CPU and the rest, in
// percent summing to 100. On short calls cpu + runq can exceed wall by a
// scheduler tick; the parts are then divided by their own sum so none is
// negative. Without run-queue accounting the wait is part of "other".
func breakdown(x *acc, runqOK bool) *model.TimeBreakdown {
	if x.wall == 0 {
		return nil
	}
	parts := float64(x.cpu)
	if runqOK {
		parts += float64(x.runq)
	}
	den := math.Max(float64(x.wall), parts)
	tb := &model.TimeBreakdown{CPU: 100 * float64(x.cpu) / den, Other: 100 * (den - parts) / den}
	if runqOK {
		v := 100 * float64(x.runq) / den
		tb.CPUWait = &v
	}
	return tb
}

// waiting keeps the digests with measured run-queue wait (none when the
// kernel lacks scheduler stats).
func waiting(in []model.QueryDigestStats) []model.QueryDigestStats {
	out := make([]model.QueryDigestStats, 0, len(in))
	for _, s := range in {
		if s.TimeBreakdown != nil && s.TimeBreakdown.CPUWait != nil && s.RunqNs > 0 {
			out = append(out, s)
		}
	}
	return out
}
