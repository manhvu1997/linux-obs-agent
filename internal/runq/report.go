// Package runq builds the run-queue diagnostic report from the runqlat eBPF
// module.  It is a pure on-demand builder — no goroutines, no polling — called
// from GET /api/diagnose, mirroring internal/cpuprofile.
package runq

import (
	"fmt"
	"math"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/runqlat"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/procinfo"
)

// Options carries the thresholds in force for one report.
type Options struct {
	TopN         int
	StaleSeconds int
	// ProcessThresholdUs is the level-2 filter: report a process only when its
	// MAX run-queue wait reached this many microseconds.
	ProcessThresholdUs uint64
	// TrackMinUs is the in-kernel aggregation floor, echoed into the report so
	// consumers can interpret AvgLatencyMs correctly.
	TrackMinUs uint64
	// NodeCPUThreshold / NodeLoadThreshold are the level-1 thresholds, echoed
	// for the same reason.
	NodeCPUThreshold  float64
	NodeLoadThreshold float64
}

// BuildReport reads the runqlat eBPF maps and produces a RunQueueAnalysis.
//
// Returns nil when no process breached the level-2 threshold, so the field is
// omitted from the diagnose response rather than appearing empty.
func BuildReport(l *runqlat.Loader, m model.NodeMetrics, opt Options) *model.RunQueueAnalysis {
	minMaxNs := opt.ProcessThresholdUs * 1000
	offenders := l.TopOffenders(opt.TopN, uint64(opt.StaleSeconds)*uint64(time.Second), minMaxNs)
	if len(offenders) == 0 {
		return nil
	}

	out := make([]model.RunQOffender, 0, len(offenders))
	for _, o := range offenders {
		var avgMs float64
		if o.TrackedSwitches > 0 {
			avgMs = round2dp(float64(o.TotalLatencyNs) / float64(o.TrackedSwitches) / 1e6)
		}
		out = append(out, model.RunQOffender{
			PID:             o.PID,
			Comm:            o.Comm,
			Cmdline:         procinfo.ReadCmdline(o.PID),
			CgroupPath:      procinfo.ReadCgroup(o.PID),
			TrackedSwitches: o.TrackedSwitches,
			SlowEvents:      o.SlowEvents,
			AvgLatencyMs:    avgMs,
			MaxLatencyMs:    round2dp(float64(o.MaxLatencyNs) / 1e6),
			ProfileURL:      fmt.Sprintf("/api/profile?pid=%d", o.PID),
		})
	}

	var normLoad float64
	if m.LoadAvg.NumCPU > 0 {
		normLoad = round2dp(m.LoadAvg.Load1 / float64(m.LoadAvg.NumCPU))
	}

	return &model.RunQueueAnalysis{
		Type:      "runqueue_analysis",
		Timestamp: time.Now(),
		System: model.RunQSystemInfo{
			CPUPercent:     m.CPU.UsagePercent,
			LoadNormalised: normLoad,
			NumCPU:         m.LoadAvg.NumCPU,
		},
		Thresholds: model.RunQThresholds{
			NodeCPUPercent: opt.NodeCPUThreshold,
			NodeLoad:       opt.NodeLoadThreshold,
			ProcessUs:      opt.ProcessThresholdUs,
			TrackMinUs:     opt.TrackMinUs,
		},
		Histogram:    buildHistogram(l.Histogram()),
		TopOffenders: out,
	}
}

// buildHistogram converts the in-kernel log2 buckets into a compact, labelled
// distribution.  Bucket i covers waits where log2(us+1) == i, i.e. the
// microsecond range [2^i - 1, 2^(i+1) - 2].  Empty buckets are dropped so the
// JSON carries only the occupied part of the range.
func buildHistogram(raw [64]uint64) []model.RunQLatBucket {
	var out []model.RunQLatBucket
	for i, count := range raw {
		if count == 0 {
			continue
		}
		low := uint64(1)<<uint(i) - 1
		high := uint64(1)<<uint(i+1) - 2
		out = append(out, model.RunQLatBucket{
			Range:  fmt.Sprintf("%s-%s", formatUs(low), formatUs(high)),
			LowUs:  low,
			HighUs: high,
			Count:  count,
		})
	}
	return out
}

// formatUs renders a microsecond value with the largest sensible unit.
func formatUs(us uint64) string {
	switch {
	case us >= 1_000_000:
		return fmt.Sprintf("%gs", round2dp(float64(us)/1e6))
	case us >= 1_000:
		return fmt.Sprintf("%gms", round2dp(float64(us)/1e3))
	default:
		return fmt.Sprintf("%dus", us)
	}
}

func round2dp(f float64) float64 {
	return math.Round(f*100) / 100
}
