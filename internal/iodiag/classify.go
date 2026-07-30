// Package iodiag correlates the I/O signals that the agent collects into a
// single auditable verdict.
//
// The problem it solves: every individual signal is ambiguous.
//
//	iowait alone      – cannot tell a stalled machine from an idle one
//	throughput alone  – cannot tell a slow device from a saturated one
//	a CPU profile     – cannot see a blocked task at all
//	a D-state count   – says something is stuck, not what or why
//
// Only the combination decides. This package walks the layers in order —
// node → device → blocked tasks → process → stack — and emits both the verdict
// and the evidence, so the reasoning can be checked rather than trusted.
package iodiag

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Thresholds tune the classifier. Zero values fall back to Defaults().
type Thresholds struct {
	// IOWaitPercent: below this, there is nothing to diagnose.
	IOWaitPercent float64
	// LowThroughputMBPerSec: aggregate device throughput under this counts as
	// "not actually moving data".
	LowThroughputMBPerSec float64
	// LowUtilPercent: device utilisation under this counts as "not busy".
	LowUtilPercent float64
	// HighUtilPercent: utilisation above this counts as saturated.
	HighUtilPercent float64
	// DStateStallMs: a task blocked continuously longer than this is a stall
	// rather than normal I/O.
	DStateStallMs int64
	// SlowDeviceWaitMs: mean per-request service time above this is a slow
	// device even when utilisation looks low.
	SlowDeviceWaitMs float64
	// DirtyRatioPercent: dirty page share above this suggests writeback
	// throttling in balance_dirty_pages.
	DirtyRatioPercent float64
	// PSIFullAvg10: io.full above this confirms genuine lost work.
	PSIFullAvg10 float64
}

// Defaults returns the shipped thresholds.
func Defaults() Thresholds {
	return Thresholds{
		IOWaitPercent:         50.0,
		LowThroughputMBPerSec: 10.0,
		LowUtilPercent:        20.0,
		HighUtilPercent:       70.0,
		DStateStallMs:         1000,
		SlowDeviceWaitMs:      50.0,
		DirtyRatioPercent:     15.0,
		PSIFullAvg10:          10.0,
	}
}

func (t Thresholds) withDefaults() Thresholds {
	d := Defaults()
	if t.IOWaitPercent == 0 {
		t.IOWaitPercent = d.IOWaitPercent
	}
	if t.LowThroughputMBPerSec == 0 {
		t.LowThroughputMBPerSec = d.LowThroughputMBPerSec
	}
	if t.LowUtilPercent == 0 {
		t.LowUtilPercent = d.LowUtilPercent
	}
	if t.HighUtilPercent == 0 {
		t.HighUtilPercent = d.HighUtilPercent
	}
	if t.DStateStallMs == 0 {
		t.DStateStallMs = d.DStateStallMs
	}
	if t.SlowDeviceWaitMs == 0 {
		t.SlowDeviceWaitMs = d.SlowDeviceWaitMs
	}
	if t.DirtyRatioPercent == 0 {
		t.DirtyRatioPercent = d.DirtyRatioPercent
	}
	if t.PSIFullAvg10 == 0 {
		t.PSIFullAvg10 = d.PSIFullAvg10
	}
	return t
}

// storagePathWchans are kernel symbols that place a blocked task inside the
// storage or writeback path. Matched as substrings, since the exact symbol
// varies across kernel versions (wait_on_page_bit → folio_wait_bit in 5.16+).
var storagePathWchans = []string{
	"io_schedule", "wait_on_page", "folio_wait", "wait_on_buffer",
	"balance_dirty_pages", "writeback", "wb_wait", "blk_", "submit_bio",
	"jbd2", "journal", "xlog", "filemap_fault", "wait_transaction",
	"congestion_wait", "wait_iff_congested",
}

// Classify produces the correlated verdict.
//
// offcpuReport may be nil (the module is only active under sustained iowait);
// it upgrades the chain from "which task" to "which stack", so its absence
// lowers confidence rather than blocking the diagnosis.
func Classify(m model.NodeMetrics, offcpuReport *model.OffCPUReport, t Thresholds) *model.IODiagnosis {
	t = t.withDefaults()

	ev := gatherEvidence(m)
	d := &model.IODiagnosis{
		Type:      "io_diagnosis",
		Timestamp: time.Now(),
		Evidence:  ev,
	}

	if !ev.PSIAvailable {
		d.Missing = append(d.Missing, "psi (needs CONFIG_PSI=y; io.full is the strongest stall signal)")
	}
	if !m.DState.Available {
		d.Missing = append(d.Missing, "d_state census (collect.d_state_disabled is set)")
	}
	if offcpuReport == nil {
		d.Missing = append(d.Missing, "offcpu_report (module inactive — no blocking stacks)")
	}

	// ── Nothing to explain ───────────────────────────────────────────────
	if ev.IOWaitPercent < t.IOWaitPercent && ev.PSIIOSomeAvg10 < t.PSIFullAvg10 {
		d.Verdict = model.VerdictHealthy
		d.Confidence = model.ConfidenceHigh
		d.Summary = fmt.Sprintf("No I/O pressure worth reporting (iowait %.1f%%, PSI io.some %.1f%%).",
			ev.IOWaitPercent, ev.PSIIOSomeAvg10)
		d.Chain = []model.IOChainLink{{Stage: "node", Confirmed: true,
			Detail: d.Summary}}
		return d
	}

	// ── Layer 1: node ────────────────────────────────────────────────────
	deviceBusy := ev.DeviceUtilPct >= t.HighUtilPercent
	deviceIdle := ev.DeviceUtilPct < t.LowUtilPercent
	lowThroughput := ev.DeviceMBPerSec < t.LowThroughputMBPerSec
	realStall := ev.PSIAvailable && ev.PSIIOFullAvg10 >= t.PSIFullAvg10
	noStall := ev.PSIAvailable && ev.PSIIOSomeAvg10 < 1.0
	// A device serving few requests but taking a long time over each one is
	// slow by definition — independent evidence that does not depend on the
	// D-state census or the off-CPU profiler being available.
	slowDevice := ev.DeviceAvgWaitMs >= t.SlowDeviceWaitMs

	d.Chain = append(d.Chain, model.IOChainLink{
		Stage:     "node",
		Confirmed: true,
		Detail: fmt.Sprintf("iowait %.1f%%, idle %.1f%%, load/cpu %.2f, %d procs blocked; PSI io some=%.1f%% full=%.1f%%%s",
			ev.IOWaitPercent, ev.IdlePercent, ev.LoadNormalised, ev.BlockedProcs,
			ev.PSIIOSomeAvg10, ev.PSIIOFullAvg10, psiNote(ev.PSIAvailable)),
	})

	// ── Layer 2: device ──────────────────────────────────────────────────
	d.Chain = append(d.Chain, model.IOChainLink{
		Stage:     "device",
		Confirmed: ev.BusiestDevice != "",
		Detail: fmt.Sprintf("%s: util %.1f%%, %.2f MB/s, avg wait %.2f ms, in-flight %d",
			orNA(ev.BusiestDevice), ev.DeviceUtilPct, ev.DeviceMBPerSec,
			ev.DeviceAvgWaitMs, ev.DeviceInFlight),
	})

	// ── Layer 3: blocked tasks ───────────────────────────────────────────
	longStall := ev.DStateLongestMs >= t.DStateStallMs
	inStoragePath := matchesStoragePath(ev.TopBlockedWchan)
	d.Chain = append(d.Chain, model.IOChainLink{
		Stage:     "blocked_tasks",
		Confirmed: ev.DStateCount > 0,
		Detail:    describeBlocked(m.DState, t.DStateStallMs),
	})

	// ── Layers 4-5: process and stack, from the off-CPU profiler ─────────
	stackInStoragePath := false
	if offcpuReport != nil && len(offcpuReport.Processes) > 0 {
		top := offcpuReport.Processes[0]
		d.Chain = append(d.Chain, model.IOChainLink{
			Stage:     "process",
			Confirmed: true,
			Detail: fmt.Sprintf("%s (pid %d) blocked %.0f ms across %d events, max %.0f ms — %.1f%% of all blocked time",
				top.Comm, top.PID, top.BlockedMs, top.Events, top.MaxBlockedMs, top.PercentOfTotal),
		})
		if len(top.TopStacks) > 0 {
			st := top.TopStacks[0]
			stackInStoragePath = matchesStoragePath(strings.Join(st.SymbolStack, ";"))
			d.Chain = append(d.Chain, model.IOChainLink{
				Stage:     "stack",
				Confirmed: true,
				Detail: fmt.Sprintf("%.0f ms (%.1f%%) in: %s",
					st.BlockedMs, st.Percent, strings.Join(tail(st.SymbolStack, 6), " → ")),
			})
		}
	} else {
		d.Chain = append(d.Chain,
			model.IOChainLink{Stage: "process", Confirmed: false,
				Detail: "not attributed — off-CPU profiler was not active"},
			model.IOChainLink{Stage: "stack", Confirmed: false,
				Detail: "no blocking stacks; enable offcpu or query /api/profile?mode=offcpu"})
	}

	inStorage := inStoragePath || stackInStoragePath

	// ── Verdict ──────────────────────────────────────────────────────────
	switch {
	// The rule this package was built for: high iowait, device NOT moving
	// data, tasks stuck for a long time in the storage path. The device is
	// slow, not busy — adding IOPS capacity will not help.
	// Two independent routes to this verdict: the D-state + stack evidence
	// (longStall && inStorage), or the device demonstrably serving each
	// request slowly while barely moving data (slowDevice). Either alone is
	// sufficient; the confidence field records how much corroboration there was.
	case ev.IOWaitPercent >= t.IOWaitPercent && lowThroughput && ((longStall && inStorage) || slowDevice):
		d.Verdict = model.VerdictStorageLatencyStall
		d.Confidence = confidence(realStall, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = fmt.Sprintf(
			"Storage LATENCY stall, not throughput: iowait %.1f%% while %s moved only %.2f MB/s at %.1f%% util "+
				"(avg wait %.2f ms/request), longest blocked task %.1fs.",
			ev.IOWaitPercent, orNA(ev.BusiestDevice), ev.DeviceMBPerSec,
			ev.DeviceUtilPct, ev.DeviceAvgWaitMs, float64(ev.DStateLongestMs)/1000)
		d.NextSteps = []string{
			"Per-request service time is the problem, not queue depth — more IOPS capacity will not help.",
			"Check the layer beneath the device: network storage round-trip, hypervisor steal, cgroup io.max throttling, or a failing disk.",
			"Correlate with /api/diagnose .io_latency_histogram for the latency distribution.",
			"Run: GET /api/profile?pid=<pid>&mode=offcpu&format=folded for the full blocking flamegraph.",
		}

	// Dirty pages piling up: the stall is in the page cache, not the device.
	case ev.DirtyRatioPct >= t.DirtyRatioPercent && ev.IOWaitPercent >= t.IOWaitPercent:
		d.Verdict = model.VerdictWritebackCongestion
		d.Confidence = confidence(realStall, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = fmt.Sprintf(
			"Writeback congestion: %.1f%% of memory is dirty (%s) with %s under writeback; writers are being throttled in balance_dirty_pages.",
			ev.DirtyRatioPct, humanBytes(ev.DirtyBytes), humanBytes(ev.WritebackBytes))
		d.NextSteps = []string{
			"Lower vm.dirty_ratio / vm.dirty_background_ratio so writeback starts earlier and in smaller batches.",
			"Identify the writer: /api/diagnose .disk_report.top_writers and .fsync_report.",
			"Consider whether the workload should be using O_DIRECT or batching its fsyncs.",
		}

	// Device genuinely saturated: this is a capacity problem.
	case deviceBusy && !lowThroughput:
		d.Verdict = model.VerdictHighDiskThroughput
		d.Confidence = confidence(realStall, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = fmt.Sprintf(
			"Device saturated: %s at %.1f%% util moving %.2f MB/s (avg wait %.2f ms). This is a capacity limit, not a latency fault.",
			orNA(ev.BusiestDevice), ev.DeviceUtilPct, ev.DeviceMBPerSec, ev.DeviceAvgWaitMs)
		d.NextSteps = []string{
			"Reduce I/O demand or provision faster/more storage.",
			"Identify the heaviest writer via /api/diagnose .disk_report.top_writers.",
		}

	// High iowait but nothing is actually stalled — the dragonfly/io_uring
	// case. Idle CPU time relabelled because a task sits parked in D state.
	case deviceIdle && lowThroughput && !longStall &&
		(noStall || (ev.LoadNormalised < 1.0 && ev.DeviceInFlight == 0)):
		d.Verdict = model.VerdictIOWaitAccountingArtifact
		d.Confidence = confidence(false, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = fmt.Sprintf(
			"iowait %.1f%% is an accounting artifact, NOT an I/O problem: %s is idle (%.1f%% util, %.2f MB/s), "+
				"load/cpu is %.2f and nothing blocked longer than %dms. The CPU was idle while a task sat parked in D state.",
			ev.IOWaitPercent, orNA(ev.BusiestDevice), ev.DeviceUtilPct,
			ev.DeviceMBPerSec, ev.LoadNormalised, t.DStateStallMs)
		d.NextSteps = []string{
			"No action needed. iowait is idle time charged differently when any task on the runqueue is in D state.",
			"Alert on PSI io.full (pressure.io.full.avg10) instead of iowait — it measures lost work rather than idle time.",
		}

	default:
		d.Verdict = model.VerdictInconclusive
		d.Confidence = model.ConfidenceLow
		d.Summary = fmt.Sprintf(
			"Elevated iowait (%.1f%%) that does not match a known pattern: %s at %.1f%% util, %.2f MB/s, longest D-state %dms.",
			ev.IOWaitPercent, orNA(ev.BusiestDevice), ev.DeviceUtilPct,
			ev.DeviceMBPerSec, ev.DStateLongestMs)
		d.NextSteps = []string{
			"Enable the off-CPU profiler and re-query to attribute the blocked time to a stack.",
			"Check PSI availability — io.full is the decisive signal and is missing here if listed above.",
		}
	}

	return d
}

// ─── Evidence gathering ──────────────────────────────────────────────────────

func gatherEvidence(m model.NodeMetrics) model.IOEvidence {
	ev := model.IOEvidence{
		IOWaitPercent:  m.CPU.IOWaitPercent,
		IdlePercent:    m.CPU.IdlePercent,
		BlockedProcs:   m.CPU.BlockedProcs,
		PSIAvailable:   m.Pressure.IO.Available,
		DirtyBytes:     m.VMStat.DirtyBytes,
		WritebackBytes: m.VMStat.WritebackBytes,
		DirtyRatioPct:  m.VMStat.DirtyRatioPercent,
		DStateCount:    m.DState.Count,
	}
	if m.Pressure.IO.Available {
		ev.PSIIOSomeAvg10 = m.Pressure.IO.Some.Avg10
		ev.PSIIOFullAvg10 = m.Pressure.IO.Full.Avg10
	}
	if m.LoadAvg.NumCPU > 0 {
		ev.LoadNormalised = round2(m.LoadAvg.Load1 / float64(m.LoadAvg.NumCPU))
	}
	if m.DState.Available {
		ev.DStateLongestMs = m.DState.LongestMs
		if len(m.DState.Tasks) > 0 {
			ev.TopBlockedComm = m.DState.Tasks[0].Comm
			ev.TopBlockedWchan = m.DState.Tasks[0].Wchan
		}
	}

	// Pick the device carrying the most traffic; ties broken by utilisation so
	// an idle-but-stalled device still surfaces.
	var best *model.DiskMetrics
	var bestScore float64
	for i := range m.Disk {
		dk := &m.Disk[i]
		score := dk.ReadBytesPerSec + dk.WriteBytesPerSec
		if best == nil || score > bestScore ||
			(score == bestScore && dk.IOUtilPercent > best.IOUtilPercent) {
			best, bestScore = dk, score
		}
	}
	if best != nil {
		ev.BusiestDevice = best.Device
		ev.DeviceUtilPct = round2(best.IOUtilPercent)
		ev.DeviceMBPerSec = round2((best.ReadBytesPerSec + best.WriteBytesPerSec) / (1024 * 1024))
		ev.DeviceAvgWaitMs = round2(best.AvgWaitMs)
		ev.DeviceInFlight = best.InFlight
	}
	return ev
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// matchesStoragePath reports whether a wchan symbol or joined stack places the
// task inside the storage / writeback path.
func matchesStoragePath(s string) bool {
	if s == "" {
		return false
	}
	l := strings.ToLower(s)
	for _, w := range storagePathWchans {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func describeBlocked(c model.DStateCensus, stallMs int64) string {
	if !c.Available {
		return "D-state census disabled"
	}
	if c.Count == 0 {
		return "no tasks in uninterruptible sleep"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d task(s) in D state, longest %dms", c.Count, c.LongestMs)
	if c.LongestMs >= stallMs {
		b.WriteString(" (STALL)")
	}
	shown := 0
	for _, t := range c.Tasks {
		if shown >= 3 {
			break
		}
		kind := ""
		if t.KernelThread {
			kind = " [kthread]"
		}
		fmt.Fprintf(&b, "; %s(%d)%s", t.Comm, t.PID, kind)
		if t.Wchan != "" {
			fmt.Fprintf(&b, " wchan=%s", t.Wchan)
		}
		fmt.Fprintf(&b, " %dms", t.InDStateMs)
		shown++
	}
	return b.String()
}

// confidence downgrades when links of the chain are missing.
func confidence(psiConfirms, haveStacks, psiAvailable bool) model.IOConfidence {
	switch {
	case psiConfirms && haveStacks:
		return model.ConfidenceHigh
	case haveStacks || psiConfirms:
		return model.ConfidenceMedium
	case !psiAvailable:
		return model.ConfidenceLow
	default:
		return model.ConfidenceMedium
	}
}

func psiNote(available bool) string {
	if available {
		return ""
	}
	return " (PSI unavailable)"
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

// tail returns the last n elements — the innermost frames, which name the wait.
func tail(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
