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
	// PSI is AUTHORITATIVE: io.full measures time in which no task could make
	// progress. When it is high the machine is genuinely stalling, and no
	// combination of "device looks idle" or "load is low" may override it.
	psiSaysStalling := ev.PSIAvailable && ev.PSIIOFullAvg10 >= t.PSIFullAvg10
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
		Confirmed: ev.DStateCount > 0 || ev.DStateBlockedSamplePct > 0,
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
	//
	// Note the ordering: the PSI-driven cases come first so that a genuine
	// stall can never fall through to the "accounting artifact" branch.
	// Constant short blocking: most sub-samples caught something in D even
	// though no single block was long. Typical of a synchronous userspace hook
	// rather than a slow device.
	constantBlocking := ev.DStateBlockedSamplePct >= 50.0

	switch {
	// Work genuinely could not proceed, but the block device is doing nothing.
	// The wait is therefore not block I/O — look at fanotify hooks, network
	// filesystems, or throttling.
	case psiSaysStalling && deviceIdle && lowThroughput:
		d.Verdict = model.VerdictStallWithoutDeviceIO
		d.Confidence = confidence(true, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = stallWithoutDeviceSummary(ev, constantBlocking)
		d.NextSteps = stallWithoutDeviceNextSteps(ev)

	// The rule this package was built for: high iowait, device NOT moving
	// data, tasks stuck for a long time in the storage path. The device is
	// slow, not busy — adding IOPS capacity will not help.
	// Two independent routes to this verdict: the D-state + stack evidence
	// (longStall && inStorage), or the device demonstrably serving each
	// request slowly while barely moving data (slowDevice). Either alone is
	// sufficient; the confidence field records how much corroboration there was.
	case ev.IOWaitPercent >= t.IOWaitPercent && lowThroughput && ((longStall && inStorage) || slowDevice):
		d.Verdict = model.VerdictStorageLatencyStall
		d.Confidence = confidence(psiSaysStalling, offcpuReport != nil, ev.PSIAvailable)
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
		d.Confidence = confidence(psiSaysStalling, offcpuReport != nil, ev.PSIAvailable)
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
		d.Confidence = confidence(psiSaysStalling, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = fmt.Sprintf(
			"Device saturated: %s at %.1f%% util moving %.2f MB/s (avg wait %.2f ms). This is a capacity limit, not a latency fault.",
			orNA(ev.BusiestDevice), ev.DeviceUtilPct, ev.DeviceMBPerSec, ev.DeviceAvgWaitMs)
		d.NextSteps = []string{
			"Reduce I/O demand or provision faster/more storage.",
			"Identify the heaviest writer via /api/diagnose .disk_report.top_writers.",
		}

	// High iowait but nothing is actually stalled — the dragonfly/io_uring
	// case. Idle CPU time relabelled because a task sits parked in D state.
	// Genuinely nothing wrong. Requires PSI to agree, OR (when PSI is
	// unavailable) every other signal to be quiet. Never reached while
	// io.full is meaningful.
	case !psiSaysStalling && deviceIdle && lowThroughput && !longStall && !constantBlocking &&
		(noStall || (!ev.PSIAvailable && ev.LoadNormalised < 1.0 && ev.DeviceInFlight == 0)):
		d.Verdict = model.VerdictIOWaitAccountingArtifact
		d.Confidence = confidence(false, offcpuReport != nil, ev.PSIAvailable)
		d.Summary = fmt.Sprintf(
			"iowait %.1f%% is an accounting artifact, NOT an I/O problem: PSI io.full is only %.1f%% "+
				"(nothing was actually prevented from running), %s is idle (%.1f%% util, %.2f MB/s), "+
				"load/cpu is %.2f and nothing blocked longer than %dms.",
			ev.IOWaitPercent, ev.PSIIOFullAvg10, orNA(ev.BusiestDevice), ev.DeviceUtilPct,
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
		IOWaitPercent:          m.CPU.IOWaitPercent,
		IdlePercent:            m.CPU.IdlePercent,
		BlockedProcs:           m.CPU.BlockedProcs,
		PSIAvailable:           m.Pressure.IO.Available,
		DirtyBytes:             m.VMStat.DirtyBytes,
		WritebackBytes:         m.VMStat.WritebackBytes,
		DirtyRatioPct:          m.VMStat.DirtyRatioPercent,
		DStateCount:            m.DState.Count,
		DStateBlockedSamplePct: m.DState.BlockedSamplePercent,
		BlockingFanotify:       m.BlockingHooks.BlockingCount,
	}
	if len(m.BlockingHooks.Fanotify) > 0 {
		for _, h := range m.BlockingHooks.Fanotify {
			if h.Blocking {
				ev.BlockingHookComm = h.Comm
				ev.BlockingHookPID = h.PID
				break
			}
		}
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
	if c.PeakCount == 0 {
		if c.Samples > 0 {
			return fmt.Sprintf("no tasks in uninterruptible sleep across %d sub-samples (%dms apart)",
				c.Samples, c.SubSampledMs)
		}
		return "no tasks in uninterruptible sleep"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "peak %d task(s) in D, blocked in %.0f%% of %d sub-samples, longest %dms",
		c.PeakCount, c.BlockedSamplePercent, c.Samples, c.LongestMs)
	if c.LongestMs >= stallMs {
		b.WriteString(" (LONG STALL)")
	} else if c.BlockedSamplePercent >= 50 {
		b.WriteString(" (CONSTANT SHORT BLOCKING)")
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
		fmt.Fprintf(&b, "; %s(tid %d, pid %d)%s", t.Comm, t.TID, t.PID, kind)
		if t.Wchan != "" {
			fmt.Fprintf(&b, " wchan=%s", t.Wchan)
		}
		fmt.Fprintf(&b, " %dms/%.0f%%", t.InDStateMs, t.ObservedPercent)
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

// stallWithoutDeviceSummary explains a genuine stall that the block device
// cannot account for.
func stallWithoutDeviceSummary(ev model.IOEvidence, constantBlocking bool) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"REAL stall, but NOT block I/O: PSI io.full is %.1f%% (work genuinely could not proceed) "+
			"while %s is idle — %.1f%% util, %.2f MB/s, in-flight %d.",
		ev.PSIIOFullAvg10, orNA(ev.BusiestDevice), ev.DeviceUtilPct,
		ev.DeviceMBPerSec, ev.DeviceInFlight)

	if ev.BlockingFanotify > 0 {
		fmt.Fprintf(&b,
			" Most likely cause: %s (pid %d) holds a fanotify descriptor in PERMISSION mode — "+
				"every file access waits for its verdict in D state, producing iowait with no disk traffic.",
			orNA(ev.BlockingHookComm), ev.BlockingHookPID)
	} else if constantBlocking {
		fmt.Fprintf(&b,
			" Something was blocked in %.0f%% of sub-samples yet the longest single block was only %dms — "+
				"constant SHORT blocking, which points at a synchronous hook rather than a slow device.",
			ev.DStateBlockedSamplePct, ev.DStateLongestMs)
	}
	if ev.TopBlockedWchan != "" {
		fmt.Fprintf(&b, " Longest blocked task: %s waiting in %s.",
			orNA(ev.TopBlockedComm), ev.TopBlockedWchan)
	}
	return b.String()
}

// stallWithoutDeviceNextSteps orders the candidate causes by how often each
// turns out to be the answer, and names the concrete check for each.
func stallWithoutDeviceNextSteps(ev model.IOEvidence) []string {
	steps := make([]string, 0, 5)

	if ev.BlockingFanotify > 0 {
		steps = append(steps,
			fmt.Sprintf("PRIMARY SUSPECT: %s (pid %d) is intercepting file access via fanotify permission events. "+
				"Confirm with: cat /proc/%d/fdinfo/* | grep fanotify",
				orNA(ev.BlockingHookComm), ev.BlockingHookPID, ev.BlockingHookPID),
			"If it is an on-access antivirus scanner, exclude the hot data directories from real-time scanning "+
				"(for a database this is usually its entire data dir) and re-measure.")
	} else {
		steps = append(steps,
			"Check for an on-access scanner or audit agent: grep -l fanotify /proc/*/fdinfo/* 2>/dev/null")
	}

	steps = append(steps,
		"Check for network/FUSE filesystems, whose latency never appears in /proc/diskstats: "+
			"findmnt -t nfs,nfs4,cifs,fuse.* ; and for cgroup throttling: cat /sys/fs/cgroup/**/io.max",
		"Attribute it precisely: GET /api/profile?pid=<pid>&mode=offcpu&format=folded — "+
			"the blocking stack names the exact wait.",
		"Alert on pressure.io.full.avg10 rather than cpu.iowait_percent; this condition is invisible to disk metrics.")
	return steps
}
