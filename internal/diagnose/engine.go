// Package diagnose is the root-cause correlation engine.
//
// It turns a model.DiagnoseReport — the raw, aggregated evidence already
// gathered by the collector, process inspector, eBPF manager, and the
// always-on tracers — into a single model.Diagnosis: which resource is under
// pressure, which process is responsible, what activity drives it, whether the
// behavior is normal/inefficient/misconfiguration/bottleneck/application-bug,
// and a root-cause hypothesis with remediation hints.
//
// The engine is a pure function. It performs no I/O, starts no goroutines, and
// holds no state, so it adds zero background CPU/RAM and no kernel overhead — it
// runs synchronously once per /api/diagnose request over data already in memory.
package diagnose

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Thresholds mirror internal/trigger/engine.go so the diagnosis is consistent
// with the conditions that activated the on-demand eBPF deep-dive modules.
const (
	cpuThreshold    = 85.0 // % total CPU
	iowaitThreshold = 20.0 // % iowait
	memThreshold    = 85.0 // % memory used
	loadNormalised  = 1.5  // load1 / numCPU
	diskUtilBusy    = 80.0 // % device utilisation
	swapActive      = 10.0 // % swap used
)

// Severity weights used for ranking findings and labelling the diagnosis.
const (
	sevInfo     = 1
	sevWarning  = 2
	sevCritical = 3
)

// scoredFinding pairs a public Finding with an internal severity used only for
// ranking and for setting the top-level Diagnosis.Severity.
type scoredFinding struct {
	f   model.Finding
	sev int
}

// rule inspects the report and returns at most one finding (nil = not firing).
type rule func(r *model.DiagnoseReport) *scoredFinding

// Analyze correlates every section of a DiagnoseReport into a single Diagnosis.
// It never returns nil: when no pressure is detected the result has
// Severity=="normal" and an empty findings list.
func Analyze(r *model.DiagnoseReport) *model.Diagnosis {
	d := &model.Diagnosis{
		Type:            "rca",
		Timestamp:       time.Now(),
		PrimaryResource: "none",
		Severity:        severityString(0),
		Summary:         "no performance degradation detected",
		Findings:        []model.Finding{},
	}
	if r == nil {
		return d
	}

	rules := []rule{cpuRule, diskRule, memoryRule, schedulerRule, networkRule}

	scored := make([]scoredFinding, 0, len(rules))
	for _, rl := range rules {
		if sf := rl(r); sf != nil {
			scored = append(scored, *sf)
		}
	}
	if len(scored) == 0 {
		return d
	}

	// Rank by severity, then confidence (both descending).
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].sev != scored[j].sev {
			return scored[i].sev > scored[j].sev
		}
		return scored[i].f.Confidence > scored[j].f.Confidence
	})

	d.Findings = make([]model.Finding, len(scored))
	for i := range scored {
		d.Findings[i] = scored[i].f
	}

	top := scored[0]
	d.Severity = severityString(top.sev)
	d.PrimaryResource = top.f.Resource
	d.Summary = top.f.Explanation
	d.RootCause = &model.RootCauseHypothesis{
		Statement:       top.f.Explanation,
		Resource:        top.f.Resource,
		Process:         top.f.Process,
		Confidence:      top.f.Confidence,
		Recommendations: recommendations(top.f),
	}
	return d
}

// ─── CPU ──────────────────────────────────────────────────────────────────────

func cpuRule(r *model.DiagnoseReport) *scoredFinding {
	cpu := r.Metrics.CPU
	if cpu.UsagePercent <= cpuThreshold {
		return nil
	}

	sev := sevWarning
	if cpu.UsagePercent >= 95 {
		sev = sevCritical
	}

	evidence := []string{
		fmt.Sprintf("cpu.usage_percent=%.1f (user=%.1f sys=%.1f iowait=%.1f steal=%.1f)",
			cpu.UsagePercent, cpu.UserPercent, cpu.SysPercent, cpu.IOWaitPercent, cpu.StealPercent),
	}

	kernelBound := cpu.SysPercent > cpu.UserPercent
	activity := "cpu_bound"
	behavior := "inefficient"
	confidence := 0.6

	var culprit *model.Culprit
	var hotDetail string

	// Prefer the eBPF CPU profile (sampled on-CPU time) when present: it is the
	// strongest attribution and can name the hot functions.
	if rep := r.CPUProfileReport; rep != nil && len(rep.Processes) > 0 && rep.System.TotalSamples > 0 {
		hp := rep.Processes[0]
		share := float64(hp.Samples) / float64(rep.System.TotalSamples) * 100
		culprit = enrich(r, &model.Culprit{PID: hp.PID, Comm: hp.Comm})
		evidence = append(evidence,
			fmt.Sprintf("cpu_profile: pid=%d comm=%s holds %.0f%% of %d on-CPU samples (user=%d kernel=%d)",
				hp.PID, hp.Comm, share, rep.System.TotalSamples, hp.UserSamples, hp.KernelSamples))
		kernelBound = hp.KernelSamples > hp.UserSamples
		if kernelBound && len(hp.TopKernStacks) > 0 {
			hotDetail = fmt.Sprintf(" eBPF profiling attributes the hottest kernel path to %s.", stackSummary(hp.TopKernStacks[0].SymbolStack))
		} else if len(hp.TopUserStacks) > 0 {
			hotDetail = fmt.Sprintf(" eBPF profiling attributes the hottest user-space path to %s.", stackSummary(hp.TopUserStacks[0].SymbolStack))
		}
		if share >= 50 {
			confidence = 0.9
		} else {
			confidence = 0.75
		}
	} else if p := topByCPU(r.TopProcesses); p != nil {
		culprit = procToCulprit(p)
		evidence = append(evidence, fmt.Sprintf("top process: pid=%d comm=%s cpu=%.1f%% state=%s",
			p.PID, p.Comm, p.CPUPercent, p.State))
		if p.CPUPercent >= 60 {
			confidence = 0.75
		} else {
			confidence = 0.6
		}
	}

	if kernelBound {
		activity = "syscall_bound"
	}

	boundDesc := "application-bound (user-space)"
	if kernelBound {
		boundDesc = "kernel-bound (system/syscall time)"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "CPU usage reached %.1f%%.", cpu.UsagePercent)
	if culprit != nil {
		fmt.Fprintf(&sb, " Process %s (PID %d) is the dominant consumer.", culprit.Comm, culprit.PID)
	}
	sb.WriteString(hotDetail)
	fmt.Fprintf(&sb, " The workload appears %s.", boundDesc)

	return &scoredFinding{
		sev: sev,
		f: model.Finding{
			Resource:    "cpu",
			Process:     culprit,
			Activity:    activity,
			Behavior:    behavior,
			Explanation: sb.String(),
			Evidence:    evidence,
			Confidence:  confidence,
		},
	}
}

// ─── Disk / IO ──────────────────────────────────────────────────────────────

func diskRule(r *model.DiagnoseReport) *scoredFinding {
	cpu := r.Metrics.CPU
	busiest := busiestDisk(r.Metrics.Disk)
	iowaitHigh := cpu.IOWaitPercent > iowaitThreshold
	diskBusy := busiest != nil && busiest.IOUtilPercent > diskUtilBusy
	if !iowaitHigh && !diskBusy {
		return nil
	}

	sev := sevWarning
	if cpu.IOWaitPercent >= 40 || (busiest != nil && busiest.IOUtilPercent >= 95) {
		sev = sevCritical
	}

	evidence := []string{
		fmt.Sprintf("cpu.iowait_percent=%.1f, blocked_procs=%d", cpu.IOWaitPercent, cpu.BlockedProcs),
	}
	if busiest != nil {
		evidence = append(evidence, fmt.Sprintf("device %s: util=%.1f%% avg_wait=%.2fms write=%.0fB/s read=%.0fB/s",
			busiest.Device, busiest.IOUtilPercent, busiest.AvgWaitMs, busiest.WriteBytesPerSec, busiest.ReadBytesPerSec))
	}

	activity := "disk_write_pressure"
	behavior := "bottleneck"
	confidence := 0.55
	var culprit *model.Culprit
	var who string

	switch {
	case r.FsyncReport != nil && len(r.FsyncReport.TopOffenders) > 0:
		// fsync is the most precise per-process disk attribution we have.
		o := r.FsyncReport.TopOffenders[0]
		culprit = enrich(r, &model.Culprit{PID: o.PID, Comm: o.Comm, Cmdline: o.Cmdline, CgroupPath: o.CgroupPath, AppType: o.AppType})
		activity = "excessive_fsync"
		who = fmt.Sprintf("Process %s (PID %d) issued %d fsync calls (avg %.1fms, max %.1fms)",
			o.Comm, o.PID, o.FsyncCalls, o.AvgLatencyMs, o.MaxLatencyMs)
		evidence = append(evidence, who+".")
		// Slow individual fsyncs point at the device; fast-but-frequent points
		// at the application.
		if o.MaxLatencyMs >= 10 {
			behavior = "bottleneck"
		} else {
			behavior = "inefficient"
		}
		confidence = 0.85
	case r.DiskReport != nil && len(r.DiskReport.TopWriters) > 0:
		tw := r.DiskReport.TopWriters[0]
		culprit = enrich(r, &model.Culprit{PID: tw.PID, Comm: tw.Comm})
		who = fmt.Sprintf("Process %s (PID %d) wrote %s", tw.Comm, tw.PID, humanBytes(tw.BytesWritten))
		if tw.LastFilename != "" {
			who += " (last file: " + tw.LastFilename + ")"
		}
		evidence = append(evidence, who+".")
		confidence = 0.75
	default:
		if p := topByWrite(r.TopProcesses); p != nil {
			culprit = procToCulprit(p)
			who = fmt.Sprintf("Process %s (PID %d) write=%.0fB/s read=%.0fB/s state=%s",
				p.Comm, p.PID, p.WriteBytesPerSec, p.ReadBytesPerSec, p.State)
			evidence = append(evidence, who+".")
			confidence = 0.6
		}
	}

	// Fold in io_latency outliers if the module sampled any.
	if n, maxUs, comm := scanIOLatency(r.RecentEvents); n > 0 {
		evidence = append(evidence, fmt.Sprintf("io_latency: %d slow block IOs sampled, worst %.1fms (%s)",
			n, float64(maxUs)/1000, comm))
		if confidence < 0.8 {
			confidence += 0.05
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Disk is under pressure (iowait %.1f%%", cpu.IOWaitPercent)
	if busiest != nil {
		fmt.Fprintf(&sb, ", %s util %.0f%%, avg wait %.1fms", busiest.Device, busiest.IOUtilPercent, busiest.AvgWaitMs)
	}
	sb.WriteString("). ")
	if who != "" {
		sb.WriteString(who)
		sb.WriteString(". ")
	}
	if cpu.BlockedProcs > 0 {
		fmt.Fprintf(&sb, "%d process(es) are blocked in uninterruptible (D) state waiting on IO.", cpu.BlockedProcs)
	}

	return &scoredFinding{
		sev: sev,
		f: model.Finding{
			Resource:    "disk",
			Process:     culprit,
			Activity:    activity,
			Behavior:    behavior,
			Explanation: strings.TrimSpace(sb.String()),
			Evidence:    evidence,
			Confidence:  confidence,
		},
	}
}

// ─── Memory ───────────────────────────────────────────────────────────────────

func memoryRule(r *model.DiagnoseReport) *scoredFinding {
	mem := r.Metrics.Memory
	memHigh := mem.UsagePercent > memThreshold
	swapping := mem.SwapTotalBytes > 0 && mem.SwapPercent > swapActive
	if !memHigh && !swapping {
		return nil
	}

	sev := sevWarning
	if mem.UsagePercent >= 95 || mem.SwapPercent >= 50 {
		sev = sevCritical
	}

	activity := "memory_pressure"
	if swapping {
		activity = "swapping"
	}

	evidence := []string{
		fmt.Sprintf("mem.usage_percent=%.1f, available=%s, swap_percent=%.1f",
			mem.UsagePercent, humanBytes(mem.AvailableBytes), mem.SwapPercent),
	}

	confidence := 0.6
	var culprit *model.Culprit
	var who string
	if p := topByRSS(r.TopProcesses); p != nil {
		culprit = procToCulprit(p)
		who = fmt.Sprintf("Process %s (PID %d) holds the largest resident set: %s (%.1f%% of RAM)",
			p.Comm, p.PID, humanBytes(p.MemRSSBytes), p.MemPercent)
		evidence = append(evidence, who+".")
		confidence = 0.7
	}

	// Direct-reclaim stalls confirm the kernel is struggling to free memory.
	if wb := r.WritebackReport; wb != nil && len(wb.TopOffenders) > 0 {
		o := wb.TopOffenders[0]
		evidence = append(evidence, fmt.Sprintf("writeback: pid=%d comm=%s reclaim_count=%d max_reclaim=%.1fms",
			o.PID, o.Comm, o.ReclaimCount, o.MaxReclaimMs))
		confidence = maxF(confidence, 0.8)
	}

	var sb strings.Builder
	if swapping {
		fmt.Fprintf(&sb, "Memory pressure is forcing swap (%.1f%% used, %.1f%% RAM used). ", mem.SwapPercent, mem.UsagePercent)
	} else {
		fmt.Fprintf(&sb, "Memory usage reached %.1f%% (%s available). ", mem.UsagePercent, humanBytes(mem.AvailableBytes))
	}
	if who != "" {
		sb.WriteString(who)
		sb.WriteString(".")
	}

	return &scoredFinding{
		sev: sev,
		f: model.Finding{
			Resource:    "memory",
			Process:     culprit,
			Activity:    activity,
			Behavior:    "bottleneck",
			Explanation: strings.TrimSpace(sb.String()),
			Evidence:    evidence,
			Confidence:  confidence,
		},
	}
}

// ─── Scheduler ─────────────────────────────────────────────────────────────────

func schedulerRule(r *model.DiagnoseReport) *scoredFinding {
	load := r.Metrics.LoadAvg
	ncpu := load.NumCPU
	if ncpu <= 0 {
		ncpu = 1
	}
	norm := load.Load1 / float64(ncpu)
	if norm <= loadNormalised {
		return nil
	}
	cpu := r.Metrics.CPU

	sev := sevWarning
	if norm >= 4 {
		sev = sevCritical
	}

	evidence := []string{
		fmt.Sprintf("load1=%.2f over %d CPUs (normalised=%.2f), cpu_usage=%.1f%%, running=%d blocked=%d",
			load.Load1, ncpu, norm, cpu.UsagePercent, cpu.RunningProcs, cpu.BlockedProcs),
	}

	// High load with low CPU = tasks waiting (run-queue or D-state), not burning
	// cycles. High load with high CPU + scheduler latency = oversubscription /
	// context-switch thrash.
	activity := "runqueue_saturation"
	behavior := "bottleneck"
	confidence := 0.55
	if cpu.UsagePercent >= 50 {
		activity = "ctx_switch_thrash"
		behavior = "inefficient"
	}

	if n, maxUs, comm := scanRunQLat(r.RecentEvents); n > 0 {
		evidence = append(evidence, fmt.Sprintf("runqlat: %d scheduling delays sampled, worst %.1fms (%s)",
			n, float64(maxUs)/1000, comm))
		confidence = maxF(confidence, 0.75)
	}

	var culprit *model.Culprit
	if p := topByCPU(r.TopProcesses); p != nil && cpu.UsagePercent >= 50 {
		culprit = procToCulprit(p)
	}

	expl := fmt.Sprintf("Run-queue is saturated: load %.2f on %d CPUs (%.1fx). ", load.Load1, ncpu, norm)
	if cpu.UsagePercent < 50 {
		expl += fmt.Sprintf("CPU is only %.1f%% busy, so the backlog is from tasks blocked off-CPU (IO/lock wait), not compute.", cpu.UsagePercent)
	} else {
		expl += fmt.Sprintf("CPU is %.1f%% busy with more runnable tasks than cores — the system is oversubscribed.", cpu.UsagePercent)
	}

	return &scoredFinding{
		sev: sev,
		f: model.Finding{
			Resource:    "scheduler",
			Process:     culprit,
			Activity:    activity,
			Behavior:    behavior,
			Explanation: expl,
			Evidence:    evidence,
			Confidence:  confidence,
		},
	}
}

// ─── Network ──────────────────────────────────────────────────────────────────

func networkRule(r *model.DiagnoseReport) *scoredFinding {
	n, maxLoss, sample := scanRetransmits(r.RecentEvents)
	drops := scanDrops(r.RecentEvents)
	if n == 0 && drops == 0 {
		return nil
	}

	sev := sevWarning
	if maxLoss >= 5 {
		sev = sevCritical
	}

	evidence := []string{
		fmt.Sprintf("tcp_retransmit events=%d (max loss_rate=%.2f%%), tcp_drop events=%d", n, maxLoss, drops),
	}

	var culprit *model.Culprit
	var flowDesc string
	if sample != nil {
		culprit = enrich(r, &model.Culprit{PID: sample.PID, Comm: sample.Comm})
		flowDesc = fmt.Sprintf("%s → %s:%d", sample.Flow, sample.DstIP, sample.DstPort)
		evidence = append(evidence, fmt.Sprintf("worst flow: %s state=%s rtt=%.1fms cwnd=%d retransmits=%d",
			sample.Flow, sample.TCPState, float64(sample.RTTUS)/1000, sample.SndCwnd, sample.RetransmitCount))
	}

	expl := "Network path is lossy: TCP retransmissions detected"
	if sample != nil {
		expl += fmt.Sprintf(" on flow %s (process %s, PID %d), peak loss rate %.2f%%",
			flowDesc, sample.Comm, sample.PID, maxLoss)
	}
	expl += ". This indicates congestion, packet loss, or an unhealthy backend link rather than local resource exhaustion."

	confidence := 0.7
	if maxLoss >= 5 {
		confidence = 0.85
	}

	return &scoredFinding{
		sev: sev,
		f: model.Finding{
			Resource:    "network",
			Process:     culprit,
			Activity:    "tcp_retransmits",
			Behavior:    "bottleneck",
			Explanation: expl,
			Evidence:    evidence,
			Confidence:  confidence,
		},
	}
}

// ─── Event scanners ─────────────────────────────────────────────────────────

func scanIOLatency(evs []model.EBPFEvent) (count int, maxUs uint64, comm string) {
	for _, e := range evs {
		if d, ok := e.Data.(model.IOLatencyEvent); ok {
			count++
			if d.LatencyUs > maxUs {
				maxUs, comm = d.LatencyUs, d.Comm
			}
		}
	}
	return
}

func scanRunQLat(evs []model.EBPFEvent) (count int, maxUs uint64, comm string) {
	for _, e := range evs {
		if d, ok := e.Data.(model.RunQLatEvent); ok {
			count++
			if d.LatencyUs > maxUs {
				maxUs, comm = d.LatencyUs, d.Comm
			}
		}
	}
	return
}

func scanRetransmits(evs []model.EBPFEvent) (count int, maxLoss float64, worst *model.TCPRetransmitEvent) {
	for i := range evs {
		if d, ok := evs[i].Data.(model.TCPRetransmitEvent); ok {
			count++
			if worst == nil || d.LossRate > maxLoss {
				maxLoss = d.LossRate
				dd := d
				worst = &dd
			}
		}
	}
	return
}

func scanDrops(evs []model.EBPFEvent) (count int) {
	for _, e := range evs {
		if _, ok := e.Data.(model.TCPDropEvent); ok {
			count++
		}
	}
	return
}

// ─── Process selection helpers ──────────────────────────────────────────────

func topByCPU(ps []model.ProcessStats) *model.ProcessStats {
	return pick(ps, func(p model.ProcessStats) float64 { return p.CPUPercent })
}

func topByRSS(ps []model.ProcessStats) *model.ProcessStats {
	return pick(ps, func(p model.ProcessStats) float64 { return float64(p.MemRSSBytes) })
}

func topByWrite(ps []model.ProcessStats) *model.ProcessStats {
	return pick(ps, func(p model.ProcessStats) float64 { return p.WriteBytesPerSec + p.ReadBytesPerSec })
}

func pick(ps []model.ProcessStats, score func(model.ProcessStats) float64) *model.ProcessStats {
	var best *model.ProcessStats
	var bestScore float64
	for i := range ps {
		s := score(ps[i])
		if best == nil || s > bestScore {
			best, bestScore = &ps[i], s
		}
	}
	if best != nil && bestScore <= 0 {
		return nil
	}
	return best
}

func busiestDisk(disks []model.DiskMetrics) *model.DiskMetrics {
	var best *model.DiskMetrics
	for i := range disks {
		if best == nil || disks[i].IOUtilPercent > best.IOUtilPercent {
			best = &disks[i]
		}
	}
	return best
}

// ─── Culprit construction ─────────────────────────────────────────────────────

func procToCulprit(p *model.ProcessStats) *model.Culprit {
	if p == nil {
		return nil
	}
	return &model.Culprit{
		PID:        p.PID,
		PPID:       p.PPID,
		Comm:       p.Comm,
		Cmdline:    p.Cmdline,
		CgroupPath: p.CgroupPath,
		AppType:    classifyApp(p.Comm, p.Cmdline),
	}
}

// enrich fills missing fields of a Culprit (built from an eBPF event that only
// carries pid+comm) by cross-referencing the /proc TopProcesses snapshot.
func enrich(r *model.DiagnoseReport, c *model.Culprit) *model.Culprit {
	if c == nil {
		return nil
	}
	for i := range r.TopProcesses {
		if r.TopProcesses[i].PID == c.PID {
			p := &r.TopProcesses[i]
			if c.PPID == 0 {
				c.PPID = p.PPID
			}
			if c.Cmdline == "" {
				c.Cmdline = p.Cmdline
			}
			if c.CgroupPath == "" {
				c.CgroupPath = p.CgroupPath
			}
			break
		}
	}
	if c.AppType == "" {
		c.AppType = classifyApp(c.Comm, c.Cmdline)
	}
	return c
}

// ─── Workload classification ──────────────────────────────────────────────────

// knownApps maps a substring of comm/cmdline to a workload class. Mirrors the
// classifier in internal/fsync; kept local so the diagnose engine has no
// dependency on the tracer packages.
var knownApps = []struct {
	substr  string
	appType string
}{
	{"mongod", "database"}, {"mongos", "database"}, {"cassandra", "database"},
	{"redis", "database"}, {"mysqld", "database"}, {"postgres", "database"},
	{"postmaster", "database"}, {"etcd", "database"},
	{"loki", "log_agent"}, {"promtail", "log_agent"}, {"filebeat", "log_agent"},
	{"fluentd", "log_agent"}, {"fluent-bit", "log_agent"}, {"logstash", "log_agent"},
	{"vector", "log_agent"},
	{"kafka", "messaging"}, {"rabbitmq", "messaging"}, {"nats", "messaging"},
	{"clamd", "antivirus"}, {"clamav", "antivirus"}, {"falcon", "antivirus"},
	{"crowdstrike", "antivirus"}, {"carbonblack", "antivirus"}, {"eset", "antivirus"},
}

func classifyApp(comm, cmdline string) string {
	haystack := strings.ToLower(comm + " " + cmdline)
	for _, k := range knownApps {
		if strings.Contains(haystack, k.substr) {
			return k.appType
		}
	}
	return ""
}

// ─── Recommendations ──────────────────────────────────────────────────────────

func recommendations(f model.Finding) []string {
	switch f.Activity {
	case "cpu_bound":
		return []string{
			"Profile the dominant process; the cpu_profile_report names the hottest user-space functions.",
			"If a single process is pegged, check for hot loops, missing caching, or serialization overhead.",
		}
	case "syscall_bound":
		return []string{
			"High kernel CPU: inspect the hottest kernel stacks in cpu_profile_report (locking, memory, IO paths).",
			"Reduce syscall volume (batch IO, larger buffers) or investigate lock contention.",
		}
	case "excessive_fsync":
		return []string{
			"Identify why the process fsyncs so often; batch or relax durability if the workload allows.",
			"If max fsync latency is high, the backing device is the bottleneck — check disk health/IO scheduler.",
		}
	case "disk_write_pressure":
		return []string{
			"Throttle or relocate the heavy writer; verify the target filesystem/device is not saturated.",
		}
	case "memory_pressure", "swapping":
		return []string{
			"Cap the largest process's memory (cgroup limit) or add RAM.",
			"If swapping, reduce working set or disable swap for latency-sensitive workloads.",
		}
	case "runqueue_saturation":
		return []string{
			"Load exceeds CPU count with tasks blocked off-CPU — investigate IO/lock waits (see disk/runqlat).",
		}
	case "ctx_switch_thrash":
		return []string{
			"Reduce thread/goroutine oversubscription; pin or limit concurrency to the core count.",
		}
	case "tcp_retransmits":
		return []string{
			"Inspect the affected flow's destination/backend; check for network congestion or packet loss.",
		}
	}
	return nil
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

func severityString(sev int) string {
	switch sev {
	case sevCritical:
		return "critical"
	case sevWarning:
		return "warning"
	case sevInfo:
		return "info"
	default:
		return "normal"
	}
}

// stackSummary renders the innermost few frames of a symbol stack.
func stackSummary(symbols []string) string {
	if len(symbols) == 0 {
		return "unknown"
	}
	n := len(symbols)
	if n > 3 {
		n = 3
	}
	return strings.Join(symbols[:n], " ← ")
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
