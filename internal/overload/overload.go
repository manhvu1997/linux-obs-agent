// Package overload decides which query pattern, if any, is overloading the
// node's CPU or its disk. Each resource is assessed separately and every check
// is reported so the verdict is auditable:
//
//	check               cpu                                     disk
//	node_saturated      window CPU used% or load/NumCPU over     io_diagnosis verdict is
//	                    threshold                               high_disk_throughput,
//	                                                            storage_latency_stall or
//	                                                            writeback_congestion
//	mysqld_top_consumer mysqld family is #1 by CPU              mysqld family is #1 by disk reads
//	dominant_digest     top digest by CPU has cpu_role culprit  top digest by disk reads has
//	                                                            io_role culprit
//	victims             digests whose largest wait is the run   digests whose largest wait is
//	                    queue (victim_of cpu)                   disk or commit (victim_of
//	                                                            disk / commit)
//
// A digest is a victim when its measured waits sum to >= victim_wait_percent
// of its time and it is slow; victim_of names the largest wait. Only waits
// measured in every poll of the window (mysql_report.accounting "ok") count:
// an unmeasured wait is listed in missing ("cpu_wait", "disk_wait",
// "commit_wait"), its count is omitted, and a query_*_overload verdict whose
// relevant waits are all unmeasured has confidence medium. Each assessment
// fills only its own resource's evidence and thresholds.
//
// The verdict is the saturated resource's assessment; when both are saturated
// a query_*_overload verdict beats any other, then the larger top-digest share
// (percent_of_node_cpu_used vs percent_of_disk_read) wins, and the other
// assessment is reported in secondary. With neither saturated the CPU
// assessment is the verdict.
//
// Node CPU comes from mysql_report.node, built from the same polls as the
// digests. Pure function over one diagnose call's inputs.
package overload

import (
	"fmt"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// Thresholds tune the node check. Zero values fall back to Defaults().
type Thresholds struct {
	NodeCPUPercent float64
	NodeLoad       float64
}

func Defaults() Thresholds { return Thresholds{NodeCPUPercent: 85, NodeLoad: 1.5} }

func (t Thresholds) withDefaults() Thresholds {
	d := Defaults()
	if t.NodeCPUPercent <= 0 {
		t.NodeCPUPercent = d.NodeCPUPercent
	}
	if t.NodeLoad <= 0 {
		t.NodeLoad = d.NodeLoad
	}
	return t
}

// Inputs are the signals of one diagnose call.
type Inputs struct {
	Metrics model.NodeMetrics
	MySQL   *model.MySQLAnalysis
	// Families: every process family by CPU desc; PIDFamilies: PID → family.
	// Both nil when the process inspector is unavailable.
	Families    []model.FamilyStats
	PIDFamilies map[uint32]string
	// IOVerdict is this call's io_diagnosis verdict; "" when there is none.
	IOVerdict model.IOVerdict
}

const (
	checkNode    = "node_saturated"
	checkDigest  = "dominant_digest"
	checkVictims = "victims"
	resourceCPU  = "cpu"
)

// Assess returns nil when there is no MySQL report to assess. The CPU and the
// disk are assessed separately; the verdict is the saturated one, and when
// both are saturated the one whose top digest has the larger share (a
// query_*_overload verdict wins over any other), the other in Secondary.
func Assess(in Inputs, th Thresholds, now time.Time) *model.QueryOverload {
	if in.MySQL == nil {
		return nil
	}
	return AssessEngine(MySQLEngine, fromMySQL(in.MySQL), in, th, 0, now)
}

func isOverload(v model.OverloadVerdict) bool {
	return v == model.OverloadQueryCPU || v == model.OverloadQueryDisk
}

// preferDisk: an overload verdict beats any other; otherwise the larger
// culprit share (cpu: percent_of_node_cpu_used, disk: percent_of_disk_read).
func preferDisk(cpu, disk *model.QueryOverload) bool {
	if isOverload(cpu.Verdict) != isOverload(disk.Verdict) {
		return isOverload(disk.Verdict)
	}
	return share(disk.Digest, true) > share(cpu.Digest, false)
}

func share(d *model.OverloadDigest, disk bool) float64 {
	switch {
	case d == nil:
		return -1
	case disk && d.PercentOfDiskRead != nil:
		return *d.PercentOfDiskRead
	case !disk && d.PercentOfNodeCPUUsed != nil:
		return *d.PercentOfNodeCPUUsed
	}
	return -1
}

// assessCPU assesses the CPU of one engine report.
func assessCPU(e Engine, my *Report, in Inputs, th Thresholds, bgPct float64, now time.Time) *model.QueryOverload {
	th = th.withDefaults()
	m := in.Metrics
	r := &model.QueryOverload{Type: "query_overload", Timestamp: now, Resource: resourceCPU, Cluster: my.Cluster,
		Thresholds: model.OverloadThresholds{NodeCPUPercent: th.NodeCPUPercent, NodeLoad: th.NodeLoad}}
	if t := my.Thresholds; t != nil {
		r.Thresholds.CPUCulpritPercentOfNodeCPUUsed = t.CPUCulpritPercentOfNodeCPUUsed
		r.Thresholds.CPUCulpritMinNodeCPUUsedPercent = t.CPUCulpritMinNodeCPUUsedPercent
	}
	if e.Background {
		r.Thresholds.BackgroundDominantPercent = bgPct
	}
	ev := &r.Evidence
	ev.WindowSeconds = my.WindowSeconds
	ev.QueryCPUCoveragePercent = my.QueryCPUCoveragePercent
	cpuWait := measure(my, querystats.AccountingKeyCPUWait, querystats.VictimCPU)
	if cpuWait.measured {
		ev.CPUVictims = intp(cpuWait.n)
	} else {
		r.Missing = append(r.Missing, querystats.AccountingKeyCPUWait)
	}
	psi := m.Pressure.CPU
	ev.PSIAvailable = &psi.Available
	if psi.Available {
		ev.PSICPUSomeAvg10 = floatp(psi.Some.Avg10)
	}
	var load float64
	if m.LoadAvg.NumCPU > 0 {
		load = m.LoadAvg.Load1 / float64(m.LoadAvg.NumCPU)
		ev.LoadNormalised = floatp(load)
	}
	var used float64
	if n := my.Node; n != nil {
		used = n.CPUUsedPercent
		ev.NodeCPUSource, ev.NodeCPUUsedCores, ev.NumCPU = "window", floatp(n.CPUUsedCores), n.NumCPU
	} else {
		used = m.CPU.UsagePercent
		ev.NodeCPUSource, ev.NumCPU = "sample", m.LoadAvg.NumCPU
		r.Missing = append(r.Missing, "node_cpu_window")
	}
	ev.NodeCPUUsedPercent = floatp(used)

	// 1. node
	nodeOK := used >= th.NodeCPUPercent || load >= th.NodeLoad
	nodeDetail := fmt.Sprintf("CPU used %.1f%% (%s; threshold %.0f%%), load/cpu %.2f (threshold %.2f)",
		used, nodeSourceText(ev, my.WindowSeconds), th.NodeCPUPercent, load, th.NodeLoad)
	if psi.Available {
		nodeDetail += fmt.Sprintf(", PSI cpu some %.1f%%", psi.Some.Avg10)
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkNode, Passed: nodeOK, Detail: nodeDetail})

	vc := cpuVictimsCheck(cpuWait)
	bgType, bgVal, bgTotal, bgOK := dominantBackground(e, my, false, bgPct)
	d, found := candidate(my.TopDigests)
	if !found {
		// PostgreSQL: autovacuum or checkpoints can saturate a node with no
		// statement running at all.
		if bgOK && nodeOK {
			if fam, famCPU, top, known := familyCPU(in, my.ServerPID); known && top.Family == fam {
				ev.TopFamily, ev.TopFamilyCPUPercent = top.Family, floatp(top.CPUPercent)
				e.SetCPUFamily(ev, fam, famCPU)
				r.Checks = append(r.Checks,
					model.OverloadCheck{Name: e.CheckProcess, Passed: true, Detail: fmt.Sprintf("%s (pid %d) family %s uses %.1f%% of node CPU; top family is %s at %.1f%%",
						e.Process, my.ServerPID, fam, famCPU, top.Family, top.CPUPercent)},
					model.OverloadCheck{Name: checkDigest, Detail: "no digest data"},
					vc)
				backgroundVerdict(e, r, saturatedText(used, load), fam, bgType, bgVal, bgTotal, false)
				return r
			}
		}
		r.Checks = append(r.Checks,
			model.OverloadCheck{Name: e.CheckProcess, Detail: "no digest data"},
			model.OverloadCheck{Name: checkDigest, Detail: "no digest data"},
			vc)
		r.Verdict, r.Confidence = model.OverloadNoData, model.ConfidenceLow
		r.Missing = append(r.Missing, "query_digests")
		r.Summary = "No query digest statistics in the window (" + e.NoDigestsHint + ")."
		return r
	}
	r.Digest = &model.OverloadDigest{PID: d.PID, DigestID: d.DigestID, DigestText: d.DigestText, Command: d.Command,
		CPUCores: floatp(d.CPUCores), PercentOfNodeCPUUsed: d.PercentOfNodeCPUUsed, CallsPerSec: d.CallsPerSec,
		BytesOutPerCall: d.BytesOutPerCall, CPURole: d.CPURole}

	// 2. process
	mysqldKnown, mysqldOK := false, false
	mysqldDetail := "process families unavailable"
	var engFam string
	var engFamCPU float64
	if fam, famCPU, top, known := familyCPU(in, d.PID); known {
		mysqldKnown = true
		engFam, engFamCPU = fam, famCPU
		ev.TopFamily, ev.TopFamilyCPUPercent = top.Family, floatp(top.CPUPercent)
		e.SetCPUFamily(ev, fam, famCPU)
		mysqldOK = top.Family == fam
		mysqldDetail = fmt.Sprintf("%s (pid %d) family %s uses %.1f%% of node CPU; top family is %s at %.1f%%",
			e.Process, d.PID, fam, famCPU, top.Family, top.CPUPercent)
	} else {
		r.Missing = append(r.Missing, "process_families")
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: e.CheckProcess, Passed: mysqldOK, Detail: mysqldDetail})

	// 3. query
	pct := pctText(d.PercentOfNodeCPUUsed)
	digestOK := d.CPURole == querystats.RoleCulprit
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkDigest, Passed: digestOK, Detail: fmt.Sprintf(
		"top digest %s did %s of all CPU work (%.2f cores); cpu_role %s (needs >= %.0f%% while the node is >= %.0f%% busy)",
		d.DigestID, pct, d.CPUCores, orNone(d.CPURole), r.Thresholds.CPUCulpritPercentOfNodeCPUUsed, r.Thresholds.CPUCulpritMinNodeCPUUsedPercent)})

	// 4. effect
	r.Checks = append(r.Checks, vc)

	switch {
	case !nodeOK:
		r.Verdict, r.Confidence = model.OverloadNodeNotSaturated, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("Node CPU is not saturated (%.1f%% used, load/cpu %.2f). The top digest did %s of the CPU work; it may dominate MySQL but does not overload the server.",
			used, load, pct)
	case mysqldKnown && !mysqldOK:
		r.Verdict, r.Confidence = e.NotEngine, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("%s but the top CPU family is %s (%.1f%%), not %s's %s (%.1f%%). Look at process_report.top_families_cpu.",
			saturatedText(used, load), ev.TopFamily, *ev.TopFamilyCPUPercent, e.Process, engFam, engFamCPU)
	case !digestOK && mysqldKnown && bgOK:
		backgroundVerdict(e, r, saturatedText(used, load), engFam, bgType, bgVal, bgTotal, false)
	case !digestOK:
		r.Verdict = model.OverloadNoDominantQuery
		// A culprit needs percent_of_node_cpu_used (so a node window) and the
		// node at least cpu_culprit_min_node_cpu_used_percent busy: when either
		// is missing "no dominant query" is true by construction, not evidence.
		minUsed := r.Thresholds.CPUCulpritMinNodeCPUUsedPercent
		switch {
		case d.PercentOfNodeCPUUsed == nil:
			r.Confidence = model.ConfidenceLow
			r.Summary = fmt.Sprintf("%s but the digests' share of node CPU is unavailable (%s.node missing for a poll in the window), so no digest can be judged a CPU culprit%s.",
				saturatedText(used, load), e.Report, coverageClause(e, ev.QueryCPUCoveragePercent))
		case used < minUsed:
			r.Confidence = model.ConfidenceLow
			if load >= th.NodeLoad {
				r.Summary = fmt.Sprintf("Node is saturated by load (load/cpu %.2f), not CPU (CPU used %.1f%%, below the %.0f%% a CPU culprit needs), so no query can be a CPU culprit. Check io_diagnosis for an I/O or D-state stall.",
					load, used, minUsed)
			} else {
				r.Summary = fmt.Sprintf("%s but CPU used is below the %.0f%% a CPU culprit needs, so no query can be a CPU culprit.",
					saturatedText(used, load), minUsed)
			}
		default:
			r.Confidence = model.ConfidenceHigh
			if !mysqldKnown {
				r.Confidence = model.ConfidenceLow
			}
			r.Summary = fmt.Sprintf("%s but no single digest dominates it: the top digest did %s of the CPU work. The load is spread over many queries or is outside query execution%s.",
				saturatedText(used, load), pct, coverageClause(e, ev.QueryCPUCoveragePercent))
		}
	default:
		r.Verdict = model.OverloadQueryCPU
		r.Confidence = overloadConfidence(mysqldKnown, cpuWait.measured, vc.Passed)
		victims := fmt.Sprintf("%d digest(s) are victims whose largest wait is the run queue", cpuWait.n)
		if !cpuWait.measured {
			victims = fmt.Sprintf("victims could not be measured (accounting.cpu_wait = %s)", cpuWait.reason)
		}
		r.Summary = fmt.Sprintf("digest %s did %s of all CPU work (%.2f cores of %s used); %s is the top CPU consumer%s; %s",
			d.DigestID, pct, d.CPUCores, usedCoresText(ev), familyOrUnknown(e, engFam), coverageClause(e, ev.QueryCPUCoveragePercent), victims)
	}
	return r
}

// overloadConfidence grades a query_*_overload verdict: low without process
// families, medium when no relevant wait is measured (victims unknown) or
// there are no victims, high with victims.
func overloadConfidence(mysqldKnown, waitsMeasured, victims bool) model.IOConfidence {
	switch {
	case !mysqldKnown:
		return model.ConfidenceLow
	case waitsMeasured && victims:
		return model.ConfidenceHigh
	}
	return model.ConfidenceMedium
}

var diskSaturated = map[model.IOVerdict]bool{
	model.VerdictHighDiskThroughput:  true,
	model.VerdictStorageLatencyStall: true,
	model.VerdictWritebackCongestion: true,
}

const resourceDisk = "disk"

func assessDisk(e Engine, my *Report, in Inputs, bgPct float64, now time.Time) *model.QueryOverload {
	r := &model.QueryOverload{Type: "query_overload", Timestamp: now, Resource: resourceDisk, Cluster: my.Cluster}
	if t := my.Thresholds; t != nil {
		r.Thresholds.IOCulpritPercentOfDiskRead = t.IOCulpritPercentOfDiskRead
		r.Thresholds.IOCulpritMinNodeDiskReadMBPerSec = t.IOCulpritMinNodeDiskReadMBPerSec
	}
	if e.Background {
		r.Thresholds.BackgroundDominantPercent = bgPct
	}
	ev := &r.Evidence
	ev.WindowSeconds = my.WindowSeconds
	ev.IOVerdict = string(in.IOVerdict)
	ev.QueryDiskReadCoveragePercent = my.QueryDiskReadCoveragePercent
	diskWait := measure(my, querystats.AccountingKeyDiskWait, querystats.VictimDisk)
	if diskWait.measured {
		ev.DiskVictims = intp(diskWait.n)
	} else {
		r.Missing = append(r.Missing, querystats.AccountingKeyDiskWait)
	}
	var commits []namedWait
	commitMeasured := false
	for _, w := range e.CommitWaits {
		wc := measure(my, w.Key, w.Victim)
		if w.Optional && wc.reason == "not_attached" {
			continue
		}
		if wc.measured {
			w.SetCount(ev, wc.n)
			commitMeasured = true
		} else {
			r.Missing = append(r.Missing, w.Key)
		}
		commits = append(commits, namedWait{w, wc})
	}
	if my.DiskEstimated {
		ev.DiskEstimated = boolp(true)
	}
	if my.Node != nil {
		ev.NodeDiskReadMBPerSec = my.Node.DiskReadMBPerSec
	}

	// 1. node
	nodeOK := diskSaturated[in.IOVerdict]
	nodeDetail := fmt.Sprintf("io_diagnosis verdict %s (disk saturated: high_disk_throughput, storage_latency_stall or writeback_congestion)", orNone(string(in.IOVerdict)))
	if in.IOVerdict == "" {
		nodeDetail = "io_diagnosis unavailable"
		r.Missing = append(r.Missing, "io_diagnosis")
	}
	if v := ev.NodeDiskReadMBPerSec; v != nil {
		nodeDetail += fmt.Sprintf("; physical disks read %.1f MB/s over the last %ds", *v, my.WindowSeconds)
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkNode, Passed: nodeOK, Detail: nodeDetail})

	d, found := candidate(my.TopDigestsByDiskRead)
	vc := diskVictimsCheck(diskWait, commits)
	bgType, bgVal, bgTotal, bgOK := dominantBackground(e, my, true, bgPct)
	if !found {
		if bgOK && nodeOK {
			if fam, famRead, top, topRead, known := familyDisk(in, my.ServerPID); known && top.Family == fam {
				ev.TopDiskFamily, ev.TopDiskFamilyReadMBPerSec = top.Family, floatp(topRead)
				e.SetDiskFamily(ev, fam, famRead)
				r.Checks = append(r.Checks,
					model.OverloadCheck{Name: e.CheckProcess, Passed: true, Detail: fmt.Sprintf("%s (pid %d) family %s reads %.1f MB/s; top disk-reading family is %s at %.1f MB/s",
						e.Process, my.ServerPID, fam, famRead, top.Family, topRead)},
					model.OverloadCheck{Name: checkDigest, Detail: "no per-statement disk reads"},
					vc)
				backgroundVerdict(e, r, fmt.Sprintf("The disk is saturated (%s)", in.IOVerdict), fam, bgType, bgVal, bgTotal, true)
				return r
			}
		}
		r.Checks = append(r.Checks,
			model.OverloadCheck{Name: e.CheckProcess, Detail: "no per-statement disk reads"},
			model.OverloadCheck{Name: checkDigest, Detail: "no per-statement disk reads"},
			vc)
		r.Verdict, r.Confidence = model.OverloadNoData, model.ConfidenceLow
		r.Missing = append(r.Missing, "query_disk_reads")
		r.Summary = "No per-statement disk reads in the window (no statement read from disk, or disk accounting unavailable — see " + e.Report + ".accounting.disk_bytes)."
		if !nodeOK {
			r.Verdict, r.Confidence = model.OverloadNodeNotSaturated, model.ConfidenceHigh
		}
		return r
	}
	r.Digest = &model.OverloadDigest{PID: d.PID, DigestID: d.DigestID, DigestText: d.DigestText, Command: d.Command,
		CallsPerSec: d.CallsPerSec, BytesOutPerCall: d.BytesOutPerCall, DiskReadMBPerSec: d.DiskReadMBPerSec,
		PercentOfDiskRead: d.PercentOfDiskRead, DiskReadPagesPerCall: d.DiskReadPagesPerCall, IORole: d.IORole}

	// 2. process: the family reading the most from storage. Family read rates
	// are only measured with process.include_io: all zero means unmeasured.
	mysqldKnown, mysqldOK := false, false
	mysqldDetail := "process families or their I/O unavailable (process.include_io)"
	var engFam string
	var engFamRead float64
	if fam, famRead, top, topRead, known := familyDisk(in, d.PID); known {
		mysqldKnown = true
		engFam, engFamRead = fam, famRead
		ev.TopDiskFamily, ev.TopDiskFamilyReadMBPerSec = top.Family, floatp(topRead)
		e.SetDiskFamily(ev, fam, famRead)
		mysqldOK = top.Family == fam
		mysqldDetail = fmt.Sprintf("%s (pid %d) family %s reads %.1f MB/s; top disk-reading family is %s at %.1f MB/s",
			e.Process, d.PID, fam, famRead, top.Family, topRead)
	}
	if !mysqldKnown {
		r.Missing = append(r.Missing, "family_disk_io")
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: e.CheckProcess, Passed: mysqldOK, Detail: mysqldDetail})

	// 3. query
	pct := pctText(d.PercentOfDiskRead)
	digestOK := d.IORole == querystats.RoleCulprit
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkDigest, Passed: digestOK, Detail: fmt.Sprintf(
		"top digest by disk reads %s read %s of the disk's reads (%s); io_role %s (needs >= %.0f%% while the node reads >= %.0f MB/s)",
		d.DigestID, pct, mbText(d.DiskReadMBPerSec), orNone(d.IORole), r.Thresholds.IOCulpritPercentOfDiskRead, r.Thresholds.IOCulpritMinNodeDiskReadMBPerSec)})

	// 4. effect
	r.Checks = append(r.Checks, vc)

	switch {
	case !nodeOK:
		r.Verdict, r.Confidence = model.OverloadNodeNotSaturated, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("The disk is not saturated (io_diagnosis %s). The top digest read %s of the disk's reads.", orNone(string(in.IOVerdict)), pct)
	case mysqldKnown && !mysqldOK:
		r.Verdict, r.Confidence = e.NotEngine, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("The disk is saturated (%s) but the top disk-reading family is %s (%.1f MB/s), not %s's %s (%.1f MB/s). Look at process_report.",
			in.IOVerdict, ev.TopDiskFamily, *ev.TopDiskFamilyReadMBPerSec, e.Process, engFam, engFamRead)
	case !digestOK && mysqldKnown && bgOK:
		backgroundVerdict(e, r, fmt.Sprintf("The disk is saturated (%s)", in.IOVerdict), engFam, bgType, bgVal, bgTotal, true)
	case !digestOK:
		r.Verdict = model.OverloadNoDominantQuery
		r.Confidence = model.ConfidenceHigh
		if !mysqldKnown || d.PercentOfDiskRead == nil {
			r.Confidence = model.ConfidenceLow
		}
		r.Summary = fmt.Sprintf("The disk is saturated (%s) but no single digest dominates its reads: the top digest read %s. The reads are spread over many queries, or come from %s%s.",
			in.IOVerdict, pct, e.DiskBackgroundText, diskCoverageClause(ev.QueryDiskReadCoveragePercent))
	default:
		r.Verdict = model.OverloadQueryDisk
		r.Confidence = overloadConfidence(mysqldKnown, diskWait.measured || commitMeasured, vc.Passed)
		if my.DiskEstimated && r.Confidence == model.ConfidenceHigh {
			r.Confidence = model.ConfidenceMedium // the per-digest reads are an estimate
		}
		r.Summary = fmt.Sprintf("digest %s read %s of the disk's reads (%s, %s)%s; %s is the top disk reader; %s",
			d.DigestID, pct, mbText(d.DiskReadMBPerSec), pagesText(d.DiskReadPagesPerCall), e.PagesAdvice(d.DiskReadPagesPerCall),
			familyOrUnknown(e, engFam), diskVictimsSummary(diskWait, commits))
	}
	return r
}

// waitCount is one victim kind: whether its wait was measured in every poll
// of the window (accounting entry "ok"), the accounting value, and the count.
type waitCount struct {
	measured bool
	reason   string
	n        int
}

// namedWait is one commit-like wait with its count.
type namedWait struct {
	w  Wait
	wc waitCount
}

func measure(my *Report, accountingKey, victimKind string) waitCount {
	reason := my.Accounting[accountingKey]
	if reason == "" {
		reason = "missing"
	}
	return waitCount{measured: reason == querystats.AccountingOK, reason: reason, n: my.Victims[victimKind]}
}

func nodeSourceText(ev *model.OverloadEvidence, window int) string {
	if ev.NodeCPUSource == "window" {
		return fmt.Sprintf("over the last %ds, %.1f of %d cores", window, *ev.NodeCPUUsedCores, ev.NumCPU)
	}
	return "latest collector sample; window value unavailable"
}

func saturatedText(used, load float64) string {
	return fmt.Sprintf("Node is saturated (CPU used %.1f%%, load/cpu %.2f)", used, load)
}

func floatp(v float64) *float64 { return &v }
func boolp(v bool) *bool        { return &v }
func intp(v int) *int           { return &v }

func usedCoresText(ev *model.OverloadEvidence) string {
	if ev.NodeCPUUsedCores == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.1f", *ev.NodeCPUUsedCores)
}

func pctText(p *float64) string {
	if p == nil {
		return "an unknown share"
	}
	return fmt.Sprintf("%.0f%%", *p)
}

func coverageClause(e Engine, c *float64) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("; queries explain %.0f%% of %s CPU", *c, e.Process)
}

func familyOrUnknown(e Engine, f string) string {
	if f == "" {
		return e.Process + " (family unknown)"
	}
	return f
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// candidate is the first digest of a ranking (by CPU or by disk reads), skipping the synthetic overflow digest.
func candidate(top []model.QueryDigestStats) (model.QueryDigestStats, bool) {
	for _, d := range top {
		if d.DigestID != querystats.OtherDigestID {
			return d, true
		}
	}
	return model.QueryDigestStats{}, false
}

func cpuVictimsCheck(w waitCount) model.OverloadCheck {
	if !w.measured {
		return model.OverloadCheck{Name: checkVictims,
			Detail: fmt.Sprintf("CPU waits not measured (accounting.cpu_wait = %s)", w.reason)}
	}
	return model.OverloadCheck{Name: checkVictims, Passed: w.n > 0,
		Detail: fmt.Sprintf("%d digest(s) with victim_of cpu (largest wait is the run queue; waits >= victim_wait_percent of their time and slow)", w.n)}
}

func mbText(v *float64) string {
	if v == nil {
		return "unknown MB/s"
	}
	return fmt.Sprintf("%.1f MB/s", *v)
}

func pagesText(v *float64) string {
	if v == nil {
		return "unknown pages per call"
	}
	return fmt.Sprintf("%.0f pages per call", *v)
}

func diskCoverageClause(c *float64) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("; statements explain %.0f%% of the disk's reads", *c)
}

// diskVictimsCheck passes when a measured disk or commit-like wait has
// victims; an unmeasured wait is named in the detail, never counted as 0.
func diskVictimsCheck(disk waitCount, commits []namedWait) model.OverloadCheck {
	part := func(w waitCount, key, name string) string {
		if !w.measured {
			return fmt.Sprintf("%s waits not measured (accounting.%s = %s)", name, key, w.reason)
		}
		return fmt.Sprintf("%d digest(s) with victim_of %s", w.n, name)
	}
	parts := []string{part(disk, querystats.AccountingKeyDiskWait, querystats.VictimDisk)}
	names := []string{querystats.VictimDisk}
	measured, passed := disk.measured, disk.measured && disk.n > 0
	for _, c := range commits {
		parts = append(parts, part(c.wc, c.w.Key, c.w.Victim))
		names = append(names, c.w.Victim)
		measured = measured || c.wc.measured
		passed = passed || (c.wc.measured && c.wc.n > 0)
	}
	detail := strings.Join(parts, "; ")
	if measured {
		detail += fmt.Sprintf(" (largest wait is %s; waits >= victim_wait_percent of their time and slow)", strings.Join(names, " / "))
	}
	return model.OverloadCheck{Name: checkVictims, Detail: detail, Passed: passed}
}

// diskVictimsSummary names the measured victim counts, then the unmeasured
// waits with their accounting values.
func diskVictimsSummary(disk waitCount, commits []namedWait) string {
	type item struct {
		wc        waitCount
		key, name string
	}
	all := []item{{disk, querystats.AccountingKeyDiskWait, querystats.VictimDisk}}
	for _, c := range commits {
		all = append(all, item{c.wc, c.w.Key, c.w.Victim})
	}
	var measured, missing []item
	for _, it := range all {
		if it.wc.measured {
			measured = append(measured, it)
		} else {
			missing = append(missing, it)
		}
	}
	if len(measured) == 0 {
		var reasons []string
		for _, it := range missing {
			reasons = append(reasons, fmt.Sprintf("accounting.%s = %s", it.key, it.wc.reason))
		}
		return "victims could not be measured (" + strings.Join(reasons, ", ") + ")"
	}
	s := fmt.Sprintf("%d digest(s) are victims whose largest wait is %s", measured[0].wc.n, measured[0].name)
	for _, it := range measured[1:] {
		s += fmt.Sprintf(" and %d whose largest wait is %s", it.wc.n, it.name)
	}
	if len(missing) > 0 {
		var notes []string
		for _, it := range missing {
			notes = append(notes, fmt.Sprintf("%s waits not measured: accounting.%s = %s", it.name, it.key, it.wc.reason))
		}
		s += " (" + strings.Join(notes, "; ") + ")"
	}
	return s
}

// AnnotateIODiagnosis returns io_diagnosis with a first next step pointing at
// overload_cause when the verdict, or its secondary assessment, is a query
// disk overload; otherwise d unchanged. d is never mutated (it may be shared).
func AnnotateIODiagnosis(d *model.IODiagnosis, oc *model.QueryOverload) *model.IODiagnosis {
	return AnnotateIODiagnosisFor(d, oc, MySQLEngine.Report)
}

// AnnotateIODiagnosisFor is AnnotateIODiagnosis for the report named report
// ("mysql_report" | "postgres_report"); it also points at a disk
// background_overload.
func AnnotateIODiagnosisFor(d *model.IODiagnosis, oc *model.QueryOverload, report string) *model.IODiagnosis {
	if d == nil || oc == nil {
		return d
	}
	where, disk := report+".overload_cause", oc
	if !isDiskOverload(disk) {
		where, disk = report+".overload_cause.secondary", oc.Secondary
	}
	if !isDiskOverload(disk) {
		return d
	}
	step := fmt.Sprintf("%s names the query behind this disk load: digest %s (verdict query_disk_overload).", where, diskDigestID(disk))
	if disk.Verdict == model.OverloadBackground {
		step = fmt.Sprintf("%s names the background work behind this disk load: %s backends (verdict background_overload).", where, disk.Evidence.BackgroundType)
	}
	cp := *d
	cp.NextSteps = append([]string{step}, d.NextSteps...)
	return &cp
}

func diskDigestID(oc *model.QueryOverload) string {
	if oc.Digest == nil {
		return ""
	}
	return oc.Digest.DigestID
}

func isDiskOverload(oc *model.QueryOverload) bool {
	if oc == nil {
		return false
	}
	return (oc.Verdict == model.OverloadQueryDisk && oc.Digest != nil) ||
		(oc.Verdict == model.OverloadBackground && oc.Resource == resourceDisk)
}
