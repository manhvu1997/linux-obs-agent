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
	checkMySQLd  = "mysqld_top_consumer"
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
	cpu := assessCPU(in, th, now)
	disk := assessDisk(in, now)
	cpuSat, diskSat := cpu.Checks[0].Passed, disk.Checks[0].Passed
	switch {
	case cpuSat && diskSat:
		primary, secondary := cpu, disk
		if preferDisk(cpu, disk) {
			primary, secondary = disk, cpu
		}
		primary.Secondary = secondary
		return primary
	case diskSat:
		return disk
	default:
		return cpu
	}
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

// assessCPU assesses the CPU; in.MySQL is non-nil.
func assessCPU(in Inputs, th Thresholds, now time.Time) *model.QueryOverload {
	th = th.withDefaults()
	my, m := in.MySQL, in.Metrics
	r := &model.QueryOverload{Type: "query_overload", Timestamp: now, Resource: resourceCPU,
		Thresholds: model.OverloadThresholds{NodeCPUPercent: th.NodeCPUPercent, NodeLoad: th.NodeLoad}}
	if t := my.Thresholds; t != nil {
		r.Thresholds.CPUCulpritPercentOfNodeCPUUsed = t.CPUCulpritPercentOfNodeCPUUsed
		r.Thresholds.CPUCulpritMinNodeCPUUsedPercent = t.CPUCulpritMinNodeCPUUsedPercent
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
	d, found := candidate(my.TopDigests)
	if !found {
		r.Checks = append(r.Checks,
			model.OverloadCheck{Name: checkMySQLd, Detail: "no digest data"},
			model.OverloadCheck{Name: checkDigest, Detail: "no digest data"},
			vc)
		r.Verdict, r.Confidence = model.OverloadNoData, model.ConfidenceLow
		r.Missing = append(r.Missing, "query_digests")
		r.Summary = "No query digest statistics in the window (mysql.emit_all_queries off, or no queries yet)."
		return r
	}
	r.Digest = &model.OverloadDigest{PID: d.PID, DigestID: d.DigestID, DigestText: d.DigestText, Command: d.Command,
		CPUCores: floatp(d.CPUCores), PercentOfNodeCPUUsed: d.PercentOfNodeCPUUsed, CallsPerSec: d.CallsPerSec,
		BytesOutPerCall: d.BytesOutPerCall, CPURole: d.CPURole}

	// 2. process
	mysqldKnown, mysqldOK := false, false
	mysqldDetail := "process families unavailable"
	if fam := in.PIDFamilies[d.PID]; fam != "" && len(in.Families) > 0 {
		mysqldKnown = true
		top := in.Families[0]
		var famCPU float64
		for _, f := range in.Families {
			if f.Family == fam {
				famCPU = f.CPUPercent
				break
			}
		}
		ev.TopFamily, ev.TopFamilyCPUPercent, ev.MySQLFamily, ev.MySQLFamilyCPUPercent = top.Family, floatp(top.CPUPercent), fam, floatp(famCPU)
		mysqldOK = top.Family == fam
		mysqldDetail = fmt.Sprintf("mysqld (pid %d) family %s uses %.1f%% of node CPU; top family is %s at %.1f%%",
			d.PID, fam, famCPU, top.Family, top.CPUPercent)
	} else {
		r.Missing = append(r.Missing, "process_families")
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkMySQLd, Passed: mysqldOK, Detail: mysqldDetail})

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
		r.Verdict, r.Confidence = model.OverloadNotMySQL, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("%s but the top CPU family is %s (%.1f%%), not mysqld's %s (%.1f%%). Look at process_report.top_families_cpu.",
			saturatedText(used, load), ev.TopFamily, *ev.TopFamilyCPUPercent, ev.MySQLFamily, *ev.MySQLFamilyCPUPercent)
	case !digestOK:
		r.Verdict = model.OverloadNoDominantQuery
		// A culprit needs percent_of_node_cpu_used (so a node window) and the
		// node at least cpu_culprit_min_node_cpu_used_percent busy: when either
		// is missing "no dominant query" is true by construction, not evidence.
		minUsed := r.Thresholds.CPUCulpritMinNodeCPUUsedPercent
		switch {
		case d.PercentOfNodeCPUUsed == nil:
			r.Confidence = model.ConfidenceLow
			r.Summary = fmt.Sprintf("%s but the digests' share of node CPU is unavailable (mysql_report.node missing for a poll in the window), so no digest can be judged a CPU culprit%s.",
				saturatedText(used, load), coverageClause(ev.QueryCPUCoveragePercent))
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
				saturatedText(used, load), pct, coverageClause(ev.QueryCPUCoveragePercent))
		}
	default:
		r.Verdict = model.OverloadQueryCPU
		r.Confidence = overloadConfidence(mysqldKnown, cpuWait.measured, vc.Passed)
		victims := fmt.Sprintf("%d digest(s) are victims whose largest wait is the run queue", cpuWait.n)
		if !cpuWait.measured {
			victims = fmt.Sprintf("victims could not be measured (accounting.cpu_wait = %s)", cpuWait.reason)
		}
		r.Summary = fmt.Sprintf("digest %s did %s of all CPU work (%.2f cores of %s used); %s is the top CPU consumer%s; %s",
			d.DigestID, pct, d.CPUCores, usedCoresText(ev), familyOrUnknown(ev.MySQLFamily), coverageClause(ev.QueryCPUCoveragePercent), victims)
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

func assessDisk(in Inputs, now time.Time) *model.QueryOverload {
	my := in.MySQL
	r := &model.QueryOverload{Type: "query_overload", Timestamp: now, Resource: resourceDisk}
	if t := my.Thresholds; t != nil {
		r.Thresholds.IOCulpritPercentOfDiskRead = t.IOCulpritPercentOfDiskRead
		r.Thresholds.IOCulpritMinNodeDiskReadMBPerSec = t.IOCulpritMinNodeDiskReadMBPerSec
	}
	ev := &r.Evidence
	ev.WindowSeconds = my.WindowSeconds
	ev.IOVerdict = string(in.IOVerdict)
	ev.QueryDiskReadCoveragePercent = my.QueryDiskReadCoveragePercent
	diskWait := measure(my, querystats.AccountingKeyDiskWait, querystats.VictimDisk)
	commitWait := measure(my, querystats.AccountingKeyCommitWait, querystats.VictimCommit)
	if diskWait.measured {
		ev.DiskVictims = intp(diskWait.n)
	} else {
		r.Missing = append(r.Missing, querystats.AccountingKeyDiskWait)
	}
	if commitWait.measured {
		ev.CommitVictims = intp(commitWait.n)
	} else {
		r.Missing = append(r.Missing, querystats.AccountingKeyCommitWait)
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
	vc := diskVictimsCheck(diskWait, commitWait)
	if !found {
		r.Checks = append(r.Checks,
			model.OverloadCheck{Name: checkMySQLd, Detail: "no per-statement disk reads"},
			model.OverloadCheck{Name: checkDigest, Detail: "no per-statement disk reads"},
			vc)
		r.Verdict, r.Confidence = model.OverloadNoData, model.ConfidenceLow
		r.Missing = append(r.Missing, "query_disk_reads")
		r.Summary = "No per-statement disk reads in the window (no statement read from disk, or disk accounting unavailable — see mysql_report.accounting.disk_bytes)."
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
	if fam := in.PIDFamilies[d.PID]; fam != "" {
		var top model.FamilyStats
		var famRead float64
		for _, f := range in.Families {
			if f.ReadBytesPerSec > top.ReadBytesPerSec {
				top = f
			}
			if f.Family == fam {
				famRead = f.ReadBytesPerSec / (1 << 20)
			}
		}
		if top.ReadBytesPerSec > 0 {
			mysqldKnown = true
			topRead := top.ReadBytesPerSec / (1 << 20)
			ev.TopDiskFamily, ev.TopDiskFamilyReadMBPerSec = top.Family, floatp(topRead)
			ev.MySQLFamily, ev.MySQLFamilyDiskReadMBPerSec = fam, floatp(famRead)
			mysqldOK = top.Family == fam
			mysqldDetail = fmt.Sprintf("mysqld (pid %d) family %s reads %.1f MB/s; top disk-reading family is %s at %.1f MB/s",
				d.PID, fam, famRead, top.Family, topRead)
		}
	}
	if !mysqldKnown {
		r.Missing = append(r.Missing, "family_disk_io")
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkMySQLd, Passed: mysqldOK, Detail: mysqldDetail})

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
		r.Verdict, r.Confidence = model.OverloadNotMySQL, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("The disk is saturated (%s) but the top disk-reading family is %s (%.1f MB/s), not mysqld's %s (%.1f MB/s). Look at process_report.",
			in.IOVerdict, ev.TopDiskFamily, *ev.TopDiskFamilyReadMBPerSec, ev.MySQLFamily, *ev.MySQLFamilyDiskReadMBPerSec)
	case !digestOK:
		r.Verdict = model.OverloadNoDominantQuery
		r.Confidence = model.ConfidenceHigh
		if !mysqldKnown || d.PercentOfDiskRead == nil {
			r.Confidence = model.ConfidenceLow
		}
		r.Summary = fmt.Sprintf("The disk is saturated (%s) but no single digest dominates its reads: the top digest read %s. The reads are spread over many queries, or come from InnoDB background work or writes%s.",
			in.IOVerdict, pct, diskCoverageClause(ev.QueryDiskReadCoveragePercent))
	default:
		r.Verdict = model.OverloadQueryDisk
		r.Confidence = overloadConfidence(mysqldKnown, diskWait.measured || commitWait.measured, vc.Passed)
		r.Summary = fmt.Sprintf("digest %s read %s of the disk's reads (%s, %s)%s; %s is the top disk reader; %s",
			d.DigestID, pct, mbText(d.DiskReadMBPerSec), pagesText(d.DiskReadPagesPerCall), pagesAdvice(d.DiskReadPagesPerCall),
			familyOrUnknown(ev.MySQLFamily), diskVictimsSummary(diskWait, commitWait))
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

func measure(my *model.MySQLAnalysis, accountingKey, victimKind string) waitCount {
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

func coverageClause(c *float64) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("; queries explain %.0f%% of mysqld CPU", *c)
}

func familyOrUnknown(f string) string {
	if f == "" {
		return "mysqld (family unknown)"
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

// pagesAdvice reads disk_read_pages_per_call (16 KiB pages).
func pagesAdvice(v *float64) string {
	switch {
	case v == nil:
		return ""
	case *v <= 4:
		return ": reads look like buffer-pool misses — consider a larger innodb_buffer_pool_size"
	case *v >= 100:
		return ": reads look like a scan — EXPLAIN it, add an index or a LIMIT"
	}
	return ""
}

func diskCoverageClause(c *float64) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("; statements explain %.0f%% of the disk's reads", *c)
}

// diskVictimsCheck passes when a measured disk or commit wait has victims;
// an unmeasured wait is named in the detail, never counted as 0.
func diskVictimsCheck(disk, commit waitCount) model.OverloadCheck {
	part := func(w waitCount, name string) string {
		if !w.measured {
			return fmt.Sprintf("%s waits not measured (accounting.%s_wait = %s)", name, name, w.reason)
		}
		return fmt.Sprintf("%d digest(s) with victim_of %s", w.n, name)
	}
	detail := part(disk, "disk") + "; " + part(commit, "commit")
	if disk.measured || commit.measured {
		detail += " (largest wait is disk / commit; waits >= victim_wait_percent of their time and slow)"
	}
	return model.OverloadCheck{Name: checkVictims, Detail: detail,
		Passed: (disk.measured && disk.n > 0) || (commit.measured && commit.n > 0)}
}

func diskVictimsSummary(disk, commit waitCount) string {
	switch {
	case disk.measured && commit.measured:
		return fmt.Sprintf("%d digest(s) are victims whose largest wait is disk and %d whose largest wait is commit", disk.n, commit.n)
	case disk.measured:
		return fmt.Sprintf("%d digest(s) are victims whose largest wait is disk (commit waits not measured: accounting.commit_wait = %s)", disk.n, commit.reason)
	case commit.measured:
		return fmt.Sprintf("%d digest(s) are victims whose largest wait is commit (disk waits not measured: accounting.disk_wait = %s)", commit.n, disk.reason)
	}
	return fmt.Sprintf("victims could not be measured (accounting.disk_wait = %s, accounting.commit_wait = %s)", disk.reason, commit.reason)
}

// AnnotateIODiagnosis returns io_diagnosis with a first next step pointing at
// overload_cause when the verdict, or its secondary assessment, is a query
// disk overload; otherwise d unchanged. d is never mutated (it may be shared).
func AnnotateIODiagnosis(d *model.IODiagnosis, oc *model.QueryOverload) *model.IODiagnosis {
	if d == nil || oc == nil {
		return d
	}
	where, disk := "mysql_report.overload_cause", oc
	if !isDiskOverload(disk) {
		where, disk = "mysql_report.overload_cause.secondary", oc.Secondary
	}
	if !isDiskOverload(disk) {
		return d
	}
	cp := *d
	cp.NextSteps = append([]string{fmt.Sprintf(
		"%s names the query behind this disk load: digest %s (verdict query_disk_overload).", where, disk.Digest.DigestID)},
		d.NextSteps...)
	return &cp
}

func isDiskOverload(oc *model.QueryOverload) bool {
	return oc != nil && oc.Verdict == model.OverloadQueryDisk && oc.Digest != nil
}
