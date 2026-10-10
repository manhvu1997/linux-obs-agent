// Package overload decides which query pattern, if any, is overloading the
// node's CPU. Every check is reported so the verdict is auditable:
//
//	node_saturated      window CPU used% or load/NumCPU over threshold   (node)
//	mysqld_top_consumer the digest's mysqld family is #1 by CPU            (process)
//	dominant_digest     the top digest by CPU has cpu_role culprit         (query)
//	victims             digests slowed mostly by waiting for a CPU          (effect)
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
}

const (
	checkNode    = "node_saturated"
	checkMySQLd  = "mysqld_top_consumer"
	checkDigest  = "dominant_digest"
	checkVictims = "victims"
	resourceCPU  = "cpu"
)

// Assess returns nil when there is no MySQL report to assess.
func Assess(in Inputs, th Thresholds, now time.Time) *model.QueryOverload {
	if in.MySQL == nil {
		return nil
	}
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
	ev.CPUVictims = my.Victims[querystats.VictimCPU]
	ev.PSICPUSomeAvg10, ev.PSIAvailable = m.Pressure.CPU.Some.Avg10, m.Pressure.CPU.Available
	if m.LoadAvg.NumCPU > 0 {
		ev.LoadNormalised = m.LoadAvg.Load1 / float64(m.LoadAvg.NumCPU)
	}
	if n := my.Node; n != nil {
		cores := n.CPUUsedCores
		ev.NodeCPUUsedPercent, ev.NodeCPUSource, ev.NodeCPUUsedCores, ev.NumCPU = n.CPUUsedPercent, "window", &cores, n.NumCPU
	} else {
		ev.NodeCPUUsedPercent, ev.NodeCPUSource, ev.NumCPU = m.CPU.UsagePercent, "sample", m.LoadAvg.NumCPU
		r.Missing = append(r.Missing, "node_cpu_window")
	}

	// 1. node
	nodeOK := ev.NodeCPUUsedPercent >= th.NodeCPUPercent || ev.LoadNormalised >= th.NodeLoad
	nodeDetail := fmt.Sprintf("CPU used %.1f%% (%s; threshold %.0f%%), load/cpu %.2f (threshold %.2f)",
		ev.NodeCPUUsedPercent, nodeSourceText(ev, my.WindowSeconds), th.NodeCPUPercent, ev.LoadNormalised, th.NodeLoad)
	if ev.PSIAvailable {
		nodeDetail += fmt.Sprintf(", PSI cpu some %.1f%%", ev.PSICPUSomeAvg10)
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkNode, Passed: nodeOK, Detail: nodeDetail})

	d, found := candidate(my.TopDigests)
	if !found {
		r.Checks = append(r.Checks,
			model.OverloadCheck{Name: checkMySQLd, Detail: "no digest data"},
			model.OverloadCheck{Name: checkDigest, Detail: "no digest data"},
			victimsCheck(ev.CPUVictims))
		r.Verdict, r.Confidence = model.OverloadNoData, model.ConfidenceLow
		r.Missing = append(r.Missing, "query_digests")
		r.Summary = "No query digest statistics in the window (mysql.emit_all_queries off, or no queries yet)."
		return r
	}
	r.Digest = &model.OverloadDigest{PID: d.PID, DigestID: d.DigestID, DigestText: d.DigestText, Command: d.Command,
		CPUCores: d.CPUCores, PercentOfNodeCPUUsed: d.PercentOfNodeCPUUsed, CallsPerSec: d.CallsPerSec,
		BytesOutPerCall: d.BytesOutPerCall, CPURole: d.CPURole}

	// 2. process
	mysqldKnown, mysqldOK := false, false
	mysqldDetail := "process families unavailable"
	if fam := in.PIDFamilies[d.PID]; fam != "" && len(in.Families) > 0 {
		mysqldKnown = true
		top := in.Families[0]
		ev.TopFamily, ev.TopFamilyCPUPercent, ev.MySQLFamily = top.Family, top.CPUPercent, fam
		for _, f := range in.Families {
			if f.Family == fam {
				ev.MySQLFamilyCPUPercent = f.CPUPercent
				break
			}
		}
		mysqldOK = top.Family == fam
		mysqldDetail = fmt.Sprintf("mysqld (pid %d) family %s uses %.1f%% of node CPU; top family is %s at %.1f%%",
			d.PID, fam, ev.MySQLFamilyCPUPercent, top.Family, top.CPUPercent)
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
	vc := victimsCheck(ev.CPUVictims)
	r.Checks = append(r.Checks, vc)

	switch {
	case !nodeOK:
		r.Verdict, r.Confidence = model.OverloadNodeNotSaturated, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("Node CPU is not saturated (%.1f%% used, load/cpu %.2f). The top digest did %s of the CPU work; it may dominate MySQL but does not overload the server.",
			ev.NodeCPUUsedPercent, ev.LoadNormalised, pct)
	case mysqldKnown && !mysqldOK:
		r.Verdict, r.Confidence = model.OverloadNotMySQL, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("Node CPU is saturated but the top CPU family is %s (%.1f%%), not mysqld's %s (%.1f%%). Look at process_report.top_families_cpu.",
			ev.TopFamily, ev.TopFamilyCPUPercent, ev.MySQLFamily, ev.MySQLFamilyCPUPercent)
	case !digestOK:
		r.Verdict, r.Confidence = model.OverloadNoDominantQuery, model.ConfidenceHigh
		if !mysqldKnown {
			r.Confidence = model.ConfidenceLow
		}
		r.Summary = fmt.Sprintf("Node CPU is saturated but no single digest dominates it: the top digest did %s of the CPU work. The load is spread over many queries or is outside query execution%s.",
			pct, coverageClause(ev.QueryCPUCoveragePercent))
	default:
		r.Verdict = model.OverloadQueryCPU
		switch {
		case !mysqldKnown:
			r.Confidence = model.ConfidenceLow
		case vc.Passed:
			r.Confidence = model.ConfidenceHigh
		default:
			r.Confidence = model.ConfidenceMedium
		}
		r.Summary = fmt.Sprintf("digest %s did %s of all CPU work (%.2f cores of %s used); %s is the top CPU consumer%s; %d digest(s) slowed by waiting for CPU",
			d.DigestID, pct, d.CPUCores, usedCoresText(ev), familyOrUnknown(ev.MySQLFamily), coverageClause(ev.QueryCPUCoveragePercent), ev.CPUVictims)
	}
	return r
}

func nodeSourceText(ev *model.OverloadEvidence, window int) string {
	if ev.NodeCPUSource == "window" {
		return fmt.Sprintf("over the last %ds, %.1f of %d cores", window, *ev.NodeCPUUsedCores, ev.NumCPU)
	}
	return "latest 5 s sample; window value unavailable"
}

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

// candidate is the top digest by CPU, skipping the synthetic overflow digest.
func candidate(top []model.QueryDigestStats) (model.QueryDigestStats, bool) {
	for _, d := range top {
		if d.DigestID != querystats.OtherDigestID {
			return d, true
		}
	}
	return model.QueryDigestStats{}, false
}

func victimsCheck(n int) model.OverloadCheck {
	return model.OverloadCheck{Name: checkVictims, Passed: n > 0,
		Detail: fmt.Sprintf("%d digest(s) with victim_of cpu (waited for a CPU >= victim_wait_percent of their time and slow)", n)}
}
