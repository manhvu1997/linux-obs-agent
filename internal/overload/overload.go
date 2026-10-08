// Package overload decides whether one MySQL query pattern is overloading
// the node, as opposed to merely dominating MySQL's own query CPU.
//
// The digest "culprit" role is relative to mysqld: it says a digest burns most
// of the query CPU and a real fraction of one core. It cannot say whether the
// node is short of CPU, nor whether mysqld is what consumes it. Assess adds
// those links and reports every check, so the verdict is auditable:
//
//	node_saturated      CPU% or load/NumCPU over threshold      (node)
//	mysqld_top_consumer the digest's mysqld family is #1 by CPU (process)
//	dominant_digest     role culprit AND ≥ N % of node CPU      (query)
//	victims             other digests wait in the run queue     (effect)
//
// Pure function over one diagnose call's inputs — no state, no I/O.
package overload

import (
	"fmt"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// Thresholds tune the assessment. Zero values fall back to Defaults().
type Thresholds struct {
	// NodeCPUPercent / NodeLoad: either one marks the node saturated.
	NodeCPUPercent float64
	NodeLoad       float64
	// MinNodeCPUPercent: the culprit digest must use at least this % of the
	// node's total CPU capacity over the digest window.
	MinNodeCPUPercent float64
}

// Defaults returns the shipped thresholds.
func Defaults() Thresholds {
	return Thresholds{NodeCPUPercent: 85, NodeLoad: 1.5, MinNodeCPUPercent: 20}
}

func (t Thresholds) withDefaults() Thresholds {
	d := Defaults()
	if t.NodeCPUPercent <= 0 {
		t.NodeCPUPercent = d.NodeCPUPercent
	}
	if t.NodeLoad <= 0 {
		t.NodeLoad = d.NodeLoad
	}
	if t.MinNodeCPUPercent <= 0 {
		t.MinNodeCPUPercent = d.MinNodeCPUPercent
	}
	return t
}

// Inputs are the signals of one diagnose call.
type Inputs struct {
	Metrics model.NodeMetrics
	MySQL   *model.MySQLAnalysis
	// Families is every process family sorted by CPU desc; PIDFamilies maps
	// PID → family. Both nil when the process inspector is unavailable.
	Families    []model.FamilyStats
	PIDFamilies map[uint32]string
}

const (
	checkNode    = "node_saturated"
	checkMySQLd  = "mysqld_top_consumer"
	checkDigest  = "dominant_digest"
	checkVictims = "victims"
)

// Assess returns nil when there is no MySQL report to assess.
func Assess(in Inputs, th Thresholds, now time.Time) *model.QueryOverload {
	if in.MySQL == nil {
		return nil
	}
	th = th.withDefaults()
	m := in.Metrics
	loadNorm := 0.0
	if m.LoadAvg.NumCPU > 0 {
		loadNorm = m.LoadAvg.Load1 / float64(m.LoadAvg.NumCPU)
	}
	r := &model.QueryOverload{
		Type:      "query_overload",
		Timestamp: now,
		Evidence: model.OverloadEvidence{
			NodeCPUPercent:  m.CPU.UsagePercent,
			LoadNormalised:  loadNorm,
			NumCPU:          m.LoadAvg.NumCPU,
			PSICPUSomeAvg10: m.Pressure.CPU.Some.Avg10,
			PSIAvailable:    m.Pressure.CPU.Available,
			VictimDigests:   in.MySQL.VictimDigests,
		},
		Thresholds: model.OverloadThresholds{
			NodeCPUPercent:    th.NodeCPUPercent,
			NodeLoad:          th.NodeLoad,
			MinNodeCPUPercent: th.MinNodeCPUPercent,
		},
	}
	if t := in.MySQL.Thresholds; t != nil {
		r.Thresholds.CulpritCPUSharePct = t.CulpritCPUSharePercent
		r.Thresholds.CulpritMinCPUPercent = t.CulpritMinCPUPercent
	}
	ev := &r.Evidence

	// 1. node
	nodeOK := m.CPU.UsagePercent >= th.NodeCPUPercent || loadNorm >= th.NodeLoad
	nodeDetail := fmt.Sprintf("cpu %.1f%% (threshold %.0f%%), load/cpu %.2f (threshold %.2f)",
		m.CPU.UsagePercent, th.NodeCPUPercent, loadNorm, th.NodeLoad)
	if ev.PSIAvailable {
		nodeDetail += fmt.Sprintf(", PSI cpu some %.1f%%", ev.PSICPUSomeAvg10)
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkNode, Passed: nodeOK, Detail: nodeDetail})

	d, found := candidate(in.MySQL.TopDigests)
	if !found {
		r.Checks = append(r.Checks,
			model.OverloadCheck{Name: checkMySQLd, Detail: "no digest data"},
			model.OverloadCheck{Name: checkDigest, Detail: "no digest data"},
			victimsCheck(in.MySQL.VictimDigests))
		r.Verdict, r.Confidence = model.OverloadNoData, model.ConfidenceLow
		r.Missing = append(r.Missing, "query_digests")
		r.Summary = "No query digest statistics in the window (mysql.emit_all_queries off, or no queries yet)."
		return r
	}
	r.PID, r.DigestID, r.DigestText = d.PID, d.DigestID, d.DigestText
	ev.DigestCPUSharePercent = d.CPUSharePercent
	ev.DigestCPUPercentOfCore = d.CPUPercentOfCore
	ev.DigestCPUPercentOfNode = d.CPUPercentOfNode
	ev.DigestRole = d.Role

	// 2. process
	mysqldKnown, mysqldOK := false, false
	mysqldDetail := "process families unavailable"
	if fam := in.PIDFamilies[d.PID]; fam != "" && len(in.Families) > 0 {
		mysqldKnown = true
		top := in.Families[0]
		ev.TopFamily, ev.TopFamilyCPUPercent = top.Family, top.CPUPercent
		ev.MySQLFamily = fam
		for _, f := range in.Families {
			if f.Family == fam {
				ev.MySQLFamilyCPU = f.CPUPercent
				break
			}
		}
		mysqldOK = top.Family == fam
		mysqldDetail = fmt.Sprintf("mysqld (pid %d) family %s uses %.1f%% of node CPU; top family is %s at %.1f%%",
			d.PID, fam, ev.MySQLFamilyCPU, top.Family, top.CPUPercent)
	} else {
		r.Missing = append(r.Missing, "process_families")
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkMySQLd, Passed: mysqldOK, Detail: mysqldDetail})

	// 3. query
	digestOK := d.Role == querystats.RoleCulprit && d.CPUPercentOfNode >= th.MinNodeCPUPercent
	roleText := d.Role
	if roleText == "" {
		roleText = "none"
	}
	r.Checks = append(r.Checks, model.OverloadCheck{Name: checkDigest, Passed: digestOK, Detail: fmt.Sprintf(
		"top digest %s: role %s, %.1f%% of mysqld query CPU, %.1f%% of one core, %.1f%% of node CPU (needs culprit and >= %.0f%% of node)",
		d.DigestID, roleText, d.CPUSharePercent, d.CPUPercentOfCore, d.CPUPercentOfNode, th.MinNodeCPUPercent)})

	// 4. effect
	vc := victimsCheck(in.MySQL.VictimDigests)
	r.Checks = append(r.Checks, vc)

	switch {
	case !nodeOK:
		r.Verdict, r.Confidence = model.OverloadNodeNotSaturated, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("Node is not CPU-saturated (cpu %.1f%%, load/cpu %.2f). The top digest uses %.1f%% of node CPU; it may dominate MySQL but does not overload the server.",
			m.CPU.UsagePercent, loadNorm, d.CPUPercentOfNode)
	case mysqldKnown && !mysqldOK:
		r.Verdict, r.Confidence = model.OverloadNotMySQL, model.ConfidenceHigh
		r.Summary = fmt.Sprintf("Node is saturated but the top CPU family is %s (%.1f%%), not mysqld's %s (%.1f%%). Look at process_report.top_families_cpu.",
			ev.TopFamily, ev.TopFamilyCPUPercent, ev.MySQLFamily, ev.MySQLFamilyCPU)
	case !digestOK:
		r.Verdict, r.Confidence = model.OverloadNoDominantQuery, model.ConfidenceHigh
		if !mysqldKnown {
			r.Confidence = model.ConfidenceLow
		}
		r.Summary = fmt.Sprintf("Node is saturated but no single digest dominates it: the top digest uses %.1f%% of node CPU (role %s). The load is spread over many queries or is outside query execution.",
			d.CPUPercentOfNode, roleText)
	default:
		r.Verdict = model.OverloadByQuery
		switch {
		case !mysqldKnown:
			r.Confidence = model.ConfidenceLow
		case vc.Passed:
			r.Confidence = model.ConfidenceHigh
		default:
			r.Confidence = model.ConfidenceMedium
		}
		r.Summary = fmt.Sprintf("Digest %s overloads the node: %.1f%% of node CPU (%.1f%% of one core, %.1f%% of mysqld query CPU) while the node is saturated; %d victim digest(s) waited in the run queue.",
			d.DigestID, d.CPUPercentOfNode, d.CPUPercentOfCore, d.CPUSharePercent, in.MySQL.VictimDigests)
	}
	return r
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
		Detail: fmt.Sprintf("%d digest(s) with role victim (run-queue wait > victim_runq_ratio × CPU and slow)", n)}
}
