// Package procreport assembles process_report for GET /api/diagnose from the
// process inspector's top lists, the netflow accumulator and the /proc
// connection inventory. Pure: every dependency is an interface.
package procreport

import (
	"fmt"
	"sort"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// NetSource is satisfied by *netflow.Accumulator.
type NetSource interface {
	Process(tgid uint32) model.NetworkSummary
	Family(name string) model.NetworkSummary
}

// InventorySource is satisfied by *netinv.Inventory.
type InventorySource interface {
	ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections
}

// Inputs to Build. Net and Inventory must be nil interfaces (not typed-nil
// pointers) when unavailable: callers must not store a nil *Accumulator or
// *Inventory in them, since that compares != nil and would be dereferenced.
type Inputs struct {
	TopCPU, TopMem           []model.ProcessStats
	FamiliesCPU, FamiliesMem []model.FamilyStats
	Net                      NetSource
	NetworkSource            string
	InboundAccounting        string
	WindowSeconds            int
	Inventory                InventorySource
	MaxConnections           int
}

func Build(in Inputs, now time.Time) *model.ProcessReport {
	var pids []uint32
	seen := make(map[uint32]bool)
	add := func(pid uint32) {
		if pid != 0 && !seen[pid] {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	for _, list := range [][]model.ProcessStats{in.TopCPU, in.TopMem} {
		for _, p := range list {
			add(p.PID)
		}
	}
	for _, list := range [][]model.FamilyStats{in.FamiliesCPU, in.FamiliesMem} {
		for _, f := range list {
			add(f.RootPID)
			for _, m := range f.TopMembers {
				add(m.PID)
			}
		}
	}
	conns := map[uint32]model.ProcessConnections{}
	if in.Inventory != nil && len(pids) > 0 {
		conns = in.Inventory.ForPIDs(pids, in.MaxConnections)
	}

	r := &model.ProcessReport{
		Type:              "process_analysis",
		Timestamp:         now,
		WindowSeconds:     in.WindowSeconds,
		NetworkSource:     in.NetworkSource,
		InboundAccounting: in.InboundAccounting,
		TopCPU:            make([]model.ProcessEntry, 0, len(in.TopCPU)),
		TopMem:            make([]model.ProcessEntry, 0, len(in.TopMem)),
		TopFamiliesCPU:    make([]model.FamilyEntry, 0, len(in.FamiliesCPU)),
		TopFamiliesMem:    make([]model.FamilyEntry, 0, len(in.FamiliesMem)),
	}
	for _, p := range in.TopCPU {
		r.TopCPU = append(r.TopCPU, processEntry(p, conns[p.PID], in.Net))
	}
	for _, p := range in.TopMem {
		r.TopMem = append(r.TopMem, processEntry(p, conns[p.PID], in.Net))
	}
	for _, f := range in.FamiliesCPU {
		r.TopFamiliesCPU = append(r.TopFamiliesCPU, familyEntry(f, conns, in.Net))
	}
	for _, f := range in.FamiliesMem {
		r.TopFamiliesMem = append(r.TopFamiliesMem, familyEntry(f, conns, in.Net))
	}
	return r
}

func processEntry(p model.ProcessStats, pc model.ProcessConnections, net NetSource) model.ProcessEntry {
	e := model.ProcessEntry{
		PID: p.PID, PPID: p.PPID, Comm: p.Comm, Cmdline: p.Cmdline, Family: p.Family,
		CPUPercent: p.CPUPercent, MemRSSBytes: p.MemRSSBytes, MemPercent: p.MemPercent,
		Threads: p.Threads, OpenFiles: p.OpenFiles,
		ListeningPorts:       nonNil(pc.ListeningPorts),
		Connections:          pc.Connections,
		ConnectionsTruncated: pc.Truncated,
		ConnectionsError:     pc.Error,
		ProfileURL:           fmt.Sprintf("/api/profile?pid=%d", p.PID),
	}
	if e.Connections == nil {
		e.Connections = []model.Connection{}
	}
	if net != nil {
		s := net.Process(p.PID)
		e.Network = &s
	}
	return e
}

func familyEntry(f model.FamilyStats, conns map[uint32]model.ProcessConnections, net NetSource) model.FamilyEntry {
	e := model.FamilyEntry{FamilyStats: f}
	seen := make(map[model.ListenPort]bool)
	pids := []uint32{f.RootPID}
	for _, m := range f.TopMembers {
		pids = append(pids, m.PID)
	}
	for _, pid := range pids {
		for _, lp := range conns[pid].ListeningPorts {
			if !seen[lp] {
				seen[lp] = true
				e.ListeningPorts = append(e.ListeningPorts, lp)
			}
		}
	}
	e.ListeningPorts = nonNil(e.ListeningPorts)
	sort.Slice(e.ListeningPorts, func(i, j int) bool { return e.ListeningPorts[i].Port < e.ListeningPorts[j].Port })
	if e.TopMembers == nil {
		e.TopMembers = []model.FamilyMember{}
	}
	if net != nil {
		s := net.Family(f.Family)
		e.Network = &s
	}
	return e
}

func nonNil(lp []model.ListenPort) []model.ListenPort {
	if lp == nil {
		return []model.ListenPort{}
	}
	return lp
}
