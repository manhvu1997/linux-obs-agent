// internal/process/family.go
package process

import (
	"sort"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	FamilyBySystemdUnit = "systemd_unit"
	FamilyByCgroup      = "cgroup"
	UnknownFamily       = "unknown"
)

// FamilyKey derives a process family from the full contents of
// /proc/<pid>/cgroup. In systemd_unit mode it returns the innermost
// "*.service" component of the path, else the innermost "*.scope", else the
// whole path. Grouping by unit keeps double-forking daemons together where a
// PPID chain would break.
func FamilyKey(cgroupFile, mode string) string {
	path, ok := cgroupPath(cgroupFile)
	if !ok {
		return UnknownFamily
	}
	if mode == FamilyByCgroup {
		return path
	}
	parts := strings.Split(path, "/")
	for _, suffix := range []string{".service", ".scope"} {
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], suffix) {
				return parts[i]
			}
		}
	}
	return path
}

// cgroupPath picks the hierarchy systemd manages: unified v2 ("0::"), then
// v1 "name=systemd", then the first well-formed line.
func cgroupPath(content string) (string, bool) {
	var first, v1 string
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 || f[2] == "" {
			continue
		}
		if f[0] == "0" && f[1] == "" {
			return f[2], true
		}
		if f[1] == "name=systemd" {
			v1 = f[2]
		}
		if first == "" {
			first = f[2]
		}
	}
	if v1 != "" {
		return v1, true
	}
	return first, first != ""
}

// BuildFamilies groups processes by Family. The root is the oldest process
// (lowest StartTime, then lowest PID). TopMembers holds up to topMembers
// processes by CPU. The result is sorted by family name.
func BuildFamilies(procs []model.ProcessStats, topMembers int) []model.FamilyStats {
	type agg struct {
		f         model.FamilyStats
		rootStart uint64
		members   []model.ProcessStats
	}
	by := make(map[string]*agg)
	for _, p := range procs {
		a, ok := by[p.Family]
		if !ok {
			a = &agg{f: model.FamilyStats{Family: p.Family}, rootStart: p.StartTime}
			a.f.RootPID, a.f.RootCmdline = p.PID, rootCmdline(p)
			by[p.Family] = a
		} else if p.StartTime < a.rootStart || (p.StartTime == a.rootStart && p.PID < a.f.RootPID) {
			a.rootStart = p.StartTime
			a.f.RootPID, a.f.RootCmdline = p.PID, rootCmdline(p)
		}
		a.f.ProcessCount++
		a.f.CPUPercent += p.CPUPercent
		a.f.MemRSSBytes += p.MemRSSBytes
		a.f.MemPercent += p.MemPercent
		a.members = append(a.members, p)
	}
	out := make([]model.FamilyStats, 0, len(by))
	for _, a := range by {
		m := a.members
		sort.Slice(m, func(i, j int) bool {
			if m[i].CPUPercent != m[j].CPUPercent {
				return m[i].CPUPercent > m[j].CPUPercent
			}
			return m[i].PID < m[j].PID
		})
		if len(m) > topMembers {
			m = m[:topMembers]
		}
		a.f.TopMembers = make([]model.FamilyMember, 0, len(m))
		for _, p := range m {
			a.f.TopMembers = append(a.f.TopMembers, model.FamilyMember{
				PID: p.PID, Comm: p.Comm, CPUPercent: p.CPUPercent, MemRSSBytes: p.MemRSSBytes,
			})
		}
		out = append(out, a.f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

func rootCmdline(p model.ProcessStats) string {
	if p.Cmdline != "" {
		return p.Cmdline
	}
	return "[" + p.Comm + "]"
}
