// Package process implements per-process inspection from /proc/[pid].
//
// It scans all visible PIDs every ScanInterval, computes CPU/IO rates using
// a two-sample delta, and keeps the top-N processes by CPU and RSS.
//
// Container / Kubernetes metadata is extracted from the cgroup path:
//
//	/sys/fs/cgroup/…/kubepods/pod<uid>/<container-id>/…
//
// and from /proc/[pid]/environ (HOSTNAME env var set by Kubernetes).
package process

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const clkTck = 100 // USER_HZ – safe default for all common Linux kernels

type prevSample struct {
	cpuTime    uint64
	readBytes  uint64
	writeBytes uint64
	sampleTime time.Time
}

// Inspector scans /proc periodically and maintains a sorted top-N snapshot.
type Inspector struct {
	cfg       *config.ProcessConfig
	mu        sync.RWMutex
	topCPU    []model.ProcessStats
	topMem    []model.ProcessStats
	reportCPU []model.ProcessStats
	reportMem []model.ProcessStats
	famCPU    []model.FamilyStats // all families, sorted by CPU desc
	famMem    []model.FamilyStats // all families, sorted by RSS desc
	pidFamily map[uint32]string
	prev      map[uint32]prevSample
	memTotal  uint64

	// famDrain folds every scan's families for the ClickHouse family_stats
	// table; nil until EnableFamilyDrain. Own lock: scan holds mu briefly.
	drainMu  sync.Mutex
	famDrain map[string]*famAcc
}

func NewInspector(cfg *config.ProcessConfig) *Inspector {
	return &Inspector{
		cfg:  cfg,
		prev: make(map[uint32]prevSample),
	}
}

// Run starts the periodic scan. Blocks until ctx is cancelled.
func (i *Inspector) Run(ctx context.Context) {
	// Read total RAM once – used for RSS % calculation.
	i.memTotal = readMemTotal()

	tick := time.NewTicker(i.cfg.ScanInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			i.scan()
		}
	}
}

// TopCPU returns the top-N processes by CPU usage.
func (i *Inspector) TopCPU() []model.ProcessStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]model.ProcessStats, len(i.topCPU))
	copy(out, i.topCPU)
	return out
}

// TopMem returns the top-N processes by RSS.
func (i *Inspector) TopMem() []model.ProcessStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]model.ProcessStats, len(i.topMem))
	copy(out, i.topMem)
	return out
}

// ReportTopCPU / ReportTopMem return process.report_top_cpu / report_top_mem
// (default report_top_n) processes for process_report (independent of the legacy top_n list).
func (i *Inspector) ReportTopCPU() []model.ProcessStats {
	return i.copyProcs(func() []model.ProcessStats { return i.reportCPU })
}
func (i *Inspector) ReportTopMem() []model.ProcessStats {
	return i.copyProcs(func() []model.ProcessStats { return i.reportMem })
}

// TopFamiliesCPU / TopFamiliesMem return the top report_top_families_cpu /
// report_top_families_mem (default report_top_n) families.
func (i *Inspector) TopFamiliesCPU() []model.FamilyStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return head(i.famCPU, i.cfg.EffectiveReportTopFamiliesCPU())
}

func (i *Inspector) TopFamiliesMem() []model.FamilyStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return head(i.famMem, i.cfg.EffectiveReportTopFamiliesMem())
}

// AllFamilies returns every family sorted by CPU desc (for Prometheus).
func (i *Inspector) AllFamilies() []model.FamilyStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return head(i.famCPU, len(i.famCPU))
}

// PIDFamilies returns a copy of the pid → family map from the last scan.
func (i *Inspector) PIDFamilies() map[uint32]string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make(map[uint32]string, len(i.pidFamily))
	for k, v := range i.pidFamily {
		out[k] = v
	}
	return out
}

func (i *Inspector) copyProcs(get func() []model.ProcessStats) []model.ProcessStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	src := get()
	out := make([]model.ProcessStats, len(src))
	copy(out, src)
	return out
}

// ─── Scanning ────────────────────────────────────────────────────────────────

func (i *Inspector) scan() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		slog.Warn("process: ReadDir /proc", "err", err)
		return
	}

	now := time.Now()
	numCPU := float64(runtime.NumCPU())
	var all []model.ProcessStats

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}
		pid := uint32(pid64)

		stats, err := i.readProc(pid, now, numCPU)
		if err != nil {
			continue // process may have exited
		}
		all = append(all, stats)
	}

	// Trim stale prev entries.
	active := make(map[uint32]struct{}, len(all))
	for _, s := range all {
		active[s.PID] = struct{}{}
	}
	for pid := range i.prev {
		if _, ok := active[pid]; !ok {
			delete(i.prev, pid)
		}
	}

	byCPU := sortedProcs(all, func(a, b model.ProcessStats) bool { return a.CPUPercent > b.CPUPercent })
	byMem := sortedProcs(all, func(a, b model.ProcessStats) bool { return a.MemRSSBytes > b.MemRSSBytes })

	fams := BuildFamilies(all, 5)
	famCPU := append([]model.FamilyStats(nil), fams...)
	sort.SliceStable(famCPU, func(a, b int) bool { return famCPU[a].CPUPercent > famCPU[b].CPUPercent })
	famMem := append([]model.FamilyStats(nil), fams...)
	sort.SliceStable(famMem, func(a, b int) bool { return famMem[a].MemRSSBytes > famMem[b].MemRSSBytes })

	pidFamily := make(map[uint32]string, len(all))
	for _, s := range all {
		pidFamily[s.PID] = s.Family
	}

	i.mu.Lock()
	i.topCPU = head(byCPU, i.cfg.TopN)
	i.topMem = head(byMem, i.cfg.TopN)
	i.reportCPU = head(byCPU, i.cfg.EffectiveReportTopCPU())
	i.reportMem = head(byMem, i.cfg.EffectiveReportTopMem())
	i.famCPU = famCPU
	i.famMem = famMem
	i.pidFamily = pidFamily
	i.mu.Unlock()
	i.observeFamilies(fams)
}

func sortedProcs(all []model.ProcessStats, less func(a, b model.ProcessStats) bool) []model.ProcessStats {
	out := make([]model.ProcessStats, len(all))
	copy(out, all)
	sort.SliceStable(out, func(a, b int) bool { return less(out[a], out[b]) })
	return out
}

func head[T any](s []T, n int) []T {
	if len(s) > n {
		s = s[:n]
	}
	out := make([]T, len(s))
	copy(out, s)
	return out
}

// readProc reads all interesting fields for one PID.
func (i *Inspector) readProc(pid uint32, now time.Time, numCPU float64) (model.ProcessStats, error) {
	base := fmt.Sprintf("/proc/%d", pid)

	stat, err := readProcStat(base + "/stat")
	if err != nil {
		return model.ProcessStats{}, err
	}

	status, err := readProcStatus(base + "/status")
	if err != nil {
		return model.ProcessStats{}, err
	}

	cmdline := readCmdline(base + "/cmdline")
	cgroupRaw, _ := os.ReadFile(base + "/cgroup")
	cgroupPath := strings.SplitN(string(cgroupRaw), "\n", 2)[0]

	s := model.ProcessStats{
		PID:         pid,
		PPID:        stat.ppid,
		Comm:        stat.comm,
		Cmdline:     cmdline,
		State:       string([]byte{stat.state}),
		Threads:     stat.numThreads,
		MemRSSBytes: stat.rss * 4096, // pages → bytes
		MemVMSBytes: uint64(stat.vsize),
		CgroupPath:  cgroupPath,
		Family:      FamilyKey(string(cgroupRaw), i.cfg.FamilyBy),
		StartTime:   stat.starttime,
	}

	if i.memTotal > 0 {
		s.MemPercent = 100.0 * float64(s.MemRSSBytes) / float64(i.memTotal)
	}

	// Delta CPU.
	curCPUTime := stat.utime + stat.stime
	if prev, ok := i.prev[pid]; ok {
		elapsed := now.Sub(prev.sampleTime).Seconds()
		if elapsed > 0 {
			cpuDelta := float64(curCPUTime-prev.cpuTime) / float64(clkTck)
			s.CPUPercent = 100.0 * cpuDelta / elapsed / numCPU
			if s.CPUPercent < 0 {
				s.CPUPercent = 0
			}
		}
	}

	// IO stats (best-effort – may fail without CAP_SYS_PTRACE on some kernels).
	if i.cfg.IncludeIO {
		rio, wio, err := readProcIO(base + "/io")
		if err == nil {
			s.ReadBytesTotal = rio
			s.WriteBytesTotal = wio
			if prev, ok := i.prev[pid]; ok {
				elapsed := now.Sub(prev.sampleTime).Seconds()
				if elapsed > 0 {
					s.ReadBytesPerSec = float64(rio-prev.readBytes) / elapsed
					s.WriteBytesPerSec = float64(wio-prev.writeBytes) / elapsed
				}
			}
		}
	}

	// Open file count (non-fatal).
	if fds, err := countFDs(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
		s.OpenFiles = fds
	}

	// Container / K8s metadata from cgroup path and environ.
	s.ContainerID, s.K8sPodName, s.K8sNamespace = extractK8sMeta(cgroupPath, base)

	i.prev[pid] = prevSample{
		cpuTime:    curCPUTime,
		readBytes:  s.ReadBytesTotal,
		writeBytes: s.WriteBytesTotal,
		sampleTime: now,
	}

	_ = status // available for future fields (e.g. UIDs)
	return s, nil
}

// ─── /proc/[pid]/stat parser ─────────────────────────────────────────────────

type procStatFields struct {
	comm       string
	state      byte
	ppid       uint32
	utime      uint64 // jiffies
	stime      uint64
	numThreads uint32
	vsize      uint64 // bytes
	rss        uint64 // pages
	starttime  uint64 // clock ticks since boot
}

func readProcStat(path string) (procStatFields, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return procStatFields{}, err
	}
	s := string(data)

	// comm is between the first '(' and last ')' to handle spaces in names.
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start < 0 || end < 0 || end <= start {
		return procStatFields{}, fmt.Errorf("malformed stat: %s", path)
	}
	comm := s[start+1 : end]
	rest := strings.Fields(s[end+2:]) // skip ") "
	if len(rest) < 22 {
		return procStatFields{}, fmt.Errorf("too few fields in stat: %s", path)
	}

	u := func(i int) uint64 {
		v, _ := strconv.ParseUint(rest[i], 10, 64)
		return v
	}

	return procStatFields{
		comm:       comm,
		state:      rest[0][0],
		ppid:       uint32(u(1)),
		utime:      u(11),
		stime:      u(12),
		numThreads: uint32(u(17)),
		vsize:      u(20),
		rss:        u(21),
		starttime:  u(19),
	}, nil
}

// readProcStatus parses /proc/[pid]/status (key: value lines).
func readProcStatus(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m, sc.Err()
}

func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// cmdline is NUL-separated.
	s := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(s)
}

// readProcIO parses /proc/[pid]/io for read_bytes and write_bytes.
func readProcIO(path string) (rBytes, wBytes uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ": ", 2)
		if len(parts) != 2 {
			continue
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		switch parts[0] {
		case "read_bytes":
			rBytes = v
		case "write_bytes":
			wBytes = v
		}
	}
	return rBytes, wBytes, sc.Err()
}

func countFDs(fdDir string) (int, error) {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func readMemTotal() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseUint(fields[1], 10, 64)
				return v * 1024
			}
		}
	}
	return 0
}

// ─── Kubernetes / container metadata ─────────────────────────────────────────

// extractK8sMeta extracts containerID, pod name, and namespace from the cgroup
// path and/or environment variables.
//
// Example cgroup path (cgroupv1):
//
//	12:cpuset:/kubepods/burstable/pod3d3abcc5-c745-11e8/3e596c0d5ecf08ba5dbb...
//
// Example cgroup path (cgroupv2):
//
//	0::/kubepods.slice/kubepods-pod<uid>.slice/<containerid>.scope
func extractK8sMeta(cgroupPath, procBase string) (containerID, podName, namespace string) {
	// Parse container ID from cgroup path (last 64-char hex segment).
	parts := strings.Split(cgroupPath, "/")
	for _, p := range parts {
		// Remove .scope suffix (cgroupv2).
		p = strings.TrimSuffix(p, ".scope")
		if len(p) == 64 {
			containerID = p[:12] // short form
			break
		}
		// docker / containerd: sha256:<id>
		if strings.HasPrefix(p, "docker-") || strings.HasPrefix(p, "crio-") {
			raw := p
			raw = strings.TrimPrefix(raw, "docker-")
			raw = strings.TrimPrefix(raw, "crio-")
			if len(raw) >= 12 {
				containerID = raw[:12]
			}
		}
	}

	// Extract pod UID from "podXXX" segment.
	for _, p := range parts {
		if strings.HasPrefix(p, "pod") {
			podUID := strings.TrimPrefix(p, "pod")
			podUID = strings.TrimSuffix(podUID, ".slice")
			_ = podUID // could be used for lookup
		}
	}

	// Best-effort: read HOSTNAME and NAMESPACE from /proc/[pid]/environ
	// (only works for the agent's own namespace or with sufficient privileges).
	env := readEnvVars(filepath.Join(procBase, "environ"),
		"HOSTNAME", "POD_NAMESPACE", "POD_NAME")
	if v, ok := env["HOSTNAME"]; ok {
		podName = v
	}
	if v, ok := env["POD_NAME"]; ok {
		podName = v
	}
	if v, ok := env["POD_NAMESPACE"]; ok {
		namespace = v
	}
	return
}

// readEnvVars reads NUL-separated KEY=VALUE pairs from /proc/[pid]/environ
// and returns a map filtered to the requested keys.
func readEnvVars(path string, keys ...string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	want := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		want[k] = struct{}{}
	}
	result := make(map[string]string)
	for _, entry := range strings.Split(string(data), "\x00") {
		idx := strings.IndexByte(entry, '=')
		if idx < 0 {
			continue
		}
		k, v := entry[:idx], entry[idx+1:]
		if _, ok := want[k]; ok {
			result[k] = v
		}
	}
	return result
}
