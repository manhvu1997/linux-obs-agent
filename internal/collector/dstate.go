package collector

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// DStateCollector enumerates tasks in TASK_UNINTERRUPTIBLE (D) state.
//
// These are the tasks that produce iowait, and enumerating them with the kernel
// symbol each is sleeping in (wchan) is the missing link between "the node
// reports iowait" and "this specific worker is stuck in this specific path".
//
// It also tracks how long each task has been *continuously* in D across
// consecutive scans, which is what makes the "D-state longer than 1 s"
// classification possible without eBPF.
type DStateCollector struct {
	// firstSeen records when each PID was first observed in D during the
	// current uninterrupted run. Cleared as soon as it leaves D.
	firstSeen map[uint32]time.Time
	maxTasks  int
	// scanThreads additionally walks /proc/<pid>/task/<tid>. Off by default:
	// it multiplies the scan cost by the thread count, and the usual targets
	// (kworker/flush, jbd2, io_uring workers) are top-level PIDs anyway.
	scanThreads bool
}

// NewDStateCollector creates the scanner. maxTasks caps how many tasks are
// reported (0 → 20); the count and longest duration are always exact.
func NewDStateCollector(maxTasks int, scanThreads bool) *DStateCollector {
	if maxTasks <= 0 {
		maxTasks = 20
	}
	return &DStateCollector{
		firstSeen:   make(map[uint32]time.Time),
		maxTasks:    maxTasks,
		scanThreads: scanThreads,
	}
}

// Collect scans /proc for tasks currently in D state.
func (d *DStateCollector) Collect() model.DStateCensus {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return model.DStateCensus{}
	}

	now := time.Now()
	seen := make(map[uint32]bool)
	var tasks []model.DStateTask

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a pid directory
		}
		pid := uint32(pid64)

		if t, ok := d.inspect(pid, "/proc/"+e.Name(), now); ok {
			seen[pid] = true
			tasks = append(tasks, t)
		}

		if d.scanThreads {
			tasks = append(tasks, d.inspectThreads(pid, e.Name(), now, seen)...)
		}
	}

	// Forget tasks that are no longer blocked so the duration restarts if they
	// block again, and so the map cannot grow without bound.
	for pid := range d.firstSeen {
		if !seen[pid] {
			delete(d.firstSeen, pid)
		}
	}

	census := model.DStateCensus{Count: len(tasks), Available: true}
	for _, t := range tasks {
		if t.InDStateMs > census.LongestMs {
			census.LongestMs = t.InDStateMs
		}
	}

	// Longest-blocked first: that is the one worth looking at.
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].InDStateMs > tasks[j].InDStateMs })
	if len(tasks) > d.maxTasks {
		tasks = tasks[:d.maxTasks]
	}
	census.Tasks = tasks
	return census
}

// inspect reads one task's stat file and returns a DStateTask when it is in D.
func (d *DStateCollector) inspect(pid uint32, dir string, now time.Time) (model.DStateTask, bool) {
	data, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return model.DStateTask{}, false // process exited mid-scan
	}

	comm, state, ppid, ok := parseStatMinimal(string(data))
	if !ok || state != 'D' {
		return model.DStateTask{}, false
	}

	first, ok := d.firstSeen[pid]
	if !ok {
		first = now
		d.firstSeen[pid] = first
	}

	t := model.DStateTask{
		PID:          pid,
		PPID:         ppid,
		Comm:         comm,
		Wchan:        readWchan(dir),
		InDStateMs:   now.Sub(first).Milliseconds(),
		KernelThread: isKernelThread(dir),
	}
	if !t.KernelThread {
		t.CgroupPath = readCgroupFile(dir + "/cgroup")
	}
	return t, true
}

func (d *DStateCollector) inspectThreads(pid uint32, name string, now time.Time, seen map[uint32]bool) []model.DStateTask {
	taskDir := "/proc/" + name + "/task"
	tids, err := os.ReadDir(taskDir)
	if err != nil || len(tids) <= 1 {
		return nil
	}
	var out []model.DStateTask
	for _, te := range tids {
		tid64, err := strconv.ParseUint(te.Name(), 10, 32)
		if err != nil {
			continue
		}
		tid := uint32(tid64)
		if tid == pid || seen[tid] {
			continue // main thread already covered
		}
		if t, ok := d.inspect(tid, taskDir+"/"+te.Name(), now); ok {
			seen[tid] = true
			out = append(out, t)
		}
	}
	return out
}

// parseStatMinimal extracts comm, state and ppid from a /proc/<pid>/stat line.
//
// comm is wrapped in parentheses and may itself contain spaces and
// parentheses, so the only safe split point is the LAST ')'.
func parseStatMinimal(s string) (comm string, state byte, ppid uint32, ok bool) {
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return "", 0, 0, false
	}
	comm = s[open+1 : closeIdx]

	rest := strings.Fields(s[closeIdx+1:])
	if len(rest) < 2 {
		return "", 0, 0, false
	}
	// rest[0] = state, rest[1] = ppid
	state = rest[0][0]
	if v, err := strconv.ParseUint(rest[1], 10, 32); err == nil {
		ppid = uint32(v)
	}
	return comm, state, ppid, true
}

// readWchan returns the kernel symbol the task is sleeping in.
//
// Values like "folio_wait_bit", "io_schedule" or "balance_dirty_pages" name the
// wait directly. Returns "" when unreadable (needs CAP_SYS_ADMIN on some
// hardened kernels) or when the kernel writes "0" for a running task.
func readWchan(dir string) string {
	data, err := os.ReadFile(dir + "/wchan")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if s == "0" {
		return ""
	}
	return s
}

// isKernelThread reports whether the task has no address space. Kernel threads
// (kworker/*, jbd2/*, kswapd) have an empty cmdline.
func isKernelThread(dir string) bool {
	data, err := os.ReadFile(dir + "/cmdline")
	if err != nil {
		return false
	}
	return len(data) == 0
}

// readCgroupFile returns the cgroup path from the first line of a cgroup file.
func readCgroupFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	parts := strings.SplitN(line, ":", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return ""
}
