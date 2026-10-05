package collector

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// DStateCollector enumerates tasks in TASK_UNINTERRUPTIBLE (D) state.
//
// These are the tasks that produce iowait, and naming them together with the
// kernel symbol each is sleeping in (wchan) is the link between "the node
// reports iowait" and "this specific task is stuck in this specific path".
//
// Two design points that matter, both learned the hard way:
//
//  1. THREADS, not just processes. A blocked task is very often a worker
//     thread (an antivirus scanner thread, an io_uring worker, a JVM GC
//     thread), which never appears as a top-level /proc/<pid> entry. Scanning
//     only top-level PIDs reports zero blocked tasks while /proc/stat's
//     procs_blocked says otherwise — the census misses exactly what it exists
//     to find.
//
//  2. SUB-SAMPLING, not one point sample. A machine can spend 80% of its time
//     with something blocked while no single instant lands on a long block:
//     many short waits, constantly. Sampling once per 5 s collection interval
//     sees nothing. So this collector runs its own fast ticker and reports the
//     aggregate over the interval, including the fraction of samples in which
//     anything at all was blocked.
type DStateCollector struct {
	maxTasks    int
	scanThreads bool
	interval    time.Duration

	mu sync.Mutex
	// firstSeen records when each task was first observed in D during its
	// current uninterrupted run. Cleared as soon as it leaves D.
	firstSeen map[uint32]time.Time
	// acc accumulates observations between Collect() calls.
	acc dstateAccumulator
}

// dstateAccumulator aggregates fast samples over one collection interval.
type dstateAccumulator struct {
	samples        int
	samplesBlocked int
	peakCount      int
	longestMs      int64
	// tasks is keyed by tid; the record with the longest observed block wins.
	tasks map[uint32]*taskObservation
}

type taskObservation struct {
	task model.DStateTask
	// hits counts how many samples caught this task in D.
	hits int
}

// NewDStateCollector creates the scanner.
//
//	maxTasks    – cap on reported tasks (0 → 20); count/longest stay exact
//	scanThreads – walk /proc/<pid>/task/<tid> as well (default true; see above)
//	interval    – sub-sampling period (0 → 250ms)
func NewDStateCollector(maxTasks int, scanThreads bool, interval time.Duration) *DStateCollector {
	if maxTasks <= 0 {
		maxTasks = 20
	}
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	return &DStateCollector{
		maxTasks:    maxTasks,
		scanThreads: scanThreads,
		interval:    interval,
		firstSeen:   make(map[uint32]time.Time),
		acc:         newAccumulator(),
	}
}

func newAccumulator() dstateAccumulator {
	return dstateAccumulator{tasks: make(map[uint32]*taskObservation)}
}

// Run drives the fast sampling loop. It blocks until ctx is cancelled.
//
// Without this the census is a single instantaneous look per collection
// interval, which systematically misses short-but-frequent blocking.
func (d *DStateCollector) Run(ctx context.Context) {
	tick := time.NewTicker(d.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			d.sample()
		}
	}
}

// Collect returns the aggregate since the previous call and resets it.
func (d *DStateCollector) Collect() model.DStateCensus {
	d.mu.Lock()
	defer d.mu.Unlock()

	acc := d.acc
	d.acc = newAccumulator()

	census := model.DStateCensus{
		Available:    true,
		Samples:      acc.samples,
		PeakCount:    acc.peakCount,
		LongestMs:    acc.longestMs,
		Count:        acc.peakCount,
		SubSampledMs: d.interval.Milliseconds(),
	}
	if acc.samples > 0 {
		census.BlockedSamplePercent = round2dp(100 * float64(acc.samplesBlocked) / float64(acc.samples))
	}

	tasks := make([]model.DStateTask, 0, len(acc.tasks))
	for _, obs := range acc.tasks {
		t := obs.task
		if acc.samples > 0 {
			t.ObservedPercent = round2dp(100 * float64(obs.hits) / float64(acc.samples))
		}
		tasks = append(tasks, t)
	}
	// Longest-blocked first — that is the one worth looking at.
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].InDStateMs != tasks[j].InDStateMs {
			return tasks[i].InDStateMs > tasks[j].InDStateMs
		}
		return tasks[i].ObservedPercent > tasks[j].ObservedPercent
	})
	if len(tasks) > d.maxTasks {
		tasks = tasks[:d.maxTasks]
	}
	census.Tasks = tasks
	return census
}

// sample takes one instantaneous census and folds it into the accumulator.
func (d *DStateCollector) sample() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	now := time.Now()
	seen := make(map[uint32]bool)
	var found []model.DStateTask

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)

		if t, ok := d.inspect(pid, pid, "/proc/"+e.Name(), now); ok {
			seen[pid] = true
			found = append(found, t)
		}
		if d.scanThreads {
			for _, t := range d.inspectThreads(pid, e.Name(), now, seen) {
				found = append(found, t)
			}
		}
	}

	// Forget tasks no longer blocked: the duration restarts if they block
	// again, and the map cannot grow without bound.
	for tid := range d.firstSeen {
		if !seen[tid] {
			delete(d.firstSeen, tid)
		}
	}

	d.acc.samples++
	if len(found) > 0 {
		d.acc.samplesBlocked++
	}
	if len(found) > d.acc.peakCount {
		d.acc.peakCount = len(found)
	}
	for _, t := range found {
		if t.InDStateMs > d.acc.longestMs {
			d.acc.longestMs = t.InDStateMs
		}
		obs, ok := d.acc.tasks[t.TID]
		if !ok {
			d.acc.tasks[t.TID] = &taskObservation{task: t, hits: 1}
			continue
		}
		obs.hits++
		// Keep the observation with the longest block and a non-empty wchan.
		if t.InDStateMs > obs.task.InDStateMs {
			obs.task.InDStateMs = t.InDStateMs
		}
		if obs.task.Wchan == "" && t.Wchan != "" {
			obs.task.Wchan = t.Wchan
		}
	}
}

// inspect reads one task's stat file and returns a DStateTask when it is in D.
func (d *DStateCollector) inspect(tid, pid uint32, dir string, now time.Time) (model.DStateTask, bool) {
	data, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return model.DStateTask{}, false // exited mid-scan
	}

	comm, state, ppid, ok := parseStatMinimal(string(data))
	if !ok || state != 'D' {
		return model.DStateTask{}, false
	}

	first, ok := d.firstSeen[tid]
	if !ok {
		first = now
		d.firstSeen[tid] = first
	}

	t := model.DStateTask{
		TID:          tid,
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
		if t, ok := d.inspect(tid, pid, taskDir+"/"+te.Name(), now); ok {
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
	state = rest[0][0]
	if v, err := strconv.ParseUint(rest[1], 10, 32); err == nil {
		ppid = uint32(v)
	}
	return comm, state, ppid, true
}

// readWchan returns the kernel symbol the task is sleeping in.
//
// Values like "folio_wait_bit", "io_schedule" or "fanotify_handle_event" name
// the wait directly. Returns "" when unreadable (hardened kernels require
// CAP_SYS_ADMIN) or when the kernel writes "0".
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

func round2dp(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
