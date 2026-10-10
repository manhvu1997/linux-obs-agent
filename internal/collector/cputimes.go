package collector

import "fmt"

// jiffyNs converts /proc/stat jiffies to nanoseconds (USER_HZ 100, as in
// internal/process).
const jiffyNs = 10_000_000

// NodeCPUTimes is the cumulative CPU time of all CPUs since boot.
type NodeCPUTimes struct {
	UsedNs  uint64 // user+nice+system+irq+softirq+steal (the numerator of usage_percent)
	TotalNs uint64 // used + idle + iowait
	NumCPU  int    // cpuN lines in /proc/stat
}

// ReadNodeCPUTimes reads the cumulative counters from /proc/stat. Callers
// difference two readings; unlike CPUCollector it keeps no state.
func ReadNodeCPUTimes() (NodeCPUTimes, error) {
	agg, perCPU, _, _, _, _, _, err := readProcStat()
	if err != nil {
		return NodeCPUTimes{}, fmt.Errorf("reading /proc/stat: %w", err)
	}
	return nodeCPUTimes(agg, len(perCPU)), nil
}

func nodeCPUTimes(agg cpuStat, numCPU int) NodeCPUTimes {
	return NodeCPUTimes{UsedNs: agg.active() * jiffyNs, TotalNs: agg.total() * jiffyNs, NumCPU: numCPU}
}
