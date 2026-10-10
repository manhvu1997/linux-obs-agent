package collector

import "testing"

func TestNodeCPUTimesSplitsUsedAndTotal(t *testing.T) {
	agg := cpuStat{user: 100, nice: 10, system: 50, idle: 800, iowait: 20, irq: 5, softirq: 5, steal: 10}
	got := nodeCPUTimes(agg, 4)
	// used = user+nice+system+irq+softirq+steal = 180 jiffies; total = 1000 jiffies
	if got.UsedNs != 180*jiffyNs || got.TotalNs != 1000*jiffyNs || got.NumCPU != 4 {
		t.Fatalf("got %+v", got)
	}
}
