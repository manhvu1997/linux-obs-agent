package querystats

// HostDelta is what the node and the traced mysqld processes did between
// two polls. Recorded with AddHost at the same time as that poll's
// AddDeltas, so window numerators and denominators cover the same polls.
type HostDelta struct {
	NodeCPUUsedNs  uint64 // all CPUs: user+nice+system+irq+softirq+steal
	NodeCPUTotalNs uint64 // all CPUs, every state (capacity)
	NumCPU         int
	NodeOK         bool   // false: no valid node delta for this poll
	MysqldCPUNs    uint64 // Σ utime+stime of the traced PIDs
	MysqldPartial  bool   // a traced PID had no usable baseline (new, restarted or gone)
}
