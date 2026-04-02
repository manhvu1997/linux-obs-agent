// Package collector provides lightweight /proc and /sys based metric scrapers.
// All collectors implement the Collector interface and are designed to
// have negligible CPU overhead (<0.1%).
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// cpuStat holds the raw /proc/stat fields for one CPU.
type cpuStat struct {
	user    uint64
	nice    uint64
	system  uint64
	idle    uint64
	iowait  uint64
	irq     uint64
	softirq uint64
	steal   uint64
}

func (s cpuStat) total() uint64 {
	return s.user + s.nice + s.system + s.idle + s.iowait +
		s.irq + s.softirq + s.steal
}

func (s cpuStat) active() uint64 {
	return s.total() - s.idle - s.iowait
}

// CPUCollector collects CPU metrics from /proc/stat.
type CPUCollector struct {
	prev      cpuStat
	prevCPUs  []cpuStat
	prevCtx   uint64
	prevIntr  uint64
	prevForks uint64
	lastTime  time.Time
}

func NewCPUCollector() *CPUCollector {
	return &CPUCollector{}
}

// Collect reads /proc/stat and returns delta-based CPU metrics.
func (c *CPUCollector) Collect() (model.CPUMetrics, error) {
	stat, cpus, ctx, intr, forks, running, blocked, err := readProcStat()
	if err != nil {
		return model.CPUMetrics{}, fmt.Errorf("reading /proc/stat: %w", err)
	}

	now := time.Now()
	m := model.CPUMetrics{
		RunningProcs: running,
		BlockedProcs: blocked,
	}

	// On the first call we just save the baseline.
	if c.lastTime.IsZero() {
		c.prev, c.prevCPUs = stat, cpus
		c.prevCtx, c.prevIntr, c.prevForks = ctx, intr, forks
		c.lastTime = now
		return m, nil
	}

	elapsed := now.Sub(c.lastTime).Seconds()

	// Aggregate CPU percentages.
	totalDelta := float64(stat.total() - c.prev.total())
	if totalDelta > 0 {
		m.UserPercent = 100 * float64(stat.user+stat.nice-c.prev.user-c.prev.nice) / totalDelta
		m.SysPercent = 100 * float64(stat.system-c.prev.system) / totalDelta
		m.IOWaitPercent = 100 * float64(stat.iowait-c.prev.iowait) / totalDelta
		m.IdlePercent = 100 * float64(stat.idle-c.prev.idle) / totalDelta
		m.StealPercent = 100 * float64(stat.steal-c.prev.steal) / totalDelta
		m.UsagePercent = 100.0 - m.IdlePercent - m.IOWaitPercent
		if m.UsagePercent < 0 {
			m.UsagePercent = 0
		}
	}

	// Delta counters.
	if elapsed > 0 {
		m.CtxSwitches = uint64(float64(ctx-c.prevCtx) / elapsed)
		m.Interrupts = uint64(float64(intr-c.prevIntr) / elapsed)
		m.Forks = uint64(float64(forks-c.prevForks) / elapsed)
	}

	// Per-CPU.
	m.PerCPU = make([]model.PerCPUMetrics, len(cpus))
	for i, cu := range cpus {
		if i >= len(c.prevCPUs) {
			break
		}
		d := float64(cu.total() - c.prevCPUs[i].total())
		if d > 0 {
			m.PerCPU[i] = model.PerCPUMetrics{
				ID:           i,
				UsagePercent: 100 * float64(cu.active()-c.prevCPUs[i].active()) / d,
				IOWait:       100 * float64(cu.iowait-c.prevCPUs[i].iowait) / d,
			}
		}
	}

	c.prev, c.prevCPUs = stat, cpus
	c.prevCtx, c.prevIntr, c.prevForks = ctx, intr, forks
	c.lastTime = now
	return m, nil
}

// readProcStat parses /proc/stat.
func readProcStat() (agg cpuStat, perCPU []cpuStat, ctx, intr, forks uint64, running, blocked uint32, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch {
		case fields[0] == "cpu":
			agg = parseCPULine(fields)
		case strings.HasPrefix(fields[0], "cpu"):
			perCPU = append(perCPU, parseCPULine(fields))
		case fields[0] == "ctxt":
			ctx, _ = strconv.ParseUint(fields[1], 10, 64)
		case fields[0] == "intr":
			intr, _ = strconv.ParseUint(fields[1], 10, 64)
		case fields[0] == "processes":
			forks, _ = strconv.ParseUint(fields[1], 10, 64)
		case fields[0] == "procs_running":
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			running = uint32(v)
		case fields[0] == "procs_blocked":
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			blocked = uint32(v)
		}
	}
	err = sc.Err()
	return
}

func parseCPULine(fields []string) cpuStat {
	u := func(i int) uint64 {
		if i >= len(fields) {
			return 0
		}
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		return v
	}
	return cpuStat{
		user:    u(1),
		nice:    u(2),
		system:  u(3),
		idle:    u(4),
		iowait:  u(5),
		irq:     u(6),
		softirq: u(7),
		steal:   u(8),
	}
}
