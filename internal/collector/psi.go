package collector

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// PSICollector reads Linux Pressure Stall Information from /proc/pressure/*.
//
// Why this matters more than iowait: iowait is charged to a CPU that went idle
// while any task on its runqueue sat in D state, so an idle machine with one
// parked kernel worker reports enormous iowait while losing no work at all.
// PSI measures the opposite — time during which work could NOT proceed:
//
//	some – at least one runnable task was stalled on the resource
//	full – every non-idle task was stalled; the machine made no progress
//
// io.full is therefore the decisive signal for "is this a real storage stall?".
type PSICollector struct {
	prev     map[string]psiTotals
	prevTime time.Time
}

// psiTotals holds the cumulative some/full stall counters for one resource.
type psiTotals struct {
	some uint64
	full uint64
}

func NewPSICollector() *PSICollector {
	return &PSICollector{prev: make(map[string]psiTotals)}
}

// psiResources maps the /proc/pressure file name to its slot in the result.
var psiResources = []string{"io", "cpu", "memory"}

// Collect reads all three pressure files in one pass.
//
// Missing files are not an error: PSI requires CONFIG_PSI=y and, on some
// distributions, the psi=1 boot parameter. Callers see Available=false.
func (p *PSICollector) Collect() model.PressureMetrics {
	now := time.Now()
	elapsed := now.Sub(p.prevTime).Seconds()
	if p.prevTime.IsZero() {
		elapsed = 0
	}

	var out model.PressureMetrics
	for _, res := range psiResources {
		m := p.collectOne(res, elapsed)
		switch res {
		case "io":
			out.IO = m
		case "cpu":
			out.CPU = m
		case "memory":
			out.Memory = m
		}
	}

	p.prevTime = now
	return out
}

func (p *PSICollector) collectOne(resource string, elapsed float64) model.PSIMetrics {
	data, err := os.ReadFile("/proc/pressure/" + resource)
	if err != nil {
		return model.PSIMetrics{} // Available stays false
	}

	m := model.PSIMetrics{Available: true}
	var cur psiTotals

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		parsed := parsePSILine(fields[1:])
		switch fields[0] {
		case "some":
			m.Some = parsed
			cur.some = parsed.TotalUs
		case "full":
			m.Full = parsed
			cur.full = parsed.TotalUs
		}
	}

	// Derive the per-second stall rate from the cumulative totals. This is
	// more responsive than avg10 and is what the classifier keys on.
	if prev, ok := p.prev[resource]; ok && elapsed > 0 {
		if cur.some >= prev.some {
			m.Some.TotalUsPerSec = float64(cur.some-prev.some) / elapsed
		}
		if cur.full >= prev.full {
			m.Full.TotalUsPerSec = float64(cur.full-prev.full) / elapsed
		}
	}
	p.prev[resource] = cur

	return m
}

// parsePSILine parses `avg10=0.00 avg60=0.00 avg300=0.00 total=0`.
//
// Note: the cpu resource has no `full` line on most kernels (a fully stalled
// CPU is a contradiction), so PSIMetrics.Full stays zero there.
func parsePSILine(fields []string) model.PSILine {
	var l model.PSILine
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "avg10":
			l.Avg10, _ = strconv.ParseFloat(v, 64)
		case "avg60":
			l.Avg60, _ = strconv.ParseFloat(v, 64)
		case "avg300":
			l.Avg300, _ = strconv.ParseFloat(v, 64)
		case "total":
			l.TotalUs, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return l
}
