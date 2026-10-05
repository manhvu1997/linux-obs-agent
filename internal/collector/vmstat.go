package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// VMStatCollector reads the writeback-relevant subset of /proc/vmstat.
//
// This is what distinguishes a device-latency stall from writeback congestion:
// when nr_dirty climbs toward the kernel's dirty_ratio, writers are throttled
// inside balance_dirty_pages() and stall regardless of how fast the disk is.
type VMStatCollector struct {
	prev     map[string]uint64
	prevTime time.Time
	pageSize uint64
	memTotal uint64
}

// vmstatCounters are the cumulative fields we turn into per-second rates.
var vmstatCounters = []string{
	"nr_dirtied", "nr_written", "pgpgin", "pgpgout", "pswpin", "pswpout",
}

// vmstatGauges are the point-in-time page counts we read directly.
var vmstatGauges = []string{"nr_dirty", "nr_writeback"}

func NewVMStatCollector() *VMStatCollector {
	return &VMStatCollector{
		prev:     make(map[string]uint64),
		pageSize: uint64(os.Getpagesize()),
	}
}

// Collect reads /proc/vmstat and returns gauges plus per-second deltas.
//
// memTotalBytes comes from the memory collector in the same cycle and is used
// only to express dirty pages as a ratio; pass 0 to skip that.
func (v *VMStatCollector) Collect(memTotalBytes uint64) model.VMStatMetrics {
	fields, err := readVMStat()
	if err != nil {
		return model.VMStatMetrics{}
	}

	now := time.Now()
	elapsed := now.Sub(v.prevTime).Seconds()
	if v.prevTime.IsZero() {
		elapsed = 0
	}

	m := model.VMStatMetrics{Available: true}
	m.DirtyBytes = fields["nr_dirty"] * v.pageSize
	m.WritebackBytes = fields["nr_writeback"] * v.pageSize

	if memTotalBytes > 0 {
		m.DirtyRatioPercent = 100 * float64(m.DirtyBytes) / float64(memTotalBytes)
	}

	if elapsed > 0 {
		rate := func(key string) float64 {
			cur, ok := fields[key]
			if !ok {
				return 0
			}
			prev, ok := v.prev[key]
			if !ok || cur < prev { // counter reset (reboot / wrap)
				return 0
			}
			return float64(cur-prev) / elapsed
		}
		m.DirtiedPagesPerSec = rate("nr_dirtied")
		m.WrittenPagesPerSec = rate("nr_written")
		// pgpgin/pgpgout are already reported in kilobytes by the kernel.
		m.PgPgInPerSec = rate("pgpgin")
		m.PgPgOutPerSec = rate("pgpgout")
		m.PSwpInPerSec = rate("pswpin")
		m.PSwpOutPerSec = rate("pswpout")
	}

	for _, k := range vmstatCounters {
		if val, ok := fields[k]; ok {
			v.prev[k] = val
		}
	}
	v.prevTime = now
	return m
}

// readVMStat parses /proc/vmstat, keeping only the keys we care about.
// The file has ~200 lines; filtering keeps the map tiny.
func readVMStat() (map[string]uint64, error) {
	f, err := os.Open("/proc/vmstat")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	want := make(map[string]bool, len(vmstatCounters)+len(vmstatGauges))
	for _, k := range vmstatCounters {
		want[k] = true
	}
	for _, k := range vmstatGauges {
		want[k] = true
	}

	out := make(map[string]uint64, len(want))
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), " ")
		if !ok || !want[key] {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64)
		if err != nil {
			continue
		}
		out[key] = n
	}
	return out, sc.Err()
}
