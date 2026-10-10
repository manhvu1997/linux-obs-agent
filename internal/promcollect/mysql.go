package promcollect

import (
	"math"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

const digestTextMaxBytes = 120

var (
	myQueriesDesc = prometheus.NewDesc("obs_agent_mysql_queries_total",
		"MySQL commands executed, by command class (query | stmt_prepare | stmt_execute | other).", []string{"command"}, nil)
	myCPUDesc = prometheus.NewDesc("obs_agent_mysql_query_cpu_seconds_total",
		"On-CPU seconds spent inside dispatch_command, by command class.", []string{"command"}, nil)
	myRunqDesc = prometheus.NewDesc("obs_agent_mysql_query_runq_wait_seconds_total",
		"Seconds MySQL worker threads waited for a CPU while executing commands.", []string{"command"}, nil)
	myWallDesc = prometheus.NewDesc("obs_agent_mysql_query_wall_seconds_total",
		"Wall-clock seconds spent inside dispatch_command, by command class.", []string{"command"}, nil)
	myBytesDesc = prometheus.NewDesc("obs_agent_mysql_query_bytes_total",
		"Result bytes sent to clients per command class (flow=\"out\").", []string{"command", "flow"}, nil)
	myDigestCPUDesc = prometheus.NewDesc("obs_agent_mysql_digest_cpu_seconds_total",
		"On-CPU seconds spent executing statements of this digest.", []string{"digest_id"}, nil)
	myDigestCallsDesc = prometheus.NewDesc("obs_agent_mysql_digest_calls_total",
		"Executions of statements of this digest.", []string{"digest_id"}, nil)
	myDigestOutDesc = prometheus.NewDesc("obs_agent_mysql_digest_bytes_out_total",
		"Result bytes sent for statements of this digest.", []string{"digest_id"}, nil)
	myDigestRunqDesc = prometheus.NewDesc("obs_agent_mysql_digest_runq_wait_seconds_total",
		"Seconds statements of this digest waited for a CPU.", []string{"digest_id"}, nil)
	myDiskReadDesc = prometheus.NewDesc("obs_agent_mysql_query_disk_read_bytes_total",
		"Bytes MySQL statements caused to be read from storage (task I/O accounting), by command class.", []string{"command"}, nil)
	myDiskWriteDesc = prometheus.NewDesc("obs_agent_mysql_query_disk_write_bytes_total",
		"Bytes MySQL statements caused to be written (dirtied or O_DIRECT), by command class.", []string{"command"}, nil)
	myIOWaitDesc = prometheus.NewDesc("obs_agent_mysql_query_io_wait_seconds_total",
		"Seconds MySQL statements waited for block I/O (kernel delay accounting), by command class. Absent while not measured.", []string{"command"}, nil)
	myRedoWaitDesc = prometheus.NewDesc("obs_agent_mysql_query_redo_wait_seconds_total",
		"Seconds MySQL statements waited for the redo log inside log_write_up_to (commit wait), by command class. Absent while not measured.", []string{"command"}, nil)
	myDigestDiskReadDesc = prometheus.NewDesc("obs_agent_mysql_digest_disk_read_bytes_total",
		"Bytes statements of this digest caused to be read from storage.", []string{"digest_id"}, nil)
	myDigestIOWaitDesc = prometheus.NewDesc("obs_agent_mysql_digest_io_wait_seconds_total",
		"Seconds statements of this digest waited for block I/O (full mode).", []string{"digest_id"}, nil)
	myQueryCoverageDesc = prometheus.NewDesc("obs_agent_mysql_query_cpu_coverage_ratio",
		"Share (0-1) of the traced mysqld processes' CPU spent inside dispatch_command over the digest window (absent while unknown).", nil, nil)
	myIOAvailDesc = prometheus.NewDesc("obs_agent_mysql_io_wait_available",
		"1 when per-statement block-I/O wait is measured over the whole digest window (delay accounting on), else 0.", nil, nil)
	myRedoAvailDesc = prometheus.NewDesc("obs_agent_mysql_redo_wait_available",
		"1 when per-statement commit wait is measured over the whole digest window, else 0.", nil, nil)
	myDigestInfoDesc = prometheus.NewDesc("obs_agent_mysql_digest_info",
		"Normalised SQL text of a digest (value is always 1); join with * on(digest_id) group_left(digest_text).",
		[]string{"digest_id", "digest_text"}, nil)
	myCoverageDesc = prometheus.NewDesc("obs_agent_mysql_digest_coverage_ratio",
		"Share (0-1) of the window's query CPU explained by the per-digest series exported in the current mode.", nil, nil)
	myDroppedDesc = prometheus.NewDesc("obs_agent_mysql_events_dropped_total",
		"Commands lost before reaching the digest aggregator (fallback ring buffer full or consumer behind); digest totals undercount when this rises. Text events are counted separately.", nil, nil)
	myTextDroppedDesc = prometheus.NewDesc("obs_agent_mysql_text_events_dropped_total",
		"Statement text events dropped because the consumer was behind; first-sight texts are re-requested from the kernel (no command is lost; until the resend the hash's commands may show under a text-unavailable placeholder).", nil, nil)
	myAggOverflowDesc = prometheus.NewDesc("obs_agent_mysql_agg_overflow_total",
		"Commands that bypassed in-kernel aggregation because the map was full (processed as full events; totals stay exact).", nil, nil)
	myHashMismatchDesc = prometheus.NewDesc("obs_agent_mysql_hash_mismatch_total",
		"Kernel text hashes found inconsistent: a verification sample or resend whose digest differed from the cached one, or a first-sight text whose kernel hash differed from the Go reference; the hash is switched to exact per-event processing.", nil, nil)
)

// MySQLHealth are the tracer's health counters. A nil func reports 0.
type MySQLHealth struct {
	Dropped        func() uint64 // commands lost (obs_agent_mysql_events_dropped_total)
	TextDropped    func() uint64 // text events dropped, re-requested (…_text_events_dropped_total)
	AggOverflow    func() uint64 // commands that bypassed kernel aggregation (map full)
	HashMismatches func() uint64 // kernel text hash disagreed with the digest
}

func (h MySQLHealth) read(f func() uint64) float64 {
	if f == nil {
		return 0
	}
	return float64(f())
}

// MySQLCollector exports MySQL command counters and per-digest counters in
// one of three modes (mysql.prometheus_digests).
type MySQLCollector struct {
	snap        func() *querystats.Snapshot
	health      MySQLHealth
	mode        string
	minimalTopN int
}

func NewMySQLCollector(snap func() *querystats.Snapshot, health MySQLHealth, mode string, minimalTopN int) *MySQLCollector {
	if minimalTopN < 1 {
		minimalTopN = 20
	}
	return &MySQLCollector{snap: snap, health: health, mode: mode, minimalTopN: minimalTopN}
}

func (c *MySQLCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{myQueriesDesc, myCPUDesc, myRunqDesc, myWallDesc, myBytesDesc,
		myDigestCPUDesc, myDigestCallsDesc, myDigestOutDesc, myDigestRunqDesc, myDigestInfoDesc, myCoverageDesc, myDroppedDesc,
		myTextDroppedDesc, myAggOverflowDesc, myHashMismatchDesc,
		myDiskReadDesc, myDiskWriteDesc, myIOWaitDesc, myRedoWaitDesc, myDigestDiskReadDesc, myDigestIOWaitDesc,
		myQueryCoverageDesc, myIOAvailDesc, myRedoAvailDesc} {
		ch <- d
	}
}

func (c *MySQLCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.snap()
	if s == nil {
		return
	}
	sec := func(ns uint64) float64 { return float64(ns) / 1e9 }
	// Wait counters exist only while measured over the whole window: a
	// counter stuck at 0 would read as "no wait" rather than "unknown".
	ioWaitOK := s.Accounting[querystats.AccountingKeyDiskWait] == querystats.AccountingOK
	redoWaitOK := s.Accounting[querystats.AccountingKeyCommitWait] == querystats.AccountingOK
	for cmd, q := range s.Commands {
		emit(ch, myQueriesDesc, prometheus.CounterValue, float64(q.Calls), cmd)
		emit(ch, myCPUDesc, prometheus.CounterValue, sec(q.CPUNs), cmd)
		emit(ch, myRunqDesc, prometheus.CounterValue, sec(q.RunqNs), cmd)
		emit(ch, myWallDesc, prometheus.CounterValue, sec(q.WallNs), cmd)
		emit(ch, myBytesDesc, prometheus.CounterValue, float64(q.BytesOut), cmd, "out")
		emit(ch, myDiskReadDesc, prometheus.CounterValue, float64(q.DiskReadBytes), cmd)
		emit(ch, myDiskWriteDesc, prometheus.CounterValue, float64(q.DiskWriteBytes), cmd)
		if ioWaitOK {
			emit(ch, myIOWaitDesc, prometheus.CounterValue, sec(q.IOWaitNs), cmd)
		}
		if redoWaitOK {
			emit(ch, myRedoWaitDesc, prometheus.CounterValue, sec(q.RedoWaitNs), cmd)
		}
	}
	emit(ch, myIOAvailDesc, prometheus.GaugeValue, boolGauge(ioWaitOK))
	emit(ch, myRedoAvailDesc, prometheus.GaugeValue, boolGauge(redoWaitOK))
	if s.QueryCPUCoveragePercent != nil {
		emit(ch, myQueryCoverageDesc, prometheus.GaugeValue, *s.QueryCPUCoveragePercent/100)
	}
	var exported []querystats.ExportedDigest
	switch c.mode {
	case config.DigestsOff:
	case config.DigestsMinimal:
		exported = unionTop(s.Exported, c.minimalTopN)
		var cpu, calls, disk, allCPU, allCalls, allDisk uint64
		for _, d := range exported {
			emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(d.Counters.CPUNs), d.ID)
			emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(d.Counters.Calls), d.ID)
			emit(ch, myDigestDiskReadDesc, prometheus.CounterValue, float64(d.Counters.DiskReadBytes), d.ID)
			emit(ch, myDigestInfoDesc, prometheus.GaugeValue, 1, d.ID, SanitizeLabel(d.Text, digestTextMaxBytes))
			cpu += d.Counters.CPUNs
			calls += d.Counters.Calls
			disk += d.Counters.DiskReadBytes
		}
		for _, q := range s.Commands {
			allCPU += q.CPUNs
			allCalls += q.Calls
			allDisk += q.DiskReadBytes
		}
		// "other" = everything not exported. It can drop when a digest
		// joins the exported set: a counter reset that rate() tolerates.
		emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(subFloor(allCPU, cpu)), "other")
		emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(subFloor(allCalls, calls)), "other")
		emit(ch, myDigestDiskReadDesc, prometheus.CounterValue, float64(subFloor(allDisk, disk)), "other")
	default: // config.DigestsFull
		exported = s.Exported
		for _, d := range exported {
			emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(d.Counters.CPUNs), d.ID)
			emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(d.Counters.Calls), d.ID)
			emit(ch, myDigestOutDesc, prometheus.CounterValue, float64(d.Counters.BytesOut), d.ID)
			emit(ch, myDigestRunqDesc, prometheus.CounterValue, sec(d.Counters.RunqNs), d.ID)
			emit(ch, myDigestDiskReadDesc, prometheus.CounterValue, float64(d.Counters.DiskReadBytes), d.ID)
			if ioWaitOK {
				emit(ch, myDigestIOWaitDesc, prometheus.CounterValue, sec(d.Counters.IOWaitNs), d.ID)
			}
			emit(ch, myDigestInfoDesc, prometheus.GaugeValue, 1, d.ID, SanitizeLabel(d.Text, digestTextMaxBytes))
		}
	}
	emit(ch, myCoverageDesc, prometheus.GaugeValue, coverage(c.mode, exported, s.QueryCPUMsTotal))
	h := c.health
	emit(ch, myDroppedDesc, prometheus.CounterValue, h.read(h.Dropped))
	emit(ch, myTextDroppedDesc, prometheus.CounterValue, h.read(h.TextDropped))
	emit(ch, myAggOverflowDesc, prometheus.CounterValue, h.read(h.AggOverflow))
	emit(ch, myHashMismatchDesc, prometheus.CounterValue, h.read(h.HashMismatches))
}

// unionTop: the top n by lifetime CPU plus the top n by lifetime disk read,
// sorted by ID. A ranking only admits digests with a non-zero value, so on a
// server with no disk reads minimal stays the top n by CPU.
func unionTop(in []querystats.ExportedDigest, n int) []querystats.ExportedDigest {
	byCPU := topBy(in, n, func(d querystats.ExportedDigest) uint64 { return d.Counters.CPUNs })
	byDisk := topBy(in, n, func(d querystats.ExportedDigest) uint64 { return d.Counters.DiskReadBytes })
	seen := map[string]bool{}
	var out []querystats.ExportedDigest
	for _, d := range append(byCPU, byDisk...) {
		if !seen[d.ID] {
			seen[d.ID] = true
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// topBy returns the n digests with the largest non-zero metric, ties broken
// by ID.
func topBy(in []querystats.ExportedDigest, n int, metric func(querystats.ExportedDigest) uint64) []querystats.ExportedDigest {
	out := make([]querystats.ExportedDigest, 0, len(in))
	for _, d := range in {
		if metric(d) > 0 {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if mi, mj := metric(out[i]), metric(out[j]); mi != mj {
			return mi > mj
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func subFloor(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// coverage: window CPU of the exported digests over all query CPU in the
// window. Always 0 in off mode; 1 on an idle server (nothing to explain).
func coverage(mode string, exp []querystats.ExportedDigest, totalMs float64) float64 {
	if mode == config.DigestsOff {
		return 0
	}
	if totalMs <= 0 {
		return 1
	}
	var ns uint64
	for _, d := range exp {
		ns += d.WindowCPUNs
	}
	return math.Min(1, float64(ns)/1e6/totalMs)
}
