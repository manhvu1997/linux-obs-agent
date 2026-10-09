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
		"Bytes received (statement) and sent (result) per command class.", []string{"command", "flow"}, nil)
	myDigestCPUDesc = prometheus.NewDesc("obs_agent_mysql_digest_cpu_seconds_total",
		"On-CPU seconds spent executing statements of this digest.", []string{"digest_id"}, nil)
	myDigestCallsDesc = prometheus.NewDesc("obs_agent_mysql_digest_calls_total",
		"Executions of statements of this digest.", []string{"digest_id"}, nil)
	myDigestOutDesc = prometheus.NewDesc("obs_agent_mysql_digest_bytes_out_total",
		"Result bytes sent for statements of this digest.", []string{"digest_id"}, nil)
	myDigestRunqDesc = prometheus.NewDesc("obs_agent_mysql_digest_runq_wait_seconds_total",
		"Seconds statements of this digest waited for a CPU.", []string{"digest_id"}, nil)
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
		"Kernel text-hash verification samples whose digest differed from the cached one; the hash is switched to exact per-event processing.", nil, nil)
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
		myTextDroppedDesc, myAggOverflowDesc, myHashMismatchDesc} {
		ch <- d
	}
}

func (c *MySQLCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.snap()
	if s == nil {
		return
	}
	sec := func(ns uint64) float64 { return float64(ns) / 1e9 }
	for cmd, q := range s.Commands {
		emit(ch, myQueriesDesc, prometheus.CounterValue, float64(q.Calls), cmd)
		emit(ch, myCPUDesc, prometheus.CounterValue, sec(q.CPUNs), cmd)
		emit(ch, myRunqDesc, prometheus.CounterValue, sec(q.RunqNs), cmd)
		emit(ch, myWallDesc, prometheus.CounterValue, sec(q.WallNs), cmd)
		emit(ch, myBytesDesc, prometheus.CounterValue, float64(q.BytesIn), cmd, "in")
		emit(ch, myBytesDesc, prometheus.CounterValue, float64(q.BytesOut), cmd, "out")
	}
	var exported []querystats.ExportedDigest
	switch c.mode {
	case config.DigestsOff:
	case config.DigestsMinimal:
		exported = topExported(s.Exported, c.minimalTopN)
		var cpu, calls, allCPU, allCalls uint64
		for _, d := range exported {
			emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(d.Counters.CPUNs), d.ID)
			emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(d.Counters.Calls), d.ID)
			emit(ch, myDigestInfoDesc, prometheus.GaugeValue, 1, d.ID, SanitizeLabel(d.Text, digestTextMaxBytes))
			cpu += d.Counters.CPUNs
			calls += d.Counters.Calls
		}
		for _, q := range s.Commands {
			allCPU += q.CPUNs
			allCalls += q.Calls
		}
		// "other" = everything not exported. It can drop when a digest
		// joins the exported set: a counter reset that rate() tolerates.
		emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(subFloor(allCPU, cpu)), "other")
		emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(subFloor(allCalls, calls)), "other")
	default: // config.DigestsFull
		exported = s.Exported
		for _, d := range exported {
			emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(d.Counters.CPUNs), d.ID)
			emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(d.Counters.Calls), d.ID)
			emit(ch, myDigestOutDesc, prometheus.CounterValue, float64(d.Counters.BytesOut), d.ID)
			emit(ch, myDigestRunqDesc, prometheus.CounterValue, sec(d.Counters.RunqNs), d.ID)
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

func topExported(in []querystats.ExportedDigest, n int) []querystats.ExportedDigest {
	out := append([]querystats.ExportedDigest(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Counters.CPUNs != out[j].Counters.CPUNs {
			return out[i].Counters.CPUNs > out[j].Counters.CPUNs
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
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
