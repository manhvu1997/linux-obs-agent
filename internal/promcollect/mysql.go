package promcollect

import (
	"github.com/prometheus/client_golang/prometheus"

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
	myDroppedDesc = prometheus.NewDesc("obs_agent_mysql_events_dropped_total",
		"Per-statement events lost (ring buffer full or consumer behind); digest totals undercount when this rises.", nil, nil)
)

// MySQLCollector exports MySQL command and sticky-digest counters.
type MySQLCollector struct {
	snap    func() *querystats.Snapshot
	dropped func() uint64
}

func NewMySQLCollector(snap func() *querystats.Snapshot, dropped func() uint64) *MySQLCollector {
	return &MySQLCollector{snap: snap, dropped: dropped}
}

func (c *MySQLCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{myQueriesDesc, myCPUDesc, myRunqDesc, myWallDesc, myBytesDesc,
		myDigestCPUDesc, myDigestCallsDesc, myDigestOutDesc, myDigestRunqDesc, myDigestInfoDesc, myDroppedDesc} {
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
	for _, d := range s.Exported {
		emit(ch, myDigestCPUDesc, prometheus.CounterValue, sec(d.Counters.CPUNs), d.ID)
		emit(ch, myDigestCallsDesc, prometheus.CounterValue, float64(d.Counters.Calls), d.ID)
		emit(ch, myDigestOutDesc, prometheus.CounterValue, float64(d.Counters.BytesOut), d.ID)
		emit(ch, myDigestRunqDesc, prometheus.CounterValue, sec(d.Counters.RunqNs), d.ID)
		emit(ch, myDigestInfoDesc, prometheus.GaugeValue, 1, d.ID, SanitizeLabel(d.Text, digestTextMaxBytes))
	}
	emit(ch, myDroppedDesc, prometheus.CounterValue, float64(c.dropped()))
}
