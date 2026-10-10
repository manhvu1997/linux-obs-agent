package promcollect

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

var (
	nodeDiskReadDesc = prometheus.NewDesc("obs_agent_node_disk_read_bytes_total",
		"Bytes read by the node's physical disks (whole devices without slaves; no loop, zram, dm or md).", nil, nil)
	nodeDiskWriteDesc = prometheus.NewDesc("obs_agent_node_disk_write_bytes_total",
		"Bytes written by the node's physical disks (whole devices without slaves; no loop, zram, dm or md).", nil, nil)
	nodeDisksDesc = prometheus.NewDesc("obs_agent_node_physical_disks",
		"Number of physical disks counted in obs_agent_node_disk_*_bytes_total.", nil, nil)
	psiIOFullDesc = prometheus.NewDesc("obs_agent_pressure_io_full_avg10",
		"PSI io full avg10 (percent of time no task could progress because of I/O), from /proc/pressure/io.", nil, nil)
	psiIOSomeDesc = prometheus.NewDesc("obs_agent_pressure_io_some_avg10",
		"PSI io some avg10 (percent of time at least one task waited for I/O), from /proc/pressure/io.", nil, nil)
	psiCPUSomeDesc = prometheus.NewDesc("obs_agent_pressure_cpu_some_avg10",
		"PSI cpu some avg10 (percent of time at least one runnable task waited for a CPU), from /proc/pressure/cpu.", nil, nil)
)

// NodeCollector exports node-wide disk counters (read at scrape time) and
// PSI gauges (from the collector's latest sample, only when available).
type NodeCollector struct {
	disk    func() (collector.NodeDiskBytes, error)
	metrics func() model.NodeMetrics
}

func NewNodeCollector(disk func() (collector.NodeDiskBytes, error), metrics func() model.NodeMetrics) *NodeCollector {
	return &NodeCollector{disk: disk, metrics: metrics}
}

func (c *NodeCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{nodeDiskReadDesc, nodeDiskWriteDesc, nodeDisksDesc, psiIOFullDesc, psiIOSomeDesc, psiCPUSomeDesc} {
		ch <- d
	}
}

func (c *NodeCollector) Collect(ch chan<- prometheus.Metric) {
	// An unreadable /proc/diskstats yields no series, never a 0 counter
	// (a drop to 0 would read as a counter reset).
	if d, err := c.disk(); err == nil {
		emit(ch, nodeDiskReadDesc, prometheus.CounterValue, float64(d.ReadBytes))
		emit(ch, nodeDiskWriteDesc, prometheus.CounterValue, float64(d.WriteBytes))
		emit(ch, nodeDisksDesc, prometheus.GaugeValue, float64(d.Disks))
	}
	p := c.metrics().Pressure
	if p.IO.Available {
		emit(ch, psiIOFullDesc, prometheus.GaugeValue, p.IO.Full.Avg10)
		emit(ch, psiIOSomeDesc, prometheus.GaugeValue, p.IO.Some.Avg10)
	}
	if p.CPU.Available {
		emit(ch, psiCPUSomeDesc, prometheus.GaugeValue, p.CPU.Some.Avg10)
	}
}
