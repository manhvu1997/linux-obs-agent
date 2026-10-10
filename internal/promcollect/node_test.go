package promcollect

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestNodeCollector(t *testing.T) {
	var m model.NodeMetrics
	m.Pressure.IO.Available, m.Pressure.IO.Full.Avg10, m.Pressure.IO.Some.Avg10 = true, 12.5, 30
	c := NewNodeCollector(func() (collector.NodeDiskBytes, error) {
		return collector.NodeDiskBytes{ReadBytes: 1 << 20, WriteBytes: 2 << 20, Disks: 2}, nil
	}, func() model.NodeMetrics { return m })
	want := `
# HELP obs_agent_node_disk_read_bytes_total Bytes read by the node's physical disks (whole devices without slaves; no loop, zram, dm or md).
# TYPE obs_agent_node_disk_read_bytes_total counter
obs_agent_node_disk_read_bytes_total 1.048576e+06
# HELP obs_agent_node_disk_write_bytes_total Bytes written by the node's physical disks (whole devices without slaves; no loop, zram, dm or md).
# TYPE obs_agent_node_disk_write_bytes_total counter
obs_agent_node_disk_write_bytes_total 2.097152e+06
# HELP obs_agent_node_physical_disks Number of physical disks counted in obs_agent_node_disk_*_bytes_total.
# TYPE obs_agent_node_physical_disks gauge
obs_agent_node_physical_disks 2
# HELP obs_agent_pressure_io_full_avg10 PSI io full avg10 (percent of time no task could progress because of I/O), from /proc/pressure/io.
# TYPE obs_agent_pressure_io_full_avg10 gauge
obs_agent_pressure_io_full_avg10 12.5
# HELP obs_agent_pressure_io_some_avg10 PSI io some avg10 (percent of time at least one task waited for I/O), from /proc/pressure/io.
# TYPE obs_agent_pressure_io_some_avg10 gauge
obs_agent_pressure_io_some_avg10 30
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_node_disk_read_bytes_total", "obs_agent_node_disk_write_bytes_total", "obs_agent_node_physical_disks",
		"obs_agent_pressure_io_full_avg10", "obs_agent_pressure_io_some_avg10"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_pressure_cpu_some_avg10"); n != 0 {
		t.Fatal("PSI cpu unavailable: no series")
	}
}

func TestNodeCollectorCPUPressure(t *testing.T) {
	var m model.NodeMetrics
	m.Pressure.CPU.Available, m.Pressure.CPU.Some.Avg10 = true, 7.5
	c := NewNodeCollector(func() (collector.NodeDiskBytes, error) { return collector.NodeDiskBytes{}, nil },
		func() model.NodeMetrics { return m })
	want := `
# HELP obs_agent_pressure_cpu_some_avg10 PSI cpu some avg10 (percent of time at least one runnable task waited for a CPU), from /proc/pressure/cpu.
# TYPE obs_agent_pressure_cpu_some_avg10 gauge
obs_agent_pressure_cpu_some_avg10 7.5
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_pressure_cpu_some_avg10"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_pressure_io_full_avg10"); n != 0 {
		t.Fatal("PSI io unavailable: no series")
	}
}

func TestNodeCollectorDiskError(t *testing.T) {
	c := NewNodeCollector(func() (collector.NodeDiskBytes, error) { return collector.NodeDiskBytes{}, errors.New("no diskstats") },
		func() model.NodeMetrics { return model.NodeMetrics{} })
	if n := testutil.CollectAndCount(c, "obs_agent_node_disk_read_bytes_total"); n != 0 {
		t.Fatal("unreadable diskstats: no series (never a 0 counter)")
	}
	if n := testutil.CollectAndCount(c, "obs_agent_node_physical_disks"); n != 0 {
		t.Fatal("unreadable diskstats: no disk count")
	}
}
