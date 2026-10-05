package promcollect

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

func families() []model.FamilyStats {
	return []model.FamilyStats{
		{Family: "mysql.service", CPUPercent: 80, MemRSSBytes: 6000, ProcessCount: 1},
		{Family: "php-fpm.service", CPUPercent: 64, MemRSSBytes: 180, ProcessCount: 3},
		{Family: "cron.service", CPUPercent: 3, MemRSSBytes: 5, ProcessCount: 2},
	}
}

func TestFamilyGaugesFoldOverflowIntoOther(t *testing.T) {
	c := NewFamilyCollector(families, func() (netflow.Counters, bool) { return netflow.Counters{}, false }, 2)
	want := `
# HELP obs_agent_family_cpu_percent CPU usage of all processes in a process family (systemd unit), percent of total CPU.
# TYPE obs_agent_family_cpu_percent gauge
obs_agent_family_cpu_percent{family="mysql.service"} 80
obs_agent_family_cpu_percent{family="other"} 3
obs_agent_family_cpu_percent{family="php-fpm.service"} 64
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_cpu_percent"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_family_net_bytes_total"); n != 0 {
		t.Fatalf("net metrics must be absent when netflow is unavailable, got %d", n)
	}
}

func TestFamilyNetCounters(t *testing.T) {
	counters := netflow.Counters{
		Dir:      []netflow.FamilyDirCounter{{Family: "mysql.service", Direction: "inbound", BytesRx: 10, BytesTx: 900, Opened: 4, Active: 3}},
		Inbound:  []netflow.FamilyPortCounter{{Family: "mysql.service", ServicePort: 3306, BytesRx: 10, BytesTx: 900}},
		Outbound: []netflow.FamilyPeerCounter{{Family: "app.service", PeerIP: "10.0.5.2", ServicePort: 3306, BytesRx: 900, BytesTx: 10}},
	}
	c := NewFamilyCollector(families, func() (netflow.Counters, bool) { return counters, true }, 50)
	want := `
# HELP obs_agent_family_outbound_peer_bytes_total Outbound TCP bytes per process family, remote peer IP and remote service port.
# TYPE obs_agent_family_outbound_peer_bytes_total counter
obs_agent_family_outbound_peer_bytes_total{family="app.service",flow="rx",peer_ip="10.0.5.2",service_port="3306"} 900
obs_agent_family_outbound_peer_bytes_total{family="app.service",flow="tx",peer_ip="10.0.5.2",service_port="3306"} 10
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_outbound_peer_bytes_total"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_family_net_bytes_total"); n != 2 {
		t.Fatalf("net_bytes series = %d, want rx+tx = 2", n)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("pedantic gather: %v", err)
	}
}

// A family literally named "other" in the input, plus overflow, must yield a
// single family="other" series (duplicates fail a pedantic gather).
func TestFamilyLiteralOtherNoDuplicateSeries(t *testing.T) {
	in := func() []model.FamilyStats {
		return append(families(), model.FamilyStats{Family: "other", CPUPercent: 50, MemRSSBytes: 7, ProcessCount: 4})
	}
	c := NewFamilyCollector(in, func() (netflow.Counters, bool) { return netflow.Counters{}, false }, 2)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("pedantic gather: %v", err)
	}
	want := `
# HELP obs_agent_family_cpu_percent CPU usage of all processes in a process family (systemd unit), percent of total CPU.
# TYPE obs_agent_family_cpu_percent gauge
obs_agent_family_cpu_percent{family="mysql.service"} 80
obs_agent_family_cpu_percent{family="other"} 53
obs_agent_family_cpu_percent{family="php-fpm.service"} 64
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_cpu_percent"); err != nil {
		t.Fatal(err)
	}
}
