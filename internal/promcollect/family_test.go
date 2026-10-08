package promcollect

import (
	"strings"
	"testing"
	"unicode/utf8"

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

// ServicePort 0 is the accumulator's folded "other" bucket for outbound
// service ports beyond its budget.
func TestFamilyOutboundPortZeroRendersOther(t *testing.T) {
	counters := netflow.Counters{
		Outbound: []netflow.FamilyPeerCounter{{Family: "app.service", PeerIP: "10.0.5.2", ServicePort: 0, BytesRx: 5, BytesTx: 6}},
	}
	c := NewFamilyCollector(families, func() (netflow.Counters, bool) { return counters, true }, 50)
	want := `
# HELP obs_agent_family_outbound_peer_bytes_total Outbound TCP bytes per process family, remote peer IP and remote service port.
# TYPE obs_agent_family_outbound_peer_bytes_total counter
obs_agent_family_outbound_peer_bytes_total{family="app.service",flow="rx",peer_ip="10.0.5.2",service_port="other"} 5
obs_agent_family_outbound_peer_bytes_total{family="app.service",flow="tx",peer_ip="10.0.5.2",service_port="other"} 6
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_outbound_peer_bytes_total"); err != nil {
		t.Fatal(err)
	}
}

// Family names come from raw cgroup/unit names; invalid UTF-8 must never
// break the scrape or crash the agent, on the gauge path or the counters.
func TestFamilyInvalidUTF8Label(t *testing.T) {
	bad := "a\xffpp.service"
	fams := func() []model.FamilyStats {
		return []model.FamilyStats{{Family: bad, CPUPercent: 5, MemRSSBytes: 1, ProcessCount: 1}}
	}
	counters := netflow.Counters{
		Dir:      []netflow.FamilyDirCounter{{Family: bad, Direction: "outbound", BytesTx: 1}},
		Inbound:  []netflow.FamilyPortCounter{{Family: bad, ServicePort: 80, BytesRx: 1}},
		Outbound: []netflow.FamilyPeerCounter{{Family: bad, PeerIP: "10.0.5.2", ServicePort: 3306, BytesTx: 1}},
	}
	c := NewFamilyCollector(fams, func() (netflow.Counters, bool) { return counters, true }, 50)
	for name, perSeries := range map[string]int{
		"obs_agent_family_cpu_percent":               1,
		"obs_agent_family_net_bytes_total":           2,
		"obs_agent_family_inbound_bytes_total":       2,
		"obs_agent_family_outbound_peer_bytes_total": 2,
	} {
		vals := gatherOne(t, c, name, "family")
		if len(vals) != perSeries {
			t.Fatalf("%s: %d series, want %d", name, len(vals), perSeries)
		}
		for _, v := range vals {
			if !utf8.ValidString(v) || v != "a?pp.service" {
				t.Fatalf("%s: family label %q, want valid %q", name, v, "a?pp.service")
			}
		}
	}
}

func TestFamilyCollectorInboundPeers(t *testing.T) {
	counters := func() (netflow.Counters, bool) {
		return netflow.Counters{InboundPeers: []netflow.FamilyPeerCounter{
			{Family: "mysql.service", PeerIP: "10.0.0.2", ServicePort: 3306, BytesRx: 100, BytesTx: 900},
		}}, true
	}
	c := NewFamilyCollector(func() []model.FamilyStats { return nil }, counters, 50)
	want := `
# HELP obs_agent_family_inbound_peer_bytes_total Inbound TCP bytes per process family, client peer IP and local service port.
# TYPE obs_agent_family_inbound_peer_bytes_total counter
obs_agent_family_inbound_peer_bytes_total{family="mysql.service",flow="rx",peer_ip="10.0.0.2",service_port="3306"} 100
obs_agent_family_inbound_peer_bytes_total{family="mysql.service",flow="tx",peer_ip="10.0.0.2",service_port="3306"} 900
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_inbound_peer_bytes_total"); err != nil {
		t.Fatal(err)
	}
}
