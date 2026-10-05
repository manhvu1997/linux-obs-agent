// Package promcollect exposes process-family and MySQL digest data as
// Prometheus metrics. Collectors read analyzer snapshots at scrape time, so
// a label that disappears from the snapshot disappears from /metrics.
package promcollect

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

var (
	famCPUDesc = prometheus.NewDesc("obs_agent_family_cpu_percent",
		"CPU usage of all processes in a process family (systemd unit), percent of total CPU.", []string{"family"}, nil)
	famMemDesc = prometheus.NewDesc("obs_agent_family_mem_rss_bytes",
		"Resident memory of all processes in a process family.", []string{"family"}, nil)
	famProcsDesc = prometheus.NewDesc("obs_agent_family_processes",
		"Number of processes in a process family.", []string{"family"}, nil)
	famNetBytesDesc = prometheus.NewDesc("obs_agent_family_net_bytes_total",
		"TCP bytes per process family, direction (inbound = accepted, outbound = initiated) and flow (rx|tx).",
		[]string{"family", "direction", "flow"}, nil)
	famOpenedDesc = prometheus.NewDesc("obs_agent_family_net_connections_opened_total",
		"TCP connections opened per process family and direction.", []string{"family", "direction"}, nil)
	famActiveDesc = prometheus.NewDesc("obs_agent_family_net_connections_active",
		"Open TCP connections per process family and direction, as tracked by eBPF.", []string{"family", "direction"}, nil)
	famInDesc = prometheus.NewDesc("obs_agent_family_inbound_bytes_total",
		"Inbound TCP bytes per process family and local service port.", []string{"family", "service_port", "flow"}, nil)
	famOutDesc = prometheus.NewDesc("obs_agent_family_outbound_peer_bytes_total",
		"Outbound TCP bytes per process family, remote peer IP and remote service port.",
		[]string{"family", "peer_ip", "service_port", "flow"}, nil)
)

// FamilyCollector exports family gauges and netflow counters.
type FamilyCollector struct {
	families    func() []model.FamilyStats
	counters    func() (netflow.Counters, bool)
	maxFamilies int
}

func NewFamilyCollector(families func() []model.FamilyStats, counters func() (netflow.Counters, bool), maxFamilies int) *FamilyCollector {
	if maxFamilies < 1 {
		maxFamilies = 50
	}
	return &FamilyCollector{families: families, counters: counters, maxFamilies: maxFamilies}
}

func (c *FamilyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{famCPUDesc, famMemDesc, famProcsDesc, famNetBytesDesc, famOpenedDesc, famActiveDesc, famInDesc, famOutDesc} {
		ch <- d
	}
}

func (c *FamilyCollector) Collect(ch chan<- prometheus.Metric) {
	// Copy: never reorder the caller's slice.
	fams := append([]model.FamilyStats(nil), c.families()...)
	sort.SliceStable(fams, func(i, j int) bool {
		if fams[i].CPUPercent != fams[j].CPUPercent {
			return fams[i].CPUPercent > fams[j].CPUPercent
		}
		return fams[i].Family < fams[j].Family
	})
	var other model.FamilyStats
	haveOther := false
	seen := 0
	for _, f := range fams {
		label := SanitizeLabel(f.Family, 200)
		if label == "other" || seen >= c.maxFamilies {
			other.CPUPercent += f.CPUPercent
			other.MemRSSBytes += f.MemRSSBytes
			other.ProcessCount += f.ProcessCount
			haveOther = true
			continue
		}
		seen++
		emitFamily(ch, label, f)
	}
	if haveOther {
		emitFamily(ch, "other", other)
	}

	nc, ok := c.counters()
	if !ok {
		return
	}
	for _, d := range nc.Dir {
		fam := SanitizeLabel(d.Family, 200)
		ch <- prometheus.MustNewConstMetric(famNetBytesDesc, prometheus.CounterValue, float64(d.BytesRx), fam, d.Direction, "rx")
		ch <- prometheus.MustNewConstMetric(famNetBytesDesc, prometheus.CounterValue, float64(d.BytesTx), fam, d.Direction, "tx")
		ch <- prometheus.MustNewConstMetric(famOpenedDesc, prometheus.CounterValue, float64(d.Opened), fam, d.Direction)
		ch <- prometheus.MustNewConstMetric(famActiveDesc, prometheus.GaugeValue, float64(d.Active), fam, d.Direction)
	}
	for _, p := range nc.Inbound {
		fam, port := SanitizeLabel(p.Family, 200), strconv.Itoa(int(p.ServicePort))
		ch <- prometheus.MustNewConstMetric(famInDesc, prometheus.CounterValue, float64(p.BytesRx), fam, port, "rx")
		ch <- prometheus.MustNewConstMetric(famInDesc, prometheus.CounterValue, float64(p.BytesTx), fam, port, "tx")
	}
	for _, p := range nc.Outbound {
		fam, port := SanitizeLabel(p.Family, 200), strconv.Itoa(int(p.ServicePort))
		ch <- prometheus.MustNewConstMetric(famOutDesc, prometheus.CounterValue, float64(p.BytesRx), fam, p.PeerIP, port, "rx")
		ch <- prometheus.MustNewConstMetric(famOutDesc, prometheus.CounterValue, float64(p.BytesTx), fam, p.PeerIP, port, "tx")
	}
}

func emitFamily(ch chan<- prometheus.Metric, label string, f model.FamilyStats) {
	ch <- prometheus.MustNewConstMetric(famCPUDesc, prometheus.GaugeValue, f.CPUPercent, label)
	ch <- prometheus.MustNewConstMetric(famMemDesc, prometheus.GaugeValue, float64(f.MemRSSBytes), label)
	ch <- prometheus.MustNewConstMetric(famProcsDesc, prometheus.GaugeValue, float64(f.ProcessCount), label)
}

// SanitizeLabel returns s as valid UTF-8 of at most max bytes, never
// splitting a multi-byte rune. Invalid UTF-8 in a label value makes the
// whole /metrics scrape fail, so every free-text label goes through this.
func SanitizeLabel(s string, max int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= max {
		return s
	}
	cut := 0
	for i, r := range s {
		if i+utf8.RuneLen(r) > max {
			break
		}
		cut = i + utf8.RuneLen(r)
	}
	return s[:cut]
}
