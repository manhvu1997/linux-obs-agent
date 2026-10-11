package promcollect

import "github.com/prometheus/client_golang/prometheus"

var hostInfoDesc = prometheus.NewDesc("obs_agent_host_info",
	"Always 1; host is agent.node_name, else the OS hostname (the ClickHouse host column). Join on instance to show hostnames.",
	[]string{"host"}, nil)

// HostInfoCollector exports obs_agent_host_info{host} so dashboards can select
// and label agents by hostname instead of instance (IP:port).
type HostInfoCollector struct{ host string }

func NewHostInfoCollector(host string) *HostInfoCollector { return &HostInfoCollector{host: host} }

func (c *HostInfoCollector) Describe(ch chan<- *prometheus.Desc) { ch <- hostInfoDesc }

func (c *HostInfoCollector) Collect(ch chan<- prometheus.Metric) {
	if c.host == "" {
		return
	}
	emit(ch, hostInfoDesc, prometheus.GaugeValue, 1, c.host)
}
