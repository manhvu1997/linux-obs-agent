package promcollect

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestHostInfoCollector(t *testing.T) {
	want := `
# HELP obs_agent_host_info Always 1; host is agent.node_name, else the OS hostname (the ClickHouse host column). Join on instance to show hostnames.
# TYPE obs_agent_host_info gauge
obs_agent_host_info{host="db-01"} 1
`
	if err := testutil.CollectAndCompare(NewHostInfoCollector("db-01"), strings.NewReader(want), "obs_agent_host_info"); err != nil {
		t.Fatal(err)
	}
}

func TestHostInfoCollectorEmptyHost(t *testing.T) {
	if n := testutil.CollectAndCount(NewHostInfoCollector(""), "obs_agent_host_info"); n != 0 {
		t.Fatalf("empty host emitted %d series, want 0", n)
	}
}
