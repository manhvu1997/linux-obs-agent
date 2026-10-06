package mysql

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
)

func TestSampleQueriesOptOut(t *testing.T) {
	ev := mysqlq.CmdEvent{PID: 1, Command: cmdmap.ComQuery, Query: "CREATE USER u IDENTIFIED BY 'secret'", QueryLen: 36}
	for _, keep := range []bool{true, false} {
		cfg := config.Defaults().MySQL
		cfg.SampleQueries = keep
		a := NewAnalyzer(&cfg, nil)
		e := a.toEvent(ev, time.Unix(0, 0))
		if keep && e.SampleQuery == "" {
			t.Fatal("sample_queries=true: SampleQuery must be kept")
		}
		if !keep && e.SampleQuery != "" {
			t.Fatalf("sample_queries=false: SampleQuery = %q, want empty", e.SampleQuery)
		}
		if e.Digest.ID == "" {
			t.Fatal("digest must be computed regardless of sample_queries")
		}
	}
}
