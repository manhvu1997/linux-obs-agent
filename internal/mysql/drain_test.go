package mysql

import (
	"testing"
	"time"

	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestSlowDrainReceivesRecordedEvents(t *testing.T) {
	cfg := config.Defaults().MySQL
	a := NewAnalyzer(&cfg, nil)
	a.recordSlow(model.MySQLSlowEvent{PID: 1, Query: "select 1"}) // before enable: not drained
	a.EnableSlowDrain(10)
	a.recordSlow(model.MySQLSlowEvent{PID: 2, Query: "select 2"})
	got, dropped := a.DrainSlowQueries()
	if len(got) != 1 || got[0].Event.PID != 2 || dropped != 0 {
		t.Fatalf("got %+v dropped %d", got, dropped)
	}
	if len(a.recentSlowQueries) != 2 {
		t.Fatalf("recent ring = %d, want both events", len(a.recentSlowQueries))
	}
}

// The slow path must assign the same digest id the command path would.
func TestSlowDigestIDMatchesCommandPath(t *testing.T) {
	cfg := config.Defaults().MySQL
	cfg.FoldSystemSchemas = true
	a := NewAnalyzer(&cfg, nil)
	a.EnableSlowDrain(10)

	sys := "select * from information_schema.tables where table_name = 'x'"
	cases := []struct {
		cmd   uint32
		query string
	}{
		{cmdmap.ComQuery, sys},
		{cmdmap.ComQuery, ""},
		{cmdmap.ComStmtExecute, ""},
		{cmdmap.ComQuery, "select * from users where id = 7"},
	}
	for _, c := range cases {
		a.recordSlow(model.MySQLSlowEvent{Query: cmdmap.SlowQueryText(c.cmd, c.query, true)})
	}
	got, _ := a.DrainSlowQueries()
	for i, c := range cases {
		want := a.toEvent(mysqlq.CmdEvent{Command: c.cmd, Query: c.query, QueryLen: uint32(len(c.query))}, time.Now(), true).Digest.ID
		if got[i].DigestID != want {
			t.Errorf("case %d: slow id %s, command-path id %s", i, got[i].DigestID, want)
		}
	}
}
