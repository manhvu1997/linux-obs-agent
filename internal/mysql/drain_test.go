package mysql

import (
	"testing"

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
	if len(got) != 1 || got[0].PID != 2 || dropped != 0 {
		t.Fatalf("got %+v dropped %d", got, dropped)
	}
	if len(a.recentSlowQueries) != 2 {
		t.Fatalf("recent ring = %d, want both events", len(a.recentSlowQueries))
	}
}
