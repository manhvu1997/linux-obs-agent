package process

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestOnScanReceivesEveryScan(t *testing.T) {
	i := NewInspector(&config.ProcessConfig{})
	var got []model.ProcessStats
	var at time.Time
	i.OnScan(func(all []model.ProcessStats, t time.Time) { got, at = all, t })
	now := time.Unix(5, 0)
	i.notifyScan([]model.ProcessStats{{PID: 7}}, now)
	if len(got) != 1 || got[0].PID != 7 || !at.Equal(now) {
		t.Fatalf("got %+v at %v", got, at)
	}
}
