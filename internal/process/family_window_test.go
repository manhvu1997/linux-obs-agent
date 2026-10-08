package process

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestFamilyDrainDisabled(t *testing.T) {
	i := NewInspector(&config.ProcessConfig{})
	i.observeFamilies([]model.FamilyStats{{Family: "a", CPUPercent: 1}})
	if got := i.DrainFamilies(); got != nil {
		t.Fatalf("disabled drain returned %+v", got)
	}
}

func TestFamilyDrainAvgMax(t *testing.T) {
	i := NewInspector(&config.ProcessConfig{})
	i.EnableFamilyDrain()
	i.observeFamilies([]model.FamilyStats{
		{Family: "a.service", CPUPercent: 10, MemRSSBytes: 100, ProcessCount: 2},
		{Family: "b.service", CPUPercent: 1, MemRSSBytes: 5, ProcessCount: 1},
	})
	i.observeFamilies([]model.FamilyStats{
		{Family: "a.service", CPUPercent: 30, MemRSSBytes: 80, ProcessCount: 3},
	})
	got := i.DrainFamilies()
	if len(got) != 2 || got[0].Family != "a.service" || got[1].Family != "b.service" {
		t.Fatalf("got %+v", got)
	}
	a := got[0]
	if a.CPUPercentAvg != 20 || a.CPUPercentMax != 30 || a.RSSBytesMax != 100 || a.ProcessesMax != 3 {
		t.Fatalf("a.service = %+v", a)
	}
	if again := i.DrainFamilies(); again != nil {
		t.Fatalf("second drain = %+v, want nil", again)
	}
}
