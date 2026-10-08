package process

import (
	"sort"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// FamilyWindow is one family's resource use over a ClickHouse flush
// interval, folded from every scan in which the family had processes.
type FamilyWindow struct {
	Family        string
	CPUPercentAvg float64
	CPUPercentMax float64
	RSSBytesMax   uint64
	ProcessesMax  int
}

type famAcc struct {
	cpuSum, cpuMax float64
	scans          int
	rssMax         uint64
	procsMax       int
}

// EnableFamilyDrain starts folding family scans for DrainFamilies.
func (i *Inspector) EnableFamilyDrain() {
	i.drainMu.Lock()
	defer i.drainMu.Unlock()
	if i.famDrain == nil {
		i.famDrain = make(map[string]*famAcc)
	}
}

func (i *Inspector) observeFamilies(fams []model.FamilyStats) {
	i.drainMu.Lock()
	defer i.drainMu.Unlock()
	if i.famDrain == nil {
		return
	}
	for _, f := range fams {
		a := i.famDrain[f.Family]
		if a == nil {
			a = &famAcc{}
			i.famDrain[f.Family] = a
		}
		a.cpuSum += f.CPUPercent
		a.cpuMax = max(a.cpuMax, f.CPUPercent)
		a.scans++
		a.rssMax = max(a.rssMax, f.MemRSSBytes)
		a.procsMax = max(a.procsMax, f.ProcessCount)
	}
}

// DrainFamilies returns one window per family seen since the previous call,
// sorted by family name, and resets the accumulator. nil when disabled or
// when no scan completed in the interval.
func (i *Inspector) DrainFamilies() []FamilyWindow {
	i.drainMu.Lock()
	m := i.famDrain
	if m != nil {
		i.famDrain = make(map[string]*famAcc, len(m))
	}
	i.drainMu.Unlock()
	if len(m) == 0 {
		return nil
	}
	out := make([]FamilyWindow, 0, len(m))
	for name, a := range m {
		out = append(out, FamilyWindow{
			Family: name, CPUPercentAvg: a.cpuSum / float64(a.scans), CPUPercentMax: a.cpuMax,
			RSSBytesMax: a.rssMax, ProcessesMax: a.procsMax,
		})
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Family < out[y].Family })
	return out
}
