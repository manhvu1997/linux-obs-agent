// internal/netflow/analyzer.go
package netflow

import (
	"context"
	"log/slog"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/netinv"
)

// ListenLister lists LISTEN sockets (implemented by *netinv.Inventory).
type ListenLister interface {
	Listening() ([]netinv.Socket, error)
}

// FamilyLookup maps PIDs to families (implemented by *process.Inspector).
type FamilyLookup interface {
	PIDFamilies() map[uint32]string
}

// Analyzer polls a Source into an Accumulator and keeps the kernel's
// listen_ports map current so lazily adopted sockets get the right direction.
type Analyzer struct {
	src         Source
	inv         ListenLister
	procs       FamilyLookup
	acc         *Accumulator
	poll        time.Duration
	listenEvery time.Duration
}

func NewAnalyzer(src Source, inv ListenLister, procs FamilyLookup, acc *Accumulator, poll, listenEvery time.Duration) *Analyzer {
	return &Analyzer{src: src, inv: inv, procs: procs, acc: acc, poll: poll, listenEvery: listenEvery}
}

// Run blocks until ctx is cancelled.
func (a *Analyzer) Run(ctx context.Context) {
	a.RefreshListen()
	pt := time.NewTicker(a.poll)
	defer pt.Stop()
	lt := time.NewTicker(a.listenEvery)
	defer lt.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-pt.C:
			a.PollOnce(now)
		case <-lt.C:
			a.RefreshListen()
		}
	}
}

// PollOnce reads the kernel map once. A failed read is logged and skipped;
// counters are never reset.
func (a *Analyzer) PollOnce(now time.Time) {
	flows, err := a.src.ReadFlows()
	if err != nil {
		slog.Warn("netflow: reading flow map", "err", err)
		return
	}
	a.acc.Ingest(now, flows, a.procs.PIDFamilies())
}

// RefreshListen pushes the host's listening ports into the kernel map.
func (a *Analyzer) RefreshListen() {
	socks, err := a.inv.Listening()
	if err != nil {
		slog.Warn("netflow: listing listening sockets", "err", err)
		return
	}
	if err := a.src.SetListenPorts(netinv.ListenPorts(socks)); err != nil {
		slog.Warn("netflow: updating listen_ports map", "err", err)
	}
}
