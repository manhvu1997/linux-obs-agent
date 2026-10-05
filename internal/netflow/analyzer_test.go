package netflow

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/netinv"
)

type fakeSource struct {
	flows  map[FlowKey]FlowValue
	err    error
	listen []uint16
}

func (f *fakeSource) ReadFlows() (map[FlowKey]FlowValue, error) { return f.flows, f.err }
func (f *fakeSource) SetListenPorts(p []uint16) error           { f.listen = p; return nil }
func (f *fakeSource) InboundAccounting() string                 { return "accept" }

type fakeInv struct{ socks []netinv.Socket }

func (f fakeInv) Listening() ([]netinv.Socket, error) { return f.socks, nil }

type fakeProcs map[uint32]string

func (f fakeProcs) PIDFamilies() map[uint32]string { return f }

func TestAnalyzerPollAndListen(t *testing.T) {
	src := &fakeSource{flows: map[FlowKey]FlowValue{k(7, Inbound, "10.0.0.9", 3306): {BytesRx: 42}}}
	inv := fakeInv{socks: []netinv.Socket{{State: "LISTEN", Local: netip.MustParseAddrPort("0.0.0.0:3306")}}}
	acc := NewAccumulator(cfg())
	an := NewAnalyzer(src, inv, fakeProcs{7: "mysql.service"}, acc, 5*time.Second, 30*time.Second)

	an.RefreshListen()
	if len(src.listen) != 1 || src.listen[0] != 3306 {
		t.Fatalf("listen ports pushed = %v", src.listen)
	}
	an.PollOnce(t0)
	if got := acc.Family("mysql.service").Inbound.BytesRx; got != 42 {
		t.Fatalf("family rx = %d", got)
	}

	src.err = errors.New("map read failed")
	an.PollOnce(t0.Add(5 * time.Second)) // must not panic or reset counters
	if got := acc.Counters().Dir[0].BytesRx; got != 42 {
		t.Fatalf("counter after failed poll = %d", got)
	}
}
