package netflow

import (
	"net/netip"
	"testing"
	"time"
)

func TestFlowDrainDisabled(t *testing.T) {
	a := NewAccumulator(cfg())
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.2", 3306): {BytesTx: 5}}, nil)
	if out, folded := a.DrainFlows(); out != nil || folded != 0 {
		t.Fatalf("disabled drain returned %v, %d", out, folded)
	}
}

func TestFlowDrainSumsPollsAndResets(t *testing.T) {
	a := NewAccumulator(cfg())
	a.EnableDrain(100)
	key := k(10, Outbound, "10.0.5.2", 3306)
	fam := map[uint32]string{10: "app.service"}
	// The first poll is a window baseline for process_report, but it is real
	// traffic since the eBPF map was loaded, so the drain keeps it.
	a.Ingest(t0, map[FlowKey]FlowValue{key: {BytesTx: 100, Opened: 1}}, fam)
	a.Ingest(t0.Add(5*time.Second), map[FlowKey]FlowValue{key: {BytesTx: 150, Opened: 1}}, fam)
	first, _ := a.DrainFlows()
	a.Ingest(t0.Add(10*time.Second), map[FlowKey]FlowValue{key: {BytesTx: 170, Opened: 1, Closed: 1}}, fam)
	second, _ := a.DrainFlows()

	if len(first) != 1 || first[0].BytesTx != 150 || first[0].Opened != 1 ||
		first[0].Family != "app.service" || first[0].Direction != "outbound" || first[0].ServicePort != 3306 {
		t.Fatalf("first = %+v", first)
	}
	if len(second) != 1 || second[0].BytesTx != 20 || second[0].Closed != 1 || second[0].Opened != 0 {
		t.Fatalf("second = %+v", second)
	}
}

func TestFlowDrainUsesRawFamilyNames(t *testing.T) {
	c := cfg()
	c.MaxFamilies = 1 // Prometheus budget: the second family becomes "other"
	a := NewAccumulator(c)
	a.EnableDrain(100)
	fam := map[uint32]string{1: "a.service", 2: "b.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Inbound, "10.0.0.9", 80):  {BytesRx: 1},
		k(2, Inbound, "10.0.0.9", 443): {BytesRx: 1},
	}, fam)
	out, _ := a.DrainFlows()
	got := map[string]bool{}
	for _, f := range out {
		got[f.Family] = true
	}
	if !got["a.service"] || !got["b.service"] || got["other"] {
		t.Fatalf("families = %v, want raw names without \"other\"", got)
	}
}

func TestFlowDrainCapFolds(t *testing.T) {
	a := NewAccumulator(cfg())
	a.EnableDrain(1)
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Outbound, "10.0.0.2", 3306): {BytesTx: 10},
		k(1, Outbound, "10.0.0.3", 3306): {BytesTx: 20},
	}, nil)
	out, folded := a.DrainFlows()
	if folded != 1 || len(out) != 2 {
		t.Fatalf("folded=%d out=%+v", folded, out)
	}
	var total uint64
	var overflow bool
	for _, f := range out {
		total += f.BytesTx
		if f.Peer == netip.IPv6Unspecified() && f.ServicePort == 0 {
			overflow = true
		}
	}
	if total != 30 || !overflow {
		t.Fatalf("total=%d overflow=%v out=%+v", total, overflow, out)
	}
}
