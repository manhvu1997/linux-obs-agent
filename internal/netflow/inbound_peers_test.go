package netflow

import (
	"testing"
	"time"
)

func TestInboundPeerBudget(t *testing.T) {
	c := cfg()
	c.MaxInboundPeers = 1
	a := NewAccumulator(c)
	fam := map[uint32]string{1: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Inbound, "10.0.0.2", 3306): {BytesRx: 100, BytesTx: 1000},
		k(1, Inbound, "10.0.0.3", 3306): {BytesRx: 50, BytesTx: 500},
	}, fam)
	got := map[string]uint64{}
	for _, p := range a.Counters().InboundPeers {
		if p.Family != "mysql.service" || p.ServicePort != 3306 {
			t.Fatalf("unexpected peer counter %+v", p)
		}
		got[p.PeerIP] += p.BytesRx
	}
	if len(got) != 2 || got["other"] == 0 || got["other"]+sumExcept(got, "other") != 150 {
		t.Fatalf("inbound peers = %v, want one real IP + \"other\" summing to 150", got)
	}
}

func sumExcept(m map[string]uint64, skip string) uint64 {
	var s uint64
	for k, v := range m {
		if k != skip {
			s += v
		}
	}
	return s
}

func TestInboundPeersDisabled(t *testing.T) {
	c := cfg()
	c.MaxInboundPeers = -1
	a := NewAccumulator(c)
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Inbound, "10.0.0.2", 80): {BytesRx: 1}}, nil)
	if n := len(a.Counters().InboundPeers); n != 0 {
		t.Fatalf("inbound peers = %d, want 0 when disabled", n)
	}
}

func TestInboundPeerIdleExpiry(t *testing.T) {
	c := cfg()
	c.LabelIdleTTL = time.Minute
	a := NewAccumulator(c)
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Inbound, "10.0.0.2", 80): {BytesRx: 1}}, nil)
	a.Ingest(t0.Add(2*time.Minute), map[FlowKey]FlowValue{k(1, Inbound, "10.0.0.9", 80): {BytesRx: 1}}, nil)
	for _, p := range a.Counters().InboundPeers {
		if p.PeerIP == "10.0.0.2" {
			t.Fatalf("idle inbound peer 10.0.0.2 should have expired: %+v", a.Counters().InboundPeers)
		}
	}
}
