//go:build linux

package netflow

import (
	"net/netip"
	"testing"

	nf "github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

func v4Mapped(a, b, c, d byte) [16]uint8 {
	return [16]uint8{10: 0xff, 11: 0xff, 12: a, 13: b, 14: c, 15: d}
}

func TestCollapseFlowsMergesFamilies(t *testing.T) {
	peer := v4Mapped(10, 0, 0, 7)
	raw := map[NetflowFlowKey]NetflowFlowVal{
		{Tgid: 42, Dir: 2, Family: 2, SvcPort: 3306, Peer: peer}:  {BytesTx: 100, BytesRx: 10, Opened: 1, Closed: 1},
		{Tgid: 42, Dir: 2, Family: 10, SvcPort: 3306, Peer: peer}: {BytesTx: 5, BytesRx: 7, Opened: 2},
	}
	out := collapseFlows(raw)
	if len(out) != 1 {
		t.Fatalf("want 1 collapsed key, got %d: %+v", len(out), out)
	}
	key := nf.FlowKey{TGID: 42, Dir: nf.Outbound, Peer: netip.MustParseAddr("10.0.0.7"), ServicePort: 3306}
	got, ok := out[key]
	if !ok {
		t.Fatalf("key %+v missing from %+v", key, out)
	}
	want := nf.FlowValue{BytesTx: 105, BytesRx: 17, Opened: 3, Closed: 1}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCollapseFlowsKeepsTGIDsSeparate(t *testing.T) {
	peer := v4Mapped(10, 0, 0, 7)
	raw := map[NetflowFlowKey]NetflowFlowVal{
		{Tgid: 1, Dir: 1, Family: 2, SvcPort: 80, Peer: peer}: {BytesRx: 1},
		{Tgid: 2, Dir: 1, Family: 2, SvcPort: 80, Peer: peer}: {BytesRx: 2},
	}
	out := collapseFlows(raw)
	if len(out) != 2 {
		t.Fatalf("want 2 keys, got %d: %+v", len(out), out)
	}
	for _, tg := range []uint32{1, 2} {
		k := nf.FlowKey{TGID: tg, Dir: nf.Inbound, Peer: netip.MustParseAddr("10.0.0.7"), ServicePort: 80}
		if out[k].BytesRx != uint64(tg) {
			t.Fatalf("tgid %d: got %+v", tg, out[k])
		}
	}
}

// ReadFlows dedupes by collecting Iterate() output into a map keyed by the raw
// BPF key: a key the kernel yields twice (LRU eviction restarts the walk)
// overwrites its first copy instead of being summed. This pins that semantics.
func TestCollapseFlowsDuplicateRawKeyCountedOnce(t *testing.T) {
	k := NetflowFlowKey{Tgid: 9, Dir: 2, Family: 2, SvcPort: 443, Peer: v4Mapped(1, 2, 3, 4)}
	raw := make(map[NetflowFlowKey]NetflowFlowVal)
	for i := 0; i < 2; i++ { // same key yielded twice by the iterator
		raw[k] = NetflowFlowVal{BytesTx: 1000, Opened: 1}
	}
	out := collapseFlows(raw)
	key := nf.FlowKey{TGID: 9, Dir: nf.Outbound, Peer: netip.MustParseAddr("1.2.3.4"), ServicePort: 443}
	if got := out[key]; got != (nf.FlowValue{BytesTx: 1000, Opened: 1}) {
		t.Fatalf("duplicate raw key was double counted: %+v", got)
	}
}
