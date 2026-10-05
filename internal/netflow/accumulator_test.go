// internal/netflow/accumulator_test.go
package netflow

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

func cfg() Config { return Config{MaxPeersPerProcess: 20} }

func k(tgid uint32, dir Direction, peer string, port uint16) FlowKey {
	return FlowKey{TGID: tgid, Dir: dir, Peer: netip.MustParseAddr(peer), ServicePort: port}
}

func TestDeltaAcrossEviction(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Outbound, "10.0.5.2", 3306)
	fam := map[uint32]string{10: "app.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {BytesTx: 100}}, fam)
	a.Ingest(t0.Add(5*time.Second), map[FlowKey]FlowValue{key: {BytesTx: 150}}, fam)
	// Entry evicted from the LRU and re-created: value restarts below previous.
	a.Ingest(t0.Add(10*time.Second), map[FlowKey]FlowValue{key: {BytesTx: 30}}, fam)
	if got := a.Process(10).Outbound.BytesTx; got != 180 {
		t.Fatalf("window tx = %d, want 180", got)
	}
	c := a.Counters()
	if len(c.Dir) != 1 || c.Dir[0].BytesTx != 180 || c.Dir[0].Family != "app.service" || c.Dir[0].Direction != "outbound" {
		t.Fatalf("counters = %+v", c.Dir)
	}
}

func TestWindowRollOffKeepsCounters(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {BytesRx: 500}}, fam)
	a.Ingest(t0.Add(90*time.Second), map[FlowKey]FlowValue{key: {BytesRx: 500}}, fam)
	if got := a.Process(10).Inbound.BytesRx; got != 0 {
		t.Fatalf("window rx = %d, want 0 after roll-off", got)
	}
	if got := a.Counters().Dir[0].BytesRx; got != 500 {
		t.Fatalf("lifetime counter = %d, want 500", got)
	}
}

func TestActiveConnections(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {Opened: 3, Closed: 1}}, fam)
	s := a.Process(10)
	if s.Inbound.ConnsActive != 2 || s.Inbound.ConnsOpened != 3 || s.Inbound.ConnsClosed != 1 {
		t.Fatalf("inbound = %+v", s.Inbound)
	}
	if len(s.TopPeers) != 1 || s.TopPeers[0].ConnsActive != 2 {
		t.Fatalf("peers = %+v", s.TopPeers)
	}
	// More closes than opens (pre-existing connections) never go negative.
	a.Ingest(t0.Add(5*time.Second), map[FlowKey]FlowValue{key: {Opened: 3, Closed: 6}}, fam)
	if got := a.Process(10).Inbound.ConnsActive; got != 0 {
		t.Fatalf("active = %d, want clamped 0", got)
	}
}

func TestFamilyAggregation(t *testing.T) {
	a := NewAccumulator(cfg())
	fam := map[uint32]string{1301: "php-fpm.service", 1302: "php-fpm.service", 99: "other.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1301, Outbound, "10.0.5.2", 3306): {BytesTx: 10, BytesRx: 100},
		k(1302, Outbound, "10.0.5.2", 3306): {BytesTx: 20, BytesRx: 200},
		k(99, Outbound, "10.0.5.2", 3306):   {BytesTx: 1000},
	}, fam)
	s := a.Family("php-fpm.service")
	if s.Outbound.BytesTx != 30 || s.Outbound.BytesRx != 300 {
		t.Fatalf("family outbound = %+v", s.Outbound)
	}
	if len(s.TopPeers) != 1 || s.TopPeers[0].BytesRx != 300 {
		t.Fatalf("merged peers = %+v", s.TopPeers)
	}
}

func TestOutboundPeerLabelCap(t *testing.T) {
	c := cfg()
	c.MaxOutboundPeers = 2
	a := NewAccumulator(c)
	fam := map[uint32]string{1: "app.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1},
		k(1, Outbound, "10.0.0.2", 443): {BytesTx: 2},
		k(1, Outbound, "10.0.0.3", 443): {BytesTx: 4},
	}, fam)
	var total uint64
	labels := map[string]bool{}
	for _, o := range a.Counters().Outbound {
		total += o.BytesTx
		labels[o.PeerIP] = true
	}
	if len(labels) != 3 || !labels["other"] || total != 7 {
		t.Fatalf("labels=%v total=%d", labels, total)
	}
}

func TestFamilyLabelCap(t *testing.T) {
	c := cfg()
	c.MaxFamilies = 1
	a := NewAccumulator(c)
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Inbound, "10.0.0.1", 80): {BytesRx: 1},
		k(2, Inbound, "10.0.0.1", 80): {BytesRx: 2},
	}, map[uint32]string{1: "a.service", 2: "b.service"})
	// Which family wins the single slot depends on map iteration order;
	// assert the invariant instead: one real label + "other", nothing lost.
	fams := map[string]uint64{}
	var total uint64
	for _, d := range a.Counters().Dir {
		fams[d.Family] += d.BytesRx
		total += d.BytesRx
	}
	if len(fams) != 2 || fams["other"] == 0 || total != 3 {
		t.Fatalf("families = %v", fams)
	}
}

func TestLabelExpiryDropsCounters(t *testing.T) {
	c := cfg()
	c.LabelIdleTTL = time.Minute
	a := NewAccumulator(c)
	fam := map[uint32]string{1: "app.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1}}, fam)
	a.Ingest(t0.Add(2*time.Minute), map[FlowKey]FlowValue{}, fam)
	if n := len(a.Counters().Outbound); n != 0 {
		t.Fatalf("expired peer label still exported (%d series)", n)
	}
}

func TestTopPeersCapAndOrder(t *testing.T) {
	c := cfg()
	c.MaxPeersPerProcess = 2
	a := NewAccumulator(c)
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1},
		k(1, Outbound, "10.0.0.2", 443): {BytesTx: 50},
		k(1, Inbound, "10.0.0.3", 80):   {BytesRx: 20},
	}, map[uint32]string{1: "app.service"})
	p := a.Process(1).TopPeers
	if len(p) != 2 || p[0].PeerIP != "10.0.0.2" || p[1].PeerIP != "10.0.0.3" || p[1].Direction != "inbound" {
		t.Fatalf("top peers = %+v", p)
	}
}

func TestProcessRatesFiniteAfterFirstIngest(t *testing.T) {
	a := NewAccumulator(cfg())
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1000}}, nil)
	s := a.Process(1)
	if s.Outbound.BytesTxPerSec != 0 {
		t.Fatalf("rate with zero elapsed = %v, want 0", s.Outbound.BytesTxPerSec)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatalf("summary not JSON-encodable: %v", err)
	}
	a.Ingest(t0.Add(10*time.Second), map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.1", 443): {BytesTx: 2000}}, nil)
	if got := a.Process(1).Outbound.BytesTxPerSec; got != 200 {
		t.Fatalf("rate = %v, want 200 B/s", got)
	}
}

func TestUnknownProcessHasEmptyPeers(t *testing.T) {
	s := NewAccumulator(cfg()).Process(42)
	if s.TopPeers == nil {
		t.Fatal("TopPeers must be an empty slice, not nil (JSON [] not null)")
	}
}

func TestPeerFromBytesUnmapsV4(t *testing.T) {
	var b [16]byte
	b[10], b[11] = 0xff, 0xff
	copy(b[12:], []byte{10, 0, 0, 1})
	if got := PeerFromBytes(b).String(); got != "10.0.0.1" {
		t.Fatalf("PeerFromBytes = %s", got)
	}
	v6 := netip.MustParseAddr("2001:db8::1").As16()
	if got := PeerFromBytes(v6).String(); got != "2001:db8::1" {
		t.Fatalf("PeerFromBytes v6 = %s", got)
	}
}

func TestActiveClampDoesNotHideLaterOpens(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	// Closes of pre-existing connections first (stored value must not go to -2)...
	a.Ingest(t0, map[FlowKey]FlowValue{key: {Closed: 2}}, fam)
	// ...then 3 genuine opens: all 3 are active.
	a.Ingest(t0.Add(5*time.Second), map[FlowKey]FlowValue{key: {Opened: 3, Closed: 2}}, fam)
	if got := a.Process(10).Inbound.ConnsActive; got != 3 {
		t.Fatalf("active = %d, want 3", got)
	}
}

func TestIdleConnectionStaysActive(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {Opened: 3}}, fam)
	a.Ingest(t0.Add(15*time.Minute), map[FlowKey]FlowValue{key: {Opened: 3}}, fam)
	if got := a.Process(10).Inbound.ConnsActive; got != 3 {
		t.Fatalf("idle pooled connections dropped: active = %d, want 3", got)
	}
}

func TestGoneProcessActiveIsPruned(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	a.Ingest(t0, map[FlowKey]FlowValue{key: {Opened: 3}}, map[uint32]string{10: "mysql.service"})
	a.Ingest(t0.Add(15*time.Minute), map[FlowKey]FlowValue{}, map[uint32]string{})
	if got := a.Process(10).Inbound.ConnsActive; got != 0 {
		t.Fatalf("gone process still active = %d, want 0", got)
	}
	if len(a.active) != 0 {
		t.Fatalf("active map not pruned: %v", a.active)
	}
}

func TestAliveProcessAbsentFromMapKeepsActive(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {Opened: 3}}, fam)
	a.Ingest(t0.Add(15*time.Minute), map[FlowKey]FlowValue{}, fam)
	if got := a.Process(10).Inbound.ConnsActive; got != 3 {
		t.Fatalf("alive process active = %d, want 3", got)
	}
}
