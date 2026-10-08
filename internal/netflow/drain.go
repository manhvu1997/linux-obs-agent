package netflow

import (
	"net/netip"
	"sort"
)

// FlowDelta is one (tgid, direction, peer, service port) aggregate since the
// previous DrainFlows call. Family is the raw family name: unlike the
// Prometheus counters it has no label budget, because ClickHouse has no
// cardinality limit to protect.
type FlowDelta struct {
	TGID        uint32
	Family      string
	Direction   string // "inbound" | "outbound"
	Peer        netip.Addr
	ServicePort uint16
	BytesRx     uint64
	BytesTx     uint64
	Opened      uint64
	Closed      uint64
}

type drainFlow struct {
	family string
	v      FlowValue
}

// EnableDrain starts accumulating per-flow deltas for DrainFlows. maxKeys
// bounds the keys per interval; later keys fold into (tgid, dir, ::, 0).
func (a *Accumulator) EnableDrain(maxKeys int) {
	if maxKeys < 1 {
		maxKeys = 1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.drainMax = maxKeys
	if a.drain == nil {
		a.drain = make(map[FlowKey]*drainFlow)
	}
}

// addDrain is called from Ingest with a.mu held, after pidFamily is updated.
func (a *Accumulator) addDrain(k FlowKey, d FlowValue) {
	f, ok := a.drain[k]
	if !ok {
		if len(a.drain) >= a.drainMax {
			a.drainFolded++
			k = FlowKey{TGID: k.TGID, Dir: k.Dir, Peer: netip.IPv6Unspecified()}
			f = a.drain[k]
		}
		if f == nil {
			f = &drainFlow{family: a.familyOf(k.TGID)}
			a.drain[k] = f
		}
	}
	f.v.BytesRx += d.BytesRx
	f.v.BytesTx += d.BytesTx
	f.v.Opened += d.Opened
	f.v.Closed += d.Closed
}

// DrainFlows returns everything accumulated since the previous call and
// resets the accumulator. folded counts keys that went to the overflow key.
func (a *Accumulator) DrainFlows() (out []FlowDelta, folded uint64) {
	a.mu.Lock()
	m := a.drain
	folded = a.drainFolded
	if m != nil {
		a.drain = make(map[FlowKey]*drainFlow, len(m))
		a.drainFolded = 0
	}
	a.mu.Unlock()
	if len(m) == 0 {
		return nil, folded
	}
	out = make([]FlowDelta, 0, len(m))
	for k, f := range m {
		out = append(out, FlowDelta{
			TGID: k.TGID, Family: f.family, Direction: k.Dir.String(), Peer: k.Peer, ServicePort: k.ServicePort,
			BytesRx: f.v.BytesRx, BytesTx: f.v.BytesTx, Opened: f.v.Opened, Closed: f.v.Closed,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.TGID != y.TGID {
			return x.TGID < y.TGID
		}
		if x.Direction != y.Direction {
			return x.Direction < y.Direction
		}
		if c := x.Peer.Compare(y.Peer); c != 0 {
			return c < 0
		}
		return x.ServicePort < y.ServicePort
	})
	return out, folded
}
