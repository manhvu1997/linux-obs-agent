// internal/netflow/accumulator.go
package netflow

import (
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	otherLabel    = "other"
	unknownFamily = "unknown"
)

// Config tunes the accumulator. Zero values take the documented defaults.
type Config struct {
	Window             time.Duration // 60s
	MaxFamilies        int           // 50
	MaxOutboundPeers   int           // 100
	MaxPeersPerProcess int           // 20
	// MaxServicePorts bounds the distinct service_port values of the
	// outbound peer counters node-wide; later ports fold into port 0
	// (exported as service_port="other"). Internal, not in YAML.
	MaxServicePorts int // 200
	// LabelIdleTTL: counters for a label idle longer than this are dropped to
	// bound memory (churning unit names would otherwise grow the maps without
	// limit). If the label returns it restarts from 0, a normal Prometheus
	// counter reset that rate() tolerates.
	LabelIdleTTL time.Duration // 1h
	PIDIdleTTL   time.Duration // 10m
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 60 * time.Second
	}
	if c.MaxFamilies <= 0 {
		c.MaxFamilies = 50
	}
	if c.MaxOutboundPeers <= 0 {
		c.MaxOutboundPeers = 100
	}
	if c.MaxPeersPerProcess <= 0 {
		c.MaxPeersPerProcess = 20
	}
	if c.MaxServicePorts <= 0 {
		c.MaxServicePorts = 200
	}
	if c.LabelIdleTTL <= 0 {
		c.LabelIdleTTL = time.Hour
	}
	if c.PIDIdleTTL <= 0 {
		c.PIDIdleTTL = 10 * time.Minute
	}
	return c
}

type FamilyDirCounter struct {
	Family, Direction string
	BytesRx, BytesTx  uint64
	Opened            uint64
	Active            int64
}

type FamilyPortCounter struct {
	Family           string
	ServicePort      uint16
	BytesRx, BytesTx uint64
}

// FamilyPeerCounter is one outbound (family, peer, service port) counter.
// ServicePort 0 means "other": the node-wide service-port budget
// (Config.MaxServicePorts) was exhausted and the port was folded.
type FamilyPeerCounter struct {
	Family, PeerIP   string
	ServicePort      uint16
	BytesRx, BytesTx uint64
}

// Counters is a point-in-time copy of the lifetime counters.
type Counters struct {
	Dir      []FamilyDirCounter
	Inbound  []FamilyPortCounter
	Outbound []FamilyPeerCounter
}

type famDirKey struct {
	fam string
	dir Direction
}
type famPortKey struct {
	fam  string
	port uint16
}
type famPeerKey struct {
	fam, peer string
	port      uint16
}
type dirCounter struct{ rx, tx, opened uint64 }
type byteCounter struct{ rx, tx uint64 }

type sample struct {
	at     time.Time
	deltas map[FlowKey]FlowValue
}

// labelBudget hands out at most max distinct label values; later values map
// to "other". Idle values are released after a TTL.
type labelBudget struct {
	max  int
	seen map[string]time.Time
}

func (b *labelBudget) label(v string, now time.Time) string {
	if _, ok := b.seen[v]; ok || len(b.seen) < b.max {
		b.seen[v] = now
		return v
	}
	return otherLabel
}

func (b *labelBudget) peek(v string) string {
	if _, ok := b.seen[v]; ok {
		return v
	}
	return otherLabel
}

func (b *labelBudget) expire(now time.Time, ttl time.Duration) map[string]bool {
	gone := make(map[string]bool)
	for v, t := range b.seen {
		if now.Sub(t) > ttl {
			delete(b.seen, v)
			gone[v] = true
		}
	}
	return gone
}

// Accumulator is safe for concurrent use.
type Accumulator struct {
	mu        sync.Mutex
	cfg       Config
	prev      map[FlowKey]FlowValue
	samples   []sample
	firstAt   time.Time
	lastAt    time.Time
	active    map[FlowKey]int64
	pidSeen   map[uint32]time.Time
	pidFamily map[uint32]string

	famDir     map[famDirKey]*dirCounter
	famIn      map[famPortKey]*byteCounter
	famOut     map[famPeerKey]*byteCounter
	famLabels  labelBudget
	peerLabels labelBudget
	portLabels labelBudget // outbound service ports, node-wide

	// drain is the ClickHouse delta accumulator, nil until EnableDrain.
	drain       map[FlowKey]*drainFlow
	drainMax    int
	drainFolded uint64
}

func NewAccumulator(cfg Config) *Accumulator {
	cfg = cfg.withDefaults()
	return &Accumulator{
		cfg:        cfg,
		prev:       make(map[FlowKey]FlowValue),
		active:     make(map[FlowKey]int64),
		pidSeen:    make(map[uint32]time.Time),
		pidFamily:  make(map[uint32]string),
		famDir:     make(map[famDirKey]*dirCounter),
		famIn:      make(map[famPortKey]*byteCounter),
		famOut:     make(map[famPeerKey]*byteCounter),
		famLabels:  labelBudget{max: cfg.MaxFamilies, seen: make(map[string]time.Time)},
		peerLabels: labelBudget{max: cfg.MaxOutboundPeers, seen: make(map[string]time.Time)},
		portLabels: labelBudget{max: cfg.MaxServicePorts, seen: make(map[string]time.Time)},
	}
}

func delta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur // LRU entry evicted and re-created since the last poll
}

// Ingest records one poll of the kernel map. cur is owned by the
// accumulator afterwards. Keys absent from cur were evicted; if they
// reappear they count from zero.
func (a *Accumulator) Ingest(now time.Time, cur map[FlowKey]FlowValue, pidFamily map[uint32]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// The first poll's deltas span agent start → first poll (the whole
	// cumulative kernel value) while elapsed starts at the first poll, so
	// it is a window baseline only: lifetime counters, active tracking and
	// pid seen-tracking still use it, window samples do not.
	baseline := a.firstAt.IsZero()
	if baseline {
		a.firstAt = now
	}
	a.lastAt = now
	if pidFamily != nil {
		a.pidFamily = pidFamily
	}

	deltas := make(map[FlowKey]FlowValue)
	for k, v := range cur {
		p := a.prev[k]
		d := FlowValue{
			BytesTx: delta(v.BytesTx, p.BytesTx), BytesRx: delta(v.BytesRx, p.BytesRx),
			Opened: delta(v.Opened, p.Opened), Closed: delta(v.Closed, p.Closed),
		}
		if d != (FlowValue{}) {
			deltas[k] = d
			a.pidSeen[k.TGID] = now
		}
	}
	a.prev = cur

	if !baseline {
		a.samples = append(a.samples, sample{at: now, deltas: deltas})
	}
	// Keep ages < Window: a sample covers the interval ending at its time,
	// so Window/interval samples span exactly Window.
	cut := 0
	for cut < len(a.samples) && now.Sub(a.samples[cut].at) >= a.cfg.Window {
		cut++
	}
	a.samples = a.samples[cut:]

	for k, d := range deltas {
		if a.drain != nil {
			a.addDrain(k, d)
		}
		a.active[k] += int64(d.Opened) - int64(d.Closed)
		if a.active[k] < 0 { // closes of connections opened before we started
			a.active[k] = 0
		}
		fam := a.famLabels.label(a.familyOf(k.TGID), now)
		dc := a.famDir[famDirKey{fam, k.Dir}]
		if dc == nil {
			dc = &dirCounter{}
			a.famDir[famDirKey{fam, k.Dir}] = dc
		}
		dc.rx += d.BytesRx
		dc.tx += d.BytesTx
		dc.opened += d.Opened
		if k.Dir == Inbound {
			bc := a.famIn[famPortKey{fam, k.ServicePort}]
			if bc == nil {
				bc = &byteCounter{}
				a.famIn[famPortKey{fam, k.ServicePort}] = bc
			}
			bc.rx += d.BytesRx
			bc.tx += d.BytesTx
		} else {
			peer := a.peerLabels.label(k.Peer.String(), now)
			port := k.ServicePort
			if a.portLabels.label(strconv.Itoa(int(port)), now) == otherLabel {
				port = 0
			}
			pk := famPeerKey{fam, peer, port}
			bc := a.famOut[pk]
			if bc == nil {
				bc = &byteCounter{}
				a.famOut[pk] = bc
			}
			bc.rx += d.BytesRx
			bc.tx += d.BytesTx
		}
	}

	// A tgid is gone only when absent from both the kernel map and the live
	// process list for > PIDIdleTTL; idle pooled connections stay active.
	for k := range cur {
		a.pidSeen[k.TGID] = now
	}
	tracked := make(map[uint32]struct{}, len(a.pidSeen))
	for tgid := range a.pidSeen {
		tracked[tgid] = struct{}{}
	}
	for k := range a.active {
		tracked[k.TGID] = struct{}{}
	}
	for tgid := range pidFamily {
		if _, ok := tracked[tgid]; ok {
			a.pidSeen[tgid] = now
		}
	}
	expired := make(map[uint32]struct{})
	for tgid := range tracked {
		seen, ok := a.pidSeen[tgid]
		if !ok {
			// active entries without a pidSeen record: start the idle clock now
			a.pidSeen[tgid] = now
			continue
		}
		if now.Sub(seen) > a.cfg.PIDIdleTTL {
			delete(a.pidSeen, tgid)
			expired[tgid] = struct{}{}
		}
	}
	if len(expired) > 0 {
		for k := range a.active {
			if _, ok := expired[k.TGID]; ok {
				delete(a.active, k)
			}
		}
	}
	if gone := a.famLabels.expire(now, a.cfg.LabelIdleTTL); len(gone) > 0 {
		for k := range a.famDir {
			if gone[k.fam] {
				delete(a.famDir, k)
			}
		}
		for k := range a.famIn {
			if gone[k.fam] {
				delete(a.famIn, k)
			}
		}
		for k := range a.famOut {
			if gone[k.fam] {
				delete(a.famOut, k)
			}
		}
	}
	if gone := a.peerLabels.expire(now, a.cfg.LabelIdleTTL); len(gone) > 0 {
		for k := range a.famOut {
			if gone[k.peer] {
				delete(a.famOut, k)
			}
		}
	}
	if gone := a.portLabels.expire(now, a.cfg.LabelIdleTTL); len(gone) > 0 {
		for k := range a.famOut {
			if k.port != 0 && gone[strconv.Itoa(int(k.port))] {
				delete(a.famOut, k)
			}
		}
	}
}

func (a *Accumulator) familyOf(tgid uint32) string {
	if f, ok := a.pidFamily[tgid]; ok && f != "" {
		return f
	}
	return unknownFamily
}

// WindowSeconds is the configured window length in seconds.
func (a *Accumulator) WindowSeconds() int { return int(a.cfg.Window / time.Second) }

// Process summarises one tgid over the window.
func (a *Accumulator) Process(tgid uint32) model.NetworkSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.summary(func(t uint32) bool { return t == tgid })
}

// Family summarises every tgid currently mapped to the family.
func (a *Accumulator) Family(name string) model.NetworkSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.summary(func(t uint32) bool { return a.familyOf(t) == name })
}

type peerKey struct {
	dir  Direction
	peer netip.Addr
	port uint16
}

func (a *Accumulator) summary(match func(uint32) bool) model.NetworkSummary {
	var s model.NetworkSummary
	peers := make(map[peerKey]*model.PeerStats)
	peerOf := func(k FlowKey) *model.PeerStats {
		pk := peerKey{k.Dir, k.Peer, k.ServicePort}
		p := peers[pk]
		if p == nil {
			p = &model.PeerStats{Direction: k.Dir.String(), PeerIP: k.Peer.String(), ServicePort: k.ServicePort}
			peers[pk] = p
		}
		return p
	}
	dirOf := func(d Direction) *model.DirectionStats {
		if d == Inbound {
			return &s.Inbound
		}
		return &s.Outbound
	}
	for _, smp := range a.samples {
		for k, d := range smp.deltas {
			if !match(k.TGID) {
				continue
			}
			ds := dirOf(k.Dir)
			ds.BytesRx += d.BytesRx
			ds.BytesTx += d.BytesTx
			ds.ConnsOpened += d.Opened
			ds.ConnsClosed += d.Closed
			p := peerOf(k)
			p.BytesRx += d.BytesRx
			p.BytesTx += d.BytesTx
		}
	}
	for k, n := range a.active {
		if n <= 0 || !match(k.TGID) {
			continue
		}
		dirOf(k.Dir).ConnsActive += n
		peerOf(k).ConnsActive += n
	}

	elapsed := a.lastAt.Sub(a.firstAt)
	if elapsed > a.cfg.Window {
		elapsed = a.cfg.Window
	}
	if secs := elapsed.Seconds(); secs > 0 {
		for _, ds := range []*model.DirectionStats{&s.Inbound, &s.Outbound} {
			ds.BytesRxPerSec = float64(ds.BytesRx) / secs
			ds.BytesTxPerSec = float64(ds.BytesTx) / secs
		}
	}

	s.TopPeers = make([]model.PeerStats, 0, len(peers))
	for _, p := range peers {
		s.TopPeers = append(s.TopPeers, *p)
	}
	sort.Slice(s.TopPeers, func(i, j int) bool {
		a, b := s.TopPeers[i], s.TopPeers[j]
		if a.BytesRx+a.BytesTx != b.BytesRx+b.BytesTx {
			return a.BytesRx+a.BytesTx > b.BytesRx+b.BytesTx
		}
		if a.ConnsActive != b.ConnsActive {
			return a.ConnsActive > b.ConnsActive
		}
		if a.PeerIP != b.PeerIP {
			return a.PeerIP < b.PeerIP
		}
		return a.ServicePort < b.ServicePort
	})
	if len(s.TopPeers) > a.cfg.MaxPeersPerProcess {
		s.TopPeers = s.TopPeers[:a.cfg.MaxPeersPerProcess]
	}
	return s
}

// Counters returns sorted copies of the lifetime counters for Prometheus.
func (a *Accumulator) Counters() Counters {
	a.mu.Lock()
	defer a.mu.Unlock()

	dir := make(map[famDirKey]*FamilyDirCounter)
	for k, c := range a.famDir {
		dir[k] = &FamilyDirCounter{Family: k.fam, Direction: k.dir.String(), BytesRx: c.rx, BytesTx: c.tx, Opened: c.opened}
	}
	for k, n := range a.active {
		if n <= 0 {
			continue
		}
		dk := famDirKey{a.famLabels.peek(a.familyOf(k.TGID)), k.Dir}
		d := dir[dk]
		if d == nil {
			d = &FamilyDirCounter{Family: dk.fam, Direction: dk.dir.String()}
			dir[dk] = d
		}
		d.Active += n
	}
	var out Counters
	for _, d := range dir {
		out.Dir = append(out.Dir, *d)
	}
	for k, c := range a.famIn {
		out.Inbound = append(out.Inbound, FamilyPortCounter{Family: k.fam, ServicePort: k.port, BytesRx: c.rx, BytesTx: c.tx})
	}
	for k, c := range a.famOut {
		out.Outbound = append(out.Outbound, FamilyPeerCounter{Family: k.fam, PeerIP: k.peer, ServicePort: k.port, BytesRx: c.rx, BytesTx: c.tx})
	}
	sort.Slice(out.Dir, func(i, j int) bool {
		if out.Dir[i].Family != out.Dir[j].Family {
			return out.Dir[i].Family < out.Dir[j].Family
		}
		return out.Dir[i].Direction < out.Dir[j].Direction
	})
	sort.Slice(out.Inbound, func(i, j int) bool {
		if out.Inbound[i].Family != out.Inbound[j].Family {
			return out.Inbound[i].Family < out.Inbound[j].Family
		}
		return out.Inbound[i].ServicePort < out.Inbound[j].ServicePort
	})
	sort.Slice(out.Outbound, func(i, j int) bool {
		x, y := out.Outbound[i], out.Outbound[j]
		if x.Family != y.Family {
			return x.Family < y.Family
		}
		if x.PeerIP != y.PeerIP {
			return x.PeerIP < y.PeerIP
		}
		return x.ServicePort < y.ServicePort
	})
	return out
}
