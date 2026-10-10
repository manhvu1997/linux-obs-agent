// internal/querystats/querystats.go

// Package querystats aggregates per-statement measurements (CPU time,
// run-queue wait, wall time, bytes) by normalised digest over a rolling
// window and labels each digest as a CPU culprit or a cascade victim.
//
// Database-agnostic: the MySQL analyzer is the first producer of Events.
package querystats

import (
	"sort"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

const (
	AccountingOK         = "ok"
	AccountingNoRunDelay = "run_delay_unavailable"
	RoleCulprit          = "culprit"
	OtherDigestID        = "other"
	OtherDigestText      = "<other>"

	// noRunDelayMinEvents: run_delay is declared unavailable only after this
	// many events that clearly waited (wall − cpu > 10 ms) all reported 0.
	noRunDelayMinEvents = 1000
	waitedGapNs         = 10_000_000
)

// Event is one executed statement.
type Event struct {
	PID         uint32
	Command     string // "query" | "stmt_prepare" | "stmt_execute" | "other"
	Digest      sqldigest.Digest
	SampleQuery string
	Truncated   bool
	WallNs      uint64
	CPUNs       uint64
	RunqNs      uint64
	BytesIn     uint64
	BytesOut    uint64
	At          time.Time
}

// Config tunes the aggregator. Zero values take the documented defaults.
type Config struct {
	Window                       time.Duration // 60s
	BucketWidth                  time.Duration // 5s
	MaxDigests                   int           // 5000 per bucket and in lifetime table
	TopN                         int           // 20
	TopNBytes                    int           // 10
	SlowWallNs                   uint64        // victim needs wall_avg >= this
	StickyMax                    int           // 50
	StickyTTL                    time.Duration // 1h
	CPUCulpritPercentOfNodeUsed  float64       // 20: cpu_role culprit needs ≥ this % of the node's CPU used
	CPUCulpritMinNodeUsedPercent float64       // 50: … and the node ≥ this % busy over the window
	VictimWaitPercent            float64       // 50: victim_of needs waits ≥ this % of its time (time_breakdown_percent.cpu_wait)
	TopNWait                     int           // 10
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 60 * time.Second
	}
	if c.BucketWidth <= 0 {
		c.BucketWidth = 5 * time.Second
	}
	if c.MaxDigests <= 0 {
		c.MaxDigests = 5000
	}
	if c.TopN <= 0 {
		c.TopN = 20
	}
	if c.TopNBytes <= 0 {
		c.TopNBytes = 10
	}
	if c.StickyMax <= 0 {
		c.StickyMax = 50
	}
	if c.StickyTTL <= 0 {
		c.StickyTTL = time.Hour
	}
	if c.CPUCulpritPercentOfNodeUsed <= 0 {
		c.CPUCulpritPercentOfNodeUsed = 20
	}
	if c.CPUCulpritMinNodeUsedPercent <= 0 {
		c.CPUCulpritMinNodeUsedPercent = 50
	}
	if c.VictimWaitPercent <= 0 {
		c.VictimWaitPercent = 50
	}
	if c.TopNWait <= 0 {
		c.TopNWait = 10
	}
	return c
}

// ExportedDigest carries lifetime counters for a digest in the sticky
// Prometheus export set.
type ExportedDigest struct {
	ID       string
	Text     string
	Counters model.QueryCounters
	// WindowCPUNs is this digest's on-CPU time inside the report window,
	// summed across PIDs (for the Prometheus coverage ratio).
	WindowCPUNs uint64
}

// Snapshot is the read-only result of one Snapshot call.
type Snapshot struct {
	WindowSeconds int
	// QueryCPUMsTotal is the on-CPU time of every command in the window, all
	// PIDs (the denominator of the Prometheus digest coverage ratio).
	QueryCPUMsTotal float64
	Thresholds      model.QueryRoleThresholds
	TopByCPU        []model.QueryDigestStats
	TopByBytesOut   []model.QueryDigestStats
	Exported        []ExportedDigest
	Commands        map[string]model.QueryCounters
	// Node is the node CPU over the window; nil when the window has no host
	// sample or a poll in it had no valid node delta.
	Node *model.MySQLNodeWindow
	// QueryCPUCoveragePercent: Σ digest CPU ÷ traced mysqld CPU × 100; nil
	// when a poll in the window was partial or mysqld CPU is 0.
	QueryCPUCoveragePercent *float64
	TopByWait               []model.QueryDigestStats
	// Victims counts digests per victim_of kind over ALL digests in the
	// window: victims burn little CPU, so most never reach TopByCPU.
	// VictimCPU is present (0 included) when run-queue accounting is ok.
	Victims map[string]int
	// Accounting: AccountingKeyCPUWait → AccountingOK | AccountingNoRunDelay.
	Accounting map[string]string
}

type key struct {
	pid uint32
	id  string
}

type acc struct {
	command, text, sample  string
	normalized, truncated  bool
	calls, cpu, runq, wall uint64
	wallMax, in, out       uint64
}

func (x *acc) add(d Delta) {
	x.calls += d.Calls
	x.cpu += d.CPUNs
	x.runq += d.RunqNs
	x.wall += d.WallNs
	x.in += d.BytesIn
	x.out += d.BytesOut
	x.wallMax = max(x.wallMax, d.WallMaxNs)
	x.truncated = x.truncated || d.Truncated
	if x.sample == "" {
		x.sample = d.SampleQuery
	}
}

func (x *acc) merge(y *acc) {
	x.calls += y.calls
	x.cpu += y.cpu
	x.runq += y.runq
	x.wall += y.wall
	x.in += y.in
	x.out += y.out
	x.wallMax = max(x.wallMax, y.wallMax)
	x.truncated = x.truncated || y.truncated
	if x.sample == "" {
		x.sample = y.sample
	}
}

type bucket struct {
	epoch int64
	m     map[key]*acc
	host  hostAcc
}

type life struct {
	text     string
	c        model.QueryCounters
	lastSeen time.Time
}

// Aggregator is safe for concurrent Add and Snapshot.
type Aggregator struct {
	mu       sync.Mutex
	cfg      Config
	buckets  []bucket
	life     map[string]*life
	commands map[string]model.QueryCounters
	sticky   map[string]time.Time
	waited   uint64 // calls whose average wall − cpu exceeded waitedGapNs (per Delta)
	runqSum  uint64
	// drain is the ClickHouse delta accumulator, nil until EnableDrain.
	drain       map[key]*acc
	drainMax    int
	drainFolded uint64
}

func New(cfg Config) *Aggregator {
	cfg = cfg.withDefaults()
	n := int(cfg.Window / cfg.BucketWidth)
	if n < 1 {
		n = 1
	}
	return &Aggregator{
		cfg:      cfg,
		buckets:  make([]bucket, n),
		life:     make(map[string]*life),
		commands: make(map[string]model.QueryCounters),
		sticky:   make(map[string]time.Time),
	}
}

func addCounters(c *model.QueryCounters, d Delta) {
	c.Calls += d.Calls
	c.CPUNs += d.CPUNs
	c.RunqNs += d.RunqNs
	c.WallNs += d.WallNs
	c.BytesIn += d.BytesIn
	c.BytesOut += d.BytesOut
}

// Add records one call; equivalent to AddDeltas with DeltaFromEvent(e).
func (a *Aggregator) Add(e Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addDeltaLocked(DeltaFromEvent(e), e.At)
}

func (a *Aggregator) addDeltaLocked(d Delta, at time.Time) {
	b := a.bucketFor(at)
	k := key{d.PID, d.Digest.ID}
	x, ok := b.m[k]
	if !ok {
		if len(b.m) >= a.cfg.MaxDigests {
			k = key{d.PID, OtherDigestID}
			if x, ok = b.m[k]; !ok {
				x = &acc{command: "other", text: OtherDigestText, normalized: true}
				b.m[k] = x
			}
		} else {
			x = &acc{command: d.Command, text: d.Digest.Text, normalized: d.Digest.Normalized}
			b.m[k] = x
		}
	}
	x.add(d)
	if a.drain != nil {
		a.addDrain(d)
	}
	a.addLife(k.id, x.text, d, at)
	c := a.commands[d.Command]
	addCounters(&c, d)
	a.commands[d.Command] = c
	// Run-delay detection on sums: these calls waited when their average
	// off-CPU time exceeds waitedGapNs (per-call rule of the event path).
	if d.WallNs > d.CPUNs+d.Calls*waitedGapNs {
		a.waited += d.Calls
	}
	a.runqSum += d.RunqNs
}

// addLife: life may exceed MaxDigests by at most StickyMax (see markSticky).
func (a *Aggregator) addLife(id, text string, d Delta, at time.Time) {
	l, ok := a.life[id]
	if !ok {
		if len(a.life) >= a.cfg.MaxDigests {
			id, text = OtherDigestID, OtherDigestText
			if l, ok = a.life[id]; !ok {
				l = &life{text: text}
				a.life[id] = l
			}
		} else {
			l = &life{text: text}
			a.life[id] = l
		}
	}
	addCounters(&l.c, d)
	l.lastSeen = at
}

func (a *Aggregator) bucketFor(t time.Time) *bucket {
	epoch := t.UnixNano() / a.cfg.BucketWidth.Nanoseconds()
	b := &a.buckets[int(epoch%int64(len(a.buckets)))]
	if epoch > b.epoch || b.m == nil {
		b.epoch = epoch
		b.m = make(map[key]*acc)
		b.host = hostAcc{}
	}
	// epoch < b.epoch: a late event; count it into the newer bucket rather
	// than wiping fresher data.
	return b
}

// inWindow returns the buckets inside the window ending at now.
func (a *Aggregator) inWindow(now time.Time) []*bucket {
	cur := now.UnixNano() / a.cfg.BucketWidth.Nanoseconds()
	n := int64(len(a.buckets))
	out := make([]*bucket, 0, len(a.buckets))
	for i := range a.buckets {
		b := &a.buckets[i]
		if b.m == nil || b.epoch <= cur-n || b.epoch > cur {
			continue
		}
		out = append(out, b)
	}
	return out
}

// Snapshot merges the buckets inside the window, ranks digests, updates the
// sticky export set and returns a copy. Call it periodically (the analyzer
// does so every poll interval); it mutates the sticky set.
func (a *Aggregator) Snapshot(now time.Time) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	bs := a.inWindow(now)
	merged := make(map[key]*acc)
	for _, b := range bs {
		for k, x := range b.m {
			m, ok := merged[k]
			if !ok {
				cp := *x
				merged[k] = &cp
				continue
			}
			m.merge(x)
		}
	}

	acct := AccountingOK
	if a.waited >= noRunDelayMinEvents && a.runqSum == 0 {
		acct = AccountingNoRunDelay
	}
	var cpuAll uint64
	for _, x := range merged {
		cpuAll += x.cpu
	}

	hw := a.hostTotals(bs)
	node := hw.node(a.cfg.Window)

	// The node's CPU used over the same polls: denominator of
	// percent_of_node_cpu_used and the cpu_role gate.
	var nd *nodeDenom
	if used, ok := hw.nodeUsedNs(); ok && used > 0 && node != nil {
		nd = &nodeDenom{usedNs: used, usedPercent: node.CPUUsedPercent}
	}

	stats := make([]model.QueryDigestStats, 0, len(merged))
	victims := make(map[string]int)
	if acct == AccountingOK {
		// A real zero: cpu waits are measured, so "no cpu victims" is known
		// (and survives omitempty). Unavailable accounting leaves the key out.
		victims[VictimCPU] = 0
	}
	for k, x := range merged {
		s := toStats(k, x)
		a.addNewStats(&s, k, x, acct, nd)
		if s.VictimOf != "" {
			victims[s.VictimOf]++
		}
		stats = append(stats, s)
	}
	byWait := topBy(waiting(stats), a.cfg.TopNWait, func(s model.QueryDigestStats) float64 { return float64(s.RunqNs) })
	byCPU := topBy(stats, a.cfg.TopN, func(s model.QueryDigestStats) float64 { return float64(s.CPUNs) })
	bytesOut := func(s model.QueryDigestStats) float64 { return float64(s.BytesOut) }
	byOut := topBy(stats, a.cfg.TopNBytes, bytesOut)
	// Sticky entry uses top-TopN by bytes (spec §4.2); the reported list stays TopNBytes.
	stickyOut := topBy(stats, a.cfg.TopN, bytesOut)

	for _, list := range [][]model.QueryDigestStats{byCPU, stickyOut} {
		for _, s := range list {
			a.markSticky(s.DigestID, stats, now)
		}
	}
	a.expire(now)

	winCPU := make(map[string]uint64, len(merged))
	for k, x := range merged {
		winCPU[k.id] += x.cpu
	}
	exported := make([]ExportedDigest, 0, len(a.sticky))
	for id := range a.sticky {
		if l, ok := a.life[id]; ok {
			exported = append(exported, ExportedDigest{ID: id, Text: l.text, Counters: l.c, WindowCPUNs: winCPU[id]})
		}
	}
	sort.Slice(exported, func(i, j int) bool { return exported[i].ID < exported[j].ID })

	cmds := make(map[string]model.QueryCounters, len(a.commands))
	for k, v := range a.commands {
		cmds[k] = v
	}

	var coverage *float64
	if hw.samples > 0 && !hw.mysqldPartial && hw.mysqld > 0 {
		v := 100 * float64(cpuAll) / float64(hw.mysqld)
		coverage = &v
	}

	return Snapshot{
		WindowSeconds:   int(a.cfg.Window / time.Second),
		QueryCPUMsTotal: float64(cpuAll) / 1e6,
		Thresholds: model.QueryRoleThresholds{
			CPUCulpritPercentOfNodeCPUUsed:  a.cfg.CPUCulpritPercentOfNodeUsed,
			CPUCulpritMinNodeCPUUsedPercent: a.cfg.CPUCulpritMinNodeUsedPercent,
			VictimWaitPercent:               a.cfg.VictimWaitPercent,
			VictimMinLatencyMs:              float64(a.cfg.SlowWallNs) / 1e6,
		},
		TopByCPU:                byCPU,
		TopByBytesOut:           byOut,
		Exported:                exported,
		Commands:                cmds,
		Node:                    node,
		QueryCPUCoveragePercent: coverage,
		TopByWait:               byWait,
		Victims:                 victims,
		Accounting:              map[string]string{AccountingKeyCPUWait: acct},
	}
}

// markSticky adds id to the sticky set (never the synthetic <other>) and makes
// sure a lifetime entry exists, seeding it from the window counters when the
// digest was folded into "other" in life.
func (a *Aggregator) markSticky(id string, stats []model.QueryDigestStats, now time.Time) {
	if id == OtherDigestID {
		return
	}
	a.sticky[id] = now
	if _, ok := a.life[id]; ok {
		return
	}
	l := &life{lastSeen: now}
	for _, s := range stats {
		if s.DigestID != id {
			continue
		}
		l.text = s.DigestText
		l.c.Calls += s.Calls
		l.c.CPUNs += s.CPUNs
		l.c.WallNs += s.WallNs
		l.c.RunqNs += s.RunqNs
		l.c.BytesOut += s.BytesOut
	}
	a.life[id] = l
}

func (a *Aggregator) expire(now time.Time) {
	for id, t := range a.sticky {
		if now.Sub(t) > a.cfg.StickyTTL {
			delete(a.sticky, id)
		}
	}
	if over := len(a.sticky) - a.cfg.StickyMax; over > 0 {
		type kv struct {
			id string
			t  time.Time
		}
		all := make([]kv, 0, len(a.sticky))
		for id, t := range a.sticky {
			all = append(all, kv{id, t})
		}
		sort.Slice(all, func(i, j int) bool {
			if !all[i].t.Equal(all[j].t) {
				return all[i].t.Before(all[j].t)
			}
			return all[i].id < all[j].id
		})
		for _, e := range all[:over] {
			delete(a.sticky, e.id)
		}
	}
	for id, l := range a.life {
		if _, sticky := a.sticky[id]; !sticky && now.Sub(l.lastSeen) > a.cfg.StickyTTL {
			delete(a.life, id)
		}
	}
}

// toStats builds a digest's identity fields; addNewStats fills the statistics.
func toStats(k key, x *acc) model.QueryDigestStats {
	return model.QueryDigestStats{
		PID: k.pid, DigestID: k.id, Command: x.command, DigestText: x.text,
		SampleQuery: x.sample, Normalized: x.normalized, Truncated: x.truncated, Calls: x.calls,
	}
}

func topBy(in []model.QueryDigestStats, n int, metric func(model.QueryDigestStats) float64) []model.QueryDigestStats {
	out := make([]model.QueryDigestStats, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		mi, mj := metric(out[i]), metric(out[j])
		if mi != mj {
			return mi > mj
		}
		if out[i].DigestID != out[j].DigestID {
			return out[i].DigestID < out[j].DigestID
		}
		return out[i].PID < out[j].PID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
