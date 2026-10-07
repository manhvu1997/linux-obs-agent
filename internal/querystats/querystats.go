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
	RoleVictim           = "victim"
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
	Window                 time.Duration // 60s
	BucketWidth            time.Duration // 5s
	MaxDigests             int           // 5000 per bucket and in lifetime table
	TopN                   int           // 20
	TopNBytes              int           // 10
	CulpritCPUSharePercent float64       // 20
	CulpritMinCPUPercent   float64       // 5: culprit also needs ≥ this % of one core over Window
	VictimRunqRatio        float64       // 5
	SlowWallNs             uint64        // victim needs wall_avg >= this
	StickyMax              int           // 50
	StickyTTL              time.Duration // 1h
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
	if c.CulpritCPUSharePercent <= 0 {
		c.CulpritCPUSharePercent = 20
	}
	if c.CulpritMinCPUPercent <= 0 {
		c.CulpritMinCPUPercent = 5
	}
	if c.VictimRunqRatio <= 0 {
		c.VictimRunqRatio = 5
	}
	if c.StickyMax <= 0 {
		c.StickyMax = 50
	}
	if c.StickyTTL <= 0 {
		c.StickyTTL = time.Hour
	}
	return c
}

// ExportedDigest carries lifetime counters for a digest in the sticky
// Prometheus export set.
type ExportedDigest struct {
	ID       string
	Text     string
	Counters model.QueryCounters
}

// Snapshot is the read-only result of one Snapshot call.
type Snapshot struct {
	WindowSeconds int
	CPUAccounting string
	// QueryCPUMsTotal is the on-CPU time of every command in the window, all
	// PIDs: the absolute scale behind each digest's CPUSharePercent.
	QueryCPUMsTotal float64
	Thresholds      model.QueryRoleThresholds
	TopByCPU        []model.QueryDigestStats
	TopByBytesOut   []model.QueryDigestStats
	Exported        []ExportedDigest
	Commands        map[string]model.QueryCounters
}

type key struct {
	pid uint32
	id  string
}

type acc struct {
	command, text, sample          string
	normalized, truncated          bool
	calls, cpu, cpuMax, runq, wall uint64
	wallMax, in, out               uint64
}

func (x *acc) add(e Event) {
	x.calls++
	x.cpu += e.CPUNs
	x.runq += e.RunqNs
	x.wall += e.WallNs
	x.in += e.BytesIn
	x.out += e.BytesOut
	x.cpuMax = max(x.cpuMax, e.CPUNs)
	x.wallMax = max(x.wallMax, e.WallNs)
	x.truncated = x.truncated || e.Truncated
	if x.sample == "" {
		x.sample = e.SampleQuery
	}
}

func (x *acc) merge(y *acc) {
	x.calls += y.calls
	x.cpu += y.cpu
	x.runq += y.runq
	x.wall += y.wall
	x.in += y.in
	x.out += y.out
	x.cpuMax = max(x.cpuMax, y.cpuMax)
	x.wallMax = max(x.wallMax, y.wallMax)
	x.truncated = x.truncated || y.truncated
	if x.sample == "" {
		x.sample = y.sample
	}
}

type bucket struct {
	epoch int64
	m     map[key]*acc
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
	waited   uint64 // events with wall − cpu > waitedGapNs
	runqSum  uint64
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

func addCounters(c *model.QueryCounters, e Event) {
	c.Calls++
	c.CPUNs += e.CPUNs
	c.RunqNs += e.RunqNs
	c.WallNs += e.WallNs
	c.BytesIn += e.BytesIn
	c.BytesOut += e.BytesOut
}

func (a *Aggregator) Add(e Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	b := a.bucketFor(e.At)
	k := key{e.PID, e.Digest.ID}
	x, ok := b.m[k]
	if !ok {
		if len(b.m) >= a.cfg.MaxDigests {
			k = key{e.PID, OtherDigestID}
			if x, ok = b.m[k]; !ok {
				x = &acc{command: "other", text: OtherDigestText, normalized: true}
				b.m[k] = x
			}
		} else {
			x = &acc{command: e.Command, text: e.Digest.Text, normalized: e.Digest.Normalized}
			b.m[k] = x
		}
	}
	x.add(e)

	a.addLife(k.id, x.text, e)
	c := a.commands[e.Command]
	addCounters(&c, e)
	a.commands[e.Command] = c
	if e.WallNs > e.CPUNs+waitedGapNs {
		a.waited++
	}
	a.runqSum += e.RunqNs
}

// addLife: life may exceed MaxDigests by at most StickyMax (see markSticky).
func (a *Aggregator) addLife(id, text string, e Event) {
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
	addCounters(&l.c, e)
	l.lastSeen = e.At
}

func (a *Aggregator) bucketFor(t time.Time) *bucket {
	epoch := t.UnixNano() / a.cfg.BucketWidth.Nanoseconds()
	b := &a.buckets[int(epoch%int64(len(a.buckets)))]
	if epoch > b.epoch || b.m == nil {
		b.epoch = epoch
		b.m = make(map[key]*acc)
	}
	// epoch < b.epoch: a late event; count it into the newer bucket rather
	// than wiping fresher data.
	return b
}

// Snapshot merges the buckets inside the window, ranks digests, updates the
// sticky export set and returns a copy. Call it periodically (the analyzer
// does so every poll interval); it mutates the sticky set.
func (a *Aggregator) Snapshot(now time.Time) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	cur := now.UnixNano() / a.cfg.BucketWidth.Nanoseconds()
	n := int64(len(a.buckets))
	merged := make(map[key]*acc)
	for i := range a.buckets {
		b := &a.buckets[i]
		if b.m == nil || b.epoch <= cur-n || b.epoch > cur {
			continue
		}
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
	cpuByPID := make(map[uint32]uint64)
	var cpuAll uint64
	for k, x := range merged {
		cpuByPID[k.pid] += x.cpu
		cpuAll += x.cpu
	}
	stats := make([]model.QueryDigestStats, 0, len(merged))
	for k, x := range merged {
		stats = append(stats, a.toStats(k, x, cpuByPID[k.pid], acct))
	}
	byCPU := topBy(stats, a.cfg.TopN, func(s model.QueryDigestStats) float64 { return s.CPUMsTotal })
	bytesOut := func(s model.QueryDigestStats) float64 { return float64(s.BytesOutTotal) }
	byOut := topBy(stats, a.cfg.TopNBytes, bytesOut)
	// Sticky entry uses top-TopN by bytes (spec §4.2); the reported list stays TopNBytes.
	stickyOut := topBy(stats, a.cfg.TopN, bytesOut)

	for _, list := range [][]model.QueryDigestStats{byCPU, stickyOut} {
		for _, s := range list {
			a.markSticky(s.DigestID, stats, now)
		}
	}
	a.expire(now)

	exported := make([]ExportedDigest, 0, len(a.sticky))
	for id := range a.sticky {
		if l, ok := a.life[id]; ok {
			exported = append(exported, ExportedDigest{ID: id, Text: l.text, Counters: l.c})
		}
	}
	sort.Slice(exported, func(i, j int) bool { return exported[i].ID < exported[j].ID })

	cmds := make(map[string]model.QueryCounters, len(a.commands))
	for k, v := range a.commands {
		cmds[k] = v
	}
	return Snapshot{
		WindowSeconds:   int(a.cfg.Window / time.Second),
		CPUAccounting:   acct,
		QueryCPUMsTotal: float64(cpuAll) / 1e6,
		Thresholds: model.QueryRoleThresholds{
			CulpritCPUSharePercent: a.cfg.CulpritCPUSharePercent,
			CulpritMinCPUPercent:   a.cfg.CulpritMinCPUPercent,
			VictimRunqRatio:        a.cfg.VictimRunqRatio,
		},
		TopByCPU:      byCPU,
		TopByBytesOut: byOut,
		Exported:      exported,
		Commands:      cmds,
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
		l.c.CPUNs += uint64(s.CPUMsTotal*1e6 + 0.5)
		l.c.WallNs += uint64(s.WallMsAvg*float64(s.Calls)*1e6 + 0.5)
		l.c.RunqNs += uint64(s.RunqWaitMsAvg*float64(s.Calls)*1e6 + 0.5)
		l.c.BytesIn += s.BytesInTotal
		l.c.BytesOut += s.BytesOutTotal
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

func (a *Aggregator) toStats(k key, x *acc, pidCPU uint64, acct string) model.QueryDigestStats {
	ms := func(ns uint64) float64 { return float64(ns) / 1e6 }
	calls := float64(x.calls)
	cpuAvg, runqAvg, wallAvg := ms(x.cpu)/calls, ms(x.runq)/calls, ms(x.wall)/calls
	share := 0.0
	if pidCPU > 0 {
		share = 100 * float64(x.cpu) / float64(pidCPU)
	}
	// Averaged over the full window, so it is understated (never overstated)
	// while the agent has run for less than one window.
	ofCore := 100 * float64(x.cpu) / float64(a.cfg.Window.Nanoseconds())
	wait := runqAvg
	if acct == AccountingNoRunDelay {
		wait = wallAvg - cpuAvg
	}
	role := ""
	switch {
	// share alone is relative to the other queries: on an idle server the
	// monitoring queries reach 80–90 % of almost nothing. A culprit must also
	// burn a real fraction of a core.
	case share >= a.cfg.CulpritCPUSharePercent && ofCore >= a.cfg.CulpritMinCPUPercent:
		role = RoleCulprit
	case wait > cpuAvg*a.cfg.VictimRunqRatio && wallAvg >= ms(a.cfg.SlowWallNs):
		role = RoleVictim
	}
	if k.id == OtherDigestID {
		role = ""
	}
	return model.QueryDigestStats{
		PID: k.pid, DigestID: k.id, Command: x.command, DigestText: x.text,
		SampleQuery: x.sample, Normalized: x.normalized, Truncated: x.truncated,
		Calls:      x.calls,
		CPUMsTotal: ms(x.cpu), CPUMsAvg: cpuAvg, CPUMsMax: ms(x.cpuMax),
		RunqWaitMsAvg: runqAvg,
		WallMsAvg:     wallAvg, WallMsMax: ms(x.wallMax),
		BytesInTotal: x.in, BytesOutTotal: x.out, BytesOutAvg: float64(x.out) / calls,
		CPUSharePercent:  share,
		CPUPercentOfCore: ofCore,
		Role:             role,
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
