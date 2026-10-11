package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/drain"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/overload"
	"github.com/manhvu1997/linux-obs-agent/internal/pgdrain"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pghash"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgstat"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgsym"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
	"github.com/manhvu1997/linux-obs-agent/internal/procinfo"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
	"github.com/manhvu1997/linux-obs-agent/internal/textcache"
)

// sessionCapacity is the kernel's pg_session map size.
const sessionCapacity = 16384

// Accounting values set by the analyzer (postgres names).
const (
	reasonNoIOAccounting = "io_accounting_unavailable"
	reasonNoBlkioDelay   = "blkio_delay_unavailable"
	reasonDelayAcctOff   = "delayacct_disabled"
	reasonAsyncIO        = "io_method_async"
	reasonNoXLogFlush    = "xlogflush_unavailable"
	reasonNotAttached    = "not_attached"
	reasonNoTracer       = "tracer_unavailable"
	StateActive          = "active"
	StateShed            = "shed"
)

// Options configure the analyzer; cmd/agent maps config.PostgresConfig.
type Options struct {
	SlowQueryThresholdMs                                        uint64
	PollInterval, DigestWindow, DiscoverInterval, ShedCooldown  time.Duration
	SQLPollInterval                                             time.Duration
	TopDigests, StickyDigestsMax, MaxRecentQueries              int
	StickyDigestTTL                                             time.Duration
	CPUCulpritPercentOfNodeCPUUsed, CPUCulpritMinNodeCPUUsedPct float64
	VictimWaitPercent, IOCulpritPercentOfDiskRead               float64
	IOCulpritMinNodeDiskReadMBPerSec, BackgroundDominantPercent float64
	MaxStatementsPerSec                                         float64
	FoldSystemCatalogs, SampleQueries, EnableDelayAcct          bool
	IncludeIO                                                   bool
	SyncRepWait                                                 string   // auto | true | false
	BinaryPaths                                                 []string // allow-list; empty traces every postmaster
}

// Deps are the analyzer's I/O; zero fields take the real implementation.
type Deps struct {
	Tracer     pgtrace.Tracer   // required
	Enricher   *pgstat.Enricher // nil: SQL enrichment off
	Proc       procFS
	ReadELF    func(path string) (pgsym.Version, []string, error)
	NodeCPU    func() (collector.NodeCPUTimes, error)
	NodeDisk   func() (collector.NodeDiskBytes, error)
	ReadThread func(tid uint32) (procCounters, error)
	DelayAcct  func() (bool, error)
	Mono       func() uint64 // CLOCK_MONOTONIC ns (bpf_ktime_get_ns)
	SysFS      string
	PIDCPU     func(pid uint32) (uint64, error)
	Children   func(pid uint32) []uint32
	NumCPU     int
	StatKey    func(path string) (pgtrace.BinaryKey, error) // binary_paths → keys
}

type binary struct {
	path     string
	hooks    pgsym.Hooks
	err      error
	attached bool
	syncRep  bool
	queryID  bool
	res      pgtrace.Attached
}

type cluster struct {
	pid     uint32 // postmaster PID (immutable; the clusters map key)
	pmMu    sync.RWMutex
	pm      Postmaster // refreshed by discover; read through post()
	name    string
	version pgsym.Version
	consts  pgtrace.ClusterConst
	key     pgtrace.BinaryKey
	agg     *querystats.Aggregator
	cpu     *clusterCPU

	mu         sync.Mutex
	recent     []model.PGSlowQuery
	slow       drain.Buffer[model.PGSlowQuery]
	enrichSent time.Time // enrichment deltas already exported to ClickHouse
}

func (c *cluster) post() Postmaster {
	c.pmMu.RLock()
	defer c.pmMu.RUnlock()
	return c.pm
}

func (c *cluster) setPost(pm Postmaster) {
	c.pmMu.Lock()
	c.pm = pm
	c.pmMu.Unlock()
}

// tr is the tracer, or a no-op one after a failed start.
func (a *Analyzer) tr() pgtrace.Tracer {
	if a.noTracer.Load() {
		return noTracer{}
	}
	return a.d.Tracer
}

// noTracer stands in for a tracer that failed to start.
type noTracer struct{}

func (noTracer) Start(context.Context) error                       { return nil }
func (noTracer) Stop()                                             {}
func (noTracer) SetClusters(map[uint32]pgtrace.ClusterConst) error { return nil }
func (noTracer) Attach(pgtrace.Binary) (pgtrace.Attached, error)   { return pgtrace.Attached{}, nil }
func (noTracer) Detach(pgtrace.BinaryKey)                          {}
func (noTracer) DetachAll()                                        {}
func (noTracer) ClearSessions() error                              { return nil }
func (noTracer) DrainAgg() ([]pgtrace.AggEntry, error)             { return nil, nil }
func (noTracer) OpenSessions() ([]pgtrace.Session, error)          { return nil, nil }
func (noTracer) QueryIDs() (map[uint64]int64, error)               { return nil, nil }
func (noTracer) ForgetText(uint64)                                 {}
func (noTracer) MarkUnsafe(uint64)                                 {}
func (noTracer) Texts() <-chan pgtrace.TextEvent                   { return nil }
func (noTracer) Cmds() <-chan pgtrace.CmdEvent                     { return nil }
func (noTracer) Slows() <-chan pgtrace.SlowEvent                   { return nil }
func (noTracer) Dropped() uint64                                   { return 0 }
func (noTracer) TextDropped() uint64                               { return 0 }
func (noTracer) AggOverflow() uint64                               { return 0 }
func (noTracer) LiteralSkip() bool                                 { return true }
func (noTracer) Accounting() pgtrace.Accounting                    { return pgtrace.Accounting{} }

// ClusterView is one cluster's latest state for the exporters.
type ClusterView struct {
	Name          string
	PostmasterPID uint32
	Snapshot      *querystats.Snapshot
	Overload      overload.Report
	Backends      map[string]BackendLife
	Accounting    map[string]string
	EnrichmentUp  bool
}

// Analyzer attributes PostgreSQL load (see package doc).
type Analyzer struct {
	opts Options
	d    Deps
	text *textcache.Cache
	cred *creditor
	brk  breaker
	back *BackendSampler

	mu        sync.Mutex // clusters, binaries
	clusters  map[uint32]*cluster
	binaries  map[pgtrace.BinaryKey]*binary
	drainKeys int // 0: ClickHouse digest drain off
	drainSlow int
	toForget  []int // enricher ports of dropped clusters, forgotten after a.mu is released

	// poll goroutine only
	prevNode collector.NodeCPUTimes
	haveNode bool
	prevDisk collector.NodeDiskBytes
	haveDisk bool

	latest        atomic.Pointer[model.PostgresAnalysis]
	views         atomic.Pointer[[]ClusterView]
	state         atomic.Value // string
	overCap       atomic.Bool
	noTracer      atomic.Bool   // the tracer failed to start: report without digests
	cmdCalls      atomic.Uint64 // calls of fallback command events since the last poll (breaker input)
	enriching     atomic.Bool   // single-flight guard of the SQL poll
	wg            sync.WaitGroup
	shedTotal     atomic.Uint64
	creditDropped atomic.Uint64
	rediscover    chan struct{} // enrichment asks the main loop to re-run discovery
}

// NewAnalyzer wires an analyzer; Start runs it.
func NewAnalyzer(o Options, d Deps) *Analyzer {
	if d.Proc == nil {
		d.Proc = realProc{}
	}
	if d.ReadELF == nil {
		d.ReadELF = pgsym.ReadELF
	}
	if d.NodeCPU == nil {
		d.NodeCPU = collector.ReadNodeCPUTimes
	}
	if d.NodeDisk == nil {
		d.NodeDisk = collector.ReadNodeDiskBytes
	}
	if d.ReadThread == nil {
		d.ReadThread = readThread
	}
	if d.DelayAcct == nil {
		d.DelayAcct = procinfo.DelayAcctEnabled
	}
	if d.Mono == nil {
		d.Mono = monoNow
	}
	if d.SysFS == "" {
		d.SysFS = "/sys"
	}
	if d.PIDCPU == nil {
		d.PIDCPU = procinfo.ReadCPUTimeNs
	}
	if d.Children == nil {
		d.Children = childrenOf
	}
	if d.StatKey == nil {
		d.StatKey = statKey
	}
	a := &Analyzer{opts: o, d: d, clusters: map[uint32]*cluster{}, binaries: map[pgtrace.BinaryKey]*binary{},
		brk:  breaker{max: o.MaxStatementsPerSec, cooldown: o.ShedCooldown},
		back: NewBackendSampler(o.DigestWindow, o.IncludeIO),
		cred: newCreditor(uint64(o.PollInterval), d.ReadThread), rediscover: make(chan struct{}, 1)}
	a.text = textcache.New(32768, textcache.Hooks{
		Forget:     func(_ uint32, h uint64) { d.Tracer.ForgetText(h) },
		MarkUnsafe: func(_ uint32, h uint64) { d.Tracer.MarkUnsafe(h) },
		Command:    func(e textcache.Entry, s textcache.Sums) string { return commandOf(s.Kind, e) },
	})
	a.state.Store(StateActive)
	return a
}

func monoNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// Start loads the tracer, discovers clusters and polls until ctx is done.
func (a *Analyzer) Start(ctx context.Context) error {
	if err := a.d.Tracer.Start(ctx); err != nil {
		// Spec §11: keep discovering clusters and reporting backend types
		// without the tracer; the report says why there are no digests.
		slog.Warn("postgres: tracer unavailable; reporting backend types only", "err", err)
		a.state.Store("unavailable: " + err.Error())
		a.noTracer.Store(true)
	} else {
		defer a.d.Tracer.Stop()
	}
	defer func() { // join the goroutines first: none may use the tracer or enricher afterwards
		a.wg.Wait()
		if a.d.Enricher != nil {
			a.d.Enricher.Close()
		}
	}()
	if a.opts.EnableDelayAcct {
		if on, err := procinfo.DelayAcctEnabled(); err == nil && !on {
			if err := procinfo.EnableDelayAcct(); err != nil {
				slog.Warn("postgres: could not enable delay accounting (needs CAP_SYS_ADMIN)", "err", err)
			}
		}
	}
	a.primeNode()
	a.discover(time.Now())
	if a.noTracer.Load() {
		a.poll(time.Now()) // publish the "unavailable" report without waiting for a tick
	}
	if !a.noTracer.Load() {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.consume(ctx)
		}()
	}

	poll := time.NewTicker(a.opts.PollInterval)
	disc := time.NewTicker(a.opts.DiscoverInterval)
	defer poll.Stop()
	defer disc.Stop()
	var sql <-chan time.Time
	if a.d.Enricher != nil {
		t := time.NewTicker(a.opts.SQLPollInterval)
		defer t.Stop()
		sql = t.C
		a.startEnrich(ctx, time.Now())
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-poll.C:
			a.poll(now)
		case now := <-disc.C:
			a.discover(now)
		case now := <-sql:
			a.startEnrich(ctx, now)
		case <-a.rediscover:
			a.discover(time.Now())
		}
	}
}

// startEnrich runs one SQL poll in the background unless the previous one is
// still running (single-flight); it reports whether one was started.
func (a *Analyzer) startEnrich(ctx context.Context, now time.Time) bool {
	if !a.enriching.CompareAndSwap(false, true) {
		return false
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.enriching.Store(false)
		a.enrich(ctx, now)
	}()
	return true
}

func (a *Analyzer) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-a.tr().Texts():
			a.learnText(ev)
		case ev := <-a.tr().Cmds():
			a.recordCmd(ev, time.Now())
		case ev := <-a.tr().Slows():
			a.recordSlow(ev)
		}
	}
}

// ─── Text and placeholders ───────────────────────────────────────────────────

func mkDigest(text string) sqldigest.Digest {
	return sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: true}
}

var (
	systemCatalogDigest = mkDigest("<system catalogs>")
	textUnavailable     = mkDigest("<text unavailable>")
	fastpathDigest      = mkDigest("<FASTPATH function call>")
)

func (a *Analyzer) classify(text string, truncated bool) textcache.Entry {
	d := sqldigest.NormalizeDialect(text, sqldigest.Postgres)
	// The command is named from the raw statement, before catalog folding: an
	// "autovacuum: VACUUM … pg_catalog.x" must stay autovacuum, never client.
	class := commandFor(pgtrace.KindClient, d.Text)
	sample := text
	// Only client statements fold: an autovacuum or walsender digest is per-table and
	// must not share an id (and thus a command) with client catalog queries.
	if a.opts.FoldSystemCatalogs && class == CommandClient && sqldigest.ReferencesSystemCatalog(d.Text) {
		d, sample, truncated = systemCatalogDigest, "", false
	}
	if !a.opts.SampleQueries {
		sample = ""
	}
	return textcache.Entry{Class: class, Digest: d, Sample: sample, Truncated: truncated}
}

func byKind(kind uint32) textcache.Entry {
	if kind == pgtrace.KindFastpath {
		return textcache.Entry{Class: CommandFastpath, Digest: fastpathDigest}
	}
	return textcache.Entry{Class: CommandClient, Digest: textUnavailable}
}

// learnText records a text event; a first-sight text is also checked against
// the Go reference of the kernel hash (any drift marks the hash unsafe).
func (a *Analyzer) learnText(ev pgtrace.TextEvent) {
	e := a.classify(ev.Text, ev.Truncated)
	k := textcache.Key{Hash: ev.Hash}
	if ev.Verify {
		if a.text.Verify(k, e) {
			slog.Warn("postgres: kernel text hash disagrees with the digest; statement switched to exact processing", "hash", ev.Hash)
		}
		return
	}
	if a.text.Learn(k, e) {
		return
	}
	want := pghash.ExactHash
	if a.tr().LiteralSkip() {
		want = pghash.KernelHash
	}
	if got := want([]byte(ev.Text)); got != ev.Hash {
		slog.Warn("postgres: kernel text hash differs from the Go reference; statement switched to exact processing",
			"kernel_hash", ev.Hash, "go_hash", got)
		a.text.FlagMismatch(k)
	}
}

func cacheKey(kind uint32, hash uint64) textcache.Key {
	if hash == 0 {
		return textcache.Key{Command: kind} // placeholder by kind
	}
	return textcache.Key{Hash: hash}
}

// zeroParallel keeps only a parallel worker's CPU and disk bytes: the
// leader's interval already covers the elapsed time and the waits.
func zeroParallel(s *textcache.Sums) {
	if s.Kind == pgtrace.KindParallel {
		s.Calls, s.WallNs, s.WallMaxNs, s.RunqNs, s.IOWaitNs, s.RedoWaitNs, s.ReplicaWaitNs = 0, 0, 0, 0, 0, 0, 0
	}
}

// resolve turns drained entries and credits into deltas per postmaster and
// returns the statement count (calls) for the circuit breaker.
func (a *Analyzer) resolve(entries []pgtrace.AggEntry, credits []credit) (map[uint32][]querystats.Delta, uint64) {
	out := map[uint32][]querystats.Delta{}
	var calls uint64
	add := func(d querystats.Delta, ok bool) {
		if ok {
			d.Auxiliary = d.Command == CommandParallel
			out[d.PID] = append(out[d.PID], d)
		}
	}
	for _, en := range entries {
		calls += en.Calls
		s := textcache.Sums{PID: en.Postmaster, Kind: en.Kind, Calls: en.Calls, WallNs: en.WallNs, WallMaxNs: en.WallMaxNs,
			CPUNs: en.CPUNs, RunqNs: en.RunqNs, DiskReadBytes: en.DiskReadBytes, DiskWriteBytes: en.DiskWriteBytes,
			IOWaitNs: en.IOWaitNs, RedoWaitNs: en.WALWaitNs, ReplicaWaitNs: en.SyncRepWaitNs}
		zeroParallel(&s)
		add(a.text.Resolve(cacheKey(en.Kind, en.Hash), s, byKind))
	}
	for _, c := range credits {
		s := textcache.Sums{PID: c.Postmaster, Kind: c.Kind, CPUNs: c.CPU, RunqNs: c.Runq,
			DiskReadBytes: c.Read, DiskWriteBytes: c.Write, IOWaitNs: c.Blkio}
		zeroParallel(&s)
		add(a.text.Resolve(cacheKey(c.Kind, c.Hash), s, byKind))
	}
	for _, d := range a.text.EndTick(func(uint32) textcache.Entry { return byKind(pgtrace.KindClient) }) {
		add(d, true)
	}
	return out, calls
}

func (a *Analyzer) cluster(pm uint32) *cluster {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clusters[pm]
}

// recordCmd handles an interval the kernel could not aggregate. Credit already
// given to the interval while it ran is subtracted (the event carries the full
// sums), and a hash whose text has not arrived yet is parked until it does
// (or, after a tick, shown as unavailable) exactly like an aggregated entry.
func (a *Analyzer) recordCmd(ev pgtrace.CmdEvent, now time.Time) {
	c := a.cluster(ev.Postmaster)
	if c == nil {
		return
	}
	a.cmdCalls.Add(ev.Calls)
	p := procCounters{CPU: ev.CPUNs, Runq: ev.RunqNs, Read: ev.DiskReadBytes, Write: ev.DiskWriteBytes, Blkio: ev.IOWaitNs}
	a.cred.SettleCmd(aggKey{ev.Postmaster, ev.Kind, ev.Hash}, ev.PID, &p)
	s := textcache.Sums{PID: ev.Postmaster, Kind: ev.Kind, Calls: ev.Calls, WallNs: ev.WallNs, WallMaxNs: ev.WallNs, CPUNs: p.CPU,
		RunqNs: p.Runq, DiskReadBytes: p.Read, DiskWriteBytes: p.Write, IOWaitNs: p.Blkio,
		RedoWaitNs: ev.WALWaitNs, ReplicaWaitNs: ev.SyncRepWaitNs}
	zeroParallel(&s)
	var d querystats.Delta
	if ev.Text != "" {
		e := a.classify(ev.Text, len(ev.Text) >= pghash.MaxText)
		d = querystats.Delta{PID: s.PID, Command: commandOf(ev.Kind, e), Digest: e.Digest, SampleQuery: e.Sample, Truncated: e.Truncated,
			Calls: s.Calls, WallNs: s.WallNs, WallMaxNs: s.WallMaxNs, CPUNs: s.CPUNs, RunqNs: s.RunqNs,
			DiskReadBytes: s.DiskReadBytes, DiskWriteBytes: s.DiskWriteBytes, IOWaitNs: s.IOWaitNs,
			RedoWaitNs: s.RedoWaitNs, ReplicaWaitNs: s.ReplicaWaitNs}
	} else {
		var ok bool
		if d, ok = a.text.Resolve(cacheKey(ev.Kind, ev.Hash), s, byKind); !ok {
			return // parked: poll's EndTick emits it once the text arrives
		}
	}
	d.Auxiliary = d.Command == CommandParallel
	c.agg.AddDeltas([]querystats.Delta{d}, now)
}

// recordSlow keeps slow client statements (not autovacuum or replication).
func (a *Analyzer) recordSlow(ev pgtrace.SlowEvent) {
	c := a.cluster(ev.Postmaster)
	if c == nil {
		return
	}
	e, ok := a.text.Lookup(textcache.Key{Hash: ev.Hash})
	if ev.Hash == 0 || !ok {
		e = byKind(pgtrace.KindClient)
	}
	if commandOf(pgtrace.KindClient, e) != CommandClient {
		return
	}
	q := model.PGSlowQuery{PID: ev.PID, DigestID: e.Digest.ID, DigestText: e.Digest.Text, SampleQuery: e.Sample,
		LatencyMs: float64(ev.WallNs) / 1e6, CPUMs: float64(ev.CPUNs) / 1e6, Timestamp: ev.At}
	max := a.opts.MaxRecentQueries
	if max <= 0 {
		max = 100
	}
	c.mu.Lock()
	c.recent = append(c.recent, q)
	if len(c.recent) > max {
		c.recent = c.recent[len(c.recent)-max:]
	}
	c.mu.Unlock()
	c.slow.Add(q)
}

// ─── Discovery ───────────────────────────────────────────────────────────────

func (a *Analyzer) newCluster(pm Postmaster, name string, b *binary) *cluster {
	agg := querystats.New(querystats.Config{
		Window: a.opts.DigestWindow, TopN: a.opts.TopDigests, TopNBytes: 1,
		CPUCulpritPercentOfNodeUsed: a.opts.CPUCulpritPercentOfNodeCPUUsed, CPUCulpritMinNodeUsedPercent: a.opts.CPUCulpritMinNodeCPUUsedPct,
		VictimWaitPercent: a.opts.VictimWaitPercent, IOCulpritPercentOfDiskRead: a.opts.IOCulpritPercentOfDiskRead,
		IOCulpritMinNodeDiskReadMBPerSec: a.opts.IOCulpritMinNodeDiskReadMBPerSec,
		SlowWallNs:                       a.opts.SlowQueryThresholdMs * uint64(time.Millisecond),
		StickyMax:                        a.opts.StickyDigestsMax, StickyTTL: a.opts.StickyDigestTTL,
		PageBytes: PageBytes, ReplicaWait: true,
	})
	if a.drainKeys > 0 {
		agg.EnableDrain(a.drainKeys)
		agg.EnableHostDrain()
	}
	c := &cluster{pid: pm.PID, pm: pm, name: name, version: b.hooks.Version, key: pm.Key, agg: agg,
		consts: pgtrace.ClusterConst{Running: b.hooks.States.Running, Fastpath: b.hooks.States.Fastpath},
		cpu: &clusterCPU{cgroupRead: cgroupCPUReader(a.d.SysFS, pm.Cgroup, pm.Unit),
			pids: func() []uint32 { return a.d.Children(pm.PID) }, pidCPU: a.d.PIDCPU, prevPID: map[uint32]uint64{}}}
	if a.drainSlow > 0 {
		c.slow.Enable(a.drainSlow)
	}
	c.cpu.sample() // baseline
	return c
}

// dropClusterLocked forgets a cluster that vanished or restarted. Limit: data
// it accumulated since the last ClickHouse drain is discarded with it.
func (a *Analyzer) dropClusterLocked(pid uint32) {
	c := a.clusters[pid]
	delete(a.clusters, pid)
	a.back.Forget(pid)
	if a.d.Enricher != nil && c != nil {
		a.toForget = append(a.toForget, c.post().Port)
	}
}

// wantSyncRep: postgres.syncrep_wait true, or auto with synchronous
// standbys configured (needs SQL).
func (a *Analyzer) wantSyncRep(port int) bool {
	switch a.opts.SyncRepWait {
	case "true":
		return true
	case "auto":
		return a.d.Enricher != nil && a.d.Enricher.Snapshot(port).Settings.SyncRep()
	}
	return false
}

// discover reconciles postmasters, the clusters map and the attached binaries.
func (a *Analyzer) discover(now time.Time) {
	a.discoverLocked(now)
	// Forget can wait for an in-flight SQL poll: never under a.mu.
	a.mu.Lock()
	ports := a.toForget
	a.toForget = nil
	a.mu.Unlock()
	for _, p := range ports {
		a.d.Enricher.Forget(p)
	}
}

func (a *Analyzer) discoverLocked(now time.Time) {
	pms, err := Discover(a.d.Proc)
	if err != nil {
		slog.Warn("postgres: discovery", "err", err)
		return
	}
	allow := a.allowedKeys()
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := map[uint32]bool{}
	live := make(map[uint32]bool, len(pms))
	for _, pm := range pms {
		live[pm.PID] = true
	}
	for _, pm := range pms {
		if allow != nil && !allow[pm.Key] {
			continue // postgres.binary_paths excludes this binary
		}
		seen[pm.PID] = true
		b := a.binaries[pm.Key]
		if b == nil {
			b = &binary{}
			v, syms, err := a.d.ReadELF(pm.Exe)
			if err == nil {
				b.hooks, err = pgsym.Resolve(v, syms)
			}
			b.err = err
			a.binaries[pm.Key] = b
			if err != nil {
				slog.Warn("postgres: binary not traced", "path", pm.Exe, "err", err)
			}
		}
		b.path = pm.Exe // a live postmaster's /proc/<pid>/exe
		if b.err != nil {
			continue
		}
		if c, ok := a.clusters[pm.PID]; ok {
			c.setPost(pm)
			continue
		}
		name := ClusterName(pm, b.hooks.Version.Major)
		for pid, old := range a.clusters {
			if old.name == name && !live[pid] { // restarted: the old postmaster is gone
				a.dropClusterLocked(pid)
			}
		}
		a.clusters[pm.PID] = a.newCluster(pm, name, b)
		slog.Info("postgres: cluster traced", "cluster", name, "version", b.hooks.Version.String(), "postmaster", pm.PID, "port", pm.Port)
	}
	for pid := range a.clusters {
		if !seen[pid] {
			a.dropClusterLocked(pid)
		}
	}
	consts := map[uint32]pgtrace.ClusterConst{}
	used := map[pgtrace.BinaryKey]bool{}
	syncReps := map[pgtrace.BinaryKey]bool{} // OR over every cluster sharing the binary: order-independent
	for pid, c := range a.clusters {
		consts[pid] = c.consts
		used[c.key] = true
		syncReps[c.key] = syncReps[c.key] || a.wantSyncRep(c.post().Port)
	}
	if err := a.tr().SetClusters(consts); err != nil {
		slog.Warn("postgres: clusters map", "err", err)
	}
	if len(consts) > 0 && a.overCap.Load() {
		slog.Warn("postgres: more live backends than the kernel session map holds; some intervals are lost", "capacity", sessionCapacity)
	}
	if a.brk.shed {
		return
	}
	for key, b := range a.binaries {
		if !used[key] || b.err != nil {
			if b.attached {
				a.tr().Detach(key)
				b.attached = false
			}
			continue
		}
		syncRep, queryID := syncReps[key], a.d.Enricher != nil
		if b.attached && b.syncRep == syncRep && b.queryID == queryID {
			continue
		}
		if b.attached && ((b.syncRep && !syncRep) || (b.queryID && !queryID)) {
			// An optional hook must go: only a full re-attach removes it, and
			// the sessions opened under the old hooks are meaningless after it.
			a.tr().Detach(key)
			if err := a.tr().ClearSessions(); err != nil {
				slog.Warn("postgres: clearing sessions", "err", err)
			}
		} // adding a hook needs no Detach: Attach attaches only what is new, without a gap
		h := b.hooks
		res, err := a.tr().Attach(pgtrace.Binary{Key: key, Path: b.path, SyncRep: syncRep, QueryID: queryID,
			Hooks: pgtrace.Hooks{Activity: h.Activity, PortalRun: h.PortalRun, QueryID: h.QueryID,
				XLogFlush: h.XLogFlush, SyncRep: h.SyncRep, Parallel: h.Parallel}})
		if err != nil {
			slog.Warn("postgres: attach failed", "path", b.path, "err", err)
			b.attached = false
			continue
		}
		b.attached, b.syncRep, b.queryID, b.res = true, syncRep, queryID, res
		slog.Info("postgres hooks ("+h.Version.String()+"): "+h.Summary(queryID, syncRep), "path", b.path)
	}
}

// allowedKeys resolves postgres.binary_paths to inodes (nil: no allow-list).
// A path that cannot be read is logged and skipped.
func (a *Analyzer) allowedKeys() map[pgtrace.BinaryKey]bool {
	if len(a.opts.BinaryPaths) == 0 {
		return nil
	}
	out := map[pgtrace.BinaryKey]bool{}
	for _, p := range a.opts.BinaryPaths {
		k, err := a.d.StatKey(p)
		if err != nil {
			slog.Warn("postgres: binary_paths entry unreadable", "path", p, "err", err)
			continue
		}
		out[k] = true
	}
	return out
}

func statKey(path string) (pgtrace.BinaryKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return pgtrace.BinaryKey{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return pgtrace.BinaryKey{}, fmt.Errorf("no stat_t for %s", path)
	}
	return pgtrace.BinaryKey{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}

// ObserveScan is the process inspector's scan hook (backend types).
func (a *Analyzer) ObserveScan(all []model.ProcessStats, at time.Time) {
	a.mu.Lock()
	pms := make(map[uint32]bool, len(a.clusters))
	for pid := range a.clusters {
		pms[pid] = true
	}
	a.mu.Unlock()
	n := 0
	for _, p := range all {
		if pms[p.PPID] {
			n++
		}
	}
	a.overCap.Store(n >= sessionCapacity)
	numCPU := a.d.NumCPU
	if numCPU <= 0 {
		numCPU = 1
	}
	a.back.Observe(all, pms, numCPU, at)
}

// ─── Poll ────────────────────────────────────────────────────────────────────

func (a *Analyzer) primeNode() {
	if n, err := a.d.NodeCPU(); err == nil {
		a.prevNode, a.haveNode = n, true
	}
	if dk, err := a.d.NodeDisk(); err == nil {
		a.prevDisk, a.haveDisk = dk, true
	}
}

// sampleNode returns the node's CPU and disk deltas since the last poll.
func (a *Analyzer) sampleNode() querystats.HostDelta {
	var h querystats.HostDelta
	if n, err := a.d.NodeCPU(); err != nil {
		a.haveNode = false
	} else if a.haveNode && n.UsedNs >= a.prevNode.UsedNs && n.TotalNs > a.prevNode.TotalNs {
		h.NodeOK = true
		h.NodeCPUUsedNs, h.NodeCPUTotalNs, h.NumCPU = n.UsedNs-a.prevNode.UsedNs, n.TotalNs-a.prevNode.TotalNs, n.NumCPU
		a.prevNode = n
	} else {
		a.prevNode, a.haveNode = n, true
	}
	if dk, err := a.d.NodeDisk(); err != nil {
		a.haveDisk = false
	} else if a.haveDisk && dk.Disks == a.prevDisk.Disks && dk.ReadBytes >= a.prevDisk.ReadBytes && dk.WriteBytes >= a.prevDisk.WriteBytes {
		h.DiskOK = true
		h.DiskReadBytes, h.DiskWriteBytes = dk.ReadBytes-a.prevDisk.ReadBytes, dk.WriteBytes-a.prevDisk.WriteBytes
		a.prevDisk = dk
	} else {
		a.prevDisk, a.haveDisk = dk, true
	}
	return h
}

// async: PG 18+ reads go through I/O workers or io_uring unless io_method is
// sync (known only with SQL; without it PG 18+ is treated as async).
func (a *Analyzer) async(c *cluster) bool {
	if c.version.Major < 18 {
		return false
	}
	if a.d.Enricher != nil {
		if v := a.d.Enricher.Snapshot(c.post().Port); v.Known {
			return v.Settings.IOMethod != "sync"
		}
	}
	return true
}

func (a *Analyzer) setReasons(c *cluster, res pgtrace.Attached, h *querystats.HostDelta) {
	if a.noTracer.Load() {
		h.QueryDiskReason, h.IOWaitReason, h.RedoWaitReason, h.ReplicaWaitReason = reasonNoTracer, reasonNoTracer, reasonNoTracer, reasonNoTracer
		return
	}
	acct := a.tr().Accounting()
	async := a.async(c)
	switch {
	case !acct.DiskBytes:
		h.QueryDiskReason = reasonNoIOAccounting
	case async:
		h.QueryDiskReason = reasonAsyncIO
	}
	switch on, err := a.d.DelayAcct(); {
	case !acct.BlkioDelay:
		h.IOWaitReason = reasonNoBlkioDelay
	case err != nil || !on:
		h.IOWaitReason = reasonDelayAcctOff
	case async:
		h.IOWaitReason = reasonAsyncIO
	}
	if !res.WAL {
		h.RedoWaitReason = reasonNoXLogFlush
	}
	if !res.SyncRep {
		h.ReplicaWaitReason = reasonNotAttached
	}
}

// poll drains the kernel, credits long intervals and publishes the report.
func (a *Analyzer) poll(now time.Time) {
	if a.brk.shed {
		if a.brk.observe(0, now) != actResume {
			return
		}
		a.state.Store(StateActive)
		slog.Info("postgres: circuit breaker cooldown over; re-attaching probes")
		a.discover(now)
		// Nothing was sampled during the cooldown: re-baseline everything so
		// the first poll after it is not booked as one huge valid interval,
		// and drop credit for sessions the detached probes can no longer close.
		a.primeNode()
		a.mu.Lock()
		for _, c := range a.clusters {
			c.cpu.sample()
		}
		a.mu.Unlock()
		a.cred.Reset()
	}
	entries, err := a.tr().DrainAgg()
	if err != nil {
		slog.Warn("postgres: draining kernel aggregation", "err", err)
	}
	sessions, err := a.tr().OpenSessions()
	var credits []credit
	if err != nil {
		// An unreadable session map is not "no sessions": crediting nothing
		// is safe, settling (which would age and drop owed credit) is not.
		slog.Debug("postgres: reading sessions", "err", err)
	} else {
		known := func(h uint64) bool { _, ok := a.text.Lookup(textcache.Key{Hash: h}); return ok }
		credits = a.cred.Credit(sessions, a.d.Mono(), known)
		entries = a.cred.Settle(entries)
	}
	a.creditDropped.Store(a.cred.Dropped())
	byPM, calls := a.resolve(entries, credits)
	calls += a.cmdCalls.Swap(0) // intervals the kernel map could not aggregate count too
	if a.brk.observe(float64(calls)/a.opts.PollInterval.Seconds(), now) == actShed {
		slog.Warn("postgres: statement rate above postgres.max_statements_per_sec for two polls; probes detached",
			"rate_per_sec", float64(calls)/a.opts.PollInterval.Seconds(), "cooldown", a.opts.ShedCooldown)
		a.tr().DetachAll()
		if err := a.tr().ClearSessions(); err != nil {
			slog.Warn("postgres: clearing sessions", "err", err)
		}
		a.mu.Lock()
		for _, b := range a.binaries {
			b.attached = false
		}
		a.mu.Unlock()
		a.state.Store(StateShed)
		a.shedTotal.Store(a.brk.total)
	}
	node := a.sampleNode()

	a.mu.Lock()
	type item struct {
		c   *cluster
		res pgtrace.Attached
	}
	var cs []item
	for _, c := range a.clusters {
		cs = append(cs, item{c, a.binaries[c.key].res})
	}
	a.mu.Unlock()
	sort.Slice(cs, func(i, j int) bool { return cs[i].c.name < cs[j].c.name })

	views := make([]ClusterView, 0, len(cs))
	for _, it := range cs {
		c := it.c
		c.agg.AddDeltas(byPM[c.pid], now)
		h := node
		h.MysqldCPUNs, h.MysqldPartial = c.cpu.sample()
		a.setReasons(c, it.res, &h)
		c.agg.AddHost(h, now)
		snap := c.agg.Snapshot(now)
		views = append(views, a.view(c, &snap))
	}
	a.views.Store(&views)
	a.latest.Store(a.report(views, now))
}

// ─── Report ──────────────────────────────────────────────────────────────────

// digestEnrichment maps digest id → enrichment over the latest SQL poll.
func (a *Analyzer) digestEnrichment(c *cluster) (map[string]enrichment, pgstat.View) {
	if a.d.Enricher == nil {
		return nil, pgstat.View{Status: pgstat.StatusNotConfigured}
	}
	v := a.d.Enricher.Snapshot(c.post().Port)
	qids, err := a.tr().QueryIDs()
	if err != nil || len(v.Deltas) == 0 {
		return nil, v
	}
	out := map[string]enrichment{}
	for h, id := range qids {
		e, ok := a.text.Lookup(textcache.Key{Hash: h})
		d, okd := v.Deltas[id]
		if !ok || !okd {
			continue
		}
		x := out[e.Digest.ID]
		if x.queryID != 0 && x.queryID == id {
			continue // same queryid through another hash: counted once
		}
		x.queryID = id
		x.Calls += d.Calls
		x.SharedHit += d.SharedHit
		x.SharedRead += d.SharedRead
		x.TempWrite += d.TempWrite
		x.ReadTimeMs += d.ReadTimeMs
		x.Window, x.BlockSize, x.TrackIOTiming = v.Window, max(v.Settings.BlockSize, PageBytes), v.Settings.TrackIOTiming
		out[e.Digest.ID] = x
	}
	return out, v
}

func (a *Analyzer) view(c *cluster, snap *querystats.Snapshot) ClusterView {
	enr, ev := a.digestEnrichment(c)
	cores, reads, _ := a.back.Window(c.pid)
	top := append([]model.QueryDigestStats(nil), snap.TopByCPU...)
	byDisk := snap.TopByDiskRead
	estimated := false
	if a.async(c) && len(enr) > 0 && reads != nil {
		shared := map[string]uint64{}
		for id, e := range enr {
			shared[id] = e.SharedRead
		}
		var nodeRead *float64
		if snap.Node != nil {
			nodeRead = snap.Node.DiskReadMBPerSec
		}
		byDisk = estimateDisk(top, shared, reads[BackendIOWorker], nodeRead, snap.Thresholds, a.opts.DigestWindow, 10)
		estimated = len(byDisk) > 0
	}
	acct := pgAccounting(snap.Accounting)
	rep := overload.Report{
		WindowSeconds: snap.WindowSeconds, Node: snap.Node, QueryCPUCoveragePercent: snap.QueryCPUCoveragePercent,
		QueryDiskReadCoveragePercent: snap.QueryDiskReadCoveragePercent, Thresholds: &snap.Thresholds,
		TopDigests: overloadDigests(top), TopDigestsByDiskRead: overloadDigests(byDisk),
		Victims: pgVictims(snap.Victims), Accounting: maps.Clone(acct), Cluster: c.name, ServerPID: c.pid,
		DiskEstimated: estimated, Backends: backendUsage(cores, reads),
	}
	return ClusterView{Name: c.name, PostmasterPID: c.pid, Snapshot: snap, Overload: rep,
		Backends: a.back.Life(c.pid), Accounting: acct, EnrichmentUp: ev.Status == pgstat.StatusOK}
}

func (a *Analyzer) clusterJSON(v ClusterView) model.PostgresCluster {
	c := a.cluster(v.PostmasterPID)
	s := v.Snapshot
	pc := model.PostgresCluster{Cluster: v.Name, PostmasterPID: v.PostmasterPID, Accounting: maps.Clone(v.Accounting),
		QueryCPUCoveragePercent: s.QueryCPUCoveragePercent, QueryDiskReadCoveragePercent: s.QueryDiskReadCoveragePercent,
		Victims: pgVictims(s.Victims), RecentSlowQueries: []model.PGSlowQuery{}}
	if c != nil {
		pm := c.post()
		pc.Version, pc.Port, pc.DataDir = c.version.String(), pm.Port, pm.DataDir
		c.mu.Lock()
		pc.RecentSlowQueries = append(pc.RecentSlowQueries, c.recent...)
		c.mu.Unlock()
		if a.d.Enricher != nil {
			pc.IOMethod = a.d.Enricher.Snapshot(c.post().Port).Settings.IOMethod
		}
	}
	if cores, reads, ok := a.back.Window(v.PostmasterPID); ok {
		pc.CPUByBackendType, pc.DiskReadByBackendType = cores, reads
	}
	enr := map[string]enrichment{}
	if c != nil {
		enr, _ = a.digestEnrichment(c)
	}
	conv := func(in []model.QueryDigestStats) []model.PGDigestStats {
		out := toPGDigests(in)
		for i := range out {
			if e, ok := enr[out[i].DigestID]; ok {
				applyEnrichment(&out[i], e)
			}
			if v.Overload.DiskEstimated && out[i].DiskReadMBPerSec != nil {
				out[i].DiskEstimated = true
			}
		}
		return out
	}
	pc.TopDigests = conv(s.TopByCPU)
	pc.TopDigestsByWait = conv(s.TopByWait)
	if v.Overload.DiskEstimated {
		pc.TopDigestsByDiskRead = conv(v.Overload.TopDigestsByDiskRead)
	} else {
		pc.TopDigestsByDiskRead = conv(s.TopByDiskRead)
	}
	if v.Overload.DiskEstimated { // estimates were applied to the overload copy; mirror them by id
		est := map[string]model.QueryDigestStats{}
		for _, d := range v.Overload.TopDigestsByDiskRead {
			est[d.DigestID] = d
		}
		for i := range pc.TopDigests {
			if d, ok := est[pc.TopDigests[i].DigestID]; ok {
				pc.TopDigests[i].DiskReadMBPerSec, pc.TopDigests[i].PercentOfDiskRead = d.DiskReadMBPerSec, d.PercentOfDiskRead
				pc.TopDigests[i].DiskReadPagesPerCall, pc.TopDigests[i].IORole, pc.TopDigests[i].DiskEstimated = d.DiskReadPagesPerCall, d.IORole, true
			}
		}
	}
	return pc
}

func (a *Analyzer) report(views []ClusterView, now time.Time) *model.PostgresAnalysis {
	r := &model.PostgresAnalysis{Type: "postgres_analysis", Timestamp: now, SlowThresholdMs: a.opts.SlowQueryThresholdMs,
		WindowSeconds: int(a.opts.DigestWindow / time.Second), Clusters: []model.PostgresCluster{}, DroppedEvents: a.tr().Dropped()}
	enrichment := pgstat.StatusNotConfigured
	for i, v := range views {
		pc := a.clusterJSON(v)
		if i == 0 {
			r.Node, r.Thresholds = v.Snapshot.Node, &v.Snapshot.Thresholds
		}
		if a.d.Enricher != nil {
			if c := a.cluster(v.PostmasterPID); c != nil {
				st := a.d.Enricher.Snapshot(c.post().Port).Status
				if enrichment == pgstat.StatusNotConfigured || enrichment == pgstat.StatusOK {
					enrichment = st
				}
			}
		}
		r.Clusters = append(r.Clusters, pc)
	}
	r.Accounting = mergeAccounting(r.Clusters)
	r.Accounting["state"] = a.state.Load().(string)
	r.Accounting["enrichment"] = enrichment
	return r
}

// ─── Exports ─────────────────────────────────────────────────────────────────

// Latest returns the cached report (nil before the first poll).
func (a *Analyzer) Latest() *model.PostgresAnalysis { return a.latest.Load() }

// Views returns the latest per-cluster state (nil before the first poll).
func (a *Analyzer) Views() []ClusterView {
	p := a.views.Load()
	if p == nil {
		return nil
	}
	out := make([]ClusterView, len(*p))
	for i, v := range *p {
		v.Accounting = maps.Clone(v.Accounting)
		v.Overload.Accounting = maps.Clone(v.Overload.Accounting)
		v.Backends = maps.Clone(v.Backends)
		out[i] = v
	}
	return out
}

// Fresh reports whether the cached digests can still be judged against fresh
// node data: tracing is active and the latest poll is at most 2 poll intervals
// old. Otherwise reason says why not ("tracing shed", "tracer unavailable",
// "no data yet", "stale").
func (a *Analyzer) Fresh(now time.Time) (ok bool, reason string) {
	switch st := a.State(); {
	case st == StateShed:
		return false, "tracing shed"
	case st != StateActive:
		return false, "tracer unavailable"
	}
	l := a.latest.Load()
	if l == nil {
		return false, "no data yet"
	}
	max := 2 * a.opts.PollInterval
	if max <= 0 {
		max = 10 * time.Second
	}
	if now.Sub(l.Timestamp) > max {
		return false, "stale"
	}
	return true, ""
}

// Assess builds overload_cause over every cluster for one diagnose call. While
// tracing is shed, unavailable or the cache is stale it returns a no_data
// verdict: frozen digests must not be combined with fresh node numbers.
func (a *Analyzer) Assess(in overload.Inputs, th overload.Thresholds, now time.Time) *model.QueryOverload {
	if ok, why := a.Fresh(now); !ok {
		return &model.QueryOverload{Type: "query_overload", Timestamp: now, Verdict: model.OverloadNoData, Resource: "cpu",
			Confidence: model.ConfidenceLow, Summary: "no PostgreSQL query data: " + why, Checks: []model.OverloadCheck{}}
	}
	var rs []*model.QueryOverload
	for _, v := range a.Views() {
		rs = append(rs, overload.AssessEngine(overload.PostgresEngine, v.Overload, in, th, a.opts.BackgroundDominantPercent, now))
	}
	return overload.PickCluster(rs)
}

// WithOverload returns a copy of the latest report with overload_cause set
// (the cached report is shared and never mutated).
func (a *Analyzer) WithOverload(in overload.Inputs, th overload.Thresholds, now time.Time) *model.PostgresAnalysis {
	l := a.latest.Load()
	if l == nil {
		return nil
	}
	cp := *l
	cp.OverloadCause = a.Assess(in, th, now)
	return &cp
}

// State is active, shed or unavailable: <reason>.
func (a *Analyzer) State() string { return a.state.Load().(string) }

func (a *Analyzer) ShedTotal() uint64      { return a.shedTotal.Load() }
func (a *Analyzer) CreditDropped() uint64  { return a.creditDropped.Load() }
func (a *Analyzer) HashMismatches() uint64 { return a.text.Mismatches() }
func (a *Analyzer) OverCapacity() bool     { return a.overCap.Load() }
func (a *Analyzer) Dropped() uint64        { return a.tr().Dropped() }
func (a *Analyzer) TextDropped() uint64    { return a.tr().TextDropped() }
func (a *Analyzer) AggOverflow() uint64    { return a.tr().AggOverflow() }

// enrich runs one SQL poll for every cluster (ids: the reported digests'
// queryids), then re-checks whether sync replication needs its hook.
// forgetIfGone closes a cluster's SQL state when the cluster was dropped while
// its Poll ran (the Poll would otherwise have recreated it after discover forgot it).
func (a *Analyzer) forgetIfGone(pid uint32, port int) {
	if a.cluster(pid) == nil {
		a.d.Enricher.Forget(port)
	}
}

func (a *Analyzer) enrich(ctx context.Context, now time.Time) {
	qids, _ := a.tr().QueryIDs()
	for _, v := range a.Views() {
		c := a.cluster(v.PostmasterPID)
		if c == nil || c.post().Port == 0 {
			continue
		}
		want := map[string]bool{}
		for _, d := range v.Snapshot.TopByCPU {
			want[d.DigestID] = true
		}
		var ids []int64
		for h, id := range qids {
			if e, ok := a.text.Lookup(textcache.Key{Hash: h}); ok && want[e.Digest.ID] && len(ids) < 50 {
				ids = append(ids, id)
			}
		}
		a.d.Enricher.Poll(ctx, c.post().Port, ids, now)
		a.forgetIfGone(v.PostmasterPID, c.post().Port)
	}
	if len(a.Views()) == 0 { // first run: connect so settings (sync rep, io_method) are known early
		a.mu.Lock()
		var ports []struct {
			pid  uint32
			port int
		}
		for _, c := range a.clusters {
			if c.post().Port > 0 {
				ports = append(ports, struct {
					pid  uint32
					port int
				}{c.pid, c.post().Port})
			}
		}
		a.mu.Unlock()
		for _, p := range ports {
			a.d.Enricher.Poll(ctx, p.port, nil, now)
			a.forgetIfGone(p.pid, p.port)
		}
	}
	select { // settings may change the optional hooks (sync replication)
	case a.rediscover <- struct{}{}:
	default:
	}
}

// ─── ClickHouse drain ────────────────────────────────────────────────────────

// EnableDrain turns on the ClickHouse drains (cmd/agent, before Start).
func (a *Analyzer) EnableDrain(maxDigestKeys, maxSlow int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.drainKeys, a.drainSlow = max(maxDigestKeys, 1), max(maxSlow, 1)
	for _, c := range a.clusters {
		c.agg.EnableDrain(a.drainKeys)
		c.agg.EnableHostDrain()
		c.slow.Enable(a.drainSlow)
	}
	a.back.EnableDrain()
}

// Drain returns everything since the previous call for ClickHouse. The host
// window is drained before the digests (see the MySQL sink): a poll landing
// between the two lands in the digests of this window and the host of the
// next, never the reverse.
func (a *Analyzer) Drain() pgdrain.Drain {
	a.mu.Lock()
	cs := make([]*cluster, 0, len(a.clusters))
	names := map[uint32]string{}
	for pid, c := range a.clusters {
		cs = append(cs, c)
		names[pid] = c.name
	}
	a.mu.Unlock()
	sort.Slice(cs, func(i, j int) bool { return cs[i].name < cs[j].name })
	estimated := map[uint32]bool{}
	for _, v := range a.Views() {
		estimated[v.PostmasterPID] = v.Overload.DiskEstimated
	}
	var out pgdrain.Drain
	for _, c := range cs {
		d := pgdrain.Cluster{Cluster: c.name, PostmasterPID: c.pid}
		d.Host = c.agg.DrainHost()
		d.Digests, d.Folded = c.agg.DrainDigests()
		d.Slow, d.SlowDropped = c.slow.Drain()
		if enr, v := a.digestEnrichment(c); len(enr) > 0 {
			c.mu.Lock()
			if v.At.After(c.enrichSent) {
				c.enrichSent = v.At
				d.Enrich = map[string]pgdrain.Enrich{}
				for id, e := range enr {
					d.Enrich[id] = pgdrain.Enrich{SharedHit: e.SharedHit, SharedRead: e.SharedRead, TempWritten: e.TempWrite}
				}
			}
			c.mu.Unlock()
		}
		d.DiskEstimated = estimated[c.pid]
		out.Clusters = append(out.Clusters, d)
	}
	for _, b := range a.back.DrainBackends() {
		if name, ok := names[b.Postmaster]; ok {
			out.Backends = append(out.Backends, pgdrain.Backend{Cluster: name, Type: b.Type, CPUNs: b.CPUNs,
				ReadBytes: b.ReadBytes, WriteBytes: b.WriteBytes, IOMeasured: b.IOMeasured, ProcessesMax: uint32(b.ProcessesMax)})
		}
	}
	return out
}
