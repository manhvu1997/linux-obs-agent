// Package mysql implements the userspace MySQL slow-query analysis loop.
//
// The Analyzer:
//  1. Starts the eBPF mysql_query module at agent startup (attaches uprobes to
//     dispatch_command inside the mysqld binary).
//  2. Drains the kernel aggregation every cfg.PollInterval (default 5 s) and
//     samples node and mysqld CPU for the same interval.
//  3. Publishes a *model.MySQLAnalysis snapshot accessible via Latest().
//  4. Maintains a ring of the most recent slow-query events (from the ringbuf).
//
// Unlike the fsync/writeback analyzers, the snapshot is always published when
// there is data – MySQL slow queries are valuable regardless of system-wide
// CPU/memory pressure.
package mysql

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/drain"
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/sqlhash"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// Analyzer owns the mysql_query eBPF loader and produces MySQLAnalysis snapshots.
type Analyzer struct {
	cfg    *config.MySQLConfig
	coll   *collector.Collector
	loader *mysqlq.Loader

	agg     *querystats.Aggregator
	host    *hostSampler // poll goroutine only
	text    *textCache   // set in Start, before started is published
	digests atomic.Pointer[querystats.Snapshot]
	started atomic.Bool

	// latest stores a *model.MySQLAnalysis; updated atomically.
	latest atomic.Pointer[model.MySQLAnalysis]

	// recentMu protects recentSlowQueries.
	recentMu          sync.Mutex
	recentSlowQueries []model.MySQLSlowEvent

	// slowDrain feeds the ClickHouse mysql_slow_queries table; disabled
	// (zero value) unless the ClickHouse export is on.
	slowDrain drain.Buffer[model.SlowQuery]
}

// NewAnalyzer creates an Analyzer.  Call Start to begin tracing.
// coll may be nil – it is accepted for API symmetry with the mongo Analyzer but
// is not used (MySQL analysis is always published when data is available).
func NewAnalyzer(cfg *config.MySQLConfig, coll *collector.Collector) *Analyzer {
	thresholdNs := cfg.SlowQueryThresholdMs * uint64(time.Millisecond)
	return &Analyzer{
		cfg:    cfg,
		coll:   coll,
		loader: mysqlq.NewLoader(thresholdNs, cfg.MysqldPath, cfg.EmitAllQueries),
		host:   newHostSampler(),
		agg: querystats.New(querystats.Config{
			Window:                       cfg.DigestWindow,
			TopN:                         cfg.TopDigests,
			TopNBytes:                    10,
			CPUCulpritPercentOfNodeUsed:  cfg.CPUCulpritPercentOfNodeCPUUsed,
			CPUCulpritMinNodeUsedPercent: cfg.CPUCulpritMinNodeCPUUsedPercent,
			VictimWaitPercent:            cfg.VictimWaitPercent,
			SlowWallNs:                   thresholdNs,
			StickyMax:                    cfg.StickyDigestsMax,
			StickyTTL:                    cfg.StickyDigestTTL,
		}),
	}
}

// Start loads the eBPF module and begins the poll loop.
// It blocks until ctx is cancelled.
func (a *Analyzer) Start(ctx context.Context) error {
	if !a.cfg.Enabled {
		slog.Info("mysql: analyzer disabled via config (set MYSQL_TRACING_ENABLED=true to enable)")
		<-ctx.Done()
		return nil
	}

	if a.cfg.PollInterval <= 0 {
		slog.Warn("mysql: poll_interval is zero or negative, defaulting to 5s",
			"configured", a.cfg.PollInterval)
		a.cfg.PollInterval = 5 * time.Second
	}

	if err := a.loader.Start(ctx); err != nil {
		return err
	}
	defer a.loader.Stop()
	a.text = newTextCache(32768, textCacheHooks{forget: a.loader.ForgetText, markUnsafe: a.loader.MarkUnsafe})
	a.host.prime()
	a.started.Store(true)
	defer a.started.Store(false)

	// Drain slow-event ringbuf in background (only outliers, low volume).
	go a.drainSlowEvents(ctx)
	go a.drainCmdEvents(ctx)
	go a.drainText(ctx)

	tick := time.NewTicker(a.cfg.PollInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			a.poll()
		}
	}
}

// Latest returns the most recently published MySQLAnalysis snapshot, or nil if
// no snapshot has been recorded yet (e.g. no MySQL queries observed).
func (a *Analyzer) Latest() *model.MySQLAnalysis {
	return a.latest.Load()
}

// DigestSnapshot returns the latest digest snapshot (nil before the first
// poll). Used by the Prometheus collector.
func (a *Analyzer) DigestSnapshot() *querystats.Snapshot { return a.digests.Load() }

// Dropped returns commands lost before the digest aggregator (not text
// events, see TextDropped); 0 when the tracer is not running.
func (a *Analyzer) Dropped() uint64 {
	if !a.started.Load() {
		return 0
	}
	return a.loader.Dropped()
}

// TextDropped returns text events dropped on a full channel (re-requested
// from the kernel, no command lost); 0 when the tracer is not running.
func (a *Analyzer) TextDropped() uint64 {
	if !a.started.Load() {
		return 0
	}
	return a.loader.TextDropped()
}

// drainCmdEvents feeds the commands the kernel could not aggregate into the
// digest aggregator: the fallback events of a full aggregation map or of a
// hash marked unsafe (verify/drift mismatch). Every other command arrives
// through DrainAgg in poll. With emit_all_queries off the kernel emits no
// command events at all.
func (a *Analyzer) drainCmdEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.loader.CmdEvents:
			if !ok {
				return
			}
			a.agg.Add(a.toEvent(ev, time.Now(), a.loader.PreparedTextTracking()))
		}
	}
}

// systemSchemaDigest is the single digest that system-schema statements fold
// into when mysql.fold_system_schemas is on.
var systemSchemaDigest = func() sqldigest.Digest {
	const text = "<system schemas: information_schema, performance_schema, sys, mysql>"
	return sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: true}
}()

// foldSystem applies the mysql.fold_system_schemas rule to a digest; shared by
// toEvent and recordSlow so both paths agree on the id.
func (a *Analyzer) foldSystem(d sqldigest.Digest) (sqldigest.Digest, bool) {
	if a.cfg.FoldSystemSchemas && sqldigest.ReferencesSystemSchema(d.Text) {
		return systemSchemaDigest, true
	}
	return d, false
}

// slowDigestID is the digest id the command path gives the same text.
func (a *Analyzer) slowDigestID(text string) string {
	d, _ := a.foldSystem(cmdmap.SlowDigest(text))
	return d.ID
}

// classify turns one statement text into its digest, applying system-schema
// folding and the sample-query privacy rule. It must stay a pure function of
// its arguments and the config: the text cache calls it (via applyAgg's
// callbacks) while holding its lock.
func (a *Analyzer) classify(command uint32, query string, queryLen uint32, preparedTracking bool) textEntry {
	class, d, sample, trunc := cmdmap.Classify(command, query, queryLen, preparedTracking)
	if folded, ok := a.foldSystem(d); ok {
		d, sample, trunc = folded, "", false
	}
	if !a.cfg.SampleQueries {
		sample = ""
	}
	return textEntry{class: class, digest: d, sample: sample, truncated: trunc}
}

// toEvent classifies one command. With mysql.sample_queries off the raw
// statement text (which carries literals) is never stored. preparedTracking
// is the loader's PreparedTextTracking(), a parameter so this stays testable
// without a loaded eBPF module.
func (a *Analyzer) toEvent(ev mysqlq.CmdEvent, now time.Time, preparedTracking bool) querystats.Event {
	e := a.classify(ev.Command, ev.Query, ev.QueryLen, preparedTracking)
	return querystats.Event{
		PID: ev.PID, Command: e.class, Digest: e.digest, SampleQuery: e.sample, Truncated: e.truncated,
		WallNs: ev.WallNs, CPUNs: ev.CPUNs, RunqNs: ev.RunqNs,
		BytesIn: ev.BytesIn, BytesOut: ev.BytesOut, At: now,
	}
}

// textUnavailable / prepareTextUnavailable are the digests of a COM_QUERY /
// COM_STMT_PREPARE whose text never arrived; distinct so a lost prepare is
// not merged into (and mislabelled as) a query digest.
var (
	textUnavailable        = unavailableDigest("<text unavailable>")
	prepareTextUnavailable = unavailableDigest("prepare: <text unavailable>")
)

func unavailableDigest(text string) sqldigest.Digest {
	return sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: true}
}

// learnText records (or, for a verification resend, checks) a text event.
// literalSkip is the loader's LiteralSkip() (a parameter for testability).
//
// Every first-sight text is also checked against the Go reference of the
// kernel hash (sqlhash.KernelHash, or ExactHash in the exact-text fallback):
// the text sent is exactly the bytes the kernel hashed — the NUL-terminated
// ≤ 511-byte capture for COM_QUERY / COM_STMT_PREPARE, and for
// COM_STMT_EXECUTE the ps_text entry whose hash was computed over that same
// text at prepare time — so any difference is a kernel/Go drift (or the
// ps_text LRU reuse race), and the hash is switched to exact processing.
func (a *Analyzer) learnText(ev mysqlq.TextEvent, preparedTracking, literalSkip bool) {
	e := a.classify(ev.Command, ev.Query, ev.QueryLen, preparedTracking)
	k := textKey{ev.Command, ev.Hash}
	if ev.Verify {
		if a.text.verify(k, e) {
			slog.Warn("mysql: kernel text hash disagrees with the digest; statement switched to exact per-event processing",
				"command", ev.Command, "hash", ev.Hash, "digest", e.digest.Text)
		}
		return
	}
	if a.text.learn(k, e) {
		return // already flagged; counting the drift check too would double count
	}
	want := sqlhash.ExactHash
	if literalSkip {
		want = sqlhash.KernelHash
	}
	if got := want([]byte(ev.Query)); got != ev.Hash {
		slog.Warn("mysql: kernel text hash differs from the Go reference; statement switched to exact per-event processing",
			"command", ev.Command, "kernel_hash", ev.Hash, "go_hash", got, "literal_skip", literalSkip)
		a.text.flagMismatch(k)
	}
}

// applyAgg resolves drained kernel entries and records them at now.
func (a *Analyzer) applyAgg(entries []mysqlq.AggEntry, now time.Time, preparedTracking bool) {
	// Both callbacks are pure (classify by command only): endTick invokes
	// unavailable with the cache lock held.
	byCommand := func(cmd uint32) textEntry { return a.classify(cmd, "", 0, preparedTracking) }
	unavailable := func(cmd uint32) textEntry {
		e := byCommand(cmd)
		switch cmd {
		case cmdmap.ComQuery:
			e.digest, e.sample = textUnavailable, ""
		case cmdmap.ComStmtPrepare:
			e.digest, e.sample = prepareTextUnavailable, ""
		}
		// COM_STMT_EXECUTE keeps cmdmap's execute placeholder ("prepared
		// before agent start" while prepared-text tracking is on).
		return e
	}
	deltas := make([]querystats.Delta, 0, len(entries))
	for _, en := range entries {
		d, ok := a.text.resolve(textKey{en.Command, en.Hash}, aggSums{
			PID: en.PID, Calls: en.Calls, WallNs: en.WallNs, WallMaxNs: en.WallMaxNs, CPUNs: en.CPUNs,
			RunqNs: en.RunqNs, BytesIn: en.BytesIn, BytesOut: en.BytesOut,
		}, byCommand)
		if ok {
			deltas = append(deltas, d)
		}
	}
	deltas = append(deltas, a.text.endTick(unavailable)...)
	a.agg.AddDeltas(deltas, now)
}

// drainText feeds the kernel's text events into the text cache.
func (a *Analyzer) drainText(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.loader.TextEvents:
			if !ok {
				return
			}
			a.learnText(ev, a.loader.PreparedTextTracking(), a.loader.LiteralSkip())
		}
	}
}

// AggOverflow: commands that bypassed kernel aggregation (map full).
func (a *Analyzer) AggOverflow() uint64 {
	if !a.started.Load() {
		return 0
	}
	return a.loader.AggOverflow()
}

// HashMismatches: kernel text hashes found inconsistent — a verification
// sample or a resend whose digest differed from the cache, or a first-sight
// text whose kernel hash differed from the Go reference.
func (a *Analyzer) HashMismatches() uint64 {
	if !a.started.Load() || a.text == nil {
		return 0
	}
	return a.text.mismatches()
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// poll drains the kernel aggregation and records one tick.
func (a *Analyzer) poll() {
	now := time.Now()
	entries, err := a.loader.DrainAgg()
	if err != nil {
		slog.Warn("mysql: draining kernel aggregation", "err", err)
		entries = nil
	}
	a.tick(now, entries, a.loader.PreparedTextTracking())
}

// tick records one poll — the drained statements and the host CPU over the
// same interval, in the same bucket — and publishes the digest snapshot and
// the report. It does not touch the loader, so it is testable.
func (a *Analyzer) tick(now time.Time, entries []mysqlq.AggEntry, preparedTracking bool) {
	a.applyAgg(entries, now, preparedTracking)
	a.agg.AddHost(a.host.sample(a.agg.WindowPIDs(now)), now)
	snap := a.agg.Snapshot(now)
	a.digests.Store(&snap)

	a.recentMu.Lock()
	recent := make([]model.MySQLSlowEvent, len(a.recentSlowQueries))
	copy(recent, a.recentSlowQueries)
	a.recentMu.Unlock()
	if len(snap.TopByCPU) == 0 && len(recent) == 0 {
		return
	}
	a.latest.Store(&model.MySQLAnalysis{
		Type:              "mysql_analysis",
		Timestamp:         now,
		SlowThresholdMs:   a.cfg.SlowQueryThresholdMs,
		MysqldPath:        a.cfg.MysqldPath,
		RecentSlowQueries: recent,

		WindowSeconds:           snap.WindowSeconds,
		Node:                    snap.Node,
		QueryCPUCoveragePercent: snap.QueryCPUCoveragePercent,
		DroppedEvents:           a.Dropped(),
		Thresholds:              &snap.Thresholds,
		TopDigests:              snap.TopByCPU,
		TopDigestsByWait:        snap.TopByWait,
		TopDigestsByBytesOut:    snap.TopByBytesOut,
		Victims:                 snap.Victims,
		Accounting:              snap.Accounting,
	})
	slog.Debug("mysql: analysis updated", "recent_slow", len(recent), "digests", len(snap.TopByCPU))
}

// drainSlowEvents consumes the ringbuf slow-event channel, appends to the
// recent ring (capped at MaxRecentQueries), and logs at Warn level.
func (a *Analyzer) drainSlowEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.loader.SlowEvents:
			if !ok {
				return
			}
			slow, ok := ev.Data.(model.MySQLSlowEvent)
			if !ok {
				continue
			}

			slog.Warn("mysql: slow query detected",
				"pid", ev.PID,
				"comm", ev.Comm,
				"latency_ms", slow.LatencyMs,
				"query", slow.Query,
			)

			a.recordSlow(slow)
		}
	}
}

// EnableSlowDrain makes every slow event also available to DrainSlowQueries,
// at most max per drain interval.
func (a *Analyzer) EnableSlowDrain(max int) { a.slowDrain.Enable(max) }

// DrainSlowQueries returns the slow events since the previous call and how
// many were discarded over the per-interval cap.
func (a *Analyzer) DrainSlowQueries() ([]model.SlowQuery, uint64) { return a.slowDrain.Drain() }

// EnableDigestDrain / DrainDigests expose the digest aggregator's drain.
func (a *Analyzer) EnableDigestDrain(maxKeys int) { a.agg.EnableDrain(maxKeys) }
func (a *Analyzer) DrainDigests() ([]querystats.DigestDelta, uint64) {
	return a.agg.DrainDigests()
}

// recordSlow appends one slow event to the recent ring and the drain.
func (a *Analyzer) recordSlow(slow model.MySQLSlowEvent) {
	maxRecent := a.cfg.MaxRecentQueries
	if maxRecent <= 0 {
		maxRecent = 100
	}
	a.recentMu.Lock()
	a.recentSlowQueries = append(a.recentSlowQueries, slow)
	if len(a.recentSlowQueries) > maxRecent {
		a.recentSlowQueries = a.recentSlowQueries[len(a.recentSlowQueries)-maxRecent:]
	}
	a.recentMu.Unlock()
	a.slowDrain.Add(model.SlowQuery{Event: slow, DigestID: a.slowDigestID(slow.Query)})
}
