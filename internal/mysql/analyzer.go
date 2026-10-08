// Package mysql implements the userspace MySQL slow-query analysis loop.
//
// The Analyzer:
//  1. Starts the eBPF mysql_query module at agent startup (attaches uprobes to
//     dispatch_command inside the mysqld binary).
//  2. Polls the in-kernel LRU map every cfg.PollInterval (default 5 s).
//  3. Enriches each PID with /proc metadata (cmdline, cgroup path).
//  4. Maintains a ring of the most recent slow-query events (from the ringbuf).
//  5. Publishes a *model.MySQLAnalysis snapshot accessible via Latest().
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
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// Analyzer owns the mysql_query eBPF loader and produces MySQLAnalysis snapshots.
type Analyzer struct {
	cfg    *config.MySQLConfig
	coll   *collector.Collector
	loader *mysqlq.Loader

	agg     *querystats.Aggregator
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
		agg: querystats.New(querystats.Config{
			Window:                 cfg.DigestWindow,
			TopN:                   cfg.TopDigests,
			TopNBytes:              10,
			CulpritCPUSharePercent: cfg.CulpritCPUSharePercent,
			CulpritMinCPUPercent:   cfg.CulpritMinCPUPercent,
			VictimRunqRatio:        cfg.VictimRunqRatio,
			SlowWallNs:             thresholdNs,
			StickyMax:              cfg.StickyDigestsMax,
			StickyTTL:              cfg.StickyDigestTTL,
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
	a.started.Store(true)
	defer a.started.Store(false)

	// Drain slow-event ringbuf in background (only outliers, low volume).
	go a.drainSlowEvents(ctx)
	go a.drainCmdEvents(ctx)

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

// Dropped returns lost per-command events; 0 when the tracer is not running.
func (a *Analyzer) Dropped() uint64 {
	if !a.started.Load() {
		return 0
	}
	return a.loader.Dropped()
}

// drainCmdEvents feeds every measured command into the digest aggregator.
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

// toEvent classifies one command. With mysql.sample_queries off the raw
// statement text (which carries literals) is never stored. preparedTracking
// is the loader's PreparedTextTracking(), a parameter so this stays testable
// without a loaded eBPF module.
func (a *Analyzer) toEvent(ev mysqlq.CmdEvent, now time.Time, preparedTracking bool) querystats.Event {
	class, d, sample, trunc := cmdmap.Classify(ev.Command, ev.Query, ev.QueryLen, preparedTracking)
	if folded, ok := a.foldSystem(d); ok {
		d, sample, trunc = folded, "", false
	}
	if !a.cfg.SampleQueries {
		sample = ""
	}
	return querystats.Event{
		PID: ev.PID, Command: class, Digest: d, SampleQuery: sample, Truncated: trunc,
		WallNs: ev.WallNs, CPUNs: ev.CPUNs, RunqNs: ev.RunqNs,
		BytesIn: ev.BytesIn, BytesOut: ev.BytesOut, At: now,
	}
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// poll reads the LRU map, enriches each PID, and publishes a new snapshot.
// Always publishes when there is data (no CPU/mem pressure gate).
func (a *Analyzer) poll() {
	snap := a.agg.Snapshot(time.Now())
	a.digests.Store(&snap)

	staleNs := uint64(a.cfg.StaleSeconds) * uint64(time.Second)
	raw := a.loader.TopSlowPIDs(a.cfg.TopN, staleNs)
	if len(raw) == 0 && len(snap.TopByCPU) == 0 {
		return
	}

	processes := make([]model.MySQLProcessStats, 0, len(raw))
	for _, r := range raw {
		avgMs := 0.0
		if r.TotalQueries > 0 {
			avgMs = float64(r.TotalLatencyNs) / float64(r.TotalQueries) / 1e6
		}
		processes = append(processes, model.MySQLProcessStats{
			PID:          r.PID,
			Comm:         r.Comm,
			Cmdline:      mysqlq.ReadCmdline(r.PID),
			CgroupPath:   mysqlq.ReadCgroup(r.PID),
			TotalQueries: r.TotalQueries,
			SlowQueries:  r.SlowQueries,
			AvgLatencyMs: avgMs,
			MaxLatencyMs: float64(r.MaxLatencyNs) / 1e6,
		})
	}

	// Copy the current recent slow-query ring under lock.
	a.recentMu.Lock()
	recent := make([]model.MySQLSlowEvent, len(a.recentSlowQueries))
	copy(recent, a.recentSlowQueries)
	a.recentMu.Unlock()

	analysis := &model.MySQLAnalysis{
		Type:              "mysql_analysis",
		Timestamp:         time.Now(),
		SlowThresholdMs:   a.cfg.SlowQueryThresholdMs,
		MysqldPath:        a.cfg.MysqldPath,
		RecentSlowQueries: recent,
		TopProcesses:      processes,

		WindowSeconds:        snap.WindowSeconds,
		CPUAccounting:        snap.CPUAccounting,
		QueryCPUMsTotal:      snap.QueryCPUMsTotal,
		DroppedEvents:        a.loader.Dropped(),
		Thresholds:           &snap.Thresholds,
		TopDigests:           snap.TopByCPU,
		TopDigestsByBytesOut: snap.TopByBytesOut,
	}

	a.latest.Store(analysis)
	slog.Debug("mysql: analysis updated",
		"processes", len(processes),
		"recent_slow", len(recent),
		"digests", len(snap.TopByCPU),
	)
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
