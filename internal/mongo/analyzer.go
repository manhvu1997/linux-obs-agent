// Package mongo implements the userspace MongoDB slow-query analysis loop.
//
// The Analyzer:
//  1. Starts the eBPF mongo_query module at agent startup.
//  2. Polls the in-kernel LRU map every cfg.PollInterval (default 5 s).
//  3. Enriches each PID with /proc metadata (cmdline, cgroup path).
//  4. Maintains a ring of the most recent slow-query events (from the ringbuf).
//  5. Publishes a *model.MongoAnalysis snapshot accessible via Latest().
//
// Unlike the fsync/writeback analyzers, the snapshot is always published when
// there is data – MongoDB slow queries are always valuable regardless of
// system-wide CPU/memory pressure.
package mongo

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	mongoebpf "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mongo_query"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Analyzer owns the mongo_query eBPF loader and produces MongoAnalysis snapshots.
type Analyzer struct {
	cfg    *config.MongoConfig
	coll   *collector.Collector
	loader *mongoebpf.Loader

	// latest stores a *model.MongoAnalysis; updated atomically.
	latest atomic.Pointer[model.MongoAnalysis]

	// recentMu protects recentSlowQueries.
	recentMu           sync.Mutex
	recentSlowQueries  []model.MongoSlowEvent
}

// NewAnalyzer creates an Analyzer.  Call Start to begin tracing.
func NewAnalyzer(cfg *config.MongoConfig, coll *collector.Collector) *Analyzer {
	thresholdNs := cfg.SlowQueryThresholdMs * uint64(time.Millisecond)
	return &Analyzer{
		cfg:    cfg,
		coll:   coll,
		loader: mongoebpf.NewLoader(thresholdNs, cfg.Port),
	}
}

// Start loads the eBPF module and begins the poll loop.
// It blocks until ctx is cancelled.
func (a *Analyzer) Start(ctx context.Context) error {
	if !a.cfg.Enabled {
		slog.Info("mongo: analyzer disabled via config (set MONGODB_TRACING_ENABLED=true to enable)")
		<-ctx.Done()
		return nil
	}

	// Guard against zero/negative poll interval.
	if a.cfg.PollInterval <= 0 {
		slog.Warn("mongo: poll_interval is zero or negative, defaulting to 5s",
			"configured", a.cfg.PollInterval)
		a.cfg.PollInterval = 5 * time.Second
	}

	if err := a.loader.Start(ctx); err != nil {
		return err
	}
	defer a.loader.Stop()

	// Drain slow-event ringbuf in background (only outliers, low volume).
	go a.drainSlowEvents(ctx)

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

// Latest returns the most recently published MongoAnalysis snapshot, or nil if
// no snapshot has been recorded yet (e.g. no MongoDB traffic observed).
func (a *Analyzer) Latest() *model.MongoAnalysis {
	return a.latest.Load()
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// poll reads the LRU map, enriches each PID, and publishes a new snapshot.
// Always publishes when there is data (no CPU/mem pressure gate).
func (a *Analyzer) poll() {
	staleNs := uint64(a.cfg.StaleSeconds) * uint64(time.Second)
	raw := a.loader.TopSlowPIDs(a.cfg.TopN, staleNs)

	if len(raw) == 0 {
		return
	}

	processes := make([]model.MongoProcessStats, 0, len(raw))
	for _, r := range raw {
		avgMs := 0.0
		if r.TotalQueries > 0 {
			avgMs = float64(r.TotalLatencyNs) / float64(r.TotalQueries) / 1e6
		}
		processes = append(processes, model.MongoProcessStats{
			PID:          r.PID,
			Comm:         r.Comm,
			Cmdline:      mongoebpf.ReadCmdline(r.PID),
			CgroupPath:   mongoebpf.ReadCgroup(r.PID),
			TotalQueries: r.TotalQueries,
			SlowQueries:  r.SlowQueries,
			AvgLatencyMs: avgMs,
			MaxLatencyMs: float64(r.MaxLatencyNs) / 1e6,
		})
	}

	// Copy the current recent slow-query ring under lock.
	a.recentMu.Lock()
	recent := make([]model.MongoSlowEvent, len(a.recentSlowQueries))
	copy(recent, a.recentSlowQueries)
	a.recentMu.Unlock()

	analysis := &model.MongoAnalysis{
		Type:              "mongo_analysis",
		Timestamp:         time.Now(),
		SlowThresholdMs:   a.cfg.SlowQueryThresholdMs,
		RecentSlowQueries: recent,
		TopProcesses:      processes,
	}

	a.latest.Store(analysis)
	slog.Debug("mongo: analysis updated",
		"processes", len(processes),
		"recent_slow", len(recent),
	)
}

// drainSlowEvents consumes the ringbuf slow-event channel, appends to the
// recent ring (capped at MaxRecentQueries), and logs at Warn level.
func (a *Analyzer) drainSlowEvents(ctx context.Context) {
	maxRecent := a.cfg.MaxRecentQueries
	if maxRecent <= 0 {
		maxRecent = 100
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.loader.SlowEvents:
			if !ok {
				return
			}
			slow, ok := ev.Data.(model.MongoSlowEvent)
			if !ok {
				continue
			}

			slog.Warn("mongo: slow query detected",
				"pid", ev.PID,
				"comm", ev.Comm,
				"op_type", slow.OpType,
				"collection", slow.Collection,
				"dest_addr", slow.DestAddr,
				"latency_ms", slow.LatencyMs,
				"fd", slow.FD,
			)

			a.recentMu.Lock()
			a.recentSlowQueries = append(a.recentSlowQueries, slow)
			// Keep only the most recent maxRecent entries.
			if len(a.recentSlowQueries) > maxRecent {
				excess := len(a.recentSlowQueries) - maxRecent
				a.recentSlowQueries = a.recentSlowQueries[excess:]
			}
			a.recentMu.Unlock()
		}
	}
}
