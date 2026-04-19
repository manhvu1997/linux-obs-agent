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
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Analyzer owns the mysql_query eBPF loader and produces MySQLAnalysis snapshots.
type Analyzer struct {
	cfg    *config.MySQLConfig
	coll   *collector.Collector
	loader *mysqlq.Loader

	// latest stores a *model.MySQLAnalysis; updated atomically.
	latest atomic.Pointer[model.MySQLAnalysis]

	// recentMu protects recentSlowQueries.
	recentMu          sync.Mutex
	recentSlowQueries []model.MySQLSlowEvent
}

// NewAnalyzer creates an Analyzer.  Call Start to begin tracing.
// coll may be nil – it is accepted for API symmetry with the mongo Analyzer but
// is not used (MySQL analysis is always published when data is available).
func NewAnalyzer(cfg *config.MySQLConfig, coll *collector.Collector) *Analyzer {
	thresholdNs := cfg.SlowQueryThresholdMs * uint64(time.Millisecond)
	return &Analyzer{
		cfg:    cfg,
		coll:   coll,
		loader: mysqlq.NewLoader(thresholdNs, cfg.MysqldPath),
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

// Latest returns the most recently published MySQLAnalysis snapshot, or nil if
// no snapshot has been recorded yet (e.g. no MySQL queries observed).
func (a *Analyzer) Latest() *model.MySQLAnalysis {
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
	}

	a.latest.Store(analysis)
	slog.Debug("mysql: analysis updated",
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
