// Package writeback implements the userspace writeback analysis loop.
//
// The Analyzer:
//  1. Starts the eBPF writeback module.
//  2. Polls the in-kernel LRU map every cfg.PollInterval.
//  3. Enriches each PID with /proc metadata (cmdline, cgroup).
//  4. Classifies known high-writeback workloads (databases, log agents, etc.).
//  5. Stores the latest WritebackAnalysis so GET /api/diagnose can serve it.
//
// The analysis snapshot is rebuilt on every poll tick, but only published
// (replacing the cached value) when the system is under memory pressure
// (Mem > MemThreshold) OR a direct-reclaim latency spike is observed
// (max per-PID reclaim latency > ReclaimSpikeNs).
package writeback

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	ebpfwb "github.com/manhvu1997/linux-obs-agent/internal/ebpf/writeback"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// knownApps maps substrings of process comm/cmdline to an app type label.
// Checked in order; first match wins.
var knownApps = []struct {
	substr  string
	appType string
}{
	// Databases
	{"mongod", "database"},
	{"mongos", "database"},
	{"cassandra", "database"},
	{"redis", "database"},
	{"mysqld", "database"},
	{"postgres", "database"},
	{"postmaster", "database"},
	// Log agents / shippers
	{"loki", "log_agent"},
	{"promtail", "log_agent"},
	{"filebeat", "log_agent"},
	{"fluentd", "log_agent"},
	{"fluent-bit", "log_agent"},
	{"logstash", "log_agent"},
	{"vector", "log_agent"},
	// Message queues / streaming
	{"kafka", "messaging"},
	{"zookeeper", "messaging"},
	{"rabbitmq", "messaging"},
	// Object storage / batch
	{"minio", "storage"},
	{"hadoop", "storage"},
	{"spark", "storage"},
	// Antivirus / security scanners
	{"clamd", "antivirus"},
	{"clamav", "antivirus"},
	{"falcon", "antivirus"},
	{"crowdstrike", "antivirus"},
}

// classifyApp returns the app type for a process, or "" if unknown.
func classifyApp(comm, cmdline string) string {
	haystack := strings.ToLower(comm + " " + cmdline)
	for _, k := range knownApps {
		if strings.Contains(haystack, k.substr) {
			return k.appType
		}
	}
	return ""
}

// Analyzer owns the writeback eBPF loader and produces WritebackAnalysis snapshots.
type Analyzer struct {
	cfg    *config.WritebackConfig
	coll   *collector.Collector
	loader *ebpfwb.Loader

	// latest stores a *model.WritebackAnalysis; updated atomically.
	latest atomic.Pointer[model.WritebackAnalysis]
}

// NewAnalyzer creates an Analyzer.  Call Start to begin tracing.
func NewAnalyzer(cfg *config.WritebackConfig, coll *collector.Collector) *Analyzer {
	return &Analyzer{
		cfg:    cfg,
		coll:   coll,
		loader: ebpfwb.NewLoader(cfg.SlowReclaimThresholdNs),
	}
}

// Start loads the eBPF module and begins the poll loop.
// It blocks until ctx is cancelled.
func (a *Analyzer) Start(ctx context.Context) error {
	if !a.cfg.Enabled {
		slog.Info("writeback: analyzer disabled via config")
		<-ctx.Done()
		return nil
	}

	// Guard against a zero/negative poll interval.
	if a.cfg.PollInterval <= 0 {
		slog.Warn("writeback: poll_interval is zero or negative, defaulting to 5s",
			"configured", a.cfg.PollInterval)
		a.cfg.PollInterval = 5 * time.Second
	}
	// Guard: if both thresholds are 0 the snapshot would never be published.
	if a.cfg.MemThreshold == 0 && a.cfg.ReclaimSpikeNs == 0 {
		slog.Warn("writeback: mem_threshold and reclaim_spike_ns are both 0, defaulting")
		a.cfg.MemThreshold = 85.0
		a.cfg.ReclaimSpikeNs = 10_000_000 // 10 ms
	}

	if err := a.loader.Start(ctx); err != nil {
		return err
	}
	defer a.loader.Stop()

	// Drain slow-event ringbuf in background (low volume – only outliers).
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

// Latest returns the most recently published WritebackAnalysis, or nil if no
// high-pressure snapshot has been recorded yet.
func (a *Analyzer) Latest() *model.WritebackAnalysis {
	return a.latest.Load()
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// poll reads the LRU map, enriches each PID, and publishes a new snapshot
// when the system is currently under memory pressure or reclaim is spiking.
func (a *Analyzer) poll() {
	metrics := a.coll.Latest()
	if metrics.Timestamp.IsZero() {
		return // collector hasn't run yet
	}

	staleNs := uint64(a.cfg.StaleSeconds) * uint64(time.Second)
	raw := a.loader.TopDirtyProducers(a.cfg.TopN, staleNs)

	if len(raw) == 0 {
		return
	}

	// Enrich each PID with /proc metadata and classify by app type.
	offenders := make([]model.WritebackOffender, 0, len(raw))
	var maxReclaimNs uint64
	for _, r := range raw {
		avgReclaimMs := 0.0
		if r.ReclaimCount > 0 {
			avgReclaimMs = float64(r.TotalReclaimNs) / float64(r.ReclaimCount) / 1e6
		}
		maxReclaimMs := float64(r.MaxReclaimNs) / 1e6

		if r.MaxReclaimNs > maxReclaimNs {
			maxReclaimNs = r.MaxReclaimNs
		}

		cmdline := ebpfwb.ReadCmdline(r.PID)
		appType := classifyApp(r.Comm, cmdline)

		offenders = append(offenders, model.WritebackOffender{
			PID:            r.PID,
			Comm:           r.Comm,
			Cmdline:        cmdline,
			CgroupPath:     ebpfwb.ReadCgroup(r.PID),
			DirtyPages:     r.DirtyPages,
			ReclaimCount:   r.ReclaimCount,
			AvgReclaimMs:   avgReclaimMs,
			MaxReclaimMs:   maxReclaimMs,
			AppType:        appType,
		})
	}

	wbCount := a.loader.SysWritebackCount()

	analysis := &model.WritebackAnalysis{
		Type:      "writeback_analysis",
		Timestamp: time.Now(),
		System: model.WritebackSystemInfo{
			MemPercent:     metrics.Memory.UsagePercent,
			MaxReclaimMs:   float64(maxReclaimNs) / 1e6,
			WbOperations:   wbCount,
		},
		TopOffenders: offenders,
	}

	// Publish snapshot when memory pressure is high OR reclaim latency spikes.
	underPressure := metrics.Memory.UsagePercent > a.cfg.MemThreshold ||
		maxReclaimNs > a.cfg.ReclaimSpikeNs

	if underPressure {
		a.latest.Store(analysis)
		slog.Info("writeback: analysis updated (system under pressure)",
			"mem_pct", metrics.Memory.UsagePercent,
			"max_reclaim_ms", float64(maxReclaimNs)/1e6,
			"offenders", len(offenders),
		)
	}
}

// drainSlowEvents consumes the ringbuf slow-event channel and logs outliers.
func (a *Analyzer) drainSlowEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.loader.SlowEvents:
			if !ok {
				return
			}
			if slow, ok := ev.Data.(model.WritebackSlowEvent); ok {
				slog.Warn("writeback: slow direct-reclaim event",
					"pid", ev.PID,
					"comm", ev.Comm,
					"reclaim_ms", float64(slow.ReclaimLatencyNs)/1e6,
				)
			}
		}
	}
}
