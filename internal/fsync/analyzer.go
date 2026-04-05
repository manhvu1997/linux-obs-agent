// Package fsync implements the userspace fsync analysis loop.
//
// The Analyzer:
//  1. Starts the eBPF fsync module via the Manager.
//  2. Polls the in-kernel LRU map every cfg.PollInterval.
//  3. Enriches each PID with /proc metadata (cmdline, cgroup).
//  4. Classifies known high-fsync workloads (databases, log agents, AV).
//  5. Stores the latest FsyncAnalysis so GET /api/diagnose can serve it.
//
// The analysis snapshot is rebuilt on every poll tick, but only published
// (replacing the cached value) when the system is under pressure
// (CPU > CPUThreshold OR Mem > MemThreshold).  This means the diagnose
// endpoint always shows the most-recent high-pressure fsync picture.
package fsync

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	ebpffsync "github.com/manhvu1997/linux-obs-agent/internal/ebpf/fsync"
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
	{"mysqld_safe", "database"},
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
	// Antivirus / security scanners
	{"clamd", "antivirus"},
	{"clamav", "antivirus"},
	{"sophos", "antivirus"},
	{"cylance", "antivirus"},
	{"falcon", "antivirus"},
	{"crowdstrike", "antivirus"},
	{"carbonblack", "antivirus"},
	{"eset", "antivirus"},
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

// Analyzer owns the fsync eBPF loader and produces FsyncAnalysis snapshots.
type Analyzer struct {
	cfg    *config.FsyncConfig
	coll   *collector.Collector
	loader *ebpffsync.Loader

	// latest stores a *model.FsyncAnalysis; updated atomically.
	latest atomic.Pointer[model.FsyncAnalysis]
}

// NewAnalyzer creates an Analyzer.  Call Start to begin tracing.
func NewAnalyzer(cfg *config.FsyncConfig, coll *collector.Collector) *Analyzer {
	return &Analyzer{
		cfg:    cfg,
		coll:   coll,
		loader: ebpffsync.NewLoader(cfg.SlowThresholdUs),
	}
}

// Start loads the eBPF module and begins the poll loop.
// It blocks until ctx is cancelled.
func (a *Analyzer) Start(ctx context.Context) error {
	if !a.cfg.Enabled {
		slog.Info("fsync: analyzer disabled via config")
		<-ctx.Done()
		return nil
	}

	// Guard against a zero/negative poll interval (e.g. from a config that
	// wrote `poll_interval: 5` without a unit — YAML parses that as 5 ns).
	// time.NewTicker panics on duration <= 0.
	if a.cfg.PollInterval <= 0 {
		slog.Warn("fsync: poll_interval is zero or negative, defaulting to 5s",
			"configured", a.cfg.PollInterval)
		a.cfg.PollInterval = 5 * time.Second
	}
	// Likewise guard the pressure thresholds: if both are 0 the snapshot
	// would never be published (0 < 0 is always false).
	if a.cfg.CPUThreshold == 0 && a.cfg.MemThreshold == 0 {
		slog.Warn("fsync: both cpu_threshold and mem_threshold are 0, defaulting to 85%")
		a.cfg.CPUThreshold = 85.0
		a.cfg.MemThreshold = 85.0
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

// Latest returns the most recently published FsyncAnalysis, or nil if no
// high-pressure snapshot has been recorded yet.
func (a *Analyzer) Latest() *model.FsyncAnalysis {
	return a.latest.Load()
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// poll reads the LRU map, enriches each PID, and publishes a new snapshot
// when the system is currently under pressure.
func (a *Analyzer) poll() {
	metrics := a.coll.Latest()
	if metrics.Timestamp.IsZero() {
		return // collector hasn't run yet
	}

	underPressure := metrics.CPU.UsagePercent > a.cfg.CPUThreshold ||
		metrics.Memory.UsagePercent > a.cfg.MemThreshold

	// Always read the map so stale entries are not carried forward indefinitely,
	// but only publish when the system is under pressure.
	staleNs := uint64(a.cfg.StaleSeconds) * uint64(time.Second)
	raw := a.loader.TopOffenders(a.cfg.TopN, staleNs)

	if len(raw) == 0 {
		return
	}

	offenders := make([]model.FsyncOffender, 0, len(raw))
	for _, r := range raw {
		avgMs := 0.0
		if r.TotalCalls > 0 {
			avgMs = float64(r.TotalLatencyNs) / float64(r.TotalCalls) / 1e6
		}
		maxMs := float64(r.MaxLatencyNs) / 1e6

		cmdline := ebpffsync.ReadCmdline(r.PID)
		appType := classifyApp(r.Comm, cmdline)

		offenders = append(offenders, model.FsyncOffender{
			PID:          r.PID,
			Comm:         r.Comm,
			Cmdline:      cmdline,
			CgroupPath:   ebpffsync.ReadCgroup(r.PID),
			FsyncCalls:   r.TotalCalls,
			AvgLatencyMs: avgMs,
			MaxLatencyMs: maxMs,
			AppType:      appType,
		})
	}

	analysis := &model.FsyncAnalysis{
		Type:      "fsync_analysis",
		Timestamp: time.Now(),
		System: model.FsyncSystemInfo{
			CPUPercent: metrics.CPU.UsagePercent,
			MemPercent: metrics.Memory.UsagePercent,
		},
		TopOffenders: offenders,
	}

	if underPressure {
		// Atomically replace the published snapshot.
		a.latest.Store(analysis)
		slog.Info("fsync: analysis updated (system under pressure)",
			"cpu_pct", metrics.CPU.UsagePercent,
			"mem_pct", metrics.Memory.UsagePercent,
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
			if slow, ok := ev.Data.(model.FsyncSlowEvent); ok {
				slog.Warn("fsync: slow event",
					"pid", ev.PID,
					"comm", ev.Comm,
					"syscall", slow.SyscallName,
					"latency_us", slow.LatencyUs,
				)
			}
		}
	}
}

