// Package trigger implements the threshold-based eBPF activation engine.
//
// Rule evaluation happens every cfg.EvalInterval seconds.  When a metric
// threshold is breached, the corresponding eBPF module is activated via the
// Manager.  The Manager itself handles auto-stop (ActiveDuration) and
// cool-down, so the trigger engine only needs to call Activate.
//
// Trigger rules implemented:
//
//	CPU > CPUUsagePercent           → activate cpu_profile
//	IOWait > IOWaitPercent          → activate io_latency
//	load/cpu > LoadNormalised       → activate runqlat
//	ctxswitch/s > CtxSwitchDelta   → activate runqlat
//	net errors/s > NetErrorDelta    → activate tcp_retransmit
//	iowait > offcpu.IOWaitThreshold → activate offcpu (attributes blocked time)
//	high load + low CPU             → suspect IO wait → activate io_latency + runqlat
//	runq level 1 (CPU% or load)     → activate runqlat for per-process analysis
package trigger

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Engine evaluates trigger rules and signals the eBPF manager.
type Engine struct {
	cfg       *config.TriggerConfig
	runqCfg   *config.RunQueueConfig
	offcpuCfg *config.OffCPUConfig
	coll      *collector.Collector
	manager   *ebpf.Manager

	// firing tracks which modules are currently triggered so we can log
	// transitions clearly.
	firing map[ebpf.ModuleID]bool
}

// NewEngine creates the trigger engine. runqCfg and offcpuCfg may be nil, in
// which case those rules are skipped and the legacy rules alone apply.
func NewEngine(
	cfg *config.TriggerConfig,
	runqCfg *config.RunQueueConfig,
	offcpuCfg *config.OffCPUConfig,
	coll *collector.Collector,
	mgr *ebpf.Manager,
) *Engine {
	return &Engine{
		cfg:       cfg,
		runqCfg:   runqCfg,
		offcpuCfg: offcpuCfg,
		coll:      coll,
		manager:   mgr,
		firing:    make(map[ebpf.ModuleID]bool),
	}
}

// Run starts the evaluation loop. It blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	tick := time.NewTicker(e.cfg.EvalInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.evaluate(ctx)
		}
	}
}

func (e *Engine) evaluate(ctx context.Context) {
	m := e.coll.Latest()
	if m.Timestamp.IsZero() {
		// No data yet – collector hasn't run.
		return
	}

	e.evalCPU(ctx, m)
	e.evalIO(ctx, m)
	e.evalScheduler(ctx, m)
	e.evalNetwork(ctx, m)
}

// ─── Per-signal evaluators ────────────────────────────────────────────────────

func (e *Engine) evalCPU(ctx context.Context, m model.NodeMetrics) {
	if m.CPU.UsagePercent > e.cfg.CPUUsagePercent {
		e.fire(ctx, ebpf.ModCPUProfile,
			"cpu_usage", m.CPU.UsagePercent,
			"threshold", e.cfg.CPUUsagePercent)
	}
}

func (e *Engine) evalIO(ctx context.Context, m model.NodeMetrics) {
	if m.CPU.IOWaitPercent > e.cfg.IOWaitPercent {
		e.fire(ctx, ebpf.ModIOLatency,
			"iowait", m.CPU.IOWaitPercent,
			"threshold", e.cfg.IOWaitPercent)
	}

	// Sustained iowait → attribute the blocked time to processes and stacks.
	// io_latency covers the block device; offcpu covers everything a task can
	// block on, and is the only module that can explain iowait when the disk
	// turns out to be idle.
	if e.offcpuCfg != nil && e.offcpuCfg.Enabled &&
		m.CPU.IOWaitPercent > e.offcpuCfg.IOWaitThreshold {
		e.fire(ctx, ebpf.ModOffCPU,
			"iowait", m.CPU.IOWaitPercent,
			"threshold", e.offcpuCfg.IOWaitThreshold)
	}

	// Heuristic: high load but low CPU → IO-bound
	numCPU := float64(runtime.NumCPU())
	normLoad := m.LoadAvg.Load1 / numCPU
	if normLoad > e.cfg.LoadNormalised && m.CPU.UsagePercent < 50.0 {
		slog.Info("trigger: high load + low CPU → IO bound suspected",
			"load1", m.LoadAvg.Load1,
			"norm_load", normLoad,
			"cpu_pct", m.CPU.UsagePercent)
		e.fire(ctx, ebpf.ModIOLatency, "norm_load", normLoad, "cpu_pct", m.CPU.UsagePercent)
		e.fire(ctx, ebpf.ModRunQLat, "norm_load", normLoad, "cpu_pct", m.CPU.UsagePercent)
	}
}

func (e *Engine) evalScheduler(ctx context.Context, m model.NodeMetrics) {
	// High context-switch rate → scheduler pressure
	if m.CPU.CtxSwitches > e.cfg.CtxSwitchDelta {
		e.fire(ctx, ebpf.ModRunQLat,
			"ctx_switches_per_s", m.CPU.CtxSwitches,
			"threshold", e.cfg.CtxSwitchDelta)
	}

	// Very high load regardless of CPU: always check run-queue
	numCPU := float64(runtime.NumCPU())
	normLoad := m.LoadAvg.Load1 / numCPU
	if normLoad > e.cfg.LoadNormalised {
		e.fire(ctx, ebpf.ModRunQLat, "norm_load", normLoad, "threshold", e.cfg.LoadNormalised)
	}

	e.evalRunQueueLevel1(ctx, m, normLoad)
}

// evalRunQueueLevel1 is the node-wide gate of the two-level run-queue scheme.
// Breaching it loads runqlat, which then aggregates per-process waits in-kernel;
// the level-2 (per-process) filter is applied when the report is built.
//
// CPU% alone is not enough: run-queue oversubscription frequently shows up as
// high load with moderate CPU, so either signal opens the gate.
func (e *Engine) evalRunQueueLevel1(ctx context.Context, m model.NodeMetrics, normLoad float64) {
	if e.runqCfg == nil || !e.runqCfg.Enabled {
		return
	}
	cpuHot := e.runqCfg.NodeCPUThreshold > 0 && m.CPU.UsagePercent > e.runqCfg.NodeCPUThreshold
	loadHot := e.runqCfg.NodeLoadThreshold > 0 && normLoad > e.runqCfg.NodeLoadThreshold
	if !cpuHot && !loadHot {
		return
	}
	e.fire(ctx, ebpf.ModRunQLat,
		"level", 1,
		"cpu_pct", m.CPU.UsagePercent,
		"cpu_threshold", e.runqCfg.NodeCPUThreshold,
		"norm_load", normLoad,
		"load_threshold", e.runqCfg.NodeLoadThreshold)
}

func (e *Engine) evalNetwork(ctx context.Context, m model.NodeMetrics) {
	var totalErrors uint64
	for _, iface := range m.Network {
		totalErrors += iface.RxErrors + iface.TxErrors + iface.RxDropped + iface.TxDropped
	}
	if totalErrors > e.cfg.NetErrorDelta {
		e.fire(ctx, ebpf.ModTCPRetransmit,
			"net_errors_per_s", totalErrors,
			"threshold", e.cfg.NetErrorDelta)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// fire activates a module and logs the triggering condition.
func (e *Engine) fire(ctx context.Context, id ebpf.ModuleID, keyvals ...interface{}) {
	if !e.firing[id] {
		slog.Info("trigger: FIRING", append([]interface{}{"module", id}, keyvals...)...)
		e.firing[id] = true
	}

	if err := e.manager.Activate(ctx, id); err != nil {
		slog.Warn("trigger: activate failed", "module", id, "err", err)
		return
	}
}
