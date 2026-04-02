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
//	high load + low CPU             → suspect IO wait → activate io_latency + runqlat
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
	cfg     *config.TriggerConfig
	coll    *collector.Collector
	manager *ebpf.Manager

	// firing tracks which modules are currently triggered so we can log
	// transitions clearly.
	firing map[ebpf.ModuleID]bool
}

func NewEngine(cfg *config.TriggerConfig, coll *collector.Collector, mgr *ebpf.Manager) *Engine {
	return &Engine{
		cfg:     cfg,
		coll:    coll,
		manager: mgr,
		firing:  make(map[ebpf.ModuleID]bool),
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
