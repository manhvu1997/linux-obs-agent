// Command agent is the Linux observability daemon.
//
// Usage:
//
//	obs-agent [-config /etc/obs-agent/config.yaml] [-loglevel debug]
//
// The agent:
//  1. Starts lightweight /proc collectors (always-on, ~0.1% CPU).
//  2. Runs a trigger engine that auto-enables eBPF modules when thresholds fire.
//  3. Exports metrics to a Prometheus /metrics endpoint AND an optional
//     central HTTP server.
//
// Required Linux capabilities:
//
//	CAP_BPF              – load eBPF programs
//	CAP_PERFMON          – open perf_event file descriptors
//	CAP_SYS_ADMIN        – pin programs to /sys/fs/bpf (optional)
//	CAP_NET_ADMIN        – attach XDP programs (tcp_retransmit uses tp_btf, not XDP)
//	CAP_SYS_PTRACE       – read /proc/[pid]/io for all processes
//	CAP_DAC_READ_SEARCH  – read /proc/[pid]/environ for K8s metadata (optional)
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	ebpfmgr "github.com/manhvu1997/linux-obs-agent/internal/ebpf"
	"github.com/manhvu1997/linux-obs-agent/internal/exporter"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/trigger"
)

func main() {
	cfgPath := flag.String("config", "/etc/obs-agent/config.yaml", "path to YAML config file")
	logLevel := flag.String("loglevel", "", "override log level (debug|info|warn|error)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}
	if *logLevel != "" {
		cfg.Agent.LogLevel = *logLevel
	}

	setupLogger(cfg.Agent.LogLevel)

	// Override hostname if configured (useful in containers).
	if cfg.Agent.NodeName != "" {
		_ = os.Setenv("HOSTNAME", cfg.Agent.NodeName)
	}

	// Print startup info.
	slog.Info("obs-agent starting",
		"version", "1.0.0",
		"go", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"cpus", runtime.NumCPU(),
		"ebpf_enabled", cfg.EBPF.Enabled,
	)

	// Root context wired to OS signals (SIGTERM / SIGINT for systemd).
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Baseline collector ──────────────────────────────────────────────────
	coll := collector.New(&cfg.Collect)
	go coll.Run(ctx)

	// ── Process inspector ───────────────────────────────────────────────────
	insp := process.NewInspector(&cfg.Process)
	go insp.Run(ctx)

	// ── eBPF manager (lazy – nothing loaded until triggered) ────────────────
	ebpfMgr := ebpfmgr.NewManager(&cfg.EBPF)

	// ── Trigger engine ──────────────────────────────────────────────────────
	triggerEngine := trigger.NewEngine(&cfg.Trigger, coll, ebpfMgr)
	go triggerEngine.Run(ctx)

	// ── Prometheus exporter ─────────────────────────────────────────────────
	var promExp *exporter.PrometheusExporter
	if cfg.Agent.MetricsAddr != "" {
		promExp = exporter.NewPrometheusExporter(cfg.Agent.MetricsAddr, coll)
	}

	// ── HTTP exporter (optional central server) ─────────────────────────────
	httpExp := exporter.New(&cfg.Exporter)
	go httpExp.Run(ctx)

	// Wire diagnostic sources so /api/diagnose has full visibility.
	if promExp != nil {
		promExp.RegisterDiagnosticSources(ebpfMgr, insp, httpExp)
		go func() {
			if err := promExp.Run(ctx); err != nil {
				slog.Error("prometheus exporter error", "err", err)
			}
		}()
	}

	// ── eBPF event fan-out loop ─────────────────────────────────────────────
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ebpfMgr.Events:
				// 1. Record in Prometheus counter.
				if promExp != nil {
					promExp.RecordEBPFEvent(ev)
				}
				// 2. Buffer for HTTP export.
				httpExp.QueueEvent(ev)
				// 3. Structured log at debug level for local visibility.
				slog.Debug("ebpf event",
					"type", ev.Type,
					"pid", ev.PID,
					"comm", ev.Comm,
				)
			}
		}
	}()

	// ── Snapshot flush loop (send to central server on interval) ───────────
	go func() {
		if cfg.Exporter.URL == "" {
			return
		}
		tick := time.NewTicker(cfg.Exporter.FlushInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				metrics := coll.Latest()
				topProcs := insp.TopCPU()
				if err := httpExp.SendSnapshot(ctx, metrics, topProcs); err != nil {
					slog.Warn("snapshot send failed", "err", err)
				}
			}
		}
	}()

	// ── Wait for shutdown signal ────────────────────────────────────────────
	<-ctx.Done()
	slog.Info("obs-agent: shutting down gracefully")

	// Give goroutines time to clean up eBPF resources.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	// Deactivate all running eBPF modules.
	for _, id := range ebpfMgr.ActiveModules() {
		ebpfMgr.Deactivate(id)
	}
	_ = shutdownCtx
	slog.Info("obs-agent: stopped")
}

// setupLogger configures the global slog logger.
func setupLogger(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: l,
	})))
}
