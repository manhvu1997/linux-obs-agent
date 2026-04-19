// Command db-inspector is a lightweight sidecar that exposes a single
// GET /api/inspect endpoint with per-database slow-query analysis.
//
// Unlike the full obs-agent (which is a node-level DaemonSet with CPU/IO/fsync
// tracers, trigger engine, etc.), db-inspector runs as a sidecar container
// alongside your application pod and traces only the databases you configure.
//
// Usage:
//
//	db-inspector [-config /etc/db-inspector/config.yaml] [-loglevel debug]
//
// Required Linux capabilities (applied via securityContext in Kubernetes):
//
//	CAP_BPF              – load eBPF programs
//	CAP_PERFMON          – open perf_event file descriptors (syscall tracepoints)
//	CAP_SYS_ADMIN        – pin programs to /sys/fs/bpf (fallback on older kernels)
//	CAP_SYS_PTRACE       – read /proc/[pid]/cmdline, cgroup for metadata enrichment
//
// The pod must also have hostPID: true so the sidecar can observe the target
// application's file descriptors via /proc.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/dbinspector"
)

func main() {
	cfgPath := flag.String("config", "/etc/db-inspector/config.yaml", "path to YAML config file")
	logLevel := flag.String("loglevel", "", "override log level (debug|info|warn|error)")
	flag.Parse()

	cfg, err := config.LoadDBInspector(*cfgPath)
	if err != nil {
		slog.Error("db-inspector: failed to load config", "err", err)
		os.Exit(1)
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	setupLogger(cfg.LogLevel)

	slog.Info("db-inspector starting",
		"version", "1.0.0",
		"go", runtime.Version(),
		"listen", cfg.ListenAddr,
		"mongo_enabled", cfg.Mongo.Enabled,
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Build the inspector registry ──────────────────────────────────────────
	registry := dbinspector.NewRegistry()

	if cfg.Mongo.Enabled {
		registry.Register(dbinspector.NewMongoInspector(&cfg.Mongo))
	}
	// Future extension (zero changes to existing code required):
	//   if cfg.MySQL.Enabled    { registry.Register(dbinspector.NewMySQLInspector(&cfg.MySQL)) }
	//   if cfg.Cassandra.Enabled { registry.Register(dbinspector.NewCassandraInspector(&cfg.Cassandra)) }

	registry.StartAll(ctx)

	// ── HTTP server ───────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/api/inspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(registry.Report()); err != nil {
			slog.Warn("db-inspector: encode error", "err", err)
		}
	})

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	slog.Info("db-inspector: listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("db-inspector: server error", "err", err)
		os.Exit(1)
	}
	slog.Info("db-inspector: stopped")
}

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
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
