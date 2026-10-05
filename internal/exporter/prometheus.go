// Package exporter – Prometheus metrics endpoint.
//
// Exposes all baseline metrics as Prometheus gauges/counters on :9200/metrics
// so the agent is compatible with existing Prometheus/Grafana stacks.
// eBPF events are exposed as counters (total events seen per module).
package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/diskscanner"
	ebpfmgr "github.com/manhvu1997/linux-obs-agent/internal/ebpf"
	"github.com/manhvu1997/linux-obs-agent/internal/fsync"
	"github.com/manhvu1997/linux-obs-agent/internal/iodiag"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/mongo"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/runq"
	"github.com/manhvu1997/linux-obs-agent/internal/writeback"
)

// PrometheusExporter serves a /metrics endpoint.
type PrometheusExporter struct {
	addr     string
	coll     *collector.Collector
	hostname string

	// Optional diagnostic sources – set via RegisterDiagnosticSources.
	mgr               *ebpfmgr.Manager
	insp              *process.Inspector
	httpExp           *Exporter
	diskScanner       *diskscanner.Scanner
	fsyncAnalyzer     *fsync.Analyzer
	writebackAnalyzer *writeback.Analyzer
	mongoAnalyzer     *mongo.Analyzer
	mysqlAnalyzer     *mysql.Analyzer

	// Run-queue / on-demand profiling config – set via RegisterRunQueueSources.
	runqCfg    *config.RunQueueConfig
	offcpuCfg  *config.OffCPUConfig
	profileCfg *config.ProfileConfig
	iodiagCfg  *config.IODiagConfig

	// CPU
	cpuUsage     prometheus.Gauge
	cpuUser      prometheus.Gauge
	cpuSys       prometheus.Gauge
	cpuIOwait    prometheus.Gauge
	cpuSteal     prometheus.Gauge
	ctxSw        prometheus.Gauge
	runningProcs prometheus.Gauge
	blockedProcs prometheus.Gauge

	// Memory
	memTotal   prometheus.Gauge
	memUsed    prometheus.Gauge
	memFree    prometheus.Gauge
	memAvail   prometheus.Gauge
	memSwapPct prometheus.Gauge

	// Load
	load1  prometheus.Gauge
	load5  prometheus.Gauge
	load15 prometheus.Gauge

	// Disk (labelled by device)
	diskReadBPS  *prometheus.GaugeVec
	diskWriteBPS *prometheus.GaugeVec
	diskIOUtil   *prometheus.GaugeVec
	diskAvgWait  *prometheus.GaugeVec

	// Network (labelled by interface)
	netRxBPS  *prometheus.GaugeVec
	netTxBPS  *prometheus.GaugeVec
	netRxErrs *prometheus.GaugeVec
	netTxErrs *prometheus.GaugeVec

	// eBPF event counters
	ebpfEventsTotal *prometheus.CounterVec
}

func NewPrometheusExporter(addr string, coll *collector.Collector) *PrometheusExporter {
	ns := "obs_agent"
	hostname, _ := os.Hostname()
	p := &PrometheusExporter{addr: addr, coll: coll, hostname: hostname}

	p.cpuUsage = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "cpu_usage_percent"})
	p.cpuUser = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "cpu_user_percent"})
	p.cpuSys = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "cpu_sys_percent"})
	p.cpuIOwait = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "cpu_iowait_percent"})
	p.cpuSteal = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "cpu_steal_percent"})
	p.ctxSw = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "cpu_ctx_switches_per_sec"})
	p.runningProcs = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "procs_running"})
	p.blockedProcs = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "procs_blocked"})

	p.memTotal = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "mem_total_bytes"})
	p.memUsed = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "mem_used_bytes"})
	p.memFree = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "mem_free_bytes"})
	p.memAvail = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "mem_available_bytes"})
	p.memSwapPct = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "mem_swap_percent"})

	p.load1 = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "load1"})
	p.load5 = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "load5"})
	p.load15 = promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "load15"})

	labels := []string{"device"}
	p.diskReadBPS = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "disk_read_bytes_per_sec"}, labels)
	p.diskWriteBPS = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "disk_write_bytes_per_sec"}, labels)
	p.diskIOUtil = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "disk_io_util_percent"}, labels)
	p.diskAvgWait = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "disk_avg_wait_ms"}, labels)

	iLabels := []string{"interface"}
	p.netRxBPS = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "net_rx_bytes_per_sec"}, iLabels)
	p.netTxBPS = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "net_tx_bytes_per_sec"}, iLabels)
	p.netRxErrs = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "net_rx_errors_total"}, iLabels)
	p.netTxErrs = promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "net_tx_errors_total"}, iLabels)

	p.ebpfEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: ns, Name: "ebpf_events_total"},
		[]string{"module"},
	)

	return p
}

// RegisterDiagnosticSources wires the optional dependencies needed by
// GET /api/diagnose.  Call this once after all components are created.
func (p *PrometheusExporter) RegisterDiagnosticSources(
	mgr *ebpfmgr.Manager,
	insp *process.Inspector,
	exp *Exporter,
) {
	p.mgr = mgr
	p.insp = insp
	p.httpExp = exp
}

// RegisterRunQueueSources wires the run-queue and on-demand profiling config
// so /api/diagnose includes `runqueue_report` and /api/profile is served.
func (p *PrometheusExporter) RegisterRunQueueSources(
	runqCfg *config.RunQueueConfig,
	offcpuCfg *config.OffCPUConfig,
	profileCfg *config.ProfileConfig,
) {
	p.runqCfg = runqCfg
	p.offcpuCfg = offcpuCfg
	p.profileCfg = profileCfg
}

// RegisterIODiagConfig wires the correlation-classifier thresholds.
// Without it the shipped defaults apply.
func (p *PrometheusExporter) RegisterIODiagConfig(c *config.IODiagConfig) {
	p.iodiagCfg = c
}

// RegisterDiskScanner wires the disk scanner so /api/diagnose includes
// directory-growth data and top disk writers.
func (p *PrometheusExporter) RegisterDiskScanner(s *diskscanner.Scanner) {
	p.diskScanner = s
}

// RegisterFsyncAnalyzer wires the fsync analyzer so /api/diagnose includes
// the latest FsyncAnalysis snapshot (populated only under system pressure).
func (p *PrometheusExporter) RegisterFsyncAnalyzer(a *fsync.Analyzer) {
	p.fsyncAnalyzer = a
}

// RegisterWritebackAnalyzer wires the writeback analyzer so /api/diagnose
// includes the latest WritebackAnalysis snapshot (populated only when memory
// is under pressure or direct-reclaim latency spikes).
func (p *PrometheusExporter) RegisterWritebackAnalyzer(a *writeback.Analyzer) {
	p.writebackAnalyzer = a
}

// RegisterMongoAnalyzer wires the MongoDB slow-query analyzer so /api/diagnose
// includes the latest MongoAnalysis snapshot.
// Only populated when MongoDB tracing is enabled (MONGODB_TRACING_ENABLED=true).
func (p *PrometheusExporter) RegisterMongoAnalyzer(a *mongo.Analyzer) {
	p.mongoAnalyzer = a
}

// RegisterMySQLAnalyzer wires the MySQL slow-query analyzer so /api/diagnose
// includes the latest MySQLAnalysis snapshot.
// Only populated when MySQL tracing is enabled (MYSQL_TRACING_ENABLED=true).
func (p *PrometheusExporter) RegisterMySQLAnalyzer(a *mysql.Analyzer) {
	p.mysqlAnalyzer = a
}

// RecordEBPFEvent increments the per-module event counter.
func (p *PrometheusExporter) RecordEBPFEvent(ev model.EBPFEvent) {
	p.ebpfEventsTotal.WithLabelValues(string(ev.Type)).Inc()
}

// Run starts the HTTP server and launches a metrics refresh loop.
func (p *PrometheusExporter) Run(ctx context.Context) error {
	// Refresh metrics from the latest collector snapshot on every scrape.
	http.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.refresh()
		promhttp.Handler().ServeHTTP(w, r)
	}))
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// MCP / alerting diagnostic endpoint.
	http.HandleFunc("/api/diagnose", p.handleDiagnose)
	// On-demand per-process CPU profile (linked from each run-queue offender).
	http.HandleFunc("/api/profile", p.handleProfile)

	srv := &http.Server{Addr: p.addr}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	slog.Info("prometheus: listening", "addr", p.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handleDiagnose is called by GET /api/diagnose.
//
// Query parameters:
//
//	n        – max number of recent eBPF events to include (default 100)
//	top_pids – max CPU hotspots from cpu_profile map (default 20)
//
// The MCP server can POST an alert to Slack and include the JSON body of this
// endpoint so the on-call engineer immediately sees which PID / process /
// connection is responsible.
func (p *PrometheusExporter) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse optional query params.
	n := queryInt(r, "n", 100)
	topPIDsN := queryInt(r, "top_pids", 20)

	report := model.DiagnoseReport{
		Timestamp: time.Now(),
		Hostname:  p.hostname,
		Metrics:   p.coll.Latest(),
	}

	// Active eBPF modules.
	if p.mgr != nil {
		for _, id := range p.mgr.ActiveModules() {
			report.ActiveModules = append(report.ActiveModules, string(id))
		}
		// CPU hotspots: legacy flat list sorted by sample count.
		report.CPUHotspots = p.mgr.CPUTopPIDs(topPIDsN)
		// CPU profile v2: fully aggregated, symbolized, LLM-ready.
		// Nil when cpu_profile module is not active.
		report.CPUProfileReport = p.mgr.BuildCPUProfileReport()
		// Block-IO latency distribution (biolatency). Already computed
		// in-kernel on every completed request; nil when io_latency is off.
		report.IOLatencyHistogram = buildIOLatencyHistogram(p.mgr.IOLatencyHistogram())
		// Off-CPU report: where processes are BLOCKED. Nil unless the offcpu
		// module is active (triggered by sustained iowait). This is the field
		// that explains iowait — CPUHotspots/CPUProfileReport cannot, since
		// they only sample running tasks.
		if p.offcpuCfg != nil && p.offcpuCfg.Enabled {
			report.OffCPUReport = p.mgr.BuildOffCPUReport()
		}
		// Run-queue level-2 report. Nil when the node never breached level 1
		// (runqlat not loaded) or no process breached level 2.
		if p.runqCfg != nil && p.runqCfg.Enabled {
			report.RunQueueReport = p.mgr.BuildRunQueueReport(report.Metrics, runq.Options{
				TopN:               p.runqCfg.TopN,
				StaleSeconds:       p.runqCfg.StaleSeconds,
				ProcessThresholdUs: p.runqCfg.ProcessThresholdUs,
				TrackMinUs:         p.runqCfg.TrackMinUs,
				NodeCPUThreshold:   p.runqCfg.NodeCPUThreshold,
				NodeLoadThreshold:  p.runqCfg.NodeLoadThreshold,
			})
		}
	}

	// Correlated I/O diagnosis: walks node → device → blocked tasks → process
	// → stack and emits a verdict. Built last so it can consume the off-CPU
	// report assembled above, and from the same NodeMetrics snapshot so every
	// signal it compares describes the same instant.
	report.IODiagnosis = iodiag.Classify(report.Metrics, report.OffCPUReport, p.iodiagThresholds())

	// Top processes from /proc.
	if p.insp != nil {
		report.TopProcesses = p.insp.TopCPU()
	}

	// Recent eBPF events from the ring buffer.
	if p.httpExp != nil {
		report.RecentEvents = p.httpExp.RecentEvents(n)
	}

	// Disk scanner: top directories, growth events, top write processes.
	if p.diskScanner != nil {
		diskReport := &model.DiskDiagnoseReport{
			Snapshot:     p.diskScanner.Snapshot(),
			GrowthEvents: p.diskScanner.GrowthEvents(),
		}
		// Top disk writers from the disk_write eBPF module (nil when not active).
		if p.mgr != nil {
			diskReport.TopWriters = p.mgr.DiskTopWriters(topPIDsN)
		}
		report.DiskReport = diskReport
	}

	// Fsync analysis: latest high-pressure snapshot from the always-on tracer.
	// Only non-nil when the system was under CPU/mem pressure during a recent
	// poll cycle (CPU > cfg.CPUThreshold OR Mem > cfg.MemThreshold).
	if p.fsyncAnalyzer != nil {
		report.FsyncReport = p.fsyncAnalyzer.Latest()
	}

	// Writeback analysis: latest snapshot from the always-on tracer.
	// Only non-nil when memory exceeds cfg.MemThreshold OR any process has
	// experienced a direct-reclaim stall longer than cfg.ReclaimSpikeNs.
	if p.writebackAnalyzer != nil {
		report.WritebackReport = p.writebackAnalyzer.Latest()
	}

	// MongoDB slow-query analysis: latest snapshot from the always-on tracer.
	// Only non-nil when MongoDB tracing is enabled and queries have been observed.
	if p.mongoAnalyzer != nil {
		report.MongoReport = p.mongoAnalyzer.Latest()
	}

	// MySQL slow-query analysis: latest snapshot from the server-side uprobe tracer.
	// Only non-nil when MySQL tracing is enabled and queries have been observed.
	if p.mysqlAnalyzer != nil {
		report.MySQLReport = p.mysqlAnalyzer.Latest()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.Warn("diagnose: encode error", "err", err)
	}
}

// handleProfile is called by GET /api/profile.
//
// It is the click-through target of the ProfileURL carried by every run-queue
// offender in /api/diagnose: given a PID it samples that process's on-CPU
// stacks and returns a symbolized, flamegraph-ready profile.
//
// Query parameters:
//
//	pid      – required, the process to profile
//	duration – sampling window (default profile.default_duration, capped at
//	           profile.max_duration).  Ignored on a cache hit.
//	format   – "json" (default) or "folded" for flamegraph.pl / speedscope
//	mode     – "oncpu" (default) = where the process is RUNNING;
//	           "offcpu"          = where it is BLOCKED and for how long.
//	           Use offcpu when the symptom is iowait or D-state: an on-CPU
//	           sampler only fires on running tasks and cannot see a sleeper.
//
// The request blocks for the sampling window. Profiling is single-flight
// agent-wide; a concurrent request gets 429 rather than doubling the load on
// an already-stressed node.
func (p *PrometheusExporter) handleProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.mgr == nil || p.profileCfg == nil || !p.profileCfg.Enabled {
		http.Error(w, "on-demand profiling is disabled", http.StatusServiceUnavailable)
		return
	}

	pid, err := strconv.ParseUint(r.URL.Query().Get("pid"), 10, 32)
	if err != nil || pid == 0 {
		http.Error(w, "missing or invalid 'pid' parameter", http.StatusBadRequest)
		return
	}

	duration := p.profileCfg.DefaultDuration
	if s := r.URL.Query().Get("duration"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			http.Error(w, "invalid 'duration' (expected e.g. 5s, 10s)", http.StatusBadRequest)
			return
		}
		if d > p.profileCfg.MaxDuration {
			http.Error(w, fmt.Sprintf("duration exceeds profile.max_duration (%s)",
				p.profileCfg.MaxDuration), http.StatusBadRequest)
			return
		}
		duration = d
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "folded" {
		http.Error(w, "invalid 'format' (expected json or folded)", http.StatusBadRequest)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = ebpfmgr.ModeOnCPU
	}
	if mode != ebpfmgr.ModeOnCPU && mode != ebpfmgr.ModeOffCPU {
		http.Error(w, "invalid 'mode' (expected oncpu or offcpu)", http.StatusBadRequest)
		return
	}
	if mode == ebpfmgr.ModeOffCPU && (p.offcpuCfg == nil || !p.offcpuCfg.Enabled) {
		http.Error(w, "off-CPU profiling is disabled", http.StatusServiceUnavailable)
		return
	}

	res, err := p.mgr.ProfilePID(r.Context(), ebpfmgr.ProfileRequest{
		PID:      uint32(pid),
		Duration: duration,
		Folded:   format == "folded",
		Mode:     mode,
	})
	switch {
	case errors.Is(err, ebpfmgr.ErrNoSuchProcess):
		http.Error(w, fmt.Sprintf("no such process: %d", pid), http.StatusNotFound)
		return
	case errors.Is(err, ebpfmgr.ErrProfileBusy):
		w.Header().Set("Retry-After", strconv.Itoa(int(duration.Seconds())+1))
		http.Error(w, "a profile is already running; retry shortly", http.StatusTooManyRequests)
		return
	case errors.Is(err, ebpfmgr.ErrProfileDisabled):
		http.Error(w, "on-demand profiling is disabled", http.StatusServiceUnavailable)
		return
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Client disconnected mid-window; nothing useful to send.
		return
	case err != nil:
		slog.Warn("profile: failed", "pid", pid, "err", err)
		http.Error(w, "profiling failed", http.StatusInternalServerError)
		return
	}

	if format == "folded" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := w.Write(res.Folded); err != nil {
			slog.Debug("profile: folded write error", "pid", pid, "err", err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(model.ProfileResponse{
		Type:         "pid_cpu_profile",
		Timestamp:    time.Now(),
		Mode:         res.Mode,
		PID:          res.PID,
		Comm:         res.Comm,
		DurationMs:   res.Duration.Milliseconds(),
		SampleHz:     res.SampleHz,
		Cached:       res.Cached,
		Reused:       res.Reused,
		Report:       res.Report,
		OffCPUReport: res.OffCPUReport,
	}); err != nil {
		slog.Warn("profile: encode error", "err", err)
	}
}

// iodiagThresholds returns the classifier thresholds, falling back to the
// shipped defaults when no io_diag config was registered.
func (p *PrometheusExporter) iodiagThresholds() iodiag.Thresholds {
	if p.iodiagCfg == nil {
		return iodiag.Defaults()
	}
	return iodiag.Thresholds{
		IOWaitPercent:         p.iodiagCfg.IOWaitPercent,
		LowThroughputMBPerSec: p.iodiagCfg.LowThroughputMBPerSec,
		LowUtilPercent:        p.iodiagCfg.LowUtilPercent,
		HighUtilPercent:       p.iodiagCfg.HighUtilPercent,
		DStateStallMs:         p.iodiagCfg.DStateStallMs,
		SlowDeviceWaitMs:      p.iodiagCfg.SlowDeviceWaitMs,
		DirtyRatioPercent:     p.iodiagCfg.DirtyRatioPercent,
		PSIFullAvg10:          p.iodiagCfg.PSIFullAvg10,
	}
}

// buildIOLatencyHistogram converts the raw log2(us) buckets into labelled,
// non-empty entries. Bucket i covers [2^i - 1, 2^(i+1) - 2] microseconds.
func buildIOLatencyHistogram(raw map[uint32]uint64) []model.IOLatencyBucket {
	if len(raw) == 0 {
		return nil
	}
	out := make([]model.IOLatencyBucket, 0, len(raw))
	for i := uint32(0); i < 64; i++ {
		count := raw[i]
		if count == 0 {
			continue
		}
		low := uint64(1)<<i - 1
		high := uint64(1)<<(i+1) - 2
		out = append(out, model.IOLatencyBucket{
			Range:  fmt.Sprintf("%s-%s", formatUsec(low), formatUsec(high)),
			LowUs:  low,
			HighUs: high,
			Count:  count,
		})
	}
	return out
}

// formatUsec renders a microsecond value with the largest sensible unit.
func formatUsec(us uint64) string {
	switch {
	case us >= 1_000_000:
		return fmt.Sprintf("%gs", float64(us)/1e6)
	case us >= 1_000:
		return fmt.Sprintf("%gms", float64(us)/1e3)
	default:
		return fmt.Sprintf("%dus", us)
	}
}

// queryInt reads an integer query parameter, returning def if absent or invalid.
func queryInt(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func (p *PrometheusExporter) refresh() {
	m := p.coll.Latest()

	p.cpuUsage.Set(m.CPU.UsagePercent)
	p.cpuUser.Set(m.CPU.UserPercent)
	p.cpuSys.Set(m.CPU.SysPercent)
	p.cpuIOwait.Set(m.CPU.IOWaitPercent)
	p.cpuSteal.Set(m.CPU.StealPercent)
	p.ctxSw.Set(float64(m.CPU.CtxSwitches))
	p.runningProcs.Set(float64(m.CPU.RunningProcs))
	p.blockedProcs.Set(float64(m.CPU.BlockedProcs))

	p.memTotal.Set(float64(m.Memory.TotalBytes))
	p.memUsed.Set(float64(m.Memory.UsedBytes))
	p.memFree.Set(float64(m.Memory.FreeBytes))
	p.memAvail.Set(float64(m.Memory.AvailableBytes))
	p.memSwapPct.Set(m.Memory.SwapPercent)

	p.load1.Set(m.LoadAvg.Load1)
	p.load5.Set(m.LoadAvg.Load5)
	p.load15.Set(m.LoadAvg.Load15)

	for _, d := range m.Disk {
		p.diskReadBPS.WithLabelValues(d.Device).Set(d.ReadBytesPerSec)
		p.diskWriteBPS.WithLabelValues(d.Device).Set(d.WriteBytesPerSec)
		p.diskIOUtil.WithLabelValues(d.Device).Set(d.IOUtilPercent)
		p.diskAvgWait.WithLabelValues(d.Device).Set(d.AvgWaitMs)
	}

	for _, n := range m.Network {
		p.netRxBPS.WithLabelValues(n.Interface).Set(n.RxBytesPerSec)
		p.netTxBPS.WithLabelValues(n.Interface).Set(n.TxBytesPerSec)
		p.netRxErrs.WithLabelValues(n.Interface).Set(float64(n.RxErrors))
		p.netTxErrs.WithLabelValues(n.Interface).Set(float64(n.TxErrors))
	}
}
