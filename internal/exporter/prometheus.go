// Package exporter – Prometheus metrics endpoint.
//
// Exposes all baseline metrics as Prometheus gauges/counters on :9200/metrics
// so the agent is compatible with existing Prometheus/Grafana stacks.
// eBPF events are exposed as counters (total events seen per module).
package exporter

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/diskscanner"
	ebpfmgr "github.com/manhvu1997/linux-obs-agent/internal/ebpf"
	"github.com/manhvu1997/linux-obs-agent/internal/fsync"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
)

// PrometheusExporter serves a /metrics endpoint.
type PrometheusExporter struct {
	addr     string
	coll     *collector.Collector
	hostname string

	// Optional diagnostic sources – set via RegisterDiagnosticSources.
	mgr          *ebpfmgr.Manager
	insp         *process.Inspector
	httpExp      *Exporter
	diskScanner  *diskscanner.Scanner
	fsyncAnalyzer *fsync.Analyzer

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
		// CPU hotspots from the kernel-side perf counts map.
		report.CPUHotspots = p.mgr.CPUTopPIDs(topPIDsN)
	}

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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.Warn("diagnose: encode error", "err", err)
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
