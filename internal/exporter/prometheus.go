// Package exporter – Prometheus metrics endpoint.
//
// Exposes all baseline metrics as Prometheus gauges/counters on :9200/metrics
// so the agent is compatible with existing Prometheus/Grafana stacks.
// eBPF events are exposed as counters (total events seen per module).
package exporter

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// PrometheusExporter serves a /metrics endpoint.
type PrometheusExporter struct {
	addr string
	coll *collector.Collector

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
	p := &PrometheusExporter{addr: addr, coll: coll}

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
