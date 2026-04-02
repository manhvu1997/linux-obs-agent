package collector

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Collector orchestrates all /proc-based scrapes and emits NodeMetrics
// on the Metrics channel at a configurable interval.
type Collector struct {
	cfg     *config.CollectConfig
	cpu     *CPUCollector
	mem     *MemCollector
	disk    *DiskCollector
	net     *NetCollector
	Metrics chan model.NodeMetrics

	hostname string
	mu       sync.RWMutex
	latest   model.NodeMetrics
}

func New(cfg *config.CollectConfig) *Collector {
	hostname, _ := os.Hostname()
	return &Collector{
		cfg:      cfg,
		cpu:      NewCPUCollector(),
		mem:      NewMemCollector(),
		disk:     NewDiskCollector(cfg.DiskDevices),
		net:      NewNetCollector(cfg.NetInterfaces),
		Metrics:  make(chan model.NodeMetrics, 4),
		hostname: hostname,
	}
}

// Run starts the polling loop.  It blocks until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	// Warm-up: one silent collection to seed delta baselines.
	_ = c.collect()

	tick := time.NewTicker(c.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m := c.collect()
			c.mu.Lock()
			c.latest = m
			c.mu.Unlock()
			// Non-blocking send so that a slow consumer doesn't block scraping.
			select {
			case c.Metrics <- m:
			default:
				slog.Warn("collector: metrics channel full, dropping sample")
			}
		}
	}
}

// Latest returns the most recent metrics without blocking.
func (c *Collector) Latest() model.NodeMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

func (c *Collector) collect() model.NodeMetrics {
	m := model.NodeMetrics{
		Timestamp: time.Now(),
		Hostname:  c.hostname,
	}

	cpu, err := c.cpu.Collect()
	if err != nil {
		slog.Warn("cpu collect error", "err", err)
	} else {
		m.CPU = cpu
	}

	mem, err := c.mem.Collect()
	if err != nil {
		slog.Warn("mem collect error", "err", err)
	} else {
		m.Memory = mem
	}

	load, err := ReadLoadAvg()
	if err != nil {
		slog.Warn("loadavg collect error", "err", err)
	} else {
		load.NumCPU = runtime.NumCPU()
		m.LoadAvg = load
	}

	disks, err := c.disk.Collect()
	if err != nil {
		slog.Warn("disk collect error", "err", err)
	} else {
		m.Disk = disks
	}

	nets, err := c.net.Collect()
	if err != nil {
		slog.Warn("net collect error", "err", err)
	} else {
		m.Network = nets
	}

	return m
}
