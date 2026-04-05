// Package config loads and validates the agent configuration from a YAML file
// or environment variables. All fields have sensible production defaults.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration object.
type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	Collect   CollectConfig   `yaml:"collect"`
	EBPF      EBPFConfig      `yaml:"ebpf"`
	Trigger   TriggerConfig   `yaml:"trigger"`
	Exporter  ExporterConfig  `yaml:"exporter"`
	Process   ProcessConfig   `yaml:"process"`
	DiskScan  DiskScanConfig  `yaml:"disk_scan"`
	Fsync     FsyncConfig     `yaml:"fsync"`
	Writeback WritebackConfig `yaml:"writeback"`
}

type AgentConfig struct {
	// LogLevel: debug | info | warn | error
	LogLevel string `yaml:"log_level"`
	// MetricsAddr: Prometheus scrape endpoint (empty = disabled)
	MetricsAddr string `yaml:"metrics_addr"`
	// NodeName overrides the auto-detected hostname.
	NodeName string `yaml:"node_name"`
}

type CollectConfig struct {
	// Interval for /proc polling.
	Interval time.Duration `yaml:"interval"`
	// Disk devices to monitor (empty = all).
	DiskDevices []string `yaml:"disk_devices"`
	// Network interfaces to monitor (empty = all non-loopback).
	NetInterfaces []string `yaml:"net_interfaces"`
}

// EBPFConfig controls the on-demand eBPF sub-system.
type EBPFConfig struct {
	// Enabled is a master switch – if false, no eBPF programs are ever loaded.
	Enabled bool `yaml:"enabled"`
	// ActiveDuration is how long each eBPF program stays active once triggered.
	ActiveDuration time.Duration `yaml:"active_duration"`
	// CoolDown is the minimum time between two activations of the same program.
	CoolDown time.Duration `yaml:"cool_down"`
	// SlowIOThresholdUs: IO events below this are not emitted (to reduce noise).
	SlowIOThresholdUs uint64 `yaml:"slow_io_threshold_us"`
	// RunQLat threshold before emitting events.
	RunQLatThresholdUs uint64 `yaml:"runqlat_threshold_us"`
	// SampleHz is the CPU profiling frequency.
	SampleHz uint64 `yaml:"sample_hz"`
}

// TriggerConfig defines the thresholds that auto-enable eBPF modules.
type TriggerConfig struct {
	// CPUUsagePercent: enable CPU profiling when CPU > threshold.
	CPUUsagePercent float64 `yaml:"cpu_usage_percent"`
	// IOWaitPercent: enable IO latency tracing when iowait > threshold.
	IOWaitPercent float64 `yaml:"iowait_percent"`
	// LoadNormalised: enable runqlat when load/cpu > threshold (e.g. 1.5).
	LoadNormalised float64 `yaml:"load_normalised"`
	// CtxSwitchDelta: enable runqlat when ctx-switches/s > threshold.
	CtxSwitchDelta uint64 `yaml:"ctx_switch_delta"`
	// NetErrorDelta: enable TCP tracing when net errors/s > threshold.
	NetErrorDelta uint64 `yaml:"net_error_delta"`
	// EvalInterval: how often the trigger engine evaluates thresholds.
	EvalInterval time.Duration `yaml:"eval_interval"`
}

type ExporterConfig struct {
	// URL is the central server endpoint (empty = disabled).
	URL string `yaml:"url"`
	// BatchSize: max events in one HTTP POST.
	BatchSize int `yaml:"batch_size"`
	// FlushInterval: how often to flush the batch even if not full.
	FlushInterval time.Duration `yaml:"flush_interval"`
	// Compress: gzip payloads before sending.
	Compress bool `yaml:"compress"`
	// Timeout for HTTP requests.
	Timeout time.Duration `yaml:"timeout"`
}

type ProcessConfig struct {
	// TopN: how many processes to include in each snapshot.
	TopN int `yaml:"top_n"`
	// ScanInterval: how often to scan /proc for process stats.
	ScanInterval time.Duration `yaml:"scan_interval"`
	// IncludeIO: read per-process IO (requires CAP_SYS_PTRACE on some kernels).
	IncludeIO bool `yaml:"include_io"`
}

// FsyncConfig controls the eBPF fsync latency tracer and its analyzer.
// The analyzer continuously polls the in-kernel LRU map and makes the latest
// FsyncAnalysis available to GET /api/diagnose.
type FsyncConfig struct {
	// Enabled is the master switch for the fsync tracer.
	Enabled bool `yaml:"enabled"`
	// SlowThresholdUs: emit a ringbuf outlier event only when a single fsync
	// call exceeds this latency (microseconds).  Default 5 000 µs = 5 ms.
	// Normal calls update only the in-kernel LRU map (no per-event wakeup).
	SlowThresholdUs uint64 `yaml:"slow_threshold_us"`
	// PollInterval: how often the analyzer batch-reads the in-kernel LRU map.
	PollInterval time.Duration `yaml:"poll_interval"`
	// TopN: how many top offenders to include in FsyncAnalysis.
	TopN int `yaml:"top_n"`
	// StaleSeconds: ignore LRU entries whose last_seen_ts is older than this.
	StaleSeconds int `yaml:"stale_seconds"`
	// CPUThreshold: refresh the analysis snapshot when CPU usage exceeds this.
	CPUThreshold float64 `yaml:"cpu_threshold"`
	// MemThreshold: refresh the analysis snapshot when memory usage exceeds this.
	MemThreshold float64 `yaml:"mem_threshold"`
}

// WritebackConfig controls the eBPF memory writeback / direct-reclaim tracer.
// The analyzer continuously polls the in-kernel LRU map and makes the latest
// WritebackAnalysis available to GET /api/diagnose.
type WritebackConfig struct {
	// Enabled is the master switch for the writeback tracer.
	Enabled bool `yaml:"enabled"`
	// SlowReclaimThresholdNs: emit a ringbuf outlier event only when a single
	// direct-reclaim episode exceeds this duration (nanoseconds).
	// Default 100 000 000 ns = 100 ms.
	SlowReclaimThresholdNs uint64 `yaml:"slow_reclaim_threshold_ns"`
	// PollInterval: how often the analyzer batch-reads the in-kernel LRU map.
	// NOTE: bare integers (e.g. "5") are parsed as nanoseconds — always add a
	// unit suffix (e.g. "5s").
	PollInterval time.Duration `yaml:"poll_interval"`
	// TopN: how many top offenders to include in WritebackAnalysis.
	TopN int `yaml:"top_n"`
	// StaleSeconds: ignore LRU entries whose last_seen_ts is older than this.
	StaleSeconds int `yaml:"stale_seconds"`
	// MemThreshold: publish a new snapshot when memory usage exceeds this %.
	MemThreshold float64 `yaml:"mem_threshold"`
	// ReclaimSpikeNs: publish a new snapshot when any PID's max direct-reclaim
	// latency exceeds this duration (nanoseconds).  Default 10 000 000 = 10 ms.
	ReclaimSpikeNs uint64 `yaml:"reclaim_spike_ns"`
}

// DiskScanConfig controls the directory-size scanner and growth detector.
type DiskScanConfig struct {
	// Enabled is the master switch for the disk scanner.
	Enabled bool `yaml:"enabled"`
	// Dirs is the list of root directories to scan.
	Dirs []string `yaml:"dirs"`
	// MaxDepth limits how many directory levels deep each scan walks.
	MaxDepth int `yaml:"max_depth"`
	// MaxWorkers caps the number of concurrent directory-size goroutines.
	MaxWorkers int `yaml:"max_workers"`
	// IgnorePatterns are directory names to skip (e.g. node_modules, .cache).
	IgnorePatterns []string `yaml:"ignore_patterns"`
	// GrowthThresholdPct: trigger eBPF tracing when a directory grows by more
	// than this percentage between two consecutive scans.
	GrowthThresholdPct float64 `yaml:"growth_threshold_pct"`
	// ScanInterval controls how often the scanner runs.  Minimum 1 minute.
	ScanInterval time.Duration `yaml:"scan_interval"`
	// SkipNFS skips directories backed by NFS/CIFS mounts (detected via /proc/mounts).
	SkipNFS bool `yaml:"skip_nfs"`
}

// Defaults returns a Config with sensible production defaults.
func Defaults() *Config {
	return &Config{
		Agent: AgentConfig{
			LogLevel:    "info",
			MetricsAddr: ":9200",
		},
		Collect: CollectConfig{
			Interval: 5 * time.Second,
		},
		EBPF: EBPFConfig{
			Enabled:            true,
			ActiveDuration:     60 * time.Second,
			CoolDown:           120 * time.Second,
			SlowIOThresholdUs:  1000, // 1ms
			RunQLatThresholdUs: 5000, // 5ms
			SampleHz:           99,
		},
		Trigger: TriggerConfig{
			CPUUsagePercent: 85.0,
			IOWaitPercent:   20.0,
			LoadNormalised:  1.5,
			CtxSwitchDelta:  100_000,
			NetErrorDelta:   100,
			EvalInterval:    10 * time.Second,
		},
		Exporter: ExporterConfig{
			BatchSize:     200,
			FlushInterval: 30 * time.Second,
			Compress:      true,
			Timeout:       10 * time.Second,
		},
		Process: ProcessConfig{
			TopN:         20,
			ScanInterval: 10 * time.Second,
			IncludeIO:    true,
		},
		DiskScan: DiskScanConfig{
			Enabled:            true,
			Dirs:               []string{"/var", "/home", "/data", "/opt", "/root"},
			MaxDepth:           3,
			MaxWorkers:         5,
			IgnorePatterns:     []string{"node_modules", ".cache", "tmp", ".git", "__pycache__", "lost+found"},
			GrowthThresholdPct: 20.0,
			ScanInterval:       10 * time.Minute,
			SkipNFS:            true,
		},
		Fsync: FsyncConfig{
			Enabled:         true,
			SlowThresholdUs: 5000,            // 5 ms – only outliers hit the ringbuf
			PollInterval:    5 * time.Second, // poll in-kernel LRU map every 5 s
			TopN:            20,
			StaleSeconds:    60,
			CPUThreshold:    85.0,
			MemThreshold:    85.0,
		},
		Writeback: WritebackConfig{
			Enabled:                true,
			SlowReclaimThresholdNs: 100_000_000, // 100 ms – only severe stalls hit the ringbuf
			PollInterval:           5 * time.Second,
			TopN:                   20,
			StaleSeconds:           60,
			MemThreshold:           85.0,
			ReclaimSpikeNs:         10_000_000, // 10 ms – publish snapshot on any spike > 10 ms
		},
	}
}

// Load reads a YAML config file and merges it over the defaults.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Collect.Interval < time.Second {
		return fmt.Errorf("collect.interval must be >= 1s")
	}
	if c.EBPF.SampleHz == 0 || c.EBPF.SampleHz > 1000 {
		return fmt.Errorf("ebpf.sample_hz must be in [1, 1000]")
	}
	if c.Process.TopN <= 0 {
		return fmt.Errorf("process.top_n must be > 0")
	}
	return nil
}
