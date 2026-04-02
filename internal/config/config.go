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
	Agent    AgentConfig    `yaml:"agent"`
	Collect  CollectConfig  `yaml:"collect"`
	EBPF     EBPFConfig     `yaml:"ebpf"`
	Trigger  TriggerConfig  `yaml:"trigger"`
	Exporter ExporterConfig `yaml:"exporter"`
	Process  ProcessConfig  `yaml:"process"`
	DiskScan DiskScanConfig `yaml:"disk_scan"`
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
