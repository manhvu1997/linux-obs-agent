// Package config loads and validates the agent configuration from a YAML file
// or environment variables. All fields have sensible production defaults.
package config

import (
	"fmt"
	"os"
	"strconv"
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
	RunQueue  RunQueueConfig  `yaml:"runq"`
	OffCPU    OffCPUConfig    `yaml:"offcpu"`
	IODiag    IODiagConfig    `yaml:"io_diag"`
	Profile   ProfileConfig   `yaml:"profile"`
	Fsync     FsyncConfig     `yaml:"fsync"`
	Writeback WritebackConfig `yaml:"writeback"`
	Mongo     MongoConfig     `yaml:"mongo"`
	MySQL     MySQLConfig     `yaml:"mysql"`
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

	// DStateDisabled turns off the D-state census. The scan walks /proc once
	// per interval; on a host with thousands of processes that is measurable,
	// so it can be switched off — at the cost of losing the link between
	// iowait and the specific tasks producing it.
	DStateDisabled bool `yaml:"d_state_disabled"`
	// DStateMaxTasks caps how many blocked tasks are reported (0 → 20).
	// Count and longest-duration remain exact regardless.
	DStateMaxTasks int `yaml:"d_state_max_tasks"`
	// DStateScanThreads also walks /proc/<pid>/task/<tid>. Off by default: it
	// multiplies scan cost by thread count, and the usual culprits
	// (kworker/flush, jbd2, io_uring workers) are top-level PIDs anyway.
	DStateScanThreads bool `yaml:"d_state_scan_threads"`
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
	// RunQLatThresholdUs is the legacy run-queue event threshold.
	// Deprecated: prefer runq.process_threshold_us, which is both the level-2
	// report filter and the in-kernel event threshold. This field is used only
	// as a fallback when runq.process_threshold_us is 0.
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

// RunQueueConfig controls the two-level run-queue analysis.
//
//	Level 1 (node)    – NodeCPUThreshold / NodeLoadThreshold decide when the
//	                    runqlat eBPF module is loaded at all.  While the node
//	                    is healthy nothing runs and there is zero overhead.
//	Level 2 (process) – ProcessThresholdUs decides which processes appear in
//	                    the `runqueue_report` of GET /api/diagnose.
type RunQueueConfig struct {
	// Enabled is the master switch for the level-1 trigger rule and the
	// runqueue_report section of /api/diagnose.
	Enabled bool `yaml:"enabled"`
	// NodeCPUThreshold: load runqlat once node CPU usage exceeds this percent.
	NodeCPUThreshold float64 `yaml:"node_cpu_threshold"`
	// NodeLoadThreshold: load runqlat once load1/NumCPU exceeds this ratio.
	// Catches run-queue oversubscription that CPU% alone misses (high load
	// with low CPU, e.g. many runnable-but-starved tasks).
	NodeLoadThreshold float64 `yaml:"node_load_threshold"`
	// ProcessThresholdUs is the level-2 threshold: a process is reported when
	// its MAX run-queue wait reaches this many microseconds.  This value is
	// also pushed into the kernel as the ringbuf event threshold, so
	// SlowEvents counts exactly the level-2 breaches.
	ProcessThresholdUs uint64 `yaml:"process_threshold_us"`
	// TrackMinUs is the in-kernel aggregation floor.  Waits below this are
	// counted in the global histogram but do not touch the per-process map.
	// sched_switch fires 100k-500k/s, so this gate is what keeps the module
	// cheap; lower it only if sub-100us waits matter to you.
	TrackMinUs uint64 `yaml:"track_min_us"`
	// TopN caps the number of offenders in each report.
	TopN int `yaml:"top_n"`
	// StaleSeconds: ignore processes not seen within this window.
	StaleSeconds int `yaml:"stale_seconds"`
}

// OffCPUConfig controls the off-CPU (blocked-time) profiler.
//
// This is the module that explains iowait.  An on-CPU profiler samples only
// running tasks, so it can never see a task asleep in D state — which is
// exactly what iowait accounts for.  offcpu instead records the stack at the
// moment a task blocks and the time until it wakes.
type OffCPUConfig struct {
	// Enabled is the master switch for the module and its trigger rule.
	Enabled bool `yaml:"enabled"`
	// IOWaitThreshold activates the module once node iowait% exceeds this.
	IOWaitThreshold float64 `yaml:"iowait_threshold"`
	// MinBlockUs ignores blocking intervals shorter than this.  Filters out
	// the constant churn of short sleeps that carry no diagnostic signal.
	MinBlockUs uint64 `yaml:"min_block_us"`
	// MaxBlockUs is a sanity cap; intervals longer than this are discarded.
	MaxBlockUs uint64 `yaml:"max_block_us"`
	// TrackInterruptible additionally attributes ordinary S-state sleeps
	// (epoll, futex, nanosleep).  Off by default: on an idle-ish server this
	// dwarfs everything else and buries the D-state stalls you are hunting.
	TrackInterruptible bool `yaml:"track_interruptible"`
	// TopN caps processes per report.
	TopN int `yaml:"top_n"`
	// MaxStacksPerProc caps blocking sites reported per process.
	MaxStacksPerProc int `yaml:"max_stacks_per_proc"`
	// MaxMapEntries sizes the counts / stack_traces maps.
	MaxMapEntries uint32 `yaml:"max_map_entries"`
}

// IODiagConfig tunes the I/O correlation classifier that produces
// `io_diagnosis` in GET /api/diagnose.
//
// The defaults implement this rule: iowait high AND throughput low AND a task
// blocked > 1 s AND that task sitting in the writeback/storage path
// → storage LATENCY stall, not high throughput.
type IODiagConfig struct {
	// IOWaitPercent: below this there is nothing to diagnose.
	IOWaitPercent float64 `yaml:"iowait_percent"`
	// LowThroughputMBPerSec: aggregate device throughput under this counts as
	// "not actually moving data".
	LowThroughputMBPerSec float64 `yaml:"low_throughput_mb_per_sec"`
	// LowUtilPercent / HighUtilPercent bound "idle" and "saturated".
	LowUtilPercent  float64 `yaml:"low_util_percent"`
	HighUtilPercent float64 `yaml:"high_util_percent"`
	// DStateStallMs: a task blocked continuously longer than this is a stall
	// rather than ordinary I/O.
	DStateStallMs int64 `yaml:"d_state_stall_ms"`
	// SlowDeviceWaitMs: mean per-request service time above this indicates a
	// slow device even when utilisation looks low.
	SlowDeviceWaitMs float64 `yaml:"slow_device_wait_ms"`
	// DirtyRatioPercent: dirty-page share above this suggests writeback
	// throttling in balance_dirty_pages.
	DirtyRatioPercent float64 `yaml:"dirty_ratio_percent"`
	// PSIFullAvg10: io.full above this confirms genuinely lost work.
	PSIFullAvg10 float64 `yaml:"psi_full_avg10"`
}

// ProfileConfig controls on-demand per-process CPU profiling
// (GET /api/profile?pid=N).  Nothing runs in the background: sampling happens
// only while a request is in flight.
type ProfileConfig struct {
	// Enabled is the master switch for the /api/profile endpoint.
	Enabled bool `yaml:"enabled"`
	// DefaultDuration is the sampling window when ?duration= is omitted.
	DefaultDuration time.Duration `yaml:"default_duration"`
	// MaxDuration caps ?duration=; longer requests are rejected with 400.
	MaxDuration time.Duration `yaml:"max_duration"`
	// CacheTTL is how long a completed profile is reused for the same PID, so
	// repeat clicks in a UI cost nothing.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// MaxMapEntries sizes the counts / stack_traces maps for targeted
	// profiles.  Smaller than the system-wide default (10240) because a single
	// process has far fewer unique stacks.
	MaxMapEntries uint32 `yaml:"max_map_entries"`
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

// MongoConfig controls the eBPF MongoDB slow-query tracer.
// When enabled, the tracer hooks sys_enter_connect/write/read/close to detect
// MongoDB connections (by destination port) and measures per-query latency.
// Slow queries (latency > SlowQueryThresholdMs) are reported via GET /api/diagnose.
//
// Feature flag: set MONGODB_TRACING_ENABLED=true or mongo.enabled: true.
type MongoConfig struct {
	// Enabled is the master switch for the MongoDB tracer.
	// Default false – zero overhead when disabled.
	Enabled bool `yaml:"enabled"`
	// Port is the MongoDB server port to watch for connections.
	// Default 27017.
	Port uint32 `yaml:"port"`
	// SlowQueryThresholdMs: report queries that take longer than this (milliseconds).
	// Default 2000 ms = 2 s.  Set via MONGODB_SLOW_QUERY_THRESHOLD_MS.
	SlowQueryThresholdMs uint64 `yaml:"slow_query_threshold_ms"`
	// PollInterval: how often to batch-read the in-kernel LRU stats map.
	PollInterval time.Duration `yaml:"poll_interval"`
	// TopN: max number of processes to include per MongoAnalysis.
	TopN int `yaml:"top_n"`
	// StaleSeconds: ignore LRU entries not updated within this window.
	StaleSeconds int `yaml:"stale_seconds"`
	// MaxRecentQueries: max slow-query events to keep in the recent ring.
	MaxRecentQueries int `yaml:"max_recent_queries"`
}

// MySQLConfig controls the eBPF MySQL slow-query tracer.
// When enabled, uprobes are attached to dispatch_command in the mysqld binary to
// capture COM_QUERY calls and their latency directly on the server side.
// Slow queries (latency > SlowQueryThresholdMs) are reported via GET /api/diagnose.
//
// Feature flag: set MYSQL_TRACING_ENABLED=true or mysql.enabled: true.
type MySQLConfig struct {
	// Enabled is the master switch for the MySQL tracer.
	// Default false – zero overhead when disabled.
	Enabled bool `yaml:"enabled"`
	// MysqldPath is the absolute path to the mysqld binary for uprobe attachment.
	// Default "/usr/sbin/mysqld".  Set via MYSQL_MYSQLD_PATH.
	MysqldPath string `yaml:"mysqld_path"`
	// SlowQueryThresholdMs: report queries that take longer than this (milliseconds).
	// Default 100 ms.  Set via MYSQL_SLOW_QUERY_THRESHOLD_MS.
	SlowQueryThresholdMs uint64 `yaml:"slow_query_threshold_ms"`
	// PollInterval: how often to batch-read the in-kernel LRU stats map.
	PollInterval time.Duration `yaml:"poll_interval"`
	// TopN: max number of processes to include per MySQLAnalysis.
	TopN int `yaml:"top_n"`
	// StaleSeconds: ignore LRU entries not updated within this window.
	StaleSeconds int `yaml:"stale_seconds"`
	// MaxRecentQueries: max slow-query events to keep in the recent ring.
	MaxRecentQueries int `yaml:"max_recent_queries"`
}

// Defaults returns a Config with sensible production defaults.
func Defaults() *Config {
	return &Config{
		Agent: AgentConfig{
			LogLevel:    "info",
			MetricsAddr: ":9200",
		},
		Collect: CollectConfig{
			Interval:       5 * time.Second,
			DStateMaxTasks: 20,
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
		RunQueue: RunQueueConfig{
			Enabled:            true,
			NodeCPUThreshold:   85.0,
			NodeLoadThreshold:  1.5,
			ProcessThresholdUs: 10_000, // 10 ms max wait → level-2 breach
			TrackMinUs:         100,    // skip sub-100us noise in-kernel
			TopN:               20,
			StaleSeconds:       60,
		},
		OffCPU: OffCPUConfig{
			Enabled:            true,
			IOWaitThreshold:    20.0,
			MinBlockUs:         1000,       // 1 ms
			MaxBlockUs:         60_000_000, // 60 s sanity cap
			TrackInterruptible: false,      // D-state only: that is what iowait is
			TopN:               10,
			MaxStacksPerProc:   5,
			MaxMapEntries:      10240,
		},
		IODiag: IODiagConfig{
			IOWaitPercent:         50.0,
			LowThroughputMBPerSec: 10.0,
			LowUtilPercent:        20.0,
			HighUtilPercent:       70.0,
			DStateStallMs:         1000,
			SlowDeviceWaitMs:      50.0,
			DirtyRatioPercent:     15.0,
			PSIFullAvg10:          10.0,
		},
		Profile: ProfileConfig{
			Enabled:         true,
			DefaultDuration: 10 * time.Second,
			MaxDuration:     30 * time.Second,
			CacheTTL:        60 * time.Second,
			MaxMapEntries:   2048,
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
		Mongo: MongoConfig{
			Enabled:              false, // off by default; zero overhead when disabled
			Port:                 27017,
			SlowQueryThresholdMs: 2000, // 2 s
			PollInterval:         5 * time.Second,
			TopN:                 20,
			StaleSeconds:         60,
			MaxRecentQueries:     100,
		},
		MySQL: MySQLConfig{
			Enabled:              false, // off by default; zero overhead when disabled
			MysqldPath:           "/usr/sbin/mysqld",
			SlowQueryThresholdMs: 100, // 100 ms
			PollInterval:         5 * time.Second,
			TopN:                 20,
			StaleSeconds:         60,
			MaxRecentQueries:     100,
		},
	}
}

// Load reads a YAML config file and merges it over the defaults.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path == "" {
		applyMongoEnvOverrides(cfg)
		applyMySQLEnvOverrides(cfg)
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	applyMongoEnvOverrides(cfg)
	applyMySQLEnvOverrides(cfg)
	applyRunQueueEnvOverrides(cfg)
	applyOffCPUEnvOverrides(cfg)
	applyProfileEnvOverrides(cfg)
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// applyMongoEnvOverrides applies environment variable overrides for the MongoDB
// tracer.  This allows enabling/configuring MongoDB tracing at runtime without
// modifying the config file (useful in containerised environments).
//
//	MONGODB_TRACING_ENABLED=true|1|yes   – enable the tracer
//	MONGODB_SLOW_QUERY_THRESHOLD_MS=N    – slow threshold in milliseconds
//	MONGODB_PORT=N                       – MongoDB port to watch (default 27017)
func applyMongoEnvOverrides(cfg *Config) {
	if v := os.Getenv("MONGODB_TRACING_ENABLED"); v != "" {
		cfg.Mongo.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("MONGODB_SLOW_QUERY_THRESHOLD_MS"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.Mongo.SlowQueryThresholdMs = n
		}
	}
	if v := os.Getenv("MONGODB_PORT"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil && n > 0 {
			cfg.Mongo.Port = uint32(n)
		}
	}
}

// applyMySQLEnvOverrides applies environment variable overrides for the MySQL
// tracer.  This allows enabling/configuring MySQL tracing at runtime without
// modifying the config file.
//
//	MYSQL_TRACING_ENABLED=true|1|yes        – enable the tracer
//	MYSQL_SLOW_QUERY_THRESHOLD_MS=N         – slow threshold in milliseconds
//	MYSQL_MYSQLD_PATH=/path/to/mysqld       – path to mysqld binary
func applyMySQLEnvOverrides(cfg *Config) {
	if v := os.Getenv("MYSQL_TRACING_ENABLED"); v != "" {
		cfg.MySQL.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("MYSQL_SLOW_QUERY_THRESHOLD_MS"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.MySQL.SlowQueryThresholdMs = n
		}
	}
	if v := os.Getenv("MYSQL_MYSQLD_PATH"); v != "" {
		cfg.MySQL.MysqldPath = v
	}
}

func applyRunQueueEnvOverrides(cfg *Config) {
	if v := os.Getenv("RUNQ_ENABLED"); v != "" {
		cfg.RunQueue.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("RUNQ_NODE_CPU_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.RunQueue.NodeCPUThreshold = f
		}
	}
	if v := os.Getenv("RUNQ_NODE_LOAD_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.RunQueue.NodeLoadThreshold = f
		}
	}
	if v := os.Getenv("RUNQ_PROCESS_THRESHOLD_US"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.RunQueue.ProcessThresholdUs = n
		}
	}
}

func applyOffCPUEnvOverrides(cfg *Config) {
	if v := os.Getenv("OFFCPU_ENABLED"); v != "" {
		cfg.OffCPU.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("OFFCPU_IOWAIT_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.OffCPU.IOWaitThreshold = f
		}
	}
	if v := os.Getenv("OFFCPU_MIN_BLOCK_US"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.OffCPU.MinBlockUs = n
		}
	}
	if v := os.Getenv("OFFCPU_TRACK_INTERRUPTIBLE"); v != "" {
		cfg.OffCPU.TrackInterruptible = v == "true" || v == "1" || v == "yes"
	}
}

func applyProfileEnvOverrides(cfg *Config) {
	if v := os.Getenv("PROFILE_ENABLED"); v != "" {
		cfg.Profile.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("PROFILE_MAX_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Profile.MaxDuration = d
			if cfg.Profile.DefaultDuration > d {
				cfg.Profile.DefaultDuration = d
			}
		}
	}
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
	if c.RunQueue.Enabled && c.RunQueue.TopN <= 0 {
		return fmt.Errorf("runq.top_n must be > 0")
	}
	if c.OffCPU.Enabled {
		if c.OffCPU.TopN <= 0 {
			return fmt.Errorf("offcpu.top_n must be > 0")
		}
		if c.OffCPU.MaxBlockUs > 0 && c.OffCPU.MinBlockUs >= c.OffCPU.MaxBlockUs {
			return fmt.Errorf("offcpu.min_block_us must be < offcpu.max_block_us")
		}
	}
	if c.Profile.Enabled {
		if c.Profile.MaxDuration <= 0 || c.Profile.MaxDuration > 5*time.Minute {
			return fmt.Errorf("profile.max_duration must be in (0, 5m]")
		}
		if c.Profile.DefaultDuration <= 0 || c.Profile.DefaultDuration > c.Profile.MaxDuration {
			return fmt.Errorf("profile.default_duration must be in (0, profile.max_duration]")
		}
	}
	return nil
}
