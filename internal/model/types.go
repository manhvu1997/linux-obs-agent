package model

import "time"

// ─── Baseline Metrics ────────────────────────────────────────────────────────

// NodeMetrics holds all /proc-based baseline metrics for one collection cycle.
type NodeMetrics struct {
	Timestamp time.Time     `json:"timestamp"`
	Hostname  string        `json:"hostname"`
	CPU       CPUMetrics    `json:"cpu"`
	Memory    MemMetrics    `json:"memory"`
	LoadAvg   LoadMetrics   `json:"load_avg"`
	Disk      []DiskMetrics `json:"disk"`
	Network   []NetMetrics  `json:"network"`

	// The following are sampled in the SAME cycle as everything above, so they
	// are time-aligned and can be correlated without interpolation.

	// Pressure is /proc/pressure/* — the signal that separates a genuine stall
	// from idle time that merely looks like one.
	Pressure PressureMetrics `json:"pressure"`
	// VMStat is the writeback-relevant subset of /proc/vmstat.
	VMStat VMStatMetrics `json:"vmstat"`
	// DState enumerates tasks currently in uninterruptible sleep — the tasks
	// that actually produce iowait.
	DState DStateCensus `json:"d_state"`
}

type CPUMetrics struct {
	// Aggregated (all CPUs)
	UsagePercent  float64 `json:"usage_percent"`
	UserPercent   float64 `json:"user_percent"`
	SysPercent    float64 `json:"sys_percent"`
	IOWaitPercent float64 `json:"iowait_percent"`
	IdlePercent   float64 `json:"idle_percent"`
	StealPercent  float64 `json:"steal_percent"`

	// From /proc/stat
	CtxSwitches  uint64 `json:"ctx_switches_total"`
	Interrupts   uint64 `json:"interrupts_total"`
	Forks        uint64 `json:"forks_total"`
	RunningProcs uint32 `json:"running_procs"`
	BlockedProcs uint32 `json:"blocked_procs"`

	// Per-CPU (for NUMA / imbalance detection)
	PerCPU []PerCPUMetrics `json:"per_cpu,omitempty"`
}

type PerCPUMetrics struct {
	ID           int     `json:"id"`
	UsagePercent float64 `json:"usage_percent"`
	IOWait       float64 `json:"iowait_percent"`
}

type MemMetrics struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	BuffersBytes   uint64  `json:"buffers_bytes"`
	CachedBytes    uint64  `json:"cached_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`

	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	SwapPercent    float64 `json:"swap_percent"`

	SlabBytes        uint64 `json:"slab_bytes"`
	PageFaultsTotal  uint64 `json:"page_faults_total"`
	MajorFaultsTotal uint64 `json:"major_faults_total"`
}

type LoadMetrics struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
	// NumCPU is used to compute the normalised load (load / numcpu).
	NumCPU int `json:"num_cpu"`
}

type DiskMetrics struct {
	Device     string `json:"device"`
	ReadBytes  uint64 `json:"read_bytes_total"`
	WriteBytes uint64 `json:"write_bytes_total"`
	ReadOps    uint64 `json:"read_ops_total"`
	WriteOps   uint64 `json:"write_ops_total"`
	// Rate fields (delta / interval), computed by the collector
	ReadBytesPerSec  float64 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64 `json:"write_bytes_per_sec"`
	ReadOpsPerSec    float64 `json:"read_ops_per_sec"`
	WriteOpsPerSec   float64 `json:"write_ops_per_sec"`
	IOUtilPercent    float64 `json:"io_util_percent"`
	AvgWaitMs        float64 `json:"avg_wait_ms"`

	// InFlight is /proc/diskstats field 12: requests issued to the driver but
	// not yet completed, sampled instantaneously.  High InFlight with low
	// throughput is the signature of a slow device rather than a busy one.
	InFlight uint64 `json:"in_flight"`
	// AvgQueueDepth is derived from the time_in_queue delta (field 14):
	// the mean number of requests outstanding over the interval.  Unlike
	// InFlight this is an average, so it is not distorted by sample timing.
	AvgQueueDepth float64 `json:"avg_queue_depth"`
	// ReadAvgWaitMs / WriteAvgWaitMs split AvgWaitMs by direction — reads
	// stalling while writes are fine (or vice versa) narrows the cause.
	ReadAvgWaitMs  float64 `json:"read_avg_wait_ms"`
	WriteAvgWaitMs float64 `json:"write_avg_wait_ms"`
}

// ─── Pressure Stall Information (/proc/pressure/*) ───────────────────────────

// PSIMetrics holds Linux Pressure Stall Information for one resource.
//
// PSI is the single best signal for separating a genuine resource stall from
// idle time that merely looks like one.  Unlike iowait — which is charged to a
// CPU that went idle while any task sat in D state — PSI measures actual lost
// work:
//
//	Some – at least one runnable task was stalled on this resource.
//	Full – ALL non-idle tasks were stalled; nothing could make progress.
//
// A machine with 80% iowait and PSI io.full ≈ 0 is not I/O bound; it is idle
// with something parked in D state.
type PSIMetrics struct {
	Some PSILine `json:"some"`
	Full PSILine `json:"full"`
	// Available is false when the kernel lacks CONFIG_PSI or the file is
	// unreadable, so consumers can distinguish "no pressure" from "no data".
	Available bool `json:"available"`
}

// PSILine is one `some`/`full` row: percent of time stalled over each window.
type PSILine struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
	// TotalUs is the cumulative stall time in microseconds.
	TotalUs uint64 `json:"total_us"`
	// TotalUsPerSec is the delta of TotalUs over the sampling interval — the
	// most responsive form of the signal. 1e6 means one full core-second of
	// stall per second.
	TotalUsPerSec float64 `json:"total_us_per_sec"`
}

// PressureMetrics groups PSI for every resource, sampled in one pass.
type PressureMetrics struct {
	IO     PSIMetrics `json:"io"`
	CPU    PSIMetrics `json:"cpu"`
	Memory PSIMetrics `json:"memory"`
}

// ─── /proc/vmstat (page cache and writeback state) ───────────────────────────

// VMStatMetrics carries the writeback-relevant subset of /proc/vmstat.
//
// Gauge fields describe the current state of the page cache; PerSec fields are
// deltas over the sampling interval.  Together they answer whether a stall is
// caused by dirty-page writeback congestion rather than by device latency.
type VMStatMetrics struct {
	// Gauges: pages currently in each state.
	DirtyBytes     uint64 `json:"dirty_bytes"`
	WritebackBytes uint64 `json:"writeback_bytes"`

	// Counters, expressed as rates over the interval.
	DirtiedPagesPerSec float64 `json:"dirtied_pages_per_sec"`
	WrittenPagesPerSec float64 `json:"written_pages_per_sec"`
	PgPgInPerSec       float64 `json:"pgpgin_per_sec"`  // KB/s read from block devices
	PgPgOutPerSec      float64 `json:"pgpgout_per_sec"` // KB/s written to block devices
	PSwpInPerSec       float64 `json:"pswpin_per_sec"`
	PSwpOutPerSec      float64 `json:"pswpout_per_sec"`

	// DirtyRatioPercent is DirtyBytes as a share of total memory. Approaching
	// the kernel's dirty_ratio means writers get throttled in
	// balance_dirty_pages — a stall that is not the device's fault.
	DirtyRatioPercent float64 `json:"dirty_ratio_percent"`

	Available bool `json:"available"`
}

// ─── D-state task census ─────────────────────────────────────────────────────

// DStateTask is one task observed in TASK_UNINTERRUPTIBLE (D) state.
//
// These are the tasks that produce iowait. Enumerating them — with the kernel
// function each is sleeping in — is the link between "the node has iowait" and
// "this specific worker is stuck here".
type DStateTask struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	// Wchan is the kernel symbol the task is sleeping in, from
	// /proc/<pid>/wchan (e.g. "folio_wait_bit", "io_schedule",
	// "balance_dirty_pages"). Empty when unreadable.
	Wchan string `json:"wchan,omitempty"`
	// InDStateMs is how long this task has been *continuously* observed in D
	// across consecutive scans. It is a lower bound quantised to the scan
	// interval, not an exact blocked time — use the offcpu report for that.
	InDStateMs int64 `json:"in_d_state_ms"`
	// KernelThread is true for kthreads (no mm), e.g. kworker/flush workers.
	KernelThread bool   `json:"kernel_thread"`
	CgroupPath   string `json:"cgroup_path,omitempty"`
}

// DStateCensus is the result of one D-state scan.
type DStateCensus struct {
	Count int `json:"count"`
	// LongestMs is the longest continuously-observed D-state duration.
	LongestMs int64        `json:"longest_ms"`
	Tasks     []DStateTask `json:"tasks,omitempty"`
	Available bool         `json:"available"`
}

type NetMetrics struct {
	Interface string `json:"interface"`
	// Counters (ever-increasing)
	RxBytes   uint64 `json:"rx_bytes_total"`
	TxBytes   uint64 `json:"tx_bytes_total"`
	RxPackets uint64 `json:"rx_packets_total"`
	TxPackets uint64 `json:"tx_packets_total"`
	RxErrors  uint64 `json:"rx_errors_total"`
	TxErrors  uint64 `json:"tx_errors_total"`
	RxDropped uint64 `json:"rx_dropped_total"`
	TxDropped uint64 `json:"tx_dropped_total"`
	// Rates (bytes/s)
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
}

// ─── Process Snapshot ────────────────────────────────────────────────────────

// ProcessStats is one /proc/[pid] inspection result.
type ProcessStats struct {
	PID     uint32 `json:"pid"`
	PPID    uint32 `json:"ppid"`
	Comm    string `json:"comm"`    // short name (15 chars)
	Cmdline string `json:"cmdline"` // full command line

	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	MemRSSBytes uint64  `json:"mem_rss_bytes"`
	MemVMSBytes uint64  `json:"mem_vms_bytes"`

	// IO (from /proc/[pid]/io, requires read permission)
	ReadBytesTotal   uint64  `json:"read_bytes_total"`
	WriteBytesTotal  uint64  `json:"write_bytes_total"`
	ReadBytesPerSec  float64 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64 `json:"write_bytes_per_sec"`

	Threads   uint32 `json:"threads"`
	State     string `json:"state"` // R/S/D/Z/T
	OpenFiles int    `json:"open_files"`

	// Container / cgroup context (best-effort)
	CgroupPath   string `json:"cgroup_path,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	K8sPodName   string `json:"k8s_pod_name,omitempty"`
	K8sNamespace string `json:"k8s_namespace,omitempty"`
}

// ─── eBPF Events ─────────────────────────────────────────────────────────────

// EBPFEventType identifies which eBPF probe emitted an event.
type EBPFEventType string

const (
	EventCPUProfile    EBPFEventType = "cpu_profile"
	EventIOLatency     EBPFEventType = "io_latency"
	EventRunQLat       EBPFEventType = "runq_latency"
	EventTCPRetransmit EBPFEventType = "tcp_retransmit"
	EventTCPDrop       EBPFEventType = "tcp_drop"
	EventDiskWrite     EBPFEventType = "disk_write"
	EventWriteback     EBPFEventType = "writeback"
)

// EBPFEvent wraps kernel-side events with host metadata.
type EBPFEvent struct {
	Type      EBPFEventType `json:"type"`
	Timestamp time.Time     `json:"timestamp"`
	PID       uint32        `json:"pid"`
	Comm      string        `json:"comm"`
	Data      interface{}   `json:"data"`
}

// CPUProfileEvent carries a single perf-event stack sample.
type CPUProfileEvent struct {
	PID         uint32   `json:"pid"`
	Comm        string   `json:"comm"`
	KernStackID int32    `json:"kern_stack_id"`
	UserStackID int32    `json:"user_stack_id"`
	SampleCount uint64   `json:"sample_count"`
	Ustack      []uint64 `json:"user_stack,omitempty"`
	Kstack      []uint64 `json:"kern_stack,omitempty"`
}

// IOLatencyEvent is emitted when a block IO request exceeds the slow threshold.
type IOLatencyEvent struct {
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	LatencyUs uint64 `json:"latency_us"`
	Bytes     uint32 `json:"bytes"`
	Op        string `json:"op"` // "R" or "W"
	Dev       uint32 `json:"dev"`
}

// RunQLatEvent is emitted when a task waits on the run-queue longer than threshold.
type RunQLatEvent struct {
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	LatencyUs uint64 `json:"latency_us"`
}

// TCPRetransmitEvent is emitted for every TCP retransmit.
// Enriched with RTT, congestion window, byte counters, queue depths,
// cumulative per-flow retransmit count, and flow duration.
type TCPRetransmitEvent struct {
	// Connection identity
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	AF       uint16 `json:"af"`        // 2=IPv4, 10=IPv6
	TCPState string `json:"tcp_state"` // e.g. "ESTABLISHED", "CLOSE_WAIT"

	// Human-readable summary
	Flow string `json:"flow"` // "src:sport → dst:dport"

	// RTT & congestion
	RTTUS       uint32 `json:"rtt_us"`       // smoothed RTT in µs
	RTTVarUS    uint32 `json:"rtt_var_us"`   // RTT variance in µs
	SndCwnd     uint32 `json:"snd_cwnd"`     // congestion window (segments)
	SndSsthresh uint32 `json:"snd_ssthresh"` // slow-start threshold

	// Byte counters (cumulative on this socket)
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`

	// Socket queue depths
	SendQueueBytes uint32 `json:"send_queue_bytes"` // sk_wmem_queued
	RecvQueueBytes uint32 `json:"recv_queue_bytes"` // sk_backlog.rmem_alloc (kernel 6.x)
	Backlog        uint32 `json:"backlog"`          // sk_backlog.len

	// Per-flow context
	RetransmitCount uint32  `json:"retransmit_count"` // cumulative for this flow
	DurationMs      uint64  `json:"duration_ms"`      // ms since ESTABLISHED (0=unknown)
	LossRate        float64 `json:"loss_rate_pct"`    // retransmit_count/bytes_sent*100 (approx)
}

// TCPDropEvent is emitted by the kfree_skb tracepoint for dropped IP packets.
// drop_reason is 0 (unknown) on kernels < 5.17.
// location is the raw kernel symbol address of the drop site.
type TCPDropEvent struct {
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	AF          uint16 `json:"af"`
	DropReason  uint32 `json:"drop_reason"`      // raw enum skb_drop_reason value
	DropName    string `json:"drop_reason_name"` // human-readable name (best-effort)
	Location    uint64 `json:"location"`         // kernel address of drop site (raw)
	LocationHex string `json:"location_hex"`     // e.g. "0xffffffff81234567" – grep in /proc/kallsyms
	Flow        string `json:"flow"`
}

// ─── Wire Payload ─────────────────────────────────────────────────────────────

// Snapshot is the full batch payload sent to the central collector server.
type Snapshot struct {
	AgentVersion string         `json:"agent_version"`
	Timestamp    time.Time      `json:"timestamp"`
	Hostname     string         `json:"hostname"`
	Metrics      NodeMetrics    `json:"metrics"`
	TopProcesses []ProcessStats `json:"top_processes"`
	EBPFEvents   []EBPFEvent    `json:"ebpf_events,omitempty"`
}

// ─── Diagnostic Report ────────────────────────────────────────────────────────

// DiagnoseReport is returned by GET /api/diagnose.
// It is designed to be consumed by an MCP server or alerting pipeline to
// determine exactly which process / PID / connection caused the overload.
type DiagnoseReport struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`

	// ActiveModules lists the eBPF modules currently loaded in the kernel.
	ActiveModules []string `json:"active_modules"`

	// Metrics is the latest /proc snapshot at the time of the call.
	Metrics NodeMetrics `json:"metrics"`

	// TopProcesses are the top-N processes by CPU usage from /proc.
	// Each entry includes PID, Comm, Cmdline, CPUPercent, MemPercent, State,
	// and container/K8s metadata when available.
	TopProcesses []ProcessStats `json:"top_processes"`

	// CPUHotspots are the hottest PIDs sampled by the cpu_profile eBPF module
	// (only populated when cpu_profile is active).  Sorted by SampleCount desc.
	CPUHotspots []CPUProfileEvent `json:"cpu_hotspots,omitempty"`

	// CPUProfileReport is the fully-aggregated, symbolized CPU profile.
	// Populated only when cpu_profile is active.  Designed for LLM analysis:
	// top stacks per process with resolved symbol names, relative weights,
	// and a system-wide kernel function aggregate.
	CPUProfileReport *CPUProfileReport `json:"cpu_profile_report,omitempty"`

	// IODiagnosis is the correlated answer to "why is iowait high?" — it walks
	// node → device → blocked tasks → process → stack and emits a verdict with
	// the evidence behind it.  Always present; see .verdict for the outcome.
	IODiagnosis *IODiagnosis `json:"io_diagnosis,omitempty"`

	// IOLatencyHistogram is the in-kernel block-IO latency distribution
	// (biolatency), keyed by log2(microseconds).  Populated only while the
	// io_latency module is active.
	IOLatencyHistogram []IOLatencyBucket `json:"io_latency_histogram,omitempty"`

	// OffCPUReport attributes blocked (off-CPU) time to processes and stacks.
	// Populated only when the offcpu module is active — it is triggered by
	// sustained iowait.  This is the field that explains iowait; CPUHotspots
	// and CPUProfileReport cannot, since they only sample running tasks.
	OffCPUReport *OffCPUReport `json:"offcpu_report,omitempty"`

	// RunQueueReport lists the processes whose run-queue wait breached the
	// level-2 threshold, plus the global latency distribution.  Populated only
	// when the runqlat module is active — i.e. when the node itself breached
	// the level-1 threshold (CPU% or normalized load).  Each offender carries
	// a ProfileURL for on-demand per-process CPU profiling.
	RunQueueReport *RunQueueAnalysis `json:"runqueue_report,omitempty"`

	// RecentEvents contains the last N eBPF events across all active modules.
	// Each event carries PID, Comm, and module-specific fields:
	//   cpu_profile   – stack IDs, sample count
	//   runq_latency  – latency_us (scheduler wait time)
	//   io_latency    – latency_us, bytes, op (R/W), device
	//   tcp_retransmit – src_ip:port, dst_ip:port, address family
	RecentEvents []EBPFEvent `json:"recent_events,omitempty"`

	// DiskReport contains directory-growth data and top disk writers.
	// Populated when the disk scanner is enabled.
	DiskReport *DiskDiagnoseReport `json:"disk_report,omitempty"`

	// FsyncReport is the latest fsync analysis snapshot.
	// Only populated when the system was under pressure (CPU > threshold OR
	// Memory > threshold) at the time of the last poll cycle.
	// Top offenders are sorted by total fsync call count (descending) and
	// enriched with cmdline, cgroup, and application-type classification.
	FsyncReport *FsyncAnalysis `json:"fsync_report,omitempty"`

	// WritebackReport is the latest memory writeback / direct-reclaim analysis.
	// Only populated when memory usage exceeds MemThreshold OR any process has
	// experienced a direct-reclaim stall longer than ReclaimSpikeNs.
	// Top offenders are sorted by dirty pages generated (descending) and
	// enriched with cmdline, cgroup, and application-type classification.
	WritebackReport *WritebackAnalysis `json:"writeback_report,omitempty"`

	// MongoReport contains MongoDB slow query analysis.
	// Only populated when MongoDB tracing is enabled
	// (MONGODB_TRACING_ENABLED=true or mongo.enabled: true in config).
	MongoReport *MongoAnalysis `json:"mongo_report,omitempty"`

	// MySQLReport contains MySQL slow query analysis from server-side uprobe tracing.
	// Only populated when MySQL tracing is enabled (mysql.enabled: true in config
	// or MYSQL_TRACING_ENABLED=true).
	MySQLReport *MySQLAnalysis `json:"mysql_report,omitempty"`
}

// ─── Fsync Tracer ─────────────────────────────────────────────────────────────

// EventFsync is the EBPFEventType for fsync slow-event outliers.
const EventFsync EBPFEventType = "fsync"

// FsyncSlowEvent is emitted when a single fsync/fdatasync/sync_file_range call
// exceeds the configured slow threshold.  This is the ringbuf path (outliers
// only).  Bulk statistics come from FsyncAnalysis via map polling.
type FsyncSlowEvent struct {
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	Comm        string `json:"comm"`
	LatencyUs   uint64 `json:"latency_us"`
	SyscallName string `json:"syscall"` // "fsync" | "fdatasync" | "sync_file_range"
}

// FsyncOffender is one PID's aggregated fsync statistics, enriched with
// /proc metadata by the userspace analyzer.
type FsyncOffender struct {
	PID          uint32  `json:"pid"`
	Comm         string  `json:"comm"`
	Cmdline      string  `json:"cmdline,omitempty"`
	CgroupPath   string  `json:"cgroup_path,omitempty"`
	FsyncCalls   uint64  `json:"fsync_calls"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	MaxLatencyMs float64 `json:"max_latency_ms"`
	// AppType is set when the process matches a known high-fsync workload.
	// Possible values: "database", "log_agent", "antivirus", ""
	AppType string `json:"app_type,omitempty"`
}

// FsyncSystemInfo holds the system pressure snapshot at analysis time.
type FsyncSystemInfo struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
}

// FsyncAnalysis is the full fsync diagnostic report POSTed to /api/diagnose
// when CPU > 85% OR Memory > 85%.
type FsyncAnalysis struct {
	Type         string          `json:"type"` // always "fsync_analysis"
	Timestamp    time.Time       `json:"timestamp"`
	System       FsyncSystemInfo `json:"system"`
	TopOffenders []FsyncOffender `json:"top_offenders"`
}

// ─── Off-CPU (blocked time) profile ──────────────────────────────────────────

// OffCPUReport attributes blocked (off-CPU) time to processes and to the exact
// stacks where they blocked.  Returned by GET /api/diagnose as `offcpu_report`
// and by GET /api/profile?mode=offcpu.
//
// This is the report that explains iowait.  An on-CPU profile structurally
// cannot: perf_event only fires on a CPU that is running a task, so a task
// sleeping in D state — the state that produces iowait — is never sampled.
//
// Caveat when reading the numbers: BlockedMs is wall-clock time summed across
// threads, so a process with 8 threads each blocked 1 s over a 1 s window
// reports 8000 ms.  Compare stacks against each other, not against the window.
type OffCPUReport struct {
	Type      string           `json:"type"` // always "offcpu_profile"
	Timestamp time.Time        `json:"timestamp"`
	Window    OffCPUWindow     `json:"window"`
	System    OffCPUSystemInfo `json:"system"`
	Processes []OffCPUProcess  `json:"processes"`
}

// OffCPUWindow echoes the filters in force so the report is self-describing.
type OffCPUWindow struct {
	// MinBlockUs: blocking intervals shorter than this were not recorded.
	MinBlockUs uint64 `json:"min_block_us"`
	// TrackedStates: which sleep states were attributed, e.g.
	// "uninterruptible" (the iowait-producing state) or
	// "uninterruptible,interruptible".
	TrackedStates string `json:"tracked_states"`
}

// OffCPUSystemInfo holds totals across every observed process.
type OffCPUSystemInfo struct {
	TotalBlockedMs float64 `json:"total_blocked_ms"`
	TotalEvents    uint64  `json:"total_events"`
	Processes      int     `json:"processes"`
}

// OffCPUProcess is one process's blocked-time breakdown.
type OffCPUProcess struct {
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Cmdline    string `json:"cmdline,omitempty"`
	CgroupPath string `json:"cgroup_path,omitempty"`

	BlockedMs    float64 `json:"blocked_ms"`
	MaxBlockedMs float64 `json:"max_blocked_ms"`
	Events       uint64  `json:"events"`
	// ThreadsSampled counts threads that blocked at least once — not the
	// process's total thread count.
	ThreadsSampled int `json:"threads_sampled,omitempty"`
	// PercentOfTotal is this process's share of all blocked time observed.
	PercentOfTotal float64 `json:"percent_of_total"`

	// TopStacks are the blocking sites, heaviest first.
	TopStacks []OffCPUStack `json:"top_stacks,omitempty"`
}

// OffCPUStack is one blocking site: where the process went to sleep.
type OffCPUStack struct {
	// SymbolStack runs outermost → innermost: user frames first, then the
	// kernel frames that actually blocked, each suffixed "_[k]".
	SymbolStack  []string `json:"symbol_stack"`
	BlockedMs    float64  `json:"blocked_ms"`
	MaxBlockedMs float64  `json:"max_blocked_ms"`
	Events       uint64   `json:"events"`
	// Percent is this site's share of the process's blocked time, 2 dp.
	Percent float64 `json:"percent"`
}

// ─── Run-queue analysis (two-level threshold) ────────────────────────────────

// RunQueueAnalysis is the run-queue diagnostic returned by GET /api/diagnose
// as `runqueue_report`.
//
// It is produced by a two-level threshold scheme:
//
//	Level 1 (node)    – the runqlat eBPF module is only loaded once the node
//	                    itself is stressed (CPU% or normalized load).  When the
//	                    node is healthy this report is absent entirely.
//	Level 2 (process) – a process is listed only when its MAX run-queue wait
//	                    reached Thresholds.ProcessUs.
type RunQueueAnalysis struct {
	Type       string         `json:"type"` // always "runqueue_analysis"
	Timestamp  time.Time      `json:"timestamp"`
	System     RunQSystemInfo `json:"system"`
	Thresholds RunQThresholds `json:"thresholds"`
	// Histogram is the global run-queue latency distribution over every
	// context switch.  Only non-empty buckets are included.
	Histogram []RunQLatBucket `json:"histogram,omitempty"`
	// TopOffenders are the level-2 breaches, sorted by max latency descending.
	TopOffenders []RunQOffender `json:"top_offenders"`
}

// RunQSystemInfo is the node state that satisfied the level-1 threshold.
type RunQSystemInfo struct {
	CPUPercent     float64 `json:"cpu_percent"`
	LoadNormalised float64 `json:"load_normalised"` // load1 / NumCPU
	NumCPU         int     `json:"num_cpu"`
}

// RunQThresholds echoes the thresholds in force, so a consumer can interpret
// the report without reading the agent's config.
type RunQThresholds struct {
	NodeCPUPercent float64 `json:"node_cpu_percent"`
	NodeLoad       float64 `json:"node_load"`
	ProcessUs      uint64  `json:"process_us"`
	TrackMinUs     uint64  `json:"track_min_us"`
}

// RunQLatBucket is one log2 bucket of the global run-queue latency histogram.
type RunQLatBucket struct {
	Range  string `json:"range"` // human-readable, e.g. "4ms-8ms"
	LowUs  uint64 `json:"low_us"`
	HighUs uint64 `json:"high_us"`
	Count  uint64 `json:"count"`
}

// RunQOffender is one process that breached the level-2 run-queue threshold.
type RunQOffender struct {
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Cmdline    string `json:"cmdline,omitempty"`
	CgroupPath string `json:"cgroup_path,omitempty"`

	// TrackedSwitches counts only waits at or above Thresholds.TrackMinUs —
	// sub-threshold switches are deliberately not aggregated in-kernel.
	TrackedSwitches uint64 `json:"tracked_switches"`
	// SlowEvents counts waits at or above Thresholds.ProcessUs.
	SlowEvents uint64 `json:"slow_events"`
	// AvgLatencyMs is the mean over TRACKED waits, not over all switches.
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	MaxLatencyMs float64 `json:"max_latency_ms"`

	// ProfileURL is the on-demand CPU profile endpoint for this process.
	// Following it samples the process for a few seconds and returns a
	// symbolized, flamegraph-ready profile.
	ProfileURL string `json:"profile_url"`
}

// ProfileResponse is the body of GET /api/profile?pid=N.
type ProfileResponse struct {
	Type      string    `json:"type"` // always "pid_cpu_profile"
	Timestamp time.Time `json:"timestamp"`
	// Mode is "oncpu" (what the process is running) or "offcpu" (what it is
	// blocked on). Exactly one of Report / OffCPUReport is populated.
	//
	// Use offcpu when the symptom is iowait, D-state or latency that does not
	// appear as CPU usage — an on-CPU profile cannot see a sleeping task.
	Mode string `json:"mode"`
	PID  uint32 `json:"pid"`
	Comm string `json:"comm,omitempty"`
	// DurationMs is the actual sampling window. Zero when Cached or Reused,
	// since no new sampling was performed.
	DurationMs int64 `json:"duration_ms"`
	// SampleHz applies to mode=oncpu only; off-CPU profiling is event-driven,
	// not sampled.
	SampleHz uint64 `json:"sample_hz,omitempty"`
	// Cached is true when this profile was served from the result cache.
	Cached bool `json:"cached"`
	// Reused is true when the profile was extracted from the already-running
	// system-wide profiler instead of starting a new sampling window.
	Reused bool `json:"reused"`
	// Report holds a single process (the target) for mode=oncpu.
	Report *CPUProfileReport `json:"report,omitempty"`
	// OffCPUReport holds the blocked-time breakdown for mode=offcpu.
	OffCPUReport *OffCPUReport `json:"offcpu_report,omitempty"`
}

// ─── CPU Profile V2 (aggregated, symbolized) ─────────────────────────────────

// CPUProfileReport is the aggregated, symbolized CPU profiling report.
// Returned by GET /api/diagnose when the cpu_profile eBPF module is active.
// Designed for downstream LLM analysis: compact, weighted, no raw addresses.
type CPUProfileReport struct {
	Type      string               `json:"type"` // always "cpu_profile_v2"
	Timestamp time.Time            `json:"timestamp"`
	System    CPUProfileSystemInfo `json:"system"`
	// Processes sorted by total sample count descending; entries < 1% omitted.
	Processes []CPUProfileProcess `json:"processes"`
	// KernelAggregate: top-10 kernel functions across all processes.
	KernelAggregate []KernelAggEntry `json:"kernel_aggregate,omitempty"`
}

// CPUProfileSystemInfo holds system-wide sampling totals.
type CPUProfileSystemInfo struct {
	TotalSamples  uint64 `json:"total_samples"`
	UserSamples   uint64 `json:"user_samples"`   // samples with a valid user stack
	KernelSamples uint64 `json:"kernel_samples"` // samples with a valid kernel stack
}

// CPUProfileProcess is one process's aggregated profiling data.
type CPUProfileProcess struct {
	PID           uint32     `json:"pid"`
	Comm          string     `json:"comm"`
	Samples       uint64     `json:"samples"`
	UserSamples   uint64     `json:"user_samples,omitempty"`
	KernelSamples uint64     `json:"kernel_samples,omitempty"`
	Threads       int        `json:"threads,omitempty"`
	TopUserStacks []CPUStack `json:"top_user_stacks,omitempty"`
	TopKernStacks []CPUStack `json:"top_kern_stacks,omitempty"`
}

// CPUStack is one aggregated stack trace with resolved symbol names.
// Raw addresses are never included; stacks where all symbols fail are dropped.
type CPUStack struct {
	// SymbolStack: function names from innermost (top) to outermost (bottom).
	SymbolStack []string `json:"symbol_stack"`
	Samples     uint64   `json:"samples"`
	Percent     float64  `json:"percent"` // % of this process's total, 2 dp
}

// KernelAggEntry is one kernel function's aggregate across all processes.
type KernelAggEntry struct {
	Symbol  string  `json:"symbol"`
	Samples uint64  `json:"samples"`
	Percent float64 `json:"percent"` // % of total kernel samples, 2 dp
}

// ─── Writeback Tracer ─────────────────────────────────────────────────────────

// WritebackSlowEvent is emitted when a single direct-reclaim episode exceeds
// the configured slow threshold.  This is the ringbuf path (outliers only).
// Bulk statistics come from WritebackAnalysis via map polling.
type WritebackSlowEvent struct {
	PID              uint32 `json:"pid"`
	TID              uint32 `json:"tid"`
	Comm             string `json:"comm"`
	ReclaimLatencyNs uint64 `json:"reclaim_latency_ns"`
}

// WritebackOffender is one PID's aggregated writeback / direct-reclaim
// statistics, enriched with /proc metadata by the userspace analyzer.
type WritebackOffender struct {
	PID          uint32  `json:"pid"`
	Comm         string  `json:"comm"`
	Cmdline      string  `json:"cmdline,omitempty"`
	CgroupPath   string  `json:"cgroup_path,omitempty"`
	DirtyPages   uint64  `json:"dirty_pages"`
	ReclaimCount uint64  `json:"reclaim_count"`
	AvgReclaimMs float64 `json:"avg_reclaim_ms"`
	MaxReclaimMs float64 `json:"max_reclaim_ms"`
	// AppType is set when the process matches a known high-writeback workload.
	// Possible values: "database", "log_agent", "messaging", "storage", "antivirus", ""
	AppType string `json:"app_type,omitempty"`
}

// WritebackSystemInfo holds system-level writeback pressure at analysis time.
type WritebackSystemInfo struct {
	MemPercent   float64 `json:"mem_percent"`
	MaxReclaimMs float64 `json:"max_reclaim_ms"` // worst per-PID direct-reclaim stall
	WbOperations uint64  `json:"wb_operations"`  // system-wide writeback ops since start
}

// WritebackAnalysis is the full writeback diagnostic report returned by
// GET /api/diagnose when Memory > MemThreshold OR reclaim latency spikes.
type WritebackAnalysis struct {
	Type         string              `json:"type"` // always "writeback_analysis"
	Timestamp    time.Time           `json:"timestamp"`
	System       WritebackSystemInfo `json:"system"`
	TopOffenders []WritebackOffender `json:"top_offenders"`
}

// ─── MongoDB Slow Query Tracer ────────────────────────────────────────────────

// EventMongoQuery is the EBPFEventType for MongoDB slow-query outliers.
const EventMongoQuery EBPFEventType = "mongo_query"

// MongoSlowEvent is emitted when a single MongoDB query exceeds the configured
// slow threshold.  Contains the operation type, collection, and destination so
// the on-call engineer immediately sees which query was slow.
type MongoSlowEvent struct {
	PID        uint32  `json:"pid"`
	TID        uint32  `json:"tid"`
	FD         uint32  `json:"fd"`
	RequestID  uint32  `json:"request_id"`
	LatencyMs  float64 `json:"latency_ms"`
	OpType     string  `json:"op_type"`    // "find","insert","update","delete","aggregate",""
	Collection string  `json:"collection"` // empty when traffic is TLS-encrypted
	DestAddr   string  `json:"dest_addr"`  // "ip:port" of the MongoDB server
	Comm       string  `json:"comm"`
}

// MongoProcessStats holds aggregated per-PID query statistics enriched with
// /proc metadata by the userspace analyzer.
type MongoProcessStats struct {
	PID          uint32  `json:"pid"`
	Comm         string  `json:"comm"`
	Cmdline      string  `json:"cmdline,omitempty"`
	CgroupPath   string  `json:"cgroup_path,omitempty"`
	TotalQueries uint64  `json:"total_queries"`
	SlowQueries  uint64  `json:"slow_queries"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	MaxLatencyMs float64 `json:"max_latency_ms"`
}

// MongoAnalysis is the full MongoDB diagnostic report returned by
// GET /api/diagnose when MongoDB tracing is enabled.
type MongoAnalysis struct {
	Type            string    `json:"type"` // always "mongo_analysis"
	Timestamp       time.Time `json:"timestamp"`
	SlowThresholdMs uint64    `json:"slow_threshold_ms"`
	// RecentSlowQueries: last N slow queries with full detail.
	RecentSlowQueries []MongoSlowEvent `json:"recent_slow_queries"`
	// TopProcesses: per-PID aggregated stats sorted by slow_queries desc.
	TopProcesses []MongoProcessStats `json:"top_processes"`
}

// ─── Disk Scanner ─────────────────────────────────────────────────────────────

// DirEntry holds the aggregated size for one scanned directory.
type DirEntry struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	FileCount int64  `json:"file_count"`
}

// DirSnapshot captures the result of one full scan cycle.
type DirSnapshot struct {
	ScannedAt time.Time  `json:"scanned_at"`
	Top10     []DirEntry `json:"top10"`
}

// DiskGrowthEvent is emitted when a directory grows faster than the threshold.
type DiskGrowthEvent struct {
	Path          string    `json:"path"`
	PrevSizeBytes int64     `json:"prev_size_bytes"`
	CurrSizeBytes int64     `json:"curr_size_bytes"`
	GrowthBytes   int64     `json:"growth_bytes"`
	GrowthPercent float64   `json:"growth_percent"`
	DetectedAt    time.Time `json:"detected_at"`
}

// DiskWriteEvent is emitted by the disk_write eBPF module for each vfs_write call.
type DiskWriteEvent struct {
	PID          uint32 `json:"pid"`
	Comm         string `json:"comm"`
	BytesWritten uint64 `json:"bytes_written"`
	Filename     string `json:"filename"`
}

// DiskWriteProcess aggregates eBPF-traced bytes written per process.
type DiskWriteProcess struct {
	PID          uint32 `json:"pid"`
	Comm         string `json:"comm"`
	BytesWritten uint64 `json:"bytes_written"`
	LastFilename string `json:"last_filename,omitempty"`
}

// DiskDiagnoseReport is the disk-specific section of DiagnoseReport.
type DiskDiagnoseReport struct {
	Snapshot     *DirSnapshot       `json:"snapshot,omitempty"`
	GrowthEvents []DiskGrowthEvent  `json:"growth_events,omitempty"`
	TopWriters   []DiskWriteProcess `json:"top_writers,omitempty"`
}

// ─── MySQL Slow Query Tracer ──────────────────────────────────────────────────

// EventMySQLQuery is the EBPFEventType for MySQL slow-query outliers captured
// via server-side uprobes on dispatch_command in mysqld.
const EventMySQLQuery EBPFEventType = "mysql_query"

// MySQLSlowEvent is emitted when a single MySQL query (COM_QUERY) exceeds the
// configured slow threshold. The query text is captured directly from the mysqld
// binary at dispatch_command entry — no wire-protocol parsing required.
type MySQLSlowEvent struct {
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	LatencyMs float64   `json:"latency_ms"`
	Query     string    `json:"query"`
	Comm      string    `json:"comm"`
	Timestamp time.Time `json:"timestamp"`
}

// MySQLProcessStats holds aggregated per-PID query statistics enriched with
// /proc metadata by the userspace analyzer.
type MySQLProcessStats struct {
	PID          uint32  `json:"pid"`
	Comm         string  `json:"comm"`
	Cmdline      string  `json:"cmdline,omitempty"`
	CgroupPath   string  `json:"cgroup_path,omitempty"`
	TotalQueries uint64  `json:"total_queries"`
	SlowQueries  uint64  `json:"slow_queries"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	MaxLatencyMs float64 `json:"max_latency_ms"`
}

// MySQLAnalysis is the full MySQL diagnostic report returned by
// GET /api/diagnose when MySQL tracing is enabled.
type MySQLAnalysis struct {
	Type              string              `json:"type"` // always "mysql_analysis"
	Timestamp         time.Time           `json:"timestamp"`
	SlowThresholdMs   uint64              `json:"slow_threshold_ms"`
	MysqldPath        string              `json:"mysqld_path"`
	RecentSlowQueries []MySQLSlowEvent    `json:"recent_slow_queries"`
	TopProcesses      []MySQLProcessStats `json:"top_processes"`
}

// ─── DB Inspector (sidecar) ───────────────────────────────────────────────────

// DBInspectReport holds the diagnostic snapshot for one database type.
// The Database field identifies which backend (e.g. "mongo", "mysql").
// Only the relevant *Report field is populated; all others are omitted.
type DBInspectReport struct {
	Database    string         `json:"database"`
	MongoReport *MongoAnalysis `json:"mongo_report,omitempty"`
	// MySQLReport *MySQLAnalysis `json:"mysql_report,omitempty"` // future
}

// InspectReport is the full response body of GET /api/inspect exposed by the
// db-inspector sidecar.  Contains one entry per enabled database tracer.
type InspectReport struct {
	Timestamp time.Time         `json:"timestamp"`
	Databases []DBInspectReport `json:"databases"`
}
