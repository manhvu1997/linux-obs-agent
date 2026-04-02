package model

import "time"

// ─── Baseline Metrics ────────────────────────────────────────────────────────

// NodeMetrics holds all /proc-based baseline metrics for one collection cycle.
type NodeMetrics struct {
	Timestamp time.Time    `json:"timestamp"`
	Hostname  string       `json:"hostname"`
	CPU       CPUMetrics   `json:"cpu"`
	Memory    MemMetrics   `json:"memory"`
	LoadAvg   LoadMetrics  `json:"load_avg"`
	Disk      []DiskMetrics `json:"disk"`
	Network   []NetMetrics  `json:"network"`
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
	CtxSwitches uint64 `json:"ctx_switches_total"`
	Interrupts  uint64 `json:"interrupts_total"`
	Forks       uint64 `json:"forks_total"`
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
	Device     string  `json:"device"`
	ReadBytes  uint64  `json:"read_bytes_total"`
	WriteBytes uint64  `json:"write_bytes_total"`
	ReadOps    uint64  `json:"read_ops_total"`
	WriteOps   uint64  `json:"write_ops_total"`
	// Rate fields (delta / interval), computed by the collector
	ReadBytesPerSec  float64 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64 `json:"write_bytes_per_sec"`
	ReadOpsPerSec    float64 `json:"read_ops_per_sec"`
	WriteOpsPerSec   float64 `json:"write_ops_per_sec"`
	IOUtilPercent    float64 `json:"io_util_percent"`
	AvgWaitMs        float64 `json:"avg_wait_ms"`
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
	ReadBytesTotal  uint64 `json:"read_bytes_total"`
	WriteBytesTotal uint64 `json:"write_bytes_total"`
	ReadBytesPerSec float64 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64 `json:"write_bytes_per_sec"`

	Threads    uint32 `json:"threads"`
	State      string `json:"state"` // R/S/D/Z/T
	OpenFiles  int    `json:"open_files"`

	// Container / cgroup context (best-effort)
	CgroupPath    string `json:"cgroup_path,omitempty"`
	ContainerID   string `json:"container_id,omitempty"`
	K8sPodName    string `json:"k8s_pod_name,omitempty"`
	K8sNamespace  string `json:"k8s_namespace,omitempty"`
}

// ─── eBPF Events ─────────────────────────────────────────────────────────────

// EBPFEventType identifies which eBPF probe emitted an event.
type EBPFEventType string

const (
	EventCPUProfile    EBPFEventType = "cpu_profile"
	EventIOLatency     EBPFEventType = "io_latency"
	EventRunQLat       EBPFEventType = "runq_latency"
	EventTCPRetransmit EBPFEventType = "tcp_retransmit"
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
type TCPRetransmitEvent struct {
	PID     uint32 `json:"pid"`
	Comm    string `json:"comm"`
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	AF      uint16 `json:"af"` // 2=IPv4, 10=IPv6
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
