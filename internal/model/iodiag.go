package model

import "time"

// ─── Correlated I/O diagnosis ────────────────────────────────────────────────

// IOVerdict is the classification produced by the correlation engine.
type IOVerdict string

const (
	// VerdictStorageLatencyStall — iowait is high, the device is NOT busy, yet
	// tasks are blocked for a long time in the storage path. The device (or the
	// layer beneath it: network storage, hypervisor, throttling) is slow, not
	// saturated. Adding IOPS capacity will not help; the per-request latency is
	// the problem.
	VerdictStorageLatencyStall IOVerdict = "storage_latency_stall"

	// VerdictHighDiskThroughput — iowait is high because the device is
	// genuinely saturated with work. This is a capacity problem.
	VerdictHighDiskThroughput IOVerdict = "high_disk_throughput"

	// VerdictWritebackCongestion — dirty pages are piling up and writers are
	// being throttled in balance_dirty_pages. The stall originates in the page
	// cache, not the device.
	VerdictWritebackCongestion IOVerdict = "writeback_congestion"

	// VerdictIOWaitAccountingArtifact — iowait is high but nothing is actually
	// stalled: no PSI pressure, an idle device, low load. The CPU was simply
	// idle while some task sat parked in D state (io_uring workers do this).
	// Not a problem; do not page anyone.
	VerdictIOWaitAccountingArtifact IOVerdict = "iowait_accounting_artifact"

	// VerdictHealthy — no I/O pressure worth reporting.
	VerdictHealthy IOVerdict = "healthy"

	// VerdictInconclusive — signals conflict or required data was unavailable.
	VerdictInconclusive IOVerdict = "inconclusive"
)

// IOConfidence expresses how much of the evidence chain was actually present.
type IOConfidence string

const (
	ConfidenceHigh   IOConfidence = "high"
	ConfidenceMedium IOConfidence = "medium"
	ConfidenceLow    IOConfidence = "low"
)

// IODiagnosis is the correlated answer to "why is iowait high?".
//
// It exists because the individual signals are each ambiguous on their own:
// iowait alone cannot distinguish a stalled machine from an idle one, disk
// throughput alone cannot tell slow from saturated, and a CPU profile cannot
// see a blocked task at all. Chain walks the layers in order so the reasoning
// is auditable rather than a bare verdict.
type IODiagnosis struct {
	Type      string    `json:"type"` // always "io_diagnosis"
	Timestamp time.Time `json:"timestamp"`

	Verdict    IOVerdict    `json:"verdict"`
	Confidence IOConfidence `json:"confidence"`
	// Summary is a one-line human-readable conclusion.
	Summary string `json:"summary"`

	// Chain is the evidence walked layer by layer:
	// node → device → blocked tasks → process → stack.
	Chain []IOChainLink `json:"chain"`

	// Evidence holds the raw numbers the verdict was derived from, so a
	// consumer can re-check the reasoning without a second API call.
	Evidence IOEvidence `json:"evidence"`

	// Missing lists signals that were unavailable and would have raised
	// confidence (e.g. "psi", "offcpu_report"). Empty when everything was present.
	Missing []string `json:"missing,omitempty"`

	// NextSteps are concrete follow-up actions for this verdict.
	NextSteps []string `json:"next_steps,omitempty"`
}

// IOChainLink is one layer of the causal chain.
type IOChainLink struct {
	// Stage: "node" | "device" | "blocked_tasks" | "process" | "stack"
	Stage  string `json:"stage"`
	Detail string `json:"detail"`
	// Confirmed is false when this layer could not be established, which is
	// what breaks the chain and lowers overall confidence.
	Confirmed bool `json:"confirmed"`
}

// IOEvidence is the numeric basis of the verdict, all from one sampling window.
type IOEvidence struct {
	IOWaitPercent   float64 `json:"iowait_percent"`
	IdlePercent     float64 `json:"idle_percent"`
	LoadNormalised  float64 `json:"load_normalised"`
	BlockedProcs    uint32  `json:"blocked_procs"`
	PSIIOSomeAvg10  float64 `json:"psi_io_some_avg10"`
	PSIIOFullAvg10  float64 `json:"psi_io_full_avg10"`
	PSIAvailable    bool    `json:"psi_available"`
	BusiestDevice   string  `json:"busiest_device,omitempty"`
	DeviceUtilPct   float64 `json:"device_util_percent"`
	DeviceMBPerSec  float64 `json:"device_mb_per_sec"`
	DeviceAvgWaitMs float64 `json:"device_avg_wait_ms"`
	DeviceInFlight  uint64  `json:"device_in_flight"`
	DirtyBytes      uint64  `json:"dirty_bytes"`
	WritebackBytes  uint64  `json:"writeback_bytes"`
	DirtyRatioPct   float64 `json:"dirty_ratio_percent"`
	DStateCount     int     `json:"d_state_count"`
	DStateLongestMs int64   `json:"d_state_longest_ms"`
	TopBlockedComm  string  `json:"top_blocked_comm,omitempty"`
	TopBlockedWchan string  `json:"top_blocked_wchan,omitempty"`
}

// IOLatencyBucket is one log2(microsecond) bucket of the block-IO latency
// histogram maintained in-kernel by the io_latency module (biolatency).
// Only non-empty buckets are emitted.
type IOLatencyBucket struct {
	Range  string `json:"range"` // human-readable, e.g. "4ms-8ms"
	LowUs  uint64 `json:"low_us"`
	HighUs uint64 `json:"high_us"`
	Count  uint64 `json:"count"`
}
