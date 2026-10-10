package model

import "time"

// OverloadVerdict is the outcome of the query-overload assessment.
type OverloadVerdict string

const (
	// OverloadQueryCPU: the node is CPU-saturated over the window, mysqld is
	// its top CPU family and the top digest has cpu_role culprit.
	OverloadQueryCPU OverloadVerdict = "query_cpu_overload"
	// OverloadQueryDisk: the disk is saturated (io_diagnosis), mysqld is the
	// top disk-reading family and the top digest by disk reads has io_role
	// culprit.
	OverloadQueryDisk        OverloadVerdict = "query_disk_overload"
	OverloadNodeNotSaturated OverloadVerdict = "node_not_saturated"
	OverloadNotMySQL         OverloadVerdict = "not_mysql"
	OverloadNoDominantQuery  OverloadVerdict = "no_dominant_query"
	OverloadNoData           OverloadVerdict = "no_data"
)

// QueryOverload answers "which query is overloading this server, on which
// resource, and how sure are we". Checks run in order — node_saturated,
// mysqld_top_consumer, dominant_digest, victims — and are all reported.
type QueryOverload struct {
	Type       string          `json:"type"` // always "query_overload"
	Timestamp  time.Time       `json:"timestamp"`
	Verdict    OverloadVerdict `json:"verdict"`
	Resource   string          `json:"resource"` // "cpu" | "disk"
	Confidence IOConfidence    `json:"confidence"`
	Summary    string          `json:"summary"`
	// Digest is the top digest for the resource; set whenever digest data exists.
	Digest     *OverloadDigest    `json:"digest,omitempty"`
	Checks     []OverloadCheck    `json:"checks"`
	Evidence   OverloadEvidence   `json:"evidence"`
	Thresholds OverloadThresholds `json:"thresholds"`
	// Missing lists unavailable signals: "process_families", "node_cpu_window",
	// "query_digests" (cpu); "io_diagnosis", "family_disk_io",
	// "query_disk_reads" (disk).
	Missing []string `json:"missing,omitempty"`
	// Secondary is the other saturated resource's assessment, when both CPU
	// and disk are saturated (never itself has a Secondary).
	Secondary *QueryOverload `json:"secondary,omitempty"`
}

// OverloadDigest is the candidate digest (no raw SQL: digest text only).
type OverloadDigest struct {
	PID                  uint32   `json:"pid"`
	DigestID             string   `json:"digest_id"`
	DigestText           string   `json:"digest_text"`
	Command              string   `json:"command"`
	CPUCores             float64  `json:"cpu_cores"`
	PercentOfNodeCPUUsed *float64 `json:"percent_of_node_cpu_used,omitempty"`
	CallsPerSec          float64  `json:"calls_per_sec"`
	BytesOutPerCall      float64  `json:"bytes_out_per_call"`
	CPURole              string   `json:"cpu_role,omitempty"`
	DiskReadMBPerSec     *float64 `json:"disk_read_mb_per_sec,omitempty"`
	PercentOfDiskRead    *float64 `json:"percent_of_disk_read,omitempty"`
	DiskReadPagesPerCall *float64 `json:"disk_read_pages_per_call,omitempty"`
	IORole               string   `json:"io_role,omitempty"`
}

// OverloadCheck is one step of the assessment.
type OverloadCheck struct {
	// Name: "node_saturated" | "mysqld_top_consumer" | "dominant_digest" | "victims"
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// OverloadEvidence is the numeric basis of the verdict. Node CPU is the
// window value from mysql_report.node (source "window"), or the latest
// collector sample when the window value is unavailable (source "sample"). The disk
// fields are filled for resource "disk", the CPU fields for resource "cpu".
type OverloadEvidence struct {
	NodeCPUUsedPercent      float64  `json:"node_cpu_used_percent"`
	NodeCPUSource           string   `json:"node_cpu_source"`
	NodeCPUUsedCores        *float64 `json:"node_cpu_used_cores,omitempty"`
	NumCPU                  int      `json:"num_cpu"`
	LoadNormalised          float64  `json:"load_normalised"`
	PSICPUSomeAvg10         float64  `json:"psi_cpu_some_avg10"`
	PSIAvailable            bool     `json:"psi_available"`
	TopFamily               string   `json:"top_family,omitempty"`
	TopFamilyCPUPercent     float64  `json:"top_family_cpu_percent"`
	MySQLFamily             string   `json:"mysql_family,omitempty"`
	MySQLFamilyCPUPercent   float64  `json:"mysql_family_cpu_percent"`
	QueryCPUCoveragePercent *float64 `json:"query_cpu_coverage_percent,omitempty"`
	CPUVictims              int      `json:"cpu_victims"`
	WindowSeconds           int      `json:"window_seconds"`

	IOVerdict                    string   `json:"io_verdict,omitempty"`
	NodeDiskReadMBPerSec         *float64 `json:"node_disk_read_mb_per_sec,omitempty"`
	QueryDiskReadCoveragePercent *float64 `json:"query_disk_read_coverage_percent,omitempty"`
	DiskVictims                  int      `json:"disk_victims"`
	CommitVictims                int      `json:"commit_victims"`
	TopDiskFamily                string   `json:"top_disk_family,omitempty"`
	TopDiskFamilyReadMBPerSec    float64  `json:"top_disk_family_read_mb_per_sec"`
	MySQLFamilyDiskReadMBPerSec  float64  `json:"mysql_family_disk_read_mb_per_sec"`
}

// OverloadThresholds echoes the cut-offs so a consumer can re-derive the verdict.
type OverloadThresholds struct {
	NodeCPUPercent                   float64 `json:"node_cpu_percent"`
	NodeLoad                         float64 `json:"node_load"`
	CPUCulpritPercentOfNodeCPUUsed   float64 `json:"cpu_culprit_percent_of_node_cpu_used"`
	CPUCulpritMinNodeCPUUsedPercent  float64 `json:"cpu_culprit_min_node_cpu_used_percent"`
	IOCulpritPercentOfDiskRead       float64 `json:"io_culprit_percent_of_disk_read"`
	IOCulpritMinNodeDiskReadMBPerSec float64 `json:"io_culprit_min_node_disk_read_mb_per_sec"`
}
