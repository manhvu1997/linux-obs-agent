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
	// "query_digests", "cpu_wait" (cpu); "io_diagnosis", "family_disk_io",
	// "query_disk_reads", "disk_wait", "commit_wait" (disk). A wait is
	// missing when its mysql_report.accounting entry is not "ok".
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
	CPUCores             *float64 `json:"cpu_cores,omitempty"` // resource "cpu" only
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
// collector sample when the window value is unavailable (source "sample").
// Each assessment fills only its own resource's fields: the CPU fields (node
// CPU, load, PSI, CPU families, query CPU coverage, cpu_victims) for resource
// "cpu", the disk fields (io_verdict, node disk reads, disk families, query
// disk coverage, disk_victims, commit_victims) for resource "disk"; the other
// resource's fields are omitted, never 0. A victim count is present (0
// included) exactly when that wait is measured (mysql_report.accounting
// cpu_wait / disk_wait / commit_wait is "ok"); otherwise it is omitted and
// the wait is listed in missing.
type OverloadEvidence struct {
	NodeCPUUsedPercent      *float64 `json:"node_cpu_used_percent,omitempty"`
	NodeCPUSource           string   `json:"node_cpu_source,omitempty"`
	NodeCPUUsedCores        *float64 `json:"node_cpu_used_cores,omitempty"`
	NumCPU                  int      `json:"num_cpu,omitempty"`
	LoadNormalised          *float64 `json:"load_normalised,omitempty"`
	PSICPUSomeAvg10         *float64 `json:"psi_cpu_some_avg10,omitempty"`
	PSIAvailable            *bool    `json:"psi_available,omitempty"`
	TopFamily               string   `json:"top_family,omitempty"`
	TopFamilyCPUPercent     *float64 `json:"top_family_cpu_percent,omitempty"`
	MySQLFamily             string   `json:"mysql_family,omitempty"`
	MySQLFamilyCPUPercent   *float64 `json:"mysql_family_cpu_percent,omitempty"`
	QueryCPUCoveragePercent *float64 `json:"query_cpu_coverage_percent,omitempty"`
	CPUVictims              *int     `json:"cpu_victims,omitempty"`
	WindowSeconds           int      `json:"window_seconds"`

	IOVerdict                    string   `json:"io_verdict,omitempty"`
	NodeDiskReadMBPerSec         *float64 `json:"node_disk_read_mb_per_sec,omitempty"`
	QueryDiskReadCoveragePercent *float64 `json:"query_disk_read_coverage_percent,omitempty"`
	DiskVictims                  *int     `json:"disk_victims,omitempty"`
	CommitVictims                *int     `json:"commit_victims,omitempty"`
	TopDiskFamily                string   `json:"top_disk_family,omitempty"`
	TopDiskFamilyReadMBPerSec    *float64 `json:"top_disk_family_read_mb_per_sec,omitempty"`
	MySQLFamilyDiskReadMBPerSec  *float64 `json:"mysql_family_disk_read_mb_per_sec,omitempty"`
}

// OverloadThresholds echoes the cut-offs so a consumer can re-derive the
// verdict. Only the assessed resource's thresholds are set (all are > 0 when
// set); the other resource's are omitted.
type OverloadThresholds struct {
	NodeCPUPercent                   float64 `json:"node_cpu_percent,omitempty"`
	NodeLoad                         float64 `json:"node_load,omitempty"`
	CPUCulpritPercentOfNodeCPUUsed   float64 `json:"cpu_culprit_percent_of_node_cpu_used,omitempty"`
	CPUCulpritMinNodeCPUUsedPercent  float64 `json:"cpu_culprit_min_node_cpu_used_percent,omitempty"`
	IOCulpritPercentOfDiskRead       float64 `json:"io_culprit_percent_of_disk_read,omitempty"`
	IOCulpritMinNodeDiskReadMBPerSec float64 `json:"io_culprit_min_node_disk_read_mb_per_sec,omitempty"`
}
