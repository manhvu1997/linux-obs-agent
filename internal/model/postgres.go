package model

import "time"

// PostgresAnalysis is GET /api/diagnose postgres_report: one entry per
// traced PostgreSQL cluster plus the report-level verdict.
type PostgresAnalysis struct {
	Type            string    `json:"type"` // always "postgres_analysis"
	Timestamp       time.Time `json:"timestamp"`
	WindowSeconds   int       `json:"window_seconds"`
	SlowThresholdMs uint64    `json:"slow_threshold_ms"`
	// Accounting merges the clusters' accounting: a key is "ok" only when
	// every cluster's is; otherwise the first non-ok value. Adds "state"
	// (active | shed | unavailable: …) and "enrichment".
	Accounting    map[string]string    `json:"accounting"`
	Node          *MySQLNodeWindow     `json:"node,omitempty"`
	Thresholds    *QueryRoleThresholds `json:"thresholds,omitempty"`
	Clusters      []PostgresCluster    `json:"clusters"`
	DroppedEvents uint64               `json:"dropped_events"`
	// OverloadCause is built per GET /api/diagnose; never set on the
	// analyzer's cached snapshot.
	OverloadCause *QueryOverload `json:"overload_cause,omitempty"`
}

// PostgresCluster is one postmaster and everything it ran over the window.
type PostgresCluster struct {
	Cluster       string            `json:"cluster"`
	Version       string            `json:"version"`
	PostmasterPID uint32            `json:"postmaster_pid"`
	Port          int               `json:"port,omitempty"`
	DataDir       string            `json:"data_dir,omitempty"`
	IOMethod      string            `json:"io_method,omitempty"`
	Accounting    map[string]string `json:"accounting"`
	// QueryCPUCoveragePercent = Σ digest CPU ÷ cluster CPU × 100.
	QueryCPUCoveragePercent      *float64 `json:"query_cpu_coverage_percent,omitempty"`
	QueryDiskReadCoveragePercent *float64 `json:"query_disk_read_coverage_percent,omitempty"`
	// CPUByBackendType: cores per backend type over the window;
	// DiskReadByBackendType: storage MB/s per type (needs process.include_io).
	CPUByBackendType      map[string]float64 `json:"cpu_by_backend_type,omitempty"`
	DiskReadByBackendType map[string]float64 `json:"disk_read_by_backend_type,omitempty"`
	TopDigests            []PGDigestStats    `json:"top_digests"`
	TopDigestsByDiskRead  []PGDigestStats    `json:"top_digests_by_disk_read,omitempty"`
	TopDigestsByWait      []PGDigestStats    `json:"top_digests_by_wait,omitempty"`
	Victims               map[string]int     `json:"victims,omitempty"`
	RecentSlowQueries     []PGSlowQuery      `json:"recent_slow_queries"`
}

// PGDigestStats is one digest of one cluster over the window. Formulas as
// QueryDigestStats; pages are 8 KiB; waits use PostgreSQL names.
type PGDigestStats struct {
	DigestID             string           `json:"digest_id"`
	Command              string           `json:"command"` // client | parallel | fastpath | autovacuum | replication
	DigestText           string           `json:"digest_text"`
	SampleQuery          string           `json:"sample_query,omitempty"`
	Truncated            bool             `json:"truncated,omitempty"`
	QueryID              *int64           `json:"queryid,omitempty"`
	Calls                uint64           `json:"calls"`
	CallsPerSec          float64          `json:"calls_per_sec"`
	CPUCores             float64          `json:"cpu_cores"`
	PercentOfNodeCPUUsed *float64         `json:"percent_of_node_cpu_used,omitempty"`
	LatencyMsAvg         float64          `json:"latency_ms_avg"`
	LatencyMsMax         float64          `json:"latency_ms_max"`
	TimeBreakdown        *PGTimeBreakdown `json:"time_breakdown_percent,omitempty"`
	DiskReadMBPerSec     *float64         `json:"disk_read_mb_per_sec,omitempty"`
	PercentOfDiskRead    *float64         `json:"percent_of_disk_read,omitempty"`
	// DiskEstimated: the disk fields are the cluster's I/O-worker reads split
	// by shared_blks_read share (PG 18+ async I/O with enrichment).
	DiskEstimated        bool     `json:"disk_estimated,omitempty"`
	DiskReadPagesPerCall *float64 `json:"disk_read_pages_per_call,omitempty"`
	DiskWriteMBPerSec    *float64 `json:"disk_write_mb_per_sec,omitempty"`
	CPURole              string   `json:"cpu_role,omitempty"`
	IORole               string   `json:"io_role,omitempty"`
	VictimOf             string   `json:"victim_of,omitempty"` // cpu | disk | wal | syncrep
	// Enrichment (pg_stat_statements deltas), absent without postgres.sql.
	SharedHitPercent   *float64 `json:"shared_hit_percent,omitempty"`
	BufferReadMBPerSec *float64 `json:"buffer_read_mb_per_sec,omitempty"`
	TempWriteMBPerSec  *float64 `json:"temp_write_mb_per_sec,omitempty"`
	ReadTimeMsPerCall  *float64 `json:"read_time_ms_per_call,omitempty"`
}

// PGTimeBreakdown is TimeBreakdown with PostgreSQL names.
type PGTimeBreakdown struct {
	CPU         float64  `json:"cpu"`
	CPUWait     *float64 `json:"cpu_wait,omitempty"`
	DiskWait    *float64 `json:"disk_wait,omitempty"`
	WALWait     *float64 `json:"wal_wait,omitempty"`
	SyncRepWait *float64 `json:"syncrep_wait,omitempty"`
	Other       float64  `json:"other"`
}

// PGSlowQuery is one slow client interval. The kernel keeps only the hash
// (the text pointer may be freed at close), so it carries the digest text
// and, when allowed, the digest's first sample — not the literal instance.
type PGSlowQuery struct {
	PID         uint32    `json:"pid"`
	DigestID    string    `json:"digest_id"`
	DigestText  string    `json:"digest_text"`
	SampleQuery string    `json:"sample_query,omitempty"`
	LatencyMs   float64   `json:"latency_ms"`
	CPUMs       float64   `json:"cpu_ms"`
	Timestamp   time.Time `json:"timestamp"`
}
