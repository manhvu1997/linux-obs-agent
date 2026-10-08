package model

import "time"

// OverloadVerdict is the outcome of the query-overload assessment.
type OverloadVerdict string

const (
	// OverloadByQuery: the node is CPU-saturated, mysqld is its top CPU
	// family and one digest burns a large share of the node.
	OverloadByQuery OverloadVerdict = "query_overload"
	// OverloadNodeNotSaturated: the node has CPU headroom; a "culprit"
	// digest, if any, dominates MySQL but does not overload the node.
	OverloadNodeNotSaturated OverloadVerdict = "node_not_saturated"
	// OverloadNotMySQL: the node is saturated but mysqld is not its top
	// CPU consumer — look at process_report.top_families_cpu.
	OverloadNotMySQL OverloadVerdict = "not_mysql"
	// OverloadNoDominantQuery: the node is saturated by mysqld, but the load
	// is spread over many digests (or is outside query execution).
	OverloadNoDominantQuery OverloadVerdict = "no_dominant_query"
	// OverloadNoData: no digest statistics yet (emit_all_queries off, or
	// the window is empty).
	OverloadNoData OverloadVerdict = "no_data"
)

// QueryOverload answers "is one query pattern overloading this node?".
//
// A "culprit" role only says a digest dominates MySQL's query CPU. That is
// not the same as overloading the server: the node may have headroom, or
// something other than mysqld may be burning the CPU. Checks are evaluated
// in order — node_saturated, mysqld_top_consumer, dominant_digest, victims —
// and all of them are always reported so the verdict is auditable.
type QueryOverload struct {
	Type      string    `json:"type"` // always "query_overload"
	Timestamp time.Time `json:"timestamp"`

	Verdict    OverloadVerdict `json:"verdict"`
	Confidence IOConfidence    `json:"confidence"`
	Summary    string          `json:"summary"`

	// The candidate digest: the top digest by CPU in the window. Set whenever
	// digest data exists, also when the verdict is not query_overload.
	PID        uint32 `json:"pid,omitempty"`
	DigestID   string `json:"digest_id,omitempty"`
	DigestText string `json:"digest_text,omitempty"`

	Checks     []OverloadCheck    `json:"checks"`
	Evidence   OverloadEvidence   `json:"evidence"`
	Thresholds OverloadThresholds `json:"thresholds"`
	// Missing lists signals that were unavailable (e.g. "process_families").
	Missing []string `json:"missing,omitempty"`
}

// OverloadCheck is one step of the assessment.
type OverloadCheck struct {
	// Name: "node_saturated" | "mysqld_top_consumer" | "dominant_digest" | "victims"
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// OverloadEvidence is the numeric basis of the verdict. Node values are the
// latest /proc sample; digest values cover mysql_report.window_seconds.
type OverloadEvidence struct {
	NodeCPUPercent  float64 `json:"node_cpu_percent"`
	LoadNormalised  float64 `json:"load_normalised"`
	NumCPU          int     `json:"num_cpu"`
	PSICPUSomeAvg10 float64 `json:"psi_cpu_some_avg10"`
	PSIAvailable    bool    `json:"psi_available"`

	TopFamily           string  `json:"top_family,omitempty"`
	TopFamilyCPUPercent float64 `json:"top_family_cpu_percent"`
	MySQLFamily         string  `json:"mysql_family,omitempty"`
	MySQLFamilyCPU      float64 `json:"mysql_family_cpu_percent"`

	DigestCPUSharePercent  float64 `json:"digest_cpu_share_percent"`
	DigestCPUPercentOfCore float64 `json:"digest_cpu_percent_of_core"`
	DigestCPUPercentOfNode float64 `json:"digest_cpu_percent_of_node"`
	DigestRole             string  `json:"digest_role"`
	VictimDigests          int     `json:"victim_digests"`
}

// OverloadThresholds echoes the cut-offs so a consumer can re-derive the verdict.
type OverloadThresholds struct {
	NodeCPUPercent       float64 `json:"node_cpu_percent"`
	NodeLoad             float64 `json:"node_load"`
	MinNodeCPUPercent    float64 `json:"min_node_cpu_percent"`
	CulpritCPUSharePct   float64 `json:"culprit_cpu_share_percent"`
	CulpritMinCPUPercent float64 `json:"culprit_min_cpu_percent"`
}
