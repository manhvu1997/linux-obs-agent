package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// New fields must not appear in MySQL payloads.
func TestNewOverloadFieldsOmitted(t *testing.T) {
	b, err := json.Marshal(QueryOverload{Type: "query_overload", Verdict: OverloadQueryCPU})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"cluster", "other_clusters", "postgres_family", "background_type", "wal_victims", "background_dominant_percent", "disk_estimated"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s present in %s", k, b)
		}
	}
	b, _ = json.Marshal(DiagnoseReport{})
	if strings.Contains(string(b), "postgres_report") {
		t.Error("postgres_report must be omitted when nil")
	}
}

func TestPGDigestJSONNames(t *testing.T) {
	w := 12.5
	b, _ := json.Marshal(PGDigestStats{DigestID: "x", TimeBreakdown: &PGTimeBreakdown{CPU: 50, WALWait: &w, Other: 37.5}})
	for _, k := range []string{`"wal_wait":12.5`, `"time_breakdown_percent"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("%s missing in %s", k, b)
		}
	}
	if strings.Contains(string(b), "commit_wait") || strings.Contains(string(b), "syncrep_wait") {
		t.Errorf("unset waits must be omitted: %s", b)
	}
}
