package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemovedMySQLKeysLoadAndAreFound(t *testing.T) {
	yml := []byte("mysql:\n  culprit_cpu_share_percent: 20\n  top_n: 20\n  slow_query_threshold_ms: 50\n")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, yml, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("removed keys must not fail loading: %v", err)
	}
	if cfg.MySQL.SlowQueryThresholdMs != 50 {
		t.Fatalf("slow threshold = %d", cfg.MySQL.SlowQueryThresholdMs)
	}
	got := removedMySQLKeys(yml)
	if len(got) != 2 || got[0].Key != "culprit_cpu_share_percent" || got[0].Replacement != "cpu_culprit_percent_of_node_cpu_used" ||
		got[1].Key != "top_n" || got[1].Replacement != "" {
		t.Fatalf("removed keys = %+v", got)
	}
}

func TestRemovedMySQLKeysNoneOrUnparsable(t *testing.T) {
	for _, y := range []string{"", "mysql:\n  enabled: true\n", "agent:\n  top_n: 3\n", "mysql: off\n", ":::"} {
		if got := removedMySQLKeys([]byte(y)); len(got) != 0 {
			t.Fatalf("%q: removed keys = %+v", y, got)
		}
	}
}
