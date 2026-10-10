package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func chYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClickHouseDefaults(t *testing.T) {
	d := Defaults()
	c := d.ClickHouse
	if c.Enabled || c.Database != "obs" || c.FlushInterval != time.Minute || c.Timeout != 10*time.Second ||
		c.MaxBufferBytes != 32<<20 || c.MaxBatchesPerFlush != 10 || c.MaxDigestKeys != 10000 ||
		c.MaxFlowKeys != 20000 || c.MaxSlowQueriesPerFlush != 1000 || c.IncludeSampleQueries ||
		!c.Snapshots.Enabled || c.Snapshots.CheckInterval != 30*time.Second || c.Snapshots.MinInterval != 5*time.Minute {
		t.Fatalf("defaults = %+v", c)
	}
	if d.MySQL.PrometheusDigests != DigestsFull || d.MySQL.PrometheusMinimalTopN != 20 {
		t.Fatalf("mysql prometheus defaults = %q %d", d.MySQL.PrometheusDigests, d.MySQL.PrometheusMinimalTopN)
	}
}

func TestClickHouseEnvOverrides(t *testing.T) {
	t.Setenv("CLICKHOUSE_ENABLED", "true")
	t.Setenv("CLICKHOUSE_URL", "https://ch.example:8443")
	t.Setenv("CLICKHOUSE_DATABASE", "metrics")
	t.Setenv("CLICKHOUSE_USERNAME", "agent")
	t.Setenv("CLICKHOUSE_PASSWORD", "pw")
	t.Setenv("MYSQL_PROMETHEUS_DIGESTS", "minimal")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.ClickHouse
	if !c.Enabled || c.URL != "https://ch.example:8443" || c.Database != "metrics" || c.Username != "agent" || c.Password != "pw" {
		t.Fatalf("clickhouse = %+v", c)
	}
	if cfg.MySQL.PrometheusDigests != DigestsMinimal {
		t.Fatalf("prometheus_digests = %q", cfg.MySQL.PrometheusDigests)
	}
}

func TestClickHousePasswordFileWins(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := chYAML(t, "clickhouse:\n  enabled: true\n  url: http://ch:8123\n  password: inline\n  password_file: "+pw+"\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClickHouse.Password != "s3cret" {
		t.Fatalf("password = %q, want s3cret (file wins, trailing newline trimmed)", cfg.ClickHouse.Password)
	}
}

func TestClickHouseValidation(t *testing.T) {
	base := "clickhouse:\n  enabled: true\n  url: http://ch:8123\n"
	cases := map[string]struct{ yaml, want string }{
		"bad scheme":        {"clickhouse:\n  enabled: true\n  url: ftp://ch\n", "clickhouse.url"},
		"no host":           {"clickhouse:\n  enabled: true\n  url: http://\n", "clickhouse.url"},
		"bad database":      {base + "  database: \"obs; DROP\"\n", "clickhouse.database"},
		"flush too short":   {base + "  flush_interval: 5s\n", "flush_interval"},
		"timeout >= flush":  {base + "  timeout: 60s\n", "timeout"},
		"zero buffer":       {base + "  max_buffer_bytes: 0\n", "must be > 0"},
		"snap min < check":  {base + "  snapshots:\n    check_interval: 30s\n    min_interval: 10s\n", "min_interval"},
		"missing pw file":   {base + "  password_file: /nonexistent/pw\n", "password_file"},
		"bad digests mode":  {"mysql:\n  prometheus_digests: some\n", "prometheus_digests"},
		"bad minimal top n": {"mysql:\n  prometheus_minimal_top_n: 0\n", "prometheus_minimal_top_n"},
		"minor share < 0":   {base + "  min_digest_share_percent: -1\n", "min_digest_share_percent"},
		"minor share 100":   {base + "  min_digest_share_percent: 100\n", "min_digest_share_percent"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(chYAML(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestClickHouseMinDigestShare(t *testing.T) {
	if got := Defaults().ClickHouse.MinDigestSharePercent; got != 0.1 {
		t.Fatalf("default min_digest_share_percent = %v, want 0.1", got)
	}
	cfg, err := Load(chYAML(t, "clickhouse:\n  enabled: true\n  url: http://ch:8123\n  min_digest_share_percent: 0\n"))
	if err != nil {
		t.Fatalf("0 (disabled) must be accepted: %v", err)
	}
	if cfg.ClickHouse.MinDigestSharePercent != 0 {
		t.Fatalf("min_digest_share_percent = %v, want 0", cfg.ClickHouse.MinDigestSharePercent)
	}
}

func TestClickHouseDisabledSkipsValidation(t *testing.T) {
	if _, err := Load(chYAML(t, "clickhouse:\n  enabled: false\n  url: ftp://nope\n")); err != nil {
		t.Fatalf("disabled clickhouse must not be validated: %v", err)
	}
}

func TestClickHouseStringRedactsPassword(t *testing.T) {
	c := ClickHouseConfig{URL: "http://ch:8123", Password: "hunter2"}
	if s := c.String(); strings.Contains(s, "hunter2") || !strings.Contains(s, "REDACTED") {
		t.Fatalf("String() = %s", s)
	}
}

func TestValidClickHouseIdentifier(t *testing.T) {
	for s, want := range map[string]bool{"obs": true, "_x1": true, "1obs": false, "a-b": false, "a.b": false, "": false} {
		if got := ValidClickHouseIdentifier(s); got != want {
			t.Errorf("ValidClickHouseIdentifier(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestEffectiveIncludeSamples(t *testing.T) {
	for _, tc := range []struct{ ch, my, want bool }{
		{false, false, false}, {true, false, false}, {false, true, false}, {true, true, true},
	} {
		c := ClickHouseConfig{IncludeSampleQueries: tc.ch}
		if got := c.EffectiveIncludeSamples(tc.my); got != tc.want {
			t.Errorf("ch=%v mysql=%v: got %v want %v", tc.ch, tc.my, got, tc.want)
		}
	}
}

func TestStringRedactsURLCredentials(t *testing.T) {
	c := ClickHouseConfig{URL: "http://u:hunter2@ch:8123", Password: "pw123"}
	s := c.String()
	if strings.Contains(s, "hunter2") || strings.Contains(s, "pw123") {
		t.Fatalf("String leaks credentials: %s", s)
	}
}

func TestFinishURLErrorHasNoSecret(t *testing.T) {
	for _, u := range []string{"ftp://u:secret@host", "http://u:secret@ho st:1/%zz", "u:secret@host"} {
		c := defaultClickHouse()
		c.Enabled = true
		c.URL = u
		err := c.finish()
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("url %q: err = %v", u, err)
		}
	}
}
