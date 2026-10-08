package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Prometheus per-digest export modes (mysql.prometheus_digests).
const (
	DigestsFull    = "full"
	DigestsMinimal = "minimal"
	DigestsOff     = "off"
)

// ClickHouseConfig controls the optional ClickHouse export (CLAUDE.md §22).
// Disabled by default; when disabled no drain, goroutine or buffer exists.
type ClickHouseConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// PasswordFile wins over Password; trailing whitespace is trimmed.
	PasswordFile          string        `yaml:"password_file"`
	Timeout               time.Duration `yaml:"timeout"`
	TLSInsecureSkipVerify bool          `yaml:"tls_insecure_skip_verify"`
	FlushInterval         time.Duration `yaml:"flush_interval"`
	// MaxBufferBytes bounds encoded batches awaiting send; oldest dropped first.
	MaxBufferBytes         int `yaml:"max_buffer_bytes"`
	MaxBatchesPerFlush     int `yaml:"max_batches_per_flush"`
	MaxDigestKeys          int `yaml:"max_digest_keys"`
	MaxFlowKeys            int `yaml:"max_flow_keys"`
	MaxSlowQueriesPerFlush int `yaml:"max_slow_queries_per_flush"`
	// IncludeSampleQueries sends raw SQL (with literals) off-host. The
	// effective rule is the AND of this and mysql.sample_queries; see
	// EffectiveIncludeSamples.
	IncludeSampleQueries bool                     `yaml:"include_sample_queries"`
	Snapshots            ClickHouseSnapshotConfig `yaml:"snapshots"`
}

// ClickHouseSnapshotConfig controls diagnose_snapshots capture.
type ClickHouseSnapshotConfig struct {
	Enabled       bool          `yaml:"enabled"`
	CheckInterval time.Duration `yaml:"check_interval"`
	// MinInterval: at most one snapshot per interval per host, unless the
	// trigger reason changes.
	MinInterval time.Duration `yaml:"min_interval"`
}

func defaultClickHouse() ClickHouseConfig {
	return ClickHouseConfig{
		URL:                    "http://localhost:8123",
		Database:               "obs",
		Username:               "obs_agent",
		Timeout:                10 * time.Second,
		FlushInterval:          time.Minute,
		MaxBufferBytes:         32 << 20,
		MaxBatchesPerFlush:     10,
		MaxDigestKeys:          10000,
		MaxFlowKeys:            20000,
		MaxSlowQueriesPerFlush: 1000,
		Snapshots: ClickHouseSnapshotConfig{
			Enabled:       true,
			CheckInterval: 30 * time.Second,
			MinInterval:   5 * time.Minute,
		},
	}
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidClickHouseIdentifier reports whether s is safe to interpolate as a
// ClickHouse database or table name.
func ValidClickHouseIdentifier(s string) bool { return identRe.MatchString(s) }

// EffectiveIncludeSamples reports whether raw SQL may leave the host: only
// when both clickhouse.include_sample_queries and mysql.sample_queries are on.
func (c ClickHouseConfig) EffectiveIncludeSamples(mysqlSampleQueries bool) bool {
	return c.IncludeSampleQueries && mysqlSampleQueries
}

// String redacts the password so the config can be logged.
func (c ClickHouseConfig) String() string {
	type plain ClickHouseConfig
	if c.Password != "" {
		c.Password = "REDACTED"
	}
	c.URL = redactURL(c.URL)
	return fmt.Sprintf("%+v", plain(c))
}

// redactURL hides credentials embedded in a URL so it can be logged.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		if u.User != nil {
			return u.Redacted()
		}
		if !strings.Contains(raw, "@") {
			return raw
		}
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if j := strings.LastIndex(rest, "@"); j >= 0 {
			return raw[:i+3] + "REDACTED" + rest[j:]
		}
		return raw
	}
	return "REDACTED_URL"
}

// applyClickHouseEnvOverrides:
//
//	CLICKHOUSE_ENABLED=true|false, CLICKHOUSE_URL, CLICKHOUSE_DATABASE,
//	CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD
func applyClickHouseEnvOverrides(cfg *Config) {
	if v := os.Getenv("CLICKHOUSE_ENABLED"); v != "" {
		cfg.ClickHouse.Enabled = v == "true" || v == "1" || v == "yes"
	}
	for env, dst := range map[string]*string{
		"CLICKHOUSE_URL":      &cfg.ClickHouse.URL,
		"CLICKHOUSE_DATABASE": &cfg.ClickHouse.Database,
		"CLICKHOUSE_USERNAME": &cfg.ClickHouse.Username,
		"CLICKHOUSE_PASSWORD": &cfg.ClickHouse.Password,
	} {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
}

// finish reads password_file and validates. A no-op when disabled.
func (c *ClickHouseConfig) finish() error {
	if !c.Enabled {
		return nil
	}
	if c.PasswordFile != "" {
		b, err := os.ReadFile(c.PasswordFile)
		if err != nil {
			return fmt.Errorf("clickhouse.password_file: %w", err)
		}
		c.Password = strings.TrimRight(string(b), " \t\r\n")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("clickhouse.url must be an http(s) URL with a host, got %q", redactURL(c.URL))
	}
	if !ValidClickHouseIdentifier(c.Database) {
		return fmt.Errorf("clickhouse.database must match %s, got %q", identRe, c.Database)
	}
	if c.FlushInterval < 10*time.Second {
		return fmt.Errorf("clickhouse.flush_interval must be >= 10s")
	}
	if c.Timeout <= 0 || c.Timeout >= c.FlushInterval {
		return fmt.Errorf("clickhouse.timeout must be > 0 and < flush_interval")
	}
	for name, v := range map[string]int{
		"max_buffer_bytes": c.MaxBufferBytes, "max_batches_per_flush": c.MaxBatchesPerFlush,
		"max_digest_keys": c.MaxDigestKeys, "max_flow_keys": c.MaxFlowKeys,
		"max_slow_queries_per_flush": c.MaxSlowQueriesPerFlush,
	} {
		if v <= 0 {
			return fmt.Errorf("clickhouse.%s must be > 0", name)
		}
	}
	if c.Snapshots.Enabled && (c.Snapshots.CheckInterval <= 0 || c.Snapshots.MinInterval < c.Snapshots.CheckInterval) {
		return fmt.Errorf("clickhouse.snapshots.min_interval must be >= check_interval > 0")
	}
	return nil
}

// validateExport checks the export-related settings. Called on every Load
// path (with and without a config file) because env alone can enable them.
func (c *Config) validateExport() error {
	switch c.MySQL.PrometheusDigests {
	case DigestsFull, DigestsMinimal, DigestsOff:
	default:
		return fmt.Errorf("mysql.prometheus_digests must be full, minimal or off, got %q", c.MySQL.PrometheusDigests)
	}
	if c.MySQL.PrometheusMinimalTopN < 1 {
		return fmt.Errorf("mysql.prometheus_minimal_top_n must be >= 1")
	}
	return c.ClickHouse.finish()
}
