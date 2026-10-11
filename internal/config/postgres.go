package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// PostgresConfig: PostgreSQL query attribution (CLAUDE.md §23). Off by
// default: nothing is loaded, allocated or started.
type PostgresConfig struct {
	// Enabled is the master switch. Env POSTGRES_TRACING_ENABLED.
	Enabled bool `yaml:"enabled"`
	// BinaryPaths restricts tracing to these postgres binaries; empty traces
	// every running postmaster. Env POSTGRES_BINARY_PATHS (comma-separated).
	BinaryPaths      []string      `yaml:"binary_paths"`
	DiscoverInterval time.Duration `yaml:"discover_interval"`
	// SlowQueryThresholdMs: a client interval this long feeds
	// recent_slow_queries and makes a digest eligible as a victim.
	// Env POSTGRES_SLOW_QUERY_THRESHOLD_MS.
	SlowQueryThresholdMs uint64        `yaml:"slow_query_threshold_ms"`
	PollInterval         time.Duration `yaml:"poll_interval"`
	DigestWindow         time.Duration `yaml:"digest_window"`
	TopDigests           int           `yaml:"top_digests"`
	MaxRecentQueries     int           `yaml:"max_recent_queries"`
	// FoldSystemCatalogs merges pg_catalog / information_schema / pg_*
	// relation reads into one "<system catalogs>" digest.
	FoldSystemCatalogs bool `yaml:"fold_system_catalogs"`
	// SampleQueries keeps each digest's first raw text (literals, possibly
	// secrets) as sample_query. false never stores it.
	SampleQueries bool `yaml:"sample_queries"`
	// EnableDelayAcct writes kernel.task_delayacct=1 at start when it reads 0.
	// Env POSTGRES_ENABLE_DELAYACCT.
	EnableDelayAcct bool `yaml:"enable_delayacct"`
	// SyncRepWait: auto (attach SyncRepWaitForLSN when SQL shows synchronous
	// standbys; false without postgres.sql) | true | false.
	SyncRepWait string `yaml:"syncrep_wait"`
	// MaxStatementsPerSec: circuit breaker — above this traced statement rate
	// for two polls every probe detaches for ShedCooldown.
	// Env POSTGRES_MAX_STATEMENTS_PER_SEC.
	MaxStatementsPerSec       float64       `yaml:"max_statements_per_sec"`
	ShedCooldown              time.Duration `yaml:"shed_cooldown"`
	BackgroundDominantPercent float64       `yaml:"background_dominant_percent"`
	// PrometheusDigests: full | minimal (default) | off, as mysql.
	// Env POSTGRES_PROMETHEUS_DIGESTS.
	PrometheusDigests     string        `yaml:"prometheus_digests"`
	PrometheusMinimalTopN int           `yaml:"prometheus_minimal_top_n"`
	StickyDigestsMax      int           `yaml:"sticky_digests_max"`
	StickyDigestTTL       time.Duration `yaml:"sticky_digest_ttl"`
	// Role and overload thresholds: same meaning and defaults as mysql.
	CPUCulpritPercentOfNodeCPUUsed   float64 `yaml:"cpu_culprit_percent_of_node_cpu_used"`
	CPUCulpritMinNodeCPUUsedPercent  float64 `yaml:"cpu_culprit_min_node_cpu_used_percent"`
	VictimWaitPercent                float64 `yaml:"victim_wait_percent"`
	IOCulpritPercentOfDiskRead       float64 `yaml:"io_culprit_percent_of_disk_read"`
	IOCulpritMinNodeDiskReadMBPerSec float64 `yaml:"io_culprit_min_node_disk_read_mb_per_sec"`
	OverloadNodeCPUPercent           float64 `yaml:"overload_node_cpu_percent"`
	OverloadNodeLoad                 float64 `yaml:"overload_node_load"`
	// SQL is the optional pg_stat_statements enrichment (off without dsn).
	SQL PostgresSQLConfig `yaml:"sql"`
}

// PostgresSQLConfig configures the optional enrichment connection.
type PostgresSQLConfig struct {
	// DSN is a libpq/pgx connection string; "{port}" is replaced by each
	// discovered cluster's port. Env POSTGRES_SQL_DSN.
	DSN string `yaml:"dsn"`
	// PasswordFile wins over Password (env POSTGRES_SQL_PASSWORD only).
	PasswordFile     string        `yaml:"password_file"`
	Password         string        `yaml:"-"`
	PollInterval     time.Duration `yaml:"poll_interval"`
	StatementTimeout time.Duration `yaml:"statement_timeout"`
}

// Enabled reports whether the enrichment is configured.
func (s PostgresSQLConfig) Enabled() bool { return s.DSN != "" }

// String redacts the password so the config can be logged.
func (s PostgresSQLConfig) String() string {
	if s.Password != "" {
		s.Password = "REDACTED"
	}
	return fmt.Sprintf("{dsn:%q password_file:%q password:%s poll_interval:%s statement_timeout:%s}",
		s.DSN, s.PasswordFile, s.Password, s.PollInterval, s.StatementTimeout)
}

func defaultPostgres() PostgresConfig {
	return PostgresConfig{
		DiscoverInterval: 30 * time.Second, SlowQueryThresholdMs: 100, PollInterval: 5 * time.Second,
		DigestWindow: 60 * time.Second, TopDigests: 20, MaxRecentQueries: 100,
		FoldSystemCatalogs: true, SampleQueries: true, SyncRepWait: "auto",
		MaxStatementsPerSec: 30000, ShedCooldown: 10 * time.Minute, BackgroundDominantPercent: 50,
		PrometheusDigests: DigestsMinimal, PrometheusMinimalTopN: 20, StickyDigestsMax: 50, StickyDigestTTL: time.Hour,
		CPUCulpritPercentOfNodeCPUUsed: 20, CPUCulpritMinNodeCPUUsedPercent: 50, VictimWaitPercent: 50,
		IOCulpritPercentOfDiskRead: 20, IOCulpritMinNodeDiskReadMBPerSec: 5,
		OverloadNodeCPUPercent: 85, OverloadNodeLoad: 1.5,
		SQL: PostgresSQLConfig{PollInterval: 60 * time.Second, StatementTimeout: 2 * time.Second},
	}
}

// applyPostgresEnvOverrides:
//
//	POSTGRES_TRACING_ENABLED, POSTGRES_SLOW_QUERY_THRESHOLD_MS, POSTGRES_BINARY_PATHS,
//	POSTGRES_ENABLE_DELAYACCT, POSTGRES_SQL_DSN, POSTGRES_SQL_PASSWORD,
//	POSTGRES_PROMETHEUS_DIGESTS, POSTGRES_MAX_STATEMENTS_PER_SEC
func applyPostgresEnvOverrides(cfg *Config) {
	p := &cfg.Postgres
	truthy := func(v string) bool { return v == "true" || v == "1" || v == "yes" }
	if v := os.Getenv("POSTGRES_TRACING_ENABLED"); v != "" {
		p.Enabled = truthy(v)
	}
	if v := os.Getenv("POSTGRES_SLOW_QUERY_THRESHOLD_MS"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			p.SlowQueryThresholdMs = n
		}
	}
	if v := os.Getenv("POSTGRES_BINARY_PATHS"); v != "" {
		p.BinaryPaths = nil
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				p.BinaryPaths = append(p.BinaryPaths, s)
			}
		}
	}
	if v := os.Getenv("POSTGRES_ENABLE_DELAYACCT"); v != "" {
		p.EnableDelayAcct = truthy(v)
	}
	if v := os.Getenv("POSTGRES_SQL_DSN"); v != "" {
		p.SQL.DSN = v
	}
	if v := os.Getenv("POSTGRES_SQL_PASSWORD"); v != "" {
		p.SQL.Password = v
	}
	if v := os.Getenv("POSTGRES_PROMETHEUS_DIGESTS"); v != "" {
		p.PrometheusDigests = v
	}
	if v := os.Getenv("POSTGRES_MAX_STATEMENTS_PER_SEC"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.MaxStatementsPerSec = f
		}
	}
}

// finish validates and reads password_file. prometheus_digests is always
// validated; the rest only when enabled.
func (p *PostgresConfig) finish() error {
	switch p.PrometheusDigests {
	case DigestsFull, DigestsMinimal, DigestsOff:
	default:
		return fmt.Errorf("postgres.prometheus_digests must be full, minimal or off, got %q", p.PrometheusDigests)
	}
	if p.PrometheusMinimalTopN < 1 {
		return fmt.Errorf("postgres.prometheus_minimal_top_n must be >= 1")
	}
	if !p.Enabled {
		return nil
	}
	switch {
	case p.PollInterval <= 0 || p.DigestWindow < p.PollInterval:
		return fmt.Errorf("postgres.digest_window must be >= postgres.poll_interval > 0")
	case p.DiscoverInterval < 5*time.Second:
		return fmt.Errorf("postgres.discover_interval must be >= 5s")
	case p.TopDigests < 1 || p.StickyDigestsMax < 1 || p.StickyDigestTTL <= 0 || p.MaxRecentQueries < 1:
		return fmt.Errorf("postgres.top_digests, sticky_digests_max, sticky_digest_ttl and max_recent_queries must be > 0")
	case p.MaxStatementsPerSec < 1000:
		return fmt.Errorf("postgres.max_statements_per_sec must be >= 1000")
	case p.ShedCooldown <= 0:
		return fmt.Errorf("postgres.shed_cooldown must be > 0")
	case p.SyncRepWait != "auto" && p.SyncRepWait != "true" && p.SyncRepWait != "false":
		return fmt.Errorf("postgres.syncrep_wait must be auto, true or false, got %q", p.SyncRepWait)
	case p.IOCulpritMinNodeDiskReadMBPerSec <= 0 || p.OverloadNodeCPUPercent <= 0 || p.OverloadNodeLoad <= 0:
		return fmt.Errorf("postgres.io_culprit_min_node_disk_read_mb_per_sec, overload_node_cpu_percent and overload_node_load must be > 0")
	}
	for name, v := range map[string]float64{"cpu_culprit_percent_of_node_cpu_used": p.CPUCulpritPercentOfNodeCPUUsed,
		"cpu_culprit_min_node_cpu_used_percent": p.CPUCulpritMinNodeCPUUsedPercent, "victim_wait_percent": p.VictimWaitPercent,
		"io_culprit_percent_of_disk_read": p.IOCulpritPercentOfDiskRead, "background_dominant_percent": p.BackgroundDominantPercent} {
		if v <= 0 || v > 100 {
			return fmt.Errorf("postgres.%s must be in (0, 100]", name)
		}
	}
	if !p.SQL.Enabled() {
		return nil
	}
	if p.SQL.PollInterval < 30*time.Second {
		return fmt.Errorf("postgres.sql.poll_interval must be >= 30s")
	}
	if p.SQL.StatementTimeout <= 0 || p.SQL.StatementTimeout >= p.SQL.PollInterval {
		return fmt.Errorf("postgres.sql.statement_timeout must be in (0, poll_interval)")
	}
	if p.SQL.PasswordFile != "" {
		b, err := os.ReadFile(p.SQL.PasswordFile)
		if err != nil {
			return fmt.Errorf("postgres.sql.password_file: %w", err)
		}
		p.SQL.Password = strings.TrimRight(string(b), " \t\r\n")
	}
	return nil
}
