package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresDefaults(t *testing.T) {
	p := Defaults().Postgres
	if p.Enabled || p.PollInterval != 5*time.Second || p.DigestWindow != time.Minute || p.MaxStatementsPerSec != 30000 ||
		p.ShedCooldown != 10*time.Minute || p.SyncRepWait != "auto" || p.PrometheusDigests != DigestsMinimal ||
		p.BackgroundDominantPercent != 50 || p.SQL.Enabled() || p.SQL.PollInterval != time.Minute {
		t.Fatalf("defaults %+v", p)
	}
	c := Defaults()
	c.Postgres.Enabled = true
	if err := c.validate(); err != nil {
		t.Fatalf("enabled defaults invalid: %v", err)
	}
}

func TestPostgresEnvOverrides(t *testing.T) {
	t.Setenv("POSTGRES_TRACING_ENABLED", "true")
	t.Setenv("POSTGRES_BINARY_PATHS", "/usr/lib/postgresql/16/bin/postgres, /usr/lib/postgresql/18/bin/postgres")
	t.Setenv("POSTGRES_SQL_DSN", "host=/var/run/postgresql port={port} dbname=postgres user=obs_agent")
	t.Setenv("POSTGRES_SQL_PASSWORD", "s3cret")
	t.Setenv("POSTGRES_MAX_STATEMENTS_PER_SEC", "50000")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	p := c.Postgres
	if !p.Enabled || len(p.BinaryPaths) != 2 || !p.SQL.Enabled() || p.SQL.Password != "s3cret" || p.MaxStatementsPerSec != 50000 {
		t.Fatalf("%+v", p)
	}
	if strings.Contains(p.SQL.String(), "s3cret") {
		t.Fatal("password must be redacted")
	}
}

func TestPostgresValidation(t *testing.T) {
	bad := []func(*PostgresConfig){
		func(p *PostgresConfig) { p.DigestWindow = time.Second },
		func(p *PostgresConfig) { p.MaxStatementsPerSec = 10 },
		func(p *PostgresConfig) { p.MaxStatementsPerSec = 0 },
		func(p *PostgresConfig) { p.SyncRepWait = "maybe" },
		func(p *PostgresConfig) { p.BackgroundDominantPercent = 0 },
		func(p *PostgresConfig) { p.SQL.DSN = "port={port}"; p.SQL.PollInterval = 10 * time.Second },
		func(p *PostgresConfig) { p.SQL.DSN = "port={port}"; p.SQL.StatementTimeout = 2 * time.Minute },
		func(p *PostgresConfig) { p.SQL.DSN = "port={port}"; p.SQL.PasswordFile = "/nonexistent/pw" },
		func(p *PostgresConfig) { p.SQL.DSN = "host=/var/run/postgresql dbname=postgres" }, // no {port}
	}
	for i, f := range bad {
		c := Defaults()
		c.Postgres.Enabled = true
		f(&c.Postgres)
		if err := c.validate(); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	c := Defaults()
	c.Postgres.PrometheusDigests = "all"
	if err := c.validate(); err == nil {
		t.Error("prometheus_digests is validated even when disabled")
	}
}

func TestPostgresPasswordFile(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.Postgres.Enabled, c.Postgres.SQL.DSN, c.Postgres.SQL.PasswordFile = true, "port={port}", pw
	if err := c.validate(); err != nil || c.Postgres.SQL.Password != "hunter2" {
		t.Fatalf("err %v password %q", err, c.Postgres.SQL.Password)
	}
}

func TestPostgresSQLStringRedactsDSNPassword(t *testing.T) {
	for _, dsn := range []string{"postgres://obs:hunter2@localhost:{port}/postgres", "host=h port={port} user=obs password=hunter2 dbname=x",
		"host=h port={port} password='hun ter2' user=obs"} {
		out := PostgresSQLConfig{DSN: dsn}.String()
		if strings.Contains(out, "hunter2") || strings.Contains(out, "hun ter2") || !strings.Contains(out, "REDACTED") {
			t.Errorf("dsn %q leaked: %s", dsn, out)
		}
	}
}
