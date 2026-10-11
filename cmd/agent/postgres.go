package main

import (
	"runtime"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	pgquery "github.com/manhvu1997/linux-obs-agent/internal/ebpf/pg_query"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgstat"
)

// newPostgresAnalyzer builds the PostgreSQL analyzer; call only when
// cfg.Postgres.Enabled.
func newPostgresAnalyzer(cfg *config.Config) *postgres.Analyzer {
	pc := &cfg.Postgres
	var enr *pgstat.Enricher
	if pc.SQL.Enabled() {
		enr = pgstat.NewEnricher(pgstat.PgxDialer(pc.SQL.DSN, pc.SQL.Password, pc.SQL.StatementTimeout))
	}
	return postgres.NewAnalyzer(postgres.OptionsFromConfig(pc, cfg.Process.IncludeIO), postgres.Deps{
		Tracer:   pgquery.NewLoader(pc.SlowQueryThresholdMs * uint64(time.Millisecond)),
		Enricher: enr,
		NumCPU:   runtime.NumCPU(), // the divisor of process CPU% (CLAUDE.md §13 cpu_count)
	})
}
