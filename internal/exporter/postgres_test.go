package exporter

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
)

// Without a registered analyzer (postgres.enabled false) the report has no
// postgres_report.
func TestDiagnoseWithoutPostgres(t *testing.T) {
	p := bareExporter()
	p.RegisterPostgresAnalyzer(nil, &config.Defaults().Postgres)
	if r := p.BuildDiagnoseReport(10, 5); r.PostgresReport != nil {
		t.Fatalf("postgres_report present: %+v", r.PostgresReport)
	}
}
