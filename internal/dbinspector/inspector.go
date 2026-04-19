// Package dbinspector defines the DBInspector interface and the Registry that
// manages multiple database tracers in the db-inspector sidecar.
//
// Adding a new database tracer requires only:
//  1. Implement DBInspector for the new DB (e.g. mysqlInspector)
//  2. Add the corresponding config to DBInspectorConfig
//  3. Register it in cmd/db-inspector/main.go
//
// No changes to existing inspectors are needed.
package dbinspector

import (
	"context"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// DBInspector is the contract every database tracer must satisfy.
type DBInspector interface {
	// Name returns a short identifier for the database type (e.g. "mongo", "mysql").
	Name() string

	// Start begins eBPF tracing and blocks until ctx is cancelled.
	// Returns a non-nil error only for unrecoverable startup failures.
	Start(ctx context.Context) error

	// Report returns the latest diagnostic snapshot, or nil if no data has
	// been collected yet (e.g. no queries observed since startup).
	Report() *model.DBInspectReport
}
