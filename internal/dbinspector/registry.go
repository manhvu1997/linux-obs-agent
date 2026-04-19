package dbinspector

import (
	"context"
	"log/slog"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Registry holds all registered DBInspectors and manages their lifecycle.
type Registry struct {
	inspectors []DBInspector
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds an inspector to the registry.
// Must be called before StartAll.
func (r *Registry) Register(i DBInspector) {
	r.inspectors = append(r.inspectors, i)
}

// StartAll launches every registered inspector in its own goroutine.
// Errors from individual inspectors are logged but do not stop others.
func (r *Registry) StartAll(ctx context.Context) {
	for _, i := range r.inspectors {
		insp := i
		go func() {
			slog.Info("db-inspector: starting", "db", insp.Name())
			if err := insp.Start(ctx); err != nil {
				slog.Error("db-inspector: fatal error", "db", insp.Name(), "err", err)
			}
		}()
	}
}

// Report collects the latest snapshot from every inspector and returns a
// combined InspectReport.  Inspectors that have not observed any traffic yet
// (Report() == nil) are omitted from the databases list.
func (r *Registry) Report() *model.InspectReport {
	report := &model.InspectReport{
		Timestamp: time.Now(),
	}
	for _, i := range r.inspectors {
		if snap := i.Report(); snap != nil {
			report.Databases = append(report.Databases, *snap)
		}
	}
	return report
}
