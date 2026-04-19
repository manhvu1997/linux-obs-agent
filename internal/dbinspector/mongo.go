package dbinspector

import (
	"context"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/mongo"
)

// MongoInspector wraps mongo.Analyzer to satisfy the DBInspector interface.
// All eBPF logic stays in internal/mongo and internal/ebpf/mongo_query.
type MongoInspector struct {
	analyzer *mongo.Analyzer
}

// NewMongoInspector creates a MongoInspector.
// Pass nil for the collector — the sidecar always publishes regardless of
// system CPU/mem pressure (no baseline metrics available in sidecar mode).
func NewMongoInspector(cfg *config.MongoConfig) *MongoInspector {
	return &MongoInspector{
		analyzer: mongo.NewAnalyzer(cfg, nil),
	}
}

func (m *MongoInspector) Name() string { return "mongo" }

func (m *MongoInspector) Start(ctx context.Context) error {
	return m.analyzer.Start(ctx)
}

func (m *MongoInspector) Report() *model.DBInspectReport {
	snap := m.analyzer.Latest()
	if snap == nil {
		return nil
	}
	return &model.DBInspectReport{
		Database:    "mongo",
		MongoReport: snap,
	}
}
