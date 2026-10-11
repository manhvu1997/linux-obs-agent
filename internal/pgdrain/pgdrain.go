// Package pgdrain holds the per-flush PostgreSQL data handed to the
// ClickHouse sink. Pure types so internal/chsink does not import the
// analyzer (which imports eBPF-generated code on Linux).
package pgdrain

import (
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// Enrich is one digest's pg_stat_statements deltas over the interval.
type Enrich struct{ SharedHit, SharedRead, TempWritten uint64 }

// Cluster is one cluster's interval.
type Cluster struct {
	Cluster       string
	PostmasterPID uint32
	Digests       []querystats.DigestDelta
	Folded        uint64 // digests folded into "other" by the drain cap
	Host          querystats.HostWindow
	DiskEstimated bool              // disk bytes are the async-I/O estimate (PG 18+)
	Enrich        map[string]Enrich // by digest id; nil without enrichment
	Slow          []model.PGSlowQuery
	SlowDropped   uint64
}

// Backend is one backend type's totals over the interval.
type Backend struct {
	Cluster, Type         string
	CPUNs                 uint64
	ReadBytes, WriteBytes uint64
	IOMeasured            bool
	ProcessesMax          uint32
}

// Drain is everything since the previous drain.
type Drain struct {
	Clusters []Cluster
	Backends []Backend
}
