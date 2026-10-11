// Package pgtrace holds the plain data types exchanged between the pg_query
// eBPF loader and the PostgreSQL analyzer, and the Tracer interface the
// analyzer depends on. Pure: no eBPF imports, so internal/postgres is tested
// on any OS with a fake Tracer.
package pgtrace

import (
	"context"
	"time"
)

// Backend kinds (struct pg_session_t.kind; agg key kind).
const (
	KindClient   uint32 = 1
	KindParallel uint32 = 2
	KindFastpath uint32 = 3
)

// BinaryKey identifies one postgres executable (an inode).
type BinaryKey struct{ Dev, Ino uint64 }

// Hooks are the symbols to attach (from pgsym.Hooks).
type Hooks struct {
	Activity, PortalRun                   string // required
	QueryID, XLogFlush, SyncRep, Parallel string // "" = unavailable
}

// Binary is one executable to attach to. Path is /proc/<postmaster>/exe so a
// binary replaced on disk (package upgrade) is still reachable.
type Binary struct {
	Key     BinaryKey
	Path    string
	Hooks   Hooks
	QueryID bool // attach pgstat_report_query_id (SQL enrichment on)
	SyncRep bool // attach SyncRepWaitForLSN (sync replication in use)
}

// Attached says which optional hooks are live for a binary.
type Attached struct{ QueryID, WAL, SyncRep, Parallel bool }

// ClusterConst are one postmaster's BackendState values.
type ClusterConst struct{ Running, Fastpath uint32 }

// AggEntry is one kernel aggregation entry since the previous drain.
type AggEntry struct {
	Postmaster, Kind                      uint32
	Hash                                  uint64
	Calls, WallNs, WallMaxNs, CPUNs       uint64
	RunqNs, DiskReadBytes, DiskWriteBytes uint64
	IOWaitNs, WALWaitNs, SyncRepWaitNs    uint64
}

// Session is one backend's open interval with its baselines (ktime ns).
type Session struct {
	TID, Postmaster uint32
	Kind            uint32
	Hash            uint64
	OpenTS          uint64 // bpf_ktime_get_ns (CLOCK_MONOTONIC)
	CPU, Runq       uint64
	ReadBytes       uint64
	WriteBytes      uint64
	Blkio           uint64
}

// TextEvent is a statement text: first sight of its hash, or a 1/1024
// verification resend.
type TextEvent struct {
	Hash      uint64
	Len       uint32
	Verify    bool
	Truncated bool
	Text      string
}

// CmdEvent is one interval that could not be aggregated (map full, or an
// unsafe hash). Text is empty when the kernel kept no copy (map full).
type CmdEvent struct {
	Postmaster, PID, Kind              uint32
	Hash                               uint64
	Calls, WallNs, CPUNs, RunqNs       uint64
	DiskReadBytes, DiskWriteBytes      uint64
	IOWaitNs, WALWaitNs, SyncRepWaitNs uint64
	Text                               string
}

// SlowEvent is one slow client interval (no text: the hash only).
type SlowEvent struct {
	Postmaster, PID                 uint32
	Hash                            uint64
	WallNs, CPUNs, RunqNs, IOWaitNs uint64
	WALWaitNs                       uint64
	At                              time.Time
}

// Accounting says which per-statement signals the running kernel provides.
type Accounting struct{ DiskBytes, BlkioDelay bool }

// Tracer is the pg_query loader as the analyzer uses it.
type Tracer interface {
	Start(ctx context.Context) error
	Stop()
	SetClusters(map[uint32]ClusterConst) error
	Attach(Binary) (Attached, error)
	Detach(BinaryKey)
	DetachAll()
	ClearSessions() error
	DrainAgg() ([]AggEntry, error)
	OpenSessions() ([]Session, error)
	QueryIDs() (map[uint64]int64, error)
	ForgetText(hash uint64)
	MarkUnsafe(hash uint64)
	Texts() <-chan TextEvent
	Cmds() <-chan CmdEvent
	Slows() <-chan SlowEvent
	Dropped() uint64
	TextDropped() uint64
	AggOverflow() uint64
	LiteralSkip() bool
	Accounting() Accounting
}
