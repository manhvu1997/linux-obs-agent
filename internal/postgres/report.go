package postgres

import (
	"sort"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/overload"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// Commands (querystats command / Prometheus label).
const (
	CommandClient      = "client"
	CommandParallel    = "parallel"
	CommandFastpath    = "fastpath"
	CommandAutovacuum  = "autovacuum"
	CommandReplication = "replication"
)

// PageBytes is PostgreSQL's default block size (disk_read_pages_per_call).
const PageBytes = 8192

// replicationCommands are walsender commands (first token of the digest).
var replicationCommands = map[string]bool{"start_replication": true, "identify_system": true, "base_backup": true,
	"create_replication_slot": true, "drop_replication_slot": true, "alter_replication_slot": true,
	"read_replication_slot": true, "timeline_history": true, "upload_manifest": true}

// commandFor names an interval: parallel and fastpath by kind; autovacuum
// workers and walsenders report RUNNING with their own text, which must
// never be judged as a client query.
func commandFor(kind uint32, digestText string) string {
	switch kind {
	case pgtrace.KindParallel:
		return CommandParallel
	case pgtrace.KindFastpath:
		return CommandFastpath
	}
	if strings.HasPrefix(digestText, "autovacuum :") {
		return CommandAutovacuum
	}
	if f, _, _ := strings.Cut(digestText, " "); replicationCommands[f] {
		return CommandReplication
	}
	return CommandClient
}

// queryCommand: digests that may be a query culprit (client statements and
// fastpath calls; parallel shares are on the leader's digest).
func queryCommand(cmd string) bool { return cmd == CommandClient || cmd == CommandFastpath }

func pgKey(k string) string {
	switch k {
	case querystats.AccountingKeyCommitWait:
		return overload.PGAccountingWAL
	case querystats.AccountingKeyReplicaWait:
		return overload.PGAccountingSyncRep
	}
	return k
}

func pgVictim(v string) string {
	switch v {
	case querystats.VictimCommit:
		return overload.PGVictimWAL
	case querystats.VictimReplica:
		return overload.PGVictimSyncRep
	}
	return v
}

func pgAccounting(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[pgKey(k)] = v
	}
	return out
}

func pgVictims(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[pgVictim(k)] = v
	}
	return out
}

func pgBreakdown(tb *model.TimeBreakdown) *model.PGTimeBreakdown {
	if tb == nil {
		return nil
	}
	return &model.PGTimeBreakdown{CPU: tb.CPU, CPUWait: tb.CPUWait, DiskWait: tb.DiskWait,
		WALWait: tb.CommitWait, SyncRepWait: tb.ReplicaWait, Other: tb.Other}
}

// pgStats renames a querystats digest for the PostgreSQL overload engine.
func pgStats(s model.QueryDigestStats) model.QueryDigestStats {
	s.VictimOf = pgVictim(s.VictimOf)
	return s
}

func toPGDigest(s model.QueryDigestStats) model.PGDigestStats {
	return model.PGDigestStats{
		DigestID: s.DigestID, Command: s.Command, DigestText: s.DigestText, SampleQuery: s.SampleQuery, Truncated: s.Truncated,
		Calls: s.Calls, CallsPerSec: s.CallsPerSec, CPUCores: s.CPUCores, PercentOfNodeCPUUsed: s.PercentOfNodeCPUUsed,
		LatencyMsAvg: s.LatencyMsAvg, LatencyMsMax: s.LatencyMsMax, TimeBreakdown: pgBreakdown(s.TimeBreakdown),
		DiskReadMBPerSec: s.DiskReadMBPerSec, PercentOfDiskRead: s.PercentOfDiskRead, DiskReadPagesPerCall: s.DiskReadPagesPerCall,
		DiskWriteMBPerSec: s.DiskWriteMBPerSec, CPURole: s.CPURole, IORole: s.IORole, VictimOf: pgVictim(s.VictimOf),
	}
}

// enrichment is one digest's pg_stat_statements deltas over Window.
type enrichment struct {
	queryID                                 int64
	Calls, SharedHit, SharedRead, TempWrite uint64
	ReadTimeMs                              float64
	Window                                  time.Duration
	BlockSize                               int
	TrackIOTiming                           bool
}

// applyEnrichment sets the enrichment fields of one JSON digest.
func applyEnrichment(d *model.PGDigestStats, e enrichment) {
	id := e.queryID
	d.QueryID = &id
	if e.SharedHit+e.SharedRead > 0 {
		p := 100 * float64(e.SharedHit) / float64(e.SharedHit+e.SharedRead)
		d.SharedHitPercent = &p
	}
	if w := e.Window.Seconds(); w > 0 {
		r := float64(e.SharedRead) * float64(e.BlockSize) / w / (1 << 20)
		tw := float64(e.TempWrite) * float64(e.BlockSize) / w / (1 << 20)
		d.BufferReadMBPerSec, d.TempWriteMBPerSec = &r, &tw
	}
	if e.TrackIOTiming && e.Calls > 0 {
		v := e.ReadTimeMs / float64(e.Calls)
		d.ReadTimeMsPerCall = &v
	}
}

// estimateDisk splits the cluster's I/O-worker reads (ioWorkerMBps, PG 18+
// async I/O) among digests by their share of shared_blks_read, and recomputes
// their disk fields and io_role. stats is modified in place; the returned
// slice is the top n by estimated reads. nodeReadMBps nil: no node disk.
func estimateDisk(stats []model.QueryDigestStats, sharedRead map[string]uint64, ioWorkerMBps float64,
	nodeReadMBps *float64, th model.QueryRoleThresholds, window time.Duration, n int) []model.QueryDigestStats {
	var total uint64
	for _, s := range stats {
		total += sharedRead[s.DigestID]
	}
	if total == 0 || ioWorkerMBps <= 0 {
		return nil
	}
	var ranked []model.QueryDigestStats
	for i := range stats {
		s := &stats[i]
		r, ok := sharedRead[s.DigestID]
		if !ok || r == 0 {
			continue
		}
		mb := ioWorkerMBps * float64(r) / float64(total)
		s.DiskReadMBPerSec, s.IORole = &mb, ""
		s.DiskReadBytes = uint64(mb * (1 << 20) * window.Seconds())
		if s.Calls > 0 {
			pages := float64(s.DiskReadBytes) / float64(s.Calls) / PageBytes
			s.DiskReadPagesPerCall = &pages
		}
		if nodeReadMBps != nil && *nodeReadMBps > 0 {
			p := 100 * mb / *nodeReadMBps
			s.PercentOfDiskRead = &p
			if p >= th.IOCulpritPercentOfDiskRead && *nodeReadMBps >= th.IOCulpritMinNodeDiskReadMBPerSec {
				s.IORole = querystats.RoleCulprit
			}
		}
		ranked = append(ranked, *s)
	}
	sort.Slice(ranked, func(i, j int) bool { return *ranked[i].DiskReadMBPerSec > *ranked[j].DiskReadMBPerSec })
	if len(ranked) > n {
		ranked = ranked[:n]
	}
	return ranked
}

// mergeAccounting: a key is "ok" only when every cluster's is; otherwise the
// first non-ok value (clusters in name order).
func mergeAccounting(cs []model.PostgresCluster) map[string]string {
	out := map[string]string{}
	for _, c := range cs {
		for k, v := range c.Accounting {
			if cur, ok := out[k]; !ok || cur == querystats.AccountingOK {
				out[k] = v
			}
		}
	}
	return out
}

func toPGDigests(in []model.QueryDigestStats) []model.PGDigestStats {
	out := make([]model.PGDigestStats, 0, len(in))
	for _, s := range in {
		out = append(out, toPGDigest(s))
	}
	return out
}

// overloadDigests keeps the digests that can be a query culprit.
func overloadDigests(in []model.QueryDigestStats) []model.QueryDigestStats {
	var out []model.QueryDigestStats
	for _, s := range in {
		if queryCommand(s.Command) {
			out = append(out, pgStats(s))
		}
	}
	return out
}

func backendUsage(cores, reads map[string]float64) []overload.BackendUsage {
	var out []overload.BackendUsage
	for typ, c := range cores {
		u := overload.BackendUsage{Type: typ, CPUCores: c}
		if reads != nil {
			r := reads[typ]
			u.DiskReadMBPerSec = &r
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
