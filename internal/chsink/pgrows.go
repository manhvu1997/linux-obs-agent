package chsink

import (
	"sort"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/pgdrain"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// PGDigestStatRow is one pg_digest_stats row. Nullable columns are NULL when
// not every poll of the interval measured them (or enrichment is off).
type PGDigestStatRow struct {
	WindowStart     string  `json:"window_start"`
	WindowEnd       string  `json:"window_end"`
	Host            string  `json:"host"`
	Cluster         string  `json:"cluster"`
	PostmasterPID   uint32  `json:"postmaster_pid"`
	DigestID        string  `json:"digest_id"`
	Command         string  `json:"command"`
	Calls           uint64  `json:"calls"`
	CPUNs           uint64  `json:"cpu_ns"`
	RunqNs          uint64  `json:"runq_ns"`
	WallNs          uint64  `json:"wall_ns"`
	WallMaxNs       uint64  `json:"wall_max_ns"`
	DiskReadBytes   *uint64 `json:"disk_read_bytes"`
	DiskWriteBytes  *uint64 `json:"disk_write_bytes"`
	DiskEstimated   uint8   `json:"disk_estimated"`
	IOWaitNs        *uint64 `json:"io_wait_ns"`
	WALWaitNs       *uint64 `json:"wal_wait_ns"`
	SyncRepWaitNs   *uint64 `json:"syncrep_wait_ns"`
	SharedBlksHit   *uint64 `json:"shared_blks_hit"`
	SharedBlksRead  *uint64 `json:"shared_blks_read"`
	TempBlksWritten *uint64 `json:"temp_blks_written"`
}

type PGDigestTextRow struct {
	DigestID    string  `json:"digest_id"`
	DigestText  string  `json:"digest_text"`
	QueryID     *int64  `json:"queryid"`
	SampleQuery *string `json:"sample_query"`
	FirstSeen   string  `json:"first_seen"`
}

type PGSlowQueryRow struct {
	TS        string  `json:"ts"`
	Host      string  `json:"host"`
	Cluster   string  `json:"cluster"`
	PID       uint32  `json:"pid"`
	LatencyMs float64 `json:"latency_ms"`
	CPUMs     float64 `json:"cpu_ms"`
	DigestID  string  `json:"digest_id"`
	Query     string  `json:"query"`
}

type PGBackendRow struct {
	WindowStart    string  `json:"window_start"`
	WindowEnd      string  `json:"window_end"`
	Host           string  `json:"host"`
	Cluster        string  `json:"cluster"`
	BackendType    string  `json:"backend_type"`
	CPUNs          uint64  `json:"cpu_ns"`
	DiskReadBytes  *uint64 `json:"disk_read_bytes"`
	DiskWriteBytes *uint64 `json:"disk_write_bytes"`
	ProcessesMax   uint32  `json:"processes_max"`
}

func optU(ok bool, v uint64) *uint64 {
	if !ok {
		return nil
	}
	return &v
}

// pgDigestRows renders one cluster's digest deltas; the host window says
// which signals every poll measured.
func pgDigestRows(host string, w flushWindow, c pgdrain.Cluster, d []querystats.DigestDelta) []PGDigestStatRow {
	hw := c.Host
	measured := hw.Samples > 0
	rows := make([]PGDigestStatRow, 0, len(d))
	for _, x := range d {
		r := PGDigestStatRow{
			WindowStart: chTime(w.start), WindowEnd: chTime(w.end), Host: host, Cluster: c.Cluster, PostmasterPID: c.PostmasterPID,
			DigestID: x.DigestID, Command: x.Command, Calls: x.Calls, CPUNs: x.CPUNs, RunqNs: x.RunqNs,
			WallNs: x.WallNs, WallMaxNs: x.WallMaxNs,
			DiskReadBytes:  optU(measured && hw.DiskBytesOK, x.DiskReadBytes),
			DiskWriteBytes: optU(measured && hw.DiskBytesOK, x.DiskWriteBytes),
			IOWaitNs:       optU(measured && hw.IOWaitOK, x.IOWaitNs),
			WALWaitNs:      optU(measured && hw.RedoWaitOK, x.RedoWaitNs),
			SyncRepWaitNs:  optU(measured && hw.ReplicaWaitOK, x.ReplicaWaitNs),
		}
		if c.DiskEstimated {
			r.DiskEstimated = 1
		}
		if e, ok := c.Enrich[x.DigestID]; ok {
			r.SharedBlksHit, r.SharedBlksRead, r.TempBlksWritten = optU(true, e.SharedHit), optU(true, e.SharedRead), optU(true, e.TempWritten)
		}
		rows = append(rows, r)
	}
	return rows
}

// pgTextRows: one row per digest id not yet sent (separate seen set).
func pgTextRows(d []querystats.DigestDelta, seen *idSet, includeSample bool, now time.Time) []PGDigestTextRow {
	var rows []PGDigestTextRow
	for _, x := range d {
		if !seen.addNew(x.DigestID) {
			continue
		}
		r := PGDigestTextRow{DigestID: x.DigestID, DigestText: x.Text, FirstSeen: chTime(now)}
		if includeSample && x.Sample != "" {
			s := x.Sample
			r.SampleQuery = &s
		}
		rows = append(rows, r)
	}
	return rows
}

// pgSlowRows: the query column is the digest text, or the digest's first
// sample when raw SQL may leave the host.
func pgSlowRows(host, cluster string, ev []model.PGSlowQuery, includeRaw bool) []PGSlowQueryRow {
	rows := make([]PGSlowQueryRow, 0, len(ev))
	for _, e := range ev {
		q := e.DigestText
		if includeRaw && e.SampleQuery != "" {
			q = e.SampleQuery
		}
		rows = append(rows, PGSlowQueryRow{TS: chTime64(e.Timestamp), Host: host, Cluster: cluster, PID: e.PID,
			LatencyMs: e.LatencyMs, CPUMs: e.CPUMs, DigestID: e.DigestID, Query: q})
	}
	return rows
}

// pgBackendRows: no row without signal (zero CPU and no reads).
func pgBackendRows(host string, w flushWindow, b []pgdrain.Backend) []PGBackendRow {
	var rows []PGBackendRow
	for _, x := range b {
		if x.CPUNs == 0 && x.ReadBytes == 0 && x.WriteBytes == 0 {
			continue
		}
		rows = append(rows, PGBackendRow{WindowStart: chTime(w.start), WindowEnd: chTime(w.end), Host: host,
			Cluster: x.Cluster, BackendType: x.Type, CPUNs: x.CPUNs,
			DiskReadBytes: optU(x.IOMeasured, x.ReadBytes), DiskWriteBytes: optU(x.IOMeasured, x.WriteBytes),
			ProcessesMax: x.ProcessesMax})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Cluster != rows[j].Cluster {
			return rows[i].Cluster < rows[j].Cluster
		}
		return rows[i].BackendType < rows[j].BackendType
	})
	return rows
}
