package chsink

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// Columns are DateTime('UTC') / DateTime64(3, 'UTC'): always write UTC so an
// agent and a server in different time zones agree.
const (
	timeLayout   = "2006-01-02 15:04:05"
	time64Layout = "2006-01-02 15:04:05.000"
)

func chTime(t time.Time) string   { return t.UTC().Format(timeLayout) }
func chTime64(t time.Time) string { return t.UTC().Format(time64Layout) }

// peerIP renders an address for an IPv6 column: IPv4 as ::ffff:a.b.c.d.
func peerIP(a netip.Addr) string {
	if !a.IsValid() {
		return "::"
	}
	return netip.AddrFrom16(a.As16()).String()
}

type flushWindow struct{ start, end time.Time }

type DigestStatRow struct {
	WindowStart string `json:"window_start"`
	WindowEnd   string `json:"window_end"`
	Host        string `json:"host"`
	PID         uint32 `json:"pid"`
	DigestID    string `json:"digest_id"`
	Command     string `json:"command"`
	Calls       uint64 `json:"calls"`
	CPUNs       uint64 `json:"cpu_ns"`
	RunqNs      uint64 `json:"runq_ns"`
	WallNs      uint64 `json:"wall_ns"`
	WallMaxNs   uint64 `json:"wall_max_ns"`
	BytesOut    uint64 `json:"bytes_out"`
	// Disk bytes are always measured; a wait is NULL when not every poll in
	// the interval could measure it (or no host window exists).
	DiskReadBytes  uint64  `json:"disk_read_bytes"`
	DiskWriteBytes uint64  `json:"disk_write_bytes"`
	IOWaitNs       *uint64 `json:"io_wait_ns"`
	RedoWaitNs     *uint64 `json:"redo_wait_ns"`
}

// HostRow is one host_stats row: the interval's denominators for the digest
// rows. Nullable columns are NULL when not every poll measured them.
type HostRow struct {
	WindowStart    string  `json:"window_start"`
	WindowEnd      string  `json:"window_end"`
	Host           string  `json:"host"`
	CPUCount       uint16  `json:"cpu_count"`
	NodeCPUUsedNs  *uint64 `json:"node_cpu_used_ns"`
	MysqldCPUNs    *uint64 `json:"mysqld_cpu_ns"`
	DiskReadBytes  *uint64 `json:"disk_read_bytes"`
	DiskWriteBytes *uint64 `json:"disk_write_bytes"`
}

type DigestTextRow struct {
	DigestID    string  `json:"digest_id"`
	DigestText  string  `json:"digest_text"`
	SampleQuery *string `json:"sample_query"`
	FirstSeen   string  `json:"first_seen"`
}

type SlowQueryRow struct {
	TS        string  `json:"ts"`
	Host      string  `json:"host"`
	PID       uint32  `json:"pid"`
	TID       uint32  `json:"tid"`
	Comm      string  `json:"comm"`
	LatencyMs float64 `json:"latency_ms"`
	DigestID  string  `json:"digest_id"`
	Query     string  `json:"query"`
}

type PeerRow struct {
	WindowStart string `json:"window_start"`
	WindowEnd   string `json:"window_end"`
	Host        string `json:"host"`
	Family      string `json:"family"`
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	Direction   string `json:"direction"`
	PeerIP      string `json:"peer_ip"`
	ServicePort uint16 `json:"service_port"`
	BytesRx     uint64 `json:"bytes_rx"`
	BytesTx     uint64 `json:"bytes_tx"`
	ConnsOpened uint64 `json:"conns_opened"`
	ConnsClosed uint64 `json:"conns_closed"`
}

type FamilyRow struct {
	WindowStart   string  `json:"window_start"`
	WindowEnd     string  `json:"window_end"`
	Host          string  `json:"host"`
	Family        string  `json:"family"`
	CPUPercentAvg float32 `json:"cpu_percent_avg"`
	CPUPercentMax float32 `json:"cpu_percent_max"`
	RSSBytesMax   uint64  `json:"rss_bytes_max"`
	ProcessesMax  uint32  `json:"processes_max"`
}

type SnapshotRow struct {
	TS      string `json:"ts"`
	Host    string `json:"host"`
	Reason  string `json:"reason"`
	Verdict string `json:"verdict"`
	Report  string `json:"report"`
}

// digestRows renders the interval's digest deltas. hw says which waits every
// poll measured: io_wait_ns / redo_wait_ns are written only when hw has
// samples and the matching flag is set, NULL otherwise (never a partial 0).
func digestRows(host string, w flushWindow, d []querystats.DigestDelta, hw querystats.HostWindow) []DigestStatRow {
	ioOK := hw.Samples > 0 && hw.IOWaitOK
	redoOK := hw.Samples > 0 && hw.RedoWaitOK
	rows := make([]DigestStatRow, 0, len(d))
	for _, x := range d {
		r := DigestStatRow{
			WindowStart: chTime(w.start), WindowEnd: chTime(w.end), Host: host,
			PID: x.PID, DigestID: x.DigestID, Command: x.Command,
			Calls: x.Calls, CPUNs: x.CPUNs, RunqNs: x.RunqNs, WallNs: x.WallNs, WallMaxNs: x.WallMaxNs,
			BytesOut: x.BytesOut, DiskReadBytes: x.DiskReadBytes, DiskWriteBytes: x.DiskWriteBytes,
		}
		if ioOK {
			v := x.IOWaitNs
			r.IOWaitNs = &v
		}
		if redoOK {
			v := x.RedoWaitNs
			r.RedoWaitNs = &v
		}
		rows = append(rows, r)
	}
	return rows
}

// hostRows is one host_stats row for the interval, or nil when no poll ran
// or nothing moved (no row without signal). A value whose polls were not
// all valid is NULL, so sum() over a range never mixes in a partial value.
// cpu_count is not nullable: it is 0 when no poll had a valid node delta
// (node_cpu_used_ns is then NULL too).
func hostRows(host string, w flushWindow, hw querystats.HostWindow) []HostRow {
	if hw.Samples == 0 || hw.NodeCPUUsedNs+hw.MysqldCPUNs+hw.DiskReadBytes+hw.DiskWriteBytes == 0 {
		return nil
	}
	opt := func(ok bool, v uint64) *uint64 {
		if !ok {
			return nil
		}
		return &v
	}
	return []HostRow{{
		WindowStart: chTime(w.start), WindowEnd: chTime(w.end), Host: host, CPUCount: uint16(hw.NumCPU),
		NodeCPUUsedNs: opt(hw.NodeOK, hw.NodeCPUUsedNs), MysqldCPUNs: opt(hw.MysqldOK, hw.MysqldCPUNs),
		DiskReadBytes: opt(hw.DiskOK, hw.DiskReadBytes), DiskWriteBytes: opt(hw.DiskOK, hw.DiskWriteBytes),
	}}
}

// textRows returns one row per digest id not yet sent and marks it sent.
// sample_query stays NULL unless includeSample and a sample exists (the
// analyzer already blanks samples when mysql.sample_queries is off).
func textRows(d []querystats.DigestDelta, seen *idSet, includeSample bool, now time.Time) []DigestTextRow {
	var rows []DigestTextRow
	for _, x := range d {
		if !seen.addNew(x.DigestID) {
			continue
		}
		r := DigestTextRow{DigestID: x.DigestID, DigestText: x.Text, FirstSeen: chTime(now)}
		if includeSample && x.Sample != "" {
			s := x.Sample
			r.SampleQuery = &s
		}
		rows = append(rows, r)
	}
	return rows
}

// slowRows keeps the raw statement only when includeRaw; otherwise the
// literal-free digest text, so the row stays useful without secrets.
//
// DigestID is taken from the item (the analyzer computed it exactly as the
// command path does, including placeholder and system-schema folding). The
// stripped query column is the normalised text of the event's query, which
// is literal-free for every case, including placeholders.
func slowRows(host string, ev []model.SlowQuery, includeRaw bool) []SlowQueryRow {
	rows := make([]SlowQueryRow, 0, len(ev))
	for _, it := range ev {
		e := it.Event
		q := sqldigest.Normalize(e.Query).Text
		if includeRaw {
			q = e.Query
		}
		rows = append(rows, SlowQueryRow{
			TS: chTime64(e.Timestamp), Host: host, PID: e.PID, TID: e.TID, Comm: e.Comm,
			LatencyMs: e.LatencyMs, DigestID: it.DigestID, Query: q,
		})
	}
	return rows
}

func peerRows(host string, w flushWindow, f []netflow.FlowDelta, comm func(uint32) string) []PeerRow {
	comms := make(map[uint32]string)
	rows := make([]PeerRow, 0, len(f))
	for _, x := range f {
		c, ok := comms[x.TGID]
		if !ok && comm != nil {
			c = comm(x.TGID)
			comms[x.TGID] = c
		}
		rows = append(rows, PeerRow{
			WindowStart: chTime(w.start), WindowEnd: chTime(w.end), Host: host,
			Family: x.Family, PID: x.TGID, Comm: c, Direction: x.Direction,
			PeerIP: peerIP(x.Peer), ServicePort: x.ServicePort,
			BytesRx: x.BytesRx, BytesTx: x.BytesTx, ConnsOpened: x.Opened, ConnsClosed: x.Closed,
		})
	}
	return rows
}

func familyRows(host string, w flushWindow, f []process.FamilyWindow) []FamilyRow {
	rows := make([]FamilyRow, 0, len(f))
	for _, x := range f {
		rows = append(rows, FamilyRow{
			WindowStart: chTime(w.start), WindowEnd: chTime(w.end), Host: host, Family: x.Family,
			CPUPercentAvg: float32(x.CPUPercentAvg), CPUPercentMax: float32(x.CPUPercentMax),
			RSSBytesMax: x.RSSBytesMax, ProcessesMax: uint32(x.ProcessesMax),
		})
	}
	return rows
}

// idSet remembers digest ids whose text was sent. When full it is cleared:
// texts are resent, which ReplacingMergeTree absorbs.
type idSet struct {
	max int
	m   map[string]struct{}
}

func newIDSet(max int) *idSet { return &idSet{max: max, m: make(map[string]struct{})} }

func (s *idSet) addNew(id string) bool {
	if _, ok := s.m[id]; ok {
		return false
	}
	if len(s.m) >= s.max {
		s.m = make(map[string]struct{})
	}
	s.m[id] = struct{}{}
	return true
}

// forget removes ids so their text is sent again on next sight.
func (s *idSet) forget(ids []string) {
	for _, id := range ids {
		delete(s.m, id)
	}
}

// encodeRows renders rows as gzip-compressed JSONEachRow (one object per line).
func encodeRows[T any](rows []T) ([]byte, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	for i := range rows {
		if err := enc.Encode(&rows[i]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
