// Package pgstat is the optional pg_stat_statements enrichment of the
// PostgreSQL tracer: one connection per cluster, one filtered query per poll
// (no statement text transferred). Pure logic here; the pgx connection is in
// pgx.go.
package pgstat

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Status values (postgres_report.accounting.enrichment).
const (
	StatusOK            = "ok"
	StatusNotConfigured = "not_configured"
	StatusMissing       = "pg_stat_statements_missing"
	StatusAuth          = "auth_failed"
	StatusNoQueryID     = "error: compute_query_id off"
)

// Settings are read once per connection.
type Settings struct {
	VersionNum     int // server_version_num, e.g. 160015
	BlockSize      int
	TrackIOTiming  bool
	ComputeQueryID string // on | off | auto | regress
	SyncStandbys   string // synchronous_standby_names
	IOMethod       string // "" before PostgreSQL 18
}

// SyncRep reports whether synchronous replication is configured.
func (s Settings) SyncRep() bool { return strings.TrimSpace(s.SyncStandbys) != "" }

// ReadTimeColumn is pg_stat_statements' block read time column.
func (s Settings) ReadTimeColumn() string {
	if s.VersionNum >= 170000 {
		return "shared_blk_read_time"
	}
	return "blk_read_time"
}

// Row is one queryid's cumulative counters (summed over users, databases
// and top-level flags).
type Row struct {
	QueryID                                 int64
	Calls, SharedHit, SharedRead, TempWrite uint64
	ReadTimeMs                              float64
}

// Delta is one queryid's counters between two polls.
type Delta struct {
	Calls, SharedHit, SharedRead, TempWrite uint64
	ReadTimeMs                              float64
}

// Conn is one cluster connection.
type Conn interface {
	Settings(ctx context.Context) (Settings, error)
	Statements(ctx context.Context, ids []int64, readTimeColumn string) ([]Row, error)
	Close()
}

// Dialer opens a connection to the cluster listening on port.
type Dialer func(ctx context.Context, port int) (Conn, error)

// ErrMissing / ErrAuth classify connection and query errors (pgx.go maps
// SQLSTATEs onto them).
var (
	ErrMissing = errors.New("pg_stat_statements is not installed")
	ErrAuth    = errors.New("authentication failed")
)

type clusterState struct {
	poll     sync.Mutex // serialises Poll, Forget and Close for this cluster; guards conn
	dead     bool       // forgotten or closed: Poll must not reconnect
	conn     Conn
	settings Settings
	prev     map[int64]Row
	prevAt   time.Time
	deltas   map[int64]Delta
	window   time.Duration
	fails    int
	retryAt  time.Time
	status   string
}

// Enricher polls pg_stat_statements per cluster. Safe for concurrent use.
type Enricher struct {
	dial     Dialer
	retry    time.Duration
	maxFails int
	mu       sync.Mutex
	clusters map[int]*clusterState
	closed   bool
	timeout  time.Duration // deadline of one Poll (connect + statements)
}

// NewEnricher: after maxFails (3) consecutive errors a cluster's connection
// is closed and retried after retry (5 min).
func NewEnricher(dial Dialer) *Enricher {
	return &Enricher{dial: dial, retry: 5 * time.Minute, maxFails: 3, timeout: 15 * time.Second, clusters: map[int]*clusterState{}}
}

// WithTimeout sets the deadline of one Poll (connect plus statements); a
// stalled network read can never hold a cluster's state longer.
func (e *Enricher) WithTimeout(d time.Duration) *Enricher {
	if d > 0 {
		e.timeout = d
	}
	return e
}

// Poll refreshes one cluster: connect (and read settings) when needed, then
// read the counters of ids and keep the delta since the previous poll.
func (e *Enricher) Poll(ctx context.Context, port int, ids []int64, now time.Time) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	st := e.clusters[port]
	if st == nil {
		st = &clusterState{status: StatusNotConfigured}
		e.clusters[port] = st
	}
	e.mu.Unlock()
	st.poll.Lock()
	defer st.poll.Unlock()
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	if st.dead || now.Before(st.retryAt) {
		return
	}
	if st.conn == nil {
		c, err := e.dial(ctx, port)
		if err != nil {
			e.fail(st, err, now)
			return
		}
		s, err := c.Settings(ctx)
		if err != nil {
			c.Close()
			e.fail(st, err, now)
			return
		}
		e.mu.Lock()
		st.conn, st.settings, st.prev = c, s, nil
		e.mu.Unlock()
	}
	if st.settings.ComputeQueryID == "off" {
		e.setStatus(st, StatusNoQueryID)
		return
	}
	if len(ids) == 0 {
		e.setStatus(st, StatusOK)
		return
	}
	rows, err := st.conn.Statements(ctx, ids, st.settings.ReadTimeColumn())
	if err != nil {
		e.fail(st, err, now)
		return
	}
	cur := aggregate(rows)
	e.mu.Lock()
	defer e.mu.Unlock()
	if st.prev != nil {
		st.deltas, st.window = diffRows(st.prev, cur), now.Sub(st.prevAt)
	}
	st.prev, st.prevAt, st.fails, st.status = cur, now, 0, StatusOK
}

func (e *Enricher) setStatus(st *clusterState, s string) {
	e.mu.Lock()
	st.status, st.fails = s, 0
	e.mu.Unlock()
}

func (e *Enricher) fail(st *clusterState, err error, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st.status = Classify(err)
	if st.fails++; st.fails >= e.maxFails || errors.Is(err, ErrAuth) {
		if st.conn != nil {
			st.conn.Close()
			st.conn = nil
		}
		st.fails, st.retryAt, st.prev, st.deltas = 0, now.Add(e.retry), nil, nil
	}
}

// View is one cluster's enrichment state.
type View struct {
	Settings Settings
	Known    bool            // settings were read at least once
	Deltas   map[int64]Delta // by queryid, between the last two polls
	Window   time.Duration   // the interval the deltas cover
	At       time.Time       // when the deltas were taken (zero: none yet)
	Status   string          // accounting.enrichment
}

// Snapshot returns a cluster's enrichment state (by port).
func (e *Enricher) Snapshot(port int) View {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.clusters[port]
	if st == nil {
		return View{Status: StatusNotConfigured}
	}
	v := View{Settings: st.settings, Known: st.settings.VersionNum > 0, Deltas: st.deltas, Window: st.window, Status: st.status}
	if st.deltas != nil {
		v.At = st.prevAt
	}
	return v
}

// Forget drops a cluster that is gone and closes its connection once a Poll
// of it still running has returned (bounded by the Poll timeout). It does not
// block, and a late Poll never reconnects the forgotten state.
func (e *Enricher) Forget(port int) {
	e.mu.Lock()
	st := e.clusters[port]
	delete(e.clusters, port)
	e.mu.Unlock()
	go e.kill(st) // never wait for a Poll stalled on the network: the caller may be the main loop
}

func (e *Enricher) kill(st *clusterState) {
	if st == nil {
		return
	}
	st.poll.Lock()
	defer st.poll.Unlock()
	st.dead = true
	if st.conn != nil {
		st.conn.Close()
		st.conn = nil
	}
}

// Close closes every connection; Poll is a no-op afterwards.
func (e *Enricher) Close() {
	e.mu.Lock()
	e.closed = true
	cs := make([]*clusterState, 0, len(e.clusters))
	for port, st := range e.clusters {
		cs = append(cs, st)
		delete(e.clusters, port)
	}
	e.mu.Unlock()
	for _, st := range cs {
		e.kill(st)
	}
}

// Classify maps an error to an accounting.enrichment value.
func Classify(err error) string {
	switch {
	case errors.Is(err, ErrAuth):
		return StatusAuth
	case errors.Is(err, ErrMissing):
		return StatusMissing
	}
	s := err.Error()
	if len(s) > 80 {
		s = s[:80]
	}
	return "error: " + s
}

func aggregate(rows []Row) map[int64]Row {
	out := make(map[int64]Row, len(rows))
	for _, r := range rows {
		a := out[r.QueryID]
		a.QueryID = r.QueryID
		a.Calls += r.Calls
		a.SharedHit += r.SharedHit
		a.SharedRead += r.SharedRead
		a.TempWrite += r.TempWrite
		a.ReadTimeMs += r.ReadTimeMs
		out[r.QueryID] = a
	}
	return out
}

// diffRows returns cur − prev per queryid. A queryid whose counters went
// down (pg_stat_statements_reset(), or the entry was evicted and re-created)
// is skipped for this interval; a new queryid has no delta yet.
func diffRows(prev, cur map[int64]Row) map[int64]Delta {
	out := map[int64]Delta{}
	for id, c := range cur {
		p, ok := prev[id]
		if !ok || c.Calls < p.Calls || c.SharedHit < p.SharedHit || c.SharedRead < p.SharedRead ||
			c.TempWrite < p.TempWrite || c.ReadTimeMs < p.ReadTimeMs {
			continue
		}
		out[id] = Delta{Calls: c.Calls - p.Calls, SharedHit: c.SharedHit - p.SharedHit,
			SharedRead: c.SharedRead - p.SharedRead, TempWrite: c.TempWrite - p.TempWrite, ReadTimeMs: c.ReadTimeMs - p.ReadTimeMs}
	}
	return out
}
