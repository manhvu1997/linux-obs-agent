package pg_query

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// drainGrace: see mysql_query.drainGrace (uprobe programs can be preempted
// mid-update on preempt=full kernels ≥ 6.1).
const drainGrace = 50 * time.Millisecond

// DrainAgg flips the active aggregation buffer and returns (and clears) the
// one the programs were writing. Poll goroutine only. Every entry is
// returned exactly once; on a delete error the rest stay for a later drain.
func (l *Loader) DrainAgg() ([]pgtrace.AggEntry, error) {
	if !l.ready.Load() || l.objs.AggActive == nil {
		return nil, errors.New("pg_query: DrainAgg called before Start")
	}
	old := l.aggActive
	next := 1 - old
	if err := l.objs.AggActive.Set(next); err != nil {
		return nil, fmt.Errorf("pg_query: flipping agg_active: %w", err)
	}
	l.aggActive = next
	time.Sleep(drainGrace)
	m := l.objs.Agg0
	if old == 1 {
		m = l.objs.Agg1
	}
	return drainRows(func(yield func(PgQueryAggKeyT, PgQueryAggValT)) error {
		var (
			k PgQueryAggKeyT
			v PgQueryAggValT
		)
		it := m.Iterate()
		for it.Next(&k, &v) {
			yield(k, v)
		}
		return it.Err()
	}, func(k PgQueryAggKeyT) error { return m.Delete(&k) })
}

func drainRows(iterate func(yield func(PgQueryAggKeyT, PgQueryAggValT)) error, del func(PgQueryAggKeyT) error) ([]pgtrace.AggEntry, error) {
	type row struct {
		key PgQueryAggKeyT
		e   pgtrace.AggEntry
	}
	var rows []row
	if err := iterate(func(k PgQueryAggKeyT, v PgQueryAggValT) {
		rows = append(rows, row{k, pgtrace.AggEntry{
			Postmaster: k.Postmaster, Kind: k.Kind, Hash: k.Hash,
			Calls: v.Calls, WallNs: v.WallNs, WallMaxNs: v.WallMaxNs, CPUNs: v.CpuNs, RunqNs: v.RunqNs,
			DiskReadBytes: v.DiskReadBytes, DiskWriteBytes: v.DiskWriteBytes, IOWaitNs: v.IoWaitNs,
			WALWaitNs: v.WalWaitNs, SyncRepWaitNs: v.SyncrepWaitNs,
		}})
	}); err != nil {
		return nil, fmt.Errorf("pg_query: iterating agg map: %w", err)
	}
	out := make([]pgtrace.AggEntry, 0, len(rows))
	var firstErr error
	for _, r := range rows {
		if err := del(r.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if firstErr == nil {
				firstErr = fmt.Errorf("pg_query: clearing agg map: %w", err)
			}
			continue
		}
		out = append(out, r.e)
	}
	if len(out) == 0 {
		out = nil
	}
	return out, firstErr
}

// OpenSessions returns the backends' open intervals (for in-flight credit).
func (l *Loader) OpenSessions() ([]pgtrace.Session, error) {
	if !l.ready.Load() {
		return nil, errNotStarted
	}
	var (
		tid uint32
		s   PgQueryPgSessionT
		out []pgtrace.Session
	)
	it := l.objs.PgSession.Iterate()
	for it.Next(&tid, &s) {
		if s.Open == 0 {
			continue
		}
		out = append(out, pgtrace.Session{TID: tid, Postmaster: s.Postmaster, Kind: uint32(s.Kind), Hash: s.Hash,
			OpenTS: s.Ts, CPU: s.Cpu, Runq: s.Runq, ReadBytes: s.Rd, WriteBytes: s.Wr, Blkio: s.Blkio})
	}
	return out, it.Err()
}

// ClearSessions deletes every session (after DetachAll, so stale intervals
// never close with a huge wall time on re-attach).
func (l *Loader) ClearSessions() error {
	if !l.ready.Load() {
		return errNotStarted
	}
	for _, m := range []*ebpf.Map{l.objs.InParallel, l.objs.UnsafeText} {
		if err := clearMap32(m); err != nil {
			return err
		}
	}
	var tid uint32
	var keys []uint32
	it := l.objs.PgSession.Iterate()
	var s PgQueryPgSessionT
	for it.Next(&tid, &s) {
		keys = append(keys, tid)
	}
	for i := range keys {
		if err := l.objs.PgSession.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return it.Err()
}

// clearMap32 deletes every entry of a map keyed by uint32 (value ignored).
func clearMap32(m *ebpf.Map) error {
	var keys []uint32
	var k uint32
	val := make([]byte, m.ValueSize())
	it := m.Iterate()
	for it.Next(&k, val) {
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// QueryIDs returns hash → PostgreSQL queryid (enrichment).
func (l *Loader) QueryIDs() (map[uint64]int64, error) {
	if !l.ready.Load() {
		return nil, errNotStarted
	}
	var h, id uint64
	out := map[uint64]int64{}
	it := l.objs.Qid.Iterate()
	for it.Next(&h, &id) {
		out[h] = int64(id)
	}
	return out, it.Err()
}

// ForgetText makes the kernel resend the text of hash.
func (l *Loader) ForgetText(hash uint64) {
	if !l.ready.Load() {
		return
	}
	if err := l.objs.TextSeen.Delete(&hash); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		slog.Debug("pg_query: text_seen delete", "err", err)
	}
}

// MarkUnsafe sends every later interval of hash through the exact path.
func (l *Loader) MarkUnsafe(hash uint64) {
	if !l.ready.Load() {
		return
	}
	if err := l.objs.UnsafeHash.Put(&hash, uint8(1)); err != nil {
		slog.Warn("pg_query: unsafe_hash full; hash keeps aggregating", "hash", hash, "err", err)
	}
}

func (l *Loader) counter(idx uint32) uint64 {
	var perCPU []uint64
	var total uint64
	if l.ready.Load() && l.objs.Counters != nil && l.objs.Counters.Lookup(idx, &perCPU) == nil {
		for _, v := range perCPU {
			total += v
		}
	}
	return total
}

// Dropped: intervals lost (fallback ring full in the kernel, or consumer behind).
func (l *Loader) Dropped() uint64 { return l.counter(0) + l.userDropped.Load() }

// AggOverflow: intervals that bypassed aggregation because the map was full.
func (l *Loader) AggOverflow() uint64 { return l.counter(1) }

// TextDropped: text events dropped on a full channel (re-requested).
func (l *Loader) TextDropped() uint64 { return l.textDropped.Load() }
