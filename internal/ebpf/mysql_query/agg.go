package mysql_query

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// AggEntry is one kernel aggregation entry: the sums of every command with
// the same {tgid, command, text hash} since the previous DrainAgg.
type AggEntry struct {
	PID, Command uint32
	Hash         uint64
	Calls        uint64
	WallNs       uint64
	WallMaxNs    uint64
	CPUNs        uint64
	CPUMaxNs     uint64
	RunqNs       uint64
	BytesIn      uint64
	BytesOut     uint64
}

// TextEvent carries a statement text: on the first sight of its (command,
// hash), or as a 1/1024 verification resend (Verify).
type TextEvent struct {
	Command, QueryLen uint32
	Hash              uint64
	Query             string
	Verify            bool
}

const textEventSize = 536 // sizeof(struct text_event_t)

// drainGrace lets a uretprobe that read the old agg_active finish its
// update before the old buffer is read. Programs run in microseconds.
const drainGrace = 5 * time.Millisecond

func decodeTextEvent(b []byte) (TextEvent, bool) {
	if len(b) < textEventSize {
		return TextEvent{}, false
	}
	le := binary.LittleEndian
	return TextEvent{
		Hash: le.Uint64(b[0:]), Command: le.Uint32(b[8:]), QueryLen: le.Uint32(b[12:]),
		Verify: le.Uint32(b[16:]) != 0, Query: nullTermU8(b[24:textEventSize]),
	}, true
}

// DrainAgg flips the active aggregation buffer and returns (and clears) the
// one the programs were writing. Not safe for concurrent use; call it from
// one goroutine (the analyzer's poll loop).
func (l *Loader) DrainAgg() ([]AggEntry, error) {
	old := l.aggActive
	next := 1 - old
	if err := l.objs.AggActive.Set(next); err != nil {
		return nil, fmt.Errorf("mysql_query: flipping agg_active: %w", err)
	}
	l.aggActive = next
	time.Sleep(drainGrace)
	m := l.objs.Agg0
	if old == 1 {
		m = l.objs.Agg1
	}
	var (
		out  []AggEntry
		keys []MysqlQueryAggKeyT
		k    MysqlQueryAggKeyT
		v    MysqlQueryAggValT
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, AggEntry{
			PID: k.Tgid, Command: k.Command, Hash: k.Hash,
			Calls: v.Calls, WallNs: v.WallNs, WallMaxNs: v.WallMaxNs, CPUNs: v.CpuNs, CPUMaxNs: v.CpuMaxNs,
			RunqNs: v.RunqNs, BytesIn: v.BytesIn, BytesOut: v.BytesOut,
		})
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		return out, fmt.Errorf("mysql_query: iterating agg map: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return out, fmt.Errorf("mysql_query: clearing agg map: %w", err)
		}
	}
	return out, nil
}

// ForgetText makes the kernel resend the text of (command, hash).
func (l *Loader) ForgetText(command uint32, hash uint64) {
	k := MysqlQueryTextKeyT{Hash: hash, Command: command}
	if err := l.objs.TextSeen.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		slog.Debug("mysql_query: text_seen delete", "err", err)
	}
}

// MarkUnsafe sends every later command of (command, hash) through the exact
// per-event path.
func (l *Loader) MarkUnsafe(command uint32, hash uint64) {
	k := MysqlQueryTextKeyT{Hash: hash, Command: command}
	if err := l.objs.UnsafeHash.Put(&k, uint8(1)); err != nil {
		slog.Warn("mysql_query: unsafe_hash full; hash keeps aggregating", "hash", hash, "err", err)
	}
}

// AggOverflow returns commands that fell back to full events because the
// aggregation map was full. Safe to call before Start.
func (l *Loader) AggOverflow() uint64 {
	var perCPU []uint64
	var total uint64
	if l.objs.AggOverflow != nil && l.objs.AggOverflow.Lookup(uint32(0), &perCPU) == nil {
		for _, v := range perCPU {
			total += v
		}
	}
	return total
}

// consumeText forwards text events; a full channel drops the event and
// counts it in Dropped() (the hash is then resent after ForgetText).
func (l *Loader) consumeText(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rec, err := l.textRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("mysql_query: text ringbuf read error", "err", err)
			continue
		}
		ev, ok := decodeTextEvent(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case l.TextEvents <- ev:
		default:
			l.userDropped.Add(1)
		}
	}
}
