package mysql_query

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDecodeTextEvent(t *testing.T) {
	b := make([]byte, textEventSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 0x1122334455667788)
	le.PutUint32(b[8:], 23)
	le.PutUint32(b[12:], 600)
	le.PutUint32(b[16:], 1)
	copy(b[24:], "SELECT ? + 41\x00stale")
	ev, ok := decodeTextEvent(b)
	if !ok || ev.Hash != 0x1122334455667788 || ev.Command != 23 || ev.QueryLen != 600 || !ev.Verify || ev.Query != "SELECT ? + 41" {
		t.Fatalf("got %+v, %v", ev, ok)
	}
	if _, ok := decodeTextEvent(b[:10]); ok {
		t.Fatal("short record accepted")
	}
}

// DrainAgg and the text/unsafe maps read the generated mirror types with
// reflection-free fixed sizes; they must match the C structs (16, 64, 16).
func TestAggTypeSizesMatchGenerated(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"agg_key_t", binary.Size(MysqlQueryAggKeyT{}), 16},
		{"agg_val_t", binary.Size(MysqlQueryAggValT{}), 64},
		{"text_key_t", binary.Size(MysqlQueryTextKeyT{}), 16},
	} {
		if c.got != c.want {
			t.Errorf("binary.Size(%s mirror) = %d, want %d", c.name, c.got, c.want)
		}
	}
}

type forgotten struct {
	command uint32
	hash    uint64
}

func TestForwardTextDropForgetsFirstSightOnly(t *testing.T) {
	l := &Loader{TextEvents: make(chan TextEvent, 1)}
	var calls []forgotten
	forget := func(c uint32, h uint64) { calls = append(calls, forgotten{c, h}) }

	// Room in the channel: delivered, nothing forgotten, nothing dropped.
	l.forwardText(TextEvent{Command: 3, Hash: 1}, forget)
	if len(l.TextEvents) != 1 || l.TextDropped() != 0 || len(calls) != 0 {
		t.Fatalf("delivered: len=%d dropped=%d forgot=%v", len(l.TextEvents), l.TextDropped(), calls)
	}

	// Channel full, first-sight event: counted and re-requested.
	l.forwardText(TextEvent{Command: 23, Hash: 0xabc}, forget)
	if l.TextDropped() != 1 {
		t.Fatalf("text dropped = %d, want 1", l.TextDropped())
	}
	if want := []forgotten{{23, 0xabc}}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("forget calls = %v, want %v", calls, want)
	}

	// Channel full, verification resend: counted, but text_seen is untouched.
	l.forwardText(TextEvent{Command: 3, Hash: 0xdef, Verify: true}, forget)
	if l.TextDropped() != 2 {
		t.Fatalf("text dropped = %d, want 2", l.TextDropped())
	}
	if len(calls) != 1 {
		t.Fatalf("verify drop must not forget; calls = %v", calls)
	}

	// A text drop is re-requested (or only a verification sample), never a
	// lost command: Dropped() must not count it.
	if l.Dropped() != 0 {
		t.Fatalf("Dropped() = %d, want 0 (text drops are not lost commands)", l.Dropped())
	}
}

func TestDrainRows(t *testing.T) {
	k := func(h uint64) MysqlQueryAggKeyT { return MysqlQueryAggKeyT{Tgid: 7, Command: 3, Hash: h} }
	v := func(c uint64) MysqlQueryAggValT { return MysqlQueryAggValT{Calls: c, CpuNs: c * 10} }
	iterOf := func(hashes []uint64, err error) func(func(MysqlQueryAggKeyT, MysqlQueryAggValT)) error {
		return func(yield func(MysqlQueryAggKeyT, MysqlQueryAggValT)) error {
			for _, h := range hashes {
				yield(k(h), v(h))
			}
			return err
		}
	}
	errBoom := errors.New("boom")
	hashes := func(es []AggEntry) []uint64 {
		var out []uint64
		for _, e := range es {
			out = append(out, e.Hash)
		}
		return out
	}

	t.Run("iteration error returns nothing and deletes nothing", func(t *testing.T) {
		deleted := 0
		got, err := drainRows(iterOf([]uint64{1, 2}, errBoom), func(MysqlQueryAggKeyT) error { deleted++; return nil })
		if got != nil || !errors.Is(err, errBoom) || deleted != 0 {
			t.Fatalf("got %v, err %v, deleted %d", got, err, deleted)
		}
	})
	t.Run("all deleted", func(t *testing.T) {
		got, err := drainRows(iterOf([]uint64{1, 2, 3}, nil), func(MysqlQueryAggKeyT) error { return nil })
		if err != nil || !reflect.DeepEqual(hashes(got), []uint64{1, 2, 3}) {
			t.Fatalf("got %v, err %v", got, err)
		}
		if got[1].PID != 7 || got[1].Command != 3 || got[1].Calls != 2 || got[1].CPUNs != 20 {
			t.Fatalf("entry fields not mapped: %+v", got[1])
		}
	})
	t.Run("failed delete is withheld and reported, the rest continue", func(t *testing.T) {
		var tried []uint64
		got, err := drainRows(iterOf([]uint64{1, 2, 3}, nil), func(key MysqlQueryAggKeyT) error {
			tried = append(tried, key.Hash)
			if key.Hash == 2 {
				return errBoom
			}
			return nil
		})
		if !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
		if !reflect.DeepEqual(hashes(got), []uint64{1, 3}) || !reflect.DeepEqual(tried, []uint64{1, 2, 3}) {
			t.Fatalf("got %v, tried %v", hashes(got), tried)
		}
	})
	t.Run("ErrKeyNotExist is ignored and the entry kept", func(t *testing.T) {
		got, err := drainRows(iterOf([]uint64{1, 2}, nil), func(MysqlQueryAggKeyT) error { return ebpf.ErrKeyNotExist })
		if err != nil || !reflect.DeepEqual(hashes(got), []uint64{1, 2}) {
			t.Fatalf("got %v, err %v", got, err)
		}
	})
}

func TestDrainAggBeforeStart(t *testing.T) {
	l := NewLoader(0, "", true)
	if got, err := l.DrainAgg(); err == nil || got != nil {
		t.Fatalf("DrainAgg before Start = %v, %v; want nil and an error", got, err)
	}
}
