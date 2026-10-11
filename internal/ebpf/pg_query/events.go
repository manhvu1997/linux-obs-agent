package pg_query

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// Record sizes and flags of pg_query.bpf.c (keep in sync with the C structs).
const (
	textEventSize = 528
	cmdEventSize  = 608
	slowEventSize = 64
	textVerify    = 1
	textTruncated = 2
)

func nullTerm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func decodeTextEvent(b []byte) (pgtrace.TextEvent, bool) {
	if len(b) < textEventSize {
		return pgtrace.TextEvent{}, false
	}
	le := binary.LittleEndian
	flags := le.Uint32(b[12:])
	return pgtrace.TextEvent{Hash: le.Uint64(b[0:]), Len: le.Uint32(b[8:]),
		Verify: flags&textVerify != 0, Truncated: flags&textTruncated != 0, Text: nullTerm(b[16:textEventSize])}, true
}

func decodeCmdEvent(b []byte) (pgtrace.CmdEvent, bool) {
	if len(b) < cmdEventSize {
		return pgtrace.CmdEvent{}, false
	}
	le := binary.LittleEndian
	u := func(off int) uint64 { return le.Uint64(b[off:]) }
	ev := pgtrace.CmdEvent{
		Postmaster: le.Uint32(b[0:]), PID: le.Uint32(b[4:]), Kind: le.Uint32(b[8:]), Hash: u(16),
		Calls: u(24), WallNs: u(32), CPUNs: u(40), RunqNs: u(48), DiskReadBytes: u(56), DiskWriteBytes: u(64),
		IOWaitNs: u(72), WALWaitNs: u(80), SyncRepWaitNs: u(88),
	}
	if le.Uint32(b[12:]) > 0 {
		ev.Text = nullTerm(b[96:cmdEventSize])
	}
	return ev, true
}

func decodeSlowEvent(b []byte) (pgtrace.SlowEvent, bool) {
	if len(b) < slowEventSize {
		return pgtrace.SlowEvent{}, false
	}
	le := binary.LittleEndian
	u := func(off int) uint64 { return le.Uint64(b[off:]) }
	return pgtrace.SlowEvent{Postmaster: le.Uint32(b[0:]), PID: le.Uint32(b[4:]), Hash: u(8),
		WallNs: u(16), CPUNs: u(24), RunqNs: u(32), IOWaitNs: u(40), WALWaitNs: u(48), At: time.Now()}, true
}

// readLoop calls fn for every record until the reader is closed (Stop).
func readLoop(ctx context.Context, rd *ringbuf.Reader, name string, fn func([]byte)) {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			slog.Debug("pg_query: ringbuf read", "ring", name, "err", err)
			continue
		}
		fn(rec.RawSample)
	}
}

// consume forwards decoded records without blocking. A dropped first-sight
// text is re-requested (ForgetText); a dropped command is counted as lost.
func (l *Loader) consume(ctx context.Context) {
	go readLoop(ctx, l.textRd, "text_events", func(b []byte) {
		ev, ok := decodeTextEvent(b)
		if !ok {
			return
		}
		select {
		case l.texts <- ev:
		default:
			l.textDropped.Add(1)
			if !ev.Verify {
				l.ForgetText(ev.Hash)
			}
		}
	})
	go readLoop(ctx, l.cmdRd, "cmd_events", func(b []byte) {
		ev, ok := decodeCmdEvent(b)
		if !ok {
			return
		}
		select {
		case l.cmds <- ev:
		default:
			l.userDropped.Add(1)
		}
	})
	go readLoop(ctx, l.slowRd, "slow_events", func(b []byte) {
		if ev, ok := decodeSlowEvent(b); ok {
			select {
			case l.slows <- ev:
			default: // slow events are samples; dropping one loses no totals
			}
		}
	})
}
