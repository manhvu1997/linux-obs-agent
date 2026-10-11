package pg_query

import (
	"encoding/binary"
	"testing"
)

func TestDecodeTextEvent(t *testing.T) {
	b := make([]byte, textEventSize)
	binary.LittleEndian.PutUint64(b[0:], 0xabc)
	binary.LittleEndian.PutUint32(b[8:], 8)
	binary.LittleEndian.PutUint32(b[12:], textVerify|textTruncated)
	copy(b[16:], "select 1\x00junk")
	ev, ok := decodeTextEvent(b)
	if !ok || ev.Hash != 0xabc || ev.Len != 8 || !ev.Verify || !ev.Truncated || ev.Text != "select 1" {
		t.Fatalf("%+v %v", ev, ok)
	}
	if _, ok := decodeTextEvent(b[:100]); ok {
		t.Fatal("short record accepted")
	}
}

func TestDecodeCmdEvent(t *testing.T) {
	b := make([]byte, cmdEventSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 100)
	le.PutUint32(b[4:], 4242)
	le.PutUint32(b[8:], 1)
	le.PutUint32(b[12:], 6)
	le.PutUint64(b[16:], 77)
	for i, v := range []uint64{3, 1000, 400, 50, 8192, 0, 10, 20, 30} {
		le.PutUint64(b[24+8*i:], v)
	}
	copy(b[96:], "COMMIT")
	ev, ok := decodeCmdEvent(b)
	if !ok || ev.Postmaster != 100 || ev.PID != 4242 || ev.Kind != 1 || ev.Hash != 77 || ev.Calls != 3 ||
		ev.WallNs != 1000 || ev.CPUNs != 400 || ev.RunqNs != 50 || ev.DiskReadBytes != 8192 ||
		ev.IOWaitNs != 10 || ev.WALWaitNs != 20 || ev.SyncRepWaitNs != 30 || ev.Text != "COMMIT" {
		t.Fatalf("%+v", ev)
	}
}

func TestDecodeSlowEvent(t *testing.T) {
	b := make([]byte, slowEventSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 100)
	le.PutUint32(b[4:], 7)
	le.PutUint64(b[8:], 99)
	for i, v := range []uint64{5e8, 1e8, 2e8, 3e7, 4e6} {
		le.PutUint64(b[16+8*i:], v)
	}
	ev, ok := decodeSlowEvent(b)
	if !ok || ev.Postmaster != 100 || ev.PID != 7 || ev.Hash != 99 || ev.WallNs != 5e8 || ev.CPUNs != 1e8 ||
		ev.RunqNs != 2e8 || ev.IOWaitNs != 3e7 || ev.WALWaitNs != 4e6 || ev.At.IsZero() {
		t.Fatalf("%+v", ev)
	}
}
