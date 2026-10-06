//go:build linux

package mysql_query

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The hand-written decodeCmdEvent must agree with the C struct
// mysql_cmd_event_t as compiled by clang (bpf2go-generated mirror type).
func TestCmdEventSizeMatchesGenerated(t *testing.T) {
	if got := binary.Size(MysqlQueryMysqlCmdEventT{}); got != cmdEventSize {
		t.Fatalf("binary.Size(MysqlQueryMysqlCmdEventT) = %d, cmdEventSize = %d", got, cmdEventSize)
	}
}

func TestDecodeCmdEventRoundTrip(t *testing.T) {
	var raw MysqlQueryMysqlCmdEventT
	raw.Pid = 0x01020304
	raw.Tid = 0x05060708
	raw.Command = 3
	raw.QueryLen = 0x0a0b0c0d
	raw.WallNs = 0x1111111111111111
	raw.CpuNs = 0x2222222222222222
	raw.RunqNs = 0x3333333333333333
	raw.BytesIn = 0x4444444444444444
	raw.BytesOut = 0x5555555555555555
	copy(raw.Comm[:], "mysqld-worker")
	const q = "SELECT REPEAT('a', 100000) AS big"
	copy(raw.Query[:], q)
	// Bytes after the NUL must be ignored by the string extraction.
	raw.Query[len(q)+1] = 'X'

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatal(err)
	}
	ev, ok := decodeCmdEvent(buf.Bytes())
	if !ok {
		t.Fatal("decodeCmdEvent returned ok=false")
	}
	want := CmdEvent{
		PID: raw.Pid, TID: raw.Tid, Command: raw.Command, QueryLen: raw.QueryLen,
		WallNs: raw.WallNs, CPUNs: raw.CpuNs, RunqNs: raw.RunqNs,
		BytesIn: raw.BytesIn, BytesOut: raw.BytesOut,
		Comm: "mysqld-worker", Query: q,
	}
	if ev != want {
		t.Fatalf("decoded\n  %+v\nwant\n  %+v", ev, want)
	}

	// Full-length, non-NUL-terminated fields decode to the whole array.
	for i := range raw.Comm {
		raw.Comm[i] = 'c'
	}
	for i := range raw.Query {
		raw.Query[i] = 'q'
	}
	buf.Reset()
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatal(err)
	}
	ev, ok = decodeCmdEvent(buf.Bytes())
	if !ok || len(ev.Comm) != len(raw.Comm) || len(ev.Query) != len(raw.Query) {
		t.Fatalf("full-length fields: ok=%v comm=%d query=%d", ok, len(ev.Comm), len(ev.Query))
	}
}

func TestDecodeCmdEventShort(t *testing.T) {
	if _, ok := decodeCmdEvent(make([]byte, cmdEventSize-1)); ok {
		t.Fatal("decodeCmdEvent accepted a short record")
	}
	if _, ok := decodeCmdEvent(nil); ok {
		t.Fatal("decodeCmdEvent accepted nil")
	}
}

// consume decodes slow events with binary.Read into the generated type; the
// C struct carries the command after the query (560 bytes).
func TestSlowEventSizeMatchesGenerated(t *testing.T) {
	if got := binary.Size(MysqlQueryMysqlSlowEventT{}); got != 560 {
		t.Fatalf("binary.Size(MysqlQueryMysqlSlowEventT) = %d, want 560", got)
	}
}
