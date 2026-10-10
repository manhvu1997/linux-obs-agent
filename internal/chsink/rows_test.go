package chsink

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func decodeRowsForTest(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad JSONEachRow line %q: %v", sc.Text(), err)
		}
		rows = append(rows, m)
	}
	return rows
}

func TestTimesAreUTC(t *testing.T) {
	ict := time.FixedZone("ICT", 7*3600)
	ts := time.Date(2026, 10, 8, 10, 0, 0, 123_000_000, ict)
	if got := chTime(ts); got != "2026-10-08 03:00:00" {
		t.Errorf("chTime = %q", got)
	}
	if got := chTime64(ts); got != "2026-10-08 03:00:00.123" {
		t.Errorf("chTime64 = %q", got)
	}
}

func TestPeerIPFormat(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1": "::ffff:10.0.0.1", "2001:db8::1": "2001:db8::1"} {
		if got := peerIP(netip.MustParseAddr(in)); got != want {
			t.Errorf("peerIP(%s) = %q, want %q", in, got, want)
		}
	}
	if got := peerIP(netip.Addr{}); got != "::" {
		t.Errorf("invalid addr -> %q, want ::", got)
	}
}

func TestTextRowsOncePerIDAndSamplePrivacy(t *testing.T) {
	seen := newIDSet(10)
	d := []querystats.DigestDelta{
		{DigestID: "a", Text: "select ?", Sample: "select 1"},
		{DigestID: "b", Text: "update t set x = ?", Sample: ""},
	}
	now := time.Unix(1_800_000_000, 0)
	rows := textRows(d, seen, false, now)
	if len(rows) != 2 || rows[0].SampleQuery != nil {
		t.Fatalf("rows = %+v, want 2 rows without sample", rows)
	}
	if again := textRows(d, seen, false, now); len(again) != 0 {
		t.Fatalf("text resent: %+v", again)
	}
	seen2 := newIDSet(10)
	rows = textRows(d, seen2, true, now)
	if rows[0].SampleQuery == nil || *rows[0].SampleQuery != "select 1" || rows[1].SampleQuery != nil {
		t.Fatalf("include: rows = %+v (empty sample must stay NULL)", rows)
	}
}

func TestIDSetClearsWhenFull(t *testing.T) {
	s := newIDSet(2)
	s.addNew("a")
	s.addNew("b")
	if !s.addNew("c") || !s.addNew("a") {
		t.Fatal("a full set must reset and accept ids again")
	}
}

func TestSlowRowsPrivacy(t *testing.T) {
	ev := []model.SlowQuery{{Event: model.MySQLSlowEvent{PID: 1, TID: 2, Comm: "mysqld", LatencyMs: 900,
		Query: "select * from users where pw = 'secret'", Timestamp: time.Unix(1_800_000_000, 5_000_000)}}}
	d := sqldigest.Normalize(ev[0].Event.Query)
	ev[0].DigestID = d.ID
	rows := slowRows("h", ev, false)
	if strings.Contains(rows[0].Query, "secret") || rows[0].Query != d.Text || rows[0].DigestID != d.ID {
		t.Fatalf("stripped row = %+v", rows[0])
	}
	if !strings.HasSuffix(rows[0].TS, ".005") {
		t.Fatalf("ts = %q, want millisecond precision", rows[0].TS)
	}
	if raw := slowRows("h", ev, true); raw[0].Query != ev[0].Event.Query {
		t.Fatalf("include raw: %q", raw[0].Query)
	}
}

func TestSlowRowsKeepSuppliedDigestID(t *testing.T) {
	ev := []model.SlowQuery{
		{DigestID: "ph-id", Event: model.MySQLSlowEvent{Query: "<COM_STMT_EXECUTE: prepared, text unavailable>"}},
		{DigestID: "sys-id", Event: model.MySQLSlowEvent{Query: "select * from information_schema.tables where n = 'secret'"}},
	}
	rows := slowRows("h", ev, false)
	if rows[0].DigestID != "ph-id" || rows[1].DigestID != "sys-id" {
		t.Fatalf("ids = %q %q, want supplied ids kept", rows[0].DigestID, rows[1].DigestID)
	}
	if strings.Contains(rows[1].Query, "secret") {
		t.Fatalf("system-schema row leaks literal: %q", rows[1].Query)
	}
}

func TestPeerRowsResolveCommOncePerPID(t *testing.T) {
	calls := 0
	comm := func(pid uint32) string { calls++; return "app" }
	f := []netflow.FlowDelta{
		{TGID: 7, Family: "app.service", Direction: "inbound", Peer: netip.MustParseAddr("10.0.0.2"), ServicePort: 80, BytesRx: 1},
		{TGID: 7, Family: "app.service", Direction: "inbound", Peer: netip.MustParseAddr("10.0.0.3"), ServicePort: 80, BytesRx: 2},
	}
	w := flushWindow{time.Unix(0, 0), time.Unix(60, 0)}
	rows := peerRows("h", w, f, comm)
	if calls != 1 || len(rows) != 2 || rows[0].Comm != "app" || rows[0].PeerIP != "::ffff:10.0.0.2" || rows[0].WindowEnd != "1970-01-01 00:01:00" {
		t.Fatalf("calls=%d rows=%+v", calls, rows)
	}
	if nilComm := peerRows("h", w, f, nil); nilComm[0].Comm != "" {
		t.Fatalf("nil resolver must give empty comm")
	}
}

func TestEncodeRowsJSONEachRow(t *testing.T) {
	w := flushWindow{time.Unix(0, 0), time.Unix(60, 0)}
	body, err := encodeRows(familyRows("h", w, []process.FamilyWindow{
		{Family: "a.service", CPUPercentAvg: 12.5, CPUPercentMax: 20, RSSBytesMax: 1 << 20, ProcessesMax: 3},
		{Family: "b.service"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	rows := decodeRowsForTest(t, body)
	if len(rows) != 2 || rows[0]["family"] != "a.service" || rows[0]["cpu_percent_avg"] != 12.5 ||
		rows[0]["processes_max"] != float64(3) || rows[0]["host"] != "h" || rows[0]["window_start"] != "1970-01-01 00:00:00" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestDigestRowsColumns(t *testing.T) {
	w := flushWindow{time.Unix(0, 0), time.Unix(60, 0)}
	rows := digestRows("h", w, []querystats.DigestDelta{{PID: 5, DigestID: "x", Command: "query", Calls: 2, CPUNs: 10, WallMaxNs: 7}},
		querystats.HostWindow{Samples: 1, IOWaitOK: true, RedoWaitOK: true})
	body, _ := encodeRows(rows)
	got := decodeRowsForTest(t, body)[0]
	for _, col := range []string{"window_start", "window_end", "host", "pid", "digest_id", "command", "calls",
		"cpu_ns", "runq_ns", "wall_ns", "wall_max_ns", "bytes_out",
		"disk_read_bytes", "disk_write_bytes", "io_wait_ns", "redo_wait_ns"} {
		if _, ok := got[col]; !ok {
			t.Errorf("missing column %s in %v", col, got)
		}
	}
	if _, ok := got["bytes_in"]; ok {
		t.Errorf("bytes_in is no longer measured; rows must not carry it: %v", got)
	}
}

func TestIDSetForget(t *testing.T) {
	s := newIDSet(10)
	s.addNew("a")
	s.addNew("b")
	s.forget([]string{"a", "zz"})
	if !s.addNew("a") || s.addNew("b") {
		t.Fatal("forget must remove only the named ids")
	}
}

var t0 = time.Unix(1_800_000_000, 0)

func TestDigestRowsNullWaits(t *testing.T) {
	d := []querystats.DigestDelta{{PID: 1, DigestID: "a", Command: "query", Calls: 1, DiskReadBytes: 4096, DiskWriteBytes: 1, IOWaitNs: 7, RedoWaitNs: 9}}
	w := flushWindow{t0, t0.Add(time.Minute)}
	got := digestRows("h", w, d, querystats.HostWindow{Samples: 12, IOWaitOK: false, RedoWaitOK: true})
	if got[0].IOWaitNs != nil || got[0].RedoWaitNs == nil || *got[0].RedoWaitNs != 9 || got[0].DiskReadBytes != 4096 {
		t.Fatalf("row = %+v", got[0])
	}
	b, _ := json.Marshal(got[0])
	if !strings.Contains(string(b), `"io_wait_ns":null`) {
		t.Fatalf("unmeasured wait must encode as null: %s", b)
	}
}

func TestDigestRowsWaitsNullWithoutHostSamples(t *testing.T) {
	d := []querystats.DigestDelta{{PID: 1, DigestID: "a", Command: "query", Calls: 1, IOWaitNs: 7, RedoWaitNs: 9}}
	w := flushWindow{t0, t0.Add(time.Minute)}
	got := digestRows("h", w, d, querystats.HostWindow{IOWaitOK: true, RedoWaitOK: true})
	if got[0].IOWaitNs != nil || got[0].RedoWaitNs != nil {
		t.Fatalf("no host samples (Sources.Host nil): waits must be NULL, row = %+v", got[0])
	}
}

func TestHostRows(t *testing.T) {
	w := flushWindow{t0, t0.Add(time.Minute)}
	got := hostRows("h", w, querystats.HostWindow{Samples: 12, NumCPU: 8, NodeCPUUsedNs: 3e11, MysqldCPUNs: 1e11, DiskReadBytes: 5, DiskWriteBytes: 6,
		NodeOK: true, MysqldOK: false, DiskOK: true})
	if len(got) != 1 || got[0].CPUCount != 8 || *got[0].NodeCPUUsedNs != 3e11 || got[0].MysqldCPUNs != nil || *got[0].DiskReadBytes != 5 {
		t.Fatalf("rows = %+v", got)
	}
}

func TestHostRowsSkippedWhenIdle(t *testing.T) {
	w := flushWindow{t0, t0.Add(time.Minute)}
	if got := hostRows("h", w, querystats.HostWindow{}); got != nil {
		t.Fatalf("no samples: rows = %+v", got)
	}
	if got := hostRows("h", w, querystats.HostWindow{Samples: 12, NumCPU: 8, NodeOK: true, DiskOK: true, MysqldOK: true}); got != nil {
		t.Fatalf("all deltas 0: rows = %+v", got)
	}
}

// NumCPU stays 0 when no poll had a valid node delta; cpu_count is not
// nullable, so the row carries 0 with node_cpu_used_ns NULL rather than
// being skipped while other values moved.
func TestHostRowsNumCPUZeroWhenNodeUnknown(t *testing.T) {
	w := flushWindow{t0, t0.Add(time.Minute)}
	got := hostRows("h", w, querystats.HostWindow{Samples: 3, MysqldCPUNs: 2e9, DiskReadBytes: 10, DiskWriteBytes: 20,
		NodeOK: false, MysqldOK: true, DiskOK: true})
	if len(got) != 1 || got[0].CPUCount != 0 || got[0].NodeCPUUsedNs != nil || got[0].MysqldCPUNs == nil || *got[0].MysqldCPUNs != 2e9 ||
		*got[0].DiskWriteBytes != 20 {
		t.Fatalf("rows = %+v", got)
	}
	b, _ := json.Marshal(got[0])
	if !strings.Contains(string(b), `"cpu_count":0`) || !strings.Contains(string(b), `"node_cpu_used_ns":null`) {
		t.Fatalf("json = %s", b)
	}
}
